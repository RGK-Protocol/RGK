//! wRPC-backed live Kaspa backend.
//!
//! This backend deliberately does not pretend that a node RPC call can answer
//! every historical spend question by outpoint. Kaspa's public UTXO RPC gives
//! current unspent outputs; spend detection for arbitrary outpoints belongs to
//! an indexer or notification listener. `WrpcBackend` therefore combines live
//! node queries with an observed-spend cache supplied by that higher layer.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use core::fmt::Display;
use core::future::Future;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::{RpcBlock, RpcHash, RpcTransaction};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use kaspa_wrpc_client::{
    client::{ConnectOptions, ConnectStrategy},
    KaspaRpcClient, Resolver, WrpcEncoding,
};

use crate::{
    KaspaBlockHash, KaspaChainBackend, KaspaNetworkError, KaspaTip, KaspaTxId, KaspaTxSummary,
    KaspaUtxo, ObservedSpend, SpendingInfo,
};
use rgk_core::{KaspaChainId, KaspaOutpoint};

/// Reusable wRPC backend for live Toccata nodes.
///
/// The backend is sync because [`KaspaChainBackend`] is sync. Internally it
/// blocks on the upstream async wRPC client. The spend cache records facts
/// already observed by an indexer/harness and lets the resolver cross-check
/// those facts against live DAA score for confirmation depth.
#[derive(Clone)]
pub struct WrpcBackend {
    client: KaspaRpcClient,
    network: KaspaChainId,
    observed_spends: Arc<Mutex<BTreeMap<KaspaOutpoint, SpendingInfo>>>,
}

/// Public network selector for Borsh wRPC connections.
///
/// `LocalToccata` uses a simnet wRPC transport but keeps RGK's stricter
/// `KaspaLocalToccata` domain id for receipts and scanner cursors.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WrpcNetwork {
    Mainnet,
    Testnet,
    Devnet,
    Simnet,
    LocalToccata,
}

impl WrpcNetwork {
    pub const fn chain_id(self) -> KaspaChainId {
        match self {
            WrpcNetwork::Mainnet => KaspaChainId::KaspaMainnet,
            WrpcNetwork::Testnet => KaspaChainId::KaspaTestnet,
            WrpcNetwork::Devnet => KaspaChainId::KaspaDevnet,
            WrpcNetwork::Simnet => KaspaChainId::KaspaSimnet,
            WrpcNetwork::LocalToccata => KaspaChainId::KaspaLocalToccata,
        }
    }

    const fn network_type(self) -> NetworkType {
        match self {
            WrpcNetwork::Mainnet => NetworkType::Mainnet,
            WrpcNetwork::Testnet => NetworkType::Testnet,
            WrpcNetwork::Devnet => NetworkType::Devnet,
            WrpcNetwork::Simnet | WrpcNetwork::LocalToccata => NetworkType::Simnet,
        }
    }
}

/// Result of polling the virtual selected-parent chain from a known block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WrpcVirtualChainScan {
    pub removed_chain_block_hashes: Vec<KaspaBlockHash>,
    pub added_chain_block_hashes: Vec<KaspaBlockHash>,
    pub last_added_daa_score: Option<u64>,
    pub observed_spends: usize,
    pub observed_spend_records: Vec<ObservedSpend>,
}

impl WrpcBackend {
    fn observed_spends_lock(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<KaspaOutpoint, SpendingInfo>>, KaspaNetworkError> {
        self.observed_spends
            .lock()
            .map_err(|_| KaspaNetworkError::Invariant("observed spend cache poisoned".into()))
    }

    pub fn new(client: KaspaRpcClient, network: KaspaChainId) -> Self {
        Self {
            client,
            network,
            observed_spends: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Connect to a node using Borsh wRPC.
    pub async fn connect_borsh(
        url: impl AsRef<str>,
        network: WrpcNetwork,
    ) -> Result<Self, KaspaNetworkError> {
        Self::connect_borsh_with_chain_id(url, network, network.chain_id()).await
    }

    /// Connect to a node using Borsh wRPC and an explicit RGK chain id.
    pub async fn connect_borsh_with_chain_id(
        url: impl AsRef<str>,
        network: WrpcNetwork,
        chain_id: KaspaChainId,
    ) -> Result<Self, KaspaNetworkError> {
        let resolver = Some(Resolver::default());
        let selected_network = Some(NetworkId::new(network.network_type()));
        let client = KaspaRpcClient::new(
            WrpcEncoding::Borsh,
            Some(url.as_ref()),
            resolver,
            selected_network,
            None,
        )
        .map_err(rpc_error)?;
        let opts = ConnectOptions {
            block_async_connect: true,
            connect_timeout: Some(Duration::from_secs(5)),
            strategy: ConnectStrategy::Fallback,
            ..Default::default()
        };
        client.connect(Some(opts)).await.map_err(rpc_error)?;
        Ok(Self::new(client, chain_id))
    }

    /// Connect to a simnet node using Borsh wRPC.
    pub async fn connect_simnet_borsh(
        url: impl AsRef<str>,
        network: KaspaChainId,
    ) -> Result<Self, KaspaNetworkError> {
        Self::connect_borsh_with_chain_id(url, WrpcNetwork::Simnet, network).await
    }

    pub fn client(&self) -> &KaspaRpcClient {
        &self.client
    }

    /// Record a spend already observed by the indexer or live harness.
    pub fn record_spend(
        &self,
        spent: KaspaOutpoint,
        info: SpendingInfo,
    ) -> Result<(), KaspaNetworkError> {
        self.observed_spends_lock()?.insert(spent, info);
        Ok(())
    }

    pub fn observed_spend(
        &self,
        spent: KaspaOutpoint,
    ) -> Result<Option<SpendingInfo>, KaspaNetworkError> {
        Ok(self.observed_spends_lock()?.get(&spent).cloned())
    }

    pub fn observed_spend_count(&self) -> Result<usize, KaspaNetworkError> {
        Ok(self.observed_spends_lock()?.len())
    }

    /// Submit a typed upstream RPC transaction. This is the production path for
    /// callers that already build `kaspa_consensus_core::tx::Transaction` and
    /// convert it to `RpcTransaction`.
    pub fn submit_rpc_transaction(
        &self,
        transaction: &RpcTransaction,
        allow_orphan: bool,
    ) -> Result<KaspaTxId, KaspaNetworkError> {
        let txid = self.run_rpc(
            self.client
                .submit_transaction(transaction.clone(), allow_orphan),
        )?;
        Ok(txid.as_bytes())
    }

    /// Ingest the inputs of a confirmed RPC transaction as observed spends.
    ///
    /// This is the boundary a production listener/indexer would call after it
    /// observes that `transaction` was accepted at `block_daa_score`.
    pub fn observe_rpc_transaction_spends(
        &self,
        txid: KaspaTxId,
        transaction: &RpcTransaction,
        block_daa_score: Option<u64>,
    ) -> Result<usize, KaspaNetworkError> {
        let spends = observed_spends_from_rpc_transaction(txid, transaction, block_daa_score)?;
        let observed = spends.len();
        let mut cache = self.observed_spends_lock()?;
        for spend in spends {
            cache.insert(spend.spent, spend.info);
        }
        Ok(observed)
    }

    /// Ingest every transaction input in a fully-fetched RPC block.
    ///
    /// Callers should pass blocks fetched with `include_transactions = true`
    /// so each transaction carries either verbose transaction id data or a
    /// matching id in the block-level verbose transaction id vector.
    pub fn observe_rpc_block_spends(&self, block: &RpcBlock) -> Result<usize, KaspaNetworkError> {
        Ok(self.observe_rpc_block_spend_records(block)?.len())
    }

    /// Ingest every transaction input in a fully-fetched RPC block and return
    /// the typed spend records that were stored in the observed-spend cache.
    pub fn observe_rpc_block_spend_records(
        &self,
        block: &RpcBlock,
    ) -> Result<Vec<ObservedSpend>, KaspaNetworkError> {
        let mut observed = Vec::new();
        let accepting_daa_score = rpc_block_accepting_daa_score(block)?;
        let mut cache = self.observed_spends_lock()?;
        for (transaction_index, transaction) in block.transactions.iter().enumerate() {
            let txid = rpc_transaction_id_from_block(block, transaction, transaction_index)?;
            let spends =
                observed_spends_from_rpc_transaction(txid, transaction, Some(accepting_daa_score))?;
            observed.reserve(spends.len());
            for spend in spends {
                cache.insert(spend.spent, spend.info.clone());
                observed.push(spend);
            }
        }
        Ok(observed)
    }

    /// Poll the virtual selected-parent chain from `start_hash`, fetch each
    /// added chain block from the live node, and ingest its transaction inputs.
    ///
    /// This is the synchronous building block for a production listener or
    /// indexer loop: callers keep a cursor block hash, call this method, then
    /// advance the cursor to the last added chain block once they have
    /// persisted the observed facts.
    pub fn scan_virtual_chain_from_block(
        &self,
        start_hash: KaspaBlockHash,
        min_confirmation_count: Option<u64>,
    ) -> Result<WrpcVirtualChainScan, KaspaNetworkError> {
        let response = self.run_rpc(self.client.get_virtual_chain_from_block(
            RpcHash::from_bytes(start_hash),
            false,
            min_confirmation_count,
        ))?;

        let mut observed_spend_records = Vec::new();
        let mut last_added_daa_score = None;
        for block_hash in &response.added_chain_block_hashes {
            let block = self.run_rpc(self.client.get_block(*block_hash, true))?;
            last_added_daa_score = Some(rpc_block_accepting_daa_score(&block)?);
            observed_spend_records.extend(self.observe_rpc_block_spend_records(&block)?);
        }

        Ok(WrpcVirtualChainScan {
            removed_chain_block_hashes: response
                .removed_chain_block_hashes
                .iter()
                .map(|hash| hash.as_bytes())
                .collect(),
            added_chain_block_hashes: response
                .added_chain_block_hashes
                .iter()
                .map(|hash| hash.as_bytes())
                .collect(),
            last_added_daa_score,
            observed_spends: observed_spend_records.len(),
            observed_spend_records,
        })
    }

    fn run_rpc<F, T, E>(&self, future: F) -> Result<T, KaspaNetworkError>
    where
        F: Future<Output = Result<T, E>>,
        E: Display,
    {
        self.block_on(future)?.map_err(rpc_error)
    }

    fn block_on<F, T>(&self, future: F) -> Result<T, KaspaNetworkError>
    where
        F: Future<Output = T>,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => Ok(tokio::task::block_in_place(|| handle.block_on(future))),
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| KaspaNetworkError::Invariant(format!("tokio runtime: {e}")))?;
                Ok(rt.block_on(future))
            }
        }
    }

    fn observed_by_txid(
        &self,
        txid: KaspaTxId,
    ) -> Result<Option<(KaspaOutpoint, SpendingInfo)>, KaspaNetworkError> {
        Ok(self
            .observed_spends_lock()?
            .iter()
            .find(|(_, info)| info.txid == txid)
            .map(|(outpoint, info)| (*outpoint, info.clone())))
    }
}

impl KaspaChainBackend for WrpcBackend {
    fn network_id(&self) -> Result<KaspaChainId, KaspaNetworkError> {
        let _ = self.run_rpc(self.client.get_server_info())?;
        Ok(self.network)
    }

    fn current_tip(&self) -> Result<KaspaTip, KaspaNetworkError> {
        let dag = self.run_rpc(self.client.get_block_dag_info())?;
        Ok(KaspaTip {
            hash: dag.sink.as_bytes(),
            blue_score: dag.block_count,
            daa_score: dag.virtual_daa_score,
        })
    }

    fn get_transaction(
        &self,
        txid: KaspaTxId,
    ) -> Result<Option<KaspaTxSummary>, KaspaNetworkError> {
        if self.observed_by_txid(txid)?.is_some() {
            return Ok(Some(KaspaTxSummary {
                txid,
                mass: 0,
                payload: vec![],
            }));
        }
        Ok(None)
    }

    fn get_utxo(&self, outpoint: KaspaOutpoint) -> Result<Option<KaspaUtxo>, KaspaNetworkError> {
        let utxo = if let Some(spending) = self.observed_spend(outpoint)? {
            Some(KaspaUtxo::new(outpoint, 0, vec![], None, Some(spending))?)
        } else {
            None
        };
        Ok(utxo)
    }

    fn get_spending_transaction(
        &self,
        outpoint: KaspaOutpoint,
    ) -> Result<Option<KaspaTxSummary>, KaspaNetworkError> {
        Ok(self
            .observed_spend(outpoint)?
            .map(|spending| KaspaTxSummary {
                txid: spending.txid,
                mass: 0,
                payload: vec![],
            }))
    }

    fn submit_transaction(&self, _tx_bytes: &[u8]) -> Result<KaspaTxId, KaspaNetworkError> {
        Err(KaspaNetworkError::UnsupportedToccataFeature(
            "WrpcBackend::submit_transaction requires a typed RpcTransaction; use submit_rpc_transaction".into(),
        ))
    }

    fn confirmation_depth(&self, txid: KaspaTxId) -> Result<Option<u64>, KaspaNetworkError> {
        let Some((_outpoint, spending)) = self.observed_by_txid(txid)? else {
            return Ok(None);
        };
        let Some(accepted_daa) = spending.block_daa_score else {
            return Ok(None);
        };
        let tip = self.current_tip()?;
        if tip.daa_score < accepted_daa {
            return Ok(None);
        }
        Ok(Some(tip.daa_score - accepted_daa + 1))
    }
}

fn rpc_error(e: impl Display) -> KaspaNetworkError {
    KaspaNetworkError::NodeUnavailable(e.to_string())
}

fn observed_spends_from_rpc_transaction(
    txid: KaspaTxId,
    transaction: &RpcTransaction,
    block_daa_score: Option<u64>,
) -> Result<Vec<ObservedSpend>, KaspaNetworkError> {
    let mut spends = Vec::with_capacity(transaction.inputs.len());
    for (input_index, input) in transaction.inputs.iter().enumerate() {
        let input_index = u32::try_from(input_index).map_err(|_| {
            KaspaNetworkError::Invariant("rpc transaction has more than u32::MAX inputs".into())
        })?;
        let spent = KaspaOutpoint {
            transaction_id: input.previous_outpoint.transaction_id.as_bytes(),
            index: input.previous_outpoint.index,
        };
        if spent == KaspaOutpoint::NULL {
            continue;
        }
        spends.push(ObservedSpend {
            spent,
            info: SpendingInfo {
                txid,
                input_index,
                block_daa_score,
            },
        });
    }
    Ok(spends)
}

fn rpc_transaction_id_from_block(
    block: &RpcBlock,
    transaction: &RpcTransaction,
    transaction_index: usize,
) -> Result<KaspaTxId, KaspaNetworkError> {
    if let Some(verbose_data) = &transaction.verbose_data {
        return Ok(verbose_data.transaction_id.as_bytes());
    }
    if let Some(txid) = block
        .verbose_data
        .as_ref()
        .and_then(|verbose| verbose.transaction_ids.get(transaction_index))
    {
        return Ok(txid.as_bytes());
    }
    Err(KaspaNetworkError::Invariant(
        "rpc block transaction is missing transaction id data".into(),
    ))
}

fn rpc_block_accepting_daa_score(block: &RpcBlock) -> Result<u64, KaspaNetworkError> {
    block.header.daa_score.checked_add(1).ok_or_else(|| {
        KaspaNetworkError::Invariant("rpc block DAA score overflowed accepting DAA score".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrpc_network_maps_rgk_local_toccata_to_simnet_transport() {
        assert_eq!(
            WrpcNetwork::LocalToccata.chain_id(),
            KaspaChainId::KaspaLocalToccata
        );
        assert_eq!(
            WrpcNetwork::LocalToccata.network_type(),
            NetworkType::Simnet
        );
    }

    #[test]
    fn wrpc_network_preserves_public_network_domains() {
        assert_eq!(WrpcNetwork::Mainnet.chain_id(), KaspaChainId::KaspaMainnet);
        assert_eq!(WrpcNetwork::Testnet.chain_id(), KaspaChainId::KaspaTestnet);
        assert_eq!(WrpcNetwork::Devnet.chain_id(), KaspaChainId::KaspaDevnet);
        assert_eq!(WrpcNetwork::Simnet.chain_id(), KaspaChainId::KaspaSimnet);
    }
}
