#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-kaspa
//!
//! Kaspa chain backend: trait, types, errors, and adapters.
//!
//! The single seam between the RGK resolver/indexer and any Kaspa network
//! access. Implementations include:
//!
//! * [`FixtureBackend`] — deterministic in-memory backend for unit and
//!   integration tests. No I/O. Always available.
//! * [`HttpBackend`] — small JSON-RPC health/read probe for a live `kaspad`
//!   daemon (requires the `http` feature, which pulls in `ureq` +
//!   `serde_json`). It does not implement [`KaspaChainBackend`].
//! * [`WrpcBackend`] — opt-in wRPC adapter for live Toccata nodes. It owns a
//!   real `KaspaRpcClient` and an observed-spend cache fed by the indexer or
//!   harness; arbitrary spend discovery remains an indexer/listener concern.
//!
//! The trait surface mirrors the operations the resolver and indexer need:
//! fetching tips, transactions, UTXOs, submitting transactions, and querying
//! confirmation depth. Every method distinguishes the typed states the resolver
//! cares about (not-found vs unconfirmed vs confirmed vs spent vs node-down)
//! so the resolver never has to interpret `Option`-or-error itself.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code, unused_imports, unused_variables)]
#![allow(clippy::needless_borrows_for_generic_args, clippy::vec_init_then_push)]
#![allow(
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::derivable_impls
)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rgk_core::{Bytes32, KaspaChainId, KaspaOutpoint};
use thiserror::Error;

/// The RGK 32-byte transaction id (matches `kaspa_hashes::Hash`).
pub type KaspaTxId = Bytes32;

/// The block hash type. Same width as a txid but a different domain.
pub type KaspaBlockHash = Bytes32;

/// Network-wide tip pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KaspaTip {
    pub hash: KaspaBlockHash,
    pub blue_score: u64,
    pub daa_score: u64,
}

/// A summary of a Kaspa transaction. The full transaction body is **not** held
/// here; callers fetch specific outputs via [`KaspaChainBackend::get_utxo`].
///
/// `mass` is the total mass of the transaction (Kaspa consensus metric).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KaspaTxSummary {
    pub txid: KaspaTxId,
    pub mass: u64,
    pub payload: Vec<u8>,
}

/// A UTXO as known to the local node. Includes the spending transaction if the
/// UTXO is already spent — the resolver uses this to detect spends and the
/// corresponding receipt-bearing transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KaspaUtxo {
    pub outpoint: KaspaOutpoint,
    pub value: u64,
    /// Script public key bytes (Kaspa P2SH wrapper + redeem script).
    pub script_public_key: Vec<u8>,
    /// Block DAA score at which this UTXO was confirmed. `None` for mempool.
    pub block_daa_score: Option<u64>,
    /// If the UTXO is spent, the spending txid and input index.
    pub spending: Option<SpendingInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendingInfo {
    pub txid: KaspaTxId,
    pub input_index: u32,
    pub block_daa_score: Option<u64>,
}

/// Typed errors. Every variant maps to a specific resolver classification
/// (see [`crate::ResolverClassify`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KaspaNetworkError {
    #[error("kaspa node unreachable: {0}")]
    NodeUnavailable(String),
    #[error("node is on chain {node:?} but the resolver is configured for {configured:?}")]
    WrongNetwork {
        node: KaspaChainId,
        configured: KaspaChainId,
    },
    #[error("feature not supported by this node build: {0}")]
    UnsupportedToccataFeature(String),
    #[error("malformed JSON-RPC response: {0}")]
    BadRpc(String),
    #[error("RPC method returned an error: code={code} {message}")]
    RpcError { code: i64, message: String },
    #[error("RPC timeout after {0} ms")]
    Timeout(u64),
    #[error("utxo/outpoint not found")]
    NotFound,
    #[error("transaction is unconfirmed (mempool only)")]
    Unconfirmed,
    #[error("transaction is confirmed at depth {0}")]
    Confirmed(u64),
    #[error("transaction has been pruned (reorg or archival boundary)")]
    Pruned,
    #[error("reorg detected at depth {0}: tip moved under the spend")]
    ReorgRisk(u64),
    #[error("resolver budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("internal invariant violated: {0}")]
    Invariant(String),
}

impl KaspaNetworkError {
    /// Coarse classification used by the resolver to choose a recovery path.
    pub fn classify(&self) -> ResolverClassify {
        match self {
            KaspaNetworkError::NodeUnavailable(_) => ResolverClassify::NodeDown,
            KaspaNetworkError::WrongNetwork { .. } => ResolverClassify::WrongNetwork,
            KaspaNetworkError::UnsupportedToccataFeature(_) => ResolverClassify::UnsupportedFeature,
            KaspaNetworkError::BadRpc(_)
            | KaspaNetworkError::RpcError { .. }
            | KaspaNetworkError::Timeout(_) => ResolverClassify::RpcFailure,
            KaspaNetworkError::NotFound => ResolverClassify::NotFound,
            KaspaNetworkError::Unconfirmed => ResolverClassify::Unconfirmed,
            KaspaNetworkError::Confirmed(_) => ResolverClassify::Confirmed,
            KaspaNetworkError::Pruned => ResolverClassify::Pruned,
            KaspaNetworkError::ReorgRisk(_) => ResolverClassify::ReorgRisk,
            KaspaNetworkError::BudgetExceeded(_) => ResolverClassify::BudgetExceeded,
            KaspaNetworkError::Invariant(_) => ResolverClassify::Invariant,
        }
    }
}

/// Coarse classification of [`KaspaNetworkError`]. Used by the resolver to
/// decide whether to retry, wait, or fail-closed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResolverClassify {
    NotFound,
    Unconfirmed,
    Confirmed,
    Pruned,
    ReorgRisk,
    NodeDown,
    WrongNetwork,
    UnsupportedFeature,
    RpcFailure,
    BudgetExceeded,
    Invariant,
}

/// The RGK Kaspa chain backend trait. Every operation the resolver/indexer
/// needs lives here. All methods take `&self` — implementations are expected
/// to be cheaply cloneable (they almost always wrap an `Arc`).
pub trait KaspaChainBackend: Send + Sync {
    /// Returns the chain id the backend is currently bound to. Implementations
    /// must refuse to operate on a chain they don't recognise.
    fn network_id(&self) -> Result<KaspaChainId, KaspaNetworkError>;

    /// Returns the current tip, including the DAA score. The DAA score is the
    /// monotonic clock the resolver uses to order events.
    fn current_tip(&self) -> Result<KaspaTip, KaspaNetworkError>;

    /// Fetches a transaction by id, if known. Returns:
    /// * `Ok(Some(_))` — known to the node (mempool or confirmed)
    /// * `Ok(None)` — not known (e.g. pruned beyond archival depth)
    /// * `Err(_)` — node-level failure
    fn get_transaction(&self, txid: KaspaTxId)
        -> Result<Option<KaspaTxSummary>, KaspaNetworkError>;

    /// Fetches a UTXO by outpoint. Returns:
    /// * `Ok(Some(utxo))` — UTXO exists (unspent or spent with `spending`)
    /// * `Ok(None)` — never seen
    /// * `Err(_)` — node-level failure
    fn get_utxo(&self, outpoint: KaspaOutpoint) -> Result<Option<KaspaUtxo>, KaspaNetworkError>;

    /// If the outpoint has been spent, returns the spending transaction.
    /// Returns `Ok(None)` if the UTXO is unspent. Returns `Err` only on node
    /// failure; "not spent yet" is a normal `Ok(None)`.
    fn get_spending_transaction(
        &self,
        outpoint: KaspaOutpoint,
    ) -> Result<Option<KaspaTxSummary>, KaspaNetworkError>;

    /// Submit a serialized transaction. Returns the new txid on success.
    /// Errors map to `NodeUnavailable`, `RpcError`, `BudgetExceeded`, etc.
    fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<KaspaTxId, KaspaNetworkError>;

    /// Returns the confirmation depth in blocks. `Ok(None)` means unconfirmed;
    /// `Err(_)` is a node-level failure.
    fn confirmation_depth(&self, txid: KaspaTxId) -> Result<Option<u64>, KaspaNetworkError>;
}

// ---------------- Fixture backend ----------------

/// A deterministic, in-memory `KaspaChainBackend`. Used by tests and by the
/// fixture-only e2e mode (`./scripts/e2e-local.sh --fixture`).
///
/// The fixture is keyed by `u64` block height. Each block is a flat map of
/// UTXOs that exist after that block; spends are tracked separately and
/// reduce the available UTXO set.
#[derive(Clone, Debug)]
pub struct FixtureBackend {
    chain: KaspaChainId,
    tip: KaspaTip,
    /// Per-block UTXO sets (height -> (outpoint -> utxo))
    blocks: BTreeMap<u64, BTreeMap<KaspaOutpoint, KaspaUtxo>>,
    /// Spends that occurred at a given height
    spends: BTreeMap<KaspaOutpoint, (u64, KaspaTxId, u32)>,
    /// Submitted transactions (for get_transaction)
    txs: BTreeMap<KaspaTxId, KaspaTxSummary>,
    /// Failure mode: if set, all calls return this error. Used by tests to
    /// exercise the NodeUnavailable / WrongNetwork paths.
    failure: Option<KaspaNetworkError>,
}

impl Default for FixtureBackend {
    fn default() -> Self {
        Self::new(KaspaChainId::KaspaLocalToccata)
    }
}

impl FixtureBackend {
    pub fn new(chain: KaspaChainId) -> Self {
        Self {
            chain,
            tip: KaspaTip {
                hash: [0u8; 32],
                blue_score: 0,
                daa_score: 0,
            },
            blocks: BTreeMap::new(),
            spends: BTreeMap::new(),
            txs: BTreeMap::new(),
            failure: None,
        }
    }

    pub fn with_failure(mut self, e: KaspaNetworkError) -> Self {
        self.failure = Some(e);
        self
    }

    /// Add a UTXO at the given block height. If the UTXO already exists in a
    /// later block, it is overwritten (used to simulate reorgs in tests).
    pub fn add_utxo_at(&mut self, height: u64, utxo: KaspaUtxo) {
        self.blocks
            .entry(height)
            .or_default()
            .insert(utxo.outpoint, utxo);
    }

    /// Mark an outpoint as spent at the given height by `txid:input_index`.
    /// The UTXO entry is annotated with the spending info but kept in the
    /// block set so historical queries can find it.
    pub fn spend_at(
        &mut self,
        outpoint: KaspaOutpoint,
        height: u64,
        txid: KaspaTxId,
        input_index: u32,
    ) {
        self.spends.insert(outpoint, (height, txid, input_index));
        // Annotate any existing UTXO entry with the spend.
        for (_, block) in self.blocks.iter_mut() {
            if let Some(u) = block.get_mut(&outpoint) {
                u.spending = Some(SpendingInfo {
                    txid,
                    input_index,
                    block_daa_score: Some(height),
                });
            }
        }
    }

    /// Submit a transaction (for the fixture). Records the txid + mass + payload.
    pub fn submit(&mut self, summary: KaspaTxSummary) -> KaspaTxId {
        let id = summary.txid;
        self.txs.insert(id, summary);
        id
    }

    pub fn set_tip(&mut self, tip: KaspaTip) {
        self.tip = tip;
    }

    fn check_failure(&self) -> Result<(), KaspaNetworkError> {
        if let Some(e) = &self.failure {
            Err(e.clone())
        } else {
            Ok(())
        }
    }

    fn locate_utxo(&self, outpoint: &KaspaOutpoint) -> Option<KaspaUtxo> {
        // Iterate from latest block to earliest, returning the most recent
        // version of the UTXO.
        for (_h, block) in self.blocks.iter().rev() {
            if let Some(u) = block.get(outpoint) {
                return Some(u.clone());
            }
        }
        None
    }
}

impl KaspaChainBackend for FixtureBackend {
    fn network_id(&self) -> Result<KaspaChainId, KaspaNetworkError> {
        self.check_failure()?;
        Ok(self.chain)
    }

    fn current_tip(&self) -> Result<KaspaTip, KaspaNetworkError> {
        self.check_failure()?;
        Ok(self.tip.clone())
    }

    fn get_transaction(
        &self,
        txid: KaspaTxId,
    ) -> Result<Option<KaspaTxSummary>, KaspaNetworkError> {
        self.check_failure()?;
        Ok(self.txs.get(&txid).cloned())
    }

    fn get_utxo(&self, outpoint: KaspaOutpoint) -> Result<Option<KaspaUtxo>, KaspaNetworkError> {
        self.check_failure()?;
        Ok(self.locate_utxo(&outpoint))
    }

    fn get_spending_transaction(
        &self,
        outpoint: KaspaOutpoint,
    ) -> Result<Option<KaspaTxSummary>, KaspaNetworkError> {
        self.check_failure()?;
        if let Some((_h, txid, _input_index)) = self.spends.get(&outpoint) {
            return Ok(self.txs.get(txid).cloned());
        }
        Ok(None)
    }

    fn submit_transaction(&self, _tx_bytes: &[u8]) -> Result<KaspaTxId, KaspaNetworkError> {
        Err(KaspaNetworkError::Invariant(
            "FixtureBackend::submit_transaction is read-only by default; use FixtureBackend::submit".into(),
        ))
    }

    fn confirmation_depth(&self, txid: KaspaTxId) -> Result<Option<u64>, KaspaNetworkError> {
        self.check_failure()?;
        Ok(self.txs.get(&txid).and_then(|t| {
            if t.mass > 0 {
                // Fixture rule: submitted transactions with non-zero mass are
                // treated as one confirmation deep.
                Some(1)
            } else {
                None
            }
        }))
    }
}

// ---------------- HTTP backend (requires `http` feature) ----------------

#[cfg(feature = "http")]
mod http {
    use super::*;

    /// JSON-RPC health/read probe for a live `kaspad` daemon. Uses `ureq` for
    /// sync HTTP. The URL points at the daemon's JSON-RPC endpoint, e.g.
    /// `http://127.0.0.1:16110`.
    ///
    /// This type intentionally does not implement [`KaspaChainBackend`]: JSON
    /// RPC does not provide the typed Toccata transaction submission and
    /// virtual-chain spend scan surface RGK needs in production. Use
    /// `WrpcBackend` for resolver/indexer execution.
    pub struct HttpBackend {
        url: String,
        network: KaspaChainId,
        timeout_ms: u64,
    }

    impl HttpBackend {
        pub fn new(url: impl Into<String>, network: KaspaChainId) -> Self {
            Self {
                url: url.into(),
                network,
                timeout_ms: 5_000,
            }
        }

        pub fn with_timeout(mut self, ms: u64) -> Self {
            self.timeout_ms = ms;
            self
        }

        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, KaspaNetworkError> {
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": "rgk",
                "method": method,
                "params": params,
            });
            let agent = ureq::AgentBuilder::new()
                .timeout_read(std::time::Duration::from_millis(self.timeout_ms))
                .timeout_write(std::time::Duration::from_millis(self.timeout_ms))
                .build();
            let resp = agent
                .post(&self.url)
                .set("Content-Type", "application/json")
                .send_string(&body.to_string())
                .map_err(|e| KaspaNetworkError::NodeUnavailable(format!("{e}")))?;
            let v: serde_json::Value = resp
                .into_json()
                .map_err(|e| KaspaNetworkError::BadRpc(format!("{e}")))?;
            if let Some(err) = v.get("error") {
                let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                let message = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                return Err(KaspaNetworkError::RpcError { code, message });
            }
            v.get("result")
                .cloned()
                .ok_or_else(|| KaspaNetworkError::BadRpc("missing result".into()))
        }

        pub fn network_id(&self) -> Result<KaspaChainId, KaspaNetworkError> {
            // The local node reports its network via `getInfo`. We do a
            // minimal call; on `simnet` the network is `0xdeadbeef`-style.
            // For simplicity we trust the configured value and assert
            // Toccata is supported by querying `getDaaScore` (always works).
            let r = self.call("getDaaScore", serde_json::json!([]))?;
            if r.get("daaScore").is_none() {
                return Err(KaspaNetworkError::BadRpc("daaScore missing".into()));
            }
            Ok(self.network)
        }

        pub fn current_tip(&self) -> Result<KaspaTip, KaspaNetworkError> {
            let r = self.call("getTipInfo", serde_json::json!([]))?;
            let hash_hex = r
                .get("virtualSelectedParentHash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    KaspaNetworkError::BadRpc("missing virtualSelectedParentHash".into())
                })?;
            let hash = hex_decode_32(hash_hex)?;
            let blue_score = r.get("blueScore").and_then(|v| v.as_u64()).unwrap_or(0);
            let daa_score = r.get("daaScore").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(KaspaTip {
                hash,
                blue_score,
                daa_score,
            })
        }

        pub fn get_transaction(
            &self,
            txid: KaspaTxId,
        ) -> Result<Option<KaspaTxSummary>, KaspaNetworkError> {
            let hex = hex_encode_32(&txid);
            let r = self.call("getTransaction", serde_json::json!([hex, false]));
            match r {
                Ok(v) => {
                    let mass = v.get("mass").and_then(|m| m.as_u64()).unwrap_or(0);
                    let payload_hex = v.get("payload").and_then(|p| p.as_str()).unwrap_or("");
                    let payload = hex::decode(payload_hex).unwrap_or_default();
                    let txid_hex = v
                        .get("transactionId")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let txid = hex_decode_32(txid_hex).unwrap_or(txid);
                    Ok(Some(KaspaTxSummary {
                        txid,
                        mass,
                        payload,
                    }))
                }
                Err(KaspaNetworkError::RpcError { code: -32602, .. })
                | Err(KaspaNetworkError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    fn hex_encode_32(b: &Bytes32) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for byte in b.iter() {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }

    fn hex_decode_32(s: &str) -> Result<Bytes32, KaspaNetworkError> {
        if s.len() != 64 {
            return Err(KaspaNetworkError::BadRpc(format!(
                "expected 64 hex chars, got {}",
                s.len()
            )));
        }
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for i in 0..32 {
            let hi = hex_val(bytes[2 * i])?;
            let lo = hex_val(bytes[2 * i + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn hex_val(c: u8) -> Result<u8, KaspaNetworkError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(KaspaNetworkError::BadRpc(format!(
                "bad hex char {:?}",
                c as char
            ))),
        }
    }
}

#[cfg(feature = "http")]
pub use http::HttpBackend;

#[cfg(feature = "wrpc")]
mod wrpc;
#[cfg(feature = "wrpc")]
pub use wrpc::{WrpcBackend, WrpcNetwork, WrpcVirtualChainScan};

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_basics() {
        let mut b = FixtureBackend::new(KaspaChainId::KaspaLocalToccata);
        assert_eq!(b.network_id().unwrap(), KaspaChainId::KaspaLocalToccata);
        let tip = KaspaTip {
            hash: [1u8; 32],
            blue_score: 100,
            daa_score: 200,
        };
        b.set_tip(tip.clone());
        assert_eq!(b.current_tip().unwrap(), tip);
    }

    #[test]
    fn fixture_utxo_lookup() {
        let mut b = FixtureBackend::new(KaspaChainId::KaspaLocalToccata);
        let outpoint = KaspaOutpoint {
            transaction_id: [2u8; 32],
            index: 0,
        };
        b.add_utxo_at(
            1,
            KaspaUtxo {
                outpoint,
                value: 1_000,
                script_public_key: vec![0x76, 0xa9],
                block_daa_score: Some(1),
                spending: None,
            },
        );
        let got = b.get_utxo(outpoint).unwrap().unwrap();
        assert_eq!(got.value, 1_000);
    }

    #[test]
    fn fixture_spend_marks_utxo() {
        let mut b = FixtureBackend::new(KaspaChainId::KaspaLocalToccata);
        let outpoint = KaspaOutpoint {
            transaction_id: [3u8; 32],
            index: 0,
        };
        b.add_utxo_at(
            1,
            KaspaUtxo {
                outpoint,
                value: 1_000,
                script_public_key: vec![],
                block_daa_score: Some(1),
                spending: None,
            },
        );
        let spend_txid = [4u8; 32];
        // The spending tx must exist in the fixture for get_spending_transaction
        // to find it.
        b.submit(KaspaTxSummary {
            txid: spend_txid,
            mass: 1,
            payload: vec![],
        });
        b.spend_at(outpoint, 2, spend_txid, 0);
        let u = b.get_utxo(outpoint).unwrap().unwrap();
        assert_eq!(u.spending.as_ref().unwrap().txid, spend_txid);
        let stx = b.get_spending_transaction(outpoint).unwrap();
        assert_eq!(stx.unwrap().txid, spend_txid);
    }

    #[test]
    fn fixture_failure_mode_propagates() {
        let b = FixtureBackend::new(KaspaChainId::KaspaLocalToccata)
            .with_failure(KaspaNetworkError::NodeUnavailable("test".into()));
        assert!(matches!(
            b.network_id(),
            Err(KaspaNetworkError::NodeUnavailable(_))
        ));
    }

    #[test]
    fn error_classify_distinguishes_paths() {
        assert_eq!(
            KaspaNetworkError::NotFound.classify(),
            ResolverClassify::NotFound
        );
        assert_eq!(
            KaspaNetworkError::Unconfirmed.classify(),
            ResolverClassify::Unconfirmed
        );
        assert_eq!(
            KaspaNetworkError::ReorgRisk(3).classify(),
            ResolverClassify::ReorgRisk
        );
        assert_eq!(
            KaspaNetworkError::WrongNetwork {
                node: KaspaChainId::KaspaMainnet,
                configured: KaspaChainId::KaspaLocalToccata
            }
            .classify(),
            ResolverClassify::WrongNetwork
        );
    }

    #[test]
    fn submit_transaction_in_fixture_is_invariant() {
        let b = FixtureBackend::new(KaspaChainId::KaspaLocalToccata);
        assert!(matches!(
            b.submit_transaction(&[]),
            Err(KaspaNetworkError::Invariant(_))
        ));
    }
}
