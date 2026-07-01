//! Live Toccata covenant lifecycle test against a running kaspad simnet,
//! local Toccata-active devnet, or an explicitly configured public testnet
//! staging endpoint.
//!
//! ## What this test proves
//!
//! End-to-end pipeline against a real `kaspad` daemon built from the local
//! `rusty-kaspa` `toccata` checkout:
//!
//! 1. **Fund a keypair we control**. Local simnet/devnet runs mine real
//!    coinbase blocks via `get_block_template` + `submit_block` over wRPC;
//!    public testnet staging must pre-fund the deterministic printed address
//!    and waits for real network confirmations.
//! 2. **Build a covenant-bearing v1 transaction** that spends the funding
//!    UTXO and creates a P2SH output whose redeem script is
//!    `CovenantSpec::build_script` or, with `real-zk`, a ZK-prefixed variant
//!    containing VK + Groth16 tag + `OpZkPrecompile` + `OpDrop`.
//!    `covenant_id` is computed via the upstream
//!    `kaspa_consensus_core::hashing::covenant_id::covenant_id(...)` function.
//! 3. **Sign the covenant transaction** using the upstream
//!    `kaspa_consensus_core::sign::sign_with_multiple_v2(...)` (Schnorr over
//!    secp256k1) so the TxScriptEngine accepts the signature.
//! 4. **Submit the signed covenant transaction** to the live node over
//!    wRPC and wait for the funded covenant output. Local runs mine the
//!    confirmation block; public staging waits for the network.
//! 5. **Spend that P2SH covenant output** with a signature script that pushes
//!    the RGK redeem script. With `real-zk`, the signature script also pushes
//!    public inputs, count, and proof for the Groth16 precompile. The node's
//!    Toccata-active validator runs:
//!    - `CovenantsContext::from_tx` (validates the covenant binding);
//!    - `check_scripts` (runs the RGK script VM with `covenants_enabled`).
//! 6. **Wait for a confirmation** that includes the covenant-script spend.
//!    Local runs mine it; public staging waits for the network.
//! 7. **Index the confirmed spend facts** through `rgk-kaspa::WrpcBackend`.
//!    Local runs scan the virtual chain from the pre-confirmation cursor.
//!    Public staging records the already-submitted, already-confirmed covenant
//!    and continuation transactions directly, then persists the advanced cursor;
//!    broad historical spend discovery remains production indexer work.
//! 8. **Run RgkResolver** with that same backend, asserting
//!    `ResolverState::NativeTransitionedValid`.

#![cfg(feature = "live-kaspa-wrpc")]

use std::time::Duration;

use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    hashing::covenant_id::covenant_id as compute_covenant_id,
    mass::ComputeBudget,
    sign::sign_with_multiple_v2,
    subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE},
    tx::{
        CovenantBinding, MutableTransaction, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::model::tx::RpcTransaction;
#[cfg(feature = "real-zk")]
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    pay_to_address_script, pay_to_script_hash_script,
    pay_to_script_hash_signature_script_with_flags, standard::extract_script_pub_key_address,
    EngineFlags,
};
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use kaspa_wrpc_client::{
    client::{ConnectOptions, ConnectStrategy},
    KaspaRpcClient, Resolver, WrpcEncoding,
};
use secp256k1::Keypair;

#[cfg(feature = "real-zk")]
use rgk_asset::{
    allocation_transcript_empty_root, private_lane_graph_empty_root, RgkAllocation,
    RgkAllocationTranscriptSide, RgkCovenantAnchor,
};
use rgk_asset::{RgkAllocationProofShape, RgkScanTag};
#[cfg(feature = "persistent-indexer")]
use rgk_core::PolicyMigrationInput;
#[cfg(feature = "real-zk")]
use rgk_core::{receipt_commitment, RgkReceipt};
use rgk_core::{
    replay_nonce, to_hex, Canonical, KaspaChainId, KaspaCovenantId, KaspaOutpoint, ProofMode,
    ReceiptPolicy, RgkStateCommitment, KASPA_LOCAL_TOCCATA,
};
use rgk_covenant::{compute_lineage_id, CovenantSpec, CovenantState};
#[cfg(not(feature = "persistent-indexer"))]
use rgk_indexer::InMemoryIndexer;
#[cfg(feature = "real-zk")]
use rgk_indexer::{AllocationAuditCertificateRecord, AllocationAuditCertificateStore};
use rgk_indexer::{ContinuationProof, IndexedLane, Indexer, ScanCursor};
#[cfg(feature = "persistent-indexer")]
use rgk_indexer::{ScanCursorStore, SledIndexer, DEFAULT_SCAN_CURSOR};
use rgk_kaspa::{SpendingInfo, WrpcBackend};
use rgk_receipt::{ReceiptBuilder, ReceiptInput, ReceiptVerifier};
use rgk_resolver::{LaneResolverState, ResolverState, RgkResolver};
#[cfg(feature = "persistent-indexer")]
use rgk_sync::{ScanService, ScanServiceConfig};
use rgk_tx::toccata_user_lane_subnetwork;
#[cfg(feature = "real-zk")]
use rgk_zk::real_zk::{
    self, Groth16PrecompileStack, Groth16Setup, ReceiptCircuit, SemanticTransitionCircuit,
    SupportedAllocationVectorCircuit, SupportedAllocationVectorWitness,
};
use rgk_zk::SemanticTransitionStatement;
use sha2::{Digest, Sha256};

// ============================================================
// Helpers
// ============================================================

const VERIFIER_COVENANT_COMPUTE_BUDGET: u16 = 300;
const ZK_COVENANT_COMPUTE_BUDGET: u16 = 2_500;
const PUBLIC_CONFIRMATION_TIMEOUT_SECS: u64 = 300;

type RpcAddressUtxoEntry = kaspa_rpc_core::model::address::RpcUtxosByAddressesEntry;

#[derive(Clone, Copy, Debug)]
struct LiveNetworkConfig {
    name: &'static str,
    network_id: NetworkId,
    chain_id: KaspaChainId,
    address_prefix: Prefix,
    default_url: Option<&'static str>,
    local_mining: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LiveToccataTxConfig {
    subnetwork_id: SubnetworkId,
    gas: u64,
}

#[derive(Clone, Debug)]
struct LiveResumeEvidence {
    network: String,
    funding_txid: Hash,
    funding_index: u32,
    funding_daa: u64,
    funding_value: u64,
    covenant_txid: Hash,
    covenant_id: Hash,
    covenant_daa: u64,
    continuation_txid: Hash,
    continuation_daa: u64,
}

impl LiveToccataTxConfig {
    fn native() -> Self {
        Self {
            subnetwork_id: SUBNETWORK_ID_NATIVE,
            gas: 0,
        }
    }

    fn user_lane(
        namespace: [u8; rgk_tx::SUBNETWORK_NAMESPACE_LEN],
        gas: u64,
    ) -> Result<Self, String> {
        if gas == 0 {
            return Err("RGK_LIVE_KASPA_GAS must be non-zero for a user-lane subnetwork".into());
        }
        let subnetwork_id = toccata_user_lane_subnetwork(namespace)
            .map_err(|err| format!("invalid RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE: {err}"))?;
        Ok(Self {
            subnetwork_id: SubnetworkId::from_bytes(subnetwork_id),
            gas,
        })
    }

    fn from_env() -> Self {
        match std::env::var("RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE") {
            Ok(namespace) => {
                let gas = std::env::var("RGK_LIVE_KASPA_GAS")
                    .unwrap_or_else(|_| {
                        panic!(
                            "RGK_LIVE_KASPA_GAS is required when RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE is set"
                        )
                    })
                    .parse::<u64>()
                    .unwrap_or_else(|err| panic!("invalid RGK_LIVE_KASPA_GAS: {err}"));
                Self::user_lane(parse_user_lane_namespace(&namespace), gas)
                    .unwrap_or_else(|err| panic!("{err}"))
            }
            Err(_) => {
                if let Ok(gas) = std::env::var("RGK_LIVE_KASPA_GAS") {
                    let parsed = gas
                        .parse::<u64>()
                        .unwrap_or_else(|err| panic!("invalid RGK_LIVE_KASPA_GAS: {err}"));
                    if parsed != 0 {
                        panic!("RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE is required for non-zero gas");
                    }
                }
                Self::native()
            }
        }
    }

    fn mode(self) -> &'static str {
        if self.subnetwork_id == SUBNETWORK_ID_NATIVE {
            "native"
        } else {
            "user-lane"
        }
    }
}

impl LiveResumeEvidence {
    fn from_env(config: LiveNetworkConfig) -> Option<Self> {
        let path = std::env::var("RGK_LIVE_KASPA_RESUME_REPORT").ok()?;
        if config.local_mining {
            panic!("RGK_LIVE_KASPA_RESUME_REPORT is only valid for public testnet staging");
        }
        let report = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read RGK_LIVE_KASPA_RESUME_REPORT={path}: {err}"));
        let evidence = Self::parse(&report)
            .unwrap_or_else(|err| panic!("parse RGK_LIVE_KASPA_RESUME_REPORT={path}: {err}"));
        assert_eq!(
            evidence.network, config.name,
            "resume report network must match RGK_LIVE_KASPA_NETWORK"
        );
        eprintln!(
            "live: resuming public staging evidence from {} (network={} covenant_txid=0x{} continuation_txid=0x{})",
            path,
            evidence.network,
            to_hex(&evidence.covenant_txid.as_bytes()),
            to_hex(&evidence.continuation_txid.as_bytes())
        );
        Some(evidence)
    }

    fn parse(report: &str) -> Result<Self, String> {
        let network = find_value(report, "network=")
            .ok_or_else(|| "missing network= line".to_string())?
            .to_string();
        let selected = find_line(report, "live: selected funding UTXO at DAA ")
            .ok_or_else(|| "missing selected funding UTXO line".to_string())?;
        let funding_daa = parse_u64_after(selected, "at DAA ")?;
        let selected_value = parse_u64_after(selected, "value=")?;
        let coinbase = find_value_in_line(selected, "coinbase=")
            .ok_or_else(|| "missing funding coinbase marker".to_string())?;
        if coinbase != "false" {
            return Err("resume funding UTXO must be non-coinbase".into());
        }

        let fetched = find_line(report, "live: fetched funding UTXO txid=")
            .ok_or_else(|| "missing fetched funding UTXO line".to_string())?;
        let funding_txid = parse_hash_array_after(fetched, "txid=")?;
        let funding_index = parse_u64_after(fetched, "index=")? as u32;
        let funding_value = parse_u64_after(fetched, "value=")?;
        if funding_value != selected_value {
            return Err("selected and fetched funding values differ".into());
        }

        let covenant_accept = find_line(report, "live: covenant tx ACCEPTED by node: txid=")
            .ok_or_else(|| "missing accepted covenant tx line".to_string())?;
        let covenant_txid = parse_hash_array_after(covenant_accept, "txid=")?;
        let covenant_confirm = find_line(report, "live: covenant output confirmed at DAA score ")
            .ok_or_else(|| "missing covenant confirmation line".to_string())?;
        let covenant_daa = parse_u64_after(covenant_confirm, "DAA score ")?;
        let covenant_id = parse_hash_array_after(covenant_confirm, "covenant_id=")?;

        let continuation_accept =
            find_line(report, "live: P2SH covenant spend ACCEPTED by node: txid=")
                .ok_or_else(|| "missing accepted covenant spend line".to_string())?;
        let continuation_txid = parse_hash_array_after(continuation_accept, "txid=")?;
        let continuation_confirm = find_line(
            report,
            "live: continuation covenant output confirmed at DAA score ",
        )
        .ok_or_else(|| "missing continuation confirmation line".to_string())?;
        let continuation_daa = parse_u64_after(continuation_confirm, "DAA score ")?;

        Ok(Self {
            network,
            funding_txid,
            funding_index,
            funding_daa,
            funding_value,
            covenant_txid,
            covenant_id,
            covenant_daa,
            continuation_txid,
            continuation_daa,
        })
    }
}

impl LiveNetworkConfig {
    fn from_env() -> Self {
        match std::env::var("RGK_LIVE_KASPA_NETWORK")
            .unwrap_or_else(|_| "local-toccata".to_string())
            .as_str()
        {
            "local-toccata" | "simnet" => Self {
                name: "local-toccata",
                network_id: NetworkId::new(NetworkType::Simnet),
                chain_id: KASPA_LOCAL_TOCCATA,
                address_prefix: Prefix::Simnet,
                default_url: Some("ws://127.0.0.1:18311/v2/kaspa/simnet/no-tls/wrpc/borsh"),
                local_mining: true,
            },
            "devnet" => Self {
                name: "devnet",
                network_id: NetworkId::new(NetworkType::Devnet),
                chain_id: KaspaChainId::KaspaDevnet,
                address_prefix: Prefix::Devnet,
                default_url: Some("ws://127.0.0.1:19111/v2/kaspa/devnet/no-tls/wrpc/borsh"),
                local_mining: true,
            },
            "testnet-10" => Self {
                name: "testnet-10",
                network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
                chain_id: KaspaChainId::KaspaTestnet,
                address_prefix: Prefix::Testnet,
                default_url: None,
                local_mining: false,
            },
            "testnet-12" => Self {
                name: "testnet-12",
                network_id: NetworkId::with_suffix(NetworkType::Testnet, 12),
                chain_id: KaspaChainId::KaspaTestnet,
                address_prefix: Prefix::Testnet,
                default_url: None,
                local_mining: false,
            },
            other => panic!(
                "unsupported RGK_LIVE_KASPA_NETWORK={other}; expected local-toccata, simnet, devnet, testnet-10, or testnet-12"
            ),
        }
    }

    fn url(self) -> String {
        match std::env::var("RGK_LIVE_KASPA_URL") {
            Ok(url) => url,
            Err(_) => self
                .default_url
                .unwrap_or_else(|| {
                    panic!(
                        "RGK_LIVE_KASPA_URL is required for public {} staging",
                        self.name
                    )
                })
                .to_string(),
        }
    }
}

fn parse_user_lane_namespace(raw: &str) -> [u8; rgk_tx::SUBNETWORK_NAMESPACE_LEN] {
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if hex.len() != rgk_tx::SUBNETWORK_NAMESPACE_LEN * 2 {
        panic!("RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE must be 4 bytes encoded as 8 hex characters");
    }
    let mut out = [0u8; rgk_tx::SUBNETWORK_NAMESPACE_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&hex[start..start + 2], 16)
            .unwrap_or_else(|err| panic!("invalid RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE: {err}"));
    }
    out
}

fn find_line<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    text.lines().find(|line| line.contains(needle))
}

fn find_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.strip_prefix(key))
}

fn find_value_in_line<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    Some(line[start..].split_whitespace().next().unwrap_or(""))
}

fn parse_u64_after(line: &str, key: &str) -> Result<u64, String> {
    find_value_in_line(line, key)
        .ok_or_else(|| format!("missing {key} in {line}"))?
        .parse::<u64>()
        .map_err(|err| format!("invalid integer after {key}: {err}"))
}

fn parse_hash_array_after(line: &str, key: &str) -> Result<Hash, String> {
    let key_start = line
        .find(key)
        .ok_or_else(|| format!("missing {key} in {line}"))?
        + key.len();
    let rest = &line[key_start..];
    let open = rest
        .find('[')
        .ok_or_else(|| format!("missing hash array after {key} in {line}"))?;
    let close = rest[open + 1..]
        .find(']')
        .ok_or_else(|| format!("unterminated hash array after {key} in {line}"))?
        + open
        + 1;
    let inner = &rest[open + 1..close];
    let mut bytes = [0u8; 32];
    let mut count = 0usize;
    for (index, part) in inner.split(',').enumerate() {
        if index >= bytes.len() {
            return Err(format!("too many bytes in hash array after {key}"));
        }
        bytes[index] = u8::from_str_radix(part.trim(), 16)
            .map_err(|err| format!("invalid hash byte after {key}: {err}"))?;
        count += 1;
    }
    if count != bytes.len() {
        return Err(format!(
            "hash array after {key} has {count} byte(s), expected {}",
            bytes.len()
        ));
    }
    Ok(Hash::from_bytes(bytes))
}

async fn connect_live_network(config: LiveNetworkConfig) -> KaspaRpcClient {
    let url = Some(config.url());
    let resolver = Some(Resolver::default());
    let network = Some(config.network_id);
    let client = KaspaRpcClient::new(WrpcEncoding::Borsh, url.as_deref(), resolver, network, None)
        .expect("KaspaRpcClient::new");
    let opts = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(5)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client.connect(Some(opts)).await.expect("wRPC connect");
    client
}

fn fresh_keypair(address_prefix: Prefix) -> (Keypair, Address) {
    // Use a FIXED deterministic keypair (NOT a random one) so that
    // repeated runs against a kaspad with the in-memory
    // `BlockTemplateCache` survive: rusty-kaspa's `modify_block_template`
    // only updates the LAST coinbase output (the red reward) when the
    // miner_data changes; the FIRST output keeps the cached pubkey. By
    // using a fixed address, the first and second `get_block_template`
    // calls both pass the same miner_data, so the cache hit returns the
    // same template and the coinbase script_pub_key is stable.
    let (kp, addr) = rgk_e2e::deterministic_live_staging_keypair(address_prefix);
    let xonly = kp.x_only_public_key().0;
    let payload = xonly.serialize();
    eprintln!("live: fixed keypair address = {}", addr);
    eprintln!("live: fixed pubkey x-only = {:02x?}", payload);
    (kp, addr)
}

async fn wait_for_daa_score(client: &KaspaRpcClient, target_daa_score: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let info = client
            .get_block_dag_info()
            .await
            .expect("get_block_dag_info");
        if info.virtual_daa_score >= target_daa_score {
            eprintln!(
                "live: reached DAA score {} (target {})",
                info.virtual_daa_score, target_daa_score
            );
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "timed out waiting for DAA score {} (current {})",
                target_daa_score, info.virtual_daa_score
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn mine_empty_block(client: &KaspaRpcClient, miner_address: &Address) {
    let template = client
        .get_block_template(miner_address.clone(), vec![])
        .await
        .expect("get_block_template");
    let submit = client
        .submit_block(template.block, false)
        .await
        .expect("submit_block");
    eprintln!("live: mined block, report: accepted={:?}", submit.report);
}

/// Mine `n` empty blocks in a tight loop. Used to mature coinbase UTXOs
/// (the local Toccata networks used here enforce a 1000-block coinbase
/// maturity period).
async fn mine_n_blocks(client: &KaspaRpcClient, miner_address: &Address, n: u64) {
    let start = std::time::Instant::now();
    for i in 0..n {
        let template = client
            .get_block_template(miner_address.clone(), vec![])
            .await
            .expect("get_block_template");
        let submit = client
            .submit_block(template.block, false)
            .await
            .expect("submit_block");
        if !matches!(submit.report, kaspa_rpc_core::SubmitBlockReport::Success) {
            panic!("live: block #{} not accepted: {:?}", i + 1, submit.report);
        }
        if (i + 1) % 100 == 0 {
            eprintln!(
                "live: mined {}/{} blocks ({:.1}s)",
                i + 1,
                n,
                start.elapsed().as_secs_f64()
            );
        }
    }
    eprintln!(
        "live: mined {} blocks in {:.1}s",
        n,
        start.elapsed().as_secs_f64()
    );
}

async fn fetch_utxos_for_address(
    client: &KaspaRpcClient,
    address: &Address,
) -> Vec<RpcAddressUtxoEntry> {
    client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .expect("get_utxos_by_addresses")
}

fn select_funding_utxo(
    entries: Vec<RpcAddressUtxoEntry>,
    min_value: u64,
    require_non_coinbase: bool,
    address: &Address,
) -> RpcAddressUtxoEntry {
    entries
        .into_iter()
        .filter(|entry| entry.utxo_entry.amount >= min_value)
        .filter(|entry| !require_non_coinbase || !entry.utxo_entry.is_coinbase)
        .min_by_key(|entry| entry.utxo_entry.block_daa_score)
        .unwrap_or_else(|| {
            panic!(
                "no spendable funding UTXO at {} with value >= {}{}",
                address,
                min_value,
                if require_non_coinbase {
                    " and non-coinbase provenance"
                } else {
                    ""
                }
            )
        })
}

async fn wait_for_address_output_by_txid(
    client: &KaspaRpcClient,
    address: &Address,
    txid: &Hash,
    label: &str,
    timeout: Duration,
) -> RpcAddressUtxoEntry {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(entry) = fetch_utxos_for_address(client, address)
            .await
            .into_iter()
            .find(|entry| entry.outpoint.transaction_id.as_bytes() == txid.as_bytes())
        {
            return entry;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "timed out waiting for {label} output txid={:02x?} at {}",
                txid.as_bytes(),
                address
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn rpc_entry_to_utxo(entry: &RpcAddressUtxoEntry) -> UtxoEntry {
    UtxoEntry {
        amount: entry.utxo_entry.amount,
        script_public_key: entry.utxo_entry.script_public_key.clone(),
        block_daa_score: entry.utxo_entry.block_daa_score,
        is_coinbase: entry.utxo_entry.is_coinbase,
        covenant_id: entry.utxo_entry.covenant_id,
    }
}

fn outpoint_to_bytes(op: &TransactionOutpoint) -> KaspaOutpoint {
    let mut transaction_id = [0u8; 32];
    transaction_id.copy_from_slice(&op.transaction_id.as_bytes());
    KaspaOutpoint {
        transaction_id,
        index: op.index,
    }
}

fn sha256_digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

#[cfg(feature = "real-zk")]
fn same_shape_zk_setup(chain_id: KaspaChainId) -> Groth16Setup {
    let covenant_id = [0x91; 32];
    let receipt = RgkReceipt {
        version: rgk_core::ENCODING_VERSION,
        chain_id,
        covenant_id,
        old_state: RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id,
            covenant_id,
            asset_id: [0x92; 32],
            state_digest: [0x01; 32],
            receipt_policy: ReceiptPolicy::ZkOrVerifier,
        },
        new_state: RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id,
            covenant_id,
            asset_id: [0x92; 32],
            state_digest: [0x02; 32],
            receipt_policy: ReceiptPolicy::ZkOrVerifier,
        },
        transition_digest: [0x93; 32],
        continuation_commitment: [0x95; 32],
        proof_mode: ProofMode::ZkReceipt,
        replay_nonce: [0x94; 32],
    };
    let receipt_id = receipt_commitment(&receipt);
    let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
    real_zk::setup(&circuit).expect("same-shape Groth16 setup")
}

#[cfg(feature = "real-zk")]
fn live_groth16_stack(setup: &Groth16Setup, receipt: &RgkReceipt) -> Groth16PrecompileStack {
    let receipt_id = receipt_commitment(receipt);
    let circuit = ReceiptCircuit::from_receipt(receipt, receipt_id);
    let proof = real_zk::prove(&setup.pk, circuit.clone()).expect("live Groth16 receipt proof");
    real_zk::groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("live Toccata Groth16 stack")
}

#[cfg(feature = "real-zk")]
fn prepend_zk_to_redeem_script(covenant_script: &[u8], verifying_key: &[u8]) -> Vec<u8> {
    let mut redeem_script = Vec::new();
    rgk_covenant::push_data(&mut redeem_script, verifying_key);
    rgk_covenant::push_data(&mut redeem_script, &[real_zk::ZK_TAG_GROTH16]);
    redeem_script.push(rgk_covenant::opcodes::OP_ZK_PRECOMPILE);
    redeem_script.push(rgk_covenant::opcodes::OP_DROP);
    redeem_script.extend_from_slice(covenant_script);
    redeem_script
}

#[cfg(feature = "real-zk")]
fn zk_signature_prefix(stack: &Groth16PrecompileStack, flags: EngineFlags) -> Vec<u8> {
    let mut signature = ScriptBuilder::with_flags(flags);
    for input in stack.public_inputs.iter().rev() {
        signature.add_data(input).expect("public input push");
    }
    signature
        .add_i64(stack.public_input_count() as i64)
        .expect("public input count push")
        .add_data(&stack.proof)
        .expect("proof push");
    signature.drain()
}

fn bytes_to_outpoint(b: KaspaOutpoint) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes(b.transaction_id), b.index)
}

#[test]
fn live_toccata_tx_config_defaults_to_native_zero_gas() {
    let config = LiveToccataTxConfig::native();

    assert_eq!(config.subnetwork_id, SUBNETWORK_ID_NATIVE);
    assert_eq!(config.subnetwork_id.as_bytes(), &[0u8; 20]);
    assert_eq!(config.gas, 0);
    assert_eq!(config.mode(), "native");
}

#[test]
fn live_toccata_tx_config_accepts_user_lane_non_zero_gas() {
    let config = LiveToccataTxConfig::user_lane([0, 0, 1, 0], 7).unwrap();
    let mut expected = [0u8; 20];
    expected[..rgk_tx::SUBNETWORK_NAMESPACE_LEN].copy_from_slice(&[0, 0, 1, 0]);

    assert_eq!(config.subnetwork_id.as_bytes(), &expected);
    assert_eq!(config.gas, 7);
    assert_eq!(config.mode(), "user-lane");
}

#[test]
fn live_toccata_tx_config_rejects_reserved_or_zero_gas_user_lane() {
    assert!(LiveToccataTxConfig::user_lane([0, 0, 1, 0], 0).is_err());
    assert!(LiveToccataTxConfig::user_lane([0, 0, 0, 0], 7).is_err());
    assert!(LiveToccataTxConfig::user_lane([2, 0, 0, 0], 7).is_err());
}

#[test]
fn live_toccata_tx_config_parses_namespace_hex() {
    assert_eq!(parse_user_lane_namespace("00000100"), [0, 0, 1, 0]);
    assert_eq!(parse_user_lane_namespace("0x00000100"), [0, 0, 1, 0]);
    assert_eq!(parse_user_lane_namespace("0X00000100"), [0, 0, 1, 0]);
}

// ============================================================
// The test
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_toccata_full_covenant_lifecycle() {
    let config = LiveNetworkConfig::from_env();
    let tx_config = LiveToccataTxConfig::from_env();
    let client = connect_live_network(config).await;
    let backend = WrpcBackend::new(client.clone(), config.chain_id);
    eprintln!(
        "live: connected to {} wRPC (chain_id={:?})",
        config.name, config.chain_id
    );
    eprintln!(
        "live: Toccata tx subnetwork=0x{} gas={} mode={}",
        to_hex(tx_config.subnetwork_id.as_bytes()),
        tx_config.gas,
        tx_config.mode()
    );
    let server_info = client
        .get_server_info()
        .await
        .expect("get_server_info for live covenant");
    eprintln!(
        "live: server_version={} network_id={} is_synced={} has_utxo_index={}",
        server_info.server_version,
        server_info.network_id,
        server_info.is_synced,
        server_info.has_utxo_index
    );
    assert_eq!(
        server_info.network_id, config.network_id,
        "live covenant endpoint network id must match RGK_LIVE_KASPA_NETWORK"
    );
    assert!(
        server_info.has_utxo_index,
        "live covenant staging endpoint must enable utxoindex"
    );

    // ----- Step 1: Generate a keypair we control.
    let (kp, miner_address) = fresh_keypair(config.address_prefix);
    let privkey_bytes = kp.secret_key().secret_bytes();
    eprintln!(
        "live: generated keypair, {} address: {}",
        config.name, miner_address
    );
    let genesis_fee: u64 = rgk_e2e::LIVE_VERIFIER_TRANSITION_FEE;
    let transition_fee: u64 = if cfg!(feature = "real-zk") {
        rgk_e2e::LIVE_ZK_TRANSITION_FEE
    } else {
        rgk_e2e::LIVE_VERIFIER_TRANSITION_FEE
    };
    let min_funding_value = genesis_fee
        .checked_add(transition_fee)
        .and_then(|value| value.checked_add(rgk_e2e::LIVE_MIN_CONTINUATION_OUTPUT_VALUE))
        .expect("minimum staging funding value overflow");
    let resume = LiveResumeEvidence::from_env(config);

    // ----- Step 2: Obtain a spendable funding UTXO.
    //
    // Local Toccata networks can mine to the deterministic address. Public
    // testnet staging cannot mine; it must pre-fund the printed address with a
    // normal, non-coinbase UTXO and then run this exact harness against a real
    // public wRPC endpoint.
    if resume.is_some() {
        eprintln!(
            "live: public testnet staging funding address = {} required_min_value={} sompi",
            miner_address, min_funding_value
        );
    } else if config.local_mining {
        mine_empty_block(&client, &miner_address).await;
        wait_for_daa_score(&client, 1).await;
        eprintln!(
            "live: coinbase block 1 mined; mining 2000 more so the FIRST coinbase \
             UTXO matures (need DAA >= 1001 to spend it)..."
        );
        mine_n_blocks(&client, &miner_address, 2000).await;
        wait_for_daa_score(&client, 2001).await;
        eprintln!("live: oldest coinbase UTXO is now mature (DAA >= 2001)");
    } else {
        eprintln!(
            "live: public testnet staging funding address = {} required_min_value={} sompi",
            miner_address, min_funding_value
        );
    }

    // ----- Step 3: Fetch the live funding UTXO from the node.
    let (funding_outpoint, funding_value, funding_daa, funding_coinbase, funding_utxo) =
        if let Some(resume) = &resume {
            assert!(
                resume.funding_value >= min_funding_value,
                "resume funding value must satisfy current real-ZK funding minimum"
            );
            let funding_outpoint =
                TransactionOutpoint::new(resume.funding_txid, resume.funding_index);
            let funding_utxo = UtxoEntry {
                amount: resume.funding_value,
                script_public_key: pay_to_address_script(&miner_address),
                block_daa_score: resume.funding_daa,
                is_coinbase: false,
                covenant_id: None,
            };
            (
                funding_outpoint,
                resume.funding_value,
                resume.funding_daa,
                false,
                funding_utxo,
            )
        } else {
            let funding_entries = fetch_utxos_for_address(&client, &miner_address).await;
            let funding_entry = select_funding_utxo(
                funding_entries,
                min_funding_value,
                !config.local_mining,
                &miner_address,
            );
            let funding_outpoint = TransactionOutpoint::new(
                funding_entry.outpoint.transaction_id,
                funding_entry.outpoint.index,
            );
            let funding_value = funding_entry.utxo_entry.amount;
            let funding_daa = funding_entry.utxo_entry.block_daa_score;
            let funding_coinbase = funding_entry.utxo_entry.is_coinbase;
            let funding_utxo = rpc_entry_to_utxo(&funding_entry);
            (
                funding_outpoint,
                funding_value,
                funding_daa,
                funding_coinbase,
                funding_utxo,
            )
        };
    eprintln!(
        "live: selected funding UTXO at DAA {} value={} coinbase={}",
        funding_daa, funding_value, funding_coinbase
    );
    eprintln!(
        "live: fetched funding UTXO txid={:02x?} index={} value={}",
        funding_outpoint.transaction_id.as_bytes(),
        funding_outpoint.index,
        funding_value
    );

    // ----- Step 4: Build the covenant-bearing output (genesis case).
    //
    // The output has covenant = Some(CovenantBinding{authorizing_input: 0,
    // covenant_id = X}) where X = covenant_id(funding_outpoint, [(0, output)]).
    // The covenant_id MUST be computed deterministically via the upstream
    // hashing function — anything else fails the genesis check at the node.
    //
    // The output value is reduced by `fee` so the tx carries a non-zero
    // fee — the local Toccata networks enforce fee >= mass * 100 sompi for compute
    // mass, and a covenant tx with ComputeBudget(300) needs ~3.1M sompi
    // of fee to clear the standardness check. We use 4_000_000 sompi to
    // leave a comfortable margin.
    let fee: u64 = genesis_fee;
    let covenant_output_value = funding_value.checked_sub(fee).expect("value > fee");
    let asset_id = [0x42u8; 32];
    let initial_state_digest = [0xA0u8; 32];
    let live_receipt_policy = if cfg!(feature = "real-zk") {
        ReceiptPolicy::ZkOrVerifier
    } else {
        ReceiptPolicy::VerifierOnly
    };
    let live_proof_mode = if cfg!(feature = "real-zk") {
        ProofMode::ZkReceipt
    } else {
        ProofMode::VerifierReceipt
    };
    #[cfg(feature = "real-zk")]
    let zk_setup = same_shape_zk_setup(config.chain_id);
    #[cfg(feature = "real-zk")]
    let zk_verifying_key =
        real_zk::serialize_verifying_key_for_precompile(&zk_setup.vk).expect("serialize ZK VK");
    let lineage_seed = outpoint_to_bytes(&funding_outpoint).encode_canonical();
    let lineage_id = compute_lineage_id(&lineage_seed, &asset_id);
    let initial_covenant_state = CovenantState {
        version: rgk_core::ENCODING_VERSION,
        chain_id: config.chain_id,
        lineage_id,
        asset_id,
        current_state_digest: initial_state_digest,
        receipt_policy: live_receipt_policy,
        genesis_proof_mode: live_proof_mode,
        replay_marker: [0u8; 32],
    };
    let covenant_spec = CovenantSpec {
        chain_id: config.chain_id,
        lineage_id,
        asset_id,
        initial_state_digest,
        receipt_policy: live_receipt_policy,
        genesis_proof_mode: live_proof_mode,
    };
    let covenant_script = covenant_spec.build_script().expect("RGK covenant script");
    #[cfg(feature = "real-zk")]
    let redeem_script = prepend_zk_to_redeem_script(&covenant_script, &zk_verifying_key);
    #[cfg(not(feature = "real-zk"))]
    let redeem_script = covenant_script;
    let covenant_output_spk = pay_to_script_hash_script(&redeem_script);
    let covenant_address =
        extract_script_pub_key_address(&covenant_output_spk, config.address_prefix)
            .expect("P2SH covenant address");
    let covenant_output_pre =
        TransactionOutput::new(covenant_output_value, covenant_output_spk.clone());
    let covenant_id = compute_covenant_id(
        funding_outpoint,
        std::iter::once((0u32, &covenant_output_pre)),
    );
    eprintln!(
        "live: computed covenant_id = {:02x?} for the genesis output (value={}, fee={})",
        covenant_id.as_bytes(),
        covenant_output_value,
        fee
    );
    if let Some(resume) = &resume {
        assert_eq!(
            covenant_id, resume.covenant_id,
            "resume report covenant_id must match the locally recomputed covenant id"
        );
    }
    let covenant_output = TransactionOutput::with_covenant(
        covenant_output_value,
        covenant_output_spk.clone(),
        Some(CovenantBinding::new(0, covenant_id)),
    );
    let genesis_payload = initial_covenant_state.encode_payload();

    // ----- Step 5: Build v1 (Toccata) unsigned transaction.
    //
    // For v1 (Toccata) transactions, `sig_op_count` MUST be 0 — the
    // post-Crescendo signature accounting uses `mass: ComputeBudget(10)`
    // (set automatically by `sign_with_multiple_v2`) rather than
    // sig_op_count. Setting sig_op_count != 0 causes the node to reject
    // the tx with "sig_op_count is inconsistent with transaction version 1".
    let input = TransactionInput::new(funding_outpoint, vec![], 0, 0);
    let unsigned_tx = Transaction::new(
        TX_VERSION_TOCCATA, // v1 — required for covenant bindings
        vec![input],
        vec![covenant_output],
        0, // lock_time
        tx_config.subnetwork_id,
        tx_config.gas,
        genesis_payload, // payload
    );

    // ----- Step 6: Sign the input with the Schnorr keypair.
    let signable = MutableTransaction::with_entries(unsigned_tx, vec![funding_utxo]);
    let signed = sign_with_multiple_v2(signable, &[privkey_bytes])
        .fully_signed()
        .expect("sign_with_multiple_v2 failed");
    let mut signed_tx: Transaction = signed.tx;
    // After signing, override `input.mass` with a generous ComputeBudget
    // (the same value the upstream integration test uses: ~30k-gram
    // per-input upper bound). The default `ComputeBudget(10)` set by
    // `sign_with_multiple_v2` is too small for a Toccata Schnorr
    // signature's script units — the verifier would reject with
    // "script units exceeded the amount committed in the input".
    let per_input_compute_budget: u16 = VERIFIER_COVENANT_COMPUTE_BUDGET;
    signed_tx
        .inputs
        .iter_mut()
        .for_each(|input| input.mass = ComputeBudget(per_input_compute_budget).into());
    eprintln!(
        "live: signed covenant tx, txid = {:02x?}",
        signed_tx.id().as_bytes()
    );

    // ----- Step 7: Submit the signed covenant transaction to the live node.
    let covenant_txid = if let Some(resume) = &resume {
        assert_eq!(
            signed_tx.id(),
            resume.covenant_txid,
            "resume report covenant txid must match the locally rebuilt Toccata v1 transaction"
        );
        eprintln!(
            "live: covenant tx ACCEPTED by node (resume report verified): txid={:02x?}",
            resume.covenant_txid.as_bytes()
        );
        resume.covenant_txid
    } else {
        let rpc_tx: RpcTransaction = (&signed_tx).into();
        let submit_result = backend.submit_rpc_transaction(&rpc_tx, false);
        match submit_result {
            Ok(id) => {
                eprintln!("live: covenant tx ACCEPTED by node: txid={:02x?}", id);
                Hash::from_bytes(id)
            }
            Err(e) => panic!("live: covenant tx REJECTED by node: {e}"),
        }
    };

    #[cfg(feature = "persistent-indexer")]
    let persistent_indexer_path = {
        let path = std::env::temp_dir().join(format!(
            "rgk-live-sled-indexer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    };

    // ----- Step 8: Mine a confirmation block.
    let pre_confirmation_dag = client
        .get_block_dag_info()
        .await
        .expect("get_block_dag_info before confirmation");
    let pre_confirmation_cursor = ScanCursor {
        chain_id: config.chain_id,
        block_hash: pre_confirmation_dag.sink.as_bytes(),
        daa_score: pre_confirmation_dag.virtual_daa_score,
    };
    #[cfg(feature = "persistent-indexer")]
    {
        let mut cursor_indexer =
            SledIndexer::open_path(&persistent_indexer_path).expect("open persistent cursor store");
        if config.local_mining {
            let mut scan_service = ScanService::new(
                &backend,
                &mut cursor_indexer,
                ScanServiceConfig::new(config.chain_id),
            );
            let tick = scan_service
                .tick()
                .expect("initialise pre-confirmation scan cursor");
            assert!(tick.initialised_cursor);
            assert_eq!(
                tick.end_cursor, pre_confirmation_cursor,
                "ScanService should initialise from the live pre-confirmation tip"
            );
            drop(scan_service);
        } else {
            cursor_indexer
                .store_scan_cursor(DEFAULT_SCAN_CURSOR, pre_confirmation_cursor.clone())
                .expect("store public pre-confirmation scan cursor");
        }
        cursor_indexer
            .flush()
            .expect("flush pre-confirmation cursor");
        drop(cursor_indexer);

        let cursor_indexer = SledIndexer::open_path(&persistent_indexer_path)
            .expect("reopen persistent cursor store");
        let recovered = cursor_indexer
            .load_scan_cursor(DEFAULT_SCAN_CURSOR)
            .expect("load pre-confirmation scan cursor")
            .expect("pre-confirmation scan cursor should exist");
        assert_eq!(
            recovered, pre_confirmation_cursor,
            "scan cursor must survive a sled reopen before the scan"
        );
    }
    if resume.is_some() {
        eprintln!(
            "live: waiting for public {} confirmation of covenant tx (resume report already confirmed)",
            config.name
        );
    } else if config.local_mining {
        mine_empty_block(&client, &miner_address).await;
        wait_for_daa_score(&client, 2).await;
        eprintln!("live: confirmation block 2 mined");
    } else {
        eprintln!(
            "live: waiting for public {} confirmation of covenant tx",
            config.name
        );
    }

    // ----- Step 9: Re-read the live P2SH covenant UTXO set.
    let (covenant_outpoint, covenant_block_daa) = if let Some(resume) = &resume {
        (
            TransactionOutpoint::new(covenant_txid, 0),
            resume.covenant_daa,
        )
    } else {
        let covenant_entry = wait_for_address_output_by_txid(
            &client,
            &covenant_address,
            &covenant_txid,
            "covenant",
            Duration::from_secs(PUBLIC_CONFIRMATION_TIMEOUT_SECS),
        )
        .await;
        assert_eq!(
            covenant_entry
                .utxo_entry
                .covenant_id
                .map(covenant_id_hash_to_bytes),
            Some(covenant_id_hash_to_bytes(covenant_id)),
            "covenant_id on the live UTXO must match the value computed at submit time"
        );
        (
            TransactionOutpoint::new(
                covenant_entry.outpoint.transaction_id,
                covenant_entry.outpoint.index,
            ),
            covenant_entry.utxo_entry.block_daa_score,
        )
    };
    eprintln!(
        "live: covenant output confirmed at DAA score {} with covenant_id={:02x?}",
        covenant_block_daa,
        covenant_id.as_bytes()
    );
    let covenant_id_bytes: KaspaCovenantId = covenant_id_hash_to_bytes(covenant_id);
    let native_asset_report = rgk_e2e::native_asset_state_report(
        config.chain_id,
        asset_id,
        outpoint_to_bytes(&covenant_outpoint),
        covenant_id_bytes,
        covenant_id_hash_to_bytes(covenant_txid),
        covenant_block_daa,
        1,
        1_000_000,
    )
    .expect("native RGK asset state digest");
    let native_asset_state_digest = native_asset_report.state_digest.0;
    eprintln!(
        "live: native RGK asset state digest = 0x{} (allocations={} daa={} confirmations=1 privacy_policy={:?} lane_id=0x{} policy_commitment=0x{} metadata_commitment=0x{} owner_commitment=0x{})",
        to_hex(&native_asset_state_digest),
        native_asset_report.allocation_count,
        covenant_block_daa,
        native_asset_report.privacy_policy,
        to_hex(&native_asset_report.lane_id),
        to_hex(&native_asset_report.policy_commitment.0),
        to_hex(&native_asset_report.metadata_commitment.0),
        to_hex(&native_asset_report.owner_commitment.0)
    );

    // ----- Step 10: Spend the P2SH covenant output through the RGK redeem script.
    let continuation_output_value = covenant_output_value
        .checked_sub(transition_fee)
        .expect("covenant value > transition fee");
    let advanced_covenant_state = CovenantState {
        version: rgk_core::ENCODING_VERSION,
        chain_id: config.chain_id,
        lineage_id,
        asset_id,
        current_state_digest: native_asset_state_digest,
        receipt_policy: live_receipt_policy,
        genesis_proof_mode: live_proof_mode,
        replay_marker: sha256_digest(&[
            b"rgk:live-covenant-script-spend",
            &initial_state_digest,
            &native_asset_state_digest,
        ]),
    };
    let old_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: config.chain_id,
        covenant_id: covenant_id_bytes,
        asset_id,
        state_digest: initial_state_digest,
        receipt_policy: live_receipt_policy,
    };
    let new_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: config.chain_id,
        covenant_id: covenant_id_bytes,
        asset_id,
        state_digest: native_asset_state_digest,
        receipt_policy: live_receipt_policy,
    };
    assert_eq!(new_state.state_digest, native_asset_state_digest);
    let spent_outpoint_payload = outpoint_to_bytes(&covenant_outpoint).encode_canonical();
    let transition_digest = sha256_digest(&[
        b"rgk:live-covenant-transition",
        &lineage_id,
        &initial_state_digest,
        &native_asset_state_digest,
    ]);
    let continuation_phase1 = rgk_e2e::native_asset_continuation_report(
        config.chain_id,
        asset_id,
        outpoint_to_bytes(&covenant_outpoint),
        covenant_id_bytes,
        covenant_id_hash_to_bytes(covenant_txid),
        covenant_block_daa,
        0,
        1_000_000,
    )
    .expect("native RGK phase-1 continuation commitment");
    let receipt_replay_nonce = replay_nonce(&spent_outpoint_payload, &transition_digest);
    let receipt_input = ReceiptInput {
        chain_id: config.chain_id,
        covenant_id: covenant_id_bytes,
        old_state: old_state.clone(),
        new_state: new_state.clone(),
        transition_digest,
        continuation_commitment: continuation_phase1.commitment.0,
        proof_mode: live_proof_mode,
        replay_nonce: receipt_replay_nonce,
    };
    let (receipt, receipt_id, receipt_bytes) =
        ReceiptBuilder::build(&receipt_input).expect("live receipt build");
    #[cfg(feature = "real-zk")]
    let zk_stack = live_groth16_stack(&zk_setup, &receipt);
    #[cfg(not(feature = "real-zk"))]
    let _ = &receipt;
    let covenant_flags = EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    };
    #[cfg(feature = "real-zk")]
    let signature_prefix = {
        eprintln!(
            "live: ZK covenant spend enabled, public_inputs={} vk_bytes={} proof_bytes={}",
            zk_stack.public_input_count(),
            zk_verifying_key.len(),
            zk_stack.proof.len()
        );
        zk_signature_prefix(&zk_stack, covenant_flags)
    };
    #[cfg(not(feature = "real-zk"))]
    let signature_prefix = vec![];
    let covenant_signature_script = pay_to_script_hash_signature_script_with_flags(
        redeem_script.clone(),
        signature_prefix,
        covenant_flags,
    )
    .expect("P2SH covenant signature script");
    let covenant_spend_compute_budget = if cfg!(feature = "real-zk") {
        ZK_COVENANT_COMPUTE_BUDGET
    } else {
        VERIFIER_COVENANT_COMPUTE_BUDGET
    };
    let covenant_spend_input = TransactionInput::new_with_compute_budget(
        covenant_outpoint,
        covenant_signature_script,
        0,
        covenant_spend_compute_budget,
    );
    let continuation_output = TransactionOutput::with_covenant(
        continuation_output_value,
        covenant_output_spk.clone(),
        Some(CovenantBinding::new(0, covenant_id)),
    );
    let mut continuation_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![covenant_spend_input],
        vec![continuation_output],
        0,
        tx_config.subnetwork_id,
        tx_config.gas,
        advanced_covenant_state.encode_payload(),
    );
    continuation_tx.finalize();
    eprintln!(
        "live: built P2SH covenant spend, txid = {:02x?}",
        continuation_tx.id().as_bytes()
    );

    let continuation_txid = if let Some(resume) = &resume {
        assert_eq!(
            continuation_tx.id(),
            resume.continuation_txid,
            "resume report continuation txid must match the locally rebuilt covenant spend"
        );
        eprintln!(
            "live: P2SH covenant spend ACCEPTED by node (resume report verified): txid={:02x?}",
            resume.continuation_txid.as_bytes()
        );
        resume.continuation_txid
    } else {
        let rpc_tx: RpcTransaction = (&continuation_tx).into();
        let submit_result = backend.submit_rpc_transaction(&rpc_tx, false);
        match submit_result {
            Ok(id) => {
                eprintln!(
                    "live: P2SH covenant spend ACCEPTED by node: txid={:02x?}",
                    id
                );
                Hash::from_bytes(id)
            }
            Err(e) => panic!("live: P2SH covenant spend REJECTED by node: {e}"),
        }
    };

    if resume.is_some() {
        eprintln!(
            "live: waiting for public {} confirmation of covenant spend (resume report already confirmed)",
            config.name
        );
    } else if config.local_mining {
        mine_empty_block(&client, &miner_address).await;
        wait_for_daa_score(&client, covenant_block_daa + 1).await;
        eprintln!("live: P2SH covenant spend confirmation block mined");
    } else {
        eprintln!(
            "live: waiting for public {} confirmation of covenant spend",
            config.name
        );
    }

    let (continuation_outpoint, continuation_block_daa) = if let Some(resume) = &resume {
        let continuation_entry = fetch_utxos_for_address(&client, &covenant_address)
            .await
            .into_iter()
            .find(|entry| entry.outpoint.transaction_id.as_bytes() == continuation_txid.as_bytes())
            .expect("resume continuation covenant output must still be visible in the UTXO set");
        assert_eq!(
            continuation_entry
                .utxo_entry
                .covenant_id
                .map(covenant_id_hash_to_bytes),
            Some(covenant_id_hash_to_bytes(covenant_id)),
            "resume continuation covenant_id must remain stable"
        );
        assert_eq!(
            continuation_entry.utxo_entry.block_daa_score, resume.continuation_daa,
            "resume continuation DAA must match the live UTXO set"
        );
        (
            TransactionOutpoint::new(
                continuation_entry.outpoint.transaction_id,
                continuation_entry.outpoint.index,
            ),
            resume.continuation_daa,
        )
    } else {
        let continuation_entry = wait_for_address_output_by_txid(
            &client,
            &covenant_address,
            &continuation_txid,
            "continuation covenant",
            Duration::from_secs(PUBLIC_CONFIRMATION_TIMEOUT_SECS),
        )
        .await;
        assert_eq!(
            continuation_entry
                .utxo_entry
                .covenant_id
                .map(covenant_id_hash_to_bytes),
            Some(covenant_id_hash_to_bytes(covenant_id)),
            "continuation covenant_id must remain stable"
        );
        (
            TransactionOutpoint::new(
                continuation_entry.outpoint.transaction_id,
                continuation_entry.outpoint.index,
            ),
            continuation_entry.utxo_entry.block_daa_score,
        )
    };
    let new_outpoint_bytes = outpoint_to_bytes(&continuation_outpoint);
    eprintln!(
        "live: continuation covenant output confirmed at DAA score {}",
        continuation_block_daa
    );
    let native_transition_report = rgk_e2e::native_asset_transition_report(
        config.chain_id,
        asset_id,
        outpoint_to_bytes(&covenant_outpoint),
        covenant_id_bytes,
        covenant_id_hash_to_bytes(covenant_txid),
        covenant_block_daa,
        new_outpoint_bytes,
        continuation_block_daa,
        covenant_id_hash_to_bytes(continuation_txid),
        1_000_000,
    )
    .expect("native RGK transition digest");
    assert_eq!(
        native_transition_report.previous_state_digest,
        native_asset_report.state_digest
    );
    assert_eq!(
        native_transition_report.continuation_commitment, continuation_phase1.commitment,
        "phase-2 finalization must preserve the receipt-bound phase-1 commitment"
    );
    let production_zk_shape = RgkAllocationProofShape::from_counts(
        native_transition_report.spent_allocation_count,
        native_transition_report.new_allocation_count,
    )
    .expect("native production-ZK allocation shape");
    eprintln!(
        "live: native production-ZK allocation guard accepted shape={} spent_allocations={} new_allocations={}",
        production_zk_shape.label(),
        native_transition_report.spent_allocation_count,
        native_transition_report.new_allocation_count
    );
    eprintln!(
        "live: native RGK transition digest = 0x{} (old_state=0x{} new_state=0x{} witness_txid=0x{} spent_allocations={} new_allocations={} privacy_policy={:?} lane_id=0x{} policy_commitment=0x{} metadata_commitment=0x{} previous_owner_commitment=0x{} new_owner_commitment=0x{} ownership_authorization_commitment=0x{})",
        to_hex(&native_transition_report.transition_digest.0),
        to_hex(&native_transition_report.previous_state_digest.0),
        to_hex(&native_transition_report.new_state_digest.0),
        to_hex(&continuation_txid.as_bytes()),
        native_transition_report.spent_allocation_count,
        native_transition_report.new_allocation_count,
        native_transition_report.privacy_policy,
        to_hex(&native_transition_report.lane_id),
        to_hex(&native_transition_report.policy_commitment.0),
        to_hex(&native_transition_report.metadata_commitment.0),
        to_hex(&native_transition_report.previous_owner_commitment.0),
        to_hex(&native_transition_report.new_owner_commitment.0),
        to_hex(&native_transition_report.ownership_authorization_commitment)
    );
    let final_native_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: config.chain_id,
        covenant_id: covenant_id_bytes,
        asset_id,
        state_digest: native_transition_report.new_state_digest.0,
        receipt_policy: live_receipt_policy,
    };
    let semantic_transition_statement =
        SemanticTransitionStatement::from_reports(&native_transition_report, &continuation_phase1)
            .expect("semantic native RGK transition statement");
    assert_eq!(
        semantic_transition_statement.continuation_commitment,
        native_transition_report.continuation_commitment.0
    );
    assert_eq!(
        semantic_transition_statement.continuation_shape_root,
        native_transition_report.continuation_shape_root.0
    );
    assert_eq!(
        semantic_transition_statement.transition_digest,
        native_transition_report.transition_digest.0
    );
    let semantic_public_inputs = semantic_transition_statement.public_inputs();
    assert_eq!(
        semantic_public_inputs.len(),
        SemanticTransitionStatement::PUBLIC_INPUT_LEN
    );
    eprintln!(
        "live: semantic RGK transition statement public_inputs={} continuation_shape_root=0x{} policy_commitment=0x{} metadata_commitment=0x{} previous_owner_commitment=0x{} new_owner_commitment=0x{} ownership_authorization_commitment=0x{}",
        semantic_public_inputs.len(),
        to_hex(&semantic_transition_statement.continuation_shape_root),
        to_hex(&semantic_transition_statement.policy_commitment),
        to_hex(&semantic_transition_statement.metadata_commitment),
        to_hex(&semantic_transition_statement.previous_owner_commitment),
        to_hex(&semantic_transition_statement.new_owner_commitment),
        to_hex(&semantic_transition_statement.ownership_authorization_commitment)
    );
    #[cfg(feature = "real-zk")]
    let mut allocation_audit_certificate_record: Option<AllocationAuditCertificateRecord> = None;
    #[cfg(feature = "real-zk")]
    {
        let semantic_circuit =
            SemanticTransitionCircuit::from_statement(&semantic_transition_statement);
        let semantic_setup =
            real_zk::setup_semantic(&semantic_circuit).expect("semantic Groth16 setup");
        let semantic_proof = real_zk::prove_semantic(&semantic_setup.pk, semantic_circuit.clone())
            .expect("semantic Groth16 proof");
        let semantic_public_fr =
            real_zk::semantic_public_inputs_as_fr(&semantic_circuit.public_inputs);
        assert!(
            real_zk::verify(&semantic_setup.vk, &semantic_public_fr, &semantic_proof)
                .expect("semantic Groth16 verify"),
            "semantic Groth16 proof must verify against final native transition statement"
        );
        let semantic_stack = real_zk::semantic_groth16_precompile_stack(
            &semantic_setup.vk,
            &semantic_proof,
            &semantic_circuit.public_inputs,
        )
        .expect("semantic Toccata Groth16 precompile stack");
        eprintln!(
            "live: semantic Groth16 proof verified public_inputs={} vk_bytes={} proof_bytes={}",
            semantic_stack.public_input_count(),
            semantic_stack.verifying_key.len(),
            semantic_stack.proof.len()
        );
        let spent_allocation = rgk_e2e::native_asset_allocation(
            config.chain_id,
            asset_id,
            outpoint_to_bytes(&covenant_outpoint),
            covenant_id_bytes,
            covenant_id_hash_to_bytes(covenant_txid),
            covenant_block_daa,
            1,
            1_000_000,
        );
        let new_allocation = RgkAllocation {
            anchor: RgkCovenantAnchor {
                chain: config.chain_id,
                covenant_outpoint: new_outpoint_bytes,
                covenant_id: covenant_id_bytes,
                witness_txid: covenant_id_hash_to_bytes(continuation_txid),
                daa_score: continuation_block_daa,
                confirmation_depth: 1,
            },
            amount: 1_000_000,
            encrypted_note_commitment: rgk_e2e::native_continuation_note_commitment(
                asset_id,
                covenant_id_bytes,
                new_outpoint_bytes.index,
                1_000_000,
            ),
        };
        let allocation_witness = SupportedAllocationVectorWitness::from_allocations(
            core::slice::from_ref(&spent_allocation),
            core::slice::from_ref(&new_allocation),
        )
        .expect("supported native allocation witness");
        let allocation_circuit = SupportedAllocationVectorCircuit::from_statement_and_witness(
            &semantic_transition_statement,
            allocation_witness,
        )
        .expect("supported allocation-vector circuit");
        let allocation_shape = allocation_circuit.shape();
        let allocation_setup = real_zk::setup_supported_allocation(&allocation_circuit)
            .expect("allocation Groth16 setup");
        let allocation_proof =
            real_zk::prove_supported_allocation(&allocation_setup.pk, allocation_circuit.clone())
                .expect("allocation Groth16 proof");
        let allocation_public_fr =
            real_zk::semantic_public_inputs_as_fr(allocation_circuit.public_inputs());
        assert!(
            real_zk::verify(
                &allocation_setup.vk,
                &allocation_public_fr,
                &allocation_proof
            )
            .expect("allocation Groth16 verify"),
            "allocation-vector Groth16 proof must verify against final native transition statement"
        );
        let allocation_stack = real_zk::supported_allocation_groth16_precompile_stack(
            &allocation_setup.vk,
            &allocation_proof,
            &allocation_circuit,
        )
        .expect("allocation-vector Toccata Groth16 precompile stack");
        eprintln!(
            "live: supported allocation-vector Groth16 proof verified shape={} public_inputs={} vk_bytes={} proof_bytes={}",
            allocation_shape.label(),
            allocation_stack.public_input_count(),
            allocation_stack.verifying_key.len(),
            allocation_stack.proof.len()
        );
        let spent_transcript_statement =
            real_zk::AllocationTranscriptSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
                RgkAllocationTranscriptSide::Spent,
                0,
                1,
                core::slice::from_ref(&spent_allocation),
                [0x51; 32],
            )
            .expect("spent allocation transcript statement");
        let new_transcript_statement =
            real_zk::AllocationTranscriptSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
                RgkAllocationTranscriptSide::New,
                0,
                1,
                core::slice::from_ref(&new_allocation),
                [0x52; 32],
            )
            .expect("new allocation transcript statement");
        let spent_transcript_witness =
            real_zk::AllocationTranscriptSegmentWitness::<1>::from_allocations(
                core::slice::from_ref(&spent_allocation),
                [0x51; 32],
            )
            .expect("spent allocation transcript witness");
        let new_transcript_witness =
            real_zk::AllocationTranscriptSegmentWitness::<1>::from_allocations(
                core::slice::from_ref(&new_allocation),
                [0x52; 32],
            )
            .expect("new allocation transcript witness");
        let spent_transcript_circuit =
            real_zk::AllocationTranscriptSegmentCircuit::<1>::from_statement_and_witness(
                &spent_transcript_statement,
                spent_transcript_witness,
            )
            .expect("spent allocation transcript circuit");
        let new_transcript_circuit =
            real_zk::AllocationTranscriptSegmentCircuit::<1>::from_statement_and_witness(
                &new_transcript_statement,
                new_transcript_witness,
            )
            .expect("new allocation transcript circuit");
        let transcript_setup =
            real_zk::setup_allocation_transcript_segment(&spent_transcript_circuit)
                .expect("allocation transcript Groth16 setup");
        let spent_transcript_proof = real_zk::prove_allocation_transcript_segment(
            &transcript_setup.pk,
            spent_transcript_circuit.clone(),
        )
        .expect("spent allocation transcript Groth16 proof");
        let new_transcript_proof = real_zk::prove_allocation_transcript_segment(
            &transcript_setup.pk,
            new_transcript_circuit.clone(),
        )
        .expect("new allocation transcript Groth16 proof");
        let spent_transcript_public_fr = real_zk::allocation_transcript_segment_public_inputs_as_fr(
            &spent_transcript_circuit.public_inputs,
        );
        let new_transcript_public_fr = real_zk::allocation_transcript_segment_public_inputs_as_fr(
            &new_transcript_circuit.public_inputs,
        );
        assert!(
            real_zk::verify(
                &transcript_setup.vk,
                &spent_transcript_public_fr,
                &spent_transcript_proof,
            )
            .expect("spent allocation transcript Groth16 verify"),
            "spent allocation transcript proof must verify against the live native allocation"
        );
        assert!(
            real_zk::verify(
                &transcript_setup.vk,
                &new_transcript_public_fr,
                &new_transcript_proof,
            )
            .expect("new allocation transcript Groth16 verify"),
            "new allocation transcript proof must verify against the live native allocation"
        );
        let spent_transcript_stack =
            real_zk::allocation_transcript_segment_groth16_precompile_stack(
                &transcript_setup.vk,
                &spent_transcript_proof,
                &spent_transcript_circuit.public_inputs,
            )
            .expect("allocation transcript Toccata Groth16 precompile stack");
        let new_transcript_stack = real_zk::allocation_transcript_segment_groth16_precompile_stack(
            &transcript_setup.vk,
            &new_transcript_proof,
            &new_transcript_circuit.public_inputs,
        )
        .expect("new allocation transcript Toccata Groth16 precompile stack");
        eprintln!(
            "live: allocation transcript segment Groth16 proof verified sides=2 segments=2 allocations=2 public_inputs_each={} vk_bytes={} proof_bytes_each={} spent_root=0x{} new_root=0x{} spent_amount_commitment=0x{} new_amount_commitment=0x{}",
            spent_transcript_stack.public_input_count(),
            spent_transcript_stack.verifying_key.len(),
            spent_transcript_stack.proof.len(),
            to_hex(&spent_transcript_statement.next_root),
            to_hex(&new_transcript_statement.next_root),
            to_hex(&spent_transcript_statement.segment_amount_commitment),
            to_hex(&new_transcript_statement.segment_amount_commitment)
        );
        let spent_conservation_statement =
            real_zk::AllocationConservationSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
                RgkAllocationTranscriptSide::Spent,
                0,
                1,
                0,
                core::slice::from_ref(&spent_allocation),
                [0x51; 32],
                [0x61; 32],
                [0x62; 32],
            )
            .expect("spent allocation conservation segment statement");
        let new_conservation_statement =
            real_zk::AllocationConservationSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
                RgkAllocationTranscriptSide::New,
                0,
                1,
                0,
                core::slice::from_ref(&new_allocation),
                [0x52; 32],
                [0x63; 32],
                [0x64; 32],
            )
            .expect("new allocation conservation segment statement");
        let spent_conservation_witness =
            real_zk::AllocationConservationSegmentWitness::<1>::from_allocations(
                0,
                core::slice::from_ref(&spent_allocation),
                [0x51; 32],
                [0x61; 32],
                [0x62; 32],
            )
            .expect("spent allocation conservation segment witness");
        let new_conservation_witness =
            real_zk::AllocationConservationSegmentWitness::<1>::from_allocations(
                0,
                core::slice::from_ref(&new_allocation),
                [0x52; 32],
                [0x63; 32],
                [0x64; 32],
            )
            .expect("new allocation conservation segment witness");
        let spent_conservation_circuit =
            real_zk::AllocationConservationSegmentCircuit::<1>::from_statement_and_witness(
                &spent_conservation_statement,
                spent_conservation_witness,
            )
            .expect("spent allocation conservation segment circuit");
        let new_conservation_circuit =
            real_zk::AllocationConservationSegmentCircuit::<1>::from_statement_and_witness(
                &new_conservation_statement,
                new_conservation_witness,
            )
            .expect("new allocation conservation segment circuit");
        let conservation_segment_setup =
            real_zk::setup_allocation_conservation_segment(&spent_conservation_circuit)
                .expect("allocation conservation segment Groth16 setup");
        let spent_conservation_proof = real_zk::prove_allocation_conservation_segment(
            &conservation_segment_setup.pk,
            spent_conservation_circuit.clone(),
        )
        .expect("spent allocation conservation segment Groth16 proof");
        let new_conservation_proof = real_zk::prove_allocation_conservation_segment(
            &conservation_segment_setup.pk,
            new_conservation_circuit.clone(),
        )
        .expect("new allocation conservation segment Groth16 proof");
        assert!(
            real_zk::verify(
                &conservation_segment_setup.vk,
                &real_zk::allocation_conservation_segment_public_inputs_as_fr(
                    &spent_conservation_circuit.public_inputs,
                ),
                &spent_conservation_proof,
            )
            .expect("spent allocation conservation segment Groth16 verify"),
            "spent allocation conservation segment proof must verify"
        );
        assert!(
            real_zk::verify(
                &conservation_segment_setup.vk,
                &real_zk::allocation_conservation_segment_public_inputs_as_fr(
                    &new_conservation_circuit.public_inputs,
                ),
                &new_conservation_proof,
            )
            .expect("new allocation conservation segment Groth16 verify"),
            "new allocation conservation segment proof must verify"
        );
        let spent_conservation_stack =
            real_zk::allocation_conservation_segment_groth16_precompile_stack(
                &conservation_segment_setup.vk,
                &spent_conservation_proof,
                &spent_conservation_circuit.public_inputs,
            )
            .expect("allocation conservation segment Toccata Groth16 precompile stack");
        let new_conservation_stack =
            real_zk::allocation_conservation_segment_groth16_precompile_stack(
                &conservation_segment_setup.vk,
                &new_conservation_proof,
                &new_conservation_circuit.public_inputs,
            )
            .expect("new allocation conservation segment Toccata Groth16 precompile stack");
        let conservation_final_statement =
            real_zk::AllocationConservationFinalStatement::from_total(
                1,
                1,
                spent_allocation.amount,
                [0x62; 32],
                [0x64; 32],
            )
            .expect("allocation conservation final statement");
        assert_eq!(
            conservation_final_statement.spent_total_commitment,
            spent_conservation_statement.next_total_commitment
        );
        assert_eq!(
            conservation_final_statement.new_total_commitment,
            new_conservation_statement.next_total_commitment
        );
        let conservation_final_witness = real_zk::AllocationConservationFinalWitness::new(
            spent_allocation.amount,
            [0x62; 32],
            [0x64; 32],
        )
        .expect("allocation conservation final witness");
        let conservation_final_circuit =
            real_zk::AllocationConservationFinalCircuit::from_statement_and_witness(
                &conservation_final_statement,
                conservation_final_witness,
            )
            .expect("allocation conservation final circuit");
        let conservation_final_setup =
            real_zk::setup_allocation_conservation_final(&conservation_final_circuit)
                .expect("allocation conservation final Groth16 setup");
        let conservation_final_proof = real_zk::prove_allocation_conservation_final(
            &conservation_final_setup.pk,
            conservation_final_circuit.clone(),
        )
        .expect("allocation conservation final Groth16 proof");
        assert!(
            real_zk::verify(
                &conservation_final_setup.vk,
                &real_zk::allocation_conservation_final_public_inputs_as_fr(
                    &conservation_final_circuit.public_inputs,
                ),
                &conservation_final_proof,
            )
            .expect("allocation conservation final Groth16 verify"),
            "allocation conservation final equality proof must verify"
        );
        let conservation_final_stack =
            real_zk::allocation_conservation_final_groth16_precompile_stack(
                &conservation_final_setup.vk,
                &conservation_final_proof,
                &conservation_final_circuit.public_inputs,
            )
            .expect("allocation conservation final Toccata Groth16 precompile stack");
        eprintln!(
            "live: allocation conservation Groth16 chain verified sides=2 segments=2 allocations=2 public_inputs_each={} final_public_inputs={} segment_vk_bytes={} segment_proof_bytes_each={} final_vk_bytes={} final_proof_bytes={} spent_total_commitment=0x{} new_total_commitment=0x{}",
            spent_conservation_stack.public_input_count(),
            conservation_final_stack.public_input_count(),
            spent_conservation_stack.verifying_key.len(),
            spent_conservation_stack.proof.len(),
            conservation_final_stack.verifying_key.len(),
            conservation_final_stack.proof.len(),
            to_hex(&conservation_final_statement.spent_total_commitment),
            to_hex(&conservation_final_statement.new_total_commitment)
        );
        let exclusion_statement =
            real_zk::AllocationExclusionSegmentPairStatement::<1, 1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
                0,
                0,
                1,
                1,
                core::slice::from_ref(&spent_allocation),
                core::slice::from_ref(&new_allocation),
                [0x51; 32],
                [0x52; 32],
            )
            .expect("allocation exclusion segment-pair statement");
        let exclusion_witness =
            real_zk::AllocationExclusionSegmentPairWitness::<1, 1>::from_allocations(
                core::slice::from_ref(&spent_allocation),
                core::slice::from_ref(&new_allocation),
                [0x51; 32],
                [0x52; 32],
            )
            .expect("allocation exclusion segment-pair witness");
        let exclusion_circuit =
            real_zk::AllocationExclusionSegmentPairCircuit::<1, 1>::from_statement_and_witness(
                &exclusion_statement,
                exclusion_witness,
            )
            .expect("allocation exclusion segment-pair circuit");
        let exclusion_setup = real_zk::setup_allocation_exclusion_segment_pair(&exclusion_circuit)
            .expect("allocation exclusion Groth16 setup");
        let exclusion_proof = real_zk::prove_allocation_exclusion_segment_pair(
            &exclusion_setup.pk,
            exclusion_circuit.clone(),
        )
        .expect("allocation exclusion Groth16 proof");
        let exclusion_public_fr = real_zk::allocation_exclusion_segment_pair_public_inputs_as_fr(
            &exclusion_circuit.public_inputs,
        );
        assert!(
            real_zk::verify(&exclusion_setup.vk, &exclusion_public_fr, &exclusion_proof,)
                .expect("allocation exclusion Groth16 verify"),
            "allocation exclusion proof must verify against the live native spent/new segments"
        );
        let exclusion_stack = real_zk::allocation_exclusion_segment_pair_groth16_precompile_stack(
            &exclusion_setup.vk,
            &exclusion_proof,
            &exclusion_circuit.public_inputs,
        )
        .expect("allocation exclusion Toccata Groth16 precompile stack");
        eprintln!(
            "live: allocation exclusion segment-pair Groth16 proof verified spent_segments=1 new_segments=1 pair_grid=1 public_inputs={} vk_bytes={} proof_bytes={} spent_root=0x{} new_root=0x{} spent_amount_commitment=0x{} new_amount_commitment=0x{}",
            exclusion_stack.public_input_count(),
            exclusion_stack.verifying_key.len(),
            exclusion_stack.proof.len(),
            to_hex(&exclusion_statement.spent_next_root),
            to_hex(&exclusion_statement.new_next_root),
            to_hex(&exclusion_statement.spent_amount_commitment),
            to_hex(&exclusion_statement.new_amount_commitment)
        );
        let spent_transcript_statements = [spent_transcript_statement.clone()];
        let new_transcript_statements = [new_transcript_statement.clone()];
        let spent_conservation_statements = [spent_conservation_statement.clone()];
        let new_conservation_statements = [new_conservation_statement.clone()];
        let exclusion_statements = [exclusion_statement.clone()];
        let allocation_audit_bundle = real_zk::AllocationAuditBundle {
            spent_transcripts: &spent_transcript_statements,
            new_transcripts: &new_transcript_statements,
            spent_conservation: &spent_conservation_statements,
            new_conservation: &new_conservation_statements,
            final_conservation: &conservation_final_statement,
            exclusions: &exclusion_statements,
        };
        let allocation_audit_report =
            real_zk::verify_allocation_audit_bundle(&allocation_audit_bundle)
                .expect("allocation audit bundle verification");
        eprintln!(
            "live: allocation audit bundle verified spent_segments={} new_segments={} exclusion_pairs={} spent_final_root=0x{} new_final_root=0x{} spent_total_commitment=0x{} new_total_commitment=0x{}",
            allocation_audit_report.spent_segments,
            allocation_audit_report.new_segments,
            allocation_audit_report.exclusion_pairs,
            to_hex(&allocation_audit_report.spent_final_root),
            to_hex(&allocation_audit_report.new_final_root),
            to_hex(&allocation_audit_report.spent_total_commitment),
            to_hex(&allocation_audit_report.new_total_commitment)
        );
        let spent_transcript_stacks = [spent_transcript_stack.clone()];
        let new_transcript_stacks = [new_transcript_stack.clone()];
        let spent_conservation_stacks = [spent_conservation_stack.clone()];
        let new_conservation_stacks = [new_conservation_stack.clone()];
        let exclusion_stacks = [exclusion_stack.clone()];
        let allocation_audit_stacks = real_zk::AllocationAuditBundleStacks {
            spent_transcripts: &spent_transcript_stacks,
            new_transcripts: &new_transcript_stacks,
            spent_conservation: &spent_conservation_stacks,
            new_conservation: &new_conservation_stacks,
            final_conservation: &conservation_final_stack,
            exclusions: &exclusion_stacks,
        };
        let allocation_audit_certificate = real_zk::build_allocation_audit_certificate(
            &allocation_audit_bundle,
            &allocation_audit_stacks,
        )
        .expect("allocation audit certificate");
        let allocation_audit_certificate_report = real_zk::verify_allocation_audit_certificate(
            &allocation_audit_certificate,
            &allocation_audit_bundle,
        )
        .expect("allocation audit certificate verification");
        assert_eq!(allocation_audit_certificate_report, allocation_audit_report);
        let allocation_audit_certificate_bytes = allocation_audit_certificate
            .encode_canonical()
            .expect("encode allocation audit certificate");
        let (decoded_allocation_audit_certificate, decoded_allocation_audit_certificate_report) =
            real_zk::verify_allocation_audit_certificate_canonical::<1, 1>(
                &allocation_audit_certificate_bytes,
            )
            .expect("canonical self-contained allocation audit certificate verification");
        assert_eq!(
            decoded_allocation_audit_certificate,
            allocation_audit_certificate
        );
        assert_eq!(
            decoded_allocation_audit_certificate_report,
            allocation_audit_report
        );
        eprintln!(
            "live: allocation audit certificate self-contained verified certificate_id=0x{} proof_entries={} canonical_bytes={}",
            to_hex(&decoded_allocation_audit_certificate.certificate_id),
            decoded_allocation_audit_certificate.proof_entry_count(),
            allocation_audit_certificate_bytes.len()
        );
        allocation_audit_certificate_record = Some(
            AllocationAuditCertificateRecord::new(
                allocation_audit_certificate.certificate_id,
                allocation_audit_certificate_bytes.clone(),
            )
            .expect("allocation audit certificate indexer record"),
        );
        eprintln!(
            "live: allocation audit certificate verified certificate_id=0x{} proof_entries={} vk_bytes_total={} proof_bytes_total={} canonical_bytes={}",
            to_hex(&allocation_audit_certificate.certificate_id),
            allocation_audit_certificate.proof_entry_count(),
            allocation_audit_certificate.total_verifying_key_bytes(),
            allocation_audit_certificate.total_proof_bytes(),
            allocation_audit_certificate_bytes.len()
        );
    }

    // ----- Step 11: Discover the confirmed covenant-script spend through the live chain.
    let spent_outpoint_bytes = outpoint_to_bytes(&covenant_outpoint);
    #[cfg(not(feature = "persistent-indexer"))]
    let (advanced_cursor, added_chain_blocks, observed_spends) = {
        if config.local_mining {
            let scan = backend
                .scan_virtual_chain_from_block(pre_confirmation_cursor.block_hash, None)
                .expect("scan virtual chain for confirmed covenant transaction");
            let advanced_cursor = ScanCursor {
                chain_id: config.chain_id,
                block_hash: *scan
                    .added_chain_block_hashes
                    .last()
                    .expect("non-empty added chain blocks"),
                daa_score: scan
                    .last_added_daa_score
                    .expect("scan should report last added DAA score"),
            };
            (
                advanced_cursor,
                scan.added_chain_block_hashes.len(),
                scan.observed_spends,
            )
        } else {
            let advanced_dag = client
                .get_block_dag_info()
                .await
                .expect("get public testnet DAG tip after confirmations");
            let advanced_cursor = ScanCursor {
                chain_id: config.chain_id,
                block_hash: advanced_dag.sink.as_bytes(),
                daa_score: advanced_dag.virtual_daa_score,
            };
            backend.record_spend(
                outpoint_to_bytes(&funding_outpoint),
                SpendingInfo {
                    txid: covenant_id_hash_to_bytes(covenant_txid),
                    input_index: 0,
                    block_daa_score: Some(covenant_block_daa),
                },
            );
            backend.record_spend(
                spent_outpoint_bytes,
                SpendingInfo {
                    txid: covenant_id_hash_to_bytes(continuation_txid),
                    input_index: 0,
                    block_daa_score: Some(continuation_block_daa),
                },
            );
            eprintln!(
                "live: public staging spend evidence recorded directly funding_spend_txid=0x{} covenant_spend_txid=0x{} cursor_daa={} observed_spends=2",
                to_hex(&covenant_id_hash_to_bytes(covenant_txid)),
                to_hex(&covenant_id_hash_to_bytes(continuation_txid)),
                advanced_cursor.daa_score
            );
            (advanced_cursor, 1, 2)
        }
    };
    #[cfg(feature = "persistent-indexer")]
    let (advanced_cursor, added_chain_blocks, observed_spends) = {
        if config.local_mining {
            let mut cursor_indexer = SledIndexer::open_path(&persistent_indexer_path)
                .expect("reopen cursor store for ScanService tick");
            let mut scan_service = ScanService::new(
                &backend,
                &mut cursor_indexer,
                ScanServiceConfig::new(config.chain_id),
            );
            let tick = scan_service
                .tick()
                .expect("scan confirmed covenant transaction through ScanService");
            assert!(!tick.initialised_cursor);
            drop(scan_service);
            cursor_indexer.flush().expect("flush advanced cursor");
            drop(cursor_indexer);

            let cursor_indexer = SledIndexer::open_path(&persistent_indexer_path)
                .expect("reopen advanced cursor store");
            assert_eq!(
                cursor_indexer
                    .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                    .expect("load advanced scan cursor"),
                Some(tick.end_cursor.clone()),
                "advanced scan cursor must survive a sled reopen"
            );
            (
                tick.end_cursor,
                tick.added_chain_blocks,
                tick.observed_spends,
            )
        } else {
            let advanced_dag = client
                .get_block_dag_info()
                .await
                .expect("get public testnet DAG tip after confirmations");
            let advanced_cursor = ScanCursor {
                chain_id: config.chain_id,
                block_hash: advanced_dag.sink.as_bytes(),
                daa_score: advanced_dag.virtual_daa_score,
            };
            backend.record_spend(
                outpoint_to_bytes(&funding_outpoint),
                SpendingInfo {
                    txid: covenant_id_hash_to_bytes(covenant_txid),
                    input_index: 0,
                    block_daa_score: Some(covenant_block_daa),
                },
            );
            backend.record_spend(
                spent_outpoint_bytes,
                SpendingInfo {
                    txid: covenant_id_hash_to_bytes(continuation_txid),
                    input_index: 0,
                    block_daa_score: Some(continuation_block_daa),
                },
            );

            let mut cursor_indexer = SledIndexer::open_path(&persistent_indexer_path)
                .expect("reopen cursor store for public staging cursor advance");
            cursor_indexer
                .store_scan_cursor(DEFAULT_SCAN_CURSOR, advanced_cursor.clone())
                .expect("store public staging advanced cursor");
            cursor_indexer
                .flush()
                .expect("flush public staging advanced cursor");
            drop(cursor_indexer);

            let cursor_indexer = SledIndexer::open_path(&persistent_indexer_path)
                .expect("reopen public staging advanced cursor store");
            assert_eq!(
                cursor_indexer
                    .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                    .expect("load public staging advanced cursor"),
                Some(advanced_cursor.clone()),
                "public staging advanced cursor must survive a sled reopen"
            );
            eprintln!(
                "live: public staging spend evidence recorded directly funding_spend_txid=0x{} covenant_spend_txid=0x{} cursor_daa={} observed_spends=2",
                to_hex(&covenant_id_hash_to_bytes(covenant_txid)),
                to_hex(&covenant_id_hash_to_bytes(continuation_txid)),
                advanced_cursor.daa_score
            );
            (advanced_cursor, 1, 2)
        }
    };
    if config.local_mining {
        assert_eq!(advanced_cursor.daa_score, continuation_block_daa);
    } else {
        assert!(
            advanced_cursor.daa_score >= continuation_block_daa,
            "public staging scan cursor must reach at least the continuation block DAA"
        );
    }
    assert!(
        added_chain_blocks > 0,
        "confirmation scan should discover at least one added chain block"
    );
    assert!(
        observed_spends >= 2,
        "confirmation scan should observe the funding spend and the covenant-script spend"
    );
    let observed_spend = backend
        .observed_spend(spent_outpoint_bytes)
        .expect("virtual-chain scan should observe the spent covenant outpoint");
    assert_eq!(
        observed_spend.txid,
        covenant_id_hash_to_bytes(continuation_txid),
        "observed spend must point to the confirmed covenant-script transaction"
    );
    assert_eq!(
        observed_spend.block_daa_score,
        Some(continuation_block_daa),
        "observed spend must carry the accepting block DAA score"
    );

    // ----- Step 12: Set up the reusable indexer and resolver.
    let verified_receipt_id = ReceiptVerifier::verify_local(
        &receipt_bytes,
        covenant_id_bytes,
        &old_state,
        config.chain_id,
    )
    .expect("live receipt verify");
    assert_eq!(verified_receipt_id, receipt_id);

    #[cfg(not(feature = "persistent-indexer"))]
    let mut indexer = InMemoryIndexer::new();
    #[cfg(feature = "persistent-indexer")]
    let mut indexer =
        SledIndexer::open_path(&persistent_indexer_path).expect("reopen persistent indexer");
    indexer
        .open(
            config.chain_id,
            covenant_id_bytes,
            [0u8; 32],
            old_state.clone(),
            spent_outpoint_bytes,
            covenant_block_daa,
        )
        .expect("indexer.open");
    indexer
        .apply_spend_with_continuation(
            covenant_id_bytes,
            receipt_id,
            spent_outpoint_bytes,
            new_outpoint_bytes,
            final_native_state.clone(),
            continuation_block_daa,
            ContinuationProof {
                commitment: native_transition_report.continuation_commitment.0,
                shape_root: native_transition_report.continuation_shape_root.0,
                transition_digest: native_transition_report.transition_digest.0,
            },
        )
        .expect("indexer.apply_spend");
    #[cfg(feature = "real-zk")]
    let allocation_audit_certificate_record =
        allocation_audit_certificate_record.expect("real-zk allocation audit certificate record");
    #[cfg(feature = "real-zk")]
    {
        indexer
            .record_allocation_audit_certificate(
                covenant_id_bytes,
                receipt_id,
                allocation_audit_certificate_record.clone(),
            )
            .expect("indexer.record_allocation_audit_certificate");
        assert_eq!(
            indexer.allocation_audit_certificate(covenant_id_bytes, receipt_id),
            Some(allocation_audit_certificate_record.clone())
        );
        eprintln!(
            "live: allocation audit certificate indexed certificate_id=0x{} canonical_bytes={}",
            to_hex(&allocation_audit_certificate_record.certificate_id),
            allocation_audit_certificate_record.canonical_len()
        );
    }
    let live_view_key = [0x41; 32];
    let live_scan_tag = RgkScanTag::derive(live_view_key, native_transition_report.lane_id, 0);
    indexer
        .register_lane(IndexedLane {
            chain_id: config.chain_id,
            covenant_id: covenant_id_bytes,
            asset_id,
            lane_id: native_transition_report.lane_id,
            epoch: 0,
            scan_tag: Some(live_scan_tag.0),
            public_lineage: false,
            state_digest: final_native_state.state_digest,
            last_update_daa_score: continuation_block_daa,
        })
        .expect("indexer.register_lane");
    eprintln!(
        "live: registered private lane for view-key discovery (lane_id=0x{} scan_tag=0x{} privacy_policy={:?})",
        to_hex(&native_transition_report.lane_id),
        to_hex(&live_scan_tag.0),
        native_transition_report.privacy_policy
    );

    #[cfg(feature = "real-zk")]
    {
        let lane_discovery_witness = real_zk::LaneDiscoveryWitness {
            view_key: live_view_key,
            asset_id,
        };
        let lane_discovery_statement = real_zk::LaneDiscoveryStatement {
            lane_id: native_transition_report.lane_id,
            scan_tag: live_scan_tag.0,
            epoch: 0,
        };
        assert!(
            lane_discovery_statement.matches_witness(&lane_discovery_witness),
            "live lane-discovery statement must match native view-key derivation"
        );
        let lane_discovery_circuit = real_zk::LaneDiscoveryCircuit::from_statement_and_witness(
            &lane_discovery_statement,
            lane_discovery_witness.clone(),
        )
        .expect("lane discovery circuit");
        let lane_discovery_setup = real_zk::setup_lane_discovery(&lane_discovery_circuit)
            .expect("lane discovery Groth16 setup");
        let lane_discovery_proof =
            real_zk::prove_lane_discovery(&lane_discovery_setup.pk, lane_discovery_circuit.clone())
                .expect("lane discovery Groth16 proof");
        let lane_discovery_public_fr =
            real_zk::lane_discovery_public_inputs_as_fr(&lane_discovery_circuit.public_inputs);
        assert!(
            real_zk::verify(
                &lane_discovery_setup.vk,
                &lane_discovery_public_fr,
                &lane_discovery_proof,
            )
            .expect("lane discovery Groth16 verify"),
            "lane-discovery Groth16 proof must verify against the live private lane statement"
        );
        let lane_discovery_stack = real_zk::lane_discovery_groth16_precompile_stack(
            &lane_discovery_setup.vk,
            &lane_discovery_proof,
            &lane_discovery_circuit.public_inputs,
        )
        .expect("lane discovery Toccata Groth16 precompile stack");
        eprintln!(
            "live: lane-discovery Groth16 proof verified public_inputs={} vk_bytes={} proof_bytes={} lane_id=0x{} scan_tag=0x{}",
            lane_discovery_stack.public_input_count(),
            lane_discovery_stack.verifying_key.len(),
            lane_discovery_stack.proof.len(),
            to_hex(&native_transition_report.lane_id),
            to_hex(&live_scan_tag.0)
        );

        let lane_graph_statement = real_zk::LaneGraphDiscoveryStatement::<2>::from_private(
            live_view_key,
            asset_id,
            [0, 1],
        );
        assert_eq!(
            lane_graph_statement.nodes[0].lane_id, native_transition_report.lane_id,
            "live lane-graph proof must include the registered current lane"
        );
        assert_eq!(
            lane_graph_statement.nodes[0].scan_tag, live_scan_tag.0,
            "live lane-graph proof must include the registered current scan tag"
        );
        assert!(
            lane_graph_statement.matches_witness(&lane_discovery_witness),
            "live lane-graph statement must match native view-key derivation"
        );
        let lane_graph_circuit =
            real_zk::LaneGraphDiscoveryCircuit::<2>::from_statement_and_witness(
                &lane_graph_statement,
                lane_discovery_witness.clone(),
            )
            .expect("lane graph discovery circuit");
        let lane_graph_setup = real_zk::setup_lane_graph_discovery(&lane_graph_circuit)
            .expect("lane graph discovery Groth16 setup");
        let lane_graph_proof =
            real_zk::prove_lane_graph_discovery(&lane_graph_setup.pk, lane_graph_circuit.clone())
                .expect("lane graph discovery Groth16 proof");
        let lane_graph_public_fr =
            real_zk::lane_graph_discovery_public_inputs_as_fr(&lane_graph_circuit.public_inputs);
        assert!(
            real_zk::verify(
                &lane_graph_setup.vk,
                &lane_graph_public_fr,
                &lane_graph_proof,
            )
            .expect("lane graph discovery Groth16 verify"),
            "lane-graph discovery Groth16 proof must verify against the live private lane graph"
        );
        let lane_graph_stack = real_zk::lane_graph_discovery_groth16_precompile_stack(
            &lane_graph_setup.vk,
            &lane_graph_proof,
            &lane_graph_circuit.public_inputs,
        )
        .expect("lane graph discovery Toccata Groth16 precompile stack");
        eprintln!(
            "live: lane-graph Groth16 proof verified nodes=2 public_inputs={} vk_bytes={} proof_bytes={} graph_root=0x{} current_lane=0x{} next_scan_tag=0x{}",
            lane_graph_stack.public_input_count(),
            lane_graph_stack.verifying_key.len(),
            lane_graph_stack.proof.len(),
            to_hex(&lane_graph_statement.graph_root),
            to_hex(&lane_graph_statement.nodes[0].lane_id),
            to_hex(&lane_graph_statement.nodes[1].scan_tag)
        );

        let first_segment_statement = real_zk::LaneGraphSegmentStatement::<2>::from_private(
            live_view_key,
            asset_id,
            private_lane_graph_empty_root(),
            0,
            [0, 1],
        );
        let second_segment_statement = real_zk::LaneGraphSegmentStatement::<2>::from_private(
            live_view_key,
            asset_id,
            first_segment_statement.next_root,
            1,
            [2, 3],
        );
        assert_eq!(
            first_segment_statement.nodes[0].lane_id, native_transition_report.lane_id,
            "live lane-graph segment chain must start from the registered current lane"
        );
        assert_eq!(
            first_segment_statement.nodes[0].scan_tag, live_scan_tag.0,
            "live lane-graph segment chain must start from the registered scan tag"
        );
        assert!(
            first_segment_statement.matches_witness(&lane_discovery_witness)
                && second_segment_statement.matches_witness(&lane_discovery_witness),
            "live lane-graph segment statements must match native view-key derivation"
        );
        let first_segment_circuit =
            real_zk::LaneGraphSegmentCircuit::<2>::from_statement_and_witness(
                &first_segment_statement,
                lane_discovery_witness.clone(),
            )
            .expect("first lane graph segment circuit");
        let second_segment_circuit =
            real_zk::LaneGraphSegmentCircuit::<2>::from_statement_and_witness(
                &second_segment_statement,
                lane_discovery_witness,
            )
            .expect("second lane graph segment circuit");
        let segment_setup = real_zk::setup_lane_graph_segment(&first_segment_circuit)
            .expect("lane graph segment Groth16 setup");
        let first_segment_proof =
            real_zk::prove_lane_graph_segment(&segment_setup.pk, first_segment_circuit.clone())
                .expect("first lane graph segment Groth16 proof");
        let second_segment_proof =
            real_zk::prove_lane_graph_segment(&segment_setup.pk, second_segment_circuit.clone())
                .expect("second lane graph segment Groth16 proof");
        let first_segment_public_fr =
            real_zk::lane_graph_segment_public_inputs_as_fr(&first_segment_circuit.public_inputs);
        let second_segment_public_fr =
            real_zk::lane_graph_segment_public_inputs_as_fr(&second_segment_circuit.public_inputs);
        assert!(
            real_zk::verify(
                &segment_setup.vk,
                &first_segment_public_fr,
                &first_segment_proof,
            )
            .expect("first lane graph segment Groth16 verify"),
            "first lane-graph segment proof must verify"
        );
        assert!(
            real_zk::verify(
                &segment_setup.vk,
                &second_segment_public_fr,
                &second_segment_proof,
            )
            .expect("second lane graph segment Groth16 verify"),
            "second lane-graph segment proof must verify"
        );
        let first_segment_stack = real_zk::lane_graph_segment_groth16_precompile_stack(
            &segment_setup.vk,
            &first_segment_proof,
            &first_segment_circuit.public_inputs,
        )
        .expect("lane graph segment Toccata Groth16 precompile stack");
        eprintln!(
            "live: segmented lane-graph Groth16 proof chain verified segments=2 nodes=4 public_inputs_each={} vk_bytes={} proof_bytes_each={} start_root=0x{} final_root=0x{} current_lane=0x{} final_scan_tag=0x{}",
            first_segment_stack.public_input_count(),
            first_segment_stack.verifying_key.len(),
            first_segment_stack.proof.len(),
            to_hex(&first_segment_statement.previous_root),
            to_hex(&second_segment_statement.next_root),
            to_hex(&first_segment_statement.nodes[0].lane_id),
            to_hex(&second_segment_statement.nodes[1].scan_tag)
        );
    }

    // ----- Step 13: Run the resolver and assert NativeTransitionedValid.
    {
        let mut resolver = RgkResolver::new(&backend, &mut indexer, config.chain_id);
        resolver.reorg_safety_depth = 1; // local live harness doesn't mine 10 blocks per test
        let state = resolver.resolve_by_covenant(covenant_id_bytes);
        eprintln!("live: resolver state = {state:?}");
        match &state {
            ResolverState::NativeTransitionedValid {
                new_state,
                allocation_audit_certificate,
                ..
            } => {
                assert_eq!(
                    new_state.state_digest, final_native_state.state_digest,
                    "resolver must carry the phase-2 native transition state digest"
                );
                #[cfg(feature = "real-zk")]
                assert_eq!(
                    allocation_audit_certificate,
                    &Some(allocation_audit_certificate_record.clone()),
                    "resolver must expose the indexed allocation audit certificate"
                );
                #[cfg(not(feature = "real-zk"))]
                let _ = allocation_audit_certificate;
                eprintln!(
                    "live: resolver carried phase-2 native state digest = 0x{}",
                    to_hex(&new_state.state_digest)
                );
            }
            other => panic!(
                "resolver should classify the confirmed covenant transition as NativeTransitionedValid; got {other:?}"
            ),
        }
        let lane_state = resolver.resolve_by_view_key(live_view_key, asset_id, 0);
        match lane_state {
            LaneResolverState::Resolved { lane, state } => {
                assert_eq!(lane.lane_id, native_transition_report.lane_id);
                assert_eq!(lane.scan_tag, Some(live_scan_tag.0));
                assert_eq!(
                    lane.state_digest, final_native_state.state_digest,
                    "lane resolver must expose the phase-2 native state digest"
                );
                assert!(
                    matches!(*state, ResolverState::NativeTransitionedValid { .. }),
                    "view-key lane resolver should classify the confirmed private lane as NativeTransitionedValid; got {state:?}"
                );
                eprintln!(
                    "live: view-key lane resolver classified as NativeTransitionedValid (lane_id=0x{} scan_tag=0x{})",
                    to_hex(&lane.lane_id),
                    to_hex(&live_scan_tag.0)
                );
            }
            other => panic!(
                "view-key lane resolver should discover the registered private lane; got {other:?}"
            ),
        }
    }

    eprintln!(
        "live: covenant transition classified as NativeTransitionedValid \
         from the confirmed live Kaspa Toccata {} spend (covenant_id={:02x?})",
        config.name, covenant_id_bytes
    );

    #[cfg(feature = "persistent-indexer")]
    {
        let migration_indexer_path = persistent_indexer_path.with_extension("policy-migration");
        let _ = std::fs::remove_dir_all(&migration_indexer_path);
        let migration_previous_policy = ReceiptPolicy::VerifierOnly;
        let migration_new_policy = ReceiptPolicy::ZkOrVerifier;
        let migration_previous_state = RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: config.chain_id,
            covenant_id: covenant_id_bytes,
            asset_id,
            state_digest: initial_state_digest,
            receipt_policy: migration_previous_policy,
        };
        let migration_final_state = RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: config.chain_id,
            covenant_id: covenant_id_bytes,
            asset_id,
            state_digest: final_native_state.state_digest,
            receipt_policy: migration_new_policy,
        };
        let migration_authorization_commitment = sha256_digest(&[
            b"rgk:live-policy-migration-auth",
            &covenant_id_bytes,
            &native_transition_report.transition_digest.0,
        ]);
        let policy_migration = PolicyMigrationInput {
            previous_policy: migration_previous_policy,
            new_policy: migration_new_policy,
            previous_state_digest: migration_previous_state.state_digest,
            new_state_digest: migration_final_state.state_digest,
            transition_digest: native_transition_report.transition_digest.0,
            authorization_commitment: migration_authorization_commitment,
        }
        .build();
        {
            let mut migration_indexer =
                SledIndexer::open_path(&migration_indexer_path).expect("open migration indexer");
            migration_indexer
                .open(
                    config.chain_id,
                    covenant_id_bytes,
                    lineage_id,
                    migration_previous_state,
                    spent_outpoint_bytes,
                    covenant_block_daa,
                )
                .expect("open live migration covenant");
            migration_indexer
                .apply_spend_with_continuation_and_policy_migration(
                    covenant_id_bytes,
                    policy_migration.migration_commitment,
                    spent_outpoint_bytes,
                    new_outpoint_bytes,
                    migration_final_state.clone(),
                    continuation_block_daa,
                    ContinuationProof {
                        commitment: native_transition_report.continuation_commitment.0,
                        shape_root: native_transition_report.continuation_shape_root.0,
                        transition_digest: native_transition_report.transition_digest.0,
                    },
                    policy_migration,
                )
                .expect("apply live policy migration spend");
            migration_indexer.flush().expect("flush migration indexer");
        }
        let mut migration_indexer =
            SledIndexer::open_path(&migration_indexer_path).expect("reopen live migration indexer");
        let stored_migration = migration_indexer
            .lookup(covenant_id_bytes)
            .and_then(|entry| entry.spend_history.last().cloned())
            .and_then(|spend| spend.policy_migration)
            .expect("policy migration proof must survive Sled reopen");
        assert_eq!(
            stored_migration, policy_migration,
            "stored live policy migration proof changed after reopen"
        );
        {
            let mut migration_resolver =
                RgkResolver::new(&backend, &mut migration_indexer, config.chain_id);
            migration_resolver.reorg_safety_depth = 1;
            let migration_state = migration_resolver.resolve_by_covenant(covenant_id_bytes);
            match migration_state {
                ResolverState::NativeTransitionedValid { new_state, .. } => {
                    assert_eq!(new_state.receipt_policy, migration_new_policy);
                    assert_eq!(new_state.state_digest, migration_final_state.state_digest);
                    eprintln!(
                        "live: policy migration proof recovered after Sled reopen (previous_policy={} new_policy={} migration=0x{} state_digest=0x{} resolver=NativeTransitionedValid)",
                        migration_previous_policy.as_domain_str(),
                        migration_new_policy.as_domain_str(),
                        to_hex(&policy_migration.migration_commitment),
                        to_hex(&migration_final_state.state_digest)
                    );
                }
                other => panic!(
                    "live policy migration resolver should classify as NativeTransitionedValid; got {other:?}"
                ),
            }
        }
        drop(migration_indexer);
        let _ = std::fs::remove_dir_all(&migration_indexer_path);
    }

    #[cfg(feature = "persistent-indexer")]
    {
        indexer.flush().expect("flush persistent live indexer");
        drop(indexer);
        let indexer = SledIndexer::open_path(&persistent_indexer_path)
            .expect("reopen final persistent indexer");
        assert_eq!(
            indexer
                .load_scan_cursor(DEFAULT_SCAN_CURSOR)
                .expect("load final scan cursor"),
            Some(advanced_cursor.clone()),
            "final scan cursor should remain durable after resolver indexing"
        );
        assert!(
            indexer.lookup(covenant_id_bytes).is_some(),
            "persistent live indexer should recover the indexed covenant after reopen"
        );
        #[cfg(feature = "real-zk")]
        {
            let recovered_certificate = indexer
                .allocation_audit_certificate(covenant_id_bytes, receipt_id)
                .expect("recover allocation audit certificate after sled reopen");
            assert_eq!(recovered_certificate, allocation_audit_certificate_record);
            eprintln!(
                "live: persistent allocation audit certificate recovered certificate_id=0x{} canonical_bytes={}",
                to_hex(&recovered_certificate.certificate_id),
                recovered_certificate.canonical_len()
            );
        }
        eprintln!(
            "live: persistent indexer recovered covenant after resolver indexing (covenant_id={:02x?} cursor_daa={})",
            covenant_id_bytes, advanced_cursor.daa_score
        );
        let _ = std::fs::remove_dir_all(&persistent_indexer_path);
    }

    // Suppress unused-binding warning for bytes_to_outpoint helper; this
    // live path does not need to convert witness bytes back to an outpoint.
    let _ = bytes_to_outpoint;
}

// ============================================================
// Local helpers for converting Hash to/from [u8; 32]
// ============================================================

fn covenant_id_hash_to_bytes(h: Hash) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.as_bytes());
    out
}
