#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-e2e
//!
//! End-to-end harness for RGK. Two modes:
//!
//! * **Fixture mode** (default in `cargo test`): a self-contained flow that
//!   exercises every crate's boundary without a live Kaspa node. Used by
//!   CI; always available; deterministic.
//!
//! * **Live mode** lives in the dedicated wRPC tests:
//!   `cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant`.
//!   Set `RGK_LIVE_KASPA_URL` to a Toccata wRPC endpoint. The generic library
//!   harness remains fixture-oriented because live transaction construction
//!   uses typed upstream Kaspa RPC objects.
//!
//! The flow mirrors the brief exactly:
//!
//! 1. create / fund a covenant UTXO (genesis)
//! 2. issue a native RGK asset state
//! 3. bind the native state digest to the covenant
//! 4. perform a native RGK transition
//! 5. build a RGK receipt
//! 6. spend the old covenant UTXO, enforce output shape + new state
//! 7. create the new covenant UTXO
//! 8. confirm / index
//! 9. resolver verifies state
//! 10. resolver verifies native state
//! 11. print deterministic success summary

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code, unused_imports, unused_variables)]
#![allow(clippy::needless_borrows_for_generic_args, clippy::vec_init_then_push)]
#![allow(
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::derivable_impls
)]

use rgk_asset::native::{
    BlindedLaneId, LanePrivacyPolicy, RgkAllocation, RgkAssetIssue, RgkContinuationAllocationShape,
    RgkContinuationCommitment, RgkContinuationPlan, RgkContinuationReport,
    RgkContinuationShapeRoot, RgkCovenantAnchor, RgkIssueReport, RgkMetadataCommitment,
    RgkOwnerCommitment, RgkProductionZkTransferPlan, RgkProofPolicy, RgkTransitionReport,
};
use rgk_asset::{domain_hash_domain, RgkScanTag, RgkStateDigest, RGK_FUNGIBLE_ASSET_SCHEMA_ID};
use rgk_core::{
    Bytes32, KaspaChainId, KaspaCovenantId, KaspaOutpoint, PolicyMigrationInput, ProofMode,
    ReceiptPolicy, RgkReceipt, RgkStateCommitment, KASPA_LOCAL_TOCCATA,
};
use rgk_covenant::{
    compute_covenant_id, compute_covenant_id_from_lineage, CovenantSpec, CovenantState,
};
#[cfg(feature = "persistent-indexer")]
use rgk_indexer::SledIndexer;
use rgk_indexer::{ContinuationProof, InMemoryIndexer, IndexedLane, Indexer};
use rgk_kaspa::{FixtureBackend, KaspaChainBackend, KaspaTxSummary, KaspaUtxo};
use rgk_receipt::{ReceiptBuilder, ReceiptInput, ReceiptVerifier};
use rgk_resolver::{LaneResolverState, ResolverState, RgkResolver};
use rgk_tx::spk_from_redeem_script;
use rgk_tx::{build_genesis_output, build_transition_outputs, build_transition_spend, UnsignedTx};
use rgk_zk::SemanticTransitionStatement;
use sha2::{Digest, Sha256};

#[cfg(feature = "live-kaspa-wrpc")]
pub const LIVE_VERIFIER_TRANSITION_FEE: u64 = 4_000_000;
#[cfg(feature = "live-kaspa-wrpc")]
pub const LIVE_ZK_TRANSITION_FEE: u64 = 40_000_000;
#[cfg(feature = "live-kaspa-wrpc")]
pub const LIVE_MIN_CONTINUATION_OUTPUT_VALUE: u64 = 1_000_000;
#[cfg(feature = "live-kaspa-wrpc")]
pub const TESTNET_STAGING_VERIFIER_ONLY_MIN_FUNDING_VALUE: u64 = LIVE_VERIFIER_TRANSITION_FEE
    + LIVE_VERIFIER_TRANSITION_FEE
    + LIVE_MIN_CONTINUATION_OUTPUT_VALUE;
#[cfg(feature = "live-kaspa-wrpc")]
pub const TESTNET_STAGING_REAL_ZK_MIN_FUNDING_VALUE: u64 =
    LIVE_VERIFIER_TRANSITION_FEE + LIVE_ZK_TRANSITION_FEE + LIVE_MIN_CONTINUATION_OUTPUT_VALUE;
#[cfg(feature = "live-kaspa-wrpc")]
pub const TESTNET_STAGING_WALLET_ROLES: [&str; 3] = ["funding", "change", "observer"];

#[cfg(feature = "live-kaspa-wrpc")]
pub fn deterministic_live_staging_keypair(
    address_prefix: kaspa_addresses::Prefix,
) -> (secp256k1::Keypair, kaspa_addresses::Address) {
    let secp = secp256k1::Secp256k1::new();
    let secret_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let sk = secp256k1::SecretKey::from_slice(&secret_bytes).expect("fixed sk");
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
    let payload = keypair.x_only_public_key().0.serialize();
    let address =
        kaspa_addresses::Address::new(address_prefix, kaspa_addresses::Version::PubKey, &payload);
    (keypair, address)
}

#[cfg(feature = "live-kaspa-wrpc")]
fn deterministic_role_keypair(
    address_prefix: kaspa_addresses::Prefix,
    network: &str,
    role: &str,
) -> (secp256k1::Keypair, kaspa_addresses::Address) {
    if role == "funding" {
        return deterministic_live_staging_keypair(address_prefix);
    }

    let secp = secp256k1::Secp256k1::new();
    for nonce in 0u8..=u8::MAX {
        let mut payload = Vec::new();
        payload.extend_from_slice(network.as_bytes());
        payload.push(0);
        payload.extend_from_slice(role.as_bytes());
        payload.push(0);
        payload.push(nonce);
        let secret_bytes = domain_hash_domain("rgk:e2e:testnet-staging-wallet-sk:v1", &payload);
        if let Ok(sk) = secp256k1::SecretKey::from_slice(&secret_bytes) {
            let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
            let address = kaspa_addresses::Address::new(
                address_prefix,
                kaspa_addresses::Version::PubKey,
                &keypair.x_only_public_key().0.serialize(),
            );
            return (keypair, address);
        }
    }
    panic!("deterministic testnet staging role key derivation exhausted");
}

#[cfg(feature = "live-kaspa-wrpc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestnetStagingWallet {
    pub role: &'static str,
    pub address: String,
    pub x_only_public_key: Bytes32,
    pub secret_fingerprint: Bytes32,
    pub required_min_value_real_zk: u64,
    pub required_min_value_verifier_only: u64,
    pub purpose: &'static str,
}

#[cfg(feature = "live-kaspa-wrpc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestnetStagingWalletSet {
    pub network: String,
    pub chain_id: &'static str,
    pub wallets: Vec<TestnetStagingWallet>,
    pub wallet_set_id: Bytes32,
}

#[cfg(feature = "live-kaspa-wrpc")]
impl TestnetStagingWalletSet {
    pub fn new(network: &str) -> Result<Self, String> {
        match network {
            "testnet-10" | "testnet-12" => {}
            other => {
                return Err(format!(
                    "unsupported public testnet network {other}; expected testnet-10 or testnet-12"
                ));
            }
        }

        let wallets = TESTNET_STAGING_WALLET_ROLES
            .into_iter()
            .map(|role| {
                let (keypair, address) =
                    deterministic_role_keypair(kaspa_addresses::Prefix::Testnet, network, role);
                let secret_bytes = keypair.secret_key().secret_bytes();
                let x_only_public_key = keypair.x_only_public_key().0.serialize();
                let secret_fingerprint = domain_hash_domain(
                    "rgk:e2e:testnet-staging-wallet-secret-fingerprint:v1",
                    &secret_bytes,
                );
                let (required_min_value_real_zk, required_min_value_verifier_only, purpose) =
                    match role {
                        "funding" => (
                            TESTNET_STAGING_REAL_ZK_MIN_FUNDING_VALUE,
                            TESTNET_STAGING_VERIFIER_ONLY_MIN_FUNDING_VALUE,
                            "public-testnet-funding",
                        ),
                        "change" => (0, 0, "reserved-change-output-isolation"),
                        "observer" => (0, 0, "observer-reporting-no-funding"),
                        _ => unreachable!("staging wallet role is fixed"),
                    };
                TestnetStagingWallet {
                    role,
                    address: address.to_string(),
                    x_only_public_key,
                    secret_fingerprint,
                    required_min_value_real_zk,
                    required_min_value_verifier_only,
                    purpose,
                }
            })
            .collect::<Vec<_>>();

        let mut payload = Vec::new();
        payload.extend_from_slice(network.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"KaspaTestnet");
        for wallet in &wallets {
            payload.push(0);
            payload.extend_from_slice(wallet.role.as_bytes());
            payload.push(0);
            payload.extend_from_slice(wallet.address.as_bytes());
            payload.push(0);
            payload.extend_from_slice(&wallet.x_only_public_key);
            payload.extend_from_slice(&wallet.secret_fingerprint);
            payload.extend_from_slice(&wallet.required_min_value_real_zk.to_le_bytes());
            payload.extend_from_slice(&wallet.required_min_value_verifier_only.to_le_bytes());
        }
        let wallet_set_id = domain_hash_domain("rgk:e2e:testnet-staging-wallet-set:v1", &payload);

        Ok(Self {
            network: network.to_string(),
            chain_id: "KaspaTestnet",
            wallets,
            wallet_set_id,
        })
    }

    pub fn funding_wallet(&self) -> &TestnetStagingWallet {
        self.wallets
            .iter()
            .find(|wallet| wallet.role == "funding")
            .expect("funding wallet exists")
    }

    pub fn render(&self) -> String {
        use rgk_core::to_hex;
        let mut out = format!(
            "RGK public testnet staging wallet set\nnetwork={}\nchain_id={}\nwallet_set_id=0x{}\nwallet_count={}\n",
            self.network,
            self.chain_id,
            to_hex(&self.wallet_set_id),
            self.wallets.len()
        );
        for wallet in &self.wallets {
            out.push_str(&format!(
                "wallet_role={} address={} xonly=0x{} secret_fingerprint=0x{} required_min_value_real_zk={} required_min_value_verifier_only={} purpose={}\n",
                wallet.role,
                wallet.address,
                to_hex(&wallet.x_only_public_key),
                to_hex(&wallet.secret_fingerprint),
                wallet.required_min_value_real_zk,
                wallet.required_min_value_verifier_only,
                wallet.purpose
            ));
        }
        out
    }
}

#[cfg(feature = "live-kaspa-wrpc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestnetStagingPreflight {
    pub network: String,
    pub chain_id: &'static str,
    pub address: String,
    pub wallet_set_id: Bytes32,
    pub wallet_count: usize,
    pub required_min_value_real_zk: u64,
    pub required_min_value_verifier_only: u64,
    pub required_non_coinbase_utxo: bool,
    pub required_utxo_index: bool,
    pub required_confirmation_depth: u64,
    pub required_live_kaspa_wrpc_feature: bool,
    pub required_real_zk_feature: bool,
    pub required_persistent_indexer_feature: bool,
    pub required_local_mining: bool,
    pub required_live_test: &'static str,
    pub endpoint_env: &'static str,
    pub network_env: &'static str,
    pub staging_script: &'static str,
    pub evidence_verifier: &'static str,
    pub expected_report: &'static str,
    pub preflight_id: Bytes32,
}

#[cfg(feature = "live-kaspa-wrpc")]
impl TestnetStagingPreflight {
    pub fn new(network: &str) -> Result<Self, String> {
        match network {
            "testnet-10" | "testnet-12" => {}
            other => {
                return Err(format!(
                    "unsupported public testnet network {other}; expected testnet-10 or testnet-12"
                ));
            }
        }
        let wallet_set = TestnetStagingWalletSet::new(network)?;
        let address = wallet_set.funding_wallet().address.clone();
        let mut payload = Vec::new();
        payload.extend_from_slice(network.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"KaspaTestnet");
        payload.push(0);
        payload.extend_from_slice(address.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&wallet_set.wallet_set_id);
        payload.extend_from_slice(&(wallet_set.wallets.len() as u64).to_le_bytes());
        payload.extend_from_slice(&TESTNET_STAGING_REAL_ZK_MIN_FUNDING_VALUE.to_le_bytes());
        payload.extend_from_slice(&TESTNET_STAGING_VERIFIER_ONLY_MIN_FUNDING_VALUE.to_le_bytes());
        payload.push(1);
        payload.push(1);
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.push(1);
        payload.push(1);
        payload.push(1);
        payload.push(0);
        payload.extend_from_slice(b"live_toccata_full_covenant_lifecycle");
        let preflight_id = domain_hash_domain("rgk:e2e:testnet-staging-preflight:v1", &payload);
        Ok(Self {
            network: network.to_string(),
            chain_id: "KaspaTestnet",
            address,
            wallet_set_id: wallet_set.wallet_set_id,
            wallet_count: wallet_set.wallets.len(),
            required_min_value_real_zk: TESTNET_STAGING_REAL_ZK_MIN_FUNDING_VALUE,
            required_min_value_verifier_only: TESTNET_STAGING_VERIFIER_ONLY_MIN_FUNDING_VALUE,
            required_non_coinbase_utxo: true,
            required_utxo_index: true,
            required_confirmation_depth: 1,
            required_live_kaspa_wrpc_feature: true,
            required_real_zk_feature: true,
            required_persistent_indexer_feature: true,
            required_local_mining: false,
            required_live_test: "live_toccata_full_covenant_lifecycle",
            endpoint_env: "RGK_LIVE_KASPA_URL",
            network_env: "RGK_LIVE_KASPA_NETWORK",
            staging_script: "scripts/e2e-testnet-staging.sh",
            evidence_verifier: "scripts/verify-testnet-staging-evidence.sh",
            expected_report: "target/rgk-testnet-staging-evidence/latest.txt",
            preflight_id,
        })
    }

    pub fn render(&self) -> String {
        use rgk_core::to_hex;
        format!(
            "RGK public testnet staging preflight\nnetwork={}\nchain_id={}\naddress={}\nscope=testnet-only deterministic staging key\nwallet_set_id=0x{}\nwallet_count={}\nfunding_status=external-funding-required\nrequired_non_coinbase_utxo={}\nrequired_utxo_index={}\nrequired_confirmation_depth={}\nrequired_min_value_real_zk={}\nrequired_min_value_verifier_only={}\nrequired_live_kaspa_wrpc_feature={}\nrequired_real_zk_feature={}\nrequired_persistent_indexer_feature={}\nrequired_local_mining={}\nrequired_live_test={}\nendpoint_env={}\nnetwork_env={}\nstaging_script={}\nevidence_verifier={}\nexpected_report={}\npreflight_id=0x{}\n",
            self.network,
            self.chain_id,
            self.address,
            to_hex(&self.wallet_set_id),
            self.wallet_count,
            self.required_non_coinbase_utxo,
            self.required_utxo_index,
            self.required_confirmation_depth,
            self.required_min_value_real_zk,
            self.required_min_value_verifier_only,
            self.required_live_kaspa_wrpc_feature,
            self.required_real_zk_feature,
            self.required_persistent_indexer_feature,
            self.required_local_mining,
            self.required_live_test,
            self.endpoint_env,
            self.network_env,
            self.staging_script,
            self.evidence_verifier,
            self.expected_report,
            to_hex(&self.preflight_id),
        )
    }
}

fn b32(s: &str) -> [u8; 32] {
    rgk_core::from_hex::<32>(s).expect("hex")
}

/// A typed summary printed at the end of the e2e run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eSummary {
    pub chain: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub lineage_id: Bytes32,
    pub asset_id: Bytes32,
    pub old_state_digest: Bytes32,
    pub new_state_digest: Bytes32,
    pub receipt_id: Bytes32,
    pub proof_mode: ProofMode,
    pub receipt_policy: ReceiptPolicy,
    pub num_transitions: usize,
    pub resolver_state: String,
    pub live_mode: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeAssetTransitionReport {
    pub transition_report: RgkTransitionReport,
    pub continuation_commitment: RgkContinuationCommitment,
    pub continuation_shape_root: RgkContinuationShapeRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMigrationRecoverySummary {
    pub chain: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub spent_outpoint: KaspaOutpoint,
    pub new_outpoint: KaspaOutpoint,
    pub previous_policy: ReceiptPolicy,
    pub new_policy: ReceiptPolicy,
    pub migration_commitment: Bytes32,
    pub resolver_state: String,
}

impl PolicyMigrationRecoverySummary {
    pub fn render(&self) -> String {
        use rgk_core::to_hex;
        format!(
            "RGK policy migration recovery\n  chain:           {:?}\n  covenant:        0x{}\n  spent_txid:      0x{}\n  new_txid:        0x{}\n  previous_policy: {}\n  new_policy:      {}\n  migration:       0x{}\n  resolver:        {}\n",
            self.chain,
            &to_hex(&self.covenant_id),
            &to_hex(&self.spent_outpoint.transaction_id),
            &to_hex(&self.new_outpoint.transaction_id),
            self.previous_policy.as_domain_str(),
            self.new_policy.as_domain_str(),
            &to_hex(&self.migration_commitment),
            self.resolver_state,
        )
    }
}

impl core::ops::Deref for NativeAssetTransitionReport {
    type Target = RgkTransitionReport;

    fn deref(&self) -> &Self::Target {
        &self.transition_report
    }
}

impl E2eSummary {
    pub fn render(&self) -> String {
        use rgk_core::to_hex;
        format!(
            "RGK e2e summary\n  chain:           {:?}\n  covenant:        0x{}\n  lineage:         0x{}\n  asset:           0x{}\n  old_state:       0x{}\n  new_state:       0x{}\n  receipt_id:      0x{}\n  proof_mode:      {}\n  policy:          {}\n  transitions:     {}\n  resolver:        {}\n  live_mode:       {}\n",
            self.chain,
            &to_hex(&self.covenant_id),
            &to_hex(&self.lineage_id),
            &to_hex(&self.asset_id),
            &to_hex(&self.old_state_digest),
            &to_hex(&self.new_state_digest),
            &to_hex(&self.receipt_id),
            self.proof_mode.as_str(),
            self.receipt_policy.as_domain_str(),
            self.num_transitions,
            self.resolver_state,
            self.live_mode,
        )
    }
}

// ---------------- helpers ----------------

fn sha256_digest(input: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(input);
    let out = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

// ---------------- tests ----------------

#[test]
fn fixture_e2e_passes() {
    let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
    // Fixture mode uses the explicit FixtureBackend API. Live submission and
    // signing live in the dedicated wRPC tests.
    let summary = run_e2e_fixture(&mut backend).expect("e2e");
    assert_eq!(summary.chain, KASPA_LOCAL_TOCCATA);
    assert_eq!(summary.proof_mode, ProofMode::VerifierReceipt);
    // The resolver state should be one of the recognised valid states.
    assert!(
        summary.resolver_state.contains("Open")
            || summary.resolver_state.contains("NativeTransitionedValid")
            || summary.resolver_state.contains("ReorgRisk"),
        "unexpected resolver state: {}",
        summary.resolver_state
    );
}

/// Executes the fixture E2E flow through the concrete `FixtureBackend` API.
pub fn run_e2e_fixture(backend: &mut FixtureBackend) -> Result<E2eSummary, String> {
    let chain = KASPA_LOCAL_TOCCATA;
    let net = backend
        .network_id()
        .map_err(|e| format!("network_id: {e}"))?;
    if net != chain {
        return Err(format!("backend on {net:?}, expected {chain:?}"));
    }

    let genesis_covenant_outpoint = KaspaOutpoint {
        transaction_id: b32("abab".repeat(16).as_str()),
        index: 0,
    };
    let asset_id = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    let lineage_id = sha256_digest(b"rgk:lineage:fixture");
    let covenant_id = compute_covenant_id_from_lineage(lineage_id);
    let initial_native_report = native_asset_state_report(
        chain,
        asset_id,
        genesis_covenant_outpoint,
        covenant_id,
        [0x55u8; 32],
        1,
        1,
        1_000_000,
    )?;
    let initial_state_digest = initial_native_report.state_digest.0;
    let state = CovenantState::genesis(
        chain,
        asset_id,
        lineage_id,
        ReceiptPolicy::Any,
        ProofMode::VerifierReceipt,
    );
    let spec = CovenantSpec {
        chain_id: chain,
        lineage_id,
        asset_id,
        initial_state_digest,
        receipt_policy: ReceiptPolicy::Any,
        genesis_proof_mode: ProofMode::VerifierReceipt,
    };
    let redeem_script = spec.build_script().map_err(|e| format!("script: {e}"))?;
    let spk = spk_from_redeem_script(&redeem_script);

    let initial_value: u64 = 1_000_000;
    let _genesis_output = build_genesis_output(&state, spk.clone(), covenant_id, 0, initial_value)
        .map_err(|e| format!("{e}"))?;
    let open_outpoint = genesis_covenant_outpoint;
    backend.add_utxo_at(
        1,
        KaspaUtxo {
            outpoint: open_outpoint,
            value: initial_value,
            script_public_key: spk.clone(),
            block_daa_score: Some(1),
            spending: None,
        },
    );

    let mut idx = InMemoryIndexer::new();
    let initial_rgk_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: chain,
        covenant_id,
        asset_id,
        state_digest: initial_state_digest,
        receipt_policy: ReceiptPolicy::Any,
    };
    idx.open(
        chain,
        covenant_id,
        lineage_id,
        initial_rgk_state.clone(),
        open_outpoint,
        1,
    )
    .map_err(|e| format!("idx.open: {e}"))?;

    let new_outpoint = KaspaOutpoint {
        transaction_id: [0x99u8; 32],
        index: 0,
    };
    let continuation_phase1 = native_asset_continuation_report(
        chain,
        asset_id,
        open_outpoint,
        covenant_id,
        [0x55u8; 32],
        1,
        new_outpoint.index,
        1_000_000,
    )?;
    let native_transition_report = native_asset_transition_report(
        chain,
        asset_id,
        open_outpoint,
        covenant_id,
        [0x55u8; 32],
        1,
        new_outpoint,
        2,
        [0x99u8; 32],
        1_000_000,
    )?;
    let new_state_digest = native_transition_report.new_state_digest.0;

    let new_rgk_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: chain,
        covenant_id,
        asset_id,
        state_digest: new_state_digest,
        receipt_policy: ReceiptPolicy::Any,
    };
    let receipt_input = ReceiptInput {
        chain_id: chain,
        covenant_id,
        old_state: initial_rgk_state.clone(),
        new_state: new_rgk_state.clone(),
        transition_digest: native_transition_report.transition_digest.0,
        continuation_commitment: native_transition_report.continuation_commitment.0,
        proof_mode: ProofMode::VerifierReceipt,
        replay_nonce: sha256_digest(b"rgk:replay-nonce-v1"),
    };
    let (receipt, receipt_id, receipt_bytes) =
        ReceiptBuilder::build(&receipt_input).map_err(|e| format!("ReceiptBuilder: {e:?}"))?;
    let semantic_statement =
        SemanticTransitionStatement::from_reports(&native_transition_report, &continuation_phase1)
            .map_err(|e| format!("SemanticTransitionStatement: {e}"))?;
    if !semantic_statement.matches_receipt(&receipt) {
        return Err("semantic transition statement must match fixture receipt".into());
    }
    if semantic_statement.public_inputs().len() != SemanticTransitionStatement::PUBLIC_INPUT_LEN {
        return Err("semantic transition statement public-input length drifted".into());
    }
    ReceiptVerifier::verify_local(&receipt_bytes, covenant_id, &initial_rgk_state, chain)
        .map_err(|e| format!("ReceiptVerifier: {e:?}"))?;

    let next_state = state
        .advance(new_state_digest, receipt_input.replay_nonce)
        .map_err(|e| format!("state.advance: {e}"))?;
    let new_spk = spk.clone();
    let new_value: u64 = 999_000;
    let outputs = build_transition_outputs(
        &next_state,
        new_spk.clone(),
        new_value,
        covenant_id,
        500,
        0,
        None,
        initial_value,
    )
    .map_err(|e| format!("{e}"))?;
    let tx = UnsignedTx {
        inputs: vec![build_transition_spend(open_outpoint)],
        outputs,
        payload: next_state.encode_payload(),
        lock_time: 0,
    };
    let _tx_bytes = tx.encode_canonical();
    let spend_txid = new_outpoint.transaction_id;
    backend.submit(KaspaTxSummary {
        txid: spend_txid,
        mass: 1,
        payload: tx.payload.clone(),
    });
    backend.spend_at(open_outpoint, 2, spend_txid, 0);
    backend.add_utxo_at(
        2,
        KaspaUtxo {
            outpoint: new_outpoint,
            value: new_value,
            script_public_key: new_spk.clone(),
            block_daa_score: Some(2),
            spending: None,
        },
    );

    idx.apply_spend_with_continuation(
        covenant_id,
        receipt_id,
        open_outpoint,
        new_outpoint,
        new_rgk_state.clone(),
        2,
        ContinuationProof {
            commitment: native_transition_report.continuation_commitment.0,
            shape_root: native_transition_report.continuation_shape_root.0,
            transition_digest: native_transition_report.transition_digest.0,
        },
    )
    .map_err(|e| format!("apply_spend: {e}"))?;

    let fixture_view_key = [0x41; 32];
    let fixture_epoch = 0;
    let lane_scan_tag = RgkScanTag::derive(
        fixture_view_key,
        native_transition_report.lane_id,
        fixture_epoch,
    );
    idx.register_lane(IndexedLane {
        chain_id: chain,
        covenant_id,
        asset_id,
        lane_id: native_transition_report.lane_id,
        epoch: fixture_epoch,
        scan_tag: Some(lane_scan_tag.0),
        public_lineage: false,
        state_digest: new_state_digest,
        last_update_daa_score: 2,
    })
    .map_err(|e| format!("register_lane: {e}"))?;

    backend.set_tip(rgk_kaspa::KaspaTip {
        hash: [9u8; 32],
        blue_score: 100,
        daa_score: 100,
    });
    let mut resolver = RgkResolver::new(backend, &mut idx, chain);
    resolver.reorg_safety_depth = 1;
    let res = resolver.resolve_by_covenant(covenant_id);
    let lane_res = resolver.resolve_by_view_key(fixture_view_key, asset_id, fixture_epoch);
    if !matches!(
        lane_res,
        LaneResolverState::Resolved { ref state, .. }
            if matches!(state.as_ref(), ResolverState::NativeTransitionedValid { .. })
    ) {
        return Err(format!("resolve_by_view_key: {lane_res:?}"));
    }
    let res_str = format!("{:?}", res);

    Ok(E2eSummary {
        chain,
        covenant_id,
        lineage_id,
        asset_id,
        old_state_digest: initial_state_digest,
        new_state_digest,
        receipt_id,
        proof_mode: ProofMode::VerifierReceipt,
        receipt_policy: ReceiptPolicy::Any,
        num_transitions: 1,
        resolver_state: res_str,
        live_mode: false,
    })
}

#[cfg(feature = "persistent-indexer")]
pub fn run_policy_migration_recovery_fixture() -> Result<PolicyMigrationRecoverySummary, String> {
    let chain = KASPA_LOCAL_TOCCATA;
    let asset_id = [0x42u8; 32];
    let lineage_id = sha256_digest(b"rgk:e2e:policy-migration:lineage");
    let covenant_id = compute_covenant_id_from_lineage(lineage_id);
    let spent_outpoint = KaspaOutpoint {
        transaction_id: [0x21u8; 32],
        index: 0,
    };
    let new_outpoint = KaspaOutpoint {
        transaction_id: [0x22u8; 32],
        index: 0,
    };
    let previous_state_digest = [0x31u8; 32];
    let new_state_digest = [0x32u8; 32];
    let transition_digest = [0x33u8; 32];
    let previous_policy = ReceiptPolicy::VerifierOnly;
    let new_policy = ReceiptPolicy::ZkOrVerifier;

    let previous_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: chain,
        covenant_id,
        asset_id,
        state_digest: previous_state_digest,
        receipt_policy: previous_policy,
    };
    let new_state = RgkStateCommitment {
        version: rgk_core::ENCODING_VERSION,
        chain_id: chain,
        covenant_id,
        asset_id,
        state_digest: new_state_digest,
        receipt_policy: new_policy,
    };
    let continuation = ContinuationProof {
        commitment: [0x44u8; 32],
        shape_root: [0x45u8; 32],
        transition_digest,
    };
    let policy_migration = PolicyMigrationInput {
        previous_policy,
        new_policy,
        previous_state_digest,
        new_state_digest,
        transition_digest,
        authorization_commitment: [0x46u8; 32],
    }
    .build();
    let receipt_id = policy_migration.migration_commitment;

    let path = temp_policy_migration_db_path();
    let _ = std::fs::remove_dir_all(&path);
    {
        let mut indexer =
            SledIndexer::open_path(&path).map_err(|e| format!("open sled indexer: {e}"))?;
        indexer
            .open(
                chain,
                covenant_id,
                lineage_id,
                previous_state.clone(),
                spent_outpoint,
                1,
            )
            .map_err(|e| format!("open migration covenant: {e}"))?;
        indexer
            .apply_spend_with_continuation_and_policy_migration(
                covenant_id,
                receipt_id,
                spent_outpoint,
                new_outpoint,
                new_state.clone(),
                2,
                continuation,
                policy_migration,
            )
            .map_err(|e| format!("apply migration spend: {e}"))?;
        indexer
            .flush()
            .map_err(|e| format!("flush migration indexer: {e}"))?;
    }

    let mut backend = FixtureBackend::new(chain);
    backend.add_utxo_at(
        1,
        KaspaUtxo {
            outpoint: spent_outpoint,
            value: 1_000_000,
            script_public_key: vec![0x51],
            block_daa_score: Some(1),
            spending: None,
        },
    );
    backend.submit(KaspaTxSummary {
        txid: new_outpoint.transaction_id,
        mass: 1,
        payload: Vec::new(),
    });
    backend.spend_at(spent_outpoint, 2, new_outpoint.transaction_id, 0);
    backend.add_utxo_at(
        2,
        KaspaUtxo {
            outpoint: new_outpoint,
            value: 999_000,
            script_public_key: vec![0x51],
            block_daa_score: Some(2),
            spending: None,
        },
    );
    backend.set_tip(rgk_kaspa::KaspaTip {
        hash: [0x47u8; 32],
        blue_score: 20,
        daa_score: 20,
    });

    let mut reopened =
        SledIndexer::open_path(&path).map_err(|e| format!("reopen sled indexer: {e}"))?;
    let recovered = reopened
        .lookup(covenant_id)
        .ok_or_else(|| "migration covenant missing after reopen".to_string())?;
    let stored_spend = recovered
        .spend_history
        .last()
        .ok_or_else(|| "migration spend missing after reopen".to_string())?;
    if stored_spend.policy_migration != Some(policy_migration) {
        return Err("stored policy migration proof changed across reopen".into());
    }

    let mut resolver = RgkResolver::new(&backend, &mut reopened, chain);
    resolver.reorg_safety_depth = 1;
    let state = resolver.resolve_by_covenant(covenant_id);
    if !matches!(state, ResolverState::NativeTransitionedValid { .. }) {
        return Err(format!("migration resolver state after reopen: {state:?}"));
    }
    let resolver_state = format!("{state:?}");
    drop(reopened);
    let _ = std::fs::remove_dir_all(&path);

    Ok(PolicyMigrationRecoverySummary {
        chain,
        covenant_id,
        spent_outpoint,
        new_outpoint,
        previous_policy,
        new_policy,
        migration_commitment: policy_migration.migration_commitment,
        resolver_state,
    })
}

#[cfg(feature = "persistent-indexer")]
fn temp_policy_migration_db_path() -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rgk-policy-migration-recovery-{}-{nanos}",
        std::process::id()
    ))
}

#[cfg(feature = "persistent-indexer")]
#[test]
fn policy_migration_recovery_fixture_survives_reopen() {
    let summary = run_policy_migration_recovery_fixture().expect("policy migration recovery");
    eprintln!("{}", summary.render());
    assert_eq!(summary.previous_policy, ReceiptPolicy::VerifierOnly);
    assert_eq!(summary.new_policy, ReceiptPolicy::ZkOrVerifier);
    assert!(summary.resolver_state.contains("NativeTransitionedValid"));
}

#[test]
fn canonical_state_digest_is_deterministic() {
    let outpoint = KaspaOutpoint {
        transaction_id: [0xabu8; 32],
        index: 0,
    };
    let covenant_id = [0xcdu8; 32];
    let asset_id = [0xefu8; 32];
    let d1 = native_asset_state_report(
        KASPA_LOCAL_TOCCATA,
        asset_id,
        outpoint,
        covenant_id,
        [0x77u8; 32],
        2,
        1,
        1_000_000,
    )
    .unwrap()
    .state_digest;
    let d2 = native_asset_state_report(
        KASPA_LOCAL_TOCCATA,
        asset_id,
        outpoint,
        covenant_id,
        [0x77u8; 32],
        2,
        1,
        1_000_000,
    )
    .unwrap()
    .state_digest;
    assert_eq!(d1, d2);
}

#[test]
fn e2e_summary_renders_all_fields() {
    let s = E2eSummary {
        chain: KASPA_LOCAL_TOCCATA,
        covenant_id: [1u8; 32],
        lineage_id: [2u8; 32],
        asset_id: [3u8; 32],
        old_state_digest: [4u8; 32],
        new_state_digest: [5u8; 32],
        receipt_id: [6u8; 32],
        proof_mode: ProofMode::VerifierReceipt,
        receipt_policy: ReceiptPolicy::Any,
        num_transitions: 1,
        resolver_state: "Open".into(),
        live_mode: false,
    };
    let r = s.render();
    assert!(r.contains("RGK e2e summary"));
    assert!(r.contains("covenant"));
    assert!(r.contains("receipt"));
    assert!(r.contains("resolver"));
}

#[cfg(feature = "live-kaspa-wrpc")]
#[test]
fn testnet_staging_wallet_set_is_stable() {
    let wallet_set = TestnetStagingWalletSet::new("testnet-12").unwrap();
    assert_eq!(wallet_set.network, "testnet-12");
    assert_eq!(wallet_set.chain_id, "KaspaTestnet");
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallet_set_id),
        "319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352"
    );
    assert_eq!(wallet_set.wallets.len(), 3);
    assert_eq!(wallet_set.wallets[0].role, "funding");
    assert_eq!(wallet_set.wallets[1].role, "change");
    assert_eq!(wallet_set.wallets[2].role, "observer");
    assert_eq!(
        wallet_set.wallets[0].address,
        "kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald"
    );
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallets[0].x_only_public_key),
        "84bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0"
    );
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallets[0].secret_fingerprint),
        "6ada37542b9cc1154d6c9659fb3e1346d503c342134abe8fdfd5de9878e10bac"
    );
    assert_eq!(
        wallet_set.wallets[1].address,
        "kaspatest:qrvpsckmgwn4cr4jtsm5uls6qe8asmu4gth5rs6tcc3kulhemel557wahjvte"
    );
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallets[1].x_only_public_key),
        "d81862db43a75c0eb25c374e7e1a064fd86f9542ef41c34bc6236e7ef9de7f4a"
    );
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallets[1].secret_fingerprint),
        "b59dd8d084986c234680dfbd907aa1cc770c1c9ba5d506ad8458be1a39129ce2"
    );
    assert_eq!(
        wallet_set.wallets[2].address,
        "kaspatest:qr5vg4qmfypldkrxenn2ruqjq5uh2p2dp63plaanpf0y0z660xt254sg5g833"
    );
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallets[2].x_only_public_key),
        "e8c4541b4903f6d866cce6a1f012053975054d0ea21ff7b30a5e478b5a7996aa"
    );
    assert_eq!(
        rgk_core::to_hex(&wallet_set.wallets[2].secret_fingerprint),
        "3446f807dd9862347162668ef58245a732584fd80c54c8bb0dd8bb9a2df16813"
    );
    assert!(wallet_set
        .wallets
        .iter()
        .all(|wallet| wallet.address.starts_with("kaspatest:")));
    let unique_addresses = wallet_set
        .wallets
        .iter()
        .map(|wallet| wallet.address.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique_addresses.len(), wallet_set.wallets.len());
    assert_eq!(
        wallet_set.funding_wallet().required_min_value_real_zk,
        TESTNET_STAGING_REAL_ZK_MIN_FUNDING_VALUE
    );
    assert_eq!(
        wallet_set.funding_wallet().required_min_value_verifier_only,
        TESTNET_STAGING_VERIFIER_ONLY_MIN_FUNDING_VALUE
    );
    assert_eq!(
        wallet_set.wallets[1].required_min_value_real_zk, 0,
        "change wallet is generated for staging reports, not funding"
    );
    assert_eq!(
        wallet_set.wallets[2].required_min_value_real_zk, 0,
        "observer wallet is generated for staging reports, not funding"
    );

    let rebuilt = TestnetStagingWalletSet::new("testnet-12").unwrap();
    assert_eq!(wallet_set, rebuilt);

    let rendered = wallet_set.render();
    assert!(rendered.contains("RGK public testnet staging wallet set"));
    assert!(rendered.contains("wallet_count=3"));
    assert!(rendered.contains("wallet_role=funding address=kaspatest:"));
    assert!(rendered.contains("wallet_role=change address=kaspatest:"));
    assert!(rendered.contains("wallet_role=observer address=kaspatest:"));
    assert!(!rendered.contains("secret_key="));
    assert!(!rendered.contains("private_key="));
}

#[cfg(feature = "live-kaspa-wrpc")]
#[test]
fn testnet_staging_preflight_manifest_is_stable() {
    let wallet_set = TestnetStagingWalletSet::new("testnet-12").unwrap();
    let preflight = TestnetStagingPreflight::new("testnet-12").unwrap();
    assert_eq!(preflight.network, "testnet-12");
    assert_eq!(preflight.chain_id, "KaspaTestnet");
    assert!(preflight.address.starts_with("kaspatest:"));
    assert_eq!(preflight.address, wallet_set.funding_wallet().address);
    assert_eq!(preflight.wallet_set_id, wallet_set.wallet_set_id);
    assert_eq!(preflight.wallet_count, wallet_set.wallets.len());
    assert_eq!(
        preflight.required_min_value_real_zk,
        TESTNET_STAGING_REAL_ZK_MIN_FUNDING_VALUE
    );
    assert_eq!(
        preflight.required_min_value_verifier_only,
        TESTNET_STAGING_VERIFIER_ONLY_MIN_FUNDING_VALUE
    );
    assert!(preflight.required_non_coinbase_utxo);
    assert!(preflight.required_utxo_index);
    assert_eq!(preflight.required_confirmation_depth, 1);
    assert!(preflight.required_live_kaspa_wrpc_feature);
    assert!(preflight.required_real_zk_feature);
    assert!(preflight.required_persistent_indexer_feature);
    assert!(!preflight.required_local_mining);
    assert_eq!(
        preflight.required_live_test,
        "live_toccata_full_covenant_lifecycle"
    );
    assert_eq!(
        rgk_core::to_hex(&preflight.preflight_id),
        "2c993d20f2726efdb0983868126544163e44c474f4b4ab4cf28901e749c29212"
    );

    let rebuilt = TestnetStagingPreflight::new("testnet-12").unwrap();
    assert_eq!(preflight, rebuilt);

    let rendered = preflight.render();
    assert!(rendered.contains("RGK public testnet staging preflight"));
    assert!(rendered.contains("funding_status=external-funding-required"));
    assert!(rendered.contains("wallet_set_id=0x"));
    assert!(rendered.contains("wallet_count=3"));
    assert!(rendered.contains("required_local_mining=false"));
    assert!(rendered.contains("required_live_test=live_toccata_full_covenant_lifecycle"));
    assert!(rendered.contains("endpoint_env=RGK_LIVE_KASPA_URL"));
    assert!(rendered.contains("preflight_id=0x"));
}

#[cfg(feature = "live-kaspa-wrpc")]
#[test]
fn testnet_staging_preflight_rejects_unsupported_network() {
    let err = TestnetStagingPreflight::new("mainnet").unwrap_err();
    assert!(err.contains("unsupported public testnet network mainnet"));
}

/// Build the current one-allocation native RGK asset validation report used by
/// the e2e harness. The report's digest is threaded into the RGK state
/// commitment so receipts and resolver state carry the same native value that
/// is printed in live evidence.
pub fn native_asset_state_report(
    chain: KaspaChainId,
    asset_id: Bytes32,
    covenant_outpoint: KaspaOutpoint,
    covenant_id: KaspaCovenantId,
    witness_txid: Bytes32,
    daa_score: u64,
    confirmation_depth: u64,
    total_supply: u64,
) -> Result<RgkIssueReport, String> {
    let issue = RgkAssetIssue {
        chain,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        allocations: vec![native_asset_allocation(
            chain,
            asset_id,
            covenant_outpoint,
            covenant_id,
            witness_txid,
            daa_score,
            confirmation_depth,
            total_supply,
        )],
        metadata_commitment: fixture_metadata_commitment(asset_id),
        owner_commitment: fixture_owner_commitment(asset_id),
        lane_id: fixture_lane_id(asset_id),
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: fixture_proof_policy(),
    };
    issue
        .validate_for_production_zk()
        .map_err(|e| format!("native RGK production-ZK asset validation: {e}"))
}

/// Build and validate a one-input/one-output native RGK transition report for
/// fixture-style flows where both outpoints are known before receipt building.
pub fn native_asset_transition_report(
    chain: KaspaChainId,
    asset_id: Bytes32,
    spent_outpoint: KaspaOutpoint,
    covenant_id: KaspaCovenantId,
    spent_witness_txid: Bytes32,
    spent_daa_score: u64,
    new_outpoint: KaspaOutpoint,
    new_daa_score: u64,
    transition_witness_txid: Bytes32,
    total_supply: u64,
) -> Result<NativeAssetTransitionReport, String> {
    let plan = native_asset_continuation_plan(
        chain,
        asset_id,
        spent_outpoint,
        covenant_id,
        spent_witness_txid,
        spent_daa_score,
        new_outpoint.index,
        total_supply,
    )?;
    if new_outpoint.transaction_id != transition_witness_txid {
        return Err(
            "native RGK continuation finalization requires new outpoint txid to equal witness txid"
                .into(),
        );
    }
    let production_zk_plan = RgkProductionZkTransferPlan::new(plan)
        .map_err(|e| format!("native RGK production-ZK transfer planning: {e}"))?;
    let continuation_report = production_zk_plan.continuation_report().clone();
    production_zk_plan
        .finalize(transition_witness_txid, new_daa_score, 1)
        .map(|finalized| NativeAssetTransitionReport {
            transition_report: finalized.into_finalized_continuation().transition_report,
            continuation_commitment: continuation_report.commitment,
            continuation_shape_root: continuation_report.shape_root,
        })
        .map_err(|e| format!("native RGK production-ZK transfer finalization: {e}"))
}

pub fn native_asset_continuation_report(
    chain: KaspaChainId,
    asset_id: Bytes32,
    spent_outpoint: KaspaOutpoint,
    covenant_id: KaspaCovenantId,
    spent_witness_txid: Bytes32,
    spent_daa_score: u64,
    output_index: u32,
    total_supply: u64,
) -> Result<RgkContinuationReport, String> {
    native_asset_continuation_plan(
        chain,
        asset_id,
        spent_outpoint,
        covenant_id,
        spent_witness_txid,
        spent_daa_score,
        output_index,
        total_supply,
    )?
    .validate_for_production_zk()
    .map_err(|e| format!("native RGK production-ZK continuation validation: {e}"))
}

fn native_asset_continuation_plan(
    chain: KaspaChainId,
    asset_id: Bytes32,
    spent_outpoint: KaspaOutpoint,
    covenant_id: KaspaCovenantId,
    spent_witness_txid: Bytes32,
    spent_daa_score: u64,
    output_index: u32,
    total_supply: u64,
) -> Result<RgkContinuationPlan, String> {
    let previous_report = native_asset_state_report(
        chain,
        asset_id,
        spent_outpoint,
        covenant_id,
        spent_witness_txid,
        spent_daa_score,
        1,
        total_supply,
    )?;
    Ok(RgkContinuationPlan {
        chain,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        previous_state_digest: previous_report.state_digest,
        spent_allocations: vec![native_asset_allocation(
            chain,
            asset_id,
            spent_outpoint,
            covenant_id,
            spent_witness_txid,
            spent_daa_score,
            1,
            total_supply,
        )],
        new_allocation_shapes: vec![RgkContinuationAllocationShape {
            output_index,
            covenant_id,
            amount: total_supply,
            encrypted_note_commitment: native_continuation_note_commitment(
                asset_id,
                covenant_id,
                output_index,
                total_supply,
            ),
        }],
        burn: None,
        metadata_commitment: fixture_metadata_commitment(asset_id),
        previous_owner_commitment: fixture_owner_commitment(asset_id),
        new_owner_commitment: fixture_owner_commitment(asset_id),
        ownership_authorization_commitment: [0; 32],
        lane_id: fixture_lane_id(asset_id),
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: fixture_proof_policy(),
    })
}

pub fn native_asset_allocation(
    chain: KaspaChainId,
    asset_id: Bytes32,
    covenant_outpoint: KaspaOutpoint,
    covenant_id: KaspaCovenantId,
    witness_txid: Bytes32,
    daa_score: u64,
    confirmation_depth: u64,
    amount: u64,
) -> RgkAllocation {
    let mut note_payload = Vec::with_capacity(32 + 32 + 4 + 8);
    note_payload.extend_from_slice(&asset_id);
    note_payload.extend_from_slice(&covenant_outpoint.transaction_id);
    note_payload.extend_from_slice(&covenant_outpoint.index.to_le_bytes());
    note_payload.extend_from_slice(&amount.to_le_bytes());
    RgkAllocation {
        anchor: RgkCovenantAnchor {
            chain,
            covenant_outpoint,
            covenant_id,
            witness_txid,
            daa_score,
            confirmation_depth,
        },
        amount,
        encrypted_note_commitment: domain_hash_domain("rgk:e2e:encrypted-note:v1", &note_payload),
    }
}

pub fn native_continuation_note_commitment(
    asset_id: Bytes32,
    covenant_id: KaspaCovenantId,
    output_index: u32,
    amount: u64,
) -> Bytes32 {
    let mut note_payload = Vec::with_capacity(32 + 32 + 4 + 8);
    note_payload.extend_from_slice(&asset_id);
    note_payload.extend_from_slice(&covenant_id);
    note_payload.extend_from_slice(&output_index.to_le_bytes());
    note_payload.extend_from_slice(&amount.to_le_bytes());
    domain_hash_domain("rgk:e2e:continuation-note:v1", &note_payload)
}

fn fixture_lane_id(asset_id: Bytes32) -> BlindedLaneId {
    rgk_asset::derive_blinded_lane_id([0x41; 32], asset_id, 0)
}

fn fixture_metadata_commitment(asset_id: Bytes32) -> RgkMetadataCommitment {
    RgkMetadataCommitment(domain_hash_domain("rgk:e2e:metadata:v1", &asset_id))
}

fn fixture_owner_commitment(asset_id: Bytes32) -> RgkOwnerCommitment {
    RgkOwnerCommitment(domain_hash_domain("rgk:e2e:owner:v1", &asset_id))
}

fn fixture_proof_policy() -> RgkProofPolicy {
    RgkProofPolicy::VerifierReceipt {
        verifier_key_hash: [0x91; 32],
    }
}
