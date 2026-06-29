#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-indexer
//!
//! Indexer for RGK covenant state. Two storage backends:
//!
//! * [`InMemoryIndexer`] — always available, BTreeMap-backed, suitable for
//!   tests and fixture e2e. Not persistent.
//! * [`SledIndexer`] — persistent, opt-in feature for restart-safe local
//!   resolver deployments.
//!
//! ## What the indexer tracks
//!
//! For each `covenant_id`:
//!
//! * the current `RgkStateCommitment` (latest accepted)
//! * the lineage id (for migration checks)
//! * the set of accepted receipt ids (replay protection)
//! * the current open outpoint (the covenant UTXO that has not yet been spent)
//! * history of spends (so the resolver can rewind on reorg)
//! * optional canonical allocation-audit certificates attached to accepted
//!   spends
//! * optional scan cursors for live-chain polling loops
//!
//! ## What the indexer does NOT do
//!
//! * It does **not** validate the chain-side of receipts. That is the
//!   resolver's job (see [`rgk_resolver`]).
//! * It does **not** own the chain RPC client. Callers combine
//!   [`ScanCursorStore`] with a chain backend or listener and persist the
//!   cursor after each durable scan batch.

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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use rgk_core::{
    Bytes32, Canonical, KaspaChainId, KaspaCovenantId, KaspaOutpoint, Reader, ReceiptId,
    ReceiptPolicy, RgkStateCommitment, Writer, MAX_BLOB_BYTES,
};
use thiserror::Error;

pub use rgk_core::{
    build_policy_migration_proof, policy_migration_commitment, PolicyMigrationInput,
    PolicyMigrationProof,
};

/// A single indexed covenant entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedCovenant {
    pub covenant_id: KaspaCovenantId,
    pub lineage_id: Bytes32,
    pub chain_id: KaspaChainId,
    /// The current open outpoint, or `None` if all history has been rolled
    /// back. The state is **only** valid if the open outpoint is set.
    pub open_outpoint: Option<KaspaOutpoint>,
    pub latest_state: RgkStateCommitment,
    /// Receipt ids accepted in the lineage, in acceptance order.
    pub accepted_receipts: Vec<ReceiptId>,
    /// Spend history: (height, spent_outpoint, new_outpoint, state_digest).
    /// Used for reorg rollback.
    pub spend_history: Vec<SpendEntry>,
    /// Block DAA score at which the latest state was last updated.
    pub last_update_daa_score: u64,
}

/// Local lane lookup material maintained by a wallet/indexer.
///
/// This is intentionally not consensus state. It lets the resolver answer
/// lane-native queries without exposing unrelated private-lane graph data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedLane {
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub asset_id: Bytes32,
    pub lane_id: Bytes32,
    pub epoch: u64,
    pub scan_tag: Option<Bytes32>,
    pub public_lineage: bool,
    pub state_digest: Bytes32,
    pub last_update_daa_score: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendEntry {
    pub daa_score: u64,
    pub spent: KaspaOutpoint,
    pub created: KaspaOutpoint,
    pub new_state_digest: Bytes32,
    pub resulting_state_digest: Bytes32,
    pub previous_receipt_policy: ReceiptPolicy,
    pub new_receipt_policy: ReceiptPolicy,
    pub receipt_id: ReceiptId,
    pub continuation: Option<ContinuationProof>,
    pub policy_migration: Option<PolicyMigrationProof>,
    pub allocation_audit_certificate: Option<AllocationAuditCertificateRecord>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ContinuationProof {
    pub commitment: Bytes32,
    pub shape_root: Bytes32,
    pub transition_digest: Bytes32,
}

pub const MAX_ALLOCATION_AUDIT_CERTIFICATE_BYTES: usize = MAX_BLOB_BYTES as usize;

const ALLOCATION_AUDIT_CERTIFICATE_MAGIC: &[u8; 8] = b"rgk:aac1";

/// Durable reference to a verified allocation-audit certificate.
///
/// The indexer deliberately stores the canonical certificate bytes without
/// depending on `rgk-zk`. Callers must verify/decode the certificate before
/// recording it here; the indexer enforces only the bounded transport envelope
/// and the embedded certificate id.
#[derive(Clone, PartialEq, Eq)]
pub struct AllocationAuditCertificateRecord {
    pub certificate_id: Bytes32,
    pub canonical_bytes: Vec<u8>,
}

impl core::fmt::Debug for AllocationAuditCertificateRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AllocationAuditCertificateRecord")
            .field(
                "certificate_id",
                &format!("0x{}", rgk_core::to_hex(&self.certificate_id)),
            )
            .field("canonical_bytes_len", &self.canonical_bytes.len())
            .finish()
    }
}

impl AllocationAuditCertificateRecord {
    pub fn new(certificate_id: Bytes32, canonical_bytes: Vec<u8>) -> Result<Self, IndexerError> {
        let record = Self {
            certificate_id,
            canonical_bytes,
        };
        validate_allocation_audit_certificate_record(&record)?;
        Ok(record)
    }

    pub fn canonical_len(&self) -> usize {
        self.canonical_bytes.len()
    }
}

/// Default cursor name for the primary live-chain scanner.
pub const DEFAULT_SCAN_CURSOR: &str = "rgk.default";

/// Durable position for a live-chain scanner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanCursor {
    pub chain_id: KaspaChainId,
    pub block_hash: Bytes32,
    pub daa_score: u64,
}

/// Durable starting point for rebuilding one covenant lineage.
///
/// This is intentionally explicit. The indexer cannot infer RGK state from a
/// bare Kaspa outpoint; callers must supply the last trusted checkpoint and
/// the verified RGK transitions they expect to replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildCheckpoint {
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub lineage_id: Bytes32,
    pub initial_state: RgkStateCommitment,
    pub open_outpoint: KaspaOutpoint,
    pub daa_score: u64,
}

/// One expected spend to replay during a rebuild.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildSpend {
    pub receipt_id: ReceiptId,
    pub spent_outpoint: KaspaOutpoint,
    pub created_outpoint: KaspaOutpoint,
    pub new_state: RgkStateCommitment,
    pub expected_spending_txid: Bytes32,
    pub min_confirmations: u64,
}

/// Rebuild plan for one covenant lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildPlan {
    pub checkpoint: RebuildCheckpoint,
    pub spends: Vec<RebuildSpend>,
}

/// Chain evidence for one replayed spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildSpendEvidence {
    pub spending_txid: Bytes32,
    pub block_daa_score: Option<u64>,
    pub confirmation_depth: Option<u64>,
}

/// Minimal evidence source needed by [`RebuildIndexer::rebuild_from`].
///
/// A production adapter can back this with `KaspaChainBackend`, a virtual-chain
/// listener cache, or an audited fixture. The indexer only consumes facts that
/// are already observed and typed.
pub trait RebuildSource {
    fn chain_id(&self) -> Result<KaspaChainId, IndexerError>;
    fn spend_evidence(
        &self,
        spent: KaspaOutpoint,
    ) -> Result<Option<RebuildSpendEvidence>, IndexerError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildSummary {
    pub opened: bool,
    pub applied_spends: usize,
    pub skipped_replays: usize,
    pub final_open_outpoint: KaspaOutpoint,
    pub final_daa_score: u64,
}

impl IndexedCovenant {
    fn empty(covenant_id: KaspaCovenantId, chain_id: KaspaChainId, lineage_id: Bytes32) -> Self {
        Self {
            covenant_id,
            lineage_id,
            chain_id,
            open_outpoint: None,
            latest_state: RgkStateCommitment {
                version: rgk_core::ENCODING_VERSION,
                chain_id,
                covenant_id,
                asset_id: [0u8; 32],
                state_digest: [0u8; 32],
                receipt_policy: rgk_core::ReceiptPolicy::Any,
            },
            accepted_receipts: Vec::new(),
            spend_history: Vec::new(),
            last_update_daa_score: 0,
        }
    }
}

/// Errors produced by the indexer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IndexerError {
    #[error("covenant not indexed: {0}")]
    NotIndexed(Hex32),
    #[error("covenant already indexed: {0}")]
    AlreadyIndexed(Hex32),
    #[error("chain id mismatch: entry is for {existing:?}, request is for {requested:?}")]
    ChainMismatch {
        existing: KaspaChainId,
        requested: KaspaChainId,
    },
    #[error("lineage mismatch: entry is {existing}, request is {requested}")]
    LineageMismatch { existing: Hex32, requested: Hex32 },
    #[error("replay detected: receipt {0} already accepted")]
    Replay(Hex32),
    #[error("reorg rollback failed: covenant has no spend history")]
    NoHistory,
    #[error("reorg rollback exceeded depth: requested {requested}, available {available}")]
    RollbackTooDeep { requested: u64, available: usize },
    #[error("open outpoint already set; spend before registering a new state")]
    OpenOutpointSet,
    #[error("continuation proof is incomplete: {0}")]
    ContinuationProofIncomplete(String),
    #[error("policy migration proof is invalid: {0}")]
    PolicyMigrationProofInvalid(String),
    #[error("allocation audit certificate is invalid: {0}")]
    AllocationAuditCertificateInvalid(String),
    #[error("lane index invariant violated: {0}")]
    LaneInvariant(String),
    #[error("spend receipt {receipt_id} is not indexed for covenant {covenant}")]
    SpendReceiptNotIndexed { covenant: Hex32, receipt_id: Hex32 },
    #[error("rebuild source failed: {0}")]
    RebuildSource(String),
    #[error("rebuild source has no spend evidence for {spent:?}")]
    RebuildSpendMissing { spent: KaspaOutpoint },
    #[error("rebuild source saw tx {actual} spending {spent:?}, expected {expected}")]
    RebuildTxMismatch {
        spent: KaspaOutpoint,
        expected: Hex32,
        actual: Hex32,
    },
    #[error("rebuild source did not report a block DAA score for spending tx {0}")]
    RebuildMissingDaaScore(Hex32),
    #[error("rebuild tx {txid} has confirmation depth {actual:?}, required {required}")]
    RebuildInsufficientConfirmations {
        txid: Hex32,
        required: u64,
        actual: Option<u64>,
    },
    #[error("invariant violated: {0}")]
    Invariant(String),
    #[error("storage I/O failure: {0}")]
    Storage(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hex32(pub Bytes32);
impl core::fmt::Display for Hex32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use rgk_core::to_hex;
        f.write_str("0x")?;
        f.write_str(&to_hex(&self.0))
    }
}
impl From<Bytes32> for Hex32 {
    fn from(b: Bytes32) -> Self {
        Hex32(b)
    }
}

/// Indexer trait. Stable contract; backed by [`InMemoryIndexer`] by default.
pub trait Indexer {
    fn open(
        &mut self,
        chain: KaspaChainId,
        covenant: KaspaCovenantId,
        lineage: Bytes32,
        initial: RgkStateCommitment,
        open_outpoint: KaspaOutpoint,
        daa_score: u64,
    ) -> Result<(), IndexerError>;
    fn apply_spend(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
    ) -> Result<(), IndexerError>;
    fn apply_spend_with_continuation(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
        continuation: ContinuationProof,
    ) -> Result<(), IndexerError>;
    fn apply_spend_with_continuation_and_policy_migration(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
        continuation: ContinuationProof,
        policy_migration: PolicyMigrationProof,
    ) -> Result<(), IndexerError>;
    fn rollback(&mut self, covenant: KaspaCovenantId, depth: u64) -> Result<(), IndexerError>;
    fn lookup(&self, covenant: KaspaCovenantId) -> Option<IndexedCovenant>;
    fn latest_state(&self, covenant: KaspaCovenantId) -> Option<RgkStateCommitment>;
    fn open_outpoint(&self, covenant: KaspaCovenantId) -> Option<KaspaOutpoint>;
    fn has_replay(&self, covenant: KaspaCovenantId, receipt_id: &ReceiptId) -> bool;
    fn list(&self) -> Vec<KaspaCovenantId>;
    fn register_lane(&mut self, lane: IndexedLane) -> Result<(), IndexerError>;
    fn lane_by_id(&self, lane_id: &Bytes32) -> Option<IndexedLane>;
    fn lane_by_scan_tag(&self, scan_tag: &Bytes32) -> Option<IndexedLane>;
    fn public_lanes(&self, asset_id: &Bytes32) -> Vec<IndexedLane>;
}

/// Storage for chain-scanner cursors.
///
/// The scanner itself lives outside this crate because it owns chain I/O. This
/// trait is deliberately small: persist the last fully-applied cursor only
/// after the caller has durably recorded the corresponding indexer effects.
pub trait ScanCursorStore {
    fn load_scan_cursor(&self, name: &str) -> Result<Option<ScanCursor>, IndexerError>;
    fn store_scan_cursor(&mut self, name: &str, cursor: ScanCursor) -> Result<(), IndexerError>;
    fn clear_scan_cursor(&mut self, name: &str) -> Result<(), IndexerError>;
}

/// Optional durable store for allocation-audit certificate bytes attached to
/// accepted spends.
pub trait AllocationAuditCertificateStore {
    fn record_allocation_audit_certificate(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        certificate: AllocationAuditCertificateRecord,
    ) -> Result<(), IndexerError>;

    fn allocation_audit_certificate(
        &self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
    ) -> Option<AllocationAuditCertificateRecord>;
}

/// Extension trait for rebuilding indexer state from an explicit checkpoint
/// and expected spend plan.
///
/// This is not a historical chain walker. It verifies that each caller-supplied
/// transition is supported by observed chain evidence before applying it.
pub trait RebuildIndexer: Indexer {
    fn rebuild_from<S: RebuildSource + ?Sized>(
        &mut self,
        source: &S,
        plan: &RebuildPlan,
    ) -> Result<RebuildSummary, IndexerError> {
        let source_chain = source.chain_id()?;
        if source_chain != plan.checkpoint.chain_id {
            return Err(IndexerError::ChainMismatch {
                existing: source_chain,
                requested: plan.checkpoint.chain_id,
            });
        }
        validate_rebuild_checkpoint_shape(&plan.checkpoint)?;

        let covenant = plan.checkpoint.covenant_id;
        let mut opened = false;
        match self.lookup(covenant) {
            Some(entry) => validate_existing_checkpoint(&entry, &plan.checkpoint)?,
            None => {
                self.open(
                    plan.checkpoint.chain_id,
                    covenant,
                    plan.checkpoint.lineage_id,
                    plan.checkpoint.initial_state.clone(),
                    plan.checkpoint.open_outpoint,
                    plan.checkpoint.daa_score,
                )?;
                opened = true;
            }
        }

        let mut applied_spends = 0usize;
        let mut skipped_replays = 0usize;
        for spend in &plan.spends {
            validate_rebuild_spend_shape(&plan.checkpoint, spend)?;
            let evidence = source.spend_evidence(spend.spent_outpoint)?.ok_or(
                IndexerError::RebuildSpendMissing {
                    spent: spend.spent_outpoint,
                },
            )?;
            if evidence.spending_txid != spend.expected_spending_txid {
                return Err(IndexerError::RebuildTxMismatch {
                    spent: spend.spent_outpoint,
                    expected: spend.expected_spending_txid.into(),
                    actual: evidence.spending_txid.into(),
                });
            }
            if evidence.confirmation_depth.unwrap_or(0) < spend.min_confirmations {
                return Err(IndexerError::RebuildInsufficientConfirmations {
                    txid: evidence.spending_txid.into(),
                    required: spend.min_confirmations,
                    actual: evidence.confirmation_depth,
                });
            }
            let daa_score =
                evidence
                    .block_daa_score
                    .ok_or(IndexerError::RebuildMissingDaaScore(
                        evidence.spending_txid.into(),
                    ))?;

            if self.has_replay(covenant, &spend.receipt_id) {
                skipped_replays += 1;
                continue;
            }

            self.apply_spend(
                covenant,
                spend.receipt_id,
                spend.spent_outpoint,
                spend.created_outpoint,
                spend.new_state.clone(),
                daa_score,
            )?;
            applied_spends += 1;
        }

        let final_entry = self
            .lookup(covenant)
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        let final_open_outpoint = final_entry.open_outpoint.ok_or_else(|| {
            IndexerError::Invariant("rebuilt covenant has no open outpoint".into())
        })?;
        Ok(RebuildSummary {
            opened,
            applied_spends,
            skipped_replays,
            final_open_outpoint,
            final_daa_score: final_entry.last_update_daa_score,
        })
    }
}

impl<T: Indexer + ?Sized> RebuildIndexer for T {}

fn validate_rebuild_checkpoint_shape(checkpoint: &RebuildCheckpoint) -> Result<(), IndexerError> {
    if checkpoint.initial_state.chain_id != checkpoint.chain_id {
        return Err(IndexerError::ChainMismatch {
            existing: checkpoint.initial_state.chain_id,
            requested: checkpoint.chain_id,
        });
    }
    if checkpoint.initial_state.covenant_id != checkpoint.covenant_id {
        return Err(IndexerError::Invariant(
            "rebuild checkpoint state covenant id does not match checkpoint covenant id".into(),
        ));
    }
    Ok(())
}

fn validate_existing_checkpoint(
    entry: &IndexedCovenant,
    checkpoint: &RebuildCheckpoint,
) -> Result<(), IndexerError> {
    if entry.chain_id != checkpoint.chain_id {
        return Err(IndexerError::ChainMismatch {
            existing: entry.chain_id,
            requested: checkpoint.chain_id,
        });
    }
    if entry.lineage_id != checkpoint.lineage_id {
        return Err(IndexerError::LineageMismatch {
            existing: entry.lineage_id.into(),
            requested: checkpoint.lineage_id.into(),
        });
    }
    if entry.latest_state.asset_id != checkpoint.initial_state.asset_id {
        return Err(IndexerError::Invariant(
            "existing covenant belongs to a different RGK asset".into(),
        ));
    }
    if entry.latest_state.receipt_policy != checkpoint.initial_state.receipt_policy {
        return Err(IndexerError::Invariant(
            "existing covenant uses a different receipt policy".into(),
        ));
    }

    if entry.accepted_receipts.is_empty() {
        if entry.open_outpoint != Some(checkpoint.open_outpoint) {
            return Err(IndexerError::Invariant(
                "existing covenant open outpoint does not match rebuild checkpoint".into(),
            ));
        }
        if entry.latest_state != checkpoint.initial_state {
            return Err(IndexerError::Invariant(
                "existing covenant state does not match rebuild checkpoint".into(),
            ));
        }
        if entry.last_update_daa_score != checkpoint.daa_score {
            return Err(IndexerError::Invariant(
                "existing covenant DAA score does not match rebuild checkpoint".into(),
            ));
        }
        return Ok(());
    }

    let Some(first_spend) = entry.spend_history.first() else {
        return Err(IndexerError::Invariant(
            "existing covenant has accepted receipts but no spend history".into(),
        ));
    };
    if first_spend.spent != checkpoint.open_outpoint {
        return Err(IndexerError::Invariant(
            "existing covenant history does not descend from rebuild checkpoint".into(),
        ));
    }
    if first_spend.new_state_digest != checkpoint.initial_state.state_digest {
        return Err(IndexerError::Invariant(
            "existing covenant history has a different checkpoint state digest".into(),
        ));
    }
    Ok(())
}

fn validate_rebuild_spend_shape(
    checkpoint: &RebuildCheckpoint,
    spend: &RebuildSpend,
) -> Result<(), IndexerError> {
    if spend.new_state.chain_id != checkpoint.chain_id {
        return Err(IndexerError::ChainMismatch {
            existing: spend.new_state.chain_id,
            requested: checkpoint.chain_id,
        });
    }
    if spend.new_state.covenant_id != checkpoint.covenant_id {
        return Err(IndexerError::Invariant(
            "rebuild spend state covenant id does not match checkpoint covenant id".into(),
        ));
    }
    if spend.new_state.asset_id != checkpoint.initial_state.asset_id {
        return Err(IndexerError::Invariant(
            "rebuild spend changes RGK asset id".into(),
        ));
    }
    if spend.new_state.receipt_policy != checkpoint.initial_state.receipt_policy {
        return Err(IndexerError::Invariant(
            "rebuild spend changes receipt policy".into(),
        ));
    }
    Ok(())
}

fn validate_continuation_proof(proof: &ContinuationProof) -> Result<(), IndexerError> {
    if proof.commitment == [0u8; 32] {
        return Err(IndexerError::ContinuationProofIncomplete(
            "missing phase-1 commitment".into(),
        ));
    }
    if proof.shape_root == [0u8; 32] {
        return Err(IndexerError::ContinuationProofIncomplete(
            "missing continuation shape root".into(),
        ));
    }
    if proof.transition_digest == [0u8; 32] {
        return Err(IndexerError::ContinuationProofIncomplete(
            "missing phase-2 transition digest".into(),
        ));
    }
    Ok(())
}

fn validate_policy_migration_proof(
    proof: &PolicyMigrationProof,
    previous_policy: ReceiptPolicy,
    new_policy: ReceiptPolicy,
    previous_state_digest: Bytes32,
    new_state_digest: Bytes32,
    transition_digest: Bytes32,
) -> Result<(), IndexerError> {
    if previous_policy == new_policy {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "policy migration proof supplied for unchanged policy".into(),
        ));
    }
    if proof.previous_policy != previous_policy {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "previous policy does not match indexed state".into(),
        ));
    }
    if proof.new_policy != new_policy {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "new policy does not match indexed state".into(),
        ));
    }
    if proof.previous_state_digest != previous_state_digest {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "previous state digest does not match indexed state".into(),
        ));
    }
    if proof.new_state_digest != new_state_digest {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "new state digest does not match indexed state".into(),
        ));
    }
    if proof.transition_digest != transition_digest {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "transition digest does not match continuation proof".into(),
        ));
    }
    if proof.authorization_commitment == [0u8; 32] {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "missing migration authorisation commitment".into(),
        ));
    }
    let expected = policy_migration_commitment(
        proof.previous_policy,
        proof.new_policy,
        proof.previous_state_digest,
        proof.new_state_digest,
        proof.transition_digest,
        proof.authorization_commitment,
    );
    if proof.migration_commitment != expected {
        return Err(IndexerError::PolicyMigrationProofInvalid(
            "migration commitment does not match proof fields".into(),
        ));
    }
    Ok(())
}

fn validate_allocation_audit_certificate_record(
    record: &AllocationAuditCertificateRecord,
) -> Result<(), IndexerError> {
    if record.certificate_id == [0u8; 32] {
        return Err(IndexerError::AllocationAuditCertificateInvalid(
            "missing certificate id".into(),
        ));
    }
    let len = record.canonical_bytes.len();
    if len > MAX_ALLOCATION_AUDIT_CERTIFICATE_BYTES {
        return Err(IndexerError::AllocationAuditCertificateInvalid(format!(
            "canonical bytes length {len} exceeds max {MAX_ALLOCATION_AUDIT_CERTIFICATE_BYTES}"
        )));
    }
    let min_len = ALLOCATION_AUDIT_CERTIFICATE_MAGIC.len() + 32 + 1;
    if len < min_len {
        return Err(IndexerError::AllocationAuditCertificateInvalid(format!(
            "canonical bytes length {len} is too short"
        )));
    }
    if &record.canonical_bytes[..ALLOCATION_AUDIT_CERTIFICATE_MAGIC.len()]
        != ALLOCATION_AUDIT_CERTIFICATE_MAGIC
    {
        return Err(IndexerError::AllocationAuditCertificateInvalid(
            "canonical bytes have bad allocation-audit certificate magic".into(),
        ));
    }
    let id_start = ALLOCATION_AUDIT_CERTIFICATE_MAGIC.len();
    let id_end = id_start + 32;
    if record.canonical_bytes[id_start..id_end] != record.certificate_id {
        return Err(IndexerError::AllocationAuditCertificateInvalid(
            "canonical bytes certificate id does not match record id".into(),
        ));
    }
    Ok(())
}

fn record_allocation_audit_certificate_on_entry(
    entry: &mut IndexedCovenant,
    receipt_id: ReceiptId,
    certificate: AllocationAuditCertificateRecord,
) -> Result<(), IndexerError> {
    validate_allocation_audit_certificate_record(&certificate)?;
    let spend = entry
        .spend_history
        .iter_mut()
        .find(|spend| spend.receipt_id == receipt_id)
        .ok_or(IndexerError::SpendReceiptNotIndexed {
            covenant: entry.covenant_id.into(),
            receipt_id: receipt_id.into(),
        })?;
    if let Some(existing) = &spend.allocation_audit_certificate {
        if existing != &certificate {
            return Err(IndexerError::AllocationAuditCertificateInvalid(
                "attempted to replace an existing allocation-audit certificate".into(),
            ));
        }
        return Ok(());
    }
    spend.allocation_audit_certificate = Some(certificate);
    Ok(())
}

fn apply_spend_to_entry(
    entry: &mut IndexedCovenant,
    receipt_id: ReceiptId,
    spent: KaspaOutpoint,
    new_outpoint: KaspaOutpoint,
    new_state: RgkStateCommitment,
    daa_score: u64,
    continuation: Option<ContinuationProof>,
    policy_migration: Option<PolicyMigrationProof>,
) -> Result<(), IndexerError> {
    if let Some(proof) = &continuation {
        validate_continuation_proof(proof)?;
    }
    if entry.accepted_receipts.contains(&receipt_id) {
        return Err(IndexerError::Replay(receipt_id.into()));
    }
    if entry.chain_id != new_state.chain_id {
        return Err(IndexerError::ChainMismatch {
            existing: entry.chain_id,
            requested: new_state.chain_id,
        });
    }
    if entry.covenant_id != new_state.covenant_id {
        return Err(IndexerError::Invariant(
            "new state covenant id does not match indexed covenant".into(),
        ));
    }
    if entry.latest_state.asset_id != new_state.asset_id {
        return Err(IndexerError::Invariant(
            "new state asset id does not match indexed asset".into(),
        ));
    }
    if entry.open_outpoint != Some(spent) {
        return Err(IndexerError::Invariant(format!(
            "expected open outpoint {:?}, got {:?}",
            entry.open_outpoint, spent
        )));
    }
    let prev_digest = entry.latest_state.state_digest;
    let previous_receipt_policy = entry.latest_state.receipt_policy;
    let new_receipt_policy = new_state.receipt_policy;
    let resulting_state_digest = new_state.state_digest;
    if prev_digest == new_state.state_digest {
        return Err(IndexerError::Invariant("state did not advance".into()));
    }
    if let Some(proof) = &policy_migration {
        let continuation = continuation.as_ref().ok_or_else(|| {
            IndexerError::PolicyMigrationProofInvalid(
                "policy migration proof requires continuation proof".into(),
            )
        })?;
        validate_policy_migration_proof(
            proof,
            previous_receipt_policy,
            new_receipt_policy,
            prev_digest,
            resulting_state_digest,
            continuation.transition_digest,
        )?;
    }
    entry.open_outpoint = Some(new_outpoint);
    entry.latest_state = new_state;
    entry.last_update_daa_score = daa_score;
    entry.accepted_receipts.push(receipt_id);
    entry.spend_history.push(SpendEntry {
        daa_score,
        spent,
        created: new_outpoint,
        new_state_digest: prev_digest,
        resulting_state_digest,
        previous_receipt_policy,
        new_receipt_policy,
        receipt_id,
        continuation,
        policy_migration,
        allocation_audit_certificate: None,
    });
    Ok(())
}

fn validate_indexed_lane(entry: &IndexedCovenant, lane: &IndexedLane) -> Result<(), IndexerError> {
    if lane.lane_id == [0u8; 32] {
        return Err(IndexerError::LaneInvariant(
            "lane id must not be zero".into(),
        ));
    }
    if lane.state_digest == [0u8; 32] {
        return Err(IndexerError::LaneInvariant(
            "lane state digest must not be zero".into(),
        ));
    }
    if let Some(scan_tag) = lane.scan_tag {
        if scan_tag == [0u8; 32] {
            return Err(IndexerError::LaneInvariant(
                "scan tag must not be zero".into(),
            ));
        }
    }
    if lane.chain_id != entry.chain_id {
        return Err(IndexerError::ChainMismatch {
            existing: entry.chain_id,
            requested: lane.chain_id,
        });
    }
    if lane.covenant_id != entry.covenant_id {
        return Err(IndexerError::LaneInvariant(
            "lane covenant id does not match indexed covenant".into(),
        ));
    }
    if lane.asset_id != entry.latest_state.asset_id {
        return Err(IndexerError::LaneInvariant(
            "lane asset id does not match indexed state".into(),
        ));
    }
    if lane.state_digest != entry.latest_state.state_digest {
        return Err(IndexerError::LaneInvariant(
            "lane state digest does not match indexed state".into(),
        ));
    }
    if lane.last_update_daa_score != entry.last_update_daa_score {
        return Err(IndexerError::LaneInvariant(
            "lane DAA score does not match indexed state".into(),
        ));
    }
    Ok(())
}

/// In-memory implementation. BTreeMap-backed. O(log n) for all ops.
#[derive(Clone, Debug, Default)]
pub struct InMemoryIndexer {
    map: BTreeMap<KaspaCovenantId, IndexedCovenant>,
    lanes: BTreeMap<Bytes32, IndexedLane>,
    lane_scan_tags: BTreeMap<Bytes32, Bytes32>,
    scan_cursors: BTreeMap<String, ScanCursor>,
}

impl InMemoryIndexer {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            lanes: BTreeMap::new(),
            lane_scan_tags: BTreeMap::new(),
            scan_cursors: BTreeMap::new(),
        }
    }
}

impl Indexer for InMemoryIndexer {
    fn open(
        &mut self,
        chain: KaspaChainId,
        covenant: KaspaCovenantId,
        lineage: Bytes32,
        initial: RgkStateCommitment,
        open_outpoint: KaspaOutpoint,
        daa_score: u64,
    ) -> Result<(), IndexerError> {
        if self.map.contains_key(&covenant) {
            return Err(IndexerError::AlreadyIndexed(covenant.into()));
        }
        if initial.chain_id != chain {
            return Err(IndexerError::ChainMismatch {
                existing: initial.chain_id,
                requested: chain,
            });
        }
        if initial.covenant_id != covenant {
            return Err(IndexerError::LineageMismatch {
                existing: initial.covenant_id.into(),
                requested: covenant.into(),
            });
        }
        let mut entry = IndexedCovenant::empty(covenant, chain, lineage);
        entry.open_outpoint = Some(open_outpoint);
        entry.latest_state = initial;
        entry.last_update_daa_score = daa_score;
        self.map.insert(covenant, entry);
        Ok(())
    }

    fn apply_spend(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
    ) -> Result<(), IndexerError> {
        let entry = self
            .map
            .get_mut(&covenant)
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        apply_spend_to_entry(
            entry,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            daa_score,
            None,
            None,
        )
    }

    fn apply_spend_with_continuation(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
        continuation: ContinuationProof,
    ) -> Result<(), IndexerError> {
        let entry = self
            .map
            .get_mut(&covenant)
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        apply_spend_to_entry(
            entry,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            daa_score,
            Some(continuation),
            None,
        )
    }

    fn apply_spend_with_continuation_and_policy_migration(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
        continuation: ContinuationProof,
        policy_migration: PolicyMigrationProof,
    ) -> Result<(), IndexerError> {
        let entry = self
            .map
            .get_mut(&covenant)
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        apply_spend_to_entry(
            entry,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            daa_score,
            Some(continuation),
            Some(policy_migration),
        )
    }

    fn rollback(&mut self, covenant: KaspaCovenantId, depth: u64) -> Result<(), IndexerError> {
        let entry = self
            .map
            .get_mut(&covenant)
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        let n = depth as usize;
        if n > entry.spend_history.len() {
            return Err(IndexerError::RollbackTooDeep {
                requested: depth,
                available: entry.spend_history.len(),
            });
        }
        // Pop the last `n` spend entries. Reverse the state.
        for _ in 0..n {
            let last = entry.spend_history.pop().expect("non-empty");
            entry.open_outpoint = Some(last.spent);
            entry.latest_state.state_digest = last.new_state_digest;
            entry.latest_state.receipt_policy = last.previous_receipt_policy;
            entry.accepted_receipts.pop();
            entry.last_update_daa_score = last.daa_score.saturating_sub(1);
        }
        Ok(())
    }

    fn lookup(&self, covenant: KaspaCovenantId) -> Option<IndexedCovenant> {
        self.map.get(&covenant).cloned()
    }

    fn latest_state(&self, covenant: KaspaCovenantId) -> Option<RgkStateCommitment> {
        self.map.get(&covenant).map(|e| e.latest_state.clone())
    }

    fn open_outpoint(&self, covenant: KaspaCovenantId) -> Option<KaspaOutpoint> {
        self.map.get(&covenant).and_then(|e| e.open_outpoint)
    }

    fn has_replay(&self, covenant: KaspaCovenantId, receipt_id: &ReceiptId) -> bool {
        self.map
            .get(&covenant)
            .map(|e| e.accepted_receipts.contains(receipt_id))
            .unwrap_or(false)
    }

    fn list(&self) -> Vec<KaspaCovenantId> {
        self.map.keys().copied().collect()
    }

    fn register_lane(&mut self, lane: IndexedLane) -> Result<(), IndexerError> {
        let entry = self
            .map
            .get(&lane.covenant_id)
            .ok_or(IndexerError::NotIndexed(lane.covenant_id.into()))?;
        validate_indexed_lane(entry, &lane)?;
        if let Some(previous) = self.lanes.insert(lane.lane_id, lane.clone()) {
            if let Some(tag) = previous.scan_tag {
                self.lane_scan_tags.remove(&tag);
            }
        }
        if let Some(scan_tag) = lane.scan_tag {
            self.lane_scan_tags.insert(scan_tag, lane.lane_id);
        }
        Ok(())
    }

    fn lane_by_id(&self, lane_id: &Bytes32) -> Option<IndexedLane> {
        self.lanes.get(lane_id).cloned()
    }

    fn lane_by_scan_tag(&self, scan_tag: &Bytes32) -> Option<IndexedLane> {
        self.lane_scan_tags
            .get(scan_tag)
            .and_then(|lane_id| self.lanes.get(lane_id))
            .cloned()
    }

    fn public_lanes(&self, asset_id: &Bytes32) -> Vec<IndexedLane> {
        self.lanes
            .values()
            .filter(|lane| lane.public_lineage && &lane.asset_id == asset_id)
            .cloned()
            .collect()
    }
}

impl ScanCursorStore for InMemoryIndexer {
    fn load_scan_cursor(&self, name: &str) -> Result<Option<ScanCursor>, IndexerError> {
        validate_scan_cursor_name(name)?;
        Ok(self.scan_cursors.get(name).cloned())
    }

    fn store_scan_cursor(&mut self, name: &str, cursor: ScanCursor) -> Result<(), IndexerError> {
        validate_scan_cursor_name(name)?;
        self.scan_cursors.insert(name.to_string(), cursor);
        Ok(())
    }

    fn clear_scan_cursor(&mut self, name: &str) -> Result<(), IndexerError> {
        validate_scan_cursor_name(name)?;
        self.scan_cursors.remove(name);
        Ok(())
    }
}

// ---------------- sled-backed persistent indexer ----------------

#[cfg(feature = "persistent")]
const SLED_COVENANTS_TREE: &str = "rgk.covenants.v0";

#[cfg(feature = "persistent")]
const SLED_SCAN_CURSORS_TREE: &str = "rgk.scan_cursors.v0";

#[cfg(feature = "persistent")]
const SLED_LANES_TREE: &str = "rgk.lanes.v0";

#[cfg(feature = "persistent")]
const INDEXED_COVENANT_MAGIC: &[u8; 8] = b"rgkidx3\0";

#[cfg(feature = "persistent")]
const INDEXED_COVENANT_MAGIC_V2: &[u8; 8] = b"rgkidx2\0";

#[cfg(feature = "persistent")]
const SCAN_CURSOR_MAGIC: &[u8; 8] = b"rgkscan\0";

#[cfg(feature = "persistent")]
const INDEXED_LANE_MAGIC: &[u8; 8] = b"rgklane\0";

/// Persistent [`Indexer`] backed by sled.
///
/// The on-disk value is a canonical RGK-specific binary record, not `serde`.
/// This keeps replay and rollback state byte-stable across dependency bumps.
#[cfg(feature = "persistent")]
#[derive(Debug)]
pub struct SledIndexer {
    db: sled::Db,
    covenants: sled::Tree,
    lanes: sled::Tree,
    scan_cursors: sled::Tree,
}

#[cfg(feature = "persistent")]
impl SledIndexer {
    pub fn open_path(path: impl AsRef<std::path::Path>) -> Result<Self, IndexerError> {
        let db = sled::open(path).map_err(storage_err)?;
        Self::from_db(db)
    }

    pub fn from_db(db: sled::Db) -> Result<Self, IndexerError> {
        let covenants = db.open_tree(SLED_COVENANTS_TREE).map_err(storage_err)?;
        let lanes = db.open_tree(SLED_LANES_TREE).map_err(storage_err)?;
        let scan_cursors = db.open_tree(SLED_SCAN_CURSORS_TREE).map_err(storage_err)?;
        Ok(Self {
            db,
            covenants,
            lanes,
            scan_cursors,
        })
    }

    pub fn flush(&self) -> Result<(), IndexerError> {
        self.db.flush().map_err(storage_err)?;
        Ok(())
    }

    fn load_entry(
        &self,
        covenant: KaspaCovenantId,
    ) -> Result<Option<IndexedCovenant>, IndexerError> {
        self.covenants
            .get(covenant)
            .map_err(storage_err)?
            .map(|bytes| decode_indexed_covenant(&bytes))
            .transpose()
    }

    fn store_entry(&self, entry: &IndexedCovenant) -> Result<(), IndexerError> {
        self.covenants
            .insert(entry.covenant_id, encode_indexed_covenant(entry))
            .map_err(storage_err)?;
        self.covenants.flush().map_err(storage_err)?;
        Ok(())
    }

    fn load_lane(&self, lane_id: &Bytes32) -> Result<Option<IndexedLane>, IndexerError> {
        self.lanes
            .get(lane_id)
            .map_err(storage_err)?
            .map(|bytes| decode_indexed_lane(&bytes))
            .transpose()
    }

    fn store_lane(&self, lane: &IndexedLane) -> Result<(), IndexerError> {
        self.lanes
            .insert(lane.lane_id, encode_indexed_lane(lane))
            .map_err(storage_err)?;
        self.lanes.flush().map_err(storage_err)?;
        Ok(())
    }
}

impl AllocationAuditCertificateStore for InMemoryIndexer {
    fn record_allocation_audit_certificate(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        certificate: AllocationAuditCertificateRecord,
    ) -> Result<(), IndexerError> {
        let entry = self
            .map
            .get_mut(&covenant)
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        record_allocation_audit_certificate_on_entry(entry, receipt_id, certificate)
    }

    fn allocation_audit_certificate(
        &self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
    ) -> Option<AllocationAuditCertificateRecord> {
        self.map
            .get(&covenant)?
            .spend_history
            .iter()
            .find(|spend| spend.receipt_id == receipt_id)?
            .allocation_audit_certificate
            .clone()
    }
}

#[cfg(feature = "persistent")]
impl ScanCursorStore for SledIndexer {
    fn load_scan_cursor(&self, name: &str) -> Result<Option<ScanCursor>, IndexerError> {
        let key = validate_scan_cursor_name(name)?;
        self.scan_cursors
            .get(key)
            .map_err(storage_err)?
            .map(|bytes| decode_scan_cursor(&bytes))
            .transpose()
    }

    fn store_scan_cursor(&mut self, name: &str, cursor: ScanCursor) -> Result<(), IndexerError> {
        let key = validate_scan_cursor_name(name)?;
        self.scan_cursors
            .insert(key, encode_scan_cursor(&cursor))
            .map_err(storage_err)?;
        self.scan_cursors.flush().map_err(storage_err)?;
        Ok(())
    }

    fn clear_scan_cursor(&mut self, name: &str) -> Result<(), IndexerError> {
        let key = validate_scan_cursor_name(name)?;
        self.scan_cursors.remove(key).map_err(storage_err)?;
        self.scan_cursors.flush().map_err(storage_err)?;
        Ok(())
    }
}

#[cfg(feature = "persistent")]
impl Indexer for SledIndexer {
    fn open(
        &mut self,
        chain: KaspaChainId,
        covenant: KaspaCovenantId,
        lineage: Bytes32,
        initial: RgkStateCommitment,
        open_outpoint: KaspaOutpoint,
        daa_score: u64,
    ) -> Result<(), IndexerError> {
        if self.load_entry(covenant)?.is_some() {
            return Err(IndexerError::AlreadyIndexed(covenant.into()));
        }
        if initial.chain_id != chain {
            return Err(IndexerError::ChainMismatch {
                existing: initial.chain_id,
                requested: chain,
            });
        }
        if initial.covenant_id != covenant {
            return Err(IndexerError::LineageMismatch {
                existing: initial.covenant_id.into(),
                requested: covenant.into(),
            });
        }
        let mut entry = IndexedCovenant::empty(covenant, chain, lineage);
        entry.open_outpoint = Some(open_outpoint);
        entry.latest_state = initial;
        entry.last_update_daa_score = daa_score;
        self.store_entry(&entry)
    }

    fn apply_spend(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
    ) -> Result<(), IndexerError> {
        let mut entry = self
            .load_entry(covenant)?
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        apply_spend_to_entry(
            &mut entry,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            daa_score,
            None,
            None,
        )?;
        self.store_entry(&entry)
    }

    fn apply_spend_with_continuation(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
        continuation: ContinuationProof,
    ) -> Result<(), IndexerError> {
        let mut entry = self
            .load_entry(covenant)?
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        apply_spend_to_entry(
            &mut entry,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            daa_score,
            Some(continuation),
            None,
        )?;
        self.store_entry(&entry)
    }

    fn apply_spend_with_continuation_and_policy_migration(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        spent: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        new_state: RgkStateCommitment,
        daa_score: u64,
        continuation: ContinuationProof,
        policy_migration: PolicyMigrationProof,
    ) -> Result<(), IndexerError> {
        let mut entry = self
            .load_entry(covenant)?
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        apply_spend_to_entry(
            &mut entry,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            daa_score,
            Some(continuation),
            Some(policy_migration),
        )?;
        self.store_entry(&entry)
    }

    fn rollback(&mut self, covenant: KaspaCovenantId, depth: u64) -> Result<(), IndexerError> {
        let mut entry = self
            .load_entry(covenant)?
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        let n = depth as usize;
        if n > entry.spend_history.len() {
            return Err(IndexerError::RollbackTooDeep {
                requested: depth,
                available: entry.spend_history.len(),
            });
        }
        for _ in 0..n {
            let last = entry.spend_history.pop().expect("non-empty");
            entry.open_outpoint = Some(last.spent);
            entry.latest_state.state_digest = last.new_state_digest;
            entry.latest_state.receipt_policy = last.previous_receipt_policy;
            entry.accepted_receipts.pop();
            entry.last_update_daa_score = last.daa_score.saturating_sub(1);
        }
        self.store_entry(&entry)
    }

    fn lookup(&self, covenant: KaspaCovenantId) -> Option<IndexedCovenant> {
        self.load_entry(covenant).ok().flatten()
    }

    fn latest_state(&self, covenant: KaspaCovenantId) -> Option<RgkStateCommitment> {
        self.lookup(covenant).map(|e| e.latest_state)
    }

    fn open_outpoint(&self, covenant: KaspaCovenantId) -> Option<KaspaOutpoint> {
        self.lookup(covenant).and_then(|e| e.open_outpoint)
    }

    fn has_replay(&self, covenant: KaspaCovenantId, receipt_id: &ReceiptId) -> bool {
        self.lookup(covenant)
            .map(|e| e.accepted_receipts.contains(receipt_id))
            .unwrap_or(false)
    }

    fn list(&self) -> Vec<KaspaCovenantId> {
        self.covenants
            .iter()
            .filter_map(|item| {
                let (key, _) = item.ok()?;
                if key.len() != 32 {
                    return None;
                }
                let mut covenant = [0u8; 32];
                covenant.copy_from_slice(&key);
                Some(covenant)
            })
            .collect()
    }

    fn register_lane(&mut self, lane: IndexedLane) -> Result<(), IndexerError> {
        let entry = self
            .load_entry(lane.covenant_id)?
            .ok_or(IndexerError::NotIndexed(lane.covenant_id.into()))?;
        validate_indexed_lane(&entry, &lane)?;
        self.store_lane(&lane)
    }

    fn lane_by_id(&self, lane_id: &Bytes32) -> Option<IndexedLane> {
        self.load_lane(lane_id).ok().flatten()
    }

    fn lane_by_scan_tag(&self, scan_tag: &Bytes32) -> Option<IndexedLane> {
        self.lanes.iter().find_map(|item| {
            let (_, bytes) = item.ok()?;
            let lane = decode_indexed_lane(&bytes).ok()?;
            (lane.scan_tag.as_ref() == Some(scan_tag)).then_some(lane)
        })
    }

    fn public_lanes(&self, asset_id: &Bytes32) -> Vec<IndexedLane> {
        self.lanes
            .iter()
            .filter_map(|item| {
                let (_, bytes) = item.ok()?;
                let lane = decode_indexed_lane(&bytes).ok()?;
                (lane.public_lineage && &lane.asset_id == asset_id).then_some(lane)
            })
            .collect()
    }
}

#[cfg(feature = "persistent")]
impl AllocationAuditCertificateStore for SledIndexer {
    fn record_allocation_audit_certificate(
        &mut self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
        certificate: AllocationAuditCertificateRecord,
    ) -> Result<(), IndexerError> {
        let mut entry = self
            .load_entry(covenant)?
            .ok_or(IndexerError::NotIndexed(covenant.into()))?;
        record_allocation_audit_certificate_on_entry(&mut entry, receipt_id, certificate)?;
        self.store_entry(&entry)
    }

    fn allocation_audit_certificate(
        &self,
        covenant: KaspaCovenantId,
        receipt_id: ReceiptId,
    ) -> Option<AllocationAuditCertificateRecord> {
        self.lookup(covenant)?
            .spend_history
            .into_iter()
            .find(|spend| spend.receipt_id == receipt_id)?
            .allocation_audit_certificate
    }
}

#[cfg(feature = "persistent")]
fn storage_err(e: sled::Error) -> IndexerError {
    IndexerError::Storage(e.to_string())
}

#[cfg(feature = "persistent")]
fn decode_err(e: rgk_core::DecodeError) -> IndexerError {
    IndexerError::Storage(format!("corrupt indexer record: {e}"))
}

#[cfg(feature = "persistent")]
fn encode_indexed_covenant(entry: &IndexedCovenant) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_bytes(INDEXED_COVENANT_MAGIC);
    w.write_bytes32(&entry.covenant_id);
    w.write_bytes32(&entry.lineage_id);
    entry.chain_id.encode(&mut w);
    w.write_bool(entry.open_outpoint.is_some());
    if let Some(open_outpoint) = entry.open_outpoint {
        open_outpoint.encode(&mut w);
    }
    entry.latest_state.encode(&mut w);
    w.write_u32(entry.accepted_receipts.len() as u32);
    for receipt_id in &entry.accepted_receipts {
        w.write_bytes32(receipt_id);
    }
    w.write_u32(entry.spend_history.len() as u32);
    for spend in &entry.spend_history {
        w.write_u64(spend.daa_score);
        spend.spent.encode(&mut w);
        spend.created.encode(&mut w);
        w.write_bytes32(&spend.new_state_digest);
        w.write_bytes32(&spend.resulting_state_digest);
        spend.previous_receipt_policy.encode(&mut w);
        spend.new_receipt_policy.encode(&mut w);
        w.write_bytes32(&spend.receipt_id);
        w.write_bool(spend.continuation.is_some());
        if let Some(proof) = spend.continuation {
            w.write_bytes32(&proof.commitment);
            w.write_bytes32(&proof.shape_root);
            w.write_bytes32(&proof.transition_digest);
        }
        w.write_bool(spend.policy_migration.is_some());
        if let Some(proof) = spend.policy_migration {
            proof.previous_policy.encode(&mut w);
            proof.new_policy.encode(&mut w);
            w.write_bytes32(&proof.previous_state_digest);
            w.write_bytes32(&proof.new_state_digest);
            w.write_bytes32(&proof.transition_digest);
            w.write_bytes32(&proof.authorization_commitment);
            w.write_bytes32(&proof.migration_commitment);
        }
        w.write_bool(spend.allocation_audit_certificate.is_some());
        if let Some(certificate) = &spend.allocation_audit_certificate {
            validate_allocation_audit_certificate_record(certificate)
                .expect("invalid allocation-audit certificate record in indexed covenant");
            w.write_bytes32(&certificate.certificate_id);
            w.write_blob(&certificate.canonical_bytes);
        }
    }
    w.write_u64(entry.last_update_daa_score);
    w.into_vec()
}

#[cfg(feature = "persistent")]
fn decode_indexed_covenant(buf: &[u8]) -> Result<IndexedCovenant, IndexerError> {
    let mut r = Reader::new(buf);
    let magic = r.read_array::<8>().map_err(decode_err)?;
    let has_allocation_audit_certificate_field = if magic == *INDEXED_COVENANT_MAGIC {
        true
    } else if magic == *INDEXED_COVENANT_MAGIC_V2 {
        false
    } else {
        return Err(IndexerError::Storage("bad indexer record magic".into()));
    };
    let covenant_id = r.read_bytes32().map_err(decode_err)?;
    let lineage_id = r.read_bytes32().map_err(decode_err)?;
    let chain_id = KaspaChainId::decode(&mut r).map_err(decode_err)?;
    let open_outpoint = if r.read_bool().map_err(decode_err)? {
        Some(KaspaOutpoint::decode(&mut r).map_err(decode_err)?)
    } else {
        None
    };
    let latest_state = RgkStateCommitment::decode(&mut r).map_err(decode_err)?;

    let receipt_len = r.read_u32().map_err(decode_err)? as usize;
    let mut accepted_receipts = Vec::with_capacity(receipt_len);
    for _ in 0..receipt_len {
        accepted_receipts.push(r.read_bytes32().map_err(decode_err)?);
    }

    let spend_len = r.read_u32().map_err(decode_err)? as usize;
    let mut spend_history = Vec::with_capacity(spend_len);
    for _ in 0..spend_len {
        let daa_score = r.read_u64().map_err(decode_err)?;
        let spent = KaspaOutpoint::decode(&mut r).map_err(decode_err)?;
        let created = KaspaOutpoint::decode(&mut r).map_err(decode_err)?;
        let new_state_digest = r.read_bytes32().map_err(decode_err)?;
        let resulting_state_digest = r.read_bytes32().map_err(decode_err)?;
        let previous_receipt_policy = ReceiptPolicy::decode(&mut r).map_err(decode_err)?;
        let new_receipt_policy = ReceiptPolicy::decode(&mut r).map_err(decode_err)?;
        let receipt_id = r.read_bytes32().map_err(decode_err)?;
        let continuation = if r.read_bool().map_err(decode_err)? {
            let proof = ContinuationProof {
                commitment: r.read_bytes32().map_err(decode_err)?,
                shape_root: r.read_bytes32().map_err(decode_err)?,
                transition_digest: r.read_bytes32().map_err(decode_err)?,
            };
            validate_continuation_proof(&proof)?;
            Some(proof)
        } else {
            None
        };
        let policy_migration = if r.read_bool().map_err(decode_err)? {
            Some(PolicyMigrationProof {
                previous_policy: ReceiptPolicy::decode(&mut r).map_err(decode_err)?,
                new_policy: ReceiptPolicy::decode(&mut r).map_err(decode_err)?,
                previous_state_digest: r.read_bytes32().map_err(decode_err)?,
                new_state_digest: r.read_bytes32().map_err(decode_err)?,
                transition_digest: r.read_bytes32().map_err(decode_err)?,
                authorization_commitment: r.read_bytes32().map_err(decode_err)?,
                migration_commitment: r.read_bytes32().map_err(decode_err)?,
            })
        } else {
            None
        };
        if let Some(proof) = &policy_migration {
            let continuation = continuation.as_ref().ok_or_else(|| {
                IndexerError::Storage(
                    "corrupt indexer record: policy migration without continuation proof".into(),
                )
            })?;
            validate_policy_migration_proof(
                proof,
                previous_receipt_policy,
                new_receipt_policy,
                new_state_digest,
                resulting_state_digest,
                continuation.transition_digest,
            )?;
        }
        let allocation_audit_certificate =
            if has_allocation_audit_certificate_field && r.read_bool().map_err(decode_err)? {
                Some(decode_allocation_audit_certificate_record(&mut r)?)
            } else {
                None
            };
        spend_history.push(SpendEntry {
            daa_score,
            spent,
            created,
            new_state_digest,
            resulting_state_digest,
            previous_receipt_policy,
            new_receipt_policy,
            receipt_id,
            continuation,
            policy_migration,
            allocation_audit_certificate,
        });
    }
    let last_update_daa_score = r.read_u64().map_err(decode_err)?;
    r.ensure_consumed().map_err(decode_err)?;
    if latest_state.covenant_id != covenant_id || latest_state.chain_id != chain_id {
        return Err(IndexerError::Storage(
            "indexer record state key mismatch".into(),
        ));
    }
    Ok(IndexedCovenant {
        covenant_id,
        lineage_id,
        chain_id,
        open_outpoint,
        latest_state,
        accepted_receipts,
        spend_history,
        last_update_daa_score,
    })
}

#[cfg(feature = "persistent")]
fn decode_allocation_audit_certificate_record(
    r: &mut Reader<'_>,
) -> Result<AllocationAuditCertificateRecord, IndexerError> {
    let certificate_id = r.read_bytes32().map_err(decode_err)?;
    let canonical_bytes = r.read_blob().map_err(decode_err)?.to_vec();
    AllocationAuditCertificateRecord::new(certificate_id, canonical_bytes)
}

#[cfg(feature = "persistent")]
fn encode_indexed_lane(lane: &IndexedLane) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_bytes(INDEXED_LANE_MAGIC);
    lane.chain_id.encode(&mut w);
    w.write_bytes32(&lane.covenant_id);
    w.write_bytes32(&lane.asset_id);
    w.write_bytes32(&lane.lane_id);
    w.write_u64(lane.epoch);
    w.write_bool(lane.scan_tag.is_some());
    if let Some(scan_tag) = lane.scan_tag {
        w.write_bytes32(&scan_tag);
    }
    w.write_bool(lane.public_lineage);
    w.write_bytes32(&lane.state_digest);
    w.write_u64(lane.last_update_daa_score);
    w.into_vec()
}

#[cfg(feature = "persistent")]
fn decode_indexed_lane(buf: &[u8]) -> Result<IndexedLane, IndexerError> {
    let mut r = Reader::new(buf);
    let magic = r.read_array::<8>().map_err(decode_err)?;
    if magic != *INDEXED_LANE_MAGIC {
        return Err(IndexerError::Storage("bad lane record magic".into()));
    }
    let chain_id = KaspaChainId::decode(&mut r).map_err(decode_err)?;
    let covenant_id = r.read_bytes32().map_err(decode_err)?;
    let asset_id = r.read_bytes32().map_err(decode_err)?;
    let lane_id = r.read_bytes32().map_err(decode_err)?;
    let epoch = r.read_u64().map_err(decode_err)?;
    let scan_tag = if r.read_bool().map_err(decode_err)? {
        Some(r.read_bytes32().map_err(decode_err)?)
    } else {
        None
    };
    let public_lineage = r.read_bool().map_err(decode_err)?;
    let state_digest = r.read_bytes32().map_err(decode_err)?;
    let last_update_daa_score = r.read_u64().map_err(decode_err)?;
    r.ensure_consumed().map_err(decode_err)?;
    let lane = IndexedLane {
        chain_id,
        covenant_id,
        asset_id,
        lane_id,
        epoch,
        scan_tag,
        public_lineage,
        state_digest,
        last_update_daa_score,
    };
    if lane.lane_id == [0u8; 32] {
        return Err(IndexerError::Storage("bad lane id".into()));
    }
    if lane.state_digest == [0u8; 32] {
        return Err(IndexerError::Storage("bad lane state digest".into()));
    }
    if lane.scan_tag == Some([0u8; 32]) {
        return Err(IndexerError::Storage("bad lane scan tag".into()));
    }
    Ok(lane)
}

fn validate_scan_cursor_name(name: &str) -> Result<&[u8], IndexerError> {
    if name.is_empty() {
        return Err(IndexerError::Invariant(
            "scan cursor name must not be empty".into(),
        ));
    }
    if name.len() > 128 {
        return Err(IndexerError::Invariant(
            "scan cursor name must be at most 128 bytes".into(),
        ));
    }
    Ok(name.as_bytes())
}

#[cfg(feature = "persistent")]
fn encode_scan_cursor(cursor: &ScanCursor) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_bytes(SCAN_CURSOR_MAGIC);
    cursor.chain_id.encode(&mut w);
    w.write_bytes32(&cursor.block_hash);
    w.write_u64(cursor.daa_score);
    w.into_vec()
}

#[cfg(feature = "persistent")]
fn decode_scan_cursor(buf: &[u8]) -> Result<ScanCursor, IndexerError> {
    let mut r = Reader::new(buf);
    let magic = r.read_array::<8>().map_err(decode_err)?;
    if magic != *SCAN_CURSOR_MAGIC {
        return Err(IndexerError::Storage("bad scan cursor magic".into()));
    }
    let chain_id = KaspaChainId::decode(&mut r).map_err(decode_err)?;
    let block_hash = r.read_bytes32().map_err(decode_err)?;
    let daa_score = r.read_u64().map_err(decode_err)?;
    r.ensure_consumed().map_err(decode_err)?;
    Ok(ScanCursor {
        chain_id,
        block_hash,
        daa_score,
    })
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rgk_core::{ReceiptPolicy, ENCODING_VERSION, KASPA_LOCAL_TOCCATA};

    #[derive(Default)]
    struct FixtureRebuildSource {
        chain_id: Option<KaspaChainId>,
        spends: BTreeMap<KaspaOutpoint, RebuildSpendEvidence>,
    }

    impl FixtureRebuildSource {
        fn new(chain_id: KaspaChainId) -> Self {
            Self {
                chain_id: Some(chain_id),
                spends: BTreeMap::new(),
            }
        }

        fn with_spend(mut self, spent: KaspaOutpoint, evidence: RebuildSpendEvidence) -> Self {
            self.spends.insert(spent, evidence);
            self
        }
    }

    impl RebuildSource for FixtureRebuildSource {
        fn chain_id(&self) -> Result<KaspaChainId, IndexerError> {
            self.chain_id
                .ok_or_else(|| IndexerError::RebuildSource("missing fixture chain id".into()))
        }

        fn spend_evidence(
            &self,
            spent: KaspaOutpoint,
        ) -> Result<Option<RebuildSpendEvidence>, IndexerError> {
            Ok(self.spends.get(&spent).cloned())
        }
    }

    fn b32(s: &str) -> [u8; 32] {
        rgk_core::from_hex::<32>(s).expect("hex")
    }

    fn state(covenant: KaspaCovenantId, digest: u8) -> RgkStateCommitment {
        RgkStateCommitment {
            version: ENCODING_VERSION,
            chain_id: KASPA_LOCAL_TOCCATA,
            covenant_id: covenant,
            asset_id: b32("2222222222222222222222222222222222222222222222222222222222222222"),
            state_digest: {
                let mut d = [0u8; 32];
                d[31] = digest;
                d
            },
            receipt_policy: rgk_core::ReceiptPolicy::Any,
        }
    }

    fn state_with_policy(
        covenant: KaspaCovenantId,
        digest: u8,
        receipt_policy: ReceiptPolicy,
    ) -> RgkStateCommitment {
        let mut state = state(covenant, digest);
        state.receipt_policy = receipt_policy;
        state
    }

    fn migration_proof(
        previous_policy: ReceiptPolicy,
        new_policy: ReceiptPolicy,
        previous_state_digest: Bytes32,
        new_state_digest: Bytes32,
        transition_digest: Bytes32,
    ) -> PolicyMigrationProof {
        let authorization_commitment = [0x88; 32];
        let migration_commitment = policy_migration_commitment(
            previous_policy,
            new_policy,
            previous_state_digest,
            new_state_digest,
            transition_digest,
            authorization_commitment,
        );
        PolicyMigrationProof {
            previous_policy,
            new_policy,
            previous_state_digest,
            new_state_digest,
            transition_digest,
            authorization_commitment,
            migration_commitment,
        }
    }

    fn outpoint(tx_byte: u8, index: u32) -> KaspaOutpoint {
        KaspaOutpoint {
            transaction_id: [tx_byte; 32],
            index,
        }
    }

    fn allocation_audit_certificate_record(id_byte: u8) -> AllocationAuditCertificateRecord {
        let certificate_id = [id_byte; 32];
        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(ALLOCATION_AUDIT_CERTIFICATE_MAGIC);
        canonical_bytes.extend_from_slice(&certificate_id);
        canonical_bytes.push(0xa5);
        AllocationAuditCertificateRecord::new(certificate_id, canonical_bytes)
            .expect("valid allocation audit certificate envelope")
    }

    fn lane_record(
        covenant: KaspaCovenantId,
        lane_id: Bytes32,
        scan_tag: Option<Bytes32>,
        public_lineage: bool,
        digest: u8,
        daa_score: u64,
    ) -> IndexedLane {
        IndexedLane {
            chain_id: KASPA_LOCAL_TOCCATA,
            covenant_id: covenant,
            asset_id: b32("2222222222222222222222222222222222222222222222222222222222222222"),
            lane_id,
            epoch: 7,
            scan_tag,
            public_lineage,
            state_digest: {
                let mut d = [0u8; 32];
                d[31] = digest;
                d
            },
            last_update_daa_score: daa_score,
        }
    }

    fn rebuild_plan(cov: KaspaCovenantId) -> RebuildPlan {
        let open = outpoint(1, 0);
        let first_created = outpoint(2, 0);
        let second_created = outpoint(4, 0);
        RebuildPlan {
            checkpoint: RebuildCheckpoint {
                chain_id: KASPA_LOCAL_TOCCATA,
                covenant_id: cov,
                lineage_id: [0xaa; 32],
                initial_state: state(cov, 1),
                open_outpoint: open,
                daa_score: 10,
            },
            spends: vec![
                RebuildSpend {
                    receipt_id: [3u8; 32],
                    spent_outpoint: open,
                    created_outpoint: first_created,
                    new_state: state(cov, 2),
                    expected_spending_txid: [9u8; 32],
                    min_confirmations: 1,
                },
                RebuildSpend {
                    receipt_id: [5u8; 32],
                    spent_outpoint: first_created,
                    created_outpoint: second_created,
                    new_state: state(cov, 3),
                    expected_spending_txid: [8u8; 32],
                    min_confirmations: 2,
                },
            ],
        }
    }

    fn rebuild_source(plan: &RebuildPlan) -> FixtureRebuildSource {
        FixtureRebuildSource::new(plan.checkpoint.chain_id)
            .with_spend(
                plan.spends[0].spent_outpoint,
                RebuildSpendEvidence {
                    spending_txid: plan.spends[0].expected_spending_txid,
                    block_daa_score: Some(11),
                    confirmation_depth: Some(3),
                },
            )
            .with_spend(
                plan.spends[1].spent_outpoint,
                RebuildSpendEvidence {
                    spending_txid: plan.spends[1].expected_spending_txid,
                    block_daa_score: Some(12),
                    confirmation_depth: Some(2),
                },
            )
    }

    #[test]
    fn open_then_lookup() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            state(cov, 1),
            KaspaOutpoint::NULL,
            10,
        )
        .unwrap();
        let e = idx.lookup(cov).unwrap();
        assert_eq!(e.lineage_id, lin);
        assert_eq!(e.open_outpoint, Some(KaspaOutpoint::NULL));
        assert_eq!(e.latest_state.state_digest[31], 1);
    }

    #[test]
    fn apply_spend_records_receipt_and_state() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        let next = KaspaOutpoint {
            transaction_id: [2u8; 32],
            index: 0,
        };
        idx.apply_spend(cov, [3u8; 32], open, next, state(cov, 2), 11)
            .unwrap();
        assert_eq!(idx.open_outpoint(cov), Some(next));
        assert_eq!(idx.latest_state(cov).unwrap().state_digest[31], 2);
        assert!(idx.has_replay(cov, &[3u8; 32]));
        let entry = idx.lookup(cov).unwrap();
        let spend = entry.spend_history.last().unwrap();
        assert_eq!(spend.previous_receipt_policy, ReceiptPolicy::Any);
        assert_eq!(spend.new_receipt_policy, ReceiptPolicy::Any);
        assert_eq!(spend.new_state_digest[31], 1);
        assert_eq!(spend.resulting_state_digest[31], 2);
    }

    #[test]
    fn apply_spend_records_receipt_policy_change_for_resolver_classification() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();

        idx.apply_spend(
            cov,
            [3u8; 32],
            open,
            next,
            state_with_policy(cov, 2, ReceiptPolicy::VerifierOnly),
            11,
        )
        .unwrap();

        let entry = idx.lookup(cov).unwrap();
        let spend = entry.spend_history.last().unwrap();
        assert_eq!(spend.previous_receipt_policy, ReceiptPolicy::Any);
        assert_eq!(spend.new_receipt_policy, ReceiptPolicy::VerifierOnly);
        assert_eq!(
            entry.latest_state.receipt_policy,
            ReceiptPolicy::VerifierOnly
        );
    }

    #[test]
    fn apply_spend_with_policy_migration_records_explicit_proof() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let previous_state = state(cov, 1);
        let new_state = state_with_policy(cov, 2, ReceiptPolicy::VerifierOnly);
        let continuation = ContinuationProof {
            commitment: [0x55; 32],
            shape_root: [0x66; 32],
            transition_digest: [0x77; 32],
        };
        let proof = migration_proof(
            ReceiptPolicy::Any,
            ReceiptPolicy::VerifierOnly,
            previous_state.state_digest,
            new_state.state_digest,
            continuation.transition_digest,
        );

        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, previous_state, open, 10)
            .unwrap();
        idx.apply_spend_with_continuation_and_policy_migration(
            cov,
            [3u8; 32],
            open,
            next,
            new_state,
            11,
            continuation,
            proof,
        )
        .unwrap();

        let entry = idx.lookup(cov).unwrap();
        assert_eq!(entry.spend_history[0].policy_migration, Some(proof));
    }

    #[test]
    fn apply_spend_with_policy_migration_rejects_bad_commitment() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let previous_state = state(cov, 1);
        let new_state = state_with_policy(cov, 2, ReceiptPolicy::VerifierOnly);
        let continuation = ContinuationProof {
            commitment: [0x55; 32],
            shape_root: [0x66; 32],
            transition_digest: [0x77; 32],
        };
        let mut proof = migration_proof(
            ReceiptPolicy::Any,
            ReceiptPolicy::VerifierOnly,
            previous_state.state_digest,
            new_state.state_digest,
            continuation.transition_digest,
        );
        proof.migration_commitment[0] ^= 0x01;

        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, previous_state, open, 10)
            .unwrap();
        let err = idx
            .apply_spend_with_continuation_and_policy_migration(
                cov,
                [3u8; 32],
                open,
                next,
                new_state,
                11,
                continuation,
                proof,
            )
            .unwrap_err();
        assert!(matches!(err, IndexerError::PolicyMigrationProofInvalid(_)));
    }

    #[test]
    fn apply_spend_with_continuation_records_proof() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let proof = ContinuationProof {
            commitment: [0x55; 32],
            shape_root: [0x66; 32],
            transition_digest: [0x77; 32],
        };
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        idx.apply_spend_with_continuation(cov, [3u8; 32], open, next, state(cov, 2), 11, proof)
            .unwrap();

        let entry = idx.lookup(cov).unwrap();
        assert_eq!(
            entry.spend_history.last().unwrap().continuation,
            Some(proof)
        );
    }

    #[test]
    fn apply_spend_with_continuation_rejects_incomplete_proof() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();

        let err = idx
            .apply_spend_with_continuation(
                cov,
                [3u8; 32],
                open,
                next,
                state(cov, 2),
                11,
                ContinuationProof {
                    commitment: [0u8; 32],
                    shape_root: [0x66; 32],
                    transition_digest: [0x77; 32],
                },
            )
            .unwrap_err();
        assert!(matches!(err, IndexerError::ContinuationProofIncomplete(_)));
    }

    #[test]
    fn allocation_audit_certificate_record_attaches_to_spend() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let receipt_id = [3u8; 32];
        let certificate = allocation_audit_certificate_record(0x44);

        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        idx.apply_spend(cov, receipt_id, open, next, state(cov, 2), 11)
            .unwrap();
        idx.record_allocation_audit_certificate(cov, receipt_id, certificate.clone())
            .unwrap();
        idx.record_allocation_audit_certificate(cov, receipt_id, certificate.clone())
            .unwrap();

        let entry = idx.lookup(cov).unwrap();
        assert_eq!(
            entry.spend_history[0].allocation_audit_certificate,
            Some(certificate.clone())
        );
        assert_eq!(
            idx.allocation_audit_certificate(cov, receipt_id),
            Some(certificate)
        );
    }

    #[test]
    fn allocation_audit_certificate_record_rejects_bad_envelopes_and_replacement() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let receipt_id = [3u8; 32];

        let mut bad_magic_bytes = Vec::new();
        bad_magic_bytes.extend_from_slice(b"notcert!");
        bad_magic_bytes.extend_from_slice(&[0x44; 32]);
        bad_magic_bytes.push(0xa5);
        let err = AllocationAuditCertificateRecord::new([0x44; 32], bad_magic_bytes)
            .expect_err("bad magic must be rejected");
        assert!(matches!(
            err,
            IndexerError::AllocationAuditCertificateInvalid(_)
        ));

        let mut mismatch_bytes = Vec::new();
        mismatch_bytes.extend_from_slice(ALLOCATION_AUDIT_CERTIFICATE_MAGIC);
        mismatch_bytes.extend_from_slice(&[0x55; 32]);
        mismatch_bytes.push(0xa5);
        let err = AllocationAuditCertificateRecord::new([0x44; 32], mismatch_bytes)
            .expect_err("id mismatch must be rejected");
        assert!(matches!(
            err,
            IndexerError::AllocationAuditCertificateInvalid(_)
        ));

        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        let missing = idx
            .record_allocation_audit_certificate(
                cov,
                receipt_id,
                allocation_audit_certificate_record(0x44),
            )
            .expect_err("certificate cannot attach before spend is indexed");
        assert!(matches!(
            missing,
            IndexerError::SpendReceiptNotIndexed { .. }
        ));

        idx.apply_spend(cov, receipt_id, open, next, state(cov, 2), 11)
            .unwrap();
        idx.record_allocation_audit_certificate(
            cov,
            receipt_id,
            allocation_audit_certificate_record(0x44),
        )
        .unwrap();
        let replacement = idx
            .record_allocation_audit_certificate(
                cov,
                receipt_id,
                allocation_audit_certificate_record(0x45),
            )
            .expect_err("different certificate replacement must be rejected");
        assert!(matches!(
            replacement,
            IndexerError::AllocationAuditCertificateInvalid(_)
        ));
    }

    #[test]
    fn register_lane_supports_exact_scan_tag_and_public_lookup() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let lane = lane_record(cov, [0x51; 32], Some([0x52; 32]), true, 1, 10);
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            state(cov, 1),
            outpoint(1, 0),
            10,
        )
        .unwrap();
        idx.register_lane(lane.clone()).unwrap();

        assert_eq!(idx.lane_by_id(&[0x51; 32]), Some(lane.clone()));
        assert_eq!(idx.lane_by_scan_tag(&[0x52; 32]), Some(lane.clone()));
        assert_eq!(idx.lane_by_scan_tag(&[0x53; 32]), None);
        assert_eq!(
            idx.public_lanes(&lane.asset_id)
                .into_iter()
                .map(|lane| lane.lane_id)
                .collect::<Vec<_>>(),
            vec![[0x51; 32]]
        );
    }

    #[test]
    fn register_lane_rejects_wrong_asset_state() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            state(cov, 1),
            outpoint(1, 0),
            10,
        )
        .unwrap();

        let mut wrong = lane_record(cov, [0x51; 32], Some([0x52; 32]), false, 2, 10);
        wrong.asset_id = [0x99; 32];
        let err = idx.register_lane(wrong).unwrap_err();
        assert!(matches!(err, IndexerError::LaneInvariant(_)));
    }

    #[test]
    fn replay_rejected() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        let next = KaspaOutpoint {
            transaction_id: [2u8; 32],
            index: 0,
        };
        let rid = [3u8; 32];
        idx.apply_spend(cov, rid, open, next, state(cov, 2), 11)
            .unwrap();
        let next2 = KaspaOutpoint {
            transaction_id: [4u8; 32],
            index: 0,
        };
        let err = idx
            .apply_spend(cov, rid, next, next2, state(cov, 3), 12)
            .unwrap_err();
        assert!(matches!(err, IndexerError::Replay(_)));
    }

    #[test]
    fn rollback_restores_previous_state() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        let next = KaspaOutpoint {
            transaction_id: [2u8; 32],
            index: 0,
        };
        idx.apply_spend(cov, [3u8; 32], open, next, state(cov, 2), 11)
            .unwrap();
        let next2 = KaspaOutpoint {
            transaction_id: [4u8; 32],
            index: 0,
        };
        idx.apply_spend(cov, [5u8; 32], next, next2, state(cov, 3), 12)
            .unwrap();

        // Roll back one step.
        idx.rollback(cov, 1).unwrap();
        assert_eq!(idx.open_outpoint(cov), Some(next));
        assert_eq!(idx.latest_state(cov).unwrap().state_digest[31], 2);
        // [3] was the receipt that advanced us to state 2; it's still in the
        // accepted set after one rollback. [5] is gone.
        assert!(idx.has_replay(cov, &[3u8; 32]));
        assert!(!idx.has_replay(cov, &[5u8; 32]));

        // Roll back one more -> back to genesis.
        idx.rollback(cov, 1).unwrap();
        assert_eq!(idx.open_outpoint(cov), Some(open));
        assert_eq!(idx.latest_state(cov).unwrap().state_digest[31], 1);
        assert!(!idx.has_replay(cov, &[3u8; 32]));
        assert!(!idx.has_replay(cov, &[5u8; 32]));
    }

    #[test]
    fn rollback_restores_previous_receipt_policy() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        idx.apply_spend(
            cov,
            [3u8; 32],
            open,
            next,
            state_with_policy(cov, 2, ReceiptPolicy::VerifierOnly),
            11,
        )
        .unwrap();
        assert_eq!(
            idx.latest_state(cov).unwrap().receipt_policy,
            ReceiptPolicy::VerifierOnly
        );

        idx.rollback(cov, 1).unwrap();
        assert_eq!(
            idx.latest_state(cov).unwrap().receipt_policy,
            ReceiptPolicy::Any
        );
    }

    proptest! {
        #[test]
        fn apply_spend_and_rollback_preserve_replay_prefix(
            transition_count in 1usize..20,
            rollback_seed in any::<usize>(),
        ) {
            let mut idx = InMemoryIndexer::new();
            let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
            let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let genesis_open = outpoint(1, 0);
            idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), genesis_open, 10)
                .expect("open covenant");

            let mut current = genesis_open;
            for step in 1..=transition_count {
                let next = outpoint((step + 1) as u8, 0);
                let receipt = [(step + 1) as u8; 32];
                idx.apply_spend(
                    cov,
                    receipt,
                    current,
                    next,
                    state(cov, (step + 1) as u8),
                    10 + step as u64,
                )
                .expect("apply spend");
                prop_assert!(idx.has_replay(cov, &receipt));
                current = next;
            }

            let rollback_depth = rollback_seed % (transition_count + 1);
            if rollback_depth > 0 {
                idx.rollback(cov, rollback_depth as u64).expect("rollback");
            }

            let remaining = transition_count - rollback_depth;
            let expected_open = if remaining == 0 {
                genesis_open
            } else {
                outpoint((remaining + 1) as u8, 0)
            };
            prop_assert_eq!(idx.open_outpoint(cov), Some(expected_open));
            prop_assert_eq!(
                idx.latest_state(cov).expect("latest state").state_digest[31],
                (remaining + 1) as u8
            );

            for step in 1..=transition_count {
                let receipt = [(step + 1) as u8; 32];
                prop_assert_eq!(idx.has_replay(cov, &receipt), step <= remaining);
            }
        }
    }

    #[test]
    fn rollback_too_deep_rejected() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        assert!(matches!(
            idx.rollback(cov, 99),
            Err(IndexerError::RollbackTooDeep { .. })
        ));
    }

    #[test]
    fn open_twice_rejected() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            state(cov, 1),
            KaspaOutpoint::NULL,
            10,
        )
        .unwrap();
        assert!(matches!(
            idx.open(
                KASPA_LOCAL_TOCCATA,
                cov,
                lin,
                state(cov, 2),
                KaspaOutpoint::NULL,
                11
            ),
            Err(IndexerError::AlreadyIndexed(_))
        ));
    }

    #[test]
    fn chain_mismatch_in_open_rejected() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let mut bad_state = state(cov, 1);
        bad_state.chain_id = KaspaChainId::KaspaMainnet;
        assert!(matches!(
            idx.open(
                KASPA_LOCAL_TOCCATA,
                cov,
                lin,
                bad_state,
                KaspaOutpoint::NULL,
                10
            ),
            Err(IndexerError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn no_op_state_rejected() {
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
            .unwrap();
        let next = KaspaOutpoint {
            transaction_id: [2u8; 32],
            index: 0,
        };
        let err = idx
            .apply_spend(cov, [3u8; 32], open, next, state(cov, 1), 11)
            .unwrap_err();
        assert!(matches!(err, IndexerError::Invariant(_)));
    }

    #[test]
    fn rebuild_from_verified_source_applies_spend_plan() {
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = rebuild_source(&plan);
        let mut idx = InMemoryIndexer::new();

        let summary = idx.rebuild_from(&source, &plan).expect("rebuild");

        assert!(summary.opened);
        assert_eq!(summary.applied_spends, 2);
        assert_eq!(summary.skipped_replays, 0);
        assert_eq!(summary.final_open_outpoint, plan.spends[1].created_outpoint);
        assert_eq!(summary.final_daa_score, 12);

        let entry = idx.lookup(cov).expect("indexed covenant");
        assert_eq!(entry.latest_state, state(cov, 3));
        assert_eq!(entry.accepted_receipts, vec![[3u8; 32], [5u8; 32]]);
        assert_eq!(entry.spend_history.len(), 2);
        assert!(idx.has_replay(cov, &[3u8; 32]));
        assert!(idx.has_replay(cov, &[5u8; 32]));
    }

    #[test]
    fn rebuild_from_verified_source_is_idempotent() {
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = rebuild_source(&plan);
        let mut idx = InMemoryIndexer::new();

        idx.rebuild_from(&source, &plan).expect("first rebuild");
        let summary = idx.rebuild_from(&source, &plan).expect("second rebuild");

        assert!(!summary.opened);
        assert_eq!(summary.applied_spends, 0);
        assert_eq!(summary.skipped_replays, 2);
        assert_eq!(idx.lookup(cov).unwrap().spend_history.len(), 2);
    }

    #[test]
    fn rebuild_rejects_chain_mismatch() {
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = FixtureRebuildSource::new(KaspaChainId::KaspaMainnet);
        let mut idx = InMemoryIndexer::new();

        let err = idx
            .rebuild_from(&source, &plan)
            .expect_err("chain mismatch expected");

        assert!(matches!(err, IndexerError::ChainMismatch { .. }));
        assert!(idx.lookup(cov).is_none());
    }

    #[test]
    fn rebuild_rejects_missing_spend_evidence() {
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = FixtureRebuildSource::new(plan.checkpoint.chain_id);
        let mut idx = InMemoryIndexer::new();

        let err = idx
            .rebuild_from(&source, &plan)
            .expect_err("missing spend expected");

        assert!(matches!(err, IndexerError::RebuildSpendMissing { .. }));
    }

    #[test]
    fn rebuild_rejects_unexpected_spending_txid() {
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = FixtureRebuildSource::new(plan.checkpoint.chain_id).with_spend(
            plan.spends[0].spent_outpoint,
            RebuildSpendEvidence {
                spending_txid: [0xee; 32],
                block_daa_score: Some(11),
                confirmation_depth: Some(1),
            },
        );
        let mut idx = InMemoryIndexer::new();

        let err = idx
            .rebuild_from(&source, &plan)
            .expect_err("tx mismatch expected");

        assert!(matches!(err, IndexerError::RebuildTxMismatch { .. }));
    }

    #[test]
    fn rebuild_rejects_unconfirmed_spend() {
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = FixtureRebuildSource::new(plan.checkpoint.chain_id).with_spend(
            plan.spends[0].spent_outpoint,
            RebuildSpendEvidence {
                spending_txid: plan.spends[0].expected_spending_txid,
                block_daa_score: Some(11),
                confirmation_depth: None,
            },
        );
        let mut idx = InMemoryIndexer::new();

        let err = idx
            .rebuild_from(&source, &plan)
            .expect_err("confirmation failure expected");

        assert!(matches!(
            err,
            IndexerError::RebuildInsufficientConfirmations { .. }
        ));
    }

    #[test]
    fn scan_cursor_store_round_trips_in_memory() {
        let mut idx = InMemoryIndexer::new();
        let first = ScanCursor {
            chain_id: KASPA_LOCAL_TOCCATA,
            block_hash: [1u8; 32],
            daa_score: 10,
        };
        idx.store_scan_cursor(DEFAULT_SCAN_CURSOR, first.clone())
            .unwrap();
        assert_eq!(
            idx.load_scan_cursor(DEFAULT_SCAN_CURSOR).unwrap(),
            Some(first)
        );

        let second = ScanCursor {
            chain_id: KASPA_LOCAL_TOCCATA,
            block_hash: [2u8; 32],
            daa_score: 11,
        };
        idx.store_scan_cursor(DEFAULT_SCAN_CURSOR, second.clone())
            .unwrap();
        assert_eq!(
            idx.load_scan_cursor(DEFAULT_SCAN_CURSOR).unwrap(),
            Some(second)
        );
        idx.clear_scan_cursor(DEFAULT_SCAN_CURSOR).unwrap();
        assert_eq!(idx.load_scan_cursor(DEFAULT_SCAN_CURSOR).unwrap(), None);
    }

    #[test]
    fn empty_scan_cursor_name_rejected() {
        let mut idx = InMemoryIndexer::new();
        let err = idx
            .store_scan_cursor(
                "",
                ScanCursor {
                    chain_id: KASPA_LOCAL_TOCCATA,
                    block_hash: [1u8; 32],
                    daa_score: 10,
                },
            )
            .unwrap_err();
        assert!(matches!(err, IndexerError::Invariant(_)));
    }

    #[cfg(feature = "persistent")]
    fn temp_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_recovers_100_covenants_after_reopen() {
        let path = temp_path("rgk-sled-indexer-test");
        let _ = std::fs::remove_dir_all(&path);

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            for i in 0..100u8 {
                let mut cov = [0u8; 32];
                cov[31] = i;
                let mut lin = [0xaa; 32];
                lin[31] = i;
                let open = KaspaOutpoint {
                    transaction_id: [i; 32],
                    index: i as u32,
                };
                let next = KaspaOutpoint {
                    transaction_id: [i.wrapping_add(1); 32],
                    index: i as u32 + 1,
                };
                idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, i as u64)
                    .unwrap();
                idx.apply_spend(
                    cov,
                    [i.wrapping_add(2); 32],
                    open,
                    next,
                    state(cov, 2),
                    i as u64 + 1,
                )
                .unwrap();
            }
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            assert_eq!(idx.list().len(), 100);
            for i in 0..100u8 {
                let mut cov = [0u8; 32];
                cov[31] = i;
                let entry = idx.lookup(cov).unwrap();
                assert_eq!(entry.latest_state.state_digest[31], 2);
                assert_eq!(
                    entry.open_outpoint,
                    Some(KaspaOutpoint {
                        transaction_id: [i.wrapping_add(1); 32],
                        index: i as u32 + 1,
                    })
                );
                assert!(idx.has_replay(cov, &[i.wrapping_add(2); 32]));
                assert_eq!(entry.spend_history.len(), 1);
            }
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_persists_continuation_proof_after_reopen() {
        let path = temp_path("rgk-sled-continuation-test");
        let _ = std::fs::remove_dir_all(&path);
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let proof = ContinuationProof {
            commitment: [0x55; 32],
            shape_root: [0x66; 32],
            transition_digest: [0x77; 32],
        };

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
                .unwrap();
            idx.apply_spend_with_continuation(cov, [3u8; 32], open, next, state(cov, 2), 11, proof)
                .unwrap();
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            let entry = idx.lookup(cov).unwrap();
            assert_eq!(entry.spend_history.len(), 1);
            assert_eq!(entry.spend_history[0].continuation, Some(proof));
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_persists_spend_receipt_policy_after_reopen() {
        let path = temp_path("rgk-sled-policy-test");
        let _ = std::fs::remove_dir_all(&path);
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
                .unwrap();
            idx.apply_spend(
                cov,
                [3u8; 32],
                open,
                next,
                state_with_policy(cov, 2, ReceiptPolicy::VerifierOnly),
                11,
            )
            .unwrap();
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            let entry = idx.lookup(cov).unwrap();
            assert_eq!(entry.spend_history.len(), 1);
            assert_eq!(
                entry.spend_history[0].previous_receipt_policy,
                ReceiptPolicy::Any
            );
            assert_eq!(
                entry.spend_history[0].new_receipt_policy,
                ReceiptPolicy::VerifierOnly
            );
            assert_eq!(
                entry.latest_state.receipt_policy,
                ReceiptPolicy::VerifierOnly
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_persists_policy_migration_proof_after_reopen() {
        let path = temp_path("rgk-sled-policy-migration-test");
        let _ = std::fs::remove_dir_all(&path);
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let previous_state = state(cov, 1);
        let new_state = state_with_policy(cov, 2, ReceiptPolicy::VerifierOnly);
        let continuation = ContinuationProof {
            commitment: [0x55; 32],
            shape_root: [0x66; 32],
            transition_digest: [0x77; 32],
        };
        let proof = migration_proof(
            ReceiptPolicy::Any,
            ReceiptPolicy::VerifierOnly,
            previous_state.state_digest,
            new_state.state_digest,
            continuation.transition_digest,
        );

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            idx.open(KASPA_LOCAL_TOCCATA, cov, lin, previous_state, open, 10)
                .unwrap();
            idx.apply_spend_with_continuation_and_policy_migration(
                cov,
                [3u8; 32],
                open,
                next,
                new_state,
                11,
                continuation,
                proof,
            )
            .unwrap();
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            let entry = idx.lookup(cov).unwrap();
            assert_eq!(entry.spend_history.len(), 1);
            assert_eq!(entry.spend_history[0].policy_migration, Some(proof));
            assert_eq!(entry.spend_history[0].resulting_state_digest[31], 2);
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_persists_allocation_audit_certificate_after_reopen() {
        let path = temp_path("rgk-sled-allocation-audit-certificate-test");
        let _ = std::fs::remove_dir_all(&path);
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = outpoint(1, 0);
        let next = outpoint(2, 0);
        let receipt_id = [3u8; 32];
        let certificate = allocation_audit_certificate_record(0x44);

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            idx.open(KASPA_LOCAL_TOCCATA, cov, lin, state(cov, 1), open, 10)
                .unwrap();
            idx.apply_spend(cov, receipt_id, open, next, state(cov, 2), 11)
                .unwrap();
            idx.record_allocation_audit_certificate(cov, receipt_id, certificate.clone())
                .unwrap();
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            let entry = idx.lookup(cov).unwrap();
            assert_eq!(entry.spend_history.len(), 1);
            assert_eq!(
                entry.spend_history[0].allocation_audit_certificate,
                Some(certificate.clone())
            );
            assert_eq!(
                idx.allocation_audit_certificate(cov, receipt_id),
                Some(certificate)
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_persists_lane_records_after_reopen() {
        let path = temp_path("rgk-sled-lane-test");
        let _ = std::fs::remove_dir_all(&path);
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let lane = lane_record(cov, [0x51; 32], Some([0x52; 32]), true, 1, 10);

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            idx.open(
                KASPA_LOCAL_TOCCATA,
                cov,
                lin,
                state(cov, 1),
                outpoint(1, 0),
                10,
            )
            .unwrap();
            idx.register_lane(lane.clone()).unwrap();
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            assert_eq!(idx.lane_by_id(&lane.lane_id), Some(lane.clone()));
            assert_eq!(idx.lane_by_scan_tag(&[0x52; 32]), Some(lane.clone()));
            assert_eq!(idx.public_lanes(&lane.asset_id), vec![lane]);
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_scan_cursor_survives_reopen() {
        let path = temp_path("rgk-sled-cursor-test");
        let _ = std::fs::remove_dir_all(&path);

        let cursor = ScanCursor {
            chain_id: KASPA_LOCAL_TOCCATA,
            block_hash: [7u8; 32],
            daa_score: 42,
        };

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            idx.store_scan_cursor(DEFAULT_SCAN_CURSOR, cursor.clone())
                .unwrap();
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            assert_eq!(
                idx.load_scan_cursor(DEFAULT_SCAN_CURSOR).unwrap(),
                Some(cursor)
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn sled_indexer_persists_rebuild_result_after_reopen() {
        let path = temp_path("rgk-sled-rebuild-test");
        let _ = std::fs::remove_dir_all(&path);
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let plan = rebuild_plan(cov);
        let source = rebuild_source(&plan);

        {
            let mut idx = SledIndexer::open_path(&path).unwrap();
            let summary = idx.rebuild_from(&source, &plan).expect("rebuild");
            assert!(summary.opened);
            assert_eq!(summary.applied_spends, 2);
            idx.flush().unwrap();
        }

        {
            let idx = SledIndexer::open_path(&path).unwrap();
            let entry = idx.lookup(cov).unwrap();
            assert_eq!(entry.latest_state, state(cov, 3));
            assert_eq!(entry.open_outpoint, Some(plan.spends[1].created_outpoint));
            assert_eq!(entry.accepted_receipts, vec![[3u8; 32], [5u8; 32]]);
            assert_eq!(entry.spend_history.len(), 2);
        }

        let _ = std::fs::remove_dir_all(&path);
    }
}
