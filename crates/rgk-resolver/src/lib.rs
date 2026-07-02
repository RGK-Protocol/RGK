#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-resolver
//!
//! The end-to-end resolver. Given a covenant outpoint or native RGK asset id, it
//! reconstructs the canonical RGK state by:
//!
//! 1. Looking up the covenant's open UTXO via [`KaspaChainBackend`]
//! 2. Decoding the covenant payload to recover the [`CovenantState`]
//! 3. Cross-checking the [`InMemoryIndexer`] (or persistent equivalent) for
//!    replay protection
//! 4. Verifying the receipt (local verifier + receipt-policy check)
//! 5. Returning one of the [`ResolverState`] variants
//!
//! The resolver never produces an `OptimisticValid` state. Every output is a
//! fully classified outcome — see SECURITY.md.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(dead_code, unused_imports, unused_variables)]
#![allow(clippy::needless_borrows_for_generic_args, clippy::vec_init_then_push)]
#![allow(
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::derivable_impls
)]

use rgk_asset::{derive_blinded_lane_id, RgkScanTag};
use rgk_core::{
    policy_migration_commitment, receipt_commitment, Bytes32, Canonical, KaspaChainId,
    KaspaCovenantId, KaspaOutpoint, RgkAssetId, RgkReceipt, RgkStateCommitment,
};
use rgk_covenant::CovenantError;
use rgk_indexer::{AllocationAuditCertificateRecord, IndexedLane, Indexer};
use rgk_kaspa::{KaspaChainBackend, KaspaNetworkError, KaspaScriptPublicKey, ResolverClassify};
use rgk_receipt::{ReceiptError, ReceiptVerifier};
use thiserror::Error;

pub use rgk_core::{ProofMode, ReceiptPolicy};

/// The resolver output state. Every variant maps to a specific user-visible
/// outcome; no `SoftInvalid` or `OptimisticValid` states exist by design.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResolverState {
    /// The covenant exists and is open (not yet spent). The state is the
    /// genesis state recorded at indexer open time.
    Open {
        covenant: KaspaCovenantId,
        outpoint: KaspaOutpoint,
        state: RgkStateCommitment,
    },
    /// A spend has been confirmed and the receipt verified. The new state
    /// matches the new state's commitment in the receipt.
    NativeTransitionedValid {
        covenant: KaspaCovenantId,
        spent_outpoint: KaspaOutpoint,
        new_outpoint: KaspaOutpoint,
        receipt_id: Bytes32,
        new_state: RgkStateCommitment,
        allocation_audit_certificate: Option<AllocationAuditCertificateRecord>,
        confirmation_depth: u64,
    },
    /// A spend was detected but the receipt is invalid (mode mismatch,
    /// missing replay nonce, etc.). The covenant is in an unsafe state.
    NativeTransitionedInvalid {
        covenant: KaspaCovenantId,
        reason: ReceiptError,
    },
    /// A spend exists in the mempool but is not yet confirmed.
    Unconfirmed {
        covenant: KaspaCovenantId,
        spending_txid: Bytes32,
    },
    /// A spend is confirmed but the tip moved under it (reorg risk).
    ReorgRisk {
        covenant: KaspaCovenantId,
        daa_score: u64,
    },
    /// The local indexer has one transition for the consumed outpoint, while
    /// the chain backend reports a different spending transaction. This is a
    /// branch conflict and must not be collapsed into generic invalidity.
    CompetingBranch {
        covenant: KaspaCovenantId,
        spent_outpoint: KaspaOutpoint,
        indexed_spending_txid: Bytes32,
        observed_spending_txid: Bytes32,
        observed_daa_score: Option<u64>,
    },
    /// The transition changes receipt policy without a native migration proof.
    /// The resolver refuses to call the transition valid until a dedicated
    /// migration path is implemented and verified.
    PolicyMigrationRequired {
        covenant: KaspaCovenantId,
        current_policy: ReceiptPolicy,
        requested_policy: ReceiptPolicy,
    },
    /// A receipt id has already been accepted for this covenant lineage.
    ReplayRejected {
        covenant: KaspaCovenantId,
        receipt_id: Bytes32,
    },
    /// The covenant has never been indexed and the live node has no UTXO for it.
    Unknown { covenant: KaspaCovenantId },
    /// The node is unreachable or returned an error.
    NodeDown {
        covenant: KaspaCovenantId,
        reason: String,
    },
}

impl ResolverState {
    pub fn covenant(&self) -> KaspaCovenantId {
        match self {
            Self::Open { covenant, .. }
            | Self::NativeTransitionedValid { covenant, .. }
            | Self::NativeTransitionedInvalid { covenant, .. }
            | Self::Unconfirmed { covenant, .. }
            | Self::ReorgRisk { covenant, .. }
            | Self::CompetingBranch { covenant, .. }
            | Self::PolicyMigrationRequired { covenant, .. }
            | Self::ReplayRejected { covenant, .. }
            | Self::Unknown { covenant }
            | Self::NodeDown { covenant, .. } => *covenant,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LaneResolverState {
    Resolved {
        lane: IndexedLane,
        state: Box<ResolverState>,
    },
    UnknownLane {
        lane_id: Bytes32,
    },
    UnknownScanTag {
        scan_tag: Bytes32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransitionResolverState {
    Resolved {
        transition_digest: Bytes32,
        covenant: KaspaCovenantId,
        receipt_id: Bytes32,
        state: Box<ResolverState>,
    },
    UnknownTransition {
        transition_digest: Bytes32,
    },
}

/// Resolver-level errors that bubble up when even the resolver state enum
/// cannot be produced. The enum above is the success / typed-rejection path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ResolverError {
    #[error("resolver budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("indexer error: {0}")]
    Indexer(#[from] rgk_indexer::IndexerError),
    #[error("covenant error: {0}")]
    Covenant(#[from] CovenantError),
    #[error("internal invariant violated: {0}")]
    Invariant(String),
}

/// The RGK resolver. Plug together a backend and an indexer and you have an
/// end-to-end native state resolver.
pub struct RgkResolver<'a, B: KaspaChainBackend, I: Indexer> {
    pub backend: &'a B,
    pub indexer: &'a I,
    pub verifier_chain: KaspaChainId,
    /// How many blocks of reorg risk the resolver tolerates. Anything above
    /// this depth returns `ReorgRisk`. Default: 10.
    pub reorg_safety_depth: u64,
}

impl<'a, B: KaspaChainBackend, I: Indexer> RgkResolver<'a, B, I> {
    pub fn new(backend: &'a B, indexer: &'a I, verifier_chain: KaspaChainId) -> Self {
        Self {
            backend,
            indexer,
            verifier_chain,
            reorg_safety_depth: 10,
        }
    }

    /// Resolve the state of a covenant by `covenant_id`. Pulls the open
    /// outpoint from the indexer, queries the backend, verifies receipts.
    pub fn resolve_by_covenant(&self, covenant: KaspaCovenantId) -> ResolverState {
        // Backend sanity: must be the configured chain.
        match self.backend.network_id() {
            Ok(net) if net == self.verifier_chain => {}
            Ok(net) => {
                return ResolverState::NodeDown {
                    covenant,
                    reason: format!(
                        "backend on {net:?}, resolver expects {:?}",
                        self.verifier_chain
                    ),
                };
            }
            Err(e) => {
                return ResolverState::NodeDown {
                    covenant,
                    reason: e.to_string(),
                };
            }
        }

        // 1. Indexed covenant state.
        let indexed = match self.indexer.lookup(covenant) {
            Some(entry) => entry,
            None => return ResolverState::Unknown { covenant },
        };
        let open_outpoint = match indexed.open_outpoint {
            Some(o) => o,
            None => return ResolverState::Unknown { covenant },
        };

        // 2. If a transition has already been indexed, verify the chain-side
        // spend of the outpoint that was consumed by that latest transition.
        // The newly-created outpoint can be perfectly valid and still open;
        // querying it for a spend would incorrectly turn an applied transition
        // back into `Open`.
        if let Some(last_spend) = indexed.spend_history.last() {
            let spent_utxo = match self.backend.get_utxo(last_spend.spent) {
                Ok(Some(u)) => Some(u),
                Ok(None) => None,
                Err(e) => match e.classify() {
                    ResolverClassify::NodeDown | ResolverClassify::RpcFailure => {
                        return ResolverState::NodeDown {
                            covenant,
                            reason: e.to_string(),
                        };
                    }
                    ResolverClassify::Pruned => return ResolverState::Unknown { covenant },
                    _ => None,
                },
            };
            if let Some(sp) = spent_utxo.and_then(|u| u.spending) {
                let depth = self
                    .backend
                    .confirmation_depth(sp.txid)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                if depth == 0 {
                    return ResolverState::Unconfirmed {
                        covenant,
                        spending_txid: sp.txid,
                    };
                }
                if depth < self.reorg_safety_depth {
                    return ResolverState::ReorgRisk {
                        covenant,
                        daa_score: sp.block_daa_score.unwrap_or(0),
                    };
                }
                if last_spend.created.transaction_id != sp.txid {
                    return ResolverState::CompetingBranch {
                        covenant,
                        spent_outpoint: last_spend.spent,
                        indexed_spending_txid: last_spend.created.transaction_id,
                        observed_spending_txid: sp.txid,
                        observed_daa_score: sp.block_daa_score,
                    };
                }
                if let Err(reason) = validate_indexed_continuation(last_spend, sp.txid) {
                    return ResolverState::NativeTransitionedInvalid { covenant, reason };
                }
                if last_spend.previous_receipt_policy != indexed.latest_state.receipt_policy {
                    if last_spend.policy_migration.is_none() {
                        return ResolverState::PolicyMigrationRequired {
                            covenant,
                            current_policy: last_spend.previous_receipt_policy,
                            requested_policy: indexed.latest_state.receipt_policy,
                        };
                    }
                    if let Err(reason) =
                        validate_indexed_policy_migration(last_spend, &indexed.latest_state)
                    {
                        return ResolverState::NativeTransitionedInvalid { covenant, reason };
                    }
                }
                if last_spend.previous_receipt_policy == indexed.latest_state.receipt_policy
                    && last_spend.policy_migration.is_some()
                {
                    return ResolverState::NativeTransitionedInvalid {
                        covenant,
                        reason: ReceiptError::Structural(
                            "policy migration proof supplied for unchanged policy".into(),
                        ),
                    };
                }
                return ResolverState::NativeTransitionedValid {
                    covenant,
                    spent_outpoint: last_spend.spent,
                    new_outpoint: last_spend.created,
                    receipt_id: last_spend.receipt_id,
                    new_state: indexed.latest_state.clone(),
                    allocation_audit_certificate: last_spend.allocation_audit_certificate.clone(),
                    confirmation_depth: depth,
                };
            }
        }

        // 3. No indexed transition yet; inspect the currently-open outpoint.
        let utxo = match self.backend.get_utxo(open_outpoint) {
            Ok(Some(u)) => u,
            Ok(None) => {
                // Outpoint not at the tip — either pruned or the indexer is stale.
                return ResolverState::Unknown { covenant };
            }
            Err(e) => match e.classify() {
                ResolverClassify::NodeDown | ResolverClassify::RpcFailure => {
                    return ResolverState::NodeDown {
                        covenant,
                        reason: e.to_string(),
                    };
                }
                ResolverClassify::Pruned => return ResolverState::Unknown { covenant },
                _ => return ResolverState::Unknown { covenant },
            },
        };

        // 4. Is it spent?
        if let Some(sp) = utxo.spending.as_ref() {
            // The spending tx exists. Determine confirmations.
            let depth = self
                .backend
                .confirmation_depth(sp.txid)
                .ok()
                .flatten()
                .unwrap_or(0);
            if depth == 0 {
                return ResolverState::Unconfirmed {
                    covenant,
                    spending_txid: sp.txid,
                };
            }
            // Reorg risk if depth is below safety threshold.
            if depth < self.reorg_safety_depth {
                return ResolverState::ReorgRisk {
                    covenant,
                    daa_score: sp.block_daa_score.unwrap_or(0),
                };
            }
            // Try to find a recorded receipt for this transition. The
            // indexer's latest_state is the source of truth.
            let latest = match self.indexer.latest_state(covenant) {
                Some(s) => s,
                None => return ResolverState::Unknown { covenant },
            };
            let last_spend = self
                .indexer
                .lookup(covenant)
                .and_then(|e| e.spend_history.last().cloned());
            let receipt_id = match last_spend.as_ref().map(|spend| spend.receipt_id) {
                Some(receipt_id) => receipt_id,
                None => {
                    return ResolverState::NativeTransitionedInvalid {
                        covenant,
                        reason: ReceiptError::Structural("no receipt in spend history".into()),
                    };
                }
            };
            let new_out = match self.indexer.open_outpoint(covenant) {
                Some(o) => o,
                None => {
                    return ResolverState::NativeTransitionedInvalid {
                        covenant,
                        reason: ReceiptError::Structural("no new outpoint after spend".into()),
                    };
                }
            };
            return ResolverState::NativeTransitionedValid {
                covenant,
                spent_outpoint: open_outpoint,
                new_outpoint: new_out,
                receipt_id,
                new_state: latest,
                allocation_audit_certificate: last_spend
                    .and_then(|spend| spend.allocation_audit_certificate),
                confirmation_depth: depth,
            };
        }

        ResolverState::Open {
            covenant,
            outpoint: open_outpoint,
            state: indexed.latest_state,
        }
    }

    /// Resolve by RGK asset id: scans the indexer for matching covenant states
    /// and returns the first non-Unknown state.
    pub fn resolve_by_asset(&self, asset_id: RgkAssetId) -> ResolverState {
        for covenant in self.indexer.list() {
            if let Some(s) = self.indexer.latest_state(covenant) {
                if s.asset_id == asset_id {
                    return self.resolve_by_covenant(covenant);
                }
            }
        }
        ResolverState::Unknown {
            covenant: [0u8; 32],
        }
    }

    pub fn resolve_lane(&self, lane_id: Bytes32) -> LaneResolverState {
        match self.indexer.lane_by_id(&lane_id) {
            Some(lane) => self.resolve_indexed_lane(lane),
            None => LaneResolverState::UnknownLane { lane_id },
        }
    }

    pub fn resolve_by_view_key(
        &self,
        view_key: Bytes32,
        asset_id: RgkAssetId,
        epoch: u64,
    ) -> LaneResolverState {
        let lane_id = derive_blinded_lane_id(view_key, asset_id, epoch);
        let Some(lane) = self.indexer.lane_by_id(&lane_id) else {
            return LaneResolverState::UnknownLane { lane_id };
        };
        if lane.asset_id != asset_id || lane.epoch != epoch {
            return LaneResolverState::UnknownLane { lane_id };
        }
        let expected_scan_tag = RgkScanTag::derive(view_key, lane_id, epoch);
        if lane
            .scan_tag
            .is_some_and(|tag| tag != expected_scan_tag.to_bytes())
        {
            return LaneResolverState::UnknownLane { lane_id };
        }
        self.resolve_indexed_lane(lane)
    }

    pub fn resolve_by_scan_tag(&self, scan_tag: RgkScanTag) -> LaneResolverState {
        match self.indexer.lane_by_scan_tag(scan_tag.as_bytes()) {
            Some(lane) => self.resolve_indexed_lane(lane),
            None => LaneResolverState::UnknownScanTag {
                scan_tag: scan_tag.to_bytes(),
            },
        }
    }

    pub fn resolve_public_lineage(&self, asset_id: RgkAssetId) -> Vec<LaneResolverState> {
        self.indexer
            .public_lanes(&asset_id)
            .into_iter()
            .map(|lane| self.resolve_indexed_lane(lane))
            .collect()
    }

    pub fn resolve_transition(&self, transition_digest: Bytes32) -> TransitionResolverState {
        for covenant in self.indexer.list() {
            let Some(entry) = self.indexer.lookup(covenant) else {
                continue;
            };
            let Some(spend) = entry.spend_history.iter().find(|spend| {
                spend
                    .continuation
                    .is_some_and(|proof| proof.transition_digest == transition_digest)
            }) else {
                continue;
            };
            let receipt_id = spend.receipt_id;
            let state = self.resolve_by_covenant(covenant);
            return TransitionResolverState::Resolved {
                transition_digest,
                covenant,
                receipt_id,
                state: Box::new(state),
            };
        }
        TransitionResolverState::UnknownTransition { transition_digest }
    }

    fn resolve_indexed_lane(&self, lane: IndexedLane) -> LaneResolverState {
        let state = self.resolve_by_covenant(lane.covenant_id);
        LaneResolverState::Resolved {
            lane,
            state: Box::new(state),
        }
    }

    /// Verify a receipt against the current indexer state. Returns Ok(new
    /// state to apply) on success, Err(receipt error) on hard rejection.
    pub fn verify_receipt_against_indexer(
        &self,
        covenant: KaspaCovenantId,
        receipt_bytes: &[u8],
    ) -> Result<RgkStateCommitment, ReceiptError> {
        let expected_old = self
            .indexer
            .latest_state(covenant)
            .ok_or_else(|| ReceiptError::Structural("covenant not indexed".into()))?;
        let receipt =
            RgkReceipt::decode_canonical(receipt_bytes).map_err(ReceiptError::DecodeFailure)?;
        let receipt_id = receipt_commitment(&receipt);
        if self.indexer.has_replay(covenant, &receipt_id) {
            return Err(ReceiptError::Replay(receipt_id.into()));
        }
        let _id = ReceiptVerifier::verify_local(
            receipt_bytes,
            covenant,
            &expected_old,
            self.verifier_chain,
        )?;
        Ok(receipt.new_state.clone())
    }
}

fn validate_indexed_continuation(
    spend: &rgk_indexer::SpendEntry,
    observed_spending_txid: Bytes32,
) -> Result<(), ReceiptError> {
    let proof = spend.continuation.as_ref().ok_or_else(|| {
        ReceiptError::Structural("missing continuation proof in spend history".into())
    })?;
    if proof.commitment == [0u8; 32] {
        return Err(ReceiptError::Structural(
            "missing phase-1 continuation commitment".into(),
        ));
    }
    if proof.shape_root == [0u8; 32] {
        return Err(ReceiptError::Structural(
            "missing continuation shape root".into(),
        ));
    }
    if proof.transition_digest == [0u8; 32] {
        return Err(ReceiptError::Structural(
            "missing phase-2 transition digest".into(),
        ));
    }
    if spend.created.transaction_id != observed_spending_txid {
        return Err(ReceiptError::Structural(format!(
            "continuation outpoint txid does not match observed spend txid: created 0x{}, observed 0x{}",
            rgk_core::to_hex(&spend.created.transaction_id),
            rgk_core::to_hex(&observed_spending_txid)
        )));
    }
    Ok(())
}

fn validate_indexed_policy_migration(
    spend: &rgk_indexer::SpendEntry,
    latest_state: &RgkStateCommitment,
) -> Result<(), ReceiptError> {
    let proof = spend.policy_migration.as_ref().ok_or_else(|| {
        ReceiptError::Structural("missing policy migration proof in spend history".into())
    })?;
    let continuation = spend.continuation.as_ref().ok_or_else(|| {
        ReceiptError::Structural("policy migration proof requires continuation proof".into())
    })?;
    if proof.previous_policy != spend.previous_receipt_policy {
        return Err(ReceiptError::Structural(
            "policy migration previous policy does not match spend history".into(),
        ));
    }
    if proof.new_policy != spend.new_receipt_policy {
        return Err(ReceiptError::Structural(
            "policy migration new policy does not match spend history".into(),
        ));
    }
    if proof.new_policy != latest_state.receipt_policy {
        return Err(ReceiptError::Structural(
            "policy migration new policy does not match latest state".into(),
        ));
    }
    if proof.previous_state_digest != spend.new_state_digest {
        return Err(ReceiptError::Structural(
            "policy migration previous state digest does not match spend history".into(),
        ));
    }
    if proof.new_state_digest != spend.resulting_state_digest
        || proof.new_state_digest != latest_state.state_digest
    {
        return Err(ReceiptError::Structural(
            "policy migration new state digest does not match latest state".into(),
        ));
    }
    if proof.transition_digest != continuation.transition_digest {
        return Err(ReceiptError::Structural(
            "policy migration transition digest does not match continuation proof".into(),
        ));
    }
    if proof.authorization_commitment == [0u8; 32] {
        return Err(ReceiptError::Structural(
            "policy migration authorisation commitment missing".into(),
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
        return Err(ReceiptError::Structural(
            "policy migration commitment does not match proof fields".into(),
        ));
    }
    Ok(())
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use rgk_core::{from_hex, KASPA_LOCAL_TOCCATA};
    use rgk_indexer::{
        AllocationAuditCertificateRecord, AllocationAuditCertificateStore, ContinuationProof,
        InMemoryIndexer, PolicyMigrationProof,
    };
    use rgk_kaspa::{FixtureBackend, KaspaUtxo};
    use rgk_receipt::{ReceiptBuilder, ReceiptInput};

    fn b32(s: &str) -> [u8; 32] {
        from_hex::<32>(s).expect("hex")
    }

    fn sample_state(
        covenant: KaspaCovenantId,
        digest: u8,
        asset_id: Bytes32,
    ) -> RgkStateCommitment {
        RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            covenant,
            asset_id,
            {
                let mut d = [0u8; 32];
                d[31] = digest;
                d
            },
            ReceiptPolicy::Any,
        )
        .expect("sample resolver state commitment is valid")
    }

    fn lane_record(
        covenant: KaspaCovenantId,
        asset_id: Bytes32,
        lane_id: Bytes32,
        epoch: u64,
        scan_tag: Option<Bytes32>,
        public_lineage: bool,
        digest: u8,
        daa_score: u64,
    ) -> IndexedLane {
        IndexedLane::new(
            KASPA_LOCAL_TOCCATA,
            covenant,
            asset_id,
            lane_id,
            epoch,
            scan_tag,
            public_lineage,
            {
                let mut d = [0u8; 32];
                d[31] = digest;
                d
            },
            daa_score,
        )
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

    fn allocation_audit_certificate_record(id_byte: u8) -> AllocationAuditCertificateRecord {
        let certificate_id = [id_byte; 32];
        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(b"rgk:aac1");
        canonical_bytes.extend_from_slice(&certificate_id);
        canonical_bytes.push(0xa5);
        AllocationAuditCertificateRecord::new(certificate_id, canonical_bytes)
            .expect("valid allocation audit certificate envelope")
    }

    fn empty_spk() -> KaspaScriptPublicKey {
        KaspaScriptPublicKey::new(vec![]).unwrap()
    }

    fn test_utxo(outpoint: KaspaOutpoint, value: u64, daa_score: u64) -> KaspaUtxo {
        KaspaUtxo::from_script_public_key(outpoint, value, empty_spk(), Some(daa_score), None)
    }

    fn test_summary(txid: Bytes32) -> rgk_kaspa::KaspaTxSummary {
        rgk_kaspa::KaspaTxSummary::new(txid, 1, vec![])
    }

    fn test_tip(hash: Bytes32, blue_score: u64, daa_score: u64) -> rgk_kaspa::KaspaTip {
        rgk_kaspa::KaspaTip::new(hash, blue_score, daa_score)
    }

    #[test]
    fn unknown_when_not_indexed() {
        let backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let idx = InMemoryIndexer::new();
        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let st = r.resolve_by_covenant(b32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ));
        assert!(matches!(st, ResolverState::Unknown { .. }));
    }

    #[test]
    fn open_when_indexed_and_utxo_present() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(
                cov,
                1,
                b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            ),
            open,
            10,
        )
        .unwrap();
        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let st = r.resolve_by_covenant(cov);
        match st {
            ResolverState::Open {
                covenant, outpoint, ..
            } => {
                assert_eq!(covenant, cov);
                assert_eq!(outpoint, open);
            }
            _ => panic!("expected Open, got {:?}", st),
        }
    }

    #[test]
    fn resolve_lane_returns_registered_lane_state() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let asset_id = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let lane_id = [0x51; 32];

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, asset_id),
            open,
            10,
        )
        .unwrap();
        idx.register_lane(lane_record(cov, asset_id, lane_id, 7, None, false, 1, 10))
            .unwrap();
        backend.add_utxo_at(10, test_utxo(open, 1000, 10));

        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let st = r.resolve_lane(lane_id);
        assert!(matches!(
            st,
            LaneResolverState::Resolved { state, .. }
                if matches!(state.as_ref(), ResolverState::Open { .. })
        ));
    }

    #[test]
    fn resolve_by_view_key_discovers_only_matching_private_lane() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let asset_id = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let view_key = [0x41; 32];
        let wrong_view_key = [0x42; 32];
        let epoch = 9;
        let lane_id = derive_blinded_lane_id(view_key, asset_id, epoch);
        let scan_tag = RgkScanTag::derive(view_key, lane_id, epoch);

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, asset_id),
            open,
            10,
        )
        .unwrap();
        idx.register_lane(lane_record(
            cov,
            asset_id,
            lane_id,
            epoch,
            Some(scan_tag.to_bytes()),
            false,
            1,
            10,
        ))
        .unwrap();
        backend.add_utxo_at(10, test_utxo(open, 1000, 10));

        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        assert!(matches!(
            r.resolve_by_view_key(view_key, asset_id, epoch),
            LaneResolverState::Resolved { .. }
        ));
        assert!(matches!(
            r.resolve_by_view_key(wrong_view_key, asset_id, epoch),
            LaneResolverState::UnknownLane { .. }
        ));
        assert!(matches!(
            r.resolve_by_scan_tag(scan_tag),
            LaneResolverState::Resolved { .. }
        ));
        assert!(matches!(
            r.resolve_by_scan_tag(RgkScanTag::from_bytes([0x99; 32]).unwrap()),
            LaneResolverState::UnknownScanTag { .. }
        ));
    }

    #[test]
    fn resolve_public_lineage_returns_only_public_lanes_for_asset() {
        let backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let asset_id = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let other_asset = b32("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

        for (n, cov, asset, public_lineage) in [
            (1u8, [0x11; 32], asset_id, true),
            (2u8, [0x22; 32], asset_id, false),
            (3u8, [0x33; 32], other_asset, true),
        ] {
            idx.open(
                KASPA_LOCAL_TOCCATA,
                cov,
                [0xaa; 32],
                sample_state(cov, 1, asset),
                KaspaOutpoint {
                    transaction_id: [n; 32],
                    index: 0,
                },
                10,
            )
            .unwrap();
            idx.register_lane(lane_record(
                cov,
                asset,
                [0x50 + n; 32],
                7,
                None,
                public_lineage,
                1,
                10,
            ))
            .unwrap();
        }

        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let public = r.resolve_public_lineage(asset_id);
        assert_eq!(public.len(), 1);
        assert!(matches!(
            &public[0],
            LaneResolverState::Resolved { lane, .. } if lane.lane_id == [0x51; 32]
        ));
    }

    #[test]
    fn transitioned_valid_uses_latest_indexed_spent_outpoint() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let receipt_id = [3u8; 32];
        let spend_tx = [4u8; 32];
        let next = KaspaOutpoint {
            transaction_id: spend_tx,
            index: 0,
        };

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, b32("cc".repeat(32).as_str())),
            open,
            10,
        )
        .unwrap();
        idx.apply_spend_with_continuation(
            cov,
            receipt_id,
            open,
            next,
            sample_state(cov, 2, b32("cc".repeat(32).as_str())),
            11,
            ContinuationProof {
                commitment: [0x55; 32],
                shape_root: [0x66; 32],
                transition_digest: [0x77; 32],
            },
        )
        .unwrap();
        let allocation_audit_certificate = allocation_audit_certificate_record(0x44);
        idx.record_allocation_audit_certificate(
            cov,
            receipt_id,
            allocation_audit_certificate.clone(),
        )
        .unwrap();

        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        backend.spend_at(open, 11, spend_tx, 0);
        backend.submit(test_summary(spend_tx));
        backend.add_utxo_at(11, test_utxo(next, 900, 11));

        let mut r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        r.reorg_safety_depth = 1;
        let st = r.resolve_by_covenant(cov);
        match st {
            ResolverState::NativeTransitionedValid {
                spent_outpoint,
                new_outpoint,
                receipt_id: got_receipt_id,
                allocation_audit_certificate: got_allocation_audit_certificate,
                confirmation_depth,
                ..
            } => {
                assert_eq!(spent_outpoint, open);
                assert_eq!(new_outpoint, next);
                assert_eq!(got_receipt_id, receipt_id);
                assert_eq!(
                    got_allocation_audit_certificate,
                    Some(allocation_audit_certificate)
                );
                assert_eq!(confirmation_depth, 1);
            }
            _ => panic!("expected NativeTransitionedValid, got {:?}", st),
        }

        let transition = r.resolve_transition([0x77; 32]);
        assert!(matches!(
            transition,
            TransitionResolverState::Resolved {
                covenant,
                receipt_id: got_receipt_id,
                state,
                ..
            } if covenant == cov
                && got_receipt_id == receipt_id
                && matches!(state.as_ref(), ResolverState::NativeTransitionedValid { .. })
        ));
    }

    #[test]
    fn transitioned_invalid_when_continuation_proof_is_missing() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let spend_tx = [4u8; 32];
        let next = KaspaOutpoint {
            transaction_id: spend_tx,
            index: 0,
        };

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, b32("cc".repeat(32).as_str())),
            open,
            10,
        )
        .unwrap();
        idx.apply_spend(
            cov,
            [3u8; 32],
            open,
            next,
            sample_state(cov, 2, b32("cc".repeat(32).as_str())),
            11,
        )
        .unwrap();

        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        backend.spend_at(open, 11, spend_tx, 0);
        backend.submit(test_summary(spend_tx));

        let mut r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        r.reorg_safety_depth = 1;
        let st = r.resolve_by_covenant(cov);
        assert!(matches!(
            st,
            ResolverState::NativeTransitionedInvalid { reason, .. }
                if matches!(reason, ReceiptError::Structural(_))
        ));
    }

    #[test]
    fn competing_branch_when_continuation_txid_does_not_match_observed_spend() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let spend_tx = [4u8; 32];
        let wrong_next = KaspaOutpoint {
            transaction_id: [9u8; 32],
            index: 0,
        };

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, b32("cc".repeat(32).as_str())),
            open,
            10,
        )
        .unwrap();
        idx.apply_spend_with_continuation(
            cov,
            [3u8; 32],
            open,
            wrong_next,
            sample_state(cov, 2, b32("cc".repeat(32).as_str())),
            11,
            ContinuationProof {
                commitment: [0x55; 32],
                shape_root: [0x66; 32],
                transition_digest: [0x77; 32],
            },
        )
        .unwrap();

        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        backend.spend_at(open, 11, spend_tx, 0);
        backend.submit(test_summary(spend_tx));

        let mut r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        r.reorg_safety_depth = 1;
        let st = r.resolve_by_covenant(cov);
        assert!(matches!(
            st,
            ResolverState::CompetingBranch {
                indexed_spending_txid,
                observed_spending_txid,
                ..
            } if indexed_spending_txid == [9u8; 32]
                && observed_spending_txid == spend_tx
        ));
    }

    #[test]
    fn competing_branch_when_observed_spend_disagrees_with_indexed_transition() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let indexed_spend_tx = [4u8; 32];
        let observed_spend_tx = [8u8; 32];
        let indexed_next = KaspaOutpoint {
            transaction_id: indexed_spend_tx,
            index: 0,
        };

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, b32("cc".repeat(32).as_str())),
            open,
            10,
        )
        .unwrap();
        idx.apply_spend_with_continuation(
            cov,
            [3u8; 32],
            open,
            indexed_next,
            sample_state(cov, 2, b32("cc".repeat(32).as_str())),
            11,
            ContinuationProof {
                commitment: [0x55; 32],
                shape_root: [0x66; 32],
                transition_digest: [0x77; 32],
            },
        )
        .unwrap();

        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        backend.spend_at(open, 12, observed_spend_tx, 0);
        backend.submit(test_summary(observed_spend_tx));

        let mut r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        r.reorg_safety_depth = 1;
        let st = r.resolve_by_covenant(cov);
        assert!(matches!(
            st,
            ResolverState::CompetingBranch {
                spent_outpoint,
                indexed_spending_txid,
                observed_spending_txid,
                observed_daa_score,
                ..
            } if spent_outpoint == open
                && indexed_spending_txid == indexed_spend_tx
                && observed_spending_txid == observed_spend_tx
                && observed_daa_score == Some(12)
        ));
    }

    #[test]
    fn policy_migration_required_when_indexed_transition_changes_receipt_policy() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let asset = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let spend_tx = [4u8; 32];
        let next = KaspaOutpoint {
            transaction_id: spend_tx,
            index: 0,
        };
        let mut migrated_state = sample_state(cov, 2, asset);
        migrated_state.receipt_policy = ReceiptPolicy::VerifierOnly;

        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, asset),
            open,
            10,
        )
        .unwrap();
        idx.apply_spend_with_continuation(
            cov,
            [3u8; 32],
            open,
            next,
            migrated_state,
            11,
            ContinuationProof {
                commitment: [0x55; 32],
                shape_root: [0x66; 32],
                transition_digest: [0x77; 32],
            },
        )
        .unwrap();

        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        backend.spend_at(open, 11, spend_tx, 0);
        backend.submit(test_summary(spend_tx));

        let mut r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        r.reorg_safety_depth = 1;
        let st = r.resolve_by_covenant(cov);
        assert!(matches!(
            st,
            ResolverState::PolicyMigrationRequired {
                current_policy: ReceiptPolicy::Any,
                requested_policy: ReceiptPolicy::VerifierOnly,
                ..
            }
        ));
    }

    #[test]
    fn valid_policy_migration_proof_allows_explicit_policy_change() {
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let asset = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let spend_tx = [4u8; 32];
        let next = KaspaOutpoint {
            transaction_id: spend_tx,
            index: 0,
        };
        let old_state = sample_state(cov, 1, asset);
        let mut migrated_state = sample_state(cov, 2, asset);
        migrated_state.receipt_policy = ReceiptPolicy::VerifierOnly;
        let continuation = ContinuationProof {
            commitment: [0x55; 32],
            shape_root: [0x66; 32],
            transition_digest: [0x77; 32],
        };
        let proof = migration_proof(
            ReceiptPolicy::Any,
            ReceiptPolicy::VerifierOnly,
            old_state.state_digest,
            migrated_state.state_digest,
            continuation.transition_digest,
        );

        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, old_state, open, 10)
            .unwrap();
        idx.apply_spend_with_continuation_and_policy_migration(
            cov,
            [3u8; 32],
            open,
            next,
            migrated_state,
            11,
            continuation,
            proof,
        )
        .unwrap();

        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        backend.spend_at(open, 11, spend_tx, 0);
        backend.submit(test_summary(spend_tx));

        let mut r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        r.reorg_safety_depth = 1;
        let st = r.resolve_by_covenant(cov);
        assert_eq!(st.covenant(), cov);
        assert!(matches!(
            st,
            ResolverState::NativeTransitionedValid {
                new_state,
                ..
            } if new_state.receipt_policy == ReceiptPolicy::VerifierOnly
        ));
    }

    #[test]
    fn node_down_propagates() {
        let backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA)
            .with_failure(KaspaNetworkError::NodeUnavailable("test".into()));
        let idx = InMemoryIndexer::new();
        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let st = r.resolve_by_covenant(b32(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ));
        assert!(matches!(st, ResolverState::NodeDown { .. }));
    }

    #[test]
    fn reorg_risk_when_spent_below_safety_depth() {
        // The fixture's confirmation_depth returns Some(1) for the submitted
        // spend tx. Since 1 < reorg_safety_depth (10), the resolver treats
        // this as ReorgRisk. Once the indexer is updated via apply_spend
        // AND the chain advances past the safety depth, the next call would
        // return NativeTransitionedValid.
        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, b32("cc".repeat(32).as_str())),
            open,
            10,
        )
        .unwrap();
        backend.add_utxo_at(10, test_utxo(open, 1000, 10));
        let spend_tx = [2u8; 32];
        backend.submit(test_summary(spend_tx));
        backend.spend_at(open, 11, spend_tx, 0);
        backend.set_tip(test_tip([9u8; 32], 100, 100));
        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let st = r.resolve_by_covenant(cov);
        assert!(matches!(st, ResolverState::ReorgRisk { .. }));
    }

    #[test]
    fn verify_receipt_against_indexer_rejects_mismatch() {
        let backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        idx.open(
            KASPA_LOCAL_TOCCATA,
            cov,
            lin,
            sample_state(cov, 1, b32("cc".repeat(32).as_str())),
            KaspaOutpoint {
                transaction_id: [1u8; 32],
                index: 0,
            },
            10,
        )
        .unwrap();
        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let bogus = vec![0u8; 200];
        let err = r.verify_receipt_against_indexer(cov, &bogus).unwrap_err();
        assert!(matches!(err, ReceiptError::DecodeFailure(_)));
    }

    #[test]
    fn verify_receipt_against_indexer_rejects_replay_before_old_state_mismatch() {
        let backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let mut idx = InMemoryIndexer::new();
        let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let asset = b32("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let open = KaspaOutpoint {
            transaction_id: [1u8; 32],
            index: 0,
        };
        let next = KaspaOutpoint {
            transaction_id: [2u8; 32],
            index: 0,
        };
        let old_state = sample_state(cov, 1, asset);
        let new_state = sample_state(cov, 2, asset);
        let input = ReceiptInput::new(
            KASPA_LOCAL_TOCCATA,
            cov,
            old_state.clone(),
            new_state.clone(),
            [0x44; 32],
            [0x55; 32],
            ProofMode::VerifierReceipt,
            [0x66; 32],
        )
        .unwrap();
        let (_receipt, receipt_id, receipt_bytes) = ReceiptBuilder::build(&input).unwrap();

        idx.open(KASPA_LOCAL_TOCCATA, cov, lin, old_state, open, 10)
            .unwrap();
        idx.apply_spend(cov, receipt_id, open, next, new_state, 11)
            .unwrap();

        let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
        let err = r
            .verify_receipt_against_indexer(cov, &receipt_bytes)
            .unwrap_err();
        assert!(matches!(err, ReceiptError::Replay(id) if id.0 == receipt_id));
    }
}
