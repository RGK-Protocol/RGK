#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-receipt
//!
//! Builds, encodes, and verifies RGK receipts.
//!
//! The receipt is the **only** object that crosses the native RGK verifier ->
//! Kaspa covenant boundary. The verifier produces a [`RgkReceipt`] by filling
//! in `old_state` from the previous covenant commitment and `new_state` from
//! the new RGK transition bundle.
//!
//! The verifier on the Kaspa side (resolver, covenant, or local node) checks:
//!
//! 1. canonical encoding + magic + version
//! 2. chain id matches the configured network
//! 3. covenant id matches the covenant under spend
//! 4. `old_state` matches the *known* current RGK state of that covenant
//! 5. `new_state` is a valid forward step from `old_state` (digest changed,
//!    asset id preserved, policy preserved)
//! 6. proof mode is admitted by the covenant's `ReceiptPolicy`
//! 7. receipt id was not seen before (replay protection — enforced by the
//!    indexer, not by the receipt itself)
//!
//! Every check is `fail-closed`: any mismatch produces a [`ReceiptError`] and
//! no optimistic acceptance is ever returned.
//!
//! What the receipt does **not** prove by itself:
//! * It does not by itself prove the RGK transition was valid against the
//!   asset grammar. That proof is the native verifier's responsibility, and
//!   the receipt's `transition_digest` binds to it. See `docs/SECURITY.md`.
//! * It does not prove the covenant lineage is real — that is the resolver's
//!   responsibility, queried against the live chain.
//! * It does not prove replay protection on its own — that is the indexer's.

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

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use rgk_core::DecodeError as CoreDecodeError;
use rgk_core::{
    receipt_commitment, Bytes32, Canonical, ContinuationCommitment, KaspaChainId, KaspaCovenantId,
    ReceiptId, RgkReceipt, RgkStateCommitment, TransitionDigest,
};
use thiserror::Error;

pub use rgk_core::{ProofMode, ReceiptPolicy};

/// A typed error returned by every receipt operation. Every variant maps to a
/// hard rejection — there is no `Ok(SoftInvalid)` variant by design.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReceiptError {
    #[error(
        "chain id mismatch: receipt declares {receipt:?}, verifier configured for {verifier:?}"
    )]
    ChainMismatch {
        receipt: KaspaChainId,
        verifier: KaspaChainId,
    },
    #[error("covenant id mismatch: receipt declares {covenant}, covenant under spend is {actual}")]
    CovenantMismatch { covenant: Hex32, actual: Hex32 },
    #[error("asset id mismatch: receipt expects {expected}, current state is {actual}")]
    AssetMismatch { expected: Hex32, actual: Hex32 },
    #[error("old state digest mismatch: receipt expects {expected}, current state is {actual}")]
    OldStateMismatch { expected: Hex32, actual: Hex32 },
    #[error("receipt policy not compatible with proof mode {mode:?} (policy {policy:?})")]
    PolicyRejectsMode {
        policy: ReceiptPolicy,
        mode: ProofMode,
    },
    #[error("receipt decode failure: {0}")]
    DecodeFailure(String),
    #[error("receipt {0} was already consumed (replay detected)")]
    Replay(Hex32),
    #[error("receipt references unknown chain {0:?}")]
    UnknownChain(KaspaChainId),
    #[error("transition digest missing (must be non-zero)")]
    MissingTransitionDigest,
    #[error("continuation commitment missing (must be non-zero)")]
    MissingContinuationCommitment,
    #[error("replay nonce missing (must be non-zero)")]
    MissingReplayNonce,
}

/// Newtype around a 32-byte array with a Display impl that renders as
/// `0x` + lowercase hex. Used in [`ReceiptError`] so the thiserror derive
/// can produce a human-readable `Display` without breaking on raw bytes.
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

/// Alias used throughout the crate to keep signatures short.
pub type RgkAssetId = Bytes32;

/// Input bundle for [`ReceiptBuilder::build`]. Mirrors the canonical receipt
/// fields without copying the encoding layer; the builder encodes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptInput {
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub old_state: RgkStateCommitment,
    pub new_state: RgkStateCommitment,
    pub transition_digest: TransitionDigest,
    pub continuation_commitment: ContinuationCommitment,
    pub proof_mode: ProofMode,
    pub replay_nonce: Bytes32,
}

/// Receipt builder. Encodes, computes the canonical id, and runs the local
/// structural checks. Does **not** verify against the indexer — that is the
/// verifier's job.
pub struct ReceiptBuilder;

impl ReceiptBuilder {
    /// Build a receipt from validated RGK/Kaspa state. Performs:
    /// * structural validation of the receipt (see [`RgkReceipt::validate_structure`])
    /// * canonical encoding
    /// * derivation of the canonical receipt id
    ///
    /// Returns the receipt and its [`ReceiptId`]. The encoding is included for
    /// convenience (e.g. to embed in the covenant's payload).
    pub fn build(input: &ReceiptInput) -> Result<(RgkReceipt, ReceiptId, Vec<u8>), ReceiptError> {
        if input.transition_digest == [0u8; 32] {
            return Err(ReceiptError::MissingTransitionDigest);
        }
        if input.continuation_commitment == [0u8; 32] {
            return Err(ReceiptError::MissingContinuationCommitment);
        }
        if input.replay_nonce == [0u8; 32] {
            return Err(ReceiptError::MissingReplayNonce);
        }
        let receipt = RgkReceipt {
            version: rgk_core::ENCODING_VERSION,
            chain_id: input.chain_id,
            covenant_id: input.covenant_id,
            old_state: input.old_state.clone(),
            new_state: input.new_state.clone(),
            transition_digest: input.transition_digest,
            continuation_commitment: input.continuation_commitment,
            proof_mode: input.proof_mode,
            replay_nonce: input.replay_nonce,
        };
        receipt
            .validate_structure()
            .map_err(|e| ReceiptError::DecodeFailure(e.to_string()))?;
        let bytes = receipt.encode_canonical();
        let id = receipt_commitment(&receipt);
        Ok((receipt, id, bytes))
    }
}

/// Local receipt verifier. Checks structural and policy invariants but does
/// **not** consult the indexer for replay protection — that is done by the
/// resolver. This split is deliberate so the verifier can be used in
/// `no_std`/embedded contexts where the indexer is not available.
pub struct ReceiptVerifier;

impl ReceiptVerifier {
    /// Verify a receipt against a known `expected_old_state` and the
    /// `covenant_id` currently under spend. Returns the receipt id on success.
    pub fn verify_local(
        receipt_bytes: &[u8],
        expected_covenant_id: KaspaCovenantId,
        expected_old_state: &RgkStateCommitment,
        verifier_chain: KaspaChainId,
    ) -> Result<ReceiptId, ReceiptError> {
        let receipt = RgkReceipt::decode_canonical(receipt_bytes)
            .map_err(|e: CoreDecodeError| ReceiptError::DecodeFailure(e.to_string()))?;
        Self::verify_local_structured(
            &receipt,
            expected_covenant_id,
            expected_old_state,
            verifier_chain,
        )
    }

    /// Same as [`Self::verify_local`] but takes a structured receipt
    /// (useful after the caller has already decoded the bytes).
    pub fn verify_local_structured(
        receipt: &RgkReceipt,
        expected_covenant_id: KaspaCovenantId,
        expected_old_state: &RgkStateCommitment,
        verifier_chain: KaspaChainId,
    ) -> Result<ReceiptId, ReceiptError> {
        // Chain
        if receipt.chain_id != verifier_chain {
            return Err(ReceiptError::ChainMismatch {
                receipt: receipt.chain_id,
                verifier: verifier_chain,
            });
        }
        // Covenant id
        if receipt.covenant_id != expected_covenant_id {
            return Err(ReceiptError::CovenantMismatch {
                covenant: Hex32(receipt.covenant_id),
                actual: Hex32(expected_covenant_id),
            });
        }
        // RGK asset id
        if receipt.old_state.asset_id != expected_old_state.asset_id
            || receipt.new_state.asset_id != expected_old_state.asset_id
        {
            return Err(ReceiptError::AssetMismatch {
                expected: Hex32(expected_old_state.asset_id),
                actual: Hex32(receipt.old_state.asset_id),
            });
        }
        // Old state digest
        if receipt.old_state.state_digest != expected_old_state.state_digest {
            return Err(ReceiptError::OldStateMismatch {
                expected: Hex32(receipt.old_state.state_digest),
                actual: Hex32(expected_old_state.state_digest),
            });
        }
        // Policy / mode compatibility
        if !expected_old_state.receipt_policy.admits(receipt.proof_mode) {
            return Err(ReceiptError::PolicyRejectsMode {
                policy: expected_old_state.receipt_policy,
                mode: receipt.proof_mode,
            });
        }
        Ok(receipt_commitment(receipt))
    }
}

/// Display helper: render a [`ReceiptId`] as 0x-hex. Mirrors the
/// `rgk_core::display_bytes32` helper but is re-exported here so downstream
/// callers do not need to depend on `rgk_core` directly.
pub fn receipt_id_hex(id: &ReceiptId) -> String {
    use rgk_core::to_hex;
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    s.push_str(&to_hex(id));
    s
}

/// A short, deterministic textual summary of a receipt for log lines.
pub fn receipt_summary(r: &RgkReceipt) -> String {
    format!(
        "RGK receipt id=0x{} chain={} covenant=0x{} mode={} policy={} transition=0x{} continuation=0x{}",
        &receipt_id_hex(&receipt_commitment(r))[..18],
        r.chain_id.as_domain_str(),
        &hex_short(&r.covenant_id),
        r.proof_mode.as_str(),
        r.old_state.receipt_policy.as_domain_str(),
        &hex_short(&r.transition_digest),
        &hex_short(&r.continuation_commitment),
    )
}

fn hex_short(b: &Bytes32) -> String {
    use rgk_core::to_hex;
    let s = to_hex(b);
    s[..16].to_string()
}

/// A typed receipt-id tracker. The verifier uses this to enforce replay
/// protection: a receipt id can only be accepted once per (covenant_id,
/// transition_digest) pair.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplaySet {
    seen: Vec<ReceiptId>,
}

impl ReplaySet {
    pub fn new() -> Self {
        Self { seen: Vec::new() }
    }

    /// Record a receipt id. Returns `Err(ReceiptError::Replay)` if already
    /// present, `Ok(())` on first acceptance.
    pub fn record(&mut self, id: ReceiptId) -> Result<(), ReceiptError> {
        if self.seen.contains(&id) {
            return Err(ReceiptError::Replay(Hex32(id)));
        }
        self.seen.push(id);
        Ok(())
    }

    pub fn contains(&self, id: &ReceiptId) -> bool {
        self.seen.contains(id)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Render a typed error using its display impl. Pulled out so the resolver can
/// format errors uniformly without re-implementing `Display`.
pub fn err_string(e: &ReceiptError) -> String {
    format!("{}", e)
}

// ---------------- helpers for callers ----------------

/// A typed `new_state` payload — convenience wrapper that prevents the caller
/// from forgetting to set the chain / covenant id consistently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewStateSpec<'a> {
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub asset_id: Bytes32,
    pub state_digest: Bytes32,
    pub receipt_policy: ReceiptPolicy,
    /// Borrowed for API symmetry; never inspected by this builder.
    pub _marker: core::marker::PhantomData<&'a ()>,
}

impl<'a> NewStateSpec<'a> {
    pub fn into_commitment(&self) -> RgkStateCommitment {
        RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: self.chain_id,
            covenant_id: self.covenant_id,
            asset_id: self.asset_id,
            state_digest: self.state_digest,
            receipt_policy: self.receipt_policy,
        }
    }
}

/// Helper: returns a default replay nonce bound to `(prev_outpoint_payload,
/// transition_digest)`. Re-export of the helper from `rgk_core::commit` so
/// callers don't need two deps.
pub fn derive_replay_nonce(
    prev_outpoint_payload: &[u8],
    transition_digest: &TransitionDigest,
) -> Bytes32 {
    rgk_core::replay_nonce(prev_outpoint_payload, transition_digest)
}

#[doc(hidden)]
pub mod __reexports {
    pub use rgk_core;
}

/// Pretty-print a list of receipt errors seen during batch verification.
pub fn batch_err_string(errs: &[ReceiptError]) -> String {
    let mut out = String::new();
    for (i, e) in errs.iter().enumerate() {
        out.push_str(&format!("[{}] {}\n", i, e));
    }
    if out.is_empty() {
        out.push_str("<no errors>\n");
    }
    out
}

/// Trait for objects that can supply the "old state" of a covenant. Used by
/// the resolver and by tests.
pub trait OldStateLookup {
    /// Returns the last *valid* `old_state` recorded for `covenant_id`, if any.
    fn last_valid_old_state(&self, covenant_id: KaspaCovenantId) -> Option<RgkStateCommitment>;
}

impl fmt::Write for NewStateSpec<'_> {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        // Intentionally a no-op — `NewStateSpec` is a builder-style payload,
        // not a textual sink. We implement `fmt::Write` so that downstream
        // loggers can chain `.write_fmt!` against it for diagnostics.
        Ok(())
    }
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rgk_core::{receipt_commitment, ENCODING_VERSION, KASPA_LOCAL_TOCCATA};

    fn b32(s: &str) -> [u8; 32] {
        use rgk_core::from_hex;
        from_hex::<32>(s).expect("valid hex")
    }

    fn sample_state(digest_suffix: u8, policy: ReceiptPolicy) -> RgkStateCommitment {
        RgkStateCommitment {
            version: ENCODING_VERSION,
            chain_id: KASPA_LOCAL_TOCCATA,
            covenant_id: b32("1111111111111111111111111111111111111111111111111111111111111111"),
            asset_id: b32("2222222222222222222222222222222222222222222222222222222222222222"),
            state_digest: {
                let mut d = [0u8; 32];
                d[31] = digest_suffix;
                d
            },
            receipt_policy: policy,
        }
    }

    fn sample_input(mode: ProofMode, policy: ReceiptPolicy) -> ReceiptInput {
        ReceiptInput {
            chain_id: KASPA_LOCAL_TOCCATA,
            covenant_id: b32("1111111111111111111111111111111111111111111111111111111111111111"),
            old_state: sample_state(1, policy),
            new_state: sample_state(2, policy),
            transition_digest: b32(
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
            continuation_commitment: b32(
                "5555555555555555555555555555555555555555555555555555555555555555",
            ),
            proof_mode: mode,
            replay_nonce: b32("4444444444444444444444444444444444444444444444444444444444444444"),
        }
    }

    fn chain_from_index(index: u8) -> KaspaChainId {
        KaspaChainId::ALL[index as usize % KaspaChainId::ALL.len()]
    }

    fn admitted_policy_mode(index: u8) -> (ReceiptPolicy, ProofMode) {
        match index % 5 {
            0 => (ReceiptPolicy::Any, ProofMode::VerifierReceipt),
            1 => (ReceiptPolicy::Any, ProofMode::ZkReceipt),
            2 => (ReceiptPolicy::Any, ProofMode::P2mrRet),
            3 => (ReceiptPolicy::VerifierOnly, ProofMode::VerifierReceipt),
            _ => (ReceiptPolicy::ZkOrVerifier, ProofMode::ZkReceipt),
        }
    }

    proptest! {
        #[test]
        fn receipt_round_trip_holds_for_random_admitted_fields(
            chain_index in any::<u8>(),
            pair_index in any::<u8>(),
            covenant_id in any::<[u8; 32]>(),
            asset_id in any::<[u8; 32]>(),
            old_digest in any::<[u8; 32]>(),
            new_digest in any::<[u8; 32]>(),
            transition_digest in any::<[u8; 32]>(),
            continuation_commitment in any::<[u8; 32]>(),
            replay_nonce in any::<[u8; 32]>(),
        ) {
            prop_assume!(old_digest != new_digest);
            prop_assume!(transition_digest != [0u8; 32]);
            prop_assume!(continuation_commitment != [0u8; 32]);
            prop_assume!(replay_nonce != [0u8; 32]);

            let chain_id = chain_from_index(chain_index);
            let (policy, proof_mode) = admitted_policy_mode(pair_index);
            let old_state = RgkStateCommitment {
                version: ENCODING_VERSION,
                chain_id,
                covenant_id,
                asset_id,
                state_digest: old_digest,
                receipt_policy: policy,
            };
            let new_state = RgkStateCommitment {
                version: ENCODING_VERSION,
                chain_id,
                covenant_id,
                asset_id,
                state_digest: new_digest,
                receipt_policy: policy,
            };
            let input = ReceiptInput {
                chain_id,
                covenant_id,
                old_state: old_state.clone(),
                new_state,
                transition_digest,
                continuation_commitment,
                proof_mode,
                replay_nonce,
            };

            let (receipt, id, bytes) = ReceiptBuilder::build(&input).expect("build receipt");
            let decoded = RgkReceipt::decode_canonical(&bytes).expect("decode receipt");
            let verified = ReceiptVerifier::verify_local(&bytes, covenant_id, &old_state, chain_id)
                .expect("verify receipt");

            prop_assert_eq!(id, receipt_commitment(&receipt));
            prop_assert_eq!(decoded, receipt);
            prop_assert_eq!(verified, id);
        }
    }

    #[test]
    fn build_round_trips_id_and_bytes() {
        let input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        let (r, id, bytes) = ReceiptBuilder::build(&input).expect("build");
        let r2 = RgkReceipt::decode_canonical(&bytes).expect("decode");
        assert_eq!(r, r2);
        assert_eq!(id, receipt_commitment(&r));
    }

    #[test]
    fn build_rejects_missing_nonce() {
        let mut input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        input.replay_nonce = [0u8; 32];
        assert!(matches!(
            ReceiptBuilder::build(&input).unwrap_err(),
            ReceiptError::MissingReplayNonce
        ));
    }

    #[test]
    fn build_rejects_missing_transition() {
        let mut input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        input.transition_digest = [0u8; 32];
        assert!(matches!(
            ReceiptBuilder::build(&input).unwrap_err(),
            ReceiptError::MissingTransitionDigest
        ));
    }

    #[test]
    fn build_rejects_missing_continuation_commitment() {
        let mut input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        input.continuation_commitment = [0u8; 32];
        assert!(matches!(
            ReceiptBuilder::build(&input).unwrap_err(),
            ReceiptError::MissingContinuationCommitment
        ));
    }

    #[test]
    fn verifier_rejects_chain_mismatch() {
        let input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        let (_r, _id, bytes) = ReceiptBuilder::build(&input).unwrap();
        let err = ReceiptVerifier::verify_local(
            &bytes,
            input.covenant_id,
            &input.old_state,
            KaspaChainId::KaspaMainnet,
        )
        .unwrap_err();
        assert!(matches!(err, ReceiptError::ChainMismatch { .. }));
    }

    #[test]
    fn verifier_rejects_covenant_mismatch() {
        let input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        let (_r, _id, bytes) = ReceiptBuilder::build(&input).unwrap();
        let bad_cov = b32("9999999999999999999999999999999999999999999999999999999999999999");
        let err = ReceiptVerifier::verify_local(&bytes, bad_cov, &input.old_state, input.chain_id)
            .unwrap_err();
        assert!(matches!(err, ReceiptError::CovenantMismatch { .. }));
    }

    #[test]
    fn verifier_rejects_old_state_mismatch() {
        let input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        let (_r, _id, bytes) = ReceiptBuilder::build(&input).unwrap();
        let mut bad_state = input.old_state.clone();
        bad_state.state_digest[0] ^= 0x01;
        let err =
            ReceiptVerifier::verify_local(&bytes, input.covenant_id, &bad_state, input.chain_id)
                .unwrap_err();
        assert!(matches!(err, ReceiptError::OldStateMismatch { .. }));
    }

    #[test]
    fn verifier_rejects_policy_mode_mismatch() {
        // The builder rejects policy/mode mismatch upfront via validate_structure.
        let bad_input = sample_input(ProofMode::ZkReceipt, ReceiptPolicy::VerifierOnly);
        let err = ReceiptBuilder::build(&bad_input).unwrap_err();
        assert!(matches!(err, ReceiptError::DecodeFailure(_)));

        // Build a structurally valid receipt with policy=Any and mode=ZkReceipt,
        // then pass it to the verifier with an expected_old_state that has
        // policy=VerifierOnly. The verifier must reject because the *expected*
        // state's policy doesn't admit the mode.
        let mut input = sample_input(ProofMode::ZkReceipt, ReceiptPolicy::Any);
        // Receipt itself stays policy=Any/mode=ZkReceipt (valid pair).
        let (_r, _id, bytes) = ReceiptBuilder::build(&input).unwrap();
        // But we tell the verifier to expect a state with policy=VerifierOnly.
        input.old_state.receipt_policy = ReceiptPolicy::VerifierOnly;
        input.new_state.receipt_policy = ReceiptPolicy::VerifierOnly;
        let err = ReceiptVerifier::verify_local(
            &bytes,
            input.covenant_id,
            &input.old_state,
            input.chain_id,
        )
        .unwrap_err();
        assert!(matches!(err, ReceiptError::PolicyRejectsMode { .. }));
    }

    #[test]
    fn replay_set_accepts_once() {
        let mut set = ReplaySet::new();
        let id = b32("ab".repeat(32).as_str());
        set.record(id).expect("first");
        assert!(matches!(
            set.record(id).unwrap_err(),
            ReceiptError::Replay(_)
        ));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn verifier_summary_is_stable() {
        let input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        let (r, _id, _bytes) = ReceiptBuilder::build(&input).unwrap();
        let s = receipt_summary(&r);
        // Not a frozen vector; we just check it includes the proof mode + chain.
        assert!(s.contains("verifier-receipt"));
        assert!(s.contains("kaspa-local-toccata"));
    }

    #[test]
    fn derive_replay_nonce_is_deterministic() {
        let d = b32("3333333333333333333333333333333333333333333333333333333333333333");
        let a = derive_replay_nonce(b"outpoint-A", &d);
        let b = derive_replay_nonce(b"outpoint-A", &d);
        assert_eq!(a, b);
        let c = derive_replay_nonce(b"outpoint-B", &d);
        assert_ne!(a, c);
    }

    #[test]
    fn no_op_transition_rejected() {
        // Same old/new state digest -> RgkReceipt::validate_structure rejects
        let mut input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        input.new_state.state_digest = input.old_state.state_digest;
        assert!(ReceiptBuilder::build(&input).is_err());
    }

    #[test]
    fn asset_id_change_rejected() {
        let mut input = sample_input(ProofMode::VerifierReceipt, ReceiptPolicy::Any);
        input.new_state.asset_id =
            b32("9999999999999999999999999999999999999999999999999999999999999999");
        assert!(ReceiptBuilder::build(&input).is_err());
    }

    #[test]
    fn receipt_id_hex_format() {
        let id = b32("ab".repeat(32).as_str());
        let s = receipt_id_hex(&id);
        assert_eq!(s.len(), 66); // "0x" + 64 hex chars
        assert!(s.starts_with("0x"));
    }

    #[test]
    fn batch_err_string_renders() {
        let errs = vec![
            ReceiptError::MissingReplayNonce,
            ReceiptError::ChainMismatch {
                receipt: KASPA_LOCAL_TOCCATA,
                verifier: KaspaChainId::KaspaMainnet,
            },
        ];
        let s = batch_err_string(&errs);
        assert!(s.contains("[0]"));
        assert!(s.contains("[1]"));
    }
}
