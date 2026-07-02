#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-zk
//!
//! The ZK-receipt mode for RGK. Provides:
//!
//! 1. A typed `ZkStatement` — the public inputs to the ZK proof, matching
//!    the RGK receipt's invariants exactly.
//! 2. An opaque Groth16 `ZkProof` wrapper for receipt-level plumbing. Its
//!    transport `[tag byte || proof bytes]` encoding is not the complete
//!    Toccata Groth16 stack. Reserved non-Groth16 tags fail closed here.
//! 3. A `ZkReceipt` builder/verifier that connects `RgkReceipt` (in
//!    [`rgk_receipt`]) to the Toccata verifier stack. The verifier is local:
//!    it re-checks the statement, decodes the proof, and produces the transport
//!    tagged proof blob used by default-mode callers.
//! 4. Under `real-zk`, complete Groth16 stack material for the Toccata
//!    `OpZkPrecompile`: public inputs, count, proof, verifying key, tag.
//! 5. A typed RISC Zero Succinct stack-material wrapper for Toccata's
//!    `R0Succinct` precompile. This is stack construction support, not an RGK
//!    RISC0 prover.
//! 6. Strict separation between **VerifierReceipt** mode (always-available,
//!    verifier-attested) and **ZkReceipt** mode (ZK-proven). The two
//!    modes have different trust assumptions; see `docs/SECURITY.md`.
//!
//! ## What this crate does NOT do
//!
//! * It does **not** implement Groth16 / RISC0 verification. That is the
//!   Kaspa txscript engine's job. We produce the encoding the engine expects.
//! * The default feature set does **not** generate real proofs. The
//!   `real-zk` feature provides a local arkworks Groth16 prover/verifier path
//!   and complete Toccata Groth16 stack serialisation used by the live
//!   covenant spend (see `docs/ZK-BOUNDARY.md`).

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
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
use core::convert::TryFrom;

use rgk_asset::{LanePrivacyPolicy, RgkContinuationReport, RgkTransitionReport};
use rgk_core::{
    Bytes32, KaspaChainId, KaspaCovenantId, ProofMode, RgkAssetId, RgkReceipt, RgkStateCommitment,
    TransitionDigest,
};
use thiserror::Error;

/// ZK tag byte, matching `kaspa_txscript::zk_precompiles::tags::ZkTag` in the
/// rusty-kaspa toccata branch (commit `0ae28f9`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ZkTag {
    /// `0x20` — Groth16 (BN254) — used by many production verifier stacks.
    Groth16 = 0x20,
    /// `0x21` — RISC Zero Succinct (STARK). Supported as Toccata stack
    /// material; not accepted by RGK's opaque receipt wrapper.
    R0Succinct = 0x21,
}

impl ZkTag {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x20 => Some(ZkTag::Groth16),
            0x21 => Some(ZkTag::R0Succinct),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Errors produced by the ZK-receipt verifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ZkError {
    #[error("zk proof missing (must be non-empty)")]
    MissingProof,
    #[error("zk proof too long: {got} bytes (max {max})")]
    ProofTooLong { got: usize, max: usize },
    #[error("zk statement field count exceeds limit: {got} (max {max})")]
    TooManyPublicInputs { got: usize, max: usize },
    #[error("zk public input too long: {got} bytes (max {max})")]
    PublicInputTooLong { got: usize, max: usize },
    #[error("semantic transition count too large for public input field {field}: {count}")]
    SemanticCountTooLarge { field: &'static str, count: usize },
    #[error("semantic transition report mismatch: {0}")]
    SemanticTransitionMismatch(&'static str),
    #[error("semantic transition report invalid: {0}")]
    SemanticTransitionInvalid(&'static str),
    #[error("unknown zk tag byte: 0x{0:02x}")]
    UnknownTag(u8),
    #[error("unsupported zk tag for the active RGK receipt path: {0:?}")]
    UnsupportedTag(ZkTag),
    #[error("invalid R0 Succinct {field} length: got {got}, expected {expected}")]
    InvalidR0SuccinctFieldLen {
        field: &'static str,
        got: usize,
        expected: usize,
    },
    #[error("invalid R0 Succinct {field} length: got {got}, expected a multiple of {multiple}")]
    InvalidR0SuccinctFieldMultiple {
        field: &'static str,
        got: usize,
        multiple: usize,
    },
    #[error("R0 Succinct {field} has too many items: got {got}, max {max}")]
    R0SuccinctTooManyItems {
        field: &'static str,
        got: usize,
        max: usize,
    },
    #[error("unsupported R0 Succinct hash function id: {0}")]
    UnsupportedR0SuccinctHashFn(u8),
    #[error("zk proof does not match the rgk receipt statement")]
    StatementMismatch,
    #[error("zk receipt mode requires ProofMode::ZkReceipt but receipt declares {0:?}")]
    WrongMode(ProofMode),
}

pub const R0_SUCCINCT_HASH_FN_POSEIDON2: u8 = 1;
pub const R0_SUCCINCT_CONTROL_DIGEST_BYTES: usize = 32;
pub const R0_SUCCINCT_CONTROL_INDEX_BYTES: usize = 4;
pub const R0_SUCCINCT_MAX_CONTROL_DIGESTS: usize = 8;
pub const R0_SUCCINCT_MAX_SEAL_BYTES: usize = 1_000_000;

/// Stack material for Toccata's RISC Zero Succinct `OpZkPrecompile` path.
///
/// The upstream precompile pops, from top to bottom: tag, hash function id,
/// control id, image id, journal, seal, control-digest siblings, control
/// index, and claim. `script_push_items()` returns those items in the order
/// they must be pushed into a Kaspa script before `OpZkPrecompile`.
///
/// This type does not generate or verify RISC0 proofs. It is a typed transport
/// boundary for receipt material produced elsewhere, with the same syntactic
/// constraints that the upstream precompile expects before integrity checking.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct R0SuccinctPrecompileStack {
    pub claim: Bytes32,
    pub control_index: [u8; R0_SUCCINCT_CONTROL_INDEX_BYTES],
    pub control_digests: Vec<u8>,
    pub seal: Vec<u8>,
    pub journal: Bytes32,
    pub image_id: Bytes32,
    pub control_id: Bytes32,
    pub hashfn: u8,
    pub tag: u8,
}

impl R0SuccinctPrecompileStack {
    pub fn new(
        claim: Bytes32,
        control_index: [u8; R0_SUCCINCT_CONTROL_INDEX_BYTES],
        control_digests: Vec<u8>,
        seal: Vec<u8>,
        journal: Bytes32,
        image_id: Bytes32,
        control_id: Bytes32,
        hashfn: u8,
    ) -> Result<Self, ZkError> {
        validate_r0_succinct_variable_fields(&control_digests, &seal, hashfn)?;
        Ok(Self {
            claim,
            control_index,
            control_digests,
            seal,
            journal,
            image_id,
            control_id,
            hashfn,
            tag: ZkTag::R0Succinct.as_byte(),
        })
    }

    pub fn script_push_items(&self) -> Vec<&[u8]> {
        vec![
            &self.claim,
            &self.control_index,
            &self.control_digests,
            &self.seal,
            &self.journal,
            &self.image_id,
            &self.control_id,
            core::slice::from_ref(&self.hashfn),
            core::slice::from_ref(&self.tag),
        ]
    }

    pub fn control_digest_count(&self) -> usize {
        self.control_digests.len() / R0_SUCCINCT_CONTROL_DIGEST_BYTES
    }
}

fn validate_r0_succinct_variable_fields(
    control_digests: &[u8],
    seal: &[u8],
    hashfn: u8,
) -> Result<(), ZkError> {
    if hashfn != R0_SUCCINCT_HASH_FN_POSEIDON2 {
        return Err(ZkError::UnsupportedR0SuccinctHashFn(hashfn));
    }
    if control_digests.len() % R0_SUCCINCT_CONTROL_DIGEST_BYTES != 0 {
        return Err(ZkError::InvalidR0SuccinctFieldMultiple {
            field: "control_digests",
            got: control_digests.len(),
            multiple: R0_SUCCINCT_CONTROL_DIGEST_BYTES,
        });
    }
    let control_digest_count = control_digests.len() / R0_SUCCINCT_CONTROL_DIGEST_BYTES;
    if control_digest_count > R0_SUCCINCT_MAX_CONTROL_DIGESTS {
        return Err(ZkError::R0SuccinctTooManyItems {
            field: "control_digests",
            got: control_digest_count,
            max: R0_SUCCINCT_MAX_CONTROL_DIGESTS,
        });
    }
    if seal.is_empty() || seal.len() % 4 != 0 {
        return Err(ZkError::InvalidR0SuccinctFieldMultiple {
            field: "seal",
            got: seal.len(),
            multiple: 4,
        });
    }
    if seal.len() > R0_SUCCINCT_MAX_SEAL_BYTES {
        return Err(ZkError::ProofTooLong {
            got: seal.len(),
            max: R0_SUCCINCT_MAX_SEAL_BYTES,
        });
    }
    Ok(())
}

/// The RGK ZK public statement. Mirrors the RGK receipt exactly so that the
/// on-chain verifier (via `OpZkPrecompile`) and the local verifier agree on
/// the public inputs.
///
/// Public inputs (in order):
/// 0. `old_state_digest` (32 bytes)
/// 1. `new_state_digest` (32 bytes)
/// 2. `asset_id` (32 bytes)
/// 3. `kaspa_covenant_id` (32 bytes)
/// 4. `chain_id` (8 bytes — encoding of the chain tag + value as two u32s)
/// 5. `receipt_id` (32 bytes)
/// 6. `transition_digest` (32 bytes)
/// 7. `continuation_commitment` (32 bytes)
///
/// Total: 7 * 32 + 8 = 232 bytes.
///
/// Private inputs (witness) — not encoded here; produced by the prover.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ZkStatement {
    pub old_state_digest: Bytes32,
    pub new_state_digest: Bytes32,
    pub asset_id: RgkAssetId,
    pub kaspa_covenant_id: KaspaCovenantId,
    pub chain_id: KaspaChainId,
    pub receipt_id: Bytes32,
    pub transition_digest: TransitionDigest,
    pub continuation_commitment: rgk_core::ContinuationCommitment,
}

impl ZkStatement {
    pub const PUBLIC_INPUT_LEN: usize = 232;

    /// Compute the statement bytes (the canonical public-input preimage).
    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.old_state_digest);
        out.extend_from_slice(&self.new_state_digest);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.kaspa_covenant_id);
        out.extend_from_slice(&self.chain_id_tagged_le_u32());
        out.extend_from_slice(&self.receipt_id);
        out.extend_from_slice(&self.transition_digest);
        out.extend_from_slice(&self.continuation_commitment);
        out
    }

    /// Two u32 LE values: the chain tag byte as a u32 (zero-padded), and the
    /// chain value byte as a u32 (zero-padded).
    fn chain_id_tagged_le_u32(&self) -> [u8; 8] {
        // The chain tag ('K' = 0x4b) and chain value byte, each as a u32 LE.
        let tag = u32::from(KaspaChainId::TAG); // 'K' = 0x4b
        let val = u32::from(self.chain_id as u8);
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&tag.to_le_bytes());
        out[4..].copy_from_slice(&val.to_le_bytes());
        out
    }

    /// Derive the statement from a fully-built `RgkReceipt` and its computed
    /// receipt id.
    pub fn from_receipt(receipt: &RgkReceipt, receipt_id: Bytes32) -> Self {
        Self {
            old_state_digest: receipt.old_state.state_digest,
            new_state_digest: receipt.new_state.state_digest,
            asset_id: receipt.old_state.asset_id,
            kaspa_covenant_id: receipt.covenant_id,
            chain_id: receipt.chain_id,
            receipt_id,
            transition_digest: receipt.transition_digest,
            continuation_commitment: receipt.continuation_commitment,
        }
    }

    /// Inverse: reconstruct the canonical RGK public inputs that the
    /// on-chain verifier will check. The verifier must reject any proof that
    /// does not match this exact byte sequence.
    pub fn matches(&self, receipt: &RgkReceipt, receipt_id: Bytes32) -> bool {
        let from = Self::from_receipt(receipt, receipt_id);
        self == &from
    }
}

/// Canonical native transition statement for the richer semantic ZK boundary.
///
/// This statement is built only from validated native RGK transition and
/// continuation reports. It deliberately does not replace [`ZkStatement`]'s
/// current 232-byte Groth16 receipt input. Instead, it provides a typed,
/// deterministic semantic statement for verifier policy, e2e evidence, and the
/// next circuit generation.
///
/// Public inputs (in order):
/// 0. `chain_id` (8 bytes — encoding of the chain tag + value as two u32s)
/// 1. native grammar id, stored in the `schema_id` field (32 bytes)
/// 2. lineage-bound `asset_id` label (32 bytes)
/// 3. `previous_state_digest` (32 bytes)
/// 4. `new_state_digest` (32 bytes)
/// 5. `transition_digest` (32 bytes)
/// 6. `continuation_commitment` (32 bytes)
/// 7. `continuation_shape_root` (32 bytes)
/// 8. `lane_id` (32 bytes)
/// 9. `policy_commitment` (32 bytes)
/// 10. `metadata_commitment` (32 bytes)
/// 11. `previous_owner_commitment` (32 bytes)
/// 12. `new_owner_commitment` (32 bytes)
/// 13. `ownership_authorization_commitment` (32 bytes, zero if owner unchanged)
/// 14. `total_supply` (8 bytes)
/// 15. `spent_allocation_count` (8 bytes)
/// 16. `new_allocation_count` (8 bytes)
/// 17. `privacy_policy` (8 bytes)
/// 18. `spent_supply` (8 bytes)
/// 19. `new_supply` (8 bytes)
/// 20. `burned_supply` (8 bytes)
/// 21. `burn_authorization_commitment` (32 bytes, zero for no-burn)
///
/// Total: 8 + 14 * 32 + 7 * 8 = 512 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SemanticTransitionStatement {
    pub chain_id: KaspaChainId,
    pub schema_id: Bytes32,
    pub asset_id: Bytes32,
    pub previous_state_digest: Bytes32,
    pub new_state_digest: Bytes32,
    pub transition_digest: Bytes32,
    pub continuation_commitment: Bytes32,
    pub continuation_shape_root: Bytes32,
    pub lane_id: Bytes32,
    pub privacy_policy: LanePrivacyPolicy,
    pub policy_commitment: Bytes32,
    pub metadata_commitment: Bytes32,
    pub previous_owner_commitment: Bytes32,
    pub new_owner_commitment: Bytes32,
    pub ownership_authorization_commitment: Bytes32,
    pub total_supply: u64,
    pub spent_allocation_count: u64,
    pub new_allocation_count: u64,
    pub spent_supply: u64,
    pub new_supply: u64,
    pub burned_supply: u64,
    pub burn_authorization_commitment: Bytes32,
}

impl SemanticTransitionStatement {
    pub const PUBLIC_INPUT_LEN: usize = 512;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: KaspaChainId,
        schema_id: Bytes32,
        asset_id: Bytes32,
        previous_state_digest: Bytes32,
        new_state_digest: Bytes32,
        transition_digest: Bytes32,
        continuation_commitment: Bytes32,
        continuation_shape_root: Bytes32,
        lane_id: Bytes32,
        privacy_policy: LanePrivacyPolicy,
        policy_commitment: Bytes32,
        metadata_commitment: Bytes32,
        previous_owner_commitment: Bytes32,
        new_owner_commitment: Bytes32,
        ownership_authorization_commitment: Bytes32,
        total_supply: u64,
        spent_allocation_count: u64,
        new_allocation_count: u64,
        spent_supply: u64,
        new_supply: u64,
        burned_supply: u64,
        burn_authorization_commitment: Bytes32,
    ) -> Result<Self, ZkError> {
        let statement = Self {
            chain_id,
            schema_id,
            asset_id,
            previous_state_digest,
            new_state_digest,
            transition_digest,
            continuation_commitment,
            continuation_shape_root,
            lane_id,
            privacy_policy,
            policy_commitment,
            metadata_commitment,
            previous_owner_commitment,
            new_owner_commitment,
            ownership_authorization_commitment,
            total_supply,
            spent_allocation_count,
            new_allocation_count,
            spent_supply,
            new_supply,
            burned_supply,
            burn_authorization_commitment,
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn from_reports(
        transition: &RgkTransitionReport,
        continuation: &RgkContinuationReport,
    ) -> Result<Self, ZkError> {
        if transition.chain != continuation.chain {
            return Err(ZkError::SemanticTransitionMismatch("chain_id"));
        }
        if transition.schema_id != continuation.schema_id {
            return Err(ZkError::SemanticTransitionMismatch("schema_id"));
        }
        if transition.asset_id != continuation.asset_id {
            return Err(ZkError::SemanticTransitionMismatch("asset_id"));
        }
        if transition.total_supply != continuation.total_supply {
            return Err(ZkError::SemanticTransitionMismatch("total_supply"));
        }
        if transition.spent_supply != continuation.spent_supply {
            return Err(ZkError::SemanticTransitionMismatch("spent_supply"));
        }
        if transition.new_supply != continuation.new_supply {
            return Err(ZkError::SemanticTransitionMismatch("new_supply"));
        }
        if transition.burned_supply != continuation.burned_supply {
            return Err(ZkError::SemanticTransitionMismatch("burned_supply"));
        }
        if transition.burn_authorization_commitment != continuation.burn_authorization_commitment {
            return Err(ZkError::SemanticTransitionMismatch(
                "burn_authorization_commitment",
            ));
        }
        if transition.spent_allocation_count != continuation.spent_allocation_count {
            return Err(ZkError::SemanticTransitionMismatch(
                "spent_allocation_count",
            ));
        }
        if transition.new_allocation_count != continuation.new_allocation_count {
            return Err(ZkError::SemanticTransitionMismatch("new_allocation_count"));
        }
        if transition.lane_id != continuation.lane_id {
            return Err(ZkError::SemanticTransitionMismatch("lane_id"));
        }
        if transition.privacy_policy != continuation.privacy_policy {
            return Err(ZkError::SemanticTransitionMismatch("privacy_policy"));
        }
        if transition.policy_commitment != continuation.policy_commitment {
            return Err(ZkError::SemanticTransitionMismatch("policy_commitment"));
        }
        if transition.metadata_commitment != continuation.metadata_commitment {
            return Err(ZkError::SemanticTransitionMismatch("metadata_commitment"));
        }
        if transition.previous_owner_commitment != continuation.previous_owner_commitment {
            return Err(ZkError::SemanticTransitionMismatch(
                "previous_owner_commitment",
            ));
        }
        if transition.new_owner_commitment != continuation.new_owner_commitment {
            return Err(ZkError::SemanticTransitionMismatch("new_owner_commitment"));
        }
        if transition.ownership_authorization_commitment
            != continuation.ownership_authorization_commitment
        {
            return Err(ZkError::SemanticTransitionMismatch(
                "ownership_authorization_commitment",
            ));
        }
        if transition.previous_state_digest != continuation.previous_state_digest {
            return Err(ZkError::SemanticTransitionMismatch("previous_state_digest"));
        }

        let spent_allocation_count =
            u64::try_from(transition.spent_allocation_count).map_err(|_| {
                ZkError::SemanticCountTooLarge {
                    field: "spent_allocation_count",
                    count: transition.spent_allocation_count,
                }
            })?;
        let new_allocation_count =
            u64::try_from(transition.new_allocation_count).map_err(|_| {
                ZkError::SemanticCountTooLarge {
                    field: "new_allocation_count",
                    count: transition.new_allocation_count,
                }
            })?;

        let statement = Self {
            chain_id: transition.chain,
            schema_id: transition.schema_id,
            asset_id: transition.asset_id,
            previous_state_digest: transition.previous_state_digest.to_bytes(),
            new_state_digest: transition.new_state_digest.to_bytes(),
            transition_digest: transition.transition_digest.to_bytes(),
            continuation_commitment: continuation.commitment.to_bytes(),
            continuation_shape_root: continuation.shape_root.to_bytes(),
            lane_id: transition.lane_id,
            privacy_policy: transition.privacy_policy,
            policy_commitment: transition.policy_commitment.to_bytes(),
            metadata_commitment: transition.metadata_commitment.to_bytes(),
            previous_owner_commitment: transition.previous_owner_commitment.to_bytes(),
            new_owner_commitment: transition.new_owner_commitment.to_bytes(),
            ownership_authorization_commitment: transition.ownership_authorization_commitment,
            total_supply: transition.total_supply,
            spent_allocation_count,
            new_allocation_count,
            spent_supply: transition.spent_supply,
            new_supply: transition.new_supply,
            burned_supply: transition.burned_supply,
            burn_authorization_commitment: transition.burn_authorization_commitment,
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.chain_id_tagged_le_u32());
        out.extend_from_slice(&self.schema_id);
        out.extend_from_slice(&self.asset_id);
        out.extend_from_slice(&self.previous_state_digest);
        out.extend_from_slice(&self.new_state_digest);
        out.extend_from_slice(&self.transition_digest);
        out.extend_from_slice(&self.continuation_commitment);
        out.extend_from_slice(&self.continuation_shape_root);
        out.extend_from_slice(&self.lane_id);
        out.extend_from_slice(&self.policy_commitment);
        out.extend_from_slice(&self.metadata_commitment);
        out.extend_from_slice(&self.previous_owner_commitment);
        out.extend_from_slice(&self.new_owner_commitment);
        out.extend_from_slice(&self.ownership_authorization_commitment);
        out.extend_from_slice(&self.total_supply.to_le_bytes());
        out.extend_from_slice(&self.spent_allocation_count.to_le_bytes());
        out.extend_from_slice(&self.new_allocation_count.to_le_bytes());
        out.extend_from_slice(&(u64::from(self.privacy_policy.as_u8())).to_le_bytes());
        out.extend_from_slice(&self.spent_supply.to_le_bytes());
        out.extend_from_slice(&self.new_supply.to_le_bytes());
        out.extend_from_slice(&self.burned_supply.to_le_bytes());
        out.extend_from_slice(&self.burn_authorization_commitment);
        out
    }

    pub fn matches_receipt(&self, receipt: &RgkReceipt) -> bool {
        receipt.chain_id == self.chain_id
            && receipt.old_state.chain_id == self.chain_id
            && receipt.new_state.chain_id == self.chain_id
            && receipt.old_state.asset_id == self.asset_id
            && receipt.new_state.asset_id == self.asset_id
            && receipt.old_state.state_digest == self.previous_state_digest
            && receipt.new_state.state_digest == self.new_state_digest
            && receipt.transition_digest == self.transition_digest
            && receipt.continuation_commitment == self.continuation_commitment
    }

    pub fn matches_zk_statement(&self, statement: &ZkStatement) -> bool {
        statement.chain_id == self.chain_id
            && statement.asset_id == self.asset_id
            && statement.old_state_digest == self.previous_state_digest
            && statement.new_state_digest == self.new_state_digest
            && statement.transition_digest == self.transition_digest
            && statement.continuation_commitment == self.continuation_commitment
    }

    fn validate(&self) -> Result<(), ZkError> {
        reject_zero_semantic(&self.schema_id, "schema_id")?;
        reject_zero_semantic(&self.asset_id, "asset_id")?;
        reject_zero_semantic(&self.previous_state_digest, "previous_state_digest")?;
        reject_zero_semantic(&self.new_state_digest, "new_state_digest")?;
        reject_zero_semantic(&self.transition_digest, "transition_digest")?;
        reject_zero_semantic(&self.continuation_commitment, "continuation_commitment")?;
        reject_zero_semantic(&self.continuation_shape_root, "continuation_shape_root")?;
        reject_zero_semantic(&self.lane_id, "lane_id")?;
        reject_zero_semantic(&self.policy_commitment, "policy_commitment")?;
        reject_zero_semantic(&self.metadata_commitment, "metadata_commitment")?;
        reject_zero_semantic(&self.previous_owner_commitment, "previous_owner_commitment")?;
        reject_zero_semantic(&self.new_owner_commitment, "new_owner_commitment")?;
        let ownership_authorization_is_zero = self
            .ownership_authorization_commitment
            .iter()
            .all(|byte| *byte == 0);
        if self.previous_owner_commitment != self.new_owner_commitment
            && ownership_authorization_is_zero
        {
            return Err(ZkError::SemanticTransitionInvalid(
                "ownership_authorization_commitment",
            ));
        }
        if self.previous_state_digest == self.new_state_digest {
            return Err(ZkError::SemanticTransitionInvalid("no-op state digest"));
        }
        if self.total_supply == 0 {
            return Err(ZkError::SemanticTransitionInvalid("total_supply"));
        }
        if self.spent_allocation_count == 0 {
            return Err(ZkError::SemanticTransitionInvalid("spent_allocation_count"));
        }
        if self.spent_supply == 0 {
            return Err(ZkError::SemanticTransitionInvalid("spent_supply"));
        }
        if self.spent_supply > self.total_supply || self.new_supply > self.total_supply {
            return Err(ZkError::SemanticTransitionInvalid(
                "supply exceeds total_supply",
            ));
        }
        let Some(accounted_supply) = self.new_supply.checked_add(self.burned_supply) else {
            return Err(ZkError::SemanticTransitionInvalid("supply overflow"));
        };
        if accounted_supply != self.spent_supply {
            return Err(ZkError::SemanticTransitionInvalid(
                "spent_supply != new_supply + burned_supply",
            ));
        }
        if self.new_allocation_count == 0 && self.burned_supply == 0 {
            return Err(ZkError::SemanticTransitionInvalid("new_allocation_count"));
        }
        if self.new_supply == 0 && self.burned_supply == 0 {
            return Err(ZkError::SemanticTransitionInvalid("new_supply"));
        }
        let burn_authorization_is_zero = self
            .burn_authorization_commitment
            .iter()
            .all(|byte| *byte == 0);
        if self.burned_supply == 0 {
            if !burn_authorization_is_zero {
                return Err(ZkError::SemanticTransitionInvalid(
                    "unexpected burn_authorization_commitment",
                ));
            }
        } else if burn_authorization_is_zero {
            return Err(ZkError::SemanticTransitionInvalid(
                "burn_authorization_commitment",
            ));
        }
        Ok(())
    }

    /// Two u32 LE values: the chain tag byte as a u32 (zero-padded), and the
    /// chain value byte as a u32 (zero-padded).
    fn chain_id_tagged_le_u32(&self) -> [u8; 8] {
        let tag = u32::from(KaspaChainId::TAG);
        let val = u32::from(self.chain_id as u8);
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&tag.to_le_bytes());
        out[4..].copy_from_slice(&val.to_le_bytes());
        out
    }
}

fn reject_zero_semantic(bytes: &Bytes32, field: &'static str) -> Result<(), ZkError> {
    if bytes.iter().all(|b| *b == 0) {
        Err(ZkError::SemanticTransitionInvalid(field))
    } else {
        Ok(())
    }
}

/// The ZK proof wrapper for the active RGK Groth16 receipt path. The Groth16
/// bytes are opaque to this crate, but reserved non-Groth16 tags fail closed so
/// unsupported proof systems cannot be misrepresented as active support. This
/// wrapper is not the complete Groth16 `OpZkPrecompile` stack. The
/// `max_proof_size` DoS budget lives here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ZkProof {
    pub tag: ZkTag,
    pub proof_bytes: Vec<u8>,
}

impl ZkProof {
    pub const MAX_PROOF_BYTES: usize = 1024 * 64; // 64 KiB hard cap

    pub fn new(tag: ZkTag, proof_bytes: Vec<u8>) -> Result<Self, ZkError> {
        if tag != ZkTag::Groth16 {
            return Err(ZkError::UnsupportedTag(tag));
        }
        if proof_bytes.is_empty() {
            return Err(ZkError::MissingProof);
        }
        if proof_bytes.len() > Self::MAX_PROOF_BYTES {
            return Err(ZkError::ProofTooLong {
                got: proof_bytes.len(),
                max: Self::MAX_PROOF_BYTES,
            });
        }
        Ok(Self { tag, proof_bytes })
    }

    /// Encode the transport tagged proof blob: `[tag_byte || proof_bytes...]`.
    ///
    /// For the complete Toccata Groth16 stack, use
    /// `real_zk::groth16_precompile_stack` with the `real-zk` feature.
    pub fn encode_for_precompile(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.proof_bytes.len());
        out.push(self.tag.as_byte());
        out.extend_from_slice(&self.proof_bytes);
        out
    }
}

/// A `ZkReceipt` = (statement, proof). Mirrors the `RgkReceipt` shape and is
/// verifiable independently of any Kaspa-side script engine.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ZkReceipt {
    pub statement: ZkStatement,
    pub proof: ZkProof,
}

impl ZkReceipt {
    /// Build a ZK receipt from a RGK receipt. The `proof` is supplied by the
    /// prover (out of scope for this crate in the default feature set).
    pub fn build(
        receipt: &RgkReceipt,
        receipt_id: Bytes32,
        proof: ZkProof,
    ) -> Result<Self, ZkError> {
        if receipt.proof_mode != ProofMode::ZkReceipt {
            return Err(ZkError::WrongMode(receipt.proof_mode));
        }
        Ok(Self {
            statement: ZkStatement::from_receipt(receipt, receipt_id),
            proof,
        })
    }

    /// Local verification. **This is NOT a substitute for the on-chain
    /// `OpZkPrecompile` call** — see SECURITY.md. It catches the obvious
    /// mismatches (mode, statement vs receipt, proof tag, public-input
    /// length) and returns the transport tagged proof blob. It does not build the
    /// full Groth16 precompile stack.
    pub fn verify_local(
        &self,
        receipt: &RgkReceipt,
        receipt_id: Bytes32,
    ) -> Result<Vec<u8>, ZkError> {
        if receipt.proof_mode != ProofMode::ZkReceipt {
            return Err(ZkError::WrongMode(receipt.proof_mode));
        }
        if !self.statement.matches(receipt, receipt_id) {
            return Err(ZkError::StatementMismatch);
        }
        let inputs = self.statement.public_inputs();
        if inputs.len() != ZkStatement::PUBLIC_INPUT_LEN {
            return Err(ZkError::PublicInputTooLong {
                got: inputs.len(),
                max: ZkStatement::PUBLIC_INPUT_LEN,
            });
        }
        let precompile_input = self.proof.encode_for_precompile();
        Ok(precompile_input)
    }
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use rgk_asset::{
        LanePrivacyPolicy, RgkContinuationCommitment, RgkContinuationReport,
        RgkContinuationShapeRoot, RgkMetadataCommitment, RgkOwnerCommitment, RgkPolicyCommitment,
        RgkStateDigest, RgkTransitionDigest, RgkTransitionReport, RGK_FUNGIBLE_ASSET_SCHEMA_ID,
    };
    use rgk_core::{receipt_commitment, KASPA_LOCAL_TOCCATA};

    fn b32(s: &str) -> [u8; 32] {
        rgk_core::from_hex::<32>(s).expect("hex")
    }

    fn sample_receipt() -> RgkReceipt {
        let covenant_id = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let asset_id = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let old_state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            asset_id,
            b32("0100000000000000000000000000000000000000000000000000000000000000"),
            rgk_core::ReceiptPolicy::ZkOrVerifier,
        )
        .expect("old sample state commitment is valid");
        let new_state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            asset_id,
            b32("0200000000000000000000000000000000000000000000000000000000000000"),
            rgk_core::ReceiptPolicy::ZkOrVerifier,
        )
        .expect("new sample state commitment is valid");
        RgkReceipt::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            old_state,
            new_state,
            b32("3333333333333333333333333333333333333333333333333333333333333333"),
            b32("5555555555555555555555555555555555555555555555555555555555555555"),
            ProofMode::ZkReceipt,
            b32("4444444444444444444444444444444444444444444444444444444444444444"),
        )
        .expect("sample receipt is valid")
    }

    fn sample_semantic_reports() -> (RgkTransitionReport, RgkContinuationReport) {
        let schema_id = RGK_FUNGIBLE_ASSET_SCHEMA_ID;
        let asset_id = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let previous_state_digest = RgkStateDigest::from_bytes(b32(
            "0100000000000000000000000000000000000000000000000000000000000000",
        ))
        .expect("fixture previous state digest is non-zero");
        let new_state_digest = RgkStateDigest::from_bytes(b32(
            "0200000000000000000000000000000000000000000000000000000000000000",
        ))
        .expect("fixture new state digest is non-zero");
        let transition_digest = RgkTransitionDigest::from_bytes(b32(
            "3333333333333333333333333333333333333333333333333333333333333333",
        ))
        .expect("fixture transition digest is non-zero");
        let continuation_commitment = RgkContinuationCommitment::from_bytes(b32(
            "5555555555555555555555555555555555555555555555555555555555555555",
        ))
        .expect("fixture continuation commitment is non-zero");
        let shape_root = RgkContinuationShapeRoot::from_bytes(b32(
            "6666666666666666666666666666666666666666666666666666666666666666",
        ))
        .expect("fixture continuation shape root is non-zero");
        let lane_id = b32("7777777777777777777777777777777777777777777777777777777777777777");
        let policy_commitment = RgkPolicyCommitment::from_bytes(b32(
            "8888888888888888888888888888888888888888888888888888888888888888",
        ))
        .expect("fixture policy commitment is non-zero");
        let metadata_commitment = RgkMetadataCommitment::from_bytes(b32(
            "9999999999999999999999999999999999999999999999999999999999999999",
        ))
        .expect("fixture metadata commitment is non-zero");
        let owner_commitment = RgkOwnerCommitment::from_bytes(b32(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ))
        .expect("fixture owner commitment is non-zero");
        let transition = RgkTransitionReport {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id,
            asset_id,
            total_supply: 1_000_000,
            metadata_commitment,
            previous_owner_commitment: owner_commitment,
            new_owner_commitment: owner_commitment,
            ownership_authorization_commitment: [0; 32],
            spent_supply: 1_000_000,
            new_supply: 1_000_000,
            burned_supply: 0,
            burn_authorization_commitment: [0; 32],
            spent_allocation_count: 1,
            new_allocation_count: 1,
            lane_id,
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            policy_commitment,
            previous_state_digest,
            new_state_digest,
            transition_digest,
        };
        let continuation = RgkContinuationReport {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id,
            asset_id,
            total_supply: 1_000_000,
            metadata_commitment,
            previous_owner_commitment: owner_commitment,
            new_owner_commitment: owner_commitment,
            ownership_authorization_commitment: [0; 32],
            spent_supply: 1_000_000,
            new_supply: 1_000_000,
            burned_supply: 0,
            burn_authorization_commitment: [0; 32],
            spent_allocation_count: 1,
            new_allocation_count: 1,
            lane_id,
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            policy_commitment,
            previous_state_digest,
            shape_root,
            commitment: continuation_commitment,
        };
        (transition, continuation)
    }

    #[test]
    fn tag_bytes_match_upstream() {
        // Pinned values from rusty-kaspa toccata `zk_precompiles::tags::ZkTag`.
        assert_eq!(ZkTag::Groth16.as_byte(), 0x20);
        assert_eq!(ZkTag::R0Succinct.as_byte(), 0x21);
        assert_eq!(ZkTag::from_byte(0x20), Some(ZkTag::Groth16));
        assert_eq!(ZkTag::from_byte(0x21), Some(ZkTag::R0Succinct));
        assert_eq!(ZkTag::from_byte(0x33), None);
    }

    #[test]
    fn r0_succinct_precompile_stack_push_order_matches_toccata() {
        let stack = R0SuccinctPrecompileStack::new(
            [0x11; 32],
            7u32.to_le_bytes(),
            vec![0x22; R0_SUCCINCT_CONTROL_DIGEST_BYTES * 2],
            vec![0x33; 16],
            [0x44; 32],
            [0x55; 32],
            [0x66; 32],
            R0_SUCCINCT_HASH_FN_POSEIDON2,
        )
        .unwrap();
        let pushes = stack.script_push_items();

        assert_eq!(pushes.len(), 9);
        assert_eq!(pushes[0], &[0x11; 32]);
        assert_eq!(pushes[1], &7u32.to_le_bytes());
        assert_eq!(pushes[2], vec![0x22; R0_SUCCINCT_CONTROL_DIGEST_BYTES * 2]);
        assert_eq!(pushes[3], vec![0x33; 16]);
        assert_eq!(pushes[4], &[0x44; 32]);
        assert_eq!(pushes[5], &[0x55; 32]);
        assert_eq!(pushes[6], &[0x66; 32]);
        assert_eq!(pushes[7], &[R0_SUCCINCT_HASH_FN_POSEIDON2]);
        assert_eq!(pushes[8], &[ZkTag::R0Succinct.as_byte()]);
        assert_eq!(stack.tag, ZkTag::R0Succinct.as_byte());
        assert_eq!(stack.control_digest_count(), 2);
    }

    #[test]
    fn r0_succinct_precompile_stack_rejects_invalid_shape() {
        assert!(matches!(
            R0SuccinctPrecompileStack::new(
                [0x11; 32],
                0u32.to_le_bytes(),
                vec![0; 31],
                vec![0; 16],
                [0x44; 32],
                [0x55; 32],
                [0x66; 32],
                R0_SUCCINCT_HASH_FN_POSEIDON2,
            ),
            Err(ZkError::InvalidR0SuccinctFieldMultiple {
                field: "control_digests",
                ..
            })
        ));
        assert!(matches!(
            R0SuccinctPrecompileStack::new(
                [0x11; 32],
                0u32.to_le_bytes(),
                vec![0; R0_SUCCINCT_CONTROL_DIGEST_BYTES * (R0_SUCCINCT_MAX_CONTROL_DIGESTS + 1)],
                vec![0; 16],
                [0x44; 32],
                [0x55; 32],
                [0x66; 32],
                R0_SUCCINCT_HASH_FN_POSEIDON2,
            ),
            Err(ZkError::R0SuccinctTooManyItems {
                field: "control_digests",
                ..
            })
        ));
        assert!(matches!(
            R0SuccinctPrecompileStack::new(
                [0x11; 32],
                0u32.to_le_bytes(),
                vec![0; R0_SUCCINCT_CONTROL_DIGEST_BYTES],
                vec![0; 15],
                [0x44; 32],
                [0x55; 32],
                [0x66; 32],
                R0_SUCCINCT_HASH_FN_POSEIDON2,
            ),
            Err(ZkError::InvalidR0SuccinctFieldMultiple { field: "seal", .. })
        ));
        assert!(matches!(
            R0SuccinctPrecompileStack::new(
                [0x11; 32],
                0u32.to_le_bytes(),
                vec![0; R0_SUCCINCT_CONTROL_DIGEST_BYTES],
                vec![0; 16],
                [0x44; 32],
                [0x55; 32],
                [0x66; 32],
                2,
            ),
            Err(ZkError::UnsupportedR0SuccinctHashFn(2))
        ));
    }

    #[test]
    fn public_inputs_length_is_pinned() {
        let r = sample_receipt();
        let id = receipt_commitment(&r);
        let s = ZkStatement::from_receipt(&r, id);
        let inputs = s.public_inputs();
        assert_eq!(inputs.len(), ZkStatement::PUBLIC_INPUT_LEN);
    }

    #[test]
    fn statement_matches_receipt_round_trip() {
        let r = sample_receipt();
        let id = receipt_commitment(&r);
        let s = ZkStatement::from_receipt(&r, id);
        assert!(s.matches(&r, id));
        let mut r2 = r.clone();
        r2.new_state.state_digest[0] ^= 1;
        assert!(!s.matches(&r2, id));
    }

    #[test]
    fn proof_rejects_empty() {
        assert!(matches!(
            ZkProof::new(ZkTag::Groth16, vec![]),
            Err(ZkError::MissingProof)
        ));
    }

    #[test]
    fn proof_rejects_oversize() {
        let big = vec![0u8; ZkProof::MAX_PROOF_BYTES + 1];
        assert!(matches!(
            ZkProof::new(ZkTag::Groth16, big),
            Err(ZkError::ProofTooLong { .. })
        ));
    }

    #[test]
    fn proof_rejects_reserved_succinct_tag() {
        assert!(matches!(
            ZkProof::new(ZkTag::R0Succinct, vec![1, 2, 3]),
            Err(ZkError::UnsupportedTag(ZkTag::R0Succinct))
        ));
    }

    #[test]
    fn proof_encode_for_precompile() {
        let p = ZkProof::new(ZkTag::Groth16, vec![1, 2, 3, 4]).unwrap();
        let encoded = p.encode_for_precompile();
        assert_eq!(encoded, vec![0x20, 1, 2, 3, 4]);
    }

    #[test]
    fn zk_receipt_rejects_wrong_mode() {
        let mut r = sample_receipt();
        r.proof_mode = ProofMode::VerifierReceipt;
        let id = receipt_commitment(&r);
        let proof = ZkProof::new(ZkTag::Groth16, vec![1, 2, 3]).unwrap();
        assert!(matches!(
            ZkReceipt::build(&r, id, proof),
            Err(ZkError::WrongMode(_))
        ));
    }

    #[test]
    fn zk_receipt_local_verify_succeeds() {
        let r = sample_receipt();
        let id = receipt_commitment(&r);
        let proof = ZkProof::new(ZkTag::Groth16, vec![9, 8, 7]).unwrap();
        let zr = ZkReceipt::build(&r, id, proof).unwrap();
        let pre = zr.verify_local(&r, id).unwrap();
        // Tag byte + proof bytes
        assert_eq!(pre, vec![0x20, 9, 8, 7]);
    }

    #[test]
    fn zk_receipt_local_verify_catches_statement_mismatch() {
        let r = sample_receipt();
        let id = receipt_commitment(&r);
        let proof = ZkProof::new(ZkTag::Groth16, vec![1]).unwrap();
        let zr = ZkReceipt::build(&r, id, proof).unwrap();
        // Tamper with receipt: change new_state digest.
        let mut r2 = r.clone();
        r2.new_state.state_digest[0] ^= 1;
        assert!(matches!(
            zr.verify_local(&r2, id),
            Err(ZkError::StatementMismatch)
        ));
    }

    #[test]
    fn chain_id_in_public_inputs_is_pinned() {
        // chain tag 'K' = 0x4b, then chain value 0x05 for KaspaLocalToccata.
        let r = sample_receipt();
        let id = receipt_commitment(&r);
        let s = ZkStatement::from_receipt(&r, id);
        let inputs = s.public_inputs();
        // Skip the first 4 * 32 = 128 bytes (old/new/asset/covenant), then
        // the next 4 bytes should be the chain tag LE u32 = 0x4b.
        assert_eq!(inputs[128..132], [0x4b, 0x00, 0x00, 0x00]);
        // Next 4 bytes: chain value LE u32 = 0x05.
        assert_eq!(inputs[132..136], [0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn semantic_transition_statement_binds_native_reports() {
        let (transition, continuation) = sample_semantic_reports();
        let statement =
            SemanticTransitionStatement::from_reports(&transition, &continuation).unwrap();
        let inputs = statement.public_inputs();
        assert_eq!(inputs.len(), SemanticTransitionStatement::PUBLIC_INPUT_LEN);
        assert_eq!(inputs[0..4], [0x4b, 0x00, 0x00, 0x00]);
        assert_eq!(inputs[4..8], [0x05, 0x00, 0x00, 0x00]);
        assert_eq!(statement.schema_id, RGK_FUNGIBLE_ASSET_SCHEMA_ID);
        assert_eq!(statement.total_supply, 1_000_000);
        assert_eq!(statement.spent_allocation_count, 1);
        assert_eq!(statement.new_allocation_count, 1);
        assert_eq!(statement.spent_supply, 1_000_000);
        assert_eq!(statement.new_supply, 1_000_000);
        assert_eq!(statement.burned_supply, 0);
        assert_eq!(statement.burn_authorization_commitment, [0; 32]);
    }

    #[test]
    fn semantic_transition_statement_rejects_report_mismatch() {
        let (transition, mut continuation) = sample_semantic_reports();
        continuation.previous_state_digest = RgkStateDigest::from_bytes(b32(
            "9999999999999999999999999999999999999999999999999999999999999999",
        ))
        .expect("fixture previous state digest is non-zero");
        assert!(matches!(
            SemanticTransitionStatement::from_reports(&transition, &continuation),
            Err(ZkError::SemanticTransitionMismatch("previous_state_digest"))
        ));
    }

    #[test]
    fn semantic_transition_statement_rejects_supply_mismatch() {
        let (mut transition, continuation) = sample_semantic_reports();
        transition.burned_supply = 1;
        assert!(matches!(
            SemanticTransitionStatement::from_reports(&transition, &continuation),
            Err(ZkError::SemanticTransitionMismatch("burned_supply"))
        ));

        let (mut transition, mut continuation) = sample_semantic_reports();
        transition.new_supply = 999_999;
        continuation.new_supply = 999_999;
        transition.burned_supply = 0;
        continuation.burned_supply = 0;
        assert!(matches!(
            SemanticTransitionStatement::from_reports(&transition, &continuation),
            Err(ZkError::SemanticTransitionInvalid(
                "spent_supply != new_supply + burned_supply"
            ))
        ));

        let (mut transition, continuation) = sample_semantic_reports();
        transition.burn_authorization_commitment = [0xa1; 32];
        assert!(matches!(
            SemanticTransitionStatement::from_reports(&transition, &continuation),
            Err(ZkError::SemanticTransitionMismatch(
                "burn_authorization_commitment"
            ))
        ));
    }

    #[test]
    fn semantic_transition_statement_rejects_noop_digest() {
        let (mut transition, continuation) = sample_semantic_reports();
        transition.new_state_digest = transition.previous_state_digest;
        assert!(matches!(
            SemanticTransitionStatement::from_reports(&transition, &continuation),
            Err(ZkError::SemanticTransitionInvalid("no-op state digest"))
        ));
    }

    #[test]
    fn semantic_transition_statement_matches_receipt_statement() {
        let receipt = sample_receipt();
        let receipt_id = receipt_commitment(&receipt);
        let zk_statement = ZkStatement::from_receipt(&receipt, receipt_id);
        let (transition, continuation) = sample_semantic_reports();
        let statement =
            SemanticTransitionStatement::from_reports(&transition, &continuation).unwrap();

        assert!(statement.matches_receipt(&receipt));
        assert!(statement.matches_zk_statement(&zk_statement));

        let mut tampered_receipt = receipt.clone();
        tampered_receipt.continuation_commitment[0] ^= 1;
        assert!(!statement.matches_receipt(&tampered_receipt));

        let mut tampered_zk_statement = zk_statement;
        tampered_zk_statement.new_state_digest[0] ^= 1;
        assert!(!statement.matches_zk_statement(&tampered_zk_statement));
    }
}

/// Real Groth16 prover + verifier (gated by the `real-zk` feature).
#[cfg(feature = "real-zk")]
pub mod real_zk;
