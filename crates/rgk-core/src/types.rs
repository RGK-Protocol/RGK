//! Canonical RGK types.
//!
//! These are the canonical objects that cross the RGK asset / Kaspa boundary. Every field
//! is documented in `docs/RECEIPT-SPEC.md` and the byte layout is frozen by the
//! hand-rolled [`crate::encoding`] impls.
//!
//! Naming note: the task brief proposed `RgkAssetRef`, `RgkStateCommitment`
//! and `RgkReceipt`. We keep those exact type names because they describe the
//! native protocol surface. Native RGK asset labels and grammar identifiers
//! are 32-byte commitments, Kaspa's covenant id is `kaspa_hashes::Hash`
//! (32 bytes), and a Kaspa outpoint is `{ transaction_id: Hash, index: u32 }`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::bytes::{fmt_hex, Bytes32};
use crate::chain::KaspaChainId;
use crate::encoding::{Canonical, Reader, Writer};
use crate::error::DecodeError;
use crate::policy::{ProofMode, ReceiptPolicy};

/// A reference to a native RGK asset: its lineage-bound 32-byte
/// [`RgkAssetId`] label plus the 32-byte native grammar id
/// [`RgkSchemaId`].
///
/// Both ids are RGK domain-separated commitments stored as raw `[u8;32]`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct RgkAssetRef {
    pub asset_id: RgkAssetId,
    pub schema_id: RgkSchemaId,
}

/// Native RGK asset label (32-byte domain-separated commitment hash).
pub type RgkAssetId = Bytes32;
/// Native RGK asset grammar id (32-byte domain-separated commitment hash).
pub type RgkSchemaId = Bytes32;

/// Kaspa covenant id = `kaspa_hashes::Hash` (32 bytes), computed by
/// `kaspa_consensus_core::hashing::covenant_id::covenant_id` at covenant genesis.
pub type KaspaCovenantId = Bytes32;

/// A Kaspa outpoint = `{ transaction_id: 32-byte Hash, index: u32 }`. Matches
/// `kaspa_consensus_core::tx::TransactionOutpoint` exactly in content
/// (encoding order is fixed here, independent of upstream's borsh layout).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KaspaOutpoint {
    pub transaction_id: Bytes32,
    pub index: u32,
}

impl KaspaOutpoint {
    pub const NULL: KaspaOutpoint = KaspaOutpoint {
        transaction_id: [0u8; 32],
        index: 0,
    };
}

/// A stable lineage id grouping all covenant UTXOs that descend from the same
/// genesis outpoint. By default a lineage is preserved across transitions
/// (same `covenant_id`); migrations are an explicit, separately-tagged event.
pub type CovenantLineageId = Bytes32;

/// The deterministic digest of an RGK transition that the receipt commits to.
pub type TransitionDigest = Bytes32;

/// The phase-1 continuation commitment that a receipt commits to before the
/// phase-2 Kaspa transaction id is known.
pub type ContinuationCommitment = Bytes32;

/// The domain-separated commitment carried by an explicit receipt-policy
/// migration proof.
pub type PolicyMigrationCommitment = Bytes32;

/// The RGK receipt id. It is *derived* (not chosen) from the receipt contents
/// via [`crate::commit::receipt_commitment`], so it is a pure function of the
/// canonical encoding. Stored as a 32-byte SHA-256 commitment.
pub type ReceiptId = Bytes32;

/// Input fields a wallet or verifier supplies when constructing an explicit
/// receipt-policy migration proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyMigrationInput {
    pub previous_policy: ReceiptPolicy,
    pub new_policy: ReceiptPolicy,
    pub previous_state_digest: Bytes32,
    pub new_state_digest: Bytes32,
    pub transition_digest: TransitionDigest,
    pub authorization_commitment: Bytes32,
}

/// Explicit native proof material for a receipt-policy change.
///
/// A normal RGK receipt cannot silently change receipt policy. This proof binds
/// the previous and new policies to the old/new state digests, the native
/// transition digest, and a wallet/verifier authorisation commitment.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyMigrationProof {
    pub previous_policy: ReceiptPolicy,
    pub new_policy: ReceiptPolicy,
    pub previous_state_digest: Bytes32,
    pub new_state_digest: Bytes32,
    pub transition_digest: TransitionDigest,
    pub authorization_commitment: Bytes32,
    pub migration_commitment: PolicyMigrationCommitment,
}

/// A RGK state commitment: a typed binding of "the RGK asset state for asset X,
/// on Kaspa chain Y, under covenant Z, is currently summarised by
/// `state_digest`".
///
/// `state_digest` is computed by the native asset grammar from RGK objects
/// (see `docs/RECEIPT-SPEC.md` for the exact recipe) and is opaque to
/// `rgk-core` on purpose: the core only guarantees it is 32 bytes and that it
/// is compared exactly by the verifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RgkStateCommitment {
    /// Canonical encoding version of this commitment (currently 0).
    pub version: u16,
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub asset_id: RgkAssetId,
    /// Opaque 32-byte RGK state digest.
    pub state_digest: Bytes32,
    pub receipt_policy: ReceiptPolicy,
}

impl RgkStateCommitment {
    /// Domain-separation literal for this struct (see [`crate::commit`]).
    pub const DOMAIN: &'static str = "rgk:state-commitment";
}

/// The RGK receipt: a typed, replay-protected statement that an RGK transition
/// moved a covenant's state from `old_state` to `new_state`.
///
/// Receipts are generated by the `rgk-receipt` crate from native RGK asset
/// validation results plus Kaspa covenant context, and verified by both the
/// local verifier and (for output-shape + lineage) the on-chain covenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RgkReceipt {
    pub version: u16,
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub old_state: RgkStateCommitment,
    pub new_state: RgkStateCommitment,
    pub transition_digest: TransitionDigest,
    pub continuation_commitment: ContinuationCommitment,
    pub proof_mode: ProofMode,
    /// Anti-replay nonce. Must be unique per (covenant_id, transition) pair; the
    /// covenant/indexer enforces non-reuse. 32 bytes to allow a hash-derived
    /// nonce (e.g. `H(prev_outpoint || transition_digest)`).
    pub replay_nonce: Bytes32,
}

impl RgkReceipt {
    pub const DOMAIN: &'static str = "rgk:receipt";

    /// Cross-field structural invariants every well-formed receipt must satisfy.
    /// These are checked by the verifier too, but encoding refuses to produce a
    /// receipt that violates them, and decoding refuses to accept one.
    pub fn validate_structure(&self) -> Result<(), DecodeError> {
        if self.old_state.chain_id != self.chain_id || self.new_state.chain_id != self.chain_id {
            return Err(DecodeError::Structural(
                "chain id mismatch in receipt".to_string(),
            ));
        }
        if self.old_state.covenant_id != self.covenant_id
            || self.new_state.covenant_id != self.covenant_id
        {
            return Err(DecodeError::Structural(
                "covenant id mismatch in receipt".to_string(),
            ));
        }
        if self.old_state.asset_id != self.new_state.asset_id {
            return Err(DecodeError::Structural(
                "asset id changed across transition".to_string(),
            ));
        }
        if self.old_state.receipt_policy != self.new_state.receipt_policy {
            return Err(DecodeError::Structural(
                "receipt policy changed across transition".to_string(),
            ));
        }
        if self.old_state.state_digest == self.new_state.state_digest {
            // A no-op transition is not a valid state change; the covenant
            // exists precisely to advance state. Reject to avoid trivial
            // self-replay.
            return Err(DecodeError::Structural(
                "state digest did not change".to_string(),
            ));
        }
        if self.continuation_commitment == [0u8; 32] {
            return Err(DecodeError::Structural(
                "continuation commitment missing".to_string(),
            ));
        }
        if !self.old_state.receipt_policy.admits(self.proof_mode) {
            return Err(DecodeError::Structural(format!(
                "proof mode {:?} not admitted by receipt policy {:?}",
                self.proof_mode, self.old_state.receipt_policy
            )));
        }
        Ok(())
    }
}

// ---------------- Canonical encodings ----------------

impl Canonical for KaspaOutpoint {
    fn encode(&self, w: &mut Writer) {
        w.write_bytes32(&self.transaction_id);
        w.write_u32(self.index);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(KaspaOutpoint {
            transaction_id: r.read_bytes32()?,
            index: r.read_u32()?,
        })
    }
}

impl Canonical for RgkAssetRef {
    fn encode(&self, w: &mut Writer) {
        w.write_bytes32(&self.asset_id);
        w.write_bytes32(&self.schema_id);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(RgkAssetRef {
            asset_id: r.read_bytes32()?,
            schema_id: r.read_bytes32()?,
        })
    }
}

impl Canonical for RgkStateCommitment {
    fn encode(&self, w: &mut Writer) {
        w.write_u16(self.version);
        self.chain_id.encode(w);
        w.write_bytes32(&self.covenant_id);
        w.write_bytes32(&self.asset_id);
        w.write_bytes32(&self.state_digest);
        self.receipt_policy.encode(w);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let version = r.read_u16()?;
        let chain_id = KaspaChainId::decode(r)?;
        let covenant_id = r.read_bytes32()?;
        let asset_id = r.read_bytes32()?;
        let state_digest = r.read_bytes32()?;
        let receipt_policy = ReceiptPolicy::decode(r)?;
        Ok(RgkStateCommitment {
            version,
            chain_id,
            covenant_id,
            asset_id,
            state_digest,
            receipt_policy,
        })
    }
}

impl Canonical for RgkReceipt {
    fn encode(&self, w: &mut Writer) {
        w.write_u16(self.version);
        self.chain_id.encode(w);
        w.write_bytes32(&self.covenant_id);
        self.old_state.encode(w);
        self.new_state.encode(w);
        w.write_bytes32(&self.transition_digest);
        w.write_bytes32(&self.continuation_commitment);
        self.proof_mode.encode(w);
        w.write_bytes32(&self.replay_nonce);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let version = r.read_u16()?;
        let chain_id = KaspaChainId::decode(r)?;
        let covenant_id = r.read_bytes32()?;
        let old_state = RgkStateCommitment::decode(r)?;
        let new_state = RgkStateCommitment::decode(r)?;
        let transition_digest = r.read_bytes32()?;
        let continuation_commitment = r.read_bytes32()?;
        let proof_mode = ProofMode::decode(r)?;
        let replay_nonce = r.read_bytes32()?;
        let receipt = RgkReceipt {
            version,
            chain_id,
            covenant_id,
            old_state,
            new_state,
            transition_digest,
            continuation_commitment,
            proof_mode,
            replay_nonce,
        };
        receipt.validate_structure()?;
        Ok(receipt)
    }
}

// ---------------- Display helpers ----------------

impl core::fmt::Display for KaspaOutpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_hex(&self.transaction_id, f)?;
        write!(f, ":{}", self.index)
    }
}

impl core::fmt::Display for RgkReceipt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(
            f,
            "RgkReceipt v{} ({})",
            self.version,
            self.chain_id.as_domain_str()
        )?;
        writeln!(f, "  covenant:      ")?;
        fmt_hex(&self.covenant_id, f)?;
        writeln!(f)?;
        writeln!(f, "  asset:         ")?;
        fmt_hex(&self.old_state.asset_id, f)?;
        writeln!(f)?;
        writeln!(f, "  proof_mode:    {}", self.proof_mode.as_str())?;
        writeln!(
            f,
            "  policy:        {}",
            self.old_state.receipt_policy.as_domain_str()
        )?;
        writeln!(f, "  old_state:     ")?;
        fmt_hex(&self.old_state.state_digest, f)?;
        writeln!(f)?;
        writeln!(f, "  new_state:     ")?;
        fmt_hex(&self.new_state.state_digest, f)?;
        writeln!(f)?;
        writeln!(f, "  transition:    ")?;
        fmt_hex(&self.transition_digest, f)?;
        writeln!(f)?;
        writeln!(f, "  continuation:  ")?;
        fmt_hex(&self.continuation_commitment, f)?;
        writeln!(f)?;
        writeln!(f, "  replay_nonce:  ")?;
        fmt_hex(&self.replay_nonce, f)
    }
}

/// Truncate a Vec<u8> display helper for logs/tests.
pub fn short_hex(b: &[u8]) -> String {
    let n = b.len().min(8);
    crate::bytes::to_hex::<8>(&{
        let mut out = [0u8; 8];
        out[..n].copy_from_slice(&b[..n]);
        out
    })
}

// Re-export Bytes32 display helper.
pub fn display_bytes32(b: &Bytes32) -> String {
    format!("0x{}", crate::bytes::to_hex(b))
}
