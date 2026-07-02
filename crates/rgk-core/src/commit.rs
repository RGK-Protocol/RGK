//! Domain-separated SHA-256 commitments.
//!
//! Every RGK commitment is SHA-256 over a *tagged* preimage. The tag is a
//! fixed ASCII literal that uniquely identifies the commitment purpose. This is
//! the standard domain-separation discipline (cf. BIP-340 tagged hashes) and
//! it defeats cross-protocol confusion attacks:
//! a `state_commitment` can never collide with a `receipt_commitment` even if
//! the underlying payloads were identical.
//!
//! Concrete recipe (single SHA-256, not double):
//!
//! ```text
//! commitment = SHA256( ascii_tag_le32_len || ascii_tag_bytes || payload )
//! ```
//!
//! where `ascii_tag_le32_len = (tag.len() as u32).to_le_bytes()`. This matches
//! a simple tagged-hash recipe while remaining fully self-contained.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::bytes::Bytes32;
use crate::chain::KaspaChainId;
use crate::policy::{ProofMode, ReceiptPolicy};
use crate::types::{
    PolicyMigrationCommitment, PolicyMigrationInput, PolicyMigrationProof, RgkAssetId, RgkReceipt,
    RgkStateCommitment, TransitionDigest,
};

/// A typed domain-separation tag. Each variant maps to a fixed ASCII literal.
#[derive(Copy, Clone, Debug)]
pub enum DomainTag {
    /// `rgk:state-commitment` — digest of a [`RgkStateCommitment`] payload.
    StateCommitment,
    /// `rgk:receipt` — the canonical receipt id.
    Receipt,
    /// `rgk:lineage` — covenant lineage id (derived from genesis outpoint).
    Lineage,
    /// `rgk:replay-nonce` — anti-replay nonce for a transition.
    ReplayNonce,
    /// `rgk:policy-migration` — explicit native receipt-policy migration proof.
    PolicyMigration,
    /// `rgk:advanced-covenant-policy:v1` — advanced covenant policy shape.
    AdvancedCovenantPolicy,
    /// `rgk:advanced-covenant-execution:v1` — advanced covenant execution evidence.
    AdvancedCovenantExecution,
}

impl DomainTag {
    pub const fn ascii(self) -> &'static str {
        match self {
            DomainTag::StateCommitment => "rgk:state-commitment",
            DomainTag::Receipt => "rgk:receipt",
            DomainTag::Lineage => "rgk:lineage",
            DomainTag::ReplayNonce => "rgk:replay-nonce",
            DomainTag::PolicyMigration => "rgk:policy-migration",
            DomainTag::AdvancedCovenantPolicy => "rgk:advanced-covenant-policy:v1",
            DomainTag::AdvancedCovenantExecution => "rgk:advanced-covenant-execution:v1",
        }
    }
}

/// Compute a tagged SHA-256 over `payload`.
pub fn domain_hash(tag: DomainTag, payload: &[u8]) -> Bytes32 {
    domain_hash_str(tag.ascii(), payload)
}

/// Compute a tagged SHA-256 over `payload` using an explicit ASCII domain.
///
/// Prefer [`domain_hash`] for core protocol domains with stable enum variants.
/// This helper exists for higher-level crates such as `rgk-asset` that have a
/// larger set of grammar-specific domain strings.
pub fn domain_hash_str(domain: &str, payload: &[u8]) -> Bytes32 {
    let tag_bytes = domain.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update((tag_bytes.len() as u32).to_le_bytes());
    hasher.update(tag_bytes);
    hasher.update(payload);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Canonical state-commitment digest for a [`RgkStateCommitment`] payload.
///
/// The payload is the struct's canonical body (without the domain magic header
/// used for wire encoding — see `RECEIPT-SPEC.md` for the exact split).
pub fn state_commitment(s: &RgkStateCommitment) -> Bytes32 {
    // Reuse the wire body (without magic+version) as the commitment preimage,
    // so the commitment is a pure function of the canonical encoding.
    let body = s.encode_body();
    domain_hash(DomainTag::StateCommitment, &body)
}

/// Canonical receipt id for a [`RgkReceipt`]. This is the value that lives in
/// `ReceiptId` and that the indexer tracks for replay protection.
pub fn receipt_commitment(r: &RgkReceipt) -> Bytes32 {
    let body = r.encode_body();
    domain_hash(DomainTag::Receipt, &body)
}

/// Covenant lineage id derived from a genesis outpoint + native RGK asset id.
pub fn lineage_id(genesis_outpoint_payload: &[u8], asset_id: &RgkAssetId) -> Bytes32 {
    let mut payload = Vec::with_capacity(genesis_outpoint_payload.len() + 32);
    payload.extend_from_slice(genesis_outpoint_payload);
    payload.extend_from_slice(asset_id);
    domain_hash(DomainTag::Lineage, &payload)
}

/// Derive a deterministic anti-replay nonce from a previous outpoint and a
/// transition digest. Callers may instead supply their own random nonce; this
/// helper exists so that two independent parties compute the same nonce for the
/// same transition (useful in single-signer flows).
pub fn replay_nonce(prev_outpoint_payload: &[u8], transition_digest: &TransitionDigest) -> Bytes32 {
    let mut payload = Vec::with_capacity(prev_outpoint_payload.len() + 32);
    payload.extend_from_slice(prev_outpoint_payload);
    payload.extend_from_slice(transition_digest);
    domain_hash(DomainTag::ReplayNonce, &payload)
}

/// Commitment for an explicit native receipt-policy migration proof.
pub fn policy_migration_commitment(
    previous_policy: ReceiptPolicy,
    new_policy: ReceiptPolicy,
    previous_state_digest: Bytes32,
    new_state_digest: Bytes32,
    transition_digest: TransitionDigest,
    authorization_commitment: Bytes32,
) -> PolicyMigrationCommitment {
    use crate::encoding::Canonical;

    let mut w = crate::encoding::Writer::new();
    previous_policy.encode(&mut w);
    new_policy.encode(&mut w);
    w.write_bytes32(&previous_state_digest);
    w.write_bytes32(&new_state_digest);
    w.write_bytes32(&transition_digest);
    w.write_bytes32(&authorization_commitment);
    domain_hash(DomainTag::PolicyMigration, &w.into_vec())
}

/// Build explicit native receipt-policy migration proof material from the
/// wallet/verifier input fields.
pub fn build_policy_migration_proof(input: PolicyMigrationInput) -> PolicyMigrationProof {
    let migration_commitment = policy_migration_commitment(
        input.previous_policy,
        input.new_policy,
        input.previous_state_digest,
        input.new_state_digest,
        input.transition_digest,
        input.authorization_commitment,
    );
    PolicyMigrationProof {
        previous_policy: input.previous_policy,
        new_policy: input.new_policy,
        previous_state_digest: input.previous_state_digest,
        new_state_digest: input.new_state_digest,
        transition_digest: input.transition_digest,
        authorization_commitment: input.authorization_commitment,
        migration_commitment,
    }
}

impl PolicyMigrationInput {
    /// Build a proof with the canonical `rgk:policy-migration` commitment.
    pub fn build(self) -> PolicyMigrationProof {
        build_policy_migration_proof(self)
    }
}

// ---- body-only encoders (no magic header) ----
//
// These mirror the `Canonical::encode` impls but omit the outer magic+version
// header, because the commitment must be over the *content*, not the framing.

impl RgkStateCommitment {
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        use crate::encoding::Writer;
        let mut w = Writer::new();
        // Domain string first — binds the chain, covenant, asset, policy
        // into a single human-auditable prefix that is part of the commitment.
        w.write_str(&domain_string(self.chain_id, self.receipt_policy, None));
        w.write_bytes32(&self.covenant_id);
        w.write_bytes32(&self.asset_id);
        w.write_bytes32(&self.state_digest);
        w.into_vec()
    }
}

impl RgkReceipt {
    /// Encode the receipt body without the magic+version header. This is
    /// the canonical preimage of `receipt_commitment` and is exposed so
    /// external verifiers / ZK circuits can rebuild the commitment.
    pub fn encode_body(&self) -> Vec<u8> {
        use crate::encoding::Writer;
        let mut w = Writer::new();
        w.write_str(&domain_string(
            self.chain_id,
            self.old_state.receipt_policy,
            Some(self.proof_mode),
        ));
        w.write_bytes32(&self.covenant_id);
        w.write_bytes32(&self.old_state.state_digest);
        w.write_bytes32(&self.new_state.state_digest);
        w.write_bytes32(&self.transition_digest);
        w.write_bytes32(&self.continuation_commitment);
        w.write_bytes32(&self.replay_nonce);
        w.into_vec()
    }
}

/// Build the canonical, human-readable domain-separation string. Order matters
/// and is frozen by the spec:
///
/// ```text
/// rgk:v0 | chain=<chain> | policy=<policy> | mode=<mode?>
/// ```
pub fn domain_string(
    chain: KaspaChainId,
    policy: ReceiptPolicy,
    mode: Option<ProofMode>,
) -> String {
    use alloc::format;
    match mode {
        Some(m) => format!(
            "rgk:v0 | chain={} | policy={} | mode={}",
            chain.as_domain_str(),
            policy.as_domain_str(),
            m.as_domain_str()
        ),
        None => format!(
            "rgk:v0 | chain={} | policy={}",
            chain.as_domain_str(),
            policy.as_domain_str()
        ),
    }
}
