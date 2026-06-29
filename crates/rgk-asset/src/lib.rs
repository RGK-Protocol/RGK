#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-asset semantics
//!
//! This crate exposes RGK's native asset grammar and lane validation. It is not
//! an adapter for another client-side asset runtime.
//!
//! RGK is a Kaspa-native client-side asset protocol. It defines client-side
//! validation, receipt evidence, and seal discipline over Kaspa Toccata
//! covenant lineages.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::needless_borrows_for_generic_args)]

extern crate alloc;

use rgk_core::Bytes32;

pub mod native;

pub use native::{
    allocation_transcript_amount_commitment, allocation_transcript_empty_root,
    derive_blinded_lane_id, derive_private_lane_graph_root, discover_lane,
    extend_allocation_transcript_root, extend_private_lane_graph_root,
    private_lane_graph_empty_root, BlindedLaneId, ImageIdPolicy, LanePrivacyPolicy, RgkAllocation,
    RgkAllocationProofShape, RgkAllocationTranscriptSide, RgkAssetError, RgkAssetId,
    RgkAssetIdDerivation, RgkAssetIssue, RgkBurnProof, RgkCollectionId,
    RgkContinuationAllocationShape, RgkContinuationCommitment, RgkContinuationPlan,
    RgkContinuationReport, RgkContinuationShapeRoot, RgkCovenantSeal, RgkFinalizedContinuation,
    RgkFinalizedProductionAllocationStrategyTransfer, RgkFinalizedProductionZkTransfer,
    RgkIssueReport, RgkLane, RgkLaneGraphNode, RgkLaneState, RgkLaneStateInput,
    RgkMetadataCommitment, RgkNftBurnContinuationReport, RgkNftBurnReport,
    RgkNftCollectionIdDerivation, RgkNftCollectionPolicy, RgkNftMarketplaceSaleCommitment,
    RgkNftMarketplaceSaleReport, RgkNftMarketplaceSaleTerms, RgkNftMintReport,
    RgkNftPolicyCommitment, RgkNftTemplateCommitment, RgkNftTokenCommitment, RgkNftTokenId,
    RgkNftTokenSpec, RgkNftTransferReport, RgkNullifier, RgkOwnerCommitment, RgkOwnerDescriptor,
    RgkPolicyCommitment, RgkPrivacyPolicy, RgkProductionAllocationStrategy,
    RgkProductionAllocationStrategyCommitment, RgkProductionAllocationStrategyPlan,
    RgkProductionZkTransferPlan, RgkProofPolicy, RgkReceiptCommitment, RgkScanTag, RgkSchemaId,
    RgkStateDigest, RgkTransition, RgkTransitionDigest, RgkTransitionReport,
    RGK_PRODUCTION_ZK_ALLOCATION_MAX_NEW, RGK_PRODUCTION_ZK_ALLOCATION_MAX_SPENT,
    RGK_PRODUCTION_ZK_ALLOCATION_SHAPES, RGK_PRODUCTION_ZK_ALLOCATION_SHAPE_LABELS,
    RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY,
};

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

pub const RGK_FUNGIBLE_ASSET_SCHEMA_ID: RgkSchemaId = *b"rgk:asset:schema:v1_____________";

/// Compute a tagged SHA-256 hash with a domain string.
pub fn domain_hash_domain(domain: &str, payload: &[u8]) -> Bytes32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u32).to_le_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(payload);
    let out = hasher.finalize();
    let mut out32 = [0u8; 32];
    out32.copy_from_slice(&out);
    out32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_id_is_native_rgk_text() {
        assert_eq!(
            RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            *b"rgk:asset:schema:v1_____________"
        );
    }
}
