#![allow(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]
//! # rgk-asset semantics
//!
//! This crate exposes RGK's native asset grammar and lane validation.
//!
//! RGK is a Kaspa-native asset grammar over Toccata covenant lineages. It
//! defines client-side validation, receipt evidence, and covenant-output
//! discipline over Kaspa Toccata covenant lineages.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(clippy::needless_borrows_for_generic_args)]

extern crate alloc;

pub mod native;

pub use native::{
    allocation_transcript_amount_commitment, allocation_transcript_empty_root,
    derive_blinded_lane_id, derive_private_lane_graph_root, discover_lane,
    extend_allocation_transcript_root, extend_private_lane_graph_root,
    private_lane_graph_empty_root, BlindedLaneId, ImageIdPolicy, LanePrivacyPolicy, RgkAllocation,
    RgkAllocationProofShape, RgkAllocationTranscriptSide, RgkAssetError, RgkAssetId,
    RgkAssetIdDerivation, RgkAssetIssue, RgkBurnProof, RgkCollectionId,
    RgkContinuationAllocationShape, RgkContinuationCommitment, RgkContinuationPlan,
    RgkContinuationReport, RgkContinuationShapeRoot, RgkCovenantAnchor, RgkFinalizedContinuation,
    RgkFinalizedProductionAllocationStrategyTransfer, RgkFinalizedProductionZkTransfer,
    RgkIssueReport, RgkLane, RgkLaneGraphNode, RgkLaneState, RgkLaneStateInput,
    RgkMetadataCommitment, RgkNftBurnContinuationReport, RgkNftBurnReport,
    RgkNftCollectionIdDerivation, RgkNftCollectionPolicy, RgkNftMarketplaceSaleCommitment,
    RgkNftMarketplaceSaleReport, RgkNftMarketplaceSaleTerms, RgkNftMintReport,
    RgkNftPolicyCommitment, RgkNftTemplateCommitment, RgkNftTokenCommitment, RgkNftTokenId,
    RgkNftTokenSpec, RgkNftTransferReport, RgkNullifier, RgkOwnerCommitment, RgkOwnerDescriptor,
    RgkPolicyCommitment, RgkPrivacyPolicy, RgkProductionAllocationStrategy,
    RgkProductionAllocationStrategyCommitment, RgkProductionAllocationStrategyPlan,
    RgkProductionAllocationStrategyRecord, RgkProductionZkTransferPlan, RgkProofPolicy,
    RgkReceiptCommitment, RgkScanTag, RgkSchemaId, RgkStateDigest, RgkTransition,
    RgkTransitionDigest, RgkTransitionReport, RGK_ALLOCATION_STRATEGY_RECORD_TAG,
    RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW, RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT,
    RGK_ALLOCATION_STRATEGY_ZK_SHAPES, RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS,
    RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY,
};
pub use rgk_core::Hex32;

/// Commitment and digest marker types used by the native asset grammar.
pub mod commitments {
    pub use crate::native::{
        RgkContinuationCommitment, RgkContinuationShapeRoot, RgkMetadataCommitment, RgkNullifier,
        RgkOwnerCommitment, RgkPolicyCommitment, RgkReceiptCommitment, RgkScanTag, RgkStateDigest,
        RgkTransitionDigest,
    };
}

/// Lane privacy, discovery, and private-lane graph helpers.
pub mod lanes {
    pub use crate::native::{
        derive_blinded_lane_id, derive_private_lane_graph_root, discover_lane,
        extend_private_lane_graph_root, private_lane_graph_empty_root, BlindedLaneId,
        LanePrivacyPolicy, RgkLane, RgkLaneGraphNode, RgkLaneState, RgkLaneStateInput,
        RgkPrivacyPolicy,
    };
}

/// Native fungible-asset issue, transition, continuation, and burn types.
pub mod fungible {
    pub use crate::native::{
        RgkAllocation, RgkAssetId, RgkAssetIdDerivation, RgkAssetIssue, RgkBurnProof,
        RgkContinuationAllocationShape, RgkContinuationPlan, RgkContinuationReport,
        RgkCovenantAnchor, RgkFinalizedContinuation, RgkIssueReport, RgkOwnerDescriptor,
        RgkProofPolicy, RgkSchemaId, RgkTransition, RgkTransitionReport,
    };
}

/// NFT collection, mint, transfer, burn, and marketplace-sale types.
pub mod nft {
    pub use crate::native::{
        RgkCollectionId, RgkNftBurnContinuationReport, RgkNftBurnReport,
        RgkNftCollectionIdDerivation, RgkNftCollectionPolicy, RgkNftMarketplaceSaleCommitment,
        RgkNftMarketplaceSaleReport, RgkNftMarketplaceSaleTerms, RgkNftMintReport,
        RgkNftPolicyCommitment, RgkNftTemplateCommitment, RgkNftTokenCommitment, RgkNftTokenId,
        RgkNftTokenSpec, RgkNftTransferReport,
    };
}

/// Allocation transcript and allocation-strategy ZK helper types.
pub mod allocation_strategy {
    pub use crate::native::{
        allocation_transcript_amount_commitment, allocation_transcript_empty_root,
        extend_allocation_transcript_root, RgkAllocationProofShape, RgkAllocationTranscriptSide,
        RgkFinalizedProductionAllocationStrategyTransfer, RgkFinalizedProductionZkTransfer,
        RgkProductionAllocationStrategy, RgkProductionAllocationStrategyCommitment,
        RgkProductionAllocationStrategyPlan, RgkProductionAllocationStrategyRecord,
        RgkProductionZkTransferPlan, RGK_ALLOCATION_STRATEGY_RECORD_TAG,
        RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW, RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT,
        RGK_ALLOCATION_STRATEGY_ZK_SHAPES, RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS,
        RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY,
    };
}

#[doc(hidden)]
pub mod internal {
    use rgk_core::Bytes32;

    /// Compute an RGK asset-domain SHA-256 hash from a string domain.
    pub fn asset_domain_hash(domain: &str, payload: &[u8]) -> Bytes32 {
        rgk_core::domain_hash_str(domain, payload)
    }
}

pub const RGK_FUNGIBLE_ASSET_SCHEMA_ID: RgkSchemaId = *b"rgk:asset:schema:v1_____________";

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
