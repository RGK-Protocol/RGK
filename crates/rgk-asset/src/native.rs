//! Kaspa-native RGK asset and lane validation primitives.
//!
//! RGK defines client-side validation and seal discipline natively over Kaspa
//! Toccata covenant lineages. This module is not an external-runtime adapter.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use rgk_core::{Bytes32, KaspaChainId, KaspaCovenantId, KaspaOutpoint};
use thiserror::Error;

use crate::{domain_hash_domain, Hex32};

pub type RgkAssetId = Bytes32;
pub type RgkSchemaId = Bytes32;
pub type BlindedLaneId = Bytes32;
pub type RgkCollectionId = Bytes32;
pub type RgkNftTokenId = Bytes32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RgkAllocationTranscriptSide {
    Spent,
    New,
}

impl RgkAllocationTranscriptSide {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Spent => 0,
            Self::New => 1,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkStateDigest(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkTransitionDigest(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkReceiptCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNullifier(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkScanTag(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkPolicyCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkMetadataCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkOwnerCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftTemplateCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftPolicyCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftTokenCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftMarketplaceSaleCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RgkOwnerDescriptor {
    KeyHash(Bytes32),
    ScriptHash(Bytes32),
    CovenantId(KaspaCovenantId),
}

impl RgkOwnerDescriptor {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::KeyHash(_) => "key-hash",
            Self::ScriptHash(_) => "script-hash",
            Self::CovenantId(_) => "covenant-id",
        }
    }

    const fn tag(&self) -> u8 {
        match self {
            Self::KeyHash(_) => 0,
            Self::ScriptHash(_) => 1,
            Self::CovenantId(_) => 2,
        }
    }

    fn payload(&self) -> &Bytes32 {
        match self {
            Self::KeyHash(bytes) | Self::ScriptHash(bytes) | Self::CovenantId(bytes) => bytes,
        }
    }

    pub fn derive_commitment(&self) -> Result<RgkOwnerCommitment, RgkAssetError> {
        validate_owner_descriptor(self)?;
        let mut payload = Vec::with_capacity(33);
        payload.push(self.tag());
        payload.extend_from_slice(self.payload());
        Ok(RgkOwnerCommitment(domain_hash_domain(
            "rgk:owner:descriptor:v1",
            &payload,
        )))
    }
}

impl RgkOwnerCommitment {
    pub fn from_descriptor(descriptor: &RgkOwnerDescriptor) -> Result<Self, RgkAssetError> {
        descriptor.derive_commitment()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftCollectionIdDerivation {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub max_supply: u64,
    pub issuer_owner_commitment: RgkOwnerCommitment,
    pub template_commitment: RgkNftTemplateCommitment,
    pub royalty_policy_commitment: RgkNftPolicyCommitment,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftCollectionPolicy {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub collection_id: RgkCollectionId,
    pub max_supply: u64,
    pub issuer_owner_commitment: RgkOwnerCommitment,
    pub template_commitment: RgkNftTemplateCommitment,
    pub royalty_policy_commitment: RgkNftPolicyCommitment,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftTokenSpec {
    pub collection: RgkNftCollectionPolicy,
    pub token_index: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub owner_commitment: RgkOwnerCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkNftMintReport {
    pub token_id: RgkNftTokenId,
    pub token_commitment: RgkNftTokenCommitment,
    pub issue_report: RgkIssueReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkNftTransferReport {
    pub token_id: RgkNftTokenId,
    pub token_commitment: RgkNftTokenCommitment,
    pub transition_report: RgkTransitionReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkNftBurnContinuationReport {
    pub token_id: RgkNftTokenId,
    pub burned_token_commitment: RgkNftTokenCommitment,
    pub continuation_report: RgkContinuationReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkNftBurnReport {
    pub token_id: RgkNftTokenId,
    pub burned_token_commitment: RgkNftTokenCommitment,
    pub transition_report: RgkTransitionReport,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkNftMarketplaceSaleTerms {
    pub chain: KaspaChainId,
    pub collection_id: RgkCollectionId,
    pub token_id: RgkNftTokenId,
    pub seller_owner_commitment: RgkOwnerCommitment,
    pub buyer_owner_commitment: RgkOwnerCommitment,
    pub payment_asset_id: RgkAssetId,
    pub price_amount: u64,
    pub royalty_policy_commitment: RgkNftPolicyCommitment,
    pub royalty_amount: u64,
    pub authorization_commitment: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkNftMarketplaceSaleReport {
    pub token_id: RgkNftTokenId,
    pub sale_commitment: RgkNftMarketplaceSaleCommitment,
    pub token_commitment: RgkNftTokenCommitment,
    pub transition_report: RgkTransitionReport,
}

impl RgkNftMarketplaceSaleTerms {
    pub fn validate_basic(&self) -> Result<(), RgkAssetError> {
        reject_zero(&self.collection_id, RgkAssetError::ZeroNftCollectionId)?;
        reject_zero(&self.token_id, RgkAssetError::ZeroNftTokenId)?;
        validate_owner_commitment(self.seller_owner_commitment, "marketplace-seller")?;
        validate_owner_commitment(self.buyer_owner_commitment, "marketplace-buyer")?;
        if self.seller_owner_commitment == self.buyer_owner_commitment {
            return Err(RgkAssetError::NftMarketplaceSelfSale);
        }
        reject_zero(
            &self.payment_asset_id,
            RgkAssetError::ZeroNftMarketplacePaymentAsset,
        )?;
        if self.price_amount == 0 {
            return Err(RgkAssetError::ZeroNftMarketplacePrice);
        }
        reject_zero(
            &self.royalty_policy_commitment.0,
            RgkAssetError::ZeroNftPolicyCommitment,
        )?;
        if self.royalty_amount > self.price_amount {
            return Err(RgkAssetError::NftMarketplaceRoyaltyExceedsPrice {
                royalty: self.royalty_amount,
                price: self.price_amount,
            });
        }
        reject_zero(
            &self.authorization_commitment,
            RgkAssetError::ZeroOwnershipAuthorization,
        )
    }

    pub fn commitment(&self) -> Result<RgkNftMarketplaceSaleCommitment, RgkAssetError> {
        self.validate_basic()?;
        let mut payload = Vec::with_capacity(1 + (32 * 7) + (8 * 2));
        payload.push(self.chain as u8);
        payload.extend_from_slice(&self.collection_id);
        payload.extend_from_slice(&self.token_id);
        payload.extend_from_slice(&self.seller_owner_commitment.0);
        payload.extend_from_slice(&self.buyer_owner_commitment.0);
        payload.extend_from_slice(&self.payment_asset_id);
        payload.extend_from_slice(&self.price_amount.to_le_bytes());
        payload.extend_from_slice(&self.royalty_policy_commitment.0);
        payload.extend_from_slice(&self.royalty_amount.to_le_bytes());
        payload.extend_from_slice(&self.authorization_commitment);
        Ok(RgkNftMarketplaceSaleCommitment(domain_hash_domain(
            "rgk:nft:marketplace-sale:v1",
            &payload,
        )))
    }
}

impl RgkNftCollectionPolicy {
    pub fn derive_collection_id(
        input: RgkNftCollectionIdDerivation,
    ) -> Result<RgkCollectionId, RgkAssetError> {
        validate_nft_collection_material(
            input.schema_id,
            input.max_supply,
            input.issuer_owner_commitment,
            input.template_commitment,
            input.royalty_policy_commitment,
        )?;
        let mut payload = Vec::with_capacity(1 + 32 + 8 + 32 + 32 + 32);
        payload.push(input.chain as u8);
        payload.extend_from_slice(&input.schema_id);
        payload.extend_from_slice(&input.max_supply.to_le_bytes());
        payload.extend_from_slice(&input.issuer_owner_commitment.0);
        payload.extend_from_slice(&input.template_commitment.0);
        payload.extend_from_slice(&input.royalty_policy_commitment.0);
        Ok(domain_hash_domain("rgk:nft:collection-id:v1", &payload))
    }

    pub fn validate(&self) -> Result<(), RgkAssetError> {
        validate_nft_collection_material(
            self.schema_id,
            self.max_supply,
            self.issuer_owner_commitment,
            self.template_commitment,
            self.royalty_policy_commitment,
        )?;
        reject_zero(&self.collection_id, RgkAssetError::ZeroNftCollectionId)
    }
}

impl RgkNftTokenSpec {
    pub fn validate(&self) -> Result<(), RgkAssetError> {
        self.collection.validate()?;
        if self.token_index >= self.collection.max_supply {
            return Err(RgkAssetError::NftTokenIndexOutOfRange {
                token_index: self.token_index,
                max_supply: self.collection.max_supply,
            });
        }
        validate_metadata_commitment(self.metadata_commitment)?;
        validate_owner_commitment(self.owner_commitment, "nft-token")?;
        Ok(())
    }

    pub fn token_id(&self) -> Result<RgkNftTokenId, RgkAssetError> {
        self.validate()?;
        let mut payload = Vec::with_capacity(32 + 8 + 32 + 32 + 32);
        payload.extend_from_slice(&self.collection.collection_id);
        payload.extend_from_slice(&self.token_index.to_le_bytes());
        payload.extend_from_slice(&self.collection.template_commitment.0);
        payload.extend_from_slice(&self.collection.royalty_policy_commitment.0);
        payload.extend_from_slice(&self.metadata_commitment.0);
        Ok(domain_hash_domain("rgk:nft:token-id:v1", &payload))
    }

    pub fn token_commitment(&self) -> Result<RgkNftTokenCommitment, RgkAssetError> {
        self.token_commitment_for_owner(self.owner_commitment)
    }

    pub fn token_commitment_for_owner(
        &self,
        owner_commitment: RgkOwnerCommitment,
    ) -> Result<RgkNftTokenCommitment, RgkAssetError> {
        validate_owner_commitment(owner_commitment, "nft-token")?;
        let token_id = self.token_id()?;
        let mut payload = Vec::with_capacity(32 + 32 + 32);
        payload.extend_from_slice(&self.collection.collection_id);
        payload.extend_from_slice(&token_id);
        payload.extend_from_slice(&owner_commitment.0);
        Ok(RgkNftTokenCommitment(domain_hash_domain(
            "rgk:nft:token-commitment:v1",
            &payload,
        )))
    }

    pub fn validate_mint_issue(
        &self,
        issue: &RgkAssetIssue,
    ) -> Result<RgkNftMintReport, RgkAssetError> {
        self.validate()?;
        let token_id = self.token_id()?;
        validate_nft_issue_shape(self, issue, token_id)?;
        let issue_report = issue.validate()?;
        Ok(RgkNftMintReport {
            token_id,
            token_commitment: self.token_commitment()?,
            issue_report,
        })
    }

    pub fn validate_single_token_transfer(
        &self,
        transition: &RgkTransition,
        new_owner_commitment: RgkOwnerCommitment,
    ) -> Result<RgkNftTransferReport, RgkAssetError> {
        self.validate()?;
        validate_owner_commitment(new_owner_commitment, "new-nft-token")?;
        let token_id = self.token_id()?;
        validate_nft_transition_shape(self, transition, token_id, new_owner_commitment)?;
        let transition_report = transition.validate()?;
        Ok(RgkNftTransferReport {
            token_id,
            token_commitment: self.token_commitment_for_owner(new_owner_commitment)?,
            transition_report,
        })
    }

    pub fn validate_marketplace_sale_transition(
        &self,
        transition: &RgkTransition,
        sale_terms: RgkNftMarketplaceSaleTerms,
    ) -> Result<RgkNftMarketplaceSaleReport, RgkAssetError> {
        self.validate()?;
        let token_id = self.token_id()?;
        validate_nft_marketplace_sale_terms(self, &sale_terms, token_id)?;
        if transition.ownership_authorization_commitment != sale_terms.authorization_commitment {
            return Err(RgkAssetError::NftMarketplaceAuthorizationMismatch);
        }
        let transfer_report =
            self.validate_single_token_transfer(transition, sale_terms.buyer_owner_commitment)?;
        Ok(RgkNftMarketplaceSaleReport {
            token_id,
            sale_commitment: sale_terms.commitment()?,
            token_commitment: transfer_report.token_commitment,
            transition_report: transfer_report.transition_report,
        })
    }

    pub fn validate_token_burn_continuation(
        &self,
        plan: &RgkContinuationPlan,
    ) -> Result<RgkNftBurnContinuationReport, RgkAssetError> {
        self.validate()?;
        let token_id = self.token_id()?;
        validate_nft_burn_continuation_shape(self, plan, token_id)?;
        let continuation_report = plan.validate()?;
        Ok(RgkNftBurnContinuationReport {
            token_id,
            burned_token_commitment: self.token_commitment()?,
            continuation_report,
        })
    }

    pub fn validate_token_burn_transition(
        &self,
        transition: &RgkTransition,
    ) -> Result<RgkNftBurnReport, RgkAssetError> {
        self.validate()?;
        let token_id = self.token_id()?;
        validate_nft_burn_transition_shape(self, transition, token_id)?;
        let transition_report = transition.validate()?;
        Ok(RgkNftBurnReport {
            token_id,
            burned_token_commitment: self.token_commitment()?,
            transition_report,
        })
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum LanePrivacyPolicy {
    PublicLineage,
    #[default]
    PrivateLane,
    StealthLane,
}

impl LanePrivacyPolicy {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::PublicLineage => 0,
            Self::PrivateLane => 1,
            Self::StealthLane => 2,
        }
    }

    pub fn exposes_public_fields(self) -> bool {
        matches!(self, Self::PublicLineage)
    }
}

pub type RgkPrivacyPolicy = LanePrivacyPolicy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageIdPolicy {
    Fixed(Bytes32),
    AllowedSet(Vec<Bytes32>),
    PolicyBranch(Bytes32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RgkProofPolicy {
    VerifierReceipt {
        verifier_key_hash: Bytes32,
    },
    ZkReceipt {
        verifier_key_id: Bytes32,
        image_id_policy: ImageIdPolicy,
    },
    Hybrid {
        verifier_key_hash: Bytes32,
        verifier_key_id: Bytes32,
    },
}

impl RgkProofPolicy {
    pub fn validate(&self) -> Result<(), RgkAssetError> {
        match self {
            Self::VerifierReceipt { verifier_key_hash } => {
                reject_zero(verifier_key_hash, RgkAssetError::ZeroVerifierKey)
            }
            Self::ZkReceipt {
                verifier_key_id,
                image_id_policy,
            } => {
                reject_zero(verifier_key_id, RgkAssetError::ZeroVerifierKey)?;
                match image_id_policy {
                    ImageIdPolicy::Fixed(image_id) => {
                        reject_zero(image_id, RgkAssetError::UnconstrainedImageId)
                    }
                    ImageIdPolicy::AllowedSet(set) => {
                        if set.is_empty() {
                            return Err(RgkAssetError::UnconstrainedImageId);
                        }
                        for image_id in set {
                            reject_zero(image_id, RgkAssetError::UnconstrainedImageId)?;
                        }
                        Ok(())
                    }
                    ImageIdPolicy::PolicyBranch(branch) => {
                        reject_zero(branch, RgkAssetError::UnconstrainedImageId)
                    }
                }
            }
            Self::Hybrid {
                verifier_key_hash,
                verifier_key_id,
            } => {
                reject_zero(verifier_key_hash, RgkAssetError::ZeroVerifierKey)?;
                reject_zero(verifier_key_id, RgkAssetError::ZeroVerifierKey)
            }
        }
    }

    pub fn commitment(&self) -> Result<RgkPolicyCommitment, RgkAssetError> {
        self.validate()?;
        let mut payload = Vec::new();
        encode_proof_policy(&mut payload, self);
        Ok(RgkPolicyCommitment(domain_hash_domain(
            "rgk:asset:policy:v1",
            &payload,
        )))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RgkAllocationProofShape {
    OneInZeroOut,
    OneInOneOut,
    TwoInTwoOut,
    ThreeInTwoOut,
    FourInTwoOut,
    FourInFourOut,
}

pub const RGK_PRODUCTION_ZK_ALLOCATION_SHAPES: [RgkAllocationProofShape; 6] = [
    RgkAllocationProofShape::OneInZeroOut,
    RgkAllocationProofShape::OneInOneOut,
    RgkAllocationProofShape::TwoInTwoOut,
    RgkAllocationProofShape::ThreeInTwoOut,
    RgkAllocationProofShape::FourInTwoOut,
    RgkAllocationProofShape::FourInFourOut,
];
pub const RGK_PRODUCTION_ZK_ALLOCATION_SHAPE_LABELS: &str = "1x0, 1x1, 2x2, 3x2, 4x2, 4x4";
pub const RGK_PRODUCTION_ZK_ALLOCATION_MAX_SPENT: usize = 4;
pub const RGK_PRODUCTION_ZK_ALLOCATION_MAX_NEW: usize = 4;
pub const RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY: usize = 2;

impl RgkAllocationProofShape {
    pub const fn spent_count(self) -> usize {
        match self {
            Self::OneInZeroOut => 1,
            Self::OneInOneOut => 1,
            Self::TwoInTwoOut => 2,
            Self::ThreeInTwoOut => 3,
            Self::FourInTwoOut => 4,
            Self::FourInFourOut => 4,
        }
    }

    pub const fn new_count(self) -> usize {
        match self {
            Self::OneInZeroOut => 0,
            Self::OneInOneOut => 1,
            Self::TwoInTwoOut | Self::ThreeInTwoOut | Self::FourInTwoOut => 2,
            Self::FourInFourOut => 4,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::OneInZeroOut => "1x0",
            Self::OneInOneOut => "1x1",
            Self::TwoInTwoOut => "2x2",
            Self::ThreeInTwoOut => "3x2",
            Self::FourInTwoOut => "4x2",
            Self::FourInFourOut => "4x4",
        }
    }

    pub fn from_counts(spent_count: usize, new_count: usize) -> Option<Self> {
        RGK_PRODUCTION_ZK_ALLOCATION_SHAPES
            .iter()
            .copied()
            .find(|shape| shape.spent_count() == spent_count && shape.new_count() == new_count)
    }

    pub fn require_counts(spent_count: usize, new_count: usize) -> Result<Self, RgkAssetError> {
        Self::from_counts(spent_count, new_count).ok_or(
            RgkAssetError::UnsupportedProductionZkAllocationShape {
                spent_count,
                new_count,
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkLane {
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkLaneState {
    pub lane_id: BlindedLaneId,
    pub epoch: u64,
    pub state_digest: RgkStateDigest,
    pub receipt_commitment: RgkReceiptCommitment,
    pub nullifier: RgkNullifier,
    pub scan_tag: Option<RgkScanTag>,
    pub policy_commitment: RgkPolicyCommitment,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkLaneStateInput<'a> {
    pub lane_id: BlindedLaneId,
    pub epoch: u64,
    pub state_digest: RgkStateDigest,
    pub receipt_commitment: RgkReceiptCommitment,
    pub spend_secret: Bytes32,
    pub seal: &'a RgkCovenantSeal,
    pub view_key: Option<Bytes32>,
    pub policy_commitment: RgkPolicyCommitment,
}

impl RgkLaneState {
    pub fn new(input: RgkLaneStateInput<'_>) -> Self {
        let nullifier = RgkNullifier::derive(input.spend_secret, input.seal);
        let scan_tag = input
            .view_key
            .map(|key| RgkScanTag::derive(key, input.lane_id, input.epoch));
        Self {
            lane_id: input.lane_id,
            epoch: input.epoch,
            state_digest: input.state_digest,
            receipt_commitment: input.receipt_commitment,
            nullifier,
            scan_tag,
            policy_commitment: input.policy_commitment,
        }
    }

    pub fn public_observer_commitment(&self) -> Bytes32 {
        let mut payload = Vec::with_capacity(32 * 5 + 8);
        payload.extend_from_slice(&self.lane_id);
        payload.extend_from_slice(&self.epoch.to_le_bytes());
        payload.extend_from_slice(&self.state_digest.0);
        payload.extend_from_slice(&self.receipt_commitment.0);
        payload.extend_from_slice(&self.nullifier.0);
        payload.extend_from_slice(&self.policy_commitment.0);
        if let Some(tag) = self.scan_tag {
            payload.extend_from_slice(&tag.0);
        }
        domain_hash_domain("rgk:lane:observer-commitment:v1", &payload)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkLaneGraphNode {
    pub lane_id: BlindedLaneId,
    pub scan_tag: RgkScanTag,
    pub epoch: u64,
}

impl RgkLaneGraphNode {
    pub fn from_private(view_key: Bytes32, asset_id: RgkAssetId, epoch: u64) -> Self {
        let lane_id = derive_blinded_lane_id(view_key, asset_id, epoch);
        let scan_tag = RgkScanTag::derive(view_key, lane_id, epoch);
        Self {
            lane_id,
            scan_tag,
            epoch,
        }
    }
}

pub fn derive_private_lane_graph_root(nodes: &[RgkLaneGraphNode]) -> Bytes32 {
    let mut payload = Vec::with_capacity(8 + nodes.len() * (32 + 32 + 8));
    payload.extend_from_slice(&(nodes.len() as u64).to_le_bytes());
    for node in nodes {
        payload.extend_from_slice(&node.lane_id);
        payload.extend_from_slice(&node.scan_tag.0);
        payload.extend_from_slice(&node.epoch.to_le_bytes());
    }
    domain_hash_domain("rgk:lane:graph-root:v1", &payload)
}

pub fn private_lane_graph_empty_root() -> Bytes32 {
    domain_hash_domain("rgk:lane:graph-empty-root:v1", &[])
}

pub fn extend_private_lane_graph_root(
    previous_root: Bytes32,
    segment_index: u64,
    nodes: &[RgkLaneGraphNode],
) -> Bytes32 {
    let mut payload = Vec::with_capacity(32 + 8 + 8 + nodes.len() * (32 + 32 + 8));
    payload.extend_from_slice(&previous_root);
    payload.extend_from_slice(&segment_index.to_le_bytes());
    payload.extend_from_slice(&(nodes.len() as u64).to_le_bytes());
    for node in nodes {
        payload.extend_from_slice(&node.lane_id);
        payload.extend_from_slice(&node.scan_tag.0);
        payload.extend_from_slice(&node.epoch.to_le_bytes());
    }
    domain_hash_domain("rgk:lane:graph-segment-root:v1", &payload)
}

pub fn allocation_transcript_empty_root(side: RgkAllocationTranscriptSide) -> Bytes32 {
    domain_hash_domain(
        "rgk:asset:allocation-transcript-empty-root:v1",
        &[side.as_u8()],
    )
}

pub fn extend_allocation_transcript_root(
    previous_root: Bytes32,
    side: RgkAllocationTranscriptSide,
    segment_index: u64,
    total_count: u64,
    allocations: &[RgkAllocation],
) -> Bytes32 {
    let mut ordered: Vec<&RgkAllocation> = allocations.iter().collect();
    ordered.sort_by_key(|allocation| allocation_key(allocation));

    let mut payload = Vec::with_capacity(57 + ordered.len() * 157);
    payload.extend_from_slice(&previous_root);
    payload.push(side.as_u8());
    payload.extend_from_slice(&segment_index.to_le_bytes());
    payload.extend_from_slice(&total_count.to_le_bytes());
    payload.extend_from_slice(&(ordered.len() as u64).to_le_bytes());
    for allocation in ordered {
        encode_allocation(&mut payload, allocation);
    }
    domain_hash_domain("rgk:asset:allocation-transcript-segment-root:v1", &payload)
}

pub fn allocation_transcript_amount_commitment(
    side: RgkAllocationTranscriptSide,
    segment_index: u64,
    total_count: u64,
    segment_amount: u64,
    amount_blinding: Bytes32,
) -> Bytes32 {
    let mut payload = Vec::with_capacity(57);
    payload.push(side.as_u8());
    payload.extend_from_slice(&segment_index.to_le_bytes());
    payload.extend_from_slice(&total_count.to_le_bytes());
    payload.extend_from_slice(&segment_amount.to_le_bytes());
    payload.extend_from_slice(&amount_blinding);
    domain_hash_domain("rgk:asset:allocation-transcript-amount:v1", &payload)
}

impl RgkScanTag {
    pub fn derive(view_key: Bytes32, lane_id: BlindedLaneId, epoch: u64) -> Self {
        let mut payload = Vec::with_capacity(32 + 32 + 8);
        payload.extend_from_slice(&view_key);
        payload.extend_from_slice(&lane_id);
        payload.extend_from_slice(&epoch.to_le_bytes());
        Self(domain_hash_domain("rgk:lane:scan-tag:v1", &payload))
    }
}

impl RgkNullifier {
    pub fn derive(spend_secret: Bytes32, seal: &RgkCovenantSeal) -> Self {
        let mut payload = Vec::with_capacity(32 + 32 + 4 + 32);
        payload.extend_from_slice(&spend_secret);
        payload.extend_from_slice(&seal.covenant_outpoint.transaction_id);
        payload.extend_from_slice(&seal.covenant_outpoint.index.to_le_bytes());
        payload.extend_from_slice(&seal.covenant_id);
        Self(domain_hash_domain("rgk:lane:nullifier:v1", &payload))
    }
}

pub fn derive_blinded_lane_id(
    view_key: Bytes32,
    asset_id: RgkAssetId,
    epoch: u64,
) -> BlindedLaneId {
    let mut payload = Vec::with_capacity(32 + 32 + 8);
    payload.extend_from_slice(&view_key);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&epoch.to_le_bytes());
    domain_hash_domain("rgk:lane:blinded-id:v1", &payload)
}

pub fn discover_lane(
    view_key: Bytes32,
    asset_id: RgkAssetId,
    epoch: u64,
    candidate: BlindedLaneId,
) -> bool {
    derive_blinded_lane_id(view_key, asset_id, epoch) == candidate
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkCovenantSeal {
    pub chain: KaspaChainId,
    pub covenant_outpoint: KaspaOutpoint,
    pub covenant_id: KaspaCovenantId,
    pub witness_txid: Bytes32,
    pub daa_score: u64,
    pub confirmation_depth: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkAllocation {
    pub seal: RgkCovenantSeal,
    pub amount: u64,
    pub encrypted_note_commitment: Bytes32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkAssetIdDerivation<'a> {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub owner_commitment: RgkOwnerCommitment,
    pub allocations: &'a [RgkAllocation],
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub proof_policy: &'a RgkProofPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkBurnProof {
    pub amount: u64,
    pub authorization_commitment: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkAssetIssue {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub asset_id: RgkAssetId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub owner_commitment: RgkOwnerCommitment,
    pub allocations: Vec<RgkAllocation>,
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub proof_policy: RgkProofPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkTransition {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub asset_id: RgkAssetId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub previous_owner_commitment: RgkOwnerCommitment,
    pub new_owner_commitment: RgkOwnerCommitment,
    pub ownership_authorization_commitment: Bytes32,
    pub previous_state_digest: RgkStateDigest,
    pub spent_allocations: Vec<RgkAllocation>,
    pub new_allocations: Vec<RgkAllocation>,
    pub burn: Option<RgkBurnProof>,
    pub witness_txid: Bytes32,
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub proof_policy: RgkProofPolicy,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkContinuationCommitment(pub Bytes32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RgkContinuationShapeRoot(pub Bytes32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkContinuationAllocationShape {
    pub output_index: u32,
    pub covenant_id: KaspaCovenantId,
    pub amount: u64,
    pub encrypted_note_commitment: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkContinuationPlan {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub asset_id: RgkAssetId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub previous_owner_commitment: RgkOwnerCommitment,
    pub new_owner_commitment: RgkOwnerCommitment,
    pub ownership_authorization_commitment: Bytes32,
    pub previous_state_digest: RgkStateDigest,
    pub spent_allocations: Vec<RgkAllocation>,
    pub new_allocation_shapes: Vec<RgkContinuationAllocationShape>,
    pub burn: Option<RgkBurnProof>,
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub proof_policy: RgkProofPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkIssueReport {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub asset_id: RgkAssetId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub owner_commitment: RgkOwnerCommitment,
    pub allocation_count: usize,
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub policy_commitment: RgkPolicyCommitment,
    pub state_digest: RgkStateDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkTransitionReport {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub asset_id: RgkAssetId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub previous_owner_commitment: RgkOwnerCommitment,
    pub new_owner_commitment: RgkOwnerCommitment,
    pub ownership_authorization_commitment: Bytes32,
    pub spent_supply: u64,
    pub new_supply: u64,
    pub burned_supply: u64,
    pub burn_authorization_commitment: Bytes32,
    pub spent_allocation_count: usize,
    pub new_allocation_count: usize,
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub policy_commitment: RgkPolicyCommitment,
    pub previous_state_digest: RgkStateDigest,
    pub new_state_digest: RgkStateDigest,
    pub transition_digest: RgkTransitionDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkContinuationReport {
    pub chain: KaspaChainId,
    pub schema_id: RgkSchemaId,
    pub asset_id: RgkAssetId,
    pub total_supply: u64,
    pub metadata_commitment: RgkMetadataCommitment,
    pub previous_owner_commitment: RgkOwnerCommitment,
    pub new_owner_commitment: RgkOwnerCommitment,
    pub ownership_authorization_commitment: Bytes32,
    pub spent_supply: u64,
    pub new_supply: u64,
    pub burned_supply: u64,
    pub burn_authorization_commitment: Bytes32,
    pub spent_allocation_count: usize,
    pub new_allocation_count: usize,
    pub lane_id: BlindedLaneId,
    pub privacy_policy: LanePrivacyPolicy,
    pub policy_commitment: RgkPolicyCommitment,
    pub previous_state_digest: RgkStateDigest,
    pub shape_root: RgkContinuationShapeRoot,
    pub commitment: RgkContinuationCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkFinalizedContinuation {
    pub commitment: RgkContinuationCommitment,
    pub transition: RgkTransition,
    pub transition_report: RgkTransitionReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkProductionZkTransferPlan {
    continuation_plan: RgkContinuationPlan,
    continuation_report: RgkContinuationReport,
    allocation_shape: RgkAllocationProofShape,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkFinalizedProductionZkTransfer {
    finalized_continuation: RgkFinalizedContinuation,
    allocation_shape: RgkAllocationProofShape,
}

pub type RgkProductionAllocationStrategyCommitment = Bytes32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RgkProductionAllocationStrategy {
    FixedAllocationVector {
        shape: RgkAllocationProofShape,
    },
    SegmentedAllocationAudit {
        segment_capacity: usize,
        spent_segments: usize,
        new_segments: usize,
        exclusion_cells: usize,
        groth16_proof_cells: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkProductionAllocationStrategyPlan {
    continuation_plan: RgkContinuationPlan,
    continuation_report: RgkContinuationReport,
    strategy: RgkProductionAllocationStrategy,
    strategy_commitment: RgkProductionAllocationStrategyCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RgkFinalizedProductionAllocationStrategyTransfer {
    finalized_continuation: RgkFinalizedContinuation,
    strategy: RgkProductionAllocationStrategy,
    strategy_commitment: RgkProductionAllocationStrategyCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RgkAssetError {
    #[error("RGK asset schema id is zero")]
    ZeroSchemaId,
    #[error("RGK asset id is zero")]
    ZeroAssetId,
    #[error("RGK total supply is zero")]
    ZeroTotalSupply,
    #[error("RGK metadata commitment is zero")]
    ZeroMetadataCommitment,
    #[error("RGK {role} owner commitment is zero")]
    ZeroOwnerCommitment { role: &'static str },
    #[error("RGK {kind} owner descriptor is zero")]
    ZeroOwnerDescriptor { kind: &'static str },
    #[error("RGK NFT collection id is zero")]
    ZeroNftCollectionId,
    #[error("RGK NFT token id is zero")]
    ZeroNftTokenId,
    #[error("RGK NFT template commitment is zero")]
    ZeroNftTemplateCommitment,
    #[error("RGK NFT policy commitment is zero")]
    ZeroNftPolicyCommitment,
    #[error("RGK NFT marketplace payment asset id is zero")]
    ZeroNftMarketplacePaymentAsset,
    #[error("RGK NFT marketplace price is zero")]
    ZeroNftMarketplacePrice,
    #[error("RGK NFT marketplace royalty {royalty} exceeds price {price}")]
    NftMarketplaceRoyaltyExceedsPrice { royalty: u64, price: u64 },
    #[error("RGK NFT marketplace collection mismatch")]
    NftMarketplaceCollectionMismatch,
    #[error("RGK NFT marketplace token mismatch")]
    NftMarketplaceTokenMismatch,
    #[error("RGK NFT marketplace royalty policy mismatch")]
    NftMarketplaceRoyaltyPolicyMismatch,
    #[error("RGK NFT marketplace seller and buyer are the same owner commitment")]
    NftMarketplaceSelfSale,
    #[error("RGK NFT marketplace authorization commitment does not match transition")]
    NftMarketplaceAuthorizationMismatch,
    #[error("RGK NFT token index {token_index} is outside fixed collection supply {max_supply}")]
    NftTokenIndexOutOfRange { token_index: u64, max_supply: u64 },
    #[error("RGK NFT chain mismatch: expected {expected:?}, got {actual:?}")]
    NftChainMismatch {
        expected: KaspaChainId,
        actual: KaspaChainId,
    },
    #[error("RGK NFT schema id mismatch")]
    NftSchemaMismatch,
    #[error("RGK NFT token asset id mismatch")]
    NftAssetMismatch,
    #[error("RGK NFT total supply {actual} does not equal {expected}")]
    NftSupplyMismatch { expected: u64, actual: u64 },
    #[error("RGK NFT {role} allocation count {count} does not equal 1")]
    NftAllocationShapeMismatch { role: &'static str, count: usize },
    #[error("RGK NFT {role} allocation amount {actual} does not equal {expected}")]
    NftAllocationAmountMismatch {
        role: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("RGK NFT metadata commitment mismatch")]
    NftMetadataMismatch,
    #[error("RGK NFT {role} owner commitment mismatch")]
    NftOwnerMismatch { role: &'static str },
    #[error("RGK NFT single-token transfer unexpectedly carried a burn proof")]
    NftUnexpectedBurn,
    #[error("RGK ownership handoff authorization commitment is zero")]
    ZeroOwnershipAuthorization,
    #[error("RGK allocation set is empty")]
    EmptyAllocations,
    #[error("RGK allocation {index} has zero amount")]
    ZeroAllocationAmount { index: usize },
    #[error("RGK allocation {index} is on {actual:?}, expected {expected:?}")]
    ChainMismatch {
        index: usize,
        expected: KaspaChainId,
        actual: KaspaChainId,
    },
    #[error("RGK allocation {index} has a null covenant outpoint")]
    NullCovenantOutpoint { index: usize },
    #[error("RGK allocation {index} has zero covenant id")]
    ZeroCovenantId { index: usize },
    #[error("RGK allocation {index} has zero witness txid")]
    ZeroWitnessTxid { index: usize },
    #[error("RGK allocation {index} has zero encrypted note commitment")]
    ZeroEncryptedNote { index: usize },
    #[error("RGK allocation {index} is not confirmed")]
    UnconfirmedSeal { index: usize },
    #[error("RGK allocation {index} reuses covenant outpoint")]
    DuplicateSealOutpoint { index: usize },
    #[error("RGK allocation supply overflow")]
    SupplyOverflow,
    #[error("RGK allocation sum {actual} does not equal total supply {expected}")]
    SupplyMismatch { expected: u64, actual: u64 },
    #[error("RGK transition inflates supply: spent {spent}, new {new}")]
    SupplyInflation { spent: u64, new: u64 },
    #[error("RGK transition deflates supply without burn proof: spent {spent}, new {new}")]
    SupplyDeflationWithoutBurn { spent: u64, new: u64 },
    #[error("RGK burn proof has zero amount")]
    ZeroBurnAmount,
    #[error("RGK burn proof has zero authorization commitment")]
    ZeroBurnAuthorization,
    #[error("RGK burn proof amount {actual} does not match burned supply {expected}")]
    BurnAmountMismatch { expected: u64, actual: u64 },
    #[error("RGK state digest mismatch: expected 0x{expected}, got 0x{actual}")]
    DigestMismatch { expected: Hex32, actual: Hex32 },
    #[error("RGK previous state digest is zero")]
    ZeroPreviousStateDigest,
    #[error("RGK transition witness txid is zero")]
    ZeroTransitionWitnessTxid,
    #[error("RGK transition does not change state")]
    NoOpTransition,
    #[error("RGK transition new allocation {index} reuses a closed seal")]
    ReusedClosedSeal { index: usize },
    #[error("RGK previous state digest mismatch: expected 0x{expected}, got 0x{actual}")]
    PreviousStateDigestMismatch { expected: Hex32, actual: Hex32 },
    #[error("RGK transition digest mismatch: expected 0x{expected}, got 0x{actual}")]
    TransitionDigestMismatch { expected: Hex32, actual: Hex32 },
    #[error("RGK lane id is zero")]
    ZeroLaneId,
    #[error("RGK verifier key is zero")]
    ZeroVerifierKey,
    #[error("RGK image id policy is unconstrained")]
    UnconstrainedImageId,
    #[error("RGK continuation shape is empty")]
    EmptyContinuationShape,
    #[error("RGK continuation shape {index} has zero amount")]
    ZeroContinuationAmount { index: usize },
    #[error("RGK continuation shape {index} has zero covenant id")]
    ZeroContinuationCovenantId { index: usize },
    #[error("RGK continuation shape {index} has zero encrypted note commitment")]
    ZeroContinuationEncryptedNote { index: usize },
    #[error("RGK continuation shape {index} reuses output index")]
    DuplicateContinuationOutput { index: usize },
    #[error("RGK continuation commitment mismatch: expected 0x{expected}, got 0x{actual}")]
    ContinuationCommitmentMismatch { expected: Hex32, actual: Hex32 },
    #[error("RGK production ZK allocation proof shape {spent_count}x{new_count} is unsupported; supported shapes are 1x0, 1x1, 2x2, 3x2, 4x2, 4x4")]
    UnsupportedProductionZkAllocationShape {
        spent_count: usize,
        new_count: usize,
    },
    #[error("RGK production ZK {role} allocation count {count} exceeds maximum {max}")]
    ProductionZkAllocationBoundExceeded {
        role: &'static str,
        count: usize,
        max: usize,
    },
    #[error(
        "RGK segmented allocation audit strategy requires a conserving transfer, got burned supply {burned_supply}"
    )]
    SegmentedAllocationAuditRequiresConservation { burned_supply: u64 },
    #[error("RGK segmented allocation audit strategy has empty {role} allocation side")]
    SegmentedAllocationAuditEmptySide { role: &'static str },
    #[error(
        "RGK segmented allocation audit strategy has invalid segment capacity {segment_capacity}"
    )]
    SegmentedAllocationAuditInvalidSegmentCapacity { segment_capacity: usize },
    #[error("RGK segmented allocation audit proof grid is too large")]
    SegmentedAllocationAuditGridTooLarge,
}

impl RgkAssetIssue {
    pub fn derive_asset_id(input: RgkAssetIdDerivation<'_>) -> Result<RgkAssetId, RgkAssetError> {
        validate_metadata_commitment(input.metadata_commitment)?;
        validate_owner_commitment(input.owner_commitment, "issue")?;
        let policy = input.proof_policy.commitment()?;
        let root = allocation_root(input.allocations);
        let mut payload = Vec::with_capacity(1 + 32 + 8 + 32 + 32 + 32 + 1 + 32 + 32);
        payload.push(input.chain as u8);
        payload.extend_from_slice(&input.schema_id);
        payload.extend_from_slice(&input.total_supply.to_le_bytes());
        payload.extend_from_slice(&input.metadata_commitment.0);
        payload.extend_from_slice(&input.owner_commitment.0);
        payload.extend_from_slice(&root);
        payload.push(input.privacy_policy.as_u8());
        payload.extend_from_slice(&input.lane_id);
        payload.extend_from_slice(&policy.0);
        Ok(domain_hash_domain("rgk:asset:id:v2", &payload))
    }

    pub fn validate(&self) -> Result<RgkIssueReport, RgkAssetError> {
        self.validate_structure()?;
        self.report_unchecked()
    }

    pub fn validate_for_production_zk(&self) -> Result<RgkIssueReport, RgkAssetError> {
        self.validate_structure()?;
        validate_production_zk_issue_count(self.allocations.len())?;
        self.report_unchecked()
    }

    pub fn validate_against_state_digest(
        &self,
        expected: RgkStateDigest,
    ) -> Result<RgkIssueReport, RgkAssetError> {
        let report = self.validate()?;
        if report.state_digest != expected {
            return Err(RgkAssetError::DigestMismatch {
                expected: expected.0.into(),
                actual: report.state_digest.0.into(),
            });
        }
        Ok(report)
    }

    pub fn validate_against_state_digest_for_production_zk(
        &self,
        expected: RgkStateDigest,
    ) -> Result<RgkIssueReport, RgkAssetError> {
        let report = self.validate_for_production_zk()?;
        if report.state_digest != expected {
            return Err(RgkAssetError::DigestMismatch {
                expected: expected.0.into(),
                actual: report.state_digest.0.into(),
            });
        }
        Ok(report)
    }

    fn validate_structure(&self) -> Result<(), RgkAssetError> {
        validate_common(
            self.schema_id,
            self.asset_id,
            self.total_supply,
            self.lane_id,
            &self.proof_policy,
        )?;
        validate_metadata_commitment(self.metadata_commitment)?;
        validate_owner_commitment(self.owner_commitment, "issue")?;
        validate_allocation_set_exact(self.chain, self.total_supply, &self.allocations)
    }

    fn report_unchecked(&self) -> Result<RgkIssueReport, RgkAssetError> {
        let policy_commitment = self.proof_policy.commitment()?;
        Ok(RgkIssueReport {
            chain: self.chain,
            schema_id: self.schema_id,
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            metadata_commitment: self.metadata_commitment,
            owner_commitment: self.owner_commitment,
            allocation_count: self.allocations.len(),
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            state_digest: RgkStateDigest(state_digest_for_allocations(RgkStateDigestInput {
                asset_id: self.asset_id,
                total_supply: self.total_supply,
                allocations: &self.allocations,
                lane_id: self.lane_id,
                privacy_policy: self.privacy_policy,
                policy_commitment,
                metadata_commitment: self.metadata_commitment,
                owner_commitment: self.owner_commitment,
            })),
        })
    }
}

impl RgkTransition {
    pub fn validate(&self) -> Result<RgkTransitionReport, RgkAssetError> {
        self.validate_structure()?;
        self.report_unchecked()
    }

    pub fn validate_for_production_zk(&self) -> Result<RgkTransitionReport, RgkAssetError> {
        self.validate_structure()?;
        RgkAllocationProofShape::require_counts(
            self.spent_allocations.len(),
            self.new_allocations.len(),
        )?;
        self.report_unchecked()
    }

    pub fn validate_against_transition_digest(
        &self,
        expected: RgkTransitionDigest,
    ) -> Result<RgkTransitionReport, RgkAssetError> {
        let report = self.validate()?;
        if report.transition_digest != expected {
            return Err(RgkAssetError::TransitionDigestMismatch {
                expected: expected.0.into(),
                actual: report.transition_digest.0.into(),
            });
        }
        Ok(report)
    }

    pub fn validate_against_transition_digest_for_production_zk(
        &self,
        expected: RgkTransitionDigest,
    ) -> Result<RgkTransitionReport, RgkAssetError> {
        let report = self.validate_for_production_zk()?;
        if report.transition_digest != expected {
            return Err(RgkAssetError::TransitionDigestMismatch {
                expected: expected.0.into(),
                actual: report.transition_digest.0.into(),
            });
        }
        Ok(report)
    }

    fn validate_structure(&self) -> Result<(), RgkAssetError> {
        validate_common(
            self.schema_id,
            self.asset_id,
            self.total_supply,
            self.lane_id,
            &self.proof_policy,
        )?;
        validate_metadata_commitment(self.metadata_commitment)?;
        validate_owner_commitment(self.previous_owner_commitment, "previous")?;
        validate_owner_commitment(self.new_owner_commitment, "new")?;
        validate_ownership_handoff(
            self.previous_owner_commitment,
            self.new_owner_commitment,
            self.ownership_authorization_commitment,
        )?;
        if is_zero32(&self.previous_state_digest.0) {
            return Err(RgkAssetError::ZeroPreviousStateDigest);
        }
        if is_zero32(&self.witness_txid) {
            return Err(RgkAssetError::ZeroTransitionWitnessTxid);
        }
        if self.spent_allocations.is_empty() {
            return Err(RgkAssetError::EmptyAllocations);
        }

        let spent_supply = validate_allocation_set_structure(self.chain, &self.spent_allocations)?;
        let new_supply =
            validate_allocation_set_structure_allow_empty(self.chain, &self.new_allocations)?;
        validate_supply_delta(spent_supply, new_supply, self.burn.as_ref())?;

        let policy_commitment = self.proof_policy.commitment()?;
        let computed_previous = RgkStateDigest(state_digest_for_allocations(RgkStateDigestInput {
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            allocations: &self.spent_allocations,
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            metadata_commitment: self.metadata_commitment,
            owner_commitment: self.previous_owner_commitment,
        }));
        if computed_previous != self.previous_state_digest {
            return Err(RgkAssetError::PreviousStateDigestMismatch {
                expected: self.previous_state_digest.0.into(),
                actual: computed_previous.0.into(),
            });
        }

        let new_state_digest = RgkStateDigest(state_digest_for_allocations(RgkStateDigestInput {
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            allocations: &self.new_allocations,
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            metadata_commitment: self.metadata_commitment,
            owner_commitment: self.new_owner_commitment,
        }));
        if new_state_digest == self.previous_state_digest {
            return Err(RgkAssetError::NoOpTransition);
        }

        let closed: BTreeSet<KaspaOutpoint> = self
            .spent_allocations
            .iter()
            .map(|allocation| allocation.seal.covenant_outpoint)
            .collect();
        for (index, allocation) in self.new_allocations.iter().enumerate() {
            if closed.contains(&allocation.seal.covenant_outpoint) {
                return Err(RgkAssetError::ReusedClosedSeal { index });
            }
        }

        Ok(())
    }

    fn report_unchecked(&self) -> Result<RgkTransitionReport, RgkAssetError> {
        let spent_supply = validate_allocation_set_structure(self.chain, &self.spent_allocations)?;
        let new_supply =
            validate_allocation_set_structure_allow_empty(self.chain, &self.new_allocations)?;
        let burned_supply = validate_supply_delta(spent_supply, new_supply, self.burn.as_ref())?;
        let policy_commitment = self.proof_policy.commitment()?;
        let new_state_digest = RgkStateDigest(state_digest_for_allocations(RgkStateDigestInput {
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            allocations: &self.new_allocations,
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            metadata_commitment: self.metadata_commitment,
            owner_commitment: self.new_owner_commitment,
        }));
        let transition_digest = RgkTransitionDigest(
            self.transition_digest_unchecked(new_state_digest, policy_commitment),
        );
        Ok(RgkTransitionReport {
            chain: self.chain,
            schema_id: self.schema_id,
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            metadata_commitment: self.metadata_commitment,
            previous_owner_commitment: self.previous_owner_commitment,
            new_owner_commitment: self.new_owner_commitment,
            ownership_authorization_commitment: self.ownership_authorization_commitment,
            spent_supply,
            new_supply,
            burned_supply,
            burn_authorization_commitment: burn_authorization_commitment(self.burn.as_ref()),
            spent_allocation_count: self.spent_allocations.len(),
            new_allocation_count: self.new_allocations.len(),
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            previous_state_digest: self.previous_state_digest,
            new_state_digest,
            transition_digest,
        })
    }

    fn transition_digest_unchecked(
        &self,
        new_state_digest: RgkStateDigest,
        policy_commitment: RgkPolicyCommitment,
    ) -> Bytes32 {
        let mut payload =
            Vec::with_capacity(1 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 1 + 32 + 128 + 8);
        payload.push(self.chain as u8);
        payload.extend_from_slice(&self.schema_id);
        payload.extend_from_slice(&self.asset_id);
        payload.extend_from_slice(&self.total_supply.to_le_bytes());
        payload.extend_from_slice(&self.previous_state_digest.0);
        payload.extend_from_slice(&new_state_digest.0);
        payload.extend_from_slice(&self.witness_txid);
        encode_burn_proof(&mut payload, self.burn.as_ref());
        payload.extend_from_slice(&self.lane_id);
        payload.push(self.privacy_policy.as_u8());
        payload.extend_from_slice(&policy_commitment.0);
        payload.extend_from_slice(&self.metadata_commitment.0);
        payload.extend_from_slice(&self.previous_owner_commitment.0);
        payload.extend_from_slice(&self.new_owner_commitment.0);
        payload.extend_from_slice(&self.ownership_authorization_commitment);
        payload.extend_from_slice(&(self.spent_allocations.len() as u32).to_le_bytes());
        for allocation in &self.spent_allocations {
            payload.push(b'i');
            encode_allocation(&mut payload, allocation);
        }
        payload.extend_from_slice(&(self.new_allocations.len() as u32).to_le_bytes());
        for allocation in &self.new_allocations {
            payload.push(b'o');
            encode_allocation(&mut payload, allocation);
        }
        domain_hash_domain("rgk:asset:transition:v2", &payload)
    }
}

impl RgkContinuationPlan {
    pub fn validate(&self) -> Result<RgkContinuationReport, RgkAssetError> {
        self.validate_structure()?;
        self.report_unchecked()
    }

    pub fn validate_for_production_zk(&self) -> Result<RgkContinuationReport, RgkAssetError> {
        self.validate_structure()?;
        RgkAllocationProofShape::require_counts(
            self.spent_allocations.len(),
            self.new_allocation_shapes.len(),
        )?;
        self.report_unchecked()
    }

    pub fn into_production_zk_transfer_plan(
        self,
    ) -> Result<RgkProductionZkTransferPlan, RgkAssetError> {
        RgkProductionZkTransferPlan::new(self)
    }

    pub fn validate_against_commitment(
        &self,
        expected: RgkContinuationCommitment,
    ) -> Result<RgkContinuationReport, RgkAssetError> {
        let report = self.validate()?;
        if report.commitment != expected {
            return Err(RgkAssetError::ContinuationCommitmentMismatch {
                expected: expected.0.into(),
                actual: report.commitment.0.into(),
            });
        }
        Ok(report)
    }

    pub fn validate_against_commitment_for_production_zk(
        &self,
        expected: RgkContinuationCommitment,
    ) -> Result<RgkContinuationReport, RgkAssetError> {
        let report = self.validate_for_production_zk()?;
        if report.commitment != expected {
            return Err(RgkAssetError::ContinuationCommitmentMismatch {
                expected: expected.0.into(),
                actual: report.commitment.0.into(),
            });
        }
        Ok(report)
    }

    pub fn finalize(
        &self,
        witness_txid: Bytes32,
        daa_score: u64,
        confirmation_depth: u64,
    ) -> Result<RgkFinalizedContinuation, RgkAssetError> {
        let continuation_report = self.validate()?;
        let new_allocations = self
            .new_allocation_shapes
            .iter()
            .map(|shape| RgkAllocation {
                seal: RgkCovenantSeal {
                    chain: self.chain,
                    covenant_outpoint: KaspaOutpoint {
                        transaction_id: witness_txid,
                        index: shape.output_index,
                    },
                    covenant_id: shape.covenant_id,
                    witness_txid,
                    daa_score,
                    confirmation_depth,
                },
                amount: shape.amount,
                encrypted_note_commitment: shape.encrypted_note_commitment,
            })
            .collect();
        let transition = RgkTransition {
            chain: self.chain,
            schema_id: self.schema_id,
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            metadata_commitment: self.metadata_commitment,
            previous_owner_commitment: self.previous_owner_commitment,
            new_owner_commitment: self.new_owner_commitment,
            ownership_authorization_commitment: self.ownership_authorization_commitment,
            previous_state_digest: self.previous_state_digest,
            spent_allocations: self.spent_allocations.clone(),
            new_allocations,
            burn: self.burn.clone(),
            witness_txid,
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            proof_policy: self.proof_policy.clone(),
        };
        let transition_report = transition.validate()?;
        Ok(RgkFinalizedContinuation {
            commitment: continuation_report.commitment,
            transition,
            transition_report,
        })
    }

    pub fn finalize_for_production_zk(
        &self,
        witness_txid: Bytes32,
        daa_score: u64,
        confirmation_depth: u64,
    ) -> Result<RgkFinalizedContinuation, RgkAssetError> {
        self.validate_for_production_zk()?;
        let finalized = self.finalize(witness_txid, daa_score, confirmation_depth)?;
        RgkAllocationProofShape::require_counts(
            finalized.transition.spent_allocations.len(),
            finalized.transition.new_allocations.len(),
        )?;
        Ok(finalized)
    }

    fn validate_structure(&self) -> Result<(), RgkAssetError> {
        validate_common(
            self.schema_id,
            self.asset_id,
            self.total_supply,
            self.lane_id,
            &self.proof_policy,
        )?;
        validate_metadata_commitment(self.metadata_commitment)?;
        validate_owner_commitment(self.previous_owner_commitment, "previous")?;
        validate_owner_commitment(self.new_owner_commitment, "new")?;
        validate_ownership_handoff(
            self.previous_owner_commitment,
            self.new_owner_commitment,
            self.ownership_authorization_commitment,
        )?;
        if is_zero32(&self.previous_state_digest.0) {
            return Err(RgkAssetError::ZeroPreviousStateDigest);
        }
        if self.spent_allocations.is_empty() {
            return Err(RgkAssetError::EmptyAllocations);
        }
        let spent_supply = validate_allocation_set_structure(self.chain, &self.spent_allocations)?;

        let policy_commitment = self.proof_policy.commitment()?;
        let computed_previous = RgkStateDigest(state_digest_for_allocations(RgkStateDigestInput {
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            allocations: &self.spent_allocations,
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            metadata_commitment: self.metadata_commitment,
            owner_commitment: self.previous_owner_commitment,
        }));
        if computed_previous != self.previous_state_digest {
            return Err(RgkAssetError::PreviousStateDigestMismatch {
                expected: self.previous_state_digest.0.into(),
                actual: computed_previous.0.into(),
            });
        }

        let new_supply = validate_continuation_shapes_structure_allow_empty(
            &self.new_allocation_shapes,
            self.burn.as_ref(),
        )?;
        validate_supply_delta(spent_supply, new_supply, self.burn.as_ref())?;
        Ok(())
    }

    fn report_unchecked(&self) -> Result<RgkContinuationReport, RgkAssetError> {
        let spent_supply = validate_allocation_set_structure(self.chain, &self.spent_allocations)?;
        let new_supply = validate_continuation_shapes_structure_allow_empty(
            &self.new_allocation_shapes,
            self.burn.as_ref(),
        )?;
        let burned_supply = validate_supply_delta(spent_supply, new_supply, self.burn.as_ref())?;
        let policy_commitment = self.proof_policy.commitment()?;
        let shape_root = RgkContinuationShapeRoot(continuation_shape_root(
            self.chain,
            &self.new_allocation_shapes,
        ));
        let commitment =
            RgkContinuationCommitment(self.commitment_unchecked(policy_commitment, shape_root));
        Ok(RgkContinuationReport {
            chain: self.chain,
            schema_id: self.schema_id,
            asset_id: self.asset_id,
            total_supply: self.total_supply,
            metadata_commitment: self.metadata_commitment,
            previous_owner_commitment: self.previous_owner_commitment,
            new_owner_commitment: self.new_owner_commitment,
            ownership_authorization_commitment: self.ownership_authorization_commitment,
            spent_supply,
            new_supply,
            burned_supply,
            burn_authorization_commitment: burn_authorization_commitment(self.burn.as_ref()),
            spent_allocation_count: self.spent_allocations.len(),
            new_allocation_count: self.new_allocation_shapes.len(),
            lane_id: self.lane_id,
            privacy_policy: self.privacy_policy,
            policy_commitment,
            previous_state_digest: self.previous_state_digest,
            shape_root,
            commitment,
        })
    }

    fn commitment_unchecked(
        &self,
        policy_commitment: RgkPolicyCommitment,
        shape_root: RgkContinuationShapeRoot,
    ) -> Bytes32 {
        let spent_root = allocation_root(&self.spent_allocations);
        let mut payload = Vec::with_capacity(1 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 1 + 32 + 128);
        payload.push(self.chain as u8);
        payload.extend_from_slice(&self.schema_id);
        payload.extend_from_slice(&self.asset_id);
        payload.extend_from_slice(&self.total_supply.to_le_bytes());
        payload.extend_from_slice(&self.previous_state_digest.0);
        payload.extend_from_slice(&spent_root);
        payload.extend_from_slice(&shape_root.0);
        encode_burn_proof(&mut payload, self.burn.as_ref());
        payload.extend_from_slice(&self.lane_id);
        payload.push(self.privacy_policy.as_u8());
        payload.extend_from_slice(&policy_commitment.0);
        payload.extend_from_slice(&self.metadata_commitment.0);
        payload.extend_from_slice(&self.previous_owner_commitment.0);
        payload.extend_from_slice(&self.new_owner_commitment.0);
        payload.extend_from_slice(&self.ownership_authorization_commitment);
        domain_hash_domain("rgk:continuation:phase1:v2", &payload)
    }
}

impl RgkProductionZkTransferPlan {
    pub fn new(continuation_plan: RgkContinuationPlan) -> Result<Self, RgkAssetError> {
        let continuation_report = continuation_plan.validate_for_production_zk()?;
        let allocation_shape = RgkAllocationProofShape::require_counts(
            continuation_report.spent_allocation_count,
            continuation_report.new_allocation_count,
        )?;
        Ok(Self {
            continuation_plan,
            continuation_report,
            allocation_shape,
        })
    }

    pub fn continuation_plan(&self) -> &RgkContinuationPlan {
        &self.continuation_plan
    }

    pub fn continuation_report(&self) -> &RgkContinuationReport {
        &self.continuation_report
    }

    pub const fn allocation_shape(&self) -> RgkAllocationProofShape {
        self.allocation_shape
    }

    pub fn into_continuation_plan(self) -> RgkContinuationPlan {
        self.continuation_plan
    }

    pub fn finalize(
        &self,
        witness_txid: Bytes32,
        daa_score: u64,
        confirmation_depth: u64,
    ) -> Result<RgkFinalizedProductionZkTransfer, RgkAssetError> {
        let finalized_continuation = self.continuation_plan.finalize_for_production_zk(
            witness_txid,
            daa_score,
            confirmation_depth,
        )?;
        let allocation_shape = RgkAllocationProofShape::require_counts(
            finalized_continuation
                .transition_report
                .spent_allocation_count,
            finalized_continuation
                .transition_report
                .new_allocation_count,
        )?;
        Ok(RgkFinalizedProductionZkTransfer {
            finalized_continuation,
            allocation_shape,
        })
    }
}

impl TryFrom<RgkContinuationPlan> for RgkProductionZkTransferPlan {
    type Error = RgkAssetError;

    fn try_from(value: RgkContinuationPlan) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl RgkFinalizedProductionZkTransfer {
    pub fn finalized_continuation(&self) -> &RgkFinalizedContinuation {
        &self.finalized_continuation
    }

    pub fn transition(&self) -> &RgkTransition {
        &self.finalized_continuation.transition
    }

    pub fn transition_report(&self) -> &RgkTransitionReport {
        &self.finalized_continuation.transition_report
    }

    pub const fn allocation_shape(&self) -> RgkAllocationProofShape {
        self.allocation_shape
    }

    pub fn into_finalized_continuation(self) -> RgkFinalizedContinuation {
        self.finalized_continuation
    }
}

impl RgkProductionAllocationStrategy {
    pub fn for_continuation_report(report: &RgkContinuationReport) -> Result<Self, RgkAssetError> {
        if let Some(shape) = RgkAllocationProofShape::from_counts(
            report.spent_allocation_count,
            report.new_allocation_count,
        ) {
            return Ok(Self::FixedAllocationVector { shape });
        }
        Self::segmented_audit_for_report(report, RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY)
    }

    pub fn segmented_audit_for_report(
        report: &RgkContinuationReport,
        segment_capacity: usize,
    ) -> Result<Self, RgkAssetError> {
        if segment_capacity == 0 {
            return Err(
                RgkAssetError::SegmentedAllocationAuditInvalidSegmentCapacity { segment_capacity },
            );
        }
        if report.burned_supply != 0 {
            return Err(
                RgkAssetError::SegmentedAllocationAuditRequiresConservation {
                    burned_supply: report.burned_supply,
                },
            );
        }
        if report.spent_allocation_count == 0 {
            return Err(RgkAssetError::SegmentedAllocationAuditEmptySide { role: "spent" });
        }
        if report.new_allocation_count == 0 {
            return Err(RgkAssetError::SegmentedAllocationAuditEmptySide { role: "new" });
        }
        let spent_segments = report.spent_allocation_count.div_ceil(segment_capacity);
        let new_segments = report.new_allocation_count.div_ceil(segment_capacity);
        let exclusion_cells = spent_segments
            .checked_mul(new_segments)
            .ok_or(RgkAssetError::SegmentedAllocationAuditGridTooLarge)?;
        let transcript_and_conservation_cells = spent_segments
            .checked_add(new_segments)
            .and_then(|segments| segments.checked_mul(2))
            .ok_or(RgkAssetError::SegmentedAllocationAuditGridTooLarge)?;
        let groth16_proof_cells = transcript_and_conservation_cells
            .checked_add(1)
            .and_then(|cells| cells.checked_add(exclusion_cells))
            .ok_or(RgkAssetError::SegmentedAllocationAuditGridTooLarge)?;
        Ok(Self::SegmentedAllocationAudit {
            segment_capacity,
            spent_segments,
            new_segments,
            exclusion_cells,
            groth16_proof_cells,
        })
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::FixedAllocationVector { .. } => "fixed-allocation-vector",
            Self::SegmentedAllocationAudit { .. } => "segmented-allocation-audit",
        }
    }

    pub const fn requires_allocation_audit_certificate(self) -> bool {
        matches!(self, Self::SegmentedAllocationAudit { .. })
    }

    pub const fn fixed_shape(self) -> Option<RgkAllocationProofShape> {
        match self {
            Self::FixedAllocationVector { shape } => Some(shape),
            Self::SegmentedAllocationAudit { .. } => None,
        }
    }

    pub const fn groth16_proof_cells(self) -> usize {
        match self {
            Self::FixedAllocationVector { .. } => 1,
            Self::SegmentedAllocationAudit {
                groth16_proof_cells,
                ..
            } => groth16_proof_cells,
        }
    }
}

impl RgkProductionAllocationStrategyPlan {
    pub fn new(continuation_plan: RgkContinuationPlan) -> Result<Self, RgkAssetError> {
        let continuation_report = continuation_plan.validate()?;
        let strategy =
            RgkProductionAllocationStrategy::for_continuation_report(&continuation_report)?;
        let strategy_commitment =
            production_allocation_strategy_commitment(&continuation_report, strategy);
        Ok(Self {
            continuation_plan,
            continuation_report,
            strategy,
            strategy_commitment,
        })
    }

    pub fn continuation_plan(&self) -> &RgkContinuationPlan {
        &self.continuation_plan
    }

    pub fn continuation_report(&self) -> &RgkContinuationReport {
        &self.continuation_report
    }

    pub const fn strategy(&self) -> RgkProductionAllocationStrategy {
        self.strategy
    }

    pub const fn strategy_commitment(&self) -> RgkProductionAllocationStrategyCommitment {
        self.strategy_commitment
    }

    pub fn into_continuation_plan(self) -> RgkContinuationPlan {
        self.continuation_plan
    }

    pub fn finalize(
        &self,
        witness_txid: Bytes32,
        daa_score: u64,
        confirmation_depth: u64,
    ) -> Result<RgkFinalizedProductionAllocationStrategyTransfer, RgkAssetError> {
        let finalized_continuation =
            self.continuation_plan
                .finalize(witness_txid, daa_score, confirmation_depth)?;
        let finalized_strategy =
            RgkProductionAllocationStrategy::for_continuation_report(&self.continuation_report)?;
        if finalized_strategy != self.strategy {
            return Err(RgkAssetError::UnsupportedProductionZkAllocationShape {
                spent_count: finalized_continuation
                    .transition_report
                    .spent_allocation_count,
                new_count: finalized_continuation
                    .transition_report
                    .new_allocation_count,
            });
        }
        Ok(RgkFinalizedProductionAllocationStrategyTransfer {
            finalized_continuation,
            strategy: self.strategy,
            strategy_commitment: self.strategy_commitment,
        })
    }
}

impl TryFrom<RgkContinuationPlan> for RgkProductionAllocationStrategyPlan {
    type Error = RgkAssetError;

    fn try_from(value: RgkContinuationPlan) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl RgkFinalizedProductionAllocationStrategyTransfer {
    pub fn finalized_continuation(&self) -> &RgkFinalizedContinuation {
        &self.finalized_continuation
    }

    pub fn transition(&self) -> &RgkTransition {
        &self.finalized_continuation.transition
    }

    pub fn transition_report(&self) -> &RgkTransitionReport {
        &self.finalized_continuation.transition_report
    }

    pub const fn strategy(&self) -> RgkProductionAllocationStrategy {
        self.strategy
    }

    pub const fn strategy_commitment(&self) -> RgkProductionAllocationStrategyCommitment {
        self.strategy_commitment
    }

    pub fn into_finalized_continuation(self) -> RgkFinalizedContinuation {
        self.finalized_continuation
    }
}

fn validate_common(
    schema_id: RgkSchemaId,
    asset_id: RgkAssetId,
    total_supply: u64,
    lane_id: BlindedLaneId,
    proof_policy: &RgkProofPolicy,
) -> Result<(), RgkAssetError> {
    if is_zero32(&schema_id) {
        return Err(RgkAssetError::ZeroSchemaId);
    }
    if is_zero32(&asset_id) {
        return Err(RgkAssetError::ZeroAssetId);
    }
    if total_supply == 0 {
        return Err(RgkAssetError::ZeroTotalSupply);
    }
    if is_zero32(&lane_id) {
        return Err(RgkAssetError::ZeroLaneId);
    }
    proof_policy.validate()
}

fn production_allocation_strategy_commitment(
    report: &RgkContinuationReport,
    strategy: RgkProductionAllocationStrategy,
) -> RgkProductionAllocationStrategyCommitment {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + 8 + 32 + 32 + 32 + 64);
    payload.push(report.chain as u8);
    payload.extend_from_slice(&report.schema_id);
    payload.extend_from_slice(&report.asset_id);
    payload.extend_from_slice(&report.total_supply.to_le_bytes());
    payload.extend_from_slice(&report.previous_state_digest.0);
    payload.extend_from_slice(&report.shape_root.0);
    payload.extend_from_slice(&report.commitment.0);
    payload.extend_from_slice(&report.spent_supply.to_le_bytes());
    payload.extend_from_slice(&report.new_supply.to_le_bytes());
    payload.extend_from_slice(&report.burned_supply.to_le_bytes());
    payload.extend_from_slice(&(report.spent_allocation_count as u64).to_le_bytes());
    payload.extend_from_slice(&(report.new_allocation_count as u64).to_le_bytes());
    match strategy {
        RgkProductionAllocationStrategy::FixedAllocationVector { shape } => {
            payload.push(0);
            payload.extend_from_slice(&(shape.spent_count() as u64).to_le_bytes());
            payload.extend_from_slice(&(shape.new_count() as u64).to_le_bytes());
        }
        RgkProductionAllocationStrategy::SegmentedAllocationAudit {
            segment_capacity,
            spent_segments,
            new_segments,
            exclusion_cells,
            groth16_proof_cells,
        } => {
            payload.push(1);
            payload.extend_from_slice(&(segment_capacity as u64).to_le_bytes());
            payload.extend_from_slice(&(spent_segments as u64).to_le_bytes());
            payload.extend_from_slice(&(new_segments as u64).to_le_bytes());
            payload.extend_from_slice(&(exclusion_cells as u64).to_le_bytes());
            payload.extend_from_slice(&(groth16_proof_cells as u64).to_le_bytes());
        }
    }
    domain_hash_domain("rgk:asset:production-allocation-strategy:v1", &payload)
}

fn validate_metadata_commitment(
    metadata_commitment: RgkMetadataCommitment,
) -> Result<(), RgkAssetError> {
    reject_zero(
        &metadata_commitment.0,
        RgkAssetError::ZeroMetadataCommitment,
    )
}

fn validate_owner_commitment(
    owner_commitment: RgkOwnerCommitment,
    role: &'static str,
) -> Result<(), RgkAssetError> {
    reject_zero(
        &owner_commitment.0,
        RgkAssetError::ZeroOwnerCommitment { role },
    )
}

fn validate_owner_descriptor(descriptor: &RgkOwnerDescriptor) -> Result<(), RgkAssetError> {
    reject_zero(
        descriptor.payload(),
        RgkAssetError::ZeroOwnerDescriptor {
            kind: descriptor.kind(),
        },
    )
}

fn validate_nft_collection_material(
    schema_id: RgkSchemaId,
    max_supply: u64,
    issuer_owner_commitment: RgkOwnerCommitment,
    template_commitment: RgkNftTemplateCommitment,
    royalty_policy_commitment: RgkNftPolicyCommitment,
) -> Result<(), RgkAssetError> {
    if is_zero32(&schema_id) {
        return Err(RgkAssetError::ZeroSchemaId);
    }
    if max_supply == 0 {
        return Err(RgkAssetError::ZeroTotalSupply);
    }
    validate_owner_commitment(issuer_owner_commitment, "nft-issuer")?;
    reject_zero(
        &template_commitment.0,
        RgkAssetError::ZeroNftTemplateCommitment,
    )?;
    reject_zero(
        &royalty_policy_commitment.0,
        RgkAssetError::ZeroNftPolicyCommitment,
    )
}

fn validate_nft_issue_shape(
    spec: &RgkNftTokenSpec,
    issue: &RgkAssetIssue,
    token_id: RgkNftTokenId,
) -> Result<(), RgkAssetError> {
    if issue.chain != spec.collection.chain {
        return Err(RgkAssetError::NftChainMismatch {
            expected: spec.collection.chain,
            actual: issue.chain,
        });
    }
    if issue.schema_id != spec.collection.schema_id {
        return Err(RgkAssetError::NftSchemaMismatch);
    }
    if issue.asset_id != token_id {
        return Err(RgkAssetError::NftAssetMismatch);
    }
    if issue.total_supply != 1 {
        return Err(RgkAssetError::NftSupplyMismatch {
            expected: 1,
            actual: issue.total_supply,
        });
    }
    if issue.metadata_commitment != spec.metadata_commitment {
        return Err(RgkAssetError::NftMetadataMismatch);
    }
    if issue.owner_commitment != spec.owner_commitment {
        return Err(RgkAssetError::NftOwnerMismatch { role: "issue" });
    }
    validate_single_nft_allocation("issue", &issue.allocations)
}

fn validate_nft_transition_shape(
    spec: &RgkNftTokenSpec,
    transition: &RgkTransition,
    token_id: RgkNftTokenId,
    new_owner_commitment: RgkOwnerCommitment,
) -> Result<(), RgkAssetError> {
    if transition.chain != spec.collection.chain {
        return Err(RgkAssetError::NftChainMismatch {
            expected: spec.collection.chain,
            actual: transition.chain,
        });
    }
    if transition.schema_id != spec.collection.schema_id {
        return Err(RgkAssetError::NftSchemaMismatch);
    }
    if transition.asset_id != token_id {
        return Err(RgkAssetError::NftAssetMismatch);
    }
    if transition.total_supply != 1 {
        return Err(RgkAssetError::NftSupplyMismatch {
            expected: 1,
            actual: transition.total_supply,
        });
    }
    if transition.metadata_commitment != spec.metadata_commitment {
        return Err(RgkAssetError::NftMetadataMismatch);
    }
    if transition.previous_owner_commitment != spec.owner_commitment {
        return Err(RgkAssetError::NftOwnerMismatch { role: "previous" });
    }
    if transition.new_owner_commitment != new_owner_commitment {
        return Err(RgkAssetError::NftOwnerMismatch { role: "new" });
    }
    if transition.burn.is_some() {
        return Err(RgkAssetError::NftUnexpectedBurn);
    }
    validate_single_nft_allocation("spent", &transition.spent_allocations)?;
    validate_single_nft_allocation("new", &transition.new_allocations)
}

fn validate_nft_marketplace_sale_terms(
    spec: &RgkNftTokenSpec,
    sale_terms: &RgkNftMarketplaceSaleTerms,
    token_id: RgkNftTokenId,
) -> Result<(), RgkAssetError> {
    sale_terms.validate_basic()?;
    if sale_terms.chain != spec.collection.chain {
        return Err(RgkAssetError::NftChainMismatch {
            expected: spec.collection.chain,
            actual: sale_terms.chain,
        });
    }
    if sale_terms.collection_id != spec.collection.collection_id {
        return Err(RgkAssetError::NftMarketplaceCollectionMismatch);
    }
    if sale_terms.token_id != token_id {
        return Err(RgkAssetError::NftMarketplaceTokenMismatch);
    }
    if sale_terms.seller_owner_commitment != spec.owner_commitment {
        return Err(RgkAssetError::NftOwnerMismatch {
            role: "marketplace-seller",
        });
    }
    if sale_terms.royalty_policy_commitment != spec.collection.royalty_policy_commitment {
        return Err(RgkAssetError::NftMarketplaceRoyaltyPolicyMismatch);
    }
    Ok(())
}

struct RgkNftBurnCommonInput<'a> {
    spec: &'a RgkNftTokenSpec,
    chain: KaspaChainId,
    schema_id: RgkSchemaId,
    asset_id: RgkAssetId,
    total_supply: u64,
    metadata_commitment: RgkMetadataCommitment,
    previous_owner_commitment: RgkOwnerCommitment,
    new_owner_commitment: RgkOwnerCommitment,
    burn: Option<&'a RgkBurnProof>,
    token_id: RgkNftTokenId,
}

fn validate_nft_burn_common(input: RgkNftBurnCommonInput<'_>) -> Result<(), RgkAssetError> {
    let spec = input.spec;
    if input.chain != spec.collection.chain {
        return Err(RgkAssetError::NftChainMismatch {
            expected: spec.collection.chain,
            actual: input.chain,
        });
    }
    if input.schema_id != spec.collection.schema_id {
        return Err(RgkAssetError::NftSchemaMismatch);
    }
    if input.asset_id != input.token_id {
        return Err(RgkAssetError::NftAssetMismatch);
    }
    if input.total_supply != 1 {
        return Err(RgkAssetError::NftSupplyMismatch {
            expected: 1,
            actual: input.total_supply,
        });
    }
    if input.metadata_commitment != spec.metadata_commitment {
        return Err(RgkAssetError::NftMetadataMismatch);
    }
    if input.previous_owner_commitment != spec.owner_commitment {
        return Err(RgkAssetError::NftOwnerMismatch { role: "previous" });
    }
    if input.new_owner_commitment != spec.owner_commitment {
        return Err(RgkAssetError::NftOwnerMismatch { role: "burn" });
    }
    match input.burn {
        Some(proof) if proof.amount == 1 => Ok(()),
        Some(proof) => Err(RgkAssetError::NftAllocationAmountMismatch {
            role: "burn",
            expected: 1,
            actual: proof.amount,
        }),
        None => Err(RgkAssetError::SupplyDeflationWithoutBurn { spent: 1, new: 0 }),
    }
}

fn validate_nft_burn_transition_shape(
    spec: &RgkNftTokenSpec,
    transition: &RgkTransition,
    token_id: RgkNftTokenId,
) -> Result<(), RgkAssetError> {
    validate_nft_burn_common(RgkNftBurnCommonInput {
        spec,
        chain: transition.chain,
        schema_id: transition.schema_id,
        asset_id: transition.asset_id,
        total_supply: transition.total_supply,
        metadata_commitment: transition.metadata_commitment,
        previous_owner_commitment: transition.previous_owner_commitment,
        new_owner_commitment: transition.new_owner_commitment,
        burn: transition.burn.as_ref(),
        token_id,
    })?;
    validate_single_nft_allocation("spent", &transition.spent_allocations)?;
    validate_empty_nft_allocations("burn-new", transition.new_allocations.len())
}

fn validate_nft_burn_continuation_shape(
    spec: &RgkNftTokenSpec,
    plan: &RgkContinuationPlan,
    token_id: RgkNftTokenId,
) -> Result<(), RgkAssetError> {
    validate_nft_burn_common(RgkNftBurnCommonInput {
        spec,
        chain: plan.chain,
        schema_id: plan.schema_id,
        asset_id: plan.asset_id,
        total_supply: plan.total_supply,
        metadata_commitment: plan.metadata_commitment,
        previous_owner_commitment: plan.previous_owner_commitment,
        new_owner_commitment: plan.new_owner_commitment,
        burn: plan.burn.as_ref(),
        token_id,
    })?;
    validate_single_nft_allocation("spent", &plan.spent_allocations)?;
    validate_empty_nft_allocations("burn-new", plan.new_allocation_shapes.len())
}

fn validate_single_nft_allocation(
    role: &'static str,
    allocations: &[RgkAllocation],
) -> Result<(), RgkAssetError> {
    if allocations.len() != 1 {
        return Err(RgkAssetError::NftAllocationShapeMismatch {
            role,
            count: allocations.len(),
        });
    }
    if allocations[0].amount != 1 {
        return Err(RgkAssetError::NftAllocationAmountMismatch {
            role,
            expected: 1,
            actual: allocations[0].amount,
        });
    }
    Ok(())
}

fn validate_empty_nft_allocations(role: &'static str, count: usize) -> Result<(), RgkAssetError> {
    if count != 0 {
        return Err(RgkAssetError::NftAllocationShapeMismatch { role, count });
    }
    Ok(())
}

fn validate_ownership_handoff(
    previous_owner_commitment: RgkOwnerCommitment,
    new_owner_commitment: RgkOwnerCommitment,
    ownership_authorization_commitment: Bytes32,
) -> Result<(), RgkAssetError> {
    if previous_owner_commitment != new_owner_commitment
        && is_zero32(&ownership_authorization_commitment)
    {
        return Err(RgkAssetError::ZeroOwnershipAuthorization);
    }
    Ok(())
}

fn validate_production_zk_issue_count(count: usize) -> Result<(), RgkAssetError> {
    if count > RGK_PRODUCTION_ZK_ALLOCATION_MAX_SPENT {
        return Err(RgkAssetError::ProductionZkAllocationBoundExceeded {
            role: "issue-state",
            count,
            max: RGK_PRODUCTION_ZK_ALLOCATION_MAX_SPENT,
        });
    }
    Ok(())
}

fn validate_allocation_set_exact(
    chain: KaspaChainId,
    total_supply: u64,
    allocations: &[RgkAllocation],
) -> Result<(), RgkAssetError> {
    let total = validate_allocation_set_structure(chain, allocations)?;
    if total != total_supply {
        return Err(RgkAssetError::SupplyMismatch {
            expected: total_supply,
            actual: total,
        });
    }
    Ok(())
}

fn validate_allocation_set_structure(
    chain: KaspaChainId,
    allocations: &[RgkAllocation],
) -> Result<u64, RgkAssetError> {
    if allocations.is_empty() {
        return Err(RgkAssetError::EmptyAllocations);
    }
    validate_allocation_set_structure_allow_empty(chain, allocations)
}

fn validate_allocation_set_structure_allow_empty(
    chain: KaspaChainId,
    allocations: &[RgkAllocation],
) -> Result<u64, RgkAssetError> {
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for (index, allocation) in allocations.iter().enumerate() {
        if allocation.amount == 0 {
            return Err(RgkAssetError::ZeroAllocationAmount { index });
        }
        if allocation.seal.chain != chain {
            return Err(RgkAssetError::ChainMismatch {
                index,
                expected: chain,
                actual: allocation.seal.chain,
            });
        }
        if allocation.seal.covenant_outpoint == KaspaOutpoint::NULL {
            return Err(RgkAssetError::NullCovenantOutpoint { index });
        }
        if is_zero32(&allocation.seal.covenant_id) {
            return Err(RgkAssetError::ZeroCovenantId { index });
        }
        if is_zero32(&allocation.seal.witness_txid) {
            return Err(RgkAssetError::ZeroWitnessTxid { index });
        }
        if is_zero32(&allocation.encrypted_note_commitment) {
            return Err(RgkAssetError::ZeroEncryptedNote { index });
        }
        if allocation.seal.confirmation_depth == 0 {
            return Err(RgkAssetError::UnconfirmedSeal { index });
        }
        if !seen.insert(allocation.seal.covenant_outpoint) {
            return Err(RgkAssetError::DuplicateSealOutpoint { index });
        }
        total = total
            .checked_add(allocation.amount)
            .ok_or(RgkAssetError::SupplyOverflow)?;
    }
    Ok(total)
}

fn validate_continuation_shapes_structure(
    shapes: &[RgkContinuationAllocationShape],
) -> Result<u64, RgkAssetError> {
    if shapes.is_empty() {
        return Err(RgkAssetError::EmptyContinuationShape);
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for (index, shape) in shapes.iter().enumerate() {
        if shape.amount == 0 {
            return Err(RgkAssetError::ZeroContinuationAmount { index });
        }
        if is_zero32(&shape.covenant_id) {
            return Err(RgkAssetError::ZeroContinuationCovenantId { index });
        }
        if is_zero32(&shape.encrypted_note_commitment) {
            return Err(RgkAssetError::ZeroContinuationEncryptedNote { index });
        }
        if !seen.insert(shape.output_index) {
            return Err(RgkAssetError::DuplicateContinuationOutput { index });
        }
        total = total
            .checked_add(shape.amount)
            .ok_or(RgkAssetError::SupplyOverflow)?;
    }
    Ok(total)
}

fn validate_continuation_shapes_structure_allow_empty(
    shapes: &[RgkContinuationAllocationShape],
    burn: Option<&RgkBurnProof>,
) -> Result<u64, RgkAssetError> {
    if shapes.is_empty() {
        if burn.is_some() {
            Ok(0)
        } else {
            Err(RgkAssetError::EmptyContinuationShape)
        }
    } else {
        validate_continuation_shapes_structure(shapes)
    }
}

fn validate_supply_delta(
    spent_supply: u64,
    new_supply: u64,
    burn: Option<&RgkBurnProof>,
) -> Result<u64, RgkAssetError> {
    if new_supply > spent_supply {
        return Err(RgkAssetError::SupplyInflation {
            spent: spent_supply,
            new: new_supply,
        });
    }

    let burned_supply = spent_supply - new_supply;
    match (burned_supply, burn) {
        (0, None) => Ok(0),
        (0, Some(proof)) => {
            if proof.amount == 0 {
                return Err(RgkAssetError::ZeroBurnAmount);
            }
            Err(RgkAssetError::BurnAmountMismatch {
                expected: 0,
                actual: proof.amount,
            })
        }
        (_, None) => Err(RgkAssetError::SupplyDeflationWithoutBurn {
            spent: spent_supply,
            new: new_supply,
        }),
        (amount, Some(proof)) => {
            if proof.amount == 0 {
                return Err(RgkAssetError::ZeroBurnAmount);
            }
            if is_zero32(&proof.authorization_commitment) {
                return Err(RgkAssetError::ZeroBurnAuthorization);
            }
            if proof.amount != amount {
                return Err(RgkAssetError::BurnAmountMismatch {
                    expected: amount,
                    actual: proof.amount,
                });
            }
            Ok(amount)
        }
    }
}

fn burn_authorization_commitment(burn: Option<&RgkBurnProof>) -> Bytes32 {
    burn.map_or([0; 32], |proof| proof.authorization_commitment)
}

struct RgkStateDigestInput<'a> {
    asset_id: RgkAssetId,
    total_supply: u64,
    allocations: &'a [RgkAllocation],
    lane_id: BlindedLaneId,
    privacy_policy: LanePrivacyPolicy,
    policy_commitment: RgkPolicyCommitment,
    metadata_commitment: RgkMetadataCommitment,
    owner_commitment: RgkOwnerCommitment,
}

fn state_digest_for_allocations(input: RgkStateDigestInput<'_>) -> Bytes32 {
    let allocation_root = allocation_root(input.allocations);
    let mut payload = Vec::with_capacity(32 + 8 + 32 + 32 + 32 + 32 + 1 + 32);
    payload.extend_from_slice(&input.asset_id);
    payload.extend_from_slice(&input.total_supply.to_le_bytes());
    payload.extend_from_slice(&allocation_root);
    payload.extend_from_slice(&input.policy_commitment.0);
    payload.extend_from_slice(&input.metadata_commitment.0);
    payload.extend_from_slice(&input.owner_commitment.0);
    payload.push(input.privacy_policy.as_u8());
    payload.extend_from_slice(&input.lane_id);
    domain_hash_domain("rgk:asset:state:v2", &payload)
}

fn continuation_shape_root(
    chain: KaspaChainId,
    shapes: &[RgkContinuationAllocationShape],
) -> Bytes32 {
    let mut ordered: Vec<&RgkContinuationAllocationShape> = shapes.iter().collect();
    ordered.sort_by_key(|shape| {
        (
            shape.output_index,
            shape.covenant_id,
            shape.encrypted_note_commitment,
            shape.amount,
        )
    });

    let mut payload = Vec::with_capacity(4 + ordered.len() * 77);
    payload.push(chain as u8);
    payload.extend_from_slice(&(ordered.len() as u32).to_le_bytes());
    for shape in ordered {
        payload.extend_from_slice(&shape.output_index.to_le_bytes());
        payload.extend_from_slice(&shape.covenant_id);
        payload.extend_from_slice(&shape.amount.to_le_bytes());
        payload.extend_from_slice(&shape.encrypted_note_commitment);
    }
    domain_hash_domain("rgk:continuation:shape-root:v1", &payload)
}

fn allocation_root(allocations: &[RgkAllocation]) -> Bytes32 {
    let mut ordered: Vec<&RgkAllocation> = allocations.iter().collect();
    ordered.sort_by_key(|allocation| allocation_key(allocation));

    let mut payload = Vec::with_capacity(4 + ordered.len() * 157);
    payload.extend_from_slice(&(ordered.len() as u32).to_le_bytes());
    for allocation in ordered {
        encode_allocation(&mut payload, allocation);
    }
    domain_hash_domain("rgk:asset:allocation-root:v1", &payload)
}

fn encode_allocation(payload: &mut Vec<u8>, allocation: &RgkAllocation) {
    payload.push(allocation.seal.chain as u8);
    payload.extend_from_slice(&allocation.seal.covenant_outpoint.transaction_id);
    payload.extend_from_slice(&allocation.seal.covenant_outpoint.index.to_le_bytes());
    payload.extend_from_slice(&allocation.seal.covenant_id);
    payload.extend_from_slice(&allocation.seal.witness_txid);
    payload.extend_from_slice(&allocation.seal.daa_score.to_le_bytes());
    payload.extend_from_slice(&allocation.seal.confirmation_depth.to_le_bytes());
    payload.extend_from_slice(&allocation.amount.to_le_bytes());
    payload.extend_from_slice(&allocation.encrypted_note_commitment);
}

fn encode_burn_proof(payload: &mut Vec<u8>, burn: Option<&RgkBurnProof>) {
    match burn {
        None => payload.push(0),
        Some(proof) => {
            payload.push(1);
            payload.extend_from_slice(&proof.amount.to_le_bytes());
            payload.extend_from_slice(&proof.authorization_commitment);
        }
    }
}

fn allocation_key(allocation: &RgkAllocation) -> (KaspaOutpoint, Bytes32, Bytes32, u64, u64) {
    (
        allocation.seal.covenant_outpoint,
        allocation.seal.covenant_id,
        allocation.seal.witness_txid,
        allocation.seal.daa_score,
        allocation.amount,
    )
}

fn encode_proof_policy(payload: &mut Vec<u8>, policy: &RgkProofPolicy) {
    match policy {
        RgkProofPolicy::VerifierReceipt { verifier_key_hash } => {
            payload.push(0);
            payload.extend_from_slice(verifier_key_hash);
        }
        RgkProofPolicy::ZkReceipt {
            verifier_key_id,
            image_id_policy,
        } => {
            payload.push(1);
            payload.extend_from_slice(verifier_key_id);
            encode_image_id_policy(payload, image_id_policy);
        }
        RgkProofPolicy::Hybrid {
            verifier_key_hash,
            verifier_key_id,
        } => {
            payload.push(2);
            payload.extend_from_slice(verifier_key_hash);
            payload.extend_from_slice(verifier_key_id);
        }
    }
}

fn encode_image_id_policy(payload: &mut Vec<u8>, policy: &ImageIdPolicy) {
    match policy {
        ImageIdPolicy::Fixed(image_id) => {
            payload.push(0);
            payload.extend_from_slice(image_id);
        }
        ImageIdPolicy::AllowedSet(set) => {
            payload.push(1);
            payload.extend_from_slice(&(set.len() as u32).to_le_bytes());
            for image_id in set {
                payload.extend_from_slice(image_id);
            }
        }
        ImageIdPolicy::PolicyBranch(branch) => {
            payload.push(2);
            payload.extend_from_slice(branch);
        }
    }
}

fn reject_zero(bytes: &Bytes32, error: RgkAssetError) -> Result<(), RgkAssetError> {
    if is_zero32(bytes) {
        Err(error)
    } else {
        Ok(())
    }
}

fn is_zero32(bytes: &Bytes32) -> bool {
    bytes.iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rgk_core::{to_hex, KASPA_LOCAL_TOCCATA};

    fn proof_policy() -> RgkProofPolicy {
        RgkProofPolicy::VerifierReceipt {
            verifier_key_hash: [0x91; 32],
        }
    }

    fn lane_id() -> BlindedLaneId {
        [0x71; 32]
    }

    fn metadata_commitment() -> RgkMetadataCommitment {
        RgkMetadataCommitment([0x81; 32])
    }

    fn owner_commitment() -> RgkOwnerCommitment {
        RgkOwnerCommitment([0x82; 32])
    }

    fn new_owner_commitment() -> RgkOwnerCommitment {
        RgkOwnerCommitment([0x83; 32])
    }

    fn ownership_authorization_commitment() -> Bytes32 {
        [0x84; 32]
    }

    fn rederive_asset_id(issue: &RgkAssetIssue) -> RgkAssetId {
        RgkAssetIssue::derive_asset_id(RgkAssetIdDerivation {
            chain: issue.chain,
            schema_id: issue.schema_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            owner_commitment: issue.owner_commitment,
            allocations: &issue.allocations,
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: &issue.proof_policy,
        })
        .unwrap()
    }

    fn nft_schema_id() -> RgkSchemaId {
        let mut schema_id = [b'_'; 32];
        schema_id[..17].copy_from_slice(b"rgk:nft:schema:v1");
        schema_id
    }

    fn nft_template_commitment() -> RgkNftTemplateCommitment {
        RgkNftTemplateCommitment([0xa1; 32])
    }

    fn nft_policy_commitment() -> RgkNftPolicyCommitment {
        RgkNftPolicyCommitment([0xa2; 32])
    }

    fn nft_metadata_commitment() -> RgkMetadataCommitment {
        RgkMetadataCommitment([0xa3; 32])
    }

    fn nft_collection_policy(max_supply: u64) -> RgkNftCollectionPolicy {
        let schema_id = nft_schema_id();
        let issuer_owner_commitment = RgkOwnerDescriptor::KeyHash([0xa4; 32])
            .derive_commitment()
            .unwrap();
        let template_commitment = nft_template_commitment();
        let royalty_policy_commitment = nft_policy_commitment();
        let collection_id =
            RgkNftCollectionPolicy::derive_collection_id(RgkNftCollectionIdDerivation {
                chain: KASPA_LOCAL_TOCCATA,
                schema_id,
                max_supply,
                issuer_owner_commitment,
                template_commitment,
                royalty_policy_commitment,
            })
            .unwrap();
        RgkNftCollectionPolicy {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id,
            collection_id,
            max_supply,
            issuer_owner_commitment,
            template_commitment,
            royalty_policy_commitment,
        }
    }

    fn nft_token_spec(token_index: u64, owner_commitment: RgkOwnerCommitment) -> RgkNftTokenSpec {
        RgkNftTokenSpec {
            collection: nft_collection_policy(10),
            token_index,
            metadata_commitment: nft_metadata_commitment(),
            owner_commitment,
        }
    }

    fn nft_issue(spec: &RgkNftTokenSpec) -> RgkAssetIssue {
        RgkAssetIssue {
            chain: spec.collection.chain,
            schema_id: spec.collection.schema_id,
            asset_id: spec.token_id().unwrap(),
            total_supply: 1,
            metadata_commitment: spec.metadata_commitment,
            owner_commitment: spec.owner_commitment,
            allocations: vec![allocation(0xa5, 0, 1)],
            lane_id: lane_id(),
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        }
    }

    fn nft_burn_continuation_plan(spec: &RgkNftTokenSpec) -> RgkContinuationPlan {
        let issue = nft_issue(spec);
        let previous_report = issue.validate().unwrap();
        RgkContinuationPlan {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: spec.owner_commitment,
            new_owner_commitment: spec.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocation_shapes: vec![],
            burn: Some(burn_proof(1, 0xe1)),
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        }
    }

    fn seal(seed: u8, amount_index: u32) -> RgkCovenantSeal {
        RgkCovenantSeal {
            chain: KASPA_LOCAL_TOCCATA,
            covenant_outpoint: KaspaOutpoint {
                transaction_id: [seed; 32],
                index: amount_index,
            },
            covenant_id: [seed.wrapping_add(0x10); 32],
            witness_txid: [seed.wrapping_add(0x20); 32],
            daa_score: 10_000 + amount_index as u64,
            confirmation_depth: 12,
        }
    }

    fn allocation(seed: u8, index: u32, amount: u64) -> RgkAllocation {
        RgkAllocation {
            seal: seal(seed, index),
            amount,
            encrypted_note_commitment: [seed.wrapping_add(0x30); 32],
        }
    }

    fn issue() -> RgkAssetIssue {
        let allocations = vec![allocation(0x22, 0, 40), allocation(0x11, 1, 60)];
        issue_with_allocations(100, allocations)
    }

    fn issue_with_allocations(total_supply: u64, allocations: Vec<RgkAllocation>) -> RgkAssetIssue {
        let schema_id = *b"rgk:asset:schema:v1_____________";
        let policy = proof_policy();
        let asset_id = RgkAssetIssue::derive_asset_id(RgkAssetIdDerivation {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: &allocations,
            lane_id: lane_id(),
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: &policy,
        })
        .unwrap();
        RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations,
            lane_id: lane_id(),
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: policy,
        }
    }

    fn next_allocations() -> Vec<RgkAllocation> {
        vec![allocation(0x44, 0, 25), allocation(0x55, 1, 75)]
    }

    fn burn_proof(amount: u64, seed: u8) -> RgkBurnProof {
        RgkBurnProof {
            amount,
            authorization_commitment: [seed; 32],
        }
    }

    fn transition() -> RgkTransition {
        let issue = issue();
        let previous_report = issue.validate().unwrap();
        RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: next_allocations(),
            burn: None,
            witness_txid: [0x77; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        }
    }

    fn continuation_shapes() -> Vec<RgkContinuationAllocationShape> {
        vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id: [0x54; 32],
                amount: 25,
                encrypted_note_commitment: [0x74; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id: [0x65; 32],
                amount: 75,
                encrypted_note_commitment: [0x85; 32],
            },
        ]
    }

    fn continuation_plan() -> RgkContinuationPlan {
        let issue = issue();
        let previous_report = issue.validate().unwrap();
        RgkContinuationPlan {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocation_shapes: continuation_shapes(),
            burn: None,
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        }
    }

    fn large_issue() -> RgkAssetIssue {
        issue_with_allocations(
            100,
            vec![
                allocation(0x21, 0, 10),
                allocation(0x22, 1, 20),
                allocation(0x23, 2, 15),
                allocation(0x24, 3, 25),
                allocation(0x25, 4, 30),
            ],
        )
    }

    fn large_continuation_shapes() -> Vec<RgkContinuationAllocationShape> {
        vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id: [0x61; 32],
                amount: 5,
                encrypted_note_commitment: [0x71; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id: [0x62; 32],
                amount: 35,
                encrypted_note_commitment: [0x72; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 2,
                covenant_id: [0x63; 32],
                amount: 15,
                encrypted_note_commitment: [0x73; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 3,
                covenant_id: [0x64; 32],
                amount: 20,
                encrypted_note_commitment: [0x74; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 4,
                covenant_id: [0x65; 32],
                amount: 25,
                encrypted_note_commitment: [0x75; 32],
            },
        ]
    }

    fn large_continuation_plan() -> RgkContinuationPlan {
        let issue = large_issue();
        let previous_report = issue.validate().unwrap();
        RgkContinuationPlan {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocation_shapes: large_continuation_shapes(),
            burn: None,
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        }
    }

    #[test]
    fn production_zk_allocation_shape_policy_is_native_and_exact() {
        assert_eq!(
            RGK_PRODUCTION_ZK_ALLOCATION_SHAPES,
            [
                RgkAllocationProofShape::OneInZeroOut,
                RgkAllocationProofShape::OneInOneOut,
                RgkAllocationProofShape::TwoInTwoOut,
                RgkAllocationProofShape::ThreeInTwoOut,
                RgkAllocationProofShape::FourInTwoOut,
                RgkAllocationProofShape::FourInFourOut,
            ]
        );
        assert_eq!(
            RGK_PRODUCTION_ZK_ALLOCATION_SHAPE_LABELS,
            "1x0, 1x1, 2x2, 3x2, 4x2, 4x4"
        );
        assert_eq!(RGK_PRODUCTION_ZK_ALLOCATION_MAX_SPENT, 4);
        assert_eq!(RGK_PRODUCTION_ZK_ALLOCATION_MAX_NEW, 4);
        assert_eq!(
            RgkAllocationProofShape::from_counts(1, 0),
            Some(RgkAllocationProofShape::OneInZeroOut)
        );
        assert_eq!(
            RgkAllocationProofShape::from_counts(1, 1),
            Some(RgkAllocationProofShape::OneInOneOut)
        );
        assert_eq!(
            RgkAllocationProofShape::from_counts(2, 2),
            Some(RgkAllocationProofShape::TwoInTwoOut)
        );
        assert_eq!(
            RgkAllocationProofShape::from_counts(3, 2),
            Some(RgkAllocationProofShape::ThreeInTwoOut)
        );
        assert_eq!(
            RgkAllocationProofShape::from_counts(4, 2),
            Some(RgkAllocationProofShape::FourInTwoOut)
        );
        assert_eq!(
            RgkAllocationProofShape::from_counts(4, 4),
            Some(RgkAllocationProofShape::FourInFourOut)
        );
        assert_eq!(RgkAllocationProofShape::from_counts(1, 2), None);
        assert_eq!(RgkAllocationProofShape::from_counts(4, 3), None);
    }

    #[test]
    fn production_zk_issue_rejects_unprovable_initial_state() {
        let issue = issue_with_allocations(
            100,
            vec![
                allocation(0x21, 0, 20),
                allocation(0x22, 1, 20),
                allocation(0x23, 2, 20),
                allocation(0x24, 3, 20),
                allocation(0x25, 4, 20),
            ],
        );
        assert!(issue.validate().is_ok());
        let err = issue.validate_for_production_zk().unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::ProductionZkAllocationBoundExceeded {
                role: "issue-state",
                count: 5,
                max: 4
            }
        ));
    }

    #[test]
    fn production_zk_transition_rejects_unsupported_shape_only_on_zk_path() {
        let mut transition = transition();
        transition.new_allocations = vec![allocation(0x66, 0, 100)];
        assert!(transition.validate().is_ok());
        let err = transition.validate_for_production_zk().unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::UnsupportedProductionZkAllocationShape {
                spent_count: 2,
                new_count: 1
            }
        ));
    }

    #[test]
    fn production_zk_continuation_rejects_unsupported_shape_before_finalization() {
        let mut plan = continuation_plan();
        plan.new_allocation_shapes = vec![RgkContinuationAllocationShape {
            output_index: 0,
            covenant_id: [0x54; 32],
            amount: 100,
            encrypted_note_commitment: [0x74; 32],
        }];
        assert!(plan.validate().is_ok());
        let err = plan.validate_for_production_zk().unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::UnsupportedProductionZkAllocationShape {
                spent_count: 2,
                new_count: 1
            }
        ));
        assert!(matches!(
            plan.finalize_for_production_zk([0x88; 32], 20_000, 3),
            Err(RgkAssetError::UnsupportedProductionZkAllocationShape {
                spent_count: 2,
                new_count: 1
            })
        ));
    }

    #[test]
    fn production_zk_transfer_plan_certifies_full_state_shape_before_txid() {
        let plan = continuation_plan();
        let expected_report = plan.validate_for_production_zk().unwrap();
        let transfer_plan = RgkProductionZkTransferPlan::new(plan).unwrap();
        assert_eq!(
            transfer_plan.allocation_shape(),
            RgkAllocationProofShape::TwoInTwoOut
        );
        assert_eq!(transfer_plan.continuation_report(), &expected_report);
        assert_eq!(
            transfer_plan
                .continuation_plan()
                .new_allocation_shapes
                .len(),
            2
        );

        let finalized = transfer_plan.finalize([0x88; 32], 20_000, 3).unwrap();
        assert_eq!(
            finalized.allocation_shape(),
            RgkAllocationProofShape::TwoInTwoOut
        );
        assert_eq!(finalized.transition_report().spent_allocation_count, 2);
        assert_eq!(finalized.transition_report().new_allocation_count, 2);
        assert_ne!(
            finalized.transition_report().previous_state_digest,
            finalized.transition_report().new_state_digest
        );
    }

    #[test]
    fn production_zk_transfer_plan_rejects_partial_previous_state_spend() {
        let issue = issue();
        let previous_state_digest = issue.validate().unwrap().state_digest;
        let mut plan = continuation_plan();
        plan.previous_state_digest = previous_state_digest;
        plan.spent_allocations = vec![issue.allocations[0].clone()];
        plan.new_allocation_shapes = vec![RgkContinuationAllocationShape {
            output_index: 0,
            covenant_id: [0x54; 32],
            amount: issue.total_supply,
            encrypted_note_commitment: [0x74; 32],
        }];

        let err = RgkProductionZkTransferPlan::new(plan).unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::PreviousStateDigestMismatch { .. }
        ));
    }

    #[test]
    fn production_zk_transfer_plan_rejects_unsupported_shape_before_txid() {
        let mut plan = continuation_plan();
        plan.new_allocation_shapes = vec![RgkContinuationAllocationShape {
            output_index: 0,
            covenant_id: [0x54; 32],
            amount: 100,
            encrypted_note_commitment: [0x74; 32],
        }];

        let err = plan
            .into_production_zk_transfer_plan()
            .expect_err("2x1 is not a production-ZK allocation shape");
        assert!(matches!(
            err,
            RgkAssetError::UnsupportedProductionZkAllocationShape {
                spent_count: 2,
                new_count: 1
            }
        ));
    }

    #[test]
    fn production_allocation_strategy_selects_fixed_and_segmented_paths() {
        let fixed_plan = RgkProductionAllocationStrategyPlan::new(continuation_plan()).unwrap();
        assert_eq!(
            fixed_plan.strategy(),
            RgkProductionAllocationStrategy::FixedAllocationVector {
                shape: RgkAllocationProofShape::TwoInTwoOut
            }
        );
        assert!(!fixed_plan
            .strategy()
            .requires_allocation_audit_certificate());
        assert_eq!(fixed_plan.strategy().groth16_proof_cells(), 1);

        let segmented_plan =
            RgkProductionAllocationStrategyPlan::new(large_continuation_plan()).unwrap();
        assert_eq!(
            segmented_plan.strategy(),
            RgkProductionAllocationStrategy::SegmentedAllocationAudit {
                segment_capacity: RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY,
                spent_segments: 3,
                new_segments: 3,
                exclusion_cells: 9,
                groth16_proof_cells: 22,
            }
        );
        assert!(segmented_plan
            .strategy()
            .requires_allocation_audit_certificate());
        assert_eq!(
            segmented_plan.continuation_report().spent_allocation_count,
            5
        );
        assert_eq!(segmented_plan.continuation_report().new_allocation_count, 5);

        let finalized = segmented_plan.finalize([0x88; 32], 20_000, 3).unwrap();
        assert_eq!(finalized.strategy(), segmented_plan.strategy());
        assert_eq!(
            finalized.strategy_commitment(),
            segmented_plan.strategy_commitment()
        );
        assert_eq!(finalized.transition_report().spent_allocation_count, 5);
        assert_eq!(finalized.transition_report().new_allocation_count, 5);
    }

    #[test]
    fn segmented_allocation_strategy_requires_conserving_nonempty_sides() {
        let mut burn_plan = large_continuation_plan();
        burn_plan.new_allocation_shapes.pop();
        burn_plan.burn = Some(burn_proof(25, 0xb1));
        assert!(burn_plan.validate().is_ok());
        let err = RgkProductionAllocationStrategyPlan::new(burn_plan).unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::SegmentedAllocationAuditRequiresConservation { burned_supply: 25 }
        ));

        let mut empty_new = large_continuation_plan();
        empty_new.new_allocation_shapes.clear();
        empty_new.burn = Some(burn_proof(100, 0xb2));
        assert!(empty_new.validate().is_ok());
        let report = empty_new.validate().unwrap();
        let err =
            RgkProductionAllocationStrategy::segmented_audit_for_report(&report, 2).unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::SegmentedAllocationAuditRequiresConservation { burned_supply: 100 }
        ));
    }

    #[test]
    fn production_allocation_strategy_commitment_binds_counts_and_segment_grid() {
        let segmented =
            RgkProductionAllocationStrategyPlan::new(large_continuation_plan()).unwrap();

        let mut changed_plan = large_continuation_plan();
        changed_plan.new_allocation_shapes = vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id: [0x66; 32],
                amount: 50,
                encrypted_note_commitment: [0x76; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id: [0x67; 32],
                amount: 50,
                encrypted_note_commitment: [0x77; 32],
            },
        ];
        let changed = RgkProductionAllocationStrategyPlan::new(changed_plan).unwrap();

        assert_ne!(
            segmented.continuation_report().commitment,
            changed.continuation_report().commitment
        );
        assert_ne!(
            segmented.strategy_commitment(),
            changed.strategy_commitment()
        );
        assert_eq!(
            changed.strategy(),
            RgkProductionAllocationStrategy::SegmentedAllocationAudit {
                segment_capacity: RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY,
                spent_segments: 3,
                new_segments: 1,
                exclusion_cells: 3,
                groth16_proof_cells: 12,
            }
        );
    }

    #[test]
    fn fungible_multi_output_fanout_2x2_is_production_zk_supported() {
        let issue =
            issue_with_allocations(100, vec![allocation(0x31, 0, 80), allocation(0x32, 1, 20)]);
        let previous_report = issue.validate_for_production_zk().unwrap();
        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: vec![allocation(0x61, 0, 45), allocation(0x62, 1, 55)],
            burn: None,
            witness_txid: [0x93; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };

        let report = transition.validate_for_production_zk().unwrap();
        assert_eq!(report.spent_supply, 100);
        assert_eq!(report.new_supply, 100);
        assert_eq!(report.burned_supply, 0);
        assert_eq!(
            RgkAllocationProofShape::from_counts(
                report.spent_allocation_count,
                report.new_allocation_count
            ),
            Some(RgkAllocationProofShape::TwoInTwoOut)
        );
    }

    #[test]
    fn fungible_multi_input_merge_3x2_is_production_zk_supported() {
        let issue = issue_with_allocations(
            100,
            vec![
                allocation(0x33, 0, 20),
                allocation(0x34, 1, 30),
                allocation(0x35, 2, 50),
            ],
        );
        let previous_report = issue.validate_for_production_zk().unwrap();
        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: vec![allocation(0x63, 0, 70), allocation(0x64, 1, 30)],
            burn: None,
            witness_txid: [0x94; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };

        let report = transition.validate_for_production_zk().unwrap();
        assert_eq!(report.spent_supply, 100);
        assert_eq!(report.new_supply, 100);
        assert_eq!(report.burned_supply, 0);
        assert_eq!(
            RgkAllocationProofShape::from_counts(
                report.spent_allocation_count,
                report.new_allocation_count
            ),
            Some(RgkAllocationProofShape::ThreeInTwoOut)
        );
    }

    #[test]
    fn fungible_four_input_merge_4x2_is_production_zk_supported() {
        let issue = issue_with_allocations(
            100,
            vec![
                allocation(0x46, 0, 10),
                allocation(0x47, 1, 20),
                allocation(0x48, 2, 30),
                allocation(0x49, 3, 40),
            ],
        );
        let previous_report = issue.validate_for_production_zk().unwrap();
        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: vec![allocation(0x69, 0, 70), allocation(0x6a, 1, 30)],
            burn: None,
            witness_txid: [0x96; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };

        let report = transition.validate_for_production_zk().unwrap();
        assert_eq!(report.spent_supply, 100);
        assert_eq!(report.new_supply, 100);
        assert_eq!(report.burned_supply, 0);
        assert_eq!(
            RgkAllocationProofShape::from_counts(
                report.spent_allocation_count,
                report.new_allocation_count
            ),
            Some(RgkAllocationProofShape::FourInTwoOut)
        );
    }

    #[test]
    fn fungible_batch_transfer_4x4_is_production_zk_supported() {
        let issue = issue_with_allocations(
            100,
            vec![
                allocation(0x36, 0, 10),
                allocation(0x37, 1, 20),
                allocation(0x38, 2, 30),
                allocation(0x39, 3, 40),
            ],
        );
        let previous_report = issue.validate_for_production_zk().unwrap();
        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: issue.owner_commitment,
            new_owner_commitment: issue.owner_commitment,
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: vec![
                allocation(0x65, 0, 15),
                allocation(0x66, 1, 25),
                allocation(0x67, 2, 35),
                allocation(0x68, 3, 25),
            ],
            burn: None,
            witness_txid: [0x95; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };

        let report = transition.validate_for_production_zk().unwrap();
        assert_eq!(report.spent_supply, 100);
        assert_eq!(report.new_supply, 100);
        assert_eq!(report.burned_supply, 0);
        assert_eq!(
            RgkAllocationProofShape::from_counts(
                report.spent_allocation_count,
                report.new_allocation_count
            ),
            Some(RgkAllocationProofShape::FourInFourOut)
        );
    }

    #[test]
    fn native_issue_digest_stable() {
        let report = issue().validate().unwrap();
        assert_eq!(report.allocation_count, 2);
        assert_eq!(
            to_hex(&report.state_digest.0),
            "ecd012e0f9da256322414745b354e58b254d6c66b1b36d89e58e7e256711670f"
        );
    }

    #[test]
    fn native_issue_digest_is_allocation_order_stable() {
        let original = issue();
        let original_digest = original.validate().unwrap().state_digest;
        let mut reversed = original.clone();
        reversed.allocations.reverse();
        assert_eq!(reversed.validate().unwrap().state_digest, original_digest);
    }

    #[test]
    fn native_issue_digest_binds_metadata_and_owner_commitments() {
        let original = issue();
        let expected = original.validate().unwrap().state_digest;

        let mut changed_metadata = original.clone();
        changed_metadata.metadata_commitment.0[0] ^= 1;
        assert!(matches!(
            changed_metadata.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));

        let mut changed_owner = original.clone();
        changed_owner.owner_commitment.0[0] ^= 1;
        assert!(matches!(
            changed_owner.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));

        let mut zero_metadata = original.clone();
        zero_metadata.metadata_commitment = RgkMetadataCommitment([0; 32]);
        assert!(matches!(
            zero_metadata.validate(),
            Err(RgkAssetError::ZeroMetadataCommitment)
        ));

        let mut zero_owner = original;
        zero_owner.owner_commitment = RgkOwnerCommitment([0; 32]);
        assert!(matches!(
            zero_owner.validate(),
            Err(RgkAssetError::ZeroOwnerCommitment { role: "issue" })
        ));
    }

    #[test]
    fn owner_descriptor_commitments_bind_owner_control_shape() {
        let key_owner = RgkOwnerDescriptor::KeyHash([0x31; 32])
            .derive_commitment()
            .unwrap();
        let rotated_key_owner = RgkOwnerDescriptor::KeyHash([0x32; 32])
            .derive_commitment()
            .unwrap();
        let script_owner = RgkOwnerDescriptor::ScriptHash([0x41; 32])
            .derive_commitment()
            .unwrap();
        let covenant_owner = RgkOwnerDescriptor::CovenantId([0x51; 32])
            .derive_commitment()
            .unwrap();

        assert_ne!(key_owner, rotated_key_owner);
        assert_ne!(key_owner, script_owner);
        assert_ne!(script_owner, covenant_owner);
        assert_eq!(
            RgkOwnerCommitment::from_descriptor(&RgkOwnerDescriptor::CovenantId([0x51; 32]))
                .unwrap(),
            covenant_owner
        );

        assert!(matches!(
            RgkOwnerDescriptor::KeyHash([0; 32]).derive_commitment(),
            Err(RgkAssetError::ZeroOwnerDescriptor { kind }) if kind == "key-hash"
        ));
        assert!(matches!(
            RgkOwnerDescriptor::ScriptHash([0; 32]).derive_commitment(),
            Err(RgkAssetError::ZeroOwnerDescriptor { kind }) if kind == "script-hash"
        ));
        assert!(matches!(
            RgkOwnerDescriptor::CovenantId([0; 32]).derive_commitment(),
            Err(RgkAssetError::ZeroOwnerDescriptor { kind }) if kind == "covenant-id"
        ));
    }

    #[test]
    fn nft_collection_policy_derives_fixed_supply_token_ids() {
        let owner = RgkOwnerDescriptor::KeyHash([0xb1; 32])
            .derive_commitment()
            .unwrap();
        let first = nft_token_spec(0, owner);
        let second = nft_token_spec(1, owner);

        assert_ne!(first.token_id().unwrap(), second.token_id().unwrap());
        assert_eq!(first.collection.max_supply, 10);
        assert_ne!(
            first.token_commitment().unwrap(),
            first
                .token_commitment_for_owner(
                    RgkOwnerDescriptor::ScriptHash([0xb2; 32])
                        .derive_commitment()
                        .unwrap()
                )
                .unwrap()
        );

        let out_of_range = nft_token_spec(10, owner);
        assert!(matches!(
            out_of_range.validate(),
            Err(RgkAssetError::NftTokenIndexOutOfRange {
                token_index: 10,
                max_supply: 10
            })
        ));

        let mut zero_template = first.collection;
        zero_template.template_commitment = RgkNftTemplateCommitment([0; 32]);
        assert!(matches!(
            zero_template.validate(),
            Err(RgkAssetError::ZeroNftTemplateCommitment)
        ));
    }

    #[test]
    fn nft_mint_issue_binds_collection_template_and_metadata() {
        let owner = RgkOwnerDescriptor::KeyHash([0xc1; 32])
            .derive_commitment()
            .unwrap();
        let spec = nft_token_spec(3, owner);
        let issue = nft_issue(&spec);

        let report = spec.validate_mint_issue(&issue).unwrap();
        assert_eq!(report.token_id, issue.asset_id);
        assert_eq!(report.issue_report.total_supply, 1);
        assert_eq!(report.issue_report.allocation_count, 1);

        let mut wrong_supply = issue.clone();
        wrong_supply.total_supply = 2;
        assert!(matches!(
            spec.validate_mint_issue(&wrong_supply),
            Err(RgkAssetError::NftSupplyMismatch {
                expected: 1,
                actual: 2
            })
        ));

        let mut wrong_metadata = issue.clone();
        wrong_metadata.metadata_commitment.0[0] ^= 1;
        assert!(matches!(
            spec.validate_mint_issue(&wrong_metadata),
            Err(RgkAssetError::NftMetadataMismatch)
        ));

        let mut wrong_token_id = issue;
        wrong_token_id.asset_id[0] ^= 1;
        assert!(matches!(
            spec.validate_mint_issue(&wrong_token_id),
            Err(RgkAssetError::NftAssetMismatch)
        ));
    }

    #[test]
    fn nft_single_token_transfer_preserves_metadata_and_owner_handoff() {
        let previous_owner = RgkOwnerDescriptor::KeyHash([0xd1; 32])
            .derive_commitment()
            .unwrap();
        let new_owner = RgkOwnerDescriptor::CovenantId([0xd2; 32])
            .derive_commitment()
            .unwrap();
        let spec = nft_token_spec(4, previous_owner);
        let issue = nft_issue(&spec);
        let previous_report = issue.validate().unwrap();
        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: previous_owner,
            new_owner_commitment: new_owner,
            ownership_authorization_commitment: [0xd3; 32],
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: vec![allocation(0xd4, 0, 1)],
            burn: None,
            witness_txid: [0xd5; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };

        let report = spec
            .validate_single_token_transfer(&transition, new_owner)
            .unwrap();
        assert_eq!(report.token_id, transition.asset_id);
        assert_eq!(report.transition_report.spent_supply, 1);
        assert_eq!(report.transition_report.new_supply, 1);

        let mut missing_authorization = transition.clone();
        missing_authorization.ownership_authorization_commitment = [0; 32];
        assert!(matches!(
            spec.validate_single_token_transfer(&missing_authorization, new_owner),
            Err(RgkAssetError::ZeroOwnershipAuthorization)
        ));

        let mut changed_metadata = transition.clone();
        changed_metadata.metadata_commitment.0[0] ^= 1;
        assert!(matches!(
            spec.validate_single_token_transfer(&changed_metadata, new_owner),
            Err(RgkAssetError::NftMetadataMismatch)
        ));

        let mut duplicated_output = transition;
        duplicated_output
            .new_allocations
            .push(allocation(0xd6, 1, 1));
        assert!(matches!(
            spec.validate_single_token_transfer(&duplicated_output, new_owner),
            Err(RgkAssetError::NftAllocationShapeMismatch {
                role: "new",
                count: 2
            })
        ));
    }

    #[test]
    fn nft_marketplace_sale_binds_payment_royalty_and_owner_handoff() {
        let seller = RgkOwnerDescriptor::KeyHash([0xf1; 32])
            .derive_commitment()
            .unwrap();
        let buyer = RgkOwnerDescriptor::ScriptHash([0xf2; 32])
            .derive_commitment()
            .unwrap();
        let spec = nft_token_spec(6, seller);
        let issue = nft_issue(&spec);
        let previous_report = issue.validate().unwrap();
        let authorization = [0xf3; 32];
        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: seller,
            new_owner_commitment: buyer,
            ownership_authorization_commitment: authorization,
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: vec![allocation(0xf4, 0, 1)],
            burn: None,
            witness_txid: [0xf5; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };
        let sale_terms = RgkNftMarketplaceSaleTerms {
            chain: spec.collection.chain,
            collection_id: spec.collection.collection_id,
            token_id: spec.token_id().unwrap(),
            seller_owner_commitment: seller,
            buyer_owner_commitment: buyer,
            payment_asset_id: [0xf6; 32],
            price_amount: 120_000,
            royalty_policy_commitment: spec.collection.royalty_policy_commitment,
            royalty_amount: 12_000,
            authorization_commitment: authorization,
        };

        let report = spec
            .validate_marketplace_sale_transition(&transition, sale_terms)
            .unwrap();
        assert_eq!(report.token_id, transition.asset_id);
        assert_eq!(report.transition_report.spent_supply, 1);
        assert_eq!(report.transition_report.new_supply, 1);
        assert_eq!(report.sale_commitment, sale_terms.commitment().unwrap());
        assert_eq!(
            report.token_commitment,
            spec.token_commitment_for_owner(buyer).unwrap()
        );

        let mut changed_price = sale_terms;
        changed_price.price_amount += 1;
        assert_ne!(
            changed_price.commitment().unwrap(),
            report.sale_commitment,
            "sale commitment must bind price"
        );

        let mut excessive_royalty = sale_terms;
        excessive_royalty.royalty_amount = excessive_royalty.price_amount + 1;
        assert!(matches!(
            spec.validate_marketplace_sale_transition(&transition, excessive_royalty),
            Err(RgkAssetError::NftMarketplaceRoyaltyExceedsPrice {
                royalty: 120_001,
                price: 120_000
            })
        ));

        let mut wrong_token = sale_terms;
        wrong_token.token_id[0] ^= 1;
        assert!(matches!(
            spec.validate_marketplace_sale_transition(&transition, wrong_token),
            Err(RgkAssetError::NftMarketplaceTokenMismatch)
        ));

        let mut self_sale = sale_terms;
        self_sale.buyer_owner_commitment = seller;
        assert!(matches!(
            spec.validate_marketplace_sale_transition(&transition, self_sale),
            Err(RgkAssetError::NftMarketplaceSelfSale)
        ));

        let mut wrong_authorization = transition;
        wrong_authorization.ownership_authorization_commitment = [0xf7; 32];
        assert!(matches!(
            spec.validate_marketplace_sale_transition(&wrong_authorization, sale_terms),
            Err(RgkAssetError::NftMarketplaceAuthorizationMismatch)
        ));
    }

    #[test]
    fn nft_burn_lifecycle_closes_token_without_successor_allocation() {
        let owner = RgkOwnerDescriptor::KeyHash([0xe1; 32])
            .derive_commitment()
            .unwrap();
        let spec = nft_token_spec(5, owner);
        let plan = nft_burn_continuation_plan(&spec);

        let continuation_report = spec.validate_token_burn_continuation(&plan).unwrap();
        assert_eq!(continuation_report.token_id, spec.token_id().unwrap());
        assert_eq!(continuation_report.continuation_report.spent_supply, 1);
        assert_eq!(continuation_report.continuation_report.new_supply, 0);
        assert_eq!(continuation_report.continuation_report.burned_supply, 1);
        assert_eq!(
            plan.validate_for_production_zk().unwrap(),
            continuation_report.continuation_report
        );

        let transfer_plan = plan
            .clone()
            .into_production_zk_transfer_plan()
            .expect("NFT terminal burn is a supported 1x0 production-ZK shape");
        assert_eq!(
            transfer_plan.allocation_shape(),
            RgkAllocationProofShape::OneInZeroOut
        );

        let finalized = transfer_plan.finalize([0xe2; 32], 20_000, 3).unwrap();
        assert_eq!(
            finalized.allocation_shape(),
            RgkAllocationProofShape::OneInZeroOut
        );
        assert!(finalized.transition().new_allocations.is_empty());
        let burn_report = spec
            .validate_token_burn_transition(finalized.transition())
            .unwrap();
        assert_eq!(burn_report.token_id, spec.token_id().unwrap());
        assert_eq!(burn_report.transition_report.spent_supply, 1);
        assert_eq!(burn_report.transition_report.new_supply, 0);
        assert_eq!(burn_report.transition_report.burned_supply, 1);
        assert_eq!(
            burn_report.burned_token_commitment,
            continuation_report.burned_token_commitment
        );

        let mut forged_successor = finalized.transition().clone();
        forged_successor
            .new_allocations
            .push(allocation(0xe3, 0, 1));
        assert!(matches!(
            spec.validate_token_burn_transition(&forged_successor),
            Err(RgkAssetError::NftAllocationShapeMismatch {
                role: "burn-new",
                count: 1
            })
        ));

        let mut missing_burn = finalized.transition().clone();
        missing_burn.burn = None;
        assert!(matches!(
            spec.validate_token_burn_transition(&missing_burn),
            Err(RgkAssetError::SupplyDeflationWithoutBurn { spent: 1, new: 0 })
        ));
    }

    #[test]
    fn native_issue_rejects_supply_mismatch() {
        let mut issue = issue();
        issue.allocations[0].amount = 41;
        let err = issue.validate().unwrap_err();
        assert!(matches!(err, RgkAssetError::SupplyMismatch { .. }));
    }

    #[test]
    fn native_issue_rejects_duplicate_seal_outpoint() {
        let mut issue = issue();
        issue.allocations[1].seal.covenant_outpoint = issue.allocations[0].seal.covenant_outpoint;
        let err = issue.validate().unwrap_err();
        assert!(matches!(err, RgkAssetError::DuplicateSealOutpoint { .. }));
    }

    #[test]
    fn native_issue_rejects_mismatched_seal_chain() {
        let mut issue = issue();
        issue.allocations[0].seal.chain = KaspaChainId::KaspaDevnet;
        let err = issue.validate().unwrap_err();
        assert!(matches!(err, RgkAssetError::ChainMismatch { .. }));
    }

    #[test]
    fn native_transition_rejects_ownership_handoff_without_authorization() {
        let mut transition = transition();
        transition.new_owner_commitment = new_owner_commitment();
        let err = transition.validate().unwrap_err();
        assert!(matches!(err, RgkAssetError::ZeroOwnershipAuthorization));
    }

    #[test]
    fn native_transition_binds_authorized_ownership_handoff() {
        let mut transition = transition();
        transition.new_owner_commitment = new_owner_commitment();
        transition.ownership_authorization_commitment = ownership_authorization_commitment();

        let report = transition.validate().unwrap();
        assert_eq!(report.previous_owner_commitment, owner_commitment());
        assert_eq!(report.new_owner_commitment, new_owner_commitment());
        assert_eq!(
            report.ownership_authorization_commitment,
            ownership_authorization_commitment()
        );
        assert_ne!(report.previous_state_digest, report.new_state_digest);

        let mut missing_handoff_auth = transition.clone();
        missing_handoff_auth.ownership_authorization_commitment = [0; 32];
        assert!(matches!(
            missing_handoff_auth.validate(),
            Err(RgkAssetError::ZeroOwnershipAuthorization)
        ));

        let expected_digest = report.transition_digest;
        let mut changed_auth = transition;
        changed_auth.ownership_authorization_commitment[0] ^= 1;
        assert!(matches!(
            changed_auth.validate_against_transition_digest(expected_digest),
            Err(RgkAssetError::TransitionDigestMismatch { .. })
        ));
    }

    #[test]
    fn native_transition_binds_owner_key_rotation_descriptor() {
        let previous_owner = RgkOwnerDescriptor::KeyHash([0x91; 32])
            .derive_commitment()
            .unwrap();
        let next_owner = RgkOwnerDescriptor::KeyHash([0x92; 32])
            .derive_commitment()
            .unwrap();

        let mut issue = issue();
        issue.owner_commitment = previous_owner;
        issue.asset_id = rederive_asset_id(&issue);
        let previous_report = issue.validate().unwrap();

        let transition = RgkTransition {
            chain: issue.chain,
            schema_id: issue.schema_id,
            asset_id: issue.asset_id,
            total_supply: issue.total_supply,
            metadata_commitment: issue.metadata_commitment,
            previous_owner_commitment: previous_owner,
            new_owner_commitment: next_owner,
            ownership_authorization_commitment: ownership_authorization_commitment(),
            previous_state_digest: previous_report.state_digest,
            spent_allocations: issue.allocations,
            new_allocations: next_allocations(),
            burn: None,
            witness_txid: [0x88; 32],
            lane_id: issue.lane_id,
            privacy_policy: issue.privacy_policy,
            proof_policy: issue.proof_policy,
        };

        let report = transition.validate().unwrap();
        assert_eq!(report.previous_owner_commitment, previous_owner);
        assert_eq!(report.new_owner_commitment, next_owner);
        assert_eq!(
            report.ownership_authorization_commitment,
            ownership_authorization_commitment()
        );

        let mut changed_next_owner = transition;
        changed_next_owner.new_owner_commitment = RgkOwnerDescriptor::ScriptHash([0x93; 32])
            .derive_commitment()
            .unwrap();
        changed_next_owner.ownership_authorization_commitment = [0x94; 32];
        assert!(changed_next_owner.validate().is_ok());
    }

    #[test]
    fn native_negative_vectors_fail_expected_digest() {
        let original = issue();
        let expected = original.validate().unwrap().state_digest;

        let mut changed_amount = original.clone();
        changed_amount.allocations[0].amount = 39;
        changed_amount.allocations[1].amount = 61;
        assert!(matches!(
            changed_amount.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));

        let mut changed_note = original.clone();
        changed_note.allocations[0].encrypted_note_commitment[0] ^= 1;
        assert!(matches!(
            changed_note.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));

        let mut changed_policy = original.clone();
        changed_policy.proof_policy = RgkProofPolicy::Hybrid {
            verifier_key_hash: [0x91; 32],
            verifier_key_id: [0x92; 32],
        };
        assert!(matches!(
            changed_policy.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));

        let mut changed_privacy = original;
        changed_privacy.privacy_policy = LanePrivacyPolicy::PublicLineage;
        assert!(matches!(
            changed_privacy.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn proof_policy_downgrade_is_rejected_by_state_digest() {
        let mut original = issue();
        original.proof_policy = RgkProofPolicy::Hybrid {
            verifier_key_hash: [0x91; 32],
            verifier_key_id: [0x92; 32],
        };
        let expected = original.validate().unwrap().state_digest;

        let mut downgraded = original;
        downgraded.proof_policy = RgkProofPolicy::VerifierReceipt {
            verifier_key_hash: [0x91; 32],
        };
        assert!(matches!(
            downgraded.validate_against_state_digest(expected),
            Err(RgkAssetError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn native_transition_digest_stable() {
        let report = transition().validate().unwrap();
        assert_eq!(report.spent_allocation_count, 2);
        assert_eq!(report.new_allocation_count, 2);
        assert_ne!(report.previous_state_digest, report.new_state_digest);
        assert_eq!(
            to_hex(&report.transition_digest.0),
            "e2c1a478a6e12d63e5667aa5904b9f253acf33b2541c34127a17f446eb4acef0"
        );
    }

    #[test]
    fn continuation_phase1_commitment_is_stable_without_future_txid() {
        let report = continuation_plan().validate().unwrap();
        assert_eq!(report.spent_allocation_count, 2);
        assert_eq!(report.new_allocation_count, 2);
        assert_eq!(
            to_hex(&report.commitment.0),
            "f8f750eb9b4078db0dc0be1d45860db86f6e0073ce9b79ab525eb106f7682a12"
        );
    }

    #[test]
    fn continuation_finalization_closes_old_seal_and_creates_new_seal() {
        let plan = continuation_plan();
        let finalized = plan.finalize([0x88; 32], 20_000, 3).unwrap();
        assert_eq!(
            finalized.transition.spent_allocations,
            plan.spent_allocations
        );
        assert_eq!(finalized.transition.new_allocations.len(), 2);
        assert_eq!(
            finalized.transition.new_allocations[0]
                .seal
                .covenant_outpoint
                .transaction_id,
            [0x88; 32]
        );
        assert_eq!(
            finalized.transition.new_allocations[0]
                .seal
                .covenant_outpoint
                .index,
            0
        );
        assert_ne!(
            finalized.transition_report.previous_state_digest,
            finalized.transition_report.new_state_digest
        );
    }

    #[test]
    fn continuation_phase2_binds_actual_txid() {
        let plan = continuation_plan();
        let first = plan.finalize([0x88; 32], 20_000, 3).unwrap();
        let second = plan.finalize([0x89; 32], 20_000, 3).unwrap();
        assert_ne!(
            first.transition_report.transition_digest,
            second.transition_report.transition_digest
        );
    }

    #[test]
    fn continuation_wrong_commitment_is_rejected() {
        let plan = continuation_plan();
        let expected = plan.validate().unwrap().commitment;
        let mut changed = plan;
        changed.new_allocation_shapes[0].amount = 26;
        changed.new_allocation_shapes[1].amount = 74;
        assert!(matches!(
            changed.validate_against_commitment(expected),
            Err(RgkAssetError::ContinuationCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn continuation_replay_reusing_closed_seal_is_rejected() {
        let mut plan = continuation_plan();
        let closed = plan.spent_allocations[0].seal.covenant_outpoint;
        plan.new_allocation_shapes = vec![RgkContinuationAllocationShape {
            output_index: closed.index,
            covenant_id: [0x54; 32],
            amount: 100,
            encrypted_note_commitment: [0x74; 32],
        }];
        let err = plan.finalize(closed.transaction_id, 20_000, 3).unwrap_err();
        assert!(matches!(err, RgkAssetError::ReusedClosedSeal { .. }));
    }

    #[test]
    fn continuation_duplicate_output_shape_is_rejected() {
        let mut plan = continuation_plan();
        plan.new_allocation_shapes[1].output_index = plan.new_allocation_shapes[0].output_index;
        let err = plan.validate().unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::DuplicateContinuationOutput { .. }
        ));
    }

    #[test]
    fn native_transition_rejects_previous_state_mismatch() {
        let mut transition = transition();
        transition.previous_state_digest.0[0] ^= 1;
        let err = transition.validate().unwrap_err();
        assert!(matches!(
            err,
            RgkAssetError::PreviousStateDigestMismatch { .. }
        ));
    }

    #[test]
    fn native_transition_rejects_no_op() {
        let mut transition = transition();
        transition.new_allocations = transition.spent_allocations.clone();
        let err = transition.validate().unwrap_err();
        assert!(matches!(err, RgkAssetError::NoOpTransition));
    }

    #[test]
    fn native_transition_rejects_closed_seal_reuse() {
        let mut transition = transition();
        transition.new_allocations[0].seal.covenant_outpoint =
            transition.spent_allocations[0].seal.covenant_outpoint;
        let err = transition.validate().unwrap_err();
        assert!(matches!(err, RgkAssetError::ReusedClosedSeal { .. }));
    }

    #[test]
    fn native_transition_rejects_supply_inflation_and_deflation() {
        let mut inflated = transition();
        inflated.new_allocations[0].amount = 26;
        assert!(matches!(
            inflated.validate().unwrap_err(),
            RgkAssetError::SupplyInflation {
                spent: 100,
                new: 101
            }
        ));

        let mut deflated = transition();
        deflated.new_allocations[0].amount = 24;
        assert!(matches!(
            deflated.validate().unwrap_err(),
            RgkAssetError::SupplyDeflationWithoutBurn {
                spent: 100,
                new: 99
            }
        ));

        let mut burned = deflated.clone();
        burned.burn = Some(burn_proof(1, 0xa1));
        let report = burned.validate().unwrap();
        assert_eq!(report.spent_supply, 100);
        assert_eq!(report.new_supply, 99);
        assert_eq!(report.burned_supply, 1);
        assert_eq!(burned.validate_for_production_zk().unwrap(), report);

        let mut mismatched_burn = deflated.clone();
        mismatched_burn.burn = Some(burn_proof(2, 0xa1));
        assert!(matches!(
            mismatched_burn.validate().unwrap_err(),
            RgkAssetError::BurnAmountMismatch {
                expected: 1,
                actual: 2
            }
        ));

        let mut zero_amount = deflated.clone();
        zero_amount.burn = Some(burn_proof(0, 0xa1));
        assert!(matches!(
            zero_amount.validate().unwrap_err(),
            RgkAssetError::ZeroBurnAmount
        ));

        let mut zero_authorization = deflated.clone();
        zero_authorization.burn = Some(RgkBurnProof {
            amount: 1,
            authorization_commitment: [0; 32],
        });
        assert!(matches!(
            zero_authorization.validate().unwrap_err(),
            RgkAssetError::ZeroBurnAuthorization
        ));

        let mut changed_authorization = burned.clone();
        changed_authorization.burn = Some(burn_proof(1, 0xa2));
        assert_ne!(
            burned.validate().unwrap().transition_digest,
            changed_authorization.validate().unwrap().transition_digest
        );
    }

    #[test]
    fn continuation_accepts_explicit_burn_for_supported_production_zk_shape() {
        let mut plan = continuation_plan();
        plan.new_allocation_shapes[0].amount = 24;
        plan.burn = Some(burn_proof(1, 0xb1));

        let report = plan.validate().unwrap();
        assert_eq!(report.spent_supply, 100);
        assert_eq!(report.new_supply, 99);
        assert_eq!(report.burned_supply, 1);
        assert_eq!(plan.validate_for_production_zk().unwrap(), report);
        let transfer_plan = plan
            .clone()
            .into_production_zk_transfer_plan()
            .expect("supported burn shape should be production-ZK plannable");
        assert_eq!(
            transfer_plan.allocation_shape(),
            RgkAllocationProofShape::TwoInTwoOut
        );

        let finalized = plan.finalize([0x88; 32], 20_000, 3).unwrap();
        assert_eq!(finalized.transition.burn, Some(burn_proof(1, 0xb1)));
        assert_eq!(finalized.transition_report.spent_supply, 100);
        assert_eq!(finalized.transition_report.new_supply, 99);
        assert_eq!(finalized.transition_report.burned_supply, 1);
        let finalized_for_zk = transfer_plan.finalize([0x88; 32], 20_000, 3).unwrap();
        assert_eq!(finalized_for_zk.transition_report().burned_supply, 1);
    }

    #[test]
    fn native_transition_digest_binds_mutations() {
        let transition = transition();
        let expected = transition.validate().unwrap().transition_digest;

        let mut changed_witness = transition.clone();
        changed_witness.witness_txid[0] ^= 1;
        assert!(matches!(
            changed_witness.validate_against_transition_digest(expected),
            Err(RgkAssetError::TransitionDigestMismatch { .. })
        ));

        let mut changed_input_order = transition.clone();
        changed_input_order.spent_allocations.reverse();
        assert!(matches!(
            changed_input_order.validate_against_transition_digest(expected),
            Err(RgkAssetError::TransitionDigestMismatch { .. })
        ));

        let mut changed_output_order = transition;
        changed_output_order.new_allocations.reverse();
        assert!(matches!(
            changed_output_order.validate_against_transition_digest(expected),
            Err(RgkAssetError::TransitionDigestMismatch { .. })
        ));
    }

    #[test]
    fn private_lane_discovery_and_tags_behave_as_commitments() {
        let asset_id = issue().asset_id;
        let right_key = [0x41; 32];
        let wrong_key = [0x42; 32];
        let lane = derive_blinded_lane_id(right_key, asset_id, 7);
        assert!(discover_lane(right_key, asset_id, 7, lane));
        assert!(!discover_lane(wrong_key, asset_id, 7, lane));

        let tag_7 = RgkScanTag::derive(right_key, lane, 7);
        let tag_8 = RgkScanTag::derive(right_key, lane, 8);
        assert_ne!(tag_7, tag_8);
    }

    #[test]
    fn private_lane_graph_root_binds_ordered_lane_nodes() {
        let asset_id = issue().asset_id;
        let view_key = [0x41; 32];
        let nodes = [
            RgkLaneGraphNode::from_private(view_key, asset_id, 7),
            RgkLaneGraphNode::from_private(view_key, asset_id, 8),
        ];

        assert_eq!(
            nodes[0].lane_id,
            derive_blinded_lane_id(view_key, asset_id, 7)
        );
        assert_eq!(
            nodes[1].scan_tag,
            RgkScanTag::derive(view_key, nodes[1].lane_id, 8)
        );
        assert_ne!(nodes[0].lane_id, nodes[1].lane_id);
        assert_ne!(
            derive_private_lane_graph_root(&nodes[..1]),
            derive_private_lane_graph_root(&nodes)
        );

        let mut reordered = nodes;
        reordered.swap(0, 1);
        assert_ne!(
            derive_private_lane_graph_root(&nodes),
            derive_private_lane_graph_root(&reordered)
        );

        let mut changed_tag = nodes;
        changed_tag[1].scan_tag.0[0] ^= 1;
        assert_ne!(
            derive_private_lane_graph_root(&nodes),
            derive_private_lane_graph_root(&changed_tag)
        );
    }

    #[test]
    fn private_lane_graph_segment_root_binds_chain_and_segment() {
        let asset_id = issue().asset_id;
        let view_key = [0x41; 32];
        let first_segment = [
            RgkLaneGraphNode::from_private(view_key, asset_id, 7),
            RgkLaneGraphNode::from_private(view_key, asset_id, 8),
        ];
        let second_segment = [
            RgkLaneGraphNode::from_private(view_key, asset_id, 9),
            RgkLaneGraphNode::from_private(view_key, asset_id, 10),
        ];
        let empty = private_lane_graph_empty_root();
        let first_root = extend_private_lane_graph_root(empty, 0, &first_segment);
        let second_root = extend_private_lane_graph_root(first_root, 1, &second_segment);

        assert_ne!(empty, first_root);
        assert_ne!(first_root, second_root);
        assert_ne!(
            extend_private_lane_graph_root(empty, 1, &first_segment),
            first_root
        );
        assert_ne!(
            extend_private_lane_graph_root([0x99; 32], 0, &first_segment),
            first_root
        );
        assert_ne!(
            extend_private_lane_graph_root(first_root, 1, &second_segment[..1]),
            second_root
        );

        let mut reordered = second_segment;
        reordered.swap(0, 1);
        assert_ne!(
            extend_private_lane_graph_root(first_root, 1, &reordered),
            second_root
        );

        let mut changed_tag = second_segment;
        changed_tag[0].scan_tag.0[0] ^= 1;
        assert_ne!(
            extend_private_lane_graph_root(first_root, 1, &changed_tag),
            second_root
        );
    }

    #[test]
    fn allocation_transcript_root_binds_native_segment_metadata() {
        let first = allocation(0x22, 0, 40);
        let second = allocation(0x11, 1, 60);
        let allocations = vec![first.clone(), second.clone()];
        let empty_spent = allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent);
        let empty_new = allocation_transcript_empty_root(RgkAllocationTranscriptSide::New);
        let root = extend_allocation_transcript_root(
            empty_spent,
            RgkAllocationTranscriptSide::Spent,
            0,
            2,
            &allocations,
        );

        assert_ne!(empty_spent, empty_new);
        assert_ne!(empty_spent, root);
        assert_ne!(
            extend_allocation_transcript_root(
                empty_new,
                RgkAllocationTranscriptSide::New,
                0,
                2,
                &allocations,
            ),
            root
        );
        assert_ne!(
            extend_allocation_transcript_root(
                empty_spent,
                RgkAllocationTranscriptSide::Spent,
                1,
                2,
                &allocations,
            ),
            root
        );
        assert_ne!(
            extend_allocation_transcript_root(
                [0x99; 32],
                RgkAllocationTranscriptSide::Spent,
                0,
                2,
                &allocations,
            ),
            root
        );
        assert_ne!(
            extend_allocation_transcript_root(
                empty_spent,
                RgkAllocationTranscriptSide::Spent,
                0,
                3,
                &allocations,
            ),
            root
        );

        let mut changed_amount = allocations.clone();
        changed_amount[1].amount += 1;
        assert_ne!(
            extend_allocation_transcript_root(
                empty_spent,
                RgkAllocationTranscriptSide::Spent,
                0,
                2,
                &changed_amount,
            ),
            root
        );
    }

    #[test]
    fn allocation_transcript_root_uses_canonical_allocation_order() {
        let first = allocation(0x22, 0, 40);
        let second = allocation(0x11, 1, 60);
        let forward = vec![first.clone(), second.clone()];
        let reversed = vec![second, first];
        let empty = allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent);

        assert_eq!(
            extend_allocation_transcript_root(
                empty,
                RgkAllocationTranscriptSide::Spent,
                0,
                2,
                &forward,
            ),
            extend_allocation_transcript_root(
                empty,
                RgkAllocationTranscriptSide::Spent,
                0,
                2,
                &reversed,
            )
        );
    }

    #[test]
    fn allocation_transcript_amount_commitment_hides_bound_amount() {
        let commitment = allocation_transcript_amount_commitment(
            RgkAllocationTranscriptSide::Spent,
            0,
            2,
            100,
            [0x51; 32],
        );

        assert_ne!(
            allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::New,
                0,
                2,
                100,
                [0x51; 32],
            ),
            commitment
        );
        assert_ne!(
            allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::Spent,
                1,
                2,
                100,
                [0x51; 32],
            ),
            commitment
        );
        assert_ne!(
            allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::Spent,
                0,
                3,
                100,
                [0x51; 32],
            ),
            commitment
        );
        assert_ne!(
            allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::Spent,
                0,
                2,
                101,
                [0x51; 32],
            ),
            commitment
        );
        assert_ne!(
            allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::Spent,
                0,
                2,
                100,
                [0x52; 32],
            ),
            commitment
        );
    }

    #[test]
    fn nullifier_is_stable_but_unlinked_to_lane_id() {
        let seal = seal(0x33, 0);
        let secret = [0x51; 32];
        let n1 = RgkNullifier::derive(secret, &seal);
        let n2 = RgkNullifier::derive(secret, &seal);
        assert_eq!(n1, n2);
        assert_ne!(n1.0, lane_id());
    }

    #[test]
    fn public_and_private_lane_policies_have_different_visibility() {
        assert!(LanePrivacyPolicy::PublicLineage.exposes_public_fields());
        assert!(!LanePrivacyPolicy::PrivateLane.exposes_public_fields());
        assert_eq!(LanePrivacyPolicy::default(), LanePrivacyPolicy::PrivateLane);
    }

    #[test]
    fn unconstrained_image_id_is_rejected() {
        let policy = RgkProofPolicy::ZkReceipt {
            verifier_key_id: [0x81; 32],
            image_id_policy: ImageIdPolicy::AllowedSet(vec![]),
        };
        assert!(matches!(
            policy.commitment(),
            Err(RgkAssetError::UnconstrainedImageId)
        ));
    }
}
