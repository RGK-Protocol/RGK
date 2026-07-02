//! Real Groth16 prover + verifier for RGK receipts and semantic statements
//! (real-zk feature).
//!
//! Links `ark-groth16` + `ark-bn254` + `ark-relations` and implements a real
//! Groth16 proof path on BN254 with complete stack material for Toccata's
//! `OpZkPrecompile` (same curve, same public-input shape).
//!
//! ## What this circuit proves (v0.x, intentionally narrow)
//!
//! The circuit proves **knowledge of the private canonical receipt body whose
//! domain-tagged SHA-256 digest equals the public `receipt_id`**. The SHA-256
//! computation itself is constrained inside R1CS using arkworks' SHA-256
//! gadget; the resolver still independently re-computes the same digest as a
//! client-local defence-in-depth check.
//!
//! What this gives us concretely:
//! * A real Groth16 proof over BN254.
//! * The full 232-byte `ZkStatement` packed as public BN254 field inputs.
//! * In-circuit equality for the receipt body fields that are present in the
//!   canonical receipt body, plus the receipt-id hash check.
//! * A separate semantic transition circuit whose public input is the 512-byte
//!   `SemanticTransitionStatement`, with in-circuit statement layout checks,
//!   native commitment non-zero checks, old/new state inequality, known-chain
//!   encoding, known privacy-policy encoding, non-zero allocation counts,
//!   metadata/owner commitment binding, and authorised ownership handoff.
//! * Dedicated 1x1/2x2 allocation-vector circuits plus a const-generic
//!   fixed-arity circuit family for native covenant lifecycle shapes. They
//!   reconstruct native allocation roots, state digests, continuation shape
//!   root, continuation commitment, and transition digest from private
//!   canonical allocation witnesses. `AllocationCircuitShape` lists the
//!   currently supported proof shapes.
//! * A bounded private-lane graph circuit that proves several public lane
//!   discovery nodes share one hidden view key and asset id, and that the public
//!   graph root commits to that exact ordered node set.
//! * A segmented private-lane graph circuit that proves an ordered bounded
//!   segment extends a native rolling graph root. Wallets can chain segment
//!   proofs for arbitrary-size lane graphs without claiming one recursive proof.
//! * Segmented allocation transcript, conservation, and exclusion circuits that
//!   let verifiers audit large allocation sides with amount-hiding proof chains
//!   while the production transition proof strategy remains explicitly bounded.
//! * Local prove → verify round-trip that is end-to-end correct.
//!
//! Honest disclosure matters more than a one-line "ZK verified" claim.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

use rgk_asset::{
    allocation_transcript_amount_commitment, derive_blinded_lane_id,
    derive_private_lane_graph_root, extend_allocation_transcript_root,
    extend_private_lane_graph_root, RgkAllocation, RgkAllocationProofShape,
    RgkAllocationTranscriptSide, RgkLaneGraphNode, RgkScanTag, RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW,
    RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT, RGK_ALLOCATION_STRATEGY_ZK_SHAPES,
    RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS,
};
use rgk_core::{
    Bytes32, Canonical, DecodeError, KaspaChainId, KaspaOutpoint, ProofMode, Reader, ReceiptPolicy,
    RgkReceipt, RgkStateCommitment, Writer, MAX_BLOB_BYTES,
};

use crate::SemanticTransitionStatement;

/// ZK tag byte for Groth16 on BN254. Matches `kaspa_txscript::zk_precompiles::tags::ZkTag::Groth16`.
pub const ZK_TAG_GROTH16: u8 = 0x20;
const PUBLIC_INPUT_LEN: usize = 232;
const SEMANTIC_PUBLIC_INPUT_LEN: usize = SemanticTransitionStatement::PUBLIC_INPUT_LEN;
const PUBLIC_OLD_STATE_FRS: core::ops::Range<usize> = 0..4;
const PUBLIC_NEW_STATE_FRS: core::ops::Range<usize> = 4..8;
const PUBLIC_COVENANT_FRS: core::ops::Range<usize> = 12..16;
const PUBLIC_RECEIPT_ID_FRS: core::ops::Range<usize> = 17..21;
const PUBLIC_TRANSITION_FRS: core::ops::Range<usize> = 21..25;
const PUBLIC_CONTINUATION_FRS: core::ops::Range<usize> = 25..29;
const ALLOCATION_WITNESS_LEN: usize = 157;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct BurnDigestEncoding {
    amount: [u8; 8],
    authorization_commitment: Bytes32,
}

fn burn_digest_encoding(
    public_inputs: &[u8],
) -> Result<Option<BurnDigestEncoding>, SynthesisError> {
    if public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&public_inputs[472..480]);
    let mut authorization_commitment = [0u8; 32];
    authorization_commitment.copy_from_slice(&public_inputs[480..512]);

    let amount_is_zero = amount.iter().all(|byte| *byte == 0);
    let authorization_is_zero = authorization_commitment.iter().all(|byte| *byte == 0);
    match (amount_is_zero, authorization_is_zero) {
        (true, true) => Ok(None),
        (true, false) | (false, true) => Err(SynthesisError::Unsatisfiable),
        (false, false) => Ok(Some(BurnDigestEncoding {
            amount,
            authorization_commitment,
        })),
    }
}
const ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN: usize = 128;
const ALLOCATION_CONSERVATION_SEGMENT_PUBLIC_INPUT_LEN: usize = 192;
const ALLOCATION_CONSERVATION_FINAL_PUBLIC_INPUT_LEN: usize = 80;
const ALLOCATION_EXCLUSION_SEGMENT_PAIR_PUBLIC_INPUT_LEN: usize = 232;
const ALLOCATION_AUDIT_CERTIFICATE_MAGIC: &[u8; 8] = b"rgk:aac1";
const MAX_ALLOCATION_AUDIT_CERTIFICATE_PROOF_ENTRIES: usize = 16_384;
const MAX_ALLOCATION_AUDIT_STACK_PUBLIC_INPUTS: usize = 8_192;
const LANE_DISCOVERY_PUBLIC_INPUT_LEN: usize = LaneDiscoveryStatement::PUBLIC_INPUT_LEN;
const LANE_GRAPH_DISCOVERY_ROOT_LEN: usize = 32;
const LANE_GRAPH_SEGMENT_PREFIX_LEN: usize = 72;

struct ReceiptBodyOffsets {
    covenant: usize,
    old_state: usize,
    new_state: usize,
    transition: usize,
    continuation: usize,
}

/// R1CS circuit: prove that the prover knows the canonical receipt body whose
/// `SHA256(domain_tag_len || domain_tag || body)` equals the public
/// `receipt_id`.
#[derive(Clone)]
pub struct ReceiptCircuit {
    /// Public inputs (232 bytes; layout matches `ZkStatement::public_inputs`).
    pub public_inputs: Vec<u8>,
    /// Private witness (the canonical receipt body).
    pub witness: Vec<u8>,
}

impl ReceiptCircuit {
    pub fn from_receipt(receipt: &RgkReceipt, receipt_id: Bytes32) -> Self {
        let mut public_inputs = Vec::with_capacity(PUBLIC_INPUT_LEN);
        public_inputs.extend_from_slice(&receipt.old_state.state_digest);
        public_inputs.extend_from_slice(&receipt.new_state.state_digest);
        public_inputs.extend_from_slice(&receipt.old_state.asset_id);
        public_inputs.extend_from_slice(&receipt.covenant_id);
        let tag = u32::from(KaspaChainId::TAG);
        let val = u32::from(receipt.chain_id as u8);
        public_inputs.extend_from_slice(&tag.to_le_bytes());
        public_inputs.extend_from_slice(&val.to_le_bytes());
        public_inputs.extend_from_slice(&receipt_id);
        public_inputs.extend_from_slice(&receipt.transition_digest);
        public_inputs.extend_from_slice(&receipt.continuation_commitment);
        // Witness is the canonical receipt body (without magic + version
        // header). The receipt_commitment is `SHA256(domain_tag || body)`.
        let witness = receipt.encode_body();
        Self {
            public_inputs,
            witness,
        }
    }
}

/// R1CS circuit for RGK's canonical 512-byte semantic transition statement.
///
/// The statement itself is public. The private witness repeats the same
/// canonical byte layout so the circuit can constrain statement-level
/// invariants rather than accepting arbitrary public bytes.
#[derive(Clone)]
pub struct SemanticTransitionCircuit {
    /// Public inputs (512 bytes; layout matches
    /// `SemanticTransitionStatement::public_inputs`).
    pub public_inputs: Vec<u8>,
    /// Private witness with the same canonical statement bytes.
    pub witness: Vec<u8>,
}

/// Public statement for bounded private-lane discovery.
///
/// Public inputs are:
///
/// * blinded lane id (32 bytes)
/// * scan tag (32 bytes)
/// * epoch (8 bytes, little-endian)
///
/// The private witness carries the view key and asset id. The circuit proves
/// that both native lane commitments were derived with the same hidden view
/// key and the public epoch:
///
/// * `derive_blinded_lane_id(view_key, asset_id, epoch) == lane_id`
/// * `RgkScanTag::derive(view_key, lane_id, epoch) == scan_tag`
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneDiscoveryStatement {
    pub lane_id: Bytes32,
    pub scan_tag: Bytes32,
    pub epoch: u64,
}

impl LaneDiscoveryStatement {
    pub const PUBLIC_INPUT_LEN: usize = 72;

    pub const fn new(lane_id: Bytes32, scan_tag: Bytes32, epoch: u64) -> Self {
        Self {
            lane_id,
            scan_tag,
            epoch,
        }
    }

    pub fn from_private(view_key: Bytes32, asset_id: Bytes32, epoch: u64) -> Self {
        let lane_id = derive_blinded_lane_id(view_key, asset_id, epoch);
        let scan_tag = RgkScanTag::derive(view_key, lane_id, epoch).to_bytes();
        Self::new(lane_id, scan_tag, epoch)
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.lane_id);
        out.extend_from_slice(&self.scan_tag);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
    }

    pub fn matches_witness(&self, witness: &LaneDiscoveryWitness) -> bool {
        self == &Self::from_private(witness.view_key, witness.asset_id, self.epoch)
    }
}

/// Private witness for bounded private-lane discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneDiscoveryWitness {
    pub view_key: Bytes32,
    pub asset_id: Bytes32,
}

/// R1CS circuit for RGK private-lane discovery.
///
/// This is deliberately a narrow discovery proof. It proves the native
/// lane-id and scan-tag derivations in-circuit; it does not claim to prove the
/// full private lane graph or arbitrary allocation-vector privacy semantics.
#[derive(Clone)]
pub struct LaneDiscoveryCircuit {
    pub public_inputs: Vec<u8>,
    pub witness: LaneDiscoveryWitness,
}

impl LaneDiscoveryCircuit {
    pub fn from_statement_and_witness(
        statement: &LaneDiscoveryStatement,
        witness: LaneDiscoveryWitness,
    ) -> Result<Self, String> {
        if !statement.matches_witness(&witness) {
            return Err(
                "lane discovery witness does not derive the public lane id and scan tag"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            witness,
        })
    }
}

/// Public statement for a bounded private-lane graph discovery proof.
///
/// Public inputs are:
///
/// * graph root (32 bytes), computed by the native asset crate over the ordered
///   lane-node set
/// * `LANES` lane discovery nodes, each encoded as lane id, scan tag, and epoch
///
/// The private witness carries one view key and one asset id. The circuit proves
/// that every public lane node is derived from the same hidden pair and that the
/// graph root commits to the exact ordered public node set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneGraphDiscoveryStatement<const LANES: usize> {
    pub graph_root: Bytes32,
    pub nodes: [LaneDiscoveryStatement; LANES],
}

impl<const LANES: usize> LaneGraphDiscoveryStatement<LANES> {
    pub const PUBLIC_INPUT_LEN: usize =
        LANE_GRAPH_DISCOVERY_ROOT_LEN + LANES * LaneDiscoveryStatement::PUBLIC_INPUT_LEN;

    pub fn from_private(view_key: Bytes32, asset_id: Bytes32, epochs: [u64; LANES]) -> Self {
        let nodes =
            epochs.map(|epoch| LaneDiscoveryStatement::from_private(view_key, asset_id, epoch));
        let native_nodes = Self::native_nodes_from(&nodes);
        Self {
            graph_root: derive_private_lane_graph_root(&native_nodes),
            nodes,
        }
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.graph_root);
        for node in &self.nodes {
            out.extend_from_slice(&node.public_inputs());
        }
        out
    }

    pub fn matches_witness(&self, witness: &LaneDiscoveryWitness) -> bool {
        if LANES == 0 {
            return false;
        }
        let native_nodes = Self::native_nodes_from(&self.nodes);
        self.graph_root == derive_private_lane_graph_root(&native_nodes)
            && self.nodes.iter().all(|node| node.matches_witness(witness))
    }

    pub fn native_nodes(&self) -> [RgkLaneGraphNode; LANES] {
        Self::native_nodes_from(&self.nodes)
    }

    fn native_nodes_from(nodes: &[LaneDiscoveryStatement; LANES]) -> [RgkLaneGraphNode; LANES] {
        core::array::from_fn(|index| RgkLaneGraphNode {
            lane_id: nodes[index].lane_id,
            scan_tag: RgkScanTag::from_bytes_unchecked(nodes[index].scan_tag),
            epoch: nodes[index].epoch,
        })
    }
}

/// R1CS circuit for bounded private-lane graph discovery.
#[derive(Clone)]
pub struct LaneGraphDiscoveryCircuit<const LANES: usize> {
    pub public_inputs: Vec<u8>,
    pub witness: LaneDiscoveryWitness,
}

impl<const LANES: usize> LaneGraphDiscoveryCircuit<LANES> {
    pub fn from_statement_and_witness(
        statement: &LaneGraphDiscoveryStatement<LANES>,
        witness: LaneDiscoveryWitness,
    ) -> Result<Self, String> {
        if LANES == 0 {
            return Err("lane graph discovery requires at least one lane node".to_string());
        }
        if !statement.matches_witness(&witness) {
            return Err(
                "lane graph discovery witness does not derive the public graph nodes and root"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            witness,
        })
    }
}

/// Public statement for one bounded segment in an arbitrary-size private-lane
/// graph proof chain.
///
/// Public inputs are:
///
/// * previous rolling graph root
/// * next rolling graph root
/// * segment index
/// * `LANES` ordered lane nodes, each encoded as lane id, scan tag, and epoch
///
/// A verifier can accept an arbitrary-size graph by checking a contiguous chain
/// of these segment proofs from the empty root to the advertised final root.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaneGraphSegmentStatement<const LANES: usize> {
    pub previous_root: Bytes32,
    pub next_root: Bytes32,
    pub segment_index: u64,
    pub nodes: [LaneDiscoveryStatement; LANES],
}

impl<const LANES: usize> LaneGraphSegmentStatement<LANES> {
    pub const PUBLIC_INPUT_LEN: usize =
        LANE_GRAPH_SEGMENT_PREFIX_LEN + LANES * LaneDiscoveryStatement::PUBLIC_INPUT_LEN;

    pub fn from_private(
        view_key: Bytes32,
        asset_id: Bytes32,
        previous_root: Bytes32,
        segment_index: u64,
        epochs: [u64; LANES],
    ) -> Self {
        let nodes =
            epochs.map(|epoch| LaneDiscoveryStatement::from_private(view_key, asset_id, epoch));
        let native_nodes = Self::native_nodes_from(&nodes);
        Self {
            previous_root,
            next_root: extend_private_lane_graph_root(previous_root, segment_index, &native_nodes),
            segment_index,
            nodes,
        }
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.previous_root);
        out.extend_from_slice(&self.next_root);
        out.extend_from_slice(&self.segment_index.to_le_bytes());
        for node in &self.nodes {
            out.extend_from_slice(&node.public_inputs());
        }
        out
    }

    pub fn matches_witness(&self, witness: &LaneDiscoveryWitness) -> bool {
        if LANES == 0 {
            return false;
        }
        let native_nodes = Self::native_nodes_from(&self.nodes);
        self.next_root
            == extend_private_lane_graph_root(self.previous_root, self.segment_index, &native_nodes)
            && self.nodes.iter().all(|node| node.matches_witness(witness))
    }

    pub fn native_nodes(&self) -> [RgkLaneGraphNode; LANES] {
        Self::native_nodes_from(&self.nodes)
    }

    fn native_nodes_from(nodes: &[LaneDiscoveryStatement; LANES]) -> [RgkLaneGraphNode; LANES] {
        core::array::from_fn(|index| RgkLaneGraphNode {
            lane_id: nodes[index].lane_id,
            scan_tag: RgkScanTag::from_bytes_unchecked(nodes[index].scan_tag),
            epoch: nodes[index].epoch,
        })
    }
}

/// R1CS circuit for one bounded private-lane graph segment.
#[derive(Clone)]
pub struct LaneGraphSegmentCircuit<const LANES: usize> {
    pub public_inputs: Vec<u8>,
    pub witness: LaneDiscoveryWitness,
}

impl<const LANES: usize> LaneGraphSegmentCircuit<LANES> {
    pub fn from_statement_and_witness(
        statement: &LaneGraphSegmentStatement<LANES>,
        witness: LaneDiscoveryWitness,
    ) -> Result<Self, String> {
        if LANES == 0 {
            return Err("lane graph segment requires at least one lane node".to_string());
        }
        if !statement.matches_witness(&witness) {
            return Err(
                "lane graph segment witness does not derive the public segment nodes and root"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            witness,
        })
    }
}

impl SemanticTransitionCircuit {
    pub fn from_statement(statement: &SemanticTransitionStatement) -> Self {
        let public_inputs = statement.public_inputs();
        let witness = public_inputs.clone();
        Self {
            public_inputs,
            witness,
        }
    }
}

/// Private canonical allocation witness for a terminal one-input/zero-output
/// burn. The transition witness txid is explicit because no successor
/// allocation exists to carry it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneInZeroOutAllocationWitness {
    pub spent_allocation: Vec<u8>,
    pub transition_witness_txid: Bytes32,
}

impl OneInZeroOutAllocationWitness {
    pub fn new(
        spent_allocation: Vec<u8>,
        transition_witness_txid: Bytes32,
    ) -> Result<Self, String> {
        if spent_allocation.len() != ALLOCATION_WITNESS_LEN {
            return Err(format!(
                "expected {ALLOCATION_WITNESS_LEN}-byte spent allocation witness, got {}",
                spent_allocation.len()
            ));
        }
        if transition_witness_txid.iter().all(|byte| *byte == 0) {
            return Err("expected non-zero terminal burn transition witness txid".to_string());
        }
        Ok(Self {
            spent_allocation,
            transition_witness_txid,
        })
    }

    pub fn from_allocation(
        spent: &RgkAllocation,
        transition_witness_txid: Bytes32,
    ) -> Result<Self, String> {
        Self::new(encode_native_allocation(spent), transition_witness_txid)
    }
}

/// Private canonical allocation witnesses for the current one-input/one-output
/// native transition circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneInOneOutAllocationWitness {
    pub spent_allocation: Vec<u8>,
    pub new_allocation: Vec<u8>,
}

impl OneInOneOutAllocationWitness {
    pub fn new(spent_allocation: Vec<u8>, new_allocation: Vec<u8>) -> Result<Self, String> {
        if spent_allocation.len() != ALLOCATION_WITNESS_LEN {
            return Err(format!(
                "expected {ALLOCATION_WITNESS_LEN}-byte spent allocation witness, got {}",
                spent_allocation.len()
            ));
        }
        if new_allocation.len() != ALLOCATION_WITNESS_LEN {
            return Err(format!(
                "expected {ALLOCATION_WITNESS_LEN}-byte new allocation witness, got {}",
                new_allocation.len()
            ));
        }
        Ok(Self {
            spent_allocation,
            new_allocation,
        })
    }

    pub fn from_allocations(spent: &RgkAllocation, new: &RgkAllocation) -> Result<Self, String> {
        Self::new(
            encode_native_allocation(spent),
            encode_native_allocation(new),
        )
    }
}

/// Private canonical allocation witnesses for the two-input/two-output native
/// transition circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwoInTwoOutAllocationWitness {
    pub spent_allocations: [Vec<u8>; 2],
    pub new_allocations: [Vec<u8>; 2],
}

impl TwoInTwoOutAllocationWitness {
    pub fn new(
        spent_allocations: [Vec<u8>; 2],
        new_allocations: [Vec<u8>; 2],
    ) -> Result<Self, String> {
        for (index, allocation) in spent_allocations.iter().enumerate() {
            if allocation.len() != ALLOCATION_WITNESS_LEN {
                return Err(format!(
                    "expected {ALLOCATION_WITNESS_LEN}-byte spent allocation witness {index}, got {}",
                    allocation.len()
                ));
            }
        }
        for (index, allocation) in new_allocations.iter().enumerate() {
            if allocation.len() != ALLOCATION_WITNESS_LEN {
                return Err(format!(
                    "expected {ALLOCATION_WITNESS_LEN}-byte new allocation witness {index}, got {}",
                    allocation.len()
                ));
            }
        }
        Ok(Self {
            spent_allocations,
            new_allocations,
        })
    }

    pub fn from_allocations(
        spent: [&RgkAllocation; 2],
        new: [&RgkAllocation; 2],
    ) -> Result<Self, String> {
        Self::new(
            [
                encode_native_allocation(spent[0]),
                encode_native_allocation(spent[1]),
            ],
            [
                encode_native_allocation(new[0]),
                encode_native_allocation(new[1]),
            ],
        )
    }
}

/// Private canonical allocation witnesses for any fixed native transition
/// arity.
///
/// Groth16 still needs one setup per concrete circuit shape. This generic type
/// removes the old hand-written circuit-per-arity pattern while preserving
/// explicit, reviewable fixed shapes such as 3-input/2-output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedAllocationVectorWitness<const SPENT: usize, const NEW: usize> {
    pub spent_allocations: [Vec<u8>; SPENT],
    pub new_allocations: [Vec<u8>; NEW],
}

impl<const SPENT: usize, const NEW: usize> FixedAllocationVectorWitness<SPENT, NEW> {
    pub fn new(
        spent_allocations: [Vec<u8>; SPENT],
        new_allocations: [Vec<u8>; NEW],
    ) -> Result<Self, String> {
        if SPENT == 0 || NEW == 0 {
            return Err(
                "allocation-vector witnesses require at least one spent and one new allocation"
                    .to_string(),
            );
        }
        for (index, allocation) in spent_allocations.iter().enumerate() {
            if allocation.len() != ALLOCATION_WITNESS_LEN {
                return Err(format!(
                    "expected {ALLOCATION_WITNESS_LEN}-byte spent allocation witness {index}, got {}",
                    allocation.len()
                ));
            }
        }
        for (index, allocation) in new_allocations.iter().enumerate() {
            if allocation.len() != ALLOCATION_WITNESS_LEN {
                return Err(format!(
                    "expected {ALLOCATION_WITNESS_LEN}-byte new allocation witness {index}, got {}",
                    allocation.len()
                ));
            }
        }
        Ok(Self {
            spent_allocations,
            new_allocations,
        })
    }

    pub fn from_allocations(
        spent: [&RgkAllocation; SPENT],
        new: [&RgkAllocation; NEW],
    ) -> Result<Self, String> {
        Self::new(
            spent.map(encode_native_allocation),
            new.map(encode_native_allocation),
        )
    }
}

/// R1CS circuit for RGK's current one-input/one-output allocation-vector
/// transition.
///
/// The public input is the same 512-byte `SemanticTransitionStatement`. The
/// private witness contains the canonical spent allocation and finalised new
/// allocation. The circuit reconstructs the native roots and transition
/// digests from those witness allocations.
#[derive(Clone)]
pub struct OneInZeroOutAllocationCircuit {
    pub public_inputs: Vec<u8>,
    pub statement_witness: Vec<u8>,
    pub allocation_witness: OneInZeroOutAllocationWitness,
}

impl OneInZeroOutAllocationCircuit {
    pub fn from_statement_and_witness(
        statement: &SemanticTransitionStatement,
        allocation_witness: OneInZeroOutAllocationWitness,
    ) -> Result<Self, String> {
        let public_inputs = statement.public_inputs();
        if public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN {
            return Err(format!(
                "expected {SEMANTIC_PUBLIC_INPUT_LEN}-byte semantic statement, got {}",
                public_inputs.len()
            ));
        }
        Ok(Self {
            statement_witness: public_inputs.clone(),
            public_inputs,
            allocation_witness,
        })
    }
}

#[derive(Clone)]
pub struct OneInOneOutAllocationCircuit {
    pub public_inputs: Vec<u8>,
    pub statement_witness: Vec<u8>,
    pub allocation_witness: OneInOneOutAllocationWitness,
}

impl OneInOneOutAllocationCircuit {
    pub fn from_statement_and_witness(
        statement: &SemanticTransitionStatement,
        allocation_witness: OneInOneOutAllocationWitness,
    ) -> Result<Self, String> {
        let public_inputs = statement.public_inputs();
        if public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN {
            return Err(format!(
                "expected {SEMANTIC_PUBLIC_INPUT_LEN}-byte semantic statement, got {}",
                public_inputs.len()
            ));
        }
        Ok(Self {
            statement_witness: public_inputs.clone(),
            public_inputs,
            allocation_witness,
        })
    }
}

/// R1CS circuit for RGK's two-input/two-output allocation-vector transition.
///
/// The public input is the same 512-byte `SemanticTransitionStatement`. The
/// private witness contains canonical ordered spent allocations and finalised
/// new allocations.
#[derive(Clone)]
pub struct TwoInTwoOutAllocationCircuit {
    pub public_inputs: Vec<u8>,
    pub statement_witness: Vec<u8>,
    pub allocation_witness: TwoInTwoOutAllocationWitness,
}

impl TwoInTwoOutAllocationCircuit {
    pub fn from_statement_and_witness(
        statement: &SemanticTransitionStatement,
        allocation_witness: TwoInTwoOutAllocationWitness,
    ) -> Result<Self, String> {
        let public_inputs = statement.public_inputs();
        if public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN {
            return Err(format!(
                "expected {SEMANTIC_PUBLIC_INPUT_LEN}-byte semantic statement, got {}",
                public_inputs.len()
            ));
        }
        Ok(Self {
            statement_witness: public_inputs.clone(),
            public_inputs,
            allocation_witness,
        })
    }
}

/// R1CS circuit family for RGK's fixed-arity allocation-vector transitions.
///
/// Each concrete `SPENT`/`NEW` pair is a distinct Groth16 setup shape. The
/// generic implementation reconstructs the same native RGK roots and digests
/// as the dedicated 1x1 and 2x2 circuits.
#[derive(Clone)]
pub struct FixedAllocationVectorCircuit<const SPENT: usize, const NEW: usize> {
    pub public_inputs: Vec<u8>,
    pub statement_witness: Vec<u8>,
    pub allocation_witness: FixedAllocationVectorWitness<SPENT, NEW>,
}

impl<const SPENT: usize, const NEW: usize> FixedAllocationVectorCircuit<SPENT, NEW> {
    pub fn from_statement_and_witness(
        statement: &SemanticTransitionStatement,
        allocation_witness: FixedAllocationVectorWitness<SPENT, NEW>,
    ) -> Result<Self, String> {
        let public_inputs = statement.public_inputs();
        if public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN {
            return Err(format!(
                "expected {SEMANTIC_PUBLIC_INPUT_LEN}-byte semantic statement, got {}",
                public_inputs.len()
            ));
        }
        if SPENT == 0 || NEW == 0 {
            return Err(
                "allocation-vector circuits require at least one spent and one new allocation"
                    .to_string(),
            );
        }
        Ok(Self {
            statement_witness: public_inputs.clone(),
            public_inputs,
            allocation_witness,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllocationTranscriptSegmentStatement<const ALLOCS: usize> {
    pub previous_root: Bytes32,
    pub next_root: Bytes32,
    pub chain_id: KaspaChainId,
    pub side: RgkAllocationTranscriptSide,
    pub segment_index: u64,
    pub total_count: u64,
    pub segment_amount_commitment: Bytes32,
}

impl<const ALLOCS: usize> AllocationTranscriptSegmentStatement<ALLOCS> {
    pub const PUBLIC_INPUT_LEN: usize = ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN;

    pub fn from_allocations(
        previous_root: Bytes32,
        side: RgkAllocationTranscriptSide,
        segment_index: u64,
        total_count: u64,
        allocations: &[RgkAllocation],
        amount_blinding: Bytes32,
    ) -> Result<Self, String> {
        if ALLOCS == 0 {
            return Err(
                "allocation transcript segment requires at least one allocation".to_string(),
            );
        }
        if allocations.len() != ALLOCS {
            return Err(format!(
                "expected {ALLOCS} allocation transcript witnesses, got {}",
                allocations.len()
            ));
        }
        if total_count < ALLOCS as u64 {
            return Err(format!(
                "total allocation count {total_count} is smaller than segment length {ALLOCS}"
            ));
        }

        let chain_id = allocations[0].anchor.chain;
        if allocations
            .iter()
            .any(|allocation| allocation.anchor.chain != chain_id)
        {
            return Err("allocation transcript segment contains mixed chain ids".to_string());
        }
        let segment_amount = allocations.iter().try_fold(0u64, |sum, allocation| {
            sum.checked_add(allocation.amount)
                .ok_or_else(|| "allocation transcript segment amount overflow".to_string())
        })?;
        if segment_amount == 0 {
            return Err("allocation transcript segment amount must be non-zero".to_string());
        }

        Ok(Self {
            previous_root,
            next_root: extend_allocation_transcript_root(
                previous_root,
                side,
                segment_index,
                total_count,
                allocations,
            ),
            chain_id,
            side,
            segment_index,
            total_count,
            segment_amount_commitment: allocation_transcript_amount_commitment(
                side,
                segment_index,
                total_count,
                segment_amount,
                amount_blinding,
            ),
        })
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.previous_root);
        out.extend_from_slice(&self.next_root);
        let tag = u32::from(KaspaChainId::TAG);
        let value = u32::from(self.chain_id as u8);
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out.push(self.side.as_u8());
        out.extend_from_slice(&[0u8; 7]);
        out.extend_from_slice(&self.segment_index.to_le_bytes());
        out.extend_from_slice(&self.total_count.to_le_bytes());
        out.extend_from_slice(&self.segment_amount_commitment);
        out
    }

    pub fn matches_witness(&self, witness: &AllocationTranscriptSegmentWitness<ALLOCS>) -> bool {
        if ALLOCS == 0 {
            return false;
        }
        if witness
            .allocations
            .iter()
            .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
        {
            return false;
        }
        if witness
            .allocations
            .iter()
            .any(|allocation| allocation[0] != self.chain_id as u8)
        {
            return false;
        }
        let Some(segment_amount) = witness
            .allocations
            .iter()
            .try_fold(0u64, |sum, allocation| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&allocation[117..125]);
                sum.checked_add(u64::from_le_bytes(bytes))
            })
        else {
            return false;
        };
        segment_amount == witness.segment_amount
            && self.segment_amount_commitment
                == allocation_transcript_amount_commitment(
                    self.side,
                    self.segment_index,
                    self.total_count,
                    witness.segment_amount,
                    witness.amount_blinding,
                )
            && self.next_root
                == allocation_transcript_segment_root_from_witness(
                    self.previous_root,
                    self.side,
                    self.segment_index,
                    self.total_count,
                    &witness.allocations,
                )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationTranscriptSegmentWitness<const ALLOCS: usize> {
    pub allocations: [Vec<u8>; ALLOCS],
    pub segment_amount: u64,
    pub amount_blinding: Bytes32,
}

impl<const ALLOCS: usize> AllocationTranscriptSegmentWitness<ALLOCS> {
    pub fn new(
        allocations: [Vec<u8>; ALLOCS],
        segment_amount: u64,
        amount_blinding: Bytes32,
    ) -> Result<Self, String> {
        if ALLOCS == 0 {
            return Err(
                "allocation transcript segment requires at least one allocation".to_string(),
            );
        }
        for (index, allocation) in allocations.iter().enumerate() {
            if allocation.len() != ALLOCATION_WITNESS_LEN {
                return Err(format!(
                    "expected {ALLOCATION_WITNESS_LEN}-byte allocation transcript witness {index}, got {}",
                    allocation.len()
                ));
            }
        }
        if segment_amount == 0 {
            return Err("allocation transcript segment amount must be non-zero".to_string());
        }
        Ok(Self {
            allocations,
            segment_amount,
            amount_blinding,
        })
    }

    pub fn from_allocations(
        allocations: &[RgkAllocation],
        amount_blinding: Bytes32,
    ) -> Result<Self, String> {
        if allocations.len() != ALLOCS {
            return Err(format!(
                "expected {ALLOCS} allocation transcript witnesses, got {}",
                allocations.len()
            ));
        }
        let segment_amount = allocations.iter().try_fold(0u64, |sum, allocation| {
            sum.checked_add(allocation.amount)
                .ok_or_else(|| "allocation transcript segment amount overflow".to_string())
        })?;
        let mut ordered: Vec<&RgkAllocation> = allocations.iter().collect();
        ordered.sort_by_key(|allocation| allocation_sort_key(allocation));
        Self::new(
            core::array::from_fn(|index| encode_native_allocation(ordered[index])),
            segment_amount,
            amount_blinding,
        )
    }
}

#[derive(Clone)]
pub struct AllocationTranscriptSegmentCircuit<const ALLOCS: usize> {
    pub public_inputs: Vec<u8>,
    pub allocation_witness: AllocationTranscriptSegmentWitness<ALLOCS>,
}

impl<const ALLOCS: usize> AllocationTranscriptSegmentCircuit<ALLOCS> {
    pub fn from_statement_and_witness(
        statement: &AllocationTranscriptSegmentStatement<ALLOCS>,
        allocation_witness: AllocationTranscriptSegmentWitness<ALLOCS>,
    ) -> Result<Self, String> {
        if !statement.matches_witness(&allocation_witness) {
            return Err(
                "allocation transcript witness does not match the public segment root and amount"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            allocation_witness,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllocationConservationSegmentStatement<const ALLOCS: usize> {
    pub transcript: AllocationTranscriptSegmentStatement<ALLOCS>,
    pub previous_total_commitment: Bytes32,
    pub next_total_commitment: Bytes32,
}

impl<const ALLOCS: usize> AllocationConservationSegmentStatement<ALLOCS> {
    pub const PUBLIC_INPUT_LEN: usize = ALLOCATION_CONSERVATION_SEGMENT_PUBLIC_INPUT_LEN;

    #[allow(clippy::too_many_arguments)]
    pub fn from_allocations(
        previous_root: Bytes32,
        side: RgkAllocationTranscriptSide,
        segment_index: u64,
        total_count: u64,
        previous_running_total: u64,
        allocations: &[RgkAllocation],
        amount_blinding: Bytes32,
        previous_total_blinding: Bytes32,
        next_total_blinding: Bytes32,
    ) -> Result<Self, String> {
        if previous_total_blinding == [0u8; 32] || next_total_blinding == [0u8; 32] {
            return Err(
                "allocation conservation running total blindings must be non-zero".to_string(),
            );
        }
        if segment_index == 0 && previous_running_total != 0 {
            return Err("initial allocation conservation segment must start from zero".to_string());
        }
        let transcript = AllocationTranscriptSegmentStatement::<ALLOCS>::from_allocations(
            previous_root,
            side,
            segment_index,
            total_count,
            allocations,
            amount_blinding,
        )?;
        let segment_amount = allocation_amount_sum(allocations)?;
        let next_running_total = previous_running_total
            .checked_add(segment_amount)
            .ok_or_else(|| "allocation conservation running total overflow".to_string())?;
        Ok(Self {
            previous_total_commitment: allocation_conservation_total_commitment(
                side,
                total_count,
                previous_running_total,
                previous_total_blinding,
            ),
            next_total_commitment: allocation_conservation_total_commitment(
                side,
                total_count,
                next_running_total,
                next_total_blinding,
            ),
            transcript,
        })
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.transcript.public_inputs());
        out.extend_from_slice(&self.previous_total_commitment);
        out.extend_from_slice(&self.next_total_commitment);
        out
    }

    pub fn matches_witness(&self, witness: &AllocationConservationSegmentWitness<ALLOCS>) -> bool {
        allocation_conservation_segment_matches(self, witness)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationConservationSegmentWitness<const ALLOCS: usize> {
    pub transcript: AllocationTranscriptSegmentWitness<ALLOCS>,
    pub previous_total: u64,
    pub next_total: u64,
    pub previous_total_blinding: Bytes32,
    pub next_total_blinding: Bytes32,
}

impl<const ALLOCS: usize> AllocationConservationSegmentWitness<ALLOCS> {
    pub fn from_allocations(
        previous_running_total: u64,
        allocations: &[RgkAllocation],
        amount_blinding: Bytes32,
        previous_total_blinding: Bytes32,
        next_total_blinding: Bytes32,
    ) -> Result<Self, String> {
        if previous_total_blinding == [0u8; 32] || next_total_blinding == [0u8; 32] {
            return Err(
                "allocation conservation running total blindings must be non-zero".to_string(),
            );
        }
        let segment_amount = allocation_amount_sum(allocations)?;
        let next_total = previous_running_total
            .checked_add(segment_amount)
            .ok_or_else(|| "allocation conservation running total overflow".to_string())?;
        Ok(Self {
            transcript: AllocationTranscriptSegmentWitness::from_allocations(
                allocations,
                amount_blinding,
            )?,
            previous_total: previous_running_total,
            next_total,
            previous_total_blinding,
            next_total_blinding,
        })
    }
}

#[derive(Clone)]
pub struct AllocationConservationSegmentCircuit<const ALLOCS: usize> {
    pub public_inputs: Vec<u8>,
    pub witness: AllocationConservationSegmentWitness<ALLOCS>,
}

impl<const ALLOCS: usize> AllocationConservationSegmentCircuit<ALLOCS> {
    pub fn from_statement_and_witness(
        statement: &AllocationConservationSegmentStatement<ALLOCS>,
        witness: AllocationConservationSegmentWitness<ALLOCS>,
    ) -> Result<Self, String> {
        if !statement.matches_witness(&witness) {
            return Err(
                "allocation conservation segment witness does not match the public roots, amount commitment, or running totals"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            witness,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllocationConservationFinalStatement {
    pub spent_total_count: u64,
    pub new_total_count: u64,
    pub spent_total_commitment: Bytes32,
    pub new_total_commitment: Bytes32,
}

impl AllocationConservationFinalStatement {
    pub const PUBLIC_INPUT_LEN: usize = ALLOCATION_CONSERVATION_FINAL_PUBLIC_INPUT_LEN;

    pub fn from_total(
        spent_total_count: u64,
        new_total_count: u64,
        total: u64,
        spent_total_blinding: Bytes32,
        new_total_blinding: Bytes32,
    ) -> Result<Self, String> {
        if spent_total_count == 0 || new_total_count == 0 {
            return Err("allocation conservation final counts must be non-zero".to_string());
        }
        if total == 0 {
            return Err("allocation conservation final total must be non-zero".to_string());
        }
        if spent_total_blinding == [0u8; 32] || new_total_blinding == [0u8; 32] {
            return Err("allocation conservation final blindings must be non-zero".to_string());
        }
        Ok(Self {
            spent_total_count,
            new_total_count,
            spent_total_commitment: allocation_conservation_total_commitment(
                RgkAllocationTranscriptSide::Spent,
                spent_total_count,
                total,
                spent_total_blinding,
            ),
            new_total_commitment: allocation_conservation_total_commitment(
                RgkAllocationTranscriptSide::New,
                new_total_count,
                total,
                new_total_blinding,
            ),
        })
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.spent_total_count.to_le_bytes());
        out.extend_from_slice(&self.new_total_count.to_le_bytes());
        out.extend_from_slice(&self.spent_total_commitment);
        out.extend_from_slice(&self.new_total_commitment);
        out
    }

    pub fn matches_witness(&self, witness: &AllocationConservationFinalWitness) -> bool {
        self.spent_total_count != 0
            && self.new_total_count != 0
            && witness.total != 0
            && witness.spent_total_blinding != [0u8; 32]
            && witness.new_total_blinding != [0u8; 32]
            && self.spent_total_commitment
                == allocation_conservation_total_commitment(
                    RgkAllocationTranscriptSide::Spent,
                    self.spent_total_count,
                    witness.total,
                    witness.spent_total_blinding,
                )
            && self.new_total_commitment
                == allocation_conservation_total_commitment(
                    RgkAllocationTranscriptSide::New,
                    self.new_total_count,
                    witness.total,
                    witness.new_total_blinding,
                )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationConservationFinalWitness {
    pub total: u64,
    pub spent_total_blinding: Bytes32,
    pub new_total_blinding: Bytes32,
}

impl AllocationConservationFinalWitness {
    pub fn new(
        total: u64,
        spent_total_blinding: Bytes32,
        new_total_blinding: Bytes32,
    ) -> Result<Self, String> {
        if total == 0 {
            return Err("allocation conservation final total must be non-zero".to_string());
        }
        if spent_total_blinding == [0u8; 32] || new_total_blinding == [0u8; 32] {
            return Err("allocation conservation final blindings must be non-zero".to_string());
        }
        Ok(Self {
            total,
            spent_total_blinding,
            new_total_blinding,
        })
    }
}

#[derive(Clone)]
pub struct AllocationConservationFinalCircuit {
    pub public_inputs: Vec<u8>,
    pub witness: AllocationConservationFinalWitness,
}

impl AllocationConservationFinalCircuit {
    pub fn from_statement_and_witness(
        statement: &AllocationConservationFinalStatement,
        witness: AllocationConservationFinalWitness,
    ) -> Result<Self, String> {
        if !statement.matches_witness(&witness) {
            return Err(
                "allocation conservation final witness does not open both public total commitments to the same amount"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            witness,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllocationExclusionSegmentPairStatement<const SPENT: usize, const NEW: usize> {
    pub spent_previous_root: Bytes32,
    pub spent_next_root: Bytes32,
    pub new_previous_root: Bytes32,
    pub new_next_root: Bytes32,
    pub chain_id: KaspaChainId,
    pub spent_segment_index: u64,
    pub new_segment_index: u64,
    pub spent_total_count: u64,
    pub new_total_count: u64,
    pub spent_amount_commitment: Bytes32,
    pub new_amount_commitment: Bytes32,
}

impl<const SPENT: usize, const NEW: usize> AllocationExclusionSegmentPairStatement<SPENT, NEW> {
    pub const PUBLIC_INPUT_LEN: usize = ALLOCATION_EXCLUSION_SEGMENT_PAIR_PUBLIC_INPUT_LEN;

    #[allow(clippy::too_many_arguments)]
    pub fn from_allocations(
        spent_previous_root: Bytes32,
        new_previous_root: Bytes32,
        spent_segment_index: u64,
        new_segment_index: u64,
        spent_total_count: u64,
        new_total_count: u64,
        spent_allocations: &[RgkAllocation],
        new_allocations: &[RgkAllocation],
        spent_amount_blinding: Bytes32,
        new_amount_blinding: Bytes32,
    ) -> Result<Self, String> {
        if SPENT == 0 || NEW == 0 {
            return Err(
                "allocation exclusion segment-pair proof requires non-empty spent and new segments"
                    .to_string(),
            );
        }
        if spent_allocations.len() != SPENT || new_allocations.len() != NEW {
            return Err(format!(
                "expected spent/new segment lengths {SPENT}/{NEW}, got {}/{}",
                spent_allocations.len(),
                new_allocations.len()
            ));
        }
        if spent_total_count < SPENT as u64 || new_total_count < NEW as u64 {
            return Err("allocation exclusion total counts must cover their segments".to_string());
        }

        let chain_id = spent_allocations[0].anchor.chain;
        if spent_allocations
            .iter()
            .chain(new_allocations.iter())
            .any(|allocation| allocation.anchor.chain != chain_id)
        {
            return Err(
                "allocation exclusion segment-pair proof contains mixed chain ids".to_string(),
            );
        }

        let spent_amount = allocation_amount_sum(spent_allocations)?;
        let new_amount = allocation_amount_sum(new_allocations)?;
        if spent_amount == 0 || new_amount == 0 {
            return Err("allocation exclusion segment amount must be non-zero".to_string());
        }

        Ok(Self {
            spent_previous_root,
            spent_next_root: extend_allocation_transcript_root(
                spent_previous_root,
                RgkAllocationTranscriptSide::Spent,
                spent_segment_index,
                spent_total_count,
                spent_allocations,
            ),
            new_previous_root,
            new_next_root: extend_allocation_transcript_root(
                new_previous_root,
                RgkAllocationTranscriptSide::New,
                new_segment_index,
                new_total_count,
                new_allocations,
            ),
            chain_id,
            spent_segment_index,
            new_segment_index,
            spent_total_count,
            new_total_count,
            spent_amount_commitment: allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::Spent,
                spent_segment_index,
                spent_total_count,
                spent_amount,
                spent_amount_blinding,
            ),
            new_amount_commitment: allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::New,
                new_segment_index,
                new_total_count,
                new_amount,
                new_amount_blinding,
            ),
        })
    }

    pub fn public_inputs(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PUBLIC_INPUT_LEN);
        out.extend_from_slice(&self.spent_previous_root);
        out.extend_from_slice(&self.spent_next_root);
        out.extend_from_slice(&self.new_previous_root);
        out.extend_from_slice(&self.new_next_root);
        let tag = u32::from(KaspaChainId::TAG);
        let value = u32::from(self.chain_id as u8);
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
        out.extend_from_slice(&self.spent_segment_index.to_le_bytes());
        out.extend_from_slice(&self.new_segment_index.to_le_bytes());
        out.extend_from_slice(&self.spent_total_count.to_le_bytes());
        out.extend_from_slice(&self.new_total_count.to_le_bytes());
        out.extend_from_slice(&self.spent_amount_commitment);
        out.extend_from_slice(&self.new_amount_commitment);
        out
    }

    pub fn matches_witness(
        &self,
        witness: &AllocationExclusionSegmentPairWitness<SPENT, NEW>,
    ) -> bool {
        allocation_exclusion_segment_pair_matches(self, witness)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationExclusionSegmentPairWitness<const SPENT: usize, const NEW: usize> {
    pub spent: AllocationTranscriptSegmentWitness<SPENT>,
    pub new: AllocationTranscriptSegmentWitness<NEW>,
}

impl<const SPENT: usize, const NEW: usize> AllocationExclusionSegmentPairWitness<SPENT, NEW> {
    pub fn from_allocations(
        spent_allocations: &[RgkAllocation],
        new_allocations: &[RgkAllocation],
        spent_amount_blinding: Bytes32,
        new_amount_blinding: Bytes32,
    ) -> Result<Self, String> {
        Ok(Self {
            spent: AllocationTranscriptSegmentWitness::from_allocations(
                spent_allocations,
                spent_amount_blinding,
            )?,
            new: AllocationTranscriptSegmentWitness::from_allocations(
                new_allocations,
                new_amount_blinding,
            )?,
        })
    }
}

#[derive(Clone)]
pub struct AllocationExclusionSegmentPairCircuit<const SPENT: usize, const NEW: usize> {
    pub public_inputs: Vec<u8>,
    pub witness: AllocationExclusionSegmentPairWitness<SPENT, NEW>,
}

impl<const SPENT: usize, const NEW: usize> AllocationExclusionSegmentPairCircuit<SPENT, NEW> {
    pub fn from_statement_and_witness(
        statement: &AllocationExclusionSegmentPairStatement<SPENT, NEW>,
        witness: AllocationExclusionSegmentPairWitness<SPENT, NEW>,
    ) -> Result<Self, String> {
        if !statement.matches_witness(&witness) {
            return Err(
                "allocation exclusion segment-pair witness does not match the public roots, commitments, or exclusion relation"
                    .to_string(),
            );
        }
        Ok(Self {
            public_inputs: statement.public_inputs(),
            witness,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AllocationAuditBundle<'a, const SPENT: usize, const NEW: usize> {
    pub spent_transcripts: &'a [AllocationTranscriptSegmentStatement<SPENT>],
    pub new_transcripts: &'a [AllocationTranscriptSegmentStatement<NEW>],
    pub spent_conservation: &'a [AllocationConservationSegmentStatement<SPENT>],
    pub new_conservation: &'a [AllocationConservationSegmentStatement<NEW>],
    pub final_conservation: &'a AllocationConservationFinalStatement,
    pub exclusions: &'a [AllocationExclusionSegmentPairStatement<SPENT, NEW>],
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllocationAuditBundleReport {
    pub chain_id: KaspaChainId,
    pub spent_segments: usize,
    pub new_segments: usize,
    pub exclusion_pairs: usize,
    pub spent_total_count: u64,
    pub new_total_count: u64,
    pub spent_final_root: Bytes32,
    pub new_final_root: Bytes32,
    pub spent_total_commitment: Bytes32,
    pub new_total_commitment: Bytes32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationAuditProofKind {
    SpentTranscriptSegment,
    NewTranscriptSegment,
    SpentConservationSegment,
    NewConservationSegment,
    ConservationFinal,
    ExclusionSegmentPair,
}

impl AllocationAuditProofKind {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::SpentTranscriptSegment => 0,
            Self::NewTranscriptSegment => 1,
            Self::SpentConservationSegment => 2,
            Self::NewConservationSegment => 3,
            Self::ConservationFinal => 4,
            Self::ExclusionSegmentPair => 5,
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::SpentTranscriptSegment),
            1 => Some(Self::NewTranscriptSegment),
            2 => Some(Self::SpentConservationSegment),
            3 => Some(Self::NewConservationSegment),
            4 => Some(Self::ConservationFinal),
            5 => Some(Self::ExclusionSegmentPair),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::SpentTranscriptSegment => "spent transcript segment",
            Self::NewTranscriptSegment => "new transcript segment",
            Self::SpentConservationSegment => "spent conservation segment",
            Self::NewConservationSegment => "new conservation segment",
            Self::ConservationFinal => "conservation final",
            Self::ExclusionSegmentPair => "exclusion segment pair",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationAuditProofEntry {
    pub kind: AllocationAuditProofKind,
    pub spent_segment_index: Option<u64>,
    pub new_segment_index: Option<u64>,
    pub public_inputs: Vec<u8>,
    pub stack: Groth16PrecompileStack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationAuditCertificate {
    pub certificate_id: Bytes32,
    pub report: AllocationAuditBundleReport,
    pub proofs: Vec<AllocationAuditProofEntry>,
}

impl AllocationAuditCertificate {
    pub fn proof_entry_count(&self) -> usize {
        self.proofs.len()
    }

    pub fn total_verifying_key_bytes(&self) -> usize {
        self.proofs
            .iter()
            .map(|proof| proof.stack.verifying_key.len())
            .sum()
    }

    pub fn total_proof_bytes(&self) -> usize {
        self.proofs
            .iter()
            .map(|proof| proof.stack.proof.len())
            .sum()
    }

    /// Encode the certificate as a byte-stable RGK artefact suitable for
    /// wallet, resolver, indexer, and evidence-tool handoff.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, String> {
        let expected_id = allocation_audit_certificate_id(&self.report, &self.proofs)?;
        if self.certificate_id != expected_id {
            return Err("allocation audit certificate id does not bind its payload".to_string());
        }
        let mut out = Vec::new();
        out.extend_from_slice(ALLOCATION_AUDIT_CERTIFICATE_MAGIC);
        out.extend_from_slice(&self.certificate_id);
        out.extend_from_slice(&allocation_audit_certificate_body(
            &self.report,
            &self.proofs,
        )?);
        Ok(out)
    }

    /// Decode a byte-stable RGK allocation audit certificate and reject
    /// malformed, trailing, oversized, or id-mismatched encodings.
    pub fn decode_canonical(buf: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(buf);
        let magic = r
            .read_array::<8>()
            .map_err(allocation_audit_certificate_decode_err)?;
        if magic != *ALLOCATION_AUDIT_CERTIFICATE_MAGIC {
            return Err("allocation audit certificate has bad magic".to_string());
        }
        let certificate_id = r
            .read_bytes32()
            .map_err(allocation_audit_certificate_decode_err)?;
        let report = decode_allocation_audit_report(&mut r)?;
        let proofs = decode_allocation_audit_proof_entries(&mut r)?;
        r.ensure_consumed()
            .map_err(allocation_audit_certificate_decode_err)?;
        let expected_id = allocation_audit_certificate_id(&report, &proofs)?;
        if certificate_id != expected_id {
            return Err("allocation audit certificate id does not bind its payload".to_string());
        }
        Ok(Self {
            certificate_id,
            report,
            proofs,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AllocationAuditBundleStacks<'a> {
    pub spent_transcripts: &'a [Groth16PrecompileStack],
    pub new_transcripts: &'a [Groth16PrecompileStack],
    pub spent_conservation: &'a [Groth16PrecompileStack],
    pub new_conservation: &'a [Groth16PrecompileStack],
    pub final_conservation: &'a Groth16PrecompileStack,
    pub exclusions: &'a [Groth16PrecompileStack],
}

pub fn verify_allocation_audit_bundle<const SPENT: usize, const NEW: usize>(
    bundle: &AllocationAuditBundle<'_, SPENT, NEW>,
) -> Result<AllocationAuditBundleReport, String> {
    if SPENT == 0 || NEW == 0 {
        return Err("allocation audit bundle requires non-zero segment arities".to_string());
    }

    let spent_chain = verify_allocation_transcript_chain(
        "spent",
        RgkAllocationTranscriptSide::Spent,
        bundle.spent_transcripts,
    )?;
    let new_chain = verify_allocation_transcript_chain(
        "new",
        RgkAllocationTranscriptSide::New,
        bundle.new_transcripts,
    )?;
    if spent_chain.chain_id != new_chain.chain_id {
        return Err("allocation audit bundle contains mixed spent/new chain ids".to_string());
    }

    if bundle.final_conservation.spent_total_count != spent_chain.total_count {
        return Err(
            "allocation audit final spent count does not match spent transcript chain".to_string(),
        );
    }
    if bundle.final_conservation.new_total_count != new_chain.total_count {
        return Err(
            "allocation audit final new count does not match new transcript chain".to_string(),
        );
    }

    verify_allocation_conservation_chain(
        "spent",
        bundle.spent_transcripts,
        bundle.spent_conservation,
        bundle.final_conservation.spent_total_commitment,
    )?;
    verify_allocation_conservation_chain(
        "new",
        bundle.new_transcripts,
        bundle.new_conservation,
        bundle.final_conservation.new_total_commitment,
    )?;
    verify_allocation_exclusion_grid(
        bundle.spent_transcripts,
        bundle.new_transcripts,
        bundle.exclusions,
        spent_chain.chain_id,
    )?;

    Ok(AllocationAuditBundleReport {
        chain_id: spent_chain.chain_id,
        spent_segments: bundle.spent_transcripts.len(),
        new_segments: bundle.new_transcripts.len(),
        exclusion_pairs: bundle.exclusions.len(),
        spent_total_count: spent_chain.total_count,
        new_total_count: new_chain.total_count,
        spent_final_root: spent_chain.final_root,
        new_final_root: new_chain.final_root,
        spent_total_commitment: bundle.final_conservation.spent_total_commitment,
        new_total_commitment: bundle.final_conservation.new_total_commitment,
    })
}

pub fn build_allocation_audit_certificate<const SPENT: usize, const NEW: usize>(
    bundle: &AllocationAuditBundle<'_, SPENT, NEW>,
    stacks: &AllocationAuditBundleStacks<'_>,
) -> Result<AllocationAuditCertificate, String> {
    let report = verify_allocation_audit_bundle(bundle)?;
    let mut proofs = Vec::new();
    append_allocation_audit_certificate_entries(bundle, stacks, &mut proofs)?;
    let certificate_id = allocation_audit_certificate_id(&report, &proofs)?;
    Ok(AllocationAuditCertificate {
        certificate_id,
        report,
        proofs,
    })
}

pub fn verify_allocation_audit_certificate<const SPENT: usize, const NEW: usize>(
    certificate: &AllocationAuditCertificate,
    bundle: &AllocationAuditBundle<'_, SPENT, NEW>,
) -> Result<AllocationAuditBundleReport, String> {
    let expected_report = verify_allocation_audit_bundle(bundle)?;
    if certificate.report != expected_report {
        return Err("allocation audit certificate report does not match bundle".to_string());
    }
    let mut expected_entries = Vec::new();
    append_allocation_audit_manifest_entries(bundle, &mut expected_entries);
    if certificate.proofs.len() != expected_entries.len() {
        return Err(format!(
            "allocation audit certificate has {} proof entries, expected {}",
            certificate.proofs.len(),
            expected_entries.len()
        ));
    }
    for (index, (actual, expected)) in certificate
        .proofs
        .iter()
        .zip(expected_entries.iter())
        .enumerate()
    {
        if actual.kind != expected.kind
            || actual.spent_segment_index != expected.spent_segment_index
            || actual.new_segment_index != expected.new_segment_index
            || actual.public_inputs != expected.public_inputs
        {
            return Err(format!(
                "allocation audit certificate proof entry {index} does not match the bundle manifest"
            ));
        }
        verify_groth16_stack_against_public_inputs(
            actual.kind,
            &actual.stack,
            &actual.public_inputs,
        )?;
    }
    let expected_id = allocation_audit_certificate_id(&certificate.report, &certificate.proofs)?;
    if certificate.certificate_id != expected_id {
        return Err("allocation audit certificate id does not bind its payload".to_string());
    }
    Ok(certificate.report.clone())
}

pub fn verify_allocation_audit_certificate_self_contained<const SPENT: usize, const NEW: usize>(
    certificate: &AllocationAuditCertificate,
) -> Result<AllocationAuditBundleReport, String> {
    let expected_id = allocation_audit_certificate_id(&certificate.report, &certificate.proofs)?;
    if certificate.certificate_id != expected_id {
        return Err("allocation audit certificate id does not bind its payload".to_string());
    }

    let mut spent_transcripts = Vec::new();
    let mut new_transcripts = Vec::new();
    let mut spent_conservation = Vec::new();
    let mut new_conservation = Vec::new();
    let mut final_conservation = None;
    let mut exclusions = Vec::new();

    for (entry_index, entry) in certificate.proofs.iter().enumerate() {
        verify_groth16_stack_against_public_inputs(entry.kind, &entry.stack, &entry.public_inputs)?;
        match entry.kind {
            AllocationAuditProofKind::SpentTranscriptSegment => {
                let statement = parse_allocation_transcript_public_inputs::<SPENT>(
                    &entry.public_inputs,
                    "allocation audit spent transcript entry",
                )?;
                if statement.side != RgkAllocationTranscriptSide::Spent {
                    return Err(format!(
                        "allocation audit certificate proof entry {entry_index} has the wrong transcript side"
                    ));
                }
                check_allocation_audit_entry_indices(
                    entry_index,
                    entry,
                    Some(statement.segment_index),
                    None,
                )?;
                spent_transcripts.push(statement);
            }
            AllocationAuditProofKind::NewTranscriptSegment => {
                let statement = parse_allocation_transcript_public_inputs::<NEW>(
                    &entry.public_inputs,
                    "allocation audit new transcript entry",
                )?;
                if statement.side != RgkAllocationTranscriptSide::New {
                    return Err(format!(
                        "allocation audit certificate proof entry {entry_index} has the wrong transcript side"
                    ));
                }
                check_allocation_audit_entry_indices(
                    entry_index,
                    entry,
                    None,
                    Some(statement.segment_index),
                )?;
                new_transcripts.push(statement);
            }
            AllocationAuditProofKind::SpentConservationSegment => {
                let statement = parse_allocation_conservation_public_inputs::<SPENT>(
                    &entry.public_inputs,
                    "allocation audit spent conservation entry",
                )?;
                if statement.transcript.side != RgkAllocationTranscriptSide::Spent {
                    return Err(format!(
                        "allocation audit certificate proof entry {entry_index} has the wrong conservation side"
                    ));
                }
                check_allocation_audit_entry_indices(
                    entry_index,
                    entry,
                    Some(statement.transcript.segment_index),
                    None,
                )?;
                spent_conservation.push(statement);
            }
            AllocationAuditProofKind::NewConservationSegment => {
                let statement = parse_allocation_conservation_public_inputs::<NEW>(
                    &entry.public_inputs,
                    "allocation audit new conservation entry",
                )?;
                if statement.transcript.side != RgkAllocationTranscriptSide::New {
                    return Err(format!(
                        "allocation audit certificate proof entry {entry_index} has the wrong conservation side"
                    ));
                }
                check_allocation_audit_entry_indices(
                    entry_index,
                    entry,
                    None,
                    Some(statement.transcript.segment_index),
                )?;
                new_conservation.push(statement);
            }
            AllocationAuditProofKind::ConservationFinal => {
                if final_conservation.is_some() {
                    return Err(
                        "allocation audit certificate has duplicate final conservation entries"
                            .to_string(),
                    );
                }
                let statement = parse_allocation_conservation_final_public_inputs(
                    &entry.public_inputs,
                    "allocation audit final conservation entry",
                )?;
                check_allocation_audit_entry_indices(entry_index, entry, None, None)?;
                final_conservation = Some(statement);
            }
            AllocationAuditProofKind::ExclusionSegmentPair => {
                let statement = parse_allocation_exclusion_public_inputs::<SPENT, NEW>(
                    &entry.public_inputs,
                    "allocation audit exclusion pair",
                )?;
                check_allocation_audit_entry_indices(
                    entry_index,
                    entry,
                    Some(statement.spent_segment_index),
                    Some(statement.new_segment_index),
                )?;
                exclusions.push(statement);
            }
        }
    }

    spent_transcripts.sort_by_key(|statement| statement.segment_index);
    new_transcripts.sort_by_key(|statement| statement.segment_index);
    spent_conservation.sort_by_key(|statement| statement.transcript.segment_index);
    new_conservation.sort_by_key(|statement| statement.transcript.segment_index);
    exclusions
        .sort_by_key(|statement| (statement.spent_segment_index, statement.new_segment_index));

    let final_conservation = final_conservation.ok_or_else(|| {
        "allocation audit certificate is missing final conservation entry".to_string()
    })?;
    let bundle = AllocationAuditBundle {
        spent_transcripts: &spent_transcripts,
        new_transcripts: &new_transcripts,
        spent_conservation: &spent_conservation,
        new_conservation: &new_conservation,
        final_conservation: &final_conservation,
        exclusions: &exclusions,
    };
    let report = verify_allocation_audit_bundle(&bundle)?;
    if certificate.report != report {
        return Err(
            "allocation audit certificate report does not match reconstructed manifest".to_string(),
        );
    }

    let mut expected_entries = Vec::new();
    append_allocation_audit_manifest_entries(&bundle, &mut expected_entries);
    if certificate.proofs.len() != expected_entries.len() {
        return Err(format!(
            "allocation audit certificate has {} proof entries, expected {}",
            certificate.proofs.len(),
            expected_entries.len()
        ));
    }
    for (index, (actual, expected)) in certificate
        .proofs
        .iter()
        .zip(expected_entries.iter())
        .enumerate()
    {
        if actual.kind != expected.kind
            || actual.spent_segment_index != expected.spent_segment_index
            || actual.new_segment_index != expected.new_segment_index
            || actual.public_inputs != expected.public_inputs
        {
            return Err(format!(
                "allocation audit certificate proof entry {index} is not in deterministic manifest order"
            ));
        }
    }

    Ok(report)
}

pub fn verify_allocation_audit_certificate_canonical<const SPENT: usize, const NEW: usize>(
    buf: &[u8],
) -> Result<(AllocationAuditCertificate, AllocationAuditBundleReport), String> {
    let certificate = AllocationAuditCertificate::decode_canonical(buf)?;
    let report = verify_allocation_audit_certificate_self_contained::<SPENT, NEW>(&certificate)?;
    Ok((certificate, report))
}

fn parse_allocation_transcript_public_inputs<const ALLOCS: usize>(
    public: &[u8],
    label: &str,
) -> Result<AllocationTranscriptSegmentStatement<ALLOCS>, String> {
    if public.len() != AllocationTranscriptSegmentStatement::<ALLOCS>::PUBLIC_INPUT_LEN {
        return Err(format!(
            "{label} has {} public-input bytes, expected {}",
            public.len(),
            AllocationTranscriptSegmentStatement::<ALLOCS>::PUBLIC_INPUT_LEN
        ));
    }
    let side = parse_allocation_transcript_side(public[72], label)?;
    if public[73..80].iter().any(|byte| *byte != 0) {
        return Err(format!("{label} transcript padding is not canonical"));
    }
    let statement = AllocationTranscriptSegmentStatement {
        previous_root: public_bytes32_at(public, 0, label, "previous root")?,
        next_root: public_bytes32_at(public, 32, label, "next root")?,
        chain_id: public_chain_id_at(public, 64, label)?,
        side,
        segment_index: public_u64_at(public, 80, label, "segment index")?,
        total_count: public_u64_at(public, 88, label, "total count")?,
        segment_amount_commitment: public_bytes32_at(public, 96, label, "amount commitment")?,
    };
    ensure_canonical_public_inputs(label, public, &statement.public_inputs())?;
    Ok(statement)
}

fn parse_allocation_conservation_public_inputs<const ALLOCS: usize>(
    public: &[u8],
    label: &str,
) -> Result<AllocationConservationSegmentStatement<ALLOCS>, String> {
    if public.len() != AllocationConservationSegmentStatement::<ALLOCS>::PUBLIC_INPUT_LEN {
        return Err(format!(
            "{label} has {} public-input bytes, expected {}",
            public.len(),
            AllocationConservationSegmentStatement::<ALLOCS>::PUBLIC_INPUT_LEN
        ));
    }
    let transcript = parse_allocation_transcript_public_inputs::<ALLOCS>(
        &public[..AllocationTranscriptSegmentStatement::<ALLOCS>::PUBLIC_INPUT_LEN],
        label,
    )?;
    let statement = AllocationConservationSegmentStatement {
        transcript,
        previous_total_commitment: public_bytes32_at(
            public,
            128,
            label,
            "previous total commitment",
        )?,
        next_total_commitment: public_bytes32_at(public, 160, label, "next total commitment")?,
    };
    ensure_canonical_public_inputs(label, public, &statement.public_inputs())?;
    Ok(statement)
}

fn parse_allocation_conservation_final_public_inputs(
    public: &[u8],
    label: &str,
) -> Result<AllocationConservationFinalStatement, String> {
    if public.len() != AllocationConservationFinalStatement::PUBLIC_INPUT_LEN {
        return Err(format!(
            "{label} has {} public-input bytes, expected {}",
            public.len(),
            AllocationConservationFinalStatement::PUBLIC_INPUT_LEN
        ));
    }
    let statement = AllocationConservationFinalStatement {
        spent_total_count: public_u64_at(public, 0, label, "spent total count")?,
        new_total_count: public_u64_at(public, 8, label, "new total count")?,
        spent_total_commitment: public_bytes32_at(public, 16, label, "spent total commitment")?,
        new_total_commitment: public_bytes32_at(public, 48, label, "new total commitment")?,
    };
    ensure_canonical_public_inputs(label, public, &statement.public_inputs())?;
    Ok(statement)
}

fn parse_allocation_exclusion_public_inputs<const SPENT: usize, const NEW: usize>(
    public: &[u8],
    label: &str,
) -> Result<AllocationExclusionSegmentPairStatement<SPENT, NEW>, String> {
    if public.len() != AllocationExclusionSegmentPairStatement::<SPENT, NEW>::PUBLIC_INPUT_LEN {
        return Err(format!(
            "{label} has {} public-input bytes, expected {}",
            public.len(),
            AllocationExclusionSegmentPairStatement::<SPENT, NEW>::PUBLIC_INPUT_LEN
        ));
    }
    let statement = AllocationExclusionSegmentPairStatement {
        spent_previous_root: public_bytes32_at(public, 0, label, "spent previous root")?,
        spent_next_root: public_bytes32_at(public, 32, label, "spent next root")?,
        new_previous_root: public_bytes32_at(public, 64, label, "new previous root")?,
        new_next_root: public_bytes32_at(public, 96, label, "new next root")?,
        chain_id: public_chain_id_at(public, 128, label)?,
        spent_segment_index: public_u64_at(public, 136, label, "spent segment index")?,
        new_segment_index: public_u64_at(public, 144, label, "new segment index")?,
        spent_total_count: public_u64_at(public, 152, label, "spent total count")?,
        new_total_count: public_u64_at(public, 160, label, "new total count")?,
        spent_amount_commitment: public_bytes32_at(public, 168, label, "spent amount commitment")?,
        new_amount_commitment: public_bytes32_at(public, 200, label, "new amount commitment")?,
    };
    ensure_canonical_public_inputs(label, public, &statement.public_inputs())?;
    Ok(statement)
}

fn check_allocation_audit_entry_indices(
    entry_index: usize,
    entry: &AllocationAuditProofEntry,
    expected_spent: Option<u64>,
    expected_new: Option<u64>,
) -> Result<(), String> {
    if entry.spent_segment_index != expected_spent || entry.new_segment_index != expected_new {
        return Err(format!(
            "allocation audit certificate proof entry {entry_index} has inconsistent segment indices"
        ));
    }
    Ok(())
}

fn parse_allocation_transcript_side(
    side: u8,
    label: &str,
) -> Result<RgkAllocationTranscriptSide, String> {
    match side {
        0 => Ok(RgkAllocationTranscriptSide::Spent),
        1 => Ok(RgkAllocationTranscriptSide::New),
        _ => Err(format!("{label} has unknown transcript side {side}")),
    }
}

fn public_chain_id_at(public: &[u8], offset: usize, label: &str) -> Result<KaspaChainId, String> {
    let tag = public_u32_at(public, offset, label, "chain id tag")?;
    if tag != u32::from(KaspaChainId::TAG) {
        return Err(format!("{label} has bad chain id tag {tag}"));
    }
    let value = public_u32_at(public, offset + 4, label, "chain id value")?;
    if value > u8::MAX as u32 {
        return Err(format!("{label} has out-of-range chain id value {value}"));
    }
    KaspaChainId::from_tag(value as u8)
        .ok_or_else(|| format!("{label} has unknown chain id value {value}"))
}

fn public_u32_at(public: &[u8], offset: usize, label: &str, field: &str) -> Result<u32, String> {
    let bytes = public_slice_at(public, offset, 4, label, field)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn public_u64_at(public: &[u8], offset: usize, label: &str, field: &str) -> Result<u64, String> {
    let bytes = public_slice_at(public, offset, 8, label, field)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn public_bytes32_at(
    public: &[u8],
    offset: usize,
    label: &str,
    field: &str,
) -> Result<Bytes32, String> {
    let bytes = public_slice_at(public, offset, 32, label, field)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn public_slice_at<'a>(
    public: &'a [u8],
    offset: usize,
    len: usize,
    label: &str,
    field: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| format!("{label} {field} offset overflow"))?;
    public
        .get(offset..end)
        .ok_or_else(|| format!("{label} is missing {field}"))
}

fn ensure_canonical_public_inputs(
    label: &str,
    actual: &[u8],
    expected: &[u8],
) -> Result<(), String> {
    if actual != expected {
        return Err(format!("{label} public inputs are not canonical"));
    }
    Ok(())
}

fn append_allocation_audit_certificate_entries<const SPENT: usize, const NEW: usize>(
    bundle: &AllocationAuditBundle<'_, SPENT, NEW>,
    stacks: &AllocationAuditBundleStacks<'_>,
    proofs: &mut Vec<AllocationAuditProofEntry>,
) -> Result<(), String> {
    check_stack_count(
        "spent transcript",
        stacks.spent_transcripts.len(),
        bundle.spent_transcripts.len(),
    )?;
    check_stack_count(
        "new transcript",
        stacks.new_transcripts.len(),
        bundle.new_transcripts.len(),
    )?;
    check_stack_count(
        "spent conservation",
        stacks.spent_conservation.len(),
        bundle.spent_conservation.len(),
    )?;
    check_stack_count(
        "new conservation",
        stacks.new_conservation.len(),
        bundle.new_conservation.len(),
    )?;
    check_stack_count(
        "exclusion",
        stacks.exclusions.len(),
        bundle.exclusions.len(),
    )?;

    for (statement, stack) in bundle
        .spent_transcripts
        .iter()
        .zip(stacks.spent_transcripts.iter())
    {
        proofs.push(verified_allocation_audit_proof_entry(
            AllocationAuditProofKind::SpentTranscriptSegment,
            Some(statement.segment_index),
            None,
            statement.public_inputs(),
            stack,
        )?);
    }
    for (statement, stack) in bundle
        .new_transcripts
        .iter()
        .zip(stacks.new_transcripts.iter())
    {
        proofs.push(verified_allocation_audit_proof_entry(
            AllocationAuditProofKind::NewTranscriptSegment,
            None,
            Some(statement.segment_index),
            statement.public_inputs(),
            stack,
        )?);
    }
    for (statement, stack) in bundle
        .spent_conservation
        .iter()
        .zip(stacks.spent_conservation.iter())
    {
        proofs.push(verified_allocation_audit_proof_entry(
            AllocationAuditProofKind::SpentConservationSegment,
            Some(statement.transcript.segment_index),
            None,
            statement.public_inputs(),
            stack,
        )?);
    }
    for (statement, stack) in bundle
        .new_conservation
        .iter()
        .zip(stacks.new_conservation.iter())
    {
        proofs.push(verified_allocation_audit_proof_entry(
            AllocationAuditProofKind::NewConservationSegment,
            None,
            Some(statement.transcript.segment_index),
            statement.public_inputs(),
            stack,
        )?);
    }
    proofs.push(verified_allocation_audit_proof_entry(
        AllocationAuditProofKind::ConservationFinal,
        None,
        None,
        bundle.final_conservation.public_inputs(),
        stacks.final_conservation,
    )?);
    for (statement, stack) in bundle.exclusions.iter().zip(stacks.exclusions.iter()) {
        proofs.push(verified_allocation_audit_proof_entry(
            AllocationAuditProofKind::ExclusionSegmentPair,
            Some(statement.spent_segment_index),
            Some(statement.new_segment_index),
            statement.public_inputs(),
            stack,
        )?);
    }
    Ok(())
}

fn append_allocation_audit_manifest_entries<const SPENT: usize, const NEW: usize>(
    bundle: &AllocationAuditBundle<'_, SPENT, NEW>,
    proofs: &mut Vec<AllocationAuditProofEntry>,
) {
    for statement in bundle.spent_transcripts {
        proofs.push(allocation_audit_manifest_entry(
            AllocationAuditProofKind::SpentTranscriptSegment,
            Some(statement.segment_index),
            None,
            statement.public_inputs(),
        ));
    }
    for statement in bundle.new_transcripts {
        proofs.push(allocation_audit_manifest_entry(
            AllocationAuditProofKind::NewTranscriptSegment,
            None,
            Some(statement.segment_index),
            statement.public_inputs(),
        ));
    }
    for statement in bundle.spent_conservation {
        proofs.push(allocation_audit_manifest_entry(
            AllocationAuditProofKind::SpentConservationSegment,
            Some(statement.transcript.segment_index),
            None,
            statement.public_inputs(),
        ));
    }
    for statement in bundle.new_conservation {
        proofs.push(allocation_audit_manifest_entry(
            AllocationAuditProofKind::NewConservationSegment,
            None,
            Some(statement.transcript.segment_index),
            statement.public_inputs(),
        ));
    }
    proofs.push(allocation_audit_manifest_entry(
        AllocationAuditProofKind::ConservationFinal,
        None,
        None,
        bundle.final_conservation.public_inputs(),
    ));
    for statement in bundle.exclusions {
        proofs.push(allocation_audit_manifest_entry(
            AllocationAuditProofKind::ExclusionSegmentPair,
            Some(statement.spent_segment_index),
            Some(statement.new_segment_index),
            statement.public_inputs(),
        ));
    }
}

fn check_stack_count(label: &str, got: usize, expected: usize) -> Result<(), String> {
    if got != expected {
        return Err(format!(
            "allocation audit certificate has {got} {label} stacks, expected {expected}"
        ));
    }
    Ok(())
}

fn allocation_audit_manifest_entry(
    kind: AllocationAuditProofKind,
    spent_segment_index: Option<u64>,
    new_segment_index: Option<u64>,
    public_inputs: Vec<u8>,
) -> AllocationAuditProofEntry {
    AllocationAuditProofEntry {
        kind,
        spent_segment_index,
        new_segment_index,
        public_inputs,
        stack: empty_allocation_audit_stack(),
    }
}

fn verified_allocation_audit_proof_entry(
    kind: AllocationAuditProofKind,
    spent_segment_index: Option<u64>,
    new_segment_index: Option<u64>,
    public_inputs: Vec<u8>,
    stack: &Groth16PrecompileStack,
) -> Result<AllocationAuditProofEntry, String> {
    verify_groth16_stack_against_public_inputs(kind, stack, &public_inputs)?;
    Ok(AllocationAuditProofEntry {
        kind,
        spent_segment_index,
        new_segment_index,
        public_inputs,
        stack: stack.clone(),
    })
}

fn empty_allocation_audit_stack() -> Groth16PrecompileStack {
    Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: Vec::new(),
        proof: Vec::new(),
        public_inputs: Vec::new(),
    }
}

fn verify_groth16_stack_against_public_inputs(
    kind: AllocationAuditProofKind,
    stack: &Groth16PrecompileStack,
    expected_public_inputs: &[u8],
) -> Result<(), String> {
    if stack.tag != [ZK_TAG_GROTH16] {
        return Err(format!(
            "allocation audit {} stack has the wrong Groth16 tag",
            kind.label()
        ));
    }
    let expected_stack_inputs = public_inputs_as_uncompressed_fr_bytes_with_len(
        expected_public_inputs,
        expected_public_inputs.len(),
    )?;
    if stack.public_inputs != expected_stack_inputs {
        return Err(format!(
            "allocation audit {} stack public inputs do not match the statement",
            kind.label()
        ));
    }
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&stack.verifying_key[..])
        .map_err(|e| format!("allocation audit {} verifying key: {e}", kind.label()))?;
    let proof = Proof::<Bn254>::deserialize_compressed(&stack.proof[..])
        .map_err(|e| format!("allocation audit {} proof: {e}", kind.label()))?;
    let public_inputs = groth16_stack_public_inputs_as_fr(stack, kind)?;
    if !verify(&vk, &public_inputs, &proof)? {
        return Err(format!(
            "allocation audit {} Groth16 proof did not verify",
            kind.label()
        ));
    }
    Ok(())
}

fn groth16_stack_public_inputs_as_fr(
    stack: &Groth16PrecompileStack,
    kind: AllocationAuditProofKind,
) -> Result<Vec<Fr>, String> {
    stack
        .public_inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if input.len() != 32 {
                return Err(format!(
                    "allocation audit {} public input {index} has {} bytes, expected 32",
                    kind.label(),
                    input.len()
                ));
            }
            Fr::deserialize_uncompressed(&input[..]).map_err(|e| {
                format!(
                    "allocation audit {} public input {index} deserialize: {e}",
                    kind.label()
                )
            })
        })
        .collect()
}

fn allocation_audit_certificate_id(
    report: &AllocationAuditBundleReport,
    proofs: &[AllocationAuditProofEntry],
) -> Result<Bytes32, String> {
    let payload = allocation_audit_certificate_body(report, proofs)?;
    Ok(rgk_asset::internal::asset_domain_hash(
        "rgk:zk:allocation-audit-certificate:v1",
        &payload,
    ))
}

fn allocation_audit_certificate_body(
    report: &AllocationAuditBundleReport,
    proofs: &[AllocationAuditProofEntry],
) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    encode_allocation_audit_report(report, &mut w)?;
    write_certificate_len(
        &mut w,
        "allocation audit certificate proof entries",
        proofs.len(),
        MAX_ALLOCATION_AUDIT_CERTIFICATE_PROOF_ENTRIES,
    )?;
    for proof in proofs {
        encode_allocation_audit_proof_entry(proof, &mut w)?;
    }
    Ok(w.into_vec())
}

fn encode_allocation_audit_report(
    report: &AllocationAuditBundleReport,
    w: &mut Writer,
) -> Result<(), String> {
    report.chain_id.encode(w);
    write_usize_as_u64(w, "spent segment count", report.spent_segments)?;
    write_usize_as_u64(w, "new segment count", report.new_segments)?;
    write_usize_as_u64(w, "exclusion pair count", report.exclusion_pairs)?;
    w.write_u64(report.spent_total_count);
    w.write_u64(report.new_total_count);
    w.write_bytes32(&report.spent_final_root);
    w.write_bytes32(&report.new_final_root);
    w.write_bytes32(&report.spent_total_commitment);
    w.write_bytes32(&report.new_total_commitment);
    Ok(())
}

fn decode_allocation_audit_report(
    r: &mut Reader<'_>,
) -> Result<AllocationAuditBundleReport, String> {
    let chain_id = KaspaChainId::decode(r).map_err(allocation_audit_certificate_decode_err)?;
    let spent_segments =
        read_usize_from_u64(r, "allocation audit certificate spent segment count")?;
    let new_segments = read_usize_from_u64(r, "allocation audit certificate new segment count")?;
    let exclusion_pairs =
        read_usize_from_u64(r, "allocation audit certificate exclusion pair count")?;
    let spent_total_count = r
        .read_u64()
        .map_err(allocation_audit_certificate_decode_err)?;
    let new_total_count = r
        .read_u64()
        .map_err(allocation_audit_certificate_decode_err)?;
    let spent_final_root = r
        .read_bytes32()
        .map_err(allocation_audit_certificate_decode_err)?;
    let new_final_root = r
        .read_bytes32()
        .map_err(allocation_audit_certificate_decode_err)?;
    let spent_total_commitment = r
        .read_bytes32()
        .map_err(allocation_audit_certificate_decode_err)?;
    let new_total_commitment = r
        .read_bytes32()
        .map_err(allocation_audit_certificate_decode_err)?;
    Ok(AllocationAuditBundleReport {
        chain_id,
        spent_segments,
        new_segments,
        exclusion_pairs,
        spent_total_count,
        new_total_count,
        spent_final_root,
        new_final_root,
        spent_total_commitment,
        new_total_commitment,
    })
}

fn encode_allocation_audit_proof_entry(
    proof: &AllocationAuditProofEntry,
    w: &mut Writer,
) -> Result<(), String> {
    w.write_u8(proof.kind.as_u8());
    write_optional_u64(w, proof.spent_segment_index);
    write_optional_u64(w, proof.new_segment_index);
    write_certificate_blob(w, "allocation audit public inputs", &proof.public_inputs)?;
    w.write_u8(proof.stack.tag[0]);
    write_certificate_blob(
        w,
        "allocation audit verifying key",
        &proof.stack.verifying_key,
    )?;
    write_certificate_blob(w, "allocation audit proof", &proof.stack.proof)?;
    write_certificate_len(
        w,
        "allocation audit stack public inputs",
        proof.stack.public_inputs.len(),
        MAX_ALLOCATION_AUDIT_STACK_PUBLIC_INPUTS,
    )?;
    for public_input in &proof.stack.public_inputs {
        write_certificate_blob(w, "allocation audit stack public input", public_input)?;
    }
    Ok(())
}

fn decode_allocation_audit_proof_entries(
    r: &mut Reader<'_>,
) -> Result<Vec<AllocationAuditProofEntry>, String> {
    let len = read_bounded_len(
        r,
        "allocation audit certificate proof entries",
        MAX_ALLOCATION_AUDIT_CERTIFICATE_PROOF_ENTRIES,
    )?;
    let mut proofs = Vec::with_capacity(len);
    for index in 0..len {
        proofs.push(decode_allocation_audit_proof_entry(r, index)?);
    }
    Ok(proofs)
}

fn decode_allocation_audit_proof_entry(
    r: &mut Reader<'_>,
    index: usize,
) -> Result<AllocationAuditProofEntry, String> {
    let kind_tag = r
        .read_u8()
        .map_err(allocation_audit_certificate_decode_err)?;
    let kind = AllocationAuditProofKind::from_u8(kind_tag).ok_or_else(|| {
        format!("allocation audit certificate proof entry {index} has unknown kind {kind_tag}")
    })?;
    let spent_segment_index = read_optional_u64(r, "spent segment index")?;
    let new_segment_index = read_optional_u64(r, "new segment index")?;
    let public_inputs = read_certificate_blob(r, "allocation audit public inputs")?;
    let tag = [r
        .read_u8()
        .map_err(allocation_audit_certificate_decode_err)?];
    let verifying_key = read_certificate_blob(r, "allocation audit verifying key")?;
    let proof = read_certificate_blob(r, "allocation audit proof")?;
    let public_input_len = read_bounded_len(
        r,
        "allocation audit stack public inputs",
        MAX_ALLOCATION_AUDIT_STACK_PUBLIC_INPUTS,
    )?;
    let mut stack_public_inputs = Vec::with_capacity(public_input_len);
    for _ in 0..public_input_len {
        stack_public_inputs.push(read_certificate_blob(
            r,
            "allocation audit stack public input",
        )?);
    }
    Ok(AllocationAuditProofEntry {
        kind,
        spent_segment_index,
        new_segment_index,
        public_inputs,
        stack: Groth16PrecompileStack {
            tag,
            verifying_key,
            proof,
            public_inputs: stack_public_inputs,
        },
    })
}

fn write_optional_u64(w: &mut Writer, value: Option<u64>) {
    match value {
        Some(value) => {
            w.write_u8(1);
            w.write_u64(value);
        }
        None => {
            w.write_u8(0);
            w.write_u64(0);
        }
    }
}

fn read_optional_u64(r: &mut Reader<'_>, label: &str) -> Result<Option<u64>, String> {
    let tag = r
        .read_u8()
        .map_err(allocation_audit_certificate_decode_err)?;
    let value = r
        .read_u64()
        .map_err(allocation_audit_certificate_decode_err)?;
    match tag {
        0 if value == 0 => Ok(None),
        0 => Err(format!(
            "allocation audit certificate {label} none tag carried a non-zero value"
        )),
        1 => Ok(Some(value)),
        _ => Err(format!(
            "allocation audit certificate {label} has bad optional tag {tag}"
        )),
    }
}

fn write_certificate_len(
    w: &mut Writer,
    label: &str,
    value: usize,
    max: usize,
) -> Result<(), String> {
    if value > max {
        return Err(format!(
            "{label} count {value} exceeds the allocation audit certificate limit {max}"
        ));
    }
    if value > u32::MAX as usize {
        return Err(format!("{label} count exceeds u32"));
    }
    w.write_u32(value as u32);
    Ok(())
}

fn read_bounded_len(r: &mut Reader<'_>, label: &str, max: usize) -> Result<usize, String> {
    let value = r
        .read_u32()
        .map_err(allocation_audit_certificate_decode_err)? as usize;
    if value > max {
        return Err(format!(
            "{label} count {value} exceeds the allocation audit certificate limit {max}"
        ));
    }
    Ok(value)
}

fn write_certificate_blob(w: &mut Writer, label: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_BLOB_BYTES as usize {
        return Err(format!(
            "{label} length {} exceeds the allocation audit certificate blob limit {}",
            bytes.len(),
            MAX_BLOB_BYTES
        ));
    }
    w.write_blob(bytes);
    Ok(())
}

fn read_certificate_blob(r: &mut Reader<'_>, label: &str) -> Result<Vec<u8>, String> {
    r.read_blob()
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("allocation audit certificate {label}: {e}"))
}

fn write_usize_as_u64(w: &mut Writer, label: &str, value: usize) -> Result<(), String> {
    if value > u64::MAX as usize {
        return Err(format!("allocation audit certificate {label} exceeds u64"));
    }
    w.write_u64(value as u64);
    Ok(())
}

fn read_usize_from_u64(r: &mut Reader<'_>, label: &str) -> Result<usize, String> {
    let value = r
        .read_u64()
        .map_err(allocation_audit_certificate_decode_err)?;
    usize::try_from(value).map_err(|_| format!("{label} exceeds usize"))
}

fn allocation_audit_certificate_decode_err(e: DecodeError) -> String {
    format!("allocation audit certificate decode: {e}")
}

/// Fixed allocation-vector circuit shapes with proof and upstream VM evidence.
///
/// This is RGK's current operational ZK support boundary. Shapes not listed
/// here remain native-validator bound until they are explicitly instantiated
/// and tested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocationCircuitShape {
    OneInZeroOut,
    OneInOneOut,
    TwoInTwoOut,
    ThreeInTwoOut,
    FourInTwoOut,
    FourInFourOut,
}

pub const SUPPORTED_ALLOCATION_CIRCUIT_SHAPES: [AllocationCircuitShape; 6] = [
    AllocationCircuitShape::OneInZeroOut,
    AllocationCircuitShape::OneInOneOut,
    AllocationCircuitShape::TwoInTwoOut,
    AllocationCircuitShape::ThreeInTwoOut,
    AllocationCircuitShape::FourInTwoOut,
    AllocationCircuitShape::FourInFourOut,
];

/// Production allocation-proof strategy for the current RGK ZK boundary.
///
/// RGK deliberately uses a bounded strategy until a recursive or otherwise
/// genuinely unbounded allocation-vector proof has been implemented and
/// evidenced. Wallet/prover callers must keep every full-state intermediate
/// transition inside the supported shapes before asking this module for an
/// allocation proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionAllocationProofStrategy {
    BoundedSupportedShapes,
}

pub const DEFAULT_ALLOCATION_PROOF_STRATEGY: ProductionAllocationProofStrategy =
    ProductionAllocationProofStrategy::BoundedSupportedShapes;
pub const DEFAULT_ALLOCATION_MAX_SPENT: usize = RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT;
pub const DEFAULT_ALLOCATION_MAX_NEW: usize = RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionAllocationProofPlan {
    pub strategy: ProductionAllocationProofStrategy,
    pub shape: AllocationCircuitShape,
}

impl ProductionAllocationProofStrategy {
    pub const fn label(self) -> &'static str {
        match self {
            Self::BoundedSupportedShapes => "bounded-supported-shapes",
        }
    }

    pub const fn max_spent_count(self) -> usize {
        match self {
            Self::BoundedSupportedShapes => DEFAULT_ALLOCATION_MAX_SPENT,
        }
    }

    pub const fn max_new_count(self) -> usize {
        match self {
            Self::BoundedSupportedShapes => DEFAULT_ALLOCATION_MAX_NEW,
        }
    }

    pub fn plan_counts(
        self,
        spent_count: usize,
        new_count: usize,
    ) -> Result<ProductionAllocationProofPlan, String> {
        RgkAllocationProofShape::require_counts(spent_count, new_count)
            .map(|native_shape| ProductionAllocationProofPlan {
                strategy: self,
                shape: AllocationCircuitShape::from_native(native_shape),
            })
            .map_err(|err| {
                format!(
                    "{err}; outside RGK production ZK strategy {}; keep each full-state intermediate transition inside supported shapes, or use a future recursive/aggregated allocation proof strategy before requesting an allocation proof",
                    self.label()
                )
            })
    }

    pub fn plan_statement(
        self,
        statement: &SemanticTransitionStatement,
    ) -> Result<ProductionAllocationProofPlan, String> {
        self.plan_counts(
            statement.spent_allocation_count as usize,
            statement.new_allocation_count as usize,
        )
    }
}

impl Default for ProductionAllocationProofStrategy {
    fn default() -> Self {
        DEFAULT_ALLOCATION_PROOF_STRATEGY
    }
}

impl AllocationCircuitShape {
    pub const fn from_native(shape: RgkAllocationProofShape) -> Self {
        match shape {
            RgkAllocationProofShape::OneInZeroOut => Self::OneInZeroOut,
            RgkAllocationProofShape::OneInOneOut => Self::OneInOneOut,
            RgkAllocationProofShape::TwoInTwoOut => Self::TwoInTwoOut,
            RgkAllocationProofShape::ThreeInTwoOut => Self::ThreeInTwoOut,
            RgkAllocationProofShape::FourInTwoOut => Self::FourInTwoOut,
            RgkAllocationProofShape::FourInFourOut => Self::FourInFourOut,
        }
    }

    pub const fn native_shape(self) -> RgkAllocationProofShape {
        match self {
            Self::OneInZeroOut => RgkAllocationProofShape::OneInZeroOut,
            Self::OneInOneOut => RgkAllocationProofShape::OneInOneOut,
            Self::TwoInTwoOut => RgkAllocationProofShape::TwoInTwoOut,
            Self::ThreeInTwoOut => RgkAllocationProofShape::ThreeInTwoOut,
            Self::FourInTwoOut => RgkAllocationProofShape::FourInTwoOut,
            Self::FourInFourOut => RgkAllocationProofShape::FourInFourOut,
        }
    }

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
        RgkAllocationProofShape::from_counts(spent_count, new_count).map(Self::from_native)
    }

    pub fn from_statement(statement: &SemanticTransitionStatement) -> Option<Self> {
        Self::from_counts(
            statement.spent_allocation_count as usize,
            statement.new_allocation_count as usize,
        )
    }

    pub fn require_counts(spent_count: usize, new_count: usize) -> Result<Self, String> {
        DEFAULT_ALLOCATION_PROOF_STRATEGY
            .plan_counts(spent_count, new_count)
            .map(|plan| plan.shape)
    }

    pub fn require_statement(statement: &SemanticTransitionStatement) -> Result<Self, String> {
        DEFAULT_ALLOCATION_PROOF_STRATEGY
            .plan_statement(statement)
            .map(|plan| plan.shape)
    }
}

fn supported_allocation_shape_labels() -> String {
    RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS.to_string()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupportedAllocationVectorWitness {
    OneInZeroOut(OneInZeroOutAllocationWitness),
    OneInOneOut(OneInOneOutAllocationWitness),
    TwoInTwoOut(TwoInTwoOutAllocationWitness),
    ThreeInTwoOut(FixedAllocationVectorWitness<3, 2>),
    FourInTwoOut(FixedAllocationVectorWitness<4, 2>),
    FourInFourOut(FixedAllocationVectorWitness<4, 4>),
}

impl SupportedAllocationVectorWitness {
    pub fn shape(&self) -> AllocationCircuitShape {
        match self {
            Self::OneInZeroOut(_) => AllocationCircuitShape::OneInZeroOut,
            Self::OneInOneOut(_) => AllocationCircuitShape::OneInOneOut,
            Self::TwoInTwoOut(_) => AllocationCircuitShape::TwoInTwoOut,
            Self::ThreeInTwoOut(_) => AllocationCircuitShape::ThreeInTwoOut,
            Self::FourInTwoOut(_) => AllocationCircuitShape::FourInTwoOut,
            Self::FourInFourOut(_) => AllocationCircuitShape::FourInFourOut,
        }
    }

    pub fn terminal_burn_from_allocation(
        spent: &RgkAllocation,
        transition_witness_txid: Bytes32,
    ) -> Result<Self, String> {
        Ok(Self::OneInZeroOut(
            OneInZeroOutAllocationWitness::from_allocation(spent, transition_witness_txid)?,
        ))
    }

    pub fn from_allocations(
        spent: &[RgkAllocation],
        new: &[RgkAllocation],
    ) -> Result<Self, String> {
        let shape = AllocationCircuitShape::require_counts(spent.len(), new.len())?;
        match shape {
            AllocationCircuitShape::OneInZeroOut => Err(
                "terminal 1x0 burn witnesses require an explicit transition witness txid"
                    .to_string(),
            ),
            AllocationCircuitShape::OneInOneOut => Ok(Self::OneInOneOut(
                OneInOneOutAllocationWitness::from_allocations(&spent[0], &new[0])?,
            )),
            AllocationCircuitShape::TwoInTwoOut => Ok(Self::TwoInTwoOut(
                TwoInTwoOutAllocationWitness::from_allocations(
                    [&spent[0], &spent[1]],
                    [&new[0], &new[1]],
                )?,
            )),
            AllocationCircuitShape::ThreeInTwoOut => Ok(Self::ThreeInTwoOut(
                FixedAllocationVectorWitness::<3, 2>::from_allocations(
                    [&spent[0], &spent[1], &spent[2]],
                    [&new[0], &new[1]],
                )?,
            )),
            AllocationCircuitShape::FourInTwoOut => Ok(Self::FourInTwoOut(
                FixedAllocationVectorWitness::<4, 2>::from_allocations(
                    [&spent[0], &spent[1], &spent[2], &spent[3]],
                    [&new[0], &new[1]],
                )?,
            )),
            AllocationCircuitShape::FourInFourOut => Ok(Self::FourInFourOut(
                FixedAllocationVectorWitness::<4, 4>::from_allocations(
                    [&spent[0], &spent[1], &spent[2], &spent[3]],
                    [&new[0], &new[1], &new[2], &new[3]],
                )?,
            )),
        }
    }
}

#[derive(Clone)]
pub enum SupportedAllocationVectorCircuit {
    OneInZeroOut(OneInZeroOutAllocationCircuit),
    OneInOneOut(OneInOneOutAllocationCircuit),
    TwoInTwoOut(TwoInTwoOutAllocationCircuit),
    ThreeInTwoOut(FixedAllocationVectorCircuit<3, 2>),
    FourInTwoOut(FixedAllocationVectorCircuit<4, 2>),
    FourInFourOut(FixedAllocationVectorCircuit<4, 4>),
}

impl SupportedAllocationVectorCircuit {
    pub fn from_statement_and_witness(
        statement: &SemanticTransitionStatement,
        witness: SupportedAllocationVectorWitness,
    ) -> Result<Self, String> {
        let statement_shape = AllocationCircuitShape::require_statement(statement)?;
        let witness_shape = witness.shape();
        if statement_shape != witness_shape {
            return Err(format!(
                "allocation witness shape {} does not match statement shape {}",
                witness_shape.label(),
                statement_shape.label()
            ));
        }

        match witness {
            SupportedAllocationVectorWitness::OneInZeroOut(witness) => Ok(Self::OneInZeroOut(
                OneInZeroOutAllocationCircuit::from_statement_and_witness(statement, witness)?,
            )),
            SupportedAllocationVectorWitness::OneInOneOut(witness) => Ok(Self::OneInOneOut(
                OneInOneOutAllocationCircuit::from_statement_and_witness(statement, witness)?,
            )),
            SupportedAllocationVectorWitness::TwoInTwoOut(witness) => Ok(Self::TwoInTwoOut(
                TwoInTwoOutAllocationCircuit::from_statement_and_witness(statement, witness)?,
            )),
            SupportedAllocationVectorWitness::ThreeInTwoOut(witness) => Ok(Self::ThreeInTwoOut(
                FixedAllocationVectorCircuit::<3, 2>::from_statement_and_witness(
                    statement, witness,
                )?,
            )),
            SupportedAllocationVectorWitness::FourInTwoOut(witness) => Ok(Self::FourInTwoOut(
                FixedAllocationVectorCircuit::<4, 2>::from_statement_and_witness(
                    statement, witness,
                )?,
            )),
            SupportedAllocationVectorWitness::FourInFourOut(witness) => Ok(Self::FourInFourOut(
                FixedAllocationVectorCircuit::<4, 4>::from_statement_and_witness(
                    statement, witness,
                )?,
            )),
        }
    }

    pub fn shape(&self) -> AllocationCircuitShape {
        match self {
            Self::OneInZeroOut(_) => AllocationCircuitShape::OneInZeroOut,
            Self::OneInOneOut(_) => AllocationCircuitShape::OneInOneOut,
            Self::TwoInTwoOut(_) => AllocationCircuitShape::TwoInTwoOut,
            Self::ThreeInTwoOut(_) => AllocationCircuitShape::ThreeInTwoOut,
            Self::FourInTwoOut(_) => AllocationCircuitShape::FourInTwoOut,
            Self::FourInFourOut(_) => AllocationCircuitShape::FourInFourOut,
        }
    }

    pub fn public_inputs(&self) -> &[u8] {
        match self {
            Self::OneInZeroOut(circuit) => &circuit.public_inputs,
            Self::OneInOneOut(circuit) => &circuit.public_inputs,
            Self::TwoInTwoOut(circuit) => &circuit.public_inputs,
            Self::ThreeInTwoOut(circuit) => &circuit.public_inputs,
            Self::FourInTwoOut(circuit) => &circuit.public_inputs,
            Self::FourInFourOut(circuit) => &circuit.public_inputs,
        }
    }
}

impl ConstraintSynthesizer<Fr> for ReceiptCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != PUBLIC_INPUT_LEN {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Public statement as 29 Fr inputs (8 LE bytes per Fr), matching
        // `ZkStatement::public_inputs`.
        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;

        // Private canonical receipt body. The preimage prefix is exactly the
        // `rgk_core::domain_hash(DomainTag::Receipt, body)` recipe.
        let witness = UInt8::new_witness_vec(cs.clone(), &self.witness)?;
        let mut preimage = UInt8::<Fr>::constant_vec(&receipt_domain_prefix());
        preimage.extend(witness.iter().cloned());

        let computed_digest = Sha256Gadget::<Fr>::digest(&preimage)?;
        let computed_frs = digest_bytes_as_frs(&computed_digest.0)?;

        // Equality constraints: the private receipt body hashes to the public
        // receipt id. A different body under the same public receipt id cannot
        // satisfy these constraints.
        enforce_frs_equal(&computed_frs, &public_frs[PUBLIC_RECEIPT_ID_FRS])?;

        // Constrain the body-derived public fields against the private receipt
        // body. The RGK asset id and chain id remain statement-level
        // fields: the receipt body binds chain through the domain string and
        // the RGK asset through the state-digest recipe outside this narrow
        // receipt circuit.
        let offsets = receipt_body_offsets(&self.witness)?;
        enforce_bytes_equal_public_frs(
            &witness[offsets.old_state..offsets.old_state + 32],
            &public_frs[PUBLIC_OLD_STATE_FRS],
        )?;
        enforce_bytes_equal_public_frs(
            &witness[offsets.new_state..offsets.new_state + 32],
            &public_frs[PUBLIC_NEW_STATE_FRS],
        )?;
        enforce_bytes_equal_public_frs(
            &witness[offsets.covenant..offsets.covenant + 32],
            &public_frs[PUBLIC_COVENANT_FRS],
        )?;
        enforce_bytes_equal_public_frs(
            &witness[offsets.transition..offsets.transition + 32],
            &public_frs[PUBLIC_TRANSITION_FRS],
        )?;
        enforce_bytes_equal_public_frs(
            &witness[offsets.continuation..offsets.continuation + 32],
            &public_frs[PUBLIC_CONTINUATION_FRS],
        )?;
        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for SemanticTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.witness.len() != SEMANTIC_PUBLIC_INPUT_LEN
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        burn_digest_encoding(&self.public_inputs)?;

        // Public statement as 48 Fr inputs (8 LE bytes per Fr), matching
        // `SemanticTransitionStatement::public_inputs`.
        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let witness = UInt8::new_witness_vec(cs.clone(), &self.witness)?;
        let witness_frs = digest_bytes_as_frs(&witness)?;
        enforce_frs_equal(&witness_frs, &public_frs)?;

        enforce_semantic_layout(&witness)
    }
}

impl ConstraintSynthesizer<Fr> for LaneDiscoveryCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != LANE_DISCOVERY_PUBLIC_INPUT_LEN {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Public lane discovery statement as 9 Fr inputs: 32-byte lane id,
        // 32-byte scan tag, and 8-byte epoch.
        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_lane_discovery_public_layout(&public_bytes)?;

        let view_key = UInt8::new_witness_vec(cs.clone(), &self.witness.view_key)?;
        let asset_id = UInt8::new_witness_vec(cs, &self.witness.asset_id)?;

        let mut lane_payload = Vec::with_capacity(72);
        lane_payload.extend(view_key.iter().cloned());
        lane_payload.extend(asset_id);
        lane_payload.extend(public_bytes[64..72].iter().cloned());
        let derived_lane_id = domain_hash_digest(b"rgk:lane:blinded-id:v1", lane_payload)?;
        derived_lane_id
            .as_slice()
            .enforce_equal(&public_bytes[0..32])?;

        let mut scan_payload = Vec::with_capacity(72);
        scan_payload.extend(view_key);
        scan_payload.extend(public_bytes[0..32].iter().cloned());
        scan_payload.extend(public_bytes[64..72].iter().cloned());
        let derived_scan_tag = domain_hash_digest(b"rgk:lane:scan-tag:v1", scan_payload)?;
        derived_scan_tag
            .as_slice()
            .enforce_equal(&public_bytes[32..64])?;

        Ok(())
    }
}

impl<const LANES: usize> ConstraintSynthesizer<Fr> for LaneGraphDiscoveryCircuit<LANES> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if LANES == 0 || self.public_inputs.len() != lane_graph_discovery_public_input_len(LANES) {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_lane_graph_discovery_public_layout::<LANES>(&public_bytes)?;

        let mut root_payload = UInt8::<Fr>::constant_vec(&(LANES as u64).to_le_bytes());
        root_payload.extend(
            public_bytes[LANE_GRAPH_DISCOVERY_ROOT_LEN..]
                .iter()
                .cloned(),
        );
        let graph_root = domain_hash_digest(b"rgk:lane:graph-root:v1", root_payload)?;
        graph_root
            .as_slice()
            .enforce_equal(&public_bytes[..LANE_GRAPH_DISCOVERY_ROOT_LEN])?;

        let view_key = UInt8::new_witness_vec(cs.clone(), &self.witness.view_key)?;
        let asset_id = UInt8::new_witness_vec(cs, &self.witness.asset_id)?;
        for node_index in 0..LANES {
            let offset =
                LANE_GRAPH_DISCOVERY_ROOT_LEN + node_index * LANE_DISCOVERY_PUBLIC_INPUT_LEN;
            let lane_id = &public_bytes[offset..offset + 32];
            let scan_tag = &public_bytes[offset + 32..offset + 64];
            let epoch = &public_bytes[offset + 64..offset + 72];

            let mut lane_payload = Vec::with_capacity(72);
            lane_payload.extend(view_key.iter().cloned());
            lane_payload.extend(asset_id.iter().cloned());
            lane_payload.extend(epoch.iter().cloned());
            let derived_lane_id = domain_hash_digest(b"rgk:lane:blinded-id:v1", lane_payload)?;
            derived_lane_id.as_slice().enforce_equal(lane_id)?;

            let mut scan_payload = Vec::with_capacity(72);
            scan_payload.extend(view_key.iter().cloned());
            scan_payload.extend(lane_id.iter().cloned());
            scan_payload.extend(epoch.iter().cloned());
            let derived_scan_tag = domain_hash_digest(b"rgk:lane:scan-tag:v1", scan_payload)?;
            derived_scan_tag.as_slice().enforce_equal(scan_tag)?;
        }

        Ok(())
    }
}

impl<const LANES: usize> ConstraintSynthesizer<Fr> for LaneGraphSegmentCircuit<LANES> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if LANES == 0 || self.public_inputs.len() != lane_graph_segment_public_input_len(LANES) {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_lane_graph_segment_public_layout::<LANES>(&public_bytes)?;

        let previous_root = &public_bytes[0..32];
        let next_root = &public_bytes[32..64];
        let segment_index = &public_bytes[64..72];
        let nodes = &public_bytes[LANE_GRAPH_SEGMENT_PREFIX_LEN..];

        let mut root_payload =
            Vec::with_capacity(32 + 8 + 8 + LANES * LANE_DISCOVERY_PUBLIC_INPUT_LEN);
        root_payload.extend(previous_root.iter().cloned());
        root_payload.extend(segment_index.iter().cloned());
        root_payload.extend(UInt8::<Fr>::constant_vec(&(LANES as u64).to_le_bytes()));
        root_payload.extend(nodes.iter().cloned());
        let computed_next_root =
            domain_hash_digest(b"rgk:lane:graph-segment-root:v1", root_payload)?;
        computed_next_root.as_slice().enforce_equal(next_root)?;

        let view_key = UInt8::new_witness_vec(cs.clone(), &self.witness.view_key)?;
        let asset_id = UInt8::new_witness_vec(cs, &self.witness.asset_id)?;
        for node_index in 0..LANES {
            let offset =
                LANE_GRAPH_SEGMENT_PREFIX_LEN + node_index * LANE_DISCOVERY_PUBLIC_INPUT_LEN;
            let lane_id = &public_bytes[offset..offset + 32];
            let scan_tag = &public_bytes[offset + 32..offset + 64];
            let epoch = &public_bytes[offset + 64..offset + 72];

            let mut lane_payload = Vec::with_capacity(72);
            lane_payload.extend(view_key.iter().cloned());
            lane_payload.extend(asset_id.iter().cloned());
            lane_payload.extend(epoch.iter().cloned());
            let derived_lane_id = domain_hash_digest(b"rgk:lane:blinded-id:v1", lane_payload)?;
            derived_lane_id.as_slice().enforce_equal(lane_id)?;

            let mut scan_payload = Vec::with_capacity(72);
            scan_payload.extend(view_key.iter().cloned());
            scan_payload.extend(lane_id.iter().cloned());
            scan_payload.extend(epoch.iter().cloned());
            let derived_scan_tag = domain_hash_digest(b"rgk:lane:scan-tag:v1", scan_payload)?;
            derived_scan_tag.as_slice().enforce_equal(scan_tag)?;
        }

        Ok(())
    }
}

impl ConstraintSynthesizer<Fr> for OneInOneOutAllocationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.statement_witness.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.allocation_witness.spent_allocation.len() != ALLOCATION_WITNESS_LEN
            || self.allocation_witness.new_allocation.len() != ALLOCATION_WITNESS_LEN
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let burn = burn_digest_encoding(&self.public_inputs)?;

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let statement = UInt8::new_witness_vec(cs.clone(), &self.statement_witness)?;
        let statement_frs = digest_bytes_as_frs(&statement)?;
        enforce_frs_equal(&statement_frs, &public_frs)?;
        enforce_semantic_layout(&statement)?;

        let spent = UInt8::new_witness_vec(cs.clone(), &self.allocation_witness.spent_allocation)?;
        let new = UInt8::new_witness_vec(cs, &self.allocation_witness.new_allocation)?;
        let spent_allocations = [spent.as_slice()];
        let new_allocations = [new.as_slice()];
        enforce_allocation_transition(&statement, &spent_allocations, &new_allocations, burn, None)
    }
}

impl ConstraintSynthesizer<Fr> for OneInZeroOutAllocationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.statement_witness.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.allocation_witness.spent_allocation.len() != ALLOCATION_WITNESS_LEN
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let burn = burn_digest_encoding(&self.public_inputs)?;
        if burn.is_none() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let statement = UInt8::new_witness_vec(cs.clone(), &self.statement_witness)?;
        let statement_frs = digest_bytes_as_frs(&statement)?;
        enforce_frs_equal(&statement_frs, &public_frs)?;
        enforce_semantic_layout(&statement)?;

        let spent = UInt8::new_witness_vec(cs.clone(), &self.allocation_witness.spent_allocation)?;
        let transition_witness_txid =
            UInt8::new_witness_vec(cs, &self.allocation_witness.transition_witness_txid)?;
        enforce_nonzero_bytes(&transition_witness_txid)?;
        let spent_allocations = [spent.as_slice()];
        let new_allocations: [&[UInt8<Fr>]; 0] = [];
        enforce_allocation_transition(
            &statement,
            &spent_allocations,
            &new_allocations,
            burn,
            Some(&transition_witness_txid),
        )
    }
}

impl ConstraintSynthesizer<Fr> for TwoInTwoOutAllocationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.statement_witness.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self
                .allocation_witness
                .spent_allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
            || self
                .allocation_witness
                .new_allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let burn = burn_digest_encoding(&self.public_inputs)?;

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let statement = UInt8::new_witness_vec(cs.clone(), &self.statement_witness)?;
        let statement_frs = digest_bytes_as_frs(&statement)?;
        enforce_frs_equal(&statement_frs, &public_frs)?;
        enforce_semantic_layout(&statement)?;

        let spent_0 =
            UInt8::new_witness_vec(cs.clone(), &self.allocation_witness.spent_allocations[0])?;
        let spent_1 =
            UInt8::new_witness_vec(cs.clone(), &self.allocation_witness.spent_allocations[1])?;
        let new_0 =
            UInt8::new_witness_vec(cs.clone(), &self.allocation_witness.new_allocations[0])?;
        let new_1 = UInt8::new_witness_vec(cs, &self.allocation_witness.new_allocations[1])?;
        let spent_allocations = [spent_0.as_slice(), spent_1.as_slice()];
        let new_allocations = [new_0.as_slice(), new_1.as_slice()];
        enforce_allocation_transition(&statement, &spent_allocations, &new_allocations, burn, None)
    }
}

impl<const SPENT: usize, const NEW: usize> ConstraintSynthesizer<Fr>
    for FixedAllocationVectorCircuit<SPENT, NEW>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if SPENT == 0
            || NEW == 0
            || self.public_inputs.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self.statement_witness.len() != SEMANTIC_PUBLIC_INPUT_LEN
            || self
                .allocation_witness
                .spent_allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
            || self
                .allocation_witness
                .new_allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let burn = burn_digest_encoding(&self.public_inputs)?;

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let statement = UInt8::new_witness_vec(cs.clone(), &self.statement_witness)?;
        let statement_frs = digest_bytes_as_frs(&statement)?;
        enforce_frs_equal(&statement_frs, &public_frs)?;
        enforce_semantic_layout(&statement)?;

        let spent_witnesses = self
            .allocation_witness
            .spent_allocations
            .iter()
            .map(|allocation| UInt8::new_witness_vec(cs.clone(), allocation))
            .collect::<Result<Vec<_>, _>>()?;
        let new_witnesses = self
            .allocation_witness
            .new_allocations
            .iter()
            .map(|allocation| UInt8::new_witness_vec(cs.clone(), allocation))
            .collect::<Result<Vec<_>, _>>()?;
        let spent_allocations = spent_witnesses
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let new_allocations = new_witnesses.iter().map(Vec::as_slice).collect::<Vec<_>>();
        enforce_allocation_transition(&statement, &spent_allocations, &new_allocations, burn, None)
    }
}

impl<const ALLOCS: usize> ConstraintSynthesizer<Fr> for AllocationTranscriptSegmentCircuit<ALLOCS> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if ALLOCS == 0
            || self.public_inputs.len() != ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN
            || self
                .allocation_witness
                .allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_allocation_transcript_segment_public_layout(&public_bytes)?;
        let segment_amount = UInt8::new_witness_vec(
            cs.clone(),
            &self.allocation_witness.segment_amount.to_le_bytes(),
        )?;
        let amount_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.allocation_witness.amount_blinding)?;

        let allocation_witnesses = self
            .allocation_witness
            .allocations
            .iter()
            .map(|allocation| UInt8::new_witness_vec(cs.clone(), allocation))
            .collect::<Result<Vec<_>, _>>()?;
        let allocation_slices = allocation_witnesses
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        enforce_allocation_transcript_segment::<ALLOCS>(
            &public_bytes,
            &segment_amount,
            &amount_blinding,
            &allocation_slices,
        )
    }
}

impl<const ALLOCS: usize> ConstraintSynthesizer<Fr>
    for AllocationConservationSegmentCircuit<ALLOCS>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if ALLOCS == 0
            || self.public_inputs.len() != ALLOCATION_CONSERVATION_SEGMENT_PUBLIC_INPUT_LEN
            || self
                .witness
                .transcript
                .allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_allocation_conservation_segment_public_layout(&public_bytes)?;

        let segment_amount = UInt8::new_witness_vec(
            cs.clone(),
            &self.witness.transcript.segment_amount.to_le_bytes(),
        )?;
        let amount_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.witness.transcript.amount_blinding)?;
        let previous_total =
            UInt8::new_witness_vec(cs.clone(), &self.witness.previous_total.to_le_bytes())?;
        let next_total =
            UInt8::new_witness_vec(cs.clone(), &self.witness.next_total.to_le_bytes())?;
        let previous_total_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.witness.previous_total_blinding)?;
        let next_total_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.witness.next_total_blinding)?;

        let allocation_witnesses = self
            .witness
            .transcript
            .allocations
            .iter()
            .map(|allocation| UInt8::new_witness_vec(cs.clone(), allocation))
            .collect::<Result<Vec<_>, _>>()?;
        let allocation_slices = allocation_witnesses
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        enforce_allocation_conservation_segment::<ALLOCS>(
            &public_bytes,
            &segment_amount,
            &amount_blinding,
            &previous_total,
            &next_total,
            &previous_total_blinding,
            &next_total_blinding,
            &allocation_slices,
        )
    }
}

impl ConstraintSynthesizer<Fr> for AllocationConservationFinalCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.public_inputs.len() != ALLOCATION_CONSERVATION_FINAL_PUBLIC_INPUT_LEN {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_allocation_conservation_final_public_layout(&public_bytes)?;

        let total = UInt8::new_witness_vec(cs.clone(), &self.witness.total.to_le_bytes())?;
        let spent_total_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.witness.spent_total_blinding)?;
        let new_total_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.witness.new_total_blinding)?;
        enforce_allocation_conservation_final(
            &public_bytes,
            &total,
            &spent_total_blinding,
            &new_total_blinding,
        )
    }
}

impl<const SPENT: usize, const NEW: usize> ConstraintSynthesizer<Fr>
    for AllocationExclusionSegmentPairCircuit<SPENT, NEW>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if SPENT == 0
            || NEW == 0
            || self.public_inputs.len() != ALLOCATION_EXCLUSION_SEGMENT_PAIR_PUBLIC_INPUT_LEN
            || self
                .witness
                .spent
                .allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
            || self
                .witness
                .new
                .allocations
                .iter()
                .any(|allocation| allocation.len() != ALLOCATION_WITNESS_LEN)
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        let public_frs = public_inputs_as_vars(cs.clone(), &self.public_inputs)?;
        let public_bytes = UInt8::new_witness_vec(cs.clone(), &self.public_inputs)?;
        let public_bytes_frs = digest_bytes_as_frs(&public_bytes)?;
        enforce_frs_equal(&public_bytes_frs, &public_frs)?;
        enforce_allocation_exclusion_segment_pair_public_layout(&public_bytes)?;

        let spent_amount =
            UInt8::new_witness_vec(cs.clone(), &self.witness.spent.segment_amount.to_le_bytes())?;
        let spent_blinding =
            UInt8::new_witness_vec(cs.clone(), &self.witness.spent.amount_blinding)?;
        let new_amount =
            UInt8::new_witness_vec(cs.clone(), &self.witness.new.segment_amount.to_le_bytes())?;
        let new_blinding = UInt8::new_witness_vec(cs.clone(), &self.witness.new.amount_blinding)?;

        let spent_witnesses = self
            .witness
            .spent
            .allocations
            .iter()
            .map(|allocation| UInt8::new_witness_vec(cs.clone(), allocation))
            .collect::<Result<Vec<_>, _>>()?;
        let new_witnesses = self
            .witness
            .new
            .allocations
            .iter()
            .map(|allocation| UInt8::new_witness_vec(cs.clone(), allocation))
            .collect::<Result<Vec<_>, _>>()?;
        let spent_allocations = spent_witnesses
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let new_allocations = new_witnesses.iter().map(Vec::as_slice).collect::<Vec<_>>();

        enforce_allocation_exclusion_segment_pair::<SPENT, NEW>(
            &public_bytes,
            &spent_amount,
            &spent_blinding,
            &new_amount,
            &new_blinding,
            &spent_allocations,
            &new_allocations,
        )
    }
}

fn encode_native_allocation(allocation: &RgkAllocation) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ALLOCATION_WITNESS_LEN);
    payload.push(allocation.anchor.chain as u8);
    payload.extend_from_slice(&allocation.anchor.covenant_outpoint.transaction_id);
    payload.extend_from_slice(&allocation.anchor.covenant_outpoint.index.to_le_bytes());
    payload.extend_from_slice(&allocation.anchor.covenant_id);
    payload.extend_from_slice(&allocation.anchor.witness_txid);
    payload.extend_from_slice(&allocation.anchor.daa_score.to_le_bytes());
    payload.extend_from_slice(&allocation.anchor.confirmation_depth.to_le_bytes());
    payload.extend_from_slice(&allocation.amount.to_le_bytes());
    payload.extend_from_slice(&allocation.encrypted_note_commitment);
    payload
}

fn allocation_sort_key(allocation: &RgkAllocation) -> (KaspaOutpoint, Bytes32, Bytes32, u64, u64) {
    (
        allocation.anchor.covenant_outpoint,
        allocation.anchor.covenant_id,
        allocation.anchor.witness_txid,
        allocation.anchor.daa_score,
        allocation.amount,
    )
}

fn allocation_amount_sum(allocations: &[RgkAllocation]) -> Result<u64, String> {
    allocations.iter().try_fold(0u64, |sum, allocation| {
        sum.checked_add(allocation.amount)
            .ok_or_else(|| "allocation amount sum overflow".to_string())
    })
}

/// Blinded commitment to a private running total in an allocation-conservation
/// proof chain.
pub fn allocation_conservation_total_commitment(
    side: RgkAllocationTranscriptSide,
    total_count: u64,
    running_total: u64,
    blinding: Bytes32,
) -> Bytes32 {
    let mut payload = Vec::with_capacity(49);
    payload.push(side.as_u8());
    payload.extend_from_slice(&total_count.to_le_bytes());
    payload.extend_from_slice(&running_total.to_le_bytes());
    payload.extend_from_slice(&blinding);
    rgk_asset::internal::asset_domain_hash("rgk:asset:allocation-conservation-total:v1", &payload)
}

fn allocation_witness_amount<const ALLOCS: usize>(allocations: &[Vec<u8>; ALLOCS]) -> Option<u64> {
    allocations.iter().try_fold(0u64, |sum, allocation| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(allocation.get(117..125)?);
        sum.checked_add(u64::from_le_bytes(bytes))
    })
}

fn allocation_conservation_segment_matches<const ALLOCS: usize>(
    statement: &AllocationConservationSegmentStatement<ALLOCS>,
    witness: &AllocationConservationSegmentWitness<ALLOCS>,
) -> bool {
    if witness.previous_total_blinding == [0u8; 32] || witness.next_total_blinding == [0u8; 32] {
        return false;
    }
    if statement.transcript.segment_index == 0 && witness.previous_total != 0 {
        return false;
    }
    if !statement.transcript.matches_witness(&witness.transcript) {
        return false;
    }
    let Some(segment_amount) = allocation_witness_amount(&witness.transcript.allocations) else {
        return false;
    };
    let Some(next_total) = witness.previous_total.checked_add(segment_amount) else {
        return false;
    };
    next_total == witness.next_total
        && statement.previous_total_commitment
            == allocation_conservation_total_commitment(
                statement.transcript.side,
                statement.transcript.total_count,
                witness.previous_total,
                witness.previous_total_blinding,
            )
        && statement.next_total_commitment
            == allocation_conservation_total_commitment(
                statement.transcript.side,
                statement.transcript.total_count,
                witness.next_total,
                witness.next_total_blinding,
            )
}

fn allocation_exclusion_segment_pair_matches<const SPENT: usize, const NEW: usize>(
    statement: &AllocationExclusionSegmentPairStatement<SPENT, NEW>,
    witness: &AllocationExclusionSegmentPairWitness<SPENT, NEW>,
) -> bool {
    if SPENT == 0 || NEW == 0 {
        return false;
    }
    if witness
        .spent
        .allocations
        .iter()
        .chain(witness.new.allocations.iter())
        .any(|allocation| {
            allocation.len() != ALLOCATION_WITNESS_LEN || allocation[0] != statement.chain_id as u8
        })
    {
        return false;
    }

    for spent in &witness.spent.allocations {
        for new in &witness.new.allocations {
            if spent[1..41] == new[1..41] {
                return false;
            }
        }
    }

    let Some(spent_amount) = allocation_witness_amount(&witness.spent.allocations) else {
        return false;
    };
    let Some(new_amount) = allocation_witness_amount(&witness.new.allocations) else {
        return false;
    };
    spent_amount == witness.spent.segment_amount
        && new_amount == witness.new.segment_amount
        && statement.spent_next_root
            == allocation_transcript_segment_root_from_witness(
                statement.spent_previous_root,
                RgkAllocationTranscriptSide::Spent,
                statement.spent_segment_index,
                statement.spent_total_count,
                &witness.spent.allocations,
            )
        && statement.new_next_root
            == allocation_transcript_segment_root_from_witness(
                statement.new_previous_root,
                RgkAllocationTranscriptSide::New,
                statement.new_segment_index,
                statement.new_total_count,
                &witness.new.allocations,
            )
        && statement.spent_amount_commitment
            == allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::Spent,
                statement.spent_segment_index,
                statement.spent_total_count,
                witness.spent.segment_amount,
                witness.spent.amount_blinding,
            )
        && statement.new_amount_commitment
            == allocation_transcript_amount_commitment(
                RgkAllocationTranscriptSide::New,
                statement.new_segment_index,
                statement.new_total_count,
                witness.new.segment_amount,
                witness.new.amount_blinding,
            )
}

struct AllocationTranscriptChainAudit {
    chain_id: KaspaChainId,
    total_count: u64,
    final_root: Bytes32,
}

fn verify_allocation_transcript_chain<const ALLOCS: usize>(
    label: &str,
    side: RgkAllocationTranscriptSide,
    segments: &[AllocationTranscriptSegmentStatement<ALLOCS>],
) -> Result<AllocationTranscriptChainAudit, String> {
    if ALLOCS == 0 {
        return Err(format!(
            "{label} transcript chain requires a non-zero segment arity"
        ));
    }
    let first = segments
        .first()
        .ok_or_else(|| format!("{label} transcript chain must contain at least one segment"))?;
    if first.side != side {
        return Err(format!("{label} transcript chain has the wrong side"));
    }
    let empty_root = rgk_asset::allocation_transcript_empty_root(side);
    if first.previous_root != empty_root {
        return Err(format!(
            "{label} transcript chain must start at the empty root"
        ));
    }
    let expected_total_usize = segments
        .len()
        .checked_mul(ALLOCS)
        .ok_or_else(|| format!("{label} transcript chain allocation count overflow"))?;
    if expected_total_usize > u64::MAX as usize {
        return Err(format!(
            "{label} transcript chain allocation count exceeds u64"
        ));
    }
    let expected_total = expected_total_usize as u64;
    if first.total_count != expected_total {
        return Err(format!(
            "{label} transcript chain total_count={} does not equal segment coverage {expected_total}",
            first.total_count
        ));
    }

    let chain_id = first.chain_id;
    let mut previous_next_root = first.previous_root;
    for (position, segment) in segments.iter().enumerate() {
        if position > u64::MAX as usize {
            return Err(format!("{label} transcript chain index exceeds u64"));
        }
        let expected_index = position as u64;
        if segment.side != side {
            return Err(format!(
                "{label} transcript segment {position} has the wrong side"
            ));
        }
        if segment.chain_id != chain_id {
            return Err(format!(
                "{label} transcript segment {position} has a different chain id"
            ));
        }
        if segment.segment_index != expected_index {
            return Err(format!(
                "{label} transcript segment index {} is not contiguous at {expected_index}",
                segment.segment_index
            ));
        }
        if segment.total_count != expected_total {
            return Err(format!(
                "{label} transcript segment {position} total_count={} does not equal {expected_total}",
                segment.total_count
            ));
        }
        if segment.previous_root != previous_next_root {
            return Err(format!(
                "{label} transcript segment {position} does not link to the previous segment root"
            ));
        }
        previous_next_root = segment.next_root;
    }

    Ok(AllocationTranscriptChainAudit {
        chain_id,
        total_count: expected_total,
        final_root: previous_next_root,
    })
}

fn verify_allocation_conservation_chain<const ALLOCS: usize>(
    label: &str,
    transcripts: &[AllocationTranscriptSegmentStatement<ALLOCS>],
    conservation: &[AllocationConservationSegmentStatement<ALLOCS>],
    final_total_commitment: Bytes32,
) -> Result<(), String> {
    if conservation.len() != transcripts.len() {
        return Err(format!(
            "{label} conservation chain has {} segments for {} transcript segments",
            conservation.len(),
            transcripts.len()
        ));
    }
    let mut previous_next_commitment = None;
    for (position, (transcript, statement)) in
        transcripts.iter().zip(conservation.iter()).enumerate()
    {
        if &statement.transcript != transcript {
            return Err(format!(
                "{label} conservation segment {position} does not bind the matching transcript segment"
            ));
        }
        if position == 0 && transcript.segment_index != 0 {
            return Err(format!(
                "{label} conservation chain does not start at segment index zero"
            ));
        }
        if let Some(expected_previous) = previous_next_commitment {
            if statement.previous_total_commitment != expected_previous {
                return Err(format!(
                    "{label} conservation segment {position} does not link to the previous running-total commitment"
                ));
            }
        }
        previous_next_commitment = Some(statement.next_total_commitment);
    }
    if previous_next_commitment != Some(final_total_commitment) {
        return Err(format!(
            "{label} conservation chain terminal commitment does not match final equality statement"
        ));
    }
    Ok(())
}

fn verify_allocation_exclusion_grid<const SPENT: usize, const NEW: usize>(
    spent_transcripts: &[AllocationTranscriptSegmentStatement<SPENT>],
    new_transcripts: &[AllocationTranscriptSegmentStatement<NEW>],
    exclusions: &[AllocationExclusionSegmentPairStatement<SPENT, NEW>],
    chain_id: KaspaChainId,
) -> Result<(), String> {
    let expected_entries = spent_transcripts
        .len()
        .checked_mul(new_transcripts.len())
        .ok_or_else(|| "allocation exclusion grid size overflow".to_string())?;
    if exclusions.len() != expected_entries {
        return Err(format!(
            "allocation exclusion grid has {} pairs, expected {expected_entries}",
            exclusions.len()
        ));
    }

    let mut seen = Vec::with_capacity(exclusions.len());
    for exclusion in exclusions {
        if exclusion.chain_id != chain_id {
            return Err("allocation exclusion grid contains a mixed chain id".to_string());
        }
        let pair = (exclusion.spent_segment_index, exclusion.new_segment_index);
        if seen.contains(&pair) {
            return Err(format!(
                "duplicate allocation exclusion grid pair spent={} new={}",
                pair.0, pair.1
            ));
        }
        let spent = spent_transcripts
            .iter()
            .find(|segment| segment.segment_index == exclusion.spent_segment_index)
            .ok_or_else(|| {
                format!(
                    "allocation exclusion pair references unknown spent segment {}",
                    exclusion.spent_segment_index
                )
            })?;
        let new = new_transcripts
            .iter()
            .find(|segment| segment.segment_index == exclusion.new_segment_index)
            .ok_or_else(|| {
                format!(
                    "allocation exclusion pair references unknown new segment {}",
                    exclusion.new_segment_index
                )
            })?;

        if exclusion.spent_previous_root != spent.previous_root
            || exclusion.spent_next_root != spent.next_root
            || exclusion.spent_total_count != spent.total_count
            || exclusion.spent_amount_commitment != spent.segment_amount_commitment
        {
            return Err(format!(
                "allocation exclusion pair spent={} new={} does not bind the spent transcript segment",
                pair.0, pair.1
            ));
        }
        if exclusion.new_previous_root != new.previous_root
            || exclusion.new_next_root != new.next_root
            || exclusion.new_total_count != new.total_count
            || exclusion.new_amount_commitment != new.segment_amount_commitment
        {
            return Err(format!(
                "allocation exclusion pair spent={} new={} does not bind the new transcript segment",
                pair.0, pair.1
            ));
        }
        seen.push(pair);
    }

    for spent in spent_transcripts {
        for new in new_transcripts {
            if !seen.contains(&(spent.segment_index, new.segment_index)) {
                return Err(format!(
                    "allocation exclusion grid is missing pair spent={} new={}",
                    spent.segment_index, new.segment_index
                ));
            }
        }
    }
    Ok(())
}

fn allocation_transcript_segment_root_from_witness<const ALLOCS: usize>(
    previous_root: Bytes32,
    side: RgkAllocationTranscriptSide,
    segment_index: u64,
    total_count: u64,
    allocations: &[Vec<u8>; ALLOCS],
) -> Bytes32 {
    let mut payload = Vec::with_capacity(57 + ALLOCS * ALLOCATION_WITNESS_LEN);
    payload.extend_from_slice(&previous_root);
    payload.push(side.as_u8());
    payload.extend_from_slice(&segment_index.to_le_bytes());
    payload.extend_from_slice(&total_count.to_le_bytes());
    payload.extend_from_slice(&(ALLOCS as u64).to_le_bytes());
    for allocation in allocations {
        payload.extend_from_slice(allocation);
    }
    rgk_asset::internal::asset_domain_hash(
        "rgk:asset:allocation-transcript-segment-root:v1",
        &payload,
    )
}

fn enforce_allocation_transition(
    statement: &[UInt8<Fr>],
    spent_allocations: &[&[UInt8<Fr>]],
    new_allocations: &[&[UInt8<Fr>]],
    burn: Option<BurnDigestEncoding>,
    terminal_witness_txid: Option<&[UInt8<Fr>]>,
) -> Result<(), SynthesisError> {
    if statement.len() != SEMANTIC_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    validate_nonempty_allocation_slices(spent_allocations)?;
    if new_allocations.is_empty() {
        let witness_txid = terminal_witness_txid.ok_or(SynthesisError::Unsatisfiable)?;
        if witness_txid.len() != 32 || burn.is_none() {
            return Err(SynthesisError::Unsatisfiable);
        }
        enforce_nonzero_bytes(witness_txid)?;
    } else {
        validate_nonempty_allocation_slices(new_allocations)?;
        if terminal_witness_txid.is_some() {
            return Err(SynthesisError::Unsatisfiable);
        }
    }

    enforce_bytes_equal_const(
        &statement[432..440],
        &(spent_allocations.len() as u64).to_le_bytes(),
    )?;
    enforce_bytes_equal_const(
        &statement[440..448],
        &(new_allocations.len() as u64).to_le_bytes(),
    )?;

    for allocation in spent_allocations {
        enforce_allocation_common(statement, allocation)?;
    }
    for allocation in new_allocations {
        enforce_allocation_common(statement, allocation)?;
        allocation[1..33].enforce_equal(&allocation[69..101])?;
    }
    enforce_distinct_outpoints(spent_allocations)?;
    enforce_distinct_outpoints(new_allocations)?;
    enforce_spent_anchors_not_reused(spent_allocations, new_allocations)?;
    enforce_allocation_supply_delta(statement, spent_allocations, new_allocations)?;

    let spent_root = allocation_root_digest(spent_allocations)?;
    let new_root = allocation_root_digest(new_allocations)?;
    let old_state_digest = state_digest(statement, &spent_root, &statement[328..360])?;
    old_state_digest
        .as_slice()
        .enforce_equal(&statement[72..104])?;
    let new_state_digest = state_digest(statement, &new_root, &statement[360..392])?;
    new_state_digest
        .as_slice()
        .enforce_equal(&statement[104..136])?;

    let shape_root = continuation_shape_root_digest(statement, new_allocations)?;
    shape_root.as_slice().enforce_equal(&statement[200..232])?;
    let continuation_commitment =
        continuation_commitment_digest(statement, &spent_root, &shape_root, burn)?;
    continuation_commitment
        .as_slice()
        .enforce_equal(&statement[168..200])?;

    let transition_digest = transition_digest(
        statement,
        spent_allocations,
        new_allocations,
        burn,
        terminal_witness_txid,
    )?;
    transition_digest
        .as_slice()
        .enforce_equal(&statement[136..168])?;

    Ok(())
}

fn enforce_allocation_transcript_segment<const ALLOCS: usize>(
    public: &[UInt8<Fr>],
    segment_amount: &[UInt8<Fr>],
    amount_blinding: &[UInt8<Fr>],
    allocations: &[&[UInt8<Fr>]],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN || allocations.len() != ALLOCS
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    if segment_amount.len() != 8 || amount_blinding.len() != 32 {
        return Err(SynthesisError::Unsatisfiable);
    }
    validate_nonempty_allocation_slices(allocations)?;
    enforce_nonzero_bytes(segment_amount)?;
    enforce_nonzero_bytes(amount_blinding)?;

    for allocation in allocations {
        enforce_allocation_common_for_chain(&public[68], allocation)?;
    }
    enforce_distinct_outpoints(allocations)?;

    let segment_amount_fr = le_bytes_as_fr(segment_amount)?;
    let amount_sum = sum_allocation_amounts(allocations)?;
    amount_sum.enforce_equal(&segment_amount_fr)?;
    let amount_commitment = allocation_transcript_amount_commitment_digest(
        &public[72],
        &public[80..88],
        &public[88..96],
        segment_amount,
        amount_blinding,
    )?;
    amount_commitment
        .as_slice()
        .enforce_equal(&public[96..128])?;

    let computed_next_root = allocation_transcript_segment_root_digest::<ALLOCS>(
        &public[0..32],
        &public[72],
        &public[80..88],
        &public[88..96],
        allocations,
    )?;
    computed_next_root
        .as_slice()
        .enforce_equal(&public[32..64])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn enforce_allocation_conservation_segment<const ALLOCS: usize>(
    public: &[UInt8<Fr>],
    segment_amount: &[UInt8<Fr>],
    amount_blinding: &[UInt8<Fr>],
    previous_total: &[UInt8<Fr>],
    next_total: &[UInt8<Fr>],
    previous_total_blinding: &[UInt8<Fr>],
    next_total_blinding: &[UInt8<Fr>],
    allocations: &[&[UInt8<Fr>]],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_CONSERVATION_SEGMENT_PUBLIC_INPUT_LEN
        || previous_total.len() != 8
        || next_total.len() != 8
        || previous_total_blinding.len() != 32
        || next_total_blinding.len() != 32
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_allocation_transcript_segment::<ALLOCS>(
        &public[..ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN],
        segment_amount,
        amount_blinding,
        allocations,
    )?;
    enforce_nonzero_bytes(previous_total_blinding)?;
    enforce_nonzero_bytes(next_total_blinding)?;

    let previous_total_fr = le_bytes_as_fr(previous_total)?;
    let next_total_fr = le_bytes_as_fr(next_total)?;
    let segment_amount_fr = le_bytes_as_fr(segment_amount)?;
    let computed_next_total = previous_total_fr + segment_amount_fr;
    computed_next_total.enforce_equal(&next_total_fr)?;
    enforce_initial_conservation_total_zero_for_first_segment(&public[80..88], previous_total)?;

    let previous_total_commitment = allocation_conservation_total_commitment_digest(
        &public[72],
        &public[88..96],
        previous_total,
        previous_total_blinding,
    )?;
    previous_total_commitment
        .as_slice()
        .enforce_equal(&public[128..160])?;
    let next_total_commitment = allocation_conservation_total_commitment_digest(
        &public[72],
        &public[88..96],
        next_total,
        next_total_blinding,
    )?;
    next_total_commitment
        .as_slice()
        .enforce_equal(&public[160..192])?;
    Ok(())
}

fn enforce_initial_conservation_total_zero_for_first_segment(
    segment_index: &[UInt8<Fr>],
    previous_total: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if segment_index.len() != 8 || previous_total.len() != 8 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let is_first_segment = segment_index.is_eq(&UInt8::constant_vec(&[0u8; 8]))?;
    let not_first_segment = !&is_first_segment;
    for byte in previous_total {
        let byte_is_zero = byte.is_eq(&UInt8::constant(0))?;
        Boolean::kary_or(&[not_first_segment.clone(), byte_is_zero])?
            .enforce_equal(&Boolean::TRUE)?;
    }
    Ok(())
}

fn enforce_allocation_conservation_final(
    public: &[UInt8<Fr>],
    total: &[UInt8<Fr>],
    spent_total_blinding: &[UInt8<Fr>],
    new_total_blinding: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_CONSERVATION_FINAL_PUBLIC_INPUT_LEN
        || total.len() != 8
        || spent_total_blinding.len() != 32
        || new_total_blinding.len() != 32
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(total)?;
    enforce_nonzero_bytes(spent_total_blinding)?;
    enforce_nonzero_bytes(new_total_blinding)?;

    let spent_total_commitment = allocation_conservation_total_commitment_digest(
        &UInt8::constant(RgkAllocationTranscriptSide::Spent.as_u8()),
        &public[0..8],
        total,
        spent_total_blinding,
    )?;
    spent_total_commitment
        .as_slice()
        .enforce_equal(&public[16..48])?;
    let new_total_commitment = allocation_conservation_total_commitment_digest(
        &UInt8::constant(RgkAllocationTranscriptSide::New.as_u8()),
        &public[8..16],
        total,
        new_total_blinding,
    )?;
    new_total_commitment
        .as_slice()
        .enforce_equal(&public[48..80])?;
    Ok(())
}

fn enforce_allocation_exclusion_segment_pair<const SPENT: usize, const NEW: usize>(
    public: &[UInt8<Fr>],
    spent_amount: &[UInt8<Fr>],
    spent_blinding: &[UInt8<Fr>],
    new_amount: &[UInt8<Fr>],
    new_blinding: &[UInt8<Fr>],
    spent_allocations: &[&[UInt8<Fr>]],
    new_allocations: &[&[UInt8<Fr>]],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_EXCLUSION_SEGMENT_PAIR_PUBLIC_INPUT_LEN
        || spent_allocations.len() != SPENT
        || new_allocations.len() != NEW
        || spent_amount.len() != 8
        || new_amount.len() != 8
        || spent_blinding.len() != 32
        || new_blinding.len() != 32
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    validate_nonempty_allocation_slices(spent_allocations)?;
    validate_nonempty_allocation_slices(new_allocations)?;
    enforce_nonzero_bytes(spent_amount)?;
    enforce_nonzero_bytes(new_amount)?;
    enforce_nonzero_bytes(spent_blinding)?;
    enforce_nonzero_bytes(new_blinding)?;

    for allocation in spent_allocations {
        enforce_allocation_common_for_chain(&public[132], allocation)?;
    }
    for allocation in new_allocations {
        enforce_allocation_common_for_chain(&public[132], allocation)?;
    }
    enforce_distinct_outpoints(spent_allocations)?;
    enforce_distinct_outpoints(new_allocations)?;
    enforce_spent_anchors_not_reused(spent_allocations, new_allocations)?;

    sum_allocation_amounts(spent_allocations)?.enforce_equal(&le_bytes_as_fr(spent_amount)?)?;
    sum_allocation_amounts(new_allocations)?.enforce_equal(&le_bytes_as_fr(new_amount)?)?;

    let spent_amount_commitment = allocation_transcript_amount_commitment_digest(
        &UInt8::constant(RgkAllocationTranscriptSide::Spent.as_u8()),
        &public[136..144],
        &public[152..160],
        spent_amount,
        spent_blinding,
    )?;
    spent_amount_commitment
        .as_slice()
        .enforce_equal(&public[168..200])?;
    let new_amount_commitment = allocation_transcript_amount_commitment_digest(
        &UInt8::constant(RgkAllocationTranscriptSide::New.as_u8()),
        &public[144..152],
        &public[160..168],
        new_amount,
        new_blinding,
    )?;
    new_amount_commitment
        .as_slice()
        .enforce_equal(&public[200..232])?;

    let spent_next_root = allocation_transcript_segment_root_digest::<SPENT>(
        &public[0..32],
        &UInt8::constant(RgkAllocationTranscriptSide::Spent.as_u8()),
        &public[136..144],
        &public[152..160],
        spent_allocations,
    )?;
    spent_next_root.as_slice().enforce_equal(&public[32..64])?;
    let new_next_root = allocation_transcript_segment_root_digest::<NEW>(
        &public[64..96],
        &UInt8::constant(RgkAllocationTranscriptSide::New.as_u8()),
        &public[144..152],
        &public[160..168],
        new_allocations,
    )?;
    new_next_root.as_slice().enforce_equal(&public[96..128])?;
    Ok(())
}

fn validate_nonempty_allocation_slices(allocations: &[&[UInt8<Fr>]]) -> Result<(), SynthesisError> {
    if allocations.is_empty() {
        return Err(SynthesisError::Unsatisfiable);
    }
    for allocation in allocations {
        if allocation.len() != ALLOCATION_WITNESS_LEN {
            return Err(SynthesisError::Unsatisfiable);
        }
    }
    Ok(())
}

fn enforce_allocation_common(
    statement: &[UInt8<Fr>],
    allocation: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    enforce_allocation_common_for_chain(&statement[4], allocation)
}

fn enforce_allocation_common_for_chain(
    chain_value: &UInt8<Fr>,
    allocation: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    allocation[0].enforce_equal(chain_value)?;
    enforce_nonzero_bytes(&allocation[1..37])?; // covenant txid
    enforce_nonzero_bytes(&allocation[37..69])?; // covenant id
    enforce_nonzero_bytes(&allocation[69..101])?; // witness txid
    enforce_nonzero_bytes(&allocation[109..117])?; // confirmation depth
    enforce_nonzero_bytes(&allocation[117..125])?; // amount
    enforce_nonzero_bytes(&allocation[125..157])?; // encrypted note
    Ok(())
}

fn enforce_distinct_outpoints(allocations: &[&[UInt8<Fr>]]) -> Result<(), SynthesisError> {
    for left in 0..allocations.len() {
        for right in left + 1..allocations.len() {
            allocations[left][1..41]
                .is_neq(&allocations[right][1..41])?
                .enforce_equal(&Boolean::TRUE)?;
        }
    }
    Ok(())
}

fn enforce_spent_anchors_not_reused(
    spent_allocations: &[&[UInt8<Fr>]],
    new_allocations: &[&[UInt8<Fr>]],
) -> Result<(), SynthesisError> {
    for spent in spent_allocations {
        for new in new_allocations {
            spent[1..41]
                .is_neq(&new[1..41])?
                .enforce_equal(&Boolean::TRUE)?;
        }
    }
    Ok(())
}

fn enforce_allocation_supply_delta(
    statement: &[UInt8<Fr>],
    spent_allocations: &[&[UInt8<Fr>]],
    new_allocations: &[&[UInt8<Fr>]],
) -> Result<(), SynthesisError> {
    let public_spent_supply = le_bytes_as_fr(&statement[456..464])?;
    let public_new_supply = le_bytes_as_fr(&statement[464..472])?;
    let public_burned_supply = le_bytes_as_fr(&statement[472..480])?;
    let spent_sum = sum_allocation_amounts(spent_allocations)?;
    let new_sum = sum_allocation_amounts(new_allocations)?;

    spent_sum.enforce_equal(&public_spent_supply)?;
    new_sum.enforce_equal(&public_new_supply)?;
    let accounted_supply = new_sum + public_burned_supply;
    spent_sum.enforce_equal(&accounted_supply)
}

fn sum_allocation_amounts(allocations: &[&[UInt8<Fr>]]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut iter = allocations.iter();
    let Some(first) = iter.next() else {
        return Ok(FpVar::<Fr>::Constant(Fr::from(0u64)));
    };
    let mut sum = le_bytes_as_fr(&first[117..125])?;
    for allocation in iter {
        sum += le_bytes_as_fr(&allocation[117..125])?;
    }
    Ok(sum)
}

fn allocation_root_digest(allocations: &[&[UInt8<Fr>]]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut payload = UInt8::<Fr>::constant_vec(&(allocations.len() as u32).to_le_bytes());
    for allocation in allocations {
        payload.extend(allocation.iter().cloned());
    }
    domain_hash_digest(b"rgk:asset:allocation-root:v1", payload)
}

fn encode_burn_digest(payload: &mut Vec<UInt8<Fr>>, burn: Option<BurnDigestEncoding>) {
    match burn {
        None => payload.push(UInt8::constant(0)),
        Some(burn) => {
            payload.push(UInt8::constant(1));
            payload.extend(UInt8::<Fr>::constant_vec(&burn.amount));
            payload.extend(UInt8::<Fr>::constant_vec(&burn.authorization_commitment));
        }
    }
}

fn allocation_transcript_segment_root_digest<const ALLOCS: usize>(
    previous_root: &[UInt8<Fr>],
    side: &UInt8<Fr>,
    segment_index: &[UInt8<Fr>],
    total_count: &[UInt8<Fr>],
    allocations: &[&[UInt8<Fr>]],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    if previous_root.len() != 32
        || segment_index.len() != 8
        || total_count.len() != 8
        || allocations.len() != ALLOCS
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut payload = Vec::with_capacity(57 + ALLOCS * ALLOCATION_WITNESS_LEN);
    payload.extend(previous_root.iter().cloned());
    payload.push(side.clone());
    payload.extend(segment_index.iter().cloned());
    payload.extend(total_count.iter().cloned());
    payload.extend(UInt8::<Fr>::constant_vec(&(ALLOCS as u64).to_le_bytes()));
    for allocation in allocations {
        payload.extend(allocation.iter().cloned());
    }
    domain_hash_digest(b"rgk:asset:allocation-transcript-segment-root:v1", payload)
}

fn allocation_transcript_amount_commitment_digest(
    side: &UInt8<Fr>,
    segment_index: &[UInt8<Fr>],
    total_count: &[UInt8<Fr>],
    segment_amount: &[UInt8<Fr>],
    amount_blinding: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    if segment_index.len() != 8
        || total_count.len() != 8
        || segment_amount.len() != 8
        || amount_blinding.len() != 32
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut payload = Vec::with_capacity(57);
    payload.push(side.clone());
    payload.extend(segment_index.iter().cloned());
    payload.extend(total_count.iter().cloned());
    payload.extend(segment_amount.iter().cloned());
    payload.extend(amount_blinding.iter().cloned());
    domain_hash_digest(b"rgk:asset:allocation-transcript-amount:v1", payload)
}

fn allocation_conservation_total_commitment_digest(
    side: &UInt8<Fr>,
    total_count: &[UInt8<Fr>],
    running_total: &[UInt8<Fr>],
    blinding: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    if total_count.len() != 8 || running_total.len() != 8 || blinding.len() != 32 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut payload = Vec::with_capacity(49);
    payload.push(side.clone());
    payload.extend(total_count.iter().cloned());
    payload.extend(running_total.iter().cloned());
    payload.extend(blinding.iter().cloned());
    domain_hash_digest(b"rgk:asset:allocation-conservation-total:v1", payload)
}

fn state_digest(
    statement: &[UInt8<Fr>],
    allocation_root: &[UInt8<Fr>],
    owner_commitment: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut payload = Vec::with_capacity(201);
    payload.extend(statement[40..72].iter().cloned()); // asset_id
    payload.extend(statement[424..432].iter().cloned()); // total_supply
    payload.extend(allocation_root.iter().cloned());
    payload.extend(statement[264..296].iter().cloned()); // policy_commitment
    payload.extend(statement[296..328].iter().cloned()); // metadata_commitment
    payload.extend(owner_commitment.iter().cloned());
    payload.push(statement[448].clone()); // privacy_policy
    payload.extend(statement[232..264].iter().cloned()); // lane_id
    domain_hash_digest(b"rgk:asset:state:v2", payload)
}

fn continuation_shape_root_digest(
    statement: &[UInt8<Fr>],
    new_allocations: &[&[UInt8<Fr>]],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut payload = Vec::with_capacity(5 + new_allocations.len() * 76);
    payload.push(statement[4].clone()); // chain value byte
    payload.extend(UInt8::<Fr>::constant_vec(
        &(new_allocations.len() as u32).to_le_bytes(),
    ));
    for new in new_allocations {
        payload.extend(new[33..37].iter().cloned()); // output index
        payload.extend(new[37..69].iter().cloned()); // covenant id
        payload.extend(new[117..125].iter().cloned()); // amount
        payload.extend(new[125..157].iter().cloned()); // encrypted note
    }
    domain_hash_digest(b"rgk:continuation:shape-root:v1", payload)
}

fn continuation_commitment_digest(
    statement: &[UInt8<Fr>],
    spent_root: &[UInt8<Fr>],
    shape_root: &[UInt8<Fr>],
    burn: Option<BurnDigestEncoding>,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut payload = Vec::with_capacity(234);
    payload.push(statement[4].clone()); // chain value byte
    payload.extend(statement[8..40].iter().cloned()); // schema_id
    payload.extend(statement[40..72].iter().cloned()); // asset_id
    payload.extend(statement[424..432].iter().cloned()); // total_supply
    payload.extend(statement[72..104].iter().cloned()); // previous_state_digest
    payload.extend(spent_root.iter().cloned());
    payload.extend(shape_root.iter().cloned());
    encode_burn_digest(&mut payload, burn);
    payload.extend(statement[232..264].iter().cloned()); // lane_id
    payload.push(statement[448].clone()); // privacy_policy
    payload.extend(statement[264..296].iter().cloned()); // policy_commitment
    payload.extend(statement[296..328].iter().cloned()); // metadata_commitment
    payload.extend(statement[328..360].iter().cloned()); // previous_owner_commitment
    payload.extend(statement[360..392].iter().cloned()); // new_owner_commitment
    payload.extend(statement[392..424].iter().cloned()); // ownership_authorization_commitment
    domain_hash_digest(b"rgk:continuation:phase1:v2", payload)
}

fn transition_digest(
    statement: &[UInt8<Fr>],
    spent_allocations: &[&[UInt8<Fr>]],
    new_allocations: &[&[UInt8<Fr>]],
    burn: Option<BurnDigestEncoding>,
    terminal_witness_txid: Option<&[UInt8<Fr>]>,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let witness_txid = match (new_allocations.first(), terminal_witness_txid) {
        (Some(first_new), None) => &first_new[69..101],
        (None, Some(witness_txid)) if witness_txid.len() == 32 => witness_txid,
        _ => return Err(SynthesisError::Unsatisfiable),
    };
    let mut payload = Vec::with_capacity(
        104 + 4 + spent_allocations.len() * 158 + 4 + new_allocations.len() * 158,
    );
    payload.push(statement[4].clone()); // chain value byte
    payload.extend(statement[8..40].iter().cloned()); // schema_id
    payload.extend(statement[40..72].iter().cloned()); // asset_id
    payload.extend(statement[424..432].iter().cloned()); // total_supply
    payload.extend(statement[72..104].iter().cloned()); // previous_state_digest
    payload.extend(statement[104..136].iter().cloned()); // new_state_digest
    payload.extend(witness_txid.iter().cloned()); // transition witness txid
    encode_burn_digest(&mut payload, burn);
    payload.extend(statement[232..264].iter().cloned()); // lane_id
    payload.push(statement[448].clone()); // privacy_policy
    payload.extend(statement[264..296].iter().cloned()); // policy_commitment
    payload.extend(statement[296..328].iter().cloned()); // metadata_commitment
    payload.extend(statement[328..360].iter().cloned()); // previous_owner_commitment
    payload.extend(statement[360..392].iter().cloned()); // new_owner_commitment
    payload.extend(statement[392..424].iter().cloned()); // ownership_authorization_commitment
    payload.extend(UInt8::<Fr>::constant_vec(
        &(spent_allocations.len() as u32).to_le_bytes(),
    ));
    for spent in spent_allocations {
        payload.push(UInt8::constant(b'i'));
        payload.extend(spent.iter().cloned());
    }
    payload.extend(UInt8::<Fr>::constant_vec(
        &(new_allocations.len() as u32).to_le_bytes(),
    ));
    for new in new_allocations {
        new[69..101].enforce_equal(witness_txid)?;
        payload.push(UInt8::constant(b'o'));
        payload.extend(new.iter().cloned());
    }
    domain_hash_digest(b"rgk:asset:transition:v2", payload)
}

fn enforce_semantic_layout(statement: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    if statement.len() != SEMANTIC_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }

    // chain_id: tag u32 LE ('K') + known chain value u32 LE.
    enforce_chain_id_layout(&statement[0..8])?;

    enforce_nonzero_bytes(&statement[8..40])?; // schema_id
    enforce_nonzero_bytes(&statement[40..72])?; // asset_id
    enforce_nonzero_bytes(&statement[72..104])?; // previous_state_digest
    enforce_nonzero_bytes(&statement[104..136])?; // new_state_digest
    statement[72..104]
        .is_neq(&statement[104..136])?
        .enforce_equal(&Boolean::TRUE)?;
    enforce_nonzero_bytes(&statement[136..168])?; // transition_digest
    enforce_nonzero_bytes(&statement[168..200])?; // continuation_commitment
    enforce_nonzero_bytes(&statement[200..232])?; // continuation_shape_root
    enforce_nonzero_bytes(&statement[232..264])?; // lane_id
    enforce_nonzero_bytes(&statement[264..296])?; // policy_commitment
    enforce_nonzero_bytes(&statement[296..328])?; // metadata_commitment
    enforce_nonzero_bytes(&statement[328..360])?; // previous_owner_commitment
    enforce_nonzero_bytes(&statement[360..392])?; // new_owner_commitment
    let owners_equal = statement[328..360].is_eq(&statement[360..392])?;
    let ownership_authorization_is_nonzero = nonzero_bytes_bool(&statement[392..424])?;
    Boolean::kary_or(&[owners_equal, ownership_authorization_is_nonzero])?
        .enforce_equal(&Boolean::TRUE)?;

    enforce_nonzero_bytes(&statement[424..432])?; // total_supply
    enforce_nonzero_bytes(&statement[432..440])?; // spent_allocation_count

    enforce_byte_in(&statement[448], &[0, 1, 2])?;
    for byte in &statement[449..456] {
        enforce_byte_equals(byte, 0)?;
    }

    enforce_nonzero_bytes(&statement[456..464])?; // spent_supply
    let spent_supply = le_bytes_as_fr(&statement[456..464])?;
    let new_supply = le_bytes_as_fr(&statement[464..472])?;
    let burned_supply = le_bytes_as_fr(&statement[472..480])?;
    let accounted_supply = new_supply + burned_supply;
    accounted_supply.enforce_equal(&spent_supply)?;
    let burned_supply_is_nonzero = nonzero_bytes_bool(&statement[472..480])?;
    Boolean::kary_or(&[
        nonzero_bytes_bool(&statement[440..448])?,
        burned_supply_is_nonzero.clone(),
    ])?
    .enforce_equal(&Boolean::TRUE)?;
    Boolean::kary_or(&[
        nonzero_bytes_bool(&statement[464..472])?,
        burned_supply_is_nonzero,
    ])?
    .enforce_equal(&Boolean::TRUE)?;

    Ok(())
}

fn enforce_allocation_transcript_segment_public_layout(
    public: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(&public[0..32])?; // previous transcript root
    enforce_nonzero_bytes(&public[32..64])?; // next transcript root
    public[0..32]
        .is_neq(&public[32..64])?
        .enforce_equal(&Boolean::TRUE)?;
    enforce_chain_id_layout(&public[64..72])?;
    enforce_byte_in(&public[72], &[0, 1])?;
    for byte in &public[73..80] {
        enforce_byte_equals(byte, 0)?;
    }
    enforce_nonzero_bytes(&public[88..96])?; // total allocation count
    enforce_nonzero_bytes(&public[96..128])?; // segment amount commitment
    Ok(())
}

fn enforce_allocation_conservation_segment_public_layout(
    public: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_CONSERVATION_SEGMENT_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_allocation_transcript_segment_public_layout(
        &public[..ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN],
    )?;
    enforce_nonzero_bytes(&public[128..160])?; // previous running total commitment
    enforce_nonzero_bytes(&public[160..192])?; // next running total commitment
    Ok(())
}

fn enforce_allocation_conservation_final_public_layout(
    public: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_CONSERVATION_FINAL_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(&public[0..8])?; // spent total count
    enforce_nonzero_bytes(&public[8..16])?; // new total count
    enforce_nonzero_bytes(&public[16..48])?; // spent running total commitment
    enforce_nonzero_bytes(&public[48..80])?; // new running total commitment
    Ok(())
}

fn enforce_allocation_exclusion_segment_pair_public_layout(
    public: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if public.len() != ALLOCATION_EXCLUSION_SEGMENT_PAIR_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(&public[0..32])?; // spent previous root
    enforce_nonzero_bytes(&public[32..64])?; // spent next root
    enforce_nonzero_bytes(&public[64..96])?; // new previous root
    enforce_nonzero_bytes(&public[96..128])?; // new next root
    public[0..32]
        .is_neq(&public[32..64])?
        .enforce_equal(&Boolean::TRUE)?;
    public[64..96]
        .is_neq(&public[96..128])?
        .enforce_equal(&Boolean::TRUE)?;
    enforce_chain_id_layout(&public[128..136])?;
    enforce_nonzero_bytes(&public[152..160])?; // spent total count
    enforce_nonzero_bytes(&public[160..168])?; // new total count
    enforce_nonzero_bytes(&public[168..200])?; // spent amount commitment
    enforce_nonzero_bytes(&public[200..232])?; // new amount commitment
    Ok(())
}

fn enforce_chain_id_layout(public: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    if public.len() != 8 {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_byte_equals(&public[0], KaspaChainId::TAG)?;
    enforce_byte_equals(&public[1], 0)?;
    enforce_byte_equals(&public[2], 0)?;
    enforce_byte_equals(&public[3], 0)?;
    enforce_byte_in(
        &public[4],
        &[
            KaspaChainId::KaspaMainnet as u8,
            KaspaChainId::KaspaTestnet as u8,
            KaspaChainId::KaspaSimnet as u8,
            KaspaChainId::KaspaDevnet as u8,
            KaspaChainId::KaspaLocalToccata as u8,
        ],
    )?;
    enforce_byte_equals(&public[5], 0)?;
    enforce_byte_equals(&public[6], 0)?;
    enforce_byte_equals(&public[7], 0)
}

fn enforce_lane_discovery_public_layout(public: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    if public.len() != LANE_DISCOVERY_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_lane_discovery_node_layout(public)
}

fn enforce_lane_graph_discovery_public_layout<const LANES: usize>(
    public: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if LANES == 0 || public.len() != lane_graph_discovery_public_input_len(LANES) {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(&public[..LANE_GRAPH_DISCOVERY_ROOT_LEN])?; // graph root
    for node_index in 0..LANES {
        let offset = LANE_GRAPH_DISCOVERY_ROOT_LEN + node_index * LANE_DISCOVERY_PUBLIC_INPUT_LEN;
        enforce_lane_discovery_node_layout(
            &public[offset..offset + LANE_DISCOVERY_PUBLIC_INPUT_LEN],
        )?;
    }
    Ok(())
}

fn enforce_lane_graph_segment_public_layout<const LANES: usize>(
    public: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    if LANES == 0 || public.len() != lane_graph_segment_public_input_len(LANES) {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(&public[0..32])?; // previous rolling root
    enforce_nonzero_bytes(&public[32..64])?; // next rolling root
    public[0..32]
        .is_neq(&public[32..64])?
        .enforce_equal(&Boolean::TRUE)?;
    for node_index in 0..LANES {
        let offset = LANE_GRAPH_SEGMENT_PREFIX_LEN + node_index * LANE_DISCOVERY_PUBLIC_INPUT_LEN;
        enforce_lane_discovery_node_layout(
            &public[offset..offset + LANE_DISCOVERY_PUBLIC_INPUT_LEN],
        )?;
    }
    Ok(())
}

fn enforce_lane_discovery_node_layout(public: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    if public.len() != LANE_DISCOVERY_PUBLIC_INPUT_LEN {
        return Err(SynthesisError::Unsatisfiable);
    }
    enforce_nonzero_bytes(&public[0..32])?; // blinded lane id
    enforce_nonzero_bytes(&public[32..64])?; // scan tag
    Ok(())
}

fn enforce_byte_equals(byte: &UInt8<Fr>, expected: u8) -> Result<(), SynthesisError> {
    byte.enforce_equal(&UInt8::constant(expected))
}

fn enforce_byte_in(byte: &UInt8<Fr>, allowed: &[u8]) -> Result<(), SynthesisError> {
    let matches = allowed
        .iter()
        .map(|value| byte.is_eq(&UInt8::constant(*value)))
        .collect::<Result<Vec<_>, _>>()?;
    Boolean::kary_or(&matches)?.enforce_equal(&Boolean::TRUE)
}

fn enforce_nonzero_bytes(bytes: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    nonzero_bytes_bool(bytes)?.enforce_equal(&Boolean::TRUE)
}

fn nonzero_bytes_bool(bytes: &[UInt8<Fr>]) -> Result<Boolean<Fr>, SynthesisError> {
    let zero = UInt8::<Fr>::constant_vec(&alloc::vec![0u8; bytes.len()]);
    bytes.is_neq(&zero)
}

fn enforce_bytes_equal_const(bytes: &[UInt8<Fr>], expected: &[u8]) -> Result<(), SynthesisError> {
    bytes.enforce_equal(&UInt8::constant_vec(expected))
}

fn le_bytes_as_fr(bytes: &[UInt8<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        bits.extend(byte.to_bits_le()?);
    }
    Boolean::le_bits_to_fp(&bits)
}

fn public_inputs_as_vars(
    cs: ConstraintSystemRef<Fr>,
    public_inputs: &[u8],
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    public_inputs
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from_le_bytes_mod_order(&buf)))
        })
        .collect()
}

fn enforce_bytes_equal_public_frs(
    bytes: &[UInt8<Fr>],
    public_frs: &[FpVar<Fr>],
) -> Result<(), SynthesisError> {
    let field_vars = digest_bytes_as_frs(bytes)?;
    enforce_frs_equal(&field_vars, public_frs)
}

fn enforce_frs_equal(lhs: &[FpVar<Fr>], rhs: &[FpVar<Fr>]) -> Result<(), SynthesisError> {
    if lhs.len() != rhs.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        a.enforce_equal(b)?;
    }
    Ok(())
}

fn receipt_body_offsets(body: &[u8]) -> Result<ReceiptBodyOffsets, SynthesisError> {
    if body.len() < 4 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut len = [0u8; 4];
    len.copy_from_slice(&body[..4]);
    let domain_len = u32::from_le_bytes(len) as usize;
    let covenant = 4usize
        .checked_add(domain_len)
        .ok_or(SynthesisError::Unsatisfiable)?;
    let required = covenant
        .checked_add(192)
        .ok_or(SynthesisError::Unsatisfiable)?;
    if body.len() != required {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(ReceiptBodyOffsets {
        covenant,
        old_state: covenant + 32,
        new_state: covenant + 64,
        transition: covenant + 96,
        continuation: covenant + 128,
    })
}

fn receipt_domain_prefix() -> Vec<u8> {
    const DOMAIN: &[u8] = b"rgk:receipt";
    let mut prefix = Vec::with_capacity(4 + DOMAIN.len());
    prefix.extend_from_slice(&(DOMAIN.len() as u32).to_le_bytes());
    prefix.extend_from_slice(DOMAIN);
    prefix
}

fn domain_hash_digest(
    domain: &[u8],
    payload: Vec<UInt8<Fr>>,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut preimage = UInt8::<Fr>::constant_vec(&(domain.len() as u32).to_le_bytes());
    preimage.extend(UInt8::<Fr>::constant_vec(domain));
    preimage.extend(payload);
    Ok(Sha256Gadget::<Fr>::digest(&preimage)?.0)
}

const fn lane_graph_discovery_public_input_len(lanes: usize) -> usize {
    LANE_GRAPH_DISCOVERY_ROOT_LEN + lanes * LANE_DISCOVERY_PUBLIC_INPUT_LEN
}

const fn lane_graph_segment_public_input_len(lanes: usize) -> usize {
    LANE_GRAPH_SEGMENT_PREFIX_LEN + lanes * LANE_DISCOVERY_PUBLIC_INPUT_LEN
}

fn digest_bytes_as_frs(digest: &[UInt8<Fr>]) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    digest
        .chunks(8)
        .map(|chunk| {
            let mut bits = Vec::with_capacity(chunk.len() * 8);
            for byte in chunk {
                bits.extend(byte.to_bits_le()?);
            }
            Boolean::le_bits_to_fp(&bits)
        })
        .collect()
}

/// Groth16 setup (proving key + verifying key) for the [`ReceiptCircuit`].
/// Uses a deterministic RNG for reproducibility; production must run a
/// proper trusted-setup ceremony.
pub struct Groth16Setup {
    pub pk: ProvingKey<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

fn setup_for<C>(circuit: &C) -> Result<Groth16Setup, String>
where
    C: ConstraintSynthesizer<Fr> + Clone,
{
    let mut rng = deterministic_rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng)
        .map_err(|e| format!("setup failed: {e}"))?;
    Ok(Groth16Setup { pk, vk })
}

pub fn setup(circuit: &ReceiptCircuit) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_semantic(circuit: &SemanticTransitionCircuit) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_lane_discovery(circuit: &LaneDiscoveryCircuit) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_lane_graph_discovery<const LANES: usize>(
    circuit: &LaneGraphDiscoveryCircuit<LANES>,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_lane_graph_segment<const LANES: usize>(
    circuit: &LaneGraphSegmentCircuit<LANES>,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_transcript_segment<const ALLOCS: usize>(
    circuit: &AllocationTranscriptSegmentCircuit<ALLOCS>,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_conservation_segment<const ALLOCS: usize>(
    circuit: &AllocationConservationSegmentCircuit<ALLOCS>,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_conservation_final(
    circuit: &AllocationConservationFinalCircuit,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_exclusion_segment_pair<const SPENT: usize, const NEW: usize>(
    circuit: &AllocationExclusionSegmentPairCircuit<SPENT, NEW>,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_1x1(
    circuit: &OneInOneOutAllocationCircuit,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_1x0(
    circuit: &OneInZeroOutAllocationCircuit,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_2x2(
    circuit: &TwoInTwoOutAllocationCircuit,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_allocation_fixed<const SPENT: usize, const NEW: usize>(
    circuit: &FixedAllocationVectorCircuit<SPENT, NEW>,
) -> Result<Groth16Setup, String> {
    setup_for(circuit)
}

pub fn setup_supported_allocation(
    circuit: &SupportedAllocationVectorCircuit,
) -> Result<Groth16Setup, String> {
    match circuit {
        SupportedAllocationVectorCircuit::OneInZeroOut(circuit) => setup_allocation_1x0(circuit),
        SupportedAllocationVectorCircuit::OneInOneOut(circuit) => setup_allocation_1x1(circuit),
        SupportedAllocationVectorCircuit::TwoInTwoOut(circuit) => setup_allocation_2x2(circuit),
        SupportedAllocationVectorCircuit::ThreeInTwoOut(circuit) => setup_allocation_fixed(circuit),
        SupportedAllocationVectorCircuit::FourInTwoOut(circuit) => setup_allocation_fixed(circuit),
        SupportedAllocationVectorCircuit::FourInFourOut(circuit) => setup_allocation_fixed(circuit),
    }
}

pub fn prove(pk: &ProvingKey<Bn254>, circuit: ReceiptCircuit) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_semantic(
    pk: &ProvingKey<Bn254>,
    circuit: SemanticTransitionCircuit,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_lane_discovery(
    pk: &ProvingKey<Bn254>,
    circuit: LaneDiscoveryCircuit,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_lane_graph_discovery<const LANES: usize>(
    pk: &ProvingKey<Bn254>,
    circuit: LaneGraphDiscoveryCircuit<LANES>,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_lane_graph_segment<const LANES: usize>(
    pk: &ProvingKey<Bn254>,
    circuit: LaneGraphSegmentCircuit<LANES>,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_transcript_segment<const ALLOCS: usize>(
    pk: &ProvingKey<Bn254>,
    circuit: AllocationTranscriptSegmentCircuit<ALLOCS>,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_conservation_segment<const ALLOCS: usize>(
    pk: &ProvingKey<Bn254>,
    circuit: AllocationConservationSegmentCircuit<ALLOCS>,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_conservation_final(
    pk: &ProvingKey<Bn254>,
    circuit: AllocationConservationFinalCircuit,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_exclusion_segment_pair<const SPENT: usize, const NEW: usize>(
    pk: &ProvingKey<Bn254>,
    circuit: AllocationExclusionSegmentPairCircuit<SPENT, NEW>,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_1x1(
    pk: &ProvingKey<Bn254>,
    circuit: OneInOneOutAllocationCircuit,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_1x0(
    pk: &ProvingKey<Bn254>,
    circuit: OneInZeroOutAllocationCircuit,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_2x2(
    pk: &ProvingKey<Bn254>,
    circuit: TwoInTwoOutAllocationCircuit,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_allocation_fixed<const SPENT: usize, const NEW: usize>(
    pk: &ProvingKey<Bn254>,
    circuit: FixedAllocationVectorCircuit<SPENT, NEW>,
) -> Result<Proof<Bn254>, String> {
    prove_for(pk, circuit)
}

pub fn prove_supported_allocation(
    pk: &ProvingKey<Bn254>,
    circuit: SupportedAllocationVectorCircuit,
) -> Result<Proof<Bn254>, String> {
    match circuit {
        SupportedAllocationVectorCircuit::OneInZeroOut(circuit) => {
            prove_allocation_1x0(pk, circuit)
        }
        SupportedAllocationVectorCircuit::OneInOneOut(circuit) => prove_allocation_1x1(pk, circuit),
        SupportedAllocationVectorCircuit::TwoInTwoOut(circuit) => prove_allocation_2x2(pk, circuit),
        SupportedAllocationVectorCircuit::ThreeInTwoOut(circuit) => {
            prove_allocation_fixed(pk, circuit)
        }
        SupportedAllocationVectorCircuit::FourInTwoOut(circuit) => {
            prove_allocation_fixed(pk, circuit)
        }
        SupportedAllocationVectorCircuit::FourInFourOut(circuit) => {
            prove_allocation_fixed(pk, circuit)
        }
    }
}

fn prove_for<C>(pk: &ProvingKey<Bn254>, circuit: C) -> Result<Proof<Bn254>, String>
where
    C: ConstraintSynthesizer<Fr>,
{
    let mut rng = deterministic_rng();
    Groth16::<Bn254>::prove(pk, circuit, &mut rng).map_err(|e| format!("prove: {e}"))
}

pub fn verify(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &Proof<Bn254>,
) -> Result<bool, String> {
    Groth16::<Bn254>::verify(vk, public_inputs, proof).map_err(|e| format!("verify: {e}"))
}

/// Complete stack material for Toccata's Groth16 `OpZkPrecompile`.
///
/// The upstream precompile pops, from top to bottom: tag, verifying key,
/// proof, public input count, then the public input `Fr` elements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16PrecompileStack {
    pub tag: [u8; 1],
    pub verifying_key: Vec<u8>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
}

impl Groth16PrecompileStack {
    pub fn public_input_count(&self) -> usize {
        self.public_inputs.len()
    }
}

/// Serialize the verifying key exactly as Toccata's Groth16 precompile
/// deserializes it: arkworks compressed `VerifyingKey<Bn254>`.
pub fn serialize_verifying_key_for_precompile(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(vk.serialized_size(Compress::Yes));
    vk.serialize_compressed(&mut bytes)
        .map_err(|e| format!("serialize verifying key: {e}"))?;
    Ok(bytes)
}

/// Serialize the proof exactly as Toccata's Groth16 precompile deserializes
/// it: arkworks compressed `Proof<Bn254>`.
pub fn serialize_proof_for_precompile(proof: &Proof<Bn254>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(proof.serialized_size(Compress::Yes));
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|e| format!("serialize proof: {e}"))?;
    Ok(bytes)
}

/// Convert RGK's 232-byte public-input preimage into the 29 uncompressed BN254
/// `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(public_inputs, PUBLIC_INPUT_LEN)
}

/// Convert RGK's 512-byte semantic statement into the 64 uncompressed BN254
/// `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn semantic_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(public_inputs, SEMANTIC_PUBLIC_INPUT_LEN)
}

/// Convert RGK's 72-byte private-lane discovery statement into the 9
/// uncompressed BN254 `Fr` stack items consumed by Toccata's Groth16
/// precompile.
pub fn lane_discovery_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(public_inputs, LANE_DISCOVERY_PUBLIC_INPUT_LEN)
}

/// Convert a bounded private-lane graph discovery statement into uncompressed
/// BN254 `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn lane_graph_discovery_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    validate_lane_graph_discovery_public_input_len(public_inputs.len())?;
    public_inputs_as_uncompressed_fr_bytes_with_len(public_inputs, public_inputs.len())
}

/// Convert a bounded private-lane graph segment statement into uncompressed
/// BN254 `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn lane_graph_segment_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    validate_lane_graph_segment_public_input_len(public_inputs.len())?;
    public_inputs_as_uncompressed_fr_bytes_with_len(public_inputs, public_inputs.len())
}

/// Convert an allocation transcript segment statement into uncompressed BN254
/// `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn allocation_transcript_segment_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(
        public_inputs,
        ALLOCATION_TRANSCRIPT_SEGMENT_PUBLIC_INPUT_LEN,
    )
}

/// Convert an allocation conservation segment statement into uncompressed
/// BN254 `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn allocation_conservation_segment_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(
        public_inputs,
        ALLOCATION_CONSERVATION_SEGMENT_PUBLIC_INPUT_LEN,
    )
}

/// Convert an allocation conservation final equality statement into
/// uncompressed BN254 `Fr` stack items consumed by Toccata's Groth16
/// precompile.
pub fn allocation_conservation_final_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(
        public_inputs,
        ALLOCATION_CONSERVATION_FINAL_PUBLIC_INPUT_LEN,
    )
}

/// Convert an allocation exclusion segment-pair statement into uncompressed
/// BN254 `Fr` stack items consumed by Toccata's Groth16 precompile.
pub fn allocation_exclusion_segment_pair_public_inputs_as_uncompressed_fr_bytes(
    public_inputs: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    public_inputs_as_uncompressed_fr_bytes_with_len(
        public_inputs,
        ALLOCATION_EXCLUSION_SEGMENT_PAIR_PUBLIC_INPUT_LEN,
    )
}

fn public_inputs_as_uncompressed_fr_bytes_with_len(
    public_inputs: &[u8],
    expected_len: usize,
) -> Result<Vec<Vec<u8>>, String> {
    if public_inputs.len() != expected_len {
        return Err(format!(
            "expected {expected_len} public-input bytes, got {}",
            public_inputs.len()
        ));
    }
    public_inputs_as_fr(public_inputs)
        .iter()
        .map(|fr| {
            let mut bytes = Vec::with_capacity(fr.serialized_size(Compress::No));
            fr.serialize_uncompressed(&mut bytes)
                .map_err(|e| format!("serialize public input: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "expected 32-byte BN254 Fr serialization, got {}",
                    bytes.len()
                ));
            }
            Ok(bytes)
        })
        .collect()
}

fn validate_lane_graph_discovery_public_input_len(len: usize) -> Result<usize, String> {
    if len <= LANE_GRAPH_DISCOVERY_ROOT_LEN {
        return Err(format!(
            "expected lane graph public inputs with at least one node, got {len} bytes"
        ));
    }
    let node_bytes = len - LANE_GRAPH_DISCOVERY_ROOT_LEN;
    if node_bytes % LANE_DISCOVERY_PUBLIC_INPUT_LEN != 0 {
        return Err(format!(
            "expected lane graph public-input bytes after the root to be a multiple of {}, got {node_bytes}",
            LANE_DISCOVERY_PUBLIC_INPUT_LEN
        ));
    }
    let nodes = node_bytes / LANE_DISCOVERY_PUBLIC_INPUT_LEN;
    if nodes == 0 {
        return Err("lane graph public inputs must contain at least one node".to_string());
    }
    Ok(nodes)
}

fn validate_lane_graph_segment_public_input_len(len: usize) -> Result<usize, String> {
    if len <= LANE_GRAPH_SEGMENT_PREFIX_LEN {
        return Err(format!(
            "expected lane graph segment public inputs with at least one node, got {len} bytes"
        ));
    }
    let node_bytes = len - LANE_GRAPH_SEGMENT_PREFIX_LEN;
    if node_bytes % LANE_DISCOVERY_PUBLIC_INPUT_LEN != 0 {
        return Err(format!(
            "expected lane graph segment public-input bytes after the prefix to be a multiple of {}, got {node_bytes}",
            LANE_DISCOVERY_PUBLIC_INPUT_LEN
        ));
    }
    let nodes = node_bytes / LANE_DISCOVERY_PUBLIC_INPUT_LEN;
    if nodes == 0 {
        return Err("lane graph segment public inputs must contain at least one node".to_string());
    }
    Ok(nodes)
}

/// Build the complete Groth16 precompile stack material for this receipt
/// circuit. This is the helper callers should use before constructing a
/// script containing `OpZkPrecompile`.
pub fn groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: public_inputs_as_uncompressed_fr_bytes(public_inputs)?,
    })
}

/// Build the complete Groth16 precompile stack material for the semantic
/// transition circuit.
pub fn semantic_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: semantic_public_inputs_as_uncompressed_fr_bytes(public_inputs)?,
    })
}

/// Build the complete Groth16 precompile stack material for the bounded
/// private-lane discovery circuit.
pub fn lane_discovery_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: lane_discovery_public_inputs_as_uncompressed_fr_bytes(public_inputs)?,
    })
}

/// Build the complete Groth16 precompile stack material for a bounded
/// private-lane graph discovery circuit.
pub fn lane_graph_discovery_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: lane_graph_discovery_public_inputs_as_uncompressed_fr_bytes(public_inputs)?,
    })
}

/// Build the complete Groth16 precompile stack material for a bounded
/// private-lane graph segment circuit.
pub fn lane_graph_segment_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: lane_graph_segment_public_inputs_as_uncompressed_fr_bytes(public_inputs)?,
    })
}

/// Build the complete Groth16 precompile stack material for a native
/// allocation transcript segment circuit.
pub fn allocation_transcript_segment_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: allocation_transcript_segment_public_inputs_as_uncompressed_fr_bytes(
            public_inputs,
        )?,
    })
}

/// Build the complete Groth16 precompile stack material for a native
/// allocation conservation segment circuit.
pub fn allocation_conservation_segment_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: allocation_conservation_segment_public_inputs_as_uncompressed_fr_bytes(
            public_inputs,
        )?,
    })
}

/// Build the complete Groth16 precompile stack material for a native
/// allocation conservation final equality circuit.
pub fn allocation_conservation_final_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: allocation_conservation_final_public_inputs_as_uncompressed_fr_bytes(
            public_inputs,
        )?,
    })
}

/// Build the complete Groth16 precompile stack material for a native
/// allocation exclusion segment-pair circuit.
pub fn allocation_exclusion_segment_pair_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    Ok(Groth16PrecompileStack {
        tag: [ZK_TAG_GROTH16],
        verifying_key: serialize_verifying_key_for_precompile(vk)?,
        proof: serialize_proof_for_precompile(proof)?,
        public_inputs: allocation_exclusion_segment_pair_public_inputs_as_uncompressed_fr_bytes(
            public_inputs,
        )?,
    })
}

/// Build the complete Groth16 precompile stack material for the one-input /
/// one-output allocation-vector circuit.
pub fn allocation_1x1_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    semantic_groth16_precompile_stack(vk, proof, public_inputs)
}

/// Build the complete Groth16 precompile stack material for the two-input /
/// two-output allocation-vector circuit.
pub fn allocation_2x2_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    semantic_groth16_precompile_stack(vk, proof, public_inputs)
}

/// Build the complete Groth16 precompile stack material for a concrete
/// fixed-arity allocation-vector circuit.
pub fn allocation_fixed_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[u8],
) -> Result<Groth16PrecompileStack, String> {
    semantic_groth16_precompile_stack(vk, proof, public_inputs)
}

pub fn supported_allocation_groth16_precompile_stack(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    circuit: &SupportedAllocationVectorCircuit,
) -> Result<Groth16PrecompileStack, String> {
    semantic_groth16_precompile_stack(vk, proof, circuit.public_inputs())
}

/// Tagged proof blob for opaque receipt plumbing: `[tag_byte || proof_bytes_compressed]`.
///
/// This is useful for plumbing through the opaque `ZkProof` wrapper, but it
/// is **not** the complete Toccata Groth16 stack. Use
/// [`groth16_precompile_stack`] when executing `OpZkPrecompile`.
pub fn encode_for_precompile(proof: &Proof<Bn254>) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(1 + proof.serialized_size(Compress::Yes));
    out.push(ZK_TAG_GROTH16);
    let bytes = serialize_proof_for_precompile(proof)?;
    out.extend_from_slice(&bytes);
    Ok(out)
}

/// Public inputs as `Vec<Fr>` (8-byte LE chunks). This is the full 232-byte
/// `ZkStatement` used by the active Groth16 circuit.
pub fn public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    use ark_ff::PrimeField;
    public_inputs
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            Fr::from_le_bytes_mod_order(&buf)
        })
        .collect()
}

/// Semantic transition public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn semantic_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Lane discovery public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn lane_discovery_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Lane graph discovery public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn lane_graph_discovery_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Lane graph segment public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn lane_graph_segment_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Allocation transcript segment public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn allocation_transcript_segment_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Allocation conservation segment public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn allocation_conservation_segment_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Allocation conservation final equality public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn allocation_conservation_final_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Allocation exclusion segment-pair public inputs as `Vec<Fr>` (8-byte LE chunks).
pub fn allocation_exclusion_segment_pair_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs_as_fr(public_inputs)
}

/// Receipt-id public inputs, kept for callers that need the compact digest
/// slice. The active Groth16 circuit verifies against [`public_inputs_as_fr`].
pub fn receipt_id_public_inputs_as_fr(public_inputs: &[u8]) -> Vec<Fr> {
    public_inputs[136..168]
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            Fr::from_le_bytes_mod_order(&buf)
        })
        .collect()
}

fn deterministic_rng() -> ark_std::rand::rngs::StdRng {
    use ark_std::rand::SeedableRng;
    ark_std::rand::rngs::StdRng::from_seed([
        0x52, 0x47, 0x4b, 0x2d, 0x5a, 0x4b, 0x2d, 0x76, 0x30, 0x2e, 0x31, 0x2e, 0x30, 0x30, 0x30,
        0x31, 0x52, 0x47, 0x4b, 0x2d, 0x5a, 0x4b, 0x2d, 0x76, 0x30, 0x2e, 0x31, 0x2e, 0x30, 0x30,
        0x30, 0x31,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgk_asset::{
        allocation_transcript_empty_root, private_lane_graph_empty_root, LanePrivacyPolicy,
        RgkAllocation, RgkAssetIssue, RgkBurnProof, RgkContinuationAllocationShape,
        RgkContinuationPlan, RgkCovenantAnchor, RgkMetadataCommitment, RgkOwnerCommitment,
        RgkProofPolicy, RGK_FUNGIBLE_ASSET_SCHEMA_ID,
    };
    use rgk_core::{KaspaOutpoint, KASPA_LOCAL_TOCCATA};

    fn sample_receipt() -> RgkReceipt {
        let old_state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            [0x11u8; 32],
            [0x22u8; 32],
            [0x01u8; 32],
            ReceiptPolicy::ZkOrVerifier,
        )
        .expect("old sample state commitment is valid");
        let new_state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            [0x11u8; 32],
            [0x22u8; 32],
            [0x02u8; 32],
            ReceiptPolicy::ZkOrVerifier,
        )
        .expect("new sample state commitment is valid");
        RgkReceipt::new(
            KASPA_LOCAL_TOCCATA,
            [0x11u8; 32],
            old_state,
            new_state,
            [0x33u8; 32],
            [0x55u8; 32],
            ProofMode::ZkReceipt,
            [0x44u8; 32],
        )
        .expect("sample receipt is valid")
    }

    fn sample_semantic_statement() -> SemanticTransitionStatement {
        SemanticTransitionStatement::new(
            KASPA_LOCAL_TOCCATA,
            *b"rgk:asset:schema:v1_____________",
            [0x22u8; 32],
            [0x01u8; 32],
            [0x02u8; 32],
            [0x33u8; 32],
            [0x55u8; 32],
            [0x66u8; 32],
            [0x77u8; 32],
            LanePrivacyPolicy::PrivateLane,
            [0x88u8; 32],
            [0x99u8; 32],
            [0xaau8; 32],
            [0xaau8; 32],
            [0; 32],
            1_000_000,
            1,
            1,
            1_000_000,
            1_000_000,
            0,
            [0; 32],
        )
        .expect("semantic statement")
    }

    fn sample_lane_discovery() -> (LaneDiscoveryStatement, LaneDiscoveryWitness) {
        let witness = LaneDiscoveryWitness {
            view_key: [0x41u8; 32],
            asset_id: [0x22u8; 32],
        };
        let statement = LaneDiscoveryStatement::from_private(witness.view_key, witness.asset_id, 7);
        (statement, witness)
    }

    fn sample_lane_graph_discovery() -> (LaneGraphDiscoveryStatement<2>, LaneDiscoveryWitness) {
        let witness = LaneDiscoveryWitness {
            view_key: [0x41u8; 32],
            asset_id: [0x22u8; 32],
        };
        let statement = LaneGraphDiscoveryStatement::<2>::from_private(
            witness.view_key,
            witness.asset_id,
            [7, 8],
        );
        (statement, witness)
    }

    fn sample_lane_graph_segment() -> (LaneGraphSegmentStatement<2>, LaneDiscoveryWitness) {
        let witness = LaneDiscoveryWitness {
            view_key: [0x41u8; 32],
            asset_id: [0x22u8; 32],
        };
        let statement = LaneGraphSegmentStatement::<2>::from_private(
            witness.view_key,
            witness.asset_id,
            private_lane_graph_empty_root(),
            0,
            [7, 8],
        );
        (statement, witness)
    }

    fn sample_allocation_transcript_segment() -> (
        AllocationTranscriptSegmentStatement<2>,
        AllocationTranscriptSegmentWitness<2>,
        Vec<RgkAllocation>,
    ) {
        let allocations = alloc::vec![
            allocation(
                [0xaau8; 32],
                0,
                [0x11u8; 32],
                [0xbau8; 32],
                1,
                400_000,
                [0xcau8; 32],
            ),
            allocation(
                [0xabu8; 32],
                0,
                [0x11u8; 32],
                [0xbbu8; 32],
                1,
                600_000,
                [0xcbu8; 32],
            ),
        ];
        let statement = AllocationTranscriptSegmentStatement::<2>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
            RgkAllocationTranscriptSide::Spent,
            0,
            allocations.len() as u64,
            &allocations,
            [0x51u8; 32],
        )
        .expect("allocation transcript statement");
        let witness =
            AllocationTranscriptSegmentWitness::<2>::from_allocations(&allocations, [0x51u8; 32])
                .expect("allocation transcript witness");
        (statement, witness, allocations)
    }

    fn sample_allocation_conservation_segment() -> (
        AllocationConservationSegmentStatement<2>,
        AllocationConservationSegmentWitness<2>,
        Vec<RgkAllocation>,
    ) {
        let allocations = alloc::vec![
            allocation(
                [0xaau8; 32],
                0,
                [0x11u8; 32],
                [0xbau8; 32],
                1,
                400_000,
                [0xcau8; 32],
            ),
            allocation(
                [0xabu8; 32],
                0,
                [0x11u8; 32],
                [0xbbu8; 32],
                1,
                600_000,
                [0xcbu8; 32],
            ),
        ];
        let statement = AllocationConservationSegmentStatement::<2>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
            RgkAllocationTranscriptSide::Spent,
            0,
            allocations.len() as u64,
            0,
            &allocations,
            [0x51u8; 32],
            [0x61u8; 32],
            [0x62u8; 32],
        )
        .expect("allocation conservation segment statement");
        let witness = AllocationConservationSegmentWitness::<2>::from_allocations(
            0,
            &allocations,
            [0x51u8; 32],
            [0x61u8; 32],
            [0x62u8; 32],
        )
        .expect("allocation conservation segment witness");
        (statement, witness, allocations)
    }

    fn sample_allocation_conservation_final() -> (
        AllocationConservationFinalStatement,
        AllocationConservationFinalWitness,
    ) {
        let statement = AllocationConservationFinalStatement::from_total(
            2,
            2,
            1_000_000,
            [0x62u8; 32],
            [0x64u8; 32],
        )
        .expect("allocation conservation final statement");
        let witness =
            AllocationConservationFinalWitness::new(1_000_000, [0x62u8; 32], [0x64u8; 32])
                .expect("allocation conservation final witness");
        (statement, witness)
    }

    fn sample_allocation_exclusion_segment_pair() -> (
        AllocationExclusionSegmentPairStatement<2, 2>,
        AllocationExclusionSegmentPairWitness<2, 2>,
        Vec<RgkAllocation>,
        Vec<RgkAllocation>,
    ) {
        let spent_allocations = alloc::vec![
            allocation(
                [0xaau8; 32],
                0,
                [0x11u8; 32],
                [0xbau8; 32],
                1,
                400_000,
                [0xcau8; 32],
            ),
            allocation(
                [0xabu8; 32],
                0,
                [0x11u8; 32],
                [0xbbu8; 32],
                1,
                600_000,
                [0xcbu8; 32],
            ),
        ];
        let new_allocations = alloc::vec![
            allocation(
                [0xacu8; 32],
                0,
                [0x11u8; 32],
                [0xbcu8; 32],
                2,
                500_000,
                [0xccu8; 32],
            ),
            allocation(
                [0xadu8; 32],
                1,
                [0x11u8; 32],
                [0xbcu8; 32],
                2,
                500_000,
                [0xcdu8; 32],
            ),
        ];
        let statement = AllocationExclusionSegmentPairStatement::<2, 2>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
            0,
            0,
            spent_allocations.len() as u64,
            new_allocations.len() as u64,
            &spent_allocations,
            &new_allocations,
            [0x51u8; 32],
            [0x52u8; 32],
        )
        .expect("allocation exclusion statement");
        let witness = AllocationExclusionSegmentPairWitness::<2, 2>::from_allocations(
            &spent_allocations,
            &new_allocations,
            [0x51u8; 32],
            [0x52u8; 32],
        )
        .expect("allocation exclusion witness");
        (statement, witness, spent_allocations, new_allocations)
    }

    struct AllocationAuditBundleFixture {
        spent_transcripts: Vec<AllocationTranscriptSegmentStatement<1>>,
        new_transcripts: Vec<AllocationTranscriptSegmentStatement<1>>,
        spent_conservation: Vec<AllocationConservationSegmentStatement<1>>,
        new_conservation: Vec<AllocationConservationSegmentStatement<1>>,
        final_conservation: AllocationConservationFinalStatement,
        exclusions: Vec<AllocationExclusionSegmentPairStatement<1, 1>>,
    }

    impl AllocationAuditBundleFixture {
        fn bundle(&self) -> AllocationAuditBundle<'_, 1, 1> {
            AllocationAuditBundle {
                spent_transcripts: &self.spent_transcripts,
                new_transcripts: &self.new_transcripts,
                spent_conservation: &self.spent_conservation,
                new_conservation: &self.new_conservation,
                final_conservation: &self.final_conservation,
                exclusions: &self.exclusions,
            }
        }
    }

    struct AllocationAuditCertificateFixture {
        spent_transcripts: Vec<AllocationTranscriptSegmentStatement<1>>,
        new_transcripts: Vec<AllocationTranscriptSegmentStatement<1>>,
        spent_conservation: Vec<AllocationConservationSegmentStatement<1>>,
        new_conservation: Vec<AllocationConservationSegmentStatement<1>>,
        final_conservation: AllocationConservationFinalStatement,
        exclusions: Vec<AllocationExclusionSegmentPairStatement<1, 1>>,
        spent_transcript_stacks: Vec<Groth16PrecompileStack>,
        new_transcript_stacks: Vec<Groth16PrecompileStack>,
        spent_conservation_stacks: Vec<Groth16PrecompileStack>,
        new_conservation_stacks: Vec<Groth16PrecompileStack>,
        final_conservation_stack: Groth16PrecompileStack,
        exclusion_stacks: Vec<Groth16PrecompileStack>,
    }

    impl AllocationAuditCertificateFixture {
        fn bundle(&self) -> AllocationAuditBundle<'_, 1, 1> {
            AllocationAuditBundle {
                spent_transcripts: &self.spent_transcripts,
                new_transcripts: &self.new_transcripts,
                spent_conservation: &self.spent_conservation,
                new_conservation: &self.new_conservation,
                final_conservation: &self.final_conservation,
                exclusions: &self.exclusions,
            }
        }

        fn stacks(&self) -> AllocationAuditBundleStacks<'_> {
            AllocationAuditBundleStacks {
                spent_transcripts: &self.spent_transcript_stacks,
                new_transcripts: &self.new_transcript_stacks,
                spent_conservation: &self.spent_conservation_stacks,
                new_conservation: &self.new_conservation_stacks,
                final_conservation: &self.final_conservation_stack,
                exclusions: &self.exclusion_stacks,
            }
        }
    }

    fn sample_allocation_audit_bundle_grid() -> AllocationAuditBundleFixture {
        let spent_allocations = alloc::vec![
            allocation(
                [0xd0u8; 32],
                0,
                [0x11u8; 32],
                [0xe0u8; 32],
                1,
                400_000,
                [0xf0u8; 32],
            ),
            allocation(
                [0xd1u8; 32],
                0,
                [0x11u8; 32],
                [0xe1u8; 32],
                1,
                600_000,
                [0xf1u8; 32],
            ),
        ];
        let new_allocations = alloc::vec![
            allocation(
                [0xd2u8; 32],
                0,
                [0x11u8; 32],
                [0xe2u8; 32],
                2,
                500_000,
                [0xf2u8; 32],
            ),
            allocation(
                [0xd3u8; 32],
                0,
                [0x11u8; 32],
                [0xe3u8; 32],
                2,
                500_000,
                [0xf3u8; 32],
            ),
        ];
        let spent_amount_blindings = [[0x51u8; 32], [0x52u8; 32]];
        let new_amount_blindings = [[0x53u8; 32], [0x54u8; 32]];
        let spent_total_blindings = [[0x61u8; 32], [0x62u8; 32], [0x63u8; 32]];
        let new_total_blindings = [[0x64u8; 32], [0x65u8; 32], [0x66u8; 32]];

        let mut spent_transcripts = Vec::new();
        let mut spent_conservation = Vec::new();
        let mut spent_previous_root =
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent);
        let mut spent_running_total = 0u64;
        for (index, allocation) in spent_allocations.iter().enumerate() {
            let statement = AllocationConservationSegmentStatement::<1>::from_allocations(
                spent_previous_root,
                RgkAllocationTranscriptSide::Spent,
                index as u64,
                spent_allocations.len() as u64,
                spent_running_total,
                core::slice::from_ref(allocation),
                spent_amount_blindings[index],
                spent_total_blindings[index],
                spent_total_blindings[index + 1],
            )
            .expect("spent conservation segment statement");
            spent_previous_root = statement.transcript.next_root;
            spent_running_total = spent_running_total
                .checked_add(allocation.amount)
                .expect("spent running total");
            spent_transcripts.push(statement.transcript.clone());
            spent_conservation.push(statement);
        }

        let mut new_transcripts = Vec::new();
        let mut new_conservation = Vec::new();
        let mut new_previous_root =
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::New);
        let mut new_running_total = 0u64;
        for (index, allocation) in new_allocations.iter().enumerate() {
            let statement = AllocationConservationSegmentStatement::<1>::from_allocations(
                new_previous_root,
                RgkAllocationTranscriptSide::New,
                index as u64,
                new_allocations.len() as u64,
                new_running_total,
                core::slice::from_ref(allocation),
                new_amount_blindings[index],
                new_total_blindings[index],
                new_total_blindings[index + 1],
            )
            .expect("new conservation segment statement");
            new_previous_root = statement.transcript.next_root;
            new_running_total = new_running_total
                .checked_add(allocation.amount)
                .expect("new running total");
            new_transcripts.push(statement.transcript.clone());
            new_conservation.push(statement);
        }

        let final_conservation = AllocationConservationFinalStatement::from_total(
            spent_allocations.len() as u64,
            new_allocations.len() as u64,
            spent_running_total,
            spent_total_blindings[2],
            new_total_blindings[2],
        )
        .expect("allocation audit final conservation statement");
        assert_eq!(spent_running_total, new_running_total);

        let mut exclusions = Vec::new();
        for (spent_index, spent_allocation) in spent_allocations.iter().enumerate() {
            for (new_index, new_allocation) in new_allocations.iter().enumerate() {
                exclusions.push(
                    AllocationExclusionSegmentPairStatement::<1, 1>::from_allocations(
                        spent_transcripts[spent_index].previous_root,
                        new_transcripts[new_index].previous_root,
                        spent_index as u64,
                        new_index as u64,
                        spent_allocations.len() as u64,
                        new_allocations.len() as u64,
                        core::slice::from_ref(spent_allocation),
                        core::slice::from_ref(new_allocation),
                        spent_amount_blindings[spent_index],
                        new_amount_blindings[new_index],
                    )
                    .expect("allocation audit exclusion pair"),
                );
            }
        }

        AllocationAuditBundleFixture {
            spent_transcripts,
            new_transcripts,
            spent_conservation,
            new_conservation,
            final_conservation,
            exclusions,
        }
    }

    fn sample_allocation_audit_certificate_fixture() -> AllocationAuditCertificateFixture {
        let spent_allocation = allocation(
            [0xeau8; 32],
            0,
            [0x11u8; 32],
            [0xebu8; 32],
            1,
            1_000_000,
            [0xecu8; 32],
        );
        let new_allocation = allocation(
            [0xedu8; 32],
            0,
            [0x11u8; 32],
            [0xeeu8; 32],
            2,
            1_000_000,
            [0xefu8; 32],
        );

        let spent_transcript_statement =
            AllocationTranscriptSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
                RgkAllocationTranscriptSide::Spent,
                0,
                1,
                core::slice::from_ref(&spent_allocation),
                [0x51u8; 32],
            )
            .expect("spent transcript statement");
        let new_transcript_statement = AllocationTranscriptSegmentStatement::<1>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
            RgkAllocationTranscriptSide::New,
            0,
            1,
            core::slice::from_ref(&new_allocation),
            [0x52u8; 32],
        )
        .expect("new transcript statement");
        let spent_transcript_circuit =
            AllocationTranscriptSegmentCircuit::<1>::from_statement_and_witness(
                &spent_transcript_statement,
                AllocationTranscriptSegmentWitness::<1>::from_allocations(
                    core::slice::from_ref(&spent_allocation),
                    [0x51u8; 32],
                )
                .expect("spent transcript witness"),
            )
            .expect("spent transcript circuit");
        let new_transcript_circuit =
            AllocationTranscriptSegmentCircuit::<1>::from_statement_and_witness(
                &new_transcript_statement,
                AllocationTranscriptSegmentWitness::<1>::from_allocations(
                    core::slice::from_ref(&new_allocation),
                    [0x52u8; 32],
                )
                .expect("new transcript witness"),
            )
            .expect("new transcript circuit");
        let transcript_setup = setup_allocation_transcript_segment(&spent_transcript_circuit)
            .expect("transcript setup");
        let spent_transcript_proof = prove_allocation_transcript_segment(
            &transcript_setup.pk,
            spent_transcript_circuit.clone(),
        )
        .expect("spent transcript proof");
        let new_transcript_proof = prove_allocation_transcript_segment(
            &transcript_setup.pk,
            new_transcript_circuit.clone(),
        )
        .expect("new transcript proof");
        let spent_transcript_stack = allocation_transcript_segment_groth16_precompile_stack(
            &transcript_setup.vk,
            &spent_transcript_proof,
            &spent_transcript_circuit.public_inputs,
        )
        .expect("spent transcript stack");
        let new_transcript_stack = allocation_transcript_segment_groth16_precompile_stack(
            &transcript_setup.vk,
            &new_transcript_proof,
            &new_transcript_circuit.public_inputs,
        )
        .expect("new transcript stack");

        let spent_conservation_statement =
            AllocationConservationSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
                RgkAllocationTranscriptSide::Spent,
                0,
                1,
                0,
                core::slice::from_ref(&spent_allocation),
                [0x51u8; 32],
                [0x61u8; 32],
                [0x62u8; 32],
            )
            .expect("spent conservation statement");
        let new_conservation_statement =
            AllocationConservationSegmentStatement::<1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
                RgkAllocationTranscriptSide::New,
                0,
                1,
                0,
                core::slice::from_ref(&new_allocation),
                [0x52u8; 32],
                [0x63u8; 32],
                [0x64u8; 32],
            )
            .expect("new conservation statement");
        let spent_conservation_circuit =
            AllocationConservationSegmentCircuit::<1>::from_statement_and_witness(
                &spent_conservation_statement,
                AllocationConservationSegmentWitness::<1>::from_allocations(
                    0,
                    core::slice::from_ref(&spent_allocation),
                    [0x51u8; 32],
                    [0x61u8; 32],
                    [0x62u8; 32],
                )
                .expect("spent conservation witness"),
            )
            .expect("spent conservation circuit");
        let new_conservation_circuit =
            AllocationConservationSegmentCircuit::<1>::from_statement_and_witness(
                &new_conservation_statement,
                AllocationConservationSegmentWitness::<1>::from_allocations(
                    0,
                    core::slice::from_ref(&new_allocation),
                    [0x52u8; 32],
                    [0x63u8; 32],
                    [0x64u8; 32],
                )
                .expect("new conservation witness"),
            )
            .expect("new conservation circuit");
        let conservation_segment_setup =
            setup_allocation_conservation_segment(&spent_conservation_circuit)
                .expect("conservation segment setup");
        let spent_conservation_proof = prove_allocation_conservation_segment(
            &conservation_segment_setup.pk,
            spent_conservation_circuit.clone(),
        )
        .expect("spent conservation proof");
        let new_conservation_proof = prove_allocation_conservation_segment(
            &conservation_segment_setup.pk,
            new_conservation_circuit.clone(),
        )
        .expect("new conservation proof");
        let spent_conservation_stack = allocation_conservation_segment_groth16_precompile_stack(
            &conservation_segment_setup.vk,
            &spent_conservation_proof,
            &spent_conservation_circuit.public_inputs,
        )
        .expect("spent conservation stack");
        let new_conservation_stack = allocation_conservation_segment_groth16_precompile_stack(
            &conservation_segment_setup.vk,
            &new_conservation_proof,
            &new_conservation_circuit.public_inputs,
        )
        .expect("new conservation stack");

        let final_conservation = AllocationConservationFinalStatement::from_total(
            1,
            1,
            1_000_000,
            [0x62u8; 32],
            [0x64u8; 32],
        )
        .expect("final conservation statement");
        let final_conservation_circuit =
            AllocationConservationFinalCircuit::from_statement_and_witness(
                &final_conservation,
                AllocationConservationFinalWitness::new(1_000_000, [0x62u8; 32], [0x64u8; 32])
                    .expect("final conservation witness"),
            )
            .expect("final conservation circuit");
        let final_conservation_setup =
            setup_allocation_conservation_final(&final_conservation_circuit)
                .expect("final conservation setup");
        let final_conservation_proof = prove_allocation_conservation_final(
            &final_conservation_setup.pk,
            final_conservation_circuit.clone(),
        )
        .expect("final conservation proof");
        let final_conservation_stack = allocation_conservation_final_groth16_precompile_stack(
            &final_conservation_setup.vk,
            &final_conservation_proof,
            &final_conservation_circuit.public_inputs,
        )
        .expect("final conservation stack");

        let exclusion_statement =
            AllocationExclusionSegmentPairStatement::<1, 1>::from_allocations(
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
                allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
                0,
                0,
                1,
                1,
                core::slice::from_ref(&spent_allocation),
                core::slice::from_ref(&new_allocation),
                [0x51u8; 32],
                [0x52u8; 32],
            )
            .expect("exclusion statement");
        let exclusion_circuit =
            AllocationExclusionSegmentPairCircuit::<1, 1>::from_statement_and_witness(
                &exclusion_statement,
                AllocationExclusionSegmentPairWitness::<1, 1>::from_allocations(
                    core::slice::from_ref(&spent_allocation),
                    core::slice::from_ref(&new_allocation),
                    [0x51u8; 32],
                    [0x52u8; 32],
                )
                .expect("exclusion witness"),
            )
            .expect("exclusion circuit");
        let exclusion_setup =
            setup_allocation_exclusion_segment_pair(&exclusion_circuit).expect("exclusion setup");
        let exclusion_proof =
            prove_allocation_exclusion_segment_pair(&exclusion_setup.pk, exclusion_circuit.clone())
                .expect("exclusion proof");
        let exclusion_stack = allocation_exclusion_segment_pair_groth16_precompile_stack(
            &exclusion_setup.vk,
            &exclusion_proof,
            &exclusion_circuit.public_inputs,
        )
        .expect("exclusion stack");

        AllocationAuditCertificateFixture {
            spent_transcripts: alloc::vec![spent_transcript_statement],
            new_transcripts: alloc::vec![new_transcript_statement],
            spent_conservation: alloc::vec![spent_conservation_statement],
            new_conservation: alloc::vec![new_conservation_statement],
            final_conservation,
            exclusions: alloc::vec![exclusion_statement],
            spent_transcript_stacks: alloc::vec![spent_transcript_stack],
            new_transcript_stacks: alloc::vec![new_transcript_stack],
            spent_conservation_stacks: alloc::vec![spent_conservation_stack],
            new_conservation_stacks: alloc::vec![new_conservation_stack],
            final_conservation_stack,
            exclusion_stacks: alloc::vec![exclusion_stack],
        }
    }

    fn proof_policy() -> RgkProofPolicy {
        RgkProofPolicy::VerifierReceipt {
            verifier_key_hash: [0x91u8; 32],
        }
    }

    fn metadata_commitment() -> RgkMetadataCommitment {
        RgkMetadataCommitment::from_bytes([0x99u8; 32])
            .expect("fixture metadata commitment is non-zero")
    }

    fn owner_commitment() -> RgkOwnerCommitment {
        RgkOwnerCommitment::from_bytes([0xaau8; 32]).expect("fixture owner commitment is non-zero")
    }

    fn allocation(
        outpoint_txid: [u8; 32],
        index: u32,
        covenant_id: [u8; 32],
        witness_txid: [u8; 32],
        daa_score: u64,
        amount: u64,
        note: [u8; 32],
    ) -> RgkAllocation {
        RgkAllocation {
            anchor: RgkCovenantAnchor {
                chain: KASPA_LOCAL_TOCCATA,
                covenant_outpoint: KaspaOutpoint {
                    transaction_id: outpoint_txid,
                    index,
                },
                covenant_id,
                witness_txid,
                daa_score,
                confirmation_depth: 1,
            },
            amount,
            encrypted_note_commitment: note,
        }
    }

    fn sample_allocation_statement_and_witness(
    ) -> (SemanticTransitionStatement, OneInOneOutAllocationWitness) {
        let asset_id = [0x22u8; 32];
        let covenant_id = [0x11u8; 32];
        let total_supply = 1_000_000;
        let spent = allocation(
            [0xaau8; 32],
            0,
            covenant_id,
            [0xbbu8; 32],
            1,
            total_supply,
            [0xccu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![spent.clone()],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue.validate().expect("native issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![spent.clone()],
            new_allocation_shapes: alloc::vec![RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id,
                amount: total_supply,
                encrypted_note_commitment: [0xddu8; 32],
            }],
            burn: None,
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan.validate().expect("native continuation report");
        let finalized = plan
            .finalize([0xeeu8; 32], 2, 1)
            .expect("native finalized continuation");
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic statement");
        let witness = OneInOneOutAllocationWitness::from_allocations(
            &spent,
            &finalized.transition.new_allocations[0],
        )
        .expect("allocation witness");
        (statement, witness)
    }

    fn sample_burn_allocation_statement_and_witness(
    ) -> (SemanticTransitionStatement, OneInOneOutAllocationWitness) {
        let asset_id = [0x22u8; 32];
        let covenant_id = [0x11u8; 32];
        let total_supply = 1_000_000;
        let burned_supply = 100;
        let spent = allocation(
            [0xaau8; 32],
            0,
            covenant_id,
            [0xbbu8; 32],
            1,
            total_supply,
            [0xccu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![spent.clone()],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue.validate().expect("native issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![spent.clone()],
            new_allocation_shapes: alloc::vec![RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id,
                amount: total_supply - burned_supply,
                encrypted_note_commitment: [0xddu8; 32],
            }],
            burn: Some(RgkBurnProof {
                amount: burned_supply,
                authorization_commitment: [0xb1u8; 32],
            }),
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan
            .validate_for_production_zk()
            .expect("native burn continuation report");
        let finalized = plan
            .finalize_for_production_zk([0xeeu8; 32], 2, 1)
            .expect("native finalized burn continuation");
        assert_eq!(continuation_report.burned_supply, burned_supply);
        assert_eq!(finalized.transition_report.burned_supply, burned_supply);
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic burn statement");
        assert_eq!(statement.spent_supply, total_supply);
        assert_eq!(statement.new_supply, total_supply - burned_supply);
        assert_eq!(statement.burned_supply, burned_supply);
        let witness = OneInOneOutAllocationWitness::from_allocations(
            &spent,
            &finalized.transition.new_allocations[0],
        )
        .expect("allocation burn witness");
        (statement, witness)
    }

    fn sample_terminal_burn_statement_and_witness(
    ) -> (SemanticTransitionStatement, OneInZeroOutAllocationWitness) {
        let asset_id = [0x42u8; 32];
        let covenant_id = [0x41u8; 32];
        let total_supply = 1;
        let transition_witness_txid = [0xeeu8; 32];
        let spent = allocation(
            [0x4au8; 32],
            0,
            covenant_id,
            [0x4bu8; 32],
            1,
            total_supply,
            [0x4cu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![spent.clone()],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue.validate().expect("native terminal-burn issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![spent.clone()],
            new_allocation_shapes: alloc::vec![],
            burn: Some(RgkBurnProof {
                amount: total_supply,
                authorization_commitment: [0x4du8; 32],
            }),
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan
            .validate_for_production_zk()
            .expect("native terminal-burn continuation report");
        let finalized = plan
            .finalize_for_production_zk(transition_witness_txid, 2, 1)
            .expect("native finalized terminal-burn continuation");
        assert_eq!(continuation_report.spent_supply, total_supply);
        assert_eq!(continuation_report.new_supply, 0);
        assert_eq!(continuation_report.burned_supply, total_supply);
        assert_eq!(finalized.transition_report.new_allocation_count, 0);
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic terminal-burn statement");
        assert_eq!(statement.spent_allocation_count, 1);
        assert_eq!(statement.new_allocation_count, 0);
        assert_eq!(statement.new_supply, 0);
        assert_eq!(statement.burned_supply, total_supply);
        let witness =
            OneInZeroOutAllocationWitness::from_allocation(&spent, transition_witness_txid)
                .expect("terminal-burn allocation witness");
        (statement, witness)
    }

    fn sample_allocation_2x2_statement_and_witness(
    ) -> (SemanticTransitionStatement, TwoInTwoOutAllocationWitness) {
        let asset_id = [0x22u8; 32];
        let covenant_id = [0x11u8; 32];
        let total_supply = 1_000_000;
        let spent_0 = allocation(
            [0xaau8; 32],
            0,
            covenant_id,
            [0xbau8; 32],
            1,
            400_000,
            [0xcau8; 32],
        );
        let spent_1 = allocation(
            [0xabu8; 32],
            0,
            covenant_id,
            [0xbbu8; 32],
            1,
            600_000,
            [0xcbu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![spent_0.clone(), spent_1.clone()],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue.validate().expect("native issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![spent_0.clone(), spent_1.clone()],
            new_allocation_shapes: alloc::vec![
                RgkContinuationAllocationShape {
                    output_index: 0,
                    covenant_id,
                    amount: 250_000,
                    encrypted_note_commitment: [0xdau8; 32],
                },
                RgkContinuationAllocationShape {
                    output_index: 1,
                    covenant_id,
                    amount: 750_000,
                    encrypted_note_commitment: [0xdbu8; 32],
                },
            ],
            burn: None,
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan.validate().expect("native continuation report");
        let finalized = plan
            .finalize([0xeeu8; 32], 2, 1)
            .expect("native finalized continuation");
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic statement");
        let witness = TwoInTwoOutAllocationWitness::from_allocations(
            [&spent_0, &spent_1],
            [
                &finalized.transition.new_allocations[0],
                &finalized.transition.new_allocations[1],
            ],
        )
        .expect("allocation witness");
        (statement, witness)
    }

    fn sample_allocation_3x2_statement_and_witness() -> (
        SemanticTransitionStatement,
        FixedAllocationVectorWitness<3, 2>,
    ) {
        let asset_id = [0x22u8; 32];
        let covenant_id = [0x11u8; 32];
        let total_supply = 1_000_000;
        let spent_0 = allocation(
            [0xaau8; 32],
            0,
            covenant_id,
            [0xbau8; 32],
            1,
            100_000,
            [0xcau8; 32],
        );
        let spent_1 = allocation(
            [0xabu8; 32],
            0,
            covenant_id,
            [0xbbu8; 32],
            1,
            300_000,
            [0xcbu8; 32],
        );
        let spent_2 = allocation(
            [0xacu8; 32],
            0,
            covenant_id,
            [0xbcu8; 32],
            1,
            600_000,
            [0xccu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![spent_0.clone(), spent_1.clone(), spent_2.clone()],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue.validate().expect("native issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![spent_0.clone(), spent_1.clone(), spent_2.clone()],
            new_allocation_shapes: alloc::vec![
                RgkContinuationAllocationShape {
                    output_index: 0,
                    covenant_id,
                    amount: 450_000,
                    encrypted_note_commitment: [0xdau8; 32],
                },
                RgkContinuationAllocationShape {
                    output_index: 1,
                    covenant_id,
                    amount: 550_000,
                    encrypted_note_commitment: [0xdbu8; 32],
                },
            ],
            burn: None,
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan.validate().expect("native continuation report");
        let finalized = plan
            .finalize([0xeeu8; 32], 2, 1)
            .expect("native finalized continuation");
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic statement");
        let witness = FixedAllocationVectorWitness::<3, 2>::from_allocations(
            [&spent_0, &spent_1, &spent_2],
            [
                &finalized.transition.new_allocations[0],
                &finalized.transition.new_allocations[1],
            ],
        )
        .expect("allocation witness");
        (statement, witness)
    }

    fn sample_allocation_4x2_statement_and_witness() -> (
        SemanticTransitionStatement,
        FixedAllocationVectorWitness<4, 2>,
    ) {
        let asset_id = [0x22u8; 32];
        let covenant_id = [0x11u8; 32];
        let total_supply = 1_000_000;
        let spent_0 = allocation(
            [0xaau8; 32],
            0,
            covenant_id,
            [0xbau8; 32],
            1,
            100_000,
            [0xcau8; 32],
        );
        let spent_1 = allocation(
            [0xabu8; 32],
            0,
            covenant_id,
            [0xbbu8; 32],
            1,
            200_000,
            [0xcbu8; 32],
        );
        let spent_2 = allocation(
            [0xacu8; 32],
            0,
            covenant_id,
            [0xbcu8; 32],
            1,
            300_000,
            [0xccu8; 32],
        );
        let spent_3 = allocation(
            [0xadu8; 32],
            0,
            covenant_id,
            [0xbdu8; 32],
            1,
            400_000,
            [0xcdu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![
                spent_0.clone(),
                spent_1.clone(),
                spent_2.clone(),
                spent_3.clone()
            ],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue
            .validate_for_production_zk()
            .expect("native production-ZK issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![
                spent_0.clone(),
                spent_1.clone(),
                spent_2.clone(),
                spent_3.clone()
            ],
            new_allocation_shapes: alloc::vec![
                RgkContinuationAllocationShape {
                    output_index: 0,
                    covenant_id,
                    amount: 450_000,
                    encrypted_note_commitment: [0xdau8; 32],
                },
                RgkContinuationAllocationShape {
                    output_index: 1,
                    covenant_id,
                    amount: 550_000,
                    encrypted_note_commitment: [0xdbu8; 32],
                },
            ],
            burn: None,
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan
            .validate_for_production_zk()
            .expect("native production-ZK continuation report");
        let finalized = plan
            .finalize_for_production_zk([0xeeu8; 32], 2, 1)
            .expect("native finalized production-ZK continuation");
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic statement");
        let witness = FixedAllocationVectorWitness::<4, 2>::from_allocations(
            [&spent_0, &spent_1, &spent_2, &spent_3],
            [
                &finalized.transition.new_allocations[0],
                &finalized.transition.new_allocations[1],
            ],
        )
        .expect("allocation witness");
        (statement, witness)
    }

    fn sample_allocation_4x4_statement_and_witness() -> (
        SemanticTransitionStatement,
        FixedAllocationVectorWitness<4, 4>,
    ) {
        let asset_id = [0x22u8; 32];
        let covenant_id = [0x11u8; 32];
        let total_supply = 1_000_000;
        let spent_0 = allocation(
            [0xaau8; 32],
            0,
            covenant_id,
            [0xbau8; 32],
            1,
            100_000,
            [0xcau8; 32],
        );
        let spent_1 = allocation(
            [0xabu8; 32],
            0,
            covenant_id,
            [0xbbu8; 32],
            1,
            200_000,
            [0xcbu8; 32],
        );
        let spent_2 = allocation(
            [0xacu8; 32],
            0,
            covenant_id,
            [0xbcu8; 32],
            1,
            300_000,
            [0xccu8; 32],
        );
        let spent_3 = allocation(
            [0xadu8; 32],
            0,
            covenant_id,
            [0xbdu8; 32],
            1,
            400_000,
            [0xcdu8; 32],
        );
        let issue = RgkAssetIssue {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            owner_commitment: owner_commitment(),
            allocations: alloc::vec![
                spent_0.clone(),
                spent_1.clone(),
                spent_2.clone(),
                spent_3.clone()
            ],
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let issue_report = issue
            .validate_for_production_zk()
            .expect("native production-ZK issue report");
        let plan = RgkContinuationPlan {
            chain: KASPA_LOCAL_TOCCATA,
            schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
            asset_id,
            total_supply,
            metadata_commitment: metadata_commitment(),
            previous_owner_commitment: owner_commitment(),
            new_owner_commitment: owner_commitment(),
            ownership_authorization_commitment: [0; 32],
            previous_state_digest: issue_report.state_digest,
            spent_allocations: alloc::vec![
                spent_0.clone(),
                spent_1.clone(),
                spent_2.clone(),
                spent_3.clone()
            ],
            new_allocation_shapes: alloc::vec![
                RgkContinuationAllocationShape {
                    output_index: 0,
                    covenant_id,
                    amount: 150_000,
                    encrypted_note_commitment: [0xdau8; 32],
                },
                RgkContinuationAllocationShape {
                    output_index: 1,
                    covenant_id,
                    amount: 250_000,
                    encrypted_note_commitment: [0xdbu8; 32],
                },
                RgkContinuationAllocationShape {
                    output_index: 2,
                    covenant_id,
                    amount: 250_000,
                    encrypted_note_commitment: [0xdcu8; 32],
                },
                RgkContinuationAllocationShape {
                    output_index: 3,
                    covenant_id,
                    amount: 350_000,
                    encrypted_note_commitment: [0xddu8; 32],
                },
            ],
            burn: None,
            lane_id: [0x77u8; 32],
            privacy_policy: LanePrivacyPolicy::PrivateLane,
            proof_policy: proof_policy(),
        };
        let continuation_report = plan
            .validate_for_production_zk()
            .expect("native production-ZK continuation report");
        let finalized = plan
            .finalize_for_production_zk([0xeeu8; 32], 2, 1)
            .expect("native finalized production-ZK continuation");
        let statement = SemanticTransitionStatement::from_reports(
            &finalized.transition_report,
            &continuation_report,
        )
        .expect("semantic statement");
        let witness = FixedAllocationVectorWitness::<4, 4>::from_allocations(
            [&spent_0, &spent_1, &spent_2, &spent_3],
            [
                &finalized.transition.new_allocations[0],
                &finalized.transition.new_allocations[1],
                &finalized.transition.new_allocations[2],
                &finalized.transition.new_allocations[3],
            ],
        )
        .expect("allocation witness");
        (statement, witness)
    }

    #[test]
    fn supported_allocation_shape_registry_is_explicit() {
        assert_eq!(
            SUPPORTED_ALLOCATION_CIRCUIT_SHAPES,
            [
                AllocationCircuitShape::OneInZeroOut,
                AllocationCircuitShape::OneInOneOut,
                AllocationCircuitShape::TwoInTwoOut,
                AllocationCircuitShape::ThreeInTwoOut,
                AllocationCircuitShape::FourInTwoOut,
                AllocationCircuitShape::FourInFourOut,
            ]
        );
        assert_eq!(
            SUPPORTED_ALLOCATION_CIRCUIT_SHAPES.map(AllocationCircuitShape::native_shape),
            RGK_ALLOCATION_STRATEGY_ZK_SHAPES
        );
        assert_eq!(
            AllocationCircuitShape::from_counts(1, 0),
            Some(AllocationCircuitShape::OneInZeroOut)
        );
        assert_eq!(
            AllocationCircuitShape::from_counts(1, 1),
            Some(AllocationCircuitShape::OneInOneOut)
        );
        assert_eq!(
            AllocationCircuitShape::from_counts(2, 2),
            Some(AllocationCircuitShape::TwoInTwoOut)
        );
        assert_eq!(
            AllocationCircuitShape::from_counts(3, 2),
            Some(AllocationCircuitShape::ThreeInTwoOut)
        );
        assert_eq!(
            AllocationCircuitShape::from_counts(4, 2),
            Some(AllocationCircuitShape::FourInTwoOut)
        );
        assert_eq!(
            AllocationCircuitShape::from_counts(4, 4),
            Some(AllocationCircuitShape::FourInFourOut)
        );
        assert_eq!(AllocationCircuitShape::from_counts(4, 3), None);
    }

    #[test]
    fn production_allocation_strategy_is_bounded_and_fail_closed() {
        let strategy = DEFAULT_ALLOCATION_PROOF_STRATEGY;
        assert_eq!(strategy.label(), "bounded-supported-shapes");
        assert_eq!(strategy.max_spent_count(), 4);
        assert_eq!(strategy.max_new_count(), 4);
        assert_eq!(
            strategy.plan_counts(1, 0).expect("1x0 plan").shape,
            AllocationCircuitShape::OneInZeroOut
        );
        assert_eq!(
            strategy.plan_counts(3, 2).expect("3x2 plan").shape,
            AllocationCircuitShape::ThreeInTwoOut
        );
        assert_eq!(
            strategy.plan_counts(4, 2).expect("4x2 plan").shape,
            AllocationCircuitShape::FourInTwoOut
        );
        assert_eq!(
            strategy.plan_counts(4, 4).expect("4x4 plan").shape,
            AllocationCircuitShape::FourInFourOut
        );

        let err = strategy
            .plan_counts(3, 3)
            .expect_err("3x3 has no evidenced production circuit shape");
        assert!(
            err.contains("outside RGK production ZK strategy bounded-supported-shapes")
                && err.contains("full-state intermediate transition inside supported shapes"),
            "unexpected bounded-strategy error: {err}"
        );

        let (mut statement, _) = sample_allocation_3x2_statement_and_witness();
        statement.spent_allocation_count = 5;
        let err = strategy
            .plan_statement(&statement)
            .expect_err("5x2 statement must fail before proof construction");
        assert!(
            err.contains("production ZK allocation proof shape 5x2")
                && err.contains("1x0, 1x1, 2x2, 3x2, 4x2, 4x4"),
            "unexpected statement planning error: {err}"
        );
    }

    #[test]
    fn supported_allocation_witness_rejects_unsupported_shape() {
        let spent = alloc::vec![
            allocation(
                [0xaau8; 32],
                0,
                [0x11u8; 32],
                [0xbau8; 32],
                1,
                250_000,
                [0xcau8; 32],
            ),
            allocation(
                [0xabu8; 32],
                0,
                [0x11u8; 32],
                [0xbbu8; 32],
                1,
                250_000,
                [0xcbu8; 32],
            ),
            allocation(
                [0xacu8; 32],
                0,
                [0x11u8; 32],
                [0xbcu8; 32],
                1,
                250_000,
                [0xccu8; 32],
            ),
            allocation(
                [0xadu8; 32],
                0,
                [0x11u8; 32],
                [0xbdu8; 32],
                1,
                250_000,
                [0xcdu8; 32],
            ),
        ];
        let new = alloc::vec![
            allocation(
                [0xeeu8; 32],
                0,
                [0x11u8; 32],
                [0xeeu8; 32],
                2,
                300_000,
                [0xdau8; 32],
            ),
            allocation(
                [0xeeu8; 32],
                1,
                [0x11u8; 32],
                [0xeeu8; 32],
                2,
                300_000,
                [0xdbu8; 32],
            ),
            allocation(
                [0xeeu8; 32],
                2,
                [0x11u8; 32],
                [0xeeu8; 32],
                2,
                400_000,
                [0xdcu8; 32],
            ),
        ];
        let err = SupportedAllocationVectorWitness::from_allocations(&spent, &new)
            .expect_err("4x3 has no proved circuit shape yet");
        assert!(
            err.contains("production ZK allocation proof shape 4x3")
                && err.contains("bounded-supported-shapes")
                && err.contains("1x0, 1x1, 2x2, 3x2, 4x2, 4x4"),
            "unexpected unsupported-shape error: {err}"
        );
    }

    #[test]
    fn supported_allocation_circuit_rejects_statement_witness_shape_mismatch() {
        let (mut statement, witness) = sample_allocation_3x2_statement_and_witness();
        statement.spent_allocation_count = 2;
        let err = SupportedAllocationVectorCircuit::from_statement_and_witness(
            &statement,
            SupportedAllocationVectorWitness::ThreeInTwoOut(witness),
        )
        .err()
        .expect("2x2 statement must not accept a 3x2 witness");
        assert!(
            err.contains("witness shape 3x2") && err.contains("statement shape 2x2"),
            "unexpected shape-mismatch error: {err}"
        );
    }

    #[test]
    fn prove_then_verify_zk_receipt() {
        let receipt = sample_receipt();
        let receipt_id = rgk_core::receipt_commitment(&receipt);
        let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);

        let Groth16Setup { pk, vk } = setup(&circuit).expect("setup");
        let proof = prove(&pk, circuit.clone()).expect("prove");

        let public_fr = public_inputs_as_fr(&circuit.public_inputs);

        let ok = verify(&vk, &public_fr, &proof).expect("verify");
        assert!(ok, "Groth16 verification must accept a valid proof");

        let encoded = encode_for_precompile(&proof).expect("encode proof for precompile");
        assert_eq!(encoded[0], ZK_TAG_GROTH16);
        assert!(
            encoded.len() > 1,
            "transport proof blob must contain proof bytes"
        );
        eprintln!("[real-zk] proof size: {} bytes", encoded.len());
    }

    #[test]
    fn groth16_precompile_stack_shape_matches_toccata() {
        let receipt = sample_receipt();
        let receipt_id = rgk_core::receipt_commitment(&receipt);
        let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
        let Groth16Setup { pk, vk } = setup(&circuit).expect("setup");
        let proof = prove(&pk, circuit.clone()).expect("prove");

        let stack = groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
            .expect("precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 29);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn tampered_proof_rejected() {
        let receipt = sample_receipt();
        let receipt_id = rgk_core::receipt_commitment(&receipt);
        let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
        let Groth16Setup { pk, vk } = setup(&circuit).expect("setup");
        let proof = prove(&pk, circuit.clone()).expect("prove");

        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).expect("serialize");
        bytes[5] ^= 0x01;
        let rejected = match Proof::<Bn254>::deserialize_compressed(&bytes[..]) {
            Ok(corrupted) => {
                let public_fr = public_inputs_as_fr(&circuit.public_inputs);
                !verify(&vk, &public_fr, &corrupted).expect("verify")
            }
            Err(_) => true,
        };
        assert!(rejected, "tampered proof bytes must be rejected");
    }

    #[test]
    fn different_public_body_field_rejected() {
        let receipt = sample_receipt();
        let receipt_id = rgk_core::receipt_commitment(&receipt);
        let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
        let Groth16Setup { pk, vk } = setup(&circuit).expect("setup");
        let proof = prove(&pk, circuit.clone()).expect("prove");

        let mut public_inputs = circuit.public_inputs.clone();
        public_inputs[0] ^= 0x01;
        let public_fr = public_inputs_as_fr(&public_inputs);

        let ok = verify(&vk, &public_fr, &proof).expect("verify");
        assert!(
            !ok,
            "Groth16 verification must reject changed public receipt fields"
        );
    }

    #[test]
    fn same_receipt_id_different_body_cannot_prove() {
        use ark_relations::r1cs::ConstraintSystem;

        let receipt = sample_receipt();
        let receipt_id = rgk_core::receipt_commitment(&receipt);

        let mut tampered_receipt = receipt.clone();
        tampered_receipt.replay_nonce[0] ^= 0x01;
        let tampered_circuit = ReceiptCircuit::from_receipt(&tampered_receipt, receipt_id);

        let cs = ConstraintSystem::<Fr>::new_ref();
        tampered_circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "same public receipt_id with a different private body must not satisfy the circuit"
        );
    }

    #[test]
    fn public_inputs_as_fr_layout_is_deterministic() {
        let receipt = sample_receipt();
        let receipt_id = rgk_core::receipt_commitment(&receipt);
        let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
        let pi = public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(pi.len(), 29);
        let pi2 = public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(pi, pi2);
    }

    #[test]
    fn prove_then_verify_semantic_transition_statement() {
        let statement = sample_semantic_statement();
        let circuit = SemanticTransitionCircuit::from_statement(&statement);

        let Groth16Setup { pk, vk } = setup_semantic(&circuit).expect("semantic setup");
        let proof = prove_semantic(&pk, circuit.clone()).expect("semantic prove");

        let public_fr = semantic_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("semantic verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid semantic proof"
        );
    }

    #[test]
    fn semantic_groth16_precompile_stack_shape_matches_toccata() {
        let statement = sample_semantic_statement();
        let circuit = SemanticTransitionCircuit::from_statement(&statement);
        let Groth16Setup { pk, vk } = setup_semantic(&circuit).expect("semantic setup");
        let proof = prove_semantic(&pk, circuit.clone()).expect("semantic prove");

        let stack = semantic_groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
            .expect("semantic precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 64);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn semantic_changed_public_input_rejected() {
        let statement = sample_semantic_statement();
        let circuit = SemanticTransitionCircuit::from_statement(&statement);
        let Groth16Setup { pk, vk } = setup_semantic(&circuit).expect("semantic setup");
        let proof = prove_semantic(&pk, circuit.clone()).expect("semantic prove");

        let mut public_inputs = circuit.public_inputs.clone();
        public_inputs[8] ^= 0x01;
        let public_fr = semantic_public_inputs_as_fr(&public_inputs);

        let ok = verify(&vk, &public_fr, &proof).expect("semantic verify");
        assert!(
            !ok,
            "Groth16 verification must reject changed semantic public inputs"
        );
    }

    #[test]
    fn lane_discovery_statement_matches_native_derivation() {
        let (statement, witness) = sample_lane_discovery();
        assert!(statement.matches_witness(&witness));
        assert_eq!(statement.public_inputs().len(), 72);
        assert_eq!(
            statement.lane_id,
            derive_blinded_lane_id(witness.view_key, witness.asset_id, statement.epoch)
        );
        assert_eq!(
            statement.scan_tag,
            RgkScanTag::derive(witness.view_key, statement.lane_id, statement.epoch).to_bytes()
        );
    }

    #[test]
    fn prove_then_verify_lane_discovery() {
        let (statement, witness) = sample_lane_discovery();
        let circuit = LaneDiscoveryCircuit::from_statement_and_witness(&statement, witness)
            .expect("lane discovery circuit");

        let Groth16Setup { pk, vk } = setup_lane_discovery(&circuit).expect("lane discovery setup");
        let proof = prove_lane_discovery(&pk, circuit.clone()).expect("lane discovery prove");

        let public_fr = lane_discovery_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 9);
        let ok = verify(&vk, &public_fr, &proof).expect("lane discovery verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid lane-discovery proof"
        );
    }

    #[test]
    fn lane_discovery_precompile_stack_shape_matches_toccata() {
        let (statement, witness) = sample_lane_discovery();
        let circuit = LaneDiscoveryCircuit::from_statement_and_witness(&statement, witness)
            .expect("lane discovery circuit");
        let Groth16Setup { pk, vk } = setup_lane_discovery(&circuit).expect("lane discovery setup");
        let proof = prove_lane_discovery(&pk, circuit.clone()).expect("lane discovery prove");

        let stack = lane_discovery_groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
            .expect("lane discovery precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 9);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn lane_discovery_changed_public_scan_tag_rejected() {
        let (statement, witness) = sample_lane_discovery();
        let circuit = LaneDiscoveryCircuit::from_statement_and_witness(&statement, witness)
            .expect("lane discovery circuit");
        let Groth16Setup { pk, vk } = setup_lane_discovery(&circuit).expect("lane discovery setup");
        let proof = prove_lane_discovery(&pk, circuit.clone()).expect("lane discovery prove");

        let mut public_inputs = circuit.public_inputs.clone();
        public_inputs[32] ^= 0x01;
        let public_fr = lane_discovery_public_inputs_as_fr(&public_inputs);

        let ok = verify(&vk, &public_fr, &proof).expect("lane discovery verify");
        assert!(
            !ok,
            "Groth16 verification must reject changed public scan tags"
        );
    }

    #[test]
    fn wrong_view_key_cannot_satisfy_lane_discovery_circuit() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_lane_discovery();
        witness.view_key[0] ^= 0x01;
        assert!(!statement.matches_witness(&witness));

        let circuit = LaneDiscoveryCircuit {
            public_inputs: statement.public_inputs(),
            witness,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "wrong view key must not satisfy the lane-discovery circuit"
        );
    }

    #[test]
    fn lane_graph_discovery_statement_matches_native_graph_root() {
        let (statement, witness) = sample_lane_graph_discovery();
        assert!(statement.matches_witness(&witness));
        assert_eq!(
            statement.public_inputs().len(),
            LaneGraphDiscoveryStatement::<2>::PUBLIC_INPUT_LEN
        );
        assert_eq!(
            statement.graph_root,
            derive_private_lane_graph_root(&statement.native_nodes())
        );
        assert_ne!(statement.nodes[0].lane_id, statement.nodes[1].lane_id);
        assert_eq!(
            statement.nodes[1].scan_tag,
            RgkScanTag::derive(witness.view_key, statement.nodes[1].lane_id, 8).to_bytes()
        );
    }

    #[test]
    fn prove_then_verify_lane_graph_discovery() {
        let (statement, witness) = sample_lane_graph_discovery();
        let circuit =
            LaneGraphDiscoveryCircuit::<2>::from_statement_and_witness(&statement, witness)
                .expect("lane graph discovery circuit");

        let Groth16Setup { pk, vk } =
            setup_lane_graph_discovery(&circuit).expect("lane graph discovery setup");
        let proof =
            prove_lane_graph_discovery(&pk, circuit.clone()).expect("lane graph discovery prove");

        let public_fr = lane_graph_discovery_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 22);
        let ok = verify(&vk, &public_fr, &proof).expect("lane graph discovery verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid lane-graph discovery proof"
        );
    }

    #[test]
    fn lane_graph_discovery_precompile_stack_shape_matches_toccata() {
        let (statement, witness) = sample_lane_graph_discovery();
        let circuit =
            LaneGraphDiscoveryCircuit::<2>::from_statement_and_witness(&statement, witness)
                .expect("lane graph discovery circuit");
        let Groth16Setup { pk, vk } =
            setup_lane_graph_discovery(&circuit).expect("lane graph discovery setup");
        let proof =
            prove_lane_graph_discovery(&pk, circuit.clone()).expect("lane graph discovery prove");

        let stack =
            lane_graph_discovery_groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
                .expect("lane graph discovery precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 22);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn lane_graph_discovery_changed_public_node_rejected() {
        let (statement, witness) = sample_lane_graph_discovery();
        let circuit =
            LaneGraphDiscoveryCircuit::<2>::from_statement_and_witness(&statement, witness)
                .expect("lane graph discovery circuit");
        let Groth16Setup { pk, vk } =
            setup_lane_graph_discovery(&circuit).expect("lane graph discovery setup");
        let proof =
            prove_lane_graph_discovery(&pk, circuit.clone()).expect("lane graph discovery prove");

        let mut public_inputs = circuit.public_inputs.clone();
        public_inputs[32 + 32] ^= 0x01;
        let public_fr = lane_graph_discovery_public_inputs_as_fr(&public_inputs);

        let ok = verify(&vk, &public_fr, &proof).expect("lane graph discovery verify");
        assert!(
            !ok,
            "Groth16 verification must reject changed public lane-graph nodes"
        );
    }

    #[test]
    fn wrong_view_key_cannot_satisfy_lane_graph_discovery_circuit() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_lane_graph_discovery();
        witness.view_key[0] ^= 0x01;
        assert!(!statement.matches_witness(&witness));

        let circuit = LaneGraphDiscoveryCircuit::<2> {
            public_inputs: statement.public_inputs(),
            witness,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "wrong view key must not satisfy the lane-graph discovery circuit"
        );
    }

    #[test]
    fn lane_graph_segment_statement_matches_native_rolling_root() {
        let (statement, witness) = sample_lane_graph_segment();
        assert!(statement.matches_witness(&witness));
        assert_eq!(
            statement.public_inputs().len(),
            LaneGraphSegmentStatement::<2>::PUBLIC_INPUT_LEN
        );
        assert_eq!(
            statement.next_root,
            extend_private_lane_graph_root(
                statement.previous_root,
                statement.segment_index,
                &statement.native_nodes(),
            )
        );
        assert_ne!(statement.previous_root, statement.next_root);
        assert_eq!(
            statement.nodes[0].scan_tag,
            RgkScanTag::derive(witness.view_key, statement.nodes[0].lane_id, 7).to_bytes()
        );
    }

    #[test]
    fn prove_then_verify_lane_graph_segment() {
        let (statement, witness) = sample_lane_graph_segment();
        let circuit = LaneGraphSegmentCircuit::<2>::from_statement_and_witness(&statement, witness)
            .expect("lane graph segment circuit");

        let Groth16Setup { pk, vk } =
            setup_lane_graph_segment(&circuit).expect("lane graph segment setup");
        let proof =
            prove_lane_graph_segment(&pk, circuit.clone()).expect("lane graph segment prove");

        let public_fr = lane_graph_segment_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 27);
        let ok = verify(&vk, &public_fr, &proof).expect("lane graph segment verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid lane-graph segment proof"
        );
    }

    #[test]
    fn lane_graph_segment_precompile_stack_shape_matches_toccata() {
        let (statement, witness) = sample_lane_graph_segment();
        let circuit = LaneGraphSegmentCircuit::<2>::from_statement_and_witness(&statement, witness)
            .expect("lane graph segment circuit");
        let Groth16Setup { pk, vk } =
            setup_lane_graph_segment(&circuit).expect("lane graph segment setup");
        let proof =
            prove_lane_graph_segment(&pk, circuit.clone()).expect("lane graph segment prove");

        let stack =
            lane_graph_segment_groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
                .expect("lane graph segment precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 27);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn lane_graph_segment_changed_public_root_rejected() {
        let (statement, witness) = sample_lane_graph_segment();
        let circuit = LaneGraphSegmentCircuit::<2>::from_statement_and_witness(&statement, witness)
            .expect("lane graph segment circuit");
        let Groth16Setup { pk, vk } =
            setup_lane_graph_segment(&circuit).expect("lane graph segment setup");
        let proof =
            prove_lane_graph_segment(&pk, circuit.clone()).expect("lane graph segment prove");

        let mut public_inputs = circuit.public_inputs.clone();
        public_inputs[32] ^= 0x01;
        let public_fr = lane_graph_segment_public_inputs_as_fr(&public_inputs);

        let ok = verify(&vk, &public_fr, &proof).expect("lane graph segment verify");
        assert!(
            !ok,
            "Groth16 verification must reject changed public segment roots"
        );
    }

    #[test]
    fn wrong_view_key_cannot_satisfy_lane_graph_segment_circuit() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_lane_graph_segment();
        witness.view_key[0] ^= 0x01;
        assert!(!statement.matches_witness(&witness));

        let circuit = LaneGraphSegmentCircuit::<2> {
            public_inputs: statement.public_inputs(),
            witness,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "wrong view key must not satisfy the lane-graph segment circuit"
        );
    }

    #[test]
    fn allocation_transcript_segment_statement_matches_native_root() {
        let (statement, witness, allocations) = sample_allocation_transcript_segment();

        assert_eq!(
            statement.next_root,
            extend_allocation_transcript_root(
                statement.previous_root,
                statement.side,
                statement.segment_index,
                statement.total_count,
                &allocations,
            )
        );
        assert!(statement.matches_witness(&witness));
        assert_eq!(
            statement.public_inputs().len(),
            AllocationTranscriptSegmentStatement::<2>::PUBLIC_INPUT_LEN
        );
        assert_eq!(
            allocation_transcript_segment_public_inputs_as_fr(&statement.public_inputs()).len(),
            16
        );
        assert_eq!(
            statement.segment_amount_commitment,
            allocation_transcript_amount_commitment(
                statement.side,
                statement.segment_index,
                statement.total_count,
                witness.segment_amount,
                witness.amount_blinding,
            )
        );
    }

    #[test]
    fn prove_then_verify_allocation_transcript_segment() {
        let (statement, witness, _) = sample_allocation_transcript_segment();
        let circuit = AllocationTranscriptSegmentCircuit::<2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation transcript circuit");

        let Groth16Setup { pk, vk } =
            setup_allocation_transcript_segment(&circuit).expect("allocation transcript setup");
        let proof = prove_allocation_transcript_segment(&pk, circuit.clone())
            .expect("allocation transcript proof");

        let public_fr = allocation_transcript_segment_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 16);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation transcript verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid allocation transcript segment proof"
        );
    }

    #[test]
    fn allocation_transcript_segment_precompile_stack_shape_matches_toccata() {
        let (statement, witness, _) = sample_allocation_transcript_segment();
        let circuit = AllocationTranscriptSegmentCircuit::<2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation transcript circuit");
        let Groth16Setup { pk, vk } =
            setup_allocation_transcript_segment(&circuit).expect("allocation transcript setup");
        let proof = prove_allocation_transcript_segment(&pk, circuit.clone())
            .expect("allocation transcript proof");

        let stack = allocation_transcript_segment_groth16_precompile_stack(
            &vk,
            &proof,
            &circuit.public_inputs,
        )
        .expect("allocation transcript precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 16);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn allocation_transcript_segment_rejects_changed_public_amount_commitment() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, witness, _) = sample_allocation_transcript_segment();
        let mut circuit = AllocationTranscriptSegmentCircuit::<2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation transcript circuit");
        circuit.public_inputs[96] ^= 0x01;

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation transcript constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation transcript circuit must reject changed public segment amount commitment"
        );
    }

    #[test]
    fn allocation_transcript_segment_rejects_wrong_amount_blinding() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness, _) = sample_allocation_transcript_segment();
        witness.amount_blinding[0] ^= 0x01;
        assert!(!statement.matches_witness(&witness));
        let circuit = AllocationTranscriptSegmentCircuit::<2> {
            public_inputs: statement.public_inputs(),
            allocation_witness: witness,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation transcript constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation transcript circuit must reject a wrong private amount blinding"
        );
    }

    #[test]
    fn allocation_transcript_segment_rejects_changed_witness_amount() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness, _) = sample_allocation_transcript_segment();
        witness.allocations[0][117..125].copy_from_slice(&399_999u64.to_le_bytes());
        assert!(!statement.matches_witness(&witness));
        let circuit = AllocationTranscriptSegmentCircuit::<2> {
            public_inputs: statement.public_inputs(),
            allocation_witness: witness,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation transcript constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation transcript circuit must reject changed private allocation amount"
        );
    }

    #[test]
    fn allocation_conservation_segment_statement_matches_native_commitments() {
        let (statement, witness, allocations) = sample_allocation_conservation_segment();

        assert_eq!(
            statement.transcript.next_root,
            extend_allocation_transcript_root(
                statement.transcript.previous_root,
                statement.transcript.side,
                statement.transcript.segment_index,
                statement.transcript.total_count,
                &allocations,
            )
        );
        assert!(statement.matches_witness(&witness));
        assert_eq!(
            statement.public_inputs().len(),
            AllocationConservationSegmentStatement::<2>::PUBLIC_INPUT_LEN
        );
        assert_eq!(
            allocation_conservation_segment_public_inputs_as_fr(&statement.public_inputs()).len(),
            24
        );
        assert_eq!(
            statement.next_total_commitment,
            allocation_conservation_total_commitment(
                RgkAllocationTranscriptSide::Spent,
                2,
                1_000_000,
                [0x62u8; 32],
            )
        );
    }

    #[test]
    fn prove_then_verify_allocation_conservation_segment() {
        let (statement, witness, _) = sample_allocation_conservation_segment();
        let circuit = AllocationConservationSegmentCircuit::<2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation conservation segment circuit");

        let Groth16Setup { pk, vk } = setup_allocation_conservation_segment(&circuit)
            .expect("allocation conservation segment setup");
        let proof = prove_allocation_conservation_segment(&pk, circuit.clone())
            .expect("allocation conservation segment proof");

        let public_fr = allocation_conservation_segment_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 24);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation conservation segment verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid allocation conservation segment proof"
        );
    }

    #[test]
    fn allocation_conservation_segment_precompile_stack_shape_matches_toccata() {
        let (statement, witness, _) = sample_allocation_conservation_segment();
        let circuit = AllocationConservationSegmentCircuit::<2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation conservation segment circuit");
        let Groth16Setup { pk, vk } = setup_allocation_conservation_segment(&circuit)
            .expect("allocation conservation segment setup");
        let proof = prove_allocation_conservation_segment(&pk, circuit.clone())
            .expect("allocation conservation segment proof");

        let stack = allocation_conservation_segment_groth16_precompile_stack(
            &vk,
            &proof,
            &circuit.public_inputs,
        )
        .expect("allocation conservation segment precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 24);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn allocation_conservation_segment_rejects_changed_running_total_commitment() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, witness, _) = sample_allocation_conservation_segment();
        let mut circuit = AllocationConservationSegmentCircuit::<2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation conservation segment circuit");
        circuit.public_inputs[160] ^= 0x01;

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation conservation segment constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation conservation segment circuit must reject a changed next total commitment"
        );
    }

    #[test]
    fn allocation_conservation_segment_rejects_nonzero_initial_running_total() {
        use ark_relations::r1cs::ConstraintSystem;

        let allocation = allocation(
            [0xfau8; 32],
            0,
            [0x11u8; 32],
            [0xfbu8; 32],
            1,
            1_000_000,
            [0xfcu8; 32],
        );
        let allocations = alloc::vec![allocation];
        let constructor_error = AllocationConservationSegmentStatement::<1>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
            RgkAllocationTranscriptSide::Spent,
            0,
            1,
            7,
            &allocations,
            [0x51u8; 32],
            [0x61u8; 32],
            [0x62u8; 32],
        )
        .expect_err("initial conservation constructor must reject non-zero start");
        assert!(constructor_error.contains("start from zero"));

        let mut forged_statement = AllocationConservationSegmentStatement::<1>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
            RgkAllocationTranscriptSide::Spent,
            0,
            1,
            0,
            &allocations,
            [0x51u8; 32],
            [0x61u8; 32],
            [0x62u8; 32],
        )
        .expect("valid initial conservation statement");
        forged_statement.previous_total_commitment = allocation_conservation_total_commitment(
            RgkAllocationTranscriptSide::Spent,
            1,
            7,
            [0x61u8; 32],
        );
        forged_statement.next_total_commitment = allocation_conservation_total_commitment(
            RgkAllocationTranscriptSide::Spent,
            1,
            1_000_007,
            [0x62u8; 32],
        );
        let witness = AllocationConservationSegmentWitness::<1>::from_allocations(
            7,
            &allocations,
            [0x51u8; 32],
            [0x61u8; 32],
            [0x62u8; 32],
        )
        .expect("forged conservation witness");
        assert!(!forged_statement.matches_witness(&witness));
        let circuit = AllocationConservationSegmentCircuit::<1> {
            public_inputs: forged_statement.public_inputs(),
            witness,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation conservation segment constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "initial allocation conservation segment must prove a zero previous total"
        );
    }

    #[test]
    fn prove_then_verify_allocation_conservation_final() {
        let (statement, witness) = sample_allocation_conservation_final();
        assert!(statement.matches_witness(&witness));
        let circuit =
            AllocationConservationFinalCircuit::from_statement_and_witness(&statement, witness)
                .expect("allocation conservation final circuit");

        let Groth16Setup { pk, vk } = setup_allocation_conservation_final(&circuit)
            .expect("allocation conservation final setup");
        let proof = prove_allocation_conservation_final(&pk, circuit.clone())
            .expect("allocation conservation final proof");

        let public_fr = allocation_conservation_final_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 10);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation conservation final verify");
        assert!(
            ok,
            "Groth16 verification must accept a final allocation conservation equality proof"
        );
    }

    #[test]
    fn allocation_conservation_final_rejects_total_mismatch() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_allocation_conservation_final();
        witness.total = 999_999;
        assert!(!statement.matches_witness(&witness));
        let circuit = AllocationConservationFinalCircuit {
            public_inputs: statement.public_inputs(),
            witness,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation conservation final constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation conservation final circuit must reject a total that does not open both commitments"
        );
    }

    #[test]
    fn allocation_exclusion_segment_pair_statement_matches_native_roots() {
        let (statement, witness, spent_allocations, new_allocations) =
            sample_allocation_exclusion_segment_pair();

        assert_eq!(
            statement.spent_next_root,
            extend_allocation_transcript_root(
                statement.spent_previous_root,
                RgkAllocationTranscriptSide::Spent,
                statement.spent_segment_index,
                statement.spent_total_count,
                &spent_allocations,
            )
        );
        assert_eq!(
            statement.new_next_root,
            extend_allocation_transcript_root(
                statement.new_previous_root,
                RgkAllocationTranscriptSide::New,
                statement.new_segment_index,
                statement.new_total_count,
                &new_allocations,
            )
        );
        assert!(statement.matches_witness(&witness));
        assert_eq!(
            statement.public_inputs().len(),
            AllocationExclusionSegmentPairStatement::<2, 2>::PUBLIC_INPUT_LEN
        );
        assert_eq!(
            allocation_exclusion_segment_pair_public_inputs_as_fr(&statement.public_inputs()).len(),
            29
        );
    }

    #[test]
    fn prove_then_verify_allocation_exclusion_segment_pair() {
        let (statement, witness, _, _) = sample_allocation_exclusion_segment_pair();
        let circuit = AllocationExclusionSegmentPairCircuit::<2, 2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation exclusion circuit");

        let Groth16Setup { pk, vk } =
            setup_allocation_exclusion_segment_pair(&circuit).expect("allocation exclusion setup");
        let proof = prove_allocation_exclusion_segment_pair(&pk, circuit.clone())
            .expect("allocation exclusion proof");

        let public_fr =
            allocation_exclusion_segment_pair_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 29);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation exclusion verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid allocation exclusion segment-pair proof"
        );
    }

    #[test]
    fn allocation_exclusion_segment_pair_precompile_stack_shape_matches_toccata() {
        let (statement, witness, _, _) = sample_allocation_exclusion_segment_pair();
        let circuit = AllocationExclusionSegmentPairCircuit::<2, 2>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation exclusion circuit");
        let Groth16Setup { pk, vk } =
            setup_allocation_exclusion_segment_pair(&circuit).expect("allocation exclusion setup");
        let proof = prove_allocation_exclusion_segment_pair(&pk, circuit.clone())
            .expect("allocation exclusion proof");

        let stack = allocation_exclusion_segment_pair_groth16_precompile_stack(
            &vk,
            &proof,
            &circuit.public_inputs,
        )
        .expect("allocation exclusion precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 29);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn allocation_exclusion_segment_pair_rejects_reused_spent_anchor() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness, _, _) = sample_allocation_exclusion_segment_pair();
        let spent_outpoint = witness.spent.allocations[0][1..41].to_vec();
        witness.new.allocations[0][1..41].copy_from_slice(&spent_outpoint);
        assert!(!statement.matches_witness(&witness));
        let circuit = AllocationExclusionSegmentPairCircuit::<2, 2> {
            public_inputs: statement.public_inputs(),
            witness,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation exclusion constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation exclusion circuit must reject a new segment that reuses a spent outpoint"
        );
    }

    #[test]
    fn allocation_exclusion_segment_pair_accepts_same_txid_with_distinct_indices() {
        use ark_relations::r1cs::ConstraintSystem;

        let spent = allocation(
            [0xeeu8; 32],
            0,
            [0x11u8; 32],
            [0xbau8; 32],
            1,
            1_000_000,
            [0xcau8; 32],
        );
        let new = allocation(
            [0xeeu8; 32],
            1,
            [0x11u8; 32],
            [0xbbu8; 32],
            2,
            1_000_000,
            [0xcbu8; 32],
        );
        let statement = AllocationExclusionSegmentPairStatement::<1, 1>::from_allocations(
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
            allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
            0,
            0,
            1,
            1,
            core::slice::from_ref(&spent),
            core::slice::from_ref(&new),
            [0x51u8; 32],
            [0x52u8; 32],
        )
        .expect("allocation exclusion statement");
        let witness = AllocationExclusionSegmentPairWitness::<1, 1>::from_allocations(
            core::slice::from_ref(&spent),
            core::slice::from_ref(&new),
            [0x51u8; 32],
            [0x52u8; 32],
        )
        .expect("allocation exclusion witness");
        assert!(statement.matches_witness(&witness));
        let circuit = AllocationExclusionSegmentPairCircuit::<1, 1>::from_statement_and_witness(
            &statement, witness,
        )
        .expect("allocation exclusion circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation exclusion constraint synthesis");
        assert!(
            cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation exclusion circuit must treat the full txid+index as the spent outpoint"
        );
    }

    #[test]
    fn allocation_exclusion_segment_pair_rejects_changed_public_commitment() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, witness, _, _) = sample_allocation_exclusion_segment_pair();
        let mut circuit =
            AllocationExclusionSegmentPairCircuit::<2, 2>::from_statement_and_witness(
                &statement, witness,
            )
            .expect("allocation exclusion circuit");
        circuit.public_inputs[168] ^= 0x01;

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation exclusion constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation exclusion circuit must reject a changed public amount commitment"
        );
    }

    #[test]
    fn allocation_audit_bundle_verifies_complete_statement_grid() {
        let fixture = sample_allocation_audit_bundle_grid();
        let report = verify_allocation_audit_bundle(&fixture.bundle())
            .expect("complete allocation audit bundle");

        assert_eq!(report.chain_id, KASPA_LOCAL_TOCCATA);
        assert_eq!(report.spent_segments, 2);
        assert_eq!(report.new_segments, 2);
        assert_eq!(report.exclusion_pairs, 4);
        assert_eq!(report.spent_total_count, 2);
        assert_eq!(report.new_total_count, 2);
        assert_eq!(
            report.spent_final_root,
            fixture
                .spent_transcripts
                .last()
                .expect("spent root")
                .next_root
        );
        assert_eq!(
            report.new_final_root,
            fixture.new_transcripts.last().expect("new root").next_root
        );
        assert_eq!(
            report.spent_total_commitment,
            fixture.final_conservation.spent_total_commitment
        );
        assert_eq!(
            report.new_total_commitment,
            fixture.final_conservation.new_total_commitment
        );
    }

    #[test]
    fn allocation_audit_bundle_rejects_missing_exclusion_pair() {
        let mut fixture = sample_allocation_audit_bundle_grid();
        fixture.exclusions.pop();

        let err = verify_allocation_audit_bundle(&fixture.bundle())
            .expect_err("missing exclusion pair must be rejected");
        assert!(err.contains("allocation exclusion grid has 3 pairs, expected 4"));
    }

    #[test]
    fn allocation_audit_bundle_rejects_duplicate_exclusion_pair() {
        let mut fixture = sample_allocation_audit_bundle_grid();
        fixture.exclusions[3] = fixture.exclusions[0].clone();

        let err = verify_allocation_audit_bundle(&fixture.bundle())
            .expect_err("duplicate exclusion pair must be rejected");
        assert!(err.contains("duplicate allocation exclusion grid pair spent=0 new=0"));
    }

    #[test]
    fn allocation_audit_bundle_rejects_broken_transcript_chain_link() {
        let mut fixture = sample_allocation_audit_bundle_grid();
        fixture.spent_transcripts[1].previous_root[0] ^= 0x01;

        let err = verify_allocation_audit_bundle(&fixture.bundle())
            .expect_err("broken transcript chain link must be rejected");
        assert!(err.contains("spent transcript segment 1 does not link"));
    }

    #[test]
    fn allocation_audit_bundle_rejects_final_conservation_mismatch() {
        let mut fixture = sample_allocation_audit_bundle_grid();
        fixture.final_conservation.spent_total_commitment[0] ^= 0x01;

        let err = verify_allocation_audit_bundle(&fixture.bundle())
            .expect_err("final conservation mismatch must be rejected");
        assert!(err.contains(
            "spent conservation chain terminal commitment does not match final equality statement"
        ));
    }

    #[test]
    fn allocation_audit_certificate_binds_verified_groth16_stack_material() {
        let fixture = sample_allocation_audit_certificate_fixture();
        let bundle = fixture.bundle();
        let stacks = fixture.stacks();
        let certificate = build_allocation_audit_certificate(&bundle, &stacks)
            .expect("allocation audit certificate");
        let report = verify_allocation_audit_certificate(&certificate, &bundle)
            .expect("allocation audit certificate verification");
        let rebuilt = build_allocation_audit_certificate(&bundle, &stacks)
            .expect("rebuilt allocation audit certificate");

        assert_eq!(certificate.certificate_id, rebuilt.certificate_id);
        assert_eq!(certificate.proof_entry_count(), 6);
        assert!(certificate.total_verifying_key_bytes() > certificate.total_proof_bytes());
        assert_eq!(report.spent_segments, 1);
        assert_eq!(report.new_segments, 1);
        assert_eq!(report.exclusion_pairs, 1);
    }

    #[test]
    fn allocation_audit_certificate_canonical_encoding_round_trips() {
        let fixture = sample_allocation_audit_certificate_fixture();
        let bundle = fixture.bundle();
        let stacks = fixture.stacks();
        let certificate = build_allocation_audit_certificate(&bundle, &stacks)
            .expect("allocation audit certificate");

        let encoded = certificate
            .encode_canonical()
            .expect("encode allocation audit certificate");
        let decoded = AllocationAuditCertificate::decode_canonical(&encoded)
            .expect("decode allocation audit certificate");
        assert_eq!(decoded, certificate);
        verify_allocation_audit_certificate(&decoded, &bundle)
            .expect("decoded certificate verifies against bundle");

        let mut trailing = encoded.clone();
        trailing.push(0);
        let err = AllocationAuditCertificate::decode_canonical(&trailing)
            .expect_err("trailing bytes must be rejected");
        assert!(err.contains("trailing"), "unexpected error: {err}");

        let mut tampered_id = encoded.clone();
        tampered_id[ALLOCATION_AUDIT_CERTIFICATE_MAGIC.len()] ^= 0x01;
        let err = AllocationAuditCertificate::decode_canonical(&tampered_id)
            .expect_err("certificate id mismatch must be rejected");
        assert!(err.contains("id does not bind"), "unexpected error: {err}");

        let mut tampered_body = encoded;
        let body_byte = ALLOCATION_AUDIT_CERTIFICATE_MAGIC.len() + 32 + 4;
        tampered_body[body_byte] ^= 0x01;
        let err = AllocationAuditCertificate::decode_canonical(&tampered_body)
            .expect_err("body tamper must be rejected");
        assert!(err.contains("id does not bind"), "unexpected error: {err}");
    }

    #[test]
    fn allocation_audit_certificate_canonical_self_contained_verifies() {
        let fixture = sample_allocation_audit_certificate_fixture();
        let bundle = fixture.bundle();
        let stacks = fixture.stacks();
        let certificate = build_allocation_audit_certificate(&bundle, &stacks)
            .expect("allocation audit certificate");
        let encoded = certificate
            .encode_canonical()
            .expect("encode allocation audit certificate");

        let direct_report =
            verify_allocation_audit_certificate_self_contained::<1, 1>(&certificate)
                .expect("self-contained allocation audit certificate verification");
        let (decoded, decoded_report) =
            verify_allocation_audit_certificate_canonical::<1, 1>(&encoded)
                .expect("canonical self-contained allocation audit certificate verification");

        assert_eq!(decoded, certificate);
        assert_eq!(direct_report, decoded_report);
        assert_eq!(
            decoded_report,
            verify_allocation_audit_bundle(&bundle).expect("bundle report")
        );
    }

    #[test]
    fn allocation_audit_certificate_self_contained_rejects_rebound_tampers() {
        let fixture = sample_allocation_audit_certificate_fixture();
        let bundle = fixture.bundle();
        let stacks = fixture.stacks();
        let certificate = build_allocation_audit_certificate(&bundle, &stacks)
            .expect("allocation audit certificate");

        let mut order_tampered = certificate.clone();
        order_tampered.proofs.swap(0, 1);
        order_tampered.certificate_id =
            allocation_audit_certificate_id(&order_tampered.report, &order_tampered.proofs)
                .expect("recompute order-tampered certificate id");
        let err = verify_allocation_audit_certificate_self_contained::<1, 1>(&order_tampered)
            .expect_err("manifest order tamper must be rejected");
        assert!(
            err.contains("deterministic manifest order"),
            "unexpected error: {err}"
        );

        let mut report_tampered = certificate.clone();
        report_tampered.report.spent_segments = 2;
        report_tampered.certificate_id =
            allocation_audit_certificate_id(&report_tampered.report, &report_tampered.proofs)
                .expect("recompute report-tampered certificate id");
        let err = verify_allocation_audit_certificate_self_contained::<1, 1>(&report_tampered)
            .expect_err("report tamper must be rejected");
        assert!(
            err.contains("report does not match reconstructed manifest"),
            "unexpected error: {err}"
        );

        let mut public_input_tampered = certificate;
        public_input_tampered.proofs[0].public_inputs[80] ^= 0x01;
        public_input_tampered.certificate_id = allocation_audit_certificate_id(
            &public_input_tampered.report,
            &public_input_tampered.proofs,
        )
        .expect("recompute public-input-tampered certificate id");
        let err =
            verify_allocation_audit_certificate_self_contained::<1, 1>(&public_input_tampered)
                .expect_err("public input tamper must be rejected");
        assert!(
            err.contains("stack public inputs do not match the statement"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn allocation_audit_certificate_rejects_tampered_stack_material() {
        let fixture = sample_allocation_audit_certificate_fixture();
        let bundle = fixture.bundle();
        let stacks = fixture.stacks();
        let certificate = build_allocation_audit_certificate(&bundle, &stacks)
            .expect("allocation audit certificate");

        let mut public_input_tampered = certificate.clone();
        public_input_tampered.proofs[0].stack.public_inputs[0][0] ^= 0x01;
        let err = verify_allocation_audit_certificate(&public_input_tampered, &bundle)
            .expect_err("changed stack public input must be rejected");
        assert!(err.contains("stack public inputs do not match the statement"));

        let mut proof_tampered = certificate;
        proof_tampered.proofs[0].stack.proof[0] ^= 0x01;
        proof_tampered.certificate_id =
            allocation_audit_certificate_id(&proof_tampered.report, &proof_tampered.proofs)
                .expect("recompute tampered certificate id");

        let err = verify_allocation_audit_certificate(&proof_tampered, &bundle)
            .expect_err("tampered proof bytes must be rejected");
        assert!(
            err.contains("proof") || err.contains("Groth16 proof did not verify"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prove_then_verify_allocation_1x1_transition() {
        let (statement, witness) = sample_allocation_statement_and_witness();
        let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");

        let Groth16Setup { pk, vk } = setup_allocation_1x1(&circuit).expect("allocation setup");
        let proof = prove_allocation_1x1(&pk, circuit.clone()).expect("allocation prove");

        let public_fr = semantic_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid allocation-vector proof"
        );
    }

    #[test]
    fn prove_then_verify_allocation_1x1_burn_transition() {
        let (statement, witness) = sample_burn_allocation_statement_and_witness();
        let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("burn allocation circuit");

        let Groth16Setup { pk, vk } =
            setup_allocation_1x1(&circuit).expect("burn allocation setup");
        let proof = prove_allocation_1x1(&pk, circuit.clone()).expect("burn allocation prove");

        let public_fr = semantic_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("burn allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid burn allocation-vector proof"
        );
    }

    #[test]
    fn prove_then_verify_allocation_1x0_terminal_burn_transition() {
        let (statement, witness) = sample_terminal_burn_statement_and_witness();
        let circuit =
            OneInZeroOutAllocationCircuit::from_statement_and_witness(&statement, witness)
                .expect("terminal burn allocation circuit");

        let Groth16Setup { pk, vk } =
            setup_allocation_1x0(&circuit).expect("terminal burn allocation setup");
        let proof =
            prove_allocation_1x0(&pk, circuit.clone()).expect("terminal burn allocation prove");

        let public_fr = semantic_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("terminal burn allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid terminal burn allocation-vector proof"
        );
    }

    #[test]
    fn allocation_1x1_rejects_inconsistent_burn_accounting() {
        use ark_relations::r1cs::ConstraintSystem;

        let (mut statement, witness) = sample_burn_allocation_statement_and_witness();
        statement.burned_supply = 50;
        let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("burn allocation circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("burn allocation constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation circuit must reject public burn accounting that does not match private amounts"
        );
    }

    #[test]
    fn allocation_1x1_precompile_stack_shape_matches_toccata() {
        let (statement, witness) = sample_allocation_statement_and_witness();
        let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");
        let Groth16Setup { pk, vk } = setup_allocation_1x1(&circuit).expect("allocation setup");
        let proof = prove_allocation_1x1(&pk, circuit.clone()).expect("allocation prove");

        let stack = allocation_1x1_groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
            .expect("allocation precompile stack");

        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 64);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn allocation_1x1_rejects_supply_mismatch() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_allocation_statement_and_witness();
        witness.new_allocation[117..125].copy_from_slice(&999_999u64.to_le_bytes());
        let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation circuit must reject amount mismatch against public supply accounting"
        );
    }

    #[test]
    fn allocation_1x1_rejects_spent_anchor_reuse() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_allocation_statement_and_witness();
        let spent_outpoint = witness.spent_allocation[1..41].to_vec();
        witness.new_allocation[1..41].copy_from_slice(&spent_outpoint);
        let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "allocation circuit must reject reuse of the spent outpoint"
        );
    }

    #[test]
    fn prove_then_verify_allocation_2x2_transition() {
        let (statement, witness) = sample_allocation_2x2_statement_and_witness();
        let circuit = TwoInTwoOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");

        let Groth16Setup { pk, vk } = setup_allocation_2x2(&circuit).expect("allocation setup");
        let proof = prove_allocation_2x2(&pk, circuit.clone()).expect("allocation prove");

        let public_fr = semantic_public_inputs_as_fr(&circuit.public_inputs);
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid 2x2 allocation-vector proof"
        );

        let stack = allocation_2x2_groth16_precompile_stack(&vk, &proof, &circuit.public_inputs)
            .expect("allocation precompile stack");
        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 64);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn allocation_2x2_rejects_supply_mismatch() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_allocation_2x2_statement_and_witness();
        witness.new_allocations[0][117..125].copy_from_slice(&249_999u64.to_le_bytes());
        let circuit = TwoInTwoOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "2x2 allocation circuit must reject amount mismatch against public supply accounting"
        );
    }

    #[test]
    fn allocation_2x2_rejects_spent_anchor_reuse() {
        use ark_relations::r1cs::ConstraintSystem;

        let (statement, mut witness) = sample_allocation_2x2_statement_and_witness();
        let spent_outpoint = witness.spent_allocations[1][1..41].to_vec();
        witness.new_allocations[0][1..41].copy_from_slice(&spent_outpoint);
        let circuit = TwoInTwoOutAllocationCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "2x2 allocation circuit must reject reuse of any spent outpoint"
        );
    }

    #[test]
    fn prove_then_verify_fixed_allocation_3x2_transition() {
        let (statement, witness) = sample_allocation_3x2_statement_and_witness();
        let circuit =
            FixedAllocationVectorCircuit::<3, 2>::from_statement_and_witness(&statement, witness)
                .expect("allocation circuit");
        let supported_circuit = SupportedAllocationVectorCircuit::ThreeInTwoOut(circuit);

        let Groth16Setup { pk, vk } =
            setup_supported_allocation(&supported_circuit).expect("allocation setup");
        let proof =
            prove_supported_allocation(&pk, supported_circuit.clone()).expect("allocation prove");

        let public_fr = semantic_public_inputs_as_fr(supported_circuit.public_inputs());
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid 3x2 allocation-vector proof"
        );

        let stack = supported_allocation_groth16_precompile_stack(&vk, &proof, &supported_circuit)
            .expect("allocation precompile stack");
        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 64);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn prove_then_verify_fixed_allocation_4x2_transition() {
        let (statement, witness) = sample_allocation_4x2_statement_and_witness();
        let circuit =
            FixedAllocationVectorCircuit::<4, 2>::from_statement_and_witness(&statement, witness)
                .expect("allocation circuit");
        let supported_circuit = SupportedAllocationVectorCircuit::FourInTwoOut(circuit);

        let Groth16Setup { pk, vk } =
            setup_supported_allocation(&supported_circuit).expect("allocation setup");
        let proof =
            prove_supported_allocation(&pk, supported_circuit.clone()).expect("allocation prove");

        let public_fr = semantic_public_inputs_as_fr(supported_circuit.public_inputs());
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid 4x2 allocation-vector proof"
        );

        let stack = supported_allocation_groth16_precompile_stack(&vk, &proof, &supported_circuit)
            .expect("allocation precompile stack");
        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 64);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn prove_then_verify_fixed_allocation_4x4_transition() {
        let (statement, witness) = sample_allocation_4x4_statement_and_witness();
        let circuit =
            FixedAllocationVectorCircuit::<4, 4>::from_statement_and_witness(&statement, witness)
                .expect("allocation circuit");
        let supported_circuit = SupportedAllocationVectorCircuit::FourInFourOut(circuit);

        let Groth16Setup { pk, vk } =
            setup_supported_allocation(&supported_circuit).expect("allocation setup");
        let proof =
            prove_supported_allocation(&pk, supported_circuit.clone()).expect("allocation prove");

        let public_fr = semantic_public_inputs_as_fr(supported_circuit.public_inputs());
        assert_eq!(public_fr.len(), 64);
        let ok = verify(&vk, &public_fr, &proof).expect("allocation verify");
        assert!(
            ok,
            "Groth16 verification must accept a valid 4x4 allocation-vector proof"
        );

        let stack = supported_allocation_groth16_precompile_stack(&vk, &proof, &supported_circuit)
            .expect("allocation precompile stack");
        assert_eq!(stack.tag, [ZK_TAG_GROTH16]);
        assert_eq!(stack.public_input_count(), 64);
        assert!(stack.verifying_key.len() > stack.proof.len());
        assert!(!stack.proof.is_empty());
        assert!(
            stack.public_inputs.iter().all(|fr| fr.len() == 32),
            "Toccata expects each BN254 Fr as one 32-byte stack item"
        );
    }

    #[test]
    fn fixed_allocation_3x2_rejects_count_mismatch() {
        use ark_relations::r1cs::ConstraintSystem;

        let (mut statement, witness) = sample_allocation_3x2_statement_and_witness();
        statement.spent_allocation_count = 2;
        let circuit =
            FixedAllocationVectorCircuit::<3, 2>::from_statement_and_witness(&statement, witness)
                .expect("allocation circuit");

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("allocation constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "fixed allocation circuit must reject statement count mismatches"
        );
    }

    #[test]
    fn fixed_allocation_witness_rejects_zero_arity() {
        let err = FixedAllocationVectorWitness::<0, 1>::new(
            [],
            [alloc::vec![
                0u8;
                ALLOCATION_WITNESS_LEN
            ]],
        )
        .expect_err("zero spent side must be rejected");
        assert!(
            err.contains("at least one spent"),
            "unexpected zero-arity error: {err}"
        );
    }

    #[test]
    fn invalid_semantic_statement_cannot_satisfy_constraints() {
        use ark_relations::r1cs::ConstraintSystem;

        let mut statement = sample_semantic_statement();
        statement.new_state_digest = statement.previous_state_digest;
        let circuit = SemanticTransitionCircuit::from_statement(&statement);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("semantic constraint synthesis");
        assert!(
            !cs.is_satisfied().expect("constraint satisfaction check"),
            "old and new state digests must differ inside the semantic circuit"
        );
    }
}
