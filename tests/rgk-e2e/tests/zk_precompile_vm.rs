#![cfg(all(feature = "live-kaspa-wrpc", feature = "real-zk"))]

use kaspa_consensus_core::{hashing::sighash::SigHashReusedValuesUnsync, tx::PopulatedTransaction};
use kaspa_txscript::{
    caches::Cache, opcodes::codes::OpZkPrecompile, script_builder::ScriptBuilder, EngineFlags,
    TxScriptEngine,
};

use rgk_asset::{
    allocation_transcript_empty_root, private_lane_graph_empty_root, LanePrivacyPolicy,
    RgkAllocation, RgkAllocationTranscriptSide, RgkAssetIssue, RgkContinuationAllocationShape,
    RgkContinuationPlan, RgkCovenantSeal, RgkMetadataCommitment, RgkOwnerCommitment,
    RgkProofPolicy, RGK_FUNGIBLE_ASSET_SCHEMA_ID,
};
use rgk_core::{
    receipt_commitment, KaspaOutpoint, ProofMode, ReceiptPolicy, RgkReceipt, RgkStateCommitment,
    KASPA_LOCAL_TOCCATA,
};
use rgk_zk::real_zk::{
    self, AllocationConservationFinalCircuit, AllocationConservationFinalStatement,
    AllocationConservationFinalWitness, AllocationConservationSegmentCircuit,
    AllocationConservationSegmentStatement, AllocationConservationSegmentWitness,
    AllocationExclusionSegmentPairCircuit, AllocationExclusionSegmentPairStatement,
    AllocationExclusionSegmentPairWitness, AllocationTranscriptSegmentCircuit,
    AllocationTranscriptSegmentStatement, AllocationTranscriptSegmentWitness,
    FixedAllocationVectorWitness, Groth16PrecompileStack, LaneDiscoveryCircuit,
    LaneDiscoveryStatement, LaneDiscoveryWitness, LaneGraphDiscoveryCircuit,
    LaneGraphDiscoveryStatement, LaneGraphSegmentCircuit, LaneGraphSegmentStatement,
    OneInOneOutAllocationCircuit, OneInOneOutAllocationWitness, ReceiptCircuit,
    SemanticTransitionCircuit, SupportedAllocationVectorCircuit, SupportedAllocationVectorWitness,
    TwoInTwoOutAllocationCircuit, TwoInTwoOutAllocationWitness,
};
use rgk_zk::SemanticTransitionStatement;

fn sample_receipt() -> RgkReceipt {
    RgkReceipt {
        version: rgk_core::ENCODING_VERSION,
        chain_id: KASPA_LOCAL_TOCCATA,
        covenant_id: [0x11; 32],
        old_state: RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: KASPA_LOCAL_TOCCATA,
            covenant_id: [0x11; 32],
            asset_id: [0x22; 32],
            state_digest: [0x01; 32],
            receipt_policy: ReceiptPolicy::ZkOrVerifier,
        },
        new_state: RgkStateCommitment {
            version: rgk_core::ENCODING_VERSION,
            chain_id: KASPA_LOCAL_TOCCATA,
            covenant_id: [0x11; 32],
            asset_id: [0x22; 32],
            state_digest: [0x02; 32],
            receipt_policy: ReceiptPolicy::ZkOrVerifier,
        },
        transition_digest: [0x33; 32],
        continuation_commitment: [0x55; 32],
        proof_mode: ProofMode::ZkReceipt,
        replay_nonce: [0x44; 32],
    }
}

fn sample_semantic_statement() -> SemanticTransitionStatement {
    SemanticTransitionStatement {
        chain_id: KASPA_LOCAL_TOCCATA,
        schema_id: *b"rgk:asset:schema:v1_____________",
        asset_id: [0x22; 32],
        previous_state_digest: [0x01; 32],
        new_state_digest: [0x02; 32],
        transition_digest: [0x33; 32],
        continuation_commitment: [0x55; 32],
        continuation_shape_root: [0x66; 32],
        lane_id: [0x77; 32],
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        policy_commitment: [0x88; 32],
        metadata_commitment: [0x99; 32],
        previous_owner_commitment: [0xaa; 32],
        new_owner_commitment: [0xaa; 32],
        ownership_authorization_commitment: [0; 32],
        total_supply: 1_000_000,
        spent_allocation_count: 1,
        new_allocation_count: 1,
        spent_supply: 1_000_000,
        new_supply: 1_000_000,
        burned_supply: 0,
        burn_authorization_commitment: [0; 32],
    }
}

fn proof_policy() -> RgkProofPolicy {
    RgkProofPolicy::VerifierReceipt {
        verifier_key_hash: [0x91; 32],
    }
}

fn metadata_commitment() -> RgkMetadataCommitment {
    RgkMetadataCommitment([0x99; 32])
}

fn owner_commitment() -> RgkOwnerCommitment {
    RgkOwnerCommitment([0xaa; 32])
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
        seal: RgkCovenantSeal {
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
    let asset_id = [0x22; 32];
    let covenant_id = [0x11; 32];
    let total_supply = 1_000_000;
    let spent = allocation(
        [0xaa; 32],
        0,
        covenant_id,
        [0xbb; 32],
        1,
        total_supply,
        [0xcc; 32],
    );
    let issue = RgkAssetIssue {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations: vec![spent.clone()],
        lane_id: [0x77; 32],
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
        spent_allocations: vec![spent.clone()],
        new_allocation_shapes: vec![RgkContinuationAllocationShape {
            output_index: 1,
            covenant_id,
            amount: total_supply,
            encrypted_note_commitment: [0xdd; 32],
        }],
        burn: None,
        lane_id: [0x77; 32],
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: proof_policy(),
    };
    let continuation_report = plan.validate().expect("native continuation report");
    let finalized = plan
        .finalize([0xee; 32], 2, 1)
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

fn sample_allocation_2x2_statement_and_witness(
) -> (SemanticTransitionStatement, TwoInTwoOutAllocationWitness) {
    let asset_id = [0x22; 32];
    let covenant_id = [0x11; 32];
    let total_supply = 1_000_000;
    let spent_0 = allocation(
        [0xaa; 32],
        0,
        covenant_id,
        [0xba; 32],
        1,
        400_000,
        [0xca; 32],
    );
    let spent_1 = allocation(
        [0xab; 32],
        0,
        covenant_id,
        [0xbb; 32],
        1,
        600_000,
        [0xcb; 32],
    );
    let issue = RgkAssetIssue {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations: vec![spent_0.clone(), spent_1.clone()],
        lane_id: [0x77; 32],
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
        spent_allocations: vec![spent_0.clone(), spent_1.clone()],
        new_allocation_shapes: vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id,
                amount: 250_000,
                encrypted_note_commitment: [0xda; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id,
                amount: 750_000,
                encrypted_note_commitment: [0xdb; 32],
            },
        ],
        burn: None,
        lane_id: [0x77; 32],
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: proof_policy(),
    };
    let continuation_report = plan.validate().expect("native continuation report");
    let finalized = plan
        .finalize([0xee; 32], 2, 1)
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
    let asset_id = [0x22; 32];
    let covenant_id = [0x11; 32];
    let total_supply = 1_000_000;
    let spent_0 = allocation(
        [0xaa; 32],
        0,
        covenant_id,
        [0xba; 32],
        1,
        100_000,
        [0xca; 32],
    );
    let spent_1 = allocation(
        [0xab; 32],
        0,
        covenant_id,
        [0xbb; 32],
        1,
        300_000,
        [0xcb; 32],
    );
    let spent_2 = allocation(
        [0xac; 32],
        0,
        covenant_id,
        [0xbc; 32],
        1,
        600_000,
        [0xcc; 32],
    );
    let issue = RgkAssetIssue {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations: vec![spent_0.clone(), spent_1.clone(), spent_2.clone()],
        lane_id: [0x77; 32],
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
        spent_allocations: vec![spent_0.clone(), spent_1.clone(), spent_2.clone()],
        new_allocation_shapes: vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id,
                amount: 450_000,
                encrypted_note_commitment: [0xda; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id,
                amount: 550_000,
                encrypted_note_commitment: [0xdb; 32],
            },
        ],
        burn: None,
        lane_id: [0x77; 32],
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: proof_policy(),
    };
    let continuation_report = plan.validate().expect("native continuation report");
    let finalized = plan
        .finalize([0xee; 32], 2, 1)
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
    let asset_id = [0x22; 32];
    let covenant_id = [0x11; 32];
    let total_supply = 1_000_000;
    let spent_0 = allocation(
        [0xaa; 32],
        0,
        covenant_id,
        [0xba; 32],
        1,
        100_000,
        [0xca; 32],
    );
    let spent_1 = allocation(
        [0xab; 32],
        0,
        covenant_id,
        [0xbb; 32],
        1,
        200_000,
        [0xcb; 32],
    );
    let spent_2 = allocation(
        [0xac; 32],
        0,
        covenant_id,
        [0xbc; 32],
        1,
        300_000,
        [0xcc; 32],
    );
    let spent_3 = allocation(
        [0xad; 32],
        0,
        covenant_id,
        [0xbd; 32],
        1,
        400_000,
        [0xcd; 32],
    );
    let issue = RgkAssetIssue {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations: vec![
            spent_0.clone(),
            spent_1.clone(),
            spent_2.clone(),
            spent_3.clone(),
        ],
        lane_id: [0x77; 32],
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
        spent_allocations: vec![
            spent_0.clone(),
            spent_1.clone(),
            spent_2.clone(),
            spent_3.clone(),
        ],
        new_allocation_shapes: vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id,
                amount: 450_000,
                encrypted_note_commitment: [0xda; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id,
                amount: 550_000,
                encrypted_note_commitment: [0xdb; 32],
            },
        ],
        burn: None,
        lane_id: [0x77; 32],
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: proof_policy(),
    };
    let continuation_report = plan
        .validate_for_production_zk()
        .expect("native production-ZK continuation report");
    let finalized = plan
        .finalize_for_production_zk([0xee; 32], 2, 1)
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
    let asset_id = [0x22; 32];
    let covenant_id = [0x11; 32];
    let total_supply = 1_000_000;
    let spent_0 = allocation(
        [0xaa; 32],
        0,
        covenant_id,
        [0xba; 32],
        1,
        100_000,
        [0xca; 32],
    );
    let spent_1 = allocation(
        [0xab; 32],
        0,
        covenant_id,
        [0xbb; 32],
        1,
        200_000,
        [0xcb; 32],
    );
    let spent_2 = allocation(
        [0xac; 32],
        0,
        covenant_id,
        [0xbc; 32],
        1,
        300_000,
        [0xcc; 32],
    );
    let spent_3 = allocation(
        [0xad; 32],
        0,
        covenant_id,
        [0xbd; 32],
        1,
        400_000,
        [0xcd; 32],
    );
    let issue = RgkAssetIssue {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id: RGK_FUNGIBLE_ASSET_SCHEMA_ID,
        asset_id,
        total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations: vec![
            spent_0.clone(),
            spent_1.clone(),
            spent_2.clone(),
            spent_3.clone(),
        ],
        lane_id: [0x77; 32],
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
        spent_allocations: vec![
            spent_0.clone(),
            spent_1.clone(),
            spent_2.clone(),
            spent_3.clone(),
        ],
        new_allocation_shapes: vec![
            RgkContinuationAllocationShape {
                output_index: 0,
                covenant_id,
                amount: 150_000,
                encrypted_note_commitment: [0xda; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 1,
                covenant_id,
                amount: 250_000,
                encrypted_note_commitment: [0xdb; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 2,
                covenant_id,
                amount: 250_000,
                encrypted_note_commitment: [0xdc; 32],
            },
            RgkContinuationAllocationShape {
                output_index: 3,
                covenant_id,
                amount: 350_000,
                encrypted_note_commitment: [0xdd; 32],
            },
        ],
        burn: None,
        lane_id: [0x77; 32],
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: proof_policy(),
    };
    let continuation_report = plan
        .validate_for_production_zk()
        .expect("native production-ZK continuation report");
    let finalized = plan
        .finalize_for_production_zk([0xee; 32], 2, 1)
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

fn zk_flags() -> EngineFlags {
    EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    }
}

fn receipt_precompile_stack() -> Groth16PrecompileStack {
    let receipt = sample_receipt();
    let receipt_id = receipt_commitment(&receipt);
    let circuit = ReceiptCircuit::from_receipt(&receipt, receipt_id);
    let setup = real_zk::setup(&circuit).expect("Groth16 setup");
    let proof = real_zk::prove(&setup.pk, circuit.clone()).expect("Groth16 proof");
    real_zk::groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("Toccata Groth16 precompile stack")
}

fn semantic_precompile_stack() -> Groth16PrecompileStack {
    let statement = sample_semantic_statement();
    let circuit = SemanticTransitionCircuit::from_statement(&statement);
    let setup = real_zk::setup_semantic(&circuit).expect("semantic Groth16 setup");
    let proof =
        real_zk::prove_semantic(&setup.pk, circuit.clone()).expect("semantic Groth16 proof");
    real_zk::semantic_groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("semantic Toccata Groth16 precompile stack")
}

fn lane_discovery_precompile_stack() -> Groth16PrecompileStack {
    let witness = LaneDiscoveryWitness {
        view_key: [0x41; 32],
        asset_id: [0x22; 32],
    };
    let statement = LaneDiscoveryStatement::from_private(witness.view_key, witness.asset_id, 7);
    let circuit = LaneDiscoveryCircuit::from_statement_and_witness(&statement, witness)
        .expect("lane discovery circuit");
    let setup = real_zk::setup_lane_discovery(&circuit).expect("lane discovery Groth16 setup");
    let proof = real_zk::prove_lane_discovery(&setup.pk, circuit.clone())
        .expect("lane discovery Groth16 proof");
    real_zk::lane_discovery_groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("lane discovery Toccata Groth16 precompile stack")
}

fn lane_graph_discovery_precompile_stack() -> Groth16PrecompileStack {
    let witness = LaneDiscoveryWitness {
        view_key: [0x41; 32],
        asset_id: [0x22; 32],
    };
    let statement =
        LaneGraphDiscoveryStatement::<2>::from_private(witness.view_key, witness.asset_id, [7, 8]);
    let circuit = LaneGraphDiscoveryCircuit::<2>::from_statement_and_witness(&statement, witness)
        .expect("lane graph discovery circuit");
    let setup =
        real_zk::setup_lane_graph_discovery(&circuit).expect("lane graph discovery Groth16 setup");
    let proof = real_zk::prove_lane_graph_discovery(&setup.pk, circuit.clone())
        .expect("lane graph discovery Groth16 proof");
    real_zk::lane_graph_discovery_groth16_precompile_stack(
        &setup.vk,
        &proof,
        &circuit.public_inputs,
    )
    .expect("lane graph discovery Toccata Groth16 precompile stack")
}

fn lane_graph_segment_precompile_stack() -> Groth16PrecompileStack {
    let witness = LaneDiscoveryWitness {
        view_key: [0x41; 32],
        asset_id: [0x22; 32],
    };
    let statement = LaneGraphSegmentStatement::<2>::from_private(
        witness.view_key,
        witness.asset_id,
        private_lane_graph_empty_root(),
        0,
        [7, 8],
    );
    let circuit = LaneGraphSegmentCircuit::<2>::from_statement_and_witness(&statement, witness)
        .expect("lane graph segment circuit");
    let setup =
        real_zk::setup_lane_graph_segment(&circuit).expect("lane graph segment Groth16 setup");
    let proof = real_zk::prove_lane_graph_segment(&setup.pk, circuit.clone())
        .expect("lane graph segment Groth16 proof");
    real_zk::lane_graph_segment_groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("lane graph segment Toccata Groth16 precompile stack")
}

fn allocation_transcript_segment_precompile_stack() -> Groth16PrecompileStack {
    let allocations = vec![
        allocation(
            [0xaa; 32], 0, [0x11; 32], [0xba; 32], 1, 400_000, [0xca; 32],
        ),
        allocation(
            [0xab; 32], 0, [0x11; 32], [0xbb; 32], 1, 600_000, [0xcb; 32],
        ),
    ];
    let statement = AllocationTranscriptSegmentStatement::<2>::from_allocations(
        allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
        RgkAllocationTranscriptSide::Spent,
        0,
        allocations.len() as u64,
        &allocations,
        [0x51; 32],
    )
    .expect("allocation transcript statement");
    let witness =
        AllocationTranscriptSegmentWitness::<2>::from_allocations(&allocations, [0x51; 32])
            .expect("allocation transcript witness");
    let circuit =
        AllocationTranscriptSegmentCircuit::<2>::from_statement_and_witness(&statement, witness)
            .expect("allocation transcript circuit");
    let setup = real_zk::setup_allocation_transcript_segment(&circuit)
        .expect("allocation transcript Groth16 setup");
    let proof = real_zk::prove_allocation_transcript_segment(&setup.pk, circuit.clone())
        .expect("allocation transcript Groth16 proof");
    real_zk::allocation_transcript_segment_groth16_precompile_stack(
        &setup.vk,
        &proof,
        &circuit.public_inputs,
    )
    .expect("allocation transcript Toccata Groth16 precompile stack")
}

fn allocation_conservation_segment_precompile_stack() -> Groth16PrecompileStack {
    let allocations = vec![
        allocation(
            [0xaa; 32], 0, [0x11; 32], [0xba; 32], 1, 400_000, [0xca; 32],
        ),
        allocation(
            [0xab; 32], 0, [0x11; 32], [0xbb; 32], 1, 600_000, [0xcb; 32],
        ),
    ];
    let statement = AllocationConservationSegmentStatement::<2>::from_allocations(
        allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
        RgkAllocationTranscriptSide::Spent,
        0,
        allocations.len() as u64,
        0,
        &allocations,
        [0x51; 32],
        [0x61; 32],
        [0x62; 32],
    )
    .expect("allocation conservation segment statement");
    let witness = AllocationConservationSegmentWitness::<2>::from_allocations(
        0,
        &allocations,
        [0x51; 32],
        [0x61; 32],
        [0x62; 32],
    )
    .expect("allocation conservation segment witness");
    let circuit =
        AllocationConservationSegmentCircuit::<2>::from_statement_and_witness(&statement, witness)
            .expect("allocation conservation segment circuit");
    let setup = real_zk::setup_allocation_conservation_segment(&circuit)
        .expect("allocation conservation segment Groth16 setup");
    let proof = real_zk::prove_allocation_conservation_segment(&setup.pk, circuit.clone())
        .expect("allocation conservation segment Groth16 proof");
    real_zk::allocation_conservation_segment_groth16_precompile_stack(
        &setup.vk,
        &proof,
        &circuit.public_inputs,
    )
    .expect("allocation conservation segment Toccata Groth16 precompile stack")
}

fn allocation_conservation_final_precompile_stack() -> Groth16PrecompileStack {
    let statement =
        AllocationConservationFinalStatement::from_total(2, 2, 1_000_000, [0x62; 32], [0x64; 32])
            .expect("allocation conservation final statement");
    let witness = AllocationConservationFinalWitness::new(1_000_000, [0x62; 32], [0x64; 32])
        .expect("allocation conservation final witness");
    let circuit =
        AllocationConservationFinalCircuit::from_statement_and_witness(&statement, witness)
            .expect("allocation conservation final circuit");
    let setup = real_zk::setup_allocation_conservation_final(&circuit)
        .expect("allocation conservation final Groth16 setup");
    let proof = real_zk::prove_allocation_conservation_final(&setup.pk, circuit.clone())
        .expect("allocation conservation final Groth16 proof");
    real_zk::allocation_conservation_final_groth16_precompile_stack(
        &setup.vk,
        &proof,
        &circuit.public_inputs,
    )
    .expect("allocation conservation final Toccata Groth16 precompile stack")
}

fn allocation_exclusion_segment_pair_precompile_stack() -> Groth16PrecompileStack {
    let spent = vec![allocation(
        [0xaa; 32], 0, [0x11; 32], [0xba; 32], 1, 1_000_000, [0xca; 32],
    )];
    let new = vec![allocation(
        [0xab; 32], 0, [0x11; 32], [0xbb; 32], 2, 1_000_000, [0xcb; 32],
    )];
    let statement = AllocationExclusionSegmentPairStatement::<1, 1>::from_allocations(
        allocation_transcript_empty_root(RgkAllocationTranscriptSide::Spent),
        allocation_transcript_empty_root(RgkAllocationTranscriptSide::New),
        0,
        0,
        spent.len() as u64,
        new.len() as u64,
        &spent,
        &new,
        [0x51; 32],
        [0x52; 32],
    )
    .expect("allocation exclusion statement");
    let witness = AllocationExclusionSegmentPairWitness::<1, 1>::from_allocations(
        &spent, &new, [0x51; 32], [0x52; 32],
    )
    .expect("allocation exclusion witness");
    let circuit = AllocationExclusionSegmentPairCircuit::<1, 1>::from_statement_and_witness(
        &statement, witness,
    )
    .expect("allocation exclusion circuit");
    let setup = real_zk::setup_allocation_exclusion_segment_pair(&circuit)
        .expect("allocation exclusion Groth16 setup");
    let proof = real_zk::prove_allocation_exclusion_segment_pair(&setup.pk, circuit.clone())
        .expect("allocation exclusion Groth16 proof");
    real_zk::allocation_exclusion_segment_pair_groth16_precompile_stack(
        &setup.vk,
        &proof,
        &circuit.public_inputs,
    )
    .expect("allocation exclusion Toccata Groth16 precompile stack")
}

fn allocation_1x1_precompile_stack() -> Groth16PrecompileStack {
    let (statement, witness) = sample_allocation_statement_and_witness();
    let circuit = OneInOneOutAllocationCircuit::from_statement_and_witness(&statement, witness)
        .expect("allocation circuit");
    let setup = real_zk::setup_allocation_1x1(&circuit).expect("allocation Groth16 setup");
    let proof = real_zk::prove_allocation_1x1(&setup.pk, circuit.clone())
        .expect("allocation Groth16 proof");
    real_zk::allocation_1x1_groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("allocation Toccata Groth16 precompile stack")
}

fn allocation_2x2_precompile_stack() -> Groth16PrecompileStack {
    let (statement, witness) = sample_allocation_2x2_statement_and_witness();
    let circuit = TwoInTwoOutAllocationCircuit::from_statement_and_witness(&statement, witness)
        .expect("allocation circuit");
    let setup = real_zk::setup_allocation_2x2(&circuit).expect("allocation Groth16 setup");
    let proof = real_zk::prove_allocation_2x2(&setup.pk, circuit.clone())
        .expect("allocation Groth16 proof");
    real_zk::allocation_2x2_groth16_precompile_stack(&setup.vk, &proof, &circuit.public_inputs)
        .expect("allocation Toccata Groth16 precompile stack")
}

fn allocation_3x2_precompile_stack() -> Groth16PrecompileStack {
    let (statement, witness) = sample_allocation_3x2_statement_and_witness();
    let circuit = SupportedAllocationVectorCircuit::from_statement_and_witness(
        &statement,
        SupportedAllocationVectorWitness::ThreeInTwoOut(witness),
    )
    .expect("allocation circuit");
    let setup = real_zk::setup_supported_allocation(&circuit).expect("allocation Groth16 setup");
    let proof = real_zk::prove_supported_allocation(&setup.pk, circuit.clone())
        .expect("allocation Groth16 proof");
    real_zk::supported_allocation_groth16_precompile_stack(&setup.vk, &proof, &circuit)
        .expect("allocation Toccata Groth16 precompile stack")
}

fn allocation_4x2_precompile_stack() -> Groth16PrecompileStack {
    let (statement, witness) = sample_allocation_4x2_statement_and_witness();
    let circuit = SupportedAllocationVectorCircuit::from_statement_and_witness(
        &statement,
        SupportedAllocationVectorWitness::FourInTwoOut(witness),
    )
    .expect("allocation circuit");
    let setup = real_zk::setup_supported_allocation(&circuit).expect("allocation Groth16 setup");
    let proof = real_zk::prove_supported_allocation(&setup.pk, circuit.clone())
        .expect("allocation Groth16 proof");
    real_zk::supported_allocation_groth16_precompile_stack(&setup.vk, &proof, &circuit)
        .expect("allocation Toccata Groth16 precompile stack")
}

fn allocation_4x4_precompile_stack() -> Groth16PrecompileStack {
    let (statement, witness) = sample_allocation_4x4_statement_and_witness();
    let circuit = SupportedAllocationVectorCircuit::from_statement_and_witness(
        &statement,
        SupportedAllocationVectorWitness::FourInFourOut(witness),
    )
    .expect("allocation circuit");
    let setup = real_zk::setup_supported_allocation(&circuit).expect("allocation Groth16 setup");
    let proof = real_zk::prove_supported_allocation(&setup.pk, circuit.clone())
        .expect("allocation Groth16 proof");
    real_zk::supported_allocation_groth16_precompile_stack(&setup.vk, &proof, &circuit)
        .expect("allocation Toccata Groth16 precompile stack")
}

fn build_groth16_precompile_script(stack: &Groth16PrecompileStack) -> Vec<u8> {
    let mut builder = ScriptBuilder::with_flags(zk_flags());
    for input in stack.public_inputs.iter().rev() {
        builder.add_data(input).expect("public input push");
    }
    builder
        .add_i64(stack.public_input_count() as i64)
        .expect("public input count push")
        .add_data(&stack.proof)
        .expect("proof push")
        .add_data(&stack.verifying_key)
        .expect("verifying key push")
        .add_data(&stack.tag)
        .expect("tag push")
        .add_op(OpZkPrecompile)
        .expect("OpZkPrecompile");
    builder.drain()
}

fn execute_script(script: &[u8]) -> Result<(), String> {
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let mut vm = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
        script,
        &reused_values,
        &sig_cache,
        zk_flags(),
    );
    vm.execute().map_err(|e| format!("{e:?}"))
}

#[test]
fn rgk_receipt_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = receipt_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK Groth16 receipt proof");
    eprintln!(
        "[zk-precompile-vm] public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_semantic_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = semantic_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK semantic Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] semantic public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_lane_discovery_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = lane_discovery_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK lane-discovery Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] lane_discovery public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_lane_graph_discovery_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = lane_graph_discovery_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK lane-graph discovery Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] lane_graph_discovery public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_lane_graph_segment_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = lane_graph_segment_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK lane-graph segment Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] lane_graph_segment public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_transcript_segment_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_transcript_segment_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script)
        .expect("upstream VM accepts RGK allocation transcript segment Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_transcript_segment public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_conservation_segment_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_conservation_segment_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script)
        .expect("upstream VM accepts RGK allocation conservation segment Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_conservation_segment public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_conservation_final_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_conservation_final_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script)
        .expect("upstream VM accepts RGK allocation conservation final Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_conservation_final public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_exclusion_segment_pair_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_exclusion_segment_pair_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script)
        .expect("upstream VM accepts RGK allocation exclusion segment-pair Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_exclusion_segment_pair public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_1x1_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_1x1_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK allocation-vector Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_1x1 public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_2x2_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_2x2_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK 2x2 allocation-vector Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_2x2 public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_3x2_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_3x2_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK 3x2 allocation-vector Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_3x2 public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_4x2_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_4x2_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK 4x2 allocation-vector Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_4x2 public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn rgk_allocation_4x4_groth16_proof_executes_in_upstream_toccata_vm() {
    let stack = allocation_4x4_precompile_stack();
    let script = build_groth16_precompile_script(&stack);

    execute_script(&script).expect("upstream VM accepts RGK 4x4 allocation-vector Groth16 proof");
    eprintln!(
        "[zk-precompile-vm] allocation_4x4 public_inputs={} vk_bytes={} proof_bytes={} script_bytes={}",
        stack.public_input_count(),
        stack.verifying_key.len(),
        stack.proof.len(),
        script.len()
    );
}

#[test]
fn upstream_toccata_vm_rejects_changed_public_input() {
    let mut stack = receipt_precompile_stack();
    stack.public_inputs[0][0] ^= 0x01;
    let script = build_groth16_precompile_script(&stack);

    let err = execute_script(&script)
        .expect_err("upstream VM rejects a proof under changed public inputs");
    assert!(
        err.contains("Groth16 verification failed"),
        "unexpected txscript error: {err}"
    );
}
