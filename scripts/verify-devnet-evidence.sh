#!/usr/bin/env bash
# RGK: verify that a devnet evidence report contains the required production
# readiness markers. The checks are deliberately textual so they can be run
# against archived evidence without replaying the chain.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_DEVNET_EVIDENCE_REPORT:-${ROOT}/target/rgk-devnet-evidence/latest.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-devnet-evidence] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-devnet-evidence] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

require_regex "evidence header" '^RGK devnet evidence$'
require_regex "UTC timestamp" '^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_regex "devnet URL" '^url=ws://'
require_regex "Toccata activation override" '^override_params_json=.*"toccata_activation":0'

require_regex "public testnet staging preflight" '^RGK public testnet staging preflight$'
require_regex "public testnet preflight network" '^network=testnet-12$'
require_regex "public testnet preflight chain id" '^chain_id=KaspaTestnet$'
require_regex "public testnet preflight address" '^address=kaspatest:[a-z0-9]+$'
require_regex "public testnet preflight funding status" '^funding_status=external-funding-required$'
require_regex "public testnet preflight non-coinbase funding" '^required_non_coinbase_utxo=true$'
require_regex "public testnet preflight utxo index" '^required_utxo_index=true$'
require_regex "public testnet preflight confirmation depth" '^required_confirmation_depth=1$'
require_regex "public testnet preflight real-zk feature" '^required_real_zk_feature=true$'
require_regex "public testnet preflight persistent indexer feature" '^required_persistent_indexer_feature=true$'
require_regex "public testnet preflight no local mining" '^required_local_mining=false$'
require_regex "public testnet preflight live covenant test" '^required_live_test=live_toccata_full_covenant_lifecycle$'
require_regex "public testnet preflight id" '^preflight_id=0x[0-9a-f]{64}$'
require_regex "public testnet preflight verifier" '^\[verify-testnet-staging-preflight\] ok: .*/target/rgk-testnet-staging-evidence/preflight\.txt$'
require_regex "public testnet preflight test pass" 'test testnet_staging_preflight_manifest_is_stable \.\.\. ok'

require_regex "node identity" 'live-devnet: server_version=.* network_id=devnet .*has_utxo_index=true'
require_regex "persistent scan cursor initialisation" 'live-devnet: scan cursor initialised chain=KaspaDevnet'
require_regex "public lineage resolver test pass" 'test tests::resolve_public_lineage_returns_only_public_lanes_for_asset \.\.\. ok'

require_regex "policy migration fixture" '^RGK policy migration recovery$'
require_regex "policy migration proof commitment" '  migration:       0x[0-9a-f]{64}'
require_regex "policy migration resolver recovery" '  resolver:        NativeTransitionedValid'
require_regex "policy migration test pass" 'test policy_migration_recovery_fixture_survives_reopen \.\.\. ok'
require_regex "advanced covenant policy unique commitments" 'test tests::advanced_covenant_policy_shapes_have_unique_commitments \.\.\. ok'
require_regex "advanced covenant policy fail-closed validation" 'test tests::advanced_covenant_policy_shapes_fail_closed_on_missing_material \.\.\. ok'
require_regex "advanced covenant policy commitment binding" 'test tests::advanced_covenant_policy_commitment_binds_flow_and_material \.\.\. ok'
require_regex "advanced covenant execution all flows" 'test tests::advanced_covenant_execution_plans_validate_all_flows \.\.\. ok'
require_regex "advanced covenant execution fail-closed validation" 'test tests::advanced_covenant_execution_enforces_payment_and_timelock_rules \.\.\. ok'
require_regex "advanced covenant execution commitment binding" 'test tests::advanced_covenant_execution_commitment_binds_policy_and_evidence \.\.\. ok'
require_regex "advanced covenant execution record handoff" 'test tests::advanced_covenant_execution_record_round_trips_and_rejects_tamper \.\.\. ok'
require_regex "native burn transition test pass" 'test native::tests::native_transition_rejects_supply_inflation_and_deflation \.\.\. ok'
require_regex "native burn continuation test pass" 'test native::tests::continuation_accepts_explicit_burn_for_supported_production_zk_shape \.\.\. ok'
require_regex "native burn allocation Groth16 proof" 'test real_zk::tests::prove_then_verify_allocation_1x1_burn_transition \.\.\. ok'
require_regex "production-ZK burn proof" 'native burn: production-ZK burn proof supported for shape=1x1'
require_regex "fungible fanout 2x2 test pass" 'test native::tests::fungible_multi_output_fanout_2x2_is_production_zk_supported \.\.\. ok'
require_regex "fungible merge 3x2 test pass" 'test native::tests::fungible_multi_input_merge_3x2_is_production_zk_supported \.\.\. ok'
require_regex "fungible batch 4x4 test pass" 'test native::tests::fungible_batch_transfer_4x4_is_production_zk_supported \.\.\. ok'
require_regex "production allocation strategy fixed and segmented paths" 'test native::tests::production_allocation_strategy_selects_fixed_and_segmented_paths \.\.\. ok'
require_regex "segmented allocation strategy fail-closed validation" 'test native::tests::segmented_allocation_strategy_requires_conserving_nonempty_sides \.\.\. ok'
require_regex "production allocation strategy commitment binding" 'test native::tests::production_allocation_strategy_commitment_binds_counts_and_segment_grid \.\.\. ok'
require_regex "metadata owner digest test pass" 'test native::tests::native_issue_digest_binds_metadata_and_owner_commitments \.\.\. ok'
require_regex "ownership handoff test pass" 'test native::tests::native_transition_binds_authorized_ownership_handoff \.\.\. ok'
require_regex "ownership auth rejection test pass" 'test native::tests::native_transition_rejects_ownership_handoff_without_authorization \.\.\. ok'
require_regex "owner descriptor derivation test pass" 'test native::tests::owner_descriptor_commitments_bind_owner_control_shape \.\.\. ok'
require_regex "owner key rotation test pass" 'test native::tests::native_transition_binds_owner_key_rotation_descriptor \.\.\. ok'
require_regex "NFT collection policy test pass" 'test native::tests::nft_collection_policy_derives_fixed_supply_token_ids \.\.\. ok'
require_regex "NFT mint metadata test pass" 'test native::tests::nft_mint_issue_binds_collection_template_and_metadata \.\.\. ok'
require_regex "NFT single-token transfer test pass" 'test native::tests::nft_single_token_transfer_preserves_metadata_and_owner_handoff \.\.\. ok'
require_regex "NFT marketplace sale test pass" 'test native::tests::nft_marketplace_sale_binds_payment_royalty_and_owner_handoff \.\.\. ok'
require_regex "NFT terminal burn lifecycle test pass" 'test native::tests::nft_burn_lifecycle_closes_token_without_successor_allocation \.\.\. ok'
require_regex "NFT terminal burn allocation Groth16 proof" 'test real_zk::tests::prove_then_verify_allocation_1x0_terminal_burn_transition \.\.\. ok'
require_regex "production-ZK NFT terminal burn proof" 'native NFT burn: production-ZK terminal burn proof supported for shape=1x0'
require_regex "fungible merge 4x2 test pass" 'test native::tests::fungible_four_input_merge_4x2_is_production_zk_supported \.\.\. ok'
require_regex "4x2 allocation-vector VM proof" 'test rgk_allocation_4x2_groth16_proof_executes_in_upstream_toccata_vm \.\.\. ok'
require_regex "production-ZK 4x2 proof" 'native allocation: production-ZK proof supported for shape=4x2'
require_regex "4x4 allocation-vector VM proof" 'test rgk_allocation_4x4_groth16_proof_executes_in_upstream_toccata_vm \.\.\. ok'
require_regex "production-ZK 4x4 proof" 'native allocation: production-ZK proof supported for shape=4x4'

require_regex "covenant funding accepted" 'live: covenant tx ACCEPTED by node'
require_regex "native issue digest" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*privacy_policy=PrivateLane .*lane_id=0x[0-9a-f]{64}'
require_regex "native proof policy commitment" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*policy_commitment=0x[0-9a-f]{64}'
require_regex "native metadata commitment" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*metadata_commitment=0x[0-9a-f]{64}'
require_regex "native owner commitment" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*owner_commitment=0x[0-9a-f]{64}'
require_regex "ZK covenant spend" 'live: ZK covenant spend enabled, public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+'
require_regex "covenant spend accepted" 'live: P2SH covenant spend ACCEPTED by node'
require_regex "continuation output confirmed" 'live: continuation covenant output confirmed at DAA score [0-9]+'
require_regex "production-ZK shape guard" 'live: native production-ZK allocation guard accepted shape=1x1 spent_allocations=1 new_allocations=1'
require_regex "native transition digest" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*privacy_policy=PrivateLane .*lane_id=0x[0-9a-f]{64}'
require_regex "native transition policy commitment" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*policy_commitment=0x[0-9a-f]{64}'
require_regex "native transition metadata commitment" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*metadata_commitment=0x[0-9a-f]{64}'
require_regex "native transition owner commitments" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*previous_owner_commitment=0x[0-9a-f]{64} new_owner_commitment=0x[0-9a-f]{64} ownership_authorization_commitment=0x[0-9a-f]{64}'
require_regex "semantic transition policy commitment" 'live: semantic RGK transition statement public_inputs=[0-9]+ continuation_shape_root=0x[0-9a-f]{64} policy_commitment=0x[0-9a-f]{64}'
require_regex "semantic transition metadata commitment" 'live: semantic RGK transition statement public_inputs=[0-9]+ .*metadata_commitment=0x[0-9a-f]{64}'
require_regex "semantic transition owner commitments" 'live: semantic RGK transition statement public_inputs=[0-9]+ .*previous_owner_commitment=0x[0-9a-f]{64} new_owner_commitment=0x[0-9a-f]{64} ownership_authorization_commitment=0x[0-9a-f]{64}'
require_regex "semantic Groth16 proof" 'live: semantic Groth16 proof verified public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+'
require_regex "allocation-vector Groth16 proof" 'live: supported allocation-vector Groth16 proof verified shape=1x1 public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+'
require_regex "allocation transcript segment Groth16 proof" 'live: allocation transcript segment Groth16 proof verified sides=2 segments=2 allocations=2 public_inputs_each=[0-9]+ vk_bytes=[0-9]+ proof_bytes_each=[0-9]+ spent_root=0x[0-9a-f]{64} new_root=0x[0-9a-f]{64} spent_amount_commitment=0x[0-9a-f]{64} new_amount_commitment=0x[0-9a-f]{64}'
require_regex "allocation conservation Groth16 chain" 'live: allocation conservation Groth16 chain verified sides=2 segments=2 allocations=2 public_inputs_each=[0-9]+ final_public_inputs=[0-9]+ segment_vk_bytes=[0-9]+ segment_proof_bytes_each=[0-9]+ final_vk_bytes=[0-9]+ final_proof_bytes=[0-9]+ spent_total_commitment=0x[0-9a-f]{64} new_total_commitment=0x[0-9a-f]{64}'
require_regex "allocation exclusion segment-pair Groth16 proof" 'live: allocation exclusion segment-pair Groth16 proof verified spent_segments=1 new_segments=1 pair_grid=1 public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+ spent_root=0x[0-9a-f]{64} new_root=0x[0-9a-f]{64} spent_amount_commitment=0x[0-9a-f]{64} new_amount_commitment=0x[0-9a-f]{64}'
require_regex "allocation audit bundle" 'live: allocation audit bundle verified spent_segments=1 new_segments=1 exclusion_cells=1 spent_final_root=0x[0-9a-f]{64} new_final_root=0x[0-9a-f]{64} spent_total_commitment=0x[0-9a-f]{64} new_total_commitment=0x[0-9a-f]{64}'
require_regex "allocation audit certificate" 'live: allocation audit certificate verified certificate_id=0x[0-9a-f]{64} proof_cells=6 vk_bytes_total=[0-9]+ proof_bytes_total=[0-9]+ canonical_bytes=[0-9]+'
require_regex "self-contained allocation audit certificate" 'live: allocation audit certificate self-contained verified certificate_id=0x[0-9a-f]{64} proof_cells=6 canonical_bytes=[0-9]+'
require_regex "indexed allocation audit certificate" 'live: allocation audit certificate indexed certificate_id=0x[0-9a-f]{64} canonical_bytes=[0-9]+'
require_regex "persistent allocation audit certificate recovery" 'live: persistent allocation audit certificate recovered certificate_id=0x[0-9a-f]{64} canonical_bytes=[0-9]+'
require_regex "private lane scan tag" 'live: registered private lane for view-key discovery .*scan_tag=0x[0-9a-f]{64} privacy_policy=PrivateLane'
require_regex "lane-discovery Groth16 proof" 'live: lane-discovery Groth16 proof verified public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+ lane_id=0x[0-9a-f]{64} scan_tag=0x[0-9a-f]{64}'
require_regex "lane-graph Groth16 proof" 'live: lane-graph Groth16 proof verified nodes=2 public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+ graph_root=0x[0-9a-f]{64} current_lane=0x[0-9a-f]{64} next_scan_tag=0x[0-9a-f]{64}'
require_regex "segmented lane-graph Groth16 proof chain" 'live: segmented lane-graph Groth16 proof chain verified segments=2 nodes=4 public_inputs_each=[0-9]+ vk_bytes=[0-9]+ proof_bytes_each=[0-9]+ start_root=0x[0-9a-f]{64} final_root=0x[0-9a-f]{64} current_lane=0x[0-9a-f]{64} final_scan_tag=0x[0-9a-f]{64}'
require_regex "resolver classification" 'live: resolver state = NativeTransitionedValid'
require_regex "phase-2 resolver state digest" 'live: resolver carried phase-2 native state digest = 0x[0-9a-f]{64}'
require_regex "view-key resolver classification" 'live: view-key lane resolver classified as NativeTransitionedValid'
require_regex "live policy migration recovery" 'live: policy migration proof recovered after Sled reopen \(previous_policy=verifier-only new_policy=zk-or-verifier migration=0x[0-9a-f]{64} state_digest=0x[0-9a-f]{64} resolver=NativeTransitionedValid\)'
require_regex "persistent live indexer recovery" 'live: persistent indexer recovered covenant after resolver indexing'

require_regex "scanner initial tick" 'tick initialised=true added_chain_blocks=[0-9]+ observed_spends=[0-9]+ start_daa=[0-9]+ end_daa=[0-9]+ end_hash_prefix=[0-9a-f]+'
require_regex "scanner reload tick" 'tick initialised=false added_chain_blocks=[0-9]+ observed_spends=[0-9]+ start_daa=[0-9]+ end_daa=[0-9]+ end_hash_prefix=[0-9a-f]+'
require_regex "Silverscript artifact verifier" '^\[verify-silverscript-artifacts\] ok: .*/examples/silverscript/artifacts/manifest\.tsv rows=[0-9]+ compiler=d25bd3427a093c17327ca3d6b9e1aa5f7688c863'
require_regex "example matrix verifier" '^\[verify-example-matrix\] ok: .*/examples/contract-matrix\.tsv rows=13'

echo "[verify-devnet-evidence] ok: ${REPORT}"
