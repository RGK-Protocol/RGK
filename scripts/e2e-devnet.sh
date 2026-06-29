#!/usr/bin/env bash
# RGK: local devnet evidence harness.
#
# This starts or targets a Toccata-active local kaspad devnet, verifies node
# identity over wRPC, runs the full live ZK covenant lifecycle under the
# KaspaDevnet domain, initialises a persistent RGK scan cursor, and records the
# evidence under target/rgk-devnet-evidence/.
#
# Usage:
#   ./scripts/e2e-devnet.sh                  # requires a running devnet node
#   ./scripts/e2e-devnet.sh --start-kaspa    # start local devnet first
#   ./scripts/e2e-devnet.sh --stop-kaspa     # stop the backgrounded devnet

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

DEFAULT_URL="ws://127.0.0.1:19111/v2/kaspa/devnet/no-tls/wrpc/borsh"
DEVNET_URL="${RGK_LIVE_DEVNET_URL:-${DEFAULT_URL}}"
EVIDENCE_DIR="${RGK_DEVNET_EVIDENCE_DIR:-${ROOT}/target/rgk-devnet-evidence}"
SYNC_DB="${RGK_DEVNET_SYNC_DB:-${EVIDENCE_DIR}/sled}"

while [ $# -gt 0 ]; do
    case "$1" in
        --start-kaspa)
            "${ROOT}/scripts/run-kaspa-devnet.sh" --background
            shift
            ;;
        --stop-kaspa)
            DATADIR="${RGK_KASPA_DEVNET_DATADIR:-${ROOT}/.rgk-devnet}"
            PID_FILE="${DATADIR}/kaspad.pid"
            if [ -f "${PID_FILE}" ]; then
                kill "$(cat "${PID_FILE}")" || true
                rm -f "${PID_FILE}"
                echo "[e2e-devnet] stopped"
            fi
            exit 0
            ;;
        *)
            echo "[e2e-devnet] unknown argument: $1"
            exit 2
            ;;
    esac
done

LIVE_HOST="$(printf '%s\n' "${DEVNET_URL}" | sed -E 's#^[^:]+://([^:/]+).*#\1#')"
LIVE_PORT="$(printf '%s\n' "${DEVNET_URL}" | sed -E 's#^[^:]+://[^:/]+:([0-9]+).*#\1#')"
if [ "${LIVE_HOST}" = "${DEVNET_URL}" ]; then
    LIVE_HOST="127.0.0.1"
fi
if [ "${LIVE_PORT}" = "${DEVNET_URL}" ]; then
    LIVE_PORT="19111"
fi
if ! (echo > "/dev/tcp/${LIVE_HOST}/${LIVE_PORT}") >/dev/null 2>&1; then
    echo "[e2e-devnet] devnet node unreachable at ${LIVE_HOST}:${LIVE_PORT}"
    echo "[e2e-devnet] start it with: ./scripts/e2e-devnet.sh --start-kaspa"
    exit 3
fi

mkdir -p "${EVIDENCE_DIR}"
rm -rf "${SYNC_DB}"

REPORT="${EVIDENCE_DIR}/latest.txt"
{
    echo "RGK devnet evidence"
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "url=${DEVNET_URL}"
    echo "override_params=${ROOT}/scripts/devnet-toccata-overrides.json"
    echo "override_params_json=$(tr -d '\n ' < "${ROOT}/scripts/devnet-toccata-overrides.json")"
    echo
} > "${REPORT}"

export RGK_LIVE_DEVNET_URL="${DEVNET_URL}"

echo "[e2e-devnet] live devnet RPC: ${RGK_LIVE_DEVNET_URL}"
echo "[e2e-devnet] running public testnet staging preflight"
bash "${ROOT}/scripts/e2e-testnet-staging.sh" --preflight testnet-12 \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-e2e --features live-kaspa-wrpc --lib testnet_staging_preflight_manifest_is_stable -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
echo "[e2e-devnet] running live_devnet test"
cargo test -p rgk-e2e --features live-kaspa-wrpc,persistent-indexer --test live_devnet -- --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running public-lineage resolver fixture"
cargo test -p rgk-resolver tests::resolve_public_lineage_returns_only_public_lanes_for_asset -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running policy migration recovery fixture"
cargo test -p rgk-e2e --features persistent-indexer --lib policy_migration_recovery_fixture_survives_reopen -- --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running advanced covenant policy fixtures"
cargo test -p rgk-covenant tests::advanced_covenant_policy_shapes_have_unique_commitments -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-covenant tests::advanced_covenant_policy_shapes_fail_closed_on_missing_material -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-covenant tests::advanced_covenant_policy_commitment_binds_flow_and_material -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-covenant tests::advanced_covenant_execution_plans_validate_all_flows -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-covenant tests::advanced_covenant_execution_enforces_payment_and_timelock_rules -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-covenant tests::advanced_covenant_execution_commitment_binds_policy_and_evidence -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-covenant tests::advanced_covenant_execution_record_round_trips_and_rejects_tamper -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running native burn lifecycle fixtures"
cargo test -p rgk-asset native::tests::native_transition_rejects_supply_inflation_and_deflation -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::continuation_accepts_explicit_burn_for_supported_production_zk_shape -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-zk --features real-zk real_zk::tests::prove_then_verify_allocation_1x1_burn_transition -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
echo "native burn: production-ZK burn proof supported for shape=1x1" | tee -a "${REPORT}"

echo "[e2e-devnet] running metadata and ownership guardrail fixtures"
cargo test -p rgk-asset native::tests::native_issue_digest_binds_metadata_and_owner_commitments -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::native_transition_binds_authorized_ownership_handoff -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::native_transition_rejects_ownership_handoff_without_authorization -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::owner_descriptor_commitments_bind_owner_control_shape -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::native_transition_binds_owner_key_rotation_descriptor -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running NFT lane-policy fixtures"
cargo test -p rgk-asset native::tests::nft_collection_policy_derives_fixed_supply_token_ids -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::nft_mint_issue_binds_collection_template_and_metadata -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::nft_single_token_transfer_preserves_metadata_and_owner_handoff -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::nft_marketplace_sale_binds_payment_royalty_and_owner_handoff -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::nft_burn_lifecycle_closes_token_without_successor_allocation -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-zk --features real-zk real_zk::tests::prove_then_verify_allocation_1x0_terminal_burn_transition -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
echo "native NFT burn: production-ZK terminal burn proof supported for shape=1x0" | tee -a "${REPORT}"

echo "[e2e-devnet] running fungible transfer-shape fixtures"
cargo test -p rgk-asset native::tests::fungible_multi_output_fanout_2x2_is_production_zk_supported -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::fungible_multi_input_merge_3x2_is_production_zk_supported -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::fungible_four_input_merge_4x2_is_production_zk_supported -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::fungible_batch_transfer_4x4_is_production_zk_supported -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running production allocation strategy fixtures"
cargo test -p rgk-asset native::tests::production_allocation_strategy_selects_fixed_and_segmented_paths -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::segmented_allocation_strategy_requires_conserving_nonempty_sides -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
cargo test -p rgk-asset native::tests::production_allocation_strategy_commitment_binds_counts_and_segment_grid -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running 4x2 allocation-vector VM fixture"
cargo test -p rgk-e2e --features live-kaspa-wrpc,real-zk --test zk_precompile_vm rgk_allocation_4x2_groth16_proof_executes_in_upstream_toccata_vm -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
echo "native allocation: production-ZK proof supported for shape=4x2" | tee -a "${REPORT}"

echo "[e2e-devnet] running 4x4 allocation-vector VM fixture"
cargo test -p rgk-e2e --features live-kaspa-wrpc,real-zk --test zk_precompile_vm rgk_allocation_4x4_groth16_proof_executes_in_upstream_toccata_vm -- --exact --nocapture \
    2>&1 | tee -a "${REPORT}"
echo "native allocation: production-ZK proof supported for shape=4x4" | tee -a "${REPORT}"

echo "[e2e-devnet] running full covenant lifecycle on devnet"
RGK_LIVE_KASPA_URL="${DEVNET_URL}" \
RGK_LIVE_KASPA_NETWORK="devnet" \
cargo test -p rgk-e2e --features live-kaspa-wrpc,persistent-indexer,real-zk --test live_covenant -- --nocapture \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running rgk-sync scanner smoke (initialise cursor)"
cargo run -p rgk-sync --features daemon --bin rgk-sync -- \
    --url "${DEVNET_URL}" \
    --network devnet \
    --db "${SYNC_DB}" \
    --once \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] running rgk-sync scanner smoke (reload cursor)"
cargo run -p rgk-sync --features daemon --bin rgk-sync -- \
    --url "${DEVNET_URL}" \
    --network devnet \
    --db "${SYNC_DB}" \
    --once \
    2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] verifying examples coverage matrix"
bash "${ROOT}/scripts/verify-example-matrix.sh" 2>&1 | tee -a "${REPORT}"

"${ROOT}/scripts/verify-devnet-evidence.sh" "${REPORT}" 2>&1 | tee -a "${REPORT}"

echo "[e2e-devnet] evidence: ${REPORT}"
