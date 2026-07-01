#!/usr/bin/env bash
# RGK: produce machine-checkable local evidence for the private-lane public
# observer boundary. This is a local protocol gate and has no public-network
# dependency.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_PRIVACY_OBSERVER_REPORT:-${ROOT}/target/rgk-privacy-observer-evidence/latest.txt}}"

mkdir -p "$(dirname "${REPORT}")"
: >"${REPORT}"

emit() {
    printf '%s=%s\n' "$1" "$2" | tee -a "${REPORT}"
}

run_step() {
    local key="$1"
    shift
    printf '[privacy-observer] %s:' "${key}" | tee -a "${REPORT}"
    printf ' %q' "$@" | tee -a "${REPORT}"
    printf '\n' | tee -a "${REPORT}"
    "$@" 2>&1 | tee -a "${REPORT}"
}

echo "RGK privacy observer evidence" | tee -a "${REPORT}"
emit "timestamp_utc" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
emit "workspace" "${ROOT}"
emit "rustc_version" "$(rustc --version)"
emit "cargo_version" "$(cargo --version)"

cd "${ROOT}"

run_step "observer_boundary" \
    cargo test -p rgk-asset \
    native::tests::private_lane_public_observer_boundary_is_commitment_only \
    -- --exact --nocapture
run_step "private_lane_discovery" \
    cargo test -p rgk-asset \
    native::tests::private_lane_discovery_and_tags_behave_as_commitments \
    -- --exact --nocapture
run_step "amount_commitment" \
    cargo test -p rgk-asset \
    native::tests::allocation_transcript_amount_commitment_hides_bound_amount \
    -- --exact --nocapture
run_step "nullifier_boundary" \
    cargo test -p rgk-asset \
    native::tests::nullifier_is_stable_but_unlinked_to_lane_id \
    -- --exact --nocapture
run_step "privacy_policy_default" \
    cargo test -p rgk-asset \
    native::tests::public_and_private_lane_policies_have_different_visibility \
    -- --exact --nocapture
run_step "view_key_resolver" \
    cargo test -p rgk-resolver \
    tests::resolve_by_view_key_discovers_only_matching_private_lane \
    -- --exact --nocapture

emit "privacy_observer_default" "PrivateLane"
emit "privacy_observer_learns" "blinded_lane_ids,rotating_scan_tags,nullifiers,opaque_commitments"
emit "privacy_observer_does_not_learn" "asset_id,owner,amount,lane_graph,plaintext_proof_policy"
emit "privacy_observer_view_key_required" "true"
emit "privacy_observer_public_lineage_opt_in" "true"

bash "${ROOT}/scripts/verify-privacy-observer-evidence.sh" "${REPORT}" | tee -a "${REPORT}"
echo "[privacy-observer] evidence: ${REPORT}" | tee -a "${REPORT}"
