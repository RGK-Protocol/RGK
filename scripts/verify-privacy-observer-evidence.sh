#!/usr/bin/env bash
# RGK: verify the local private-lane public-observer evidence report.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_PRIVACY_OBSERVER_REPORT:-${ROOT}/target/rgk-privacy-observer-evidence/latest.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-privacy-observer-evidence] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-privacy-observer-evidence] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

require_regex "evidence header" '^RGK privacy observer evidence$'
require_regex "UTC timestamp" '^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_regex "workspace path" '^workspace=/.+'
require_regex "rustc version" '^rustc_version=rustc [0-9]+\.[0-9]+\.[0-9]+'
require_regex "cargo version" '^cargo_version=cargo [0-9]+\.[0-9]+\.[0-9]+'
require_regex "observer boundary test pass" '^test native::tests::private_lane_public_observer_boundary_is_commitment_only \.\.\. ok$'
require_regex "private lane discovery test pass" '^test native::tests::private_lane_discovery_and_tags_behave_as_commitments \.\.\. ok$'
require_regex "amount commitment test pass" '^test native::tests::allocation_transcript_amount_commitment_hides_bound_amount \.\.\. ok$'
require_regex "nullifier boundary test pass" '^test native::tests::nullifier_is_stable_but_unlinked_to_lane_id \.\.\. ok$'
require_regex "privacy policy default test pass" '^test native::tests::public_and_private_lane_policies_have_different_visibility \.\.\. ok$'
require_regex "view-key resolver test pass" '^test tests::resolve_by_view_key_discovers_only_matching_private_lane \.\.\. ok$'
require_regex "observer default" '^privacy_observer_default=PrivateLane$'
require_regex "observer learns boundary" '^privacy_observer_learns=blinded_lane_ids,rotating_scan_tags,nullifiers,opaque_commitments$'
require_regex "observer does not learn boundary" '^privacy_observer_does_not_learn=asset_id,owner,amount,lane_graph,plaintext_proof_policy$'
require_regex "view key required" '^privacy_observer_view_key_required=true$'
require_regex "public lineage opt-in" '^privacy_observer_public_lineage_opt_in=true$'

echo "[verify-privacy-observer-evidence] ok: ${REPORT}"
