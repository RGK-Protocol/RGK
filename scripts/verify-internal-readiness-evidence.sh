#!/usr/bin/env bash
# RGK: verify that the local internal readiness report contains all launch
# checklist gates that are not public-network dependent.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_INTERNAL_READINESS_REPORT:-${ROOT}/target/rgk-internal-readiness/latest.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-internal-readiness-evidence] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-internal-readiness-evidence] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

if grep -Eq '^[a-z0-9_]+=(failed|blocked)$' "${REPORT}"; then
    echo "[verify-internal-readiness-evidence] report contains failed or blocked gate" >&2
    grep -En '^[a-z0-9_]+=(failed|blocked)$' "${REPORT}" >&2
    exit 1
fi

require_regex "evidence header" '^RGK internal readiness evidence$'
require_regex "UTC timestamp" '^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_regex "workspace path" '^workspace=/.+'
require_regex "rustc version" '^rustc_version=rustc [0-9]+\.[0-9]+\.[0-9]+'
require_regex "cargo version" '^cargo_version=cargo [0-9]+\.[0-9]+\.[0-9]+'
require_regex "cargo fmt" '^cargo_fmt=ok$'
require_regex "native terminology gate" '^native_terminology_gate=ok$'
require_regex "native terminology verifier" '^\[verify-native-terminology\] ok$'
require_regex "Silverscript artifacts" '^silverscript_artifacts=ok$'
require_regex "Silverscript verifier" '^\[verify-silverscript-artifacts\] ok: .*/examples/silverscript/artifacts/manifest\.tsv rows=[0-9]+ compiler=d25bd3427a093c17327ca3d6b9e1aa5f7688c863$'
require_regex "examples matrix" '^examples_matrix=ok$'
require_regex "examples matrix verifier" '^\[verify-example-matrix\] ok: .*/examples/contract-matrix\.tsv rows=[0-9]+$'
require_regex "native grammar default tests" '^native_grammar_default_tests=ok$'
require_regex "native grammar no-default tests" '^native_grammar_no_default_tests=ok$'
require_regex "Toccata tx tests" '^toccata_tx_tests=ok$'
require_regex "live Toccata tx config tests" '^live_toccata_tx_config_tests=ok$'
require_regex "covenant tests" '^covenant_tests=ok$'
require_regex "covenant policy VM tests" '^covenant_policy_vm_tests=ok$'
require_regex "covenant policy fanout VM pass" 'test covenant_spec_policy_script_accepts_fanout_with_explicit_change_output \.\.\. ok'
require_regex "covenant policy missing output VM reject" 'test covenant_spec_policy_script_rejects_missing_declared_continuation_output \.\.\. ok'
require_regex "covenant shared merge VM pass" 'test covenant_shared_policy_script_accepts_two_input_merge_with_change_output \.\.\. ok'
require_regex "covenant shared batch VM pass" 'test covenant_shared_policy_script_accepts_two_input_two_output_batch_with_change \.\.\. ok'
require_regex "covenant shared missing output VM reject" 'test covenant_shared_policy_script_rejects_missing_shared_covenant_output \.\.\. ok'
require_regex "R0 Succinct VM tests" '^r0_succinct_vm_tests=ok$'
require_regex "R0 Succinct fixture VM pass" 'test r0_succinct_fixture_executes_in_upstream_toccata_vm \.\.\. ok'
require_regex "R0 Succinct changed journal VM reject" 'test r0_succinct_fixture_rejects_changed_journal \.\.\. ok'
require_regex "privacy observer evidence" '^privacy_observer_evidence=ok$'
require_regex "privacy observer verifier" '^\[verify-privacy-observer-evidence\] ok: .+'
require_regex "Toccata covenant clippy" '^toccata_covenant_clippy=ok$'
require_regex "asset clippy all-features" '^asset_clippy_all_features=ok$'
require_regex "e2e live real-zk clippy" '^e2e_clippy_live_real_zk=ok$'
require_regex "workspace no-default tests" '^workspace_no_default_tests=ok$'
require_regex "e2e lib all-features tests" '^e2e_lib_all_features_tests=ok$'
require_regex "workspace all-features tests" '^workspace_all_features_tests=ok$'
require_regex "rustdoc all-features" '^rustdoc_all_features=ok$'

echo "[verify-internal-readiness-evidence] ok: ${REPORT}"
