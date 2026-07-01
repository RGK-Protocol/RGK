#!/usr/bin/env bash
# RGK: produce machine-checkable local internal readiness evidence. This is
# intentionally separate from the launch audit because several gates are
# expensive and may require a local live simnet for workspace --all-features.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_INTERNAL_READINESS_REPORT:-${ROOT}/target/rgk-internal-readiness/latest.txt}}"

mkdir -p "$(dirname "${REPORT}")"
: >"${REPORT}"

emit() {
    printf '%s=%s\n' "$1" "$2" | tee -a "${REPORT}"
}

run_step() {
    local key="$1"
    shift
    printf '[internal-readiness] %s:' "${key}" | tee -a "${REPORT}"
    printf ' %q' "$@" | tee -a "${REPORT}"
    printf '\n' | tee -a "${REPORT}"
    if "$@" 2>&1 | tee -a "${REPORT}"; then
        emit "${key}" "ok"
        return 0
    fi
    emit "${key}" "failed"
    return 1
}

echo "RGK internal readiness evidence" | tee -a "${REPORT}"
emit "timestamp_utc" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
emit "workspace" "${ROOT}"
emit "rustc_version" "$(rustc --version)"
emit "cargo_version" "$(cargo --version)"

cd "${ROOT}"

run_step "cargo_fmt" cargo fmt --all -- --check
run_step "native_terminology_gate" bash "${ROOT}/scripts/verify-native-terminology.sh"
run_step "silverscript_artifacts" bash "${ROOT}/scripts/verify-silverscript-artifacts.sh"
run_step "examples_matrix" bash "${ROOT}/scripts/verify-example-matrix.sh"
run_step "native_grammar_default_tests" cargo test -p rgk-asset
run_step "native_grammar_no_default_tests" cargo test -p rgk-asset --no-default-features
run_step "toccata_tx_tests" cargo test -p rgk-tx
run_step "live_toccata_tx_config_tests" cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant live_toccata_tx_config -- --nocapture
run_step "covenant_tests" cargo test -p rgk-covenant
run_step "covenant_policy_vm_tests" cargo test -p rgk-e2e --features live-kaspa-wrpc --test covenant_script_vm -- --nocapture
run_step "r0_succinct_vm_tests" cargo test -p rgk-e2e --features live-kaspa-wrpc,real-zk --test zk_precompile_vm r0_succinct -- --nocapture
run_step "privacy_observer_evidence" bash "${ROOT}/scripts/e2e-privacy-observer.sh"
run_step "toccata_covenant_clippy" cargo clippy -p rgk-tx -p rgk-covenant --all-targets -- -D warnings
run_step "asset_clippy_all_features" cargo clippy -p rgk-asset --all-targets --all-features -- -D warnings
run_step "e2e_clippy_live_real_zk" cargo clippy -p rgk-e2e --all-targets --features live-kaspa-wrpc,persistent-indexer,real-zk -- -D warnings
run_step "workspace_no_default_tests" cargo test --workspace --no-default-features
run_step "e2e_lib_all_features_tests" cargo test -p rgk-e2e --all-features --lib
run_step "workspace_all_features_tests" cargo test --workspace --all-features --exclude rgk-e2e
run_step "rustdoc_all_features" env "RUSTDOCFLAGS=-D warnings" cargo doc --workspace --all-features --no-deps

echo "[internal-readiness] evidence: ${REPORT}" | tee -a "${REPORT}"
