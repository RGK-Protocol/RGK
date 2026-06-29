#!/usr/bin/env bash
# RGK: audit current launch readiness from already produced evidence. Strict
# mode is fail-closed; --allow-blocked is for local/devnet CI before a funded
# public testnet report exists.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_REPORT="${RGK_DEVNET_EVIDENCE_REPORT:-${ROOT}/target/rgk-devnet-evidence/latest.txt}"
PREFLIGHT_REPORT="${RGK_TESTNET_STAGING_PREFLIGHT_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/preflight.txt}"
TESTNET_REPORT="${RGK_TESTNET_STAGING_EVIDENCE_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/latest.txt}"
ALLOW_BLOCKED=0

usage() {
    echo "usage: $0 [--allow-blocked]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --allow-blocked)
            ALLOW_BLOCKED=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

failures=()
blockers=()
internal_ready=1
public_ready=1

emit() {
    printf '%s=%s\n' "$1" "$2"
}

record_failure() {
    failures+=("$1")
    internal_ready=0
}

record_blocker() {
    blockers+=("$1")
    public_ready=0
}

show_log() {
    local key="$1"
    local log="$2"
    sed "s/^/[verify-launch-readiness] ${key}: /" "${log}" >&2
}

run_gate() {
    local key="$1"
    shift
    local log="${tmp_dir}/${key}.log"
    if "$@" >"${log}" 2>&1; then
        emit "${key}" "ok"
        return 0
    fi
    emit "${key}" "failed"
    show_log "${key}" "${log}"
    return 1
}

print_list() {
    if [ "$#" -eq 0 ]; then
        printf 'none\n'
        return
    fi
    local IFS=,
    printf '%s\n' "$*"
}

check_external_runtime_dependencies() {
    local key="external_runtime_dependencies"
    local log="${tmp_dir}/${key}.log"
    local dep_core dep_lib
    dep_core="rgb""-core"
    dep_lib="rgb""-lib"

    if ! cargo tree --workspace --all-features --prefix none >"${log}" 2>&1; then
        emit "${key}" "failed"
        show_log "${key}" "${log}"
        record_failure "${key}"
        return
    fi

    if grep -Eq "(^|[[:space:]])(${dep_core}|${dep_lib})([[:space:]]|$)" "${log}"; then
        emit "${key}" "failed"
        show_log "${key}" "${log}"
        record_failure "${key}"
        return
    fi

    emit "${key}" "absent"
}

echo "RGK launch readiness audit"
emit "devnet_report" "${DEVNET_REPORT}"
emit "public_testnet_preflight_report" "${PREFLIGHT_REPORT}"
emit "public_testnet_report" "${TESTNET_REPORT}"

if ! run_gate "devnet_evidence" bash "${ROOT}/scripts/verify-devnet-evidence.sh" "${DEVNET_REPORT}"; then
    record_failure "devnet_evidence"
fi

if ! run_gate "public_testnet_preflight" bash "${ROOT}/scripts/verify-testnet-staging-preflight.sh" "${PREFLIGHT_REPORT}"; then
    record_failure "public_testnet_preflight"
fi

if run_gate "examples_matrix" bash "${ROOT}/scripts/verify-example-matrix.sh"; then
    emit "silverscript_artifacts" "ok"
else
    record_failure "examples_matrix"
    record_failure "silverscript_artifacts"
    emit "silverscript_artifacts" "failed"
fi

check_external_runtime_dependencies

if [ -f "${TESTNET_REPORT}" ]; then
    if run_gate "public_testnet_funded_report" bash "${ROOT}/scripts/verify-testnet-staging-evidence.sh" "${TESTNET_REPORT}"; then
        emit "public_policy_migration_staging" "ok"
        emit "public_production_allocation_staging" "ok"
    else
        failures+=("public_testnet_funded_report")
        public_ready=0
        emit "public_policy_migration_staging" "failed"
        emit "public_production_allocation_staging" "failed"
    fi
else
    emit "public_testnet_funded_report" "blocked"
    emit "public_policy_migration_staging" "blocked"
    emit "public_production_allocation_staging" "blocked"
    record_blocker "funded-public-testnet-report-missing"
fi

emit "single_recursive_allocation_proof" "not-required-unless-product-scope"

if [ "${internal_ready}" -eq 1 ]; then
    emit "internal_readiness" "ok"
else
    emit "internal_readiness" "failed"
fi

if [ "${public_ready}" -eq 1 ]; then
    emit "public_network_readiness" "ok"
else
    emit "public_network_readiness" "blocked"
fi

if [ "${#failures[@]}" -eq 0 ]; then
    emit "failed_gate" "none"
else
    emit "failed_gate" "$(print_list "${failures[@]}")"
fi

if [ "${#blockers[@]}" -eq 0 ]; then
    emit "blocked_reason" "none"
else
    emit "blocked_reason" "$(print_list "${blockers[@]}")"
fi

if [ "${internal_ready}" -eq 1 ] && [ "${public_ready}" -eq 1 ]; then
    emit "launch_readiness" "ok"
    exit 0
fi

emit "launch_readiness" "blocked"

if [ "${internal_ready}" -eq 1 ] && [ "${ALLOW_BLOCKED}" -eq 1 ] && [ "${#blockers[@]}" -gt 0 ] && [ "${#failures[@]}" -eq 0 ]; then
    exit 0
fi

exit 1
