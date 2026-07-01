#!/usr/bin/env bash
# RGK: audit current launch readiness from already produced evidence. Strict
# mode is fail-closed; --allow-blocked is for local/devnet CI before a funded
# public testnet report exists.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_REPORT="${RGK_DEVNET_EVIDENCE_REPORT:-${ROOT}/target/rgk-devnet-evidence/latest.txt}"
PREFLIGHT_REPORT="${RGK_TESTNET_STAGING_PREFLIGHT_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/preflight.txt}"
FUNDING_READINESS_REPORT="${RGK_TESTNET_FUNDING_READINESS_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/funding-readiness.txt}"
TESTNET_REPORT="${RGK_TESTNET_STAGING_EVIDENCE_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/latest.txt}"
INTERNAL_REPORT="${RGK_INTERNAL_READINESS_REPORT:-${ROOT}/target/rgk-internal-readiness/latest.txt}"
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

report_value() {
    local key="$1"
    local report="$2"
    sed -nE "s/^${key}=(.*)$/\\1/p" "${report}" | head -n 1
}

check_external_runtime_dependencies() {
    local key="external_runtime_dependencies"
    local log="${tmp_dir}/${key}.log"
    local dep_core dep_lib
    dep_core="$(printf '\162\147\142-core')"
    dep_lib="$(printf '\162\147\142-lib')"

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
emit "internal_readiness_report" "${INTERNAL_REPORT}"
emit "public_testnet_preflight_report" "${PREFLIGHT_REPORT}"
emit "public_testnet_funding_readiness_report" "${FUNDING_READINESS_REPORT}"
emit "public_testnet_report" "${TESTNET_REPORT}"

if ! run_gate "internal_readiness_evidence" bash "${ROOT}/scripts/verify-internal-readiness-evidence.sh" "${INTERNAL_REPORT}"; then
    record_failure "internal_readiness_evidence"
fi

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
    funded_log="${tmp_dir}/public_testnet_funded_report.log"
    if bash "${ROOT}/scripts/verify-testnet-staging-evidence.sh" "${TESTNET_REPORT}" >"${funded_log}" 2>&1; then
        emit "public_testnet_funded_report" "ok"
        emit "public_policy_migration_staging" "ok"
        emit "public_production_allocation_staging" "ok"
    else
        show_log "public_testnet_funded_report" "${funded_log}"
        funding_blocked=0
        if [ -f "${FUNDING_READINESS_REPORT}" ]; then
            if run_gate "public_testnet_funding_readiness" bash "${ROOT}/scripts/verify-testnet-funding-readiness.sh" "${FUNDING_READINESS_REPORT}"; then
                preflight_network="$(report_value "network" "${PREFLIGHT_REPORT}")"
                funding_network="$(report_value "network" "${FUNDING_READINESS_REPORT}")"
                preflight_wallet_set_id="$(report_value "wallet_set_id" "${PREFLIGHT_REPORT}")"
                funding_wallet_set_id="$(report_value "wallet_set_id" "${FUNDING_READINESS_REPORT}")"
                preflight_address="$(report_value "address" "${PREFLIGHT_REPORT}")"
                funding_address="$(report_value "funding_address" "${FUNDING_READINESS_REPORT}")"
                if [ "${preflight_network}" != "${funding_network}" ] \
                    || [ "${preflight_wallet_set_id}" != "${funding_wallet_set_id}" ] \
                    || [ "${preflight_address}" != "${funding_address}" ]; then
                    emit "public_testnet_funding_consistency" "failed"
                    failures+=("public_testnet_funding_consistency")
                    emit "public_testnet_funding_status" "failed"
                    public_ready=0
                else
                    emit "public_testnet_funding_consistency" "ok"
                    if grep -Eq '^funding_readiness=ok$' "${FUNDING_READINESS_REPORT}"; then
                        emit "public_testnet_funding_status" "ready"
                    else
                        emit "public_testnet_funding_status" "blocked"
                        funding_blocked=1
                    fi
                fi
            else
                failures+=("public_testnet_funding_readiness")
                public_ready=0
                emit "public_testnet_funding_status" "failed"
            fi
        else
            emit "public_testnet_funding_readiness" "not-run"
            emit "public_testnet_funding_consistency" "not-run"
            emit "public_testnet_funding_status" "unknown"
        fi

        if [ "${funding_blocked}" -eq 1 ]; then
            emit "public_testnet_funded_report" "blocked"
            emit "public_policy_migration_staging" "blocked"
            emit "public_production_allocation_staging" "blocked"
            record_blocker "funded-public-testnet-report-waiting-for-funding"
        else
            emit "public_testnet_funded_report" "failed"
            failures+=("public_testnet_funded_report")
            public_ready=0
            emit "public_policy_migration_staging" "failed"
            emit "public_production_allocation_staging" "failed"
        fi
    fi
else
    if [ -f "${FUNDING_READINESS_REPORT}" ]; then
        if run_gate "public_testnet_funding_readiness" bash "${ROOT}/scripts/verify-testnet-funding-readiness.sh" "${FUNDING_READINESS_REPORT}"; then
            preflight_network="$(report_value "network" "${PREFLIGHT_REPORT}")"
            funding_network="$(report_value "network" "${FUNDING_READINESS_REPORT}")"
            preflight_wallet_set_id="$(report_value "wallet_set_id" "${PREFLIGHT_REPORT}")"
            funding_wallet_set_id="$(report_value "wallet_set_id" "${FUNDING_READINESS_REPORT}")"
            preflight_address="$(report_value "address" "${PREFLIGHT_REPORT}")"
            funding_address="$(report_value "funding_address" "${FUNDING_READINESS_REPORT}")"
            if [ "${preflight_network}" != "${funding_network}" ] \
                || [ "${preflight_wallet_set_id}" != "${funding_wallet_set_id}" ] \
                || [ "${preflight_address}" != "${funding_address}" ]; then
                emit "public_testnet_funding_consistency" "failed"
                failures+=("public_testnet_funding_consistency")
                emit "public_testnet_funding_status" "failed"
                public_ready=0
            else
                emit "public_testnet_funding_consistency" "ok"
            fi
            if grep -Eq '^funding_readiness=ok$' "${FUNDING_READINESS_REPORT}"; then
                if [ "${preflight_network}" = "${funding_network}" ] \
                    && [ "${preflight_wallet_set_id}" = "${funding_wallet_set_id}" ] \
                    && [ "${preflight_address}" = "${funding_address}" ]; then
                    emit "public_testnet_funding_status" "ready"
                fi
            else
                if [ "${preflight_network}" = "${funding_network}" ] \
                    && [ "${preflight_wallet_set_id}" = "${funding_wallet_set_id}" ] \
                    && [ "${preflight_address}" = "${funding_address}" ]; then
                    emit "public_testnet_funding_status" "blocked"
                fi
            fi
        else
            failures+=("public_testnet_funding_readiness")
            public_ready=0
            emit "public_testnet_funding_status" "failed"
        fi
    else
        emit "public_testnet_funding_readiness" "not-run"
        emit "public_testnet_funding_consistency" "not-run"
        emit "public_testnet_funding_status" "unknown"
    fi
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
