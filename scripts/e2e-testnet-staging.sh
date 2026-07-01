#!/usr/bin/env bash
# RGK: public Kaspa testnet staging harness.
#
# This does not mine. Fund the deterministic address printed by --print-address
# on public testnet, then run this script with a real public Borsh wRPC endpoint:
#
#   RGK_LIVE_KASPA_URL="wss://..." bash scripts/e2e-testnet-staging.sh
#
# Override RGK_LIVE_KASPA_NETWORK=testnet-10 only when staging explicitly
# targets that public network. The default is testnet-12.
#
# Print the deterministic funding address without connecting to a node:
#
#   bash scripts/e2e-testnet-staging.sh --print-address
#
# Print and verify the public-staging preflight manifest without connecting:
#
#   bash scripts/e2e-testnet-staging.sh --preflight
#
# Print and verify the deterministic public testnet wallet set:
#
#   bash scripts/e2e-testnet-staging.sh --wallets
#
# Check a real public testnet endpoint and funding address without submitting
# transactions:
#
#   RGK_LIVE_KASPA_URL="wss://..." bash scripts/e2e-testnet-staging.sh --funding-readiness
#
# Print funding instructions and exact faucet URLs for the deterministic
# address:
#
#   bash scripts/e2e-testnet-staging.sh --funding-help [testnet-10|testnet-12]
#
# Resume a previously interrupted public staging report without submitting new
# transactions. The report must already contain accepted and confirmed covenant
# and continuation transaction evidence:
#
#   bash scripts/e2e-testnet-staging.sh --resume target/rgk-testnet-staging-evidence/latest.txt

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_DIR="${RGK_TESTNET_STAGING_EVIDENCE_DIR:-${ROOT}/target/rgk-testnet-staging-evidence}"
REPORT="${EVIDENCE_DIR}/latest.txt"

if [ "${1:-}" = "--print-address" ]; then
    NETWORK="${2:-${RGK_LIVE_KASPA_NETWORK:-testnet-12}}"
    cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address -- \
        "${NETWORK}"
    exit 0
fi

if [ "${1:-}" = "--preflight" ]; then
    NETWORK="${2:-${RGK_LIVE_KASPA_NETWORK:-testnet-12}}"
    mkdir -p "${EVIDENCE_DIR}"
    PREFLIGHT_REPORT="${EVIDENCE_DIR}/preflight.txt"
    cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address -- \
        --preflight "${NETWORK}" > "${PREFLIGHT_REPORT}"
    cat "${PREFLIGHT_REPORT}"
    bash "${ROOT}/scripts/verify-testnet-staging-preflight.sh" "${PREFLIGHT_REPORT}"
    exit 0
fi

if [ "${1:-}" = "--funding-help" ]; then
    NETWORK="${2:-${RGK_LIVE_KASPA_NETWORK:-testnet-12}}"
    mkdir -p "${EVIDENCE_DIR}"
    HELP_REPORT="${EVIDENCE_DIR}/funding-help-${NETWORK}.txt"
    PREFLIGHT_TMP="$(mktemp)"
    trap 'rm -f "${PREFLIGHT_TMP}"' EXIT
    cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address -- \
        --preflight "${NETWORK}" > "${PREFLIGHT_TMP}"
    funding_address="$(sed -nE 's/^address=(kaspatest:[a-z0-9]+)$/\1/p' "${PREFLIGHT_TMP}")"
    required_sompi="$(sed -nE 's/^required_min_value_real_zk=([0-9]+)$/\1/p' "${PREFLIGHT_TMP}")"
    required_kas="$(awk -v sompi="${required_sompi}" 'BEGIN { printf "%.8f", sompi / 100000000 }')"
    faucet_browser_url="https://faucet-testnet.kaspanet.io/"
    if [ "${NETWORK}" = "testnet-10" ]; then
        faucet_browser_url="https://faucet-tn10.kaspanet.io/"
    fi
    faucet_api_get_url="${faucet_browser_url%/}/api/get/${funding_address}/1"
    {
        echo "RGK public testnet funding help"
        echo "network=${NETWORK}"
        echo "funding_address=${funding_address}"
        echo "required_min_value_real_zk_sompi=${required_sompi}"
        echo "required_min_value_real_zk_kas=${required_kas}"
        echo "suggested_faucet_amount_kas=1"
        echo "faucet_browser_url=${faucet_browser_url}"
        echo "faucet_api_get_url=${faucet_api_get_url}"
        echo "funding_readiness_command=RGK_LIVE_KASPA_URL=<public-borsh-wrpc-url> bash scripts/e2e-testnet-staging.sh --funding-readiness ${NETWORK}"
        echo "full_staging_command=RGK_LIVE_KASPA_NETWORK=${NETWORK} RGK_LIVE_KASPA_URL=<public-borsh-wrpc-url> bash scripts/e2e-testnet-staging.sh"
        echo
        cat "${PREFLIGHT_TMP}"
    } > "${HELP_REPORT}"
    cat "${HELP_REPORT}"
    exit 0
fi

if [ "${1:-}" = "--wallets" ]; then
    NETWORK="${2:-${RGK_LIVE_KASPA_NETWORK:-testnet-12}}"
    mkdir -p "${EVIDENCE_DIR}"
    WALLET_REPORT="${EVIDENCE_DIR}/wallets.txt"
    cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address -- \
        --wallets "${NETWORK}" > "${WALLET_REPORT}"
    cat "${WALLET_REPORT}"
    bash "${ROOT}/scripts/verify-testnet-staging-wallets.sh" "${WALLET_REPORT}"
    exit 0
fi

if [ "${1:-}" = "--funding-readiness" ]; then
    NETWORK="${RGK_LIVE_KASPA_NETWORK:-testnet-12}"
    LIVE_URL="${RGK_LIVE_KASPA_URL:-}"
    if [ -n "${2:-}" ]; then
        case "${2}" in
            ws://*|wss://*)
                LIVE_URL="${2}"
                ;;
            *)
                NETWORK="${2}"
                LIVE_URL="${LIVE_URL:-${3:-}}"
                ;;
        esac
    fi
    if [ -z "${LIVE_URL}" ]; then
        echo "[e2e-testnet-staging] set RGK_LIVE_KASPA_URL to a public testnet Borsh wRPC endpoint" >&2
        exit 2
    fi
    mkdir -p "${EVIDENCE_DIR}"
    FUNDING_REPORT="${EVIDENCE_DIR}/funding-readiness.txt"
    set +e
    cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-funding-readiness -- \
        "${NETWORK}" "${LIVE_URL}" > "${FUNDING_REPORT}"
    status=$?
    set -e
    cat "${FUNDING_REPORT}"
    bash "${ROOT}/scripts/verify-testnet-funding-readiness.sh" "${FUNDING_REPORT}"
    if [ "${status}" -ne 0 ]; then
        exit "${status}"
    fi
    exit 0
fi

if [ "${1:-}" = "--resume" ]; then
    SOURCE_REPORT="${2:-${REPORT}}"
    if [ ! -f "${SOURCE_REPORT}" ]; then
        echo "[e2e-testnet-staging] missing resume report: ${SOURCE_REPORT}" >&2
        exit 2
    fi
    mkdir -p "${EVIDENCE_DIR}"
    SOURCE_CANON="$(cd "$(dirname "${SOURCE_REPORT}")" && pwd -P)/$(basename "${SOURCE_REPORT}")"
    REPORT_CANON="$(cd "$(dirname "${REPORT}")" && pwd -P)/$(basename "${REPORT}")"
    if [ "${SOURCE_CANON}" != "${REPORT_CANON}" ]; then
        cp "${SOURCE_REPORT}" "${REPORT}"
    fi
    RESUME_NETWORK="$(sed -nE 's/^network=(testnet-(10|12))$/\1/p' "${REPORT}" | head -n 1)"
    RESUME_URL="$(sed -nE 's/^url=(wss?:\/\/.+)$/\1/p' "${REPORT}" | head -n 1)"
    if [ -z "${RESUME_NETWORK}" ] || [ -z "${RESUME_URL}" ]; then
        echo "[e2e-testnet-staging] resume report must contain network=testnet-10|12 and url=ws(s)://..." >&2
        exit 2
    fi
    {
        echo "[e2e-testnet-staging] resuming interrupted public staging report: ${SOURCE_REPORT}"
        echo "[e2e-testnet-staging] resume network: ${RESUME_NETWORK}"
        echo "[e2e-testnet-staging] resume public testnet RPC: ${RESUME_URL}"
    } | tee -a "${REPORT}"
    RGK_LIVE_KASPA_NETWORK="${RESUME_NETWORK}" \
    RGK_LIVE_KASPA_URL="${RESUME_URL}" \
    RGK_LIVE_KASPA_RESUME_REPORT="${REPORT}" \
    cargo test -p rgk-e2e --features live-kaspa-wrpc,persistent-indexer,real-zk --test live_covenant live_toccata_full_covenant_lifecycle -- --exact --nocapture \
        2>&1 | tee -a "${REPORT}"

    bash "${ROOT}/scripts/verify-testnet-staging-evidence.sh" "${REPORT}" 2>&1 | tee -a "${REPORT}"
    echo "[e2e-testnet-staging] evidence: ${REPORT}"
    exit 0
fi

LIVE_URL="${RGK_LIVE_KASPA_URL:-${1:-}}"
STAGING_NETWORK="${RGK_LIVE_KASPA_NETWORK:-testnet-12}"

if [ -z "${LIVE_URL}" ]; then
    echo "[e2e-testnet-staging] set RGK_LIVE_KASPA_URL to a public testnet Borsh wRPC endpoint" >&2
    exit 2
fi

case "${LIVE_URL}" in
    ws://*)
        LIVE_REST="${LIVE_URL#ws://}"
        DEFAULT_PORT="80"
        ;;
    wss://*)
        LIVE_REST="${LIVE_URL#wss://}"
        DEFAULT_PORT="443"
        ;;
    *)
        echo "[e2e-testnet-staging] expected ws:// or wss:// URL: ${LIVE_URL}" >&2
        exit 2
        ;;
esac
LIVE_AUTHORITY="${LIVE_REST%%/*}"
if [[ "${LIVE_AUTHORITY}" == *:* ]]; then
    LIVE_HOST="${LIVE_AUTHORITY%:*}"
    LIVE_PORT="${LIVE_AUTHORITY##*:}"
else
    LIVE_HOST="${LIVE_AUTHORITY}"
    LIVE_PORT="${DEFAULT_PORT}"
fi
if ! (echo > "/dev/tcp/${LIVE_HOST}/${LIVE_PORT}") >/dev/null 2>&1; then
    echo "[e2e-testnet-staging] testnet node unreachable at ${LIVE_HOST}:${LIVE_PORT}" >&2
    exit 3
fi

mkdir -p "${EVIDENCE_DIR}"
{
    echo "RGK public testnet staging evidence"
    echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "url=${LIVE_URL}"
} > "${REPORT}"

echo "[e2e-testnet-staging] recording public staging preflight"
cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address -- \
    --wallets "${STAGING_NETWORK}" \
    2>&1 | tee -a "${REPORT}"
bash "${ROOT}/scripts/verify-testnet-staging-wallets.sh" "${REPORT}" 2>&1 | tee -a "${REPORT}"
cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address -- \
    --preflight "${STAGING_NETWORK}" \
    2>&1 | tee -a "${REPORT}"
bash "${ROOT}/scripts/verify-testnet-staging-preflight.sh" "${REPORT}" 2>&1 | tee -a "${REPORT}"

echo "[e2e-testnet-staging] public testnet RPC: ${LIVE_URL}"
echo "[e2e-testnet-staging] running full covenant lifecycle on public testnet"
RGK_LIVE_KASPA_NETWORK="${STAGING_NETWORK}" \
RGK_LIVE_KASPA_URL="${LIVE_URL}" \
cargo test -p rgk-e2e --features live-kaspa-wrpc,persistent-indexer,real-zk --test live_covenant -- --nocapture \
    2>&1 | tee -a "${REPORT}"

bash "${ROOT}/scripts/verify-testnet-staging-evidence.sh" "${REPORT}" 2>&1 | tee -a "${REPORT}"

echo "[e2e-testnet-staging] evidence: ${REPORT}"
