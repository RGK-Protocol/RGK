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
