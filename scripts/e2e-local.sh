#!/usr/bin/env bash
# RGK: end-to-end local harness. Drives a full covenant-backed RGK receipt
# flow against either a live Toccata node or the in-process fixture.
#
# Usage:
#   ./scripts/e2e-local.sh                     # fixture-only (no node required)
#   ./scripts/e2e-local.sh --live              # requires a running kaspad
#   ./scripts/e2e-local.sh --start-kaspa       # also start kaspad in background
#   ./scripts/e2e-local.sh --stop-kaspa        # stop the backgrounded kaspad
#
# Exit codes:
#   0   success
#   2   missing prerequisite (e.g. kaspad not built and --live given)
#   3   live node unreachable / wrong network
#   4   cargo test failure

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

MODE="fixture"
EXTRA=""
LIVE_URL=""
DEFAULT_LIVE_URL="ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh"

while [ $# -gt 0 ]; do
    case "$1" in
        --live)
            MODE="live"
            LIVE_URL="${RGK_LIVE_KASPA_URL:-${DEFAULT_LIVE_URL}}"
            shift
            ;;
        --fixture)
            MODE="fixture"
            shift
            ;;
        --start-kaspa)
            "${ROOT}/scripts/run-kaspa-local.sh" --background
            shift
            ;;
        --stop-kaspa)
            DATADIR="${RGK_KASPA_DATADIR:-${ROOT}/.rgk-localnet}"
            PID_FILE="${DATADIR}/kaspad.pid"
            if [ -f "${PID_FILE}" ]; then
                kill "$(cat "${PID_FILE}")" || true
                rm -f "${PID_FILE}"
                echo "[e2e-local] stopped"
            fi
            exit 0
            ;;
        *)
            EXTRA="$1"
            shift
            ;;
    esac
done

echo "[e2e-local] mode: ${MODE}"

if [ "${MODE}" = "live" ]; then
    LIVE_HOST="$(printf '%s\n' "${LIVE_URL}" | sed -E 's#^[^:]+://([^:/]+).*#\1#')"
    LIVE_PORT="$(printf '%s\n' "${LIVE_URL}" | sed -E 's#^[^:]+://[^:/]+:([0-9]+).*#\1#')"
    if [ "${LIVE_HOST}" = "${LIVE_URL}" ]; then
        LIVE_HOST="127.0.0.1"
    fi
    if [ "${LIVE_PORT}" = "${LIVE_URL}" ]; then
        LIVE_PORT="18111"
    fi
    if ! (echo > "/dev/tcp/${LIVE_HOST}/${LIVE_PORT}") >/dev/null 2>&1; then
        echo "[e2e-local] live node unreachable at ${LIVE_HOST}:${LIVE_PORT}"
        echo "[e2e-local] start it with: ./scripts/run-kaspa-local.sh --background"
        exit 3
    fi
    export RGK_LIVE_KASPA_URL="${LIVE_URL}"
    echo "[e2e-local] live RPC: ${RGK_LIVE_KASPA_URL}"
fi

if [ "${MODE}" = "live" ]; then
    echo "[e2e-local] running: cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant"
    cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant ${EXTRA} -- --nocapture
else
    echo "[e2e-local] running: cargo test -p rgk-e2e --lib"
    cargo test -p rgk-e2e --lib ${EXTRA} -- --nocapture
fi
echo "[e2e-local] OK"
