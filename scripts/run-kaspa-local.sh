#!/usr/bin/env bash
# RGK: launch a local Toccata-capable Kaspa node for the e2e harness.
#
# Usage:
#   ./scripts/run-kaspa-local.sh                  # foreground
#   ./scripts/run-kaspa-local.sh --background    # daemonize, write .pid
#
# Environment:
#   RGK_KASPA_DATADIR   override the data dir (default: ./.rgk-localnet)
#   RGK_KASPA_LPORT     p2p listen port (default: 18100)
#   RGK_KASPA_RPCPORT   JSON-RPC port (default: 18110)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATADIR="${RGK_KASPA_DATADIR:-${ROOT}/.rgk-localnet}"
LPORT="${RGK_KASPA_LPORT:-18100}"
RPCPORT="${RGK_KASPA_RPCPORT:-18110}"
PROFILE="${RGK_KASPA_PROFILE:-release}"

KASPAD="${ROOT}/external/rusty-kaspa-toccata/target/${PROFILE}/kaspad"
if [ ! -x "${KASPAD}" ]; then
    echo "[run-kaspa-local] ${KASPAD} not built; running build-kaspa.sh"
    "${ROOT}/scripts/build-kaspa.sh"
fi

mkdir -p "${DATADIR}"

ARGS=(
    --simnet
    --listen="0.0.0.0:${LPORT}"
    --rpclisten="0.0.0.0:${RPCPORT}"
    --rpclisten-borsh="0.0.0.0:$((RPCPORT + 1))"
    --rpclisten-json="0.0.0.0:$((RPCPORT + 2))"
    --appdir="${DATADIR}"
    --enable-unsynced-mining
    --utxoindex
    --disable-upnp
    --nodnsseed
    --yes
)

PID_FILE="${DATADIR}/kaspad.pid"
LOG_FILE="${DATADIR}/kaspad.log"

if [ "${1:-}" = "--background" ]; then
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "[run-kaspa-local] already running (pid $(cat "${PID_FILE}"))"
        exit 0
    fi
    echo "[run-kaspa-local] launching ${KASPAD} in background"
    nohup "${KASPAD}" "${ARGS[@]}" >"${LOG_FILE}" 2>&1 &
    echo $! > "${PID_FILE}"
    echo "[run-kaspa-local] pid: $(cat "${PID_FILE}")"
    echo "[run-kaspa-local] log: ${LOG_FILE}"
    echo "[run-kaspa-local] waiting for RPC at ws://127.0.0.1:$((RPCPORT + 1))"
    for i in {1..60}; do
        if (echo > /dev/tcp/127.0.0.1/$((RPCPORT + 1))) >/dev/null 2>&1; then
            echo "[run-kaspa-local] RPC ready after ${i}s"
            exit 0
        fi
        sleep 1
    done
    echo "[run-kaspa-local] RPC did not come up within 60s; check ${LOG_FILE}"
    exit 1
fi

echo "[run-kaspa-local] launching ${KASPAD} (foreground; ctrl-C to stop)"
exec "${KASPAD}" "${ARGS[@]}"
