#!/usr/bin/env bash
# RGK: launch a local devnet kaspad with Toccata active from genesis.
#
# Usage:
#   ./scripts/run-kaspa-devnet.sh                  # foreground
#   ./scripts/run-kaspa-devnet.sh --background    # daemonize, write .pid
#
# Environment:
#   RGK_KASPA_DEVNET_DATADIR  override the data dir (default: ./.rgk-devnet)
#   RGK_KASPA_DEVNET_LPORT    p2p listen port (default: 19100)
#   RGK_KASPA_DEVNET_RPCPORT  JSON-RPC port (default: 19110)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATADIR="${RGK_KASPA_DEVNET_DATADIR:-${ROOT}/.rgk-devnet}"
LPORT="${RGK_KASPA_DEVNET_LPORT:-19100}"
RPCPORT="${RGK_KASPA_DEVNET_RPCPORT:-19110}"
PROFILE="${RGK_KASPA_PROFILE:-release}"
OVERRIDES="${RGK_KASPA_DEVNET_OVERRIDES:-${ROOT}/scripts/devnet-toccata-overrides.json}"

KASPAD="${ROOT}/external/rusty-kaspa-toccata/target/${PROFILE}/kaspad"
if [ ! -x "${KASPAD}" ]; then
    echo "[run-kaspa-devnet] ${KASPAD} not built; running build-kaspa.sh"
    "${ROOT}/scripts/build-kaspa.sh"
fi

if [ ! -f "${OVERRIDES}" ]; then
    echo "[run-kaspa-devnet] missing override params file: ${OVERRIDES}"
    exit 2
fi

mkdir -p "${DATADIR}"

ARGS=(
    --devnet
    --override-params-file="${OVERRIDES}"
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
        echo "[run-kaspa-devnet] already running (pid $(cat "${PID_FILE}"))"
        exit 0
    fi
    echo "[run-kaspa-devnet] launching ${KASPAD} in background"
    nohup "${KASPAD}" "${ARGS[@]}" >"${LOG_FILE}" 2>&1 &
    echo $! > "${PID_FILE}"
    echo "[run-kaspa-devnet] pid: $(cat "${PID_FILE}")"
    echo "[run-kaspa-devnet] log: ${LOG_FILE}"
    echo "[run-kaspa-devnet] waiting for wRPC at ws://127.0.0.1:$((RPCPORT + 1))"
    for i in {1..60}; do
        if (echo > /dev/tcp/127.0.0.1/$((RPCPORT + 1))) >/dev/null 2>&1; then
            echo "[run-kaspa-devnet] wRPC ready after ${i}s"
            exit 0
        fi
        sleep 1
    done
    echo "[run-kaspa-devnet] wRPC did not come up within 60s; check ${LOG_FILE}"
    exit 1
fi

echo "[run-kaspa-devnet] launching ${KASPAD} (foreground; ctrl-C to stop)"
exec "${KASPAD}" "${ARGS[@]}"
