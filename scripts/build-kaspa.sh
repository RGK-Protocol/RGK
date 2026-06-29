#!/usr/bin/env bash
# RGK: build the upstream Kaspa Toccata binaries (kaspad + kaspa-miner) that
# the local e2e harness drives against.
#
# Usage:
#   ./scripts/build-kaspa.sh            # release build
#   ./scripts/build-kaspa.sh --debug   # faster compile, slower runtime
#
# Side effects:
#   - Reads/writes external/rusty-kaspa-toccata/
#   - Produces external/rusty-kaspa-toccata/target/{release,debug}/kaspad
#   - Produces external/rusty-kaspa-toccata/target/{release,debug}/kaspa-miner

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KASPA_DIR="${ROOT}/external/rusty-kaspa-toccata"

if [ ! -d "${KASPA_DIR}/.git" ]; then
    echo "[build-kaspa] ${KASPA_DIR} not found; running setup-external.sh"
    "${ROOT}/scripts/setup-external.sh"
fi

PROFILE="release"
if [ "${1:-}" = "--debug" ]; then
    PROFILE="debug"
fi

echo "[build-kaspa] building kaspad + kaspa-miner (${PROFILE}) from ${KASPA_DIR}"
pushd "${KASPA_DIR}" >/dev/null
cargo build --profile "${PROFILE}" --bin kaspad --bin kaspa-miner
popd >/dev/null

echo "[build-kaspa] OK"
echo "[build-kaspa] kaspad:        ${KASPA_DIR}/target/${PROFILE}/kaspad"
echo "[build-kaspa] kaspa-miner:   ${KASPA_DIR}/target/${PROFILE}/kaspa-miner"