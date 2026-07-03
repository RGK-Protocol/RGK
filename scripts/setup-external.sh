#!/usr/bin/env bash
# RGK: clone (or update) the external Kaspa repositories that RGK uses for
# covenant, contract compiler, and devnet evidence. Run from the workspace root.
#
# Usage:
#   ./scripts/setup-external.sh            # clone
#   ./scripts/setup-external.sh --update   # fetch + fast-forward existing clones
#
# Layout produced:
#   external/rusty-kaspa-toccata/  -> branch `master` (Toccata merged here)
#   external/silverscript/         -> pinned compiler commit

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERNAL="${ROOT}/external"

mkdir -p "${EXTERNAL}"

clone_or_update() {
    local url="$1"
    local dir="$2"
    local ref="$3"
    if [ ! -d "${dir}/.git" ]; then
        echo "[setup] cloning ${url} -> ${dir} @ ${ref}"
        git clone --quiet --no-tags "${url}" "${dir}"
    else
        echo "[setup] updating ${dir} -> ${ref}"
        (cd "${dir}" && git fetch --quiet --tags origin)
    fi
    (cd "${dir}" && git checkout --quiet "${ref}" 2>/dev/null || git checkout --quiet -B "${ref}" "origin/${ref}")
    (cd "${dir}" && git rev-parse HEAD)
}

# The upstream `toccata` branch was merged into `master` (toccata HEAD is a
# strict ancestor of master, verified via `git merge-base`). We therefore pin
# `master` so RGK tracks the line that actually carries every Toccata feature
# plus subsequent fixes. The legacy `-toc` Cargo version suffix was dropped on
# master, so capability is asserted structurally (TX_VERSION_TOCCATA) in the
# e2e harness rather than by version-string matching.
clone_or_update \
    "https://github.com/kaspanet/rusty-kaspa.git" \
    "${EXTERNAL}/rusty-kaspa-toccata" \
    "origin/master"

clone_or_update \
    "https://github.com/kaspanet/silverscript.git" \
    "${EXTERNAL}/silverscript" \
    "d25bd3427a093c17327ca3d6b9e1aa5f7688c863"

echo "[setup] external repositories ready under ${EXTERNAL}"
