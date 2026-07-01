#!/usr/bin/env bash
# RGK: verify that public vocabulary and gates stay Kaspa-native.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

fail=0

check_absent() {
    local label="$1"
    local pattern="$2"
    local status=0
    shift 2

    set +e
    rg -n -i "${pattern}" "$@" \
        --glob '!target/**' \
        --glob '!scripts/verify-native-terminology.sh'
    status=$?
    set -e
    if [ "${status}" -eq 0 ]; then
        echo "[verify-native-terminology] found ${label}" >&2
        fail=1
    elif [ "${status}" -gt 1 ]; then
        echo "[verify-native-terminology] search failed while checking ${label}" >&2
        exit "${status}"
    fi
}

workspace_scope=(README.md CHANGELOG.md docs crates examples scripts tests)
public_text_scope=(README.md CHANGELOG.md docs examples scripts tests)
legacy_prefix="$(printf '\162\147\142')"

check_absent \
    "non-native external vocabulary" \
    "\\b${legacy_prefix}\\b|${legacy_prefix}[-_]|aluvm|tapret|opret|consignment|strict[- ]types|argent" \
    "${workspace_scope[@]}"

check_absent \
    "external asset-system framing" \
    "client-side[[:space:]]+asset[[:space:]]+protocol|asset[-[:space:]]+protocol|legacy[-_[:space:]]+script" \
    "${workspace_scope[@]}"

check_absent \
    "non-Kaspa state-unit wording on the public surface" \
    "\\bcell(s)?\\b" \
    "${public_text_scope[@]}"

check_absent \
    "outpoint-seal wording" \
    "RgkCovenantSeal|outpoint[-_[:space:]]+seal|\\b(covenant|allocation|anchor|output)[-_[:space:]]+seal(ed|s)?\\b|\\bseal(ed|s)?[-_[:space:]]+(spent[-_[:space:]]+)?(outpoint|covenant|allocation|anchor|output)\\b|closed[[:space:]]+(spent[[:space:]]+)?outpoint|closed[[:space:]]+(covenant|allocation|anchor|output)" \
    "${workspace_scope[@]}"

if [ "${fail}" -ne 0 ]; then
    exit 1
fi

echo "[verify-native-terminology] ok"
