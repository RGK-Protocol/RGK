#!/usr/bin/env bash
# RGK: verify that the canonical Silverscript examples compile to the checked
# JSON artifacts recorded in examples/silverscript/artifacts/.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SILVERSCRIPT_ROOT="${RGK_SILVERSCRIPT_ROOT:-${ROOT}/external/silverscript}"
EXPECTED_COMMIT="d25bd3427a093c17327ca3d6b9e1aa5f7688c863"
NETWORK_SCOPE="kaspa_testnet12_only"
SOURCE_DIR="${ROOT}/examples/silverscript"
ARTIFACT_DIR="${SOURCE_DIR}/artifacts"
MANIFEST="${ARTIFACT_DIR}/manifest.tsv"

if [ ! -d "${SILVERSCRIPT_ROOT}/.git" ]; then
    echo "[verify-silverscript-artifacts] missing compiler checkout: ${SILVERSCRIPT_ROOT}" >&2
    echo "[verify-silverscript-artifacts] run: ./scripts/setup-external.sh" >&2
    exit 2
fi

actual_commit="$(git -C "${SILVERSCRIPT_ROOT}" rev-parse HEAD)"
if [ "${actual_commit}" != "${EXPECTED_COMMIT}" ]; then
    echo "[verify-silverscript-artifacts] compiler commit mismatch: ${actual_commit} != ${EXPECTED_COMMIT}" >&2
    exit 1
fi

if [ "${RGK_SILVERSCRIPT_UPDATE:-0}" = "1" ]; then
    mkdir -p "${ARTIFACT_DIR}"
fi

tmp_dir="$(mktemp -d)"
tmp_manifest="${tmp_dir}/manifest.tsv"
trap 'rm -rf "${tmp_dir}"' EXIT

sha256_file() {
    shasum -a 256 "$1" | awk '{print $1}'
}

json_fields() {
    python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    artifact = json.load(handle)

print(
    artifact["compiler_version"],
    len(artifact["script"]),
    len(artifact["abi"]),
    sep="\t",
)
PY
}

printf 'example_id\tsource_path\tartifact_path\tcompiler_commit\tcompiler_version\tnetwork_scope\tsource_sha256\tartifact_sha256\tscript_bytes\tabi_entries\n' > "${tmp_manifest}"

rows=0
for source in "${SOURCE_DIR}"/*.sil; do
    [ -f "${source}" ] || continue
    rows=$((rows + 1))
    example_id="$(basename "${source}" .sil)"
    compiled="${tmp_dir}/${example_id}.json"
    artifact="${ARTIFACT_DIR}/${example_id}.json"

    cargo run --quiet --manifest-path "${SILVERSCRIPT_ROOT}/Cargo.toml" -p silverscript-lang --bin silverc -- \
        "${source}" \
        -o "${compiled}"

    if [ "${RGK_SILVERSCRIPT_UPDATE:-0}" = "1" ]; then
        cp "${compiled}" "${artifact}"
    elif [ ! -f "${artifact}" ]; then
        echo "[verify-silverscript-artifacts] missing artifact: ${artifact}" >&2
        exit 1
    elif ! cmp -s "${compiled}" "${artifact}"; then
        echo "[verify-silverscript-artifacts] artifact drift for ${example_id}" >&2
        exit 1
    fi

    IFS=$'\t' read -r compiler_version script_bytes abi_entries < <(json_fields "${compiled}")
    source_rel="${source#"${ROOT}/"}"
    artifact_rel="${artifact#"${ROOT}/"}"
    source_sha="$(sha256_file "${source}")"
    artifact_sha="$(sha256_file "${artifact}")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${example_id}" \
        "${source_rel}" \
        "${artifact_rel}" \
        "${EXPECTED_COMMIT}" \
        "${compiler_version}" \
        "${NETWORK_SCOPE}" \
        "${source_sha}" \
        "${artifact_sha}" \
        "${script_bytes}" \
        "${abi_entries}" \
        >> "${tmp_manifest}"
done

if [ "${rows}" -lt 4 ]; then
    echo "[verify-silverscript-artifacts] expected at least 4 sources, got ${rows}" >&2
    exit 1
fi

if [ "${RGK_SILVERSCRIPT_UPDATE:-0}" = "1" ]; then
    cp "${tmp_manifest}" "${MANIFEST}"
elif [ ! -f "${MANIFEST}" ]; then
    echo "[verify-silverscript-artifacts] missing manifest: ${MANIFEST}" >&2
    exit 1
elif ! cmp -s "${tmp_manifest}" "${MANIFEST}"; then
    echo "[verify-silverscript-artifacts] manifest drift: ${MANIFEST}" >&2
    exit 1
fi

echo "[verify-silverscript-artifacts] ok: ${MANIFEST} rows=${rows} compiler=${EXPECTED_COMMIT}"
