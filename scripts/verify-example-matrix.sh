#!/usr/bin/env bash
# RGK: verify that the examples coverage matrix is syntactically stable and
# grounded in current local/devnet evidence labels.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${1:-${ROOT}/examples/contract-matrix.tsv}"
DEVNET_VERIFIER="${ROOT}/scripts/verify-devnet-evidence.sh"
SILVERSCRIPT_MANIFEST="${ROOT}/examples/silverscript/artifacts/manifest.tsv"

bash "${ROOT}/scripts/verify-silverscript-artifacts.sh"

if [ ! -f "${MATRIX}" ]; then
    echo "[verify-example-matrix] missing matrix: ${MATRIX}" >&2
    exit 2
fi

expected_header=$'example_id\tcategory\tcapabilities\tlocal_evidence\tdevnet_markers\tcontract_source\tsilverscript_status\tcompile_artifact_status\tpublic_staging_status\targent_equivalence_status'
actual_header="$(sed -n '1p' "${MATRIX}")"
if [ "${actual_header}" != "${expected_header}" ]; then
    echo "[verify-example-matrix] bad header" >&2
    exit 1
fi

tmp_ids="$(mktemp)"
trap 'rm -f "${tmp_ids}"' EXIT

rows=0
while IFS=$'\t' read -r example_id category capabilities local_evidence devnet_markers contract_source silverscript_status compile_artifact_status public_staging_status argent_equivalence_status extra; do
    if [ "${example_id}" = "example_id" ]; then
        continue
    fi
    if [ -n "${extra:-}" ]; then
        echo "[verify-example-matrix] too many columns for ${example_id}" >&2
        exit 1
    fi
    for value in "${example_id}" "${category}" "${capabilities}" "${local_evidence}" "${devnet_markers}" "${contract_source}" "${silverscript_status}" "${compile_artifact_status}" "${public_staging_status}" "${argent_equivalence_status}"; do
        if [ -z "${value}" ]; then
            echo "[verify-example-matrix] empty field in ${example_id}" >&2
            exit 1
        fi
    done
    printf '%s\n' "${example_id}" >> "${tmp_ids}"
    rows=$((rows + 1))

    case "${contract_source}" in
        silverscript_and_rust_toccata_fixture) ;;
        *)
            echo "[verify-example-matrix] unsupported contract_source for ${example_id}: ${contract_source}" >&2
            exit 1
            ;;
    esac
    case "${silverscript_status}" in
        silverscript_source_compiles) ;;
        *)
            echo "[verify-example-matrix] unsupported silverscript_status for ${example_id}: ${silverscript_status}" >&2
            exit 1
            ;;
    esac
    case "${compile_artifact_status}" in
        checked_silverscript_json_artifact) ;;
        *)
            echo "[verify-example-matrix] unsupported compile_artifact_status for ${example_id}: ${compile_artifact_status}" >&2
            exit 1
            ;;
    esac
    case "${public_staging_status}" in
        pending_public_staging) ;;
        *)
            echo "[verify-example-matrix] unsupported public_staging_status for ${example_id}: ${public_staging_status}" >&2
            exit 1
            ;;
    esac
    case "${argent_equivalence_status}" in
        argent_external_scope) ;;
        *)
            echo "[verify-example-matrix] unsupported argent_equivalence_status for ${example_id}: ${argent_equivalence_status}" >&2
            exit 1
            ;;
    esac

    IFS=';' read -r -a local_items <<< "${local_evidence}"
    for item in "${local_items[@]}"; do
        if ! rg -q "${item}" "${ROOT}/crates" "${ROOT}/tests"; then
            echo "[verify-example-matrix] local evidence ${item} not found for ${example_id}" >&2
            exit 1
        fi
    done

    IFS=';' read -r -a devnet_items <<< "${devnet_markers}"
    for item in "${devnet_items[@]}"; do
        if ! grep -Fq "require_regex \"${item}\"" "${DEVNET_VERIFIER}"; then
            echo "[verify-example-matrix] devnet marker ${item} not enforced for ${example_id}" >&2
            exit 1
        fi
    done

    if ! grep -Fq "${example_id}"$'\t'"examples/silverscript/${example_id}.sil"$'\t'"examples/silverscript/artifacts/${example_id}.json"$'\t' "${SILVERSCRIPT_MANIFEST}"; then
        echo "[verify-example-matrix] Silverscript artifact manifest missing ${example_id}" >&2
        exit 1
    fi
done < "${MATRIX}"

if [ "${rows}" -lt 4 ]; then
    echo "[verify-example-matrix] expected at least 4 evidenced examples, got ${rows}" >&2
    exit 1
fi

if [ "$(sort "${tmp_ids}" | uniq -d | wc -l | tr -d ' ')" != "0" ]; then
    echo "[verify-example-matrix] duplicate example ids" >&2
    exit 1
fi

echo "[verify-example-matrix] ok: ${MATRIX} rows=${rows}"
