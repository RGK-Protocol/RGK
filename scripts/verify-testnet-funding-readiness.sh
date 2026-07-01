#!/usr/bin/env bash
# RGK: verify a public testnet funding-readiness report. This is a preflight
# gate for the funded staging run; it proves endpoint identity and funding UTXO
# availability, but it is not a substitute for the full public staging report.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_TESTNET_FUNDING_READINESS_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/funding-readiness.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-testnet-funding-readiness] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-testnet-funding-readiness] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

require_regex "readiness header" '^RGK public testnet funding readiness$'
require_regex "UTC timestamp" '^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_regex "network" '^network=testnet-(10|12)$'
require_regex "chain id" '^chain_id=KaspaTestnet$'
require_regex "testnet URL" '^url=wss?://'
require_regex "wallet set id" '^wallet_set_id=0x[0-9a-f]{64}$'
require_regex "wallet count" '^wallet_count=3$'
require_regex "funding address" '^funding_address=kaspatest:[a-z0-9]+$'
require_regex "real-zk required minimum" '^required_min_value_real_zk=[1-9][0-9]*$'
require_regex "verifier-only required minimum" '^required_min_value_verifier_only=[1-9][0-9]*$'
require_regex "server identity" '^server_version=.* server_network_id=[A-Za-z0-9.-]+ server_is_synced=(true|false) server_has_utxo_index=(true|false)$'
require_regex "UTXO total count" '^utxo_total_count=[0-9]+$'
require_regex "non-coinbase UTXO count" '^utxo_non_coinbase_count=[0-9]+$'
require_regex "eligible UTXO count" '^utxo_eligible_count=[0-9]+$'
require_regex "eligible UTXO value" '^utxo_eligible_total_value=[0-9]+$'
require_regex "selected funding UTXO status" '^selected_funding_utxo=(available|none|not-checked)$'
require_regex "funding readiness" '^funding_readiness=(ok|blocked)$'
require_regex "blocked reason" '^blocked_reason=(none|endpoint-network-mismatch|utxo-index-disabled|missing-funded-non-coinbase-utxo)$'

if grep -Eiq '(secret_key|private_key|privkey)=' "${REPORT}"; then
    echo "[verify-testnet-funding-readiness] report must not contain private key material" >&2
    exit 1
fi

readiness="$(sed -nE 's/^funding_readiness=(ok|blocked)$/\1/p' "${REPORT}" | tail -n 1)"
selected="$(sed -nE 's/^selected_funding_utxo=(available|none|not-checked)$/\1/p' "${REPORT}" | tail -n 1)"
reason="$(sed -nE 's/^blocked_reason=(.*)$/\1/p' "${REPORT}" | tail -n 1)"

if [ "${readiness}" = "ok" ]; then
    if [ "${selected}" != "available" ] || [ "${reason}" != "none" ]; then
        echo "[verify-testnet-funding-readiness] ok readiness requires available selected UTXO and blocked_reason=none" >&2
        exit 1
    fi
    require_regex "selected txid" '^selected_funding_utxo_txid=0x[0-9a-f]{64}$'
    require_regex "selected index" '^selected_funding_utxo_index=[0-9]+$'
    require_regex "selected DAA" '^selected_funding_utxo_daa=[0-9]+$'
    require_regex "selected value" '^selected_funding_utxo_value=[1-9][0-9]*$'
    require_regex "selected non-coinbase provenance" '^selected_funding_utxo_coinbase=false$'
else
    if [ "${selected}" = "available" ] || [ "${reason}" = "none" ]; then
        echo "[verify-testnet-funding-readiness] blocked readiness must not select an available UTXO or use blocked_reason=none" >&2
        exit 1
    fi
fi

echo "[verify-testnet-funding-readiness] ok: ${REPORT}"
