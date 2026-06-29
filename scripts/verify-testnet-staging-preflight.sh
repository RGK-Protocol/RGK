#!/usr/bin/env bash
# RGK: verify the public testnet staging preflight manifest. This checks the
# operator-facing funding and environment contract before a public endpoint or
# funded UTXO is available.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_TESTNET_STAGING_PREFLIGHT_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/preflight.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-testnet-staging-preflight] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-testnet-staging-preflight] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

require_regex "preflight header" '^RGK public testnet staging preflight$'
require_regex "network" '^network=testnet-(10|12)$'
require_regex "chain id" '^chain_id=KaspaTestnet$'
require_regex "funding address" '^address=kaspatest:[a-z0-9]+$'
require_regex "key scope" '^scope=testnet-only deterministic staging key$'
require_regex "funding status" '^funding_status=external-funding-required$'
require_regex "non-coinbase funding requirement" '^required_non_coinbase_utxo=true$'
require_regex "utxo index requirement" '^required_utxo_index=true$'
require_regex "confirmation depth" '^required_confirmation_depth=1$'
require_regex "real-zk minimum value" '^required_min_value_real_zk=[1-9][0-9]*$'
require_regex "verifier-only minimum value" '^required_min_value_verifier_only=[1-9][0-9]*$'
require_regex "live wRPC feature" '^required_live_kaspa_wrpc_feature=true$'
require_regex "real-zk feature" '^required_real_zk_feature=true$'
require_regex "persistent indexer feature" '^required_persistent_indexer_feature=true$'
require_regex "no local mining" '^required_local_mining=false$'
require_regex "live covenant test" '^required_live_test=live_toccata_full_covenant_lifecycle$'
require_regex "endpoint environment variable" '^endpoint_env=RGK_LIVE_KASPA_URL$'
require_regex "network environment variable" '^network_env=RGK_LIVE_KASPA_NETWORK$'
require_regex "staging script" '^staging_script=scripts/e2e-testnet-staging\.sh$'
require_regex "evidence verifier" '^evidence_verifier=scripts/verify-testnet-staging-evidence\.sh$'
require_regex "expected report" '^expected_report=target/rgk-testnet-staging-evidence/latest\.txt$'
require_regex "preflight id" '^preflight_id=0x[0-9a-f]{64}$'

echo "[verify-testnet-staging-preflight] ok: ${REPORT}"
