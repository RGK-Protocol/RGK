#!/usr/bin/env bash
# RGK: verify the deterministic public testnet staging wallet-set report. The
# report intentionally contains addresses, x-only public keys, and secret
# fingerprints only; it does not print private keys.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_TESTNET_STAGING_WALLET_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/wallets.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-testnet-staging-wallets] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-testnet-staging-wallets] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

require_regex "wallet-set header" '^RGK public testnet staging wallet set$'
require_regex "network" '^network=testnet-(10|12)$'
require_regex "chain id" '^chain_id=KaspaTestnet$'
require_regex "wallet set id" '^wallet_set_id=0x[0-9a-f]{64}$'
require_regex "wallet count" '^wallet_count=3$'
require_regex "funding wallet" '^wallet_role=funding address=kaspatest:[a-z0-9]+ xonly=0x[0-9a-f]{64} secret_fingerprint=0x[0-9a-f]{64} required_min_value_real_zk=[1-9][0-9]* required_min_value_verifier_only=[1-9][0-9]* purpose=public-testnet-funding$'
require_regex "change wallet" '^wallet_role=change address=kaspatest:[a-z0-9]+ xonly=0x[0-9a-f]{64} secret_fingerprint=0x[0-9a-f]{64} required_min_value_real_zk=0 required_min_value_verifier_only=0 purpose=reserved-change-output-isolation$'
require_regex "observer wallet" '^wallet_role=observer address=kaspatest:[a-z0-9]+ xonly=0x[0-9a-f]{64} secret_fingerprint=0x[0-9a-f]{64} required_min_value_real_zk=0 required_min_value_verifier_only=0 purpose=observer-reporting-no-funding$'

if [ "$(grep -Ec '^wallet_role=' "${REPORT}")" -ne 3 ]; then
    echo "[verify-testnet-staging-wallets] expected exactly 3 wallet_role lines" >&2
    exit 1
fi

if grep -Eq '(^|[[:space:]])(secret_key|private_key|privkey)=' "${REPORT}"; then
    echo "[verify-testnet-staging-wallets] report must not contain private key material" >&2
    exit 1
fi

address_count="$(sed -nE 's/^wallet_role=[^ ]+ address=([^ ]+) .*/\1/p' "${REPORT}" | wc -l | tr -d ' ')"
unique_address_count="$(sed -nE 's/^wallet_role=[^ ]+ address=([^ ]+) .*/\1/p' "${REPORT}" | sort -u | wc -l | tr -d ' ')"
if [ "${address_count}" != "3" ] || [ "${unique_address_count}" != "3" ]; then
    echo "[verify-testnet-staging-wallets] wallet addresses must be three unique entries" >&2
    exit 1
fi

echo "[verify-testnet-staging-wallets] ok: ${REPORT}"
