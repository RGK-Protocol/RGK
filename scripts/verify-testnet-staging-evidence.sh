#!/usr/bin/env bash
# RGK: verify that a public testnet staging report contains the required live
# production-staging markers. This proves only the supplied report; it does not
# create public evidence by itself.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-${RGK_TESTNET_STAGING_EVIDENCE_REPORT:-${ROOT}/target/rgk-testnet-staging-evidence/latest.txt}}"

if [ ! -f "${REPORT}" ]; then
    echo "[verify-testnet-staging-evidence] missing report: ${REPORT}" >&2
    exit 2
fi

require_regex() {
    local label="$1"
    local pattern="$2"
    if ! grep -Eq "${pattern}" "${REPORT}"; then
        echo "[verify-testnet-staging-evidence] missing ${label}: ${pattern}" >&2
        exit 1
    fi
}

if grep -Eq 'test result: FAILED|panicked at|^test .* \.\.\. FAILED$|^failures:$|command not found' "${REPORT}"; then
    echo "[verify-testnet-staging-evidence] report contains a failed or panicked test run" >&2
    grep -En 'test result: FAILED|panicked at|^test .* \.\.\. FAILED$|^failures:$|command not found' "${REPORT}" >&2
    exit 1
fi

require_regex "evidence header" '^RGK public testnet staging evidence$'
require_regex "UTC timestamp" '^timestamp_utc=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
require_regex "testnet URL" '^url=wss?://'
require_regex "wallet-set header" '^RGK public testnet staging wallet set$'
require_regex "wallet set id" '^wallet_set_id=0x[0-9a-f]{64}$'
require_regex "wallet count" '^wallet_count=3$'
require_regex "funding wallet" '^wallet_role=funding address=kaspatest:[a-z0-9]+ xonly=0x[0-9a-f]{64} secret_fingerprint=0x[0-9a-f]{64} required_min_value_real_zk=[1-9][0-9]* required_min_value_verifier_only=[1-9][0-9]* purpose=public-testnet-funding$'
require_regex "change wallet" '^wallet_role=change address=kaspatest:[a-z0-9]+ xonly=0x[0-9a-f]{64} secret_fingerprint=0x[0-9a-f]{64} required_min_value_real_zk=0 required_min_value_verifier_only=0 purpose=reserved-change-output-isolation$'
require_regex "observer wallet" '^wallet_role=observer address=kaspatest:[a-z0-9]+ xonly=0x[0-9a-f]{64} secret_fingerprint=0x[0-9a-f]{64} required_min_value_real_zk=0 required_min_value_verifier_only=0 purpose=observer-reporting-no-funding$'
require_regex "wallet verifier" '^\[verify-testnet-staging-wallets\] ok: .*latest\.txt$'
require_regex "preflight header" '^RGK public testnet staging preflight$'
require_regex "preflight network" '^network=testnet-(10|12)$'
require_regex "preflight chain id" '^chain_id=KaspaTestnet$'
require_regex "preflight funding address" '^address=kaspatest:[a-z0-9]+$'
require_regex "preflight wallet set id" '^wallet_set_id=0x[0-9a-f]{64}$'
require_regex "preflight wallet count" '^wallet_count=3$'
require_regex "preflight funding status" '^funding_status=external-funding-required$'
require_regex "preflight non-coinbase funding" '^required_non_coinbase_utxo=true$'
require_regex "preflight utxo index" '^required_utxo_index=true$'
require_regex "preflight confirmation depth" '^required_confirmation_depth=1$'
require_regex "preflight live wRPC feature" '^required_live_kaspa_wrpc_feature=true$'
require_regex "preflight real-zk feature" '^required_real_zk_feature=true$'
require_regex "preflight persistent indexer feature" '^required_persistent_indexer_feature=true$'
require_regex "preflight no local mining" '^required_local_mining=false$'
require_regex "preflight live covenant test" '^required_live_test=live_toccata_full_covenant_lifecycle$'
require_regex "preflight id" '^preflight_id=0x[0-9a-f]{64}$'
require_regex "preflight verifier" '^\[verify-testnet-staging-preflight\] ok: .*latest\.txt$'
require_regex "testnet connection" 'live: connected to testnet-(10|12) wRPC \(chain_id=KaspaTestnet\)'
require_regex "node identity" 'live: server_version=.* network_id=testnet-(10|12) .*has_utxo_index=true'
require_regex "Toccata transaction subnetwork" '^live: Toccata tx subnetwork=0x[0-9a-f]{40} gas=[0-9]+ mode=(native|user-lane)$'
require_regex "public funding address" 'live: public testnet staging funding address = kaspatest:[a-z0-9]+ required_min_value=[0-9]+ sompi'
require_regex "prefunded non-coinbase UTXO" 'live: selected funding UTXO at DAA [0-9]+ value=[0-9]+ coinbase=false'
require_regex "covenant funding accepted" 'live: covenant tx ACCEPTED by node'
require_regex "public covenant confirmation wait" 'live: waiting for public testnet-(10|12) confirmation of covenant tx'
require_regex "native issue digest" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*privacy_policy=PrivateLane .*lane_id=0x[0-9a-f]{64}'
require_regex "native metadata commitment" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*metadata_commitment=0x[0-9a-f]{64}'
require_regex "native owner commitment" 'live: native RGK asset state digest = 0x[0-9a-f]{64} .*owner_commitment=0x[0-9a-f]{64}'
require_regex "ZK covenant spend" 'live: ZK covenant spend enabled, public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+'
require_regex "covenant spend accepted" 'live: P2SH covenant spend ACCEPTED by node'
require_regex "public covenant spend confirmation wait" 'live: waiting for public testnet-(10|12) confirmation of covenant spend'
require_regex "continuation output confirmed" 'live: continuation covenant output confirmed at DAA score [0-9]+'
require_regex "native transition digest" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*privacy_policy=PrivateLane .*lane_id=0x[0-9a-f]{64}'
require_regex "native transition metadata commitment" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*metadata_commitment=0x[0-9a-f]{64}'
require_regex "native transition owner commitments" 'live: native RGK transition digest = 0x[0-9a-f]{64} .*previous_owner_commitment=0x[0-9a-f]{64} new_owner_commitment=0x[0-9a-f]{64} ownership_authorization_commitment=0x[0-9a-f]{64}'
require_regex "semantic transition metadata commitment" 'live: semantic RGK transition statement public_inputs=[0-9]+ .*metadata_commitment=0x[0-9a-f]{64}'
require_regex "semantic transition owner commitments" 'live: semantic RGK transition statement public_inputs=[0-9]+ .*previous_owner_commitment=0x[0-9a-f]{64} new_owner_commitment=0x[0-9a-f]{64} ownership_authorization_commitment=0x[0-9a-f]{64}'
require_regex "semantic Groth16 proof" 'live: semantic Groth16 proof verified public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+'
require_regex "allocation-vector Groth16 proof" 'live: supported allocation-vector Groth16 proof verified shape=1x1 public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+'
require_regex "allocation audit bundle" 'live: allocation audit bundle verified spent_segments=1 new_segments=1 exclusion_pairs=1 spent_final_root=0x[0-9a-f]{64} new_final_root=0x[0-9a-f]{64} spent_total_commitment=0x[0-9a-f]{64} new_total_commitment=0x[0-9a-f]{64}'
require_regex "self-contained allocation audit certificate" 'live: allocation audit certificate self-contained verified certificate_id=0x[0-9a-f]{64} proof_entries=6 canonical_bytes=[0-9]+'
require_regex "indexed allocation audit certificate" 'live: allocation audit certificate indexed certificate_id=0x[0-9a-f]{64} canonical_bytes=[0-9]+'
require_regex "public staging spend evidence" 'live: public staging spend evidence recorded directly funding_spend_txid=0x[0-9a-f]{64} covenant_spend_txid=0x[0-9a-f]{64} cursor_daa=[0-9]+ observed_spends=2'
require_regex "lane discovery" 'live: lane-discovery Groth16 proof verified public_inputs=[0-9]+ vk_bytes=[0-9]+ proof_bytes=[0-9]+ lane_id=0x[0-9a-f]{64} scan_tag=0x[0-9a-f]{64}'
require_regex "resolver classification" 'live: covenant transition classified as NativeTransitionedValid from the confirmed live Kaspa Toccata testnet-(10|12) spend'
require_regex "policy migration recovery" 'live: policy migration proof recovered after Sled reopen \(previous_policy=verifier-only new_policy=zk-or-verifier migration=0x[0-9a-f]{64} state_digest=0x[0-9a-f]{64} resolver=NativeTransitionedValid\)'
require_regex "persistent allocation audit certificate recovery" 'live: persistent allocation audit certificate recovered certificate_id=0x[0-9a-f]{64} canonical_bytes=[0-9]+'
require_regex "persistent indexer recovery" 'live: persistent indexer recovered covenant after resolver indexing'
require_regex "live covenant test pass" 'test live_toccata_full_covenant_lifecycle \.\.\. ok'

wallet_set_ids="$(sed -nE 's/^wallet_set_id=(0x[0-9a-f]{64})$/\1/p' "${REPORT}")"
wallet_set_id_count="$(printf '%s\n' "${wallet_set_ids}" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "${wallet_set_id_count}" -lt 2 ]; then
    echo "[verify-testnet-staging-evidence] expected wallet_set_id in wallet and preflight sections" >&2
    exit 1
fi
first_wallet_set_id="$(printf '%s\n' "${wallet_set_ids}" | sed '/^$/d' | head -n 1)"
last_wallet_set_id="$(printf '%s\n' "${wallet_set_ids}" | sed '/^$/d' | tail -n 1)"
if [ "${first_wallet_set_id}" != "${last_wallet_set_id}" ]; then
    echo "[verify-testnet-staging-evidence] wallet_set_id mismatch between wallet report and preflight" >&2
    exit 1
fi

funding_wallet_address="$(sed -nE 's/^wallet_role=funding address=([^ ]+) .*/\1/p' "${REPORT}" | head -n 1)"
preflight_address="$(sed -nE 's/^address=(kaspatest:[a-z0-9]+)$/\1/p' "${REPORT}" | head -n 1)"
if [ -z "${funding_wallet_address}" ] || [ -z "${preflight_address}" ] || [ "${funding_wallet_address}" != "${preflight_address}" ]; then
    echo "[verify-testnet-staging-evidence] funding wallet address must match preflight address" >&2
    exit 1
fi

echo "[verify-testnet-staging-evidence] ok: ${REPORT}"
