#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_CONTRACT="${AVATO_RGK_CONTRACT:-${ROOT}/../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json}"
PORT="${RGK_WALLETD_CONTRACT_PORT:-$((18000 + ($$ % 10000)))}"
BASE_URL="http://127.0.0.1:${PORT}"
STATE="${RGK_WALLETD_CONTRACT_STATE:-${ROOT}/target/rgk-walletd/contract-smoke-${PORT}.json}"
SYNC_DB="${RGK_WALLETD_CONTRACT_SYNC_DB:-${ROOT}/target/rgk-walletd/contract-smoke-${PORT}.sled}"
KASPA_ENDPOINT="${RGK_WALLETD_CONTRACT_KASPA_ENDPOINT:-ws://127.0.0.1:9/v2/kaspa/simnet/no-tls/wrpc/borsh}"
LOG="${ROOT}/target/rgk-walletd/contract-smoke-${PORT}.log"

if [ ! -f "${FRONTEND_CONTRACT}" ]; then
    echo "[verify-avato-walletd-contract] missing frontend contract: ${FRONTEND_CONTRACT}" >&2
    exit 1
fi

mkdir -p "$(dirname "${STATE}")"
rm -f "${STATE}" "${LOG}"
rm -rf "${SYNC_DB}"

(
    cd "${ROOT}"
    cargo run -q -p rgk-walletd -- \
        --listen "127.0.0.1:${PORT}" \
        --network local-toccata \
        --kaspa-endpoint "${KASPA_ENDPOINT}" \
        --state "${STATE}" \
        --sync-db "${SYNC_DB}"
) >"${LOG}" 2>&1 &
PID="$!"

cleanup() {
    kill "${PID}" >/dev/null 2>&1 || true
    wait "${PID}" >/dev/null 2>&1 || true
    rm -rf "${SYNC_DB}"
}
trap cleanup EXIT

for _ in $(seq 1 240); do
    if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    echo "[verify-avato-walletd-contract] rgk-walletd did not become healthy" >&2
    cat "${LOG}" >&2 || true
    exit 1
fi

BASE_URL="${BASE_URL}" STATE="${STATE}" FRONTEND_CONTRACT="${FRONTEND_CONTRACT}" KASPA_ENDPOINT="${KASPA_ENDPOINT}" python3 - <<'PY'
import json
import os
import urllib.error
import urllib.request

base_url = os.environ["BASE_URL"]
state_path = os.environ["STATE"]
contract_path = os.environ["FRONTEND_CONTRACT"]
kaspa_endpoint = os.environ["KASPA_ENDPOINT"]

with open(contract_path, "r", encoding="utf-8") as handle:
    contract = json.load(handle)

expected_endpoints = {
    ("GET", "/health"),
    ("GET", "/wallet/profile"),
    ("POST", "/wallets"),
    ("POST", "/wallet/import"),
    ("POST", "/wallet/lock"),
    ("POST", "/wallet/unlock"),
    ("POST", "/wallet/kaspa-endpoint"),
    ("POST", "/wallet/sync"),
    ("GET", "/dashboard"),
    ("POST", "/lanes"),
    ("POST", "/proofs"),
    ("POST", "/transitions"),
}
contract_endpoints = {
    (endpoint["method"], endpoint["path"]) for endpoint in contract["endpoints"]
}
missing = expected_endpoints - contract_endpoints
assert not missing, f"frontend contract missing endpoints: {sorted(missing)}"

def request(method, path, payload=None, expected_status=200):
    data = None
    headers = {"accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(
        f"{base_url}{path}", data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        body = error.read()
        status = error.code

    assert status == expected_status, (
        f"{method} {path} expected {expected_status}, got {status}: "
        f"{body.decode('utf-8', 'replace')}"
    )
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        assert expected_status >= 400, (
            f"{method} {path} returned non-JSON body for status {status}: "
            f"{body.decode('utf-8', 'replace')}"
        )
        return body.decode("utf-8", "replace")

def assert_hex32(value, label):
    assert isinstance(value, str), f"{label} must be a string"
    assert value.startswith("0x") and len(value) == 66, (
        f"{label} must be a 32-byte 0x-prefixed hex value, got {value}"
    )
    int(value[2:], 16)

def assert_handle_hex32(value, label):
    assert_hex32(value.rsplit(":", 1)[-1], label)

def assert_hex_blob(value, label):
    assert isinstance(value, str), f"{label} must be a string"
    assert value.startswith("0x") and len(value) > 66 and len(value) % 2 == 0, (
        f"{label} must be non-empty 0x-prefixed hex bytes, got {value}"
    )
    int(value[2:], 16)

def hex32(byte):
    return "0x" + f"{byte:02x}" * 32

def txid(byte):
    return f"{byte:02x}" * 32

health = request("GET", "/health")
assert health["service"] == "rgk-wallet"
assert health["protocol"] == "rgk"
assert health["networkId"] == "rgk:kaspa-local-toccata"
assert health["protocolNetworkId"] == "kaspa-local-toccata"
assert health["canonicalChainDomain"] == "kaspa-local-toccata"
assert health["canonicalChainDomain"] in contract["enums"]["canonicalChainDomain"]
assert health["protocolNetworkId"] in contract["enums"]["protocolNetworkId"]

request("GET", "/wallet/profile", expected_status=404)

valid_payload = {
    "walletId": "avato-contract-smoke",
    "networkId": "rgk:kaspa-local-toccata",
    "protocolNetworkId": "kaspa-local-toccata",
    "canonicalChainDomain": "kaspa-local-toccata",
    "kaspaEndpoint": kaspa_endpoint,
    "passphrase": "contract-passphrase",
    "recoveryPhrase": [
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "abandon",
        "about",
    ],
}

wrong_network = dict(valid_payload)
wrong_network["networkId"] = "rgk:testnet-12"
wrong_network["protocolNetworkId"] = "testnet-12"
wrong_network["canonicalChainDomain"] = "kaspa-testnet"
request("POST", "/wallets", wrong_network, expected_status=400)

stale_wallet = dict(valid_payload)
stale_wallet["unexpectedField"] = "stale-client"
request("POST", "/wallets", stale_wallet, expected_status=422)

bad_wallet_id = dict(valid_payload)
bad_wallet_id["walletId"] = "bad wallet id"
request("POST", "/wallets", bad_wallet_id, expected_status=400)

bad_endpoint = dict(valid_payload)
bad_endpoint["kaspaEndpoint"] = "https://example.invalid/not-wrpc"
request("POST", "/wallets", bad_endpoint, expected_status=400)

profile = request("POST", "/wallets", valid_payload)
assert profile["walletId"] == "avato-contract-smoke"
assert profile["protocol"] == "rgk"
assert profile["networkId"] == "rgk:kaspa-local-toccata"
assert profile["protocolNetworkId"] == "kaspa-local-toccata"
assert profile["canonicalChainDomain"] == "kaspa-local-toccata"
assert profile["lifecycle"] == "ready"
assert profile["lifecycle"] in contract["enums"]["walletLifecycle"]
assert profile["identityVaultStatus"] == "unlocked"
assert profile["identityVaultStatus"] in contract["enums"]["identityVaultStatus"]
assert_hex32(profile["identityFingerprint"], "identityFingerprint")
assert profile["address"].startswith("kaspasim:")

bad_update_endpoint = {"kaspaEndpoint": "https://example.invalid/not-wrpc"}
request("POST", "/wallet/kaspa-endpoint", bad_update_endpoint, expected_status=400)

stale_update_endpoint = {
    "kaspaEndpoint": kaspa_endpoint,
    "unexpectedField": "stale-client",
}
request("POST", "/wallet/kaspa-endpoint", stale_update_endpoint, expected_status=422)

updated_kaspa_endpoint = "ws://127.0.0.1:10/v2/kaspa/simnet/no-tls/wrpc/borsh"
profile = request(
    "POST",
    "/wallet/kaspa-endpoint",
    {"kaspaEndpoint": updated_kaspa_endpoint},
)
assert profile["kaspaEndpoint"] == updated_kaspa_endpoint
assert profile["lifecycle"] == "ready"

stored_profile = request("GET", "/wallet/profile")
assert stored_profile == profile

dashboard = request("GET", "/dashboard")
assert dashboard["profile"] == profile
assert dashboard["serviceMode"] == "connected"
assert dashboard["serviceMode"] in contract["enums"]["serviceMode"]
assert dashboard["lanes"] == [], "new wallet must not invent RGK lanes"
assert dashboard["proofs"] == [], "new wallet must not invent RGK proofs"
assert dashboard["scan"]["scanMode"] in contract["enums"]["scanMode"]

request("POST", "/lanes", {
    "label": "Bad ticker lane",
    "ticker": "bad",
    "balance": "1.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
    "covenantId": "",
    "lineageId": "",
    "assetId": "",
    "laneId": "",
    "scanTag": "",
    "stateDigest": "",
    "openTxid": "",
    "openIndex": 0,
    "epoch": 0,
    "daaScore": 0,
}, expected_status=400)

request("POST", "/lanes", {
    "label": "Bad balance lane",
    "ticker": "BAD",
    "balance": "-1.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
    "covenantId": "",
    "lineageId": "",
    "assetId": "",
    "laneId": "",
    "scanTag": "",
    "stateDigest": "",
    "openTxid": "",
    "openIndex": 0,
    "epoch": 0,
    "daaScore": 0,
}, expected_status=400)

request("POST", "/lanes", {
    "label": "Stale lane",
    "ticker": "STL",
    "balance": "1.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
    "covenantId": "",
    "lineageId": "",
    "assetId": "",
    "laneId": "",
    "scanTag": "",
    "stateDigest": "",
    "openTxid": "",
    "openIndex": 0,
    "epoch": 0,
    "daaScore": 0,
    "unexpectedField": "stale-client",
}, expected_status=422)

empty_lane_evidence = {
    "covenantId": "",
    "lineageId": "",
    "assetId": "",
    "laneId": "",
    "scanTag": "",
    "stateDigest": "",
    "openTxid": "",
    "openIndex": 0,
    "epoch": 0,
    "daaScore": 0,
}

partial_lane_evidence = dict(empty_lane_evidence)
partial_lane_evidence["covenantId"] = hex32(0x61)
request("POST", "/lanes", {
    "label": "Partial indexed lane",
    "ticker": "IDX",
    "balance": "1.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
    **partial_lane_evidence,
}, expected_status=400)

lane = request("POST", "/lanes", {
    "label": "Contract smoke public lane",
    "ticker": "SMK",
    "balance": "42.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
    **empty_lane_evidence,
})
assert lane["label"] == "Contract smoke public lane"
assert lane["privacy"] == "public-lineage"
assert lane["proofPolicy"] == "verifier-only"
assert lane["resolverState"] in contract["enums"]["resolverState"]
assert lane["resolverState"] == "unknown"
assert_handle_hex32(lane["lineageId"], "lineageId")
assert_handle_hex32(lane["laneId"], "laneId")
assert_hex32(lane["covenantId"], "covenantId")
assert_hex32(lane["stateDigest"], "stateDigest")

indexed_lane_evidence = {
    "covenantId": hex32(0x61),
    "lineageId": hex32(0x62),
    "assetId": hex32(0x63),
    "laneId": hex32(0x64),
    "scanTag": hex32(0x65),
    "stateDigest": hex32(0x66),
    "openTxid": txid(0x67),
    "openIndex": 2,
    "epoch": 7,
    "daaScore": 13,
}

indexed_lane = request("POST", "/lanes", {
    "label": "Contract smoke indexed lane",
    "ticker": "IDX",
    "balance": "7.0000",
    "privacy": "private-lane",
    "proofPolicy": "verifier-only",
    **indexed_lane_evidence,
})
assert indexed_lane["label"] == "Contract smoke indexed lane"
assert indexed_lane["lineageId"] == f"rgk:lineage:{indexed_lane_evidence['lineageId']}"
assert indexed_lane["laneId"] == f"rgk:lane:private:{indexed_lane_evidence['laneId']}"
assert indexed_lane["covenantId"] == indexed_lane_evidence["covenantId"]
assert indexed_lane["stateDigest"] == indexed_lane_evidence["stateDigest"]
assert indexed_lane["resolverState"] == "unknown"

transition_payload = {
    "laneId": indexed_lane["laneId"],
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-transition",
    "newStateDigest": hex32(0x68),
    "transitionDigest": hex32(0x69),
    "continuationCommitment": hex32(0x6a),
    "continuationShapeRoot": hex32(0x6b),
    "newTxid": txid(0x6c),
    "newIndex": 3,
    "daaScore": 21,
}

metadata_only_transition = dict(transition_payload)
metadata_only_transition["laneId"] = lane["laneId"]
request("POST", "/transitions", metadata_only_transition, expected_status=400)

stale_transition = dict(transition_payload)
stale_transition["unexpectedField"] = "stale-client"
request("POST", "/transitions", stale_transition, expected_status=422)

transition = request("POST", "/transitions", transition_payload)
assert transition["strategy"] == "contract-smoke-transition"
assert transition["verifierStatus"] == "verified"
assert transition["receiptPolicy"] == "verifier-only"
assert transition["proofMode"] == "verifier-receipt"
assert transition["txid"] == txid(0x6c)
assert transition["confirmations"] == 0
assert_handle_hex32(transition["receiptId"], "transition receiptId")
assert_hex_blob(transition["receiptBytes"], "transition receiptBytes")
assert transition["transitionDigest"] == hex32(0x69)
assert transition["continuationCommitment"] == hex32(0x6a)
assert transition["continuationShapeRoot"] == hex32(0x6b)
assert transition["newStateDigest"] == hex32(0x68)

empty_proof_evidence = {
    "receiptBytes": "",
    "covenantId": "",
    "spentTxid": "",
    "spentIndex": 0,
    "newTxid": "",
    "newIndex": 0,
    "continuationShapeRoot": "",
    "daaScore": 0,
}

request("POST", "/proofs", {
    "laneId": "rgk:lane:missing",
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-orphan",
    "txid": "",
    "confirmations": 0,
    **empty_proof_evidence,
}, expected_status=400)

request("POST", "/proofs", {
    "laneId": lane["laneId"],
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-stale-client",
    "verifierStatus": "verified",
    "txid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "confirmations": 1,
    **empty_proof_evidence,
}, expected_status=422)

request("POST", "/proofs", {
    "laneId": lane["laneId"],
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-bad-txid",
    "txid": "contract-smoke-txid",
    "confirmations": 1,
    **empty_proof_evidence,
}, expected_status=400)

partial_evidence = dict(empty_proof_evidence)
partial_evidence["receiptBytes"] = "abcd"
request("POST", "/proofs", {
    "laneId": lane["laneId"],
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-partial-evidence",
    "txid": "",
    "confirmations": 0,
    **partial_evidence,
}, expected_status=400)

proof = request("POST", "/proofs", {
    "laneId": lane["laneId"],
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-verifier",
    "txid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "confirmations": 1,
    **empty_proof_evidence,
})
assert proof["strategy"] == "contract-smoke-verifier"
assert proof["verifierStatus"] == "pending"
assert proof["confirmations"] == 1
assert_handle_hex32(proof["receiptId"], "receiptId")

dashboard_after_actions = request("GET", "/dashboard")
assert len(dashboard_after_actions["lanes"]) == 2
assert len(dashboard_after_actions["proofs"]) == 2
assert dashboard_after_actions["scan"]["indexedSpends"] == 0
assert dashboard_after_actions["scan"]["observedSpends"] == 0
assert any(item["laneId"] == lane["laneId"] for item in dashboard_after_actions["lanes"])
assert any(item["laneId"] == indexed_lane["laneId"] for item in dashboard_after_actions["lanes"])
assert any(item["receiptId"] == proof["receiptId"] for item in dashboard_after_actions["proofs"])
assert any(item["receiptId"] == transition["receiptId"] for item in dashboard_after_actions["proofs"])
dashboard_transition = next(item for item in dashboard_after_actions["proofs"] if item["receiptId"] == transition["receiptId"])
assert dashboard_transition["receiptBytes"] == transition["receiptBytes"]
assert dashboard_transition["transitionDigest"] == hex32(0x69)
updated_lane = next(item for item in dashboard_after_actions["lanes"] if item["laneId"] == lane["laneId"])
assert updated_lane["latestReceiptId"] == proof["receiptId"]
assert updated_lane["resolverState"] == lane["resolverState"]
updated_indexed_lane = next(item for item in dashboard_after_actions["lanes"] if item["laneId"] == indexed_lane["laneId"])
assert updated_indexed_lane["latestReceiptId"] == transition["receiptId"]
assert updated_indexed_lane["stateDigest"] == hex32(0x68)

request("POST", "/wallet/lock", expected_status=204)
request("GET", "/dashboard", expected_status=401)
request(
    "POST",
    "/wallet/kaspa-endpoint",
    {"kaspaEndpoint": kaspa_endpoint},
    expected_status=401,
)
request("POST", "/lanes", {
    "label": "Locked lane",
    "ticker": "LCK",
    "balance": "0",
    "privacy": "private-lane",
    "proofPolicy": "zk-or-verifier",
    **empty_lane_evidence,
}, expected_status=401)
request(
    "POST",
    "/wallet/unlock",
    {"passphrase": "incorrect-passphrase"},
    expected_status=401,
)
request(
    "POST",
    "/wallet/unlock",
    {"passphrase": "contract-passphrase", "unexpectedField": "stale-client"},
    expected_status=422,
)
unlocked = request("POST", "/wallet/unlock", {"passphrase": "contract-passphrase"})
assert unlocked["lifecycle"] == "ready"
assert unlocked["identityVaultStatus"] == "unlocked"
assert unlocked["identityFingerprint"] == profile["identityFingerprint"]
assert unlocked["address"] == profile["address"]
sync_dashboard = request("POST", "/wallet/sync")
assert sync_dashboard["profile"]["lifecycle"] == "service-required"
assert sync_dashboard["profile"]["identityVaultStatus"] == "unlocked"
assert sync_dashboard["scan"]["scanMode"] == "unavailable"
assert sync_dashboard["serviceMode"] == "unavailable"
assert "scanner unavailable" in sync_dashboard["serviceNotice"].lower()

with open(state_path, "r", encoding="utf-8") as handle:
    state_text = handle.read()

assert "contract-passphrase" not in state_text
assert "abandon" not in state_text
state_json = json.loads(state_text)
assert state_json["profile"]["lifecycle"] == "locked"
assert state_json["profile"]["identityVaultStatus"] == "encrypted"
assert state_json["profile"]["identityFingerprint"] == profile["identityFingerprint"]
assert state_json["profile"]["address"] == profile["address"]
assert state_json["profile"]["kaspaEndpoint"] == updated_kaspa_endpoint
assert state_json["identityVault"]["cipher"] == "xchacha20poly1305"
assert state_json["identityVault"]["kdf"]["algorithm"] == "argon2id"
assert state_json["passphraseVerifier"].startswith("argon2id:v2:")
assert "passphraseSalt" in state_text
assert "passphraseVerifier" in state_text
assert "identityVault" in state_text

if os.name == "posix":
    mode = os.stat(state_path).st_mode & 0o777
    assert mode & 0o077 == 0, (
        f"state file must not be group/world readable, got {oct(mode)}"
    )

print("[verify-avato-walletd-contract] ok")
PY
