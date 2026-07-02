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
    ("POST", "/wallet/sync"),
    ("GET", "/dashboard"),
    ("POST", "/lanes"),
    ("POST", "/proofs"),
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
}, expected_status=400)

request("POST", "/lanes", {
    "label": "Bad balance lane",
    "ticker": "BAD",
    "balance": "-1.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
}, expected_status=400)

request("POST", "/lanes", {
    "label": "Stale lane",
    "ticker": "STL",
    "balance": "1.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
    "unexpectedField": "stale-client",
}, expected_status=422)

lane = request("POST", "/lanes", {
    "label": "Contract smoke public lane",
    "ticker": "SMK",
    "balance": "42.0000",
    "privacy": "public-lineage",
    "proofPolicy": "verifier-only",
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
assert len(dashboard_after_actions["lanes"]) == 1
assert len(dashboard_after_actions["proofs"]) == 1
assert dashboard_after_actions["scan"]["indexedSpends"] == 0
assert dashboard_after_actions["scan"]["observedSpends"] == 0
assert any(item["laneId"] == lane["laneId"] for item in dashboard_after_actions["lanes"])
assert any(item["receiptId"] == proof["receiptId"] for item in dashboard_after_actions["proofs"])
updated_lane = next(item for item in dashboard_after_actions["lanes"] if item["laneId"] == lane["laneId"])
assert updated_lane["latestReceiptId"] == proof["receiptId"]
assert updated_lane["resolverState"] == lane["resolverState"]

request("POST", "/wallet/lock", expected_status=204)
request("GET", "/dashboard", expected_status=401)
request("POST", "/lanes", {
    "label": "Locked lane",
    "ticker": "LCK",
    "balance": "0",
    "privacy": "private-lane",
    "proofPolicy": "zk-or-verifier",
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
sync_dashboard = request("POST", "/wallet/sync")
assert sync_dashboard["profile"]["lifecycle"] == "service-required"
assert sync_dashboard["scan"]["scanMode"] == "unavailable"
assert sync_dashboard["serviceMode"] == "unavailable"
assert "scanner unavailable" in sync_dashboard["serviceNotice"].lower()

with open(state_path, "r", encoding="utf-8") as handle:
    state_text = handle.read()

assert "contract-passphrase" not in state_text
assert "abandon" not in state_text
assert "passphraseSalt" in state_text
assert "passphraseVerifier" in state_text

if os.name == "posix":
    mode = os.stat(state_path).st_mode & 0o777
    assert mode & 0o077 == 0, (
        f"state file must not be group/world readable, got {oct(mode)}"
    )

print("[verify-avato-walletd-contract] ok")
PY
