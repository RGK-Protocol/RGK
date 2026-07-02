#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_CONTRACT="${AVATO_RGK_CONTRACT:-${ROOT}/../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json}"
PORT="${RGK_WALLETD_CONTRACT_PORT:-$((18000 + ($$ % 10000)))}"
BASE_URL="http://127.0.0.1:${PORT}"
STATE="${RGK_WALLETD_CONTRACT_STATE:-${ROOT}/target/rgk-walletd/contract-smoke-${PORT}.json}"
LOG="${ROOT}/target/rgk-walletd/contract-smoke-${PORT}.log"

if [ ! -f "${FRONTEND_CONTRACT}" ]; then
    echo "[verify-avato-walletd-contract] missing frontend contract: ${FRONTEND_CONTRACT}" >&2
    exit 1
fi

mkdir -p "$(dirname "${STATE}")"
rm -f "${STATE}" "${LOG}"

(
    cd "${ROOT}"
    cargo run -q -p rgk-walletd -- \
        --listen "127.0.0.1:${PORT}" \
        --network local-toccata \
        --state "${STATE}"
) >"${LOG}" 2>&1 &
PID="$!"

cleanup() {
    kill "${PID}" >/dev/null 2>&1 || true
    wait "${PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 80); do
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

BASE_URL="${BASE_URL}" STATE="${STATE}" FRONTEND_CONTRACT="${FRONTEND_CONTRACT}" python3 - <<'PY'
import json
import os
import urllib.error
import urllib.request

base_url = os.environ["BASE_URL"]
state_path = os.environ["STATE"]
contract_path = os.environ["FRONTEND_CONTRACT"]

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
    return json.loads(body)

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
    "kaspaEndpoint": "ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh",
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
assert dashboard["lanes"], "dashboard must expose at least one RGK lane"
assert dashboard["proofs"], "dashboard must expose at least one RGK proof"
assert dashboard["lanes"][0]["resolverState"] in contract["enums"]["resolverState"]
assert dashboard["lanes"][0]["proofPolicy"] in contract["enums"]["receiptPolicy"]
assert dashboard["proofs"][0]["proofMode"] in contract["enums"]["proofMode"]
assert dashboard["proofs"][0]["verifierStatus"] in contract["enums"]["proofVerifierStatus"]
assert dashboard["scan"]["scanMode"] in contract["enums"]["scanMode"]

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

request("POST", "/proofs", {
    "laneId": "rgk:lane:missing",
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-orphan",
    "verifierStatus": "pending",
    "txid": "",
    "confirmations": 0,
}, expected_status=400)

proof = request("POST", "/proofs", {
    "laneId": lane["laneId"],
    "proofMode": "verifier-receipt",
    "receiptPolicy": "verifier-only",
    "strategy": "contract-smoke-verifier",
    "verifierStatus": "verified",
    "txid": "contract-smoke-txid",
    "confirmations": 1,
})
assert proof["strategy"] == "contract-smoke-verifier"
assert proof["verifierStatus"] == "verified"
assert proof["confirmations"] == 1

dashboard_after_actions = request("GET", "/dashboard")
assert any(item["laneId"] == lane["laneId"] for item in dashboard_after_actions["lanes"])
assert any(item["receiptId"] == proof["receiptId"] for item in dashboard_after_actions["proofs"])
updated_lane = next(item for item in dashboard_after_actions["lanes"] if item["laneId"] == lane["laneId"])
assert updated_lane["latestReceiptId"] == proof["receiptId"]
assert updated_lane["resolverState"] == "native-transitioned-valid"

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
unlocked = request("POST", "/wallet/unlock", {"passphrase": "contract-passphrase"})
assert unlocked["lifecycle"] == "ready"
request("POST", "/wallet/sync")

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
