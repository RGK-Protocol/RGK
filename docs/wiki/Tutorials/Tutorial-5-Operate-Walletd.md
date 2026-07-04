# Tutorial 5 — Operate rgk-walletd

> **Read time:** ~30 minutes. **Operator-facing.** How to launch the
> Avato frontend's local HTTP daemon, point it at a Kaspa node, and verify
> the contract.

This tutorial is the production-side companion to
[Concepts / Walletd Boundary](../Concepts/Walletd-Boundary.md). The
canonical doc is [`docs/AVATO-WALLETD.md`](../../AVATO-WALLETD.md).

---

## Prerequisites

- `cargo build -p rgk-walletd` succeeds.
- A Kaspa node reachable via wRPC (simnet, devnet, testnet, or mainnet).
- The Avato frontend checkout (use `AVATO_RGK_REPO` to override the
  default developer-local path).

---

## Step 1 — Launch the Daemon

```bash
cargo run -p rgk-walletd -- \
    --listen 127.0.0.1:8788 \
    --network local-toccata \
    --state target/rgk-walletd/state.json \
    --sync-db target/rgk-walletd/sync-db \
    --kaspa-endpoint ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh
```

Or via env vars:

```bash
RGK_WALLETD_LISTEN=127.0.0.1:8788 \
RGK_WALLETD_NETWORK=local-toccata \
RGK_WALLETD_STATE=target/rgk-walletd/state.json \
RGK_SYNC_DB=target/rgk-walletd/sync-db \
RGK_LIVE_KASPA_URL=ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh \
    cargo run -p rgk-walletd
```

| Flag | Env | Default |
| --- | --- | --- |
| `--listen <addr>` | `RGK_WALLETD_LISTEN` | `127.0.0.1:8788` |
| `--network <kind>` | `RGK_WALLETD_NETWORK` | `local-toccata` |
| `--state <path>` | `RGK_WALLETD_STATE` | `target/rgk-walletd/state.json` |
| `--sync-db <path>` | `RGK_SYNC_DB` | `target/rgk-walletd/sync-db` |
| `--kaspa-endpoint <url>` | `RGK_LIVE_KASPA_URL` | network default |

The supported `--network` values: `mainnet`, `testnet-10`, `testnet-12`,
`devnet`, `simnet`, `local-toccata`.

---

## Step 2 — Health Check

```bash
curl -sS http://127.0.0.1:8788/health
```

Expected response: a small JSON object with `status: ok` and the daemon
version. Exit `0`.

---

## Step 3 — Create a Wallet

```bash
curl -sS -X POST http://127.0.0.1:8788/wallets \
    -H 'Content-Type: application/json' \
    -d '{
      "name": "alice",
      "passphrase": "..."
    }'
```

The daemon returns:

- A new wallet profile (no secrets).
- The deterministic address (the wallet-side public key).
- `identityVaultStatus: locked`.

The recovery phrase and passphrase are **never** persisted to disk in
cleartext. They are encrypted with Argon2id + XChaCha20-Poly1305 into the
identity vault, which is held in memory while unlocked.

---

## Step 4 — Unlock the Vault

```bash
curl -sS -X POST http://127.0.0.1:8788/wallet/unlock \
    -H 'Content-Type: application/json' \
    -d '{
      "name": "alice",
      "passphrase": "..."
    }'
```

The daemon returns `identityVaultStatus: ready` and the address.

---

## Step 5 — Register a Lane

```bash
curl -sS -X POST http://127.0.0.1:8788/lanes \
    -H 'Content-Type: application/json' \
    -d '{
      "lane_id": "0x…",
      "asset_id": "0x…",
      "covenant_id": "0x…",
      "epoch": 1,
      "scan_tag": "0x…"
    }'
```

This is the **metadata-only** mode. The lane is registered as `unknown`
until evidence arrives.

For a full-evidence bundle, include the `transition_report` and
`continuation_proof`:

```bash
curl -sS -X POST http://127.0.0.1:8788/lanes \
    -H 'Content-Type: application/json' \
    -d '{
      "lane_id": "0x…",
      "asset_id": "0x…",
      "covenant_id": "0x…",
      "epoch": 1,
      "scan_tag": "0x…",
      "transition_report": { ... },
      "continuation_proof": { ... }
    }'
```

The daemon verifies, attaches, and marks the lane `known`.

---

## Step 6 — Stage a Proof

```bash
curl -sS -X POST http://127.0.0.1:8788/proofs \
    -H 'Content-Type: application/json' \
    -d '{
      "covenant_id": "0x…",
      "receipt_bytes": "0x…",
      "expected_old_state": "0x…",
      "verifier_chain": "KaspaLocalToccata"
    }'
```

The daemon stages the proof as `pending`, runs `ReceiptVerifier::verify_local`,
and updates the status to `verified` (or rejects).

---

## Step 7 — Build a Transition

```bash
curl -sS -X POST http://127.0.0.1:8788/transitions \
    -H 'Content-Type: application/json' \
    -d '{
      "covenant_id": "0x…",
      "new_allocations": [ ... ],
      "burn": null,
      "ownership_authorization_commitment": "0x…"
    }'
```

The daemon builds the receipt, signs the covenant spend envelope, and
returns the unsigned transaction. The wallet frontend (Avato) signs and
broadcasts.

---

## Step 8 — Sync Once

```bash
curl -sS -X POST http://127.0.0.1:8788/wallet/sync
```

This drives one `rgk-sync` tick against the configured `--kaspa-endpoint`,
re-resolves dashboard lanes, and returns a summary.

For continuous sync, run the daemon with `--forever`-equivalent behavior
(loop every `--poll-ms`):

```bash
cargo run -p rgk-sync -- \
    --url ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh \
    --network simnet \
    --db target/rgk-sync/db \
    --forever
```

This is a separate binary; `rgk-walletd` does **not** loop on its own
(you'd typically run both in production, or call `/wallet/sync` from a
cron-like external trigger).

---

## Step 9 — View the Dashboard

```bash
curl -sS http://127.0.0.1:8788/dashboard
```

Returns the aggregated view: lanes, proofs, transitions, resolver
classifications, sync status.

---

## Step 10 — Verify the Contract

```bash
bash scripts/verify-avato-walletd-contract.sh
```

This spins up `rgk-walletd`, then a Python harness hits every endpoint
and asserts strict 4xx semantics for malformed inputs. The contract file
is at `../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json`
(use `AVATO_RGK_REPO` to override the developer-local path).

The verifier catches:

- Unknown fields (the daemon refuses frontend-supplied state).
- User-string normalisation (the daemon canonicalises; the frontend
  cannot smuggle variants).
- Chain-domain mismatches (the daemon refuses a frontend-selected chain
  domain that differs from `--network`).
- Malformed payloads (4xx with specific error codes).
- Missing required fields (4xx).

---

## Frontend Launch

```bash
VITE_RGK_API_BASE_URL=http://127.0.0.1:8788 pnpm dev:rgk
```

This launches the Avato browser frontend pointing at the local daemon.
The frontend talks to the daemon over HTTP and never sees the underlying
Kaspa node directly.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `502 Bad Gateway` from `/health`. | Daemon not running. | Re-launch with the right `--listen` and `--state`. |
| `401 Unauthorized` from `/wallet/unlock`. | Wrong passphrase. | Re-derive with the correct passphrase. |
| `409 Conflict` from `/wallets`. | A wallet with the same name already exists. | Use a different name or `/wallet/import` an existing one. |
| `422 Unprocessable Entity` from `/lanes`. | Missing or malformed fields. | Check the response body for the specific field error. |
| `503 Service Unavailable` from `/wallet/sync`. | The Kaspa node is unreachable. | Verify `--kaspa-endpoint` and that the node is running. |
| Chain-domain mismatch. | Frontend picked the wrong chain. | The daemon refuses; have the frontend re-read the configured `--network`. |

---

## Cross-references

- [`docs/AVATO-WALLETD.md`](../../AVATO-WALLETD.md) — the canonical doc.
- [Concepts / Walletd Boundary](../Concepts/Walletd-Boundary.md) — what
  is and isn't in scope.
- [Concepts / Privacy](../Concepts/Privacy.md) — the `PrivacyMode`
  subset.
- [Tutorial-4](./Tutorial-4-Run-E2E-Harness.md) — running the broader
  e2e harness.
- [`scripts/verify-avato-walletd-contract.sh`](../../scripts/verify-avato-walletd-contract.sh) —
  the contract verifier.