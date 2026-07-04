# Runbook / Funding

> **Canonical source:** [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md).
> See also [Concepts / Funding](../Concepts/Funding.md) for the
> operator-side walkthrough.

This page is a one-screen operator summary for the funding flow.

---

## Frozen Snapshot (testnet-12)

| Field | Value |
| --- | --- |
| Network | `testnet-12` |
| Chain id | `KaspaTestnet` |
| `wallet_set_id` | `0x319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352` |
| `preflight_id` | `0x2c993d20f2726efdb0983868126544163e44c474f4b4ab4cf28901e749c29212` |
| Funding address | `kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald` |
| `required_min_value_real_zk` | `45000000` sompi |
| `required_min_value_verifier_only` | `9000000` sompi |

See [Reference / Testnet Staging Snapshot](../Reference/Testnet-Staging-Snapshot.md).

---

## The 7-Step Happy Path

```bash
# 1. Print the deterministic funding address
cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address

# 2. Generate the wallet set
bash scripts/e2e-testnet-staging.sh --wallets

# 3. Run the preflight (read-only)
bash scripts/e2e-testnet-staging.sh --preflight
bash scripts/verify-testnet-staging-preflight.sh

# 4. Funding-readiness check (read-only, before funds arrive)
cargo run -p rgk-e2e --features live-kaspa-wrpc \
    --bin rgk-testnet-funding-readiness -- \
    testnet-12 ws://127.0.0.1:18311/v2/kaspa/testnet-12/no-tls/wrpc/borsh
bash scripts/verify-testnet-funding-readiness.sh

# 5. Send testnet funds to the funding address (from a faucet or external wallet)
#    NEVER send mainnet KAS.

# 6. Resume the staging run
bash scripts/e2e-testnet-staging.sh --resume

# 7. Verify the evidence
bash scripts/verify-testnet-staging-evidence.sh
```

For the per-step details, see [Concepts / Funding](../Concepts/Funding.md).

---

## Network and Endpoint Env Vars

| Env var | Default | Notes |
| --- | --- | --- |
| `RGK_LIVE_KASPA_NETWORK` | `testnet-12` | Must match the preflight network. |
| `RGK_LIVE_KASPA_URL` | (network default) | wRPC borsh endpoint. |
| `RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE` | (per script) | For Toccata tx subnetwork. |
| `RGK_LIVE_KASPA_GAS` | (per script) | For Toccata tx gas. |

---

## Required Report Line

The evidence report must include:

```text
live: Toccata tx subnetwork=… gas=… mode=…
```

`verify-testnet-staging-evidence.sh` regex-matches this line.

---

## Common Pitfalls (5)

| Pitfall | Fix |
| --- | --- |
| Targeting `testnet-10` instead of `testnet-12`. | Set `RGK_LIVE_KASPA_NETWORK=testnet-12` and re-run `--wallets` + `--preflight`. |
| Re-running `--wallets` after funding. | Don't. The preflight is pinned to a specific `wallet_set_id`. |
| Sending mainnet KAS to the testnet funding address. | Don't. There is no recovery path. |
| Mixing evidence from different runs. | Each `--resume` overwrites `latest.txt`. Move old files aside. |
| Forgetting `--features live-kaspa-wrpc`. | The bin won't compile without it. |

---

## Cross-references

- [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md) —
  canonical source.
- [Concepts / Funding](../Concepts/Funding.md) — full walkthrough.
- [Reference / Testnet Staging Snapshot](../Reference/Testnet-Staging-Snapshot.md).
- [Runbook / Launch Gates](./Launch-Gates.md).