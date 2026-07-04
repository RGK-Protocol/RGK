# Reference / Testnet Staging Snapshot

> **Canonical source:** [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md).

This page republishes the frozen wallet set and preflight contract for
`testnet-12`. The values are pinned and must not be regenerated without
publishing a new preflight manifest.

> **It is testnet-only material.** It must not be used for mainnet funds.

---

## Network and Chain

| Field | Value |
| --- | --- |
| Network | `testnet-12` |
| Chain id | `KaspaTestnet` |
| `wallet_set_id` | `0x319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352` |
| `preflight_id` | `0x2c993d20f2726efdb0983868126544163e44c474f4b4ab4cf28901e749c29212` |

---

## Wallet Set (3 roles)

### `funding`

| Field | Value |
| --- | --- |
| Address | `kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald` |
| `required_min_value_real_zk` | `45000000` sompi |
| `required_min_value_verifier_only` | `9000000` sompi |
| Purpose | Funds the staging run; signs issuance + transfers. |

> **Only `funding` needs public testnet funds.** `change` and `observer`
> do not need funding.

### `change`

Reserved change-output isolation. Does not need funding.

### `observer`

Reads receipts and resolver state, no signing. Does not need funding.

The verifier `scripts/verify-testnet-staging-wallets.sh` enforces that
**no `secret_key`, `private_key`, or `privkey` field appears in the
manifest**. Public staging evidence must never leak a secret.

---

## Preflight Manifest

The preflight binds:

- Network: `testnet-12`.
- Chain id: `KaspaTestnet`.
- Address: the funding address above.
- `wallet_set_id`: the value above.
- `funding_status`: `pending` until the funding address is funded.
- Requirements: `required_min_value_real_zk` + `required_min_value_verifier_only`.

`preflight_id` is the SHA-256 (or equivalent) of the canonical manifest.

---

## Current Status

| Item | Status |
| --- | --- |
| Wallet set | Machine-verified locally. |
| Preflight manifest | Machine-verified locally. |
| Funded public run | **Separate**. See [Concepts / Funding](../Concepts/Funding.md). |

The launch audit's strict mode remains non-zero until
`public_testnet_funded_report=ok`. Relaxed mode (`--allow-blocked`)
accepts `funding_readiness=blocked` only when the preflight and wallet
set match.

---

## Funding-Readiness Check

```bash
cargo run -p rgk-e2e --features live-kaspa-wrpc \
    --bin rgk-testnet-funding-readiness -- \
    testnet-12 ws://127.0.0.1:18311/v2/kaspa/testnet-12/no-tls/wrpc/borsh
```

Or via env vars:

```bash
RGK_LIVE_KASPA_NETWORK=testnet-12 \
RGK_LIVE_KASPA_URL=ws://... \
    cargo run -p rgk-e2e --features live-kaspa-wrpc \
        --bin rgk-testnet-funding-readiness
```

Verify with:

```bash
bash scripts/verify-testnet-funding-readiness.sh
```

See [Concepts / Funding](../Concepts/Funding.md) for the full happy-path.

---

## What "Frozen Snapshot, Not Config" Means

The values above are **load-bearing** for the current launch audit. They
are stable across local regenerations. If you intentionally regenerate
the wallet set:

1. Re-run `bash scripts/e2e-testnet-staging.sh --wallets`.
2. Re-run `bash scripts/e2e-testnet-staging.sh --preflight`.
3. Both will produce a new `wallet_set_id` / `preflight_id`.
4. The launch audit will reject evidence that pairs the new wallet set
   with the old preflight, and vice versa.

If you did **not** intend to publish a new preflight, **do not
regenerate**. Treat the values above as read-only.

---

## Cross-references

- [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md) —
  canonical source.
- [Concepts / Funding](../Concepts/Funding.md) — the full happy-path.
- [Runbook / Funding](../Runbook/Funding.md).
- [Runbook / Launch Gates](../Runbook/Launch-Gates.md).