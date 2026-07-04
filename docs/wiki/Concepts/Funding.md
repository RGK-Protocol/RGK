# Concepts / Funding

> **The funding flow is split across four docs.** This page gives you the
> single happy-path: wallet set → preflight → funding-readiness → full
> lifecycle.

The information lives, fragmented, in:

- [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md) — frozen
  wallet set + preflight snapshot for `testnet-12`.
- [`docs/E2E.md` §Public Testnet Staging](../../E2E.md#public-testnet-staging) —
  the operational flow.
- [`docs/INTEGRATION.md` §Public Testnet Staging](../../INTEGRATION.md#public-testnet-staging) —
  wallet-side integration.
- [`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md) — launch-gate rules.

This page stitches them together.

---

## The Happy Path (7 steps)

### Step 1 — Confirm you're targeting `testnet-12`

RGK's funded staging target is **`testnet-12`**, not `testnet-10`. The
two are **not interchangeable**. The drift note
([`recon/RECON-DOCS.md` §Contradictions / staleness](../../recon/RECON-DOCS.md#contradictions--staleness))
item #11 calls this out: if you accidentally target `testnet-10`, the
launch audit will reject your evidence.

The frozen snapshot is at
[`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md). It pins:

| Field | Value |
| --- | --- |
| Network | `testnet-12` |
| Chain id | `KaspaTestnet` |
| `wallet_set_id` | `0x319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352` |
| `preflight_id` | `0x2c993d20f2726efdb0983868126544163e44c474f4b4ab4cf28901e749c29212` |
| Funding address | `kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald` |
| `required_min_value_real_zk` | `45000000` sompi |
| `required_min_value_verifier_only` | `9000000` sompi |

> **Snapshot, not config.** These values are frozen. Do not regenerate
> unless you intend to publish a new preflight manifest, which requires
> regenerating both `--wallets` and `--preflight`.

### Step 2 — Generate (or load) the wallet set

```bash
cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address
```

This prints the deterministic funding address. For the full wallet set:

```bash
bash scripts/e2e-testnet-staging.sh --wallets
```

The output is a JSON manifest with three roles:

| Role | Purpose | Needs funding? |
| --- | --- | --- |
| `funding` | Funds the staging run; signs issuance + transfers. | **Yes.** |
| `change` | Receives the change output, isolated from the funding role. | No. |
| `observer` | Reads receipts and resolver state, no signing. | No. |

The verifier `scripts/verify-testnet-staging-wallets.sh` enforces that no
`secret_key` / `private_key` / `privkey` field appears in the manifest.
**Public staging evidence must never leak a secret.**

### Step 3 — Run the preflight (without funding)

```bash
bash scripts/e2e-testnet-staging.sh --preflight
```

Output: `target/rgk-testnet-staging-evidence/latest.txt` with the
`preflight_id`, network, chain id, address, wallet_set_id, funding_status,
and requirements. Verify with:

```bash
bash scripts/verify-testnet-staging-preflight.sh
```

The preflight is **read-only** — it does not submit transactions, does
not connect to the chain, and does not require funds. Run it as many times
as you want before requesting funds.

### Step 4 — Funding-readiness check (no funds yet)

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

Output: a free-form text block including:

```text
RGK public testnet funding readiness
  timestamp_utc=…
  network=testnet-12
  chain_id=KaspaTestnet
  url=…
  wallet_set_id=0x…
  wallet_count=3
  funding_address=kaspatest:…
  required_min_value_real_zk=…
  required_min_value_verifier_only=…
  server_version=… server_network_id=… server_is_synced=… server_has_utxo_index=…
```

Verify with:

```bash
bash scripts/verify-testnet-funding-readiness.sh
```

The funding-readiness report is **read-only** — it does not move funds,
it just checks the funding address is empty / funded, the node is synced,
and the wallet set / preflight still match.

### Step 5 — Request testnet funds

Send at least `required_min_value_real_zk` (currently `45000000` sompi,
i.e. 0.45 KAS) to the funding address from Step 2.

> **Important.** Only send testnet KAS. **Never** send mainnet KAS to this
> address. The frozen snapshot is testnet-only by design.

### Step 6 — Resume the staging run

After funding, the staging harness picks up where preflight left off:

```bash
bash scripts/e2e-testnet-staging.sh --resume
```

This drives the full lifecycle: issue → transfer → receipt → submit →
wait → scan → index → resolve. The output is
`target/rgk-testnet-staging-evidence/latest.txt` with the full set of
required fields.

### Step 7 — Verify the staging evidence

```bash
bash scripts/verify-testnet-staging-evidence.sh
```

This regex-matches every required field. The result is the
`public_testnet_funded_report=ok|failed|blocked` line that the launch audit
([`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md)) consumes.

---

## What `funding_readiness=blocked` Means

Until the funding-readiness script confirms the funding address has been
funded **and** the preflight matches, the launch audit returns
`funding_readiness=blocked`. The relaxed mode:

```bash
bash scripts/verify-launch-readiness.sh --allow-blocked
```

…will only pass when:

- `preflight_status=ok`
- `funding_readiness=blocked` (i.e. not yet funded, but everything else
  is consistent)
- `examples_matrix=ok`
- `internal_readiness=ok`
- `devnet_evidence=ok`

Strict mode (without `--allow-blocked`) requires `funding_readiness=ok`
and `public_testnet_funded_report=ok`. **Strict mode remains non-zero
until a real funded run publishes its evidence.**

---

## Common Pitfalls

| Pitfall | Fix |
| --- | --- |
| Targeting `testnet-10` instead of `testnet-12`. | Re-run with `RGK_LIVE_KASPA_NETWORK=testnet-12`. |
| Re-running `--wallets` after funding. | Don't. The preflight is pinned to a specific `wallet_set_id`. Regenerating breaks the audit. |
| Sending mainnet KAS to the testnet funding address. | Don't. There is no recovery path. The frozen snapshot is testnet-only. |
| Mixing evidence from different runs. | Each `--resume` overwrites `latest.txt`. Move old files aside before re-running. |
| Forgetting the `--features live-kaspa-wrpc` flag. | The bin won't compile without it. |
| Using the wrong chain id in `ReceiptInput`. | The verifier rejects chain-id mismatches; use `KaspaChainId::KaspaTestnet`. |

---

## What This Page Is Not

This page does **not** replace the canonical docs. The four sources it
draws from are:

- [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md) —
  the frozen snapshot values (cited verbatim).
- [`docs/E2E.md`](../../E2E.md) — the per-script invocation details.
- [`docs/INTEGRATION.md` §Public Testnet Staging](../../INTEGRATION.md) —
  wallet-side code paths.
- [`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md) — the launch-gate
  rules.

If this page disagrees with one of those, **the canonical doc wins**.

---

## Cross-references

- [`Runbook / Launch Gates`](../Runbook/Launch-Gates.md) — the strict vs
  relaxed mode rules.
- [`Runbook / E2E`](../Runbook/E2E.md) — operator-facing scripts.
- [`Reference / Testnet Staging Snapshot`](../Reference/Testnet-Staging-Snapshot.md) —
  the frozen snapshot, republished verbatim.
- [Tutorial-4: Run the E2E Harness](../Tutorials/Tutorial-4-Run-E2E-Harness.md) —
  the broader staging flow.