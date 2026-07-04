# Runbook / Launch Gates

> **Canonical source:** [`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md).

> **RGK is research code until these gates are complete.**

The launch audit's strict mode remains non-zero until
`public_testnet_funded_report=ok`. The relaxed `--allow-blocked` mode
exists for CI / local use **before** funded staging.

---

## The 16 Required Evidence Items

From [`docs/MAINNET-LAUNCH.md` §Required Evidence](../../MAINNET-LAUNCH.md#required-evidence):

1. `bash scripts/e2e-internal-readiness.sh`
2. `bash scripts/verify-internal-readiness-evidence.sh`
3. `bash scripts/verify-devnet-evidence.sh`
4. `bash scripts/verify-launch-readiness.sh`
5. `bash scripts/verify-launch-readiness.sh --allow-blocked` (relaxed)
6. `bash scripts/verify-example-matrix.sh`
7. `bash scripts/verify-silverscript-artifacts.sh`
8. `bash scripts/e2e-testnet-staging.sh`
9. `bash scripts/verify-testnet-staging-wallets.sh`
10. `bash scripts/verify-testnet-staging-preflight.sh`
11. `bash scripts/verify-testnet-staging-evidence.sh`
12. `bash scripts/verify-testnet-funding-readiness.sh`
13. (and 4 more — see the canonical doc for the full list)

Plus the privacy-observer and native-terminology gates (covered by the
internal-readiness gate).

---

## The 25 Required Devnet Report Fields

From [`docs/MAINNET-LAUNCH.md` §Required Devnet Fields](../../MAINNET-LAUNCH.md#required-devnet-fields):

The devnet report at `target/rgk-devnet-evidence/latest.txt` must carry
~25 regex markers, including:

- `live: Toccata tx subnetwork=…`
- `devnet: …`
- `policy_migration_recovery: …`
- `allocation_audit_certificate: …`
- `zk_precompile: r0_succinct: …`
- `vk_pinning: …`
- …and ~19 more.

The full list is at [`docs/MAINNET-LAUNCH.md:59-96`](../../MAINNET-LAUNCH.md).

---

## Strict vs Relaxed Mode

```bash
bash scripts/verify-launch-readiness.sh                  # strict
bash scripts/verify-launch-readiness.sh --allow-blocked   # relaxed
```

| Mode | Requires | Use case |
| --- | --- | --- |
| **Strict** | `funding_readiness=ok` AND `public_testnet_funded_report=ok` AND all other gates `=ok`. | The actual launch gate. |
| **Relaxed** (`--allow-blocked`) | All gates `=ok` EXCEPT `funding_readiness=blocked`. | CI / local before a funded testnet report exists. |

> **Rule.** Strict mode remains non-zero until a funded run publishes
> its evidence. Relaxed mode is for the interim period only.

---

## "Do Not Claim" List

From [`docs/MAINNET-LAUNCH.md` §Do Not Claim](../../MAINNET-LAUNCH.md#do-not-claim):

1. Do not claim mainnet readiness without `public_testnet_funded_report=ok`.
2. Do not claim "one recursive proof for arbitrary-size allocation
   vectors" — that is open.
3. Do not put R0 Succinct on the hot path.
4. Do not describe segmented audit as one recursive proof.
5. Do not skip the privacy-observer evidence.

Same list as [Concepts / Production Allocation Strategy](../Concepts/Production-Allocation-Strategy.md)
and [Glossary §"Not Yet Proven" Items](../Glossary.md#not-yet-proven-items).

---

## What "Strict Mode Remains Non-Zero" Means

A `0` exit from the launch audit means: every required evidence gate has
been collected, every required field has been verified, and the
`public_testnet_funded_report` is `ok`. Anything less (including
`--allow-blocked` passing) is **research code**.

---

## Cross-references

- [`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md) — canonical source.
- [Reference / Status](../Reference/Status.md) — the current revision
  table.
- [Concepts / Funding](../Concepts/Funding.md) — the public-testnet
  staging flow.
- [Runbook / E2E](./E2E.md).
- [Runbook / Funding](./Funding.md).