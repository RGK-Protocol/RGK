# Reference / API Surface Audit

> **Canonical source:** [`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md).

The audit walks every public item in every `rgk` crate and nine
cross-cutting dimensions, produces **40 findings** (`F-01..F-40`) with
severity tags, and tracks a remediation pass.

---

## Headline Numbers

| Item | Value |
| --- | --- |
| Total findings | 40 (`F-01..F-40`) |
| Severity legend | Blocker / High / Medium / Low |
| Largest source file | `crates/rgk-asset/src/native.rs` (**5237 lines, 338 pub items**) |
| Largest audit finding | `F-01` (the `rgk-asset` "god module") |

Crate line counts (at audit time):

| Crate | Lines |
| --- | --- |
| `rgk-core` | 65 |
| `rgk-asset` | 90 (re-exports) + `native.rs` 5237 |
| `rgk-receipt` | 684 |
| `rgk-covenant` | 2154 |
| `rgk-tx` | 1709 |
| `rgk-zk` | 1167 |
| `rgk-kaspa` | 667 |
| `rgk-indexer` | 3078 |
| `rgk-resolver` | 1516 |
| `rgk-sync` | 568 |

> The audit was scoped to the **original 11 crates**. It does not cover
> `rgk-walletd`, which was added later.

---

## Remediation Status (highlights)

Resolved items (per
[`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md)):

- Type-alias triplication (`Hex32`, `RgkAssetId`, `RgkSchemaId`).
- Feature-gate hygiene.
- Error-typed seams.
- Rename of `RGK_PRODUCTION_*` constants to the neutral
  `RGK_ALLOCATION_STRATEGY_*` family.

Open items: see the canonical doc for the per-finding "Accepted" markers.

---

## "Fixed" Markers Are Point-in-Time

The remediation list at
[`docs/audits/public-api-surface.md:40-79`](../../audits/public-api-surface.md)
is a **point-in-time snapshot**. Each "Fixed" claim is the audit-date
statement, not a current guarantee. A future commit may un-fix a finding;
check the doc page timestamp.

---

## What the Audit Does NOT Cover

- `rgk-walletd` (added after the audit was scoped).
- Third-party dependency surface (see [Reference / Unsafe Audit](./Unsafe-Audit.md)).
- Performance characteristics (see [Concepts / Bounded Objects](../Concepts/Bounded-Objects.md) for
  cost budgets, not audit).

---

## Cross-references

- [`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md) —
  canonical source.
- [Reference / API Stability Policy](./API-Stability-Policy.md).
- [Reference / Unsafe Audit](./Unsafe-Audit.md).