# Reference / Status

> **Canonical source:** [`docs/ROADMAP.md` §Current Revision](../../ROADMAP.md#current-revision).

This page republishes the current revision table for a quick "where are
we?" check.

> **Important.** A "Status" line is **release-pinned or version-neutral** —
> see [L2 protocol design — document status discipline](../../../../../.mavis/agents/mavis/memory/l2-protocol-doc-writing.md).
> This page is the neutral version. For release-pinned snapshots, see
> [`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md).

---

## Current Revision

| # | Area | Status |
| --- | --- | --- |
| 1 | Native Grammar Baseline (M0) | OK |
| 2 | Private Lanes — `PrivateLane` default | OK |
| 3 | Private Lanes — `PublicLineage` opt-in | OK |
| 4 | Private Lanes — `StealthLane` | OPEN |
| 5 | Native Resolver (M2) — 13-state machine | OK |
| 6 | Native Resolver — replay rejection | OK |
| 7 | Native Resolver — `CompetingBranch` | OK |
| 8 | Native Resolver — `PolicyMigrationRequired` | OK |
| 9 | Two-Phase Continuation (M3) | OK |
| 10 | Semantic ZK Receipt (M4) — receipt statement | OK |
| 11 | Semantic ZK Receipt — semantic transition statement | OK |
| 12 | Semantic ZK Receipt — fixed shapes (1×0, 1×1, 2×2, 3×2, 4×2, 4×4) | OK |
| 13 | Semantic ZK Receipt — segmented audit | OK |
| 14 | Semantic ZK Receipt — single recursive proof | OPEN |
| 15 | Lane Policy Examples (M5) — example matrix | PARTIAL |
| 16 | Public Staging — internal readiness | OK |
| 17 | Public Staging — local devnet | OK |
| 18 | Public Staging — funded testnet (`testnet-12`) | OPEN |
| 19 | External Frontend Equivalence | REMOVED |

---

## What "OPEN" and "PARTIAL" Mean

| Tag | Meaning |
| --- | --- |
| **OK** | Production-claimed, with evidence. |
| **PARTIAL** | Some surface works; broad coverage remains open. |
| **OPEN** | Not yet implemented or not yet proven. |
| **REMOVED** | Explicitly not a milestone. |

---

## Cross-references

- [`docs/ROADMAP.md`](../../ROADMAP.md) — canonical source.
- [Reference / Roadmap](./Roadmap.md) — milestone tracker.
- [Runbook / Launch Gates](../Runbook/Launch-Gates.md) — the strict-mode
  gate that depends on this status.
- [Glossary §"Not Yet Proven" Items](../Glossary.md#not-yet-proven-items).