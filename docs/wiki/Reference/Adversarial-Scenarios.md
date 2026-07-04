# Reference / Adversarial Scenarios

> **Canonical source:** [`docs/ADVERSARIAL-SCENARIOS.md`](../../ADVERSARIAL-SCENARIOS.md).

The existing test matrix is broad on single primitives (fixed shapes,
conservation, replay, burn, ownership handoff) but only lightly covers
**composition, timing, contention, and cross-boundary behaviour**. This
document catalogues 20 high-complexity adversarial scenarios in 5 groups.

The `file:line` references in the canonical doc are pinned to the current
code; they will drift. The wiki carries the **scenario intent** here and
links out for the citations.

---

## Priority Tags

| Tag | Meaning |
| --- | --- |
| **P0** | Must-fix before any public exposure. |
| **P1** | Must-fix before funded public testnet. |
| **P2** | Should-fix before launch-readiness strict mode passes. |
| **P3** | Nice-to-fix; tracked but not gating. |

Each scenario has a target invariant, an attack model, an expected
verdict, and a fuzz target.

---

## I. Segmented Allocation Audit (>4×4 Fallback)

| Scenario | Priority | Surface | What it tests |
| --- | --- | --- | --- |
| **S1 Cross-Segment Outpoint Reuse** | P2 | Segmented | A spent outpoint must not appear as a future continuation output across segment boundaries. Exclusion grid regression. |
| **S2 Conservation Chain Blinding-Factor Zeroing** | P2 | Segmented | Constructor + circuit-level rejection of zero blinding factor in any segment. |
| **S3 Burn vs Segmented Mutual Exclusion** | P2 | Segmented | A 5×5 + burn transition should fail closed; segmented audit and burn cannot co-occur. |
| **S4 Splitting a 5×5 into Two Stacked 4×4 Transitions** | P2 | Cross-transition | The aggregation boundary between two stacked transitions must still conserve supply. |

## II. Two-Phase Continuation Binding

| Scenario | Priority | Surface | What it tests |
| --- | --- | --- | --- |
| **P1 Phase-1 Plan Reuse Across Transactions** | **P0** | Continuation | Replay-by-receipt-id is insufficient; the phase-1 commitment must bind the next shape. |
| **P2 Segmented Path Requires Off-Circuit Txid Binding** | **P0** | Segmented + continuation | The new-allocation txid must be bound to the witness txid in the segment subproof. |
| **P3 Witness Txid Mutation Triggering `ReusedSpentAnchor`** | P3 | Continuation | A wallet that mutates the witness txid post-finalize triggers `ReusedSpentAnchor` griefing. |
| **P4 Phase-1 Commit Then Reorg Before Finalisation** | P1 | Continuation + reorg | A reorg during finalisation degrades gracefully — no orphan transition is accepted. |

## III. Resolver Trust Boundary

| Scenario | Priority | Surface | What it tests |
| --- | --- | --- | --- |
| **R1 Indexer State-Digest Poisoning** | P2 | Resolver | The resolver trusts the indexer's state digest; a poisoned digest leads to false-`Valid`. |
| **R2 Pruned Outpoint Indistinguishable From Never-Existed** | P2 | Resolver | `get_utxo` returns `None` for both. The resolver must distinguish. |
| **R3 `CompetingBranch` Requires Indexer-vs-Backend Disagreement** | P3 | Resolver | A single-adversary-backend cannot fire `CompetingBranch`; it requires disagreement. |

## IV. Advanced Covenant Composition and Boundary

| Scenario | Priority | Surface | What it tests |
| --- | --- | --- | --- |
| **A1 Escrow Counterparty Mistyped as Vault** | P2 | Advanced covenant | Counterparty id is opaque; mistyping as Vault should fail closed. |
| **A2 AtomicSwap With Zero Policy Commitment** | P1 | Advanced covenant | Conditional field requirement — zero policy commitment must reject. |
| **A3 Payment Boundary Asymmetry Between Flows** | P3 | Advanced covenant | `PaymentGatedTransfer` accepts overpayment; `AtomicSwap` requires exact. |
| **A4 VaultTimelockRelease at the Threshold** | P3 | Advanced covenant | Off-by-one at the DAA-score threshold. |
| **A5 AtomicSwap Two-Leg Race (HTLC Griefing)** | P1 | Advanced covenant | Cross-leg atomicity is wallet-side; an attacker front-running the second leg wins. |

## V. Privacy and Lane Boundary

| Scenario | Priority | Surface | What it tests |
| --- | --- | --- | --- |
| **L1 Cross-Lane Nullifier Collision** | P2 | Privacy | `RgkNullifier::derive` is lane-agnostic — must not collide across lanes. |
| **L2 `public_lineage` Flag Inconsistent With `LanePrivacyPolicy`** | P1 | Privacy | `IndexedLane` does not store `LanePrivacyPolicy`; mismatch is silent. |
| **L3 StealthLane as Dead Variant** | P3 | Privacy | The `StealthLane` enum variant has no derivation; the on-chain form is unspecified. |
| **L4 Lane With No `scan_tag` (Ghost Lane)** | P3 | Privacy | `RgkScanTag = None` should be detectable and reject-able. |

---

## Suggested Landing Points

The canonical doc suggests landing these tests in:

1. `crates/rgk-asset/src/native.rs` (P0-P3, S1-S4, L1-L4).
2. `crates/rgk-zk/src/real_zk.rs` (S1-S4, P2).
3. `crates/rgk-resolver/src/lib.rs` (R1-R3).
4. `crates/rgk-covenant/src/lib.rs` (A1-A5).
5. `crates/rgk-indexer/src/lib.rs` (L2, L4).

---

## Open Questions

Six open questions worth resolving before implementation; see
[`docs/ADVERSARIAL-SCENARIOS.md` §Open Questions](../../ADVERSARIAL-SCENARIOS.md#open-questions-worth-resolving-before-implementation).

---

## Cross-references

- [`docs/ADVERSARIAL-SCENARIOS.md`](../../ADVERSARIAL-SCENARIOS.md) —
  canonical source with `file:line` citations.
- [Reference / Threat Model](./Threat-Model.md) — the 17-row threat
  table this builds on.
- [Concepts / Resolver](../Concepts/Resolver.md) — the 13-state machine
  the scenarios target.