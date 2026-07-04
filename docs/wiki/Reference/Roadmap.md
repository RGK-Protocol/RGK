# Reference / Roadmap

> **Canonical source:** [`docs/ROADMAP.md`](../../ROADMAP.md).

The roadmap tracks RGK as a Kaspa-native covenant-lineage asset system.
Matching external wallets or validators byte-for-byte is **not** a
milestone.

---

## Vocabulary Boundary (7 protocol principles + 14 RGK-native word list)

From [`docs/ROADMAP.md` §Vocabulary Boundary](../../ROADMAP.md#vocabulary-boundary):

The 14 RGK-native terms are listed in [Glossary](../Glossary.md). The 7
principles include:

- Chain-as-notary, wallet-as-judge.
- Lineage-first identity.
- Two-phase continuation.
- Bounded verification.
- Fail-closed validation.
- Privacy-by-default.
- Native terminology (no `rgb*` legacy).

---

## Current Revision

A 19-row "Area / Status" table at
[`docs/ROADMAP.md` §Current Revision](../../ROADMAP.md#current-revision).
Each row tracks an area (Issue, Transition, Receipt, Resolver, etc.) and
its current status (`OK` / `PARTIAL` / `OPEN`).

The current revision shows:

- **Native Grammar Baseline (M0)** — OK.
- **Private Lanes (M1)** — OK for `PrivateLane` / `PublicLineage`;
  `StealthLane` is OPEN.
- **Native Resolver (M2)** — OK.
- **Two-Phase Continuation Output (M3)** — OK.
- **Semantic ZK Receipt (M4)** — OK for fixed shapes + segmented audit;
  recursive single proof is OPEN.
- **Lane Policy Examples and Public Staging (M5)** — PARTIAL; public
  testnet evidence remains OPEN.
- **External Frontend Equivalence** — REMOVED (not a milestone).

---

## M0 — Native Grammar Baseline

**Acceptance:**

- Positive supply, no supply inflation / deflation.
- Supply conservation across transfers.
- Lineage identity anchored to genesis outpoint.

## M1 — Private Lanes

**Acceptance:**

- Default `PrivateLane`.
- Opt-in `PublicLineage`.
- Blinded lane id derivation.
- Bounded Groth16 lane discovery.
- Segmented lane-graph proof chains.

## M2 — Native Resolver

**Acceptance:**

- Replay rejection.
- Lane-native entry points.
- `CompetingBranch` detection.
- `PolicyMigrationRequired` handling.
- `PolicyMigrationInput::build` in `rgk-core`.

## M3 — Two-Phase Continuation Output

**Acceptance:**

- Phase-1 commitment without future txid (stable across re-plans).
- Phase-2 finalisation (binds actual txid).
- Resolver txid-binding enforcement.

## M4 — Semantic ZK Receipt

**Acceptance:**

- 1×0 / 1×1 / 2×2 / 3×2 / 4×2 / 4×4 fixed-shape proofs.
- Segmented audit bundles + certificates.
- `RgkProductionAllocationStrategyPlan` / `Record`.
- **OPEN:** single-proof arbitrary-size conservation.

## M5 — Lane Policy Examples and Public Staging

**Acceptance (lane policy):**

- All example matrix rows verified.
- 12-bullet acceptance list (see
  [`docs/ROADMAP.md` §M5](../../ROADMAP.md#m5-lane-policy-examples-and-public-staging)).

**Status:** PARTIAL. **Public testnet evidence remains OPEN.**

---

## Removed Track

The "external wallet byte-for-byte matching" track was **removed**. It is
not a milestone. The wiki reflects this — see
[Glossary §Vocabulary Boundary](../Glossary.md#vocabulary-boundary-no-rgb-etc).

---

## Cross-references

- [`docs/ROADMAP.md`](../../ROADMAP.md) — canonical source.
- [`Reference / Status`](./Status.md) — the current revision table,
  republished.
- [Glossary](../Glossary.md).