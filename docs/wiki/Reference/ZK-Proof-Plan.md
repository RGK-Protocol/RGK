# Reference / ZK Proof Plan

> **Canonical source:** [`docs/ZK-PROOF-PLAN.md`](../../ZK-PROOF-PLAN.md).

Use fixed Groth16 allocation proofs for the evidenced shapes; use segmented
allocation-audit certificates for larger conserving full-state transfers;
never describe segmented audit as one recursive proof; never put R0
Succinct on the hot path until RGK has a native RISC0 prover, circuit
family, and cost evidence; keep every proof claim tied to a verifier, a
shape, a cost budget, and a report line.

---

## Current Claim Boundary

| Surface | Status | Production claim |
| --- | --- | --- |
| Receipt statement (Groth16) | Bound, proven on simulator + devnet | **Yes**, with `real-zk` feature. |
| Semantic transition statement | Bound, proven on simulator + devnet | **Yes**. |
| Lane discovery / lane graph | Bound, proven | **Yes**. |
| `1x0, 1x1, 2x2, 3x2, 4x2, 4x4` allocation-vector circuits | Bound, proven | **Yes**. |
| Segmented allocation-audit certificates | Bound, proven | **Yes**, for shapes > 4×4. |
| `R0SuccinctPrecompileStack` (Toccata) | Stack support only | **No** (planning track P2). |
| Single recursive proof for arbitrary-size allocation vectors | Open | **No** (planning track P2). |
| Native RISC0 prover | Open | **No**. |

Source: [`docs/ZK-PROOF-PLAN.md` §Current Claim Boundary](../../ZK-PROOF-PLAN.md#current-claim-boundary).

### "Do Not Claim" list

1. Do not claim a single recursive proof for arbitrary-size allocation vectors.
2. Do not put R0 Succinct on the hot path.
3. Do not describe segmented audit as "one recursive proof."
4. Do not claim post-quantum Groth16.
5. Do not claim mainnet readiness without a funded testnet report.

---

## Current Cost Snapshot (11 rows)

From [`docs/ZK-PROOF-PLAN.md` §Current Cost Snapshot](../../ZK-PROOF-PLAN.md#current-cost-snapshot):

| Surface | Public inputs (bytes) | VK bytes | Proof bytes | Notes |
| --- | --- | --- | --- | --- |
| Receipt statement | 232 | 2312 | 128 | Groth16 |
| Semantic transition | 512 | 2312 | 128 | Groth16 |
| `OneInOneOut` allocation | 32 | 2312 | 128 | Groth16 |
| `TwoInTwoOut` allocation | 64 | 2312 | 128 | Groth16 |
| `FixedAllocationVectorCircuit<SPENT, NEW>` | per-shape | 2312 | 128 | Groth16 |
| `OneInZeroOut` (terminal burn) | 0 | 2312 | 128 | Groth16 |
| Allocation transcript segment | 128 | 2312 | 128 | Per-segment |
| Allocation conservation segment | 192 | 2312 | 128 | Per-segment |
| Conservation final | 80 | 2312 | 128 | Per-segment |
| Exclusion pair | 232 | 2312 | 128 | Per-segment |
| Allocation audit certificate | n/a | 5392 total | 768 total | 6 proof entries, 11826 canonical bytes |

The exact byte counts will drift as new shapes are added; the
**structural shape** (Groth16 with a single 2312-byte VK, 128-byte proof)
is stable.

---

## Segmented Audit Cost Growth

```text
entries = 2 * (spent_segments + new_segments) + 1 + spent_segments * new_segments
```

Where `spent_segments` and `new_segments` are the segment counts on each
side. The `+ spent_segments * new_segments` is the exclusion-grid cost.

For a 5×5 split as two stacked 4×4 transitions:

```text
spent_segments = 2 (split into 2×4 = 8, then 5+3 = ?
```

The cleanest split for 5×5 is a 4×4 + 1×1 stack, giving
`spent_segments = 2`, `new_segments = 2`:

```text
entries = 2 * (2 + 2) + 1 + 2*2 = 9 + 1 + 4 = 13
```

So 13 proof entries for a 5×5.

---

## Production Budget Rules (7 rules)

From [`docs/ZK-PROOF-PLAN.md` §Production Budget Rules](../../ZK-PROOF-PLAN.md#production-budget-rules):

1. **Fixed Groth16 is the default for evidenced shapes.** Don't reach for
   segmented audit when a fixed shape works.
2. **Segmented audit must include a conservation proof per segment
   boundary.** Two adjacent segments that conserve separately may not
   conserve globally.
3. **A 1×0 burn is a fixed-shape proof, not segmented audit.**
4. **The witness txid must be bound into the segmented subproofs**
   (adversarial scenario P2).
5. **No "recursive proof" claim** until RGK has a native RISC0 prover.
6. **No `R0SuccinctPrecompileStack` on the hot path** (stack support only).
7. **Every proof claim is tied to a verifier + shape + cost budget + report line.**

---

## Verifier Key Governance

VKs are pinned assets. Each VK corresponds to one (shape, image_id) pair.

Before mainnet, every VK must have:

- Source ceremony documented.
- Ceremony transcript hash pinned.
- `image_id` recorded.
- Pin in the indexer config and the resolver config.
- Reject path for receipts referencing unknown VKs.
- Reject path for receipts whose statement claims a different VK.
- Cost budget per VK.
- Recovery path if a VK is later found insecure.

---

## Operational Evidence (5 commands)

From [`docs/ZK-PROOF-PLAN.md` §Operational Evidence](../../ZK-PROOF-PLAN.md#operational-evidence):

```bash
bash scripts/e2e-internal-readiness.sh
bash scripts/verify-internal-readiness-evidence.sh
bash scripts/e2e-testnet-staging.sh --resume …
bash scripts/verify-testnet-staging-evidence.sh
bash scripts/verify-launch-readiness.sh
```

These produce the evidence reports at
`target/rgk-internal-readiness/latest.txt` and
`target/rgk-testnet-staging-evidence/latest.txt`.

---

## Planning Tracks

- **P0 — keep claims honest.** Every proof claim is tied to evidence.
- **P1 — freeze mainnet budgets.** Pin the cost numbers in
  `docs/ZK-PROOF-PLAN.md`.
- **P2 — future compression work.** Recursive proofs, RISC0 native prover.

---

## Plain-Language Decision Rule

> "Use fixed Groth16 allocation proofs whenever the transfer shape is one
> of the evidenced shapes. Use segmented allocation-audit certificates
> for larger conserving full-state transfers. Never describe segmented
> audit as one recursive proof. Never put R0 Succinct on the hot path
> until RGK has a native RISC0 prover, circuit family, and cost
> evidence. Keep every proof claim tied to a verifier, a shape, a cost
> budget, and a report line that proves it."

---

## Cross-references

- [`docs/ZK-PROOF-PLAN.md`](../../ZK-PROOF-PLAN.md) — canonical source.
- [Reference / ZK Boundary](./ZK-Boundary.md) — the proven surface.
- [Concepts / Production Allocation Strategy](../Concepts/Production-Allocation-Strategy.md).
- [Glossary](../Glossary.md).