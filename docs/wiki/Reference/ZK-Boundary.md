# Reference / ZK Boundary

> **Canonical source:** [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md).

The current ZK path proves an RGK receipt statement and a canonical
512-byte `SemanticTransitionStatement`. It does not yet prove the entire
native transition semantics inside the circuit.

---

## Public-Input Sizes (the canonical table)

From [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md):

| Statement | Bytes | Fields |
| --- | --- | --- |
| Receipt statement (`ZkStatement`) | 232 | 29 |
| Semantic transition (`SemanticTransitionStatement`) | 512 | 64 |
| Lane discovery (`LaneDiscoveryCircuit`) | 72 | 9 |
| Lane graph (`LaneGraphDiscoveryCircuit<const LANES>`) | (per LANES) | (per LANES) |
| Allocation transcript (`AllocationTranscriptSegmentCircuit`) | 128 | 16 |
| Allocation conservation (`AllocationConservationSegmentCircuit`) | 192 | 24 |
| Conservation final (`AllocationConservationFinalCircuit`) | 80 | 10 |
| Exclusion pair (`AllocationExclusionSegmentPairCircuit`) | 232 | 29 |

All multiples of 32. All within `MAX_BLOB_BYTES`.

---

## Proven Surface

- **Receipt statement.** `ZkStatement::from_receipt(...)` builds the public
  inputs (chain id, covenant id, lineage-bound `asset_id`, old/new state
  digest, transition digest, continuation commitment, receipt id).
  `ZkStatement::matches(receipt, receipt_id)` verifies the binding.
  Source: [`crates/rgk-zk/src/lib.rs:262-326`](../../crates/rgk-zk/src/lib.rs).

- **Semantic transition statement.** 512-byte native-transition statement
  with metadata/owner commitments, supply, allocation counts, burn
  authorisation. Builder:
  `SemanticTransitionStatement::from_reports(transition, continuation)`.
  Source: [`crates/rgk-zk/src/lib.rs:444-554`](../../crates/rgk-zk/src/lib.rs).

- **Lane discovery.** `LaneDiscoveryCircuit` + `LaneGraphDiscoveryCircuit<const LANES>` +
  segmented `LaneGraphSegmentCircuit<const LANES>`. Groth16-proven.

- **Allocation-vector circuits.** `OneInOneOut`, `TwoInTwoOut`,
  `FixedAllocationVectorCircuit<const SPENT, const NEW>` for the
  supported shapes `1x0, 1x1, 2x2, 3x2, 4x2, 4x4`. The dispatcher is
  `SupportedAllocationVectorCircuit`. Source:
  [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md).

- **Segmented audit.** `AllocationTranscriptSegmentCircuit`,
  `AllocationConservationSegmentCircuit`,
  `AllocationConservationFinalCircuit`,
  `AllocationExclusionSegmentPairCircuit`. Plus the bundle verifier
  `AllocationAuditBundle` and the portable envelope
  `AllocationAuditCertificate`.

- **R0 Succinct stack material.** `R0SuccinctPrecompileStack` provides
  the stack support for the Toccata precompile. **It is stack support
  only** — not a native RISC0 prover, not a circuit family.

---

## Envelopes

| Envelope | Domain tag | Source |
| --- | --- | --- |
| `AllocationAuditCertificate` | `rgk:zk:allocation-audit-certificate:v1` | [`docs/ZK-BOUNDARY.md:289`](../../ZK-BOUNDARY.md) |
| Compact envelope | `rgk:aac1` | [`docs/ZK-BOUNDARY.md:287`](../../ZK-BOUNDARY.md) |

The indexer attaches the certificate via
`AllocationAuditCertificateStore` ([`crates/rgk-indexer/src/lib.rs:443`](../../crates/rgk-indexer/src/lib.rs)).

---

## Production Allocation-Proof Strategy

The wallet selector is `ProductionAllocationProofStrategy::BoundedSupportedShapes`,
which chooses between:

- Fixed-shape Groth16 proof (the hot path).
- Segmented audit certificate (for shapes > 4×4).
- Fail-closed rejection (for unconstrained / unbounded shapes).

The plan wrapper is `RgkProductionZkTransferPlan`, the strategy plan is
`RgkProductionAllocationStrategyPlan`, and the canonical on-wire record is
`RgkProductionAllocationStrategyRecord` with `canonical_bytes()` /
`decode_canonical()` at
[`crates/rgk-asset/src/native.rs:1960-2021`](../../crates/rgk-asset/src/native.rs).

See [Concepts / Production Allocation Strategy](../Concepts/Production-Allocation-Strategy.md).

---

## Native Policy Requirement

**Proof policy is part of RGK state.** A wallet cannot silently swap in
an unconstrained verifier image id later; that would change the committed
state and be rejected. See
[Glossary §Proof Policies](../Glossary.md#proof-policies).

---

## Not Yet Proven

From [`docs/ZK-BOUNDARY.md` §Not Yet Proven](../../ZK-BOUNDARY.md#not-yet-proven):

1. Single recursive proof for arbitrary-size allocation vectors.
2. RGK-native RISC0 prover + circuit family.
3. Post-quantum Groth16 replacement.

The same list appears in [Glossary §"Not Yet Proven" Items](../Glossary.md#not-yet-proven-items).

---

## Cost Snapshot

The current cost snapshot is published in
[`docs/ZK-PROOF-PLAN.md` §Current Cost Snapshot](../../ZK-PROOF-PLAN.md#current-cost-snapshot).
The cost growth formula for segmented audit is:

```text
entries = 2 * (spent_segments + new_segments) + 1 + spent_segments * new_segments
```

For a 5×5 split as two stacked 4×4 transitions, this gives 13 proof
entries.

---

## Cross-references

- [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) — canonical source.
- [`docs/ZK-PROOF-PLAN.md`](../../ZK-PROOF-PLAN.md) — cost and planning.
- [Concepts / Production Allocation Strategy](../Concepts/Production-Allocation-Strategy.md).
- [Concepts / Bounded Objects](../Concepts/Bounded-Objects.md).
- [Glossary](../Glossary.md).