# Glossary

> **The terms below are RGK-native.** They do not always map onto the
> RGB / Liquid / Bitcoin vocabulary you may have seen elsewhere, and that
> is intentional. The drift register at
> [`recon/RECON-DOCS.md` §Contradictions / staleness](../../recon/RECON-DOCS.md#contradictions--staleness)
> calls out the places where this matters.

---

## Domain-Separated Tags

RGK uses domain-separated hash commitments so the same hash algorithm can
be reused across many concepts without collision risk. Each tag below is
the literal byte string used as a hash domain prefix. Treat these as
**canonical and versioned**: a tag change is a breaking change.

| Tag | Where it appears | Source |
| --- | --- | --- |
| `"rgk:lineage"` | `lineage_id = H("rgk:lineage" \|\| genesis_outpoint_payload \|\| asset_id)` | [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md) |
| `"rgk:receipt"` | `receipt_id = H("rgk:receipt" \|\| canonical_receipt_bytes)` | [`docs/RECEIPT-SPEC.md`](../../RECEIPT-SPEC.md), [`crates/rgk-core/src/commit.rs`](../../crates/rgk-core/src/commit.rs) |
| `"rgk:asset:schema:v1_____________"` (`RGK_FUNGIBLE_ASSET_SCHEMA_ID`) | `schema_id` for the default fungible schema | [`crates/rgk-asset/src/lib.rs:111`](../../crates/rgk-asset/src/lib.rs) |
| `"rgk:lane:graph-root:v1"` | Private lane graph root derivation | [`docs/LANE-CALCULUS.md`](../../LANE-CALCULUS.md) |
| `"rgk:asset:allocation-transcript-amount:v1"` | Allocation transcript amount commitment | [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) |
| `"rgk:zk:allocation-audit-certificate:v1"` | ZK allocation-audit certificate envelope | [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) |
| `"rgk:aac1"` | Compact allocation-audit certificate envelope | [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) |
| `"rgk:policy-migration"` | Policy migration proof domain | [`docs/INTEGRATION.md`](../../INTEGRATION.md) |
| `"rgk:replay-nonce-v1"` (sample) | Replay nonce derivation test fixture | [`tests/rgk-e2e/src/lib.rs:600`](../../tests/rgk-e2e/src/lib.rs) |

> **Rule of thumb.** If you see a string literal starting with `"rgk:` in
> the source, it is a domain-separated tag. Treat changes to it as
> consensus-level.

---

## Hot-Path Types

The 14 RGK-native types you will see repeatedly. Source: [`docs/LANE-CALCULUS.md` §Native Asset Grammar](../../LANE-CALCULUS.md) and the recon.

| Type | Crate | What it represents |
| --- | --- | --- |
| `RgkAssetIssue` | `rgk-asset` | The issue-time commitment: supply, allocations, metadata + owner commitments, lane id, privacy, proof policy. |
| `RgkAllocation` | `rgk-asset` | A single allocation: amount, owner hint, lane, `RgkCovenantAnchor` (the outpoint). |
| `RgkContinuationPlan` | `rgk-asset` | Phase 1: previous state + new **shapes** (no txid yet). |
| `RgkTransition` | `rgk-asset` | Phase 2: previous state + new **allocations** anchored to the witness txid. |
| `RgkFinalizedContinuation` | `rgk-asset` | `{ commitment, transition, transition_report }` returned by `finalize(...)`. |
| `RgkCovenantAnchor` | `rgk-asset` | The covenant outpoint (transaction_id, index) anchoring an allocation. |
| `RgkStateDigest` | `rgk-core` | 32-byte digest of an asset's state. |
| `RgkTransitionDigest` | `rgk-core` | 32-byte digest of a transition. |
| `RgkReceipt` | `rgk-core` | Typed, hash-bound statement of a native transition. |
| `RgkReceiptCommitment` | `rgk-core` | The 32-byte identity of a receipt. **Derived, not chosen.** |
| `RgkLane` | `rgk-asset` | Lane material in the asset: blinded lane id + privacy policy. |
| `RgkLaneState` | `rgk-asset` | Per-lane tip state: nullifier, scan tag, etc. |
| `LanePrivacyPolicy` (alias `RgkPrivacyPolicy`) | `rgk-asset` | `PublicLineage` \| `PrivateLane` \| `StealthLane`. The default is `PrivateLane`. |
| `RgkResolver` | `rgk-resolver` | The 13-state native resolver. |

Plus three lane-discovery primitives (see
[`docs/LANE-CALCULUS.md` §Discovery](../../LANE-CALCULUS.md)):

| Type | What it represents |
| --- | --- |
| `BlindedLaneId` (= `Bytes32`) | Lane identity, derived from view key + asset id + epoch. |
| `RgkScanTag` | Rotating scan tag; recomputed per epoch. |
| `RgkNullifier` | Per-spend nullifier; stable for the spend, unlinked to lane_id. |

---

## Resolver States (the 13 hard outcomes)

Source: [`crates/rgk-resolver/src/lib.rs:42-108`](../../crates/rgk-resolver/src/lib.rs). See [Concepts / Resolver](./Concepts/Resolver.md) for the full worked treatment.

`Open`, `NativeTransitionedValid`, `NativeTransitionedInvalid`, `Unconfirmed`,
`ReorgRisk`, `CompetingBranch`, `PolicyMigrationRequired`, `ReplayRejected`,
`Unknown`, `NodeDown`, plus the three lane-level variants `LaneResolverState`
(`Resolved`, `UnknownLane`, `UnknownScanTag`) and the transition-level
`TransitionResolverState` (`Resolved`, `UnknownTransition`).

**No `OptimisticValid`. No `SoftInvalid`. No `Pending`.** This is a design
rule, not a missing enum variant.

---

## Supported Allocation Shapes

These are the six fixed allocation-vector shapes for which Groth16
allocation proofs are produced and verified end-to-end. They are listed
in [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) and
[`docs/ARCHITECTURE.md`](../../ARCHITECTURE.md), and the human-readable
form is the constant
[`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md)
line 653:

```rust
pub const RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS: &str =
    "1x0, 1x1, 2x2, 3x2, 4x2, 4x4";
```

| Shape | Spent | New | Use case |
| --- | --- | --- | --- |
| `OneInZeroOut` | 1 | 0 | Terminal burn (NFT retirement, supply-reduction). |
| `OneInOneOut` | 1 | 1 | Simplest transfer. |
| `TwoInTwoOut` | 2 | 2 | Two-source / two-destination. |
| `ThreeInTwoOut` | 3 | 2 | Three-source merge to two destinations. |
| `FourInTwoOut` | 4 | 2 | Four-source merge. |
| `FourInFourOut` | 4 | 4 | Maximum supported bounded shape. |

For shapes larger than 4-in / 4-out, RGK uses **segmented allocation audit
certificates** (`RgkProductionAllocationStrategyRecord`). See
[Concepts / Production Allocation Strategy](./Concepts/Production-Allocation-Strategy.md).

> **Important.** This list is repeated in 6+ docs. Any new shape must be
> added everywhere. The wiki binds it to this glossary entry; other pages
> cross-link here.

---

## Proof Policies

The three `RgkProofPolicy` variants
([`crates/rgk-asset/src/native.rs:455-468`](../../crates/rgk-asset/src/native.rs)):

| Variant | What it commits to |
| --- | --- |
| `VerifierReceipt { verifier_key_hash: Bytes32 }` | A precompile verifier (e.g. `OpZkPrecompile` on Toccata) gates the receipt via a known verifier key. This is the default in the fixture harness. |
| `ZkReceipt { verifier_key_id: Bytes32, image_id_policy: ImageIdPolicy }` | A real Groth16 proof is required. `image_id_policy` constrains which image ids are admissible — see below. |
| `Hybrid { verifier_key_hash: Bytes32, verifier_key_id: Bytes32 }` | Structural-only today. Not yet wired to any verifier stack; see drift note in the recon. |

`ImageIdPolicy` variants:

| Variant | What it allows |
| --- | --- |
| `Fixed(Bytes32)` | Exactly one image id. Most restrictive. |
| `AllowedSet(Vec<Bytes32>)` | A closed set of image ids. |
| `PolicyBranch(Bytes32)` | A branch-rooted set; the wallet picks one at issuance time. |

The policy commitment `RgkProofPolicy::commitment() -> RgkPolicyCommitment`
binds the chosen policy into state — **proof policy is part of RGK state**.
Downgrading to an unconstrained `image_id` is rejected. The validation
rules are at [`crates/rgk-asset/src/native.rs:470-507`](../../crates/rgk-asset/src/native.rs).

---

## Receipt Policies

The `ReceiptPolicy` enum (re-exported from `rgk-core`):

| Variant | What it admits |
| --- | --- |
| `Any` | Either `VerifierReceipt` or `ZkReceipt`. |
| `VerifierOnly` | Only `VerifierReceipt`. |
| `ZkOnly` | Only `ZkReceipt`. |

A wallet cannot silently swap in an unconstrained verifier image id later;
that would change the committed state and be rejected.

---

## The 32-Byte Invariant

Every wire object is 32 bytes (or a canonical `MAX_BLOB_BYTES`). See
[Concepts / Bounded Objects](./Concepts/Bounded-Objects.md) for the full
table and the rationale. **Do not change any of these sizes without a
consensus-level review.**

---

## "Not Yet Proven" Items

The same five-ish items appear in
[`docs/SECURITY.md`](../../SECURITY.md),
[`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md),
[`docs/ROADMAP.md`](../../ROADMAP.md),
[`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md), and
[`docs/E2E.md`](../../E2E.md). The wiki canonicalises them here:

1. **Public testnet operation.** The launch audit's strict mode remains
   non-zero until `public_testnet_funded_report=ok`. See
   [`Runbook / Launch Gates`](../Runbook/Launch-Gates.md).
2. **Single recursive Groth16 proof for arbitrary-size allocation
   vectors.** Larger transfers use segmented allocation-audit certificates
   instead. See [Concepts / Production Allocation Strategy](./Concepts/Production-Allocation-Strategy.md).
3. **Public staging evidence for continuation / policy-migration flows
   across all matrix rows.**
4. **Arbitrary historical discovery.** The resolver requires the lane to
   be currently registered (or scanned via `rgk-sync`); it does not
   reconstruct historical lineage from cold storage alone.
5. **Post-quantum security.** The Groth16 stack is BN254; a post-quantum
   migration is on the planning tracks but not implemented.

---

## Vocabulary Boundary (no `rgb*` etc.)

The verify script
[`scripts/verify-native-terminology.sh`](../../scripts/verify-native-terminology.sh)
asserts that no `rgb*` legacy vocabulary, "outpoint seal", `cell`, `aluvm`,
`tapret`, `opret`, `consignment`, `argent`, or `strict-types` strings
appear in the public workspace surface. This is enforced on every CI run.

---

## Cross-references

- [`docs/LANE-CALCULUS.md`](../../LANE-CALCULUS.md) — hot-path types.
- [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md) — covenant payload.
- [`docs/RECEIPT-SPEC.md`](../../RECEIPT-SPEC.md) — receipt invariants.
- [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) — public-input sizes.
- [`docs/VERIFICATION-BUDGET.md`](../../VERIFICATION-BUDGET.md) — bounded
  objects.
- [`docs/ROADMAP.md`](../../ROADMAP.md) — milestones and "removed track".
- [`docs/API-DEPRECATION.md`](../../API-DEPRECATION.md) — pre-release vs
  compat-tagged deprecation rules.