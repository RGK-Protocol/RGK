# Reference / Lane Calculus

> **Canonical source:** [`docs/LANE-CALCULUS.md`](../../LANE-CALCULUS.md).
> Source code: [`crates/rgk-asset/src/lanes.rs`](../../crates/rgk-asset/src/lanes.rs)
> and [`crates/rgk-asset/src/native.rs`](../../crates/rgk-asset/src/native.rs).

RGK's identity is the Kaspa covenant lineage / lane. `asset_id` is native
label material committed into state, receipts, and covenant payloads — not
an external contract id. The native asset grammar has hot-path types
listed below.

---

## Hot-Path Types

| Type | Where | What |
| --- | --- | --- |
| `RgkAssetIssue` | `rgk-asset` | The issue-time commitment. |
| `RgkAllocation` | `rgk-asset` | A single allocation (amount, owner, lane, anchor). |
| `RgkTransition` | `rgk-asset` | Phase 2 transition (with witness txid). |
| `RgkCovenantAnchor` | `rgk-asset` | The covenant outpoint. |
| `RgkStateDigest` | `rgk-core` | 32-byte state digest. |
| `RgkTransitionDigest` | `rgk-core` | 32-byte transition digest. |
| `RgkReceipt` | `rgk-core` | Typed statement. |
| `RgkLane` | `rgk-asset` | Lane material (id + privacy). |
| `RgkLaneState` | `rgk-asset` | Per-lane tip state. |
| `RgkPrivacyPolicy` (alias for `LanePrivacyPolicy`) | `rgk-asset` | Public / Private / Stealth. |
| `RgkResolver` | `rgk-resolver` | The 13-state resolver. |

See [Glossary](../Glossary.md#hot-path-types) for the full table.

---

## Lane Privacy Modes

```rust
pub enum LanePrivacyPolicy {
    PublicLineage,    // tag 0
    #[default]
    PrivateLane,      // tag 1
    StealthLane,      // tag 2 (reserved; not yet wired end-to-end)
}
```

Source: [`crates/rgk-asset/src/native.rs:424-430`](../../crates/rgk-asset/src/native.rs).

See [Concepts / Privacy](../Concepts/Privacy.md) for the full treatment.

---

## Lane Privacy Protocol Fields

For private lanes, the protocol carries:

- `BlindedLaneId` — `H(view_key, asset_id, epoch)`.
- `RgkScanTag` — `H(view_key, lane_id, epoch)`. Rotates per epoch.
- `RgkNullifier` — `H(spend_secret, covenant_anchor)`. Stable for the
  spend, unlinked to lane_id.
- Encrypted note — holder-only payload (not on chain).
- View key — holder-side secret (never on chain).

Public observers should **not** learn: `asset_id`, owner, amount, lane
graph, plaintext proof policy. They **do** learn: blinded lane ids,
rotating scan tags, nullifiers, opaque commitments.

---

## Discovery Primitives

| Function | File:line | Returns |
| --- | --- | --- |
| `RgkScanTag::derive(view_key, lane_id, epoch)` | [`crates/rgk-asset/src/native.rs:749`](../../crates/rgk-asset/src/native.rs) | `RgkScanTag` |
| `RgkNullifier::derive(spend_secret, covenant_anchor)` | [`crates/rgk-asset/src/native.rs:759`](../../crates/rgk-asset/src/native.rs) | `RgkNullifier` |
| `derive_blinded_lane_id(view_key, asset_id, epoch)` | [`crates/rgk-asset/src/native.rs:770`](../../crates/rgk-asset/src/native.rs) | `BlindedLaneId` |
| `discover_lane(view_key, asset_id, epoch, candidate)` | [`crates/rgk-asset/src/native.rs:782`](../../crates/rgk-asset/src/native.rs) | `bool` |
| `RgkLaneGraphNode` | [`crates/rgk-asset/src/native.rs`](../../crates/rgk-asset/src/native.rs) | Lane graph node |
| `derive_private_lane_graph_root` | search | Private lane graph root |
| `private_lane_graph_empty_root` | search | Empty graph root |
| `extend_private_lane_graph_root` | search | Root extension |

Domain tag: `rgk:lane:graph-root:v1` (see [Glossary](../Glossary.md#domain-separated-tags)).

---

## Proof Policy

```rust
pub enum RgkProofPolicy {
    VerifierReceipt { verifier_key_hash: Bytes32 },
    ZkReceipt { verifier_key_id: Bytes32, image_id_policy: ImageIdPolicy },
    Hybrid { verifier_key_hash: Bytes32, verifier_key_id: Bytes32 },  // not yet wired
}
```

`ImageIdPolicy`:

- `Fixed(Bytes32)` — exactly one image id. Most restrictive.
- `AllowedSet(Vec<Bytes32>)` — closed set.
- `PolicyBranch(Bytes32)` — branch-rooted set.

Validation rules at [`crates/rgk-asset/src/native.rs:470-507`](../../crates/rgk-asset/src/native.rs).
The `commitment()` method produces a 32-byte
`RgkPolicyCommitment`. **Proof policy is part of RGK state.**

---

## Two-Phase Continuation

The phase-1 commitment is **stable** without the future txid; the phase-2
transition binds the actual txid. Both are required. See
[Concepts / Continuation](../Concepts/Continuation.md) for the worked
treatment.

Implemented tests (from
[`docs/LANE-CALCULUS.md`](../../LANE-CALCULUS.md)):

- `continuation_phase1_commitment_is_stable_without_future_txid`
- `continuation_phase2_binds_actual_txid`
- `continuation_finalization_spends_old_anchor_and_creates_new_anchor`
- `continuation_replay_reusing_spent_anchor_is_rejected`
- `continuation_accepts_explicit_burn_for_supported_production_zk_shape`

---

## Cross-references

- [`docs/LANE-CALCULUS.md`](../../LANE-CALCULUS.md) — canonical source.
- [Concepts / Identity](../Concepts/Identity.md) — lineage vs label.
- [Concepts / Privacy](../Concepts/Privacy.md) — privacy modes.
- [Concepts / Continuation](../Concepts/Continuation.md) — two-phase
  model.
- [Glossary](../Glossary.md).