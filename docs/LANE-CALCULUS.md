# Lane Calculus

This document defines the native RGK asset, lane, privacy, and continuation
model.

## Identity

Canonical asset identity is the Kaspa covenant lineage / lane. `asset_id` is
native label material committed into state, receipts, and covenant payloads. It
is not an external contract id and does not replace the lineage as identity.

## Native Asset Grammar

Canonical hot-path types:

```rust
RgkAssetIssue
RgkAllocation
RgkTransition
RgkCovenantAnchor
RgkStateDigest
RgkTransitionDigest
RgkReceipt
RgkLane
RgkLaneState
RgkPrivacyPolicy
RgkResolver
```

Issue validation checks:

* chain and schema id are native RGK values
* total supply is positive
* allocations are positive
* allocation covenant outputs are unique
* allocation covenant outputs belong to the issue chain
* proof policy is constrained and committed

Transition validation checks:

* previous allocation set matches the previous state digest
* next allocation set conserves supply
* spent covenant outputs cannot be reused
* no-op transitions are rejected
* transition digest binds old state, new state, witness txid, ordered inputs,
  ordered outputs, proof policy, privacy mode, and lane id

State digest binds:

* lineage-bound asset label
* total supply
* allocation root
* policy commitment
* privacy mode
* lane id

## Lane Privacy

```rust
pub enum LanePrivacyPolicy {
    PublicLineage,
    PrivateLane,
    StealthLane,
}
```

Default: `PrivateLane`.

Public observers should not learn asset label, amount, owner, recipient, public
lane graph, or plaintext proof policy for private lanes. They should see
opaque commitments unless `PublicLineage` is explicitly selected.

Protocol fields:

* `BlindedLaneId`
* `RgkScanTag`
* encrypted note commitment
* `RgkNullifier`
* `RgkPolicyCommitment`
* private state root
* view-key based discovery

## Discovery

`RgkScanTag::derive(view_key, lane_id, epoch)` rotates by epoch. A wallet with
the right view key can discover its lane. A wrong view key computes a different
tag and cannot link the lane.

`RgkNullifier::derive(spend_secret, covenant_anchor)` is stable for the spend
but does not reveal the lane id.

`RgkLaneGraphNode` and `derive_private_lane_graph_root` commit to an ordered
set of lane nodes with the native `rgk:lane:graph-root:v1` domain. The current
Groth16 graph proof is bounded: local devnet evidence proves a 2-node
current/look-ahead graph under one hidden view key and lineage-bound asset
label.

`private_lane_graph_empty_root` and `extend_private_lane_graph_root` define the
rolling root used by segmented graph proofs. Each segment proof is bounded, but
segments can be chained from the empty root to an advertised final root for an
arbitrary-size private lane graph. Local devnet evidence proves a 2-segment /
4-node chain; a single recursive graph proof is still not claimed.

## Proof Policy

Proof policy is state:

```rust
pub enum RgkProofPolicy {
    VerifierReceipt { verifier_key_hash: [u8; 32] },
    ZkReceipt { verifier_key_id: [u8; 32], image_id_policy: ImageIdPolicy },
    Hybrid { verifier_key_hash: [u8; 32], verifier_key_id: [u8; 32] },
}
```

Dynamic image ids are allowed only when constrained by a committed
`ImageIdPolicy`. Unconstrained witness-selected image ids are rejected.

## Two-Phase Continuation Output

The continuation model must avoid circular txid dependency.

Phase 1:

* `RgkContinuationPlan` creates a continuation commitment
* the plan binds the previous allocation set and next allocation shape
* the plan avoids requiring the future txid

Phase 2:

* `RgkContinuationPlan::finalize` finalises the continuation output after the
  txid exists
* finalisation binds the actual txid by creating a normal `RgkTransition`
* receipts carry the phase-1 commitment
* spend history persists continuation proof metadata
* the resolver rejects missing continuation proof and rejects a continuation
  outpoint whose txid does not match the observed spend txid

Implemented tests:

* old covenant output spent
* new continuation output created
* future txid not needed in phase 1
* phase 2 binds actual txid
* replay rejected
* wrong continuation rejected

The remaining production work is no longer basic phase-1 persistence, local
resolver classification, wallet-side migration proof construction, local devnet
migration recovery, bounded 2-node private-lane graph proofing, or segmented
arbitrary-size graph proof chains. It is funded public staging and, if required
by product scope, a single recursive or aggregated allocation-vector proof.
The current production allocation strategy already has fixed-shape proofs for
the evidenced arities and segmented audit certificates for larger conserving
full-state transfers.
