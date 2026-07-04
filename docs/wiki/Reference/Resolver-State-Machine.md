# Reference / Resolver State Machine

> **Canonical source:** [`docs/ARCHITECTURE.md` §Resolver States](../../ARCHITECTURE.md)
> and [`crates/rgk-resolver/src/lib.rs:42-108`](../../crates/rgk-resolver/src/lib.rs).

This page is a one-screen reference to the 13-variant state machine. For
worked examples and state transitions, see
[Concepts / Resolver](../Concepts/Resolver.md).

---

## The 13 Variants (at a glance)

| # | Variant | Trigger | Failure class? |
| --- | --- | --- | --- |
| 1 | `Open { covenant, outpoint, state }` | Indexed + UTXO present | No |
| 2 | `NativeTransitionedValid { … }` | Spend + depth ≥ safety + proofs match | No (success) |
| 3 | `NativeTransitionedInvalid { covenant, reason }` | Spend observed, proofs fail | **Yes** |
| 4 | `Unconfirmed { covenant, spending_txid }` | In mempool only | No (pending) |
| 5 | `ReorgRisk { covenant, daa_score }` | Confirmed, depth < safety | No (pending) |
| 6 | `CompetingBranch { … }` | Indexer ≠ chain on spending txid | **Yes** (consensus) |
| 7 | `PolicyMigrationRequired { … }` | Receipt requests policy change w/o proof | **Yes** (recovery) |
| 8 | `ReplayRejected { covenant, receipt_id }` | Receipt id already accepted | **Yes** (security) |
| 9 | `Unknown { covenant }` | Not indexed or pruned | No |
| 10 | `NodeDown { covenant, reason }` | Backend error | No (operational) |
| 11 | `LaneResolverState::Resolved { lane, state }` | Lane lookup succeeded | No |
| 12 | `LaneResolverState::UnknownLane` | No lane for the supplied key | No |
| 13 | `LaneResolverState::UnknownScanTag` | Lane exists, scan tag mismatch | No |

Plus `TransitionResolverState` (`Resolved`, `UnknownTransition`) for
`transition_digest`-keyed lookups.

---

## Entry Points

| Call | Returns | File:line |
| --- | --- | --- |
| `resolve_by_covenant(covenant)` | `ResolverState` | [`crates/rgk-resolver/src/lib.rs:191`](../../crates/rgk-resolver/src/lib.rs) |
| `resolve_by_asset(asset_id)` | `ResolverState` (linear scan) | [`crates/rgk-resolver/src/lib.rs:399`](../../crates/rgk-resolver/src/lib.rs) |
| `resolve_lane(lane_id)` | `LaneResolverState` | [`crates/rgk-resolver/src/lib.rs:412`](../../crates/rgk-resolver/src/lib.rs) |
| `resolve_by_view_key(view_key, asset_id, epoch)` | `LaneResolverState` | [`crates/rgk-resolver/src/lib.rs:419`](../../crates/rgk-resolver/src/lib.rs) |
| `resolve_by_scan_tag(scan_tag)` | `LaneResolverState` | [`crates/rgk-resolver/src/lib.rs:442`](../../crates/rgk-resolver/src/lib.rs) |
| `resolve_public_lineage(asset_id)` | `Vec<LaneResolverState>` (filtered) | [`crates/rgk-resolver/src/lib.rs:451`](../../crates/rgk-resolver/src/lib.rs) |
| `resolve_transition(transition_digest)` | `TransitionResolverState` | [`crates/rgk-resolver/src/lib.rs:459`](../../crates/rgk-resolver/src/lib.rs) |
| `verify_receipt_against_indexer(covenant, receipt_bytes)` | `Result<RgkStateCommitment, ReceiptError>` | [`crates/rgk-resolver/src/lib.rs:493`](../../crates/rgk-resolver/src/lib.rs) |

---

## What the Resolver Does NOT Return

- No `OptimisticValid`. No `SoftInvalid`. No `Pending`. Every variant
  means one specific thing.
- No `Replayed` / `DoubleSpent` as separate variants. These collapse into
  `ReplayRejected` and `CompetingBranch`.
- No `UnknownChain`. Chain-domain mismatch is enforced upstream at
  `ReceiptInput::new`.

---

## Cross-references

- [Concepts / Resolver](../Concepts/Resolver.md) — worked treatment.
- [`docs/ARCHITECTURE.md`](../../ARCHITECTURE.md) — canonical source.
- [`docs/SECURITY.md` §Resolver Classifications](../../SECURITY.md).
- [Glossary](../Glossary.md#resolver-states-the-13-hard-outcomes).