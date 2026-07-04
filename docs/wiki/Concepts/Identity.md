# Concepts / Identity

> **The asset's real identity is the covenant lineage, not an external
> contract id.** `asset_id` is native label material committed into the
> lineage, not the primary identity.

This page pulls together the lineage formula, the `asset_id` derivation, the
provenance of the byte types, and the answer to the most common question:
"if `asset_id` is just a hash, can't I mint two assets with the same id?"

---

## The Two Identities

RGK has two distinct 32-byte fields. They look similar but play very
different roles:

| Field | What it commits to | Where it appears |
| --- | --- | --- |
| `lineage_id` | `H("rgk:lineage" \|\| genesis_outpoint_payload \|\| asset_id)` | `CovenantState.lineage_id`, `RgkStateCommitment` lineage digest. **This is the canonical asset identity.** |
| `asset_id` (`RgkAssetId`) | `RgkAssetIssue::derive_asset_id(...)` over supply + commitments + allocations + lane_id + privacy + proof policy | `CovenantState.asset_id`, label in wallets. **This is the wallet-friendly label.** |

Source locations:

- `lineage_id` formula: [`docs/COVENANT-SPEC.md` §Lineage](../../COVENANT-SPEC.md)
  (`docs/COVENANT-SPEC.md:33`).
- `RgkAssetIssue::derive_asset_id`:
  [`crates/rgk-asset/src/native.rs:1179`](../../crates/rgk-asset/src/native.rs).
- `RgkAssetIdDerivation` struct:
  [`crates/rgk-asset/src/native.rs:808-819`](../../crates/rgk-asset/src/native.rs).

---

## Why "lineage first, label second"?

Because **the lineage is what the covenant commits to**, and the covenant is
what the chain sees. If two issuances happened to derive the same
`asset_id` but anchored to different genesis outpoints, they would have
**different `lineage_id`s**, and a verifier checking the covenant payload
would see them as distinct assets.

The intuition:

```
       asset_id (label)            lineage_id (identity)
              │                              │
              │  H(supply + commitments +    │  H("rgk:lineage" ||
              │      allocations + lane +    │      genesis_outpoint_payload ||
              │      privacy + proof)        │      asset_id)
              │                              │
              ▼                              ▼
   wallet / explorer display           on-chain covenant payload
   ("RGK-USD", "My Coin #1")          (the thing that makes
                                        two assets non-fungible
                                        even if labels collide)
```

So the answer to "can I mint two assets with the same `asset_id`?" is:
*technically yes, but they will have different `lineage_id`s, and a verifier
will see them as different assets.* You cannot impersonate someone else's
asset because you cannot reuse their genesis outpoint.

The canonical statement: see [`docs/LANE-CALCULUS.md` §Identity](../../LANE-CALCULUS.md).

---

## The `lineage_id` Formula in Code

```text
lineage_id = H("rgk:lineage" || genesis_outpoint_payload || asset_id)
```

This is the literal formula at `docs/COVENANT-SPEC.md:33`. The two
ingredients:

1. **`genesis_outpoint_payload`** — the canonical encoding of the genesis
   covenant UTXO (transaction_id + index). This is the **physical anchor**:
   the chain knows there is exactly one such output per lineage.
2. **`asset_id`** — derived from the issue's commitments (see below).
   Including it inside the lineage id means two issues with the same
   supply/commitments but different genesis outputs will have **different
   lineage ids**, even if the assets would otherwise look similar.

The domain tag `"rgk:lineage"` is a [domain-separated commitment tag](../Glossary.md#domain-separated-tags)
— it is what prevents a malicious wallet from re-using the same hash for a
different purpose. See [Concepts / Bounded Objects](./Bounded-Objects.md)
for the full table.

The full lineage-vs-label explanation is also in
[`Quant Dev / INTRODUCTION.md`](https://github.com/a19q3/quant-dev/blob/main/INTRODUCTION.md#identity-lineage-first-label-second).

---

## The `asset_id` Derivation in Code

`asset_id` is not chosen by the issuer. It is **derived** from the issue's
structural fields:

```rust
// crates/rgk-asset/src/native.rs:1179
RgkAssetIssue::derive_asset_id(RgkAssetIdDerivation {
    chain,
    schema_id,                  // RGK_FUNGIBLE_ASSET_SCHEMA_ID = b"rgk:asset:schema:v1_____________"
    total_supply,
    metadata_commitment,
    owner_commitment,
    allocations: &[...],
    lane_id,
    privacy_policy: LanePrivacyPolicy::PrivateLane,
    proof_policy: &policy,
}) -> Result<RgkAssetId, RgkAssetError>
```

The derivation hashes these inputs with a domain-separated commitment
scheme. The exact algorithm is in
[`crates/rgk-asset/src/native.rs`](../../crates/rgk-asset/src/native.rs).

> **Important:** `asset_id` is not a name. It is a **commitment** to the
> issuer's full initial state. Any change to supply, allocations, owner,
> lane, privacy, or proof policy produces a different `asset_id`.

---

## The Two `Hex32` Aliases (where they come from)

Both `RgkAssetId` and `RgkSchemaId` are newtype wrappers around `[u8; 32]`.
The type alias is defined at
[`crates/rgk-asset/src/native.rs:20`](../../crates/rgk-asset/src/native.rs):

```rust
pub type BlindedLaneId = Bytes32;  // and similar aliases for asset_id, schema_id
```

The type system enforces that you cannot accidentally swap an `asset_id`
for a `lineage_id` or a `lane_id`. The audit at
[`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md)
resolved the historical `Hex32` triplication; today's code uses the
purpose-named aliases consistently.

---

## What This Means in Practice

| Scenario | What you observe |
| --- | --- |
| You issue the same supply + commitments twice (different genesis outpoints). | Two different `asset_id`s (different allocations / lane state), and **two different `lineage_id`s** (different genesis outpoint payload). The chain sees two assets. |
| You tweak the allocations between issue and first transfer. | The `asset_id` would have been different from the start — but once the lineage is anchored, **allocations cannot change** without breaking the lineage id. |
| Someone tries to swap a label on the chain. | The covenant payload carries `asset_id` + `lineage_id`. A label swap on the wallet side doesn't touch the on-chain payload; verifiers reject it. |
| You migrate the proof policy. | That goes through `RgkProofPolicy::commitment()` and `PolicyMigrationInput::build(...)` (see [Concepts / Production Allocation Strategy](./Production-Allocation-Strategy.md) and [`docs/INTEGRATION.md` §Policy Migration](../../INTEGRATION.md)). The lineage id is preserved because the migration is a state transition, not a re-issue. |

---

## Cross-references

- [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md) — `CovenantState`
  struct, payload byte layout, `lineage_id` formula.
- [`docs/LANE-CALCULUS.md` §Identity](../../LANE-CALCULUS.md) — hot-path
  types, lineage vs label boundary.
- [`docs/RECEIPT-SPEC.md`](../../RECEIPT-SPEC.md) — how `asset_id` and
  `lineage_id` flow into the receipt.
- [`Quant Dev / INTRODUCTION.md`](https://github.com/a19q3/quant-dev/blob/main/INTRODUCTION.md)
  §9 "Identity: Lineage First, Label Second".
- [Tutorial-2: Build, Verify, and Resolve a Receipt](../Tutorials/Tutorial-2-Receipts.md)
  — shows the build path.
- [Tutorial-3: Integrate a Wallet](../Tutorials/Tutorial-3-Integrate-A-Wallet.md)
  — shows the integration-side derivation.