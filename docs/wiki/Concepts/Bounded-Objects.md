# Concepts / Bounded Objects

> **Every wire object is 32 bytes (or a canonical `MAX_BLOB_BYTES`).**
> This is not arbitrary. The 32-byte invariant is what makes the resolver
> bounded, the verifier no_std-friendly, and the chain lean.

This page lifts the table from [`docs/VERIFICATION-BUDGET.md`](../../VERIFICATION-BUDGET.md)
into tutorial form and explains why each bound exists.

---

## The Table

| Object | Size | Why this size | Where it's enforced |
| --- | --- | --- | --- |
| `asset_id` (`RgkAssetId`) | 32 bytes | Hash commitment to supply + commitments + allocations + lane + privacy + proof policy. | `RgkAssetIssue::derive_asset_id` ([`crates/rgk-asset/src/native.rs:1179`](../../crates/rgk-asset/src/native.rs)). |
| `schema_id` (`RgkSchemaId`) | 32 bytes | Hash commitment to the schema grammar. `RGK_FUNGIBLE_ASSET_SCHEMA_ID = b"rgk:asset:schema:v1_____________"` is a fixed 32-byte ASCII string. | [`crates/rgk-asset/src/lib.rs:111`](../../crates/rgk-asset/src/lib.rs). |
| `state_digest` (`RgkStateDigest`) | 32 bytes | Hash commitment to the asset's current state. | `RgkStateCommitment::state_digest`. |
| `transition_digest` (`RgkTransitionDigest`) | 32 bytes | Hash commitment to the spend that produced the transition. Bound into the receipt and the covenant script. | `RgkTransitionReport::transition_digest` ([`crates/rgk-asset/src/native.rs:927`](../../crates/rgk-asset/src/native.rs)). |
| `lane_id` (`BlindedLaneId`) | 32 bytes | `H(view_key, asset_id, epoch)` for private lanes; chain-tagged for public lanes. | `derive_blinded_lane_id` ([`crates/rgk-asset/src/native.rs:770`](../../crates/rgk-asset/src/native.rs)). |
| `scan_tag` (`RgkScanTag`) | 32 bytes | `H(view_key, lane_id, epoch)`. Rotates per epoch. | `RgkScanTag::derive` ([`crates/rgk-asset/src/native.rs:749`](../../crates/rgk-asset/src/native.rs)). |
| `nullifier` (`RgkNullifier`) | 32 bytes | `H(spend_secret, covenant_anchor)`. Stable for the spend, unlinked to lane_id. | `RgkNullifier::derive` ([`crates/rgk-asset/src/native.rs:759`](../../crates/rgk-asset/src/native.rs)). |
| `policy_commitment` (`RgkPolicyCommitment`) | 32 bytes | `RgkProofPolicy::commitment()` — domain hash over the canonical policy encoding. | [`crates/rgk-asset/src/native.rs:509`](../../crates/rgk-asset/src/native.rs). |
| `receipt_id` | 32 bytes | `H("rgk:receipt" \|\| canonical_receipt_bytes)`. **Derived**, not chosen. | [`crates/rgk-core/src/commit.rs:100`](../../crates/rgk-core/src/commit.rs). |
| `continuation_commitment` (`RgkContinuationCommitment`) | 32 bytes | Domain hash over the phase-1 plan's canonical encoding. Stable across re-plans; binds the script witness. | `RgkContinuationPlan::validate` ([`crates/rgk-asset/src/native.rs:1476`](../../crates/rgk-asset/src/native.rs)). |
| `covenant_id` (`KaspaCovenantId`) | 32 bytes | Kaspa-native covenant UTXO id. | upstream Toccata. |
| `chain_id` (`KaspaChainId`) | 32 bytes | Network identifier — mainnet, testnet, devnet, simnet, local-toccata. | `rgk-core`. |
| **Receipt body** (`RgkReceipt`) | bounded by canonical `MAX_BLOB_BYTES` | All fields above plus a few small length prefixes. The Borsh-encoded body never exceeds `MAX_BLOB_BYTES`. | `ReceiptInput::new` ([`crates/rgk-receipt/src/lib.rs:115`](../../crates/rgk-receipt/src/lib.rs)). |
| **Covenant payload** (`CovenantState`) | bounded by canonical `MAX_BLOB_BYTES` | `tag \| version \| chain_id \| lineage_id \| asset_id \| state_digest \| policy \| mode \| replay_marker`. | [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md). |

---

## Why 32 Bytes?

Three reasons.

### 1. Domain separation works at 32 bytes

A 32-byte domain-separated hash is enough to give every RGK concept its
own commitment space. See [Glossary §Domain-Separated Tags](../Glossary.md#domain-separated-tags)
for the full tag list. With 32 bytes (256 bits) per tag, collision risk is
negligible for any practical deployment.

### 2. BN254 field elements fit

The ZK path uses BN254 (alt-bn128). A field element is 32 bytes. The
public-input byte/field counts in [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md)
all reflect this — every field element is one 32-byte word.

| Statement | Bytes | Fields |
| --- | --- | --- |
| Receipt statement | 232 | 29 |
| Semantic transition | 512 | 64 |
| Lane discovery | 72 | 9 |
| Allocation transcript | 128 | 16 |
| Allocation conservation | 192 | 24 |
| Conservation final | 80 | 10 |
| Exclusion pair | 232 | 29 |

All multiples of 32. None exceed `MAX_BLOB_BYTES`.

### 3. Bounded verification cost

If every wire object is 32 bytes (or a small bounded prefix), the verifier
runs in bounded time and memory. The bounded-checked property is what
makes the resolver safe to call in a hot loop, what makes the receipt
verifier `no_std`-friendly, and what lets the indexer persist millions of
records without memory pressure.

---

## Fail-Closed Rules

Every wire check is **fail-closed**. From
[`docs/VERIFICATION-BUDGET.md` §Fail-Closed Rules](../../VERIFICATION-BUDGET.md#fail-closed-rules):

| Condition | Verdict |
| --- | --- |
| Unknown version | **Reject.** |
| Unknown chain id | **Reject** — even if everything else matches. |
| Malformed payload (wrong length, wrong tag) | **Reject.** |
| Missing `transition_digest` | **Reject.** |
| Missing `replay_nonce` | **Reject.** |
| No-op transition (`old.digest == new.digest`) | **Reject.** |
| Supply mismatch (`sum(allocations[].amount) != total_supply`) | **Reject.** |
| Spent covenant-output reuse | **Reject** (the phase-1 commitment binds the next shape; reusing the spent anchor is structurally impossible). |
| Unconstrained `image_id` | **Reject** (proof policy is part of state). |
| Receipt replay (same id twice for same covenant) | **Reject** (`ReplayRejected`). |

There is no "soft" rejection. There is no "warning." There is no "skip
this check." All checks are required, all the time.

---

## What the Resolver Does NOT Do (by design)

The resolver only classifies after bounded local checks:

1. `lookup(covenant)` → O(log n) BTreeMap lookup.
2. `get_utxo(...)` → O(1) backend call.
3. Confirmation depth ≥ `reorg_safety_depth` (default 10).
4. Receipt and continuation proof pass `verify_local`-style structural
   checks — no ZK proving work here.
5. Receipt id not in the indexer's replay set.

No expensive computation. No network calls inside the resolver. No dynamic
allocation beyond the result variant. The resolver budget is bounded by
construction.

See [`docs/VERIFICATION-BUDGET.md` §Resolver Budget](../../VERIFICATION-BUDGET.md#resolver-budget)
for the full enumeration.

---

## Worked Example — Why `MAX_BLOB_BYTES` Matters

A canonical receipt encodes, in order:

```text
version : u16                       (2 bytes)
chain_id : KaspaChainId             (32 bytes)
covenant_id : KaspaCovenantId       (32 bytes)
old_state : RgkStateCommitment      (bounded by MAX_BLOB_BYTES)
new_state : RgkStateCommitment      (bounded by MAX_BLOB_BYTES)
transition_digest : Bytes32         (32 bytes)
continuation_commitment : Bytes32   (32 bytes)
proof_mode : ProofMode              (1 byte + enum-specific bytes)
replay_nonce : Bytes32              (32 bytes)
```

The total is at most `2 + 32*5 + 2 * MAX_BLOB_BYTES + 1 + 32 = 195 + 2 *
MAX_BLOB_BYTES`. `MAX_BLOB_BYTES` is the canonical blob-size limit
referenced from `RgkStateCommitment` and the covenant payload. As long as
that limit is enforced at the constructor level
([`crates/rgk-core/src/types.rs:189-205`](../../crates/rgk-core/src/types.rs)),
no crafted receipt can blow up the verifier.

---

## Cross-references

- [`docs/VERIFICATION-BUDGET.md`](../../VERIFICATION-BUDGET.md) — the
  source of this page's table.
- [`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md) — public-input byte/field
  counts.
- [`docs/RECEIPT-SPEC.md`](../../RECEIPT-SPEC.md) — `RgkReceipt` field
  layout and 9 structural invariants.
- [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md) — `CovenantState` byte
  layout.
- [Glossary](../Glossary.md) — domain-separated tags.
- [Concepts / Resolver](./Resolver.md) — the bounded-checked classification.