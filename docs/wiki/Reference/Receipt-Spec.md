# Reference / Receipt Spec

> **Canonical source:** [`docs/RECEIPT-SPEC.md`](../../RECEIPT-SPEC.md).
> Source code: [`crates/rgk-core/src/types.rs:189`](../../crates/rgk-core/src/types.rs)
> and [`crates/rgk-receipt/src/lib.rs`](../../crates/rgk-receipt/src/lib.rs).

`RgkReceipt` is the canonical statement that a native RGK asset transition
advanced a covenant state. It is **typed**, **hash-bound**, and **not the
proof** — for `ProofMode::ZkReceipt` the actual ZK proof is a separate
transport that the Toccata precompile consumes.

---

## `ReceiptInput`

```rust
pub struct ReceiptInput {
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub old_state: RgkStateCommitment,
    pub new_state: RgkStateCommitment,
    pub transition_digest: TransitionDigest,
    pub continuation_commitment: ContinuationCommitment,
    pub proof_mode: ProofMode,
    pub replay_nonce: Bytes32,
}
```

Source: [`docs/RECEIPT-SPEC.md:9-18`](../../RECEIPT-SPEC.md) and
[`crates/rgk-receipt/src/lib.rs:103`](../../crates/rgk-receipt/src/lib.rs).

Constructor: `ReceiptInput::new(...) -> Result<Self, ReceiptError>` —
validates the structure (chain id consistency, non-zero digests, etc.).

---

## `RgkStateCommitment`

```rust
pub struct RgkStateCommitment {
    pub version: u16,
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub asset_id: RgkAssetId,
    pub state_digest: Bytes32,
    pub receipt_policy: ReceiptPolicy,
}
```

Source: [`docs/RECEIPT-SPEC.md:24-31`](../../RECEIPT-SPEC.md) and
[`crates/rgk-core/src/types.rs`](../../crates/rgk-core/src/types.rs).

---

## The 9 Structural Invariants

`RgkReceipt::validate_structure` enforces (from
[`crates/rgk-core/src/types.rs:239-295`](../../crates/rgk-core/src/types.rs)):

1. No-op transitions (`old.digest == new.digest`) are **rejected**.
2. `chain_id` consistency between `old_state`, `new_state`, and the
   receipt.
3. `covenant_id` consistency.
4. `asset_id` consistency.
5. `receipt_policy` consistency.
6. `proof_mode` must be admitted by `old_state.receipt_policy`.
7. `transition_digest` is non-zero.
8. `continuation_commitment` is non-zero.
9. `replay_nonce` is non-zero.

A receipt that fails any of these cannot be verified by
`ReceiptVerifier::verify_local`.

---

## `receipt_id`

```text
receipt_id = H("rgk:receipt" || canonical_receipt_bytes)
```

Source: [`docs/RECEIPT-SPEC.md:48`](../../RECEIPT-SPEC.md) and
[`crates/rgk-core/src/commit.rs:100`](../../crates/rgk-core/src/commit.rs).

**Scope of the receipt.** The `receipt_id` is a 32-byte hash commitment to
the canonical receipt bytes. It is **derived**, not chosen. Two receipts
with the same canonical bytes have the same `receipt_id`. Two receipts
with different bytes have different `receipt_id`s with overwhelming
probability.

---

## Constructors

| Call | Returns | File:line |
| --- | --- | --- |
| `RgkReceipt::new(chain, covenant, old, new, transition_digest, continuation_commitment, proof_mode, replay_nonce)` | `Result<Self, DecodeError>` | [`crates/rgk-core/src/types.rs:211`](../../crates/rgk-core/src/types.rs) |
| `ReceiptBuilder::build(&ReceiptInput)` | `Result<(RgkReceipt, ReceiptId, Vec<u8>), ReceiptError>` | [`crates/rgk-receipt/src/lib.rs:175`](../../crates/rgk-receipt/src/lib.rs) |
| `receipt_commitment(&receipt) -> ReceiptId` | `Bytes32` | [`crates/rgk-core/src/commit.rs:100`](../../crates/rgk-core/src/commit.rs) |
| `replay_nonce(prev_outpoint_payload, transition_digest) -> Bytes32` | `Bytes32` | [`crates/rgk-core/src/commit.rs:117`](../../crates/rgk-core/src/commit.rs) |

---

## Verifiers

| Call | Returns | Notes |
| --- | --- | --- |
| `ReceiptVerifier::verify_local(receipt_bytes, expected_covenant_id, expected_old_state, verifier_chain)` | `Result<ReceiptId, ReceiptError>` | Pure structural, no indexer. Suitable for `no_std`. |
| `ReceiptVerifier::verify_local_structured(receipt, ...)` | `Result<ReceiptId, ReceiptError>` | Structured variant. |
| `RgkResolver::verify_receipt_against_indexer(covenant, receipt_bytes)` | `Result<RgkStateCommitment, ReceiptError>` | Indexer-aware: enforces replay protection. |

The chain-domain check (`chain_id` consistency) is **strict** — a mainnet
receipt will never be accepted on a simnet.

---

## Cross-references

- [`docs/RECEIPT-SPEC.md`](../../RECEIPT-SPEC.md) — canonical source.
- [Tutorial-2: Build, Verify, and Resolve a Receipt](../Tutorials/Tutorial-2-Receipts.md).
- [Concepts / Bounded Objects](../Concepts/Bounded-Objects.md) — the
  32-byte invariants.
- [Glossary](../Glossary.md#domain-separated-tags) — the `"rgk:receipt"`
  domain-separated tag.