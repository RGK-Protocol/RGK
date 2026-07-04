# Reference / Covenant Spec

> **Canonical source:** [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md).
> Source code: [`crates/rgk-covenant/src/lib.rs`](../../crates/rgk-covenant/src/lib.rs).

The RGK covenant is a Kaspa Toccata covenant UTXO that carries one native
RGK state payload for an asset lineage. The payload's `asset_id`,
`lineage_id`, `receipt_policy`, and `genesis_proof_mode` are **immutable
across ordinary spends**.

---

## `CovenantState` (verbatim)

```rust
pub struct CovenantState {
    pub version: u16,
    pub chain_id: KaspaChainId,
    pub lineage_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub current_state_digest: [u8; 32],
    pub receipt_policy: ReceiptPolicy,
    pub genesis_proof_mode: ProofMode,
    pub replay_marker: [u8; 32],
}
```

Source: [`docs/COVENANT-SPEC.md:9-19`](../../COVENANT-SPEC.md).

---

## Payload Byte Layout

```text
tag | version | chain_id | lineage_id | asset_id | state_digest | policy | mode | replay_marker
```

- `tag` — RGK covenant discriminator.
- `version` — bumping is a breaking change.
- `chain_id` — 32-byte network id.
- `lineage_id` — see [Concepts / Identity](../Concepts/Identity.md).
- `asset_id` — see [Concepts / Identity](../Concepts/Identity.md).
- `state_digest` — `RgkStateDigest` of the current state.
- `policy` — `ReceiptPolicy` (`Any` / `VerifierOnly` / `ZkOnly`).
- `mode` — `ProofMode` of the genesis.
- `replay_marker` — domain-separated tag.

Total: bounded by `MAX_BLOB_BYTES` (see [Concepts / Bounded Objects](../Concepts/Bounded-Objects.md)).

---

## Script Invariants

The default `CovenantSpec::build_script()` emits a singleton continuation
policy that preserves:

- The covenant id (so the lineage is anchored).
- The payload length.
- The lineage / asset / policy / mode constants.

Explicit forms:

- `CovenantSpec::build_script_for_policy(...)` — for non-default
  `CovenantContinuationPolicy` shapes (fanout, merge, batch).
- `CovenantSpec::build_script_for_shared_policy(...)` — for the shared
  continuation policy used by merge / batch.

Toccata opcodes referenced: `OP_TX_OUTPUT_COUNT`, `OP_COV_INPUT_COUNT`,
`OP_COV_OUTPUT_COUNT`, `OP_COV_OUTPUT_IDX`.

---

## Lineage Formula

```text
lineage_id = H("rgk:lineage" || genesis_outpoint_payload || asset_id)
```

The genesis outpoint payload is the canonical encoding of the genesis
covenant UTXO (transaction_id + index). The `asset_id` is derived per
`RgkAssetIssue::derive_asset_id` (see [Concepts / Identity](../Concepts/Identity.md)).

---

## Files

- `examples/silverscript/rgk_covenant_continuation_policy.sil` —
  reference Silverscript source.
- `examples/silverscript/artifacts/rgk_covenant_continuation_policy.json` —
  checked JSON artifact.

---

## Cross-references

- [`docs/COVENANT-SPEC.md`](../../COVENANT-SPEC.md) — canonical source.
- [Concepts / Identity](../Concepts/Identity.md) — lineage vs label.
- [Concepts / Continuation](../Concepts/Continuation.md) — the two-phase
  model the covenant enforces.
- [Concepts / Architecture](../Concepts/Architecture.md) — the L3 layer.