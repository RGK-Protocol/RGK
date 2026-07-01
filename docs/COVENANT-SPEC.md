# Covenant Spec

The RGK covenant is a Kaspa Toccata covenant UTXO that carries one native RGK
state payload for an asset lineage.

## Covenant State

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

The encoded payload preserves this order:

```text
tag | version | chain_id | lineage_id | asset_id | state_digest | policy | mode | replay_marker
```

`asset_id`, `lineage_id`, `receipt_policy`, and `genesis_proof_mode` are
immutable across ordinary spends.

## Lineage

```text
lineage_id = H("rgk:lineage" || genesis_outpoint_payload || asset_id)
```

The lineage id groups covenant outputs descended from the same genesis
outpoint and native asset label. The canonical asset identity is this covenant
lineage. `asset_id` is immutable lineage-bound label material, not an external
contract id.

## Script Invariants

`CovenantSpec::build_script()` emits the default singleton continuation
policy. It enforces:

* the spend is authorised by input 0
* there is exactly one covenant output
* the covenant output is at index 0
* input and output covenant ids are preserved
* payload length matches the canonical RGK state length
* chain id, lineage id, `asset_id` label, receipt policy, and proof mode match
  the redeem-script constants

Semantic transition validity remains a client-side RGK validation and resolver
responsibility. Native two-phase continuation primitives bind a phase-1
txid-free continuation commitment to phase-2 txid finalisation. Receipts carry
that commitment, spend history persists continuation proof metadata, and the
resolver rejects missing proof or a continuation outpoint whose txid does not
match the observed spend txid.

`CovenantSpec::build_script_for_policy()` emits the same checks for an explicit
`CovenantContinuationPolicy`:

* the configured `authorizing_input` must be the input currently executing the
  redeem script
* `OP_TX_OUTPUT_COUNT` must equal `exact_output_count`
* every listed covenant output index must keep the spent UTXO script public key
* every listed covenant output must preserve the input covenant id
* every listed covenant output must record the configured authorising input
* policy construction rejects empty, duplicate, unsorted, or out-of-range
  covenant output indices

This supports locally evidenced continuation fanout with explicit extra outputs
for fee/change slots. Those extra outputs are admitted only by exact output
count; their economic meaning remains bound by the RGK receipt/resolver layer.

`CovenantSpec::build_script_for_shared_policy()` emits a merge/batch-oriented
shape for transactions with multiple inputs carrying the same covenant id:

* `OP_TX_OUTPUT_COUNT` must equal the configured exact output count
* `OP_COV_INPUT_COUNT` must equal the configured shared covenant input count
* `OP_COV_OUTPUT_COUNT` must equal the configured shared covenant output count
* every shared covenant output returned by `OP_COV_OUTPUT_IDX` must keep the
  current covenant input's script public key
* every shared covenant output must preserve the current input covenant id

The same redeem script can therefore execute on each input of a multi-input
merge or batch transition. Local upstream VM evidence covers a two-input
one-output merge with change, a two-input two-output batch with change, and a
missing-shared-output rejection.

The low-level continuation policy surface is also recorded as checked
Silverscript source in
`examples/silverscript/rgk_covenant_continuation_policy.sil`, with the pinned
compiler artifact at
`examples/silverscript/artifacts/rgk_covenant_continuation_policy.json`. That
artifact covers the singleton continuation, explicit fanout with change, and
shared merge/batch policy shapes. The Rust builder and upstream Toccata VM tests
remain the consensus oracle for exact opcode execution.
