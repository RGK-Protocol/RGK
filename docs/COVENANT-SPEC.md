# Covenant Spec

The RGK covenant is a Kaspa Toccata covenant UTXO that carries one native RGK
state cell for an asset lineage.

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
outpoint and native asset id.

## Script Invariants

The Toccata covenant script enforces:

* the spend is authorised by input 0
* there is exactly one covenant output
* the covenant output is at index 0
* input and output covenant ids are preserved
* payload length matches the canonical RGK state length
* chain id, lineage id, asset id, receipt policy, and proof mode match the
  redeem-script constants

Semantic transition validity remains a client-side RGK validation and resolver
responsibility. Native two-phase continuation primitives bind a phase-1
txid-free continuation commitment to phase-2 txid finalisation. Receipts carry
that commitment, spend history persists continuation proof metadata, and the
resolver rejects missing proof or a continuation outpoint whose txid does not
match the observed spend txid.
