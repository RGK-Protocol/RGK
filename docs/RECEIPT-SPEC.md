# Receipt Spec

`RgkReceipt` is the canonical statement that a native RGK asset transition
advanced a covenant state.

## Receipt Input

```rust
pub struct ReceiptInput {
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub old_state: RgkStateCommitment,
    pub new_state: RgkStateCommitment,
    pub transition_digest: [u8; 32],
    pub continuation_commitment: [u8; 32],
    pub proof_mode: ProofMode,
    pub replay_nonce: [u8; 32],
}
```

## State Commitment

```rust
pub struct RgkStateCommitment {
    pub version: u16,
    pub chain_id: KaspaChainId,
    pub covenant_id: KaspaCovenantId,
    pub asset_id: [u8; 32],
    pub state_digest: [u8; 32],
    pub receipt_policy: ReceiptPolicy,
}
```

## Structural Invariants

* old and new states use the receipt chain id
* old and new states use the receipt covenant id
* old and new states preserve `asset_id`
* receipt policy is preserved
* old and new state digests differ
* proof mode is admitted by receipt policy
* transition digest is non-zero
* continuation commitment is non-zero
* replay nonce is non-zero

## Commitment

`receipt_id = H("rgk:receipt" || canonical_receipt_bytes)`.

The receipt does not by itself prove every semantic transition rule. It binds
the validated native transition result and the phase-1 continuation commitment
to the covenant lineage so the resolver and indexer can verify replay,
continuity, and chain evidence.
