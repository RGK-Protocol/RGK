# Tutorial 3 — Integrate a Wallet

!!! info "At a glance"
    **Difficulty:** Advanced · **Time:** 45 min · **Code required:** Rust ·
    **You'll implement:** the 7-step Issue and 10-step Transfer procedures
    a wallet must implement, plus private-lane discovery, policy migration,
    and advanced covenant flows.

> **Read time:** ~45 minutes. **Code-first.** The 7-step Issue and 10-step
> Transfer procedures a wallet must implement, lifted from
> [`docs/INTEGRATION.md`](../../INTEGRATION.md) and made concrete.

This tutorial is what a wallet team reads first. It assumes you have
already done [Tutorial-0](./Tutorial-0-10-Minute-Fixture-Walkthrough.md)
and [Tutorial-2](./Tutorial-2-Receipts.md).

---

## Issue — the 7-Step Procedure

The wallet must do these things in this order:

### 1. Pick `LanePrivacyPolicy::PrivateLane` (the default)

Unless the asset is intentionally public, choose private. The
[`LanePrivacyPolicy` default is `PrivateLane`](../Glossary.md#hot-path-types),
so an explicit opt-in is required for `PublicLineage`.

### 2. Commit `RgkProofPolicy`

```rust
use rgk_asset::native::RgkProofPolicy;

let policy = RgkProofPolicy::VerifierReceipt {
    verifier_key_hash: [0x91; 32],   // example; pin to your verifier key
};
```

For ZK receipts, use:

```rust
let policy = RgkProofPolicy::ZkReceipt {
    verifier_key_id: [0xab; 32],
    image_id_policy: ImageIdPolicy::Fixed([0xcd; 32]),
};
```

Never use `ImageIdPolicy::PolicyBranch([0;32])` or
`ImageIdPolicy::AllowedSet(vec![])` — both are rejected at validation. See
[Concepts / Bounded Objects](../Concepts/Bounded-Objects.md).

### 3. Build `RgkAssetIssue` with the right invariants

Source: [`crates/rgk-asset/src/native.rs:827`](../../crates/rgk-asset/src/native.rs).

```rust
let issue = RgkAssetIssue {
    chain: KASPA_LOCAL_TOCCATA,
    schema_id: *b"rgk:asset:schema:v1_____________",
    asset_id: RgkAssetIssue::derive_asset_id(RgkAssetIdDerivation {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id: *b"rgk:asset:schema:v1_____________",
        total_supply,
        metadata_commitment,
        owner_commitment,
        allocations: &allocations,
        lane_id,
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: &policy,
    })?,
    total_supply,
    metadata_commitment,
    owner_commitment,
    allocations,
    lane_id,
    privacy_policy: LanePrivacyPolicy::PrivateLane,
    proof_policy: policy,
};
```

### 4. Validate

```rust
let report: RgkIssueReport = issue.validate()?;
```

`validate()` enforces:

- `total_supply == sum(allocations[].amount)`
- `allocations.len() <= MAX_ALLOCATIONS` (bounded)
- Allocations have non-zero `covenant_outpoint.transaction_id` if they
  have anchors; genesis allocations use the genesis payload.
- `lane_id` is non-zero.
- `privacy_policy` admits the chosen `proof_policy`.

### 5. Optionally validate for production ZK

```rust
let zk_report = issue.validate_for_production_zk()?;
```

This is stricter: allocations must fit a supported ZK shape
(`RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT = 4`).

### 6. Persist the lineage / lane as identity

The wallet stores:

- `issue.asset_id` (the wallet label).
- `issue.lineage_id` (the on-chain identity; not a field — derive it
  from `H("rgk:lineage" || genesis_outpoint_payload || asset_id)`).
- `issue.lane_id` (the holder's lane, if `PrivateLane`).
- The view key (holder-side, never on disk in cleartext).

### 7. Submit the genesis covenant spend

Build a covenant genesis output:

```rust
let genesis_output = build_genesis_output(
    covenant_script,
    covenant_id,
    initial_state_payload,
)?;
```

Sign and broadcast. The chain sees one covenant UTXO carrying the lineage
payload. The wallet then waits for confirmation depth ≥
`reorg_safety_depth` and asks the resolver to confirm `Open`.

---

## Transfer — the 10-Step Procedure

### 1. Build the `RgkContinuationPlan` (phase 1)

```rust
let plan = RgkContinuationPlan {
    chain: issue.chain,
    schema_id: issue.schema_id,
    asset_id: issue.asset_id,
    total_supply: issue.total_supply,
    metadata_commitment: issue.metadata_commitment,
    previous_owner_commitment: issue.owner_commitment,
    new_owner_commitment: recipient_commitment,
    ownership_authorization_commitment: hmac_of(secret, recipient_commitment),
    previous_state_digest: previous_report.state_digest,
    spent_allocations: issue.allocations,
    new_allocation_shapes: vec![/* RgkContinuationAllocationShape */],
    burn: None,
    lane_id: issue.lane_id,
    privacy_policy: issue.privacy_policy,
    proof_policy: issue.proof_policy,
};
```

### 2. (Optional) Wrap with `RgkProductionZkTransferPlan`

```rust
let zk_plan = plan.clone().into_production_zk_transfer_plan()?;
```

This selects a `RgkAllocationProofShape` and rejects unsupported shapes.
See [Concepts / Production Allocation Strategy](../Concepts/Production-Allocation-Strategy.md).

### 3. Sign and broadcast

Build the covenant spend with the phase-1 commitment baked into the
script as a witness. Sign and broadcast.

### 4. Finalize (phase 2)

```rust
let finalized = plan.finalize(witness_txid, daa_score, confirmation_depth)?;
```

### 5. Build `RgkReceipt`

```rust
let input = ReceiptInput::new(
    chain, covenant_id,
    old_state.clone(), new_state.clone(),
    finalized.transition_report.transition_digest.to_bytes(),
    finalized.transition_report.continuation_commitment.to_bytes(),
    ProofMode::VerifierReceipt,
    replay_nonce(...),
)?;
let (receipt, receipt_id, receipt_bytes) = ReceiptBuilder::build(&input)?;
```

### 6. Verify the receipt locally

```rust
ReceiptVerifier::verify_local(&receipt_bytes, covenant_id, &old_state, chain)?;
```

Use the indexer-aware `RgkResolver::verify_receipt_against_indexer` if
you want replay protection at the wallet too.

### 7. Apply the spend to the indexer

```rust
idx.apply_spend_with_continuation(
    covenant_id,
    receipt_id,
    open_outpoint,
    new_outpoint,
    new_state.clone(),
    daa_score,
    ContinuationProof {
        commitment: ...,
        shape_root: ...,
        transition_digest: ...,
    },
)?;
```

### 8. Resolve

```rust
let st = resolver.resolve_by_covenant(covenant_id);
assert!(matches!(st, ResolverState::NativeTransitionedValid { .. }));
```

### 9. (Optional) Attach an allocation audit certificate

If the production-ZK path requires it, attach the certificate via
`AllocationAuditCertificateStore`:

```rust
audit_store.attach(covenant_id, certificate_record)?;
```

### 10. Update wallet-side state

- Move the spent allocation from "available" to "spent."
- Add the new allocations to the holder's available balance.
- Update the lane state (scan tag, nullifier, etc.) if private.
- Notify any UI surfaces.

---

## Private Lane Discovery

Source: [`docs/INTEGRATION.md` §Private Lane Discovery](../../INTEGRATION.md#private-lane-discovery).

After registering a lane with the indexer, the holder can resolve it:

```rust
let lane_res = resolver.resolve_by_view_key(view_key, asset_id, epoch);
match lane_res {
    LaneResolverState::Resolved { lane, state } => {
        // state is the latest ResolverState for this lane's covenant
    }
    LaneResolverState::UnknownLane => { /* no lane for this key */ }
    LaneResolverState::UnknownScanTag => { /* lane exists, tag mismatch */ }
}
```

The other entry points:

- `resolve_by_scan_tag(scan_tag)` — for scanners that don't have the view
  key.
- `resolve_public_lineage(asset_id)` — returns only lanes with
  `public_lineage: true`.

---

## Policy Migration

Source: [`docs/INTEGRATION.md` §Policy Migration](../../INTEGRATION.md#policy-migration).

If you need to change the proof policy (e.g. rotate the verifier key):

```rust
let migration_input = PolicyMigrationInput {
    chain, covenant_id,
    current_policy: old_policy,
    requested_policy: new_policy,
    old_state, new_state,
    transition_digest,
    // ...
};
let migration_proof = build_policy_migration_proof(&migration_input)?;
```

Apply via `apply_spend_with_continuation_and_policy_migration(...)`.

The resolver recomputes the policy commitment and verifies the migration
proof. If the migration proof is missing, the resolver returns
`PolicyMigrationRequired`.

---

## Advanced Covenant Flows

Source: [`docs/INTEGRATION.md` §Advanced Covenant Flows](../../INTEGRATION.md#advanced-covenant-flows).

RGK supports richer covenant shapes:

| Shape | Use case |
| --- | --- |
| `PaymentGatedTransfer` | Transfer only when payment asset is present. |
| `Escrow` | Funds locked until both parties sign. |
| `VaultTimelockRelease` | Funds released after a DAA-score threshold. |
| `AtomicSwap` | Cross-asset atomic exchange (HTLC-style). |

The integration:

```rust
let advanced_plan = AdvancedCovenantExecutionPlan::new(
    AdvancedCovenantPolicyShape::PaymentGatedTransfer { ... },
    advanced_evidence,
)?;
let advanced_record = AdvancedCovenantExecutionRecord::new(advanced_plan)?;
```

The wallet submits this as part of the covenant spend. The covenant
enforces the policy; the resolver validates the evidence on the resolver
side.

Adversarial scenarios for these flows are at
[`docs/ADVERSARIAL-SCENARIOS.md` §IV](../../ADVERSARIAL-SCENARIOS.md).

---

## Failure Handling

**Every integration failure is fail-closed.** From
[`docs/INTEGRATION.md` §Failure Handling](../../INTEGRATION.md#failure-handling):

| Failure | Verdict |
| --- | --- |
| Supply mismatch | Reject. |
| Allocations exceed ZK shape | Reject unless wrapped in a valid audit certificate. |
| Unconstrained `image_id` | Reject. |
| Proof-policy downgrade attempt | Reject. |
| Receipt replay | Reject (`ReplayRejected`). |
| Spent anchor reuse | Reject (`ReusedSpentAnchor`). |
| Missing migration proof | Reject (`PolicyMigrationRequired`). |
| Continuation proof mismatch | Reject (`NativeTransitionedInvalid`). |

There is no "soft" rejection. There is no "skip this check."

---

## Cross-references

- [`docs/INTEGRATION.md`](../../INTEGRATION.md) — the canonical integration
  doc.
- [Tutorial-2: Build, Verify, and Resolve a Receipt](./Tutorial-2-Receipts.md) —
  the smallest receipt-building walkthrough.
- [Concepts / Continuation](../Concepts/Continuation.md) — the two-phase
  model in depth.
- [Concepts / Production Allocation Strategy](../Concepts/Production-Allocation-Strategy.md) —
  the proof path selector.
- [Concepts / Resolver](../Concepts/Resolver.md) — what the resolver
  returns.