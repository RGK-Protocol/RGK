# Integration

This document sketches the wallet-side integration shape for native RGK.

## Issue

1. Build `RgkAssetIssue`.
2. Select `LanePrivacyPolicy::PrivateLane` unless public lineage is required.
3. Commit proof policy with `RgkProofPolicy`.
4. Validate the issue and store `RgkIssueReport`.
5. If the wallet is issuing into the production ZK path, call
   `validate_for_production_zk` so the initial state can later be spent by an
   evidenced allocation-proof shape.
6. Create the initial covenant output with the issue state digest.

## Transfer

1. Load the previous allocation set.
2. Build `RgkContinuationPlan` with the full previous allocation set and the
   intended phase-1 output shapes.
3. If producing ZK allocation proof material, wrap it with
   `RgkProductionZkTransferPlan::new` or
   `RgkContinuationPlan::into_production_zk_transfer_plan`. The planner
   validates the full-state transition and exposes the admitted
   `RgkAllocationProofShape` before a future txid exists.
4. After the covenant spend txid exists, call
   `RgkProductionZkTransferPlan::finalize` to build the final
   `RgkTransition` and transition report.
5. Do not split by spending only part of the previous allocation set. RGK
   transitions are full-state transitions, so any bounded multi-step flow must
   keep each intermediate full state inside the production-ZK shape policy.
6. Build `RgkReceipt` over the old and new state commitments, transition
   digest, and phase-1 continuation commitment.
7. Construct and sign the Toccata covenant spend.
8. Submit through a Kaspa backend.
9. Index the observed spend with continuation proof metadata.
10. Resolve to `NativeTransitionedValid` after the safety depth and
    continuation txid-binding check.

## Private Lane Discovery

Wallets should register local lane records with lane id, optional scan tag,
state digest, covenant id, and public-lineage flag. The resolver can then use:

* `resolve_by_view_key`
* `resolve_by_scan_tag`
* `resolve_lane`
* `resolve_public_lineage`
* `resolve_transition`

Wallets should still scan by view key:

* derive expected scan tags by epoch
* compare observed tags locally
* decrypt notes only after a tag match
* treat nullifiers as spend-local commitments, not public lane identifiers

## Proof Policy

Never accept a witness-selected unconstrained image id. Dynamic image ids must
be constrained by the committed `ImageIdPolicy`.

## Policy Migration

Receipt-policy changes are explicit. Wallets that deliberately migrate policy
should build `PolicyMigrationInput` from the previous policy, new policy,
previous state digest, resulting state digest, transition digest, and a
non-zero authorisation commitment, then call `build_policy_migration_proof` or
`PolicyMigrationInput::build`.

After submitting the spend, index it with
`apply_spend_with_continuation_and_policy_migration`. The indexer validates the
proof before storing it, and the resolver independently recomputes the
`rgk:policy-migration` commitment before returning `NativeTransitionedValid`.
If the spend changes receipt policy without this proof, the resolver returns
`PolicyMigrationRequired`.

The live covenant lineage still preserves policy and proof-mode constants
inside its payload. Wallets must treat migration proof construction as an
explicit local authorisation path, not as an implicit covenant payload rewrite.

## Production Allocation Strategy

Wallets that require a single fixed allocation-vector proof should keep using
`RgkProductionZkTransferPlan`; it accepts only the evidenced 1x0, 1x1, 2x2,
3x2, 4x2, and 4x4 shapes.

For the broader production path, build the normal full-state
`RgkContinuationPlan`, then call `RgkProductionAllocationStrategyPlan::new`.
The planner validates the same native continuation invariants and returns
either `FixedAllocationVector` or `SegmentedAllocationAudit`. The segmented
path is for larger conserving full-state transfers and requires the wallet or
prover to attach a verified allocation-audit certificate before resolver
handoff. Burns and empty allocation sides are rejected on that path.

Persist the strategy commitment alongside the continuation commitment and any
allocation-audit certificate id. That gives support tooling a stable handle for
the exact proof strategy, segment grid, and proof-cell count the wallet chose.

## Public Testnet Staging

Before funding a public staging run, execute:

```bash
bash scripts/e2e-testnet-staging.sh --preflight
```

The preflight manifest is machine-checked by
`scripts/verify-testnet-staging-preflight.sh`. It records the deterministic
testnet funding address, the real-ZK and verifier-only minimum funding values,
the non-coinbase funding requirement, the UTXO-index requirement, and a native
preflight id. The funded run records the same manifest in
`target/rgk-testnet-staging-evidence/latest.txt` before it submits the public
covenant transaction.

## Advanced Covenant Flows

For payment-gated transfer, escrow release, vault timelock release, atomic
swap, covenant-owned asset control, policy upgrade, or controlled termination,
wallets should first construct `AdvancedCovenantPolicyShape` and store its
native policy commitment. Before presenting the action as executable, collect
the concrete payment, counterparty, DAA score, policy, and authorisation
evidence into `AdvancedCovenantExecutionEvidence`, then call
`AdvancedCovenantExecutionPlan::new`.

The planner fails closed when required evidence does not match the committed
shape. A successful plan exposes both the policy commitment and an execution
commitment suitable for wallet logs, resolver handoff metadata, or user-facing
audit trails.

For durable handoff, wrap the plan with
`AdvancedCovenantExecutionRecord::new` and persist its canonical bytes. Decoding
those bytes recomputes the policy and execution commitments, rejects trailing
data, and fails closed if any encoded field has been tampered with. Public
staging remains a separate evidence step.

## Failure Handling

All integration failures are fail-closed. A wallet should not show a transfer
as final until the resolver returns `NativeTransitionedValid` at the configured
safety depth.
