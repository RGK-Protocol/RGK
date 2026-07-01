# Security Model

This document describes what native RGK proves, what it does not prove, and
which components are trusted.

## Top-Level Claim

RGK binds a client-side validated native asset state to a Kaspa Toccata
covenant lineage. A resolver can verify from local state and live chain
evidence that a covenant spend advanced the committed RGK state according to
the native grammar.

## What RGK Proves

1. **Lineage continuity.** The covenant lineage is preserved across spends.
2. **Output shape.** The continuation output has the expected covenant shape.
3. **State advance.** No-op transitions are rejected.
4. **Asset-label binding.** State and receipt commitments pin the same
   lineage-bound `asset_id`; the covenant lineage / lane remains the canonical
   asset identity.
5. **Supply accounting.** Native transition validation rejects inflation and
   accepts deflation only when a matching non-zero `RgkBurnProof` is committed
   to the transition or continuation.
6. **Covenant-output uniqueness.** Spent covenant outputs cannot be reused.
7. **Policy binding.** Proof policy is committed into state and transition
   digests.
8. **Replay protection.** The indexer rejects reused receipts and observed
   spend facts.
9. **Privacy mode binding.** State digest commits to the lane privacy mode.
10. **Owner-control binding.** Owner commitments are derived from native
    key-hash, script-hash, or covenant-id descriptors, and ownership handoff
    requires a non-zero authorisation commitment.
11. **NFT policy binding.** Native NFT token ids bind collection id, fixed
    supply index, collection template, royalty-policy commitment, and metadata;
    single-token transfers preserve that metadata and require owner handoff
    authorisation when ownership changes. Terminal NFT burns consume the
    single token allocation, create no successor allocation, and bind a
    non-zero burn authorisation commitment.
12. **Advanced covenant policy binding.** Payment-gated transfer, escrow,
    vault timelock, atomic swap, covenant-owned asset, policy upgrade, and
    controlled termination policy shapes bind their required material into a
    native RGK commitment and fail closed when required payment, counterparty,
    unlock, policy, or authorisation material is absent. Wallet-facing
    execution plans then bind the policy commitment plus supplied execution
    evidence and fail closed on wrong authorisation, counterparty, payment,
    timelock, or policy evidence before the flow is presented as executable.

## Privacy Claim

`PrivateLane` is the default. In private mode, public observers should see
opaque commitments rather than asset label, amount, owner, recipient, lane
graph, or proof policy in plaintext.

Protocol support includes blinded lane ids, rotating scan tags, encrypted note
commitments, nullifiers, policy commitments, private state roots, and view-key
based discovery. `PublicLineage` is explicit opt-in.

Local privacy-observer evidence is produced by
`scripts/e2e-privacy-observer.sh` and verified by
`scripts/verify-privacy-observer-evidence.sh`. The evidence checks that private
lanes disclose only blinded lane ids, rotating scan tags, nullifiers, and
opaque commitments, while keeping asset label, owner, amount, lane graph, and
plaintext proof policy outside the public observer boundary.

## What RGK Does Not Prove Yet

* Public testnet or mainnet operation. `scripts/e2e-testnet-staging.sh` is the
  public testnet evidence path, and its preflight manifest is machine-checked,
  but a funded public run and verified report are still required.
* Arbitrary one-step unbounded allocation-vector transition proof inside
  Groth16. The production ZK strategy is bounded to evidenced 1x0 terminal
  burn, 1x1, 2x2, const-generic 3x2, const-generic 4x2, and const-generic 4x4
  allocation-vector shapes;
  uninstantiated or larger one-step arities remain validator-bound unless every
  full-state intermediate transition stays inside the supported shapes or the
  wallet selects the segmented allocation-audit certificate strategy. That
  strategy is fail-closed for burns and empty sides, binds a native strategy
  commitment, and covers larger conserving full-state transfers with transcript,
  conservation, and exclusion proof bundles. It is still not a single recursive
  transition proof.
* Public staging evidence for continuation enforcement outside local devnet.
* Public staging evidence for policy-migration proof flows.
* Arbitrary historical discovery without local wallet/indexer material.
* Post-quantum security for the current Groth16 path.

## Threat Model

| Threat | Mitigation |
| --- | --- |
| Malicious covenant payload | Canonical decoding and structural invariants |
| Asset-label swap | Receipt, state, and covenant checks pin the lineage-bound `asset_id` |
| State no-op replay | Receipt and transition validation reject equal states |
| Spent covenant-output reuse | Native transition validation rejects reused outputs |
| Supply inflation | Native transition validation checks conservation |
| Proof-policy downgrade | Policy commitment is part of state |
| Owner-control substitution | Native owner descriptor commitments are domain-separated and state-bound |
| NFT template or metadata substitution | Native NFT token ids and transfer validators bind collection template and metadata commitments |
| Unconstrained image id | `RgkProofPolicy` rejects it |
| Receipt replay | Indexer rejects accepted-twice receipts |
| Reorg | Confirmation threshold and rollback-capable indexer |
| Competing branch | Resolver returns `CompetingBranch` on indexed/observed spend txid disagreement |
| Implicit policy change | Resolver returns `PolicyMigrationRequired`; accepted changes must carry a migration proof binding policies, state digests, transition digest, and authorisation commitment |
| RPC equivocation | Resolver re-verifies local receipts and indexed state |
| Private-lane scanning error | Wrong view keys fail discovery |

## Trust Assumptions

* Kaspa consensus executes Toccata covenant and precompile rules correctly.
* The wallet's native RGK validator constructs valid issues and transitions.
* The resolver is honest and fail-closed.
* The local indexer is the source of replay state.
* In ZK mode, the proving system and verifying key are trusted according to
  their normal cryptographic assumptions.

## Resolver Classifications

```text
Open
NativeTransitionedValid
NativeTransitionedInvalid
Unconfirmed
ReorgRisk
CompetingBranch
ReplayRejected
PolicyMigrationRequired
Unknown
NodeDown
```

The current implementation exposes these local classifications. Public
testnet staging is still required before any production-network claim.
