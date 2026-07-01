# Architecture

RGK is a Kaspa-native covenant-lineage asset system. The native settlement
substrate is Kaspa Toccata; the native state machine is RGK. Canonical asset
identity is the Kaspa covenant lineage / lane. `asset_id` is lineage-bound
native label material, not an external contract id or the primary identity.

## Layer Diagram

```text
Native RGK asset grammar
  RgkAssetIssue
  RgkAllocation
  RgkTransition
  RgkProofPolicy
  LanePrivacyPolicy
          |
          v
Client-side validation and receipt building
  RgkStateDigest
  RgkTransitionDigest
  RgkReceipt
  RgkReceiptCommitment
          |
          v
Kaspa Toccata covenant lineage
  CovenantState
  CovenantSpec
  lineage id / lane identity
  covenant id
  continuation output
          |
          v
Indexer and resolver
  observed spends
  replay rejection
  reorg safety
  NativeTransitionedValid / NativeTransitionedInvalid
```

## Workspace Crates

| Crate | Role |
| --- | --- |
| `rgk-core` | Canonical wire types, commitments, chain ids, and policies |
| `rgk-receipt` | Builds and verifies native RGK receipts |
| `rgk-covenant` | Encodes covenant state and builds Toccata scripts |
| `rgk-kaspa` | Fixture and live Kaspa chain backends |
| `rgk-asset` | Native RGK asset grammar |
| `rgk-zk` | Receipt statement, Groth16 precompile integration, and R0 Succinct stack material |
| `rgk-indexer` | Replay-safe in-memory and persistent indexing |
| `rgk-sync` | Restart-safe scan service |
| `rgk-resolver` | Native resolver state machine |
| `rgk-tx` | Unsigned builders and Toccata v1 transaction/Borsh-wire/hash boundary |

## Transition Flow

1. A wallet validates a native `RgkContinuationPlan` against the previous
   allocation set and previous `RgkStateDigest` before the future txid exists.
2. After the continuation txid exists, the plan finalises into `RgkTransition`.
   The transition spends previous covenant outputs, creates new allocation
   outputs, and
   rejects no-op, inflation, deflation without a matching `RgkBurnProof`, and
   spent covenant-output reuse.
3. The transition digest binds old state, new state, actual witness txid, ordered
   inputs, ordered outputs, proof policy, privacy mode, and lane id.
4. `ReceiptBuilder` creates an `RgkReceipt` over the old and new state
   commitments, the transition digest, and the phase-1 continuation
   commitment.
5. The Toccata covenant spend preserves lineage and output shape.
6. The indexer records the observed spend, continuation proof metadata, and
   replay protection.
7. The resolver confirms depth, checks the continuation txid binding, and
   reports a native resolver state.

## Lane Model

`LanePrivacyPolicy::PrivateLane` is the default. Public observers should see
only random-looking commitments unless `PublicLineage` is explicitly selected.

Private-lane state includes:

* blinded lane id
* rotating scan tag
* encrypted note commitment
* nullifier
* policy commitment
* private state root
* view-key based discovery

## Resolver States

The resolver is native-first:

```rust
pub enum RgkResolverState {
    Open,
    NativeTransitionedValid,
    NativeTransitionedInvalid,
    Unconfirmed,
    ReorgRisk,
    CompetingBranch,
    ReplayRejected,
    PolicyMigrationRequired,
    Unknown,
    NodeDown,
}
```

The current crate exposes this shape through `ResolverState`; lane-specific
entry points now include `resolve_lane`, `resolve_by_view_key`,
`resolve_by_scan_tag`, `resolve_public_lineage`, and `resolve_transition`.
They operate over durable local lane index records rather than public
consensus state, so private-lane discovery remains exact-match and wallet
scoped.

`CompetingBranch` is returned when the indexed continuation txid and the
chain-observed spending txid disagree for the same consumed outpoint.
`PolicyMigrationRequired` is returned when spend history shows a receipt-policy
change without a stored native migration proof. When such a proof is present,
the resolver recomputes the `rgk:policy-migration` commitment over previous and
new policies, previous and resulting state digests, the continuation transition
digest, and the authorisation commitment before accepting the transition.
Wallets can construct the canonical proof with `PolicyMigrationInput::build` in
`rgk-core`. The live covenant lineage still preserves its policy and mode
constants; wallet and public staging flows must construct migration proofs
deliberately rather than treating policy change as implicit.

## Boundaries

* RGK defines its own asset grammar.
* Proof policy is state, not unconstrained witness data.
* A witness-selected unconstrained image id is rejected.
* Kaspa RPC is used for chain evidence, not for semantic validation.
* ZK receipt mode proves the receipt statement currently implemented.
  `SemanticTransitionCircuit` proves the canonical 512-byte native transition
  statement, including metadata and owner commitments.
  `OneInOneOutAllocationCircuit`, `TwoInTwoOutAllocationCircuit`,
  and `FixedAllocationVectorCircuit<const SPENT, const NEW>` reconstruct
  allocation roots, state digests, continuation commitment, transition digest,
  spent/new/burned supply accounting, and spent-output non-reuse for fixed
  proven shapes.
  `AllocationTranscriptSegmentCircuit<const ALLOCS>` proves bounded rolling
  spent/new allocation transcript segments for audit evidence.
  `AllocationConservationSegmentCircuit<const ALLOCS>` and
  `AllocationConservationFinalCircuit` prove amount-hiding running-total
  conservation chains. `AllocationExclusionSegmentPairCircuit<const SPENT,
  const NEW>` proves bounded spent/new covenant-output exclusion pairs.
  `AllocationAuditBundle` composes the verified segment statements into
  complete transcript chains, conservation chains, and exclusion grids.
  `AllocationAuditCertificate` binds that bundle to the serialized Groth16
  stack material, a canonical byte envelope, and a native certificate id for
  handoff, and `rgk-zk` can verify the complete report/proof manifest directly
  from those canonical bytes. Accepted spends can persist the corresponding
  `AllocationAuditCertificateRecord`, and the resolver exposes it on valid
  transitioned states. These
  segmented proofs do not replace the fixed transition circuits or become one
  recursive allocation-vector proof.
  `SupportedAllocationVectorCircuit` is the dispatch boundary for the proven
  terminal 1x0 burn, 1x1, 2x2, 3x2, 4x2, and 4x4 shapes; larger or uninstantiated
  arities still live in the native validator.
