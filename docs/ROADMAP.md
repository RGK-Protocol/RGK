# Roadmap

The roadmap now tracks RGK as a Kaspa-native covenant-lineage asset system.
Matching external wallets or validators byte-for-byte is not a milestone.

## Vocabulary Boundary

RGK keeps these protocol principles:

* client-side validation
* single-use state discipline
* deterministic commitment
* privacy by default
* lineage-first asset identity
* canonical RGK encoding
* encrypted receipt transcripts
* resolver-based verification

Current docs, APIs, examples, and gates use RGK-native wording: covenant
output, lane state output, covenant spend, continuation output, encrypted
receipt transcript, lane calculus, lane policy, proof policy, Toccata covenant
commitment, ZK public-input boundary, private allocation transcript, blinded
amount commitment, and DAG-aware lineage reconstruction.

User-facing and protocol-facing flows use encrypted receipt transcripts,
covenant outputs, continuation outputs, and DAG-aware lineage reconstruction.

## Current Revision

| Area | Status |
| --- | --- |
| Native asset issue grammar | Live |
| Native allocation and covenant/lane state output model | Live |
| Native transition digest | Live |
| Canonical covenant-lineage / lane asset identity boundary | Live |
| Private lane default and commitments | Live |
| Native proof policy commitment | Live |
| Fixture e2e using native semantics | Live |
| Local Toccata covenant lifecycle | Live |
| Toccata v1 transaction model in `rgk-tx` | Live for version, subnetwork, gas, compute-budget, storage-mass, Borsh wire bytes, txid, rest-digest, tx-hash, and sighash projections against upstream `kaspa-consensus-core`; the live harness can be configured for native or user-lane subnetwork/gas, while broader wallet signing and public staging remain separate |
| Local devnet script | Refreshed after the native refactor |
| Two-phase continuation output | Receipt/indexer persistence and resolver txid-binding enforcement live |
| Lane resolver APIs | Lane id, view-key, scan-tag, public-lineage, and transition lookup live |
| Native resolver classifications | Competing branch, replay, and policy-migration handling live locally |
| Policy-migration recovery evidence | Persistent fixture and local devnet recovery live; public staging open |
| Lane policy and proof-policy capability coverage | Maintained examples matrix live for the current evidenced surface, including proof-policy guardrails, owner-control shapes, public-lineage opt-in, NFT mint/transfer/marketplace-sale/burn policy shapes, and fungible 2x2/3x2/4x2/4x4 transfer shapes; broad coverage remains open |
| Canonical Silverscript examples | Live for current matrix rows with pinned Testnet-12 compiler artifacts; public staging remains open |
| External frontend equivalence | Out of RGK core scope; not an RGK originality criterion |
| Public testnet staging | Harness, frozen wallet/preflight report, funding-address helper, and report verifiers live; funded public run open |

## M0 - Native Grammar Baseline

**Status**: Live.

Acceptance:

* `RgkAssetIssue` validates positive supply and allocations.
* `RgkAllocation` binds amount, covenant/lane state output, lane id, and
  encrypted note commitment.
* `RgkTransition` rejects no-op transitions, spent covenant-output reuse, supply
  inflation, and supply deflation unless a matching non-zero
  `RgkBurnProof` is bound into the transition.
* State digest binds lineage-bound asset label, allocation root, policy
  commitment, privacy mode, and lane id.
* Covenant lineage / lane is the canonical asset identity; `asset_id` is
  immutable native label material inside that lineage.
* Transition digest binds old state, new state, witness txid, ordered inputs,
  ordered outputs, policy, and lane id.

## M1 - Private Lanes

**Status**: Live primitives, resolver APIs, bounded ZK discovery proof,
bounded ZK lane-graph proof, and segmented lane-graph proof chains.

Acceptance:

* Default privacy mode is `PrivateLane`.
* Public lineage is opt-in.
* Blinded lane id, rotating scan tags, encrypted note commitments,
  nullifiers, policy commitments, and view-key discovery are protocol fields.
* Wrong view keys cannot discover a lane; the right view key can.
* A bounded Groth16 lane-discovery circuit, accepted by the upstream Toccata
  VM, proves that a hidden view key and hidden lineage-bound asset label derive
  the public blinded lane id and rotating scan tag for a public epoch.
* A bounded Groth16 lane-graph discovery circuit proves an ordered set of
  public lane nodes and graph root under the same hidden view key and
  lineage-bound asset label, with upstream Toccata VM and local devnet evidence
  for a 2-node graph.
* A segmented Groth16 lane-graph circuit proves a rolling native graph root for
  each bounded segment. Segment proofs can be chained for arbitrary-size private
  lane graphs; local devnet evidence proves a 2-segment / 4-node chain.
* Public observers see opaque commitments for private lanes.
* DONE: local privacy-observer evidence is produced by
  `scripts/e2e-privacy-observer.sh` and checked by
  `scripts/verify-privacy-observer-evidence.sh`.

## M2 - Native Resolver

**Status**: Lane-native entry points and hard-fail classifications live locally.

Current resolver states include `NativeTransitionedValid`,
`NativeTransitionedInvalid`, `CompetingBranch`, `ReplayRejected`, and
`PolicyMigrationRequired`. The resolver exposes lane-native entry points:

* `resolve_lane`
* `resolve_by_view_key`
* `resolve_by_scan_tag`
* `resolve_public_lineage`
* `resolve_transition`

Acceptance:

* DONE: replay is rejected explicitly before stale old-state mismatch can mask it.
* DONE: private-lane discovery uses exact lane id / scan-tag lookup and wrong
  view keys do not discover the lane.
* DONE: public-lineage lookup returns only lanes explicitly registered as
  public for the requested asset.
* DONE: transition digest lookup resolves the indexed covenant transition.
* DONE: competing branches are classified explicitly when chain-observed spend
  txid disagrees with the indexed continuation txid.
* DONE: policy migration is explicit; receipt-policy changes without proof
  resolve to `PolicyMigrationRequired`, while changes carrying a valid native
  migration proof can resolve as `NativeTransitionedValid`.
* DONE: wallet-safe policy-migration proof construction is exposed from
  `rgk-core` via `PolicyMigrationInput::build`.
* DONE: local devnet evidence constructs a native policy-migration proof from
  the confirmed transition digest, persists it through Sled reopen, and has the
  resolver classify the migrated state as `NativeTransitionedValid`.

## M3 - Two-Phase Continuation Output

**Status**: Native phase-1/phase-2 primitives live and enforced at the
receipt/indexer/resolver boundary.

Goal: support native continuation output transition without circular txid
dependency.

Acceptance:

* DONE: Phase 1 creates a continuation commitment without requiring the future
  txid.
* DONE: Phase 1 binds the next lane and state shape.
* DONE: Phase 2 finalises the continuation output after the txid exists.
* DONE: tests prove previous covenant output spent, continuation output
  created, future txid absent from phase 1, actual txid bound in phase 2,
  replay-by-spent-output rejected, and wrong continuation rejected.
* DONE: receipts carry the phase-1 continuation commitment.
* DONE: spend history persists continuation proof metadata.
* DONE: resolver rejects missing continuation proof and rejects continuation
  outpoints whose txid does not match the observed spending txid.

## M4 - Semantic ZK Receipt

**Status**: Receipt statement path live; semantic statement circuit live;
bounded private-lane discovery and lane-graph circuits live; 1x1 and 2x2
allocation-vector circuits live; const-generic fixed-arity circuit family has
3x2, 4x2, and 4x4 proof/VM evidence; segmented allocation transcript,
conservation, and exclusion proofs live as supplemental audit evidence;
wallet-facing production allocation strategy planning selects fixed proofs or
segmented audit certificates; arbitrary one-step single-proof unbounded
allocation-vector ZK remains unclaimed.

Current ZK mode proves the implemented receipt statement and can execute
through Toccata's Groth16 precompile. `rgk-zk` now also exposes a canonical
512-byte `SemanticTransitionStatement` derived from validated native transition
and continuation reports, including spent/new/burned supply, burn
authorisation commitment, metadata commitment, previous/new owner commitments,
and ownership handoff authorisation fields, plus a `SemanticTransitionCircuit`
that proves that statement inside Groth16 and serialises to Toccata's
precompile stack.
The Toccata `R0Succinct` stack boundary is also implemented: RGK models the
exact precompile stack material and local upstream VM evidence executes the
parent Succinct fixture and rejects a tampered journal. RGK does not yet claim
a native RISC0 prover or RISC0 circuit family for RGK statements.
`LaneDiscoveryCircuit` proves the native blinded-lane-id and scan-tag
derivations for a bounded public epoch while keeping the view key and
lineage-bound asset label private, and is accepted by the upstream Toccata VM
test harness.
`LaneGraphDiscoveryCircuit<const LANES>` proves that a bounded ordered set of
public lane nodes and the native graph root share the same hidden view key and
lineage-bound asset label; the evidenced shape is a 2-node current/look-ahead
graph accepted by the upstream Toccata VM and required by local devnet
evidence.
`LaneGraphSegmentCircuit<const LANES>` extends this to arbitrary-size lane
graphs by proving each bounded segment against a native rolling root; the
evidenced chain is two 2-node segments accepted by the upstream Toccata VM shape
test and required by local devnet evidence. Fixed 1x1 and 2x2 allocation-vector
circuits now reconstruct the native commitments inside Groth16.
`FixedAllocationVectorCircuit<const SPENT,
const NEW>` removes the hand-written circuit-per-arity pattern, with 3x2, 4x2,
and 4x4 proof plus upstream Toccata VM evidence. `AllocationTranscriptSegmentCircuit<const
ALLOCS>` proves bounded native allocation transcript segments against rolling
spent/new roots; it is audit evidence for larger allocation sides and not a
replacement for full one-step transition proofs.
`AllocationExclusionSegmentPairCircuit<const SPENT, const NEW>` proves one
bounded spent/new segment pair does not reuse any spent covenant output, while
binding the same native transcript roots and blinded amount commitments. A
verifier can cover arbitrary-size sides by checking the complete spent/new
segment-pair grid. `AllocationConservationSegmentCircuit<const ALLOCS>` proves
amount-hiding running-total updates for each bounded allocation transcript
segment, and `AllocationConservationFinalCircuit` proves the final spent and
new running-total commitments open to the same private amount. Complete spent
and new conservation chains cover arbitrary-size allocation conservation
without publishing amounts. `AllocationAuditBundle` composes the verified
transcript, conservation, final, and exclusion public statements into complete
chains and grids. `AllocationAuditCertificate` binds those statements to the
actual Toccata Groth16 stack bytes, verifies each proof from the serialized
certificate material, exposes a native certificate id, and has a bounded
canonical byte encoding with self-contained verifier entry points for
wallet/resolver/indexer handoff. Accepted spends can
persist an `AllocationAuditCertificateRecord`, and `NativeTransitionedValid`
resolver states expose that optional record. Devnet evidence now requires
bundle verification, canonical self-contained certificate verification, indexer
attachment, and sled recovery lines.
`AllocationCircuitShape` and
`SupportedAllocationVectorCircuit` make the current supported-shape boundary
explicit for wallet/prover code. `ProductionAllocationProofStrategy` chooses
the current production strategy: bounded supported shapes 1x0 terminal burn,
1x1, 2x2, 3x2, 4x2, and 4x4.
The native `RgkAllocationProofShape` policy in `rgk-asset` is the source of
truth for wallet guards and `rgk-zk` dispatch. Shapes outside that boundary
fail before native fixed-shape production-ZK validation and before setup/proving.
`RgkProductionAllocationStrategyPlan` is the wallet-facing selector for the
broader production strategy: it validates the full continuation, selects a fixed
allocation-vector proof for evidenced shapes, or selects a segmented
allocation-audit certificate for larger conserving full-state transfers. The
strategy commitment binds the continuation commitment, supplies, counts,
segment capacity, segment counts, exclusion-pair count, and proof-entry count.
`RgkProductionAllocationStrategyRecord` gives wallets and provers canonical
handoff bytes that recompute and tamper-check that strategy choice. Burns and
empty sides fail closed on the segmented strategy. RGK still needs a future
recursive/aggregated strategy before it can claim arbitrary one-step
single-proof allocation-vector ZK.

Acceptance:

* DONE: Proof policy is committed in state.
* DONE: Dynamic `image_id` is allowed only under a committed policy.
* DONE: Proof-policy downgrade is rejected.
* DONE: Semantic public inputs are derived from native RGK reports, not witness
  discretion.
* DONE: Segmented allocation audit bundles reject incomplete transcript chains,
  broken conservation terminals, missing exclusion entries, and duplicate grid
  entries.
* DONE: Allocation audit certificates bind Groth16 VK/proof/public-input stack
  material to the native bundle manifest and deterministic certificate id, and
  round-trip through bounded canonical bytes with self-contained report/proof
  verification before devnet evidence accepts them.
* DONE: Accepted spends can persist canonical allocation-audit certificate
  records through the indexer, resolver state carries the optional record, and
  local devnet evidence proves sled recovery after reopen.
* DONE: The 512-byte semantic transition statement is proven inside a Groth16
  circuit and accepted by the upstream Toccata VM; the statement now binds
  native metadata and owner commitments.
* DONE: `R0SuccinctPrecompileStack` models the Toccata RISC0 Succinct stack
  order and local upstream VM evidence accepts the parent Succinct fixture while
  rejecting a changed journal. The active RGK receipt wrapper still rejects
  opaque `R0Succinct` proofs until RGK has native RISC0 prover/circuit support.
* DONE: Bounded private-lane discovery proves, inside Groth16 and the upstream
  Toccata VM, that a hidden view key and hidden lineage-bound asset label
  derive the public blinded lane id and rotating scan tag for a public epoch.
* DONE: Bounded private-lane graph discovery proves, inside Groth16 and the
  upstream Toccata VM, that an ordered 2-node graph root and its public lane
  nodes are derived under one hidden view key and hidden lineage-bound asset
  label.
* DONE: Segmented private-lane graph discovery proves, inside Groth16 and the
  upstream Toccata VM, that each 2-node graph segment advances a native rolling
  graph root under one hidden view key and hidden lineage-bound asset label;
  local devnet evidence requires a 2-segment / 4-node chain.
* DONE: The current one-input/one-output allocation-vector transition is proven
  inside Groth16 and accepted by the upstream Toccata VM.
* DONE: A one-input/one-output authorised burn transition is proven inside
  Groth16 with public spent/new/burned supply accounting and burn
  authorisation commitment binding.
* DONE: A one-input/zero-output terminal burn transition is proven inside
  Groth16 with explicit transition-witness txid binding for cases such as NFT
  destruction.
* DONE: The two-input/two-output allocation-vector transition is proven inside
  Groth16 and accepted by the upstream Toccata VM.
* DONE: A const-generic fixed-arity allocation-vector circuit family proves a
  three-input/two-output transition and is accepted by the upstream Toccata VM.
* DONE: The same const-generic fixed-arity circuit family proves a
  four-input/two-output merge transition and is accepted by the upstream
  Toccata VM; local devnet evidence requires that VM fixture.
* DONE: The same const-generic fixed-arity circuit family proves a
  four-input/four-output batch transition and is accepted by the upstream
  Toccata VM; local devnet evidence requires that VM fixture.
* DONE: Supported allocation-vector ZK shapes are discoverable through an
  explicit registry and unsupported arities fail before proof construction.
* DONE: The production allocation-proof strategy is explicitly bounded to the
  evidenced 1x0 terminal-burn, 1x1, 2x2, 3x2, 4x2, and 4x4 shapes and fails closed
  for larger or otherwise uninstantiated one-step transition shapes.
* DONE: Native wallet-facing validation exposes `validate_for_production_zk`
  on issue, transition, and continuation-plan paths so unprovable ZK shapes
  are rejected before proof construction.
* DONE: Native wallet-facing production-ZK transfer planning exposes
  `RgkProductionZkTransferPlan`, certifies the exact allocation proof shape
  before phase-2 txid finalisation, and rejects partial previous-state spends
  through the same full-state validator.
* DONE: Native wallet-facing production allocation strategy planning exposes
  `RgkProductionAllocationStrategyPlan`, selects fixed allocation-vector proofs
  or segmented allocation-audit certificates for larger conserving full-state
  transfers, binds a strategy commitment, provides canonical strategy-record
  handoff bytes, and fails closed for segmented burns or empty allocation sides.
* DONE: The live Toccata/devnet covenant lifecycle builds its allocation-vector
  proof through the supported-shape dispatch boundary.
* DONE: Segmented allocation transcript proofs bind native spent/new allocation
  side roots, a private segment amount through a blinded commitment, segment
  index, total count, and chain id; the upstream Toccata VM accepts the stack
  and local devnet evidence requires spent/new transcript roots and amount
  commitments for a confirmed transition.
* DONE: Segmented allocation conservation proofs add private running-total
  commitments over spent/new transcript sides and a final equality proof; the
  upstream Toccata VM accepts both stacks and local devnet evidence requires the
  live 1x1 spent/new conservation chain for the confirmed transition.
* DONE: Bounded allocation exclusion segment-pair proofs reconstruct both
  native transcript segment roots and prove every spent covenant outpoint in
  the segment differs from every new outpoint in the segment. Arbitrary-size
  sides can be covered by a complete grid of bounded segment-pair proofs; local
  devnet evidence requires the live 1x1 grid entry for the confirmed
  transition.
* OPEN: Single-proof arbitrary-size allocation conservation, unbounded two-phase
  continuation consistency, and single-proof spent-output exclusion are not yet
  reconstructed from private allocation vectors inside one recursive or
  otherwise unbounded circuit strategy.

## M5 - Lane Policy Examples And Public Staging

**Status**: Local evidence live, public staging open.

Planned work:

* Keep `rgk-tx` aligned with upstream Toccata transaction semantics. The local
  v1 model now covers version, subnetwork id, gas, per-input compute budget,
  storage mass, Borsh wire bytes, covenant bindings, payload digest, rest
  digest, txid, tx hash, and Schnorr sighash with tests against the parent
  `rusty-kaspa` checkout. The live covenant harness records the selected
  Toccata subnetwork and gas and can be configured with an explicit user-lane
  namespace plus non-zero gas.
* Keep local devnet evidence fresh after native protocol changes.
* Treat Silverscript as the canonical low-level covenant/lane-policy source for
  RGK examples. The current Rust/Toccata fixtures remain the consensus oracle
  for local devnet lifecycle evidence; the checked Silverscript artifacts are
  compiler evidence, not a public-staging claim.
* Extend the maintained `examples/` matrix from the current evidence-backed
  rows to the full native RGK lane-policy and proof-policy capability surface,
  then to additional Kaspa-native covenant behaviour.
* Extend canonical Silverscript source files and checked compile artifacts as
  new supported examples are added, then pair them with public testnet/devnet
  evidence exercising the covenant lifecycle end to end.
* Keep external frontend equivalence outside RGK core scope. Another Kaspa
  covenant frontend may prove equivalent higher-level programs for the same
  examples, but that is not an RGK-specific language dependency or an
  originality criterion.
* Stage on public testnet with persistent indexer recovery.
  `scripts/e2e-testnet-staging.sh` now runs the live covenant lifecycle against
  `RGK_LIVE_KASPA_NETWORK=testnet-12` by default, using a pre-funded
  non-coinbase public testnet UTXO, waits for real confirmations instead of
  mining, and writes a report checked by
  `scripts/verify-testnet-staging-evidence.sh`. Its `--print-address` mode
  prints the deterministic funding address and minimum value, its `--wallets`
  mode writes a machine-checked deterministic testnet-only wallet-set report,
  and its `--preflight` mode writes a machine-checked funding manifest with a
  native preflight id before the funded public run.
* Stage wallet/public flows that construct native policy-migration proofs;
  local persistent and devnet recovery evidence is live, public evidence remains open.
* Publish operational evidence before any mainnet claim.

Lane policy example coverage targets:

* Native RGK asset lifecycle: issue, transfer, authorised burn, metadata
  commitment, ownership handoff, covenant continuation, policy migration, and
  receipt validation. Metadata and owner commitments are live in the native
  digest path, and owner-control descriptor examples now cover key-hash,
  script-hash, and covenant-id owner commitments; broader lane-policy examples
  remain open.
* Fungible assets: single-output transfer, multi-output fanout, multi-input
  merge, burn, owner-key rotation, script-hash owner, covenant-id owner, and
  batch transfer under supported allocation-proof shapes.
* NFTs: collection mint, fixed-supply mint, single-token transfer, burn,
  metadata-hash preservation, royalty or policy commitment hooks, and
  collection-controlled token template validation. Native policy primitives
  and examples now cover terminal 1x0 burn as a production-ZK-supported
  lifecycle, and native marketplace sale terms bind price, payment asset,
  royalty policy, royalty amount, seller/buyer handoff, and sale
  authorisation before settlement.
* Private-lane flows: blinded lane id, scan-tag discovery, encrypted note
  commitment, public-lineage opt-in, and resolver lookup by lane/view key.
* Advanced covenant flows: payment-gated transfer, escrow, vault or timelock,
  atomic swap shape, covenant-owned asset, policy upgrade, and controlled
  termination. Native policy-shape commitments, checked examples,
  wallet-facing execution-evidence planning, and canonical execution-record
  handoff are live; public-staging demonstrations remain open.

Acceptance:

* DONE: `examples/` contains a maintained coverage matrix mapping each current
  evidenced example to the RGK capability it exercises, and
  `scripts/verify-example-matrix.sh` checks it against local and devnet
  evidence labels.
* DONE: every current matrix example has a canonical Silverscript source file
  and checked JSON compile artifact generated by the pinned upstream compiler.
* DONE: the main RGK covenant continuation policy surface has checked
  Silverscript source and JSON artifact evidence in
  `rgk_covenant_continuation_policy`, covering singleton continuation, explicit
  fanout with change, and shared merge/batch policy shapes. Rust/Toccata VM
  tests remain the exact opcode execution oracle.
* DONE: local internal-readiness evidence records both
  `silverscript_artifacts=ok` and `examples_matrix=ok`, and
  `scripts/verify-internal-readiness-evidence.sh` requires the corresponding
  verifier output before the non-public-network launch gate can pass.
* DONE: the matrix includes an authorised burn lifecycle row backed by native
  burn validation tests and a checked Silverscript artifact.
* DONE: the matrix includes a native proof-policy guardrails row backed by
  downgrade and unconstrained-image-id rejection tests, explicit
  policy-commitment devnet evidence, and a checked Silverscript artifact.
* DONE: the matrix includes an owner-control policy-shapes row backed by
  native key-hash/script-hash/covenant-id owner descriptor tests, owner-key
  rotation validation, devnet evidence labels, and a checked Silverscript
  artifact.
* DONE: the matrix includes an NFT collection policy-shapes row backed by
  native fixed-supply collection id derivation, token id commitment,
  collection-template validation, metadata preservation, royalty-policy hook,
  single-token owner handoff, terminal 1x0 burn lifecycle validation, a
  Groth16 terminal-burn allocation proof, devnet evidence labels, and a
  checked Silverscript artifact.
* DONE: the matrix includes an NFT marketplace sale row backed by native sale
  terms that bind payment asset, price, royalty policy, royalty amount,
  seller/buyer owner commitments, and sale authorisation into a deterministic
  settlement commitment, with devnet evidence labels and a checked
  Silverscript artifact.
* DONE: the matrix includes a fungible transfer-shape row backed by native
  2x2 fanout, 3x2 merge, 4x2 merge, and 4x4 batch-transfer tests, evidenced
  4x2 and 4x4 Toccata VM proof markers, and a checked Silverscript artifact.
* DONE: the Toccata covenant script builder now exposes an explicit
  `CovenantContinuationPolicy`; local upstream VM evidence accepts a two-output
  covenant continuation with an explicit extra fee/change output and rejects a
  declared continuation output that omits its covenant binding.
* DONE: the Toccata covenant script builder also exposes
  `CovenantSharedContinuationPolicy` for merge/batch shapes; local upstream VM
  evidence executes the same redeem script on both inputs of a two-input
  one-output merge with change and a two-input two-output batch with change,
  then rejects a batch missing a declared shared covenant output.
* DONE: the matrix includes an advanced covenant policy-shapes row backed by
  native commitment uniqueness, fail-closed material validation, commitment
  binding tests, wallet-facing execution-plan validation, execution commitment
  binding tests, canonical execution-record handoff validation, devnet evidence
  labels, and a checked Silverscript artifact.
* DONE: the matrix includes a public-lineage opt-in row backed by resolver
  filtering of public lanes by asset, exclusion of private lanes, devnet
  evidence labels, and a checked Silverscript artifact.
* PARTIAL: the current matrix rows have fixture or local devnet evidence
  against native RGK semantics; public testnet evidence remains open.
* OPEN: external frontend equivalence, when available, is tracked only as
  optional external evidence and does not become an RGK-specific language
  dependency.

## Removed Track

The previous external-matching track has been removed. RGK no longer carries
milestones for external wallet vectors, external validator matching, or
byte-identical digest matching with another asset system.
