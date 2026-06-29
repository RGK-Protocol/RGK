# ZK Boundary

The current ZK path proves an RGK receipt statement. It does not yet prove the
entire native transition semantics inside the circuit.

## Current Statement

The statement binds:

* chain id
* covenant id
* asset id
* old state digest
* new state digest
* transition digest
* continuation commitment
* receipt id

Receipt mode is enforced by `ZkReceipt` and receipt verification. It is not a
separate raw public-input field.

The live `real-zk` path can serialise the Groth16 stack and execute through
Toccata's `OpZkPrecompile`.

## Semantic Transition Statement

`rgk-zk` also exposes `SemanticTransitionStatement`, a canonical 512-byte
native statement built from validated `RgkTransitionReport` and
`RgkContinuationReport` values.

It binds:

* chain id
* schema id
* asset id
* previous and new state digests
* transition digest
* continuation commitment
* continuation shape root
* lane id
* privacy policy
* proof-policy commitment
* metadata commitment
* previous and new owner commitments
* ownership handoff authorisation commitment
* total supply
* spent and new allocation counts
* spent, new, and burned supply
* burn authorisation commitment, zero for no-burn transitions

The deterministic fixture asserts that this semantic statement matches the
receipt statement when the receipt carries the native transition digest. The
live covenant harness prints the phase-2 semantic statement after the
continuation txid exists.

`real-zk` includes `SemanticTransitionCircuit`, a Groth16 circuit whose public
input is this 512-byte statement, packed into 64 BN254 field elements for
Toccata's `OpZkPrecompile`. The circuit constrains:

* witness bytes equal the public semantic statement
* chain tag and known chain value encoding
* non-zero schema, asset, state, transition, continuation, lane, policy,
  metadata, and owner commitments
* previous/new owner commitments either match or carry non-zero handoff
  authorisation
* previous and new state digests are different
* total supply and allocation counts are non-zero
* public supply accounting satisfies `spent_supply = new_supply + burned_supply`
* privacy policy is one of RGK's known policy values

The e2e VM tests execute this semantic proof stack through the upstream
Toccata VM. The live devnet harness also proves and verifies the semantic
statement after the continuation txid exists.

## Lane Discovery Circuit

`real-zk` includes `LaneDiscoveryCircuit`, a bounded Groth16 circuit for the
native private-lane discovery relation. Its public input is 72 bytes packed
into 9 BN254 field elements:

* blinded lane id
* scan tag
* epoch

The private witness contains the view key and asset id. The circuit
reconstructs and constrains:

* `derive_blinded_lane_id(view_key, asset_id, epoch) == lane_id`
* `RgkScanTag::derive(view_key, lane_id, epoch) == scan_tag`

This proves the discovery relation without making the asset id or view key
public. The e2e VM test executes this proof stack through the upstream Toccata
VM.

`real-zk` also includes `LaneGraphDiscoveryCircuit<const LANES>`, a bounded
extension of the same native relation. Its public input is:

* a native `rgk:lane:graph-root:v1` graph root
* `LANES` ordered lane nodes, each containing blinded lane id, scan tag, and
  epoch

The private witness is still only the view key and asset id. The circuit
reconstructs the native graph root and proves every public node was derived
under the same hidden pair. The evidenced shape is a 2-node current/look-ahead
graph, accepted by the upstream Toccata VM and required by local devnet
evidence.

For arbitrary-size private lane graphs, `real-zk` includes
`LaneGraphSegmentCircuit<const LANES>`. Its public input is:

* previous rolling graph root
* next rolling graph root
* segment index
* `LANES` ordered lane nodes

The circuit reconstructs `rgk:lane:graph-segment-root:v1`, proves every public
node in the segment under the same hidden view key and asset id, and binds the
segment into the previous root. A verifier can accept a larger graph by checking
a contiguous sequence of segment proofs from `private_lane_graph_empty_root` to
the advertised final root. The evidenced shape is a 2-node segment, accepted by
the upstream Toccata VM, with local devnet evidence for a 2-segment / 4-node
chain.

This remains intentionally scoped: it proves arbitrary-size discovery via a
sequence of bounded segment proofs, not one recursive graph proof, and it does
not prove private ownership history or arbitrary allocation-vector privacy
semantics.

## Allocation-Vector Circuit

`real-zk` includes `OneInOneOutAllocationCircuit`,
`TwoInTwoOutAllocationCircuit`, and
`FixedAllocationVectorCircuit<const SPENT, const NEW>` for fixed RGK transition
arities. Their public input is the same 512-byte semantic statement. The
private witness contains canonical ordered spent allocations and finalised new
allocations.

The circuit reconstructs and constrains:

* spent and new allocation roots
* previous and new state digests
* continuation shape root
* phase-1 continuation commitment
* transition digest
* spent/new allocation sums against public supply fields
* burn accounting against public burned supply and authorisation commitment
* chain consistency between statement and allocation witnesses
* non-zero outpoints, covenant ids, witness txids, confirmations, and encrypted
  notes
* finalised new outpoint txid equals the transition witness txid
* new allocations do not reuse closed spent outpoints

The 1x1 shape is executed by the current local Toccata lifecycle through the
supported-shape dispatch API. The 1x1, 2x2, generic 3x2, generic 4x2, and generic 4x4
shapes are executed by the upstream Toccata VM test harness.
`AllocationCircuitShape`, `SUPPORTED_ALLOCATION_CIRCUIT_SHAPES`, and
`SupportedAllocationVectorCircuit` are the public registry/dispatch boundary
for wallet and prover code. Unsupported arities fail before proof construction.
The circuits are intentionally explicit about arity; each concrete `SPENT`/`NEW`
pair is a separate Groth16 setup shape.

## Allocation Transcript Segment Circuit

`real-zk` also includes `AllocationTranscriptSegmentCircuit<const ALLOCS>`, a
supplemental native audit circuit for allocation-set transcript chains. Its
public input is 128 bytes packed into 16 BN254 field elements:

* previous rolling transcript root
* next rolling transcript root
* native Kaspa chain id
* transcript side (`Spent` or `New`)
* segment index
* total allocation count for the side
* blinded segment amount commitment

The private witness contains `ALLOCS` native-encoded allocations, the segment
amount, and a 32-byte amount blinding. The circuit checks allocation shape,
known chain encoding, side encoding, non-zero covenant fields, in-segment
distinct outpoints, private segment amount equality, the native
`rgk:asset:allocation-transcript-amount:v1` commitment, and the native
`rgk:asset:allocation-transcript-segment-root:v1` rolling root.

The statement constructor sorts allocations with the same native allocation key
used by `rgk-asset`; verifiers should treat that constructor as the canonical
statement path. This proof is an audit transcript for large allocation sides and
does not publish individual or segment amounts. It does not replace the fixed
allocation-vector transition circuits, and it does not by itself prove
cross-segment closed-seal non-reuse or arbitrary one-step allocation
conservation in a single circuit.

`AllocationConservationSegmentCircuit<const ALLOCS>` extends the transcript
segment proof with a private running total. Its public input is 192 bytes packed
into 24 BN254 field elements:

* the 128-byte allocation transcript segment statement
* previous blinded running-total commitment
* next blinded running-total commitment

The private witness contains the allocation segment, the private segment
amount, the segment amount blinding, the previous running total, the next
running total, and both running-total blindings. The circuit reconstructs the
transcript root and segment amount commitment, then proves
`next_total = previous_total + segment_amount` inside R1CS without publishing
either total or the segment amount. When the public segment index is zero, the
circuit also proves that the hidden previous running total is zero; later
segments keep their totals private and are linked by public running-total
commitments.

`AllocationConservationFinalCircuit` proves final spent/new equality. Its public
input is 80 bytes packed into 10 BN254 field elements:

* spent total allocation count
* new total allocation count
* final spent running-total commitment
* final new running-total commitment

The private witness contains one total amount and both final blindings. The
circuit opens the spent and new final commitments to the same private total.
Together, complete spent/new conservation segment chains plus this final proof
cover arbitrary-size allocation conservation without publishing amounts. This is
still a proof chain, not a single recursive allocation-vector transition proof.

`AllocationExclusionSegmentPairCircuit<const SPENT, const NEW>` proves the
bounded cross-side exclusion relation for one spent transcript segment and one
new transcript segment. Its public input is 232 bytes packed into 29 BN254 field
elements:

* spent previous and next transcript roots
* new previous and next transcript roots
* native Kaspa chain id
* spent and new segment indices
* spent and new total counts
* spent and new blinded segment amount commitments

The private witness contains both native-encoded allocation segments, both
private segment amounts, and both amount blindings. The circuit reconstructs
both transcript roots, both amount commitments, validates each allocation shape,
enforces in-segment distinct outpoints, and checks every spent outpoint against
every new outpoint. A verifier can cover arbitrary-size spent/new allocation
sides by checking a complete grid of these bounded segment-pair proofs over the
same transcript roots. This is still not a single recursive allocation-vector
transition proof.

## Allocation Audit Bundle Verifier

`AllocationAuditBundle` is the production verifier glue for segmented
allocation audit evidence. It does not create a new Groth16 proof. Instead,
after the individual transcript, conservation, final equality, and exclusion
segment proofs have verified, it checks that their public statements form one
complete native audit:

* spent and new transcript chains start from the native empty roots
* segment indices are contiguous and total counts equal covered segment arity
* spent and new conservation chains bind the matching transcript statements
* conservation running-total commitments link between segments and terminate at
  the final equality statement
* the final equality counts match the transcript counts
* the spent/new exclusion grid contains exactly one cell for every segment pair
  and every cell binds the corresponding transcript roots and amount
  commitments

The local devnet evidence now requires an `allocation audit bundle verified`
line after the individual allocation transcript, conservation, and exclusion
Groth16 proof lines.

`AllocationAuditCertificate` is the portable certificate form for wallet,
resolver, and indexer handoff. It binds:

* the verified allocation audit report
* the deterministic proof-cell manifest
* each segment statement public-input byte string
* each Toccata Groth16 stack tag
* each compressed verifying key and proof
* each uncompressed BN254 public-input stack item
* a bounded `rgk:aac1` canonical byte envelope for transport and persistence

The certificate id is the native
`rgk:zk:allocation-audit-certificate:v1` domain hash over the canonical
certificate body. Decoding rejects bad magic, trailing bytes, oversized blobs,
and id/body mismatches before the proof verifier runs. Callers that already
hold the bundle can check the certificate against it; handoff consumers can also
verify directly from the canonical bytes. The self-contained verifier rebuilds
the typed manifest from proof-cell public inputs, checks deterministic cell
ordering, recomputes the bundle report, deserializes every Groth16 stack,
verifies every proof, and then recomputes the certificate id. The certificate is
still a proof bundle, not a single recursive proof.

After verification, callers can attach the canonical bytes to the accepted
spend as an `AllocationAuditCertificateRecord`. The indexer validates the
bounded `rgk:aac1` envelope, persists the record through sled, and the resolver
surfaces it as optional metadata on `NativeTransitionedValid`. The indexer does
not re-run Groth16 verification; it stores proof material already checked by
`rgk-zk`.

## Production Allocation-Proof Strategy

`ProductionAllocationProofStrategy::BoundedSupportedShapes` remains the
single-circuit production strategy. A single allocation-vector ZK proof is
produced only for the evidenced terminal 1x0 burn, 1x1, 2x2, 3x2, 4x2, and 4x4
shapes. The native source of truth is `RgkAllocationProofShape` in
`rgk-asset`; `rgk-zk` delegates supported-shape dispatch to that policy.
Wallets that need exactly this path should call `validate_for_production_zk`
on issues, transitions, and continuation plans before requesting ZK proof
material.

For wallet/prover selection, `rgk-asset` also exposes
`RgkProductionAllocationStrategyPlan`. It validates the full native
continuation, then selects either:

* `FixedAllocationVector` for the evidenced fixed shapes; or
* `SegmentedAllocationAudit` for larger conserving full-state transfers.

The segmented strategy uses two-allocation transcript/conservation segments,
a final equality proof, and the complete spent/new exclusion grid. Its strategy
commitment binds the continuation commitment, supplies, counts, segment
capacity, segment counts, exclusion-cell count, and total Groth16 proof-cell
count. It rejects burns and empty sides because the current audit bundle proves
spent/new conservation, not authorised deflation.

Do not split by spending only part of the allocation set: RGK transitions
consume the full previous allocation state. If RGK later needs a single
arbitrary one-step allocation-vector proof, that still requires a recursive,
aggregated, or otherwise unbounded circuit with its own devnet and VM evidence.

## Native Policy Requirement

Proof policy is part of RGK state. A ZK receipt must use a verifier key or
image policy that is admitted by the committed `RgkProofPolicy`.

Unconstrained witness-selected image ids are invalid.

## Not Yet Proven

* single recursive proof for arbitrary-size allocation conservation
* single recursive proof for arbitrary-size closed-seal reuse rejection
* single recursive proof for arbitrary-size private-lane graph discovery
* arbitrary one-step unbounded two-phase continuation consistency in-circuit

The resolver and native validator remain the semantic binding layer for
allocation-vector arities that do not yet have a dedicated circuit.
