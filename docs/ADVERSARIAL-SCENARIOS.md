# Adversarial Test Scenarios

This document catalogues high-complexity, adversarial scenarios that target
specific invariant boundaries in the RGK native asset grammar, the ZK proof
path, the two-phase continuation model, the resolver trust boundary, the
advanced covenant flows, and the privacy/lane layer.

Each scenario names the exact code path it stresses, the invariant it targets,
the attack it models, and the expected verdict. The goal is not to raise
single-primitive coverage — that is already broad — but to exercise
**composition, timing, contention, and cross-boundary** behaviour, which the
existing matrix touches only lightly.

Line references are load-bearing. They use the file:line form so they remain
auditable as the code moves.

## Scope and Status Conventions

Scenarios are tagged:

* **P0** — attacks the trust root or a ZK-level binding gap. Highest priority.
* **P1** — attacks a composition, race, or commitment-binding weakness.
* **P2** — attacks a trust-delegation or completeness boundary.
* **P3** — boundary fuzzing and dead-variant coverage.

Each scenario carries an **Expected verdict** line stating what the system
should do. A scenario whose actual behaviour diverges from the expected
verdict is a candidate for either a hardened invariant or a documented
explicit limitation.

## Background: Where the Surface Lives

A short map of the surfaces targeted below. Full detail lives in
`SECURITY.md`, `ZK-BOUNDARY.md`, and `ARCHITECTURE.md`.

* **Fixed-shape ZK proof path.** Six arity shapes have in-circuit proofs:
  `1x0, 1x1, 2x2, 3x2, 4x2, 4x4`. Selection is exact-match on
  `(spent_count, new_count)` at `crates/rgk-asset/src/native.rs:575-580`.
  Anything else falls to the segmented path.
* **Segmented allocation-audit path.** For larger arity, transitions are
  chunked into segments of capacity 2 and proved as a chained allocation
  transcript, a chained conservation running-total, and a cross-segment
  exclusion grid.
* **Two-phase continuation.** Phase-1 commits to the *shape* of new
  allocations; phase-2 transition material carries the witness txid. The
  fixed-shape proof path binds new allocation txids in-circuit, while the
  segmented path needs an explicit off-circuit binding check. This avoids a
  circular txid dependency but introduces a binding boundary.
* **Resolver trust model.** The resolver trusts the indexer's recorded state
  digest; it does not re-derive digests from live chain UTXOs. The only reorg
  signal is confirmation-depth.
* **Advanced covenant flows.** Single-discriminant policy shapes
  (`PaymentGatedTransfer`, `EscrowRelease`, `VaultTimelockRelease`,
  `AtomicSwap`, `CovenantOwnedAsset`, `PolicyUpgrade`,
  `ControlledTermination`) whose unused fields are allowed zero but still
  committed.
* **Privacy/lane layer.** Nullifiers are lane-agnostic; lane discovery is
  gated by an indexer-side `public_lineage` boolean. `IndexedLane` does not
  store `LanePrivacyPolicy`, so the registration layer cannot cross-check
  the flag against the transition's intended privacy policy.

---

## I. Segmented Allocation Audit (>4x4 Fallback)

The segmented path is the largest coverage gap. Existing tests cover the six
fixed shapes broadly; the chained-segment invariants are exercised only at
the bundle level, not under adversarial construction.

### S1. Cross-Segment Outpoint Reuse Regression (P2)

**Target invariant.** The exclusion grid at
`crates/rgk-zk/src/real_zk.rs:3858-3924` rejects any pair
`(spent_segment[i], new_segment[j])` whose allocations share an outpoint.

**Mechanism.** The native exclusion check
`allocation_exclusion_segment_pair_matches` at
`crates/rgk-zk/src/real_zk.rs:3675-3681` compares the encoded slice
`allocation[1..41]`. Per the encoding at `:3565-3577`, this slice is
`transaction_id[1..33] || index[33..37] || covenant_id[37..41]` — i.e. the
full outpoint **plus the first four bytes of `covenant_id`**. A collision is
detected only when both the outpoint and the leading four covenant-id bytes
agree, which is the realistic case inside a single covenant lineage (all
allocations share the same `covenant_id`).

**Attack.** Construct two spent segments and two new segments. Make
`segment[0].new[0]` and `segment[1].spent[0]` share both a full outpoint and
the leading four covenant-id bytes. The bundle verifier requires the full
spent-segment × new-segment grid (`:3858-3939`), so the pair
`spent_segment[1] / new_segment[0]` should still be present and rejected by
`allocation_exclusion_segment_pair_matches`. Also test omission and duplicate
grid entries.

**Expected verdict.** Rejected. If accepted, the bug is a missing/incorrect
grid entry or pair verifier regression, not an already-known gap in the
current cartesian grid design.

**Fuzz target.** `(spent_count, new_count) ∈ {5,6,8}²`, one cross-segment
collision per case where the colliding allocations share both a full
outpoint and the leading four `covenant_id` bytes (the slice covered by
`[1..41]`). Vary which segment indices the colliding pair lives in.

### S2. Conservation Chain Blinding-Factor Zeroing (P2)

**Target invariant.** Each conservation segment must use a non-zero blinding
factor (`crates/rgk-zk/src/real_zk.rs:1043-1047`), and segment 0 must start
from running total zero (`:1048-1050`).

**Mechanism.** The conservation chain accumulates
`next_running_total = previous_running_total + segment_amount` (`:1060-1062`)
and the `AllocationConservationFinalStatement` proves `spent_total ==
new_total` via both sides opening to the same total with different blindings
(`:1211-1224`).

**Attack.** Set every segment's blinding to zero on one side. Exercise both
the high-level constructors and a raw circuit construction path that bypasses
the constructors. The circuit must still reject zero running-total and final
blindings via `enforce_nonzero_bytes` (`:4116-4117`, `:4177-4179`).

**Expected verdict.** Rejected by constructors at `:1043-1047` / `:1181-1183`
and by circuit constraints. A single zero blinding must fail the whole
bundle.

**Fuzz target.** `segment_count ∈ {2,3,4}`, blinding factors drawn from
`{0, 1, random}`, mismatch `spent_total - new_total ∈ {-1, 0, +1}`.

### S3. Burn vs Segmented Mutual Exclusion (P2)

**Target invariant.** A transition with `burned_supply != 0` is forced to the
fixed path (`crates/rgk-asset/src/native.rs:1811-1817`), but the fixed path
caps at 4x4.

**Mechanism.** A burning transition with more than 4 inputs or 4 outputs has
no valid strategy: the segmented path refuses burns, the fixed path refuses
the shape.

**Attack.** Construct a 5x5 transition that also declares a non-zero
`RgkBurnProof`. Confirm the error path is reached deterministically and that
no fall-through accepts it.

**Expected verdict.** `SegmentedAllocationAuditRequiresConservation`
defined at `crates/rgk-asset/src/native.rs:1161` and raised by the segmented
strategy selector at `:1811-1817`. No silent acceptance, no panic.

### S4. Splitting a 5x5 into Two Stacked 4x4 Transitions (P2)

**Target invariant.** The resolver reconstructs lineage from a chain of
transitions, each independently valid. Two individually-valid transitions
must not aggregate into a shape that would have been rejected as a single
transition.

**Mechanism.** State digest chaining across transitions
(`previous_state_digest` recomputation at `:1368-1377`) links them, but the
exclusion grid is *within-transition* only.

**Attack.** Build transition T1 (4x4, conserving) then T2 (4x4) that spends
some of T1's outputs plus carries a cross-transition outpoint reuse that
would have been illegal within one transition. Confirm whether T2's
fixed-shape/native validation catches the reuse, or whether only the natural
UTXO model does (a truly spent outpoint cannot be re-spent on-chain).

**Expected verdict.** Rejected by the UTXO layer at minimum. The interesting
case is the off-circuit resolver path: does `CompetingBranch` at
`crates/rgk-resolver/src/lib.rs:261-269` fire, or only `Unknown`?

---

## II. Two-Phase Continuation Binding

The phase-1 commitment at `crates/rgk-asset/src/native.rs:1679-1702` binds
the shape of new allocations but **not** `witness_txid`, `daa_score`, or
`confirmation_depth`. The strategy commitment at `:2080-2119` is similarly
txid-agnostic. This is the largest "reusability" surface.

### P1. Phase-1 Plan Reuse Across Transactions (P0)

**Target invariant.** Replay protection is receipt-id keyed
(`crates/rgk-resolver/src/lib.rs:505-507`,
`crates/rgk-indexer/src/lib.rs:1103-1108`), not txid keyed or
phase-1-commitment keyed.

**Mechanism.** Two transitions carrying *different* receipt ids but the
*same* phase-1 commitment are not deduplicated at this layer.

**Attack.** Party A exposes a phase-1 `RgkContinuationPlan` to party B as a
commitment. Party A then finalises the same plan on a different witnessing
transaction with a fresh receipt id. Both transitions are independently
ZK-valid. Whichever reaches the indexer first wins; the second must be
rejected by the natural UTXO model, not by the receipt set.

**Expected verdict.** Exactly one transition is accepted for the original
open outpoint. The second application must fail at the indexer/open-outpoint
or chain UTXO layer, not via `ReceiptError::Replay` when the receipt id is
fresh. This is a *documented* boundary, not a bug — but the scenario pins it
as a test so any future tightening is visible.

**Fuzz target.** same plan, two receipt ids, two witness txids; assert
exactly one of the two finalises.

### P2. Segmented Path Requires Off-Circuit Txid Binding (P0)

**Target invariant.** The fixed-shape circuit enforces
`transaction_id == witness_txid` for new allocations at
`crates/rgk-zk/src/real_zk.rs:4002`. The segmented segment circuit at
`:4042-4088` and segment-pair circuit at `:4202-4279` enforce chain match,
distinct outpoints, amount sum, amount commitment, next-root, and spent/new
exclusion — but **not** `transaction_id == transition witness txid`.

**Mechanism.** The high-level `RgkContinuationPlan::finalize` path emits
new allocation outpoints whose transaction id equals `witness_txid`
(`crates/rgk-asset/src/native.rs:1535-1545`). A manually constructed
`RgkTransition` can otherwise carry new allocation anchors that are
structurally valid but not tied to the transition witness txid by the
segmented subproof. The resolver check at
`crates/rgk-resolver/src/lib.rs:540-546` ties the indexed created outpoint to
the observed spending txid; it does not inspect every encoded new
allocation.

**Attack.** Finalise a >4x4 transition through the normal API, then build a
tampered transition/certificate pair where a new allocation's
`covenant_outpoint.transaction_id` or `witness_txid` differs from the actual
spending txid while the segmented transcript/conservation/exclusion proofs
still verify.

**Expected verdict.** Normal finalisation emits equal txids. The fixed-shape
circuit independently rejects the same mutation. For the segmented path, the
test should prove that an off-circuit verifier rejects the tampered
transition before `NativeTransitionedValid`; if no such verifier exists, this
is a real hardening task rather than a mere documentation boundary.

**Fuzz target.** `(spent, new) ∈ {(5,5),(6,4),(4,6)}` with one mutated txid;
mirror each case on a 4x4 fixed-shape transition.

### P3. Witness Txid Mutation Triggering ReusedSpentAnchor (P3)

**Target invariant.** `RgkAssetError::ReusedSpentAnchor` at
`crates/rgk-asset/src/native.rs:1382-1391` rejects a new allocation whose
outpoint collides with a spent outpoint within the same transition.

**Mechanism.** The check is a `BTreeSet<KaspaOutpoint>` membership test.

**Attack.** Mutate the witness txid during finalisation such that a new
allocation's outpoint coincidentally equals a spent outpoint. This is a
defence, but it is also a griefing vector: an adversary who can influence
txid selection (via fee or input ordering) can force a victim's plan to fail
finalisation.

**Expected verdict.** `ReusedSpentAnchor { index }` raised deterministically.
Document that covenant txid selection is *not* fully miner-controlled in the
Toccata model, bounding the griefing feasibility.

### P4. Phase-1 Commit Then Reorg Before Finalisation (P1)

**Target invariant.** The resolver's only reorg signal is
`confirmation_depth < reorg_safety_depth` (default 10) at
`crates/rgk-resolver/src/lib.rs:185, 255-260, 344-349`. Stored `daa_score` is
**never** re-validated against the chain's `block_daa_score`.

**Mechanism.** Finalisation injects `witness_txid`, `daa_score`, and
`confirmation_depth` into new-allocation anchors at
`crates/rgk-asset/src/native.rs:1535-1545`. If the chain reorgs and the
witnessing transaction's txid changes, the finalised anchors are stale.

**Attack.** Commit phase-1; simulate a reorg that changes the witnessing
txid; finalise with the now-stale txid. Confirm the resolver degrades
gracefully (`ReorgRisk` near the depth boundary, then `Unknown` once pruned)
rather than returning `NativeTransitionedValid`.

**Expected verdict.** Observable spend with depth
`reorg_safety_depth - 1` → `ReorgRisk`; observable spend with depth 0 →
`Unconfirmed`; pruned/missing outpoint → `Unknown`; conflicting observed txid
→ `CompetingBranch`. Never `NativeTransitionedValid`.

---

## III. Resolver Trust Boundary

The resolver trusts the indexer's recorded state digest and does not
re-derive it from live chain data. Reorg handling is shallow.

### R1. Indexer State-Digest Poisoning (P2)

**Target invariant.** `validate_indexed_continuation` at
`crates/rgk-resolver/src/lib.rs:518-548` checks txid agreement and proof
field presence, but does not re-derive `previous_state_digest` from the
chain UTXO.

**Mechanism.** In the already-indexed spend path, `resolve_by_covenant`
reads `indexed.spend_history.last()` and returns `indexed.latest_state` after
backend txid/depth checks plus `validate_indexed_continuation`
(`:227-305`, `:518-548`). The separate `verify_receipt_against_indexer`
API calls `ReceiptVerifier::verify_local` (`:491-515`), but that verifier is
not replayed in this indexed-spend resolution path.

**Attack.** Use a test-only poisoned indexer fixture whose
`latest_state.state_digest` or spend-history state digest does not match the
verified transition material. Confirm whether the resolver detects the
inconsistency itself or accepts the indexed state once the backend-reported
spend txid matches.

**Expected verdict.** Current resolver logic treats the indexer as a trusted
source after indexing: `verify_receipt_against_indexer` calls
`ReceiptVerifier::verify_local` (`:508-513`), but `resolve_by_covenant` does
not replay that verifier for an already indexed spend. The expected result is
therefore either documented trust-boundary acceptance, or a hardening change
that re-verifies receipt/transition material during resolution.

### R2. Pruned Outpoint Indistinguishable From Never-Existed (P2)

**Target invariant.** `get_utxo` returning `None` resolves to `Unknown`
whether the UTXO was pruned by reorg or never existed
(`crates/rgk-resolver/src/lib.rs:312-315, 238`).

**Mechanism.** There is no distinct "invalidated" state in `ResolverState`
(`:43-108`).

**Attack.** Drive a transition through `NativeTransitionedValid`, then
simulate a deep reorg that prunes the spent UTXO. Confirm the resolver's
state machine degrades deterministically into `ReorgRisk`, `Unconfirmed`, or
`Unknown` depending on the observable backend evidence across the depth
boundary `reorg_safety_depth ± 1`.

**Expected verdict.** Deterministic degradation: observable shallow spend
returns `ReorgRisk` or `Unconfirmed`, pruned/missing outpoint returns
`Unknown`, and the transition never flips back to
`NativeTransitionedValid` without fresh consistent backend/indexer evidence.

### R3. CompetingBranch Requires Indexer-vs-Backend Disagreement (P3)

**Target invariant.** `CompetingBranch` at
`crates/rgk-resolver/src/lib.rs:261-269` fires only when the indexer-recorded
spending txid differs from the backend-reported spending txid for the same
outpoint.

**Mechanism.** If a single adversarial backend feeds consistent lies to both
indexer and resolver, `CompetingBranch` cannot fire.

**Attack.** Use `FixtureBackend` to inject a conflicting txid pair and
confirm `CompetingBranch` fires. Then inject a *consistent* lie into both
indexer and backend and confirm the resolver cannot detect it from receipts
alone — this pins the backend-trust assumption explicitly.

**Expected verdict.** The consistent-lie case is *not* detectable at the
resolver layer; document that backend honesty is a stated assumption, not a
proven property.

---

## IV. Advanced Covenant Composition and Boundary

`AdvancedCovenantFlow` is a single discriminant tag
(`crates/rgk-covenant/src/lib.rs:140-148`). True composition is not
expressible, but unused fields are allowed zero and the commitment binds all
fields (`:243-247`, `:331-346`). The semantic surface is therefore narrower
than the commitment surface.

### A1. Escrow Counterparty Mistyped as Vault (P2)

**Target invariant.** `EscrowRelease` validation at
`crates/rgk-covenant/src/lib.rs:459-462` calls `require_counterparty` (exact
equality) and `require_policy_commitment` (exact equality) but does not
cross-check the *type* of the counterparty covenant.

**Mechanism.** `counterparty_covenant_id` is an opaque 32-byte id; nothing
ties it to a flow class.

**Attack.** Build an `EscrowRelease` shape whose `counterparty_covenant_id`
is actually a vault covenant id. The validator accepts. Confirm that wallet
orchestration must perform type binding out-of-band, and that no layer
rejects the mistype.

**Expected verdict.** Accepted at the covenant layer; rejected (or
explicitly allowed only with wallet attestation) at the wallet layer. Pins
the wallet-side responsibility documented in `SECURITY.md` item 12.

### A2. AtomicSwap With Zero Policy Commitment (P1)

**Target invariant.** AtomicSwap is the only flow whose `policy_commitment`
is conditionally required: at execution time it is enforced only
`if !is_zero32(&shape.policy_commitment)` at
`crates/rgk-covenant/src/lib.rs:472-474`. At shape level, AtomicSwap does
not call `require_policy_commitment` (`:315-319`).

**Mechanism.** A shape with zero `policy_commitment` passes both shape and
execution validation.

**Attack.** Build an AtomicSwap with `policy_commitment == [0; 32]`. Confirm
the swap still executes and binds counterparty, payment asset, exact payment,
and unlock. Determine whether a zero policy commitment weakens refund
semantics (e.g. allows unconditional refund after timelock).

**Expected verdict.** Accepted, with the explicit understanding that
AtomicSwap without a policy commitment has no recourse path. Document or
tighten.

### A3. Payment Boundary Asymmetry Between Flows (P3)

**Target invariant.** `PaymentGatedTransfer` rejects `paid_amount <
payment_amount` (`crates/rgk-covenant/src/lib.rs:451-456`, strict `<`), so
overpayment is accepted. `AtomicSwap` requires exact equality
(`require_exact_payment` at `:525-537`).

**Attack.** Boundary fuzz: `paid_amount ∈ {payment - 1, payment,
payment + 1}` for each flow.

**Expected verdict.** PaymentGatedTransfer accepts `payment` and
`payment + 1`, rejects `payment - 1`. AtomicSwap accepts only `payment`.
Document the asymmetry; it is intentional but easy to misimplement in a
wallet.

### A4. VaultTimelockRelease at the Threshold (P3)

**Target invariant.** `require_unlock` at
`crates/rgk-covenant/src/lib.rs:539-549` rejects `current_daa_score <
unlock_daa_score` (strict `<`), so `current == unlock` is allowed.

**Attack.** Boundary fuzz: `current_daa_score ∈ {unlock - 1, unlock,
unlock + 1}`.

**Expected verdict.** Reject `unlock - 1`; accept `unlock` and `unlock + 1`.
The threshold edge is a common off-by-one site in wallets.

### A5. AtomicSwap Two-Leg Race (HTLC Griefing) (P1)

**Target invariant.** `require_exact_payment` and `require_unlock` are
independent checks within the AtomicSwap branch (`:467-475`). The covenant
does not coordinate the two legs of a swap.

**Mechanism.** AtomicSwap is a single-covenant policy; the "two legs" are a
wallet-orchestration concept.

**Attack.** Leg A's payment has been fulfilled by the counterparty; leg A's
timelock then expires. Confirm whether the counterparty can simultaneously
hold the fulfilled payment *and* trigger a refund on the timelock leg — the
classic HTLC griefing pattern.

**Expected verdict.** The covenant layer cannot prevent this; the wallet
must coordinate. Document explicitly that cross-leg atomicity is a wallet
responsibility, and add a regression test for the specific failure mode.

---

## V. Privacy and Lane Boundary

Nullifiers are lane-agnostic and there is no nullifier index. Lane discovery
is gated by an indexer-side `public_lineage` boolean. Since `IndexedLane`
does not store `LanePrivacyPolicy`, the indexer cannot independently verify
that the registration flag matches the originating transition's privacy
policy.

### L1. Cross-Lane Nullifier Collision (P2)

**Target invariant.** `RgkNullifier::derive` at
`crates/rgk-asset/src/native.rs:759-768` hashes `spend_secret || anchor`
(txid, index, covenant_id). It does **not** include `lane_id`, `view_key`,
`asset_id`, or `epoch`.

**Mechanism.** There is no nullifier store anywhere in the codebase. The
indexer keys on `lane_id` and `scan_tag` (`crates/rgk-indexer/src/lib.rs:938-939`),
never on nullifier.

**Attack.** Construct two private lanes sharing a `spend_secret` and anchor.
They produce identical nullifiers, but `public_observer_commitment` also
binds `lane_id`, `epoch`, `state_digest`, `receipt_commitment`,
`policy_commitment`, and optional `scan_tag` (`:638-648`). Confirm that a
shared nullifier alone does not collide the observer commitment or make lane
discovery ambiguous.

**Expected verdict.** Documented as a known property: nullifier collisions
do not corrupt lane state because the indexer never indexes by nullifier,
and observer commitments remain distinct when lane-specific fields differ.
The scenario pins this so any future nullifier index is forced to include a
lane-scoped collision policy.

### L2. public_lineage Flag Inconsistent With LanePrivacyPolicy (P1)

**Target invariant.** `IndexedLane.public_lineage: bool` at
`crates/rgk-indexer/src/lib.rs:96` is set at registration time.
`validate_indexed_lane` at `:887-931` does not cross-check it against
`LanePrivacyPolicy` because that policy is not stored in `IndexedLane`.

**Mechanism.** `resolve_public_lineage` at
`crates/rgk-resolver/src/lib.rs:451-457` returns lanes where
`public_lineage == true`, regardless of policy.

**Attack.** Register lane metadata derived from a
`LanePrivacyPolicy::PrivateLane` transition, but set `public_lineage = true`
in the indexer record. Confirm the resolver exposes it via
`resolve_public_lineage`, breaking the privacy promise unless registration is
trusted or policy is stored.

**Expected verdict.** Either the indexer rejects/flags the registration, or
this is an explicit registration-trust assumption. If privacy policy is meant
to be enforced at registration time, `IndexedLane` needs enough policy
material to perform the check.

### L3. StealthLane as Dead Variant (P3)

**Target invariant.** `StealthLane` exists in the enum
(`crates/rgk-asset/src/native.rs:429`) and decoder (`:2322`) but
`exposes_public_fields` returns false for it, identical to `PrivateLane`.

**Mechanism.** No stealth-specific derivation or indexing exists.

**Attack.** Issue a transition with `LanePrivacyPolicy::StealthLane` and
confirm behaviour matches `PrivateLane` exactly, with no decoder panic.

**Expected verdict.** Accepted; behaviour identical to `PrivateLane`.
Document that `StealthLane` is reserved, not implemented.

### L4. Lane With No scan_tag (Ghost Lane) (P3)

**Target invariant.** `RgkScanTag` is `Option` in `RgkLaneState`
(`crates/rgk-asset/src/native.rs:605`); it is `None` when no view key is
supplied (`:624-626`).

**Mechanism.** `resolve_by_scan_tag` cannot discover such a lane
(`crates/rgk-resolver/src/lib.rs:442-449`).

**Attack.** Issue a lane without a view key. Confirm the lane is reachable
only by explicit `lane_id`, never by scan tag. Confirm the indexer's lane
count includes it.

**Expected verdict.** Reachable only via `lane_id`; counted by the indexer.
Document that "no view key" is a valid but maximally-private lane mode that
sacrifices scan-based discovery.

---

## Priority Summary

| Tag | Scenario | Surface | Why It Matters |
| --- | --- | --- | --- |
| P0 | P2 | Segmented txid binding gap | Segmented subproofs do not bind new allocation txids to the transition witness txid; an off-circuit verifier must do it |
| P0 | P1 | Phase-1 plan reuse | Cross-tx reuse of a phase-1 plan is a double-finalise attempt that must be stopped by UTXO/indexer state, not receipt replay |
| P1 | P4 | Phase-1 then reorg | Reorg during finalisation must degrade gracefully, not silently stay valid |
| P1 | A2 | AtomicSwap zero policy_commitment | Conditional field requirement weakens refund recourse |
| P1 | A5 | AtomicSwap two-leg race | HTLC griefing is not preventable at the covenant layer |
| P1 | L2 | public_lineage / policy mismatch | Direct privacy-promise break if registration is not validated |
| P2 | S1 | Segmented exclusion grid | Regression test that full spent × new grid catches cross-segment outpoint reuse |
| P2 | S2 | Segmented conservation chain | Constructor and circuit-level regression test for zero blinding rejection |
| P2 | S3 | Burn vs segmented exclusion | Semantic completeness of the strategy selector |
| P2 | S4 | Split 5x5 into stacked 4x4 | Cross-transition aggregation must not bypass within-transition invariants |
| P2 | R1 | Indexer state-digest poisoning | Trust-delegation boundary; resolver acceptance must be documented or hardened with re-verification |
| P2 | R2 | Pruned outpoint indistinguishability | Resolver state machine must degrade deterministically |
| P2 | A1 | Escrow counterparty mistyped | Wallet-side type binding responsibility |
| P2 | L1 | Nullifier collision | Future nullifier indexes must lane-scope collisions; current observer commitment should remain distinct |
| P3 | P3 | ReusedSpentAnchor griefing | Txid selection not fully miner-controlled; bounds the vector |
| P3 | R3 | CompetingBranch requires disagreement | Pins the backend-honesty assumption |
| P3 | A3 | Payment boundary asymmetry | Intentional, but easy to misimplement |
| P3 | A4 | VaultTimelock threshold off-by-one | Common wallet bug site |
| P3 | L3 | StealthLane dead variant | Reserved, must not panic |
| P3 | L4 | Ghost lane (no scan_tag) | Valid but maximally-private mode |

## Relationship to Existing Coverage

The existing matrix is broad on single primitives:

* Fixed-shape ZK arities 1x0/1x1/2x2/3x2/4x2/4x4 are covered by
  `crates/rgk-asset/src/native.rs:3913-4080` and
  `tests/rgk-e2e/tests/zk_precompile_vm.rs` (sample-witness builders at
  `:199, :285, :382, :502`).
* Supply conservation, replay, burn, ownership handoff are unit-tested in
  `native.rs:3556-5230`.
* Advanced covenant policy shapes are covered at the primitive level by
  `crates/rgk-covenant/src/lib.rs:1832-2025` and at the example surface by
  `examples/silverscript/advanced_covenant_policy_shapes.sil` plus
  `scripts/verify-example-matrix.sh`.
* Merge and batch continuation are VM-tested in
  `tests/rgk-e2e/tests/covenant_script_vm.rs:329-426`.

The scenarios in this document are *orthogonal*: they target composition,
timing, contention, and cross-boundary behaviour. They should be implemented
alongside the existing matrix, not as replacements.

## Suggested Landing Points

* **Segmented attacks (S1-S4)** belong in `tests/rgk-e2e/tests/zk_precompile_vm.rs`
  next to the existing allocation-vector proofs, since they exercise the
  circuit/bundle layer directly.
* **Two-phase and resolver attacks (P1-P4, R1-R3)** belong in
  `tests/rgk-e2e/src/lib.rs` next to `run_e2e_fixture` at `:490`, extended
  with FixtureBackend-driven reorg/competing-tx injection.
* **Advanced covenant attacks (A1-A5)** should start as focused
  `rgk-covenant` unit tests next to the existing advanced-flow tests. Promote
  only wallet-orchestration or script-VM cases into a new
  `tests/rgk-e2e/tests/advanced_covenant_adversarial.rs`.
* **Privacy/lane attacks (L1-L4)** belong in
  `crates/rgk-asset/src/native.rs` next to the existing privacy tests at
  `:5214`, plus an indexer-registration test in `crates/rgk-indexer/`'s test
  module for L2 and L4.

## Open Questions Worth Resolving Before Implementation

1. **S1 cross-segment collision** — *RESOLVED by test.* The exclusion check
   at `crates/rgk-zk/src/real_zk.rs:3677` compares the encoded slice
   `[1..41]`, which is `transaction_id[1..33] || index[33..37] ||
   covenant_id[37..41]` — i.e. it covers the full outpoint **plus the first
   four bytes of `covenant_id`**. A collision is therefore detected only
   when the outpoint and the leading four covenant-id bytes agree (the
   realistic case within a single covenant lineage, where all allocations
   share the same `covenant_id`). The regression test
   `exclusion_segment_pair_rejects_reused_outpoint_between_spent_and_new`
   confirms both the native `matches_witness` rejection and the in-circuit
   `enforce_spent_anchors_not_reused` defence-in-depth. Missing and
   duplicate grid entries are covered by the pre-existing
   `allocation_audit_bundle_rejects_missing_exclusion_pair` and
   `..._duplicate_exclusion_pair` tests.
2. **S2 blinding-zero** — *RESOLVED by test.* Zero total blindings are
   rejected natively by the conservation constructors at
   `crates/rgk-zk/src/real_zk.rs:1043` and `:1110`. Zero amount blinding is
   rejected in circuit by `enforce_nonzero_bytes(amount_blinding)` at
   `:4057`, even though the transcript witness constructor at `:948` does
   NOT check it natively. The tests
   `conservation_segment_witness_rejects_zero_total_blinding_natively` and
   `transcript_segment_circuit_rejects_zero_amount_blinding_in_circuit`
   pin both layers; the transcript-witness constructor gap is closed by
   the circuit and is now explicitly documented as a defence-in-depth
   seam.
3. **P1 plan reuse**: is the natural-UTXO-model rejection (the second
   finalise's anchor is already spent) reliable across reorgs, or can a
   shallow reorg un-spend the first finalise and let the second succeed?
4. **P2 segmented txid binding** — *PARTIALLY RESOLVED.* The gap is
   confirmed by three tests in `crates/rgk-zk/src/real_zk.rs`:
   `fixed_shape_circuit_binds_new_allocation_outpoint_txid_to_witness_txid`
   (fixed path rejects), `segmented_exclusion_pair_circuit_does_not_bind_outpoint_txid_to_witness_txid`
   (segmented path accepts), and
   `segmented_audit_bundle_verifies_with_detached_new_allocation_txid`
   (bundle layer accepts). The only off-circuit verifier that ties a
   segmented transition's new allocation to the observed spending txid is
   the resolver check at `crates/rgk-resolver/src/lib.rs:540`, which
   inspects only the single indexed created outpoint — not every encoded
   new allocation in the bundle. Whether a wallet or indexer must
   additionally check every new allocation's
   `covenant_outpoint.transaction_id` against the transition witness txid
   before presenting the bundle as final remains an open hardening task.
5. **L1 nullifier**: is there any plan to add a nullifier index? If yes,
   collision handling must be specified before this index exists.
6. **L2 public_lineage**: is the mismatch a registration bug to fix in the
   indexer, or a documented trust assumption about who calls
   `register_lane`?

These questions are intentionally left open in the document so that
implementation of each scenario can resolve them with a test rather than a
speculation.
