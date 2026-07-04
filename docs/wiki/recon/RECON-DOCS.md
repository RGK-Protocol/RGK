# RGK Docs Reconnaissance

**Audience:** tutorial writers preparing a GitHub wiki tutorial series for the
`rgk` repo.
**Goal:** provide a structured, per-file map of every existing `docs/` artifact
plus a `docs/ -> wiki page` recommendation, a gap analysis, and a
contradiction/staleness register.
**Scope:** read-only. No code or doc was modified. All claims are grounded in
the cited `file:line`.

The recon sweep covered every file in `/Users/arthur/RustroverProjects/rgk/docs/`
(including the `audits/` subdirectory) plus the repo-level context files
`README.md` and `CHANGELOG.md`.

## TL;DR

- **19 files mapped**: 14 docs in `docs/` + `audits/public-api-surface.md`
  + 4 reference wrappers. Each tagged by tutorial fit
  (`tutorial-shaped` / `canonical-source` / `reference-shaped`).
- **9 gaps identified** — every one is now filled by a wiki page
  (`Tutorial-0`, `Concepts/Continuation`, `Concepts/Identity`, `Concepts/Resolver`,
  `Concepts/Privacy`, `Concepts/Walletd-Boundary`, `Concepts/Funding`,
  `Concepts/Production-Allocation-Strategy`, `Glossary`).
- **12 contradictions / staleness items** tracked in the
  [§Contradictions / staleness](#contradictions--staleness) section below.
  The most load-bearing: the `1x0, 1x1, 2x2, 3x2, 4x2, 4x4` shape set is
  duplicated across 6+ docs; the wiki binds it to a single glossary entry.
- **`rgk-walletd` is the biggest drift** — present in `Cargo.toml` and
  `README.md` but missing from `ARCHITECTURE.md` and `INTRODUCTION.md`.
  The wiki fixes this in `Concepts/Architecture.md`.

## How to Use This File

1. **Read the TL;DR above.** If you need more, the [File Index](#file-index)
   maps every `docs/` file to a wiki target.
2. **The [`§Gaps`](#gaps) section is the wiki shopping list.** If a gap is
   not filled yet, this file is the source of truth.
3. **The [`§Contradictions / staleness`](#contradictions--staleness) section
   is the drift register.** Before quoting the wiki anywhere, check whether
   your claim is on this list.
4. **The [`§Cross-cutting risk`](#cross-cutting-risk-where-tutorial-writers-should-be-most-careful)
   section flags the highest-drift surfaces** that should be treated as
   "versioned, cite the date".

---

---

## File index

| # | Path | Kind | Tutorial fit |
| --- | --- | --- | --- |
| 1 | `docs/INTRODUCTION.md` | intro + tutorial | `tutorial-shaped` |
| 2 | `docs/ARCHITECTURE.md` | architecture / canonical reference | `canonical-source` |
| 3 | `docs/COVENANT-SPEC.md` | spec | `canonical-source` |
| 4 | `docs/RECEIPT-SPEC.md` | spec | `canonical-source` |
| 5 | `docs/LANE-CALCULUS.md` | spec | `canonical-source` |
| 6 | `docs/SECURITY.md` | threat model | `canonical-source` |
| 7 | `docs/ZK-BOUNDARY.md` | ZK statement spec | `canonical-source` |
| 8 | `docs/ZK-PROOF-PLAN.md` | proof plan / cost / VK governance | `reference-shaped` |
| 9 | `docs/ADVERSARIAL-SCENARIOS.md` | threat-model scenarios | `reference-shaped` |
| 10 | `docs/INTEGRATION.md` | integration how-to | `tutorial-shaped` |
| 11 | `docs/E2E.md` | runbook | `tutorial-shaped` |
| 12 | `docs/MAINNET-LAUNCH.md` | launch checklist | `reference-shaped` |
| 13 | `docs/TESTNET-STAGING-REPORT.md` | staging snapshot (testnet-12) | `reference-shaped` |
| 14 | `docs/AVATO-WALLETD.md` | wallet daemon how-to | `tutorial-shaped` |
| 15 | `docs/UNSAFE-AUDIT.md` | audit notes | `reference-shaped` |
| 16 | `docs/VERIFICATION-BUDGET.md` | verification cost budget | `reference-shaped` |
| 17 | `docs/API-DEPRECATION.md` | policy | `reference-shaped` |
| 18 | `docs/ROADMAP.md` | milestone tracker | `reference-shaped` |
| 19 | `docs/audits/public-api-surface.md` | API audit | `reference-shaped` |

---

## 1. `docs/INTRODUCTION.md`

### Header

- **Path:** `docs/INTRODUCTION.md`
- **Kind:** long-form introduction / tutorial / comparative essay.
- **Audience:** first-time reader, integrator, wallet dev (people new to RGK,
  or coming from RGB).

### Core thesis

RGK is a Kaspa-native covenant-lineage asset system whose design philosophy
matches RGB (chain as notary, wallet as judge) but lives natively on Kaspa
Toccata covenants with its own identity model (covenant lineage as canonical
identity, `asset_id` as lineage-bound label), a private-by-default privacy
posture, a two-phase continuation model that sidesteps the chicken-and-egg
txid problem, and a typed `RgkReceipt` + `RgkResolver` handoff that the resolver
classifies into nine well-defined states.

The most load-bearing sentence:

> "**RGK (Really Good Kaspa)** is a Kaspa-native asset system that lives on top
> of **Kaspa Toccata covenants**." (`docs/INTRODUCTION.md:29-30`)

### Section map

| H2 | H3 | 1-line description |
| --- | --- | --- |
| Table of Contents | — | 13-section outline. |
| TL;DR — What is RGK? | — | One-paragraph elevator pitch + core-ideas table + high-level flow diagram; RGB spiritual-cousin note. |
| The Problem RGK Solves | — | Smart-contract vs embedded-token costs; CSV as the alternative. |
| What Is Client-Side Validation? | — | Chain/event vs client/meaning, three CSV ingredients, court-reporter analogy. |
| RGK vs RGB — How Do They Compare? | Where the philosophies align / Where RGK is genuinely different | Comparison table on 8 axes; lineage vs seal, two-phase continuation, receipt/resolver handoff, throughput posture. |
| The RGK Architecture in One Picture | — | 4-layer L1..L4 architecture diagram + per-crate role table. |
| On-Chain / Off-Chain Interaction | The big picture / What goes on-chain vs off-chain | Wallet <-> chain <-> indexer flow diagram; on-chain vs off-chain data table. |
| A Transfer, Step by Step | Why each step matters | 10-step Alice-to-Bob sequence diagram; 1x1..4x4 / segmented footnote. |
| Privacy Model: Public Lineage vs Private Lane | How a private lane hides itself | Three-mode table; view-key discovery + scan tag / nullifier diagram. |
| Identity: Lineage First, Label Second | — | Lineage-id formula; "faked label doesn't forge identity" rationale. |
| Why Two Phases? The Continuation Output | — | Phase-1 / Phase-2 sequence diagram; resolver rejection conditions. |
| What the Resolver Does | — | Resolver state-diagram (`Open`, `Unconfirmed`, `NativeTransitionedValid`, ..., `PolicyMigrationRequired`). |
| Try It | — | `./scripts/e2e-local.sh` (fixture) vs `--live` vs `--start-kaspa` devnet. |
| Further Reading | — | 11-doc index table. |
| TL;DR (one more time, for the road) | — | Closing recap. |

### Cross-references (consistency-critical)

- Types named: `RgkAssetIssue`, `RgkAllocation`, `RgkTransition`, `RgkProofPolicy`, `LanePrivacyPolicy`, `RgkStateDigest`, `RgkTransitionDigest`, `RgkReceipt`, `RgkReceiptCommitment`, `RgkContinuationPlan` (`docs/INTRODUCTION.md:253, 254, 300, 364, 502`).
- Resolver states: `NativeTransitionedValid`, `NativeTransitionedInvalid`, `ReplayRejected`, `ReorgRisk`, `CompetingBranch`, `PolicyMigrationRequired` (`docs/INTRODUCTION.md:197-198, 555-569`).
- Wire formula: `lineage_id = H("rgk:lineage" || genesis_outpoint_payload || asset_id)` (`docs/INTRODUCTION.md:450`).
- Privacy modes: `PublicLineage`, `PrivateLane`, `StealthLane` (`docs/INTRODUCTION.md:398-399`).
- Crate table: `rgk-core`, `rgk-asset`, `rgk-receipt`, `rgk-covenant`, `rgk-kaspa`, `rgk-zk`, `rgk-indexer`, `rgk-sync`, `rgk-resolver`, `rgk-tx` (`docs/INTRODUCTION.md:266-274`).
- Script paths: `./scripts/e2e-local.sh`, `./scripts/setup-external.sh`, `./scripts/build-kaspa.sh`, `./scripts/run-kaspa-local.sh`, `./scripts/e2e-devnet.sh` (`docs/INTRODUCTION.md:583-593`).

### Tutorial fit

`tutorial-shaped`. This is the closest thing the corpus already has to a wiki
Home/Tutorial-1 page. Use it as the spine: light copy-edit, link the
section-anchors into the wiki sidebar, and turn the "Further Reading" table into
"Next: ..." cross-links.

### Drift risks

- Crate list omits `rgk-walletd` (visible in `README.md:194` and `Cargo.toml:14`
  but absent from the `INTRODUCTION.md:266-274` table). The omission is
  intentional in the high-level "RGK core" narrative but the wiki tutorial
  should add it back when discussing the Avato frontend.
- The "Status" row at `docs/INTRODUCTION.md:173` is hand-written prose and may
  drift from the "Launch readiness" line at `README.md:172-179`.

---

## 2. `docs/ARCHITECTURE.md`

### Header

- **Path:** `docs/ARCHITECTURE.md`
- **Kind:** architecture reference.
- **Audience:** integrator, wallet dev, auditor (people who need to know the
  crate boundary and resolver state machine exactly).

### Core thesis

RGK is a layered Kaspa-native covenant-lineage asset system: a native asset
grammar (`RgkAssetIssue` / `RgkTransition` / `RgkProofPolicy` /
`LanePrivacyPolicy`) feeds a client-side validation layer (`RgkStateDigest` /
`RgkTransitionDigest` / `RgkReceipt` / `RgkReceiptCommitment`) which is
anchored by a Toccata covenant lineage (`CovenantState` / `CovenantSpec`) and
finalised by a native resolver state machine (`RgkResolverState` with
`Open / NativeTransitionedValid / NativeTransitionedInvalid / Unconfirmed /
ReorgRisk / CompetingBranch / ReplayRejected / PolicyMigrationRequired /
Unknown / NodeDown`).

The most load-bearing sentence:

> "RGK is a Kaspa-native covenant-lineage asset system. The native settlement
> substrate is Kaspa Toccata; the native state machine is RGK. Canonical asset
> identity is the Kaspa covenant lineage / lane. `asset_id` is lineage-bound
> native label material, not an external contract id or the primary identity."
> (`docs/ARCHITECTURE.md:3-6`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Layer Diagram | ASCII stack: native grammar -> CSV/receipt -> Toccata covenant -> indexer/resolver. |
| Workspace Crates | 10-crate role table (omits `rgk-walletd`). |
| Transition Flow | 7-step transition flow narrative. |
| Lane Model | Private-lane state list (blinded lane id, scan tag, encrypted note, nullifier, policy commitment, private state root, view-key discovery). |
| Resolver States | Inline `pub enum RgkResolverState` Rust listing; lane-specific resolver entry points; `CompetingBranch` and `PolicyMigrationRequired` semantics; `PolicyMigrationInput::build` in `rgk-core`. |
| Boundaries | ZK boundary paragraph naming every circuit family and the supported-shape dispatch API. |

### Cross-references (consistency-critical)

- Crate list omits `rgk-walletd` (`docs/ARCHITECTURE.md:43-54`).
- `RgkResolverState` enum variants verbatim (`docs/ARCHITECTURE.md:96-107`).
- `resolve_lane / resolve_by_view_key / resolve_by_scan_tag / resolve_public_lineage / resolve_transition` (`docs/ARCHITECTURE.md:111-112`).
- `PolicyMigrationInput::build` in `rgk-core` (`docs/ARCHITECTURE.md:124`).
- ZK families named: `SemanticTransitionCircuit`, `OneInOneOutAllocationCircuit`, `TwoInTwoOutAllocationCircuit`, `FixedAllocationVectorCircuit<const SPENT, const NEW>`, `AllocationTranscriptSegmentCircuit<const ALLOCS>`, `AllocationConservationSegmentCircuit<const ALLOCS>`, `AllocationConservationFinalCircuit`, `AllocationExclusionSegmentPairCircuit<const SPENT, const NEW>`, `AllocationAuditBundle`, `AllocationAuditCertificate`, `SupportedAllocationVectorCircuit` (`docs/ARCHITECTURE.md:136-160`).
- Proven shapes: `1x0, 1x1, 2x2, 3x2, 4x2, 4x4` (`docs/ARCHITECTURE.md:160-161`).

### Tutorial fit

`canonical-source`. The resolver state machine (`docs/ARCHITECTURE.md:96-107`)
and the boundary paragraph (`docs/ARCHITECTURE.md:130-160`) are the
authoritative references. Tutorials should link to them, not rewrite them.

### Drift risks

- Same `rgk-walletd` omission as `INTRODUCTION.md`.
- `docs/ARCHITECTURE.md:54` describes `rgk-tx` as "Toccata v1 transaction / Borsh-wire / hash boundary"; the actual `rgk-tx` crate is more elaborate (see
  `README.md:194` and the additional fields in `ROADMAP.md:40` and
  `E2E.md:121`). Tutorial should cite the longer form.

---

## 3. `docs/COVENANT-SPEC.md`

### Header

- **Path:** `docs/COVENANT-SPEC.md`
- **Kind:** spec.
- **Audience:** wallet dev, integrator, auditor (people constructing or
  verifying covenant payloads).

### Core thesis

The RGK covenant is a Kaspa Toccata covenant UTXO carrying one native RGK
state payload; the payload's `asset_id`, `lineage_id`, `receipt_policy`, and
`genesis_proof_mode` are immutable across ordinary spends; the default
`CovenantSpec::build_script()` emits a singleton continuation policy that
preserves the covenant id, payload length, and lineage/asset/policy/mode
constants; explicit `CovenantContinuationPolicy` and
`CovenantSharedContinuationPolicy` extend the same invariants to fanout and
merge/batch shapes, all with upstream Toccata VM execution evidence and a
checked Silverscript artifact.

The most load-bearing sentence:

> "The RGK covenant is a Kaspa Toccata covenant UTXO that carries one native
> RGK state payload for an asset lineage." (`docs/COVENANT-SPEC.md:3-4`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Covenant State | Inline `pub struct CovenantState` Rust; payload byte layout line. |
| Lineage | `lineage_id` formula; identity vs label explanation. |
| Script Invariants | Default `CovenantSpec::build_script()` checks; explicit `build_script_for_policy()`; shared-policy for merge/batch; Silverscript artifact path. |

### Cross-references (consistency-critical)

- `pub struct CovenantState` fields: `version: u16`, `chain_id: KaspaChainId`, `lineage_id: [u8; 32]`, `asset_id: [u8; 32]`, `current_state_digest: [u8; 32]`, `receipt_policy: ReceiptPolicy`, `genesis_proof_mode: ProofMode`, `replay_marker: [u8; 32]` (`docs/COVENANT-SPEC.md:9-19`).
- Payload layout: `tag | version | chain_id | lineage_id | asset_id | state_digest | policy | mode | replay_marker` (`docs/COVENANT-SPEC.md:24`).
- `lineage_id = H("rgk:lineage" || genesis_outpoint_payload || asset_id)` (`docs/COVENANT-SPEC.md:33`).
- Script builder methods: `CovenantSpec::build_script()`, `build_script_for_policy()`, `build_script_for_shared_policy()` (`docs/COVENANT-SPEC.md:43, 62, 78`).
- Toccata opcodes referenced: `OP_TX_OUTPUT_COUNT`, `OP_COV_INPUT_COUNT`, `OP_COV_OUTPUT_COUNT`, `OP_COV_OUTPUT_IDX` (`docs/COVENANT-SPEC.md:66, 80-84`).
- Files: `examples/silverscript/rgk_covenant_continuation_policy.sil`, `examples/silverscript/artifacts/rgk_covenant_continuation_policy.json` (`docs/COVENANT-SPEC.md:94-97`).

### Tutorial fit

`canonical-source`. The `CovenantState` struct and the byte layout are
reference data — the wiki should link to this page rather than restate it.

### Drift risks

- `docs/COVENANT-SPEC.md:14-15` lists `proof_mode: ProofMode` as part of the
  payload, while `docs/RECEIPT-SPEC.md:14-15` lists `proof_mode: ProofMode`
  inside `ReceiptInput`. The two are the same enum but referenced at
  different layers; the tutorial must be careful which layer it is talking
  about.
- The Silverscript paths at `docs/COVENANT-SPEC.md:94-97` are pinned to a
  specific compile artifact. If the matrix is reorganised, this path will go
  stale (cf. `ROADMAP.md:46` which mentions the matrix as a "maintained" thing).

---

## 4. `docs/RECEIPT-SPEC.md`

### Header

- **Path:** `docs/RECEIPT-SPEC.md`
- **Kind:** spec.
- **Audience:** wallet dev, integrator, auditor.

### Core thesis

`RgkReceipt` is a typed, hash-bound statement of a native RGK asset transition
that wraps `ReceiptInput` (chain id, covenant id, old/new state commitments,
transition digest, continuation commitment, proof mode, replay nonce) over an
`RgkStateCommitment` (version, chain id, covenant id, asset id, state digest,
receipt policy) and is identified by `receipt_id = H("rgk:receipt" ||
canonical_receipt_bytes)`. The receipt does not prove every semantic rule on
its own; it binds the validated native transition result and the phase-1
continuation commitment to the covenant lineage so the resolver and indexer can
verify replay, continuity, and chain evidence.

The most load-bearing sentence:

> "`RgkReceipt` is the canonical statement that a native RGK asset transition
> advanced a covenant state." (`docs/RECEIPT-SPEC.md:3-4`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Receipt Input | Inline `pub struct ReceiptInput` Rust. |
| State Commitment | Inline `pub struct RgkStateCommitment` Rust. |
| Structural Invariants | 9-bullet list of receipt-time checks. |
| Commitment | `receipt_id` formula + scope-of-the-receipt caveat. |

### Cross-references (consistency-critical)

- `ReceiptInput` fields: `chain_id, covenant_id, old_state, new_state, transition_digest, continuation_commitment, proof_mode, replay_nonce` (`docs/RECEIPT-SPEC.md:9-18`).
- `RgkStateCommitment` fields: `version, chain_id, covenant_id, asset_id, state_digest, receipt_policy` (`docs/RECEIPT-SPEC.md:24-31`).
- 9 structural invariants enumerated at `docs/RECEIPT-SPEC.md:36-44`.
- `receipt_id = H("rgk:receipt" || canonical_receipt_bytes)` (`docs/RECEIPT-SPEC.md:48`).

### Tutorial fit

`canonical-source`. Tiny, dense, reference-grade. Link, don't rewrite.

### Drift risks

- None detected relative to README/CHANGELOG. The structural invariants are
  the same set the `ARCHITECTURE.md` resolver section references.

---

## 5. `docs/LANE-CALCULUS.md`

### Header

- **Path:** `docs/LANE-CALCULUS.md`
- **Kind:** spec (formerly the "internalisation" doc, per `CHANGELOG.md:195`).
- **Audience:** wallet dev, auditor, integrator.

### Core thesis

RGK's identity is the Kaspa covenant lineage / lane; `asset_id` is native
label material committed into state, receipts, and covenant payloads, not an
external contract id. The native asset grammar has hot-path types
(`RgkAssetIssue`, `RgkAllocation`, `RgkTransition`, `RgkCovenantAnchor`,
`RgkStateDigest`, `RgkTransitionDigest`, `RgkReceipt`, `RgkLane`,
`RgkLaneState`, `RgkPrivacyPolicy`, `RgkResolver`); the default lane privacy
mode is `PrivateLane`; proof policy is state, and unconstrained
witness-selected image ids are rejected; the two-phase continuation model
binds a phase-1 txid-free commitment to phase-2 txid finalisation, with
explicit resolver-side rejection of missing proof or mismatched continuation
outpoint.

The most load-bearing sentence:

> "This document defines the native RGK asset, lane, privacy, and continuation
> model." (`docs/LANE-CALCULUS.md:3-4`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Identity | Lineage-vs-label boundary. |
| Native Asset Grammar | Hot-path types list; issue/transition validation bullets; state-digest field list. |
| Lane Privacy | `LanePrivacyPolicy` enum; "public observers should not learn" invariants; private-lane protocol fields. |
| Discovery | `RgkScanTag::derive`, `RgkNullifier::derive`, `RgkLaneGraphNode`, `derive_private_lane_graph_root`, `private_lane_graph_empty_root`, `extend_private_lane_graph_root`. |
| Proof Policy | `RgkProofPolicy` enum variants. |
| Two-Phase Continuation Output | Phase 1 / Phase 2 enumeration; resolver rejection conditions; implemented tests. |

### Cross-references (consistency-critical)

- Hot-path types list: `RgkAssetIssue, RgkAllocation, RgkTransition, RgkCovenantAnchor, RgkStateDigest, RgkTransitionDigest, RgkReceipt, RgkLane, RgkLaneState, RgkPrivacyPolicy, RgkResolver` (`docs/LANE-CALCULUS.md:17-28`).
- `LanePrivacyPolicy::{PublicLineage, PrivateLane, StealthLane}` (`docs/LANE-CALCULUS.md:60-64`).
- Discovery primitives: `BlindedLaneId`, `RgkScanTag`, `RgkNullifier`, `RgkPolicyCommitment` (`docs/LANE-CALCULUS.md:75-80`).
- `RgkProofPolicy::{VerifierReceipt, ZkReceipt, Hybrid}` with `ImageIdPolicy` (`docs/LANE-CALCULUS.md:108-114`).
- Domain tag: `rgk:lane:graph-root:v1` (`docs/LANE-CALCULUS.md:93`).
- Discovery call signature: `RgkScanTag::derive(view_key, lane_id, epoch)`, `RgkNullifier::derive(spend_secret, covenant_anchor)` (`docs/LANE-CALCULUS.md:85, 89`).

### Tutorial fit

`canonical-source`. The hot-path types and proof-policy variants are
authoritative reference data. The "Implemented tests" sub-list in the
two-phase section is a good tutorial cross-link target.

### Drift risks

- `docs/LANE-CALCULUS.md:147-152` says the remaining work is "funded public
  staging and, if required by product scope, a single recursive or aggregated
  allocation-vector proof." This is consistent with `CHANGELOG.md:206-212`,
  but the wiki tutorial must not present this as a "current limitation" without
  a date.

---

## 6. `docs/SECURITY.md`

### Header

- **Path:** `docs/SECURITY.md`
- **Kind:** threat model.
- **Audience:** auditor, integrator, security reviewer.

### Core thesis

Native RGK binds a client-side validated asset state to a Kaspa Toccata
covenant lineage. The resolver can verify from local state and live chain
evidence that a covenant spend advanced the committed RGK state according to
the native grammar. RGK proves twelve things (lineage continuity, output
shape, state advance, asset-label binding, supply accounting, covenant-output
uniqueness, policy binding, replay protection, privacy mode binding,
owner-control binding, NFT policy binding, advanced covenant policy binding)
and explicitly does not yet prove: public testnet or mainnet operation, an
arbitrary one-step unbounded allocation-vector Groth16 proof, public staging
evidence for continuation / policy-migration flows, arbitrary historical
discovery, or post-quantum security.

The most load-bearing sentence:

> "RGK binds a client-side validated native asset state to a Kaspa Toccata
> covenant lineage. A resolver can verify from local state and live chain
> evidence that a covenant spend advanced the committed RGK state according to
> the native grammar." (`docs/SECURITY.md:8-11`)

### Section map

| H2 | H3 | 1-line description |
| --- | --- | --- |
| Top-Level Claim | — | One-paragraph thesis. |
| What RGK Proves | — | 12-item list (lineage continuity, supply accounting, replay, privacy mode, owner control, NFT, advanced covenant, ...). |
| Privacy Claim | — | PrivateLane default; protocol field list; `e2e-privacy-observer.sh` evidence. |
| What RGK Does Not Prove Yet | — | 5-item "not yet" list (public net, recursive, public staging evidence, historical discovery, post-quantum). |
| Threat Model | — | Inline threat-vs-mitigation table (17 rows from `Malicious covenant payload` through `Private-lane scanning error`). |
| Trust Assumptions | — | 5 bullets: Kaspa consensus, wallet validator, resolver honesty, local indexer, ZK assumptions. |
| Resolver Classifications | — | 10-state vertical list. |

### Cross-references (consistency-critical)

- 12 "proves" items enumerated at `docs/SECURITY.md:14-46`.
- 5 "does not prove yet" items at `docs/SECURITY.md:67-84`.
- Threat table rows include (selection): `Malicious covenant payload`, `Asset-label swap`, `State no-op replay`, `Spent covenant-output reuse`, `Supply inflation`, `Proof-policy downgrade`, `Owner-control substitution`, `NFT template or metadata substitution`, `Unconstrained image id`, `Receipt replay`, `Reorg`, `Implicit policy change`, `RPC equivocation`, `Private-lane scanning error` (`docs/SECURITY.md:90-104`).
- Resolver state list: `Open, NativeTransitionedValid, NativeTransitionedInvalid, Unconfirmed, ReorgRisk, CompetingBranch, ReplayRejected, PolicyMigrationRequired, Unknown, NodeDown` (`docs/SECURITY.md:118-128`).
- Scripts: `scripts/e2e-privacy-observer.sh`, `scripts/verify-privacy-observer-evidence.sh` (`docs/SECURITY.md:58-63`).

### Tutorial fit

`canonical-source`. The 12-item "What RGK Proves" list and the
"Threat Model" table are the canonical audit vocabulary.

### Drift risks

- The 5-item "Does Not Prove Yet" list at `docs/SECURITY.md:67-84` is
  effectively a launch-readiness checklist; it duplicates content in
  `docs/MAINNET-LAUNCH.md:5-55` and `docs/ROADMAP.md:322-325` and
  `docs/ZK-BOUNDARY.md:348-356`. The wiki should cross-link these three but
  mark `SECURITY.md` as the canonical security text.
- `docs/SECURITY.md:71-80` says "production ZK strategy is bounded to 1x0
  terminal burn, 1x1, 2x2, const-generic 3x2, const-generic 4x2, and
  const-generic 4x4"; this list is repeated almost verbatim in
  `ZK-BOUNDARY.md:308-317`, `ARCHITECTURE.md:158-161`, `INTEGRATION.md:93-94`,
  `E2E.md:306-307`, and `README.md:160-161`. If the supported-shape set
  changes, six places need to be touched in lockstep. The wiki should bind
  this to a single tutorial-glossary entry.

---

## 7. `docs/ZK-BOUNDARY.md`

### Header

- **Path:** `docs/ZK-BOUNDARY.md`
- **Kind:** ZK statement spec.
- **Audience:** wallet dev, prover author, auditor.

### Core thesis

The current ZK path proves an RGK receipt statement and a canonical 512-byte
`SemanticTransitionStatement`; it does not yet prove the entire native
transition semantics inside the circuit. The proven surface is: a receipt
statement (chain id, covenant id, lineage-bound `asset_id`, old/new state
digest, transition digest, continuation commitment, receipt id), a
`SemanticTransitionStatement` (with metadata/owner commitments, supply,
allocation counts, burn authorisation), bounded `LaneDiscoveryCircuit` and
`LaneGraphDiscoveryCircuit<const LANES>`, segmented
`LaneGraphSegmentCircuit<const LANES>`, fixed-shape allocation-vector circuits
(`1x0, 1x1, 2x2, 3x2, 4x2, 4x4`) through `SupportedAllocationVectorCircuit`,
segmented audit (`AllocationTranscriptSegmentCircuit`,
`AllocationConservationSegmentCircuit`, `AllocationConservationFinalCircuit`,
`AllocationExclusionSegmentPairCircuit`), the `AllocationAuditBundle`
verifier, the `AllocationAuditCertificate` portable envelope, and the
`R0SuccinctPrecompileStack` (stack support only; not a native RISC0
proving system). RGK has stack/VM support for the Toccata precompile, but
not a native RISC0 prover or RGK RISC0 circuit family.

The most load-bearing sentence:

> "The current ZK path proves an RGK receipt statement. It does not yet
> prove the entire native transition semantics inside the circuit."
> (`docs/ZK-BOUNDARY.md:3-4`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Current Statement | Receipt statement fields; `R0SuccinctPrecompileStack`; wrapper rejection of opaque Succinct proofs. |
| Semantic Transition Statement | 512-byte statement field list; circuit constraints; `real-zk` execution evidence. |
| Lane Discovery Circuit | `LaneDiscoveryCircuit` and `LaneGraphDiscoveryCircuit<const LANES>` public-input layouts. |
| Allocation-Vector Circuit | `OneInOneOut`, `TwoInTwoOut`, `FixedAllocationVectorCircuit<const SPENT, const NEW>`. |
| Allocation Transcript Segment Circuit | `AllocationTranscriptSegmentCircuit`, `AllocationConservationSegmentCircuit`, `AllocationConservationFinalCircuit`, `AllocationExclusionSegmentPairCircuit` — all with public-input byte lengths and field counts. |
| Allocation Audit Bundle Verifier | Bundle-level cross-proof checks; `AllocationAuditCertificate` envelope; `rgk:aac1` envelope; indexer attachment story. |
| Production Allocation-Proof Strategy | `ProductionAllocationProofStrategy::BoundedSupportedShapes`; `RgkAllocationProofShape`; `RgkProductionAllocationStrategyPlan`; `RgkProductionAllocationStrategyRecord`. |
| Native Policy Requirement | Proof policy is part of RGK state. |
| Not Yet Proven | 5-item "not yet" list (single recursive proof for arbitrary size, RGK-native RISC0, ...). |

### Cross-references (consistency-critical)

- Receipt statement fields at `docs/ZK-BOUNDARY.md:10-18`.
- Semantic statement fields at `docs/ZK-BOUNDARY.md:44-60`.
- `R0SuccinctPrecompileStack` is "for Toccata's RISC Zero Succinct precompile
  stack material" (`docs/ZK-BOUNDARY.md:25-30`).
- Public-input byte/field counts: `512 bytes / 64 BN254` (semantic), `72 / 9`
  (lane discovery), `128 / 16` (transcript), `192 / 24` (conservation), `80 / 10`
  (conservation final), `232 / 29` (exclusion pair) (`docs/ZK-BOUNDARY.md:67,
  89, 178, 204, 222, 237`).
- Supported shapes: `1x0, 1x1, 2x2, 3x2, 4x2, 4x4` (`docs/ZK-BOUNDARY.md:311`).
- Domain tags / envelopes: `rgk:zk:allocation-audit-certificate:v1`,
  `rgk:aac1` (`docs/ZK-BOUNDARY.md:289, 287`).
- Proven-but-not-proven split: `R0Succinct` is "stack support only" (`docs/ZK-BOUNDARY.md:31-34`).

### Tutorial fit

`canonical-source`. Long, dense, and full of byte/field counts that any
tutorial must copy verbatim. Wiki should link + extract.

### Drift risks

- The "Not Yet Proven" list at `docs/ZK-BOUNDARY.md:350-355` overlaps with
  `SECURITY.md:67-84` and `ROADMAP.md:322-325`; the wiki should pick one
  canonical home and cross-link.
- `docs/ZK-BOUNDARY.md:166-172` mixes shape names: "1x1, 2x2, generic 3x2,
  generic 4x2, and generic 4x4" is the upstream-VM-tested surface, while the
  production surface at `docs/ZK-BOUNDARY.md:311` is "1x0 terminal burn, 1x1,
  2x2, 3x2, 4x2, 4x4". This subtlety (1x0 is production-ZK but does not need
  VM-evidence separate from receipt) must not be lost when summarising.

---

## 8. `docs/ZK-PROOF-PLAN.md`

### Header

- **Path:** `docs/ZK-PROOF-PLAN.md`
- **Kind:** proof plan / cost / VK governance (plain-language planning doc).
- **Audience:** wallet dev, prover author, audit/governance reviewer.

### Core thesis

Use fixed Groth16 allocation proofs for the evidenced shapes
(`1x0, 1x1, 2x2, 3x2, 4x2, 4x4`); use segmented allocation-audit certificates
for larger conserving full-state transfers; never describe segmented audit as
one recursive proof; never put R0 Succinct on the hot path until RGK has a
native RISC0 prover, circuit family, and cost evidence; keep every proof claim
tied to a verifier, a shape, a cost budget, and a report line that proves it.
The current cost snapshot is published inline; the planning tracks are P0
(keep claims honest), P1 (freeze mainnet budgets), P2 (future compression
work). The plain-language decision rule is the closing heuristic.

The most load-bearing sentence:

> "Use fixed Groth16 allocation proofs whenever the transfer shape is one of
> the evidenced shapes." (`docs/ZK-PROOF-PLAN.md:9-10`)

### Section map

| H2 | 1-line description |
| --- | --- |
| (intro) | "The short version" — six bullets. |
| Current Claim Boundary | 6-row "surface / status / production claim" table; "Do not claim" 5-bullet list. |
| Proof Path Selector | Mermaid decision tree (fixed vs segmented vs fail-closed). |
| Current Cost Snapshot | 11-row proof-cost table (public inputs, VK bytes, proof bytes, notes). |
| Segmented Audit Cost Growth | `2*(spent+new) + 1 + spent*new` formula; growth diagram. |
| Production Budget Rules | 7-row rule table. |
| Verifier Key Governance | Mermaid setup/VK/wallet/prover/verifier sequence; 6-bullet "before mainnet" list. |
| Operational Evidence | 5 `bash` evidence-gate commands. |
| Planning Tracks | P0 / P1 / P2 sub-sections. |
| Plain-Language Decision Rule | Closing rule statement. |

### Cross-references (consistency-critical)

- 6-row claim-boundary table at `docs/ZK-PROOF-PLAN.md:23-30`.
- 11-row cost-snapshot table at `docs/ZK-PROOF-PLAN.md:69-82` (e.g.
  `Semantic transition | 64 | 2312 | 128`, `Allocation audit certificate | n/a
  | 5392 total | 768 total`).
- Segmented entry-count formula: `2 * (spent_segments + new_segments) + 1 + spent_segments * new_segments` (`docs/ZK-PROOF-PLAN.md:98`).
- Evidence-gate script paths: `scripts/e2e-internal-readiness.sh`,
  `scripts/verify-internal-readiness-evidence.sh`,
  `scripts/e2e-testnet-staging.sh --resume …`,
  `scripts/verify-testnet-staging-evidence.sh`,
  `scripts/verify-launch-readiness.sh` (`docs/ZK-PROOF-PLAN.md:174-178`).
- Output paths: `target/rgk-internal-readiness/latest.txt`,
  `target/rgk-testnet-staging-evidence/latest.txt` (`docs/ZK-PROOF-PLAN.md:175-177`).

### Tutorial fit

`reference-shaped`. The cost table and budget rules are reference data; the
P0/P1/P2 planning tracks are governance prose. This file is best surfaced as
a wiki Reference page (or two: cost + governance), not a tutorial.

### Drift risks

- `docs/ZK-PROOF-PLAN.md:78` shows `Current allocation audit certificate | n/a
  | 5392 total | 768 total | 6 proof entries, 11826 canonical bytes`. The
  exact byte counts will drift as new shapes are added; the wiki tutorial
  should cite the doc-page timestamp, not the numbers directly.
- The "Operational Evidence" section at `docs/ZK-PROOF-PLAN.md:172-188`
  duplicates `docs/MAINNET-LAUNCH.md:99-117` and `docs/E2E.md:48-123`. The
  wiki should pick one canonical "evidence gates" page.

---

## 9. `docs/ADVERSARIAL-SCENARIOS.md`

### Header

- **Path:** `docs/ADVERSARIAL-SCENARIOS.md`
- **Kind:** adversarial threat-model scenarios (composition, timing,
  contention, cross-boundary).
- **Audience:** auditor, security reviewer, advanced wallet dev.

### Core thesis

The existing test matrix is broad on single primitives (fixed shapes,
conservation, replay, burn, ownership handoff) but only lightly covers
composition, timing, contention, and cross-boundary behaviour. This document
catalogues 20 high-complexity adversarial scenarios — segmented allocation
audit (S1-S4), two-phase continuation (P1-P4), resolver trust (R1-R3),
advanced covenant composition (A1-A5), privacy/lane (L1-L4) — each pinned
to a target invariant, a `file:line` reference, an attack model, an expected
verdict, and a fuzz target. Two scenarios are P0 (P1 phase-1 plan reuse, P2
segmented path off-circuit txid binding).

The most load-bearing sentence:

> "The existing matrix is broad on single primitives: … The scenarios in this
> document are *orthogonal*: they target composition, timing, contention, and
> cross-boundary behaviour." (`docs/ADVERSARIAL-SCENARIOS.md:550-567`)

### Section map

| H2 | H3 | 1-line description |
| --- | --- | --- |
| Scope and Status Conventions | — | P0..P3 priority tags + "Expected verdict" convention. |
| Background: Where the Surface Lives | — | Six-bullet surface map (fixed shapes, segmented, two-phase, resolver, advanced covenant, privacy). |
| I. Segmented Allocation Audit (>4x4 Fallback) | S1 Cross-Segment Outpoint Reuse (P2) | Exclusion-grid regression. |
| | S2 Conservation Chain Blinding-Factor Zeroing (P2) | Constructor + circuit-level zero-blinding rejection. |
| | S3 Burn vs Segmented Mutual Exclusion (P2) | 5x5 + burn should fail closed. |
| | S4 Splitting a 5x5 into Two Stacked 4x4 Transitions (P2) | Cross-transition aggregation boundary. |
| II. Two-Phase Continuation Binding | P1 Phase-1 Plan Reuse Across Transactions (P0) | Replay-by-receipt-id is insufficient. |
| | P2 Segmented Path Requires Off-Circuit Txid Binding (P0) | New-allocation txid not bound to witness txid in segment subproof. |
| | P3 Witness Txid Mutation Triggering ReusedSpentAnchor (P3) | `RgkAssetError::ReusedSpentAnchor` griefing. |
| | P4 Phase-1 Commit Then Reorg Before Finalisation (P1) | Reorg-during-finalisation degradation. |
| III. Resolver Trust Boundary | R1 Indexer State-Digest Poisoning (P2) | Resolver trusts indexer state digest. |
| | R2 Pruned Outpoint Indistinguishable From Never-Existed (P2) | `get_utxo` returns `None`. |
| | R3 CompetingBranch Requires Indexer-vs-Backend Disagreement (P3) | Single-adversary-backend cannot fire `CompetingBranch`. |
| IV. Advanced Covenant Composition and Boundary | A1 Escrow Counterparty Mistyped as Vault (P2) | Counterparty id is opaque. |
| | A2 AtomicSwap With Zero Policy Commitment (P1) | Conditional field requirement. |
| | A3 Payment Boundary Asymmetry Between Flows (P3) | `PaymentGatedTransfer` overpayment vs `AtomicSwap` exact. |
| | A4 VaultTimelockRelease at the Threshold (P3) | Off-by-one. |
| | A5 AtomicSwap Two-Leg Race (HTLC Griefing) (P1) | Cross-leg atomicity is wallet-side. |
| V. Privacy and Lane Boundary | L1 Cross-Lane Nullifier Collision (P2) | `RgkNullifier::derive` is lane-agnostic. |
| | L2 public_lineage Flag Inconsistent With LanePrivacyPolicy (P1) | `IndexedLane` does not store `LanePrivacyPolicy`. |
| | L3 StealthLane as Dead Variant (P3) | `StealthLane` enum variant with no derivation. |
| | L4 Lane With No scan_tag (Ghost Lane) (P3) | `RgkScanTag = None`. |
| Priority Summary | — | 20-row scenario/tag/surface/why table. |
| Relationship to Existing Coverage | — | Three-bullet context. |
| Suggested Landing Points | — | Four-bullet "where to land the tests" advice. |
| Open Questions Worth Resolving Before Implementation | — | Six open questions. |

### Cross-references (consistency-critical)

- `crates/rgk-asset/src/native.rs:575-580` (shape dispatch) (`docs/ADVERSARIAL-SCENARIOS.md:38`).
- `crates/rgk-zk/src/real_zk.rs:3858-3924` (exclusion grid) (`docs/ADVERSARIAL-SCENARIOS.md:73`).
- `crates/rgk-zk/src/real_zk.rs:3675-3681` (outpoint comparison) (`docs/ADVERSARIAL-SCENARIOS.md:78-80`).
- `crates/rgk-asset/src/native.rs:1811-1817` (burn-forces-fixed) (`docs/ADVERSARIAL-SCENARIOS.md:125`).
- `crates/rgk-resolver/src/lib.rs:185, 255-260, 344-349` (reorg depth) (`docs/ADVERSARIAL-SCENARIOS.md:251-252`).
- `crates/rgk-resolver/src/lib.rs:540-546` (indexed created outpoint vs observed spending txid) (`docs/ADVERSARIAL-SCENARIOS.md:210-212`).
- `crates/rgk-covenant/src/lib.rs:140-148, 243-247, 331-346, 459-462, 472-474, 525-537, 539-549` (advanced covenant flow code) (`docs/ADVERSARIAL-SCENARIOS.md:347, 354-356, 372-377, 393-396, 419-422`).
- `crates/rgk-resolver/src/lib.rs:43-108` (`ResolverState`) (`docs/ADVERSARIAL-SCENARIOS.md:310`).
- `crates/rgk-asset/src/native.rs:759-768` (`RgkNullifier::derive`) (`docs/ADVERSARIAL-SCENARIOS.md:448-450`).
- `crates/rgk-indexer/src/lib.rs:96, 887-931, 938-939, 1103-1108` (`IndexedLane`, `validate_indexed_lane`, `resolve_by_scan_tag`, replay keys) (`docs/ADVERSARIAL-SCENARIOS.md:172-175, 454-456, 473-475, 478-480, 511-514`).
- `tests/rgk-e2e/tests/zk_precompile_vm.rs:199, 285, 382, 502` (sample-witness builders) (`docs/ADVERSARIAL-SCENARIOS.md:556-557`).
- `examples/silverscript/advanced_covenant_policy_shapes.sil` (`docs/ADVERSARIAL-SCENARIOS.md:563`).
- `tests/rgk-e2e/tests/covenant_script_vm.rs:329-426` (merge/batch VM tests) (`docs/ADVERSARIAL-SCENARIOS.md:565`).

### Tutorial fit

`reference-shaped`. The scenarios are detailed test specifications, not
tutorial material. The wiki tutorial should link to the priority-summary
table and the open-questions list as the entry points.

### Drift risks

- The `file:line` citations are fragile: every scenario in this file
  references a specific line range in the source code. The wiki tutorial
  must either keep the citations in a side-block or accept that the
  references will go stale.
- This file pins the *current* supported shape set indirectly
  (`docs/ADVERSARIAL-SCENARIOS.md:37-38, 64, 124-126`). The same
  supported-shape set is named across six other docs; the wiki should bind
  it to a single glossary entry.

---

## 10. `docs/INTEGRATION.md`

### Header

- **Path:** `docs/INTEGRATION.md`
- **Kind:** integration how-to (wallet-side).
- **Audience:** wallet dev, integrator.

### Core thesis

Native RGK wallet integration is a sequence of typed calls into `rgk-asset` /
`rgk-zk` / `rgk-receipt` / `rgk-indexer` / `rgk-resolver`. The Issue flow
selects `LanePrivacyPolicy::PrivateLane`, commits `RgkProofPolicy`, validates
the issue, optionally validates for production ZK, and persists the lineage /
lane as identity. The Transfer flow builds a `RgkContinuationPlan` with the
full previous allocation set, optionally wraps it with
`RgkProductionZkTransferPlan::new` (or
`RgkContinuationPlan::into_production_zk_transfer_plan`), finalises through
phase 2, builds `RgkReceipt`, signs the Toccata covenant spend, indexes the
spend with continuation proof metadata, and resolves to
`NativeTransitionedValid` after the safety depth. Private-lane discovery,
proof policy, policy migration, production allocation strategy, public
testnet staging, advanced covenant flows, and failure handling are all
fail-closed.

The most load-bearing sentence:

> "This document sketches the wallet-side integration shape for native RGK."
> (`docs/INTEGRATION.md:3-4`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Issue | 7-step issue procedure with `validate_for_production_zk` gate. |
| Transfer | 10-step transfer procedure with phase-1 plan, phase-2 finalisation, receipt, sign, index, resolve. |
| Private Lane Discovery | Lane registration fields; resolver entry points; scan-by-view-key procedure. |
| Proof Policy | "Never accept a witness-selected unconstrained image id." |
| Policy Migration | `PolicyMigrationInput` / `build_policy_migration_proof` / `PolicyMigrationInput::build`; indexer `apply_spend_with_continuation_and_policy_migration`; resolver recompute. |
| Production Allocation Strategy | `RgkProductionZkTransferPlan` shape set; `RgkProductionAllocationStrategyPlan::new`; `RgkProductionAllocationStrategyRecord::new`. |
| Public Testnet Staging | `scripts/e2e-testnet-staging.sh --wallets` and `--preflight`. |
| Advanced Covenant Flows | `AdvancedCovenantPolicyShape`; `AdvancedCovenantExecutionEvidence`; `AdvancedCovenantExecutionPlan::new`; `AdvancedCovenantExecutionRecord::new`. |
| Failure Handling | "All integration failures are fail-closed." |

### Cross-references (consistency-critical)

- Validator / planner functions: `validate_for_production_zk`,
  `RgkProductionZkTransferPlan::new`,
  `RgkContinuationPlan::into_production_zk_transfer_plan`,
  `RgkProductionZkTransferPlan::finalize`,
  `RgkProductionAllocationStrategyPlan::new`,
  `RgkProductionAllocationStrategyRecord::new(plan.clone())` and
  `record.canonical_bytes()?` (`docs/INTEGRATION.md:12-13, 25-32, 94, 97-111`).
- Resolver entry points: `resolve_lane`, `resolve_by_view_key`,
  `resolve_by_scan_tag`, `resolve_public_lineage`, `resolve_transition`
  (`docs/INTEGRATION.md:48-52`).
- Migration API: `PolicyMigrationInput`, `build_policy_migration_proof`,
  `PolicyMigrationInput::build`,
  `apply_spend_with_continuation_and_policy_migration` (`docs/INTEGRATION.md:74-83`).
- Scripts: `scripts/e2e-testnet-staging.sh --wallets`,
  `scripts/e2e-testnet-staging.sh --preflight`,
  `scripts/verify-testnet-staging-wallets.sh`,
  `scripts/verify-testnet-staging-preflight.sh` (`docs/INTEGRATION.md:118-128`).
- Advanced-covenant types: `AdvancedCovenantPolicyShape`,
  `AdvancedCovenantExecutionEvidence`, `AdvancedCovenantExecutionPlan`,
  `AdvancedCovenantExecutionRecord` (`docs/INTEGRATION.md:140-154`).

### Tutorial fit

`tutorial-shaped`. This is the most tutorial-ready integration doc in the
corpus. The "Issue" and "Transfer" sections are numbered, procedural, and can
become a wiki "Tutorial-2: integrate a wallet" page with minimal adaptation.

### Drift risks

- `docs/INTEGRATION.md:93-94` says the production-ZK shape set is
  `1x0, 1x1, 2x2, 3x2, 4x2, 4x4`. Same list as five other docs; must be
  cross-linked from a glossary entry.
- `docs/INTEGRATION.md:155` says "Public staging remains a separate evidence
  step." This is consistent with `MAINNET-LAUNCH.md:48-55` and
  `TESTNET-STAGING-REPORT.md:108-113`, but the wiki tutorial should not let
  the reader infer that public staging is implemented.

---

## 11. `docs/E2E.md`

### Header

- **Path:** `docs/E2E.md`
- **Kind:** runbook.
- **Audience:** operator, wallet dev, auditor (anybody running the e2e
  harness).

### Core thesis

The e2e harness exercises native RGK asset state, receipts, covenants,
indexing, and resolver classification against a fixture backend or a live
Toccata node. The local flow is `setup-external.sh` -> `build-kaspa.sh` ->
`run-kaspa-local.sh --background` -> `e2e-local.sh --live`; the devnet
flow is `e2e-devnet.sh --start-kaspa`; the public testnet staging flow is
`e2e-testnet-staging.sh --wallets / --preflight / --funding-readiness / run`.
The fixture library test executes eight steps; the live test executes ten.
The policy-migration recovery fixture proves local restart recovery by
flushing and reopening `SledIndexer` and re-resolving the recovered spend.
Public testnet / mainnet staging is "still not proven."

The most load-bearing sentence:

> "The e2e harness exercises native RGK asset state, receipts, covenants,
> indexing, and resolver classification against a fixture backend or a live
> Toccata node." (`docs/E2E.md:3-5`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Prerequisites | Rust toolchain, Git, C toolchain for `rusty-kaspa`. |
| Step 1 - Clone Kaspa Toccata | `setup-external.sh`; structural `TX_VERSION_TOCCATA` assertion. |
| Step 2 - Build Kaspad | `build-kaspa.sh`. |
| Step 3 - Run Local Simnet | `run-kaspa-local.sh --background` and `e2e-local.sh --live`; fixture mode. |
| Local Internal Readiness Evidence | `e2e-internal-readiness.sh` and verifier. |
| Local Devnet Evidence | `e2e-devnet.sh --start-kaspa`; required devnet report lines. |
| Local Protocol Gate | Non-public-network protocol checks. |
| Public Testnet Staging | Wallet generation, address print, funding help, preflight, funding-readiness, full lifecycle. |
| Fixture Flow | 8-step fixture procedure. |
| Live Covenant Flow | 10-step live test procedure. |
| Policy Migration Recovery Fixture | `policy_migration_recovery_fixture_survives_reopen`. |
| Output Shape | Sample fixture summary block. |
| Not Yet Proven | 4-item "not yet" list. |

### Cross-references (consistency-critical)

- Toccata version assertion: `kaspa_consensus_core::constants::TX_VERSION_TOCCATA` (`docs/E2E.md:24-26`).
- Scripts: `./scripts/setup-external.sh`, `./scripts/build-kaspa.sh`, `./scripts/run-kaspa-local.sh`, `./scripts/e2e-local.sh`, `./scripts/e2e-devnet.sh`, `./scripts/e2e-internal-readiness.sh`, `./scripts/verify-internal-readiness-evidence.sh`, `./scripts/verify-devnet-evidence.sh`, `./scripts/e2e-testnet-staging.sh`, `./scripts/verify-testnet-staging-evidence.sh`, `./scripts/verify-testnet-funding-readiness.sh`, `./scripts/verify-launch-readiness.sh` (all of `docs/E2E.md:16-216`).
- Env vars: `RGK_LIVE_KASPA_URL`, `RGK_LIVE_KASPA_NETWORK`, `RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE`, `RGK_LIVE_KASPA_GAS` (`docs/E2E.md:177-178, 193-195, 204-209`).
- Output paths: `target/rgk-internal-readiness/latest.txt`, `target/rgk-devnet-evidence/latest.txt`, `target/rgk-testnet-staging-evidence/latest.txt` (`docs/E2E.md:53, 73, 197`).
- ZK paths: `OpZkPrecompile`, `real-zk` feature, `live-kaspa-wrpc`, `persistent-indexer` (`docs/E2E.md:23-26, 93-99, 168-170, 254-265`).
- Required report line: `live: Toccata tx subnetwork=... gas=... mode=...` (`docs/E2E.md:209-210`).
- Test names: `policy_migration_recovery_fixture_survives_reopen`, `run_e2e_fixture` (referenced via `ADVERSARIAL-SCENARIOS.md:578`).

### Tutorial fit

`tutorial-shaped`. The "Step 1 -> Step 2 -> Step 3" structure and the
required-report-fields list are excellent tutorial material. The "Public
Testnet Staging" subsection is the best single-page onboarding for a new
operator.

### Drift risks

- The "Not Yet Proven" list at `docs/E2E.md:298-310` is now 4-6 months old in
  the timeline suggested by the file's date-of-other-evidence (the
  testnet-staging script and verifier described in the file are the
  current ones, but the launch-readiness strict mode is still gated on a
  funded public run per `MAINNET-LAUNCH.md:114-117`). The wiki tutorial
  should mark this section as "check the launch-readiness audit for current
  status."

---

## 12. `docs/MAINNET-LAUNCH.md`

### Header

- **Path:** `docs/MAINNET-LAUNCH.md`
- **Kind:** launch checklist.
- **Audience:** operator, governance, auditor.

### Core thesis

RGK is research code until all the listed evidence gates pass. The required
evidence list, the required devnet report fields, the `--allow-blocked`
relaxed-mode rules, and the "Do Not Claim" list together form a launch-gate
contract. The launch audit's strict mode remains non-zero until
`public_testnet_funded_report=ok`; `--allow-blocked` may pass only when
`funding_readiness=blocked` and the preflight and funding-readiness reports
match.

The most load-bearing sentence:

> "RGK is research code until these gates are complete." (`docs/MAINNET-LAUNCH.md:3-4`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Required Evidence | 16-bullet gate list. |
| Required Devnet Fields | 25-bullet field list. |
| Current Machine Check | "Use this before public funding is available" vs "Use strict mode for the launch gate" commands. |
| Do Not Claim | 5-bullet claim boundary. |

### Cross-references (consistency-critical)

- 16 required-evidence bullets at `docs/MAINNET-LAUNCH.md:7-55` (includes
  `scripts/e2e-internal-readiness.sh`, `scripts/verify-internal-readiness-evidence.sh`,
  `scripts/verify-devnet-evidence.sh`, `scripts/verify-launch-readiness.sh --allow-blocked`,
  `scripts/verify-example-matrix.sh`, `scripts/verify-silverscript-artifacts.sh`,
  `scripts/e2e-testnet-staging.sh`, `scripts/verify-testnet-staging-wallets.sh`,
  `scripts/verify-testnet-staging-preflight.sh`,
  `scripts/verify-testnet-staging-evidence.sh`,
  `scripts/verify-testnet-funding-readiness.sh`).
- 25 required-devnet-field bullets at `docs/MAINNET-LAUNCH.md:59-96`.
- `verify-launch-readiness.sh --allow-blocked` semantics at `docs/MAINNET-LAUNCH.md:113-117`.
- `public_testnet_funded_report=ok` claim boundary at `docs/MAINNET-LAUNCH.md:117`.

### Tutorial fit

`reference-shaped`. The launch-checklist is governance material; it should
be a wiki Reference page.

### Drift risks

- `docs/MAINNET-LAUNCH.md:36-42` requires the preflight manifest to bind
  `KaspaTestnet` chain id, `live-kaspa-wrpc`/`real-zk`/`persistent-indexer`
  feature set, and `required_local_mining=false`. The `TESTNET-STAGING-REPORT.md:96-105`
  pin is `testnet-12`. If the staging target moves to `testnet-10`, the
  `--allow-blocked` rule at `docs/MAINNET-LAUNCH.md:114-117` requires
  regenerating both `--wallets` and `--preflight` (also called out in
  `docs/TESTNET-STAGING-REPORT.md:160-163`). The wiki tutorial must teach
  this gotcha.
- The `RGK_PRODUCTION_*` constant family referenced historically (per
  `audits/public-api-surface.md:644-653`) was renamed to
  `RGK_ALLOCATION_STRATEGY_*`. `MAINNET-LAUNCH.md` does not mention the
  constant directly, but tutorial writers should be aware that any
  `scripts/` reference to the old name will not match current code.

---

## 13. `docs/TESTNET-STAGING-REPORT.md`

### Header

- **Path:** `docs/TESTNET-STAGING-REPORT.md`
- **Kind:** frozen snapshot (deterministic testnet wallet set + preflight).
- **Audience:** operator, auditor.

### Core thesis

The deterministic public testnet staging wallet set and preflight contract
are pinned to `testnet-12` with a specific `wallet_set_id`,
`preflight_id`, and three roles (`funding`, `change`, `observer`); the
funding address is the only role that needs public testnet funds, and the
frozen snapshot must not be used for mainnet funds. The funding-readiness
report is read-only and must match the preflight network, wallet-set id, and
funding address before the launch audit will accept it.

The most load-bearing sentence:

> "It is testnet-only material. It must not be used for mainnet funds."
> (`docs/TESTNET-STAGING-REPORT.md:6-7`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Wallet Set | 3-role deterministic wallet set snapshot. |
| funding | Address, xonly, secret_fingerprint, required_min_value_real_zk, required_min_value_verifier_only, purpose. |
| change | Address, xonly, secret_fingerprint, "reserved-change-output-isolation". |
| observer | Address, xonly, secret_fingerprint, "observer-reporting-no-funding". |
| Preflight | `testnet-12` preflight manifest (network, chain_id, address, wallet_set_id, funding_status, requirements, preflight_id). |
| Current Status | Wallet set + preflight are machine-verified locally; funded public run is separate. |
| Funding Readiness | Funding instructions, network-mixing warning, gating rules. |

### Cross-references (consistency-critical)

- Network: `testnet-12`, chain id `KaspaTestnet` (`docs/TESTNET-STAGING-REPORT.md:25-26, 84-85`).
- `wallet_set_id=0x319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352` (`docs/TESTNET-STAGING-REPORT.md:27`).
- `preflight_id=0x2c993d20f2726efdb0983868126544163e44c474f4b4ab4cf28901e749c29212` (`docs/TESTNET-STAGING-REPORT.md:105`).
- Funding address: `kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald` (`docs/TESTNET-STAGING-REPORT.md:34`).
- `required_min_value_real_zk=45000000`, `required_min_value_verifier_only=9000000` (sompi) (`docs/TESTNET-STAGING-REPORT.md:37-38`).
- `endpoint_env=RGK_LIVE_KASPA_URL`, `network_env=RGK_LIVE_KASPA_NETWORK` (`docs/TESTNET-STAGING-REPORT.md:100-101`).
- Verifier reject rule: "no `secret_key`, `private_key`, or `privkey` field" (`docs/TESTNET-STAGING-REPORT.md:64-65`).

### Tutorial fit

`reference-shaped`. The frozen snapshot is governance material; the wiki
should publish it as-is on a Reference page and link to it from the
public-staging tutorial.

### Drift risks

- `testnet-12` is hard-coded in three places (`docs/TESTNET-STAGING-REPORT.md:25, 84`;
  the funding-help default in `E2E.md:161`; and the launch-audit gate in
  `MAINNET-LAUNCH.md:39-42`). The wiki tutorial must teach the "do not mix
  testnet-10 and testnet-12 reports" rule (`docs/TESTNET-STAGING-REPORT.md:160-163`).
- The xonly / secret_fingerprint / address values in the snapshot are
  pinned. If a future commit regenerates the wallet set, this file becomes
  the diff that breaks. The wiki should make it clear that the snapshot is
  load-bearing for the current launch audit and is meant to be stable
  across local regenerations.

---

## 14. `docs/AVATO-WALLETD.md`

### Header

- **Path:** `docs/AVATO-WALLETD.md`
- **Kind:** daemon how-to (Avato frontend boundary).
- **Audience:** frontend dev, integrator, operator.

### Core thesis

`rgk-walletd` is the local HTTP boundary that the Avato frontend talks to;
it is non-custodial, owns local profile state, health checks, lock/unlock,
and (forward) handoff to scanner/resolver/prover services. The Avato contract
exposes `GET /health`, `GET /wallet/profile`, `POST /wallets`,
`POST /wallet/import`, `POST /wallet/lock`, `POST /wallet/unlock`,
`POST /wallet/kaspa-endpoint`, `POST /wallet/sync`, `GET /dashboard`,
`POST /lanes`, `POST /proofs`, `POST /transitions`. The daemon is strict
about frontend-supplied fields (no stale clients smuggling obsolete state),
normalises user-controlled strings, refuses to accept a frontend-selected
chain domain that differs from its configured `--network`, and persists only
public profile metadata to disk (recovery phrases, passphrases, private keys
never appear in the JSON state file). The verifier script
`scripts/verify-avato-walletd-contract.sh` runs the full contract.

The most load-bearing sentence:

> "`rgk-walletd` is the local HTTP boundary used by Avato's RGK frontend. It
> is a non-custodial local daemon: the browser talks to this process, and
> this process owns local profile state, health checks, lock/unlock state, and
> the future handoff to scanner/resolver/prover services."
> (`docs/AVATO-WALLETD.md:3-7`)

### Section map

| H2 | 1-line description |
| --- | --- |
| (intro) | Avato frontend local launch path. |
| (CLI launch) | `cargo run -p rgk-walletd -- --listen 127.0.0.1:8788 --network local-toccata --state target/rgk-walletd/state.json`. |
| (frontend launch) | `VITE_RGK_API_BASE_URL=http://127.0.0.1:8788 pnpm dev:rgk`. |
| (HTTP contract) | 11-endpoint list. |
| (chain-domain rule) | "must not be treated as interchangeable display labels." |
| (request validation) | Strict unknown-field rejection; user-string normalisation. |
| (wallet identity / vault) | Argon2id + XChaCha20-Poly1305; `WalletProfile.address`. |
| (lock/unlock cycle) | `ready` is in-memory; restart -> `locked` with `identityVaultStatus=encrypted`. |
| `POST /lanes` | Two modes: metadata-only (`unknown`) vs full-evidence bundle. |
| `POST /proofs` | Manual staging as `pending`; `verified` after receipt verification. |
| `POST /transitions` | Wallet-built receipt path. |
| `POST /wallet/kaspa-endpoint` | Endpoint update. |
| `POST /wallet/sync` | Restart-safe `rgk-sync` tick; re-resolves dashboard lanes. |
| (verifier) | `bash scripts/verify-avato-walletd-contract.sh`. |

### Cross-references (consistency-critical)

- Env vars: `AVATO_RGK_REPO`, `RGK_WALLETD_LISTEN`, `RGK_WALLETD_NETWORK`,
  `RGK_WALLETD_STATE`, `RGK_SYNC_DB` (`docs/AVATO-WALLETD.md:17-20`).
- CLI flags: `--listen`, `--network`, `--state` (`docs/AVATO-WALLETD.md:26-29`).
- Frontend env: `VITE_RGK_API_BASE_URL` (`docs/AVATO-WALLETD.md:34`).
- Network prefixes: `kaspa:`, `kaspatest:`, `kaspadev:`, `kaspasim:` (`docs/AVATO-WALLETD.md:81-83`).
- Chain domains: `kaspa-local-toccata`, `kaspa-testnet`, `kaspa-mainnet` (`docs/AVATO-WALLETD.md:54-55`).
- Contract file path: `../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json` (`docs/AVATO-WALLETD.md:148`).
- Verifier script: `scripts/verify-avato-walletd-contract.sh` (`docs/AVATO-WALLETD.md:144`).
- `xchaCha20-Poly1305`, `argon2id` (`docs/AVATO-WALLETD.md:67-68`).
- `rgk-sync` restart-safe scanner (`docs/AVATO-WALLETD.md:128-130`).

### Tutorial fit

`tutorial-shaped`. The 11-endpoint list and the request-validation
paragraphs can become a "Tutorial-4: operate rgk-walletd against the Avato
frontend" wiki page directly.

### Drift risks

- `docs/AVATO-WALLETD.md:31` hard-codes the frontend checkout path
  `/Users/arthur/RustroverProjects/avato-wallet-frontend`. This is a
  developer-local path and must be replaced with a tutorial-time path or
  the `AVATO_RGK_REPO` env-var override in the wiki.
- `docs/AVATO-WALLETD.md:74-75` says "lanes and receipt evidence appear only
  after explicit wallet actions or future scanner/resolver/prover
  integration" — i.e. the integration is partial. The wiki tutorial must
  not advertise `walletd` as production-ready.

---

## 15. `docs/UNSAFE-AUDIT.md`

### Header

- **Path:** `docs/UNSAFE-AUDIT.md`
- **Kind:** audit notes (dated 2026-07-02).
- **Audience:** auditor, security reviewer.

### Core thesis

All production crates use `#![forbid(unsafe_code)]`; a `rg` scan of
`crates/` and `tests/` finds no Rust `unsafe` code (one prose-only hit in a
resolver doc comment); 94 normal dependencies are in the workspace feature
set; the bounded `cargo-geiger --forbid-only` check confirms the first-party
source is unsafe-forbidden but cannot certify the third-party dependency
surface; the audit therefore treats RGK first-party source as
unsafe-forbidden and third-party unsafe exposure as accepted external risk.

The most load-bearing sentence:

> "All production crates use `#![forbid(unsafe_code)]`." (`docs/UNSAFE-AUDIT.md:7`)

### Section map

| H2 | 1-line description |
| --- | --- |
| (heading) | "Unsafe audit notes" + date. |
| Workspace policy | `#![forbid(unsafe_code)]` + scan commands. |
| Dependency inventory | `cargo tree --workspace -e normal --prefix none | sort -u | wc -l` = 94. |
| Dependency unsafe scan | `cargo-geiger v0.13.0`; `rgk-core` marked `:)`, dependencies marked `?`. |
| Follow-up | First-party unsafe-forbidden; third-party accepted as external risk. |

### Cross-references (consistency-critical)

- `#![forbid(unsafe_code)]` (`docs/UNSAFE-AUDIT.md:7`).
- Scan command: `rg -n "\\bunsafe\\b" crates tests --glob '*.rs'` (`docs/UNSAFE-AUDIT.md:9`).
- Dependency count: `94` (`docs/UNSAFE-AUDIT.md:15`).
- `cargo-geiger v0.13.0`, `cargo geiger --all-features --output-format Ratio`,
  `cargo geiger --forbid-only --all-features` (`docs/UNSAFE-AUDIT.md:19-30`).

### Tutorial fit

`reference-shaped`. Audit notes; wiki should publish verbatim.

### Drift risks

- The `94 normal dependency entries` count will drift; the
  `cargo-geiger --all-features` fallback note at
  `docs/UNSAFE-AUDIT.md:22-30` is a fragile observation that depends on
  upstream `cargo-geiger` behaviour. The wiki should cite the doc-page
  timestamp and not the number.

---

## 16. `docs/VERIFICATION-BUDGET.md`

### Header

- **Path:** `docs/VERIFICATION-BUDGET.md`
- **Kind:** verification cost budget.
- **Audience:** auditor, wallet dev (people who need to know the
  bounded-checked objects).

### Core thesis

RGK validation must stay bounded and fail-closed: every wire object is
32-byte (or canonical `MAX_BLOB_BYTES`); unknown versions / chain ids /
malformed payloads / missing transition digests / missing replay nonces /
no-op transitions / supply mismatches / spent covenant-output reuse /
unconstrained image ids / replays are all rejected; the resolver only
classifies after bounded local checks.

The most load-bearing sentence:

> "RGK validation must stay bounded and fail-closed." (`docs/VERIFICATION-BUDGET.md:3`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Bounded Objects | 10-row bound table (`asset_id`, `state_digest`, `transition_digest`, `lane_id`, `scan_tag`, `nullifier`, `policy commitment`, receipt body, covenant payload, all 32 bytes or `MAX_BLOB_BYTES`). |
| Fail-Closed Rules | 10-bullet rule list. |
| Resolver Budget | 5-step bounded local checks before classification. |

### Cross-references (consistency-critical)

- Bounded objects: `asset_id` label, schema id, state digest, transition
  digest, lane id, scan tag, nullifier, policy commitment (all 32 bytes);
  receipt body and covenant payload (canonical `MAX_BLOB_BYTES`)
  (`docs/VERIFICATION-BUDGET.md:7-18`).
- `MAX_BLOB_BYTES` constant (referenced as a native bound) (`docs/VERIFICATION-BUDGET.md:17-18`).
- Resolver states referenced: `Unknown`, `Unconfirmed`, `ReorgRisk`,
  `NodeDown` (`docs/VERIFICATION-BUDGET.md:43-45`).

### Tutorial fit

`reference-shaped`. The 32-byte invariants and the fail-closed rules are
the tutorial's most important "always do this" list. The wiki can lift the
table directly into a "Concepts / Bounded Objects" page.

### Drift risks

- The bounds table is a contract: any change to the byte sizes of these
  fields is a consensus-level change. The wiki tutorial must teach the
  reader that `32` is not arbitrary.

---

## 17. `docs/API-DEPRECATION.md`

### Header

- **Path:** `docs/API-DEPRECATION.md`
- **Kind:** policy.
- **Audience:** wallet dev, integrator, library author.

### Core thesis

During pre-release, misleading or unsafe public APIs may be removed or
renamed directly when keeping an alias would preserve the wrong semantics.
After the first compatibility-tagged release, public API changes follow a
`#[deprecated(note = "...")]` policy with at least one compatibility release
of overlap and a pointer to the replacement / migration document / audit
finding. Consensus encodings, covenant validation semantics, and
security-sensitive constructors never keep a deprecated alias when the alias
would make an invalid state easier to construct. The public audit at
`docs/audits/public-api-surface.md` tracks deliberate exceptions.

The most load-bearing sentence:

> "During the pre-release phase, misleading or unsafe public APIs may be
> removed or renamed directly when keeping an alias would preserve the wrong
> semantics." (`docs/API-DEPRECATION.md:3-6`)

### Section map

| H2 | 1-line description |
| --- | --- |
| (intro / policy) | Pre-release vs compatibility-tagged policy. |
| (4 numbered items) | The deprecation policy in 4 steps. |
| (audit reference) | `docs/audits/public-api-surface.md` tracks exceptions. |

### Cross-references (consistency-critical)

- `#[deprecated(note = "...")]` attribute convention (`docs/API-DEPRECATION.md:11`).
- Audit reference: `docs/audits/public-api-surface.md` (`docs/API-DEPRECATION.md:19`).

### Tutorial fit

`reference-shaped`. Wiki tutorial should link to this as "API stability
policy" and stop.

### Drift risks

- None detected. The cross-reference to `audits/public-api-surface.md` is
  intact.

---

## 18. `docs/ROADMAP.md`

### Header

- **Path:** `docs/ROADMAP.md`
- **Kind:** milestone tracker.
- **Audience:** governance, integrator, anyone tracking "is X ready?"

### Core thesis

The roadmap tracks RGK as a Kaspa-native covenant-lineage asset system, and
matching external wallets or validators byte-for-byte is explicitly **not** a
milestone. The current revision is captured in a single "Current Revision"
status table; the document walks through M0 (Native Grammar Baseline), M1
(Private Lanes), M2 (Native Resolver), M3 (Two-Phase Continuation Output),
M4 (Semantic ZK Receipt), and M5 (Lane Policy Examples and Public Staging).
The "Removed Track" section declares that the previous external-matching
track has been removed.

The most load-bearing sentence:

> "The roadmap now tracks RGK as a Kaspa-native covenant-lineage asset
> system. Matching external wallets or validators byte-for-byte is not a
> milestone." (`docs/ROADMAP.md:3-5`)

### Section map

| H2 | 1-line description |
| --- | --- |
| Vocabulary Boundary | 7 protocol principles + 14 RGK-native word list. |
| Current Revision | 19-row "Area / Status" table. |
| M0 - Native Grammar Baseline | Acceptance: positive supply, no-op rejected, supply conservation, lineage identity. |
| M1 - Private Lanes | Acceptance: default `PrivateLane`, opt-in `PublicLineage`, blinded lane id, bounded Groth16 lane discovery, segmented lane-graph proof chains. |
| M2 - Native Resolver | Acceptance: replay rejection, lane-native entry points, `CompetingBranch`, `PolicyMigrationRequired`, `PolicyMigrationInput::build` in `rgk-core`. |
| M3 - Two-Phase Continuation Output | Acceptance: phase-1 commitment without future txid, phase-2 finalisation, resolver txid-binding enforcement. |
| M4 - Semantic ZK Receipt | Long acceptance list covering 1x0 / 1x1 / 2x2 / 3x2 / 4x2 / 4x4 fixed-shape proofs, segmented audit bundles / certificates, `RgkProductionAllocationStrategyPlan` / `Record`, and the explicit "OPEN" for single-proof arbitrary-size conservation. |
| M5 - Lane Policy Examples And Public Staging | Lane policy example coverage targets + 12-bullet acceptance list; "PARTIAL: … public testnet evidence remains open"; "OPEN: external frontend equivalence". |
| Removed Track | External wallet vectors / validator matching / byte-identical digest matching removed. |

### Cross-references (consistency-critical)

- Vocabulary list: 14 RGK-native terms (`docs/ROADMAP.md:19-23`).
- 19-row Current Revision table (`docs/ROADMAP.md:30-49`).
- M0-M5 status markers (`docs/ROADMAP.md:52, 71, 98, 131, 153, 328`).
- M4 fixed-shape set: `1x0, 1x1, 2x2, 3x2, 4x2, 4x4` (`docs/ROADMAP.md:218-219, 291-292`).
- "Removed Track" content (`docs/ROADMAP.md:459-462`).
- Public staging / devnet evidence scripts referenced repeatedly
  (`docs/ROADMAP.md:356-364`).

### Tutorial fit

`reference-shaped`. The roadmap is governance material; the wiki should
publish it as a "Roadmap / Status" page and link from each tutorial.

### Drift risks

- `docs/ROADMAP.md:46` says "broad coverage remains open" for the
  examples-matrix. This is consistent with the "PARTIAL" marker at
  `docs/ROADMAP.md:452-453`, but a reader skimming the Current Revision
  table could miss the qualifier.
- `docs/ROADMAP.md:188-189` uses "1x1 and 2x2 allocation-vector circuits"
  (older phrasing) while `docs/ROADMAP.md:218-219, 291-292` uses the current
  "1x0, 1x1, 2x2, 3x2, 4x2, 4x4" set. The earlier phrasing should be
  considered stale, but is not contradictory — the 1x0 burn is a separate
  addition.

---

## 19. `docs/audits/public-api-surface.md`

### Header

- **Path:** `docs/audits/public-api-surface.md`
- **Kind:** static public-API audit.
- **Audience:** library author, auditor, reviewer tracking the
  `pub`-surface hygiene.

### Core thesis

The audit walks every public item in every `rgk` crate and nine
cross-cutting dimensions, produces 40 findings (`F-01`..`F-40`) with
severity tags, and tracks a remediation pass. The single biggest finding is
the `rgk-asset` "god module" (`crates/rgk-asset/src/native.rs`, 5237 lines,
338 pub items); the largest block of fixed items resolves type-alias
triplication (`Hex32`, `RgkAssetId`, `RgkSchemaId`), feature-gate hygiene,
error-typed seams, and the rename of the public `RGK_PRODUCTION_*`
constants to the neutral `RGK_ALLOCATION_STRATEGY_*` family. Appendices
list items not flagged, recommended refactor order, and the `rg` queries
used.

The most load-bearing sentence:

> "The single biggest source file by far is `crates/rgk-asset/src/native.rs`
> (**5237 lines, 338 pub items**); every other crate is single-file at
> lib.rs. That is the audit's #1 finding, see F-01."
> (`docs/audits/public-api-surface.md:36-38`)

### Section map

| H2 | 1-line description |
| --- | --- |
| (intro) | Scope, method, severity legend, headline numbers. |
| Remediation status | Per-finding "Fixed" / "Accepted" markers. |
| Findings index | 40-row F-01..F-40 table. |
| F-01..F-40 (44 sub-headings) | Per-finding write-up. |
| Appendix A | Items not flagged but worth tracking. |
| Appendix B | Recommended refactor order. |
| Appendix C | Audit-time `rg` queries used. |

### Cross-references (consistency-critical)

- 40 finding IDs `F-01`..`F-40` (`docs/audits/public-api-surface.md:86-100, 130-1726`).
- Crate / lib.rs line counts: `rgk-core:65`, `rgk-asset:90`, `rgk-receipt:684`,
  `rgk-covenant:2154`, `rgk-tx:1709`, `rgk-zk:1167`, `rgk-kaspa:667`,
  `rgk-indexer:3078`, `rgk-resolver:1516`, `rgk-sync:568`, `tests/rgk-e2e:—`
  (`docs/audits/public-api-surface.md:22-35`).
- `rgk-asset/src/native.rs:5237` lines, `338` pub items (`docs/audits/public-api-surface.md:36-38`).
- `RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS: &str = "1x0, 1x1, 2x2, 3x2, 4x2, 4x4"` (`docs/audits/public-api-surface.md:653`).
- Remediation list (resolved F-IDs) at `docs/audits/public-api-surface.md:40-79`.
- Findings severity legend: Blocker / High / Medium / Low (`docs/audits/public-api-surface.md:12-19`).

### Tutorial fit

`reference-shaped`. Wiki tutorial should not retell the audit; instead it
should link to a "Reference / API surface audit" page that publishes the
40-row findings index.

### Drift risks

- The findings list is a point-in-time snapshot. The "Fixed" markers at
  `docs/audits/public-api-surface.md:40-79` may drift if subsequent
  remediation un-fixes something; the wiki tutorial should treat the audit
  as "the audit at <date>," not "current API contract."
- The "11-crate" headline table at `docs/audits/public-api-surface.md:22-35`
  predates `rgk-walletd` (which appears in `Cargo.toml:14` and
  `README.md:194` but is not in the audit table). The audit was scoped to
  the original 11 crates; the wiki tutorial should not interpret the audit
  as covering `rgk-walletd`.

---

## Additional analysis

### `docs/` -> wiki page map

This table maps every existing `docs/` file to a recommended wiki target.
Pages are: `Home`, `Tutorial-N` (numbered walkthroughs), `Concepts`
(identity / privacy / continuation), `Reference` (specs, threat model,
budgets, governance), `Runbook` (operator-facing), and `Glossary`.

| Source doc | Target wiki page(s) | Why |
| --- | --- | --- |
| `docs/INTRODUCTION.md` | `Home`, `Tutorial-1: What is RGK?` | Already a tutorial-shaped intro with TL;DR, comparison to RGB, and step-by-step transfer. |
| `docs/ARCHITECTURE.md` | `Concepts / Architecture`, `Reference / Resolver State Machine` | Crate map + resolver enum are reference-grade; "Transition Flow" is tutorial-adjacent. |
| `docs/COVENANT-SPEC.md` | `Reference / Covenant Spec`, `Concepts / Lineage vs Label` | `CovenantState` struct + payload layout are reference. |
| `docs/RECEIPT-SPEC.md` | `Reference / Receipt Spec`, `Tutorial-2: receipts` | Tiny spec; the 9-bullet invariants can be a tutorial checklist. |
| `docs/LANE-CALCULUS.md` | `Concepts / Lane Calculus`, `Glossary / Hot-Path Types` | Authoritative list of native types and lane-privacy variants. |
| `docs/SECURITY.md` | `Reference / Threat Model`, `Concepts / What RGK Proves` | 12-item "proves" list and 17-row threat table are reference. |
| `docs/ZK-BOUNDARY.md` | `Reference / ZK Boundary`, `Concepts / Statement Sizes` | Public-input byte/field counts are reference. |
| `docs/ZK-PROOF-PLAN.md` | `Reference / ZK Proof Plan`, `Reference / Cost & Governance` | Cost table, planning tracks, decision rule. |
| `docs/ADVERSARIAL-SCENARIOS.md` | `Reference / Adversarial Scenarios`, `Glossary / Scenario IDs` | Scenario IDs and `file:line` references are governance-grade. |
| `docs/INTEGRATION.md` | `Tutorial-2: integrate a wallet` | Numbered Issue / Transfer / Discovery / Migration procedure. |
| `docs/E2E.md` | `Tutorial-3: run the e2e harness`, `Runbook / E2E` | Step-1 / Step-2 / Step-3 structure and required-report-fields list. |
| `docs/MAINNET-LAUNCH.md` | `Runbook / Launch Gates` | 16-bullet gate list and "Do Not Claim" list. |
| `docs/TESTNET-STAGING-REPORT.md` | `Reference / Testnet Staging Snapshot`, `Runbook / Funding` | Frozen wallet set + preflight. |
| `docs/AVATO-WALLETD.md` | `Tutorial-4: operate rgk-walletd` | 11-endpoint list, daemon launch procedure, verifier script. |
| `docs/UNSAFE-AUDIT.md` | `Reference / Unsafe Audit` | Dated audit notes; publish verbatim. |
| `docs/VERIFICATION-BUDGET.md` | `Concepts / Bounded Objects`, `Glossary / 32-byte Invariants` | 32-byte and `MAX_BLOB_BYTES` bounds. |
| `docs/API-DEPRECATION.md` | `Reference / API Stability Policy` | Pre-release vs compat-tagged deprecation rules. |
| `docs/ROADMAP.md` | `Reference / Roadmap`, `Reference / Status` | M0..M5 milestone tracker. |
| `docs/audits/public-api-surface.md` | `Reference / API Surface Audit` | 40-finding index. |

### Gaps

These are topics that the wiki tutorial series should cover but for which
no current `docs/` file is dedicated.

1. **A first-time reader walkthrough.** `INTRODUCTION.md` is the closest, but
   it is 635 lines and does not give a new reader a 10-minute "try the
   fixture harness" experience. The wiki needs `Tutorial-0: 10-minute
   fixture walkthrough` that links directly to the harness commands and
   shows the expected fixture output shape (which is documented in
   `E2E.md:282-296`).
2. **A "Concepts / Continuation" page** that explains the two-phase model
   without the breadth of `LANE-CALCULUS.md`. The current "Why Two Phases"
   sub-section in `INTRODUCTION.md:492-539` is a good seed.
3. **A "Concepts / Identity" page** that draws together
   `lineage_id = H("rgk:lineage" || genesis_outpoint_payload || asset_id)`,
   the `asset_id` vs lineage distinction, the
   `RgkAssetId` / `RgkSchemaId` provenance from `rgk-core`, and the
   `RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS` label constant. No single doc
   tells this story today.
4. **A "Concepts / Resolver" page** that turns the 10-state enum from
   `ARCHITECTURE.md:96-107` and the state diagram from
   `INTRODUCTION.md:548-570` into a tutorial-style explanation with
   worked examples for each transition between states.
5. **A "Concepts / Privacy" page** that explains the difference between
   `PublicLineage`, `PrivateLane`, and `StealthLane` for a wallet dev (the
   "StealthLane as Dead Variant" caveat at
   `ADVERSARIAL-SCENARIOS.md:492-504` should be carried into the tutorial,
   not buried in an audit file).
6. **A "Concepts / Walletd Boundary" page** that explains what is
   in-scope and out-of-scope for `rgk-walletd` (the daemon's role today is
   narrow per `AVATO-WALLETD.md:74-75`; the wiki should not overstate its
   coverage).
7. **A "Concepts / Funding" page** that walks through the funding
   readiness flow end-to-end. The information is split across
   `TESTNET-STAGING-REPORT.md`, `E2E.md:125-216`, `INTEGRATION.md:113-134`,
   and `MAINNET-LAUNCH.md:26-55`. None of the current docs give a wallet
   operator a single happy-path.
8. **A "Concepts / Production Allocation Strategy" page** that draws
   together the `BoundedSupportedShapes` selector
   (`ZK-BOUNDARY.md:309-316`), the `RgkProductionAllocationStrategyPlan`
   (`INTEGRATION.md:96-111`), the cost table
   (`ZK-PROOF-PLAN.md:69-82`), and the "Do Not Claim" list
   (`MAINNET-LAUNCH.md:120-127`).
9. **A "Glossary" page** that defines the domain-separated commitment tags
   (`rgk:lineage`, `rgk:receipt`, `rgk:lane:graph-root:v1`,
   `rgk:asset:allocation-transcript-amount:v1`,
   `rgk:zk:allocation-audit-certificate:v1`, `rgk:aac1`,
   `rgk:policy-migration`). They are scattered across
   `COVENANT-SPEC.md`, `RECEIPT-SPEC.md`, `LANE-CALCULUS.md`, and
   `ZK-BOUNDARY.md`.

### Contradictions / staleness {#contradictions--staleness}

This is the drift register. Each item is something a tutorial writer must
either canonicalise, version-pin, or teach the reader to verify.

1. **"Supported allocation shapes" repeated in 6+ places, with subtle
   phrasing variations.** The list `1x0, 1x1, 2x2, 3x2, 4x2, 4x4` appears
   in `ARCHITECTURE.md:160-161`, `INTEGRATION.md:93-94`, `README.md:160-161`,
   `ROADMAP.md:218-219, 291-292`, `SECURITY.md:71-80`, `ZK-BOUNDARY.md:165-167, 311`,
   and the audit `public-api-surface.md:653` as a string literal. Any new
   shape must be added everywhere. The wiki should bind this list to a
   single glossary entry that the other pages cross-link.
2. **"Not Yet Proven" lists duplicated across SECURITY, ZK-BOUNDARY, ROADMAP,
   MAINNET-LAUNCH, and E2E.** The same five-ish items (public testnet,
   recursive allocation proof, post-quantum, etc.) appear in
   `SECURITY.md:67-84`, `ZK-BOUNDARY.md:350-355`, `ROADMAP.md:322-325`,
   `MAINNET-LAUNCH.md:5-55`, and `E2E.md:298-310`. The wiki tutorial should
   pick SECURITY as the canonical "what is not yet proven" page and link
   from the others.
3. **`rgk-walletd` is missing from the ARCHITECTURE and INTRODUCTION crate
   tables.** `ARCHITECTURE.md:43-54` lists 10 crates, `INTRODUCTION.md:266-274`
   lists 10, but `README.md:194` and `Cargo.toml:14` include `rgk-walletd`.
   The `public-api-surface.md:22-35` audit table is also 11-crate but
   predates `rgk-walletd` (per its "audit point" framing). The wiki
   tutorial should add `rgk-walletd` to the crate table.
4. **E2E.md's Toccata version assertion vs README's setup-external
   behaviour.** `E2E.md:22-26` says Toccata capability is asserted
   structurally via `TX_VERSION_TOCCATA` rather than by Cargo version
   suffix. `README.md:132-135` says `setup-external.sh` "only clones the
   Kaspa Toccata repository." These are consistent, but the tutorial should
   not promise a `toc` Cargo suffix anywhere.
5. **`rgb-` vs `RGK-` ticker usage in INTRODUCTION.md:486** ("friendly
   tickers (e.g. `RGK-USD`)") and the otherwise consistent lineage
   identity model. The wiki tutorial must be careful not to let the reader
   infer that `RGK-USD` is an on-chain ticker; it is a wallet-side label
   per the lineage-first identity model.
6. **STORAGE_MASS / covenant binding in `rgk-tx` is described differently
   in different docs.** `ARCHITECTURE.md:54` says `rgk-tx` covers "Borsh
   wire and hash boundary." `ROADMAP.md:40` and `E2E.md:121-122` describe a
   richer surface (storage mass, txid / tx hash / sighash projections
   against parent `rusty-kaspa`). The wiki tutorial should follow the
   richer description.
7. **"Launch readiness audit reports" semantics differ in presentation.**
   `MAINNET-LAUNCH.md:14-18, 99-117` frames `--allow-blocked` as a CI
   relax-mode; `E2E.md:212-216` frames it as the public-staging default
   until `funding_readiness=blocked` is machine-verified. The two are
   consistent, but the tutorial should teach the strict-vs-relaxed
   distinction in one place.
8. **`AUDIT-FIXED` markers in `public-api-surface.md` may un-fix.** The
   remediation list at `public-api-surface.md:40-79` is point-in-time. The
   wiki tutorial should treat each "Fixed" claim as the audit-date
   statement, not a current guarantee.
9. **ADVERSARIAL-SCENARIOS.md scenario line references are line-pinned.**
   Every scenario in that doc cites a `file:line` range. As the code moves,
   the references will go stale. The wiki tutorial should either keep the
   citations in a side-block or accept that the references are
   tutorial-time only.
10. **AVATO-WALLETD.md has a developer-local path baked in.**
    `AVATO-WALLETD.md:31` hard-codes
    `/Users/arthur/RustroverProjects/avato-wallet-frontend`. The wiki
    tutorial must replace this with a portable example or the
    `AVATO_RGK_REPO` override (`AVATO-WALLETD.md:17-18`).
11. **TESTNET-STAGING-REPORT.md is a frozen snapshot, not a config.** The
    file pins `testnet-12`, specific `wallet_set_id`, `preflight_id`,
    `xonly` and `secret_fingerprint` values
    (`TESTNET-STAGING-REPORT.md:25-105`). The wiki tutorial should
    explicitly call this out as a snapshot, not a re-run target.
12. **README "What is implemented" vs CHANGELOG.** `README.md:136-179` and
    `CHANGELOG.md:6-195` are largely consistent. The only minor drift is
    that `README.md:165-170` mentions "The examples matrix tracks the
    maintained coverage surface" without giving the
    `bash scripts/verify-example-matrix.sh` invocation (which appears in
    `README.md:168-170` and in `MAINNET-LAUNCH.md:20`). The wiki tutorial
    should give the script invocation in one place and link from the
    others.

---

## Cross-cutting risk: where tutorial writers should be most careful

For convenience, the highest-drift surfaces a tutorial writer should treat as
"versioned, cite the date":

- **Supported allocation shape set** (`1x0, 1x1, 2x2, 3x2, 4x2, 4x4`) — 6
  docs.
- **Domain-separated commitment tags** (`rgk:lineage`, `rgk:receipt`,
  `rgk:lane:graph-root:v1`, `rgk:zk:allocation-audit-certificate:v1`,
  `rgk:aac1`, `rgk:policy-migration`) — 5 docs.
- **"Not Yet Proven" lists** — 5 docs.
- **Public testnet funding address, wallet_set_id, preflight_id** — pinned in
  `TESTNET-STAGING-REPORT.md`, referenced by `E2E.md`, `INTEGRATION.md`,
  `MAINNET-LAUNCH.md`.
- **`file:line` references in `ADVERSARIAL-SCENARIOS.md`** — 60+
  references; all will drift.
- **Resolver state enum and entry points** — `ARCHITECTURE.md:96-107`,
  `INTRODUCTION.md:548-570`, `INTEGRATION.md:48-52`, `SECURITY.md:118-128`.
