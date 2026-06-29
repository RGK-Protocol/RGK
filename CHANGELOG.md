# Changelog

RGK tracks progress by engineering milestone.

## Native RGK Asset Refactor

* Reframed RGK as a Kaspa-native client-side asset protocol inspired by RGB.
* Removed the previous external-adapter track from the hot path.
* Renamed the asset grammar package to `rgk-asset`.
* Removed external RGB runtime dependencies, upstream wallet vector scripts,
  and external-vector-gated files from the default workspace.
* Replaced public core field names with native `asset_id` and
  `transition_digest` terminology.
* Added native `RgkAssetIssue`, `RgkAllocation`, `RgkTransition`,
  `RgkCovenantSeal`, `RgkStateDigest`, and `RgkTransitionDigest`.
* Added `LanePrivacyPolicy` with `PrivateLane` as the default.
* Added blinded lane ids, rotating scan tags, encrypted note commitments,
  nullifiers, policy commitments, and view-key discovery helpers.
* Added native `RgkProofPolicy` and `ImageIdPolicy`; unconstrained
  witness-selected image ids are rejected.
* Added proof-policy guardrail example coverage with a checked Silverscript
  artifact, downgrade rejection test coverage, and devnet evidence for native
  policy commitments.
* Added fungible transfer-shape example coverage for production-ZK-supported
  2x2 fanout, 3x2 merge, 4x2 merge, and 4x4 batch transfer paths.
* Added `RgkProductionAllocationStrategyPlan` as the wallet-facing selector for
  fixed allocation-vector proofs or segmented allocation-audit certificates.
  The native strategy commitment binds continuation, count, segment-grid, and
  proof-cell material, and segmented burns or empty allocation sides fail
  closed before wallets can request proof material.
* Hardened the public testnet staging preflight manifest. It now binds the
  expected `KaspaTestnet` chain id, one-confirmation live covenant test
  contract, required `live-kaspa-wrpc`/`real-zk`/`persistent-indexer` feature
  set, and `required_local_mining=false` into the preflight id and evidence
  verifiers.
* Added native metadata and owner commitments to asset issue, transition,
  continuation, state digest, transition digest, semantic ZK statement, and
  devnet evidence. Ownership handoff now requires a non-zero authorisation
  commitment, with checked `metadata_ownership_guardrails` example coverage.
* Added native owner-control descriptors for key-hash, script-hash, and
  covenant-id owners, plus owner-key rotation validation and checked
  `owner_control_policy_shapes` example coverage.
* Added native NFT policy primitives for fixed collection supply, collection
  template commitments, token ids, metadata preservation, royalty-policy hooks,
  single-token owner handoff, and terminal 1x0 NFT burn lifecycle validation,
  with checked `nft_collection_policy_shapes` example coverage.
* Added native NFT marketplace sale terms and settlement reports. The sale
  commitment binds token id, collection, seller, buyer, payment asset, price,
  royalty policy, royalty amount, and authorisation before a marketplace
  handoff can be presented as executable, with checked example and devnet
  evidence.
* Added native advanced covenant policy-shape commitments for payment-gated
  transfer, escrow release, vault timelock, atomic swap, covenant-owned asset,
  policy upgrade, and controlled termination, with fail-closed validation and
  checked `advanced_covenant_policy_shapes` example coverage.
* Added checked public-lineage opt-in example coverage. The matrix now binds
  public-lineage asset filtering and private-lane exclusion to the resolver
  test and pinned Silverscript artifact evidence.
* Added wallet-facing advanced covenant execution planning. Execution evidence
  for payment, counterparty, timelock, policy, and authorisation material is
  validated against the committed native policy shape and bound into an
  execution commitment before wallets can present the flow as executable.
* Added canonical advanced covenant execution records for wallet/resolver
  handoff. Records encode the policy shape, validated execution evidence,
  policy commitment, and execution commitment with a fixed RGK tag, then decode
  by recomputing both commitments and rejecting trailing or tampered bytes.
* Added native two-phase continuation primitives:
  `RgkContinuationPlan`, `RgkContinuationAllocationShape`,
  `RgkContinuationCommitment`, shape roots, and phase-2 finalisation into
  `RgkTransition`.
* Added receipt-level `continuation_commitment`, persisted continuation proof
  metadata in indexer spend history, and made the resolver reject missing
  continuation proof or continuation outpoints whose txid does not match the
  observed spend txid.
* Added durable local lane records to the indexer and native resolver entry
  points for lane id, view-key, scan-tag, public-lineage, and transition-digest
  lookup.
* Added explicit resolver classification for competing branches and
  receipt-policy migration requirements.
* Persisted previous/new receipt policy in spend history so resolver
  classification survives indexer restart.
* Added native policy-migration proof records, persistent encoding, and
  resolver recomputation of the `rgk:policy-migration` commitment before
  accepting explicit receipt-policy changes.
* Moved canonical policy-migration proof input and builder APIs to `rgk-core`
  so wallet code can construct proofs without depending on indexer storage.
* Added persistent e2e evidence for policy-migration recovery: the fixture
  constructs a migration proof, reopens `SledIndexer`, and resolves the
  recovered spend as `NativeTransitionedValid`.
* Added canonical `SemanticTransitionStatement` in `rgk-zk`, derived from
  validated native transition and continuation reports, with fixture receipt
  matching and live devnet statement evidence.
* Added `SemanticTransitionCircuit`, a real Groth16 circuit for the 512-byte
  semantic transition statement, plus upstream Toccata VM execution evidence.
* Added `OneInOneOutAllocationCircuit`, a real Groth16 circuit for the current
  live one-input/one-output allocation-vector transition, including native root
  reconstruction, supply equality, continuation commitment, transition digest,
  and closed-seal non-reuse checks.
* Added `TwoInTwoOutAllocationCircuit`, a fixed two-input/two-output
  allocation-vector circuit with the same native commitment reconstruction and
  upstream Toccata VM execution evidence.
* Added `FixedAllocationVectorCircuit<const SPENT, const NEW>` and
  `FixedAllocationVectorWitness<const SPENT, const NEW>`, with native
  three-input/two-output proof and upstream Toccata VM execution evidence.
* Added an explicit supported-shape registry and dispatch API for allocation
  ZK proof construction, rejecting unsupported arities before setup/proving.
* Added `ProductionAllocationProofStrategy::BoundedSupportedShapes` as the
  current production allocation-proof strategy. Wallet/prover callers now get
  an explicit fail-closed planning error for shapes outside 1x0 terminal burn,
  1x1, 2x2, 3x2, 4x2, and 4x4, and larger logical transfers must keep every
  full-state intermediate transition inside supported shapes before requesting
  ZK allocation proof material.
* Moved the production allocation-proof shape contract into native asset
  semantics with `RgkAllocationProofShape` and `validate_for_production_zk`
  entry points for issues, transitions, and continuation plans. `rgk-zk`
  delegates its supported-shape dispatch to that native policy.
* Added native authorised burn semantics with `RgkBurnProof`, explicit
  spent/new/burned supply reports, burn-bound transition and continuation
  commitments, burn-aware semantic ZK statement fields, a supported 1x1
  production allocation-vector burn proof, and a checked
  `burn_authorised_lifecycle` example matrix row.
* Added `RgkProductionZkTransferPlan` as the wallet-facing full-state planner
  for production-ZK transfers. It certifies the exact allocation proof shape
  before phase-2 txid finalisation and rejects partial previous-state spends
  before proof material is requested.
* Added self-contained allocation-audit certificate verification from canonical
  handoff bytes. Wallet/resolver/indexer consumers can now decode the bounded
  certificate, rebuild the typed manifest from public-input cells, verify every
  embedded Groth16 stack, enforce deterministic proof-cell ordering, and recover
  the native report without a separately supplied bundle object.
* Added a public testnet staging harness and report verifier. The live covenant
  lifecycle can now run with `RGK_LIVE_KASPA_NETWORK=testnet-12`, consume a
  real pre-funded non-coinbase public testnet UTXO, wait for real confirmations
  instead of mining, and produce a machine-checked staging report. The staging
  script can also print the deterministic funding address and minimum funding
  values before a public endpoint is available.
* Added a machine-checked public testnet staging preflight manifest. It binds
  the deterministic funding address, network, minimum funding values,
  non-coinbase funding requirement, UTXO-index requirement, evidence paths, and
  a native preflight id before operators fund or run public staging.
* Added a fail-closed launch readiness audit that composes devnet evidence,
  public preflight, example coverage, Silverscript artifact, and dependency
  absence checks, then reports funded public testnet evidence as the remaining
  external blocker until the public staging verifier passes.
* Added a machine-checked devnet evidence verifier and wired the devnet harness
  to fail if required native issue, transition, ZK, resolver, restart-recovery,
  and scanner markers are absent.
* Routed the live covenant allocation-vector proof through the supported-shape
  dispatch API, so refreshed devnet evidence exercises the same prover
  boundary.
* Updated e2e fixture semantics to use native issue and transition reports.
* Updated fixture/live native transition helpers to finalise through the
  two-phase continuation plan.
* Added live devnet view-key lane resolver evidence for private lanes.
* Renamed the old internalisation document to `docs/LANE-CALCULUS.md`.

## Toccata Evidence

* Fixture e2e and focused native asset tests pass with the native grammar.
* Local simnet/devnet scripts remain the evidence path for covenant lifecycle
  and scanner behaviour.
* Devnet evidence was refreshed after this refactor, including native issue
  digest, native transition digest, private-lane policy, ZK covenant spend,
  continuation confirmation, and native resolver classification.

## Remaining Work

* Stage on public testnet with restart recovery evidence.
* Stage wallet-facing policy-migration proof flows publicly.
* Stage the production allocation strategy publicly, and implement recursive
  aggregation if arbitrary one-step single-proof allocation proofs become a
  product requirement.
