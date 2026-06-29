# RGK - Really Good Kaspa

> RGK is a Kaspa-native client-side asset protocol inspired by RGB.

RGK borrows the client-side validation idea, receipt/consignment intuition,
and single-use seal discipline from RGB. It implements those ideas natively on
Kaspa Toccata covenant lineages.

The hot path is native RGK:

1. `RgkAssetIssue` defines an asset, total supply, initial allocations, proof
   policy, privacy policy, and lane id.
2. `RgkContinuationPlan` binds the previous allocation set and next output
   shape before the continuation txid exists.
3. `RgkTransition` finalises that plan after the txid exists, closes previous
   covenant seals, opens new allocations, and binds old state, new state,
   witness txid, ordered inputs, ordered outputs, proof policy, privacy mode,
   and lane id.
4. `RgkReceipt` carries the typed statement, including the phase-1
   continuation commitment, consumed by the covenant, resolver, and indexer.
5. `RgkResolver` classifies live chain evidence as native RGK state and
   rejects indexed transitions with missing continuation proof or a
   continuation outpoint txid that does not match the observed spend txid.

The asset grammar crate is `crates/rgk-asset`. Its public API is native RGK
asset grammar and lane validation, not an adapter for an external runtime.

## What RGK Is Not

* It is not a Kaspa port of another asset protocol.
* It does not claim full equivalence with any external asset protocol.
* It does not call external RGB runtime libraries or tooling in the hot path.
* It is not a Bitcoin / Kaspa bridge.
* It is not automatically post-quantum. The current ZK path uses Toccata's
  Groth16 precompile.

## Run The Local E2E

```bash
./scripts/setup-external.sh
./scripts/build-kaspa.sh
./scripts/run-kaspa-local.sh --background
./scripts/e2e-local.sh --live
```

Fixture mode requires no node:

```bash
./scripts/e2e-local.sh
```

Local devnet evidence:

```bash
./scripts/e2e-devnet.sh --start-kaspa
```

`setup-external.sh` only clones the Kaspa Toccata repository used for covenant
and devnet evidence.

## Current Status

| Area | Status |
| --- | --- |
| Native asset grammar | Live in `rgk_asset::native` |
| Native state digest | Live and pinned by tests; v2 binds metadata and owner commitments |
| Native transition digest | Live and pinned by tests |
| Private lane default | Live: `LanePrivacyPolicy::PrivateLane` |
| Scan tag and view-key discovery | Live in protocol helpers |
| Lane-discovery ZK circuit | Bounded Groth16 proof live in `rgk-zk`: public lane id, scan tag, and epoch; private view key and asset id |
| Lane-graph ZK circuit | Bounded 2-node Groth16 proof live in `rgk-zk`: public graph root and lane nodes; private view key and asset id |
| Segmented lane-graph ZK chain | Live for arbitrary-size graphs via bounded segment proofs; devnet evidence covers a 2-segment / 4-node chain |
| Segmented allocation transcript ZK | Supplemental audit proof live in `rgk-zk`; VM evidence covers bounded segments and devnet evidence covers spent/new transcript roots for a confirmed transition |
| Segmented allocation conservation ZK | Amount-hiding running-total proof chain live in `rgk-zk`; final equality proof shows spent/new totals match without publishing amounts, with local devnet evidence for the live 1x1 chain |
| Allocation exclusion segment-pair ZK | Bounded spent/new segment-pair proof live in `rgk-zk`; complete grids cover arbitrary-size closed-seal exclusion, with local devnet evidence for the live 1x1 pair |
| Allocation audit bundle verifier | Statement-level verifier composes verified transcript, conservation, final, and exclusion proofs into complete chains and grids; local devnet evidence requires the bundle line |
| Allocation audit certificate | Native certificate binds bundle statements to Groth16 VK/proof/public-input stack bytes, exposes a deterministic certificate id, verifies self-contained from canonical handoff bytes, persists on accepted spends, and is required by devnet evidence |
| Production allocation strategy planner | Live in `rgk-asset`: wallets select fixed allocation-vector proofs for evidenced shapes or segmented allocation-audit certificates for larger conserving full-state transfers, with native strategy commitments and fail-closed burn/empty-side checks |
| Nullifier and encrypted note commitment | Live in native allocation/lane state |
| Native proof policy commitment | Live and part of state digest; example coverage now includes downgrade and unconstrained-image-id guardrails |
| Native metadata and owner commitments | Live in state digest, transition digest, continuation commitment, semantic statement, devnet evidence, and `metadata_ownership_guardrails` example coverage |
| Native owner-control descriptors | Live for key-hash, script-hash, and covenant-id owner commitments, with owner-key rotation validation and `owner_control_policy_shapes` example coverage |
| Native NFT policy primitives | Live for fixed collection supply, token ids, metadata/template preservation, royalty-policy hooks, single-token owner handoff, marketplace sale settlement commitments, and terminal 1x0 NFT burn lifecycle |
| Advanced covenant policy and execution shapes | Live for payment-gated transfer, escrow release, vault timelock, atomic swap, covenant-owned asset, policy upgrade, and controlled termination commitments in `advanced_covenant_policy_shapes`, with wallet-facing execution-evidence planning and canonical execution-record handoff in `rgk-covenant` |
| Resolver native states | Live for valid/invalid transition, competing branch, replay, policy-migration proof handling, and optional allocation-audit certificate metadata |
| Policy-migration construction | Live in `rgk-core`; public staging open |
| Policy-migration recovery evidence | Live in persistent fixture and local devnet recovery against a confirmed spend; public staging open |
| Semantic and fixed allocation-vector circuits | Supported-shape registry for terminal 1x0 burn, 1x1, 2x2, const-generic 3x2, const-generic 4x2, and const-generic 4x4 evidence live in `rgk-zk`; larger conserving full-state transfers use the segmented audit-certificate strategy rather than an unevidenced single unbounded circuit |
| Examples coverage matrix | Live for the current evidence-backed examples in `examples/contract-matrix.tsv`, including proof-policy guardrails, metadata/ownership guardrails, owner-control shapes, public-lineage opt-in, advanced covenant policy shapes, NFT policy and marketplace-sale shapes, and fungible 2x2/3x2/4x2/4x4 transfer shapes; Silverscript sources and checked JSON artifacts are pinned to the upstream Testnet-12 compiler, while public staging remains open |
| Lane resolver APIs | Live for lane id, view key, scan tag, public lineage, and transition digest |
| Toccata covenant lifecycle | Live in fixture and local-node harnesses |
| Local devnet script | Refreshed after the native refactor |
| Two-phase continuation seal | Receipt/indexer persistence and resolver txid-binding enforcement live |
| Public testnet/mainnet staging | Public testnet harness, hardened preflight manifest, funding-address helper, and report verifier live; funded public run and verified report still open |
| Launch readiness audit | Live: `scripts/verify-launch-readiness.sh --allow-blocked` verifies local/devnet gates and reports the funded public testnet report as the remaining external blocker; strict mode stays non-zero until that report verifies |

## Quality Gates

```bash
cargo fmt --all -- --check
cargo test -p rgk-asset
cargo test -p rgk-asset --no-default-features
cargo test -p rgk-e2e --lib
cargo clippy -p rgk-asset --all-targets --all-features -- -D warnings
cargo clippy -p rgk-e2e --all-targets --features live-kaspa-wrpc,persistent-indexer,real-zk -- -D warnings
cargo test --workspace --no-default-features
cargo test --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
bash scripts/verify-silverscript-artifacts.sh
bash scripts/verify-example-matrix.sh
bash scripts/verify-launch-readiness.sh --allow-blocked
./scripts/e2e-devnet.sh --start-kaspa
```

## Repository Layout

```text
crates/
  rgk-core/        canonical RGK wire types and commitments
  rgk-receipt/     receipt builder and verifier
  rgk-covenant/    Toccata covenant state and script builder
  rgk-kaspa/       chain backend trait and live wRPC backend
  rgk-asset/       native RGK asset grammar
  rgk-zk/          ZK statement encoding and Groth16 receipt path
  rgk-indexer/     in-memory and sled indexers
  rgk-sync/        restart-safe scanner service
  rgk-resolver/    native state reconstruction
  rgk-tx/          unsigned transaction builders
tests/rgk-e2e/     fixture and live e2e harness
scripts/           Kaspa setup, local node, devnet, and e2e scripts
docs/              architecture, lane calculus, specs, security, and runbooks
```

## Documentation

* `docs/ARCHITECTURE.md` - system boundaries and data flow
* `docs/LANE-CALCULUS.md` - native asset, lane, privacy, and continuation model
* `docs/RECEIPT-SPEC.md` - receipt wire format
* `docs/COVENANT-SPEC.md` - covenant state and script contract
* `docs/ZK-BOUNDARY.md` - what the ZK path proves
* `docs/SECURITY.md` - threat model and trust assumptions
* `docs/VERIFICATION-BUDGET.md` - bounded verification costs
* `docs/E2E.md` - local and devnet runbook
* `docs/INTEGRATION.md` - wallet integration shape
* `docs/MAINNET-LAUNCH.md` - public-network launch gates

## Licence

Dual MIT / Apache-2.0.
