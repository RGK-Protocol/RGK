# Mainnet Launch Checklist

RGK is research code until these gates are complete.

## Required Evidence

* Native grammar tests pass with default features and no-default features.
* Workspace all-features and no-default-features tests pass.
* Rustdoc builds with warnings denied.
* Local devnet evidence is refreshed after the native refactor.
* Local devnet evidence passes `scripts/verify-devnet-evidence.sh`.
* Launch readiness audit reports `internal_readiness=ok` via
  `scripts/verify-launch-readiness.sh --allow-blocked`; strict mode must pass
  before any mainnet-readiness claim.
* Local examples coverage passes `scripts/verify-example-matrix.sh` and is
  recorded in refreshed devnet evidence.
* Local Silverscript source/artifact evidence passes
  `scripts/verify-silverscript-artifacts.sh` against the pinned compiler.
* Local policy-migration recovery evidence proves proof construction, Sled
  reopen, and resolver acceptance after restart.
* Local devnet policy-migration recovery evidence proves the same migration
  path against a confirmed live covenant spend.
* Public testnet staging path is executable through
  `scripts/e2e-testnet-staging.sh` and its report verifier, using a real
  pre-funded public testnet UTXO rather than local mining. The deterministic
  funding address is printed by `scripts/e2e-testnet-staging.sh --print-address`.
  Before funding, `scripts/e2e-testnet-staging.sh --preflight` must produce a
  machine-checked manifest that binds the target network, deterministic address,
  `KaspaTestnet` chain id, minimum funding values, non-coinbase funding
  requirement, UTXO-index requirement, one-confirmation live test contract,
  required `live-kaspa-wrpc`/`real-zk`/`persistent-indexer` features,
  no-local-mining requirement, and preflight id.
* Public testnet staging demonstrates funding, continuation spend, indexing,
  resolver classification, and restart recovery.
* Public testnet staging demonstrates policy-migration proof flows if policy
  changes are enabled for that staging scope.
* Two-phase continuation commitment is persisted and enforced by the resolver.
* Private lane discovery has wallet-facing tests.
* Security review covers covenant script, receipt verification, proof policy,
  lane privacy, and indexer replay behaviour.

## Required Devnet Fields

Evidence should include:

* network id
* server version
* native issue digest
* native transition digest
* proof policy commitment on native state and transition evidence
* privacy policy
* blinded lane id
* rotating scan tag
* policy-migration recovery fixture with reopened persistent indexer
* policy-migration recovery against a confirmed local devnet spend
* public-lineage resolver filtering by asset and exclusion of private lanes
* advanced covenant execution-record canonical handoff and tamper rejection
* public testnet staging preflight manifest and
  `verify-testnet-staging-preflight` pass
* covenant funding accepted
* covenant spend accepted
* ZK precompile path when enabled
* allocation conservation proof chain when `real-zk` is enabled
* allocation audit bundle verification when `real-zk` is enabled
* allocation audit certificate canonical encode/decode, self-contained
  verification, and bundle-backed verification when `real-zk` is enabled
* allocation audit certificate indexer attachment and persistent recovery when
  `real-zk` and `persistent-indexer` are enabled
* NFT marketplace sale terms with bound payment, royalty, owner handoff, and
  sale authorisation evidence
* continuation output confirmed
* resolver `NativeTransitionedValid`
* view-key lane resolver `NativeTransitionedValid`
* Silverscript source and JSON artifact verifier pass
* examples coverage matrix verifier pass
* machine-checked `verify-devnet-evidence` pass

## Current Machine Check

Use this before public funding is available:

```bash
bash scripts/verify-launch-readiness.sh --allow-blocked
```

Use strict mode for the launch gate:

```bash
bash scripts/verify-launch-readiness.sh
```

`--allow-blocked` may exit successfully only when local/devnet gates verify and
the remaining blocker is the missing funded public testnet report. Strict mode
remains non-zero until `public_testnet_funded_report=ok`.

## Do Not Claim

* mainnet readiness before public staging
* public staging before the preflight manifest and funded public report both
  verify
* arbitrary one-step unbounded allocation-vector ZK transition proof before a
  recursive, aggregated, or otherwise unbounded strategy has evidence
* privacy beyond the private-lane commitment model
* equivalence with any external asset protocol
