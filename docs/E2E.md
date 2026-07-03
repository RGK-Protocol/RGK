# End-To-End Runbook

The e2e harness exercises native RGK asset state, receipts, covenants,
indexing, and resolver classification against a fixture backend or a live
Toccata node.

## Prerequisites

* Rust toolchain matching the workspace `rust-version`.
* Git.
* A C toolchain for building `rusty-kaspa`.

## Step 1 - Clone Kaspa Toccata

```bash
./scripts/setup-external.sh
```

This prepares the Kaspa Toccata source used for covenant and devnet evidence.
Upstream merged the `toccata` branch into `master`, so `setup-external.sh`
pins `origin/master` (a strict superset of the former `toccata` branch). The
legacy `-toc` Cargo version suffix was dropped on master, so Toccata
capability is asserted structurally — the e2e harness links against
`kaspa_consensus_core::constants::TX_VERSION_TOCCATA`, which only compiles
when the dependency tree carries Toccata — rather than by version-string
matching.

## Step 2 - Build Kaspad

```bash
./scripts/build-kaspa.sh
```

## Step 3 - Run Local Simnet

```bash
./scripts/run-kaspa-local.sh --background
./scripts/e2e-local.sh --live
```

Fixture mode:

```bash
./scripts/e2e-local.sh
```

## Local Internal Readiness Evidence

```bash
bash scripts/e2e-internal-readiness.sh
```

The script writes `target/rgk-internal-readiness/latest.txt` and records the
local launch checklist gates that do not depend on public-network funding:
formatting, native vocabulary, checked Silverscript artifacts, examples matrix
coverage, native grammar tests with default and no-default features, focused
clippy gates, workspace no-default/all-features tests, `rgk-e2e` all-features
library tests, and rustdoc with warnings denied. It intentionally keeps the
node-dependent live lifecycle in the devnet/public-staging scripts. Verify it
with:

```bash
bash scripts/verify-internal-readiness-evidence.sh
```

## Local Devnet Evidence

```bash
./scripts/e2e-devnet.sh --start-kaspa
```

The script writes `target/rgk-devnet-evidence/latest.txt` and then runs
`scripts/verify-devnet-evidence.sh` against that report. The refreshed native
evidence is intentionally local/devnet scoped. It does not include the public
testnet preflight or funded public staging checks; those remain part of the
separate public-staging and launch-readiness gates. The devnet report must
show:

* `network_id`
* server version
* policy-migration proof construction, persistent indexer reopen, and resolver
  `NativeTransitionedValid` in the recovery fixture
* public-lineage resolver filtering by asset and exclusion of private lanes
* native issue digest
* native transition digest
* advanced covenant execution-record canonical handoff and tamper rejection
* privacy policy
* blinded lane id
* rotating scan tag
* fixture and live view-key lane resolver paths
* covenant funding accepted
* covenant spend accepted
* ZK precompile path when enabled
* allocation conservation proof chain when `real-zk` is enabled
* allocation audit bundle verification when `real-zk` is enabled
* allocation audit certificate canonical encode/decode, self-contained
  verification, and bundle-backed verification when `real-zk` is enabled
* allocation audit certificate indexer attachment and persistent recovery when
  `real-zk` and `persistent-indexer` are enabled
* production allocation strategy-record canonical handoff and tamper rejection
* Toccata v1 transaction Borsh wire and txid/hash projection tests against parent
  `rusty-kaspa`
* NFT marketplace sale terms binding payment asset, price, royalty policy,
  royalty amount, seller/buyer handoff, and sale authorisation
* continuation output confirmed
* resolver `NativeTransitionedValid`
* persistent live indexer recovery after resolver indexing
* Silverscript source and JSON artifact verifier pass for the current examples
* examples coverage matrix verifier pass
* `verify-devnet-evidence` pass

## Local Protocol Gate

```bash
bash scripts/e2e-internal-readiness.sh
bash scripts/verify-internal-readiness-evidence.sh
```

This gate covers non-public-network protocol checks, including `rgk-tx`
Toccata v1 transaction Borsh-wire, storage-mass, txid/hash, and sighash
projections against the parent `rusty-kaspa` consensus core, covenant tests,
and focused clippy checks for the transaction/covenant boundary. Public
testnet and mainnet evidence are not part of this gate.

## Public Testnet Staging

The live covenant harness can run against a public Kaspa testnet endpoint, but
it cannot mine funds there. First generate and verify the deterministic
testnet-only wallet-set report:

```bash
bash scripts/e2e-testnet-staging.sh --wallets
```

The report is written to
`target/rgk-testnet-staging-evidence/wallets.txt` and is checked by
`scripts/verify-testnet-staging-wallets.sh`. The frozen wallet/preflight
snapshot is recorded in [`TESTNET-STAGING-REPORT.md`](TESTNET-STAGING-REPORT.md).
It contains three deterministic testnet roles:

* `funding` - the address used by the live covenant test and the only role that
  needs public testnet funds;
* `change` - a reserved address for change-output isolation in staging reports;
* `observer` - a no-funding address for observer/reporting provenance.

Then print the deterministic funding address:

```bash
bash scripts/e2e-testnet-staging.sh --print-address
```

For the exact faucet URLs and follow-up commands, generate the funding helper:

```bash
bash scripts/e2e-testnet-staging.sh --funding-help testnet-10
```

or, for the default target:

```bash
bash scripts/e2e-testnet-staging.sh --funding-help testnet-12
```

Fund the printed `kaspatest:` address on public testnet with at least
`required_min_value_real_zk`. The address is derived from the deterministic
testnet-only staging wallet set and must not be used for mainnet funds. The
preflight manifest also binds the wallet-set id, expected `KaspaTestnet` chain
id, one-confirmation live test contract,
`live-kaspa-wrpc`/`real-zk`/`persistent-indexer` feature set, and
`required_local_mining=false` so public staging cannot be replaced by local
mining evidence.

Before running the full lifecycle, check the selected public endpoint and
funding UTXO without submitting a transaction:

```bash
RGK_LIVE_KASPA_URL="wss://host.example/v2/kaspa/testnet-12/no-tls/wrpc/borsh" \
  bash scripts/e2e-testnet-staging.sh --funding-readiness
```

This writes `target/rgk-testnet-staging-evidence/funding-readiness.txt` and
checks it with `scripts/verify-testnet-funding-readiness.sh`. A report with
`funding_readiness=ok` proves the endpoint network, `utxoindex`, and a
spendable non-coinbase UTXO meeting the real-ZK funding minimum. A blocked
report records the precise reason and is not full public staging evidence.
The launch gate also checks that funding-readiness uses the same network,
wallet-set id, and funding address as the preflight report. If staging targets
`testnet-10`, regenerate `--wallets` and `--preflight` with `testnet-10`
instead of mixing them with the default `testnet-12` reports.
Then run:

```bash
RGK_LIVE_KASPA_URL="wss://host.example/v2/kaspa/testnet-12/no-tls/wrpc/borsh" \
  bash scripts/e2e-testnet-staging.sh
```

The script writes `target/rgk-testnet-staging-evidence/latest.txt`, runs the
full live covenant lifecycle with `RGK_LIVE_KASPA_NETWORK=testnet-12` by
default, records the wallet-set report and preflight manifest, waits for real
public confirmations instead of mining, and checks the report with
`scripts/verify-testnet-staging-evidence.sh`.

The live covenant harness uses the native Toccata subnetwork with gas `0` by
default. To stage a based-app user lane, set
`RGK_LIVE_KASPA_SUBNETWORK_NAMESPACE` to a four-byte hex namespace such as
`00000100` and set `RGK_LIVE_KASPA_GAS` to a non-zero value. A non-zero gas
value without a user-lane namespace fails before submission. Devnet and public
staging verifiers require the report line
`live: Toccata tx subnetwork=... gas=... mode=...` so the chosen transaction
lane is explicit evidence rather than an implicit default.

Until that report verifies from a real public endpoint, public staging remains
open. `scripts/verify-launch-readiness.sh --allow-blocked` may still pass for
CI only when the preflight and funding-readiness reports match and
`funding_readiness=blocked`; if funding is ready, a stale or partial public
report is a failed gate.

## Fixture Flow

The fixture library test:

1. Builds a native `RgkAssetIssue`.
2. Validates the issue and gets `RgkStateDigest`.
3. Builds a native `RgkContinuationPlan` without a future txid.
4. Finalises the plan after the continuation txid exists and gets
   `RgkTransitionDigest`.
5. Builds an `RgkReceipt`.
6. Builds a canonical `SemanticTransitionStatement` from the validated native
   reports and checks it matches the fixture receipt statement.
7. Applies the fixture covenant spend and indexer update.
8. Resolves the covenant through `RgkResolver`.

The fixture e2e uses native RGK semantics only.

## Live Covenant Flow

The live test:

1. Connects to a Toccata wRPC endpoint.
2. Mines spendable simnet/devnet funds.
3. Funds a covenant-bearing output.
4. Spends it through the generated Toccata covenant script.
5. Observes the spend through virtual-chain scanning.
6. Records the indexed native transition.
7. Proves and verifies the phase-2 semantic transition and one-input/one-output
   allocation-vector Groth16 statements after the continuation txid exists,
   using the supported allocation-shape dispatch API.
8. Registers the private lane with a scan tag.
9. Resolves the transition as `NativeTransitionedValid`.
10. Rediscovers the private lane by view key and resolves it as
   `NativeTransitionedValid`.

The separate upstream Toccata VM test harness executes receipt, semantic,
single-lane discovery, 2-node lane-graph discovery, 2-node lane-graph segment,
allocation transcript segment, allocation conservation segment, allocation
conservation final equality, allocation exclusion segment-pair, 1x1
allocation-vector, 2x2 allocation-vector, const-generic 3x2, and
const-generic 4x2 and 4x4 allocation-vector Groth16 stacks against `OpZkPrecompile`.
The 3x2, 4x2, and 4x4 paths go through the supported-shape dispatch API used by
wallet/prover code. Local
devnet evidence also verifies a 2-segment / 4-node lane-graph proof chain,
spent/new allocation transcript segment proofs, a spent/new conservation chain
with final equality, the live 1x1 spent/new exclusion grid pair, and the
allocation audit bundle plus canonical certificate round-trip, indexer
attachment, resolver exposure, and sled recovery for a confirmed transition.

## Policy Migration Recovery Fixture

The devnet evidence script also runs the deterministic persistent fixture
`policy_migration_recovery_fixture_survives_reopen`. It builds a
`PolicyMigrationInput`, derives the native migration commitment, applies the
spend to `SledIndexer`, flushes and reopens the database, then resolves the
recovered covenant as `NativeTransitionedValid`.

This proves local restart recovery for wallet-facing migration proof material.
It is not a substitute for public testnet staging.

## Output Shape

Typical fixture summary:

```text
RGK e2e summary
  chain:           KaspaLocalToccata
  covenant:        0x...
  lineage:         0x...
  asset:           0x...
  old_state:       0x...
  new_state:       0x...
  receipt_id:      0x...
  proof_mode:      verifier-receipt
  policy:          any
  transitions:     1
  resolver:        Open { ... }
  live_mode:       false
```

## Not Yet Proven

* Public testnet or mainnet staging. `scripts/e2e-testnet-staging.sh` is the
  executable public-testnet path, but it must still be run against a real
  funded public endpoint and produce verified staging evidence.
* Public staging evidence for continuation enforcement outside local devnet.
* Public staging evidence for policy-migration proof flows.
* Arbitrary one-step unbounded allocation-vector transition proof inside ZK.
  The production ZK strategy is bounded to fixed 1x1, 2x2, const-generic 3x2,
  const-generic 4x2, and const-generic 4x4 allocation-vector evidence; uninstantiated or larger
  one-step arities are still native-validator bound. Segmented transcript, conservation, and
  exclusion proofs provide supplemental amount-hiding audit evidence for larger
  allocation sides, not a single allocation-vector transition proof.
* Automatic historical discovery without local wallet/indexer data.
