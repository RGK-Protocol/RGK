# Tutorial 4 — Run the E2E Harness

> **Read time:** ~30 minutes for the local path; longer for live. **Operator-facing.**
> This tutorial walks through every script in `scripts/` from the perspective
> of someone running them.

The canonical reference is [`docs/E2E.md`](../../E2E.md). This wiki page
adds ordering, expected output, and decision points.

---

## The Local Path (no public network)

This path exercises everything except a live Kaspa network connection. It
is the right place to start.

### Step 1 — Build the workspace

```bash
cargo build --workspace --all-features
```

Or for a faster dev loop:

```bash
cargo test -p rgk-asset -p rgk-receipt -p rgk-resolver
```

### Step 2 — Run the fixture e2e

```bash
./scripts/e2e-local.sh
```

This runs:

```bash
cargo test -p rgk-e2e --lib
```

Expected output:

```text
running N tests
test fixture_e2e_passes ... ok
test native_asset_state_report ... ok
... (28 tests)
test result: ok. N passed; 0 failed
[e2e-local] OK
```

Exit code `0` for success, `4` for test failures.

### Step 3 — Run the internal-readiness gate

```bash
bash scripts/e2e-internal-readiness.sh
bash scripts/verify-internal-readiness-evidence.sh
```

This runs the strict, no-public-network launch-readiness subset. Every key
line in `target/rgk-internal-readiness/latest.txt` must be `<key>=ok`. If
any line ends in `=failed` or `=blocked`, the verifier exits non-zero.

The 21 gates are documented in
[`scripts/e2e-internal-readiness.sh`](../../scripts/e2e-internal-readiness.sh)
and the
[`recon/RECON-RUNTIME.md`](../../recon/RECON-RUNTIME.md#scriptsinventory)
file.

### Step 4 — Run the privacy-observer evidence

```bash
bash scripts/e2e-privacy-observer.sh
bash scripts/verify-privacy-observer-evidence.sh
```

The producer emits the 14 required fields
(`privacy_observer_default`, `privacy_observer_learns`,
`privacy_observer_does_not_learn`, etc.). The verifier regex-matches every
field.

### Step 5 — Verify the silverscript artifacts

```bash
bash scripts/verify-silverscript-artifacts.sh
```

Recompiles every `examples/silverscript/*.sil` against the pinned compiler
commit, byte-compares the JSON to the checked-in artifacts, regenerates
`examples/silverscript/artifacts/manifest.tsv`. To overwrite (rare):

```bash
RGK_SILVERSCRIPT_UPDATE=1 bash scripts/verify-silverscript-artifacts.sh
```

### Step 6 — Verify the example matrix

```bash
bash scripts/verify-example-matrix.sh
```

Walks `examples/contract-matrix.tsv`, asserts that every `local_evidence`
regex resolves in `crates/` + `tests/`, every `devnet_markers` regex
resolves in `verify-devnet-evidence.sh`, and the silverscript artifact
manifest covers every `example_id`.

### Step 7 — Verify native terminology

```bash
bash scripts/verify-native-terminology.sh
```

Asserts that no `rgb*` legacy vocabulary, "outpoint seal", `cell`,
`aluvm`, `tapret`, `opret`, `consignment`, `argent`, or `strict-types`
strings appear in the public workspace surface.

**You should be green on every gate above before going live.**

---

## The Live Simnet Path

Requires a built `kaspad` reachable at
`ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh`.

### Step 1 — Clone the upstream Toccata branch

```bash
./scripts/setup-external.sh
```

Clones `kaspanet/rusty-kaspa` (branch `master`, where Toccata is merged)
and `kaspanet/silverscript` (pinned to `d25bd3427a09…`).

### Step 2 — Build kaspad

```bash
./scripts/build-kaspa.sh          # release
./scripts/build-kaspa.sh --debug  # faster compile
```

Binaries land at `external/rusty-kaspa-toccata/target/{release,debug}/kaspad`
and `…/kaspa-miner`.

### Step 3 — Start the simnet

```bash
./scripts/run-kaspa-local.sh --background
```

Launches `kaspad --simnet --enable-unsynced-mining --utxoindex --rpclisten-borsh`.

### Step 4 — Run the live covenant test

```bash
./scripts/e2e-local.sh --live
```

Or with all-features:

```bash
cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant \
    -- live_toccata_full_covenant_lifecycle --nocapture
```

The gold reference is
[`tests/rgk-e2e/tests/live_covenant.rs:730`](../../tests/rgk-e2e/tests/live_covenant.rs):
the test runs the full pipeline (mine, fund, build covenant, sign,
submit, wait, scan, index, resolve) and asserts the resolver returns
`NativeTransitionedValid` with the expected fields.

### Step 5 — Tear down

```bash
./scripts/e2e-local.sh --stop-kaspa
```

---

## The Local Devnet Path

A Toccata-active devnet (from genesis) is more thorough than a simnet.
The devnet uses
`scripts/devnet-toccata-overrides.json`
(`{"skip_proof_of_work": true, "toccata_activation": 0}`) to start with
Toccata active and skip PoW so blocks mine instantly.

### Step 1 — Start the devnet

```bash
./scripts/run-kaspa-devnet.sh --background
```

### Step 2 — Run the devnet e2e

```bash
./scripts/e2e-devnet.sh --start-kaspa
```

This drives (in order):

1. The live devnet test (Toccata node identity + persistent scan cursor).
2. The public-lineage resolver fixture.
3. The policy-migration recovery fixture.
4. 7 advanced-covenant tests from `rgk-covenant`.
5. 3 native burn / production-ZK burn tests from `rgk-asset` and `rgk-zk`.
6. 5 metadata/ownership tests.
7. 6 NFT lane-policy tests.
8. 4 fungible transfer-shape tests.
9. 4 production allocation-strategy tests.
10. The 4×2 and 4×4 allocation-vector VM tests.
11. The full covenant lifecycle on devnet (`cargo test --test live_covenant`).
12. The `rgk-sync` scanner smoke.
13. `verify-example-matrix.sh`.
14. `verify-devnet-evidence.sh` against the assembled report.

Total: ~70+ required regex markers in
`target/rgk-devnet-evidence/latest.txt`.

### Step 3 — Tear down

```bash
./scripts/e2e-devnet.sh --stop-kaspa
```

---

## The Public Testnet Staging Path

This is the gated path that produces the launch-audit evidence. See
[Concepts / Funding](../Concepts/Funding.md) for the full happy-path.

```bash
bash scripts/e2e-testnet-staging.sh --wallets
bash scripts/e2e-testnet-staging.sh --preflight
# fund the address printed by --wallets
bash scripts/e2e-testnet-staging.sh --funding-readiness
bash scripts/e2e-testnet-staging.sh --resume
bash scripts/verify-testnet-staging-evidence.sh
```

Target network: **`testnet-12`** (not `testnet-10`). The frozen wallet set
and preflight are pinned in
[`docs/TESTNET-STAGING-REPORT.md`](../../TESTNET-STAGING-REPORT.md).

---

## The Launch Audit

```bash
bash scripts/verify-launch-readiness.sh                  # strict mode
bash scripts/verify-launch-readiness.sh --allow-blocked   # relaxed mode
```

Strict mode requires:

- `internal_readiness=ok`
- `devnet_evidence=ok`
- `preflight_status=ok`
- `examples_matrix=ok`
- `funding_readiness=ok`
- `public_testnet_funded_report=ok`

Relaxed mode (CI / local before funded testnet) accepts
`funding_readiness=blocked` **only if** all other lines are `=ok` and
preflight matches the wallet set.

See [`Runbook / Launch Gates`](../Runbook/Launch-Gates.md).

---

## Cross-references

- [`docs/E2E.md`](../../E2E.md) — the canonical runbook.
- [`recon/RECON-RUNTIME.md`](../../recon/RECON-RUNTIME.md) — every
  executable action RGK exposes, with prereqs and expected output.
- [`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md) — the launch-gate
  contract.
- [Concepts / Funding](../Concepts/Funding.md) — the public-testnet
  staging flow.
- [Tutorial-0](./Tutorial-0-10-Minute-Fixture-Walkthrough.md) — the
  10-minute local path.