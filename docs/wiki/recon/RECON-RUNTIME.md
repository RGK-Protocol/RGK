# RGK — Runtime / Runnable-Action Reconnaissance

> **Purpose.** A read-only inventory of every executable action RGK exposes, so
> wiki tutorial writers know which script, test, or example to use as the demo
> anchor for each concept. This is a recon, not a tutorial — it tells you what
> exists and what it does, not how to explain it.
>
> **Scope.** `scripts/`, `examples/`, `tests/rgk-e2e/`, and the README's
> "Try It", "What Is Implemented", and "Quality Checks" sections.
> Everything below was verified by reading the file contents directly, not
> inferred from names.
>
> **Snapshot date.** `git status` is clean against the workspace at
> `target` time; script files referenced below were read at the listed
> line numbers on `Sat Jul 04 2026`.

---

## 1. `scripts/` inventory

Every executable script in `scripts/`. Listed in the order they appear on
disk. "Shebang" is `#!/usr/bin/env bash` for every one of them; none use
`python` directly except `verify-avato-walletd-contract.sh` which embeds a
`python3 <<'PY' ... PY` block.

| # | Path | Shebang | Demonstrable concept |
|---|------|---------|----------------------|
| 1 | `scripts/build-kaspa.sh` | bash | Cloning the upstream Toccata-capable kaspad and producing `kaspad` + `kaspa-miner` binaries. |
| 2 | `scripts/devnet-toccata-overrides.json` | (data) | The `toccata_activation: 0` + `skip_proof_of_work: true` overrides passed to `kaspad --devnet --override-params-file=`. |
| 3 | `scripts/e2e-devnet.sh` | bash | End-to-end harness against a local Toccata-active devnet, including live_resolver classification, persistent scan cursor, and the full fixture roll. |
| 4 | `scripts/e2e-internal-readiness.sh` | bash | The local (no public network) launch-readiness gate runner that produces `target/rgk-internal-readiness/latest.txt`. |
| 5 | `scripts/e2e-local.sh` | bash | Drives either the fixture-only flow (`cargo test -p rgk-e2e --lib`) or a live simnet flow against a Toccata-capable `kaspad`. |
| 6 | `scripts/e2e-privacy-observer.sh` | bash | Produces `target/rgk-privacy-observer-evidence/latest.txt` proving the public observer only sees commitments, not plaintext. |
| 7 | `scripts/e2e-testnet-staging.sh` | bash | Public Kaspa testnet staging harness (six subcommands: default, `--print-address`, `--preflight`, `--wallets`, `--funding-readiness`, `--resume`). |
| 8 | `scripts/e2e-privacy-observer.sh` / `scripts/verify-privacy-observer-evidence.sh` | bash | Privacy-observer evidence producer + gate verifier (must-pass regex check on the produced report). |
| 9 | `scripts/run-kaspa-devnet.sh` | bash | Launches a `kaspad --devnet --override-params-file=scripts/devnet-toccata-overrides.json` (Toccata from genesis). |
| 10 | `scripts/run-kaspa-local.sh` | bash | Launches a `kaspad --simnet` with `--enable-unsynced-mining` + `--utxoindex` + `--rpclisten-borsh`. |
| 11 | `scripts/setup-external.sh` | bash | Clones `kaspanet/rusty-kaspa` (branch `master`, where Toccata is merged) and `kaspanet/silverscript` (pinned to `d25bd3427a09…`). |
| 12 | `scripts/verify-avato-walletd-contract.sh` | bash + embedded `python3` | Spins up `rgk-walletd`, then a Python harness hits the HTTP contract endpoints and asserts strict 4xx semantics. |
| 13 | `scripts/verify-devnet-evidence.sh` | bash | Verifies the `target/rgk-devnet-evidence/latest.txt` report contains every required regex marker (~70 of them). |
| 14 | `scripts/verify-example-matrix.sh` | bash | Verifies the `examples/contract-matrix.tsv` header, every row's field values, that `local_evidence` regexes resolve in `crates/`+`tests/`, that `devnet_markers` resolve in `verify-devnet-evidence.sh`, and that the Silverscript artifact manifest covers every example_id. |
| 15 | `scripts/verify-internal-readiness-evidence.sh` | bash | Verifies the internal-readiness report passes every required gate; explicitly fails on any `=failed` or `=blocked` line. |
| 16 | `scripts/verify-launch-readiness.sh` | bash | Top-level launch audit. Combines internal-readiness + devnet + preflight + examples-matrix + funding-readiness + funded-testnet evidence into a single `launch_readiness=ok|blocked` line. `--allow-blocked` is for local/devnet CI before a funded testnet report exists. |
| 17 | `scripts/verify-native-terminology.sh` | bash | Asserts that no `rgb*` legacy vocabulary, "outpoint seal", `cell`, `aluvm`, `tapret`, `opret`, `consignment`, `argent`, or `strict-types` strings appear in the public workspace surface. |
| 18 | `scripts/verify-privacy-observer-evidence.sh` | bash | Regex-matches the 14 required fields in the privacy-observer evidence report. |
| 19 | `scripts/verify-silverscript-artifacts.sh` | bash | Recompiles every `examples/silverscript/*.sil` against the pinned compiler commit, byte-compares the resulting JSON to the checked-in artifacts, regenerates `examples/silverscript/artifacts/manifest.tsv`. Set `RGK_SILVERSCRIPT_UPDATE=1` to overwrite. |
| 20 | `scripts/verify-testnet-funding-readiness.sh` | bash | Regex-checks a public testnet funding-readiness report (does not connect itself). |
| 21 | `scripts/verify-testnet-staging-evidence.sh` | bash | Regex-checks a public testnet staging report (does not submit). |
| 22 | `scripts/verify-testnet-staging-preflight.sh` | bash | Regex-checks a public testnet staging preflight manifest. |
| 23 | `scripts/verify-testnet-staging-wallets.sh` | bash | Regex-checks the deterministic public testnet wallet set (must not contain any `secret_key=` / `private_key=` / `privkey=` line). |

### 1.1 Per-script detail

For each script the table below records: what it does, prerequisites,
the exact invocation form a learner would type, the expected output and
exit code on success, and which concept or test it ties to.

> All paths are relative to the workspace root
> (`/Users/arthur/RustroverProjects/rgk`). Line numbers refer to the
> files as they exist in the current checkout.

#### `scripts/build-kaspa.sh` (36 lines)

- **What it does** — if `external/rusty-kaspa-toccata/` is missing, calls
  `setup-external.sh` first; then `cargo build --profile <release|debug>
  --bin kaspad --bin kaspa-miner` inside that clone. (lines 19–32.)
- **Prereqs** — a working C/C++ toolchain for Kaspa (Go is **not**
  required because Rust) plus ~10 minutes of compile time on a modern
  laptop. `rustup` with stable Rust.
- **Invocation** — `./scripts/build-kaspa.sh` for a release build;
  `./scripts/build-kaspa.sh --debug` for a faster compile.
- **Expected success output** — the two binaries land at
  `external/rusty-kaspa-toccata/target/{release,debug}/kaspad` and
  `…/kaspa-miner`. The script prints both paths at the end. Exit code `0`.
- **Concept** — "Toccata is a Rusty-Kaspa branch, RGK builds kaspad
  from that branch". Required precursor for `run-kaspa-local.sh` and
  `run-kaspa-devnet.sh`.

#### `scripts/devnet-toccata-overrides.json` (4 lines, data)

- **What it does** — `{"skip_proof_of_work": true, "toccata_activation": 0}`.
- **Concept** — Tells the devnet `kaspad` "start with Toccata active from
  block 0, and skip PoW so blocks mine instantly". Consumed by
  `run-kaspa-devnet.sh` via `--override-params-file=`.

#### `scripts/e2e-local.sh` (86 lines)

- **What it does** — Two modes (line 22): `fixture` (default) runs
  `cargo test -p rgk-e2e --lib`; `live` runs
  `cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant`.
  Helper flags: `--start-kaspa` invokes `run-kaspa-local.sh --background`,
  `--stop-kaspa` kills the backgrounded kaspad by PID file,
  `--fixture` forces fixture mode. (lines 27–57.)
- **Prereqs** — for fixture mode, nothing more than a working `cargo`.
  For `--live` you need a `kaspad` simnet reachable on
  `ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh` (or the
  `RGK_LIVE_KASPA_URL` env var). The script refuses to run `--live` if
  the TCP port is unreachable. (lines 61–77.)
- **Invocation** —
  ```bash
  ./scripts/e2e-local.sh                # fixture-only
  ./scripts/e2e-local.sh --live         # connect to local simnet
  ./scripts/e2e-local.sh --start-kaspa  # also start the simnet
  ./scripts/e2e-local.sh --stop-kaspa   # stop the simnet
  ```
- **Expected success output** — fixture mode prints
  `running: cargo test -p rgk-e2e --lib` and ends with `[e2e-local] OK`.
  Live mode prints `running: cargo test -p rgk-e2e --features
  live-kaspa-wrpc --test live_covenant` and the same `OK` line.
  Exit code `0`; exit code `2` for "missing prereq"; `3` for "live node
  unreachable"; `4` for "cargo test failure". (lines 11–16.)
- **Concept** — "RGK has a fast fixture path and a slower live path";
  the resolver's `NativeTransitionedValid` state is observed in both
  (see `fixture_e2e_passes` at `tests/rgk-e2e/src/lib.rs:472` and
  `live_toccata_full_covenant_lifecycle` at
  `tests/rgk-e2e/tests/live_covenant.rs:730`).

#### `scripts/e2e-devnet.sh` (199 lines)

- **What it does** — runs against a Toccata-active devnet. After
  confirming the wRPC port is open, it deletes the sled sync DB under
  `target/rgk-devnet-evidence/sled` and sequentially runs (lines 78–196):
  - the live devnet test (Toccata node identity + persistent scan
    cursor initialisation);
  - the public-lineage resolver fixture;
  - the policy-migration recovery fixture;
  - 7 advanced-covenant tests from `rgk-covenant`;
  - 3 native burn / production-ZK burn tests from `rgk-asset` and
    `rgk-zk`;
  - 5 metadata/ownership tests;
  - 6 NFT lane-policy tests;
  - 4 fungible transfer-shape tests;
  - 4 production allocation-strategy tests;
  - the 4×2 and 4×4 allocation-vector VM tests
    (`rgk_allocation_4x2_groth16_proof_executes_in_upstream_toccata_vm`,
    `…_4x4_…`);
  - the full covenant lifecycle on devnet
    (`cargo test --test live_covenant`);
  - the `rgk-sync` scanner smoke (initialise + reload cursor);
  - `verify-example-matrix.sh`;
  - `verify-devnet-evidence.sh` against the assembled report.
- **Prereqs** — a running devnet node (use `--start-kaspa` for a local
  one), `cargo`, a built `rgk-sync` binary.
- **Invocation** —
  ```bash
  ./scripts/e2e-devnet.sh                # needs an existing devnet
  ./scripts/e2e-devnet.sh --start-kaspa  # boots a local devnet
  ./scripts/e2e-devnet.sh --stop-kaspa   # tears it down
  ```
- **Expected success output** — a single concatenated
  `target/rgk-devnet-evidence/latest.txt` containing every
  `[e2e-devnet] running …` line and the matched `live: …` markers.
  The final line is `[e2e-devnet] evidence: <path>`. Exit code `0` when
  every step and `verify-devnet-evidence.sh` passes; non-zero
  propagation through `set -euo pipefail` otherwise.
- **Concept** — "All shapes claimed in `What Is Implemented` have live
  devnet evidence under one log file". The devnet URL default is
  `ws://127.0.0.1:19111/v2/kaspa/devnet/no-tls/wrpc/borsh`. (line 19.)

#### `scripts/e2e-internal-readiness.sh` (60 lines)

- **What it does** — runs a fixed sequence of 21 local gates and
  appends `key=ok|failed` to the report (lines 40–58):
  `cargo_fmt`, native-terminology gate, silverscript-artifacts, examples
  matrix, native-grammar default + no-default, toccata_tx_tests,
  live_toccata_tx_config_tests, `cargo test -p rgk-covenant`,
  `cargo test -p rgk-e2e --test covenant_script_vm`, `… --test
  zk_precompile_vm r0_succinct`, the privacy-observer evidence producer,
  three clippy runs (tx+covenant, asset all-features, e2e live+real-zk),
  workspace no-default tests, e2e lib all-features, workspace
  all-features excluding e2e, `RUSTDOCFLAGS=-D warnings cargo doc …`.
- **Prereqs** — `cargo`, `rustc`, `rg`, `bash`; the silverscript compiler
  clone in `external/silverscript` (run `setup-external.sh` first if not
  present); no public network.
- **Invocation** — `bash scripts/e2e-internal-readiness.sh` (default
  output: `target/rgk-internal-readiness/latest.txt`).
- **Expected success output** — every key line is `<key>=ok`, the file
  ends with `[internal-readiness] evidence: …`. Exit code `0` on full
  success; non-zero on any `run_step` failure.
- **Concept** — "the local, non-public-network launch checklist". It
  is intentionally a strict subset of the public launch audit
  (`verify-launch-readiness.sh`).

#### `scripts/e2e-privacy-observer.sh` (67 lines)

- **What it does** — runs six observer-boundary tests
  (`rgk-asset::native::tests::private_lane_public_observer_boundary_is_commitment_only`,
  `…_discovery_and_tags_behave_as_commitments`,
  `allocation_transcript_amount_commitment_hides_bound_amount`,
  `nullifier_is_stable_but_unlinked_to_lane_id`,
  `public_and_private_lane_policies_have_different_visibility`,
  `rgk-resolver::tests::resolve_by_view_key_discovers_only_matching_private_lane`)
  and emits the static labels
  `privacy_observer_default=PrivateLane`,
  `privacy_observer_learns=blinded_lane_ids,rotating_scan_tags,nullifiers,opaque_commitments`,
  `privacy_observer_does_not_learn=asset_id,owner,amount,lane_graph,plaintext_proof_policy`,
  `privacy_observer_view_key_required=true`,
  `privacy_observer_public_lineage_opt_in=true`. (lines 35–65.)
- **Prereqs** — `cargo`, `rustc`; no node.
- **Invocation** — `bash scripts/e2e-privacy-observer.sh`. Output
  defaults to `target/rgk-privacy-observer-evidence/latest.txt` (line 9).
- **Expected success output** — every test prints `... ok`, the static
  labels print as `key=value`, the verifier sub-call ends with
  `[verify-privacy-observer-evidence] ok: …`. Exit code `0`.
- **Concept** — "private lane public observer only learns commitments,
  not plaintext, not ownership, not amounts".

#### `scripts/e2e-testnet-staging.sh` (237 lines)

- **What it does** — six sub-commands (line 22 onwards):
  - `--print-address` (no network) → derives the deterministic testnet
    staging keypair and prints the funding address;
  - `--preflight` (no network) → renders the preflight manifest and
    runs `verify-testnet-staging-preflight.sh` on it;
  - `--wallets` (no network) → renders the 3-wallet set
    (funding + change + observer) and runs
    `verify-testnet-staging-wallets.sh`;
  - `--funding-readiness [network] [url]` → connects to a public testnet
    Borsh wRPC endpoint, finds the deterministic funding UTXO, prints
    the funding-readiness report, runs
    `verify-testnet-funding-readiness.sh`;
  - `--resume <report>` → resumes the public testnet staging
    `live_toccata_full_covenant_lifecycle` test from a previous
    partially-validated report;
  - default (no flags) → requires `RGK_LIVE_KASPA_URL` to be set to
    `ws://`/`wss://`; runs preflight + wallets + the full
    `live_toccata_full_covenant_lifecycle` test and pipes everything
    through `verify-testnet-staging-evidence.sh`.
- **Prereqs** — `--print-address`, `--preflight`, `--wallets` need
  only the binary `cargo run -p rgk-e2e --bin rgk-testnet-staging-address`;
  `--funding-readiness` and the default mode additionally need a
  funded public testnet UTXO and a public Borsh wRPC URL. The script
  refuses to run if the host:port derived from `RGK_LIVE_KASPA_URL`
  is not TCP-reachable. (lines 199–209.)
- **Invocation examples** —
  ```bash
  bash scripts/e2e-testnet-staging.sh --print-address
  bash scripts/e2e-testnet-staging.sh --preflight
  bash scripts/e2e-testnet-staging.sh --wallets
  bash scripts/e2e-testnet-staging.sh --funding-help testnet-12
  RGK_LIVE_KASPA_URL="wss://testnet-12.kaspanet.io/..." \
      bash scripts/e2e-testnet-staging.sh
  ```
- **Expected success output** — depends on subcommand. The full
  default-mode run produces a `target/rgk-testnet-staging-evidence/latest.txt`
  containing wallet-set, preflight, and live evidence sections,
  ending with `[verify-testnet-staging-evidence] ok: …`. Exit code `0`.
  Exit code `2` for missing env / unknown subcommand; `3` for
  unreachable testnet host.
- **Concept** — "testnet staging has a public-network-aware preflight
  plus a funded main run; the script splits them so an operator can
  print the funding address without a node, then fund, then run".

#### `scripts/run-kaspa-devnet.sh` (76 lines)

- **What it does** — invokes `kaspad --devnet
  --override-params-file=scripts/devnet-toccata-overrides.json
  --rpclisten-borsh=0.0.0.0:19111 …`. (lines 35–48.) Defaults:
  data dir `./.rgk-devnet`, p2p 19100, RPC 19110. Profile defaults to
  `release` (override via `RGK_KASPA_PROFILE`).
- **Prereqs** — a built `kaspad` (`external/rusty-kaspa-toccata/target/release/kaspad`).
  Auto-runs `build-kaspa.sh` if missing. (lines 22–26.)
- **Invocation** — `./scripts/run-kaspa-devnet.sh` (foreground) or
  `./scripts/run-kaspa-devnet.sh --background` (daemonised, writes
  `./.rgk-devnet/kaspad.pid`, waits up to 60s for the wRPC port).
- **Expected success output** — when run with `--background`, prints
  `pid: <n>`, `log: <path>`, `wRPC ready after Ns`. Exit code `0`. In
  foreground mode, `exec`s kaspad so the script is kaspad.
- **Concept** — "devnet is a separate network, requires
  Toccata-from-genesis via override params".

#### `scripts/run-kaspa-local.sh` (69 lines)

- **What it does** — invokes `kaspad --simnet
  --rpclisten-borsh=0.0.0.0:18111 …`. (lines 29–41.) Defaults: data
  dir `./.rgk-localnet`, p2p 18100, RPC 18110. Auto-runs
  `build-kaspa.sh` if missing.
- **Prereqs** — same as `run-kaspa-devnet.sh`.
- **Invocation** — `./scripts/run-kaspa-local.sh` (foreground) or
  `./scripts/run-kaspa-local.sh --background` (daemonised).
- **Expected success output** — `pid: <n>`, `log: <path>`, `RPC
  ready after Ns`. Exit code `0`.
- **Concept** — "local simnet is the cheapest live Toccata-capable
  network to drive `e2e-local.sh --live` against".

#### `scripts/setup-external.sh` (51 lines)

- **What it does** — clones or fast-forwards
  `external/rusty-kaspa-toccata` to `origin/master` and
  `external/silverscript` to commit `d25bd3427a09…`. (lines 41–49.)
- **Prereqs** — `git`, network access to GitHub. No node.
- **Invocation** — `./scripts/setup-external.sh` (clone) or
  `./scripts/setup-external.sh --update` (fetch + fast-forward).
- **Expected success output** — each clone prints `cloning <url> -> <dir>
  @ <ref>` and at the end prints the current HEAD commit of each.
  Exit code `0`.
- **Concept** — "RGK tracks the upstream `toccata` branch via the
  `master` line; silverscript is pinned for artifact reproducibility".

#### `scripts/verify-avato-walletd-contract.sh` (553 lines)

- **What it does** — picks a free local port, runs
  `cargo run -q -p rgk-walletd -- --listen <port> --network
  local-toccata --kaspa-endpoint ws://127.0.0.1:9/.../borsh --state …
  --sync-db …` in the background, waits up to 24s for `/health`,
  then runs an embedded Python3 harness that posts to every endpoint in
  the Avato frontend contract JSON (`/wallets`, `/wallet/import`,
  `/wallet/lock`, `/wallet/unlock`, `/wallet/kaspa-endpoint`,
  `/wallet/sync`, `/dashboard`, `/lanes`, `/proofs`, `/transitions`),
  asserting strict 4xx semantics (no `unexpectedField`, no bad
  txid, no bad balance, no locked-wallet access). Finally inspects
  the on-disk state file for `argon2id:v2:…` verifier, `xchacha20poly1305`
  cipher, and 0o600 POSIX mode. (lines 22–552.)
- **Prereqs** — `cargo`, `python3`, `curl`. Expects
  `../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json`
  (override via `AVATO_RGK_CONTRACT`). Does **not** require a live
  kaspad — the default `KASPA_ENDPOINT` is an unreachable port so the
  service-mode assertions stay in `unavailable`.
- **Invocation** — `bash scripts/verify-avato-walletd-contract.sh`.
- **Expected success output** — final line is
  `[verify-avato-walletd-contract] ok`. Exit code `0`; non-zero on any
  contract mismatch.
- **Concept** — "rgk-walletd is the local HTTP wallet API; its
  contract with the Avato frontend is byte-level, encrypted at rest,
  and 4xx-strict on stale clients".

#### `scripts/verify-devnet-evidence.sh` (117 lines)

- **What it does** — requires ~80 `require_regex` lines
  against the supplied report (the report path is `$1` or
  `target/rgk-devnet-evidence/latest.txt`). Each `require_regex` is a
  fail-closed check: missing regex exits with code `1`. (lines 16–22.)
  Examples: `require_regex "node identity" 'live-devnet:
  server_version=.* network_id=devnet .*has_utxo_index=true'`,
  `require_regex "resolver classification" 'live: resolver state =
  NativeTransitionedValid'`, etc.
- **Prereqs** — a previously produced `target/rgk-devnet-evidence/latest.txt`.
  No node.
- **Invocation** — `bash scripts/verify-devnet-evidence.sh
  target/rgk-devnet-evidence/latest.txt`.
- **Expected success output** — `[verify-devnet-evidence] ok: <path>`.
  Exit code `0`.
- **Concept** — "the devnet evidence file is the machine-checkable
  contract for what shapes/devnet coverage we currently have".

#### `scripts/verify-example-matrix.sh` (115 lines)

- **What it does** — runs `verify-silverscript-artifacts.sh` first
  (line 12), then asserts the TSV header is exactly
  `example_id\tcategory\tcapabilities\tlocal_evidence\tdevnet_markers\tcontract_source\tsilverscript_status\tcompile_artifact_status\tpublic_staging_status\texternal_equivalence_status`
  (lines 19–24), iterates every row, checks every cell is non-empty,
  validates the `contract_source`, `silverscript_status`,
  `compile_artifact_status`, `public_staging_status`,
  `external_equivalence_status` enums (lines 47–81), asserts every
  `local_evidence` regex resolves somewhere in `crates/` or `tests/`
  via `rg -q` (line 85), asserts every `devnet_marker` regex appears
  as a `require_regex "<marker>"` line in `verify-devnet-evidence.sh`
  (lines 91–96), and asserts the same `example_id` is in the
  silverscript artifact manifest. Requires ≥ 4 rows and unique
  example_ids.
- **Prereqs** — `rg` (ripgrep), `bash`; the silverscript clone must
  exist.
- **Invocation** — `bash scripts/verify-example-matrix.sh`.
- **Expected success output** — `[verify-example-matrix] ok:
  examples/contract-matrix.tsv rows=N` (current `N=13`). Exit code `0`.
- **Concept** — "the example matrix is the inventory of what we
  currently prove; every local-evidence regex must resolve to a real
  test, and every devnet marker must be enforced".

#### `scripts/verify-internal-readiness-evidence.sh` (66 lines)

- **What it does** — exits `1` if any `^[a-z0-9_]+=(failed|blocked)$`
  appears in the report (lines 24–28), then `require_regex`-matches 30
  expected lines including the `cargo_fmt=ok`, the
  `silverscript_artifacts=ok`, and the specific
  `… ok` lines for the covenant, ZK VM, and clippy gates.
- **Prereqs** — a previously produced internal-readiness report.
- **Invocation** — `bash scripts/verify-internal-readiness-evidence.sh
  target/rgk-internal-readiness/latest.txt`.
- **Expected success output** — `[verify-internal-readiness-evidence]
  ok: <path>`. Exit code `0`.

#### `scripts/verify-launch-readiness.sh` (288 lines)

- **What it does** — the top-level audit. It calls (lines 117–249):
  - `verify-internal-readiness-evidence.sh` on the internal report,
  - `verify-devnet-evidence.sh` on the devnet report,
  - `verify-testnet-staging-preflight.sh` on the preflight report,
  - `verify-example-matrix.sh` (and indirectly
    `verify-silverscript-artifacts.sh`),
  - `cargo tree --workspace --all-features` and asserts neither
    `rgb-core` nor `rgb-lib` is a dependency (lines 93–115),
  - and if `target/rgk-testnet-staging-evidence/latest.txt` exists,
    `verify-testnet-staging-evidence.sh` plus the funding-readiness
    verifier.
  Emits per-gate `key=ok|failed|blocked|absent|not-run` lines and a
  final `launch_readiness=ok|blocked`. `--allow-blocked` exits `0` when
  internal is clean and only funded-testnet blockers remain (the
  `funded-public-testnet-report-*` blockers).
- **Prereqs** — bash, `cargo`, all prerequisite reports; for strict
  mode a funded public testnet report is required.
- **Invocation** — `bash scripts/verify-launch-readiness.sh
  --allow-blocked` (for local/devnet CI); `bash
  scripts/verify-launch-readiness.sh` (strict, blocks until funded
  testnet report verifies).
- **Expected success output (strict)** — exits `0` only when
  `internal_ready=1` AND `public_ready=1`. Otherwise exits `1` with
  the `launch_readiness=blocked` line and a list of failures/blockers.
- **Concept** — "launch readiness = internal green AND public testnet
  green; the `--allow-blocked` mode is the escape hatch CI uses
  before the funded testnet report exists".

#### `scripts/verify-native-terminology.sh` (60 lines)

- **What it does** — uses `rg -n -i` to scan
  `README.md CHANGELOG.md docs crates examples scripts tests` (with
  `!target/**` and `!scripts/verify-native-terminology.sh` excluded) and
  asserts that **none** of the following regexes match:
  - `\brgb\b|rgb[-_]|aluvm|tapret|opret|consignment|strict[- ]types|argent`
  - `client-side[[:space:]]+asset[[:space:]]+protocol|asset[-[:space:]]+protocol|legacy[-_[:space:]]+script`
  - `\bcell(s)?\b`
  - `RgkCovenantSeal|outpoint[-_[:space:]]+seal|…|closed[[:space:]]+(covenant|allocation|anchor|output)`
  (lines 36–55). Exits `1` on any hit.
- **Prereqs** — `rg`.
- **Invocation** — `bash scripts/verify-native-terminology.sh`.
- **Expected success output** — `[verify-native-terminology] ok`.
  Exit code `0`.
- **Concept** — "the public surface stays Kaspa-native: no RGB
  vocabulary, no `outpoint seal`, no `cell`".

#### `scripts/verify-privacy-observer-evidence.sh` (40 lines)

- **What it does** — `require_regex`-matches 14 expected lines in
  the privacy-observer report (lines 23–38): the header, the
  timestamp, the workspace path, the `rustc_version=…` /
  `cargo_version=…`, the six `test … ok` lines, the five static
  labels (`privacy_observer_default=PrivateLane`, etc.).
- **Prereqs** — a previously produced privacy-observer report.
- **Invocation** — `bash scripts/verify-privacy-observer-evidence.sh
  target/rgk-privacy-observer-evidence/latest.txt`.
- **Expected success output** — `[verify-privacy-observer-evidence]
  ok: <path>`. Exit code `0`.

#### `scripts/verify-silverscript-artifacts.sh` (114 lines)

- **What it does** — refuses to run unless
  `external/silverscript` is on commit `d25bd3427a09…` (lines 21–25).
  For every `examples/silverscript/*.sil`, runs
  `cargo run -p silverscript-lang --bin silverc -- <source> -o
  <tmp>/<id>.json`, then byte-compares with
  `examples/silverscript/artifacts/<id>.json` (or overwrites it when
  `RGK_SILVERSCRIPT_UPDATE=1`), then writes a TSV row with
  source/artifact relative paths, compiler commit, compiler version,
  `network_scope=kaspa_testnet12_only`, source SHA-256, artifact
  SHA-256, script byte length, ABI entry count. Finally
  byte-compares the assembled manifest with
  `examples/silverscript/artifacts/manifest.tsv`. (lines 56–112.)
- **Prereqs** — `python3`, `cargo`, the pinned silverscript clone,
  `shasum -a 256`.
- **Invocation** — `bash scripts/verify-silverscript-artifacts.sh`;
  `RGK_SILVERSCRIPT_UPDATE=1 bash scripts/verify-silverscript-artifacts.sh`
  to refresh the artifacts.
- **Expected success output** —
  `[verify-silverscript-artifacts] ok: examples/silverscript/artifacts/manifest.tsv
  rows=15 compiler=d25bd3427a093c17327ca3d6b9e1aa5f7688c863`. Exit
  code `0`.
- **Concept** — "every checked-in silverscript example is
  deterministically recompiled to a checked-in JSON artifact against
  a pinned compiler commit".

#### `scripts/verify-testnet-funding-readiness.sh` (70 lines)

- **What it does** — regex-matches a funding-readiness report: header,
  network, chain id, testnet URL, wallet-set id, wallet count, the
  three wallet lines (`funding/change/observer` with the exact field
  order: `address`, `xonly`, `secret_fingerprint`,
  `required_min_value_real_zk`, `required_min_value_verifier_only`,
  `purpose`), the server-identity line, the four UTXO counters, the
  funding-readiness verdict, and rejects any `secret_key` /
  `private_key` / `privkey` lines. (lines 25–67.)
- **Invocation** — `bash scripts/verify-testnet-funding-readiness.sh
  target/rgk-testnet-staging-evidence/funding-readiness.txt`.

#### `scripts/verify-testnet-staging-evidence.sh` (110 lines)

- **What it does** — refuses to run if any `test result: FAILED`,
  `panicked at`, `^test .* \.\.\. FAILED$`, `^failures:$`, or
  `command not found` is in the report (lines 25–29). Then
  `require_regex`es the wallet-set section, the preflight section,
  the live `live:` lines, and enforces cross-section invariants
  (wallet_set_id must match between wallet-set and preflight
  sections, funding-wallet address must match preflight address).
  (lines 31–108.)
- **Invocation** — `bash scripts/verify-testnet-staging-evidence.sh
  target/rgk-testnet-staging-evidence/latest.txt`.

#### `scripts/verify-testnet-staging-preflight.sh` (50 lines)

- **What it does** — 23 `require_regex` lines validating the
  preflight manifest: header, `network=testnet-(10|12)`,
  `chain_id=KaspaTestnet`, `address=kaspatest:…`,
  `scope=testnet-only deterministic staging key`,
  `wallet_set_id=0x…64hex`, `wallet_count=3`,
  `funding_status=external-funding-required`,
  `required_non_coinbase_utxo=true`, `required_utxo_index=true`,
  `required_confirmation_depth=1`, the minimum values, the
  required features, `required_local_mining=false`,
  `required_live_test=live_toccata_full_covenant_lifecycle`, the env
  vars, the staging script path, the verifier path, the expected
  report path, the `preflight_id=0x…64hex`.
- **Invocation** — `bash scripts/verify-testnet-staging-preflight.sh
  target/rgk-testnet-staging-evidence/preflight.txt`.

#### `scripts/verify-testnet-staging-wallets.sh` (51 lines)

- **What it does** — 8 `require_regex` lines for the wallet-set
  report header, network, chain id, wallet-set id, wallet count, and
  the three wallet-role lines. Then asserts exactly three
  `wallet_role=` lines, no `secret_key=…` / `private_key=…` /
  `privkey=…`, and three unique addresses.
- **Invocation** — `bash scripts/verify-testnet-staging-wallets.sh
  target/rgk-testnet-staging-evidence/wallets.txt`.

---

## 2. README "Try It" verification

The "Try It" section (README.md lines 110–134) contains four
invocation blocks. Each is verified against the actual script source.

### Block 1 — fixture mode (README.md:115)

```bash
./scripts/e2e-local.sh
```

| Check | Result | Evidence |
|---|---|---|
| Script exists | yes | `scripts/e2e-local.sh` (86 lines). |
| Path matches README | yes | identical. |
| Flag usage | n/a | no flags; default mode is `fixture`. |
| No stale reference | yes | exact line 5 of the script's header doc says the same thing ("`./scripts/e2e-local.sh  # fixture-only (no node required)`"). |

**Verdict:** current.

### Block 2 — live local Toccata (README.md:121–125)

```bash
./scripts/setup-external.sh
./scripts/build-kaspa.sh
./scripts/run-kaspa-local.sh --background
./scripts/e2e-local.sh --live
```

| Step | Check | Result | Evidence |
|---|---|---|---|
| `setup-external.sh` | exists, no required flags | yes | `scripts/setup-external.sh:13` invocation form matches. |
| `build-kaspa.sh` | exists, no required flags | yes | `scripts/build-kaspa.sh:14` invocation form matches. |
| `run-kaspa-local.sh --background` | flag is valid | yes | handled at `scripts/run-kaspa-local.sh:46`. |
| `e2e-local.sh --live` | flag is valid | yes | handled at `scripts/e2e-local.sh:29–32`; falls back to `RGK_LIVE_KASPA_URL` if unset. |

**Verdict:** current.

### Block 3 — local devnet (README.md:130)

```bash
./scripts/e2e-devnet.sh --start-kaspa
```

| Check | Result | Evidence |
|---|---|---|
| Script exists | yes | `scripts/e2e-devnet.sh` (199 lines). |
| Flag `--start-kaspa` is valid | yes | handled at `scripts/e2e-devnet.sh:26`. |

**Verdict:** current.

### Block 4 — example matrix (README.md:169)

```bash
bash scripts/verify-example-matrix.sh
```

| Check | Result | Evidence |
|---|---|---|
| Script exists | yes | `scripts/verify-example-matrix.sh`. |
| Invocation form | yes | no flags, takes optional `matrix` arg (line 8). |

**Verdict:** current.

### Stale references

None found. Every script path and every flag in the "Try It" section
maps to actual handling in the current source.

---

## 3. README "What Is Implemented" verification

The "What Is Implemented" section (README.md lines 136–179) makes the
following claims. For each, the most direct verifying test, example,
or fixture is listed; ✅ means the claim is reproducible today
(verified by file/line read of source), ⚠️ means the claim is
partially supported (some shapes, not all), ❌ means no current
evidence.

### Native path

| Claim (README) | Verifier | Status |
|---|---|---|
| `RgkAssetIssue` defines supply, allocations, proof policy, privacy policy, metadata, owner, lane id. | `crates/rgk-asset/src/native.rs:828` `pub struct RgkAssetIssue`. The state-digest fields are exercised by `native_issue_digest_stable` (line 4086), `native_issue_digest_is_allocation_order_stable` (line 4096), and `native_issue_digest_binds_metadata_and_owner_commitments` (line 4105). | ✅ |
| `RgkContinuationPlan` binds the previous allocation set + next output shape before the continuation txid exists. | `crates/rgk-asset/src/native.rs:873` `pub struct RgkContinuationPlan`; the two-phase semantics are exercised by `continuation_phase1_commitment_is_stable_without_future_txid` (line 4659) and `continuation_phase2_binds_actual_txid` (line 4699). | ✅ |
| `RgkTransition` finalizes the plan after the txid exists, spends old covenant outputs, creates new allocation outputs, binds ordered inputs/outputs/policy/privacy/lane_id/witness txid. | `crates/rgk-asset/src/native.rs:842` `pub struct RgkTransition`; `continuation_finalization_spends_old_anchor_and_creates_new_anchor` (line 4670), `continuation_phase2_binds_actual_txid` (line 4699), `native_transition_binds_authorized_ownership_handoff` (line 4510), `native_transition_digest_stable` (line 4647), `native_transition_digest_binds_mutations` (line 4872). | ✅ |
| `RgkReceipt` is the typed statement consumed by the covenant, indexer, resolver. | `crates/rgk-core/src/types.rs:192` `pub struct RgkReceipt`; the fixture e2e path `tests/rgk-e2e/src/lib.rs:472` calls `ReceiptBuilder::build` and `ReceiptVerifier::verify_local`. | ✅ |
| `RgkResolver` classifies live evidence as valid, invalid, replayed, competing, unconfirmed, reorg risk. | `crates/rgk-resolver/src/lib.rs:43–108` `pub enum ResolverState` enumerates `Open`, `NativeTransitionedValid`, `NativeTransitionedInvalid`, `Unconfirmed`, `ReorgRisk`, `CompetingBranch`, `PolicyMigrationRequired`, `ReplayRejected`, `Unknown`, `NodeDown`. Each is exercised by a dedicated test: `transitioned_valid_uses_latest_indexed_spent_outpoint` (line 917), `transitioned_invalid_when_continuation_proof_is_missing` (line 1008), `competing_branch_when_continuation_txid_does_not_match_observed_spend` (line 1057), `competing_branch_when_observed_spend_disagrees_with_indexed_transition` (line 1115), `policy_migration_required_when_indexed_transition_changes_receipt_policy` (line 1178). | ✅ |
| Wallet allocation strategy planning selects fixed allocation-vector proofs for evidenced shapes or segmented allocation-audit certificates for larger conserving full-state transfers, with native strategy commitments, canonical strategy-record handoff bytes, and fail-closed burn/empty-side checks. | `production_allocation_strategy_selects_fixed_and_segmented_paths` (`crates/rgk-asset/src/native.rs:3744`), `segmented_allocation_strategy_requires_conserving_nonempty_sides` (line 3789), `production_allocation_strategy_commitment_binds_counts_and_segment_grid` (line 3814), `production_allocation_strategy_record_round_trips_and_rejects_tamper` (line 3856); the `AllocationAuditCertificate` plumbing lives at `crates/rgk-zk/src/real_zk.rs:1548`. | ✅ |

### ZK and audit surface

| Claim (README) | Verifier | Status |
|---|---|---|
| Receipt and semantic transition statements. | `rgk_receipt_groth16_proof_executes_in_upstream_toccata_vm` (`tests/rgk-e2e/tests/zk_precompile_vm.rs:1045`) and `rgk_semantic_groth16_proof_executes_in_upstream_toccata_vm` (line 1060). The semantic statement type is `rgk_zk::SemanticTransitionStatement`, imported in `tests/rgk-e2e/src/lib.rs:66`. | ✅ |
| Lane discovery and segmented private-lane graph proofs. | `rgk_lane_discovery_groth16_proof_executes_in_upstream_toccata_vm` (line 1075), `rgk_lane_graph_discovery_groth16_proof_executes_in_upstream_toccata_vm` (line 1090), `rgk_lane_graph_segment_groth16_proof_executes_in_upstream_toccata_vm` (line 1105). Production sides are `prove_then_verify_lane_discovery`, `prove_then_verify_lane_graph_discovery`, `prove_then_verify_lane_graph_segment` at `crates/rgk-zk/src/real_zk.rs:7377`, `7476`, `7589`. | ✅ |
| Terminal `1x0` burn plus `1x1`, `2x2`, `3x2`, `4x2`, `4x4` allocation vector proofs. | `production_zk_allocation_shape_policy_is_native_and_exact` (`crates/rgk-asset/src/native.rs:3557`) asserts the exact set `{1x0, 1x1, 2x2, 3x2, 4x2, 4x4}`. Per-shape VM tests: `rgk_allocation_1x1_…` (line 1183), `…_2x2_…` (line 1198), `…_3x2_…` (line 1213), `…_4x2_…` (line 1228), `…_4x4_…` (line 1243); corresponding production ZK tests `prove_then_verify_allocation_1x1_burn_transition` (`crates/rgk-zk/src/real_zk.rs:8497`), `prove_then_verify_allocation_1x0_terminal_burn_transition` (line 8516), `prove_then_verify_allocation_2x2_transition` (line 8616), plus the fungible multi-output / multi-input / batch tests at `crates/rgk-asset/src/native.rs:3913`, `3950`, `3993`, `4037`. | ✅ |
| Segmented allocation transcript, conservation, final equality, and exclusion proofs. | `rgk_allocation_transcript_segment_groth16_proof_executes_in_upstream_toccata_vm` (`tests/rgk-e2e/tests/zk_precompile_vm.rs:1120`), `…_allocation_conservation_segment_…` (line 1136), `…_allocation_conservation_final_…` (line 1152), `…_allocation_exclusion_segment_pair_…` (line 1168); production sides at `crates/rgk-zk/src/real_zk.rs:7711`, `7861`, `8009`, `8089`. | ✅ |
| Allocation audit bundle and canonical allocation audit certificate handoff. | `allocation_audit_certificate_canonical_encoding_round_trips` (`crates/rgk-zk/src/real_zk.rs:8340`), `…_canonical_self_contained_verifies` (line 8377), `…_self_contained_rejects_rebound_tampers` (line 8403), `…_rejects_tampered_stack_material` (line 8451), `…_binds_verified_groth16_stack_material` (line 8320). The `AllocationAuditCertificate` struct is at `crates/rgk-zk/src/real_zk.rs:1548`. | ✅ |
| `RGK does not claim one recursive proof for arbitrary-size allocation vectors` | True by construction — `RgkAllocationProofShape::from_counts(1, 2)` returns `None` (line 3599), and the strategy explicitly falls through to a segmented audit certificate for larger transfers (`production_allocation_strategy_selects_fixed_and_segmented_paths`, `crates/rgk-asset/src/native.rs:3744`). | ✅ (negative claim) |

### Public testnet / mainnet staging

| Claim (README) | Verifier | Status |
|---|---|---|
| Public testnet/mainnet staging is still gated on a funded public run and a verified report. | `scripts/e2e-testnet-staging.sh` requires either an env-supplied wRPC URL or `--funding-readiness`; `verify-launch-readiness.sh` records the funded-testnet report as a blocker when missing (lines 245–248). The `public_testnet_funded_report=blocked` and `public_testnet_funding_status=blocked` lines are the gate. | ✅ (gate enforced, no funded report) |
| The launch readiness verifier covers internal-readiness, local/devnet, public-staging preflight, and optional funding-readiness gates. | `scripts/verify-launch-readiness.sh:117–249` runs `verify-internal-readiness-evidence.sh`, `verify-devnet-evidence.sh`, `verify-testnet-staging-preflight.sh`, `verify-example-matrix.sh`, plus optional funding-readiness and funded-testnet verifiers. | ✅ |
| Strict mode remains non-zero until the funded public testnet report verifies. | `verify-launch-readiness.sh:277–286` exits `1` when `internal_ready=1 && public_ready=0`, even with `--allow-blocked`. | ✅ |

### Examples matrix

| Claim (README) | Verifier | Status |
|---|---|---|
| `bash scripts/verify-example-matrix.sh` is the maintained coverage surface. | `examples/contract-matrix.tsv` (14 lines = 1 header + 13 rows). Current `rows=13` is asserted by both the shell script (`scripts/verify-example-matrix.sh:105`) and the in-process test (`tests/rgk-e2e/tests/example_matrix.rs:57`). | ✅ |

---

## 4. E2E coverage matrix

Each scenario below maps to a test file, an invocation, and the
observable output a learner should look for.

### 4.1 `tests/rgk-e2e/` fixtures (no live node)

| Scenario | Test file:line | Invocation | Expected observable |
|---|---|---|---|
| Fixture-only full e2e flow (issue → plan → transition → receipt → spend → continuation → resolver valid) | `tests/rgk-e2e/src/lib.rs:472` `fixture_e2e_passes` | `cargo test -p rgk-e2e --lib fixture_e2e_passes` or simply `./scripts/e2e-local.sh` | The test passes silently; the `run_e2e_fixture` helper prints `E2eSummary { … }` containing `chain`, `proof_mode = VerifierReceipt`, and a `resolver_state` matching `Open` / `NativeTransitionedValid` / `ReorgRisk`. |
| Canonical state digest is deterministic | `tests/rgk-e2e/src/lib.rs:891` | `cargo test -p rgk-e2e --lib canonical_state_digest_is_deterministic` | passes silently. |
| Policy migration survives a sled reopen | `tests/rgk-e2e/src/lib.rs:882` `policy_migration_recovery_fixture_survives_reopen` | `cargo test -p rgk-e2e --lib --features persistent-indexer policy_migration_recovery_fixture_survives_reopen` | The recovery summary renders with `resolver: NativeTransitionedValid`. |
| Testnet staging wallet set is stable | `tests/rgk-e2e/src/lib.rs:950` | `cargo test -p rgk-e2e --lib --features live-kaspa-wrpc testnet_staging_wallet_set_is_stable` | passes silently. |
| Testnet staging preflight manifest is stable | `tests/rgk-e2e/src/lib.rs:1040` | `cargo test -p rgk-e2e --lib --features live-kaspa-wrpc testnet_staging_preflight_manifest_is_stable` | passes silently. |
| Testnet staging preflight rejects unsupported network | `tests/rgk-e2e/src/lib.rs:1089` | `cargo test -p rgk-e2e --lib --features live-kaspa-wrpc testnet_staging_preflight_rejects_unsupported_network` | passes silently. |
| Example matrix is grounded in current evidence | `tests/rgk-e2e/tests/example_matrix.rs:11` | `cargo test -p rgk-e2e --test example_matrix` | passes silently. |

### 4.2 `tests/rgk-e2e/tests/covenant_script_vm.rs` (real RGK covenant scripts, in-process VM)

The whole file is `#[test]`-gated and requires the `live-kaspa-wrpc`
feature for the `real-zk` cases. Each entry below is one scenario.

| Scenario | Test file:line | Invocation | Expected observable |
|---|---|---|---|
| RGK covenant script executes in upstream Toccata VM | `covenant_script_vm.rs:315` `covenant_spec_script_executes_in_upstream_vm` | `cargo test -p rgk-e2e --test covenant_script_vm covenant_spec_script_executes_in_upstream_vm` | `vm.execute()` returns `Ok(())`. |
| Continuation policy script accepts a 1→2 fanout with explicit change | line 329 | `… covenant_spec_policy_script_accepts_fanout_with_explicit_change_output` | `Ok(())`. |
| Continuation policy script rejects a missing declared continuation output | line 348 | `… covenant_spec_policy_script_rejects_missing_declared_continuation_output` | Error string contains `VerifyError`. |
| Shared policy script accepts a 2-input merge with change | line 371 | `… covenant_shared_policy_script_accepts_two_input_merge_with_change_output` | `Ok(())` for both `input_index ∈ {0,1}`. |
| Shared policy script accepts a 2-in/2-out batch with change | line 398 | `… covenant_shared_policy_script_accepts_two_input_two_output_batch_with_change` | `Ok(())`. |
| Shared policy script rejects missing shared covenant output | line 426 | `… covenant_shared_policy_script_rejects_missing_shared_covenant_output` | Error contains `VerifyError`. |
| Covenant script rejects a wrong contract payload | line 456 | `… covenant_spec_script_rejects_wrong_contract_payload` | Error contains `VerifyError`. |
| Groth16-precompiled covenant script executes in upstream VM (real-zk) | line 478 (gated on `real-zk`) | `cargo test -p rgk-e2e --features live-kaspa-wrpc,real-zk --test covenant_script_vm covenant_spec_script_with_groth16_precompile_executes_in_upstream_vm` | `used_script_units < ComputeBudget(2_500).allowed_script_units()`. |

### 4.3 `tests/rgk-e2e/tests/zk_precompile_vm.rs` (Grothen16 / R0 precompile scripts)

Run with `cargo test -p rgk-e2e --features
live-kaspa-wrpc,real-zk --test zk_precompile_vm <name>`. Each passes
silently and prints a `[zk-precompile-vm] …` line with
`public_inputs / vk_bytes / proof_bytes / script_bytes`.

| Scenario | Test file:line | Concept |
|---|---|---|
| R0 Succinct fixture executes in upstream VM | line 1018 | Toccata R0 Succinct stack material. |
| R0 Succinct fixture rejects a changed journal | line 1032 | tamper rejection. |
| RGK receipt Groth16 proof executes | line 1045 | receipt-side ZK. |
| RGK semantic transition Groth16 proof executes | line 1060 | semantic-side ZK. |
| RGK lane-discovery Groth16 proof executes | line 1075 | private-lane scan tag proof. |
| RGK lane-graph discovery Groth16 proof executes | line 1090 | graph proof. |
| RGK lane-graph segment Groth16 proof executes | line 1105 | segmented graph chain. |
| RGK allocation transcript segment Groth16 proof executes | line 1120 | transcript segment. |
| RGK allocation conservation segment Groth16 proof executes | line 1136 | conservation segment. |
| RGK allocation conservation final Groth16 proof executes | line 1152 | final conservation. |
| RGK allocation exclusion segment-pair Groth16 proof executes | line 1168 | exclusion pair. |
| RGK allocation 1x1 Groth16 proof executes | line 1183 | smallest fixed shape. |
| RGK allocation 2x2 Groth16 proof executes | line 1198 | multi-output fanout. |
| RGK allocation 3x2 Groth16 proof executes | line 1213 | multi-input merge. |
| RGK allocation 4x2 Groth16 proof executes | line 1228 | larger merge (also exercised in `e2e-devnet.sh`). |
| RGK allocation 4x4 Groth16 proof executes | line 1243 | batch transfer (also exercised in `e2e-devnet.sh`). |

### 4.4 `tests/rgk-e2e/tests/live_kaspa.rs` (live simnet wRPC round trip)

Gated behind `live-kaspa-wrpc`. The simnet must be running and
`RGK_LIVE_KASPA_URL` must point at its Borsh wRPC.

| Scenario | Test file:line | Invocation | Expected observable |
|---|---|---|---|
| `get_block_dag_info` round-trip | `live_kaspa.rs:127` | `cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_kaspa live_simnet_get_block_dag_info_round_trip` | `eprintln!` of `block_count header_count virtual_daa_score pruning_point_hash`. |
| `get_server_info` reports Toccata | line 148 | `… live_simnet_get_server_info_reports_toccata` | `eprintln!` of `server_version network_id is_synced has_utxo_index`; asserts `server_version.contains("toc")` and `has_utxo_index`. |
| Garbage covenant tx is rejected by validator | line 177 | `… live_simnet_covenant_tx_submission_reaches_validator` | The error string is non-empty, non-transport; the node accepted-then-validated our tx. |

### 4.5 `tests/rgk-e2e/tests/live_devnet.rs` (Toccata devnet + persistent indexer)

Run with `cargo test -p rgk-e2e --features live-kaspa-wrpc
[--features persistent-indexer] --test live_devnet` and
`RGK_LIVE_DEVNET_URL` set.

| Scenario | Test file:line | Expected observable |
|---|---|---|
| Devnet node identity is Toccata | `live_devnet.rs:80` | `live-devnet: server_version=… network_id=devnet … has_utxo_index=true`; `TX_VERSION_TOCCATA == 1`. |
| Persistent scan cursor initialises and reopens | line 122 | `live-devnet: scan cursor initialised chain=KaspaDevnet daa=…`. |

### 4.6 `tests/rgk-e2e/tests/live_covenant.rs` (full lifecycle)

| Scenario | Test file:line | Invocation | Expected observable |
|---|---|---|---|
| Live Toccata tx config defaults to native / zero gas | `live_covenant.rs:691` | `cargo test -p rgk-e2e --features live-kaspa-wrpc --test live_covenant live_toccata_tx_config_defaults_to_native_zero_gas` | passes silently. |
| Live Toccata tx config accepts a non-zero-gas user lane | line 701 | `… live_toccata_tx_config_accepts_user_lane_non_zero_gas` | passes silently. |
| Live Toccata tx config rejects reserved / zero-gas / user lane with prefix `[2,…]` | line 712 | `… live_toccata_tx_config_rejects_reserved_or_zero_gas_user_lane` | passes silently. |
| User lane namespace parser handles `00000100` / `0x00000100` / `0X00000100` | line 719 | `… live_toccata_tx_config_parses_namespace_hex` | passes silently. |
| Full Toccata covenant lifecycle | line 730 `live_toccata_full_covenant_lifecycle` | `cargo test -p rgk-e2e --features live-kaspa-wrpc,persistent-indexer,real-zk --test live_covenant live_toccata_full_covenant_lifecycle` | `live: resolver state = NativeTransitionedValid`, plus a long `live: …` log describing covenant funding, P2SH spend, ZK precompile, segmented allocation audit, lane discovery, and persistent indexer recovery. This is the single test that `e2e-devnet.sh` and `e2e-testnet-staging.sh` both run in their final step. |

### 4.7 `scripts/e2e-*.sh` (the script-level e2e harnesses)

| Scenario | Script | Invocation | Observable concept |
|---|---|---|---|
| Fixture-only end-to-end | `e2e-local.sh` | `./scripts/e2e-local.sh` | "Run the full RGK flow without a node." |
| Live local Toccata simnet | `e2e-local.sh` | `./scripts/e2e-local.sh --live` | "Same flow, but the receipts and spends are checked against a real Toccata kaspad." |
| Local Toccata devnet with full coverage roll | `e2e-devnet.sh` | `./scripts/e2e-devnet.sh --start-kaspa` | "All claimed shapes have live devnet evidence under `target/rgk-devnet-evidence/latest.txt`." |
| Public testnet preflight (no node) | `e2e-testnet-staging.sh` | `bash scripts/e2e-testnet-staging.sh --preflight` | "What the funded testnet run will need: funding address, minimum value, network, etc." |
| Public testnet funding-readiness probe | `e2e-testnet-staging.sh` | `RGK_LIVE_KASPA_URL=wss://… bash scripts/e2e-testnet-staging.sh --funding-readiness` | "Is the funding UTXO actually live on the testnet?" |
| Public testnet full run | `e2e-testnet-staging.sh` | `RGK_LIVE_KASPA_URL=wss://… bash scripts/e2e-testnet-staging.sh` | "Public testnet with funding; the only run that drives the launch-readiness `public_testnet_funded_report=ok` line." |
| Privacy observer evidence roll | `e2e-privacy-observer.sh` | `bash scripts/e2e-privacy-observer.sh` | "The public observer boundary is observable-only-on-commitments." |
| Internal readiness roll | `e2e-internal-readiness.sh` | `bash scripts/e2e-internal-readiness.sh` | "The local launch checklist." |

---

## 5. Quality gates

Each gate below appears in the README "Quality Checks" section (lines
199–224) or in the surrounding scripts. "Who runs it" is from the
README's grouping.

| Gate | What it gates | Who runs it | Cost |
|---|---|---|---|
| `cargo fmt --all -- --check` | Format-only check; fails on any diff. | Every PR (per README). | Seconds. |
| `cargo test -p rgk-asset` | The native-asset grammar (issue, transition, continuation, allocation, burn, NFT, ownership, lane). | Every PR (per README). | Seconds. |
| `cargo test -p rgk-e2e --lib` | Fixture-mode full e2e + canonical state digest + policy-migration recovery + example matrix. | Every PR (per README). | Seconds. |
| `cargo clippy -p rgk-asset --all-targets --all-features -- -D warnings` | Asset crate clippy under all features. | Every PR (per README). | Seconds to a minute. |
| `cargo test --workspace --no-default-features` | Every crate compiles and tests under `no_std` (modulo `std` features). | Pre-release (per README). | Tens of seconds. |
| `cargo test --workspace --all-features` | Every crate compiles and tests under all features. | Pre-release (per README). | Tens of seconds. |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps` | Doc warnings are errors. | Pre-release (per README). | Tens of seconds. |
| `bash scripts/e2e-privacy-observer.sh` | Privacy-observer evidence roll. | Pre-release (per README). | Tens of seconds (no node). |
| `bash scripts/verify-privacy-observer-evidence.sh` | Verifies the produced report. | Pre-release (per README). | Sub-second. |
| `bash scripts/e2e-internal-readiness.sh` | 21-gate local readiness roll. | Pre-release (per README). | Several minutes (workspace all-features + clippy + rustdoc). |
| `bash scripts/verify-internal-readiness-evidence.sh` | Verifies the internal report. | Pre-release. | Sub-second. |
| `bash scripts/verify-silverscript-artifacts.sh` | Recompile every silverscript example against the pinned compiler and byte-compare. | Pre-release. | One-time `silverc` compile + seconds. Requires `external/silverscript` clone. |
| `bash scripts/verify-example-matrix.sh` | Verifies the TSV is current. | Pre-release. | Seconds. |
| `./scripts/e2e-devnet.sh --start-kaspa` | Full devnet coverage roll. | Pre-release / launch (per README). | Several minutes plus a devnet kaspad build. |
| `bash scripts/verify-launch-readiness.sh --allow-blocked` | The audit that ties them all together. | Pre-release (per README, the `--allow-blocked` mode is the documented local-CI form). | Seconds (it only reads previously produced reports). |

> **Notes on the "who runs it" column.** The README puts the first four
> commands in a "focused protocol change" block and the remainder in a
> "broader gates" block. There is no public CI config file in the repo
> (no `.github/workflows/`, no `.gitlab-ci.yml`); the "every PR" column
> should be read as the README's recommended local CI subset, not as a
> declarative CI policy.

> **The "verify-*evidence*.sh" gate family** is the only place where
> "what we already produced" is enforced as a contract. If the upstream
> report is deleted, the gate fails; if a test was renamed without
> updating the regex, the gate fails. This is by design.

---

## 6. Proposed tutorial scenario candidates

Ordered beginner → advanced. Each scenario ties to a real runnable
action with a single demo anchor.

### 6.1 Beginner — the fixture flow

1. **"Hello, RGK" — run the fixture e2e.** Anchor:
   `./scripts/e2e-local.sh` (default mode). Learners see the
   `cargo test -p rgk-e2e --lib` invocation, the `OK` line at the end,
   and the `fixture_e2e_passes` test name in the output. Outcome: "a
   receipt validated a transition that a resolver confirmed without
   any Kaspa node". Concept: *the entire RGK protocol is
   fixture-replayable; the live node is not where the validation
   logic lives*.

2. **"What does the example matrix actually prove?"** Anchor:
   `bash scripts/verify-example-matrix.sh`. Learners see the script
   emit `rows=13`, the `require_regex` for every `local_evidence`
   token, and `ok` on success. Pair with
   `cargo test -p rgk-e2e --test example_matrix` (a Rust-level
   duplicate of the same check). Outcome: "the 13 example rows
   aren't a wishlist — every `local_evidence` regex is required to
   resolve in `crates/` or `tests/`". Concept: *the example matrix
   is the bridge between docs and tests*.

3. **"What can a public observer see on a private lane?"** Anchor:
   `bash scripts/e2e-privacy-observer.sh`. Learners see the
   `privacy_observer_default=PrivateLane`,
   `privacy_observer_learns=blinded_lane_ids,…` and
   `privacy_observer_does_not_learn=asset_id,owner,amount,…` lines,
   plus the underlying `cargo test … private_lane_public_observer_boundary_is_commitment_only`
   pass line. Pair with `bash scripts/verify-privacy-observer-evidence.sh`
   to teach the gate pattern. Outcome: "the observer sees
   commitments, not plaintext". Concept: *private-by-default is
   enforced by what is not in the broadcast*.

### 6.2 Intermediate — local node and live covenant VM

4. **"Build a Toccata-capable kaspad and start a simnet."** Anchor:
   `./scripts/setup-external.sh && ./scripts/build-kaspa.sh && ./scripts/run-kaspa-local.sh --background`.
   Learners see the `pid: <n>`, `log: <path>`, `RPC ready after Ns`
   output. Outcome: "a real `kaspad --simnet` is running". Concept:
   *Toccata is a Kaspa transaction version, not a sidechain; we
   build kaspad from the same tree it ships in*.

5. **"Run a real covenant-bearing Toccata transaction through the upstream VM."** Anchor:
   `./scripts/e2e-local.sh --live`. Learners see the
   `live_toccata_full_covenant_lifecycle` test, the
   `live: resolver state = NativeTransitionedValid` line, and the
   wRPC `submit_transaction` round trip. Outcome: "the resolver's
   `NativeTransitionedValid` state is observable against a real
   kaspad". Concept: *the resolver is the user-visible contract; the
   node is just transport*.

6. **"Watch a covenant script execute in the upstream Toccata script VM."** Anchor:
   `cargo test -p rgk-e2e --features live-kaspa-wrpc --test covenant_script_vm covenant_spec_policy_script_accepts_fanout_with_explicit_change_output`.
   Learners see the test pass and (with `-- --nocapture`) the in-VM
   `compute_commit` log. Pair with
   `covenant_spec_policy_script_rejects_missing_declared_continuation_output`
   to teach the negative case. Outcome: "the covenant script enforces
   declared continuation outputs, not arbitrary output shape".
   Concept: *RGK's covenant is shape-constrained, not just
   asset-constrained*.

7. **"Watch a Groth16 RGK receipt proof execute in the upstream Toccata VM."** Anchor:
   `cargo test -p rgk-e2e --features live-kaspa-wrpc,real-zk --test zk_precompile_vm rgk_receipt_groth16_proof_executes_in_upstream_toccata_vm`.
   Learners see the `[zk-precompile-vm] public_inputs=N vk_bytes=N
   proof_bytes=N script_bytes=N` line. Pair with
   `rgk_allocation_4x2_groth16_proof_executes_in_upstream_toccata_vm`
   to show a 4×2 fixed shape. Outcome: "Groth16 is checked inside the
   Toccata script VM, not in a separate verifier". Concept: *ZK is a
   precompile, not an oracle*.

### 6.3 Advanced — devnet, public testnet, launch readiness

8. **"Drive every claimed shape through a local Toccata devnet."** Anchor:
   `./scripts/e2e-devnet.sh --start-kaspa`. Learners see the report
   land at `target/rgk-devnet-evidence/latest.txt` and the final
   `[verify-devnet-evidence] ok: …` line. Pair with
   `bash scripts/verify-devnet-evidence.sh` to teach the regex
   contract. Outcome: "every shape the README claims is devnet-live
   and machine-checked". Concept: *one log file, ~80 regexes, full
   coverage*.

9. **"Pre-flight a public testnet run without spending any KAS."** Anchor:
   `bash scripts/e2e-testnet-staging.sh --preflight` followed by
   `bash scripts/e2e-testnet-staging.sh --wallets` and
   `bash scripts/e2e-testnet-staging.sh --print-address`. Learners
   see the deterministic funding address, the three-wallet set
   (funding/change/observer), and the preflight manifest. Outcome:
   "I can print everything I need to fund a public testnet run
   without a node". Concept: *funded public staging has a
   machine-readable contract before any KAS moves*.

10. **"Run the full internal-readiness gate locally."** Anchor:
    `bash scripts/e2e-internal-readiness.sh && bash scripts/verify-internal-readiness-evidence.sh`.
    Learners see every `<key>=ok` line and the final
    `[internal-readiness] evidence: …` / `[verify-internal-readiness-evidence] ok: …`
    pair. Pair with
    `bash scripts/verify-launch-readiness.sh --allow-blocked` to
    show how the strict mode differs. Outcome: "the local launch
    checklist is one script, machine-checked by a second script".
    Concept: *gates are not advice; they are regex-asserted output*.

---

## 7. Tutorial ordering rationale

The order is **fixtures before live, single-crate before
cross-crate, in-process VM before wRPC, devnet before public
testnet**. Tutorial 1 (fixture flow) teaches only "RGK has
unit-level e2e coverage and it is one command" — no node, no
external clone, no live network. Tutorial 2 (example matrix)
adds the *meta*-idea that the documentation is gated against the
source: every `local_evidence` regex must resolve in `crates/`.
Tutorial 3 (privacy observer) introduces the *commitment-vs-plaintext*
distinction, still without a node. Tutorial 4 builds and starts a
local simnet; the learner now has a real kaspad, so Tutorials 5–7
(against `e2e-local.sh --live`, the covenant policy VM, and the
Grothen16 precompile VM) can each assume "kaspad is running and I
can hit `ws://…18111…`". Tutorial 8 (`e2e-devnet.sh`) requires
all of Tutorial 4's kaspad building plus the silverscript clone
that `verify-silverscript-artifacts.sh` enforces, and it is the
first time the learner sees the regex-asserted evidence report.
Tutorials 9–10 step out of the network entirely: Tutorial 9
teaches the preflight-before-funding pattern (no KAS spent), and
Tutorial 10 ties every prior artifact into the
`verify-launch-readiness.sh` audit. The progression is therefore
*concepts introduced*: (T1) RGK validates in clients, not
reconstructed from chain; (T2) docs are gated against source; (T3)
privacy is commitment-only; (T4) Toccata is upstream Kaspa; (T5)
the resolver is the user contract; (T6) covenants enforce shape;
(T7) ZK is a precompile; (T8) every claimed shape is devnet-live;
(T9) public staging has a preflight; (T10) the launch gate is
regex-asserted, not advisory. Each tutorial assumes only what the
previous one established.
