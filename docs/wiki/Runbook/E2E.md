# Runbook / E2E

> **Canonical source:** [`docs/E2E.md`](../../E2E.md).
> Recon: [`recon/RECON-RUNTIME.md`](../../recon/RECON-RUNTIME.md).

The e2e harness exercises native RGK asset state, receipts, covenants,
indexing, and resolver classification against a fixture backend or a
live Toccata node.

For the full operator walkthrough, see
[Tutorial-4: Run the E2E Harness](../Tutorials/Tutorial-4-Run-E2E-Harness.md).

---

## The Script Matrix

| Script | Talks to | Mode |
| --- | --- | --- |
| `scripts/build-kaspa.sh` | Upstream `kaspad` build | Local |
| `scripts/devnet-toccata-overrides.json` | Toccata activation + PoW skip | Local (data) |
| `scripts/e2e-local.sh` | `rgk-e2e --lib` (fixture) **or** `live_covenant` | Local |
| `scripts/e2e-devnet.sh` | Toccata-active devnet harness | Local |
| `scripts/e2e-internal-readiness.sh` | Local 21-gate launch-readiness subset | Local |
| `scripts/e2e-privacy-observer.sh` | Privacy-observer evidence producer | Local |
| `scripts/e2e-testnet-staging.sh` | Public testnet staging harness | Public testnet |
| `scripts/run-kaspa-devnet.sh` | `kaspad --devnet --override-params-file=…` | Local |
| `scripts/run-kaspa-local.sh` | `kaspad --simnet --utxoindex` | Local |
| `scripts/setup-external.sh` | Clones `kaspanet/rusty-kaspa` (Toccata branch) + `silverscript` | Local |
| `scripts/verify-avato-walletd-contract.sh` | `rgk-walletd` HTTP contract | Local |
| `scripts/verify-devnet-evidence.sh` | Regex-matches ~70 devnet markers | Local |
| `scripts/verify-example-matrix.sh` | Walks `examples/contract-matrix.tsv` | Local |
| `scripts/verify-internal-readiness-evidence.sh` | Verifies the 21-gate report | Local |
| `scripts/verify-launch-readiness.sh` | Top-level launch audit | Local / CI |
| `scripts/verify-native-terminology.sh` | No `rgb*` / "outpoint seal" / `cell` etc. | Local |
| `scripts/verify-privacy-observer-evidence.sh` | 14-field regex check | Local |
| `scripts/verify-silverscript-artifacts.sh` | Recompile + byte-compare + manifest | Local |
| `scripts/verify-testnet-funding-readiness.sh` | Public testnet funding-readiness regex | CI |
| `scripts/verify-testnet-staging-evidence.sh` | Public testnet staging regex | CI |
| `scripts/verify-testnet-staging-preflight.sh` | Preflight manifest regex | CI |
| `scripts/verify-testnet-staging-wallets.sh` | Wallet set regex (no `secret_key=`) | CI |

The full per-script detail (prereqs, invocation, expected output, exit
codes) is in
[`recon/RECON-RUNTIME.md` §1.1](../../recon/RECON-RUNTIME.md).

---

## The Local Flow (5 commands)

```bash
cargo test -p rgk-e2e --lib                                # fixture
bash scripts/e2e-internal-readiness.sh                    # 21-gate local
bash scripts/verify-internal-readiness-evidence.sh        # verifier
bash scripts/e2e-privacy-observer.sh                      # privacy-observer
bash scripts/verify-privacy-observer-evidence.sh          # privacy-observer verifier
```

Add the silverscript and example-matrix gates:

```bash
bash scripts/verify-silverscript-artifacts.sh
bash scripts/verify-example-matrix.sh
bash scripts/verify-native-terminology.sh
```

---

## The Live Flow (5 commands)

```bash
./scripts/setup-external.sh
./scripts/build-kaspa.sh
./scripts/run-kaspa-local.sh --background
./scripts/e2e-local.sh --live
./scripts/e2e-local.sh --stop-kaspa
```

Or against a devnet:

```bash
./scripts/run-kaspa-devnet.sh --background
./scripts/e2e-devnet.sh --start-kaspa
./scripts/e2e-devnet.sh --stop-kaspa
```

---

## Output Paths

- `target/rgk-internal-readiness/latest.txt`
- `target/rgk-devnet-evidence/latest.txt`
- `target/rgk-privacy-observer-evidence/latest.txt`
- `target/rgk-testnet-staging-evidence/latest.txt`

Each is the source of truth for one evidence gate.

---

## Cross-references

- [`docs/E2E.md`](../../E2E.md) — canonical runbook.
- [`recon/RECON-RUNTIME.md`](../../recon/RECON-RUNTIME.md) — every
  executable action RGK exposes.
- [Tutorial-4: Run the E2E Harness](../Tutorials/Tutorial-4-Run-E2E-Harness.md) —
  the operator walkthrough.
- [Runbook / Launch Gates](./Launch-Gates.md).
- [Runbook / Funding](./Funding.md).