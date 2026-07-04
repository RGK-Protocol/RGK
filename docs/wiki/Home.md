# RGK Wiki

> **RGK — Really Good Kaspa** is a Kaspa-native covenant-lineage asset system.
> The chain only proves *that* a covenant spend happened in the right shape;
> the **RGK clients** prove *what that spend means* for the asset.
>
> *The chain is the notary. The wallet is the judge.*

---

## 30-Second Orientation

If you have 30 seconds, here is the elevator pitch:

| Question | Answer |
| --- | --- |
| What is RGK? | A Kaspa-native asset system on top of **Kaspa Toccata covenants**. |
| Who decides if a transfer is valid? | The RGK **resolver** running on every holder's wallet, against local evidence + observed chain state. |
| What does the chain store? | One small covenant payload per lineage output — *opaque commitments*, not plaintext balances. |
| What about privacy? | **Private by default.** Outside observers see commitments; only the view-key holder sees their lane. |
| Where do I start? | [Tutorial-0: 10-Minute Fixture Walkthrough](./Tutorials/Tutorial-0-10-Minute-Fixture-Walkthrough.md) — no node required. |
| Long-form intro? | [`Quant Dev / INTRODUCTION.md`](https://github.com/a19q3/quant-dev/blob/main/INTRODUCTION.md) — the narrative version (1160 lines, 14 diagrams). |

---

## How to Read This Wiki

There are four surface types, each with a clear job:

| Surface | Job | Read when… |
| --- | --- | --- |
| **Tutorials** | Numbered, end-to-end walkthroughs with runnable commands. | You want to **do** something. |
| **Concepts** | Explain a single idea from first principles, with diagrams and `file:line` references. | You want to **understand** something. |
| **Reference** | Pointers to canonical specs / threat model / audits. | You need the **exact contract**. |
| **Runbook** | Operator-facing scripts and checklists. | You are about to **run** something. |

Plus:

- **[Glossary](./Glossary.md)** — domain-separated tags, hot-path types,
  supported allocation shapes, the constant `32`.
- **[recon/](./recon/RECON-CODEBASE.md)** — read-only reconnaissance
  (codebase / docs / runtime) that backs every other page. If a tutorial
  seems to disagree with the source, the recon wins.

---

## Tutorials

| # | Page | What you'll do | Time |
| --- | --- | --- | --- |
| **0** | [10-Minute Fixture Walkthrough](./Tutorials/Tutorial-0-10-Minute-Fixture-Walkthrough.md) | Run the fixture harness, read the e2e summary, look at every resolver state. | 10 min |
| **1** | [What RGK Actually Is](./Tutorials/Tutorial-1-What-RGK-Actually-Is.md) | Read the philosophy, the lineage-first identity, the chain-as-notary stance. | 20 min |
| **2** | [Build, Verify, and Resolve a Receipt](./Tutorials/Tutorial-2-Receipts.md) | Issue → transfer → receipt → resolver classification in code. | 30 min |
| **3** | [Integrate a Wallet](./Tutorials/Tutorial-3-Integrate-A-Wallet.md) | The 7-step Issue and 10-step Transfer procedures. | 45 min |
| **4** | [Run the E2E Harness](./Tutorials/Tutorial-4-Run-E2E-Harness.md) | Local fixture → live simnet → local devnet → public testnet staging. | varies |
| **5** | [Operate rgk-walletd](./Tutorials/Tutorial-5-Operate-Walletd.md) | The Avato frontend's local HTTP boundary. | 30 min |

---

## Concepts

| Page | What it explains |
| --- | --- |
| [Architecture](./Concepts/Architecture.md) | Crate map, layer boundaries, where `rgk-walletd` fits. |
| [Identity](./Concepts/Identity.md) | `lineage_id` formula, `asset_id` as label, lineage vs contract id. |
| [Continuation](./Concepts/Continuation.md) | The two-phase model that sidesteps the chicken-and-egg txid problem. |
| [Resolver](./Concepts/Resolver.md) | The 13-state machine, with worked transitions for each. |
| [Privacy](./Concepts/Privacy.md) | `PublicLineage` vs `PrivateLane` vs `StealthLane`. |
| [Bounded Objects](./Concepts/Bounded-Objects.md) | The 32-byte invariants and `MAX_BLOB_BYTES` bound. |
| [Production Allocation Strategy](./Concepts/Production-Allocation-Strategy.md) | Fixed Groth16 shapes vs segmented audit certificates. |
| [Walletd Boundary](./Concepts/Walletd-Boundary.md) | What `rgk-walletd` does and (importantly) doesn't do today. |
| [Funding](./Concepts/Funding.md) | The public testnet staging funding flow end-to-end. |

---

## Reference

| Page | Backing doc |
| --- | --- |
| [Resolver State Machine](./Reference/Resolver-State-Machine.md) | [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) |
| [Covenant Spec](./Reference/Covenant-Spec.md) | [`docs/COVENANT-SPEC.md`](../COVENANT-SPEC.md) |
| [Receipt Spec](./Reference/Receipt-Spec.md) | [`docs/RECEIPT-SPEC.md`](../RECEIPT-SPEC.md) |
| [Lane Calculus](./Reference/Lane-Calculus.md) | [`docs/LANE-CALCULUS.md`](../LANE-CALCULUS.md) |
| [Threat Model](./Reference/Threat-Model.md) | [`docs/SECURITY.md`](../SECURITY.md) |
| [ZK Boundary](./Reference/ZK-Boundary.md) | [`docs/ZK-BOUNDARY.md`](../ZK-BOUNDARY.md) |
| [ZK Proof Plan](./Reference/ZK-Proof-Plan.md) | [`docs/ZK-PROOF-PLAN.md`](../ZK-PROOF-PLAN.md) |
| [Adversarial Scenarios](./Reference/Adversarial-Scenarios.md) | [`docs/ADVERSARIAL-SCENARIOS.md`](../ADVERSARIAL-SCENARIOS.md) |
| [Roadmap](./Reference/Roadmap.md) | [`docs/ROADMAP.md`](../ROADMAP.md) |
| [Status](./Reference/Status.md) | the current revision table |
| [Testnet Staging Snapshot](./Reference/Testnet-Staging-Snapshot.md) | [`docs/TESTNET-STAGING-REPORT.md`](../TESTNET-STAGING-REPORT.md) |
| [Unsafe Audit](./Reference/Unsafe-Audit.md) | [`docs/UNSAFE-AUDIT.md`](../UNSAFE-AUDIT.md) |
| [API Stability Policy](./Reference/API-Stability-Policy.md) | [`docs/API-DEPRECATION.md`](../API-DEPRECATION.md) |
| [API Surface Audit](./Reference/API-Surface-Audit.md) | [`docs/audits/public-api-surface.md`](../audits/public-api-surface.md) |

---

## Runbook

| Page | Backing doc |
| --- | --- |
| [E2E](./Runbook/E2E.md) | [`docs/E2E.md`](../E2E.md) |
| [Launch Gates](./Runbook/Launch-Gates.md) | [`docs/MAINNET-LAUNCH.md`](../MAINNET-LAUNCH.md) |
| [Funding](./Runbook/Funding.md) | [`docs/TESTNET-STAGING-REPORT.md`](../TESTNET-STAGING-REPORT.md) |

---

## Three Surfaces, One Source

The wiki does not duplicate the long-form essay in [`Quant Dev / INTRODUCTION.md`](https://github.com/a19q3/quant-dev/blob/main/INTRODUCTION.md) or the technical specs in `docs/`. The division of labor is:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Quant Dev / INTRODUCTION.md                                        │
│  The narrative: philosophy, privacy scenarios, compliance, the      │
│  RGK + Kurrent channel roadmap.                                     │
└─────────────────────────────────────────────────────────────────────┘
                              ↓ links to
┌─────────────────────────────────────────────────────────────────────┐
│  docs/ (ARCHITECTURE, RECEIPT-SPEC, LANE-CALCULUS, …)                │
│  The canonical sources: exact structs, byte layouts, threat model.  │
└─────────────────────────────────────────────────────────────────────┘
                              ↓ organised by
┌─────────────────────────────────────────────────────────────────────┐
│  docs/wiki/ (this)                                                  │
│  The navigation + tutorial surface: how to do things, when to      │
│  read what, where the gaps are.                                     │
└─────────────────────────────────────────────────────────────────────┘
```

Three roles. Drift only happens if you change a boundary.

---

## Reconnaissance (read-only)

If you are extending the wiki or auditing a claim, the recon/ directory holds
three file-by-file inventories that ground every tutorial in a `file:line`
reference:

- [`recon/RECON-CODEBASE.md`](./recon/RECON-CODEBASE.md) — workspace map,
  public API surface, runnable examples, drift notes (1096 lines).
- [`recon/RECON-DOCS.md`](./recon/RECON-DOCS.md) — per-file map of every
  existing `docs/` artifact, gap analysis, contradiction register (1526 lines).
- [`recon/RECON-RUNTIME.md`](./recon/RECON-RUNTIME.md) — every executable
  action RGK exposes, with prereqs and expected output (924 lines).

> If a tutorial, a `docs/` file, and the recon all agree — that is the
> source of truth. If only one of them is fresh, treat it as untrusted
> until the other two catch up.