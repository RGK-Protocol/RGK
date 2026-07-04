# Tutorial 0 — 10-Minute Fixture Walkthrough

!!! info "At a glance"
    **Difficulty:** Beginner · **Time:** 10 min · **Node required:** No ·
    **You'll see:** the resolver classify a real transition as
    `NativeTransitionedValid` and the canonical e2e summary block.

> **Goal.** In 10 minutes, run the RGK fixture harness end-to-end, see the
> resolver classify a transition as `NativeTransitionedValid`, and walk away
> knowing exactly which crate each result came from.
>
> **No node required.** This uses the `FixtureBackend` in `rgk-kaspa`, not a
> live Kaspa node. Live runs are covered in [Tutorial-4](./Tutorial-4-Run-E2E-Harness.md).

---

## What You'll Build / See

By the end of this tutorial you will have:

- Run the RGK fixture harness against `FixtureBackend`.
- Read a canonical `RGK e2e summary` block — every field decoded.
- Located one test per `ResolverState` variant in the source.
- Run the privacy-observer evidence producer + verifier.

No file edits. No chain connection. No funds. Just `cargo test`.

---

## Prerequisites (30 seconds)

- Rust 1.82+ (`rustc --version`)
- The `rgk` repo checked out (`/Users/arthur/RustroverProjects/rgk`)
- Nothing else — no Kaspa node, no wallet, no funds

---

## Step 1 — Run the fixture harness (3 minutes)

```bash
cd /Users/arthur/RustroverProjects/rgk
cargo test -p rgk-e2e --lib
```

You should see something like:

```text
running N tests
test fixture_e2e_passes ... ok
test native_asset_state_report ... ok
test native_transition_rejects_supply_inflation_and_deflation ... ok
test native_issue_rejects_supply_mismatch ... ok
... (28 tests)
test result: ok. N passed; 0 failed
```

What this just did:

- Built 11 crates + the `rgk-e2e` test crate
- Created an in-memory `FixtureBackend` (a fake Kaspa node at
  `crates/rgk-kaspa/src/lib.rs:345-350`)
- Built a private-lane fungible RGK asset
- Built a 1×1 continuation plan, finalized it, generated a receipt, applied
  the spend through the indexer, and asked the resolver to classify it

Total time on a modern laptop: ~2–3 minutes (most of it is compilation).

---

## Step 2 — See the canonical e2e summary (2 minutes)

The single most informative test is `fixture_e2e_passes`. To see its full
output, run:

```bash
cargo test -p rgk-e2e --lib -- --nocapture fixture_e2e_passes
```

The output is the **canonical RGK e2e summary** — the format is defined at
`tests/rgk-e2e/src/lib.rs:437-456`. It looks like this:

```text
RGK e2e summary
  chain:           KaspaLocalToccata
  covenant:        0x1111…1111
  lineage:         0xaaaa…aaaa
  asset:           0x…
  old_state:       0x…
  new_state:       0x…
  receipt_id:      0x…
  proof_mode:      verifier-receipt
  policy:          any
  transitions:     1
  resolver:        Open { … } | NativeTransitionedValid { … } | ReorgRisk { … }
  live_mode:       false
```

Every field has a meaning. Let me decode the ones you'll use most:

| Field | Source | What it tells you |
| --- | --- | --- |
| `chain` | `KaspaChainId` (`rgk-core`) | Which Kaspa network this is. A simnet receipt will not validate against mainnet. |
| `covenant` | `KaspaCovenantId` | The covenant UTXO id. The unit of identity on chain. |
| `lineage` | `lineage_id` | `H("rgk:lineage" || genesis_outpoint_payload || asset_id)` — the **canonical asset identity**. |
| `asset` | `RgkAssetId` | The label, derived from supply + commitments + allocations. |
| `old_state` / `new_state` | `RgkStateCommitment::state_digest` | The state digest **before** and **after** this transition. |
| `receipt_id` | `receipt_commitment(&receipt)` | The receipt's identity (not a chosen id, derived from canonical bytes). |
| `proof_mode` | `ProofMode` | `VerifierReceipt` for this fixture; `ZkReceipt` would carry a real Groth16 proof. |
| `policy` | `ReceiptPolicy` | The receipt-policy gate (`Any`, `VerifierOnly`, `ZkOnly`). |
| `transitions` | counter | How many transitions this fixture has applied. |
| `resolver` | `ResolverState` | The 13-variant classification. This fixture ends in `NativeTransitionedValid`. |
| `live_mode` | bool | `false` here — we're using `FixtureBackend`. |

> If any of these names don't yet mean anything, jump to
> [Concepts/Resolver](./../Concepts/Resolver.md) for the state machine or
> [Concepts/Identity](./../Concepts/Identity.md) for the lineage formula.
> Both can be read in 10 minutes.

---

## Step 3 — See every resolver state {#step-3-see-every-resolver-state}

Each resolver state has at least one test that produces it. To see them all
at once:

```bash
cargo test -p rgk-resolver --lib -- --nocapture 2>&1 | grep -E "^(test|---- )"
```

You should see ~30+ tests. The most pedagogical ones to read in source form:

| State you want to see fired | Test (file:line) | What it does |
| --- | --- | --- |
| `Open` | `crates/rgk-resolver/src/lib.rs:740` `open_when_indexed_and_utxo_present` | Sets up an open covenant with a UTXO present. |
| `NativeTransitionedValid` | `tests/rgk-e2e/src/lib.rs:678` (the e2e path) | Applies a full transition with continuation proof. |
| `NativeTransitionedInvalid` | search `crates/rgk-resolver/src/lib.rs` for the test name | Receipt / continuation proof fails structural checks. |
| `Unconfirmed` | search `crates/rgk-resolver/src/lib.rs` | Spending tx is in mempool only, not yet in a block. |
| `ReorgRisk` | search `crates/rgk-resolver/src/lib.rs` | Spend is confirmed but `depth < reorg_safety_depth`. |
| `CompetingBranch` | search `crates/rgk-resolver/src/lib.rs` | Indexer and chain disagree on the spending txid. |
| `PolicyMigrationRequired` | search `crates/rgk-resolver/src/lib.rs` | Receipt attempts a policy change without a migration proof. |
| `ReplayRejected` | search `crates/rgk-resolver/src/lib.rs` | Receipt id already accepted for this covenant. |
| `Unknown` | search `crates/rgk-resolver/src/lib.rs` | Not indexed, or outpoint pruned. |
| `NodeDown` | search `crates/rgk-resolver/src/lib.rs` | Backend unreachable or returned an error. |

Open any of them and read the first 30 lines — each is a 30-line worked
example of one state, with a fixture `FixtureBackend` and `InMemoryIndexer`.

---

## Step 4 — Look at one example with the privacy-observer lens (2 minutes)

```bash
cargo test -p rgk-asset --lib -- --nocapture \
    private_lane_public_observer_boundary_is_commitment_only
```

This test asserts that a public observer — someone with the indexer but no
view key — only sees **commitments**, not plaintext. Read the test
(`crates/rgk-asset/src/native.rs:5156`) and notice:

- The observer can see `blinded_lane_id`, `scan_tag`, `nullifier`,
  `opaque_commitments` — but not `asset_id`, owner, amount, lane graph, or
  plaintext proof policy.
- The `LanePrivacyPolicy` default is `PrivateLane`, so the test passes
  automatically; for `PublicLineage`, the test would fail (which is the
  point — opt-in disclosure).

The full evidence report from this test is produced by
`scripts/e2e-privacy-observer.sh`. Run it if you want the gated version:

```bash
bash scripts/e2e-privacy-observer.sh
bash scripts/verify-privacy-observer-evidence.sh
```

---

## Where to go next

You just saw the full pipeline in 10 minutes. Depending on what you want
next:

| If you want to… | Go to |
| --- | --- |
| Understand the philosophy / lineage-first identity | [Tutorial-1](./Tutorial-1-What-RGK-Actually-Is.md) |
| See the receipt build / verify code | [Tutorial-2](./Tutorial-2-Receipts.md) |
| Integrate a wallet (the 7-step Issue, 10-step Transfer) | [Tutorial-3](./Tutorial-3-Integrate-A-Wallet.md) |
| Run against a live Kaspa simnet or devnet | [Tutorial-4](./Tutorial-4-Run-E2E-Harness.md) |
| Operate the `rgk-walletd` daemon | [Tutorial-5](./Tutorial-5-Operate-Walletd.md) |
| Read the exact `RgkReceipt` struct and 9 invariants | [Reference / Receipt Spec](../Reference/Receipt-Spec.md) |
| Understand the 13 resolver states in depth | [Concepts / Resolver](../Concepts/Resolver.md) |

If you'd rather read than run first, start with [Tutorial-1](./Tutorial-1-What-RGK-Actually-Is.md) or jump straight to the [Glossary](../Glossary.md).