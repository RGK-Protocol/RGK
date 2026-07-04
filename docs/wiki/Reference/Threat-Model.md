# Reference / Threat Model

> **Canonical source:** [`docs/SECURITY.md`](../../SECURITY.md).

RGK binds a client-side validated native asset state to a Kaspa Toccata
covenant lineage. A resolver can verify from local state and live chain
evidence that a covenant spend advanced the committed RGK state according
to the native grammar.

---

## What RGK Proves (12 items)

From [`docs/SECURITY.md` §What RGK Proves](../../SECURITY.md#what-rgk-proves):

1. Lineage continuity.
2. Output shape.
3. State advance.
4. Asset-label binding.
5. Supply accounting.
6. Covenant-output uniqueness.
7. Policy binding.
8. Replay protection.
9. Privacy mode binding.
10. Owner-control binding.
11. NFT policy binding.
12. Advanced covenant policy binding.

---

## What RGK Does NOT Prove Yet (5 items)

From [`docs/SECURITY.md` §What RGK Does Not Prove Yet](../../SECURITY.md#what-rgk-does-not-prove-yet):

1. Public testnet or mainnet operation.
2. An arbitrary one-step unbounded allocation-vector Groth16 proof.
3. Public staging evidence for continuation / policy-migration flows.
4. Arbitrary historical discovery.
5. Post-quantum security.

The same list appears in
[`docs/ZK-BOUNDARY.md`](../../ZK-BOUNDARY.md),
[`docs/ROADMAP.md`](../../ROADMAP.md),
[`docs/MAINNET-LAUNCH.md`](../../MAINNET-LAUNCH.md), and
[`docs/E2E.md`](../../E2E.md). See [Glossary §"Not Yet Proven" Items](../Glossary.md#not-yet-proven-items).

---

## Threat Model

From [`docs/SECURITY.md` §Threat Model](../../SECURITY.md#threat-model):

| Threat | Mitigation |
| --- | --- |
| Malicious covenant payload | Bounded structural checks; chain / covenant / asset id consistency. |
| Asset-label swap | `asset_id` is hash-bound to commitments; lineage formula binds it. |
| State no-op replay | No-op transitions rejected by `RgkReceipt::validate_structure`. |
| Spent covenant-output reuse | Phase-1 commitment binds the next shape; reuse is structurally impossible. |
| Supply inflation | `total_supply == sum(allocations[].amount)` enforced. |
| Proof-policy downgrade | `RgkProofPolicy::commitment()` is part of state. |
| Owner-control substitution | `RgkOwnerDescriptor` rotation across transitions. |
| NFT template or metadata substitution | NFT policy commitment bound into state. |
| Unconstrained `image_id` | Rejected at validation (`ImageIdPolicy::PolicyBranch([0;32])` etc.). |
| Receipt replay | `ReplayRejected` variant; indexer-aware verifier enforces it. |
| Reorg | `ReorgRisk` variant; `reorg_safety_depth` enforces waiting. |
| Implicit policy change | `PolicyMigrationRequired`; migration proof required. |
| RPC equivocation | `CompetingBranch` variant detects indexer/chain disagreement. |
| Private-lane scanning error | `RgkScanTag` rotates per epoch; nullifier is stable per spend. |

The full threat table is at
[`docs/SECURITY.md:90-104`](../../SECURITY.md). For adversarial scenarios
on top of this, see [Reference / Adversarial Scenarios](./Adversarial-Scenarios.md).

---

## Trust Assumptions

From [`docs/SECURITY.md` §Trust Assumptions](../../SECURITY.md#trust-assumptions):

1. Kaspa consensus.
2. Wallet validator (the holder runs an honest RGK validator).
3. Resolver honesty.
4. Local indexer integrity.
5. ZK assumptions (Groth16 soundness on BN254).

These are the minimum required trust. Anything more is an over-trust;
anything less is a missing security argument.

---

## Resolver Classifications

The 10 hard outcomes (the 13-variant state machine minus the three
lane-level variants). See
[Reference / Resolver State Machine](./Resolver-State-Machine.md) for
the full table.

---

## Privacy Claim

The default is `PrivateLane`. Outside observers see commitments, not
plaintext. The privacy-observer evidence is produced by
[`scripts/e2e-privacy-observer.sh`](../../scripts/e2e-privacy-observer.sh)
and gated by
[`scripts/verify-privacy-observer-evidence.sh`](../../scripts/verify-privacy-observer-evidence.sh).

See [Concepts / Privacy](../Concepts/Privacy.md) for the privacy modes in
detail.

---

## Cross-references

- [`docs/SECURITY.md`](../../SECURITY.md) — canonical source.
- [Reference / Adversarial Scenarios](./Adversarial-Scenarios.md) — 20
  high-complexity scenarios on top of this threat model.
- [Concepts / Resolver](../Concepts/Resolver.md).
- [Concepts / Bounded Objects](../Concepts/Bounded-Objects.md).