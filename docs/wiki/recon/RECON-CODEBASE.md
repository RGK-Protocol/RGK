# RGK Codebase Reconnaissance

> Source-of-truth inventory for the RGK wiki tutorial series. Every claim is
> backed by a `file:line` reference. If a tutorial needs an API to look a
> certain way, it should look the way this file says it does. Drift notes are
> at the bottom.

## TL;DR

- **12 workspace members** (11 crates + 1 e2e test crate); **no `unsafe`**;
  `edition = "2021"`, `rust-version = "1.82"`.
- **Encoding version** is a consensus-level constant: `ENCODING_VERSION` at
  `rgk-core/src/lib.rs:32`. Bumping it is a breaking change.
- **5-layer architecture** (native grammar → CSV → covenant → indexer → resolver)
  + `rgk-walletd` on top.
- **14 hot-path RGK types** (see [`../Glossary.md`](../Glossary.md#hot-path-types))
  are the canonical API surface. Every tutorial and concept page is anchored
  on `file:line` references to these types.
- **13-variant `ResolverState`** with no `OptimisticValid` / `SoftInvalid`
  (design rule, not missing enum).
- **6 supported Groth16 allocation shapes**: `1x0, 1x1, 2x2, 3x2, 4x2, 4x4`.
- **20 drift notes** at the bottom of this file — read them before quoting
  the wiki anywhere.

## At a Glance

| | |
| --- | --- |
| **Repo root** | `/Users/arthur/RustroverProjects/rgk` |
| **Cargo workspace** (`Cargo.toml:1`) | 12 members (11 crates + 1 e2e test crate). |
| **Toolchain** (`Cargo.toml:20`) | `edition = "2021"`, `rust-version = "1.82"`. |
| **Encoding version** (`rgk-core/src/lib.rs:32`) | `ENCODING_VERSION` — bumping is a breaking change. |
| **No unsafe** in the workspace | every crate sets `#![forbid(unsafe_code)]` (e.g. `rgk-core/src/lib.rs:34`, `rgk-receipt/src/lib.rs:34`, `rgk-resolver/src/lib.rs:17`, `rgk-tx/src/lib.rs:33`, `rgk-walletd/src/main.rs:1`, `rgk-sync/src/lib.rs:12`). |

## How to Use This File

1. **Read the TL;DR** above. If you need more, jump to the relevant section.
2. **Quote with the line number.** Every claim is `file:line`-pinned.
3. **Check the [Drift Notes](#drift-notes) at the bottom** before treating
   anything in the wiki as authoritative.
4. **Cross-check against [`../Glossary.md`](../Glossary.md)** for the
   canonical term definitions.

---

---

## 1. Workspace Map

The workspace has 12 members (`Cargo.toml:3-16`). Grouped by responsibility:

### Core substrate (no chain deps)

| Crate | One-line role | File | Top-level public modules | Key public types |
| --- | --- | --- | --- | --- |
| `rgk-core` | Canonical wire types + domain-separated commitments. | `crates/rgk-core/src/lib.rs` | (flat) `bytes`, `chain`, `commit`, `encoding`, `error`, `policy`, `types` | `RgkAssetRef`, `RgkStateCommitment`, `RgkReceipt`, `KaspaChainId`, `KaspaOutpoint`, `ReceiptPolicy`, `ProofMode`, `ReceiptId`, `DomainTag` |
| `rgk-receipt` | Build / verify a native RGK receipt. | `crates/rgk-receipt/src/lib.rs` | (flat) | `ReceiptBuilder`, `ReceiptVerifier`, `ReceiptInput`, `ReplaySet`, `NewStateSpec`, `derive_replay_nonce`, `receipt_id_hex`, `receipt_summary` |
| `rgk-covenant` | Toccata covenant state + script + advanced policy/execution. | `crates/rgk-covenant/src/lib.rs` | (flat) | `CovenantState`, `CovenantSpec`, `CovenantContinuationPolicy`, `CovenantSharedContinuationPolicy`, `AdvancedCovenantPolicyShape`, `AdvancedCovenantExecutionEvidence`, `AdvancedCovenantExecutionPlan`, `compute_covenant_id`, `compute_covenant_id_from_lineage`, `compute_lineage_id` |
| `rgk-zk` | ZK statement, Groth16 precompile integration, R0 Succinct stack material. | `crates/rgk-zk/src/lib.rs` | (flat) | `ZkTag`, `ZkStatement`, `SemanticTransitionStatement`, `ZkProof`, `ZkReceipt`, `R0SuccinctPrecompileStack` |
| `rgk-tx` | Pure unsigned tx builders + Toccata v1 wire boundary. | `crates/rgk-tx/src/lib.rs` | (flat) | `ToccataSigHashType`, `TxOutput`, `TxInput`, `UnsignedTx`, `ToccataV1Tx`, `ToccataScriptPublicKey`, `ToccataGenesisCovenantGroup`, `build_genesis_output`, `build_transition_spend`, `build_transition_outputs`, `build_fee_output`, `validate_balanced`, `spk_from_redeem_script`, `toccata_user_lane_subnetwork` |
| `rgk-asset` | Native RGK asset grammar + lane privacy + commitment markers. | `crates/rgk-asset/src/lib.rs` | `native`, `commitments`, `lanes`, `fungible`, `nft`, `allocation_strategy`, `internal` | `RgkAssetIssue`, `RgkTransition`, `RgkContinuationPlan`, `RgkFinalizedContinuation`, `RgkIssueReport`, `RgkTransitionReport`, `RgkContinuationReport`, `RgkAllocation`, `RgkCovenantAnchor`, `RgkProofPolicy`, `LanePrivacyPolicy` (alias `RgkPrivacyPolicy`), `ImageIdPolicy`, `RgkAllocationProofShape`, `RgkLane`, `RgkLaneState`, `RgkScanTag`, `RgkNullifier`, `RgkPolicyCommitment`, NFT types, allocation-strategy types |

### Chain backend

| Crate | One-line role | File | Key public types |
| --- | --- | --- | --- |
| `rgk-kaspa` | Trait surface for any Kaspa node. | `crates/rgk-kaspa/src/lib.rs`, `crates/rgk-kaspa/src/wrpc.rs` | `KaspaScriptPublicKey`, `KaspaTip`, `KaspaTxSummary`, `KaspaUtxo`, `SpendingInfo`, `ObservedSpend`, `KaspaNetworkError`, `ResolverClassify`, `KaspaChainBackend` (trait), `KaspaWalletBackend` (trait), `FixtureBackend`; wRPC: `WrpcBackend`, `WrpcNetwork`, `WrpcVirtualChainScan` |

### Indexer / sync

| Crate | One-line role | File | Key public types |
| --- | --- | --- | --- |
| `rgk-indexer` | Replay-safe RGK state + scan cursors + observed spends. | `crates/rgk-indexer/src/lib.rs` | `IndexedCovenant`, `IndexedLane`, `SpendEntry`, `ContinuationProof`, `AllocationAuditCertificateRecord`, `ScanCursor`, `RebuildCheckpoint`, `RebuildSpend`, `RebuildPlan`, `RebuildSpendEvidence`, `ObservedSpendRecord`, `RebuildSummary`, `Indexer` (trait), `ScanCursorStore` (trait), `ObservedSpendStore` (trait), `AllocationAuditCertificateStore` (trait), `RebuildIndexer` (trait + blanket), `RebuildSource` (trait), `InMemoryIndexer`, `SledIndexer` (feature `persistent`) |
| `rgk-sync` | Restart-safe scanner driver. | `crates/rgk-sync/src/lib.rs` | `ScanBatch`, `ScanServiceConfig`, `ScanTick`, `ScanRunSummary`, `SyncError`, `ScanBackend` (trait), `ScanService`, `KaspaRebuildSource` |

### Resolver (top-level)

| Crate | One-line role | File | Key public types |
| --- | --- | --- | --- |
| `rgk-resolver` | End-to-end native resolver state machine. | `crates/rgk-resolver/src/lib.rs` | `ResolverState`, `LaneResolverState`, `TransitionResolverState`, `ResolverError`, `RgkResolver` |

### Wallets / daemons

| Crate | One-line role | File | Key public types |
| --- | --- | --- | --- |
| `rgk-walletd` | Local Avato HTTP wallet daemon. Single `main.rs` (no `lib.rs`). | `crates/rgk-walletd/src/main.rs` | Internal: `Cli`, `CliNetwork`, `AssetLane`, `PrivacyMode`, `ReceiptPolicyName`, `ProofModeName`, `ResolverStateName`, `ScanStatus`, `ScanMode`, `ProofSummary`, `DashboardSnapshot`, `ServiceMode`, `IdentityVault`, `WalletProfile`, `WalletLifecycle`, plus a full axum router at `/health`, `/wallet/profile`, `/wallets`, `/wallet/import`, `/wallet/lock`, `/wallet/unlock`, `/wallet/kaspa-endpoint`, `/wallet/sync`, `/dashboard`, `/lanes`, `/proofs`, `/transitions`. |

### E2E harness (test crate, workspace member)

| Crate | One-line role | File | Notable items |
| --- | --- | --- | --- |
| `rgk-e2e` | End-to-end harness, fixture + live modes. | `tests/rgk-e2e/src/lib.rs`, `tests/rgk-e2e/Cargo.toml` | `run_e2e_fixture`, `run_policy_migration_recovery_fixture` (feature `persistent-indexer`), `native_asset_state_report`, `native_asset_transition_report`, `native_asset_continuation_report`, `native_asset_continuation_plan`, `native_asset_allocation`, `native_continuation_note_commitment`, `TestnetStagingWalletSet` / `TestnetStagingPreflight` (feature `live-kaspa-wrpc`); bench: `local_e2e` |

**Cargo features** the workspace exposes:

- `rgk-indexer`: feature `persistent` (enables `SledIndexer`) — `crates/rgk-indexer/Cargo.toml` (not shown but referenced by `tests/rgk-e2e/Cargo.toml:65`).
- `rgk-kaspa`: features `http` (ureq JSON-RPC probe) and `wrpc` (live wRPC backend) — `crates/rgk-kaspa/src/lib.rs:11-17`.
- `rgk-sync`: feature `wrpc` (impl `ScanBackend` for `WrpcBackend`) — `crates/rgk-sync/src/lib.rs:306`.
- `rgk-zk`: feature `real-zk` (Groth16 prover/verifier) — `crates/rgk-zk/src/lib.rs:14-31`.
- `rgk-e2e`: features `live-kaspa-wrpc`, `persistent-indexer`, `real-zk` — `tests/rgk-e2e/Cargo.toml:42-66`.

---

## 2. Core Public API Surface

The types below are the **canonical tutorial targets**. For each: file path,
key fields, the constructor / builder method the wiki will teach, and the
shortest live example we have.

### 2.1 `RgkAssetIssue`

- **File**: `crates/rgk-asset/src/native.rs:827-839`
- **Fields** (all public, `Clone Debug PartialEq Eq Hash`):
  ```rust
  pub struct RgkAssetIssue {
      pub chain: KaspaChainId,         // 1
      pub schema_id: RgkSchemaId,      // 32 bytes; RGK_FUNGIBLE_ASSET_SCHEMA_ID is the default
      pub asset_id: RgkAssetId,        // 32 bytes
      pub total_supply: u64,
      pub metadata_commitment: RgkMetadataCommitment,
      pub owner_commitment: RgkOwnerCommitment,
      pub allocations: Vec<RgkAllocation>,
      pub lane_id: BlindedLaneId,
      pub privacy_policy: LanePrivacyPolicy,
      pub proof_policy: RgkProofPolicy,
  }
  ```
- **Schema id constant**: `RGK_FUNGIBLE_ASSET_SCHEMA_ID: RgkSchemaId = *b"rgk:asset:schema:v1_____________"` — `crates/rgk-asset/src/lib.rs:111`.
- **Builders / validators**:
  - `RgkAssetIssue::derive_asset_id(input: RgkAssetIdDerivation<'_>) -> Result<RgkAssetId, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1179`. This is the **only** way to mint a new `asset_id` from the supply / commitments.
  - `RgkAssetIssue::validate(&self) -> Result<RgkIssueReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1197`. Verifies structure + recomputes the state digest.
  - `RgkAssetIssue::validate_for_production_zk(&self) -> Result<RgkIssueReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1202`. Stricter: requires allocations to fit a supported ZK shape (`RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT = 4`).
  - `RgkAssetIssue::validate_against_state_digest(&self, expected) -> Result<RgkIssueReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1208`.
- **RgkAssetIdDerivation** struct (the input to `derive_asset_id`): `crates/rgk-asset/src/native.rs:808-819`.
- **Smallest construction example** (from unit tests at `crates/rgk-asset/src/native.rs:3379-3411`):
  ```rust
  // crates/rgk-asset/src/native.rs:3384
  fn issue_with_allocations(total_supply: u64, allocations: Vec<RgkAllocation>) -> RgkAssetIssue {
      let schema_id = *b"rgk:asset:schema:v1_____________";
      let policy = proof_policy();
      let asset_id = RgkAssetIssue::derive_asset_id(RgkAssetIdDerivation {
          chain: KASPA_LOCAL_TOCCATA,
          schema_id,
          total_supply,
          metadata_commitment: metadata_commitment(),
          owner_commitment: owner_commitment(),
          allocations: &allocations,
          lane_id: lane_id(),
          privacy_policy: LanePrivacyPolicy::PrivateLane,
          proof_policy: &policy,
      })
      .unwrap();
      RgkAssetIssue {
          chain: KASPA_LOCAL_TOCCATA,
          schema_id, asset_id, total_supply,
          metadata_commitment: metadata_commitment(),
          owner_commitment: owner_commitment(),
          allocations,
          lane_id: lane_id(),
          privacy_policy: LanePrivacyPolicy::PrivateLane,
          proof_policy: policy,
      }
  }
  ```

### 2.2 `RgkContinuationPlan` (phase 1)

- **File**: `crates/rgk-asset/src/native.rs:872-889`
- **Fields**:
  ```rust
  pub struct RgkContinuationPlan {
      pub chain: KaspaChainId,
      pub schema_id: RgkSchemaId,
      pub asset_id: RgkAssetId,
      pub total_supply: u64,
      pub metadata_commitment: RgkMetadataCommitment,
      pub previous_owner_commitment: RgkOwnerCommitment,
      pub new_owner_commitment: RgkOwnerCommitment,
      pub ownership_authorization_commitment: Bytes32,
      pub previous_state_digest: RgkStateDigest,
      pub spent_allocations: Vec<RgkAllocation>,
      pub new_allocation_shapes: Vec<RgkContinuationAllocationShape>,  // <-- shapes, not allocations
      pub burn: Option<RgkBurnProof>,
      pub lane_id: BlindedLaneId,
      pub privacy_policy: LanePrivacyPolicy,
      pub proof_policy: RgkProofPolicy,
  }
  ```
- **Builders / validators**:
  - `RgkContinuationPlan::validate(&self) -> Result<RgkContinuationReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1476`. Returns the **phase-1 commitment** (no future txid required).
  - `RgkContinuationPlan::validate_for_production_zk(&self) -> Result<RgkContinuationReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1481`. Stricter: spent/new counts must be in `RGK_ALLOCATION_STRATEGY_ZK_SHAPES`.
  - `RgkContinuationPlan::into_production_zk_transfer_plan(self) -> Result<RgkProductionZkTransferPlan, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1490`.
  - `RgkContinuationPlan::validate_against_commitment(&self, expected) -> Result<RgkContinuationReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1496`.
  - `RgkContinuationPlan::finalize(&self, witness_txid, daa_score, confirmation_depth) -> Result<RgkFinalizedContinuation, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1524`. The phase-2 entry point. Produces an `RgkTransition` and `RgkTransitionReport`.
  - `RgkContinuationPlan::finalize_for_production_zk(&self, ...) -> Result<RgkFinalizedContinuation, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1576`.
- **`RgkContinuationAllocationShape`** (a phase-1 allocation, no txid yet): `crates/rgk-asset/src/native.rs:864-870`.
- **Smallest phase-1 example** (unit test at `crates/rgk-asset/src/native.rs:3464-3484`):
  ```rust
  // crates/rgk-asset/src/native.rs:3464
  fn continuation_plan() -> RgkContinuationPlan {
      let issue = issue();
      let previous_report = issue.validate().unwrap();
      RgkContinuationPlan {
          chain: issue.chain,
          schema_id: issue.schema_id,
          asset_id: issue.asset_id,
          total_supply: issue.total_supply,
          metadata_commitment: issue.metadata_commitment,
          previous_owner_commitment: issue.owner_commitment,
          new_owner_commitment: issue.owner_commitment,
          ownership_authorization_commitment: [0; 32],
          previous_state_digest: previous_report.state_digest,
          spent_allocations: issue.allocations,
          new_allocation_shapes: continuation_shapes(),
          burn: None,
          lane_id: issue.lane_id,
          privacy_policy: issue.privacy_policy,
          proof_policy: issue.proof_policy,
      }
  }
  ```

### 2.3 `RgkTransition` (phase 2)

- **File**: `crates/rgk-asset/src/native.rs:841-859`
- **Fields**:
  ```rust
  pub struct RgkTransition {
      pub chain: KaspaChainId,
      pub schema_id: RgkSchemaId,
      pub asset_id: RgkAssetId,
      pub total_supply: u64,
      pub metadata_commitment: RgkMetadataCommitment,
      pub previous_owner_commitment: RgkOwnerCommitment,
      pub new_owner_commitment: RgkOwnerCommitment,
      pub ownership_authorization_commitment: Bytes32,
      pub previous_state_digest: RgkStateDigest,
      pub spent_allocations: Vec<RgkAllocation>,
      pub new_allocations: Vec<RgkAllocation>,           // <-- full allocations, not shapes
      pub burn: Option<RgkBurnProof>,
      pub witness_txid: Bytes32,
      pub lane_id: BlindedLaneId,
      pub privacy_policy: LanePrivacyPolicy,
      pub proof_policy: RgkProofPolicy,
  }
  ```
- **Builders / validators**:
  - `RgkTransition::validate(&self) -> Result<RgkTransitionReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1277`.
  - `RgkTransition::validate_for_production_zk(&self) -> Result<RgkTransitionReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1282`.
  - `RgkTransition::validate_against_transition_digest(&self, expected) -> Result<RgkTransitionReport, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1291`.
- **Construction**: in production code, never build `RgkTransition` directly; call `RgkContinuationPlan::finalize(witness_txid, daa_score, confirmation_depth) -> RgkFinalizedContinuation` (which holds the `RgkTransition` — `crates/rgk-asset/src/native.rs:1524-1574`). The unit-test fixture in `crates/rgk-asset/src/native.rs:3424-3445` builds one by hand.
- **Note**: `RgkFinalizedContinuation` is at `crates/rgk-asset/src/native.rs:954-959` and contains `{ commitment, transition, transition_report }`. To get the inner transition use `finalized_continuation.transition` (see `crates/rgk-asset/src/native.rs:2037`).

### 2.4 `RgkReceipt`

- **File**: `crates/rgk-core/src/types.rs:189-205`
- **Fields**:
  ```rust
  pub struct RgkReceipt {
      pub version: u16,
      pub chain_id: KaspaChainId,
      pub covenant_id: KaspaCovenantId,
      pub old_state: RgkStateCommitment,
      pub new_state: RgkStateCommitment,
      pub transition_digest: TransitionDigest,
      pub continuation_commitment: ContinuationCommitment,
      pub proof_mode: ProofMode,
      pub replay_nonce: Bytes32,
  }
  ```
- **Constraints enforced by `RgkReceipt::validate_structure`**: `crates/rgk-core/src/types.rs:239-295` — no-op transitions (`old.digest == new.digest`) are rejected; chain/covenant/asset/policy must be consistent across `old_state`, `new_state`, and the receipt; `proof_mode` must be admitted by `old_state.receipt_policy`; all three 32-byte fields (`transition_digest`, `continuation_commitment`, `replay_nonce`) must be non-zero.
- **Constructors**:
  - `RgkReceipt::new(chain_id, covenant_id, old_state, new_state, transition_digest, continuation_commitment, proof_mode, replay_nonce) -> Result<Self, DecodeError>` — `crates/rgk-core/src/types.rs:211-234`.
  - `rgk_receipt::ReceiptBuilder::build(input: &ReceiptInput) -> Result<(RgkReceipt, ReceiptId, Vec<u8>), ReceiptError>` — `crates/rgk-receipt/src/lib.rs:175-180`. Returns the receipt, its `ReceiptId`, and the canonical wire bytes.
- **Receipt input** (`rgk-receipt/src/lib.rs:103-160`):
  ```rust
  pub struct ReceiptInput {
      pub chain_id: KaspaChainId,
      pub covenant_id: KaspaCovenantId,
      pub old_state: RgkStateCommitment,
      pub new_state: RgkStateCommitment,
      pub transition_digest: TransitionDigest,
      pub continuation_commitment: ContinuationCommitment,
      pub proof_mode: ProofMode,
      pub replay_nonce: Bytes32,
  }
  ```
  Constructor: `ReceiptInput::new(...) -> Result<Self, ReceiptError>` — `crates/rgk-receipt/src/lib.rs:115-137`.
- **Verifiers**:
  - `ReceiptVerifier::verify_local(receipt_bytes, expected_covenant_id, expected_old_state, verifier_chain) -> Result<ReceiptId, ReceiptError>` — `crates/rgk-receipt/src/lib.rs:192-205`. Pure-structural, no indexer.
  - `ReceiptVerifier::verify_local_structured(receipt, ...) -> Result<ReceiptId, ReceiptError>` — `crates/rgk-receipt/src/lib.rs:209-253`.
  - `RgkResolver::verify_receipt_against_indexer(&self, covenant, receipt_bytes) -> Result<RgkStateCommitment, ReceiptError>` — `crates/rgk-resolver/src/lib.rs:493-515`. Indexer-aware: enforces replay protection.
- **Smallest example** (unit test at `crates/rgk-receipt/src/lib.rs:411-426`):
  ```rust
  // crates/rgk-receipt/src/lib.rs:411
  fn sample_input(mode: ProofMode, policy: ReceiptPolicy) -> ReceiptInput {
      ReceiptInput {
          chain_id: KASPA_LOCAL_TOCCATA,
          covenant_id: b32("1111111111111111111111111111111111111111111111111111111111111111"),
          old_state: sample_state(1, policy),
          new_state: sample_state(2, policy),
          transition_digest: b32("3333333333333333333333333333333333333333333333333333333333333333"),
          continuation_commitment: b32("5555555555555555555555555555555555555555555555555555555555555555"),
          proof_mode: mode,
          replay_nonce: b32("4444444444444444444444444444444444444444444444444444444444444444"),
      }
  }
  ```

### 2.5 `RgkResolver` and friends

- **File**: `crates/rgk-resolver/src/lib.rs`
- **`RgkResolver<'a, B: KaspaChainBackend, I: Indexer>`**: `crates/rgk-resolver/src/lib.rs:170-177`
  ```rust
  pub struct RgkResolver<'a, B: KaspaChainBackend, I: Indexer> {
      pub backend: &'a B,
      pub indexer: &'a I,
      pub verifier_chain: KaspaChainId,
      pub reorg_safety_depth: u64,   // default 10
  }
  ```
  - Constructor: `RgkResolver::new(backend, indexer, verifier_chain)` — `crates/rgk-resolver/src/lib.rs:180-187`.
- **`ResolverState`** enum: `crates/rgk-resolver/src/lib.rs:42-108`. **13 variants**, each with a hard user-visible meaning. There is no `OptimisticValid` / `SoftInvalid`:
  | Variant | When it fires |
  | --- | --- |
  | `Open { covenant, outpoint, state }` | Covenant is open in the indexer and the backend has a current UTXO. |
  | `NativeTransitionedValid { covenant, spent_outpoint, new_outpoint, receipt_id, new_state, allocation_audit_certificate, confirmation_depth }` | Indexed spend observed on chain with `confirmation_depth >= reorg_safety_depth`, continuation proof matches the observed txid, and (if policy changed) the policy-migration proof is valid. |
  | `NativeTransitionedInvalid { covenant, reason }` | Spend observed but receipt / continuation / migration proof failed structural checks. |
  | `Unconfirmed { covenant, spending_txid }` | Spending tx is in mempool only. |
  | `ReorgRisk { covenant, daa_score }` | Spend is confirmed but `depth < reorg_safety_depth`. |
  | `CompetingBranch { covenant, spent_outpoint, indexed_spending_txid, observed_spending_txid, observed_daa_score }` | Indexer and chain disagree on the spending txid. |
  | `PolicyMigrationRequired { covenant, current_policy, requested_policy }` | Receipt attempts a policy change without a migration proof. |
  | `ReplayRejected { covenant, receipt_id }` | Receipt id already accepted for this covenant. |
  | `Unknown { covenant }` | Not indexed, or outpoint pruned. |
  | `NodeDown { covenant, reason }` | Backend unreachable or returned an error. |
  - `ResolverState::covenant(&self) -> KaspaCovenantId` — `crates/rgk-resolver/src/lib.rs:111-124`.
- **`LaneResolverState`** enum: `crates/rgk-resolver/src/lib.rs:128-139` (`Resolved { lane, state }`, `UnknownLane`, `UnknownScanTag`).
- **`TransitionResolverState`** enum: `crates/rgk-resolver/src/lib.rs:142-152` (`Resolved { transition_digest, covenant, receipt_id, state }`, `UnknownTransition`).
- **Resolver methods** (all on `RgkResolver`):
  - `resolve_by_covenant(covenant) -> ResolverState` — `crates/rgk-resolver/src/lib.rs:191`.
  - `resolve_by_asset(asset_id) -> ResolverState` — `crates/rgk-resolver/src/lib.rs:399`.
  - `resolve_lane(lane_id) -> LaneResolverState` — `crates/rgk-resolver/src/lib.rs:412`.
  - `resolve_by_view_key(view_key, asset_id, epoch) -> LaneResolverState` — `crates/rgk-resolver/src/lib.rs:419`. Computes `derive_blinded_lane_id(view_key, asset_id, epoch)` and checks `RgkScanTag::derive(...)` matches the registered one.
  - `resolve_by_scan_tag(scan_tag) -> LaneResolverState` — `crates/rgk-resolver/src/lib.rs:442`.
  - `resolve_public_lineage(asset_id) -> Vec<LaneResolverState>` — `crates/rgk-resolver/src/lib.rs:451`. Filters `indexer.public_lanes(asset_id)` to those with `public_lineage: true`.
  - `resolve_transition(transition_digest) -> TransitionResolverState` — `crates/rgk-resolver/src/lib.rs:459`.
  - `verify_receipt_against_indexer(covenant, receipt_bytes) -> Result<RgkStateCommitment, ReceiptError>` — `crates/rgk-resolver/src/lib.rs:493`.
- **Re-exports**: `pub use rgk_core::{ProofMode, ReceiptPolicy};` — `crates/rgk-resolver/src/lib.rs:38`.
- **Resolver error**: `ResolverError` enum: `crates/rgk-resolver/src/lib.rs:157-166` (BudgetExceeded, Indexer, Covenant, Invariant).
- **Smallest example** (resolver unit test at `crates/rgk-resolver/src/lib.rs:740-775`):
  ```rust
  // crates/rgk-resolver/src/lib.rs:740
  #[test]
  fn open_when_indexed_and_utxo_present() {
      let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
      let mut idx = InMemoryIndexer::new();
      let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
      let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      let open = KaspaOutpoint { transaction_id: [1u8; 32], index: 0 };
      idx.open(KASPA_LOCAL_TOCCATA, cov, lin, sample_state(cov, 1, asset_id), open, 10).unwrap();
      backend.add_utxo_at(10, test_utxo(open, 1000, 10));
      let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
      let st = r.resolve_by_covenant(cov);
      // ...asserts ResolverState::Open
  }
  ```

### 2.6 `RgkProofPolicy` (and helpers)

- **File**: `crates/rgk-asset/src/native.rs:455-468`
- **Definition**:
  ```rust
  pub enum RgkProofPolicy {
      VerifierReceipt { verifier_key_hash: Bytes32 },
      ZkReceipt { verifier_key_id: Bytes32, image_id_policy: ImageIdPolicy },
      Hybrid { verifier_key_hash: Bytes32, verifier_key_id: Bytes32 },
  }
  ```
- **`ImageIdPolicy`**: `crates/rgk-asset/src/native.rs:448-453` — variants: `Fixed(Bytes32)`, `AllowedSet(Vec<Bytes32>)`, `PolicyBranch(Bytes32)`.
- **Validation**: `RgkProofPolicy::validate(&self) -> Result<(), RgkAssetError>` — `crates/rgk-asset/src/native.rs:470-507`. Rejects zero verifier keys and unconstrained `image_id`.
- **Domain commitment**: `RgkProofPolicy::commitment(&self) -> Result<RgkPolicyCommitment, RgkAssetError>` — `crates/rgk-asset/src/native.rs:509-518`. Domain hash over the canonical policy encoding.
- **Smallest example** (from `crates/rgk-asset/src/native.rs:3224-3228`):
  ```rust
  fn proof_policy() -> RgkProofPolicy {
      RgkProofPolicy::VerifierReceipt { verifier_key_hash: [0x91; 32] }
  }
  ```
- **ZK allocation proof shape (the **allocation** proof, not the receipt proof)**: `RgkAllocationProofShape` enum: `crates/rgk-asset/src/native.rs:520-528` (`OneInZeroOut`, `OneInOneOut`, `TwoInTwoOut`, `ThreeInTwoOut`, `FourInTwoOut`, `FourInFourOut`); constants `RGK_ALLOCATION_STRATEGY_ZK_SHAPES`, `RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT=4`, `RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW=4` at `crates/rgk-asset/src/native.rs:530-541`.

### 2.7 `Lane` / `PrivacyMode` / `PublicLineage` / `PrivateLane` / `StealthLane`

- **`LanePrivacyPolicy`** enum (the canonical privacy mode, also re-exported as `RgkPrivacyPolicy`): `crates/rgk-asset/src/native.rs:424-430`
  ```rust
  #[derive(...)]
  pub enum LanePrivacyPolicy {
      PublicLineage,
      #[default]
      PrivateLane,
      StealthLane,
  }
  ```
  - `LanePrivacyPolicy::as_u8(self) -> u8` — `crates/rgk-asset/src/native.rs:432-439` (PublicLineage=0, PrivateLane=1, StealthLane=2).
  - `LanePrivacyPolicy::exposes_public_fields(self) -> bool` — `crates/rgk-asset/src/native.rs:441-443` (true only for `PublicLineage`).
  - **Re-export alias**: `pub type RgkPrivacyPolicy = LanePrivacyPolicy;` — `crates/rgk-asset/src/native.rs:446`.
- **`RgkLane`** (lane *material* in the asset: blinded lane id + privacy policy): `crates/rgk-asset/src/native.rs:592-596`. Distinct from `IndexedLane` (in the indexer).
- **`RgkLaneState`** (per-lane tip state): `crates/rgk-asset/src/native.rs:598-607`. Includes `nullifier` and `scan_tag` for private lanes.
- **`RgkLaneState::new(input) -> Self`** — `crates/rgk-asset/src/native.rs:621-636`. Derives the `RgkNullifier` and (if a `view_key` is set) the `RgkScanTag`.
- **Lane id derivation** (for private lanes): `derive_blinded_lane_id(view_key, asset_id, epoch) -> BlindedLaneId` — `crates/rgk-asset/src/native.rs:770-780`. Companion: `discover_lane(view_key, asset_id, epoch, candidate) -> bool` — `crates/rgk-asset/src/native.rs:782-789`.
- **`BlindedLaneId`** type alias: `pub type BlindedLaneId = Bytes32;` — `crates/rgk-asset/src/native.rs:20`.
- **Wallet-facing mapping**: in `rgk-walletd` the on-the-wire type is `enum PrivacyMode { PrivateLane, PublicLineage }` (no `StealthLane` yet exposed) — `crates/rgk-walletd/src/main.rs:312-317`. **Drift note: this is a subset of `LanePrivacyPolicy`.** See the Drift Notes section.

### 2.8 Indexer / scanner / sync types

- **`InMemoryIndexer`** (BTreeMap-backed; always available): `crates/rgk-indexer/src/lib.rs:935-954`. Constructor: `InMemoryIndexer::new() -> Self`.
- **`SledIndexer`** (feature `persistent`): `crates/rgk-indexer/src/lib.rs:1232-1294`. Constructor: `SledIndexer::open_path(path) -> Result<Self, IndexerError>`. `SledIndexer::flush(&self) -> Result<(), IndexerError>`.
- **`Indexer` trait** (the universal contract): `crates/rgk-indexer/src/lib.rs:359-409`:
  - `open(chain, covenant, lineage, initial, open_outpoint, daa_score)`
  - `apply_spend(covenant, receipt_id, spent, new_outpoint, new_state, daa_score)`
  - `apply_spend_with_continuation(..., continuation: ContinuationProof)`
  - `apply_spend_with_continuation_and_policy_migration(..., policy_migration: PolicyMigrationProof)`
  - `rollback(covenant, depth)`
  - `lookup(covenant) -> Option<IndexedCovenant>`
  - `latest_state(covenant) -> Option<RgkStateCommitment>`
  - `open_outpoint(covenant) -> Option<KaspaOutpoint>`
  - `has_replay(covenant, receipt_id) -> bool`
  - `list() -> Vec<KaspaCovenantId>`
  - `register_lane(lane: IndexedLane)`
  - `lane_by_id(lane_id) -> Option<IndexedLane>`
  - `lane_by_scan_tag(scan_tag) -> Option<IndexedLane>`
  - `public_lanes(asset_id) -> Vec<IndexedLane>`
- **`IndexedCovenant`**: `crates/rgk-indexer/src/lib.rs:65-81`. Holds `chain_id`, `lineage_id`, `open_outpoint: Option<KaspaOutpoint>`, `latest_state: RgkStateCommitment`, `accepted_receipts: Vec<ReceiptId>`, `spend_history: Vec<SpendEntry>`, `last_update_daa_score: u64`.
- **`IndexedLane`**: `crates/rgk-indexer/src/lib.rs:89-99` with builder `IndexedLane::new(...)` at `crates/rgk-indexer/src/lib.rs:101-125`. Note the `public_lineage: bool` field that the resolver uses to filter public-lineage lanes.
- **`ContinuationProof`**: `crates/rgk-indexer/src/lib.rs:142-147` — `{ commitment, shape_root, transition_digest }`. The phase-1 + phase-2 binding that the resolver validates against the observed spend.
- **`ScanCursor`**: `crates/rgk-indexer/src/lib.rs:197-201`. Default cursor name: `DEFAULT_SCAN_CURSOR: &str = "rgk.default"` — `crates/rgk-indexer/src/lib.rs:193`.
- **`ObservedSpendRecord`**: `crates/rgk-indexer/src/lib.rs:249-254`.
- **`RebuildCheckpoint`, `RebuildSpend`, `RebuildPlan`, `RebuildSpendEvidence`, `RebuildSummary`**: `crates/rgk-indexer/src/lib.rs:209-276`.
- **`RebuildSource` trait**: `crates/rgk-indexer/src/lib.rs:261-267`. `RebuildIndexer::rebuild_from(&self, source, plan) -> Result<RebuildSummary, IndexerError>` (blanket impl): `crates/rgk-indexer/src/lib.rs:464-555`.
- **`ScanCursorStore` and `ObservedSpendStore` traits**: `crates/rgk-indexer/src/lib.rs:421-439`.
- **`AllocationAuditCertificateStore` trait** (for ZK-audited spends): `crates/rgk-indexer/src/lib.rs:443-456`.
- **`ScanService`**: `crates/rgk-sync/src/lib.rs:123-242`. `ScanService::new(backend, cursor_store, config)`, `.tick() -> Result<ScanTick, SyncError>`, `.run_until_idle(max_idle_ticks) -> Result<ScanRunSummary, SyncError>`.
- **`ScanBackend` trait** (the minimum contract a chain scanner must implement): `crates/rgk-sync/src/lib.rs:53-61`. `current_scan_cursor(chain_id)`, `scan_from_cursor(cursor, min_confirmation_count) -> ScanBatch`.
- **`KaspaRebuildSource<'a, B: KaspaChainBackend + ?Sized>`**: `crates/rgk-sync/src/lib.rs:249-304`. Adapts any `KaspaChainBackend` as a `RebuildSource`.
- **Default `WrpcBackend` impl of `ScanBackend`**: `crates/rgk-sync/src/lib.rs:306-344` (feature `wrpc`).
- **`ScanBatch`**: `crates/rgk-sync/src/lib.rs:31-49`. Includes `removed_chain_block_hashes`, `added_chain_block_hashes`, `last_added_daa_score`, `observed_spends`, `observed_spend_records`.
- **Smallest indexer/scanner example** (live test, `tests/rgk-e2e/tests/live_devnet.rs:121-159`):
  ```rust
  // tests/rgk-e2e/tests/live_devnet.rs:121
  let backend = WrpcBackend::connect_borsh(&url, WrpcNetwork::Devnet).await.unwrap();
  let mut indexer = SledIndexer::open_path(&path).unwrap();
  let mut service = ScanService::new(
      &backend, &mut indexer, ScanServiceConfig::new(KaspaChainId::KaspaDevnet),
  );
  let tick = service.tick().expect("initialise devnet scan cursor");
  assert!(tick.initialised_cursor);
  indexer.flush().expect("flush devnet cursor");
  ```

---

## 3. Runnable Examples

The `examples/` directory holds **Silverscript source files** + a
machine-checked coverage matrix. There are no `cargo run --example` Rust
binaries in this repo. Tutorial writers should treat the Silverscript files
as the public-facing examples and the e2e harness (next section) as the
**runnable** surface.

### `examples/` inventory

All files live under `/Users/arthur/RustroverProjects/rgk/examples/`. Each row
maps to a row in `examples/contract-matrix.tsv`.

| Example id (file) | What it demonstrates | Status | Compile / run |
| --- | --- | --- | --- |
| `private_lane_asset_lifecycle.sil` | Private-lane fungible issue, 1×1 transition, receipt validation, view-key resolver classification. | `silverscript_source_compiles` / `checked_silverscript_json_artifact` / `pending_public_staging` | Compiled by pinned upstream silverscript (see `examples/silverscript/artifacts/manifest.tsv`); **no direct `cargo run`**. Evidence: `rgk-e2e::run_e2e_fixture` + `fixture_e2e_passes` test (`tests/rgk-e2e/src/lib.rs:471`). |
| `burn_authorised_lifecycle.sil` | `RgkBurnProof` carries a phase-1 burn + matching `spent_supply − new_supply = burned_supply`. Production-ZK 1×1 burn transition. | same | `rgk-e2e::native_transition_rejects_supply_inflation_and_deflation` + `continuation_accepts_explicit_burn_for_supported_production_zk_shape` + `prove_then_verify_allocation_1x1_burn_transition`. |
| `policy_migration_recovery.sil` | Receipt-policy change via `PolicyMigrationInput`/`PolicyMigrationProof`, persists across `SledIndexer` reopen. | same | `rgk-e2e::run_policy_migration_recovery_fixture` (`tests/rgk-e2e/src/lib.rs:723`), test `policy_migration_recovery_fixture_survives_reopen` (`tests/rgk-e2e/src/lib.rs:882`). |
| `allocation_audit_certificate_recovery.sil` | ZK allocation-audit certificate (real-zk), `SegmentedAllocationAudit` strategy, `RgkProductionAllocationStrategyRecord` round-trip. | same | `rgk-e2e::zk_precompile_vm::allocation_audit_certificate_*` tests. |
| `fungible_batch_transfer_shapes.sil` | All 6 supported `RgkAllocationProofShape`s (1×0, 1×1, 2×2, 3×2, 4×2, 4×4). | same | `rgk-asset::native::tests::fungible_*` (`crates/rgk-asset/src/native.rs:3913-4083`). |
| `metadata_ownership_guardrails.sil` | `RgkMetadataCommitment` / `RgkOwnerCommitment`; ownership handoff must carry `ownership_authorization_commitment`. | same | `rgk-asset::native::tests::native_issue_digest_binds_metadata_and_owner_commitments` etc. |
| `owner_control_policy_shapes.sil` | `RgkOwnerDescriptor::{KeyHash, ScriptHash, CovenantId}`; rotation across transitions. | same | `rgk-asset::native::tests::owner_descriptor_commitments_bind_owner_control_shape` etc. |
| `advanced_covenant_policy_shapes.sil` | `AdvancedCovenantPolicyShape` + `AdvancedCovenantExecutionEvidence` (payment-gated, escrow, vault-timelock, atomic swap, etc.). | same | `rgk-covenant::tests::advanced_covenant_*`. |
| `nft_collection_policy_shapes.sil` | NFT collection id + 1×0 terminal burn via `RgkAllocationProofShape::OneInZeroOut`. | same | `rgk-asset::native::tests::nft_collection_policy_*`. |
| `nft_marketplace_sale_policy.sil` | Marketplace sale with `payment_asset_id`, `royalty_amount`, `royalty_policy_commitment`. | same | `rgk-asset::native::tests::nft_marketplace_sale_*`. |
| `private_lane_graph_discovery.sil` | `RgkLane` discovery via view-key; `derive_blinded_lane_id`; `RgkScanTag::derive`; Groth16 lane-discovery + lane-graph + segmented lane-graph proofs. | same | `rgk-e2e::zk_precompile_vm::prove_then_verify_lane_discovery` etc. (live test: `tests/rgk-e2e/tests/live_covenant.rs:2256-2449`). |
| `public_lineage_opt_in.sil` | `LanePrivacyPolicy::PublicLineage`; `resolve_public_lineage` returns only `public_lineage: true` lanes. | same | `rgk-resolver::tests::resolve_public_lineage_returns_only_public_lanes_for_asset`. |
| `proof_policy_guardrails.sil` | `RgkProofPolicy` downgrade is rejected; `ImageIdPolicy::AllowedSet([])` and `PolicyBranch([0;32])` are rejected. | same | `rgk-asset::native::tests::proof_policy_downgrade_is_rejected_by_state_digest`, `unconstrained_image_id_is_rejected` (`crates/rgk-asset/src/native.rs:5231`). |
| `rgk_covenant_continuation_policy.sil` | Low-level `CovenantContinuationPolicy` + `CovenantSharedContinuationPolicy` shape; not a user-facing matrix row but covered in the manifest. | `checked_silverscript_json_artifact` | Compiled only (no separate rust evidence). |

### How to "run" a tutorial example

- For a fixture-only smoke test:
  ```bash
  cargo test -p rgk-e2e --test live_covenant --no-default-features --features=persistent-indexer
  ```
  but in pure fixture mode the right invocation is
  ```bash
  cargo test -p rgk-e2e --test live_covenant
  ```
  which runs the no-features harness (live tests are `#[cfg]`-gated).
- For a live test (gated by `live-kaspa-wrpc`):
  ```bash
  cargo test -p rgk-e2e --features=live-kaspa-wrpc --test live_covenant -- live_toccata_full_covenant_lifecycle --nocapture
  ```
- The full fixture E2E is the most accessible demonstration:
  ```bash
  cargo test -p rgk-e2e --test live_covenant -- fixture_e2e_passes --nocapture
  ```
  Expected stdout: a deterministic `RGK e2e summary` (the format is defined
  at `tests/rgk-e2e/src/lib.rs:437-456`):
  ```text
  RGK e2e summary
    chain:           KaspaLocalToccata
    covenant:        0x…
    lineage:         0x…
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

### Benchmarks

- `tests/rgk-e2e/benches/local_e2e.rs:1-19` — `criterion`-based bench wrapping `rgk_e2e::run_e2e_fixture`. Run with `cargo bench -p rgk-e2e --bench local_e2e`. This is the only benchmark in the workspace.

---

## 4. CLI Surface

The workspace exposes the following binaries. None of them is a
`cargo run --example`; they are workspace binaries + `tests/rgk-e2e` bins.

### `rgk-walletd` (local Avato HTTP wallet daemon)

- **Source**: `crates/rgk-walletd/src/main.rs:46-76` (`Cli` struct).
- **Invocation**:
  ```bash
  cargo run -p rgk-walletd -- \
      --listen 127.0.0.1:8788 \
      --network local-toccata \
      --state target/rgk-walletd/state.json \
      --sync-db target/rgk-walletd/sync-db \
      --kaspa-endpoint ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh
  ```
- **Top-level subcommands / endpoints** (axum router at `crates/rgk-walletd/src/main.rs:625-641`):
  `GET /health`, `GET /wallet/profile`, `POST /wallets`, `POST /wallet/import`, `POST /wallet/lock`, `POST /wallet/unlock`, `POST /wallet/kaspa-endpoint`, `POST /wallet/sync`, `GET /dashboard`, `POST /lanes`, `POST /proofs`, `POST /transitions`.
- **CLI flags / env vars**:
  | Flag | Env | Default |
  | --- | --- | --- |
  | `--listen <addr>` | `RGK_WALLETD_LISTEN` | `127.0.0.1:8788` |
  | `--network <kind>` (mainnet / testnet-10 / testnet-12 / devnet / simnet / local-toccata) | — | `local-toccata` |
  | `--kaspa-endpoint <url>` | `RGK_LIVE_KASPA_URL` | network default (simnet → `ws://127.0.0.1:18111/...`) |
  | `--state <path>` | `RGK_WALLETD_STATE` | `target/rgk-walletd/state.json` |
  | `--sync-db <path>` | `RGK_SYNC_DB` | `target/rgk-walletd/sync-db` (via `default_sync_db_path`) |
- **Scripts** wrappers / references: `scripts/verify-avato-walletd-contract.sh` (the Avato contract verifier). No `e2e-*-walletd.sh` shell wrapper, but the verify script is the canonical reference.

### `rgk-sync` (restart-safe live Kaspa scanner)

- **Source**: `crates/rgk-sync/src/bin/rgk-sync.rs:11-52` (`Cli` struct).
- **Invocation**:
  ```bash
  cargo run -p rgk-sync -- \
      --url ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh \
      --network simnet \
      --db target/rgk-sync/db
  ```
- **Top-level flags** (no subcommands — three runtime modes):
  | Flag | Purpose |
  | --- | --- |
  | `--url <url>` (env `RGK_LIVE_KASPA_URL`) | Borsh wRPC endpoint. |
  | `--network <kind>` (mainnet / testnet / devnet / simnet / local-toccata) | Default `local-toccata`. |
  | `--db <path>` (env `RGK_SYNC_DB`) | Sled database directory for scan cursor + RGK state. |
  | `--cursor-name <name>` | Defaults to `DEFAULT_SCAN_CURSOR` (`rgk.default`). |
  | `--min-confirmations <N>` | Forwarded to `ScanServiceConfig::min_confirmation_count`. |
  | `--once` | Single tick then exit. |
  | `--forever` | Loop until Ctrl+C. |
  | `--max-idle-ticks <N>` | Default 1. |
  | `--poll-ms <N>` | Default 1000. |
- **Stdout format** (`crates/rgk-sync/src/bin/rgk-sync.rs:207-232`):
  - `--once` / `--forever`: `tick initialised={bool} added_chain_blocks={N} observed_spends={N} start_daa={N} end_daa={N} end_hash_prefix={16hex}`
  - default / `--max-idle-ticks`: `summary ticks={N} initialised={bool} added_chain_blocks={N} observed_spends={N} end_daa={N|None} end_hash_prefix={16hex|none}`
- **Required env vars**: none strictly required (both `--url` and `--db` are CLI flags), but `RGK_LIVE_KASPA_URL` and `RGK_SYNC_DB` are the canonical env-var names.
- **Scripts** wrappers: none direct; the closest evidence script is `scripts/verify-devnet-evidence.sh` (validates the devnet-side evidence bundle). The walletd daemon internally calls into this binary's library, not the binary.

### `rgk-testnet-funding-readiness`

- **Source**: `tests/rgk-e2e/src/bin/rgk-testnet-funding-readiness.rs` (275 lines).
- **Invocation**:
  ```bash
  cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-funding-readiness -- \
      testnet-12 ws://127.0.0.1:18311/v2/kaspa/testnet-12/no-tls/wrpc/borsh
  ```
  Or set `RGK_LIVE_KASPA_NETWORK=testnet-12` and `RGK_LIVE_KASPA_URL=…`. Default `network = testnet-12`.
- **Output format** (free-form `println!` lines, sample at `tests/rgk-e2e/src/bin/rgk-testnet-funding-readiness.rs:80-100`):
  ```text
  RGK public testnet funding readiness
  timestamp_utc=…
  network=testnet-12
  chain_id=KaspaTestnet
  url=…
  wallet_set_id=0x…
  wallet_count=3
  funding_address=kaspatest:…
  required_min_value_real_zk=…
  required_min_value_verifier_only=…
  server_version=… server_network_id=… server_is_synced=… server_has_utxo_index=…
  ```
- **Required env vars** (when CLI args absent): `RGK_LIVE_KASPA_URL`, optional `RGK_LIVE_KASPA_NETWORK`.
- **Scripts** wrappers: `scripts/verify-testnet-funding-readiness.sh`, `scripts/e2e-testnet-staging.sh`.

### `rgk-testnet-staging-address`

- **Source**: `tests/rgk-e2e/src/bin/rgk-testnet-staging-address.rs` (small). Prints the deterministic funding address.
- **Invocation**:
  ```bash
  cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-staging-address
  ```
  Reads `RGK_LIVE_KASPA_NETWORK` (default `testnet-12`).
- **Output**: `funding_address=kaspatest:…`.
- **Scripts** wrappers: `scripts/e2e-testnet-staging.sh`.

### `criterion` bench

- **Source**: `tests/rgk-e2e/benches/local_e2e.rs`. Run via `cargo bench -p rgk-e2e --bench local_e2e`. Not a CLI but a runnable artifact.

### Quick-reference: CLI matrix

| Binary | Crate | Compile (release) | Run | Env vars |
| --- | --- | --- | --- | --- |
| `rgk-walletd` | `rgk-walletd` | `cargo build -p rgk-walletd --release` | `cargo run -p rgk-walletd -- …` | `RGK_WALLETD_LISTEN`, `RGK_WALLETD_STATE`, `RGK_LIVE_KASPA_URL`, `RGK_SYNC_DB` |
| `rgk-sync` | `rgk-sync` | `cargo build -p rgk-sync` (or with `--features wrpc` for the wRPC `ScanBackend` impl) | `cargo run -p rgk-sync -- …` | `RGK_LIVE_KASPA_URL`, `RGK_SYNC_DB` |
| `rgk-testnet-funding-readiness` | `rgk-e2e` (bin) | `cargo build -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-funding-readiness` | `cargo run -p rgk-e2e --features live-kaspa-wrpc --bin rgk-testnet-funding-readiness -- …` | `RGK_LIVE_KASPA_URL`, `RGK_LIVE_KASPA_NETWORK` |
| `rgk-testnet-staging-address` | `rgk-e2e` (bin) | same as above | same as above | `RGK_LIVE_KASPA_NETWORK` |

### Script wrappers cross-reference

| Script | Talks to |
| --- | --- |
| `scripts/build-kaspa.sh` | Builds the upstream `kaspad` from `external/rusty-kaspa-toccata`. |
| `scripts/run-kaspa-local.sh` / `scripts/run-kaspa-devnet.sh` | Launches a local simnet/devnet. |
| `scripts/e2e-local.sh` | Local e2e (fixture mode) — exercises `rgk-e2e` against `FixtureBackend`. |
| `scripts/e2e-devnet.sh` | Devnet e2e — runs the live wRPC devnet test. |
| `scripts/e2e-internal-readiness.sh` | Internal evidence collection. |
| `scripts/e2e-testnet-staging.sh` | Testnet staging driver. |
| `scripts/e2e-privacy-observer.sh` | Privacy-observer evidence. |
| `scripts/verify-avato-walletd-contract.sh` | Hard-codes the `rgk-walletd` API surface used by the Avato frontend. |
| `scripts/verify-example-matrix.sh` | Walks `examples/contract-matrix.tsv` and the silverscript manifest. |
| `scripts/verify-devnet-evidence.sh` | Verifies devnet evidence markers. |
| `scripts/verify-launch-readiness.sh` | Top-level launch readiness gate. |
| `scripts/verify-silverscript-artifacts.sh` | Validates silverscript JSON artifacts. |
| `scripts/verify-testnet-*.sh` | Testnet funding/staging evidence. |
| `scripts/verify-native-terminology.sh` | Lints docs and source for the canonical terminology (`asset_id` vs `contract_id`, etc.). |

---

## 5. Concept → Code Map (the highest-value section)

The format: concept → smallest code is at `file:line` (5–15 line block)
→ matching test is at `file:line`. Every block is quoted verbatim from the
repo so tutorial writers can re-use the snippet.

### 5.1 How to issue a new asset

**Smallest code**: `crates/rgk-asset/src/native.rs:3384-3411` (helper
`issue_with_allocations`). The pattern is `RgkAssetIssue::derive_asset_id`
on an `RgkAssetIdDerivation` then build the `RgkAssetIssue` literal.

```rust
// crates/rgk-asset/src/native.rs:3384
fn issue_with_allocations(total_supply: u64, allocations: Vec<RgkAllocation>) -> RgkAssetIssue {
    let schema_id = *b"rgk:asset:schema:v1_____________";
    let policy = proof_policy();
    let asset_id = RgkAssetIssue::derive_asset_id(RgkAssetIdDerivation {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id,
        total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations: &allocations,
        lane_id: lane_id(),
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: &policy,
    })
    .unwrap();
    RgkAssetIssue {
        chain: KASPA_LOCAL_TOCCATA,
        schema_id, asset_id, total_supply,
        metadata_commitment: metadata_commitment(),
        owner_commitment: owner_commitment(),
        allocations,
        lane_id: lane_id(),
        privacy_policy: LanePrivacyPolicy::PrivateLane,
        proof_policy: policy,
    }
}
```

**Production-ZK gate**: `RgkAssetIssue::validate_for_production_zk(&self) -> Result<RgkIssueReport, RgkAssetError>` at `crates/rgk-asset/src/native.rs:1202`. Note the helper enforces `total_supply == sum(allocations[].amount)` and
`allocations.len() <= RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT (= 4)`.

**Matching test**: `crates/rgk-asset/src/native.rs:4477` `native_issue_rejects_supply_mismatch`, plus the e2e `rgk_e2e::native_asset_state_report` at `tests/rgk-e2e/src/lib.rs:1098-1132` (the canonical "issue a private-lane RGK asset" recipe used by both fixture and live tests).

### 5.2 How to build a continuation plan (phase 1, before txid exists)

**Smallest code**: `crates/rgk-asset/src/native.rs:3464-3484`
(`continuation_plan()` helper). The pattern: validate the previous issue
report, then construct `RgkContinuationPlan` with **shapes** for the new
allocations, not full `RgkAllocation`s.

```rust
// crates/rgk-asset/src/native.rs:3464
fn continuation_plan() -> RgkContinuationPlan {
    let issue = issue();
    let previous_report = issue.validate().unwrap();
    RgkContinuationPlan {
        chain: issue.chain,
        schema_id: issue.schema_id,
        asset_id: issue.asset_id,
        total_supply: issue.total_supply,
        metadata_commitment: issue.metadata_commitment,
        previous_owner_commitment: issue.owner_commitment,
        new_owner_commitment: issue.owner_commitment,
        ownership_authorization_commitment: [0; 32],
        previous_state_digest: previous_report.state_digest,
        spent_allocations: issue.allocations,
        new_allocation_shapes: continuation_shapes(),
        burn: None,
        lane_id: issue.lane_id,
        privacy_policy: issue.privacy_policy,
        proof_policy: issue.proof_policy,
    }
}
```

**`RgkContinuationAllocationShape`** literal: `crates/rgk-asset/src/native.rs:3447-3462` (helper `continuation_shapes()`).

**Phase-1 commitment** (the value that gets bound into the receipt and into
the covenant script): `RgkContinuationPlan::validate(&self) -> Result<RgkContinuationReport, RgkAssetError>` at `crates/rgk-asset/src/native.rs:1476`. The commitment lives on `report.commitment: RgkContinuationCommitment` (`crates/rgk-asset/src/native.rs:951`).

**Production-ZK version**: `RgkContinuationPlan::into_production_zk_transfer_plan(self) -> Result<RgkProductionZkTransferPlan, RgkAssetError>` at `crates/rgk-asset/src/native.rs:1490`. This wraps the plan + report + the resolved `RgkAllocationProofShape`.

**Matching test**: `crates/rgk-asset/src/native.rs:4659` `continuation_phase1_commitment_is_stable_without_future_txid` (asserts the same plan yields the same commitment twice, proving phase 1 doesn't depend on the future txid).

### 5.3 How to finalize a transition (phase 2, after txid exists)

**Smallest code**: `crates/rgk-asset/src/native.rs:4670-4696` (test
`continuation_finalization_spends_old_anchor_and_creates_new_anchor`).

```rust
// crates/rgk-asset/src/native.rs:4670
#[test]
fn continuation_finalization_spends_old_anchor_and_creates_new_anchor() {
    let plan = continuation_plan();
    let finalized = plan.finalize([0x88; 32], 20_000, 3).unwrap();
    assert_eq!(
        finalized.transition.spent_allocations,
        plan.spent_allocations
    );
    assert_eq!(finalized.transition.new_allocations.len(), 2);
    assert_eq!(
        finalized.transition.new_allocations[0]
            .anchor
            .covenant_outpoint
            .transaction_id,
        [0x88; 32]
    );
    assert_eq!(
        finalized.transition.new_allocations[0]
            .anchor
            .covenant_outpoint
            .index,
        0
    );
    assert_ne!(
        finalized.transition_report.previous_state_digest,
        finalized.transition_report.new_state_digest
    );
}
```

The factory: `RgkContinuationPlan::finalize(&self, witness_txid: Bytes32, daa_score: u64, confirmation_depth: u64) -> Result<RgkFinalizedContinuation, RgkAssetError>` — `crates/rgk-asset/src/native.rs:1524-1574`. Returns a struct holding `commitment`, `transition`, `transition_report` (`crates/rgk-asset/src/native.rs:954-959`).

The `transition_digest` returned in `transition_report.transition_digest`
(`crates/rgk-asset/src/native.rs:927`) is the value the receipt's
`transition_digest` field must match.

**Matching test**: `crates/rgk-asset/src/native.rs:4698` `continuation_phase2_binds_actual_txid` — proves two different `witness_txid`s produce two different `transition_digest`s.

### 5.4 How to generate a receipt

**Smallest code**: `tests/rgk-e2e/src/lib.rs:600-612` (the canonical e2e
`run_e2e_fixture` flow).

```rust
// tests/rgk-e2e/src/lib.rs:600
let receipt_input = ReceiptInput::new(
    chain,
    covenant_id,
    initial_rgk_state.clone(),
    new_rgk_state.clone(),
    native_transition_report.transition_digest.to_bytes(),
    native_transition_report.continuation_commitment.to_bytes(),
    ProofMode::VerifierReceipt,
    sha256_digest(b"rgk:replay-nonce-v1"),
)
.map_err(|e| format!("ReceiptInput: {e:?}"))?;
let (receipt, receipt_id, receipt_bytes) =
    ReceiptBuilder::build(&receipt_input).map_err(|e| format!("ReceiptBuilder: {e:?}"))?;
```

**Factories**:
- `rgk_receipt::ReceiptInput::new(...) -> Result<Self, ReceiptError>` — `crates/rgk-receipt/src/lib.rs:115-137`.
- `rgk_receipt::ReceiptBuilder::build(&input) -> Result<(RgkReceipt, ReceiptId, Vec<u8>), ReceiptError>` — `crates/rgk-receipt/src/lib.rs:175-180`. The `Vec<u8>` is the canonical wire bytes the verifier and resolver consume.
- `rgk_core::receipt_commitment(&receipt) -> ReceiptId` — `crates/rgk-core/src/commit.rs:100-103` (also returned by `ReceiptBuilder::build`).
- `rgk_core::replay_nonce(prev_outpoint_payload, transition_digest) -> Bytes32` — `crates/rgk-core/src/commit.rs:117-122`. Re-exported as `rgk_receipt::derive_replay_nonce` at `crates/rgk-receipt/src/lib.rs:357-362`.

**Verifier on the local side**: `ReceiptVerifier::verify_local(receipt_bytes, expected_covenant_id, expected_old_state, verifier_chain) -> Result<ReceiptId, ReceiptError>` at `crates/rgk-receipt/src/lib.rs:192-205`. (No indexer; safe to call from `no_std`/embedded.)

**Matching tests**:
- `crates/rgk-receipt/src/lib.rs:443` `receipt_input_constructor_validates_structure`.
- `crates/rgk-receipt/src/lib.rs:535` `build_round_trips_id_and_bytes`.
- `crates/rgk-receipt/src/lib.rs:637` `replay_set_accepts_once`.
- `tests/rgk-e2e/src/lib.rs:622` calls `ReceiptVerifier::verify_local` after building.

### 5.5 How to resolve / classify a transition

**Smallest code (resolve by covenant)**: `crates/rgk-resolver/src/lib.rs:740-775`
(`open_when_indexed_and_utxo_present`).

```rust
// crates/rgk-resolver/src/lib.rs:740
#[test]
fn open_when_indexed_and_utxo_present() {
    let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
    let mut idx = InMemoryIndexer::new();
    let cov = b32("1111111111111111111111111111111111111111111111111111111111111111");
    let lin = b32("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let open = KaspaOutpoint { transaction_id: [1u8; 32], index: 0 };
    idx.open(KASPA_LOCAL_TOCCATA, cov, lin, sample_state(cov, 1, asset_id), open, 10).unwrap();
    backend.add_utxo_at(10, test_utxo(open, 1000, 10));
    let r = RgkResolver::new(&backend, &idx, KASPA_LOCAL_TOCCATA);
    let st = r.resolve_by_covenant(cov);
    match st {
        ResolverState::Open { covenant, outpoint, .. } => { /* assert */ }
        _ => panic!("expected Open, got {:?}", st),
    }
}
```

**Resolver methods that decide the state** (`crates/rgk-resolver/src/lib.rs`):

| Call | Line | Returns |
| --- | --- | --- |
| `RgkResolver::resolve_by_covenant(covenant)` | `191` | `ResolverState` (13 variants). |
| `RgkResolver::resolve_by_asset(asset_id)` | `399` | `ResolverState` (iterates `indexer.list()` and matches by `latest_state.asset_id`). |
| `RgkResolver::resolve_lane(lane_id)` | `412` | `LaneResolverState` |
| `RgkResolver::resolve_by_view_key(view_key, asset_id, epoch)` | `419` | `LaneResolverState`. Recomputes `derive_blinded_lane_id` and `RgkScanTag::derive` and checks. |
| `RgkResolver::resolve_by_scan_tag(scan_tag)` | `442` | `LaneResolverState` |
| `RgkResolver::resolve_public_lineage(asset_id)` | `451` | `Vec<LaneResolverState>` (filtered to `lane.public_lineage == true`). |
| `RgkResolver::resolve_transition(transition_digest)` | `459` | `TransitionResolverState` (linear scan over `indexer.list()`'s spend history). |
| `RgkResolver::verify_receipt_against_indexer(covenant, receipt_bytes)` | `493` | `Result<RgkStateCommitment, ReceiptError>`. Indexer-aware. |

**Matching test for receipt-aware verification**: `crates/rgk-resolver/src/lib.rs:1347` `verify_receipt_against_indexer_rejects_mismatch`, and the live test `tests/rgk-e2e/tests/live_covenant.rs:2451-2507` which builds an `RgkResolver` and asserts `ResolverState::NativeTransitionedValid` after a real covenant spend on a Toccata simnet/devnet.

### 5.6 How to build a public-lineage asset

**Pattern**: set `privacy_policy: LanePrivacyPolicy::PublicLineage` on the
issue. The `RgkPrivacyPolicy` is the same type, just an alias. The indexer
must be told the lane is public via `IndexedLane::new(..., public_lineage: true, ...)`; the resolver filters with `indexer.public_lanes(asset_id)`.

**Source location**: the canonical `LanePrivacyPolicy` enum is at `crates/rgk-asset/src/native.rs:424-430`. The "lane is public" flag on the indexer is `IndexedLane::new`'s `public_lineage: bool` parameter at `crates/rgk-indexer/src/lib.rs:101-125`. The resolver side is `RgkResolver::resolve_public_lineage(asset_id) -> Vec<LaneResolverState>` at `crates/rgk-resolver/src/lib.rs:451-457`.

The matching test is at `crates/rgk-resolver/src/lib.rs:1300+` (`resolve_public_lineage_returns_only_public_lanes_for_asset`, name inferred from the contract-matrix row `public_lineage_opt_in` in `examples/contract-matrix.tsv:13`).

**Snippet (lane registration)** — `tests/rgk-e2e/src/lib.rs:679-690`:

```rust
// tests/rgk-e2e/src/lib.rs:679
idx.register_lane(IndexedLane::new(
    chain,
    covenant_id,
    asset_id,
    native_transition_report.lane_id,
    fixture_epoch,
    Some(lane_scan_tag.to_bytes()),
    false, // <-- public_lineage
    new_state_digest,
    2,
))
.map_err(|e| format!("register_lane: {e}"))?;
```

For a public-lineage lane, pass `true` instead of `false` at the `public_lineage:` argument.

### 5.7 How to build a private-lane asset (the default)

**Pattern**: `privacy_policy: LanePrivacyPolicy::PrivateLane` is the
**default** variant (line `crates/rgk-asset/src/native.rs:428`), and the
indexer gets `public_lineage: false` and (optionally) a `scan_tag`. The
private lane's id is derived from the view key, the asset id, and the
epoch.

**Smallest construction code** (helper, `crates/rgk-asset/src/native.rs:3379-3411`, the same `issue_with_allocations` but with `LanePrivacyPolicy::PrivateLane`). For a single-allocation private-lane issue the e2e harness uses `rgk_e2e::native_asset_state_report` at `tests/rgk-e2e/src/lib.rs:1098-1132`.

**View-key discovery** (private lane) — `tests/rgk-e2e/src/lib.rs:696-703`:

```rust
// tests/rgk-e2e/src/lib.rs:696
let lane_res = resolver.resolve_by_view_key(fixture_view_key, asset_id, fixture_epoch);
if !matches!(
    lane_res,
    LaneResolverState::Resolved { ref state, .. }
        if matches!(state.as_ref(), ResolverState::NativeTransitionedValid { .. })
) {
    return Err(format!("resolve_by_view_key: {lane_res:?}"));
}
```

**Live matching test**: `tests/rgk-e2e/tests/live_covenant.rs:2484-2506` — the live equivalent that drives the same path against a Toccata simnet.

**Lane id derivation**: `derive_blinded_lane_id(view_key, asset_id, epoch) -> BlindedLaneId` at `crates/rgk-asset/src/native.rs:770-780`. Companion `discover_lane(view_key, asset_id, epoch, candidate) -> bool` at `crates/rgk-asset/src/native.rs:782-789`.

**Scan tag derivation**: `RgkScanTag::derive(view_key, lane_id, epoch) -> RgkScanTag` at `crates/rgk-asset/src/native.rs:749-757`. The scan tag is the indexer's hint for which lane a mempool/observed spend belongs to (see the `view_key` parameter in `RgkLaneState::new` at `crates/rgk-asset/src/native.rs:621-636`).

### 5.8 How to build a stealth-lane asset

**Pattern**: `privacy_policy: LanePrivacyPolicy::StealthLane`. The enum
exists, but the e2e + e2e tests do not currently exercise it. Stealth
behaves like a private lane from the chain's perspective (no public
fields), but the on-chain form has not been specialised yet. See
**Drift Notes** for the missing-example flag.

**Source**: the variant is at `crates/rgk-asset/src/native.rs:429`. Tag value
`StealthLane as u8 == 2` (`crates/rgk-asset/src/native.rs:432-439`). The
`exposes_public_fields` method returns `false` (`crates/rgk-asset/src/native.rs:441-443`).

There is no small live example in the repo. The closest is the unit test
`crates/rgk-asset/src/native.rs:5156` `private_lane_public_observer_boundary_is_commitment_only`, which proves the private-lane observer boundary is a commitment — the stealth-lane variant reuses the same boundary.

### 5.9 How to construct a ZK receipt / semantic proof / allocation proof

These are three different proofs. The repo keeps them distinct on purpose
(`docs/ZK-BOUNDARY.md` is the spec).

**(a) ZK receipt** (the proof that the receipt's claim holds, used with
`ProofMode::ZkReceipt`):

- The `RgkReceipt` itself is *typed the same way* — only the `proof_mode`
  differs. The ZK proof itself is held alongside the receipt and is **not**
  embedded in the canonical encoding of `RgkReceipt` (see
  `docs/RECEIPT-SPEC.md`). The Toccata `OpZkPrecompile` consumes the proof
  separately.
- **Public inputs** (the `ZkStatement`): `crates/rgk-zk/src/lib.rs:262-326`. `PUBLIC_INPUT_LEN = 232` bytes.
  ```rust
  // crates/rgk-zk/src/lib.rs:306
  pub fn from_receipt(receipt: &RgkReceipt, receipt_id: Bytes32) -> Self {
      Self {
          old_state_digest: receipt.old_state.state_digest,
          new_state_digest: receipt.new_state.state_digest,
          asset_id: receipt.old_state.asset_id,
          kaspa_covenant_id: receipt.covenant_id,
          chain_id: receipt.chain_id,
          receipt_id,
          transition_digest: receipt.transition_digest,
          continuation_commitment: receipt.continuation_commitment,
      }
  }
  ```
- **Receipt-vs-statement binding**: `ZkStatement::matches(receipt, receipt_id) -> bool` at `crates/rgk-zk/src/lib.rs:322-325`.

**(b) Semantic proof** (the richer 512-byte native-transition statement used by e2e + real-zk):

- `SemanticTransitionStatement` struct: `crates/rgk-zk/src/lib.rs:361-386`. `PUBLIC_INPUT_LEN = 512` bytes.
- Builder: `SemanticTransitionStatement::from_reports(transition: &RgkTransitionReport, continuation: &RgkContinuationReport) -> Result<Self, ZkError>` at `crates/rgk-zk/src/lib.rs:444-554`. Crucially, this is the "easy" way to bind a real native transition to a public statement — you do not need to re-list all 22 fields by hand.
- Validation: `SemanticTransitionStatement::new(...)` and `::validate()` — `crates/rgk-zk/src/lib.rs:388-442`.
- Public input byte order: documented at `crates/rgk-zk/src/lib.rs:336-360`.
- Matching e2e usage: `tests/rgk-e2e/src/lib.rs:613-621`:
  ```rust
  // tests/rgk-e2e/src/lib.rs:613
  let semantic_statement =
      SemanticTransitionStatement::from_reports(&native_transition_report, &continuation_phase1)
          .map_err(|e| format!("SemanticTransitionStatement: {e}"))?;
  if !semantic_statement.matches_receipt(&receipt) {
      return Err("semantic transition statement must match fixture receipt".into());
  }
  if semantic_statement.public_inputs().len() != SemanticTransitionStatement::PUBLIC_INPUT_LEN {
      return Err("semantic transition statement public-input length drifted".into());
  }
  ```

**(c) Allocation proof** (the ZK proof that the spent→new allocation vector
satisfies a `RgkAllocationProofShape`):

- The shape enum: `RgkAllocationProofShape` at `crates/rgk-asset/src/native.rs:520-528` (six variants).
- The plan wrapper: `RgkProductionZkTransferPlan` (`crates/rgk-asset/src/native.rs:961-966`) and `RgkProductionAllocationStrategyPlan` (`crates/rgk-asset/src/native.rs:990-996`).
- The strategy record (the canonical on-wire bundle): `RgkProductionAllocationStrategyRecord` (`crates/rgk-asset/src/native.rs:998-1001`) with `canonical_bytes()` and `decode_canonical()` at `crates/rgk-asset/src/native.rs:1960-2021`.
- Live Groth16 stack construction: `real_zk::live_groth16_stack(&setup, &receipt) -> Groth16PrecompileStack` (`tests/rgk-e2e/tests/live_covenant.rs:653-660`) which returns a Toccata-compatible `Groth16PrecompileStack`.
- Live end-to-end: `tests/rgk-e2e/tests/live_covenant.rs:2256-2449` (lane-discovery, lane-graph, lane-graph-segment Groth16 proofs all generated and verified).
- Allocation proof unit test: `crates/rgk-asset/src/native.rs:3700-3720` `production_zk_transfer_plan_rejects_partial_previous_state_spend` (asserts the plan rejects partial spends).

### 5.10 How to wire up the indexer / scanner

**Smallest code**: `tests/rgk-e2e/src/lib.rs:545-562` (open the indexer for
a covenant) + `tests/rgk-e2e/src/lib.rs:657-670` (apply a spend with
continuation proof).

```rust
// tests/rgk-e2e/src/lib.rs:545
let mut idx = InMemoryIndexer::new();
let initial_rgk_state = RgkStateCommitment::new(
    chain, covenant_id, asset_id, initial_state_digest, ReceiptPolicy::Any,
).map_err(|e| format!("initial state commitment: {e}"))?;
idx.open(chain, covenant_id, lineage_id, initial_rgk_state.clone(), open_outpoint, 1)
    .map_err(|e| format!("idx.open: {e}"))?;
```

```rust
// tests/rgk-e2e/src/lib.rs:657
idx.apply_spend_with_continuation(
    covenant_id,
    receipt_id,
    open_outpoint,
    new_outpoint,
    new_rgk_state.clone(),
    2,
    ContinuationProof {
        commitment: native_transition_report.continuation_commitment.to_bytes(),
        shape_root: native_transition_report.continuation_shape_root.to_bytes(),
        transition_digest: native_transition_report.transition_digest.to_bytes(),
    },
)
.map_err(|e| format!("apply_spend: {e}"))?;
```

**Wiring the scanner** (live test): `tests/rgk-e2e/tests/live_devnet.rs:121-159`:

```rust
// tests/rgk-e2e/tests/live_devnet.rs:121
let backend = WrpcBackend::connect_borsh(&url, WrpcNetwork::Devnet).await.unwrap();
let path = temp_db_path("rgk-devnet-scan");
let mut indexer = SledIndexer::open_path(&path).expect("open devnet scan cursor store");
let mut service = ScanService::new(
    &backend, &mut indexer, ScanServiceConfig::new(KaspaChainId::KaspaDevnet),
);
let tick = service.tick().expect("initialise devnet scan cursor");
assert!(tick.initialised_cursor);
indexer.flush().expect("flush devnet cursor");
```

The scan service's loop API is at `crates/rgk-sync/src/lib.rs:138-242` (`ScanService::tick`, `run_until_idle`). The trait that the `WrpcBackend` implements is `ScanBackend` at `crates/rgk-sync/src/lib.rs:53-61`.

**Resolver wiring** (after indexer is up): `tests/rgk-e2e/src/lib.rs:693-695`:

```rust
// tests/rgk-e2e/src/lib.rs:693
let mut resolver = RgkResolver::new(backend, &idx, chain);
resolver.reorg_safety_depth = 1;
let res = resolver.resolve_by_covenant(covenant_id);
```

**Live full pipeline** (one test, end to end): `tests/rgk-e2e/tests/live_covenant.rs:730-2658` is the gold reference — it runs the full pipeline (mine, fund, build covenant, sign, submit, wait, scan, index, resolve, assert `NativeTransitionedValid`).

**For a tutorial**: the cleanest "wire it up" recipe is:
1. `FixtureBackend::new(KaspaLocalToccata)` (`crates/rgk-kaspa/src/lib.rs:345-350`).
2. `InMemoryIndexer::new()` (`crates/rgk-indexer/src/lib.rs:944-953`).
3. `Indexer::open(...)` + `Indexer::apply_spend_with_continuation(...)` (`crates/rgk-indexer/src/lib.rs:956-...`).
4. `RgkResolver::new(&backend, &idx, chain)` (`crates/rgk-resolver/src/lib.rs:180-187`).
5. `resolver.resolve_by_covenant(covenant_id)` (`crates/rgk-resolver/src/lib.rs:191`).

---

## Drift Notes

The following gaps / surprises were noticed while writing this inventory.
Tutorial writers should treat them as "to be aware of, not to hide".

1. **`StealthLane` has no live example.** `LanePrivacyPolicy::StealthLane` exists at `crates/rgk-asset/src/native.rs:429` (tag `0x02`) and the `exposes_public_fields` / `as_u8` methods handle it, but neither `examples/silverscript/*.sil` nor any `rgk-e2e` test currently exercises it. The `rgk-walletd` HTTP API also omits it (the `PrivacyMode` enum at `crates/rgk-walletd/src/main.rs:312-317` is only `PrivateLane | PublicLineage`). Tutorials that advertise stealth as a real option need a placeholder example and a "no current evidence" disclaimer.

2. **Walletd `PrivacyMode` is a strict subset of `LanePrivacyPolicy`.** The daemon (`crates/rgk-walletd/src/main.rs:312-317`) does not currently surface `StealthLane`. This is an API inconsistency, not necessarily a bug — but the tutorial should not imply the two types are the same.

3. **`PrivacyMode::PublicLineage` and `LanePrivacyPolicy::PublicLineage` are the same word, different types.** The walletd's `PrivacyMode` is a serde enum (used at the JSON wire boundary), while `LanePrivacyPolicy` is the asset-side tag that flows into the on-chain state digest. The mapping is at `crates/rgk-walletd/src/main.rs:1823-1837` `resolver_state_name` (note: the file actually exposes a `state_to_name` mapping for `ResolverState`, not the privacy mapping — the privacy mapping happens implicitly via `AssetLane::privacy`).

4. **Receipts are not the proof.** `RgkReceipt` is the typed commitment the verifier emits; for `ProofMode::ZkReceipt` the actual ZK proof is a separate transport that the Toccata precompile consumes (`docs/ZK-BOUNDARY.md`). Tutorials must not show `RgkReceipt::encode_canonical` and claim "this is the ZK proof" — it's the public-input preimage; the proof is separate.

5. **`RgkTransition` is a phase-2 type but has a struct-literal constructor with no `new` method.** Production code should always go through `RgkContinuationPlan::finalize(witness_txid, daa_score, confirmation_depth)` (`crates/rgk-asset/src/native.rs:1524`). The unit-test fixture at `crates/rgk-asset/src/native.rs:3424-3445` shows the field layout; tutorial writers should treat the struct literal as "for tests" and route users through `finalize`.

6. **`receipt_id` is *derived*, not chosen.** `RgkReceipt` does not have an `id` field — the id is `receipt_commitment(&receipt) -> Bytes32` (`crates/rgk-core/src/commit.rs:100-103`). `ReceiptBuilder::build` returns it as the second tuple element (`crates/rgk-receipt/src/lib.rs:175`). Tutorials that let users "set" a receipt id are wrong.

7. **`RgkContinuationPlan` vs `RgkTransition` differ in `new_*` fields.** Phase 1 carries `new_allocation_shapes: Vec<RgkContinuationAllocationShape>` (no `encrypted_note_commitment` is committed until the txid exists), while phase 2 (`RgkTransition`) carries `new_allocations: Vec<RgkAllocation>` with a fully populated `RgkCovenantAnchor` whose `covenant_outpoint.transaction_id == witness_txid`. The `RgkContinuationPlan::finalize` source at `crates/rgk-asset/src/native.rs:1524-1574` is the conversion site; tutorial diagrams should not let the two `Vec<…>` types be confused.

8. **Resolver NEVER returns `OptimisticValid` or `SoftInvalid`.** This is a design rule, not a missing enum variant. `ResolverState` (`crates/rgk-resolver/src/lib.rs:42-108`) has only 13 hard-classified outcomes. Any tutorial that introduces a "pending" or "soft" state is a misunderstanding.

9. **`resolve_by_asset` panics the `Unknown` variant with a zero `covenant` if no match is found.** See `crates/rgk-resolver/src/lib.rs:399-410`:
   ```rust
   ResolverState::Unknown { covenant: [0u8; 32] }
   ```
   The zero-bytes covenant id is a sentinel. Callers should always check the variant before reading the covenant id; the `covenant()` helper at `crates/rgk-resolver/src/lib.rs:111-124` is safe because every variant has a `covenant` field, but `match` statements that destructure the unknown sentinel will see the all-zero id.

10. **The `FixtureBackend` is in `rgk-kaspa`, not `rgk-indexer`.** The `#[cfg(test)]` devnet harness uses both, but new contributors sometimes look for the in-memory chain backend in the indexer crate. Pointer: `crates/rgk-kaspa/src/lib.rs:345-350`.

11. **`rgk-walletd` is a single-file `main.rs` with no `lib.rs`.** It cannot be used as a library by another Rust binary; the only way to talk to it is HTTP via the axum router. Tutorial code that wants to embed wallet functionality must use the underlying crates (`rgk-asset`, `rgk-receipt`, `rgk-resolver`, `rgk-indexer`, `rgk-sync`) directly.

12. **`build_genesis_output` validates the spk is non-empty and the covenant id is non-zero, but does not require the spk to be a P2SH wrapper.** Callers must wrap with `spk_from_redeem_script` themselves (`crates/rgk-tx/src/lib.rs:1109-1115`).

13. **The receipt verifier refuses if `chain_id` mismatches even when the receipt would otherwise validate.** This is the canonical "domain separation" guarantee (`crates/rgk-receipt/src/lib.rs:215-222` and `crates/rgk-core/src/types.rs:248-252`). A mainnet receipt will never be accepted on a simnet. Tutorials that exercise this should make the chain id explicit, not implicit.

14. **`continuation_replay_reusing_spent_anchor_is_rejected` (`crates/rgk-asset/src/native.rs:4722-4736`) shows that the phase-1 commitment itself prevents reusing the spent outpoint's `transaction_id` as a future continuation output.** Worth highlighting as a property of the canonical phase-1 commitment, not just a property of the resolver.

15. **`rgk-zk/src/real_zk.rs` is a 338 KB Groth16 implementation behind the `real-zk` feature.** It is **not** the public API surface that the wiki should teach; the public surface is `rgk-zk/src/lib.rs` (the typed `ZkStatement`, `SemanticTransitionStatement`, `ZkProof`, `R0SuccinctPrecompileStack`). The real-zk module is a prover/verifier utility; tutorials that need it should reference it but route through the public types.

16. **No `cargo run --example …`.** Despite the directory name, `examples/` is purely Silverscript source + JSON artifacts + a contract matrix. There is no `[[example]]` section in any `Cargo.toml`. The runnable harness is `rgk-e2e` (test crate), not `rgk-walletd` (the daemon). Tutorial writers should not advertise a `cargo run --example` flow.

17. **`Cargo.toml` is at the repo root and lists 12 members, but `fuzz/` is a separate Cargo workspace** (`fuzz/Cargo.toml`) and is *not* part of the main workspace. `fuzz_targets/` lives under `fuzz/`. Tutorial writers should not suggest `cargo run -p fuzz_*` from the main `Cargo.toml`.

18. **`RgkProofPolicy::Hybrid` is defined but not exercised by any test or example.** See `crates/rgk-asset/src/native.rs:464-467`. Tutorials that want to mention it should note that the only validated forms are `VerifierReceipt` and `ZkReceipt`; `Hybrid` will validate structurally but is not currently wired to any verifier stack.

19. **`RgkAllocationProofShape::OneInZeroOut` is the only "burn-only" shape** (`crates/rgk-asset/src/native.rs:522`); `new_count() == 0`. This is the terminal burn shape used by NFT burn (`crates/rgk-asset/src/native.rs:4842-4870` `continuation_accepts_explicit_burn_for_supported_production_zk_shape`).

20. **The `ReceiptBuilder::build` returns `(RgkReceipt, ReceiptId, Vec<u8>)`** — the `ReceiptId` and the `bytes` are *not* the same thing. The `ReceiptId` is the 32-byte `receipt_commitment(&receipt)`; the `bytes` are the canonical encoding of the receipt itself. Both are needed downstream: the id for the indexer's replay set, the bytes for the verifier. Easy to confuse; tutorials should name both explicitly.
