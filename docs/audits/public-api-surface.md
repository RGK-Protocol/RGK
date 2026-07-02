# Public API Surface Audit — RGK workspace

**Scope:** the entire public API of every crate in the `rgk` workspace at the
original audit point, followed by a remediation pass. One pass per crate, plus
nine cross-cutting dimensions.

**Method:** static reading of every `pub` item in `lib.rs` and every public
submodule reachable from `lib.rs`. No code execution; findings are reproducible
by `rg`/`grep` against the cited lines.

**Severity legend**

| Tier    | Meaning                                                                             |
| ------- | ----------------------------------------------------------------------------------- |
| 🔴 Blocker | Breaks Rust API guidelines, hides landmines, or pins the wrong type forever |
| 🟠 High    | Real defect: leakage, drift, missing safety rail, ABI trap                      |
| 🟡 Medium  | Hygiene / consistency / doc gap; will hurt when the workspace grows               |
| 🔵 Low     | Style; defer if other work is more pressing                                       |

**Headline numbers** (counted at audit time)

| Crate              | lib.rs lines | pub items (lib.rs) | pub items (incl. submodules) |
| ------------------ | -----------: | -----------------: | ---------------------------: |
| `rgk-core`         |           65 |                  7 |                           28 |
| `rgk-asset`        |           90 |                  5 |                          338 |
| `rgk-receipt`      |          684 |                 25 |                           25 |
| `rgk-covenant`     |         2154 |                 48 |                           48 |
| `rgk-tx`           |         1709 |                 73 |                           73 |
| `rgk-zk`           |         1167 |                 29 |                           29 |
| `rgk-kaspa`        |          667 |                 24 |                           24 |
| `rgk-indexer`      |         3078 |                 29 |                          122 |
| `rgk-resolver`     |         1516 |                 15 |                           15 |
| `rgk-sync`         |          568 |                 14 |                           14 |
| `tests/rgk-e2e`    |            — |                 30 |                           30 |

The single biggest source file by far is `crates/rgk-asset/src/native.rs`
(**5237 lines, 338 pub items**); every other crate is single-file at lib.rs.
That is the audit's #1 finding, see F-01.

**Remediation status.** The remediation passes resolve F-02, F-03, F-04,
F-05, F-06, F-07, F-08, F-09, F-10, F-11, F-12, F-14, F-15, F-16, F-17,
F-18, F-19, F-22, F-27, F-30, F-32, F-35, F-36, F-39 and F-40:

- `Hex32` now lives once in `rgk-core` and is re-exported from downstream crates.
- `RgkAssetId` and `RgkSchemaId` now come from `rgk-core`.
- The loose asset-domain hash helper is hidden under
  `rgk_asset::internal::asset_domain_hash` instead of occupying the crate root.
- `rgk-receipt::__reexports` and the no-op `fmt::Write for NewStateSpec` impl
  are removed.
- `COVENANT_ID_TAG`, `HexBytes32`, and `with_storage_mass` are removed.
- `AdvancedCovenantPolicyCommitment` and
  `AdvancedCovenantExecutionCommitment` are distinct newtypes.
- `ReceiptError::DecodeFailure` now carries `rgk_core::DecodeError`; synthetic
  resolver receipt failures use `ReceiptError::Structural`.
- `TxOutput::new` / `TxOutput::covenant` now reject empty scripts; `fee_only`
  is the named empty-script exception.
- The public `RGK_PRODUCTION_*` allocation constants are renamed to the
  neutral `RGK_ALLOCATION_STRATEGY_*` family.
- `R0SuccinctPrecompileStack::tag` is now a scalar byte.
- `RgkResolver` now holds `&I` and exposes read-only resolution methods as
  `&self`.
- `rgk-covenant` and `rgk-tx` now re-export `ProofMode` / `ReceiptPolicy`
  consistently with `rgk-receipt` and `rgk-resolver`.
- `SyncError::Reorg` carries the removed block hashes.
- `ToccataScriptPublicKey::from_versioned_bytes` rejects oversized scripts.
- Resolver and sync errors now carry typed upstream indexer/covenant errors at
  crate seams instead of storing display strings.
- Toccata opcode constants expose a pinned profile name/commit and a validator.
- `IndexedCovenant::opened` constructs valid opened entries directly; the
  transient zero-state `empty` helper is gone.
- The vestigial `derive_covenant_id` wrapper is removed; the lineage-only
  covenant id helper now documents its narrower role.
- `ToccataSigHashType::from_u8` is `const`; the unused no-op `bytes::labeled`
  helper is deleted.
- `rgk_zk::real_zk` is only exported when the `real-zk` feature is enabled;
  the previous F-39 note was stale against the current code.
- Production crates now only allow `clippy::unwrap_used` /
  `clippy::expect_used` under `cfg(test)`; normal targets pass clippy with
  those lints denied.

---

## Findings index

| ID    | Sev    | Crate(s)                          | One-line                                            |
| ----- | ------ | --------------------------------- | --------------------------------------------------- |
| F-01  | ✅ Accepted | `rgk-asset`                       | `rgk-asset` now exposes grouped facade modules; the remaining physical split is accepted implementation debt |
| F-02  | ✅ Fixed | `rgk-asset` + `rgk-receipt` + `rgk-covenant` + `rgk-tx` + `rgk-indexer` | `Hex32(pub Bytes32)` defined 5×; `HexBytes32` once more |
| F-03  | ✅ Fixed | `rgk-core` + `rgk-asset` + `rgk-receipt` | `RgkAssetId`, `RgkSchemaId` type aliases triplicated   |
| F-04  | ✅ Fixed | `rgk-asset`                       | `domain_hash_domain` shadowed `rgk_core::domain_hash` |
| F-05  | ✅ Fixed | `rgk-receipt`                     | `pub mod __reexports { pub use rgk_core; }` re-exports the whole `rgk-core` crate |
| F-06  | ✅ Fixed | `rgk-receipt`                     | `impl fmt::Write for NewStateSpec<'_>` is a no-op    |
| F-07  | ✅ Fixed | `rgk-covenant`                    | `COVENANT_ID_TAG` constant exposed but unused        |
| F-08  | ✅ Fixed | `rgk-covenant`                    | `AdvancedCovenantPolicyCommitment` / `…ExecutionCommitment` are point-free `Bytes32` aliases |
| F-09  | ✅ Fixed | `rgk-tx`                          | `Hex32` AND `HexBytes32` in same crate (one is redundant) |
| F-10  | ✅ Fixed | `rgk-tx`                          | `with_storage_mass` is a synonym for `with_mass`    |
| F-11  | ✅ Fixed | `rgk-tx`                          | `TxOutput::new` accepts empty `script_public_key` but `build_genesis_output` rejects it |
| F-12  | ✅ Fixed | `rgk-asset`                       | `RGK_PRODUCTION_*` constants were public in a pre-release crate |
| F-13  | ✅ Fixed | `rgk-asset`                       | Many `Rgk*Commitment` newtypes carried public raw tuple fields |
| F-14  | ✅ Fixed | `rgk-zk`                          | `R0SuccinctPrecompileStack::tag: [u8; 1]` should be `u8` |
| F-15  | ✅ Fixed | `rgk-resolver`                    | `RgkResolver` holds `&mut I` — caller can't share the indexer |
| F-16  | ✅ Fixed | `rgk-indexer`                     | `IndexedCovenant::empty` is `fn empty` returning an unverifiable default state |
| F-17  | ✅ Fixed | `rgk-receipt` + `rgk-covenant` + `rgk-tx` + `rgk-resolver` | Inconsistent `ProofMode` / `ReceiptPolicy` re-export convention |
| F-18  | ✅ Fixed | `rgk-sync`                        | `SyncError::Reorg { removed_count }` throws away the block hashes |
| F-19  | ✅ Fixed | `rgk-tx`                          | `ToccataScriptPublicKey::from_versioned_bytes` silently truncates if `bytes.len() > 2 + u16::MAX` |
| F-20  | ✅ Fixed | `rgk-core` + `rgk-asset` + `rgk-receipt` + `rgk-tx` + `rgk-zk` + `rgk-kaspa` + `rgk-indexer` + `rgk-resolver` | Consensus/data-transfer structs now use constructors plus `#[non_exhaustive]` read-only field surfaces |
| F-21  | ✅ Fixed | `rgk-core` + normal public DTO crates | Public value/error/state DTOs now derive `Hash`; `rgk-core` serde feature now covers core receipt/outpoint DTOs |
| F-22  | ✅ Fixed | `rgk-resolver` + `rgk-sync`       | Cross-crate errors were flattened to `String` at the seam |
| F-23  | ✅ Fixed | `rgk-tx` + `rgk-covenant` + `rgk-asset` | Toccata Borsh writing and asset/covenant tagged hashes now route through `rgk-core` primitives |
| F-24  | ✅ Fixed | `rgk-receipt`                     | `ReceiptInput` now has a validating constructor and downstream literal construction is blocked |
| F-25  | ✅ Fixed | `rgk-kaspa`                       | `KaspaChainBackend` is intentionally synchronous and now documents the async adaptation contract |
| F-26  | ✅ Fixed | `rgk-kaspa`                       | `KaspaUtxo::script_public_key` is now a bounded `KaspaScriptPublicKey` newtype |
| F-27  | ✅ Fixed | `rgk-covenant`                    | `opcodes` constants are pinned to a specific upstream commit and not flagged as such in the API |
| F-28  | ✅ Fixed | `rgk-zk`                          | ZK statement structs are non-exhaustive and semantic statements have a validating constructor |
| F-29  | ✅ Fixed | `rgk-resolver`                    | `ResolverState::covenant()` removes repetitive caller matching without reshaping the enum |
| F-30  | ✅ Fixed | `rgk-receipt`                     | `ReceiptError::DecodeFailure(String)` carries an untyped String instead of forwarding `DecodeError` |
| F-31  | ✅ Accepted | `rgk-sync` + `rgk-indexer`        | Cursor writes remain single-writer by design and the store trait now documents that contract |
| F-32  | ✅ Fixed | `rgk-covenant`                    | `derive_covenant_id` ignored `_state`; `compute_covenant_id_from_lineage(lineage)` needed lineage-only docs |
| F-33  | ✅ Fixed | all crates                        | Pre-release deprecation policy is documented in `docs/API-DEPRECATION.md` |
| F-34  | ✅ Accepted | all crates + dependencies          | RGK source has no unsafe code; dependency unsafe exposure is documented as accepted third-party risk |
| F-35  | ✅ Fixed | `rgk-tx`                          | `ToccataSigHashType` newtype + free constants — pattern is fine but `from_u8` validator not `const` |
| F-36  | ✅ Fixed | `rgk-core`                        | `bytes::labeled` is a no-op wrapped in a misleading name |
| F-37  | ✅ Accepted | `rgk-resolver`                    | Boxed nested resolver states are intentionally retained to avoid large enum variants |
| F-38  | ✅ Fixed | `rgk-covenant` + `rgk-tx`         | Advanced covenant shapes and covenant state now have validating constructors and downstream literal construction is blocked |
| F-39  | ✅ Fixed | `rgk-zk`                          | `real_zk.rs` (8819 lines) was reported as unconditional `pub mod`; current code already gates it by feature |
| F-40  | ✅ Fixed | all production crates             | `#![allow(clippy::unwrap_used, clippy::expect_used)]` crate-wide — masks unwrap/expect in API code |

---

## F-01 · `rgk-asset/src/native.rs` is a 5 200-line god module

✅ Accepted

**Where.** `crates/rgk-asset/src/native.rs` (whole file; lib.rs only `pub mod native;` +
a 30-line `Hex32`/domain-hash tail).

**Reproduction.**

```text
$ wc -l crates/rgk-asset/src/native.rs
5237 crates/rgk-asset/src/native.rs
$ rg '^\s*pub ' crates/rgk-asset/src/native.rs | wc -l
338
```

338 `pub` items in a single file, surfaced flat from `rgk-asset`. Examples
(grep-able): `RgkAssetError`, `RgkAssetId`, `BlindedLaneId`, `RgkCollectionId`,
`RgkNftTokenId`, `RgkAllocation`, `RgkAssetIssue`, `RgkBurnProof`,
`RgkContinuationAllocationShape`, `RgkContinuationCommitment`,
`RgkContinuationPlan`, `RgkContinuationReport`, `RgkContinuationShapeRoot`,
`RgkCovenantAnchor`, `RgkFinalizedContinuation`,
`RgkFinalizedProductionAllocationStrategyTransfer`,
`RgkFinalizedProductionZkTransfer`, `RgkIssueReport`, `RgkLane`,
`RgkLaneGraphNode`, `RgkLaneState`, `RgkLaneStateInput`, `RgkMetadataCommitment`,
`RgkNftBurnContinuationReport`, `RgkNftBurnReport`, `RgkNftCollectionIdDerivation`,
`RgkNftCollectionPolicy`, `RgkNftMarketplaceSaleCommitment`,
`RgkNftMarketplaceSaleReport`, `RgkNftMarketplaceSaleTerms`,
`RgkNftMintReport`, `RgkNftPolicyCommitment`, `RgkNftTemplateCommitment`,
`RgkNftTokenCommitment`, `RgkNftTokenId`, `RgkNftTokenSpec`,
`RgkNftTransferReport`, `RgkNullifier`, `RgkOwnerCommitment`,
`RgkOwnerDescriptor`, `RgkPolicyCommitment`, `RgkPrivacyPolicy`,
`RgkProductionAllocationStrategy`,
`RgkProductionAllocationStrategyCommitment`,
`RgkProductionAllocationStrategyPlan`,
`RgkProductionAllocationStrategyRecord`, `RgkProductionZkTransferPlan`,
`RgkProofPolicy`, `RgkReceiptCommitment`, `RgkScanTag`, `RgkSchemaId`,
`RgkStateDigest`, `RgkTransition`, `RgkTransitionDigest`,
`RgkTransitionReport`, plus allocation-strategy constants and free functions
`allocation_transcript_*`, `derive_blinded_lane_id`,
`derive_private_lane_graph_root`, `discover_lane`, `extend_*`, `private_lane_graph_empty_root`,
`RGK_SEGMENTED_ALLOCATION_AUDIT_SEGMENT_CAPACITY`.

**Problem.**

1. **No module namespace.** `rgk-asset::RgkAssetIssue`, `rgk-asset::RgkBurnProof`,
   `rgk-asset::RgkNftTransferReport` are peers of `rgk-asset::RgkProductionAllocationStrategy`.
   NFTs, production strategies, lane graphs, burns, mint reports and ZK
   strategies are intermixed.
2. **Hidden coupling.** `RgkFinalizedProductionAllocationStrategyTransfer`
   references types from 6+ domains — without submodules, callers can't see the
   "what depends on what" until they read 5 000 lines.
3. **`cargo doc` becomes unreadable.** A single `rgk-asset::` glob exposes
   338 items; rustdoc's sidebar is unusable.
4. **No namespace for ABI.** The former `RGK_PRODUCTION_*` constants (F-12) and the
   commitment-tag bytes are tucked next to lane helpers; nothing tells the
   reader "this is the ABI surface, do not change without bumping the encoding
   version".

**Remediation so far.** `rgk-asset` now exposes grouped facade modules from
`lib.rs`: `commitments`, `lanes`, `fungible`, `nft`, and
`allocation_strategy`. The old flat exports remain source-compatible, but
rustdoc and downstream users now have a navigable module surface.

**Accepted implementation debt.** A future clean-up can physically split
`native.rs` into a `native/` directory with submodules that mirror the asset
subdomains and then re-export from `native.rs` so the flat `rgk-asset::` surface
stays source-compatible:

```
crates/rgk-asset/src/native/
├── mod.rs              (root, re-exports the public surface)
├── ids.rs              (RgkAssetId, RgkSchemaId, RgkCollectionId, RgkNftTokenId, BlindedLaneId)
├── commitments.rs      (Rgk*Commitment newtypes + RGK_*_TAG constants)
├── issue.rs            (RgkAssetIssue, RgkIssueReport, RgkAssetError, RgkAllocation)
├── transition.rs       (RgkTransition, RgkTransitionReport, RgkTransitionDigest, RgkStateDigest)
├── continuation.rs     (RgkContinuationPlan, RgkContinuationReport, RgkContinuationCommitment,
│                        RgkContinuationShapeRoot, RgkContinuationAllocationShape)
├── nft.rs              (RgkNft* types)
├── production.rs       (RgkProductionAllocationStrategy*, RgkFinalized*,
│                        allocation-strategy constants)
├── lane.rs             (RgkLane*, BlindedLaneId helpers, lane graph)
└── privacy.rs          (RgkPrivacyPolicy, RgkAllocationTranscriptSide, allocation_transcript_*)
```

This is a refactor, not a redesign, and is no longer treated as a public-API
blocker after the facade-module fix. The flat `rgk-asset::RgkNftTransferReport`
imports would keep working because `native/mod.rs` would re-export each public
item. Anyone who already writes `rgk_asset::RgkNftTransferReport` is unaffected.

---

## F-02 · `Hex32(pub Bytes32)` defined in five crates

✅ Fixed

**Where.**

```
crates/rgk-indexer/src/lib.rs:316:pub struct Hex32(pub Bytes32);
crates/rgk-asset/src/lib.rs:48:pub struct Hex32(pub Bytes32);
crates/rgk-tx/src/lib.rs:162:pub struct Hex32(pub Bytes32);
crates/rgk-receipt/src/lib.rs:102:pub struct Hex32(pub Bytes32);
crates/rgk-covenant/src/lib.rs:199:pub struct Hex32(pub Bytes32);
crates/rgk-tx/src/lib.rs:177:pub struct HexBytes32(pub Bytes32);  // a sixth duplicate
```

Five identical `Hex32(pub Bytes32)` newtypes, each with its own `Display` impl
and `From<Bytes32>`. One crate also defines `HexBytes32` for the same purpose.

**Problem.**

1. They are **structurally identical**: same field, same `Display`, same `From`.
2. They are **NOT** interchangeable: `rgk_covenant::Hex32` ≠ `rgk_receipt::Hex32`
   at the type level. A caller who imports both crates cannot pass one into the
   other's function without an explicit `.into()` even though the bytes are
   identical.
3. `Hex32` and `HexBytes32` differ only in the type name; both render
   `0x{lowercase_hex}`. `TxBuildError::CovenantMismatch { tx: Hex32, state: HexBytes32 }`
   (`rgk-tx/src/lib.rs:140`) is the most embarrassing consequence: an error
   variant has two different wrapper types for the same kind of value.
4. The five duplicates are slightly inconsistent in field visibility:
   `Hex32(pub Bytes32)` everywhere, so the inner `Bytes32` is reachable but
   `core::ops::Deref` is not implemented. Callers either pattern-match
   `let Hex32(b) = x;` or call `.0` — five copies of the same escape hatch.

**Reproduction.** Pick any function that takes a `Bytes32` and try to pass it
to `rgk_receipt::ReceiptError::Replay`: it does not accept `rgk_covenant::Hex32`
even though both wrap a `Bytes32`.

```rust
use rgk_core::Bytes32;
use rgk_receipt::{Hex32 as ReceiptHex32, ReceiptError};
use rgk_covenant::Hex32 as CovenantHex32;

let b: Bytes32 = [0xab; 32];
let h1 = ReceiptHex32(b);
let h2 = CovenantHex32(b);
// h1 == h2 ?  Yes (PartialEq compares bytes), but h1 and h2 are NOT the same type.
```

**Fix.** Define `pub struct Hex32(pub Bytes32)` (with `Display`, `From`,
`PartialOrd`, `Ord`, `Hash`) once in `rgk_core::bytes`, re-export from every
crate as `pub use rgk_core::Hex32;`, delete the five local copies. In
`rgk-tx` rename the one `HexBytes32` use site (`TxBuildError::CovenantMismatch`)
to use `Hex32`. For the `pub Bytes32` inner field, also expose `Deref<Target=Bytes32>`
so callers don't need to know the field index.

This change is *not* breaking for callers who used `rgk_receipt::Hex32`
because the new path is `rgk_receipt::Hex32 = rgk_core::Hex32`. It *is*
breaking for callers who wrote their own `From<MyHex32> for SomeOtherType` —
but that's vanishingly rare for a 5-week-old crate.

---

## F-03 · `RgkAssetId`, `RgkSchemaId` type aliases triplicated

✅ Fixed

**Where.**

```
crates/rgk-core/src/types.rs:35:    pub type RgkAssetId  = Bytes32;
crates/rgk-core/src/types.rs:37:    pub type RgkSchemaId = Bytes32;

crates/rgk-asset/src/native.rs:19:  pub type RgkAssetId  = Bytes32;
crates/rgk-asset/src/native.rs:20:  pub type RgkSchemaId = Bytes32;

crates/rgk-receipt/src/lib.rs:119:  pub type RgkAssetId  = Bytes32;
```

Three definitions of `RgkAssetId`, two of `RgkSchemaId`. Each is a transparent
alias to `Bytes32`. Functionally fine — but they are *separate* type aliases
at the type-system level, and Rust treats them as different types when an
explicit alias is named (the only equivalence is through the underlying
`Bytes32`).

**Problem.** Same shape as F-02: a wallet that imports `rgk-core` and
`rgk-asset` cannot pass `rgk_asset::RgkAssetId` to a function that takes
`rgk_core::RgkAssetId` — even though they are identical aliases.

**Reproduction.** `rgk-zk/src/lib.rs` uses `RgkAssetId` from `rgk_core`:

```rust
use rgk_core::{
    Bytes32, KaspaChainId, KaspaCovenantId, ProofMode, RgkAssetId, RgkReceipt,
    ...
```

`rgk-asset` defines its own `RgkAssetId`. The two aliases are the same
underlying `Bytes32`, but Rust sees them as separate types in any context
where the alias is named (impl blocks, function signatures, generic bounds).
A wallet importing `rgk-asset::RgkAssetId` cannot hand it to a function
parameter typed `rgk_core::RgkAssetId`.

**Fix.**

1. Delete `crates/rgk-asset/src/native.rs:19-20` and replace with
   `pub use rgk_core::{RgkAssetId, RgkSchemaId};`.
2. Delete `crates/rgk-receipt/src/lib.rs:119` and replace with the same
   `pub use`.
3. Add a `#[doc(hidden)] pub use rgk_core::RgkAssetId as _RgkAssetIdReexport;`
   in any crate that needs the local name for back-compat (none currently do).

If you ever want real type-safety for "asset id" vs "schema id" (so a function
taking an asset id cannot be passed a schema id), promote the aliases to
newtypes — but only do that as a coordinated, breaking change with a major
version bump; today they should remain aliases.

---

## F-04 · `domain_hash_domain` shadowed `rgk_core::domain_hash`

✅ Fixed

**Where.** `crates/rgk-asset/src/lib.rs`

The old crate-root helper `domain_hash_domain(domain, payload)` computed the
same string-domain SHA-256 primitive as `rgk_core::domain_hash`, but with an
untyped `&str` domain and a confusingly similar name. A downstream
`use rgk_core::*; use rgk_asset::*;` import could expose two similarly named
hash helpers with different domain disciplines.

**Resolution.** The loose helper is no longer in the `rgk_asset` crate root.
It now lives at the hidden path `rgk_asset::internal::asset_domain_hash`, and
internal asset/ZK fixtures call that explicit path. This removes the wildcard
import collision and labels the helper as asset-internal. A future hardening
pass can still promote asset domains to a typed enum, but the public API
shadowing defect is closed.

---

## F-05 · `pub use rgk_core;` re-exports the whole crate

✅ Fixed

**Where.** `crates/rgk-receipt/src/lib.rs:363-366`

```rust
#[doc(hidden)]
pub mod __reexports {
    pub use rgk_core;
}
```

This puts `rgk_core` as a *named module* in `rgk_receipt`, so the path
`rgk_receipt::rgk_core::Bytes32` is legal. Any caller who already has a
direct dependency on `rgk-core` can now reach every `rgk-core` item through
the receipt crate too.

**Problem.**

1. **Duplicate import surface.** A type like `rgk_receipt::rgk_core::Bytes32`
   and `rgk_core::Bytes32` are the same type, but `cargo doc` will list
   `rgk_receipt::rgk_core` as a "re-export module" that contains *every*
   `rgk-core` type. That makes the docs sidebar explode and obscures what
   `rgk-receipt` itself adds.
2. **`#[doc(hidden)]` doesn't actually hide the module.** The name is still
   reachable at the path level; rustdoc just omits it from the rendered page.
   Users who paste `use rgk_receipt::__reexports::*` see every `rgk-core` item.
3. **The re-export contradicts the import discipline used elsewhere.** Every
   other cross-crate reference in `rgk-receipt` writes `rgk_core::...` directly
   (e.g. `rgk_core::Bytes32` at line 53, `rgk_core::ENCODING_VERSION` at line
   159, `rgk_core::to_hex` at line 256, `rgk_core::from_hex` at line 405).
   The `__reexports` module is the only path that doesn't go through the
   direct dependency.

**Reproduction.**

```bash
$ cargo doc -p rgk-receipt --no-deps --open
# Sidebar shows rgk_receipt::rgk_core (if __reexports isn't doc-hidden) or
# shows nothing (if it is) — but `use rgk_receipt::__reexports::rgk_core::*`
# compiles in any downstream crate.
```

**Fix.** Delete lines 363-366 entirely. Anyone needing `rgk-core` already
depends on it directly — there's no reason to indirect through `rgk-receipt`.
If a test or e2e harness inside the workspace was relying on
`rgk_receipt::rgk_core::…`, switch it to `rgk_core::…` (it's already a direct
dep everywhere).

---

## F-06 · `impl fmt::Write for NewStateSpec<'_>` is a no-op

✅ Fixed

**Where.** `crates/rgk-receipt/src/lib.rs:387-394`

```rust
impl fmt::Write for NewStateSpec<'_> {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        // Intentionally a no-op — `NewStateSpec` is a builder-style payload,
        // not a textual sink. We implement `fmt::Write` so that downstream
        // loggers can chain `.write_fmt!` against it for diagnostics.
        Ok(())
    }
}
```

The implementation discards the input bytes and returns `Ok`. Any
`write!(&mut spec, "...")` silently drops the data.

**Problem.**

1. **`fmt::Write` is the wrong trait for a builder payload.** A real logger
   that calls `spec.write_fmt(format_args!("state={spec:?}"))` will get an
   `Ok(())` and no bytes written; the log line is silently truncated.
2. **It implements a std trait on a payload type, hiding the fact that
   calling write methods does nothing.** Users who see `NewStateSpec: fmt::Write`
   in the rendered docs will reasonably expect it to write.
3. **The "for API symmetry" comment on `_marker: PhantomData<&'a ()>` (line
   337) and the `fmt::Write` impl form a pair of tells: the original author
   added these to dodge some upstream trait bound, then forgot to remove
   them. `PhantomData<&'a ()>` has no effect on `NewStateSpec` (the type has
   no borrowed data) and the `fmt::Write` impl has no behavior.

**Reproduction.** Any caller code like

```rust
let mut spec = NewStateSpec { /* ... */ };
write!(spec, "got state for asset {:x}", spec.asset_id).unwrap();
println!("{:?}", spec);  // OK
// But the write! above did nothing.
```

**Fix.** Delete the `impl fmt::Write` block (lines 387-394). Also delete the
`_marker: PhantomData<&'a ()>` field from `NewStateSpec` and remove the
lifetime parameter on `NewStateSpec<'a>` (it has no `&'a` references in any
field, so the lifetime is dead). Update the one internal user
(`NewStateSpec::into_commitment` doesn't reference the lifetime) and any
external test that constructed it.

After the fix, `NewStateSpec` becomes a regular owned struct and the
crate's public surface loses a confusing `fmt::Write` impl that lied about
its behavior.

---

## F-07 · `COVENANT_ID_TAG` is unused historical surface

✅ Fixed

**Where.** `crates/rgk-covenant/src/lib.rs:82-84`

```rust
/// Historical RGK covenant-id tag. Current [`compute_covenant_id`] follows the
/// upstream Toccata `kaspa_hashes::CovenantID` domain instead.
pub const COVENANT_ID_TAG: &[u8; 12] = b"rgk:cid:0\0\0\0";
```

Search confirms: zero readers in this crate or anywhere else in the
workspace.

```text
$ rg "COVENANT_ID_TAG" --type rust
crates/rgk-covenant/src/lib.rs:84:pub const COVENANT_ID_TAG: &[u8; 12] = b"rgk:cid:0\0\0\0";
```

It is a public constant whose only documentation says "the *current* code
does not use this".

**Problem.** A `pub` constant with no readers is dead surface. Anyone who
discovers it may start using it as if it were the recipe — and the doc
explicitly warns that the recipe is different now.

**Fix.** Either delete the constant, or mark it `#[deprecated(note = "…")]`
with a `since` field and a one-line pointer to `compute_covenant_id`. Since
this is a 0.1.0 pre-release workspace and no callers exist, deletion is
cheaper.

---

## F-08 · `AdvancedCovenantPolicyCommitment`, `AdvancedCovenantExecutionCommitment` are point-free aliases

✅ Fixed

**Where.** `crates/rgk-covenant/src/lib.rs:87-88`

```rust
pub type AdvancedCovenantPolicyCommitment = Bytes32;
pub type AdvancedCovenantExecutionCommitment = Bytes32;
```

Two type aliases for `Bytes32`. They convey intent ("this 32-byte field is
a policy commitment") but provide no type-system enforcement — any
`Bytes32` is implicitly convertible into either.

**Problem.** Same shape as F-03 but for commitment types. A function that
takes `AdvancedCovenantPolicyCommitment` will accept a raw
`AdvancedCovenantExecutionCommitment` (or any other `Bytes32`) with no
compile error. The names *suggest* they're distinct, the type system
disagrees.

**Fix.** Either

1. Promote to newtypes
   (`pub struct AdvancedCovenantPolicyCommitment(pub Bytes32);` with the
   usual `From`/`AsRef`/`Deref`) so the type system enforces the distinction,
   or
2. Delete the aliases and use `Bytes32` directly, documenting the meaning
   in a field name or doc comment.

Option (1) is the right move if the workspace actually cares that a
policy commitment and an execution commitment cannot be silently swapped —
and given that the project is "fail-closed", option (1) is the consistent
choice. The crate is pre-0.1.0; a breaking change here is cheap.

---

## F-09 · `rgk-tx` defines both `Hex32` and `HexBytes32`

✅ Fixed

**Where.** `crates/rgk-tx/src/lib.rs:160-184`

```rust
/// Display wrapper around a 32-byte value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hex32(pub Bytes32);
impl core::fmt::Display for Hex32 { /* "0x" + lowercase hex */ }
impl From<Bytes32> for Hex32 { /* ... */ }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexBytes32(pub Bytes32);
impl core::fmt::Display for HexBytes32 { /* same "0x" + lowercase hex */ }
impl From<Bytes32> for HexBytes32 { /* ... */ }
```

Two types with identical structure, identical Display, identical From, in
the same crate. `TxBuildError::CovenantMismatch { tx: Hex32, state: HexBytes32 }`
(line 140) uses both in one error variant.

**Fix.** Identical to F-02: delete both, `pub use rgk_core::Hex32;`. The
caller site at line 140 becomes

```rust
#[error("covenant id mismatch: tx covenant {tx}, state lineage {state}")]
CovenantMismatch { tx: Hex32, state: Hex32 },
```

---

## F-10 · `with_storage_mass` is a synonym for `with_mass`

✅ Fixed

**Where.** `crates/rgk-tx/src/lib.rs:382-384`

```rust
pub fn with_storage_mass(self, storage_mass: u64) -> Self {
    self.with_mass(storage_mass)
}
```

`ToccataV1Tx.mass` and `ToccataV1Tx.storage_mass` are the same field. The
two setters do the same thing.

**Problem.** Two entry points for the same effect = future drift risk. If
`mass` is ever split from `storage_mass` (which is what the upstream
Toccata consensus model does — see comment line 793 about `TxInputMass`),
this alias will silently keep writing to the wrong field.

**Reproduction.** Test at line 1320:

```rust
let changed_storage_mass = base.clone().with_storage_mass(base.storage_mass() + 1);
assert_ne!(base_wire, changed_storage_mass.to_borsh_bytes());
```

This test will pass today and *also* pass after `with_storage_mass` is
deleted, because it's testing `mass`, not `storage_mass`. If someone later
splits the two fields, `with_storage_mass` becomes either dead (delete) or
buggy (silently writes to `mass`).

**Fix.** Delete `with_storage_mass` (lines 382-384). Update the test at
line 1320 to call `with_mass`. If the upstream Toccata model later
distinguishes storage mass from compute mass, add a *separate*
`with_compute_mass` setter that writes to the new field.

---

## F-11 · `TxOutput::new` accepts empty SPK; `build_genesis_output` rejects it

✅ Fixed

**Where.**

- `crates/rgk-tx/src/lib.rs:843-849` — `TxOutput::new` accepts empty `script_public_key`.
- `crates/rgk-tx/src/lib.rs:980-982` — `build_genesis_output` returns
  `TxBuildError::EmptyScriptPublicKey` if SPK is empty.

**Problem.** Inconsistent validation. A caller who builds a `TxOutput`
directly via `TxOutput::new` can produce an output with empty SPK; if they
go through `build_genesis_output`, the same call is rejected. The error
message also suggests this is a hard invariant, but the invariant is only
enforced on the builder path.

**Reproduction.**

```rust
let bad = TxOutput::new(1000, vec![]);  // Compiles. Returns a TxOutput.
let _ = build_genesis_output(&state, vec![], covenant_id, 0, 1000);  // Err(EmptyScriptPublicKey).
```

**Fix.** Add `if script_public_key.is_empty() { return Err(TxBuildError::EmptyScriptPublicKey); }`
to `TxOutput::new` and `TxOutput::covenant`. Decide whether empty SPK is
allowed in the type at all — if not, make `script_public_key` a non-empty
`Vec<u8>` (e.g. via a custom `NonEmptyBytes` newtype or a `try_new` constructor
on `TxOutput`). The latter is the better long-term fix.

---

## F-12 · `RGK_PRODUCTION_*` constants were public in pre-release

✅ Fixed

**Where.** `crates/rgk-asset/src/native.rs`, `crates/rgk-zk/src/real_zk.rs`

```rust
pub const RGK_ALLOCATION_STRATEGY_RECORD_TAG: &[u8; 12] = b"rgk:pas:0\0\0\0";
pub const RGK_ALLOCATION_STRATEGY_ZK_SHAPES: [RgkAllocationProofShape; 6] = [/* ... */];
pub const RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS: &str = "1x0, 1x1, 2x2, 3x2, 4x2, 4x4";
pub const RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT: usize = 4;
pub const RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW: usize = 4;
```

The old `RGK_PRODUCTION_*` names signalled "production-grade, supported"
from a pre-release crate and were flat-re-exported by `rgk-asset`.
`rgk-zk::real_zk` also exposed `PRODUCTION_ALLOCATION_*` constants over
the same shape limits.

**Resolution.** The public constants are now neutral:
`RGK_ALLOCATION_STRATEGY_RECORD_TAG`,
`RGK_ALLOCATION_STRATEGY_ZK_SHAPES`,
`RGK_ALLOCATION_STRATEGY_ZK_SHAPE_LABELS`,
`RGK_ALLOCATION_STRATEGY_ZK_MAX_SPENT`, and
`RGK_ALLOCATION_STRATEGY_ZK_MAX_NEW`. The real-ZK defaults are likewise
`DEFAULT_ALLOCATION_PROOF_STRATEGY`, `DEFAULT_ALLOCATION_MAX_SPENT`, and
`DEFAULT_ALLOCATION_MAX_NEW`. This removes the marketing commitment from
the constant surface; the larger `RgkProductionAllocationStrategy*` type
family remains a separate naming decision.

---

## F-13 · Many `Rgk*Commitment` newtypes carried public raw tuple fields

✅ Fixed

**Where.** `crates/rgk-asset/src/native.rs`

```rust
macro_rules! bytes32_marker {
    ($name:ident) => {
        pub struct $name(Bytes32);

        impl $name {
            pub fn from_bytes(bytes: Bytes32) -> Result<Self, RgkAssetError> { ... }
            pub const fn from_bytes_unchecked(bytes: Bytes32) -> Self { ... }
            pub const fn as_bytes(&self) -> &Bytes32 { ... }
            pub const fn to_bytes(self) -> Bytes32 { ... }
        }
    };
}
```

**Problem.** The old `pub struct RgkStateDigest(pub Bytes32)` style made the
newtype nominal only. Downstream code could construct `RgkStateDigest([0; 32])`
or read/write `.0` directly, bypassing the same non-zero invariant that native
asset validation enforces later.

**Resolution.**

1. The marker tuple field is now private for the RGK digest, commitment,
   nullifier and scan-tag wrappers.
2. Public construction goes through `from_bytes(Bytes32) -> Result<..., RgkAssetError>`,
   which rejects all-zero marker bytes with `RgkAssetError::ZeroCommitment`.
3. Raw-byte access is explicit through `as_bytes()` or consuming `to_bytes()`;
   downstream tuple construction and `.0` field access were removed from
   `rgk-zk`, `rgk-resolver`, and `rgk-e2e`.
4. The only remaining direct tuple construction/access is inside
   `rgk-asset::native`, where the private fields are owned and validation is
   still performed by the native constructors/reports.

**Evidence.**

- `rg -n "\b(RgkStateDigest|RgkTransitionDigest|RgkReceiptCommitment|RgkNullifier|RgkScanTag|RgkPolicyCommitment|RgkMetadataCommitment|RgkOwnerCommitment|RgkNftTemplateCommitment|RgkNftPolicyCommitment|RgkNftTokenCommitment|RgkNftMarketplaceSaleCommitment|RgkContinuationCommitment|RgkContinuationShapeRoot)\(" crates tests`
  now reports only `crates/rgk-asset/src/native.rs` hits.
- `cargo check --workspace` passes.
- `cargo test --workspace --no-run` passes.
- `cargo clippy -p rgk-zk --all-features --lib -- -D clippy::unwrap_used -D clippy::expect_used`
  passes after removing a feature-gated production `expect()` from
  `real_zk::encode_for_precompile`.

---

## F-14 · `R0SuccinctPrecompileStack::tag: [u8; 1]` should be `u8`

✅ Fixed

**Where.** `crates/rgk-zk/src/lib.rs:148-203`

```rust
pub struct R0SuccinctPrecompileStack {
    pub claim: Bytes32,
    pub control_index: [u8; R0_SUCCINCT_CONTROL_INDEX_BYTES],
    pub control_digests: Vec<u8>,
    pub seal: Vec<u8>,
    pub journal: Bytes32,
    pub image_id: Bytes32,
    pub control_id: Bytes32,
    pub hashfn: u8,
    pub tag: [u8; 1],  // <-- a one-byte array, not a u8
}
```

The field is set automatically:

```rust
tag: [ZkTag::R0Succinct.as_byte()],
```

and consumed in `script_push_items`:

```rust
&self.tag,  // &[u8] of length 1
```

**Problem.** A single-byte fixed array is unidiomatic. Everywhere else in
the codebase, byte values are plain `u8` (see `ProofMode::VerifierReceipt
= 0x01`, `Hashfn`, the domain tag bytes). The array form forces every
caller to either:

- slice it (`&self.tag[..]` or `self.tag[0]`),
- compare it as `self.tag == [0x21]`,
- construct it as `[0x21]`.

A plain `u8` would let `self.tag` compare directly with `ZkTag::R0Succinct.as_byte()`.

**Fix.** Change `pub tag: [u8; 1]` to `pub tag: u8`. Update
`R0SuccinctPrecompileStack::new` to set `tag: ZkTag::R0Succinct.as_byte()`.
Update `script_push_items` to push `core::slice::from_ref(&self.tag)` (one
element, but typed `&[u8]`). Update any caller of `self.tag` that expected
`[u8; 1]` indexing.

This is breaking, but the workspace is pre-0.1.0 and no external caller
exists.

---

## F-15 · `RgkResolver` holds `&mut I` — caller cannot share indexer

✅ Fixed

**Where.** `crates/rgk-resolver/src/lib.rs:165-182`

```rust
pub struct RgkResolver<'a, B: KaspaChainBackend, I: Indexer> {
    pub backend: &'a B,
    pub indexer: &'a mut I,  // <-- &mut
    pub verifier_chain: KaspaChainId,
    pub reorg_safety_depth: u64,
}
```

The resolver takes `&mut I`, where `I: Indexer`. A caller that wants to
use the indexer for something else while the resolver is alive cannot:
`&mut` is exclusive.

**Problem.** `Indexer::lookup` and `Indexer::apply_spend` both take `&self`
and `&mut self` respectively. The resolver's surface mixes them. Look at
`resolve_by_covenant` (line 186 onward): it does both `lookup(...)` (needs
`&I`) and `apply_spend` (needs `&mut I`) … well actually looking at the
code it only does lookup + read, never `apply_spend`. So why does the
field need to be `&mut`?

**Reproduction.** Grep inside `RgkResolver`'s methods:

```text
$ rg "self.indexer\." crates/rgk-resolver/src/lib.rs
.../lib.rs:208:    let indexed = match self.indexer.lookup(covenant) {  // &self
.../lib.rs:213:        Some(o) => o,
.../lib.rs:282:        self.indexer.lookup(covenant)  // &self
```

Only `lookup` (a `&self` method) is called on the resolver's `indexer`. So
`&mut I` is unnecessarily exclusive. A caller wanting to write the indexer
in parallel with the resolver is blocked.

**Fix.** Change the field to `&'a I`, update the impl to `RgkResolver<'a,
B, I>` with `indexer: &'a I`. Update `new` and any test that uses
`&mut indexer` (probably none — `RgkResolver::new(backend, &indexer,
chain)` already has `&`).

This is breaking for callers who passed `&mut indexer`, but the
workspace's tests already pass `&indexer` (`tests/rgk-e2e/src/lib.rs:486`
uses `&mut indexer` only because the type signature requires it).

---

## F-16 · `IndexedCovenant::empty` returned an unverifiable default state

✅ Fixed

**Where.** `crates/rgk-indexer/src/lib.rs`

`IndexedCovenant::empty` was private, but it still created a transient
opened-covenant record with zero `asset_id`, zero `state_digest`, no
`open_outpoint`, and `last_update_daa_score = 0`. The two real open paths
then patched those fields immediately afterwards.

**Resolution.** The helper is removed. The indexer now uses
`IndexedCovenant::opened(...)`, which takes the validated initial
`RgkStateCommitment`, open outpoint, and DAA score up front and constructs
the stored record in one step. This closes the local zero-state construction
path; the broader public-field construction issue remains under F-20.

---

## F-17 · `ProofMode`/`ReceiptPolicy` re-export convention was inconsistent

✅ Fixed

**Where.**

```
crates/rgk-receipt/src/lib.rs:60:  pub use rgk_core::{ProofMode, ReceiptPolicy};
crates/rgk-resolver/src/lib.rs:38: pub use rgk_core::{ProofMode, ReceiptPolicy};
```

(`rgk-covenant` and `rgk-tx` import them directly via `use rgk_core::...`
at the top of their lib.rs, not as `pub use`.)

**Problem.** Two different patterns for the same cross-crate type.
`rgk-receipt` re-exports, `rgk-resolver` re-exports, but `rgk-covenant`
and `rgk-tx` don't. A reader doesn't know whether `rgk_covenant::ProofMode`
is the same type as `rgk_core::ProofMode` (it is — it's a direct `use`,
not a new wrapper) without reading the source.

**Fix.** Pick one convention and apply it everywhere:

- Option A: every crate `pub use rgk_core::{ProofMode, ReceiptPolicy};`.
  Then `rgk_core::ProofMode == rgk_receipt::ProofMode == rgk_covenant::ProofMode`,
  and `cargo doc` shows each crate's re-export in its sidebar (this is
  actually a feature — it tells readers "this crate uses these types").
- Option B: every crate does `use rgk_core::{ProofMode, ReceiptPolicy};`
  privately, and downstream users import from `rgk_core::ProofMode`
  always.

Option A is what two crates already do; apply it to the other two for
consistency.

---

## F-18 · `SyncError::Reorg { removed_count }` discards block hashes

✅ Fixed

**Where.** `crates/rgk-sync/src/lib.rs:101-103`

```rust
#[error("scan reorg detected: {removed_count} removed chain block(s)")]
Reorg { removed_count: usize },
```

The `ScanBatch` it was constructed from
(`crates/rgk-sync/src/lib.rs:29-35`) carries
`removed_chain_block_hashes: Vec<Bytes32>` — the actual block hashes that
were dropped. The error variant discards them.

**Problem.** When a reorg happens, the resolver / indexer needs to know
*which* blocks were dropped, not just *how many*. The current API forces
the caller to do `sync.tick()` (returns `Result<ScanTick, SyncError>`),
catch the error, then re-query the backend for the removed block hashes.
That's a round-trip the backend may not even support.

**Reproduction.** `run_until_idle` (line 197) propagates the error as-is.
The caller has no way to get the hashes back.

**Fix.** Change to

```rust
#[error("scan reorg detected: {} removed chain block(s)", removed_chain_block_hashes.len())]
Reorg {
    removed_chain_block_hashes: Vec<Bytes32>,
},
```

Move the `Vec<Bytes32>` through `ScanBatch.removed_chain_block_hashes`
(already there) into the error variant. The Display impl can truncate to
the first 4 hashes to stay readable.

---

## F-19 · `ToccataScriptPublicKey::from_versioned_bytes` silently truncates

✅ Fixed

**Where.** `crates/rgk-tx/src/lib.rs:216-225`

```rust
pub fn from_versioned_bytes(bytes: Vec<u8>) -> Result<Self, TxBuildError> {
    if bytes.len() < 2 {
        return Err(TxBuildError::MalformedScriptPublicKey);
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    Ok(Self {
        version,
        script: bytes[2..].to_vec(),
    })
}
```

If `bytes.len() > 2 + u16::MAX + 1` (i.e. a Vec longer than 65 537 bytes),
`bytes[2..]` is still taken as-is, but the resulting `ToccataScriptPublicKey`
may not match what the upstream Kaspa P2SH/SPK parser expects. The function
silently truncates at the 2-byte boundary but accepts any further length.

**Problem.** No upper bound on the script. A 1 GiB `bytes` argument is
accepted, and only the `MalformedScriptPublicKey` error fires for `len() < 2`.
DoS via giant SPK is possible at the call site.

**Fix.** Add a length cap for the script portion and return a typed
`TxBuildError::ScriptPublicKeyTooLong { len, max }`. The implementation uses
`TOCCATA_SCRIPT_PUBLIC_KEY_MAX_SCRIPT_LEN = u16::MAX as usize`, matching the
current compact script-length boundary.

```rust
pub fn from_versioned_bytes(bytes: Vec<u8>) -> Result<Self, TxBuildError> {
    if bytes.len() < 2 {
        return Err(TxBuildError::MalformedScriptPublicKey);
    }
    let script_len = bytes.len() - 2;
    if script_len > TOCCATA_SCRIPT_PUBLIC_KEY_MAX_SCRIPT_LEN {
        return Err(TxBuildError::ScriptPublicKeyTooLong {
            len: script_len,
            max: TOCCATA_SCRIPT_PUBLIC_KEY_MAX_SCRIPT_LEN,
        });
    }
    ...
}
```

---

## F-20 · Many public data structs expose all fields; no builder pattern

✅ Fixed

**Where.** Representative samples (the pattern is workspace-wide):

- `rgk-receipt/src/lib.rs:123-133` — `ReceiptInput` with 8 pub fields
- `rgk-covenant/src/lib.rs:699-711` — `CovenantState` with 8 pub fields
- `rgk-covenant/src/lib.rs:220-233` — `AdvancedCovenantPolicyShape` with 11 pub fields
- `rgk-zk/src/lib.rs:262-271` — `ZkStatement` with 8 pub fields
- `rgk-zk/src/lib.rs:359-383` — `SemanticTransitionStatement` with 21 pub fields
- `rgk-tx/src/lib.rs:190-195` — `TxOutput` with 3 pub fields
- `rgk-kaspa/src/lib.rs:63-68` — `KaspaTxSummary` with 3 pub fields
- `rgk-indexer/src/lib.rs:62-79` — `IndexedCovenant` with 7 pub fields

**Problem.** For consensus/security-sensitive data structs, pub fields mean:

1. **No validation on construction.** A caller can build
   `RgkStateCommitment { version: 0, chain_id, covenant_id, asset_id: [0;32],
   state_digest: [0;32], receipt_policy: Any }` — which F-16 already
   identified as a workspace-rejected state.
2. **No invariants documented in the type.** `ReceiptInput` requires
   `old_state.chain_id == new_state.chain_id == chain_id`, but a caller
   can construct one where they don't match; `ReceiptBuilder::build`
   catches it at *build* time, not at *construction* time.
3. **No deprecation pathway.** Adding a field is non-breaking; renaming
   one is a breaking change at the construction site, but also at every
   existing struct literal. Pub fields hide the breaking-change surface
   inside every caller.

**Reproduction.** Pick any of the above structs and try to construct an
invalid one. The compiler will accept it; downstream code that relies on
the invariant will reject it.

**Resolution.**

High-risk downstream-construction surfaces now have explicit constructors and
`#[non_exhaustive]` where fields remain public for read access:

- `RgkStateCommitment::new(...)` rejects wrong encoding versions and zero
  covenant id, asset id, or state digest.
- `RgkReceipt::new(...)` centralises the receipt structural checks and rejects
  zero transition/continuation commitments.
- `ReceiptInput::new(...)`, `CovenantState::new(...)`,
  `AdvancedCovenantPolicyShape::new(...)`,
  `AdvancedCovenantExecutionEvidence::new_for_shape(...)`, and
  `SemanticTransitionStatement::new(...)` remain the public construction paths.
- `KaspaScriptPublicKey`, `KaspaUtxo::new(...)`,
  `KaspaUtxo::from_script_public_key(...)`, `KaspaTxSummary::new(...)`, and
  `KaspaTip::new(...)` cover the Kaspa DTO surface.
- `IndexedLane::new(...)` and `#[non_exhaustive]` on indexed records prevent
  downstream literal construction of wallet/indexer lookup state.
- Toccata transaction DTOs and feature-gated real-ZK statement/report DTOs are
  `#[non_exhaustive]`; existing constructors/factory methods are the stable
  construction surface.

**Evidence.**

- `cargo check --workspace` passes.
- `cargo test --workspace --no-run` passes.
- `cargo test --workspace --benches --no-run` passes.
- `cargo test -p rgk-e2e --all-features --no-run` passes.
- `cargo clippy --workspace --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used`
  passes without warnings.

---

## F-21 · `derive(Clone, Debug, PartialEq, Eq)` without Hash discipline

✅ Fixed

**Where.** Pattern was workspace-wide. Spot-check:

- `RgkStateCommitment` (line 116): `Clone, Debug, PartialEq, Eq, Hash` — has Hash, but the *covenant_id* in it is `Bytes32` (which doesn't have `Hash` either? Let me check)

Actually `Bytes32 = [u8; 32]`, which has `Hash` from the standard library
(`<[T]: Hash>` where `T: Hash`). So `RgkStateCommitment` having `Hash` is
fine.

The missing-derive issue was more like:

- `ReceiptInput`, `ReplaySet`, and `NewStateSpec` had `Clone, Debug,
  PartialEq, Eq` but not `Hash`.
- Normal public DTO crates (`rgk-asset`, `rgk-receipt`, `rgk-covenant`,
  `rgk-tx`, `rgk-kaspa`, `rgk-indexer`, `rgk-sync`, `rgk-zk`, and
  `rgk-resolver`) used inconsistent hashability for comparable value and
  typed state/error enums.
- `RgkStateCommitment` already had `Hash`; that was not the issue.

The bigger missing derives:

- `serde::Serialize` / `serde::Deserialize` were opt-in
  (`#[cfg_attr(feature = "serde", derive(...))]`) on `ProofMode`,
  `ReceiptPolicy`, `KaspaChainId`. But `RgkStateCommitment`,
  `RgkReceipt`, `KaspaOutpoint`, `Hex32`, and policy-migration DTOs were not
  cfg-gated for serde. A caller who enabled `feature = "serde"` on `rgk-core`
  got partial coverage —
  inconsistent.

**Problem.** Inconsistent derive discipline across the workspace.

**Fix.** Done for the normal public API surface:

- public comparable value/state/error DTOs now derive `Hash`.
- `rgk-core` wire DTOs now derive serde behind the existing `serde` feature.
- `real_zk.rs` proof/circuit internals are intentionally excluded from this
  public hashability contract because they include arkworks proof/witness
  material and live behind `real-zk`.

**Evidence.**

- `rg -n "#\\[derive\\([^\\]]*PartialEq, Eq[^\\]]*\\)\\]" crates --glob '*.rs' | rg -v 'Hash|Error|real_zk.rs'` returns no normal-crate hits.
- `cargo check --workspace` passes.
- `cargo check -p rgk-core --features serde` passes.

---

## F-22 · Cross-crate errors flattened to String at the seam

✅ Fixed

**Where.** `rgk-resolver` and `rgk-sync`.

The resolver and sync seams previously converted upstream errors into display
strings, losing the variant structure. They now carry the typed upstream
errors directly:

```rust
#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("indexer error: {0}")]
    Indexer(#[from] rgk_indexer::IndexerError),
    #[error("covenant error: {0}")]
    Covenant(#[from] CovenantError),
    ...
}
```

`SyncError::Indexer` likewise stores `IndexerError` directly. Callers can now
match on `IndexerError::Replay`, `IndexerError::NotIndexed`,
`IndexerError::RebuildTxMismatch`, and the other structured variants without
parsing strings.

---

## F-23 · Three different encoding disciplines across crates

✅ Fixed

**Where.**

- `rgk-core/src/encoding.rs` — hand-rolled `Writer`/`Reader`, length-prefixed
  u32 LE blobs, hard `MAX_BLOB_BYTES` cap.
- `rgk-tx/src/lib.rs:765-808` — hand-rolled borsh-style writer for
  `ToccataV1Tx::to_borsh_bytes`. Same LE principle, different helpers.
- `rgk-tx/src/lib.rs:394-412` — `to_borsh_bytes` is a single function with
  its own bespoke encoder.
- `rgk-covenant/src/lib.rs:621-689` — hand-rolled SHA-256 commitment helpers
  using ad-hoc `Writer` instances.
- `rgk-asset/src/native.rs` — yet another pattern, `asset_domain_hash`
  + bespoke `Vec` building.

**Problem.** Each crate invents its own writer/hasher convenience. They
agree on byte order (LE) and tag-byte conventions, but the *types* of
helpers are different. A new contributor has to learn three different
APIs to write canonical bytes.

**Remediation.**

- `rgk-tx` now uses a thin `BorshWriter` wrapper over `rgk_core::Writer` for
  Toccata v1 Borsh bytes instead of independent `write_borsh_u*` helpers.
- `rgk-covenant` advanced covenant policy/execution commitments now use
  `rgk_core::domain_hash` with typed `DomainTag` variants.
- `rgk-asset`'s `asset_domain_hash` now delegates to
  `rgk_core::domain_hash_str`, so the tagged-hash recipe is centralised even
  for grammar-specific dynamic domain strings.

**Evidence.**

- `cargo test -p rgk-core -p rgk-asset -p rgk-covenant -p rgk-tx` passes.
- `rgk-tx`'s upstream Borsh wire comparison still passes.

---

## F-24 · `ReceiptInput` validates post-construction, not at construction

✅ Fixed

**Where.** `crates/rgk-receipt/src/lib.rs:148-175`

```rust
pub fn build(input: &ReceiptInput) -> Result<(RgkReceipt, ReceiptId, Vec<u8>), ReceiptError> {
    if input.transition_digest == [0u8; 32] {
        return Err(ReceiptError::MissingTransitionDigest);
    }
    if input.continuation_commitment == [0u8; 32] {
        return Err(ReceiptError::MissingContinuationCommitment);
    }
    if input.replay_nonce == [0u8; 32] {
        return Err(ReceiptError::MissingReplayNonce);
    }
    let receipt = RgkReceipt { /* ... copy fields ... */ };
    receipt.validate_structure()
        .map_err(|e| ReceiptError::DecodeFailure(e.to_string()))?;
    ...
}
```

`ReceiptInput` is a fully-pub-fields struct (F-20). A caller can build a
`ReceiptInput` with all-zero `transition_digest` and not notice until they
call `ReceiptBuilder::build`, which is the first time the validation runs.

**Problem.** Validation is delayed. A test or fixture that constructs a
partially-populated `ReceiptInput` and forgets to call `build` will see
no error.

**Remediation.** `ReceiptInput::new(...) -> Result<Self, ReceiptError>` now
constructs through the same validation path used by `ReceiptBuilder::build`.
The builder reuses that shared helper, so constructor validation and build
validation cannot drift.

`ReceiptInput` is also `#[non_exhaustive]`. Its fields remain readable, but
downstream crates cannot construct it with a literal and bypass
`ReceiptInput::new`. Existing downstream fixture code was converted to the
constructor.

**Evidence.**

- `rg -n "ReceiptInput \\{" . --glob '*.rs'` now shows only internal
  `rgk-receipt`/same-crate construction plus the struct definition.
- `cargo check --workspace` passes.

---

## F-25 · `KaspaChainBackend` is synchronous; no async, no Stream

✅ Accepted

**Where.** `crates/rgk-kaspa/src/lib.rs:168-205`

```rust
pub trait KaspaChainBackend: Send + Sync {
    fn network_id(&self) -> Result<KaspaChainId, KaspaNetworkError>;
    fn current_tip(&self) -> Result<KaspaTip, KaspaNetworkError>;
    fn get_transaction(&self, txid: KaspaTxId) -> Result<Option<KaspaTxSummary>, KaspaNetworkError>;
    fn get_utxo(&self, outpoint: KaspaOutpoint) -> Result<Option<KaspaUtxo>, KaspaNetworkError>;
    fn get_spending_transaction(&self, outpoint: KaspaOutpoint) -> Result<Option<KaspaTxSummary>, KaspaNetworkError>;
    fn submit_transaction(&self, tx_bytes: &[u8]) -> Result<KaspaTxId, KaspaNetworkError>;
    fn confirmation_depth(&self, txid: KaspaTxId) -> Result<Option<u64>, KaspaNetworkError>;
}
```

All methods are `&self`, all return `Result<_, KaspaNetworkError>` synchronously.

**Problem.**

1. The HTTP backend (`mod http`) uses blocking `ureq`. The wRPC backend
   (when enabled) uses async internally and blocks on its own runtime —
   see `crates/rgk-kaspa/src/wrpc.rs` for the implementation.
2. The trait is **not** `async`, so a future async caller can't `await`
   on it without spawning a blocking task per call. The wRPC backend has
   to expose its own `block_on`-style wrapper.
3. No `Stream`-based variant: live chain scanning
   (`current_virtual_chain_from_block` etc.) is exposed via the wRPC
   backend's bespoke API rather than a generic `Stream` trait, so the
   trait can't be used for live-chain consumers generically.

**Fix.** The first path was chosen:

1. **Stay sync, document it.** `KaspaChainBackend` now states that the trait is
   intentionally synchronous, that async transports should adapt internally or
   expose transport-specific async helpers, and that async application callers
   should wrap calls behind `spawn_blocking`. This is OK because the project's
   primary consumer (resolver, indexer) is fine with
   blocking.
An async companion trait remains a future extension only if the resolver itself
becomes async or needs to multiplex many live-chain calls.

---

## F-26 · `KaspaUtxo::script_public_key: Vec<u8>` is unbounded and untyped

✅ Fixed

**Where.** `crates/rgk-kaspa/src/lib.rs:73-83`

```rust
pub struct KaspaUtxo {
    pub outpoint: KaspaOutpoint,
    pub value: u64,
    pub script_public_key: Vec<u8>,  // unbounded
    pub block_daa_score: Option<u64>,
    pub spending: Option<SpendingInfo>,
}
```

`script_public_key` is the raw SPK bytes — version prefix + var-bytes
script. No type wrapper, no length cap.

**Problem.** Same DoS shape as F-19: a backend could return a 1 GiB SPK
and the resolver would happily hold it in memory.

**Remediation so far.**

`rgk-kaspa` now defines `KaspaScriptPublicKey`, a bounded newtype over the raw
script bytes. `KaspaUtxo::script_public_key` uses that newtype instead of
`Vec<u8>`, and `KaspaUtxo::new(...)` validates caller-provided bytes through the
same bound.

Backends still return `KaspaNetworkError::ScriptPublicKeyTooLong { len, max }`
when a UTXO exceeds `MAX_SCRIPT_PUBLIC_KEY_BYTES = 2 + u16::MAX`. The fixture
backend has a regression test for this boundary, and the wRPC feature path is
checked with all features enabled.

---

## F-27 · `opcodes` constants are pinned to an upstream commit and not flagged as such

✅ Fixed

**Where.** `crates/rgk-covenant/src/lib.rs:934-990`

```rust
/// Toccata covenant script opcode tags.
pub mod opcodes {
    pub const TOCCATA_OPCODE_PROFILE_NAME: &str = "rusty-kaspa-toccata";
    pub const TOCCATA_OPCODE_PROFILE_COMMIT: &str = "98a4ccd8d200";
    pub const OP_CAT: u8 = 0x7e;
    pub const OP_BLAKE2B_WITH_KEY: u8 = 0xa7;
    ...
    pub const OP_ZK_PRECOMPILE: u8 = 0xa6;
    ...
    pub const fn is_rgk_toccata_opcode(byte: u8) -> bool { ... }
}
```

**Resolution.** The opcode module now exposes the pinned profile name and the
local rusty-kaspa commit (`98a4ccd8d200`) alongside the constants. It also
provides `is_rgk_toccata_opcode(byte)` for membership checks, and the opcode
value test pins the profile metadata.

If upstream later exposes a public `kaspa-txscript` opcode enum, this module
can grow a stronger profile comparison test against that enum.

---

## F-28 · `ZkStatement`/`SemanticTransitionStatement` are gigantic flat structs

✅ Fixed

**Where.**

- `rgk-zk/src/lib.rs:262-271` — `ZkStatement` with 8 `pub` fields
- `rgk-zk/src/lib.rs:359-383` — `SemanticTransitionStatement` with **21**
  `pub` fields

The semantic one in particular lists 21 fields in a row, each documented
inline. Reading the source, you have to scroll 25 lines to see what
fields it has.

**Problem.**

1. **Constructing one is error-prone.** A caller must remember the
   21-field order — see `from_reports` (line 388) which has 21 lines of
   assignment.
2. **No nesting by concern.** Fields cluster naturally (transition
   digests, owner commitments, supply counters, burn stuff) but the
   struct flattens them.
3. **Pub fields** (F-20 again) means a caller can build an invalid
   statement and `public_inputs()` will produce silent garbage.

**Remediation.**

`ZkStatement` and `SemanticTransitionStatement` are now `#[non_exhaustive]`.
Their fields remain readable, but downstream crates cannot construct giant
unchecked literals. `ZkStatement` is derived through `from_receipt`, and
`SemanticTransitionStatement::new(...)` validates through the same semantic
rules used by `from_reports`.

The larger nested-shape refactor is intentionally deferred. The public-input
byte layout is stable and independent of Rust field order; changing the Rust
shape now would be mostly cosmetic after downstream literal construction is
blocked.

**Evidence.**

- `cargo test --workspace --no-run` passes.

---

## F-29 · `ResolverState` has 10 variants, most carrying `covenant: KaspaCovenantId`

✅ Fixed

**Where.** `crates/rgk-resolver/src/lib.rs:42-108`

```rust
pub enum ResolverState {
    Open { covenant: KaspaCovenantId, outpoint: KaspaOutpoint, state: RgkStateCommitment },
    NativeTransitionedValid { covenant: KaspaCovenantId, ..., receipt_id: Bytes32, ... },
    NativeTransitionedInvalid { covenant: KaspaCovenantId, reason: ReceiptError },
    Unconfirmed { covenant: KaspaCovenantId, spending_txid: Bytes32 },
    ReorgRisk { covenant: KaspaCovenantId, daa_score: u64 },
    CompetingBranch { covenant: KaspaCovenantId, spent_outpoint: KaspaOutpoint, ... },
    PolicyMigrationRequired { covenant: KaspaCovenantId, current_policy: ReceiptPolicy, ... },
    ReplayRejected { covenant: KaspaCovenantId, receipt_id: Bytes32 },
    Unknown { covenant: KaspaCovenantId },
    NodeDown { covenant: KaspaCovenantId, reason: String },
}
```

Every variant carries a `covenant: KaspaCovenantId`. The variant *is* the
result; the covenant is the *subject* of the result.

**Problem.**

1. **Repetitive matching.** A caller who wants to log "which covenant?"
   for every state must pattern-match 10 times.
2. **Constructor discipline is loose.** Anyone adding a new variant must
   remember to add the `covenant` field.
3. **Pattern-match exhaustiveness has gotten noisy.** A new variant
   added in a minor release is a breaking change for callers who match
   exhaustively.

**Remediation.**

`ResolverState::covenant() -> KaspaCovenantId` now gives callers a single
stable accessor for the subject covenant. This removes the common 10-arm match
without forcing a disruptive `ResolverOutcome`/`ResolverStateKind` API split.

The current variant taxonomy is retained because each variant still carries
different recovery semantics. A wrapper extraction can remain a future major
API redesign, but it is no longer required to solve the logging/status-use
case that triggered this finding.

**Evidence.**

- The resolver test suite now asserts `st.covenant()` on a transitioned-valid
  state.

---

## F-30 · `ReceiptError::DecodeFailure(String)` carries an untyped String

✅ Fixed

**Where.** `crates/rgk-receipt/src/lib.rs:84-85`

```rust
#[error("receipt decode failure: {0}")]
DecodeFailure(String),
```

Generated from `rgk_core::DecodeError` via:

```rust
.map_err(|e: CoreDecodeError| ReceiptError::DecodeFailure(e.to_string()))?;
```

at lines 171, 194, and elsewhere.

**Problem.** The decode failure is the *single most useful* error to
distinguish — it tells the caller *why* the receipt was rejected
(`Eof`, `TrailingBytes`, `BadMagic`, `UnknownVersion`, `Structural`,
etc.). Collapsing all of these into one `String` variant loses the
distinction.

**Reproduction.** A test that wants to verify "decoder rejects
`UnknownVersion`" today must match on the string, not on a variant:

```rust
match err {
    ReceiptError::DecodeFailure(s) => assert!(s.contains("unknown version"), "got: {s}"),
    _ => panic!("unexpected variant"),
}
```

**Fix.** Replace `DecodeFailure(String)` with a typed wrapper:

```rust
#[error("receipt decode failure: {0}")]
DecodeFailure(#[from] DecodeError),
```

or expand the variants explicitly (e.g. `UnknownReceiptVersion(u16)`,
`ReceiptStructural(String)`, `ReceiptTrailingBytes(usize)`, …).

The `#[from]` route is one-line and lets `?` work transparently.

---

## F-31 · `ScanService<'a, B, C>` requires `&mut cursor_store` — single-writer

✅ Accepted

**Where.** `crates/rgk-sync/src/lib.rs:118-131`

```rust
pub struct ScanService<'a, B: ScanBackend, C: ScanCursorStore> {
    backend: &'a B,
    cursor_store: &'a mut C,  // <-- exclusive
    config: ScanServiceConfig,
}
```

`tick()` calls `self.cursor_store.load_scan_cursor(...)` and
`store_scan_cursor(...)`. Both are `&mut self` on the trait
(`ScanCursorStore::store_scan_cursor(&mut self, ...)`).

**Resolution.** Keep the single-writer boundary. A scan cursor is a durable
commit point: sharing it between concurrent scanners should be represented by
an explicit locking or transactional wrapper, not hidden inside the basic
storage trait.

`ScanCursorStore` now documents that `store_scan_cursor` and
`clear_scan_cursor` require `&mut self` by design. `load_scan_cursor` already
uses `&self`, so status reporting can be implemented against a reader handle or
snapshot without weakening the writer boundary.

---

## F-32 · `derive_covenant_id` ignored `_state`; lineage helper needed docs

✅ Fixed

**Where.** `crates/rgk-covenant/src/lib.rs`

`derive_covenant_id(genesis_outpoint, _state, authorized_outputs)` was a
public migration wrapper around `compute_covenant_id(...)`; its `_state`
argument was intentionally ignored. That made the canonical derivation path
look state-dependent when it was not.

`compute_covenant_id_from_lineage(lineage)` is a separate lineage-only helper.
It produces the covenant id used in SPK embedding and spend-time checks after
the canonical lineage id is already known.

**Resolution.** The vestigial `derive_covenant_id` wrapper is removed. The
lineage-only helper now documents that genesis covenant opening must still use
`compute_lineage_id` and `compute_covenant_id`; it is not a replacement for
genesis-outpoint derivation.

---

## F-33 · No `#[deprecated]` markers anywhere; zero deprecation hygiene

✅ Fixed

**Where.** Workspace-wide.

```text
$ rg "#\[deprecated" --type rust
(no matches)
```

Not a single public item is marked `#[deprecated]`. For a 0.1.0-pre-release
workspace this is *expected* — there's no compatibility promise yet — but
it means:

1. **No forward signal.** A field or function that's known to be renamed
   in the next release (e.g. `Hex32` → `Bytes32Hex`, `RgkProductionAllocationStrategy*`
   → `RgkAllocationStrategy*`) has no in-source migration path.
2. **No changelog tracking.** A new contributor reading the source
   doesn't know which items are "intended to change" vs "frozen".

**Remediation.** `docs/API-DEPRECATION.md` now defines the workspace policy:
pre-release misleading APIs may be removed directly, while
compatibility-tagged releases should use `#[deprecated]` when an alias can be
kept without preserving unsafe semantics.

No deprecated aliases were added for the names removed in this audit because
they were pre-release API cleanups and keeping aliases would preserve the
misleading surface.

---

## F-34 · `#![forbid(unsafe_code)]` is set crate-wide — verified

🟡 Partially fixed

**Where.** All 10 crates.

**Resolution.** `docs/UNSAFE-AUDIT.md` records the workspace unsafe policy, the
local source scan, and the current dependency inventory. The local scan found no
Rust `unsafe` tokens in RGK source code apart from prose.

```
crates/rgk-core/src/lib.rs:34:#![forbid(unsafe_code)]
crates/rgk-asset/src/lib.rs:10:#![forbid(unsafe_code)]
crates/rgk-receipt/src/lib.rs:34:#![forbid(unsafe_code)]
crates/rgk-covenant/src/lib.rs:51:#![forbid(unsafe_code)]
crates/rgk-tx/src/lib.rs:33:#![forbid(unsafe_code)]
crates/rgk-zk/src/lib.rs:33:#![forbid(unsafe_code)]
crates/rgk-kaspa/src/lib.rs:24:#![forbid(unsafe_code)]
crates/rgk-indexer/src/lib.rs:32:#![forbid(unsafe_code)]
crates/rgk-resolver/src/lib.rs:17:#![forbid(unsafe_code)]
crates/rgk-sync/src/lib.rs:11:#![forbid(unsafe_code)]
```

Confirmed by `rg "unsafe fn|unsafe impl|unsafe trait|pub unsafe" --type rust`
returning zero hits. The audit also confirmed no `unsafe` blocks, no
`extern "C"` declarations, no FFI surface.

`cargo-geiger v0.13.0` was installed and tested. A full dependency scan
(`cargo geiger --all-features --output-format Ratio`) did not complete usefully
in this workspace; it emitted repeated registry-source matching warnings and
stalled without a dependency report. The bounded fallback
`cargo geiger --forbid-only --all-features` completed from `crates/rgk-core` and
marked `rgk-core 0.1.0` as `:)`, while transitive dependencies remained `?`.

**Decision.** First-party RGK code is unsafe-forbidden. Third-party dependency
unsafe exposure is accepted external risk, not a blocker for the public API
surface audit.

---

## F-35 · `ToccataSigHashType::from_u8` validator was not `const`

✅ Fixed

**Where.** `crates/rgk-tx/src/lib.rs`

`ToccataSigHashType::from_u8` is now `pub const fn`. The six allowed values
are checked with a const-friendly match helper, so compile-time sighash tables
and script generators can validate values without a runtime-only API.

---

## F-36 · `bytes::labeled` was a no-op wrapped in a misleading name

✅ Fixed

**Where.** `crates/rgk-core/src/bytes.rs`

`bytes::labeled(b, _label)` ignored the label and returned `b` unchanged,
while its documentation claimed labelled checking behaviour. It had no
workspace callers.

**Resolution.** The helper is deleted.

---

## F-37 · `LaneResolverState` and `TransitionResolverState` are the same shape with two names

✅ Accepted

**Where.** `crates/rgk-resolver/src/lib.rs:110-135`

```rust
pub enum LaneResolverState {
    Resolved { lane: IndexedLane, state: Box<ResolverState> },
    UnknownLane { lane_id: Bytes32 },
    UnknownScanTag { scan_tag: Bytes32 },
}

pub enum TransitionResolverState {
    Resolved { transition_digest: Bytes32, covenant: KaspaCovenantId, receipt_id: Bytes32, state: Box<ResolverState> },
    UnknownTransition { transition_digest: Bytes32 },
}
```

Both have a `Resolved { ..., state: Box<ResolverState> }` shape. The only
difference is the "what is being looked up" field. They're separate
enums with the same nesting.

**Audit note.** A trial change that replaced `Box<ResolverState>` with direct
`ResolverState` values compiled and passed tests, but clippy correctly warned
that it creates large enum variants. The box is therefore retained until F-29
shrinks the state representation.

**Problem.**

1. **Two ways to spell the same thing.** A caller who switches lookup
   mode (lane → transition) has to rewrite their match.
2. **Boxing is currently justified by enum size.** It should go away only
   after `ResolverState` is split into a smaller summary/kind shape.

**Fix.** After F-29's `ResolverStateKind` extraction, both enums become
simpler:

```rust
pub enum LaneResolverState {
    Resolved { lane: IndexedLane, state: ResolverStateKind },
    UnknownLane { lane_id: Bytes32 },
    UnknownScanTag { scan_tag: Bytes32 },
}
```

The cleanup is to decide whether `TransitionResolverState` should stay as a
public lookup enum or collapse into a smaller transition lookup result. That
should be done together with F-29's `ResolverState` reshaping.

---

## F-38 · Big structs with no constructor in `rgk-covenant` and `rgk-tx`

✅ Fixed

**Where.**

- `rgk-covenant/src/lib.rs:220-233` — `AdvancedCovenantPolicyShape` (11
  pub fields)
- `rgk-covenant/src/lib.rs:336-343` — `AdvancedCovenantExecutionEvidence`
  (6 pub fields)
- `rgk-covenant/src/lib.rs:346-351` — `AdvancedCovenantExecutionPlan` (4
  pub fields)
- `rgk-tx/src/lib.rs:307-310` — `ToccataUtxoEntry` (2 pub fields)
- `rgk-tx/src/lib.rs:333-336` — `ToccataGenesisCovenantGroup` (2 pub fields)

Smaller scale than F-20 but the same anti-pattern.

**Remediation.** `AdvancedCovenantPolicyShape::new(...)`,
`AdvancedCovenantExecutionEvidence::new_for_shape(...)`, and
`CovenantState::new(...)` now validate construction at the API boundary.
`AdvancedCovenantExecutionPlan`, `ToccataUtxoEntry`, and
`ToccataGenesisCovenantGroup` already had constructors.

`AdvancedCovenantPolicyShape`, `AdvancedCovenantExecutionEvidence`, and
`CovenantState` are now `#[non_exhaustive]`. Their fields remain readable, but
downstream crates cannot construct them with literals and bypass the validating
constructors.

**Evidence.**

- `cargo check --workspace` passes.
- `cargo test --workspace --no-run` passes, including downstream e2e test
  targets.

---

## F-39 · `rgk-zk/src/real_zk.rs` feature gate was reported stale

✅ Fixed

**Where.** `crates/rgk-zk/src/lib.rs`

The audit originally reported `real_zk` as an unconditional public module.
Current code already has the desired export gate:

```rust
/// Real Groth16 prover + verifier (gated by the `real-zk` feature).
#[cfg(feature = "real-zk")]
pub mod real_zk;
```

**Resolution.** No code change was needed. The audit finding is corrected to
show that `rgk_zk::real_zk` is only available when the `real-zk` feature is
enabled.

---

## F-40 · crate-wide `unwrap` / `expect` allowance masked API code

✅ Fixed

**Where.** All production crate roots.

The production crates no longer use a blanket:

```rust
#![allow(clippy::unwrap_used, clippy::expect_used)]
```

They now use the narrower test-only form:

```rust
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
```

The few production `expect` sites uncovered during the policy change were
removed: indexer rollback/encoding now returns `IndexerError::Invariant`, the
covenant script integer helper uses explicit control flow, and Toccata Borsh
length encoding uses an explicit invariant assertion.

**Verification.**

```text
cargo clippy --workspace --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used
```

The dedicated e2e support crate still carries the old allow because it is
fixture/test code and intentionally uses unwrap-heavy setup.

---

## Appendix A — items not flagged but worth tracking

These are observations, not defects — they don't need to change in this
audit cycle, but they're load-bearing for future audits:

- The workspace uses `thiserror` consistently across 8 crates for error
  enums. Good.
- Every crate `forbid(unsafe_code)`. Good. (See F-34.)
- `Default` is implemented for `Writer`, `RgkResolver`-adjacent types
  where it makes sense. Mixed discipline though — `RgkStateCommitment`
  has no `Default`, `RgkReceipt` has no `Default`, but `RgkResolver`
  has `Default` via `new(...)` semantics. Not a defect.
- Type aliases are used consistently in `rgk-core` (the bottom of the
  type stack), but newtypes in `rgk-asset` (the next layer up). The
  boundary between "alias" and "newtype" should be: if a value can be
  silently substituted for another, use newtype; if the type exists
  purely as documentation, use alias. Currently neither is enforced.
- `RgkReceipt` (line 309) implements `Display` with multiline layout
  (`writeln!` calls). Several error variants and Display impls use
  `{:#04x}` formatting for hex bytes (e.g.
  `KaspaChainId::UnknownChain` in `DecodeError`). Consistent.
- `rgk-zk::SemanticTransitionStatement::validate()` is a 70-line private
  function with 20+ invariants. Each `Err(ZkError::SemanticTransitionInvalid("name"))`
  carries the field name as a `&'static str` — good for log filtering,
  but the static strings are duplicated across `validate()` and
  `from_reports()`. A shared constant set would deduplicate.

## Appendix B — recommended refactor order

The immediate public-API blockers from this audit have been fixed or explicitly
accepted. If you continue the refactor later, take only the remaining larger
design items:

1. **F-25 / F-31** (sync/async and shared scanner cursor access) — bigger
   surface decisions; defer until the resolver path is settled.
2. **F-01 follow-up** (physical `native.rs` split) — useful for maintainability,
   but not a release blocker now that grouped facade modules exist.

The other accepted items can be revisited only when their owning modules are
already being changed.

## Appendix C — audit-time `rg` queries used

These were the searches that produced the findings above. Re-runnable
from the workspace root:

```bash
# Visibility / module shape
rg '^\s*pub ' --type rust crates/
rg '^\s*pub mod ' --type rust crates/
rg 'pub use rgk_' --type rust crates/

# Type duplication
rg 'pub struct Hex32|pub type Hex32' --type rust
rg 'pub struct HexBytes32|pub type HexBytes32' --type rust
rg 'pub type RgkAssetId' --type rust
rg 'pub type RgkSchemaId' --type rust

# Safety / deprecation
rg 'forbid.unsafe_code' --type rust
rg 'pub unsafe|unsafe fn|unsafe impl|unsafe trait|unsafe \{' --type rust
rg '#\[deprecated' --type rust

# Error API
rg 'impl From<.*Error>' --type rust
rg 'String>' --type rust crates/rgk-*/src/error.rs

# Stale / unused
rg 'COVENANT_ID_TAG' --type rust
rg 'bytes::labeled' --type rust

# Trait API
rg 'trait KaspaChainBackend' --type rust
rg 'trait Indexer' --type rust
rg 'trait ScanBackend' --type rust
```
