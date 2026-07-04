# Reference / Unsafe Audit

> **Canonical source:** [`docs/UNSAFE-AUDIT.md`](../../UNSAFE-AUDIT.md).

Audit notes (dated 2026-07-02): RGK first-party source is
`#![forbid(unsafe_code)]` and a `rg` scan finds no Rust `unsafe` code in
the workspace. The third-party dependency surface is accepted external
risk.

---

## Workspace Policy

Every production crate sets `#![forbid(unsafe_code)]`. Confirmed in:

- `crates/rgk-core/src/lib.rs:34`
- `crates/rgk-receipt/src/lib.rs:34`
- `crates/rgk-resolver/src/lib.rs:17`
- `crates/rgk-tx/src/lib.rs:33`
- `crates/rgk-walletd/src/main.rs:1`
- `crates/rgk-sync/src/lib.rs:12`

The audit command:

```bash
rg -n "\\bunsafe\\b" crates tests --glob '*.rs'
```

> One prose-only hit is expected (a comment in the resolver doc); no Rust
> `unsafe` blocks.

---

## Dependency Inventory

```bash
cargo tree --workspace -e normal --prefix none | sort -u | wc -l
```

The audit reports **94** normal dependencies in the workspace feature set.
This count will drift as `Cargo.toml` changes.

---

## Dependency Unsafe Scan

```bash
cargo geiger --all-features --output-format Ratio
cargo geiger --forbid-only --all-features
```

- `cargo-geiger` v0.13.0.
- `rgk-core` is marked `:)`.
- Dependencies are marked `?` (their upstream `unsafe` exposure is not
  audited by RGK).

---

## Follow-up

- First-party source: **unsafe-forbidden.**
- Third-party dependencies: **accepted external risk.** RGK does not
  certify the third-party `unsafe` surface; that is the upstream
  crate's responsibility.

---

## Cross-references

- [`docs/UNSAFE-AUDIT.md`](../../UNSAFE-AUDIT.md) — canonical source.