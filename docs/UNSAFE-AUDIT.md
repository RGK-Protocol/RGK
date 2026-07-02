# Unsafe audit notes

Date: 2026-07-02

Workspace policy:

- All production crates use `#![forbid(unsafe_code)]`.
- Local source scan:
  - Command: `rg -n "\\bunsafe\\b" crates tests --glob '*.rs'`
  - Result: no Rust unsafe code; one prose-only hit in a resolver doc comment.

Dependency inventory:

- Command: `cargo tree --workspace -e normal --prefix none | sort -u | wc -l`
- Result: 94 normal dependency entries in the current workspace feature set.

Dependency unsafe scan:

- Installed tool: `cargo-geiger v0.13.0`.
- Full dependency command attempted from a package directory:
  `cargo geiger --all-features --output-format Ratio`.
  - Result: did not complete usefully in this workspace; it emitted repeated
    registry-source matching warnings and then stalled without producing a
    dependency unsafe report.
- Bounded fallback command:
  `cargo geiger --forbid-only --all-features` from `crates/rgk-core`.
  - Result: completed. It marked `rgk-core 0.1.0` as `:)`, meaning all entry
    point `.rs` files declare `#![forbid(unsafe_code)]`.
  - Dependencies were marked `?`, meaning third-party crates may use unsafe
    code and are not certified unsafe-free by this fallback mode.

Follow-up:

- Treat RGK first-party source as unsafe-forbidden.
- Treat third-party dependency unsafe exposure as accepted external risk unless
  a newer dependency scanner can produce a complete transitive unsafe report for
  this workspace.
