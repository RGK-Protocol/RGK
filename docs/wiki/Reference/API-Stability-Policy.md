# Reference / API Stability Policy

> **Canonical source:** [`docs/API-DEPRECATION.md`](../../API-DEPRECATION.md).

During pre-release, misleading or unsafe public APIs may be removed or
renamed directly when keeping an alias would preserve the wrong
semantics. After the first compatibility-tagged release, public API
changes follow a `#[deprecated(note = "...")]` policy with at least one
compatibility release of overlap and a pointer to the replacement /
migration document / audit finding.

---

## The 4-Step Policy

From [`docs/API-DEPRECATION.md`](../../API-DEPRECATION.md):

1. **Pre-release.** Misleading or unsafe APIs may be removed or renamed
   directly. No alias is kept if the alias would preserve the wrong
   semantics.

2. **Compatibility-tagged release.** Public API changes follow a
   `#[deprecated(note = "...")]` policy with at least one compatibility
   release of overlap. The deprecation note must point to the replacement
   function / migration document / audit finding.

3. **Consensus encodings, covenant validation semantics, and
   security-sensitive constructors** never keep a deprecated alias when
   the alias would make an invalid state easier to construct. The
   pre-release rule applies even after the first tagged release.

4. **Audit exceptions** are tracked in
   [`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md).
   Each "Accepted" entry is a deliberate exception; treat them as the
   canonical list of "this alias is intentional."

---

## Audit Reference

The public-API audit
([`docs/audits/public-api-surface.md`](../../audits/public-api-surface.md))
tracks 40 findings (`F-01..F-40`) and per-finding "Fixed" / "Accepted"
markers. See [Reference / API Surface Audit](./API-Surface-Audit.md).

---

## Cross-references

- [`docs/API-DEPRECATION.md`](../../API-DEPRECATION.md) — canonical
  source.
- [Reference / API Surface Audit](./API-Surface-Audit.md).