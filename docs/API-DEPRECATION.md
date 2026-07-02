# RGK API deprecation policy

RGK is still pre-release. During the pre-release phase, misleading or unsafe
public APIs may be removed or renamed directly when keeping an alias would
preserve the wrong semantics.

After the first compatibility-tagged release, public API changes should follow
this policy:

1. Add `#[deprecated(note = "...")]` to the old item when a source-compatible
   alias can be kept without preserving an unsafe invariant.
2. Point the note at the replacement item and, when relevant, the migration
   document or audit finding.
3. Keep the deprecated item for at least one compatibility release.
4. Do not keep deprecated aliases for consensus encodings, covenant validation
   semantics, or security-sensitive constructors when the alias would make an
   invalid state easier to construct.

The public audit in `docs/audits/public-api-surface.md` tracks any deliberate
exceptions.
