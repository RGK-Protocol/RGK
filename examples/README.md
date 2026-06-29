# RGK Contract Examples

This directory is the maintained example coverage surface for RGK.

`contract-matrix.tsv` is the authoritative machine-checked matrix. It records
only examples with current RGK fixture or devnet evidence. Silverscript source
and JSON artifacts are checked against the pinned upstream compiler recorded in
`silverscript/artifacts/manifest.tsv`. Public staging columns are explicit
evidence statuses; they are not treated as complete until public evidence is
recorded.

Verify it with:

```bash
bash scripts/verify-example-matrix.sh
```
