# Verification Budget

RGK validation must stay bounded and fail-closed.

## Bounded Objects

| Object | Bound |
| --- | --- |
| `asset_id` label | 32 bytes |
| schema id | 32 bytes |
| state digest | 32 bytes |
| transition digest | 32 bytes |
| lane id | 32 bytes |
| scan tag | 32 bytes |
| nullifier | 32 bytes |
| policy commitment | 32 bytes |
| receipt body | canonical `MAX_BLOB_BYTES` bound |
| covenant payload | canonical `MAX_BLOB_BYTES` bound |

## Fail-Closed Rules

* unknown encoding version rejected
* unknown chain id rejected
* malformed covenant payload rejected
* missing transition digest rejected
* missing replay nonce rejected
* no-op transition rejected
* supply mismatch rejected
* spent covenant-output reuse rejected
* unconstrained image id rejected
* replay rejected

## Resolver Budget

The resolver should classify only after bounded local checks:

* receipt decode
* receipt local verification
* indexer replay lookup
* confirmation-depth check
* optional persistent cursor check

If any required evidence is absent, the resolver returns a non-valid state such
as `Unknown`, `Unconfirmed`, `ReorgRisk`, or `NodeDown`.
