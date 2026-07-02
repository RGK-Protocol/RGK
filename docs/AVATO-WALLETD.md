# Avato RGK Wallet Daemon

`rgk-walletd` is the local HTTP boundary used by Avato's RGK frontend. It is a
non-custodial local daemon: the browser talks to this process, and this process
owns local profile state, health checks, lock/unlock state, and the future
handoff to scanner/resolver/prover services.

From the Avato frontend checkout, the preferred local launch path is:

```bash
pnpm dev:rgk:local
```

That command starts this daemon from the sibling RGK checkout, waits for
`GET /health`, exports `VITE_RGK_API_BASE_URL`, and then starts the RGK frontend.
Set `AVATO_RGK_REPO`, `RGK_WALLETD_LISTEN`, `RGK_WALLETD_NETWORK`, or
`RGK_WALLETD_STATE` when the checkout path, port, network, or state location
differs from the defaults. Set `RGK_SYNC_DB` to choose the restart-safe scanner
cursor database; otherwise the daemon derives a sibling `.sled` directory from
the JSON state path.

Run a local Toccata daemon for the frontend default:

```bash
cargo run -p rgk-walletd -- \
  --listen 127.0.0.1:8788 \
  --network local-toccata \
  --state target/rgk-walletd/state.json
```

Then run the frontend from `/Users/arthur/RustroverProjects/avato-wallet-frontend`:

```bash
VITE_RGK_API_BASE_URL=http://127.0.0.1:8788 pnpm dev:rgk
```

The daemon exposes the Avato contract:

* `GET /health`
* `GET /wallet/profile`
* `POST /wallets`
* `POST /wallet/import`
* `POST /wallet/lock`
* `POST /wallet/unlock`
* `POST /wallet/sync`
* `GET /dashboard`
* `POST /lanes`
* `POST /proofs`
* `POST /transitions`

The daemon deliberately does not accept a frontend-selected chain domain that
differs from its configured `--network`. RGK receipt evidence is chain-domain
separated, so `kaspa-local-toccata`, `kaspa-testnet`, and `kaspa-mainnet` must
not be treated as interchangeable display labels.

JSON request bodies are treated as a strict local API contract. Wallet, unlock,
lane, and proof endpoints reject unknown fields so stale clients cannot smuggle
obsolete state across the Avato boundary. User-controlled strings are also
normalised at the daemon boundary: wallet ids are limited to stable local id
characters, Kaspa endpoints must be `ws://` or `wss://`, lane tickers are
uppercase asset symbols, balances are non-negative decimals, and manual proof
txids must be 64 hexadecimal characters when present.

The first implementation persists wallet profile/dashboard metadata, staged RGK
lanes, staged proof receipts, and a salted passphrase verifier. It does not
persist recovery phrases or raw passphrases. On Unix platforms, the state file
is written with private user-only permissions so local metadata is not
group/world readable. New and imported wallet profiles start without synthetic
lane or proof records; lanes and receipt evidence appear only after explicit
wallet actions or future scanner/resolver/prover integration.
`POST /lanes` has two explicit modes. With empty covenant evidence fields, it
stages local metadata only, using protocol-width 32-byte textual handles and
starting in `unknown`, not `open`, because a frontend action is not chain
evidence. With a complete evidence bundle (`covenantId`, `lineageId`,
`assetId`, `laneId`, `stateDigest`, `openTxid`, plus open index, epoch, optional
scan tag, and DAA score), the daemon first validates the bundle, then opens the
covenant and registers the lane in the local sled indexer before persisting the
wallet profile row. Partial lane evidence is rejected, and duplicate lane or
covenant handles are rejected before any indexer write when they are already
present in the wallet profile. The lane still starts as `unknown`; sync/resolver
evidence is responsible for promoting it to `open` or a transition state.
Manual `POST /proofs` calls stage local receipt evidence as `pending`; they do
not move a lane into `NativeTransitionedValid`. If the request includes
canonical `receiptBytes`, `covenantId`, spent/new outpoints, a continuation
shape root, and DAA score, walletd verifies the receipt against the indexed
covenant state and records the spend in sled before returning `verified`.
Verified proof summaries retain the canonical receipt bytes and continuation
metadata so the frontend can export the artifact. Partial receipt bundles are
rejected. `NativeTransitionedValid` remains reserved for
scanner/resolver-backed chain evidence.
`POST /transitions` is the wallet-built receipt path. It requires an Avato lane
that was created with a complete covenant evidence bundle and therefore exists
in the local sled indexer. The request supplies the selected lane, proof mode,
current receipt policy, strategy label, new state digest, transition digest,
continuation commitment, continuation shape root, new outpoint, and DAA score.
walletd reads the indexed current state and open outpoint, rejects policy
mismatches and metadata-only lanes, derives a replay nonce from the open
outpoint plus transition digest, builds a canonical RGK receipt, verifies it
locally, and then records the spend in sled before returning a `verified`
`RgkProofSummary` with exportable `receiptBytes`, transition digest,
continuation commitment, continuation shape root, and new state digest. This
proves the local receipt is structurally valid against the indexed lane state;
it does not by itself prove the transition was broadcast, confirmed, or
classified by the resolver.
`POST /wallet/sync` now runs one restart-safe `rgk-sync` scanner tick against
the wallet profile's Kaspa wRPC endpoint. The scanner persists observed spend
records to sled before advancing the scan cursor; the cursor must not outrun
the evidence that the resolver will need later. After a successful scan, the
daemon re-runs the RGK resolver for dashboard lanes that carry parseable
32-byte lane or covenant handles, and only resolver output may promote those
lanes to `open`, `native-transitioned-valid`, or another classified state. If
the node or scanner database is unavailable, the endpoint still returns a
dashboard, but marks the profile `service-required`, the scanner `unavailable`,
and the service mode `unavailable`. Scanner failure must not be collapsed into
verified receipt state. Prover integration should extend this daemon behind the
same HTTP contract instead of changing the frontend shape.

To verify the daemon against the Avato frontend contract:

```bash
bash scripts/verify-avato-walletd-contract.sh
```

The script starts `rgk-walletd` on an isolated local port, reads
`../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json`, exercises
health/profile/create/dashboard/lane/proof/transition/lock/unlock/sync,
verifies that new wallets do not contain synthetic lane/proof records, rejects
a mismatched network request, and checks the state file for raw
phrase/passphrase leakage and unsafe group/world-readable permissions.
