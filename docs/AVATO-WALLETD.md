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
differs from the defaults.

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

The daemon deliberately does not accept a frontend-selected chain domain that
differs from its configured `--network`. RGK receipt evidence is chain-domain
separated, so `kaspa-local-toccata`, `kaspa-testnet`, and `kaspa-mainnet` must
not be treated as interchangeable display labels.

The first implementation persists wallet profile/dashboard metadata, staged RGK
lanes, staged proof receipts, and a salted passphrase verifier. It does not
persist recovery phrases or raw passphrases. On Unix platforms, the state file
is written with private user-only permissions so local metadata is not
group/world readable.
Scanner/resolver/prover integration should extend this daemon behind the same
HTTP contract instead of changing the frontend shape.

To verify the daemon against the Avato frontend contract:

```bash
bash scripts/verify-avato-walletd-contract.sh
```

The script starts `rgk-walletd` on an isolated local port, reads
`../avato-wallet-frontend/contracts/rgk-wallet-http-contract.json`, exercises
health/profile/create/dashboard/lane/proof/lock/unlock/sync, rejects a
mismatched network request, and checks the state file for raw phrase/passphrase
leakage and unsafe group/world-readable permissions.
