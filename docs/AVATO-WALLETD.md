# Avato RGK Wallet Daemon

`rgk-walletd` is the local HTTP boundary used by Avato's RGK frontend. It is a
non-custodial local daemon: the browser talks to this process, and this process
owns local profile state, health checks, lock/unlock state, and the future
handoff to scanner/resolver/prover services.

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

The daemon deliberately does not accept a frontend-selected chain domain that
differs from its configured `--network`. RGK receipt evidence is chain-domain
separated, so `kaspa-local-toccata`, `kaspa-testnet`, and `kaspa-mainnet` must
not be treated as interchangeable display labels.

The first implementation persists wallet profile/dashboard metadata and a
passphrase verifier. It does not persist recovery phrases or raw passphrases.
Scanner/resolver/prover integration should extend this daemon behind the same
HTTP contract instead of changing the frontend shape.

