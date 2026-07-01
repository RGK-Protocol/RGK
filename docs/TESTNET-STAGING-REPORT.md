# Public Testnet Staging Report

This report records the deterministic public testnet staging wallet set and
preflight contract used by `scripts/e2e-testnet-staging.sh`.

It is testnet-only material. It must not be used for mainnet funds.

## Wallet Set

Generated with:

```bash
bash scripts/e2e-testnet-staging.sh --wallets
```

Verified with:

```bash
bash scripts/verify-testnet-staging-wallets.sh target/rgk-testnet-staging-evidence/wallets.txt
```

Snapshot:

```text
network=testnet-12
chain_id=KaspaTestnet
wallet_set_id=0x319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352
wallet_count=3
```

### funding

```text
address=kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald
xonly=0x84bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0
secret_fingerprint=0x6ada37542b9cc1154d6c9659fb3e1346d503c342134abe8fdfd5de9878e10bac
required_min_value_real_zk=45000000
required_min_value_verifier_only=9000000
purpose=public-testnet-funding
```

### change

```text
address=kaspatest:qrvpsckmgwn4cr4jtsm5uls6qe8asmu4gth5rs6tcc3kulhemel557wahjvte
xonly=0xd81862db43a75c0eb25c374e7e1a064fd86f9542ef41c34bc6236e7ef9de7f4a
secret_fingerprint=0xb59dd8d084986c234680dfbd907aa1cc770c1c9ba5d506ad8458be1a39129ce2
required_min_value_real_zk=0
required_min_value_verifier_only=0
purpose=reserved-change-output-isolation
```

### observer

```text
address=kaspatest:qr5vg4qmfypldkrxenn2ruqjq5uh2p2dp63plaanpf0y0z660xt254sg5g833
xonly=0xe8c4541b4903f6d866cce6a1f012053975054d0ea21ff7b30a5e478b5a7996aa
secret_fingerprint=0x3446f807dd9862347162668ef58245a732584fd80c54c8bb0dd8bb9a2df16813
required_min_value_real_zk=0
required_min_value_verifier_only=0
purpose=observer-reporting-no-funding
```

The wallet report intentionally contains no `secret_key`, `private_key`, or
`privkey` field. The verifier rejects reports that expose those fields.

## Preflight

Generated with:

```bash
bash scripts/e2e-testnet-staging.sh --preflight
```

Verified with:

```bash
bash scripts/verify-testnet-staging-preflight.sh target/rgk-testnet-staging-evidence/preflight.txt
```

Snapshot:

```text
network=testnet-12
chain_id=KaspaTestnet
address=kaspatest:qzzt7atzyc4m662qppt53ua7dta99t33w923s8kwxxmxx5wvl7jtqz95u8ald
wallet_set_id=0x319ad15d9e723bbc441ad7bea195c3ca95b0ec4ccafd6f48bb4cca11d4ece352
wallet_count=3
funding_status=external-funding-required
required_non_coinbase_utxo=true
required_utxo_index=true
required_confirmation_depth=1
required_min_value_real_zk=45000000
required_min_value_verifier_only=9000000
required_live_kaspa_wrpc_feature=true
required_real_zk_feature=true
required_persistent_indexer_feature=true
required_local_mining=false
required_live_test=live_toccata_full_covenant_lifecycle
endpoint_env=RGK_LIVE_KASPA_URL
network_env=RGK_LIVE_KASPA_NETWORK
staging_script=scripts/e2e-testnet-staging.sh
evidence_verifier=scripts/verify-testnet-staging-evidence.sh
expected_report=target/rgk-testnet-staging-evidence/latest.txt
preflight_id=0x2c993d20f2726efdb0983868126544163e44c474f4b4ab4cf28901e749c29212
```

## Current Status

The deterministic wallet set and preflight manifest are generated and
machine-verified locally. A funded public testnet run is still separate: it
requires a reachable public Borsh wRPC endpoint in `RGK_LIVE_KASPA_URL` and a
non-coinbase UTXO at the funding address above.

## Funding Readiness

Generate funding instructions for the selected public testnet:

```bash
bash scripts/e2e-testnet-staging.sh --funding-help testnet-10
```

This writes a helper report such as:

```text
target/rgk-testnet-staging-evidence/funding-help-testnet-10.txt
```

The helper includes the deterministic funding address, the minimum real-ZK
funding amount in sompi and KAS, a browser faucet URL, a direct faucet API URL
where the deployed faucet permits it, and the exact follow-up commands.

Once a public testnet Borsh wRPC endpoint is selected, run:

```bash
RGK_LIVE_KASPA_URL="wss://host.example/v2/kaspa/testnet-12/no-tls/wrpc/borsh" \
  bash scripts/e2e-testnet-staging.sh --funding-readiness
```

This writes:

```text
target/rgk-testnet-staging-evidence/funding-readiness.txt
```

and verifies it with:

```bash
bash scripts/verify-testnet-funding-readiness.sh \
  target/rgk-testnet-staging-evidence/funding-readiness.txt
```

The readiness report is read-only. It checks endpoint network identity,
`utxoindex`, and whether the deterministic funding address has a non-coinbase
UTXO with at least `required_min_value_real_zk`. `funding_readiness=ok` means
the full public staging run can start; `funding_readiness=blocked` preserves the
exact blocker without submitting any transaction.

The launch audit requires funding-readiness to match the preflight network,
wallet-set id, and funding address. When using `testnet-10`, regenerate both
`--wallets` and `--preflight` for `testnet-10`; do not combine a `testnet-10`
endpoint report with the default `testnet-12` preflight.

If an older full-staging report exists but does not verify, `--allow-blocked`
treats it as a public-evidence blocker only when funding-readiness is
machine-verified, matches the preflight, and reports `funding_readiness=blocked`.
If funding is ready and the full report still fails, the launch audit remains a
real failure.

The full public staging report remains:

```text
target/rgk-testnet-staging-evidence/latest.txt
```

and must still pass:

```bash
bash scripts/verify-testnet-staging-evidence.sh \
  target/rgk-testnet-staging-evidence/latest.txt
```
