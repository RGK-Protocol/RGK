#![forbid(unsafe_code)]

#[cfg(not(feature = "live-kaspa-wrpc"))]
fn main() {
    eprintln!("rgk-testnet-funding-readiness requires --features live-kaspa-wrpc");
    std::process::exit(2);
}

#[cfg(feature = "live-kaspa-wrpc")]
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let code = run().await;
    std::process::exit(code);
}

#[cfg(feature = "live-kaspa-wrpc")]
async fn run() -> i32 {
    use kaspa_addresses::Prefix;
    use kaspa_rpc_core::api::rpc::RpcApi;
    use rgk_core::to_hex;
    use rgk_e2e::{
        deterministic_live_staging_keypair, TestnetStagingPreflight, TestnetStagingWalletSet,
    };

    let mut args = std::env::args().skip(1);
    let network = args
        .next()
        .or_else(|| std::env::var("RGK_LIVE_KASPA_NETWORK").ok())
        .unwrap_or_else(|| "testnet-12".to_string());
    let url = args
        .next()
        .or_else(|| std::env::var("RGK_LIVE_KASPA_URL").ok());

    let Some(url) = url else {
        eprintln!("set RGK_LIVE_KASPA_URL or pass a public testnet Borsh wRPC URL");
        return 2;
    };

    let expected_network = match expected_network_id(&network) {
        Ok(network_id) => network_id,
        Err(err) => {
            eprintln!("{err}");
            return 2;
        }
    };

    let wallet_set = match TestnetStagingWalletSet::new(&network) {
        Ok(wallet_set) => wallet_set,
        Err(err) => {
            eprintln!("{err}");
            return 2;
        }
    };
    let preflight = match TestnetStagingPreflight::new(&network) {
        Ok(preflight) => preflight,
        Err(err) => {
            eprintln!("{err}");
            return 2;
        }
    };
    let (_, funding_address) = deterministic_live_staging_keypair(Prefix::Testnet);

    let client = match connect(&url, expected_network).await {
        Ok(client) => client,
        Err(err) => {
            eprintln!("wRPC connect failed: {err}");
            return 3;
        }
    };

    let info = match client.get_server_info().await {
        Ok(info) => info,
        Err(err) => {
            eprintln!("get_server_info failed: {err}");
            let _ = client.disconnect().await;
            return 3;
        }
    };

    println!("RGK public testnet funding readiness");
    println!("timestamp_utc={}", utc_timestamp());
    println!("network={network}");
    println!("chain_id={}", preflight.chain_id);
    println!("url={url}");
    println!("wallet_set_id=0x{}", to_hex(&wallet_set.wallet_set_id));
    println!("wallet_count={}", wallet_set.wallets.len());
    println!("funding_address={funding_address}");
    println!(
        "required_min_value_real_zk={}",
        preflight.required_min_value_real_zk
    );
    println!(
        "required_min_value_verifier_only={}",
        preflight.required_min_value_verifier_only
    );
    println!(
        "server_version={} server_network_id={} server_is_synced={} server_has_utxo_index={}",
        info.server_version, info.network_id, info.is_synced, info.has_utxo_index
    );

    if info.network_id != expected_network {
        println!("utxo_total_count=0");
        println!("utxo_non_coinbase_count=0");
        println!("utxo_eligible_count=0");
        println!("utxo_eligible_total_value=0");
        println!("selected_funding_utxo=not-checked");
        println!("funding_readiness=blocked");
        println!("blocked_reason=endpoint-network-mismatch");
        let _ = client.disconnect().await;
        return 4;
    }

    if !info.has_utxo_index {
        println!("utxo_total_count=0");
        println!("utxo_non_coinbase_count=0");
        println!("utxo_eligible_count=0");
        println!("utxo_eligible_total_value=0");
        println!("selected_funding_utxo=not-checked");
        println!("funding_readiness=blocked");
        println!("blocked_reason=utxo-index-disabled");
        let _ = client.disconnect().await;
        return 4;
    }

    let utxos = match client
        .get_utxos_by_addresses(vec![funding_address.clone()])
        .await
    {
        Ok(utxos) => utxos,
        Err(err) => {
            eprintln!("get_utxos_by_addresses failed: {err}");
            let _ = client.disconnect().await;
            return 3;
        }
    };
    let required = preflight.required_min_value_real_zk;
    let non_coinbase_count = utxos
        .iter()
        .filter(|entry| !entry.utxo_entry.is_coinbase)
        .count();
    let eligible = utxos
        .iter()
        .filter(|entry| !entry.utxo_entry.is_coinbase)
        .filter(|entry| entry.utxo_entry.amount >= required)
        .collect::<Vec<_>>();
    let eligible_count = eligible.len();
    let eligible_total_value = eligible
        .iter()
        .map(|entry| entry.utxo_entry.amount)
        .sum::<u64>();
    let selected = eligible
        .into_iter()
        .min_by_key(|entry| entry.utxo_entry.block_daa_score);

    println!("utxo_total_count={}", utxos.len());
    println!("utxo_non_coinbase_count={non_coinbase_count}");
    println!("utxo_eligible_count={eligible_count}");
    println!("utxo_eligible_total_value={eligible_total_value}");

    match selected {
        Some(entry) => {
            println!("selected_funding_utxo=available");
            println!(
                "selected_funding_utxo_txid=0x{}",
                to_hex(&entry.outpoint.transaction_id.as_bytes())
            );
            println!("selected_funding_utxo_index={}", entry.outpoint.index);
            println!(
                "selected_funding_utxo_daa={}",
                entry.utxo_entry.block_daa_score
            );
            println!("selected_funding_utxo_value={}", entry.utxo_entry.amount);
            println!(
                "selected_funding_utxo_coinbase={}",
                entry.utxo_entry.is_coinbase
            );
            println!("funding_readiness=ok");
            println!("blocked_reason=none");
            let _ = client.disconnect().await;
            0
        }
        None => {
            println!("selected_funding_utxo=none");
            println!("funding_readiness=blocked");
            println!("blocked_reason=missing-funded-non-coinbase-utxo");
            let _ = client.disconnect().await;
            4
        }
    }
}

#[cfg(feature = "live-kaspa-wrpc")]
async fn connect(
    url: &str,
    network_id: kaspa_wrpc_client::prelude::NetworkId,
) -> Result<kaspa_wrpc_client::KaspaRpcClient, Box<dyn std::error::Error>> {
    use std::time::Duration;

    use kaspa_wrpc_client::{
        client::{ConnectOptions, ConnectStrategy},
        KaspaRpcClient, Resolver, WrpcEncoding,
    };

    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some(url),
        Some(Resolver::default()),
        Some(network_id),
        None,
    )?;
    let opts = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(10)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client.connect(Some(opts)).await?;
    Ok(client)
}

#[cfg(feature = "live-kaspa-wrpc")]
fn expected_network_id(network: &str) -> Result<kaspa_wrpc_client::prelude::NetworkId, String> {
    use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};

    match network {
        "testnet-10" => Ok(NetworkId::with_suffix(NetworkType::Testnet, 10)),
        "testnet-12" => Ok(NetworkId::with_suffix(NetworkType::Testnet, 12)),
        other => Err(format!(
            "unsupported public testnet network {other}; expected testnet-10 or testnet-12"
        )),
    }
}

#[cfg(feature = "live-kaspa-wrpc")]
fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs();
    time_from_unix(secs)
}

#[cfg(feature = "live-kaspa-wrpc")]
fn time_from_unix(secs: u64) -> String {
    const SECS_PER_MIN: u64 = 60;
    const SECS_PER_HOUR: u64 = 60 * SECS_PER_MIN;
    const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;

    let days = secs / SECS_PER_DAY;
    let mut rem = secs % SECS_PER_DAY;
    let hour = rem / SECS_PER_HOUR;
    rem %= SECS_PER_HOUR;
    let min = rem / SECS_PER_MIN;
    let sec = rem % SECS_PER_MIN;

    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(feature = "live-kaspa-wrpc")]
fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}
