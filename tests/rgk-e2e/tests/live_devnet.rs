//! Live devnet evidence against a Toccata-active kaspad devnet.
//!
//! This test is opt-in even when `live-kaspa-wrpc` is enabled: set
//! `RGK_LIVE_DEVNET_URL` to a reachable devnet Borsh wRPC URL to run it.
//! The local evidence script starts such a node with:
//!
//! ```bash
//! ./scripts/e2e-devnet.sh --start-kaspa
//! ```

#![cfg(feature = "live-kaspa-wrpc")]

use std::net::{TcpStream, ToSocketAddrs};
#[cfg(feature = "persistent-indexer")]
use std::path::PathBuf;
use std::time::Duration;
#[cfg(feature = "persistent-indexer")]
use std::time::{SystemTime, UNIX_EPOCH};

use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::prelude::{NetworkId, NetworkType};
use kaspa_wrpc_client::{
    client::{ConnectOptions, ConnectStrategy},
    KaspaRpcClient, Resolver, WrpcEncoding,
};

#[cfg(feature = "persistent-indexer")]
use rgk_core::KaspaChainId;
#[cfg(feature = "persistent-indexer")]
use rgk_indexer::{ScanCursorStore, SledIndexer, DEFAULT_SCAN_CURSOR};
#[cfg(feature = "persistent-indexer")]
use rgk_kaspa::{WrpcBackend, WrpcNetwork};
#[cfg(feature = "persistent-indexer")]
use rgk_sync::{ScanService, ScanServiceConfig};

fn live_devnet_url() -> Option<String> {
    std::env::var("RGK_LIVE_DEVNET_URL").ok()
}

fn require_reachable_url(url: &str) {
    let Some((host, port)) = host_port(url) else {
        panic!("RGK_LIVE_DEVNET_URL is not a ws://host:port URL: {url}");
    };
    let mut addrs = (host.as_str(), port)
        .to_socket_addrs()
        .unwrap_or_else(|err| panic!("cannot resolve {host}:{port}: {err}"));
    let Some(addr) = addrs.next() else {
        panic!("no socket address resolved for {host}:{port}");
    };
    TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .unwrap_or_else(|err| panic!("devnet node unreachable at {host}:{port}: {err}"));
}

fn host_port(url: &str) -> Option<(String, u16)> {
    let without_scheme = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"))?;
    let authority = without_scheme.split('/').next()?;
    let (host, port) = authority.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

async fn connect_devnet(url: &str) -> KaspaRpcClient {
    let resolver = Some(Resolver::default());
    let network = Some(NetworkId::new(NetworkType::Devnet));
    let client = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), resolver, network, None)
        .expect("KaspaRpcClient::new");
    let opts = ConnectOptions {
        block_async_connect: true,
        connect_timeout: Some(Duration::from_secs(5)),
        strategy: ConnectStrategy::Fallback,
        ..Default::default()
    };
    client.connect(Some(opts)).await.expect("wRPC connect");
    client
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_devnet_reports_toccata_node_identity() {
    let Some(url) = live_devnet_url() else {
        eprintln!("live devnet evidence skipped: RGK_LIVE_DEVNET_URL is not set");
        return;
    };
    require_reachable_url(&url);

    let client = connect_devnet(&url).await;
    let info = client.get_server_info().await.expect("get_server_info");
    eprintln!(
        "live-devnet: server_version={} network_id={} is_synced={} has_utxo_index={}",
        info.server_version, info.network_id, info.is_synced, info.has_utxo_index
    );
    assert_eq!(info.network_id.network_type(), NetworkType::Devnet);
    assert!(
        info.server_version.contains("toc"),
        "must be built from the Toccata branch; got {}",
        info.server_version
    );
    assert!(
        info.has_utxo_index,
        "devnet evidence node must enable utxoindex"
    );
    client.disconnect().await.expect("disconnect");
}

#[cfg(feature = "persistent-indexer")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_devnet_initialises_persistent_scan_cursor() {
    let Some(url) = live_devnet_url() else {
        eprintln!("live devnet scan evidence skipped: RGK_LIVE_DEVNET_URL is not set");
        return;
    };
    require_reachable_url(&url);

    let backend = WrpcBackend::connect_borsh(&url, WrpcNetwork::Devnet)
        .await
        .expect("connect devnet WrpcBackend");
    let path = temp_db_path("rgk-devnet-scan");
    let mut indexer = SledIndexer::open_path(&path).expect("open devnet scan cursor store");
    let mut service = ScanService::new(
        &backend,
        &mut indexer,
        ScanServiceConfig::new(KaspaChainId::KaspaDevnet),
    );
    let tick = service.tick().expect("initialise devnet scan cursor");
    assert!(
        tick.initialised_cursor,
        "first devnet tick should initialise the cursor"
    );
    indexer.flush().expect("flush devnet cursor");
    drop(indexer);

    let reopened = SledIndexer::open_path(&path).expect("reopen devnet scan cursor store");
    let cursor = reopened
        .load_scan_cursor(DEFAULT_SCAN_CURSOR)
        .expect("load devnet scan cursor")
        .expect("devnet scan cursor should exist");
    assert_eq!(cursor.chain_id, KaspaChainId::KaspaDevnet);
    assert_eq!(cursor, tick.end_cursor);
    eprintln!(
        "live-devnet: scan cursor initialised chain={:?} daa={} hash_prefix={}",
        cursor.chain_id,
        cursor.daa_score,
        short_hash(&cursor.block_hash)
    );
}

#[cfg(feature = "persistent-indexer")]
fn temp_db_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

#[cfg(feature = "persistent-indexer")]
fn short_hash(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(16);
    for byte in hash.iter().take(8).copied() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
