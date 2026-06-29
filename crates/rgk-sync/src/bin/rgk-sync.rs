use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use rgk_indexer::{SledIndexer, DEFAULT_SCAN_CURSOR};
use rgk_kaspa::{KaspaNetworkError, WrpcBackend, WrpcNetwork};
use rgk_sync::{ScanRunSummary, ScanService, ScanServiceConfig, ScanTick, SyncError};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(
    name = "rgk-sync",
    about = "Run the RGK restart-safe live Kaspa scanner"
)]
struct Cli {
    /// Borsh wRPC endpoint, for example ws://127.0.0.1:18311/v2/kaspa/simnet/no-tls/wrpc/borsh.
    #[arg(long, env = "RGK_LIVE_KASPA_URL", value_name = "URL")]
    url: String,

    /// Kaspa network/domain pair to use for the wRPC transport and RGK cursor domain.
    #[arg(long, value_enum, default_value = "local-toccata")]
    network: CliNetwork,

    /// Sled database directory for scan cursor and indexed RGK state.
    #[arg(long, env = "RGK_SYNC_DB", value_name = "PATH")]
    db: PathBuf,

    /// Named scanner cursor to load and update.
    #[arg(long, value_name = "NAME")]
    cursor_name: Option<String>,

    /// Minimum virtual-chain confirmation count for scanned blocks.
    #[arg(long, value_name = "COUNT")]
    min_confirmations: Option<u64>,

    /// Run exactly one scanner tick, then flush and exit.
    #[arg(long, conflicts_with = "forever")]
    once: bool,

    /// Keep polling until Ctrl+C.
    #[arg(long, conflicts_with = "once")]
    forever: bool,

    /// Stop finite mode after this many consecutive idle ticks.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    max_idle_ticks: u32,

    /// Poll delay for forever mode after an idle tick.
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(1..))]
    poll_ms: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum CliNetwork {
    Mainnet,
    Testnet,
    Devnet,
    Simnet,
    LocalToccata,
}

impl CliNetwork {
    const fn to_wrpc_network(self) -> WrpcNetwork {
        match self {
            CliNetwork::Mainnet => WrpcNetwork::Mainnet,
            CliNetwork::Testnet => WrpcNetwork::Testnet,
            CliNetwork::Devnet => WrpcNetwork::Devnet,
            CliNetwork::Simnet => WrpcNetwork::Simnet,
            CliNetwork::LocalToccata => WrpcNetwork::LocalToccata,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("failed to connect to the wRPC endpoint: {0}")]
    Connect(#[source] KaspaNetworkError),
    #[error("failed to open sync database at {path:?}: {source}")]
    OpenIndexer {
        path: PathBuf,
        source: Box<rgk_indexer::IndexerError>,
    },
    #[error("scanner failed: {0}")]
    Sync(#[from] SyncError),
    #[error("failed to flush sync database: {0}")]
    Flush(#[source] Box<rgk_indexer::IndexerError>),
    #[error("failed while waiting for Ctrl+C: {0}")]
    Signal(#[source] std::io::Error),
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rgk-sync: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let wrpc_network = cli.network.to_wrpc_network();
    let backend = WrpcBackend::connect_borsh(&cli.url, wrpc_network)
        .await
        .map_err(CliError::Connect)?;
    let mut indexer = SledIndexer::open_path(&cli.db).map_err(|source| CliError::OpenIndexer {
        path: cli.db.clone(),
        source: Box::new(source),
    })?;
    let config = scan_config(&cli, wrpc_network);

    if cli.once {
        let tick = run_tick(&backend, &mut indexer, config)?;
        print_tick(&tick);
    } else if cli.forever {
        run_forever(
            &backend,
            &mut indexer,
            config,
            Duration::from_millis(cli.poll_ms),
        )
        .await?;
    } else {
        let summary = run_until_idle(&backend, &mut indexer, config, cli.max_idle_ticks)?;
        print_summary(&summary);
    }

    Ok(())
}

fn scan_config(cli: &Cli, network: WrpcNetwork) -> ScanServiceConfig {
    let mut config = ScanServiceConfig::new(network.chain_id());
    config.cursor_name = cli
        .cursor_name
        .clone()
        .unwrap_or_else(|| DEFAULT_SCAN_CURSOR.to_string());
    config.min_confirmation_count = cli.min_confirmations;
    config
}

async fn run_forever(
    backend: &WrpcBackend,
    indexer: &mut SledIndexer,
    config: ScanServiceConfig,
    poll_interval: Duration,
) -> Result<(), CliError> {
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        let tick = run_tick(backend, indexer, config.clone())?;
        print_tick(&tick);

        let delay = if tick.initialised_cursor || tick.added_chain_blocks > 0 {
            Duration::from_millis(0)
        } else {
            poll_interval
        };

        tokio::select! {
            signal = &mut shutdown => {
                signal.map_err(CliError::Signal)?;
                eprintln!("rgk-sync: shutdown requested");
                break;
            }
            () = tokio::time::sleep(delay) => {}
        }
    }

    Ok(())
}

fn run_tick(
    backend: &WrpcBackend,
    indexer: &mut SledIndexer,
    config: ScanServiceConfig,
) -> Result<ScanTick, CliError> {
    let tick = {
        let mut service = ScanService::new(backend, indexer, config);
        service.tick()?
    };
    indexer
        .flush()
        .map_err(|source| CliError::Flush(Box::new(source)))?;
    Ok(tick)
}

fn run_until_idle(
    backend: &WrpcBackend,
    indexer: &mut SledIndexer,
    config: ScanServiceConfig,
    max_idle_ticks: u32,
) -> Result<ScanRunSummary, CliError> {
    let summary = {
        let mut service = ScanService::new(backend, indexer, config);
        service.run_until_idle(max_idle_ticks)?
    };
    indexer
        .flush()
        .map_err(|source| CliError::Flush(Box::new(source)))?;
    Ok(summary)
}

fn print_tick(tick: &ScanTick) {
    let initialised = tick.initialised_cursor;
    let added_chain_blocks = tick.added_chain_blocks;
    let observed_spends = tick.observed_spends;
    let start_daa = tick.start_cursor.daa_score;
    let end_daa = tick.end_cursor.daa_score;
    let end_hash_prefix = short_hash(&tick.end_cursor.block_hash);
    println!(
        "tick initialised={initialised} added_chain_blocks={added_chain_blocks} observed_spends={observed_spends} start_daa={start_daa} end_daa={end_daa} end_hash_prefix={end_hash_prefix}"
    );
}

fn print_summary(summary: &ScanRunSummary) {
    let ticks = summary.ticks;
    let initialised = summary.initialised_cursor;
    let added_chain_blocks = summary.added_chain_blocks;
    let observed_spends = summary.observed_spends;
    let (end_daa, end_hash_prefix) = summary
        .end_cursor
        .as_ref()
        .map(|cursor| (cursor.daa_score.to_string(), short_hash(&cursor.block_hash)))
        .unwrap_or_else(|| ("none".to_string(), "none".to_string()));
    println!(
        "summary ticks={ticks} initialised={initialised} added_chain_blocks={added_chain_blocks} observed_spends={observed_spends} end_daa={end_daa} end_hash_prefix={end_hash_prefix}"
    );
}

fn short_hash(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(16);
    for byte in hash.iter().take(8).copied() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
