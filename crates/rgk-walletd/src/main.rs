#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, ValueEnum};
use rgk_core::{
    from_hex, receipt_commitment, to_hex, Bytes32, Canonical, KaspaChainId, KaspaOutpoint,
    ProofMode, ReceiptPolicy, RgkReceipt, RgkStateCommitment, MAX_BLOB_BYTES,
};
use rgk_indexer::{ContinuationProof, IndexedLane, Indexer, ObservedSpendStore, SledIndexer};
use rgk_kaspa::{KaspaChainBackend, WrpcBackend, WrpcNetwork};
use rgk_receipt::ReceiptVerifier;
use rgk_resolver::{LaneResolverState, ResolverState, RgkResolver};
use rgk_sync::{ScanService, ScanServiceConfig, ScanTick};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

#[derive(Debug, Parser)]
#[command(
    name = "rgk-walletd",
    about = "Run the local RGK wallet HTTP API for Avato"
)]
struct Cli {
    /// HTTP listen address for the local wallet daemon.
    #[arg(long, env = "RGK_WALLETD_LISTEN", default_value = "127.0.0.1:8788")]
    listen: SocketAddr,

    /// RGK/Kaspa network served by this daemon.
    #[arg(long, value_enum, default_value = "local-toccata")]
    network: CliNetwork,

    /// Borsh wRPC endpoint reported to the frontend.
    #[arg(long, env = "RGK_LIVE_KASPA_URL")]
    kaspa_endpoint: Option<String>,

    /// Local state file. It stores profile/dashboard metadata, never recovery
    /// phrases or raw passphrases.
    #[arg(
        long,
        env = "RGK_WALLETD_STATE",
        default_value = "target/rgk-walletd/state.json"
    )]
    state: PathBuf,

    /// Sled database directory for restart-safe scanner cursors.
    #[arg(long, env = "RGK_SYNC_DB", value_name = "PATH")]
    sync_db: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum CliNetwork {
    Mainnet,
    Testnet10,
    Testnet12,
    Devnet,
    Simnet,
    LocalToccata,
}

impl CliNetwork {
    const fn network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "rgk:kaspa-mainnet",
            Self::Testnet10 => "rgk:testnet-10",
            Self::Testnet12 => "rgk:testnet-12",
            Self::Devnet => "rgk:kaspa-devnet",
            Self::Simnet => "rgk:kaspa-simnet",
            Self::LocalToccata => "rgk:kaspa-local-toccata",
        }
    }

    const fn protocol_network_id(self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa-mainnet",
            Self::Testnet10 => "testnet-10",
            Self::Testnet12 => "testnet-12",
            Self::Devnet => "kaspa-devnet",
            Self::Simnet => "kaspa-simnet",
            Self::LocalToccata => "kaspa-local-toccata",
        }
    }

    const fn chain_id(self) -> KaspaChainId {
        match self {
            Self::Mainnet => KaspaChainId::KaspaMainnet,
            Self::Testnet10 | Self::Testnet12 => KaspaChainId::KaspaTestnet,
            Self::Devnet => KaspaChainId::KaspaDevnet,
            Self::Simnet => KaspaChainId::KaspaSimnet,
            Self::LocalToccata => KaspaChainId::KaspaLocalToccata,
        }
    }

    const fn default_kaspa_endpoint(self) -> &'static str {
        match self {
            Self::Mainnet => "wss://host.example/v2/kaspa/mainnet/tls/wrpc/borsh",
            Self::Testnet10 => "wss://host.example/v2/kaspa/testnet-10/tls/wrpc/borsh",
            Self::Testnet12 => "wss://host.example/v2/kaspa/testnet-12/tls/wrpc/borsh",
            Self::Devnet => "ws://127.0.0.1:19111/v2/kaspa/devnet/no-tls/wrpc/borsh",
            Self::Simnet => "ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh",
            Self::LocalToccata => "ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh",
        }
    }

    const fn address_prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa",
            Self::Testnet10 | Self::Testnet12 => "kaspatest",
            Self::Devnet => "kaspadev",
            Self::Simnet | Self::LocalToccata => "kaspasim",
        }
    }

    const fn wrpc_network(self) -> WrpcNetwork {
        match self {
            Self::Mainnet => WrpcNetwork::Mainnet,
            Self::Testnet10 | Self::Testnet12 => WrpcNetwork::Testnet,
            Self::Devnet => WrpcNetwork::Devnet,
            Self::Simnet => WrpcNetwork::Simnet,
            Self::LocalToccata => WrpcNetwork::LocalToccata,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<DaemonConfig>,
    store: Arc<Mutex<PersistedState>>,
}

#[derive(Debug)]
struct DaemonConfig {
    network: CliNetwork,
    kaspa_endpoint: String,
    state_path: PathBuf,
    sync_db_path: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedState {
    profile: Option<WalletProfile>,
    passphrase_salt: Option<String>,
    passphrase_verifier: Option<String>,
    kas_balance: String,
    lanes: Vec<AssetLane>,
    proofs: Vec<ProofSummary>,
    scan: ScanStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_notice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WalletProfile {
    wallet_id: String,
    protocol: String,
    network_id: String,
    protocol_network_id: String,
    canonical_chain_domain: String,
    kaspa_endpoint: String,
    wallet_set_id: Option<String>,
    address: Option<String>,
    lifecycle: WalletLifecycle,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WalletLifecycle {
    NotCreated,
    Locked,
    Ready,
    Syncing,
    ServiceRequired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssetLane {
    lineage_id: String,
    lane_id: String,
    label: String,
    ticker: String,
    balance: String,
    privacy: PrivacyMode,
    proof_policy: ReceiptPolicyName,
    resolver_state: ResolverStateName,
    covenant_id: String,
    state_digest: String,
    latest_receipt_id: Option<String>,
    updated_at: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PrivacyMode {
    PrivateLane,
    PublicLineage,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReceiptPolicyName {
    Any,
    VerifierOnly,
    ZkOrVerifier,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ResolverStateName {
    Open,
    NativeTransitionedValid,
    NativeTransitionedInvalid,
    Unconfirmed,
    ReorgRisk,
    CompetingBranch,
    ReplayRejected,
    PolicyMigrationRequired,
    Unknown,
    NodeDown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofSummary {
    receipt_id: String,
    proof_mode: ProofModeName,
    receipt_policy: ReceiptPolicyName,
    strategy: String,
    verifier_status: ProofVerifierStatus,
    txid: Option<String>,
    confirmations: u64,
    updated_at: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProofModeName {
    VerifierReceipt,
    ZkReceipt,
    P2mrRet,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProofVerifierStatus {
    Verified,
    Pending,
    Unsupported,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanStatus {
    cursor_name: String,
    scan_mode: ScanMode,
    last_daa_score: Option<u64>,
    indexed_spends: u64,
    observed_spends: u64,
    reorg_risk_count: u64,
}

impl Default for ScanStatus {
    fn default() -> Self {
        Self {
            cursor_name: "avato-rgk".to_string(),
            scan_mode: ScanMode::Unavailable,
            last_daa_score: None,
            indexed_spends: 0,
            observed_spends: 0,
            reorg_risk_count: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScanMode {
    Idle,
    Scanning,
    Paused,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardSnapshot {
    profile: WalletProfile,
    kas_balance: String,
    lanes: Vec<AssetLane>,
    proofs: Vec<ProofSummary>,
    scan: ScanStatus,
    service_mode: ServiceMode,
    service_notice: String,
}

#[derive(Copy, Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ServiceMode {
    Unavailable,
    Connected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateWalletInput {
    wallet_id: String,
    network_id: String,
    protocol_network_id: String,
    canonical_chain_domain: String,
    kaspa_endpoint: String,
    passphrase: String,
    recovery_phrase: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnlockWalletInput {
    passphrase: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateLaneInput {
    label: String,
    ticker: String,
    balance: String,
    privacy: PrivacyMode,
    proof_policy: ReceiptPolicyName,
    #[serde(default)]
    covenant_id: String,
    #[serde(default)]
    lineage_id: String,
    #[serde(default)]
    asset_id: String,
    #[serde(default)]
    lane_id: String,
    #[serde(default)]
    scan_tag: String,
    #[serde(default)]
    state_digest: String,
    #[serde(default)]
    open_txid: String,
    #[serde(default)]
    open_index: u32,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    daa_score: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordProofInput {
    lane_id: String,
    proof_mode: ProofModeName,
    receipt_policy: ReceiptPolicyName,
    strategy: String,
    txid: String,
    confirmations: u64,
    #[serde(default)]
    receipt_bytes: String,
    #[serde(default)]
    covenant_id: String,
    #[serde(default)]
    spent_txid: String,
    #[serde(default)]
    spent_index: u32,
    #[serde(default)]
    new_txid: String,
    #[serde(default)]
    new_index: u32,
    #[serde(default)]
    continuation_shape_root: String,
    #[serde(default)]
    daa_score: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    service: &'static str,
    status: &'static str,
    protocol: &'static str,
    network_id: String,
    protocol_network_id: String,
    canonical_chain_domain: String,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct ApiError {
    message: String,
}

#[derive(Debug, Error)]
enum WalletdError {
    #[error("wallet profile has not been created")]
    NotFound,
    #[error("wallet is locked")]
    Locked,
    #[error("passphrase was not accepted")]
    Unauthorized,
    #[error("{0}")]
    BadRequest(String),
    #[error("state lock is poisoned")]
    PoisonedState,
    #[error("state persistence failed: {0}")]
    Persist(String),
    #[error("failed to read local entropy: {0}")]
    Entropy(String),
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Arc::new(DaemonConfig {
        network: cli.network,
        kaspa_endpoint: cli
            .kaspa_endpoint
            .unwrap_or_else(|| cli.network.default_kaspa_endpoint().to_string()),
        sync_db_path: cli
            .sync_db
            .unwrap_or_else(|| default_sync_db_path(&cli.state)),
        state_path: cli.state,
    });
    let store = Arc::new(Mutex::new(load_state(&config.state_path)?));
    let app_state = AppState { config, store };
    let app = Router::new()
        .route("/health", get(health))
        .route("/wallet/profile", get(profile))
        .route("/wallets", post(create_wallet))
        .route("/wallet/import", post(import_wallet))
        .route("/wallet/lock", post(lock_wallet))
        .route("/wallet/unlock", post(unlock_wallet))
        .route("/wallet/sync", post(sync_wallet))
        .route("/dashboard", get(dashboard))
        .route("/lanes", post(create_lane))
        .route("/proofs", post(record_proof))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let listener = TcpListener::bind(cli.listen).await?;
    eprintln!("rgk-walletd: listening on http://{}", cli.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "rgk-wallet",
        status: "ok",
        protocol: "rgk",
        network_id: state.config.network.network_id().to_string(),
        protocol_network_id: state.config.network.protocol_network_id().to_string(),
        canonical_chain_domain: state.config.network.chain_id().as_domain_str().to_string(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn profile(State(state): State<AppState>) -> ApiResult<WalletProfile> {
    let store = state.store()?;
    let profile = store
        .profile
        .clone()
        .ok_or_else(|| api_error(WalletdError::NotFound))?;
    Ok(Json(profile))
}

async fn create_wallet(
    State(state): State<AppState>,
    Json(input): Json<CreateWalletInput>,
) -> ApiResult<WalletProfile> {
    upsert_wallet(state, input).await
}

async fn import_wallet(
    State(state): State<AppState>,
    Json(input): Json<CreateWalletInput>,
) -> ApiResult<WalletProfile> {
    upsert_wallet(state, input).await
}

async fn lock_wallet(
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let mut store = state.store()?;
    let Some(profile) = store.profile.as_mut() else {
        return Err(api_error(WalletdError::NotFound));
    };
    profile.lifecycle = WalletLifecycle::Locked;
    save_state(&state.config.state_path, &store)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unlock_wallet(
    State(state): State<AppState>,
    Json(input): Json<UnlockWalletInput>,
) -> ApiResult<WalletProfile> {
    let mut store = state.store()?;
    let verifier = store
        .passphrase_verifier
        .clone()
        .ok_or_else(|| api_error(WalletdError::NotFound))?;
    let passphrase_salt = store.passphrase_salt.clone();
    let profile = store
        .profile
        .as_mut()
        .ok_or_else(|| api_error(WalletdError::NotFound))?;
    let accepted = match passphrase_salt.as_deref() {
        Some(salt) => passphrase_verifier_with_salt(salt, &profile.wallet_id, &input.passphrase),
        None => legacy_passphrase_verifier(&profile.wallet_id, &input.passphrase),
    };
    if accepted != verifier {
        return Err(api_error(WalletdError::Unauthorized));
    }
    profile.lifecycle = WalletLifecycle::Ready;
    let profile = profile.clone();
    save_state(&state.config.state_path, &store)?;
    Ok(Json(profile))
}

async fn sync_wallet(State(state): State<AppState>) -> ApiResult<DashboardSnapshot> {
    let (kaspa_endpoint, lanes) = {
        let store = state.store()?;
        let profile = ready_profile(&store)?;
        if matches!(profile.lifecycle, WalletLifecycle::Locked) {
            return Err(api_error(WalletdError::Locked));
        }
        (profile.kaspa_endpoint.clone(), store.lanes.clone())
    };

    let scan_result = run_scan_tick(Arc::clone(&state.config), kaspa_endpoint, lanes).await;

    let mut store = state.store()?;
    if matches!(
        store.profile.as_ref().map(|profile| profile.lifecycle),
        Some(WalletLifecycle::Locked)
    ) {
        return Err(api_error(WalletdError::Locked));
    }
    match scan_result {
        Ok(scan) => apply_successful_scan(&mut store, &scan),
        Err(message) => apply_failed_scan(&mut store, message),
    }
    save_state(&state.config.state_path, &store)?;
    Ok(Json(dashboard_snapshot(&store)?))
}

async fn dashboard(State(state): State<AppState>) -> ApiResult<DashboardSnapshot> {
    let store = state.store()?;
    Ok(Json(dashboard_snapshot(&store)?))
}

async fn create_lane(
    State(state): State<AppState>,
    Json(input): Json<CreateLaneInput>,
) -> ApiResult<AssetLane> {
    let (wallet_id, lane_count) = {
        let store = state.store()?;
        (ready_wallet_id(&store)?, store.lanes.len())
    };
    let label = validate_lane_label(&input.label)?;
    let ticker = validate_ticker(&input.ticker)?;
    let balance = validate_balance(&input.balance)?;
    let evidence = parse_lane_evidence(state.config.network.chain_id(), &input)
        .map_err(|message| api_error(WalletdError::BadRequest(message)))?;
    if let Some(evidence) = evidence.as_ref() {
        let store = state.store()?;
        validate_lane_profile_uniqueness(&store, evidence)?;
    }
    let indexed = index_lane_evidence(Arc::clone(&state.config), evidence.clone())
        .await
        .map_err(|message| api_error(WalletdError::BadRequest(message)))?;
    let seed = format!("{}:{}:{}:{}", wallet_id, label, ticker, lane_count);
    let updated_at = now_label();
    let lane = AssetLane {
        lineage_id: indexed
            .as_ref()
            .map(|evidence| format!("rgk:lineage:{}", hex32_label(&evidence.lineage_id)))
            .unwrap_or_else(|| format!("rgk:lineage:{}", hex_digest("lineage", &seed, 32))),
        lane_id: indexed
            .as_ref()
            .map(|evidence| {
                format!(
                    "rgk:lane:{}:{}",
                    privacy_slug(input.privacy),
                    hex32_label(&evidence.lane_id)
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "rgk:lane:{}:{}",
                    privacy_slug(input.privacy),
                    hex_digest("lane", &seed, 32)
                )
            }),
        label,
        ticker,
        balance,
        privacy: input.privacy,
        proof_policy: input.proof_policy,
        resolver_state: ResolverStateName::Unknown,
        covenant_id: indexed
            .as_ref()
            .map(|evidence| hex32_label(&evidence.covenant_id))
            .unwrap_or_else(|| hex_digest("covenant", &seed, 32)),
        state_digest: indexed
            .as_ref()
            .map(|evidence| hex32_label(&evidence.state_digest))
            .unwrap_or_else(|| hex_digest("state", &seed, 32)),
        latest_receipt_id: None,
        updated_at,
    };
    let mut store = state.store()?;
    if store.lanes.iter().any(|existing| {
        existing.lane_id == lane.lane_id || existing.covenant_id == lane.covenant_id
    }) {
        return Err(api_error(WalletdError::BadRequest(
            "lane or covenant is already present in the wallet profile".to_string(),
        )));
    }
    store.lanes.push(lane.clone());
    save_state(&state.config.state_path, &store)?;
    Ok(Json(lane))
}

async fn record_proof(
    State(state): State<AppState>,
    Json(input): Json<RecordProofInput>,
) -> ApiResult<ProofSummary> {
    let (wallet_id, selected_lane_covenant_id) = {
        let store = state.store()?;
        let wallet_id = ready_wallet_id(&store)?;
        let Some(lane) = store
            .lanes
            .iter()
            .find(|lane| lane.lane_id == input.lane_id)
        else {
            return Err(api_error(WalletdError::BadRequest(format!(
                "laneId {} was not found",
                input.lane_id
            ))));
        };
        (wallet_id, lane.covenant_id.clone())
    };
    let strategy = validate_strategy(&input.strategy)?;
    let txid = validate_optional_txid(&input.txid)?;
    validate_proof_lane_binding(&input, &selected_lane_covenant_id)
        .map_err(|message| api_error(WalletdError::BadRequest(message)))?;
    let verified = ingest_proof_evidence(Arc::clone(&state.config), input.clone())
        .await
        .map_err(|message| api_error(WalletdError::BadRequest(message)))?;

    let mut store = state.store()?;
    let seed = format!("{}:{}:{}", wallet_id, strategy, store.proofs.len());
    let updated_at = now_label();
    let proof_mode = verified
        .as_ref()
        .map(|evidence| evidence.proof_mode)
        .unwrap_or(input.proof_mode);
    let receipt_policy = verified
        .as_ref()
        .map(|evidence| evidence.receipt_policy)
        .unwrap_or(input.receipt_policy);
    let receipt_id = verified
        .as_ref()
        .map(|evidence| format!("rgk:receipt:{}", hex32_label(&evidence.receipt_id)))
        .unwrap_or_else(|| format!("rgk:receipt:{}", hex_digest("receipt", &seed, 32)));
    let txid = verified
        .as_ref()
        .map(|evidence| hex32_plain(&evidence.new_outpoint.transaction_id))
        .or(txid);
    let proof = ProofSummary {
        receipt_id,
        proof_mode,
        receipt_policy,
        strategy,
        verifier_status: if verified.is_some() {
            ProofVerifierStatus::Verified
        } else {
            ProofVerifierStatus::Pending
        },
        txid,
        confirmations: input.confirmations,
        updated_at: updated_at.clone(),
    };

    let Some(lane) = store
        .lanes
        .iter_mut()
        .find(|lane| lane.lane_id == input.lane_id)
    else {
        return Err(api_error(WalletdError::BadRequest(format!(
            "laneId {} was not found",
            input.lane_id
        ))));
    };

    lane.latest_receipt_id = Some(proof.receipt_id.clone());
    if let Some(evidence) = verified.as_ref() {
        lane.state_digest = hex32_label(&evidence.new_state_digest);
    }
    lane.updated_at = updated_at;

    store.proofs.push(proof.clone());
    save_state(&state.config.state_path, &store)?;
    Ok(Json(proof))
}

async fn upsert_wallet(state: AppState, input: CreateWalletInput) -> ApiResult<WalletProfile> {
    validate_input_network(&state.config, &input)?;
    let wallet_id = validate_wallet_id(&input.wallet_id)?;
    validate_recovery_phrase(&input.recovery_phrase)?;
    let passphrase = validate_passphrase(&input.passphrase)?;
    let kaspa_endpoint = validate_optional_kaspa_endpoint(&input.kaspa_endpoint)?
        .unwrap_or_else(|| state.config.kaspa_endpoint.clone());

    let mut store = state.store()?;
    let profile = WalletProfile {
        wallet_id: wallet_id.clone(),
        protocol: "rgk".to_string(),
        network_id: state.config.network.network_id().to_string(),
        protocol_network_id: state.config.network.protocol_network_id().to_string(),
        canonical_chain_domain: state.config.network.chain_id().as_domain_str().to_string(),
        kaspa_endpoint,
        wallet_set_id: Some(hex_digest("wallet-set", &wallet_id, 32)),
        address: Some(format!(
            "{}:qavato{}",
            state.config.network.address_prefix(),
            &hex_digest("address", &wallet_id, 12)[2..],
        )),
        lifecycle: WalletLifecycle::Ready,
    };
    let passphrase_salt = new_passphrase_salt().map_err(api_error)?;
    store.passphrase_verifier = Some(passphrase_verifier_with_salt(
        &passphrase_salt,
        &profile.wallet_id,
        &passphrase,
    ));
    store.passphrase_salt = Some(passphrase_salt);
    store.kas_balance = "0.00000000 KAS".to_string();
    store.lanes.clear();
    store.proofs.clear();
    store.scan = ScanStatus {
        cursor_name: "avato-rgk".to_string(),
        scan_mode: ScanMode::Idle,
        last_daa_score: None,
        indexed_spends: 0,
        observed_spends: 0,
        reorg_risk_count: 0,
    };
    store.scan_notice = None;
    store.profile = Some(profile.clone());
    save_state(&state.config.state_path, &store)?;
    Ok(Json(profile))
}

struct WalletdScanResult {
    tick: ScanTick,
    indexed_spends: usize,
    lane_updates: Vec<LaneResolutionUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LaneResolutionUpdate {
    lane_id: String,
    resolver_state: ResolverStateName,
    covenant_id: Option<String>,
    state_digest: Option<String>,
    latest_receipt_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LaneEvidence {
    covenant_id: Bytes32,
    lineage_id: Bytes32,
    asset_id: Bytes32,
    lane_id: Bytes32,
    state_digest: Bytes32,
    state: RgkStateCommitment,
    open_outpoint: KaspaOutpoint,
    lane: IndexedLane,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedProofEvidence {
    receipt_id: Bytes32,
    proof_mode: ProofModeName,
    receipt_policy: ReceiptPolicyName,
    new_outpoint: KaspaOutpoint,
    new_state_digest: Bytes32,
}

async fn run_scan_tick(
    config: Arc<DaemonConfig>,
    kaspa_endpoint: String,
    lanes: Vec<AssetLane>,
) -> Result<WalletdScanResult, String> {
    let backend = WrpcBackend::connect_borsh(&kaspa_endpoint, config.network.wrpc_network())
        .await
        .map_err(|error| format!("failed to connect to Kaspa wRPC: {error}"))?;
    let sync_db_path = config.sync_db_path.clone();
    let chain_id = config.network.chain_id();
    let cursor_name = "avato-rgk".to_string();

    tokio::task::spawn_blocking(move || {
        let mut indexer = SledIndexer::open_path(&sync_db_path)
            .map_err(|error| format!("failed to open scanner database: {error}"))?;
        let mut scan_config = ScanServiceConfig::new(chain_id);
        scan_config.cursor_name = cursor_name;
        let tick = {
            let mut service = ScanService::new(&backend, &mut indexer, scan_config);
            service.tick().map_err(|error| error.to_string())?
        };
        indexer
            .flush()
            .map_err(|error| format!("failed to flush scanner database: {error}"))?;
        let indexed_spends = indexer
            .observed_spend_count()
            .map_err(|error| format!("failed to count observed spends: {error}"))?;
        let lane_updates = resolve_indexed_lanes(&backend, &indexer, chain_id, &lanes);
        Ok(WalletdScanResult {
            tick,
            indexed_spends,
            lane_updates,
        })
    })
    .await
    .map_err(|error| format!("scanner task failed: {error}"))?
}

async fn index_lane_evidence(
    config: Arc<DaemonConfig>,
    evidence: Option<LaneEvidence>,
) -> Result<Option<LaneEvidence>, String> {
    let Some(evidence) = evidence else {
        return Ok(None);
    };
    let sync_db_path = config.sync_db_path.clone();
    let chain_id = config.network.chain_id();
    tokio::task::spawn_blocking(move || {
        index_lane_evidence_at_path(&sync_db_path, chain_id, evidence)
    })
    .await
    .map_err(|error| format!("lane evidence task failed: {error}"))?
}

fn index_lane_evidence_at_path(
    sync_db_path: &Path,
    chain_id: KaspaChainId,
    evidence: LaneEvidence,
) -> Result<Option<LaneEvidence>, String> {
    if evidence.lane.chain_id != chain_id {
        return Err("lane evidence chain id does not match walletd network".to_string());
    }
    let mut indexer = SledIndexer::open_path(sync_db_path)
        .map_err(|error| format!("failed to open scanner database: {error}"))?;
    indexer
        .open(
            chain_id,
            evidence.covenant_id,
            evidence.lineage_id,
            evidence.state.clone(),
            evidence.open_outpoint,
            evidence.lane.last_update_daa_score,
        )
        .map_err(|error| format!("failed to index covenant: {error}"))?;
    indexer
        .register_lane(evidence.lane.clone())
        .map_err(|error| format!("failed to register lane: {error}"))?;
    indexer
        .flush()
        .map_err(|error| format!("failed to flush scanner database: {error}"))?;

    Ok(Some(evidence))
}

fn parse_lane_evidence(
    chain_id: KaspaChainId,
    input: &CreateLaneInput,
) -> Result<Option<LaneEvidence>, String> {
    if !lane_evidence_supplied(input) {
        return Ok(None);
    }
    require_lane_evidence_bundle(input)?;
    let covenant_id = parse_bytes32_required(&input.covenant_id, "covenantId")?;
    let lineage_id = parse_bytes32_required(&input.lineage_id, "lineageId")?;
    let asset_id = parse_bytes32_required(&input.asset_id, "assetId")?;
    let lane_id = parse_bytes32_required(&input.lane_id, "laneId")?;
    let scan_tag = trimmed_optional(&input.scan_tag)
        .map(|scan_tag| parse_bytes32_required(&scan_tag, "scanTag"))
        .transpose()?;
    let state_digest = parse_bytes32_required(&input.state_digest, "stateDigest")?;
    validate_lane_evidence_invariants(lane_id, scan_tag, state_digest)?;
    let open_outpoint = KaspaOutpoint {
        transaction_id: parse_bytes32_required(&input.open_txid, "openTxid")?,
        index: input.open_index,
    };
    let state = RgkStateCommitment::new(
        chain_id,
        covenant_id,
        asset_id,
        state_digest,
        receipt_policy(input.proof_policy),
    )
    .map_err(|error| format!("indexed state commitment is invalid: {error}"))?;
    let lane = IndexedLane::new(
        chain_id,
        covenant_id,
        asset_id,
        lane_id,
        input.epoch,
        scan_tag,
        matches!(input.privacy, PrivacyMode::PublicLineage),
        state_digest,
        input.daa_score,
    );

    Ok(Some(LaneEvidence {
        covenant_id,
        lineage_id,
        asset_id,
        lane_id,
        state_digest,
        state,
        open_outpoint,
        lane,
    }))
}

fn validate_lane_evidence_invariants(
    lane_id: Bytes32,
    scan_tag: Option<Bytes32>,
    state_digest: Bytes32,
) -> Result<(), String> {
    if lane_id == [0u8; 32] {
        return Err("laneId must not be zero when lane evidence is supplied".to_string());
    }
    if state_digest == [0u8; 32] {
        return Err("stateDigest must not be zero when lane evidence is supplied".to_string());
    }
    if scan_tag == Some([0u8; 32]) {
        return Err("scanTag must not be zero when lane evidence is supplied".to_string());
    }
    Ok(())
}

fn validate_lane_profile_uniqueness(
    store: &PersistedState,
    evidence: &LaneEvidence,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    if store.lanes.iter().any(|existing| {
        parse_bytes32_handle(&existing.lane_id) == Some(evidence.lane_id)
            || parse_bytes32_handle(&existing.covenant_id) == Some(evidence.covenant_id)
    }) {
        return Err(api_error(WalletdError::BadRequest(
            "lane or covenant is already present in the wallet profile".to_string(),
        )));
    }
    Ok(())
}

fn lane_evidence_supplied(input: &CreateLaneInput) -> bool {
    !input.covenant_id.trim().is_empty()
        || !input.lineage_id.trim().is_empty()
        || !input.asset_id.trim().is_empty()
        || !input.lane_id.trim().is_empty()
        || !input.scan_tag.trim().is_empty()
        || !input.state_digest.trim().is_empty()
        || !input.open_txid.trim().is_empty()
}

fn require_lane_evidence_bundle(input: &CreateLaneInput) -> Result<(), String> {
    for (name, value) in [
        ("covenantId", input.covenant_id.as_str()),
        ("lineageId", input.lineage_id.as_str()),
        ("assetId", input.asset_id.as_str()),
        ("laneId", input.lane_id.as_str()),
        ("stateDigest", input.state_digest.as_str()),
        ("openTxid", input.open_txid.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{name} is required when lane evidence is supplied"));
        }
    }
    Ok(())
}

async fn ingest_proof_evidence(
    config: Arc<DaemonConfig>,
    input: RecordProofInput,
) -> Result<Option<VerifiedProofEvidence>, String> {
    if !proof_evidence_supplied(&input) {
        return Ok(None);
    }
    let sync_db_path = config.sync_db_path.clone();
    let chain_id = config.network.chain_id();
    tokio::task::spawn_blocking(move || {
        ingest_proof_evidence_at_path(&sync_db_path, chain_id, &input)
    })
    .await
    .map_err(|error| format!("proof evidence task failed: {error}"))?
}

fn ingest_proof_evidence_at_path(
    sync_db_path: &Path,
    chain_id: KaspaChainId,
    input: &RecordProofInput,
) -> Result<Option<VerifiedProofEvidence>, String> {
    if !proof_evidence_supplied(input) {
        return Ok(None);
    }
    require_proof_evidence_bundle(input)?;
    let receipt_bytes = parse_hex_blob(&input.receipt_bytes, "receiptBytes")?;
    let covenant_id = parse_bytes32_required(&input.covenant_id, "covenantId")?;
    let spent = KaspaOutpoint {
        transaction_id: parse_bytes32_required(&input.spent_txid, "spentTxid")?,
        index: input.spent_index,
    };
    let new_outpoint = KaspaOutpoint {
        transaction_id: parse_bytes32_required(&input.new_txid, "newTxid")?,
        index: input.new_index,
    };
    if let Some(txid) = trimmed_optional(&input.txid) {
        let txid = parse_bytes32_required(&txid, "txid")?;
        if txid != new_outpoint.transaction_id {
            return Err("txid must match newTxid when receipt evidence is supplied".to_string());
        }
    }
    let shape_root =
        parse_bytes32_required(&input.continuation_shape_root, "continuationShapeRoot")?;
    let receipt = RgkReceipt::decode_canonical(&receipt_bytes)
        .map_err(|error| format!("receiptBytes could not be decoded: {error}"))?;
    if proof_mode_name(receipt.proof_mode) != input.proof_mode {
        return Err("proofMode does not match the canonical receipt".to_string());
    }
    if receipt_policy_name(receipt.new_state.receipt_policy) != input.receipt_policy {
        return Err("receiptPolicy does not match the canonical receipt new state".to_string());
    }

    let mut indexer = SledIndexer::open_path(sync_db_path)
        .map_err(|error| format!("failed to open scanner database: {error}"))?;
    let expected_old = indexer
        .latest_state(covenant_id)
        .ok_or_else(|| "covenantId is not indexed in the wallet database".to_string())?;
    let receipt_id =
        ReceiptVerifier::verify_local_structured(&receipt, covenant_id, &expected_old, chain_id)
            .map_err(|error| format!("receipt verification failed: {error}"))?;
    let canonical_receipt_id = receipt_commitment(&receipt);
    if receipt_id != canonical_receipt_id {
        return Err("receipt verifier returned a non-canonical receipt id".to_string());
    }
    let continuation = ContinuationProof {
        commitment: receipt.continuation_commitment,
        shape_root,
        transition_digest: receipt.transition_digest,
    };
    indexer
        .apply_spend_with_continuation(
            covenant_id,
            receipt_id,
            spent,
            new_outpoint,
            receipt.new_state.clone(),
            input.daa_score,
            continuation,
        )
        .map_err(|error| format!("failed to index receipt spend: {error}"))?;
    indexer
        .flush()
        .map_err(|error| format!("failed to flush scanner database: {error}"))?;

    Ok(Some(VerifiedProofEvidence {
        receipt_id,
        proof_mode: proof_mode_name(receipt.proof_mode),
        receipt_policy: receipt_policy_name(receipt.new_state.receipt_policy),
        new_outpoint,
        new_state_digest: receipt.new_state.state_digest,
    }))
}

fn proof_evidence_supplied(input: &RecordProofInput) -> bool {
    !input.receipt_bytes.trim().is_empty()
        || !input.covenant_id.trim().is_empty()
        || !input.spent_txid.trim().is_empty()
        || !input.new_txid.trim().is_empty()
        || !input.continuation_shape_root.trim().is_empty()
}

fn require_proof_evidence_bundle(input: &RecordProofInput) -> Result<(), String> {
    for (name, value) in [
        ("receiptBytes", input.receipt_bytes.as_str()),
        ("covenantId", input.covenant_id.as_str()),
        ("spentTxid", input.spent_txid.as_str()),
        ("newTxid", input.new_txid.as_str()),
        (
            "continuationShapeRoot",
            input.continuation_shape_root.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(format!(
                "{name} is required when proof evidence is supplied"
            ));
        }
    }
    Ok(())
}

fn validate_proof_lane_binding(
    input: &RecordProofInput,
    selected_lane_covenant_id: &str,
) -> Result<(), String> {
    if !proof_evidence_supplied(input) {
        return Ok(());
    }
    let selected = parse_bytes32_required(selected_lane_covenant_id, "selected lane covenantId")?;
    let supplied = parse_bytes32_required(&input.covenant_id, "covenantId")?;
    if selected != supplied {
        return Err(
            "covenantId must match the selected lane before proof evidence can be indexed"
                .to_string(),
        );
    }
    Ok(())
}

fn apply_successful_scan(store: &mut PersistedState, scan: &WalletdScanResult) {
    if let Some(profile) = store.profile.as_mut() {
        profile.lifecycle = WalletLifecycle::Ready;
    }
    let tick = &scan.tick;
    store.scan.scan_mode = ScanMode::Idle;
    store.scan.last_daa_score = Some(tick.end_cursor.daa_score);
    let indexed_spends = u64::try_from(scan.indexed_spends).unwrap_or(u64::MAX);
    store.scan.indexed_spends = indexed_spends;
    store.scan.observed_spends = indexed_spends;
    apply_lane_resolution_updates(store, &scan.lane_updates);
    store.scan_notice = Some(if tick.initialised_cursor {
        format!(
            "RGK scanner cursor initialised at DAA {}.",
            tick.end_cursor.daa_score
        )
    } else {
        format!(
            "RGK scanner tick completed: {} added chain block(s), {} observed spend(s), cursor DAA {}.",
            tick.added_chain_blocks, tick.observed_spends, tick.end_cursor.daa_score
        )
    });
}

fn apply_failed_scan(store: &mut PersistedState, message: String) {
    if let Some(profile) = store.profile.as_mut() {
        profile.lifecycle = WalletLifecycle::ServiceRequired;
    }
    store.scan.scan_mode = ScanMode::Unavailable;
    store.scan_notice = Some(format!("RGK scanner unavailable: {message}"));
}

fn apply_lane_resolution_updates(store: &mut PersistedState, updates: &[LaneResolutionUpdate]) {
    for update in updates {
        let Some(lane) = store
            .lanes
            .iter_mut()
            .find(|lane| lane.lane_id == update.lane_id)
        else {
            continue;
        };
        let mut changed = false;
        if lane.resolver_state != update.resolver_state {
            lane.resolver_state = update.resolver_state;
            changed = true;
        }
        if let Some(covenant_id) = update.covenant_id.as_ref() {
            if lane.covenant_id != *covenant_id {
                lane.covenant_id = covenant_id.clone();
                changed = true;
            }
        }
        if let Some(state_digest) = update.state_digest.as_ref() {
            if lane.state_digest != *state_digest {
                lane.state_digest = state_digest.clone();
                changed = true;
            }
        }
        if let Some(receipt_id) = update.latest_receipt_id.as_ref() {
            if lane.latest_receipt_id.as_ref() != Some(receipt_id) {
                lane.latest_receipt_id = Some(receipt_id.clone());
                changed = true;
            }
        }
        if changed {
            lane.updated_at = now_label();
        }
    }
}

fn dashboard_snapshot(
    store: &PersistedState,
) -> Result<DashboardSnapshot, (StatusCode, Json<ApiError>)> {
    let profile = ready_profile(store)?.clone();
    if matches!(profile.lifecycle, WalletLifecycle::Locked) {
        return Err(api_error(WalletdError::Locked));
    }
    let service_mode = if matches!(store.scan.scan_mode, ScanMode::Unavailable) {
        ServiceMode::Unavailable
    } else {
        ServiceMode::Connected
    };
    Ok(DashboardSnapshot {
        profile,
        kas_balance: store.kas_balance.clone(),
        lanes: store.lanes.clone(),
        proofs: store.proofs.clone(),
        scan: store.scan.clone(),
        service_mode,
        service_notice: store
            .scan_notice
            .clone()
            .unwrap_or_else(|| "Connected to the local RGK wallet daemon.".to_string()),
    })
}

fn resolve_indexed_lanes<B, I>(
    backend: &B,
    indexer: &I,
    chain_id: KaspaChainId,
    lanes: &[AssetLane],
) -> Vec<LaneResolutionUpdate>
where
    B: KaspaChainBackend,
    I: Indexer,
{
    let resolver = RgkResolver::new(backend, indexer, chain_id);
    lanes
        .iter()
        .map(|lane| resolve_indexed_lane(&resolver, lane))
        .collect()
}

fn resolve_indexed_lane<B, I>(
    resolver: &RgkResolver<'_, B, I>,
    lane: &AssetLane,
) -> LaneResolutionUpdate
where
    B: KaspaChainBackend,
    I: Indexer,
{
    if let Some(lane_id) = parse_bytes32_handle(&lane.lane_id) {
        match resolver.resolve_lane(lane_id) {
            LaneResolverState::Resolved {
                lane: indexed_lane,
                state,
            } => {
                return lane_update_from_resolver_state(lane, Some(&indexed_lane), state.as_ref());
            }
            LaneResolverState::UnknownLane { .. } => {}
            LaneResolverState::UnknownScanTag { .. } => {}
        }
    }

    if let Some(covenant_id) = parse_bytes32_handle(&lane.covenant_id) {
        let state = resolver.resolve_by_covenant(covenant_id);
        return lane_update_from_resolver_state(lane, None, &state);
    }

    LaneResolutionUpdate {
        lane_id: lane.lane_id.clone(),
        resolver_state: ResolverStateName::Unknown,
        covenant_id: None,
        state_digest: None,
        latest_receipt_id: None,
    }
}

fn lane_update_from_resolver_state(
    lane: &AssetLane,
    indexed_lane: Option<&IndexedLane>,
    state: &ResolverState,
) -> LaneResolutionUpdate {
    let (state_digest, latest_receipt_id) = match state {
        ResolverState::Open { state, .. } => (Some(hex32_label(&state.state_digest)), None),
        ResolverState::NativeTransitionedValid {
            new_state,
            receipt_id,
            ..
        } => (
            Some(hex32_label(&new_state.state_digest)),
            Some(format!("rgk:receipt:{}", hex32_label(receipt_id))),
        ),
        _ => (None, None),
    };

    LaneResolutionUpdate {
        lane_id: lane.lane_id.clone(),
        resolver_state: resolver_state_name(state),
        covenant_id: indexed_lane.map(|indexed| hex32_label(&indexed.covenant_id)),
        state_digest,
        latest_receipt_id,
    }
}

fn resolver_state_name(state: &ResolverState) -> ResolverStateName {
    match state {
        ResolverState::Open { .. } => ResolverStateName::Open,
        ResolverState::NativeTransitionedValid { .. } => ResolverStateName::NativeTransitionedValid,
        ResolverState::NativeTransitionedInvalid { .. } => {
            ResolverStateName::NativeTransitionedInvalid
        }
        ResolverState::Unconfirmed { .. } => ResolverStateName::Unconfirmed,
        ResolverState::ReorgRisk { .. } => ResolverStateName::ReorgRisk,
        ResolverState::CompetingBranch { .. } => ResolverStateName::CompetingBranch,
        ResolverState::PolicyMigrationRequired { .. } => ResolverStateName::PolicyMigrationRequired,
        ResolverState::ReplayRejected { .. } => ResolverStateName::ReplayRejected,
        ResolverState::Unknown { .. } => ResolverStateName::Unknown,
        ResolverState::NodeDown { .. } => ResolverStateName::NodeDown,
    }
}

fn validate_input_network(
    config: &DaemonConfig,
    input: &CreateWalletInput,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let expected_chain = config.network.chain_id().as_domain_str();
    if input.network_id != config.network.network_id()
        || input.protocol_network_id != config.network.protocol_network_id()
        || input.canonical_chain_domain != expected_chain
    {
        return Err(api_error(WalletdError::BadRequest(format!(
            "request network {}, {}, {} does not match daemon network {}, {}, {}",
            input.network_id,
            input.protocol_network_id,
            input.canonical_chain_domain,
            config.network.network_id(),
            config.network.protocol_network_id(),
            expected_chain
        ))));
    }
    Ok(())
}

fn validate_wallet_id(value: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let trimmed = value.trim();
    if trimmed.len() < 3 || trimmed.len() > 64 {
        return Err(api_error(WalletdError::BadRequest(
            "walletId must be 3-64 characters".to_string(),
        )));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(api_error(WalletdError::BadRequest(
            "walletId may contain only letters, numbers, dash, underscore, or dot".to_string(),
        )));
    }
    Ok(trimmed.to_string())
}

fn validate_passphrase(value: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    if value.len() < 8 || value.len() > 256 {
        return Err(api_error(WalletdError::BadRequest(
            "passphrase must contain 8-256 characters".to_string(),
        )));
    }
    Ok(value.to_string())
}

fn validate_recovery_phrase(words: &[String]) -> Result<(), (StatusCode, Json<ApiError>)> {
    if words.len() < 12 {
        return Err(api_error(WalletdError::BadRequest(
            "recoveryPhrase must contain at least 12 words".to_string(),
        )));
    }
    if words.iter().any(|word| word.trim().is_empty()) {
        return Err(api_error(WalletdError::BadRequest(
            "recoveryPhrase words must be non-empty".to_string(),
        )));
    }
    Ok(())
}

fn validate_optional_kaspa_endpoint(
    value: &str,
) -> Result<Option<String>, (StatusCode, Json<ApiError>)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 2048
        || trimmed.bytes().any(|byte| byte.is_ascii_whitespace())
        || !(trimmed.starts_with("ws://") || trimmed.starts_with("wss://"))
    {
        return Err(api_error(WalletdError::BadRequest(
            "kaspaEndpoint must be a ws:// or wss:// URL without whitespace".to_string(),
        )));
    }
    Ok(Some(trimmed.to_string()))
}

fn validate_lane_label(value: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let label = trimmed_or_default(value, "New RGK lane");
    if label.len() > 64 {
        return Err(api_error(WalletdError::BadRequest(
            "label must be 64 characters or fewer".to_string(),
        )));
    }
    Ok(label)
}

fn validate_ticker(value: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let ticker = trimmed_or_default(value, "RGK");
    if ticker.len() < 2
        || ticker.len() > 12
        || !ticker
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(api_error(WalletdError::BadRequest(
            "ticker must be 2-12 uppercase letters or digits".to_string(),
        )));
    }
    Ok(ticker)
}

fn validate_balance(value: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let balance = trimmed_or_default(value, "0.0000");
    if balance.len() > 40 || !valid_decimal(&balance, 8) {
        return Err(api_error(WalletdError::BadRequest(
            "balance must be a non-negative decimal with up to 8 fractional digits".to_string(),
        )));
    }
    Ok(balance)
}

fn validate_strategy(value: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let strategy = trimmed_or_default(value, "verifier-receipt-baseline");
    if strategy.len() > 80
        || !strategy
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(api_error(WalletdError::BadRequest(
            "strategy must be 80 characters or fewer and contain only letters, numbers, dash, underscore, dot, or colon".to_string(),
        )));
    }
    Ok(strategy)
}

fn validate_optional_txid(value: &str) -> Result<Option<String>, (StatusCode, Json<ApiError>)> {
    let Some(txid) = trimmed_optional(value) else {
        return Ok(None);
    };
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(api_error(WalletdError::BadRequest(
            "txid must be 64 hexadecimal characters".to_string(),
        )));
    }
    Ok(Some(txid.to_ascii_lowercase()))
}

fn valid_decimal(value: &str, max_fractional_digits: usize) -> bool {
    let mut parts = value.split('.');
    let Some(whole) = parts.next() else {
        return false;
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(fractional), None) => {
            !fractional.is_empty()
                && fractional.len() <= max_fractional_digits
                && fractional.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

fn ready_wallet_id(store: &PersistedState) -> Result<String, (StatusCode, Json<ApiError>)> {
    Ok(ready_profile(store)?.wallet_id.clone())
}

fn ready_profile(store: &PersistedState) -> Result<&WalletProfile, (StatusCode, Json<ApiError>)> {
    let profile = store
        .profile
        .as_ref()
        .ok_or_else(|| api_error(WalletdError::NotFound))?;
    if matches!(profile.lifecycle, WalletLifecycle::Locked) {
        return Err(api_error(WalletdError::Locked));
    }
    Ok(profile)
}

fn trimmed_or_default(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn trimmed_optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

const fn privacy_slug(value: PrivacyMode) -> &'static str {
    match value {
        PrivacyMode::PrivateLane => "private",
        PrivacyMode::PublicLineage => "public",
    }
}

impl AppState {
    fn store(&self) -> Result<MutexGuard<'_, PersistedState>, (StatusCode, Json<ApiError>)> {
        self.store
            .lock()
            .map_err(|_| api_error(WalletdError::PoisonedState))
    }
}

fn load_state(path: &PathBuf) -> Result<PersistedState, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(PersistedState::default());
    }
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn default_sync_db_path(state_path: &Path) -> PathBuf {
    let mut path = state_path.to_path_buf();
    path.set_extension("sled");
    path
}

fn save_state(path: &Path, state: &PersistedState) -> Result<(), (StatusCode, Json<ApiError>)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| api_error(WalletdError::Persist(error.to_string())))?;
    }
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| api_error(WalletdError::Persist(error.to_string())))?;
    write_private_state_file(path, &bytes)
        .map_err(|error| api_error(WalletdError::Persist(error.to_string())))
}

fn write_private_state_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp_path = temp_state_path(path);
    let result = write_private_state_file_inner(path, &temp_path, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn write_private_state_file_inner(
    path: &Path,
    temp_path: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(temp_path)?;
    #[cfg(unix)]
    restrict_state_file_permissions(temp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(temp_path, path)?;
    #[cfg(unix)]
    restrict_state_file_permissions(path)?;
    Ok(())
}

fn temp_state_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy())
        .unwrap_or_else(|| "state.json".into());
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_name = format!(".{file_name}.tmp-{}-{timestamp}", std::process::id());
    path.parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

#[cfg(unix)]
fn restrict_state_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn api_error(error: WalletdError) -> (StatusCode, Json<ApiError>) {
    let status = match error {
        WalletdError::NotFound => StatusCode::NOT_FOUND,
        WalletdError::Locked | WalletdError::Unauthorized => StatusCode::UNAUTHORIZED,
        WalletdError::BadRequest(_) => StatusCode::BAD_REQUEST,
        WalletdError::PoisonedState | WalletdError::Persist(_) | WalletdError::Entropy(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (
        status,
        Json(ApiError {
            message: error.to_string(),
        }),
    )
}

fn passphrase_verifier_with_salt(salt: &str, wallet_id: &str, passphrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rgk-walletd:passphrase:v1");
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(wallet_id.as_bytes());
    hasher.update(b":");
    hasher.update(passphrase.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn legacy_passphrase_verifier(wallet_id: &str, passphrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rgk-walletd:passphrase:v1");
    hasher.update(wallet_id.as_bytes());
    hasher.update(b":");
    hasher.update(passphrase.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn new_passphrase_salt() -> Result<String, WalletdError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| WalletdError::Entropy(error.to_string()))?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn hex_digest(domain: &str, value: &str, bytes: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!("0x{}", hex::encode(&digest[..bytes.min(digest.len())]))
}

fn parse_bytes32_handle(value: &str) -> Option<Bytes32> {
    let segment = value.rsplit(':').next()?.trim();
    let lower = segment.to_ascii_lowercase();
    let hex = lower.strip_prefix("0x").unwrap_or(&lower);
    from_hex::<32>(hex).ok()
}

fn parse_bytes32_required(value: &str, field: &str) -> Result<Bytes32, String> {
    parse_bytes32_handle(value).ok_or_else(|| {
        format!("{field} must be a 32-byte lowercase hexadecimal value, with optional 0x prefix")
    })
}

fn parse_hex_blob(value: &str, field: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    let hex = lower.strip_prefix("0x").unwrap_or(&lower);
    if hex.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if hex.len() % 2 != 0 {
        return Err(format!(
            "{field} must contain an even number of hex characters"
        ));
    }
    let bytes = hex::decode(hex).map_err(|error| format!("{field} is not valid hex: {error}"))?;
    if bytes.len() > MAX_BLOB_BYTES as usize {
        return Err(format!(
            "{field} is too large: {} bytes exceeds {}",
            bytes.len(),
            MAX_BLOB_BYTES
        ));
    }
    Ok(bytes)
}

fn hex32_label(value: &Bytes32) -> String {
    format!("0x{}", to_hex(value))
}

fn hex32_plain(value: &Bytes32) -> String {
    to_hex(value)
}

fn proof_mode_name(value: ProofMode) -> ProofModeName {
    match value {
        ProofMode::VerifierReceipt => ProofModeName::VerifierReceipt,
        ProofMode::ZkReceipt => ProofModeName::ZkReceipt,
        ProofMode::P2mrRet => ProofModeName::P2mrRet,
    }
}

fn receipt_policy_name(value: ReceiptPolicy) -> ReceiptPolicyName {
    match value {
        ReceiptPolicy::Any => ReceiptPolicyName::Any,
        ReceiptPolicy::VerifierOnly => ReceiptPolicyName::VerifierOnly,
        ReceiptPolicy::ZkOrVerifier => ReceiptPolicyName::ZkOrVerifier,
    }
}

fn receipt_policy(value: ReceiptPolicyName) -> ReceiptPolicy {
    match value {
        ReceiptPolicyName::Any => ReceiptPolicy::Any,
        ReceiptPolicyName::VerifierOnly => ReceiptPolicy::VerifierOnly,
        ReceiptPolicyName::ZkOrVerifier => ReceiptPolicy::ZkOrVerifier,
    }
}

fn now_label() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("unix:{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgk_core::{KaspaOutpoint, ReceiptPolicy, RgkStateCommitment, KASPA_LOCAL_TOCCATA};
    use rgk_indexer::InMemoryIndexer;
    use rgk_kaspa::{FixtureBackend, KaspaUtxo};
    use rgk_receipt::{ReceiptBuilder, ReceiptInput};

    fn sample_lane(lane_id: Bytes32, covenant_id: Bytes32) -> AssetLane {
        AssetLane {
            lineage_id: "rgk:lineage:test".to_string(),
            lane_id: format!("rgk:lane:public:{}", hex32_label(&lane_id)),
            label: "Test lane".to_string(),
            ticker: "RGK".to_string(),
            balance: "1.0000".to_string(),
            privacy: PrivacyMode::PublicLineage,
            proof_policy: ReceiptPolicyName::VerifierOnly,
            resolver_state: ResolverStateName::Unknown,
            covenant_id: hex32_label(&covenant_id),
            state_digest: hex32_label(&[0u8; 32]),
            latest_receipt_id: None,
            updated_at: "unix:0".to_string(),
        }
    }

    fn proof_input() -> RecordProofInput {
        RecordProofInput {
            lane_id: "rgk:lane:public:test".to_string(),
            proof_mode: ProofModeName::VerifierReceipt,
            receipt_policy: ReceiptPolicyName::VerifierOnly,
            strategy: "verifier-receipt-baseline".to_string(),
            txid: String::new(),
            confirmations: 0,
            receipt_bytes: String::new(),
            covenant_id: String::new(),
            spent_txid: String::new(),
            spent_index: 0,
            new_txid: String::new(),
            new_index: 0,
            continuation_shape_root: String::new(),
            daa_score: 0,
        }
    }

    fn lane_input() -> CreateLaneInput {
        CreateLaneInput {
            label: "Indexed RGK lane".to_string(),
            ticker: "RGK".to_string(),
            balance: "1.0000".to_string(),
            privacy: PrivacyMode::PublicLineage,
            proof_policy: ReceiptPolicyName::VerifierOnly,
            covenant_id: String::new(),
            lineage_id: String::new(),
            asset_id: String::new(),
            lane_id: String::new(),
            scan_tag: String::new(),
            state_digest: String::new(),
            open_txid: String::new(),
            open_index: 0,
            epoch: 0,
            daa_score: 0,
        }
    }

    fn indexed_lane_input() -> CreateLaneInput {
        let mut request = lane_input();
        request.covenant_id = hex32_label(&[0x61u8; 32]);
        request.lineage_id = hex32_label(&[0x62u8; 32]);
        request.asset_id = hex32_label(&[0x63u8; 32]);
        request.lane_id = hex32_label(&[0x64u8; 32]);
        request.scan_tag = hex32_label(&[0x65u8; 32]);
        request.state_digest = hex32_label(&[0x66u8; 32]);
        request.open_txid = hex32_plain(&[0x67u8; 32]);
        request.open_index = 2;
        request.epoch = 7;
        request.daa_score = 13;
        request
    }

    fn temp_path(prefix: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("{prefix}-{}-{timestamp}", std::process::id()))
    }

    #[test]
    fn parse_bytes32_handle_accepts_prefixed_lane_handles_only_at_full_width() {
        let lane_id = [0x11u8; 32];
        assert_eq!(
            parse_bytes32_handle(&format!("rgk:lane:private:{}", hex32_label(&lane_id))),
            Some(lane_id)
        );
        assert_eq!(parse_bytes32_handle(&hex32_label(&lane_id)), Some(lane_id));
        assert_eq!(
            parse_bytes32_handle(&format!("rgk:lane:private:0X{}", to_hex(&lane_id))),
            Some(lane_id)
        );
        assert_eq!(parse_bytes32_handle("rgk:lane:private:0x1111"), None);
        assert_eq!(parse_bytes32_handle("rgk:lane:private:not-hex"), None);
    }

    #[test]
    fn parse_lane_evidence_accepts_metadata_only_lane() {
        assert_eq!(
            parse_lane_evidence(KASPA_LOCAL_TOCCATA, &lane_input()).expect("parse"),
            None
        );
    }

    #[test]
    fn parse_lane_evidence_rejects_partial_bundle() {
        let mut request = lane_input();
        request.covenant_id = hex32_label(&[0x61u8; 32]);

        let err = parse_lane_evidence(KASPA_LOCAL_TOCCATA, &request)
            .expect_err("partial lane evidence must fail");

        assert!(err.contains("lineageId is required"));
    }

    #[test]
    fn parse_lane_evidence_rejects_zero_scan_tag_before_indexing() {
        let mut request = indexed_lane_input();
        request.scan_tag = hex32_label(&[0u8; 32]);

        let err = parse_lane_evidence(KASPA_LOCAL_TOCCATA, &request)
            .expect_err("zero scan tag must fail before indexing");

        assert!(err.contains("scanTag must not be zero"));
    }

    #[test]
    fn validate_lane_profile_uniqueness_rejects_existing_lane_or_covenant() {
        let request = indexed_lane_input();
        let evidence = parse_lane_evidence(KASPA_LOCAL_TOCCATA, &request)
            .expect("parse")
            .expect("evidence");
        let store = PersistedState {
            lanes: vec![sample_lane(evidence.lane_id, evidence.covenant_id)],
            ..PersistedState::default()
        };

        let err = validate_lane_profile_uniqueness(&store, &evidence)
            .expect_err("duplicate lane evidence must fail");

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn index_lane_evidence_persists_covenant_and_lane_after_reopen() {
        let path = temp_path("rgk-walletd-lane-index");
        let _ = std::fs::remove_dir_all(&path);
        let request = indexed_lane_input();
        let evidence = parse_lane_evidence(KASPA_LOCAL_TOCCATA, &request)
            .expect("parse")
            .expect("evidence");

        let indexed = index_lane_evidence_at_path(&path, KASPA_LOCAL_TOCCATA, evidence.clone())
            .expect("index lane")
            .expect("indexed evidence");

        assert_eq!(indexed.asset_id, [0x63u8; 32]);
        let indexer = SledIndexer::open_path(&path).expect("reopen indexer");
        assert_eq!(
            indexer.latest_state(evidence.covenant_id),
            Some(evidence.state.clone())
        );
        assert_eq!(
            indexer.open_outpoint(evidence.covenant_id),
            Some(evidence.open_outpoint)
        );
        assert_eq!(
            indexer.lane_by_id(&evidence.lane_id),
            Some(evidence.lane.clone())
        );
        assert_eq!(
            indexer.lane_by_scan_tag(&[0x65u8; 32]),
            Some(evidence.lane.clone())
        );
        assert_eq!(
            indexer.public_lanes(&evidence.asset_id),
            vec![evidence.lane.clone()]
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn resolve_indexed_lanes_refreshes_open_lane_from_indexer_and_backend() {
        let covenant_id = [0x21u8; 32];
        let asset_id = [0x22u8; 32];
        let lane_id = [0x23u8; 32];
        let state_digest = [0x24u8; 32];
        let open_outpoint = KaspaOutpoint {
            transaction_id: [0x25u8; 32],
            index: 0,
        };
        let state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            asset_id,
            state_digest,
            ReceiptPolicy::VerifierOnly,
        )
        .expect("state");
        let mut indexer = InMemoryIndexer::new();
        indexer
            .open(
                KASPA_LOCAL_TOCCATA,
                covenant_id,
                [0x26u8; 32],
                state,
                open_outpoint,
                10,
            )
            .expect("open covenant");
        indexer
            .register_lane(IndexedLane::new(
                KASPA_LOCAL_TOCCATA,
                covenant_id,
                asset_id,
                lane_id,
                0,
                None,
                true,
                state_digest,
                10,
            ))
            .expect("register lane");

        let mut backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        backend.add_utxo_at(
            10,
            KaspaUtxo::new(open_outpoint, 1, Vec::new(), Some(10), None).expect("utxo"),
        );

        let updates = resolve_indexed_lanes(
            &backend,
            &indexer,
            KASPA_LOCAL_TOCCATA,
            &[sample_lane(lane_id, covenant_id)],
        );

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].resolver_state, ResolverStateName::Open);
        assert_eq!(updates[0].covenant_id, Some(hex32_label(&covenant_id)));
        assert_eq!(updates[0].state_digest, Some(hex32_label(&state_digest)));
        assert_eq!(updates[0].latest_receipt_id, None);
    }

    #[test]
    fn resolve_indexed_lanes_keeps_short_legacy_handles_unknown() {
        let lane = AssetLane {
            lane_id: "rgk:lane:public:0x1234".to_string(),
            covenant_id: "0xabcd".to_string(),
            ..sample_lane([0x31u8; 32], [0x32u8; 32])
        };
        let backend = FixtureBackend::new(KASPA_LOCAL_TOCCATA);
        let indexer = InMemoryIndexer::new();

        let updates = resolve_indexed_lanes(&backend, &indexer, KASPA_LOCAL_TOCCATA, &[lane]);

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].resolver_state, ResolverStateName::Unknown);
        assert_eq!(updates[0].covenant_id, None);
        assert_eq!(updates[0].state_digest, None);
        assert_eq!(updates[0].latest_receipt_id, None);
    }

    #[test]
    fn ingest_proof_evidence_indexes_verified_receipt_spend() {
        let path = temp_path("rgk-walletd-proof-ingest");
        let _ = std::fs::remove_dir_all(&path);
        let covenant_id = [0x41u8; 32];
        let asset_id = [0x42u8; 32];
        let old_state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            asset_id,
            [0x43u8; 32],
            ReceiptPolicy::VerifierOnly,
        )
        .expect("old state");
        let new_state = RgkStateCommitment::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            asset_id,
            [0x44u8; 32],
            ReceiptPolicy::VerifierOnly,
        )
        .expect("new state");
        let spent = KaspaOutpoint {
            transaction_id: [0x45u8; 32],
            index: 1,
        };
        let created = KaspaOutpoint {
            transaction_id: [0x46u8; 32],
            index: 0,
        };
        let transition_digest = [0x47u8; 32];
        let continuation_commitment = [0x48u8; 32];
        let shape_root = [0x49u8; 32];
        let input = ReceiptInput::new(
            KASPA_LOCAL_TOCCATA,
            covenant_id,
            old_state.clone(),
            new_state.clone(),
            transition_digest,
            continuation_commitment,
            ProofMode::VerifierReceipt,
            [0x4au8; 32],
        )
        .expect("receipt input");
        let (_receipt, receipt_id, receipt_bytes) = ReceiptBuilder::build(&input).expect("receipt");

        {
            let mut indexer = SledIndexer::open_path(&path).expect("open indexer");
            indexer
                .open(
                    KASPA_LOCAL_TOCCATA,
                    covenant_id,
                    [0x4bu8; 32],
                    old_state,
                    spent,
                    10,
                )
                .expect("open covenant");
            indexer.flush().expect("flush");
        }

        let mut request = proof_input();
        request.receipt_bytes = format!("0x{}", hex::encode(receipt_bytes));
        request.covenant_id = hex32_label(&covenant_id);
        request.spent_txid = hex32_plain(&spent.transaction_id);
        request.spent_index = spent.index;
        request.new_txid = hex32_plain(&created.transaction_id);
        request.new_index = created.index;
        request.txid = hex32_plain(&created.transaction_id);
        request.continuation_shape_root = hex32_label(&shape_root);
        request.daa_score = 11;

        let evidence = ingest_proof_evidence_at_path(&path, KASPA_LOCAL_TOCCATA, &request)
            .expect("ingest")
            .expect("verified evidence");

        assert_eq!(evidence.receipt_id, receipt_id);
        assert_eq!(evidence.proof_mode, ProofModeName::VerifierReceipt);
        assert_eq!(evidence.receipt_policy, ReceiptPolicyName::VerifierOnly);
        assert_eq!(evidence.new_outpoint, created);
        assert_eq!(evidence.new_state_digest, [0x44u8; 32]);

        let indexer = SledIndexer::open_path(&path).expect("reopen indexer");
        assert_eq!(indexer.latest_state(covenant_id), Some(new_state));
        let entry = indexer.lookup(covenant_id).expect("indexed covenant");
        assert_eq!(entry.spend_history.len(), 1);
        let spend = &entry.spend_history[0];
        assert_eq!(spend.receipt_id, receipt_id);
        assert_eq!(spend.spent, spent);
        assert_eq!(spend.created, created);
        assert_eq!(
            spend.continuation,
            Some(ContinuationProof {
                commitment: continuation_commitment,
                shape_root,
                transition_digest,
            })
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn ingest_proof_evidence_rejects_partial_bundle() {
        let mut request = proof_input();
        request.receipt_bytes = "abcd".to_string();

        let err = ingest_proof_evidence_at_path(
            Path::new("/tmp/unused-rgk-walletd-proof"),
            KASPA_LOCAL_TOCCATA,
            &request,
        )
        .expect_err("partial proof evidence must fail");

        assert!(err.contains("covenantId is required"));
    }

    #[test]
    fn validate_proof_lane_binding_rejects_cross_lane_covenant() {
        let mut request = proof_input();
        request.receipt_bytes = "abcd".to_string();
        request.covenant_id = hex32_label(&[0x51u8; 32]);

        let err = validate_proof_lane_binding(&request, &hex32_label(&[0x52u8; 32]))
            .expect_err("cross-lane proof binding must fail");

        assert!(err.contains("covenantId must match the selected lane"));
    }
}
