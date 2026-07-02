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
use rgk_core::KaspaChainId;
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

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PrivacyMode {
    PrivateLane,
    PublicLineage,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ReceiptPolicyName {
    Any,
    VerifierOnly,
    ZkOrVerifier,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProofModeName {
    VerifierReceipt,
    ZkReceipt,
    P2mrRet,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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
    Connected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
struct UnlockWalletInput {
    passphrase: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateLaneInput {
    label: String,
    ticker: String,
    balance: String,
    privacy: PrivacyMode,
    proof_policy: ReceiptPolicyName,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordProofInput {
    lane_id: String,
    proof_mode: ProofModeName,
    receipt_policy: ReceiptPolicyName,
    strategy: String,
    txid: String,
    confirmations: u64,
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
    dashboard(State(state)).await
}

async fn dashboard(State(state): State<AppState>) -> ApiResult<DashboardSnapshot> {
    let store = state.store()?;
    let profile = store
        .profile
        .clone()
        .ok_or_else(|| api_error(WalletdError::NotFound))?;
    if matches!(profile.lifecycle, WalletLifecycle::Locked) {
        return Err(api_error(WalletdError::Locked));
    }
    Ok(Json(DashboardSnapshot {
        profile,
        kas_balance: store.kas_balance.clone(),
        lanes: store.lanes.clone(),
        proofs: store.proofs.clone(),
        scan: store.scan.clone(),
        service_mode: ServiceMode::Connected,
        service_notice: "Connected to the local RGK wallet daemon.".to_string(),
    }))
}

async fn create_lane(
    State(state): State<AppState>,
    Json(input): Json<CreateLaneInput>,
) -> ApiResult<AssetLane> {
    let mut store = state.store()?;
    let wallet_id = ready_wallet_id(&store)?;
    let label = trimmed_or_default(&input.label, "New RGK lane");
    let ticker = trimmed_or_default(&input.ticker, "RGK");
    let balance = trimmed_or_default(&input.balance, "0.0000");
    let seed = format!("{}:{}:{}:{}", wallet_id, label, ticker, store.lanes.len());
    let updated_at = now_label();
    let lane = AssetLane {
        lineage_id: format!("rgk:lineage:{}", hex_digest("lineage", &seed, 8)),
        lane_id: format!(
            "rgk:lane:{}:{}",
            privacy_slug(input.privacy),
            hex_digest("lane", &seed, 8)
        ),
        label,
        ticker,
        balance,
        privacy: input.privacy,
        proof_policy: input.proof_policy,
        resolver_state: if state.config.network.chain_id().toccata_active_by_default() {
            ResolverStateName::Open
        } else {
            ResolverStateName::NodeDown
        },
        covenant_id: hex_digest("covenant", &seed, 16),
        state_digest: hex_digest("state", &seed, 16),
        latest_receipt_id: None,
        updated_at,
    };
    store.lanes.push(lane.clone());
    save_state(&state.config.state_path, &store)?;
    Ok(Json(lane))
}

async fn record_proof(
    State(state): State<AppState>,
    Json(input): Json<RecordProofInput>,
) -> ApiResult<ProofSummary> {
    let mut store = state.store()?;
    let wallet_id = ready_wallet_id(&store)?;
    let strategy = trimmed_or_default(&input.strategy, "verifier-receipt-baseline");
    let seed = format!("{}:{}:{}", wallet_id, strategy, store.proofs.len());
    let txid = trimmed_optional(&input.txid);
    let updated_at = now_label();
    let proof = ProofSummary {
        receipt_id: format!("rgk:receipt:{}", hex_digest("receipt", &seed, 8)),
        proof_mode: input.proof_mode,
        receipt_policy: input.receipt_policy,
        strategy,
        verifier_status: ProofVerifierStatus::Pending,
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
    lane.updated_at = updated_at;

    store.proofs.push(proof.clone());
    store.scan.scan_mode = ScanMode::Idle;
    store.scan.indexed_spends = store.scan.indexed_spends.saturating_add(1);
    store.scan.observed_spends = store.scan.observed_spends.saturating_add(1);
    store.scan.last_daa_score = Some(
        store
            .scan
            .last_daa_score
            .unwrap_or_default()
            .saturating_add(1),
    );
    save_state(&state.config.state_path, &store)?;
    Ok(Json(proof))
}

async fn upsert_wallet(state: AppState, input: CreateWalletInput) -> ApiResult<WalletProfile> {
    validate_input_network(&state.config, &input)?;
    if input.recovery_phrase.len() < 12 {
        return Err(api_error(WalletdError::BadRequest(
            "recoveryPhrase must contain at least 12 words".to_string(),
        )));
    }
    if input.passphrase.len() < 8 {
        return Err(api_error(WalletdError::BadRequest(
            "passphrase must contain at least 8 characters".to_string(),
        )));
    }

    let mut store = state.store()?;
    let profile = WalletProfile {
        wallet_id: input.wallet_id.clone(),
        protocol: "rgk".to_string(),
        network_id: state.config.network.network_id().to_string(),
        protocol_network_id: state.config.network.protocol_network_id().to_string(),
        canonical_chain_domain: state.config.network.chain_id().as_domain_str().to_string(),
        kaspa_endpoint: if input.kaspa_endpoint.trim().is_empty() {
            state.config.kaspa_endpoint.clone()
        } else {
            input.kaspa_endpoint
        },
        wallet_set_id: Some(hex_digest("wallet-set", &input.wallet_id, 32)),
        address: Some(format!(
            "{}:qavato{}",
            state.config.network.address_prefix(),
            &hex_digest("address", &input.wallet_id, 12)[2..],
        )),
        lifecycle: WalletLifecycle::Ready,
    };
    let passphrase_salt = new_passphrase_salt().map_err(api_error)?;
    store.passphrase_verifier = Some(passphrase_verifier_with_salt(
        &passphrase_salt,
        &profile.wallet_id,
        &input.passphrase,
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
    store.profile = Some(profile.clone());
    save_state(&state.config.state_path, &store)?;
    Ok(Json(profile))
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

fn ready_wallet_id(store: &PersistedState) -> Result<String, (StatusCode, Json<ApiError>)> {
    let profile = store
        .profile
        .as_ref()
        .ok_or_else(|| api_error(WalletdError::NotFound))?;
    if matches!(profile.lifecycle, WalletLifecycle::Locked) {
        return Err(api_error(WalletdError::Locked));
    }
    Ok(profile.wallet_id.clone())
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

fn now_label() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("unix:{seconds}")
}
