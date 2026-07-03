#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use clap::{Parser, ValueEnum};
use kaspa_addresses::{Address, Prefix as KaspaAddressPrefix, Version as KaspaAddressVersion};
use rgk_core::{
    from_hex, receipt_commitment, replay_nonce, to_hex, Bytes32, Canonical, KaspaChainId,
    KaspaOutpoint, ProofMode, ReceiptPolicy, RgkReceipt, RgkStateCommitment, MAX_BLOB_BYTES,
};
use rgk_indexer::{ContinuationProof, IndexedLane, Indexer, ObservedSpendStore, SledIndexer};
use rgk_kaspa::{KaspaChainBackend, KaspaWalletBackend, WrpcBackend, WrpcNetwork};
use rgk_receipt::{ReceiptBuilder, ReceiptInput, ReceiptVerifier};
use rgk_resolver::{LaneResolverState, ResolverState, RgkResolver};
use rgk_sync::{ScanService, ScanServiceConfig, ScanTick};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use zeroize::{Zeroize, Zeroizing};

const IDENTITY_VAULT_VERSION: u16 = 1;
const IDENTITY_VAULT_KDF_ALGORITHM: &str = "argon2id";
const IDENTITY_VAULT_CIPHER: &str = "xchacha20poly1305";
const IDENTITY_VAULT_KDF_MEMORY_KIB: u32 = 19 * 1024;
const IDENTITY_VAULT_KDF_ITERATIONS: u32 = 2;
const IDENTITY_VAULT_KDF_PARALLELISM: u32 = 1;
const IDENTITY_VAULT_SALT_BYTES: usize = 16;
const IDENTITY_VAULT_NONCE_BYTES: usize = 24;

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

    const fn default_kaspa_endpoint(self) -> Option<&'static str> {
        match self {
            Self::Mainnet | Self::Testnet10 | Self::Testnet12 => None,
            Self::Devnet => Some("ws://127.0.0.1:19111/v2/kaspa/devnet/no-tls/wrpc/borsh"),
            Self::Simnet | Self::LocalToccata => {
                Some("ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh")
            }
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

    const fn address_prefix(self) -> KaspaAddressPrefix {
        match self {
            Self::Mainnet => KaspaAddressPrefix::Mainnet,
            Self::Testnet10 | Self::Testnet12 => KaspaAddressPrefix::Testnet,
            Self::Devnet => KaspaAddressPrefix::Devnet,
            Self::Simnet | Self::LocalToccata => KaspaAddressPrefix::Simnet,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<DaemonConfig>,
    store: Arc<Mutex<PersistedState>>,
    identity_session: Arc<Mutex<RuntimeIdentitySession>>,
}

#[derive(Debug)]
struct DaemonConfig {
    network: CliNetwork,
    kaspa_endpoint: Option<String>,
    state_path: PathBuf,
    sync_db_path: PathBuf,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedState {
    profile: Option<WalletProfile>,
    passphrase_salt: Option<String>,
    passphrase_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_vault: Option<IdentityVault>,
    kas_balance: String,
    lanes: Vec<AssetLane>,
    proofs: Vec<ProofSummary>,
    scan: ScanStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_notice: Option<String>,
}

#[derive(Default)]
struct RuntimeIdentitySession {
    wallet_id: Option<String>,
    identity_fingerprint: Option<String>,
    identity_secret: Option<Zeroizing<Vec<u8>>>,
}

impl RuntimeIdentitySession {
    fn unlock(&mut self, wallet_id: String, identity: UnlockedIdentity) {
        self.wallet_id = Some(wallet_id);
        self.identity_fingerprint = Some(identity.identity_fingerprint);
        self.identity_secret = Some(identity.identity_secret);
    }

    fn clear(&mut self) {
        self.wallet_id = None;
        self.identity_fingerprint = None;
        self.identity_secret = None;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityVault {
    version: u16,
    cipher: String,
    kdf: IdentityVaultKdf,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityVaultKdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Clone, Debug)]
struct IdentityVaultContext {
    wallet_id: String,
    network_id: String,
    protocol_network_id: String,
    canonical_chain_domain: String,
}

struct WalletIdentityMaterial {
    passphrase_salt: String,
    passphrase_verifier: String,
    vault: IdentityVault,
    identity_fingerprint: String,
    identity_secret: Zeroizing<Vec<u8>>,
}

struct UnlockedIdentity {
    identity_fingerprint: String,
    identity_secret: Zeroizing<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityVaultPlaintext {
    version: u16,
    wallet_id: String,
    network_id: String,
    protocol_network_id: String,
    canonical_chain_domain: String,
    recovery_phrase: Vec<String>,
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
    #[serde(default)]
    identity_vault_status: IdentityVaultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_fingerprint: Option<String>,
    lifecycle: WalletLifecycle,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum IdentityVaultStatus {
    #[default]
    Missing,
    Encrypted,
    Unlocked,
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
    #[serde(default)]
    evidence_status: LaneEvidenceStatus,
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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum LaneEvidenceStatus {
    #[default]
    MetadataOnly,
    Indexed,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transition_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_shape_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_state_digest: Option<String>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateKaspaEndpointInput {
    kaspa_endpoint: String,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordTransitionInput {
    lane_id: String,
    proof_mode: ProofModeName,
    receipt_policy: ReceiptPolicyName,
    strategy: String,
    new_state_digest: String,
    transition_digest: String,
    continuation_commitment: String,
    continuation_shape_root: String,
    new_txid: String,
    new_index: u32,
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
    /// Stable, machine-readable snake_case identifier. Clients MUST branch on
    /// this rather than `message` (which is human-readable and may change).
    /// Of special note: `wallet_locked` and `unauthorized` share HTTP 401 but
    /// carry distinct codes, so a locked wallet can be told apart from a wrong
    /// passphrase without parsing the message.
    code: String,
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
    #[error("identity session lock is poisoned")]
    PoisonedIdentitySession,
    #[error("state persistence failed: {0}")]
    Persist(String),
    #[error("identity vault operation failed: {0}")]
    Crypto(String),
    #[error("failed to read local entropy: {0}")]
    Entropy(String),
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = Arc::new(DaemonConfig {
        network: cli.network,
        kaspa_endpoint: cli.kaspa_endpoint.or_else(|| {
            cli.network
                .default_kaspa_endpoint()
                .map(ToString::to_string)
        }),
        sync_db_path: cli
            .sync_db
            .unwrap_or_else(|| default_sync_db_path(&cli.state)),
        state_path: cli.state,
    });
    let mut loaded_state = load_state(&config.state_path)?;
    if isolate_state_for_network(&mut loaded_state, config.network) {
        eprintln!(
            "rgk-walletd: ignoring wallet state from a different network at {}",
            config.state_path.display()
        );
    }
    let store = Arc::new(Mutex::new(loaded_state));
    let app_state = AppState {
        config,
        store,
        identity_session: Arc::new(Mutex::new(RuntimeIdentitySession::default())),
    };
    let app = build_router(app_state);

    let listener = TcpListener::bind(cli.listen).await?;
    eprintln!("rgk-walletd: listening on http://{}", cli.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Builds the walletd axum router. Extracted from `main` so the HTTP-layer
/// tests can drive the real request → handler → `ApiError` → wire-shape
/// pipeline (status code + serialised `code` field) without spawning a socket.
fn build_router(app_state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/wallet/profile", get(profile))
        .route("/wallets", post(create_wallet))
        .route("/wallet/import", post(import_wallet))
        .route("/wallet/lock", post(lock_wallet))
        .route("/wallet/unlock", post(unlock_wallet))
        .route("/wallet/kaspa-endpoint", post(update_kaspa_endpoint))
        .route("/wallet/sync", post(sync_wallet))
        .route("/dashboard", get(dashboard))
        .route("/lanes", post(create_lane))
        .route("/proofs", post(record_proof))
        .route("/transitions", post(record_transition))
        .layer(CorsLayer::permissive())
        .with_state(app_state)
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

async fn update_kaspa_endpoint(
    State(state): State<AppState>,
    Json(input): Json<UpdateKaspaEndpointInput>,
) -> ApiResult<WalletProfile> {
    let kaspa_endpoint = select_kaspa_endpoint(&state.config, &input.kaspa_endpoint)?;
    let mut store = state.store()?;
    let Some(profile) = store.profile.as_mut() else {
        return Err(api_error(WalletdError::NotFound));
    };
    if matches!(profile.lifecycle, WalletLifecycle::Locked) {
        return Err(api_error(WalletdError::Locked));
    }
    profile.kaspa_endpoint = kaspa_endpoint;
    profile.lifecycle = WalletLifecycle::Ready;
    let profile = profile.clone();
    store.scan.scan_mode = ScanMode::Idle;
    store.scan_notice = Some(
        "Kaspa wRPC endpoint updated. Sync the wallet to verify the new endpoint.".to_string(),
    );
    save_state(&state.config.state_path, &store)?;
    Ok(Json(profile))
}

async fn lock_wallet(
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let mut store = state.store()?;
    let identity_vault_status = stored_identity_vault_status(store.identity_vault.is_some());
    let Some(profile) = store.profile.as_mut() else {
        return Err(api_error(WalletdError::NotFound));
    };
    profile.lifecycle = WalletLifecycle::Locked;
    profile.identity_vault_status = identity_vault_status;
    let mut identity_session = state.identity_session()?;
    identity_session.clear();
    save_state(&state.config.state_path, &store)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unlock_wallet(
    State(state): State<AppState>,
    Json(input): Json<UnlockWalletInput>,
) -> ApiResult<WalletProfile> {
    let passphrase = Zeroizing::new(validate_passphrase(&input.passphrase)?);
    let (profile_snapshot, vault) = {
        let store = state.store()?;
        let profile = store
            .profile
            .clone()
            .ok_or_else(|| api_error(WalletdError::NotFound))?;
        let vault = store.identity_vault.clone().ok_or_else(|| {
            api_error(WalletdError::BadRequest(
                "identity vault is missing; re-import this RGK wallet".to_string(),
            ))
        })?;
        (profile, vault)
    };

    let unlocked_identity = tokio::task::spawn_blocking(move || {
        decrypt_identity_vault(&profile_snapshot, &vault, &passphrase)
    })
    .await
    .map_err(|error| {
        api_error(WalletdError::Crypto(format!(
            "identity worker did not complete: {error}"
        )))
    })?
    .map_err(api_error)?;

    let address = derive_wallet_address(state.config.network, &unlocked_identity.identity_secret)
        .map_err(api_error)?;
    let identity_fingerprint = unlocked_identity.identity_fingerprint.clone();
    let mut store = state.store()?;
    let Some(profile) = store.profile.as_mut() else {
        return Err(api_error(WalletdError::NotFound));
    };
    profile.lifecycle = WalletLifecycle::Ready;
    profile.identity_vault_status = IdentityVaultStatus::Unlocked;
    profile.identity_fingerprint = Some(identity_fingerprint);
    profile.address = Some(address);
    let mut identity_session = state.identity_session()?;
    identity_session.unlock(profile.wallet_id.clone(), unlocked_identity);
    let profile = profile.clone();
    save_state(&state.config.state_path, &store)?;
    Ok(Json(profile))
}

async fn sync_wallet(State(state): State<AppState>) -> ApiResult<DashboardSnapshot> {
    let (kaspa_endpoint, lanes, address) = {
        let store = state.store()?;
        let profile = ready_profile(&store)?;
        if matches!(profile.lifecycle, WalletLifecycle::Locked) {
            return Err(api_error(WalletdError::Locked));
        }
        (
            profile.kaspa_endpoint.clone(),
            store.lanes.clone(),
            profile.address.clone(),
        )
    };

    let scan_result =
        run_scan_tick(Arc::clone(&state.config), kaspa_endpoint, lanes, address).await;

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
        evidence_status: if indexed.is_some() {
            LaneEvidenceStatus::Indexed
        } else {
            LaneEvidenceStatus::MetadataOnly
        },
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
        receipt_bytes: verified
            .as_ref()
            .map(|evidence| evidence.receipt_bytes.clone()),
        transition_digest: verified
            .as_ref()
            .map(|evidence| hex32_label(&evidence.transition_digest)),
        continuation_commitment: verified
            .as_ref()
            .map(|evidence| hex32_label(&evidence.continuation_commitment)),
        continuation_shape_root: verified
            .as_ref()
            .map(|evidence| hex32_label(&evidence.continuation_shape_root)),
        new_state_digest: verified
            .as_ref()
            .map(|evidence| hex32_label(&evidence.new_state_digest)),
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

async fn record_transition(
    State(state): State<AppState>,
    Json(input): Json<RecordTransitionInput>,
) -> ApiResult<ProofSummary> {
    let selected_lane_covenant_id = {
        let store = state.store()?;
        ready_wallet_id(&store)?;
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
        lane.covenant_id.clone()
    };
    let strategy = validate_strategy(&input.strategy)?;
    let evidence = build_transition_receipt(
        Arc::clone(&state.config),
        input.clone(),
        selected_lane_covenant_id,
    )
    .await
    .map_err(|message| api_error(WalletdError::BadRequest(message)))?;

    let mut store = state.store()?;
    let updated_at = now_label();
    let proof = ProofSummary {
        receipt_id: format!("rgk:receipt:{}", hex32_label(&evidence.receipt_id)),
        proof_mode: evidence.proof_mode,
        receipt_policy: evidence.receipt_policy,
        strategy,
        verifier_status: ProofVerifierStatus::Verified,
        txid: Some(hex32_plain(&evidence.new_outpoint.transaction_id)),
        confirmations: 0,
        receipt_bytes: Some(evidence.receipt_bytes.clone()),
        transition_digest: Some(hex32_label(&evidence.transition_digest)),
        continuation_commitment: Some(hex32_label(&evidence.continuation_commitment)),
        continuation_shape_root: Some(hex32_label(&evidence.continuation_shape_root)),
        new_state_digest: Some(hex32_label(&evidence.new_state_digest)),
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
    lane.state_digest = hex32_label(&evidence.new_state_digest);
    lane.updated_at = updated_at;

    store.proofs.push(proof.clone());
    save_state(&state.config.state_path, &store)?;
    Ok(Json(proof))
}

async fn upsert_wallet(state: AppState, input: CreateWalletInput) -> ApiResult<WalletProfile> {
    validate_input_network(&state.config, &input)?;
    let wallet_id = validate_wallet_id(&input.wallet_id)?;
    let recovery_phrase = validate_recovery_phrase(&input.recovery_phrase)?;
    let passphrase = Zeroizing::new(validate_passphrase(&input.passphrase)?);
    let kaspa_endpoint = select_kaspa_endpoint(&state.config, &input.kaspa_endpoint)?;
    let identity_context = IdentityVaultContext {
        wallet_id: wallet_id.clone(),
        network_id: state.config.network.network_id().to_string(),
        protocol_network_id: state.config.network.protocol_network_id().to_string(),
        canonical_chain_domain: state.config.network.chain_id().as_domain_str().to_string(),
    };
    let identity_material = tokio::task::spawn_blocking(move || {
        build_wallet_identity_material(identity_context, recovery_phrase, passphrase)
    })
    .await
    .map_err(|error| {
        api_error(WalletdError::Crypto(format!(
            "identity worker did not complete: {error}"
        )))
    })?
    .map_err(api_error)?;

    let address = derive_wallet_address(state.config.network, &identity_material.identity_secret)
        .map_err(api_error)?;
    let mut store = state.store()?;
    let profile = WalletProfile {
        wallet_id: wallet_id.clone(),
        protocol: "rgk".to_string(),
        network_id: state.config.network.network_id().to_string(),
        protocol_network_id: state.config.network.protocol_network_id().to_string(),
        canonical_chain_domain: state.config.network.chain_id().as_domain_str().to_string(),
        kaspa_endpoint,
        wallet_set_id: Some(hex_digest(
            "wallet-set",
            &format!(
                "{}:{}",
                state.config.network.chain_id().as_domain_str(),
                identity_material.identity_fingerprint
            ),
            32,
        )),
        address: Some(address),
        identity_vault_status: IdentityVaultStatus::Unlocked,
        identity_fingerprint: Some(identity_material.identity_fingerprint.clone()),
        lifecycle: WalletLifecycle::Ready,
    };
    store.passphrase_verifier = Some(identity_material.passphrase_verifier.clone());
    store.passphrase_salt = Some(identity_material.passphrase_salt.clone());
    store.identity_vault = Some(identity_material.vault.clone());
    store.kas_balance = format_kas_balance(0);
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
    let mut identity_session = state.identity_session()?;
    identity_session.unlock(
        profile.wallet_id.clone(),
        UnlockedIdentity {
            identity_fingerprint: identity_material.identity_fingerprint,
            identity_secret: identity_material.identity_secret,
        },
    );
    save_state(&state.config.state_path, &store)?;
    Ok(Json(profile))
}

struct WalletdScanResult {
    tick: ScanTick,
    indexed_spends: usize,
    lane_updates: Vec<LaneResolutionUpdate>,
    kas_balance_sompi: Option<u64>,
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
    receipt_bytes: String,
    transition_digest: Bytes32,
    continuation_commitment: Bytes32,
    continuation_shape_root: Bytes32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransitionReceiptEvidence {
    receipt_id: Bytes32,
    proof_mode: ProofModeName,
    receipt_policy: ReceiptPolicyName,
    new_outpoint: KaspaOutpoint,
    new_state_digest: Bytes32,
    receipt_bytes: String,
    transition_digest: Bytes32,
    continuation_commitment: Bytes32,
    continuation_shape_root: Bytes32,
}

async fn run_scan_tick(
    config: Arc<DaemonConfig>,
    kaspa_endpoint: String,
    lanes: Vec<AssetLane>,
    address: Option<String>,
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
        let kas_balance_sompi = match address.as_deref().map(str::trim) {
            Some(address) if !address.is_empty() => {
                Some(backend.balance_by_address(address).map_err(|error| {
                    format!("failed to refresh funding-address balance: {error}")
                })?)
            }
            _ => None,
        };
        Ok(WalletdScanResult {
            tick,
            indexed_spends,
            lane_updates,
            kas_balance_sompi,
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
        receipt_bytes: format!("0x{}", hex::encode(receipt_bytes)),
        transition_digest: receipt.transition_digest,
        continuation_commitment: receipt.continuation_commitment,
        continuation_shape_root: shape_root,
    }))
}

async fn build_transition_receipt(
    config: Arc<DaemonConfig>,
    input: RecordTransitionInput,
    selected_lane_covenant_id: String,
) -> Result<TransitionReceiptEvidence, String> {
    let sync_db_path = config.sync_db_path.clone();
    let chain_id = config.network.chain_id();
    tokio::task::spawn_blocking(move || {
        build_transition_receipt_at_path(
            &sync_db_path,
            chain_id,
            &input,
            &selected_lane_covenant_id,
        )
    })
    .await
    .map_err(|error| format!("transition receipt task failed: {error}"))?
}

fn build_transition_receipt_at_path(
    sync_db_path: &Path,
    chain_id: KaspaChainId,
    input: &RecordTransitionInput,
    selected_lane_covenant_id: &str,
) -> Result<TransitionReceiptEvidence, String> {
    let lane_id = parse_bytes32_required(&input.lane_id, "laneId")?;
    let covenant_id =
        parse_bytes32_required(selected_lane_covenant_id, "selected lane covenantId")?;
    let new_state_digest = parse_bytes32_required(&input.new_state_digest, "newStateDigest")?;
    let transition_digest = parse_bytes32_required(&input.transition_digest, "transitionDigest")?;
    let continuation_commitment =
        parse_bytes32_required(&input.continuation_commitment, "continuationCommitment")?;
    let continuation_shape_root =
        parse_bytes32_required(&input.continuation_shape_root, "continuationShapeRoot")?;
    let new_outpoint = KaspaOutpoint {
        transaction_id: parse_bytes32_required(&input.new_txid, "newTxid")?,
        index: input.new_index,
    };

    let mut indexer = SledIndexer::open_path(sync_db_path)
        .map_err(|error| format!("failed to open scanner database: {error}"))?;
    let indexed_lane = indexer
        .lane_by_id(&lane_id)
        .ok_or_else(|| "laneId is not indexed in the wallet database".to_string())?;
    if indexed_lane.covenant_id != covenant_id {
        return Err("indexed lane covenant does not match the selected wallet lane".to_string());
    }
    let old_state = indexer.latest_state(covenant_id).ok_or_else(|| {
        "selected lane covenant is not indexed in the wallet database".to_string()
    })?;
    let spent = indexer
        .open_outpoint(covenant_id)
        .ok_or_else(|| "selected lane has no indexed open outpoint".to_string())?;
    if receipt_policy_name(old_state.receipt_policy) != input.receipt_policy {
        return Err("receiptPolicy must match the indexed lane current policy".to_string());
    }
    let new_state = RgkStateCommitment::new(
        chain_id,
        covenant_id,
        old_state.asset_id,
        new_state_digest,
        receipt_policy(input.receipt_policy),
    )
    .map_err(|error| format!("transition state commitment is invalid: {error}"))?;
    let nonce = replay_nonce(&spent.encode_canonical(), &transition_digest);
    let receipt_input = ReceiptInput::new(
        chain_id,
        covenant_id,
        old_state.clone(),
        new_state.clone(),
        transition_digest,
        continuation_commitment,
        proof_mode(input.proof_mode),
        nonce,
    )
    .map_err(|error| format!("transition receipt input is invalid: {error}"))?;
    let (receipt, receipt_id, receipt_bytes) = ReceiptBuilder::build(&receipt_input)
        .map_err(|error| format!("failed to build transition receipt: {error}"))?;
    let verified_id =
        ReceiptVerifier::verify_local_structured(&receipt, covenant_id, &old_state, chain_id)
            .map_err(|error| format!("transition receipt verification failed: {error}"))?;
    if verified_id != receipt_id {
        return Err("transition receipt verifier returned a non-canonical receipt id".to_string());
    }
    indexer
        .apply_spend_with_continuation(
            covenant_id,
            receipt_id,
            spent,
            new_outpoint,
            new_state,
            input.daa_score,
            ContinuationProof {
                commitment: continuation_commitment,
                shape_root: continuation_shape_root,
                transition_digest,
            },
        )
        .map_err(|error| format!("failed to index transition receipt: {error}"))?;
    indexer
        .flush()
        .map_err(|error| format!("failed to flush scanner database: {error}"))?;

    Ok(TransitionReceiptEvidence {
        receipt_id,
        proof_mode: input.proof_mode,
        receipt_policy: input.receipt_policy,
        new_outpoint,
        new_state_digest,
        receipt_bytes: format!("0x{}", hex::encode(receipt_bytes)),
        transition_digest,
        continuation_commitment,
        continuation_shape_root,
    })
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
    if let Some(kas_balance_sompi) = scan.kas_balance_sompi {
        store.kas_balance = format_kas_balance(kas_balance_sompi);
    }
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
        if (update.covenant_id.is_some()
            || update.state_digest.is_some()
            || !matches!(update.resolver_state, ResolverStateName::Unknown))
            && lane.evidence_status != LaneEvidenceStatus::Indexed
        {
            lane.evidence_status = LaneEvidenceStatus::Indexed;
            changed = true;
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

fn validate_recovery_phrase(words: &[String]) -> Result<Vec<String>, (StatusCode, Json<ApiError>)> {
    if words.len() < 12 {
        return Err(api_error(WalletdError::BadRequest(
            "recoveryPhrase must contain at least 12 words".to_string(),
        )));
    }
    let normalised = words
        .iter()
        .map(|word| word.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if normalised.iter().any(|word| word.is_empty()) {
        return Err(api_error(WalletdError::BadRequest(
            "recoveryPhrase words must be non-empty".to_string(),
        )));
    }
    let phrase = normalised.join(" ");
    Mnemonic::parse_in_normalized(Language::English, &phrase).map_err(|_| {
        api_error(WalletdError::BadRequest(
            "recoveryPhrase must be a valid English BIP39 mnemonic".to_string(),
        ))
    })?;
    Ok(normalised)
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

fn select_kaspa_endpoint(
    config: &DaemonConfig,
    value: &str,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    if let Some(endpoint) = validate_optional_kaspa_endpoint(value)? {
        return Ok(endpoint);
    }
    config.kaspa_endpoint.clone().ok_or_else(|| {
        api_error(WalletdError::BadRequest(
            "kaspaEndpoint is required when rgk-walletd has no configured Kaspa wRPC endpoint"
                .to_string(),
        ))
    })
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

    fn identity_session(
        &self,
    ) -> Result<MutexGuard<'_, RuntimeIdentitySession>, (StatusCode, Json<ApiError>)> {
        self.identity_session
            .lock()
            .map_err(|_| api_error(WalletdError::PoisonedIdentitySession))
    }
}

fn load_state(path: &PathBuf) -> Result<PersistedState, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(PersistedState::default());
    }
    let bytes = fs::read(path)?;
    let mut state = serde_json::from_slice::<PersistedState>(&bytes)?;
    normalise_loaded_state(&mut state);
    Ok(state)
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
    let disk_state = state_for_disk(state);
    let bytes = serde_json::to_vec_pretty(&disk_state)
        .map_err(|error| api_error(WalletdError::Persist(error.to_string())))?;
    write_private_state_file(path, &bytes)
        .map_err(|error| api_error(WalletdError::Persist(error.to_string())))
}

fn normalise_loaded_state(state: &mut PersistedState) {
    let identity_vault_status = stored_identity_vault_status(state.identity_vault.is_some());
    if let Some(profile) = state.profile.as_mut() {
        profile.lifecycle = WalletLifecycle::Locked;
        profile.identity_vault_status = identity_vault_status;
    }
}

fn isolate_state_for_network(state: &mut PersistedState, network: CliNetwork) -> bool {
    let Some(profile) = state.profile.as_ref() else {
        return false;
    };
    if profile_matches_network(profile, network) {
        return false;
    }
    *state = PersistedState::default();
    true
}

fn profile_matches_network(profile: &WalletProfile, network: CliNetwork) -> bool {
    profile.network_id == network.network_id()
        && profile.protocol_network_id == network.protocol_network_id()
        && profile.canonical_chain_domain == network.chain_id().as_domain_str()
}

fn state_for_disk(state: &PersistedState) -> PersistedState {
    let mut disk_state = state.clone();
    let identity_vault_status = stored_identity_vault_status(disk_state.identity_vault.is_some());
    if let Some(profile) = disk_state.profile.as_mut() {
        if !matches!(profile.lifecycle, WalletLifecycle::NotCreated) {
            profile.lifecycle = WalletLifecycle::Locked;
        }
        profile.identity_vault_status = identity_vault_status;
    }
    disk_state
}

const fn stored_identity_vault_status(has_vault: bool) -> IdentityVaultStatus {
    if has_vault {
        IdentityVaultStatus::Encrypted
    } else {
        IdentityVaultStatus::Missing
    }
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
    // `Locked` and `Unauthorized` deliberately map to distinct `code` values
    // while sharing HTTP 401. Keeping the status identical preserves backward
    // compatibility for clients that only read the status line; the `code`
    // field is the new authoritative discriminator.
    let (status, code) = match error {
        WalletdError::NotFound => (StatusCode::NOT_FOUND, "wallet_not_found"),
        WalletdError::Locked => (StatusCode::UNAUTHORIZED, "wallet_locked"),
        WalletdError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
        WalletdError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
        WalletdError::PoisonedState => (StatusCode::INTERNAL_SERVER_ERROR, "poisoned_state"),
        WalletdError::PoisonedIdentitySession => {
            (StatusCode::INTERNAL_SERVER_ERROR, "poisoned_identity_session")
        }
        WalletdError::Persist(_) => (StatusCode::INTERNAL_SERVER_ERROR, "persist_failed"),
        WalletdError::Crypto(_) => (StatusCode::INTERNAL_SERVER_ERROR, "crypto_failed"),
        WalletdError::Entropy(_) => (StatusCode::INTERNAL_SERVER_ERROR, "entropy_failed"),
    };
    (
        status,
        Json(ApiError {
            code: code.to_string(),
            message: error.to_string(),
        }),
    )
}

fn build_wallet_identity_material(
    context: IdentityVaultContext,
    mut recovery_phrase: Vec<String>,
    passphrase: Zeroizing<String>,
) -> Result<WalletIdentityMaterial, WalletdError> {
    let passphrase_salt = random_hex(IDENTITY_VAULT_SALT_BYTES)?;
    let passphrase_verifier =
        passphrase_verifier_with_salt(&passphrase_salt, context.wallet_id.as_str(), &passphrase)?;
    let identity_fingerprint = identity_fingerprint(&context, &recovery_phrase);
    let identity_secret = identity_secret(&context, &recovery_phrase);
    let vault = encrypt_identity_vault(&context, &recovery_phrase, &passphrase)?;
    zeroize_words(&mut recovery_phrase);

    Ok(WalletIdentityMaterial {
        passphrase_salt,
        passphrase_verifier,
        vault,
        identity_fingerprint,
        identity_secret,
    })
}

fn encrypt_identity_vault(
    context: &IdentityVaultContext,
    recovery_phrase: &[String],
    passphrase: &str,
) -> Result<IdentityVault, WalletdError> {
    let mut salt = vec![0u8; IDENTITY_VAULT_SALT_BYTES];
    let mut nonce = vec![0u8; IDENTITY_VAULT_NONCE_BYTES];
    getrandom::getrandom(&mut salt).map_err(|error| WalletdError::Entropy(error.to_string()))?;
    getrandom::getrandom(&mut nonce).map_err(|error| WalletdError::Entropy(error.to_string()))?;

    let mut plaintext = IdentityVaultPlaintext {
        version: IDENTITY_VAULT_VERSION,
        wallet_id: context.wallet_id.clone(),
        network_id: context.network_id.clone(),
        protocol_network_id: context.protocol_network_id.clone(),
        canonical_chain_domain: context.canonical_chain_domain.clone(),
        recovery_phrase: recovery_phrase.to_vec(),
    };
    let mut plaintext_bytes =
        Zeroizing::new(serde_json::to_vec(&plaintext).map_err(|error| {
            WalletdError::Crypto(format!("encode identity plaintext: {error}"))
        })?);
    zeroize_words(&mut plaintext.recovery_phrase);
    let mut key = Zeroizing::new(derive_argon2_key(
        b"rgk-walletd:identity-vault-key:v1",
        passphrase,
        &salt,
    )?);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| WalletdError::Crypto("invalid vault key length".to_string()))?;
    let aad = identity_vault_aad(context);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext_bytes.as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| WalletdError::Crypto("identity vault encryption failed".to_string()))?;
    plaintext_bytes.zeroize();
    key.zeroize();

    Ok(IdentityVault {
        version: IDENTITY_VAULT_VERSION,
        cipher: IDENTITY_VAULT_CIPHER.to_string(),
        kdf: IdentityVaultKdf {
            algorithm: IDENTITY_VAULT_KDF_ALGORITHM.to_string(),
            memory_kib: IDENTITY_VAULT_KDF_MEMORY_KIB,
            iterations: IDENTITY_VAULT_KDF_ITERATIONS,
            parallelism: IDENTITY_VAULT_KDF_PARALLELISM,
        },
        salt: format!("0x{}", hex::encode(salt)),
        nonce: format!("0x{}", hex::encode(nonce)),
        ciphertext: format!("0x{}", hex::encode(ciphertext)),
    })
}

fn decrypt_identity_vault(
    profile: &WalletProfile,
    vault: &IdentityVault,
    passphrase: &str,
) -> Result<UnlockedIdentity, WalletdError> {
    validate_identity_vault_header(vault)?;
    let context = IdentityVaultContext::from_profile(profile);
    let salt = decode_prefixed_hex(&vault.salt, "identity vault salt")?;
    let nonce = decode_prefixed_hex(&vault.nonce, "identity vault nonce")?;
    if nonce.len() != IDENTITY_VAULT_NONCE_BYTES {
        return Err(WalletdError::Crypto(format!(
            "identity vault nonce must be {IDENTITY_VAULT_NONCE_BYTES} bytes"
        )));
    }
    let ciphertext = decode_prefixed_hex(&vault.ciphertext, "identity vault ciphertext")?;
    let mut key = Zeroizing::new(derive_argon2_key(
        b"rgk-walletd:identity-vault-key:v1",
        passphrase,
        &salt,
    )?);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| WalletdError::Crypto("invalid vault key length".to_string()))?;
    let aad = identity_vault_aad(&context);
    let mut plaintext_bytes = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| WalletdError::Unauthorized)?,
    );
    key.zeroize();
    let mut plaintext = serde_json::from_slice::<IdentityVaultPlaintext>(&plaintext_bytes)
        .map_err(|error| WalletdError::Crypto(format!("decode identity plaintext: {error}")))?;
    plaintext_bytes.zeroize();
    validate_identity_plaintext(&context, &plaintext)?;

    let identity_fingerprint = identity_fingerprint(&context, &plaintext.recovery_phrase);
    let identity_secret = identity_secret(&context, &plaintext.recovery_phrase);
    zeroize_words(&mut plaintext.recovery_phrase);
    Ok(UnlockedIdentity {
        identity_fingerprint,
        identity_secret,
    })
}

impl IdentityVaultContext {
    fn from_profile(profile: &WalletProfile) -> Self {
        Self {
            wallet_id: profile.wallet_id.clone(),
            network_id: profile.network_id.clone(),
            protocol_network_id: profile.protocol_network_id.clone(),
            canonical_chain_domain: profile.canonical_chain_domain.clone(),
        }
    }
}

fn validate_identity_vault_header(vault: &IdentityVault) -> Result<(), WalletdError> {
    if vault.version != IDENTITY_VAULT_VERSION {
        return Err(WalletdError::Crypto(format!(
            "unsupported identity vault version {}",
            vault.version
        )));
    }
    if vault.cipher != IDENTITY_VAULT_CIPHER {
        return Err(WalletdError::Crypto(format!(
            "unsupported identity vault cipher {}",
            vault.cipher
        )));
    }
    if vault.kdf.algorithm != IDENTITY_VAULT_KDF_ALGORITHM
        || vault.kdf.memory_kib != IDENTITY_VAULT_KDF_MEMORY_KIB
        || vault.kdf.iterations != IDENTITY_VAULT_KDF_ITERATIONS
        || vault.kdf.parallelism != IDENTITY_VAULT_KDF_PARALLELISM
    {
        return Err(WalletdError::Crypto(
            "unsupported identity vault KDF parameters".to_string(),
        ));
    }
    Ok(())
}

fn validate_identity_plaintext(
    context: &IdentityVaultContext,
    plaintext: &IdentityVaultPlaintext,
) -> Result<(), WalletdError> {
    if plaintext.version != IDENTITY_VAULT_VERSION
        || plaintext.wallet_id != context.wallet_id
        || plaintext.network_id != context.network_id
        || plaintext.protocol_network_id != context.protocol_network_id
        || plaintext.canonical_chain_domain != context.canonical_chain_domain
    {
        return Err(WalletdError::Crypto(
            "identity vault plaintext does not match wallet profile".to_string(),
        ));
    }
    Ok(())
}

fn passphrase_verifier_with_salt(
    salt: &str,
    wallet_id: &str,
    passphrase: &str,
) -> Result<String, WalletdError> {
    let salt_bytes = decode_prefixed_hex(salt, "passphrase salt")?;
    let mut password_material = Zeroizing::new(Vec::new());
    password_material.extend_from_slice(wallet_id.as_bytes());
    password_material.push(0);
    password_material.extend_from_slice(passphrase.as_bytes());
    let verifier = derive_argon2_key(
        b"rgk-walletd:passphrase-verifier:v2",
        std::str::from_utf8(&password_material)
            .map_err(|error| WalletdError::Crypto(format!("passphrase encoding: {error}")))?,
        &salt_bytes,
    )?;
    password_material.zeroize();
    Ok(format!("argon2id:v2:0x{}", hex::encode(verifier)))
}

fn derive_argon2_key(
    domain: &[u8],
    passphrase: &str,
    salt: &[u8],
) -> Result<[u8; 32], WalletdError> {
    let params = Params::new(
        IDENTITY_VAULT_KDF_MEMORY_KIB,
        IDENTITY_VAULT_KDF_ITERATIONS,
        IDENTITY_VAULT_KDF_PARALLELISM,
        Some(32),
    )
    .map_err(|error| WalletdError::Crypto(format!("invalid Argon2 parameters: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut password_material = Zeroizing::new(Vec::new());
    password_material.extend_from_slice(domain);
    password_material.push(0);
    password_material.extend_from_slice(passphrase.as_bytes());
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(&password_material, salt, &mut key)
        .map_err(|error| WalletdError::Crypto(format!("Argon2 failed: {error}")))?;
    password_material.zeroize();
    Ok(key)
}

fn identity_fingerprint(context: &IdentityVaultContext, recovery_phrase: &[String]) -> String {
    let digest = identity_digest(
        b"rgk-walletd:identity-fingerprint:v1",
        context,
        recovery_phrase,
    );
    format!("0x{}", hex::encode(digest))
}

fn identity_secret(
    context: &IdentityVaultContext,
    recovery_phrase: &[String],
) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        identity_digest(b"rgk-walletd:identity-secret:v1", context, recovery_phrase).to_vec(),
    )
}

fn derive_wallet_address(
    network: CliNetwork,
    identity_secret: &[u8],
) -> Result<String, WalletdError> {
    let secp = Secp256k1::new();
    for nonce in 0u32..=u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(b"rgk-walletd:kaspa-wallet-address-key:v1");
        hasher.update(network.chain_id().as_domain_str().as_bytes());
        hasher.update(identity_secret);
        hasher.update(nonce.to_le_bytes());
        let mut secret_bytes: [u8; 32] = hasher.finalize().into();
        let secret_key = SecretKey::from_slice(&secret_bytes);
        secret_bytes.zeroize();
        let Ok(secret_key) = secret_key else {
            continue;
        };
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let x_only_public_key = keypair.x_only_public_key().0.serialize();
        let address = Address::new(
            network.address_prefix(),
            KaspaAddressVersion::PubKey,
            &x_only_public_key,
        );
        return Ok(address.to_string());
    }
    Err(WalletdError::Crypto(
        "could not derive a valid Kaspa wallet address".to_string(),
    ))
}

fn identity_digest(
    domain: &[u8],
    context: &IdentityVaultContext,
    recovery_phrase: &[String],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(b":");
    hasher.update(context.network_id.as_bytes());
    hasher.update(b":");
    hasher.update(context.protocol_network_id.as_bytes());
    hasher.update(b":");
    hasher.update(context.canonical_chain_domain.as_bytes());
    hasher.update(b":");
    for word in recovery_phrase {
        hasher.update(word.as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

fn identity_vault_aad(context: &IdentityVaultContext) -> String {
    format!(
        "rgk-walletd:identity-vault:v1:{}:{}:{}:{}",
        context.wallet_id,
        context.network_id,
        context.protocol_network_id,
        context.canonical_chain_domain
    )
}

fn decode_prefixed_hex(value: &str, field: &str) -> Result<Vec<u8>, WalletdError> {
    let trimmed = value.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(WalletdError::Crypto(format!("{field} is not valid hex")));
    }
    hex::decode(hex)
        .map_err(|error| WalletdError::Crypto(format!("{field} is not valid hex: {error}")))
}

fn random_hex(bytes: usize) -> Result<String, WalletdError> {
    let mut value = vec![0u8; bytes];
    getrandom::getrandom(&mut value).map_err(|error| WalletdError::Entropy(error.to_string()))?;
    Ok(format!("0x{}", hex::encode(value)))
}

fn zeroize_words(words: &mut [String]) {
    for word in words {
        word.zeroize();
    }
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

fn proof_mode(value: ProofModeName) -> ProofMode {
    match value {
        ProofModeName::VerifierReceipt => ProofMode::VerifierReceipt,
        ProofModeName::ZkReceipt => ProofMode::ZkReceipt,
        ProofModeName::P2mrRet => ProofMode::P2mrRet,
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

const SOMPI_PER_KAS: u64 = 100_000_000;

fn format_kas_balance(sompi: u64) -> String {
    format!("{}.{:08} KAS", sompi / SOMPI_PER_KAS, sompi % SOMPI_PER_KAS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgk_core::{KaspaOutpoint, ReceiptPolicy, RgkStateCommitment, KASPA_LOCAL_TOCCATA};
    use rgk_indexer::{InMemoryIndexer, ScanCursor};
    use rgk_kaspa::{FixtureBackend, KaspaUtxo};
    use rgk_receipt::{ReceiptBuilder, ReceiptInput};
    use tower::ServiceExt;

    fn sample_lane(lane_id: Bytes32, covenant_id: Bytes32) -> AssetLane {
        AssetLane {
            lineage_id: "rgk:lineage:test".to_string(),
            lane_id: format!("rgk:lane:public:{}", hex32_label(&lane_id)),
            label: "Test lane".to_string(),
            ticker: "RGK".to_string(),
            balance: "1.0000".to_string(),
            privacy: PrivacyMode::PublicLineage,
            proof_policy: ReceiptPolicyName::VerifierOnly,
            evidence_status: LaneEvidenceStatus::Indexed,
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

    fn transition_input() -> RecordTransitionInput {
        RecordTransitionInput {
            lane_id: hex32_label(&[0x64u8; 32]),
            proof_mode: ProofModeName::VerifierReceipt,
            receipt_policy: ReceiptPolicyName::VerifierOnly,
            strategy: "verifier-receipt-baseline".to_string(),
            new_state_digest: hex32_label(&[0x68u8; 32]),
            transition_digest: hex32_label(&[0x69u8; 32]),
            continuation_commitment: hex32_label(&[0x6au8; 32]),
            continuation_shape_root: hex32_label(&[0x6bu8; 32]),
            new_txid: hex32_plain(&[0x6cu8; 32]),
            new_index: 3,
            daa_score: 21,
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

    fn identity_context() -> IdentityVaultContext {
        IdentityVaultContext {
            wallet_id: "test-wallet".to_string(),
            network_id: "rgk:kaspa-local-toccata".to_string(),
            protocol_network_id: "kaspa-local-toccata".to_string(),
            canonical_chain_domain: "kaspa-local-toccata".to_string(),
        }
    }

    fn recovery_words() -> Vec<String> {
        [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ]
        .iter()
        .map(|word| word.to_string())
        .collect()
    }

    #[test]
    fn recovery_phrase_validation_requires_bip39_checksum() {
        assert_eq!(
            validate_recovery_phrase(&recovery_words()).expect("valid recovery phrase"),
            recovery_words()
        );

        let invalid = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon",
        ]
        .iter()
        .map(|word| word.to_string())
        .collect::<Vec<_>>();

        assert!(validate_recovery_phrase(&invalid).is_err());
    }

    fn profile_with_identity(identity_fingerprint: String) -> WalletProfile {
        WalletProfile {
            wallet_id: "test-wallet".to_string(),
            protocol: "rgk".to_string(),
            network_id: "rgk:kaspa-local-toccata".to_string(),
            protocol_network_id: "kaspa-local-toccata".to_string(),
            canonical_chain_domain: "kaspa-local-toccata".to_string(),
            kaspa_endpoint: "ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh".to_string(),
            wallet_set_id: Some("0xwalletset".to_string()),
            address: None,
            identity_vault_status: IdentityVaultStatus::Unlocked,
            identity_fingerprint: Some(identity_fingerprint),
            lifecycle: WalletLifecycle::Ready,
        }
    }

    #[test]
    fn identity_vault_encrypts_recovery_phrase_and_requires_passphrase() {
        let context = identity_context();
        let material = build_wallet_identity_material(
            context,
            recovery_words(),
            Zeroizing::new("correct-passphrase".to_string()),
        )
        .expect("identity material");
        let vault_json = serde_json::to_string(&material.vault).expect("vault json");
        assert!(vault_json.contains("xchacha20poly1305"));
        assert!(!vault_json.contains("abandon"));
        assert!(!vault_json.contains("about"));

        let profile = profile_with_identity(material.identity_fingerprint.clone());
        let unlocked = decrypt_identity_vault(&profile, &material.vault, "correct-passphrase")
            .expect("unlock identity vault");

        assert_eq!(unlocked.identity_fingerprint, material.identity_fingerprint);
        assert!(matches!(
            decrypt_identity_vault(&profile, &material.vault, "wrong-passphrase"),
            Err(WalletdError::Unauthorized)
        ));
    }

    #[test]
    fn wallet_address_derivation_uses_kaspa_network_prefixes() {
        let material = build_wallet_identity_material(
            identity_context(),
            recovery_words(),
            Zeroizing::new("address-passphrase".to_string()),
        )
        .expect("identity material");

        let local = derive_wallet_address(CliNetwork::LocalToccata, &material.identity_secret)
            .expect("local-toccata address");
        let testnet = derive_wallet_address(CliNetwork::Testnet12, &material.identity_secret)
            .expect("testnet address");
        let mainnet = derive_wallet_address(CliNetwork::Mainnet, &material.identity_secret)
            .expect("mainnet address");

        assert!(local.starts_with("kaspasim:"));
        assert!(testnet.starts_with("kaspatest:"));
        assert!(mainnet.starts_with("kaspa:"));
        assert_ne!(local, testnet);
        assert_ne!(testnet, mainnet);
    }

    #[test]
    fn format_kas_balance_uses_eight_decimal_places() {
        assert_eq!(format_kas_balance(0), "0.00000000 KAS");
        assert_eq!(format_kas_balance(1), "0.00000001 KAS");
        assert_eq!(format_kas_balance(123_456_789), "1.23456789 KAS");
        assert_eq!(format_kas_balance(10_000_000_000), "100.00000000 KAS");
    }

    #[test]
    fn kaspa_endpoint_selection_uses_configured_default_only_when_available() {
        let local_endpoint = CliNetwork::LocalToccata
            .default_kaspa_endpoint()
            .expect("local endpoint")
            .to_string();
        let local_config = DaemonConfig {
            network: CliNetwork::LocalToccata,
            kaspa_endpoint: Some(local_endpoint.clone()),
            state_path: temp_path("rgk-walletd-local-state"),
            sync_db_path: temp_path("rgk-walletd-local-sync"),
        };

        assert_eq!(
            select_kaspa_endpoint(&local_config, "").expect("local fallback"),
            local_endpoint
        );

        let testnet_config = DaemonConfig {
            network: CliNetwork::Testnet12,
            kaspa_endpoint: None,
            state_path: temp_path("rgk-walletd-testnet-state"),
            sync_db_path: temp_path("rgk-walletd-testnet-sync"),
        };

        assert!(select_kaspa_endpoint(&testnet_config, "").is_err());
        assert_eq!(
            select_kaspa_endpoint(
                &testnet_config,
                "wss://example.com/v2/kaspa/testnet-12/tls/wrpc/borsh",
            )
            .expect("explicit endpoint"),
            "wss://example.com/v2/kaspa/testnet-12/tls/wrpc/borsh"
        );
    }

    #[test]
    fn successful_scan_refreshes_dashboard_kas_balance() {
        let mut store = PersistedState {
            profile: Some(profile_with_identity("0xfingerprint".to_string())),
            kas_balance: "stale".to_string(),
            ..PersistedState::default()
        };
        let cursor = ScanCursor {
            chain_id: KASPA_LOCAL_TOCCATA,
            block_hash: [0x77u8; 32],
            daa_score: 42,
        };
        let scan = WalletdScanResult {
            tick: ScanTick {
                initialised_cursor: false,
                start_cursor: cursor.clone(),
                end_cursor: cursor,
                added_chain_blocks: 0,
                observed_spends: 0,
            },
            indexed_spends: 0,
            lane_updates: Vec::new(),
            kas_balance_sompi: Some(123_456_789),
        };

        apply_successful_scan(&mut store, &scan);

        assert_eq!(store.kas_balance, "1.23456789 KAS");
    }

    #[test]
    fn loaded_state_from_another_network_is_ignored() {
        let mut state = PersistedState {
            profile: Some(profile_with_identity("0xfingerprint".to_string())),
            passphrase_salt: Some("salt".to_string()),
            passphrase_verifier: Some("verifier".to_string()),
            kas_balance: "1.00000000 KAS".to_string(),
            lanes: vec![sample_lane([0x91u8; 32], [0x92u8; 32])],
            ..PersistedState::default()
        };

        let isolated = isolate_state_for_network(&mut state, CliNetwork::Testnet12);

        assert!(isolated);
        assert!(state.profile.is_none());
        assert!(state.passphrase_salt.is_none());
        assert!(state.passphrase_verifier.is_none());
        assert!(state.lanes.is_empty());
    }

    #[test]
    fn save_state_writes_locked_encrypted_profile_without_recovery_phrase() {
        let path = temp_path("rgk-walletd-vault-state");
        let _ = std::fs::remove_file(&path);
        let material = build_wallet_identity_material(
            identity_context(),
            recovery_words(),
            Zeroizing::new("state-passphrase".to_string()),
        )
        .expect("identity material");
        let state = PersistedState {
            profile: Some(profile_with_identity(material.identity_fingerprint)),
            passphrase_salt: Some(material.passphrase_salt),
            passphrase_verifier: Some(material.passphrase_verifier),
            identity_vault: Some(material.vault),
            ..PersistedState::default()
        };

        save_state(&path, &state).expect("save state");
        let state_text = std::fs::read_to_string(&path).expect("state text");
        assert!(!state_text.contains("abandon"));
        assert!(!state_text.contains("about"));
        assert!(state_text.contains("identityVault"));

        let state_json: serde_json::Value = serde_json::from_str(&state_text).expect("state json");
        assert_eq!(state_json["profile"]["lifecycle"], "locked");
        assert_eq!(state_json["profile"]["identityVaultStatus"], "encrypted");

        let loaded = load_state(&path).expect("load state");
        let loaded_profile = loaded.profile.expect("loaded profile");
        assert_eq!(loaded_profile.lifecycle, WalletLifecycle::Locked);
        assert_eq!(
            loaded_profile.identity_vault_status,
            IdentityVaultStatus::Encrypted
        );

        let _ = std::fs::remove_file(&path);
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
    fn build_transition_receipt_indexes_spend_after_reopen() {
        let path = temp_path("rgk-walletd-transition-index");
        let _ = std::fs::remove_dir_all(&path);
        let request = indexed_lane_input();
        let evidence = parse_lane_evidence(KASPA_LOCAL_TOCCATA, &request)
            .expect("parse")
            .expect("evidence");
        index_lane_evidence_at_path(&path, KASPA_LOCAL_TOCCATA, evidence.clone())
            .expect("index lane")
            .expect("indexed");

        let transition = transition_input();
        let receipt = build_transition_receipt_at_path(
            &path,
            KASPA_LOCAL_TOCCATA,
            &transition,
            &hex32_label(&evidence.covenant_id),
        )
        .expect("transition receipt");

        assert_eq!(receipt.proof_mode, ProofModeName::VerifierReceipt);
        assert_eq!(receipt.receipt_policy, ReceiptPolicyName::VerifierOnly);
        assert_eq!(receipt.new_state_digest, [0x68u8; 32]);
        assert!(receipt.receipt_bytes.starts_with("0x"));
        assert!(receipt.receipt_bytes.len() > 66);
        assert_eq!(receipt.transition_digest, [0x69u8; 32]);
        assert_eq!(receipt.continuation_commitment, [0x6au8; 32]);
        assert_eq!(receipt.continuation_shape_root, [0x6bu8; 32]);
        assert_eq!(
            receipt.new_outpoint,
            KaspaOutpoint {
                transaction_id: [0x6cu8; 32],
                index: 3,
            }
        );

        let indexer = SledIndexer::open_path(&path).expect("reopen indexer");
        assert_eq!(
            indexer
                .latest_state(evidence.covenant_id)
                .map(|state| state.state_digest),
            Some([0x68u8; 32])
        );
        assert_eq!(
            indexer.open_outpoint(evidence.covenant_id),
            Some(KaspaOutpoint {
                transaction_id: [0x6cu8; 32],
                index: 3,
            })
        );
        let entry = indexer
            .lookup(evidence.covenant_id)
            .expect("indexed covenant");
        assert_eq!(entry.spend_history.len(), 1);
        assert_eq!(entry.spend_history[0].receipt_id, receipt.receipt_id);
        assert_eq!(
            entry.spend_history[0].continuation,
            Some(ContinuationProof {
                commitment: [0x6au8; 32],
                shape_root: [0x6bu8; 32],
                transition_digest: [0x69u8; 32],
            })
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn build_transition_receipt_rejects_policy_mismatch() {
        let path = temp_path("rgk-walletd-transition-policy");
        let _ = std::fs::remove_dir_all(&path);
        let request = indexed_lane_input();
        let evidence = parse_lane_evidence(KASPA_LOCAL_TOCCATA, &request)
            .expect("parse")
            .expect("evidence");
        index_lane_evidence_at_path(&path, KASPA_LOCAL_TOCCATA, evidence.clone())
            .expect("index lane")
            .expect("indexed");

        let mut transition = transition_input();
        transition.receipt_policy = ReceiptPolicyName::Any;
        let err = build_transition_receipt_at_path(
            &path,
            KASPA_LOCAL_TOCCATA,
            &transition,
            &hex32_label(&evidence.covenant_id),
        )
        .expect_err("policy mismatch must fail");

        assert!(err.contains("receiptPolicy must match the indexed lane current policy"));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn build_transition_receipt_rejects_unindexed_lane() {
        let path = temp_path("rgk-walletd-transition-unindexed");
        let _ = std::fs::remove_dir_all(&path);
        let transition = transition_input();

        let err = build_transition_receipt_at_path(
            &path,
            KASPA_LOCAL_TOCCATA,
            &transition,
            &hex32_label(&[0x61u8; 32]),
        )
        .expect_err("unindexed lane must fail");

        assert!(err.contains("laneId is not indexed"));
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
        assert_eq!(evidence.receipt_bytes, request.receipt_bytes);
        assert_eq!(evidence.transition_digest, transition_digest);
        assert_eq!(evidence.continuation_commitment, continuation_commitment);
        assert_eq!(evidence.continuation_shape_root, shape_root);

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

    #[test]
    fn api_error_distinguishes_locked_from_unauthorized() {
        // HTTP 401 is shared so the status line stays backward-compatible, but
        // the `code` field is the authoritative discriminator. This guards the
        // cross-repo fix for the audit's §1.3 finding: a locked wallet must be
        // distinguishable from a wrong passphrase without parsing `message`.
        let (locked_status, locked_body) = api_error(WalletdError::Locked);
        let (unauthorized_status, unauthorized_body) = api_error(WalletdError::Unauthorized);

        assert_eq!(locked_status, StatusCode::UNAUTHORIZED);
        assert_eq!(unauthorized_status, StatusCode::UNAUTHORIZED);
        assert_eq!(locked_body.code, "wallet_locked");
        assert_eq!(unauthorized_body.code, "unauthorized");
        assert_ne!(locked_body.code, unauthorized_body.code);
        assert!(!locked_body.message.is_empty());
        assert!(!unauthorized_body.message.is_empty());
    }

    #[test]
    fn api_error_codes_are_stable_per_variant() {
        // Snapshot of the full code surface — guards against silent renames
        // that would break frontend branching on `code`. If you intentionally
        // change one of these identifiers, update the frontend adapter and the
        // HTTP contract in the same change.
        let cases = [
            (WalletdError::NotFound, StatusCode::NOT_FOUND, "wallet_not_found"),
            (WalletdError::Locked, StatusCode::UNAUTHORIZED, "wallet_locked"),
            (WalletdError::Unauthorized, StatusCode::UNAUTHORIZED, "unauthorized"),
            (
                WalletdError::BadRequest("x".to_string()),
                StatusCode::BAD_REQUEST,
                "bad_request",
            ),
            (WalletdError::PoisonedState, StatusCode::INTERNAL_SERVER_ERROR, "poisoned_state"),
            (
                WalletdError::PoisonedIdentitySession,
                StatusCode::INTERNAL_SERVER_ERROR,
                "poisoned_identity_session",
            ),
            (
                WalletdError::Persist("x".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "persist_failed",
            ),
            (
                WalletdError::Crypto("x".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "crypto_failed",
            ),
            (
                WalletdError::Entropy("x".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "entropy_failed",
            ),
        ];
        for (err, expected_status, expected_code) in cases {
            let (status, body) = api_error(err);
            assert_eq!(status, expected_status);
            assert_eq!(body.code, expected_code, "stable code drift for {expected_code}");
        }
    }

    // ---- HTTP-layer integration: real request → handler → ApiError wire shape ----
    //
    // These exercise the full axum pipeline (router → handler → `api_error` →
    // axum serialisation) in-process via `tower::ServiceExt::oneshot`, so the
    // `code` field is asserted on its actual serialised wire form, not just the
    // in-memory `ApiError` struct. This is the end-to-end guarantee the frontend
    // depends on: a 401 carries a `code` that distinguishes `wallet_locked` from
    // `unauthorized` (audit §1.3).

    fn test_app_state(profile: Option<WalletProfile>) -> AppState {
        let network = CliNetwork::LocalToccata;
        AppState {
            config: Arc::new(DaemonConfig {
                network,
                kaspa_endpoint: network.default_kaspa_endpoint().map(ToString::to_string),
                state_path: std::env::temp_dir().join(format!(
                    "rgk-walletd-http-test-{}",
                    std::process::id()
                )),
                sync_db_path: std::env::temp_dir().join(format!(
                    "rgk-walletd-http-test-sync-{}",
                    std::process::id()
                )),
            }),
            store: Arc::new(Mutex::new(PersistedState {
                profile,
                ..PersistedState::default()
            })),
            identity_session: Arc::new(Mutex::new(RuntimeIdentitySession::default())),
        }
    }

    fn locked_test_profile() -> WalletProfile {
        let network = CliNetwork::LocalToccata;
        WalletProfile {
            wallet_id: "rgk:wallet:test".to_string(),
            protocol: "rgk".to_string(),
            network_id: network.network_id().to_string(),
            protocol_network_id: network.protocol_network_id().to_string(),
            canonical_chain_domain: network.protocol_network_id().to_string(),
            kaspa_endpoint: "ws://127.0.0.1:18111/v2/kaspa/simnet/no-tls/wrpc/borsh"
                .to_string(),
            wallet_set_id: None,
            address: None,
            identity_vault_status: IdentityVaultStatus::Encrypted,
            identity_fingerprint: None,
            lifecycle: WalletLifecycle::Locked,
        }
    }

    #[tokio::test]
    async fn http_dashboard_returns_locked_code_when_wallet_is_locked() {
        // The headline §1.3 guarantee over the wire: a locked wallet yields
        // HTTP 401 with a distinct `wallet_locked` code, separable from the
        // `unauthorized` (wrong-passphrase) code even though both share 401.
        let app = build_router(test_app_state(Some(locked_test_profile())));
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/dashboard")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router oneshot");

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
            .await
            .expect("collect body");
        let payload: serde_json::Value =
            serde_json::from_slice(&bytes).expect("body is valid JSON");
        assert_eq!(payload["code"], "wallet_locked");
        assert!(
            payload["message"].as_str().unwrap().contains("locked"),
            "message should describe the locked state: {}",
            payload["message"]
        );
    }

    #[tokio::test]
    async fn http_dashboard_returns_not_found_code_when_no_profile() {
        // Confirms a different error path surfaces its own code on the wire,
        // so the frontend can branch on `code` rather than status alone.
        let app = build_router(test_app_state(None));
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/dashboard")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router oneshot");

        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
            .await
            .expect("collect body");
        let payload: serde_json::Value =
            serde_json::from_slice(&bytes).expect("body is valid JSON");
        assert_eq!(payload["code"], "wallet_not_found");
        assert!(!payload["message"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn http_health_is_ok_and_carries_no_error_body() {
        // Sanity: the success path is unaffected by the ApiError change.
        let app = build_router(test_app_state(None));
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router oneshot");

        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 64)
            .await
            .expect("collect body");
        let payload: serde_json::Value =
            serde_json::from_slice(&bytes).expect("body is valid JSON");
        assert_eq!(payload["status"], "ok");
        assert_eq!(payload["protocol"], "rgk");
    }
}
