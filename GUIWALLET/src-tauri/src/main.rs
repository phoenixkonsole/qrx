#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod qrx_apps;

use serde::{Deserialize, Serialize};
use tauri::Manager;
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Write, BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock, Arc, atomic::{AtomicBool, Ordering}},
    time::{Duration, SystemTime, UNIX_EPOCH, Instant},
    collections::HashMap,
};
use thiserror::Error;
use std::str::FromStr;
use bdk::bitcoin::{Address, Network};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use argon2::{Algorithm, Argon2, Params, Version};
use openssl::{pkey::PKey, symm::Cipher, hash::{Hasher, MessageDigest}};

struct DaemonState {
    child: Mutex<Option<Child>>,
}


#[derive(Debug, Serialize)]
struct ValidatorFleetModeResult { changed: usize, daemon_running: bool, runtime_applied: bool, restart_required: bool, validator_fleet_count: usize, message: String }

struct KrakenGatewayState {
    child: Mutex<Option<Child>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KrakenCredentialVault {
    version: u32,
    venue: String,
    kdf: String,
    cipher: String,
    kdf_salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KrakenCredentialPlain {
    api_key: String,
    api_secret: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuraProviderWalletSettings {
    version: u32,
    enabled: bool,
    mode: String,
    power_profile: String,
    disk_budget_gib: u64,
    provider_id: String,
    relay_endpoint: String,
    config_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FamilySafetyPolicy {
    version: u32,
    profile: String,
    max_age_rating: u32,
    unrated_blocked: bool,
    ads_blocked: bool,
    viewer_rewards_blocked: bool,
    dapp_allowed: bool,
    payment_limit_atoms: u64,
    session_minutes: u32,
    allow_domains: Vec<String>,
    block_domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FamilySafetyVault {
    version: u32,
    kdf: String,
    cipher: String,
    kdf_salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Serialize)]
struct KrakenCredentialStatus {
    configured: bool,
    encrypted_at_rest: bool,
    venue: String,
    storage: String,
}

#[derive(Debug, Serialize)]
struct KrakenGatewayStatus {
    running: bool,
    pid: Option<u32>,
    gateway_address: Option<String>,
    venue: String,
    stdout_log: String,
    stderr_log: String,
    credential_vault_present: bool,
}

#[derive(Debug, Serialize)]
struct AgentManagerResult { action: String, agent: String, venue: String, raw_transaction_created: bool, broadcast: CommandResult }

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WalletContext {
    network: String,
    wallet: String,
    data_dir: String,
    wallet_dir: String,
    rpc_endpoint: String,
    rpc_port: u16,
    daemon_running: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CommandResult {
    ok: bool,
    method: String,
    pub(crate) result: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletListItem {
    name: String,
    path: String,
    address: Option<String>,
    has_recovery_file: bool,
    wallet_version: Option<u64>,
    legacy_or_unknown: bool,
    safety_backup_exists: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatorFleetItem {
    wallet: String,
    address: Option<String>,
    validator_mode_enabled: bool,
    is_bootstrap: bool,
    bootstrap_lock_active: bool,
    bootstrap_principal_atoms: i64,
    bootstrap_lock_until_height: i64,
    liveness_slash_grace_active: bool,
    double_sign_slashing_active: bool,
    self_stake_atoms: i64,
    locked_self_stake_atoms: i64,
    freely_unstakeable_self_stake_atoms: i64,
    spendable_balance_atoms: i64,
    status_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyGuiWalletCandidate {
    name: String,
    path: String,
    address: Option<String>,
    wallet_version: Option<u64>,
    has_recovery_file: bool,
    already_in_shared_store: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct LegacyNetworkWalletCandidate {
    name: String,
    network: String,
    path: String,
    address: Option<String>,
    has_recovery_file: bool,
    wallet_version: Option<u64>,
    hybrid_ready: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyNetworkWalletGroup {
    name: String,
    shared_exists: bool,
    shared_address: Option<String>,
    conflict: bool,
    unique_addresses: Vec<String>,
    candidates: Vec<LegacyNetworkWalletCandidate>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletAddressSet {
    wallet: String,
    primary_address: Option<String>,
    manifest_address: Option<String>,
    addresses: Vec<String>,
    additional_addresses: Vec<String>,
    address_mismatch: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportResult {
    wallet: WalletContext,
    imported_files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletInspection {
    name: String,
    path: String,
    wallet_version: Option<u64>,
    address: Option<String>,
    manifest_address: Option<String>,
    address_mismatch: bool,
    has_wallet_manifest: bool,
    has_recovery_file: bool,
    ed25519_private: bool,
    ed25519_public: bool,
    mldsa65_private: bool,
    mldsa65_public: bool,
    hybrid_ready: bool,
    private_key_encryption: String,
    passphrase_state: String,
    safety_backup_exists: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeySetImportResult {
    wallet: WalletContext,
    copied_files: Vec<String>,
    inspection: WalletInspection,
}

#[derive(Debug, Serialize, Deserialize)]
struct WalletPassphraseChangeResult {
    wallet: String,
    backup_path: String,
    passphrase_state: String,
    changed_files: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExistingWalletPrepareResult {
    wallet: WalletContext,
    wallet_version: Option<u64>,
    legacy_or_unknown: bool,
    backup_created: bool,
    backup_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateWalletResult {
    wallet: WalletContext,
    address: Option<String>,
    recovery_phrase: Option<String>,
    output: String,
}

#[derive(Debug, Serialize)]
struct RecoveryRefreshResult {
    wallet: String,
    address: Option<String>,
    recovery_phrase: String,
    recovery_file: String,
    safety_backup: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonHealth {
    running: bool,
    launched_by_app: bool,
    pid: Option<u32>,
    network: String,
    wallet: String,
    actual_wallet: Option<String>,
    actual_wallet_dir: Option<String>,
    wallet_mismatch: bool,
    data_root_mismatch: bool,
    data_dir: String,
    control_socket: String,
    stdout_log: String,
    stderr_log: String,
    info: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidatorModeStatus {
    validator_enabled: bool,
    wallet_mode_safe: bool,
    min_validator_self_stake_qub: String,
    double_sign_slash: String,
    offline_penalty: String,
    best_practice: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UiStatus {
    wallet: WalletContext,
    daemon: DaemonHealth,
    wallet_info: Option<Value>,
    staking_info: Option<Value>,
    validators: Option<Value>,
    history: Option<Value>,
    tokenomics: Option<Value>,
    peers: Option<Value>,
    node_info: Option<Value>,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<AppError> for String {
    fn from(value: AppError) -> Self {
        value.to_string()
    }
}

fn current_sidecar_binary_name(base: &str) -> String {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "unknown"
    };

    let platform = if cfg!(target_os = "windows") {
        "pc-windows-msvc"
    } else if cfg!(target_os = "macos") {
        "apple-darwin"
    } else {
        "unknown-linux-gnu"
    };

    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    format!("{base}-{arch}-{platform}{ext}")
}

pub(crate) fn app_data_dir() -> Result<PathBuf, AppError> {
    // GUI and Core intentionally share the exact same QRX data root.
    // qrx/qrxd/qrx-cli default to ~/.qrx/<network>; using ~/.qrx here means
    // an existing Core wallet is discovered and used in place instead of
    // being copied into a separate GUI-only store.
    let home = dirs::home_dir()
        .ok_or_else(|| AppError::Message("Could not resolve home directory".into()))?;
    let dir = home.join(".qrx");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}


fn wallet_settings_dir(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    // Settings/runtime state can be network-specific even though the private
    // wallet identity is shared across all QRX networks.
    let wallet = sanitize_wallet_name(wallet)?;
    let dir = network_root(network)?.join("wallet-settings").join(wallet);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn aura_provider_config_file(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(wallet_settings_dir(network, wallet)?.join("aura-provider.conf"))
}

fn aura_provider_settings_file(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(wallet_settings_dir(network, wallet)?.join("aura-provider-settings.json"))
}

fn aura_replace_file(tmp: &Path, path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    if path.exists() { fs::remove_file(path).map_err(|e| e.to_string())?; }
    fs::rename(tmp, path).map_err(|e| e.to_string())
}

fn aura_conf_value(value: &str, field: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.contains('\n') || trimmed.contains('\r') || trimmed.contains('=') {
        return Err(format!("Invalid {field}"));
    }
    Ok(trimmed.to_string())
}

#[tauri::command]
fn aura_provider_settings_load(network: String, wallet: String) -> Result<AuraProviderWalletSettings, String> {
    let config_path = aura_provider_config_file(&network, &wallet).map_err(String::from)?;
    let settings_path = aura_provider_settings_file(&network, &wallet).map_err(String::from)?;
    if settings_path.exists() {
        let mut v: AuraProviderWalletSettings = serde_json::from_slice(&fs::read(&settings_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        v.config_path = config_path.to_string_lossy().to_string();
        return Ok(v);
    }
    Ok(AuraProviderWalletSettings {
        version: 1,
        enabled: false,
        mode: "automatic".into(),
        power_profile: "balanced".into(),
        disk_budget_gib: 50,
        provider_id: String::new(),
        relay_endpoint: String::new(),
        config_path: config_path.to_string_lossy().to_string(),
    })
}

#[tauri::command]
fn aura_provider_settings_save(
    network: String,
    wallet: String,
    enabled: bool,
    mode: String,
    power_profile: String,
    disk_budget_gib: u64,
    provider_id: String,
    relay_endpoint: String,
) -> Result<AuraProviderWalletSettings, String> {
    if !matches!(mode.as_str(), "automatic" | "off") {
        return Err("AURA mode must be automatic or off".into());
    }
    if !matches!(power_profile.as_str(), "eco" | "balanced" | "performance") {
        return Err("Unknown AURA power profile".into());
    }
    if disk_budget_gib > 8192 {
        return Err("AURA model cache budget is too large".into());
    }
    let provider_id = aura_conf_value(&provider_id, "provider id")?;
    let relay_endpoint = aura_conf_value(&relay_endpoint, "relay endpoint")?;
    if enabled && provider_id.is_empty() {
        return Err("Unlock/load a wallet address before enabling AURA Compute".into());
    }
    if !relay_endpoint.is_empty() && !relay_endpoint.starts_with("qrxrelay://") {
        return Err("Relay endpoint must start with qrxrelay://".into());
    }
    let wallet_safe = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let network_safe = aura_conf_value(&network, "network")?;
    let config_path = aura_provider_config_file(&network_safe, &wallet_safe).map_err(String::from)?;
    let settings_path = aura_provider_settings_file(&network_safe, &wallet_safe).map_err(String::from)?;
    let lease_path = wallet_settings_dir(&network_safe, &wallet_safe).map_err(String::from)?.join("aura-provider.leases");
    let jobs_path = wallet_settings_dir(&network_safe, &wallet_safe).map_err(String::from)?.join("aura-provider.jobs");
    let effective_disk_gib = if disk_budget_gib == 0 {
        match power_profile.as_str() { "eco" => 10, "performance" => 200, _ => 50 }
    } else { disk_budget_gib };
    let cache_bytes = effective_disk_gib.saturating_mul(1024 * 1024 * 1024);
    let pod_id = format!("wallet-{}-auto", wallet_safe);
    let conf = format!(
        "format=QRXAURA41\nenabled={}\nprovider_id={}\npod_id={}\nnetwork={}\nregion=AUTO\ncompute_threads=0\nmodel_cache_bytes={}\nfree_memory_bytes=0\nnetwork_egress_mbps=0\nrequire_wallet_approval=1\nrequire_secure_dispatch=1\nenable_pq_hybrid_sessions=1\nlisten_host=127.0.0.1\nlisten_port=0\nlease_journal_path={}\njob_journal_path={}\nruntime_adapter=AUTO\nruntime_plugin_path=\nruntime_adapter_dir=\nrelay_required=0\n{}",
        if enabled && mode == "automatic" { 1 } else { 0 }, provider_id, pod_id, network_safe, cache_bytes,
        lease_path.to_string_lossy(), jobs_path.to_string_lossy(),
        if relay_endpoint.is_empty() { String::new() } else { format!("relay={}\n", relay_endpoint) }
    );
    let tmp = config_path.with_extension("tmp");
    fs::write(&tmp, conf.as_bytes()).map_err(|e| e.to_string())?;
    aura_replace_file(&tmp, &config_path)?;

    let settings = AuraProviderWalletSettings {
        version: 1,
        enabled: enabled && mode == "automatic",
        mode,
        power_profile,
        disk_budget_gib,
        provider_id,
        relay_endpoint,
        config_path: config_path.to_string_lossy().to_string(),
    };
    let settings_tmp = settings_path.with_extension("tmp");
    fs::write(&settings_tmp, serde_json::to_vec_pretty(&settings).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    aura_replace_file(&settings_tmp, &settings_path)?;
    Ok(settings)
}

fn validator_mode_file(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(wallet_settings_dir(network, wallet)?.join("validator_mode_enabled.txt"))
}

fn read_validator_mode(network: &str, wallet: &str) -> Result<bool, AppError> {
    let path = validator_mode_file(network, wallet)?;
    if !path.exists() {
        return Ok(false);
    }
    let value = fs::read_to_string(path)?;
    Ok(value.trim() == "1" || value.trim().eq_ignore_ascii_case("true"))
}

fn write_validator_mode(network: &str, wallet: &str, enabled: bool) -> Result<(), AppError> {
    let path = validator_mode_file(network, wallet)?;
    fs::write(path, if enabled { "1\n" } else { "0\n" })?;
    Ok(())
}

fn network_root(network: &str) -> Result<PathBuf, AppError> {
    Ok(app_data_dir()?.join(network))
}

fn wallet_root(_network: &str) -> Result<PathBuf, AppError> {
    // QRX wallet identity is network-independent. Chain state remains under
    // ~/.qrx/<network>, while one hybrid key identity lives under ~/.qrx/wallets.
    let root = app_data_dir()?.join("wallets");
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn legacy_network_candidates_for_wallet(wallet: &str) -> Result<Vec<LegacyNetworkWalletCandidate>, AppError> {
    let wallet = sanitize_wallet_name(wallet)?;
    let root = app_data_dir()?;
    let mut out = Vec::new();
    for network in ["mainnet", "alpha", "testnet", "regtest"] {
        let path = root.join(network).join("wallets").join(&wallet);
        if !path.is_dir() { continue; }
        let hybrid_ready = ["ed25519_priv.pem", "ed25519_pub.pem", "mldsa65_priv.pem", "mldsa65_pub.pem"]
            .iter().all(|name| path.join(name).is_file());
        out.push(LegacyNetworkWalletCandidate {
            name: wallet.clone(),
            network: network.to_string(),
            path: path.to_string_lossy().to_string(),
            address: read_address(&path),
            has_recovery_file: path.join("recovery.qrxseed").is_file(),
            wallet_version: read_wallet_version(&path),
            hybrid_ready,
        });
    }
    Ok(out)
}

fn best_legacy_network_candidate(candidates: &[LegacyNetworkWalletCandidate]) -> Option<LegacyNetworkWalletCandidate> {
    candidates.iter().cloned().max_by_key(|c| {
        let mut score = 0u32;
        if c.hybrid_ready { score += 100; }
        if c.has_recovery_file { score += 20; }
        if c.address.is_some() { score += 10; }
        score += c.wallet_version.unwrap_or(0).min(50) as u32;
        score
    })
}

fn wallet_dir(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    let wallet = sanitize_wallet_name(wallet)?;
    let shared = wallet_root(network)?.join(&wallet);
    if shared.is_dir() { return Ok(shared); }

    // Safe one-time migration from the former per-network layout. We never
    // privilege Alpha/Mainnet/Testnet by name. If all discovered copies resolve
    // to one identity, copy the most complete source. If different addresses
    // exist under the same wallet name, stop and let the GUI Migration Conflict
    // Wizard choose explicitly; never overwrite or silently pick a network.
    let candidates = legacy_network_candidates_for_wallet(&wallet)?;
    if candidates.is_empty() { return Ok(shared); }
    let mut unique_addresses: Vec<String> = candidates.iter().filter_map(|c| c.address.clone()).collect();
    unique_addresses.sort(); unique_addresses.dedup();
    let all_candidates_identified = candidates.iter().all(|c| c.address.is_some());
    if unique_addresses.len() > 1 || (candidates.len() > 1 && (!all_candidates_identified || unique_addresses.len() != 1)) {
        let detail = if unique_addresses.is_empty() { "addresses unavailable".to_string() } else { unique_addresses.join(", ") };
        return Err(AppError::Message(format!(
            "Legacy wallet migration conflict for '{}': the old per-network stores cannot be proven to contain the same QUB identity ({}). Open Wallets → Migration Conflict Wizard and choose explicitly; no files were changed.",
            wallet, detail
        )));
    }
    let source = best_legacy_network_candidate(&candidates)
        .ok_or_else(|| AppError::Message("No usable legacy wallet candidate found".into()))?;
    let source_path = PathBuf::from(&source.path);
    copy_dir_recursive(&source_path, &shared)?;
    let marker = serde_json::json!({
        "migration":"network-independent-wallet-identity",
        "source":source.path,
        "source_network":source.network,
        "destination":shared.to_string_lossy(),
        "address":source.address,
        "candidate_count":candidates.len(),
        "policy":"copy-only; no network preference; source preserved; conflict requires explicit GUI choice",
        "created_unix":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|AppError::Message(e.to_string()))?.as_secs()
    });
    fs::write(shared.join("QRX_SHARED_IDENTITY_MIGRATION.json"), serde_json::to_vec_pretty(&marker).map_err(|e|AppError::Message(e.to_string()))?)?;
    Ok(shared)
}

fn ensure_context(network: &str, wallet: &str) -> Result<WalletContext, AppError> {
    let wallet = sanitize_wallet_name(wallet)?;
    let data_dir = app_data_dir()?;
    let wallet_dir = wallet_dir(network, &wallet)?;
    Ok(WalletContext {
        network: network.to_string(),
        wallet,
        data_dir: data_dir.to_string_lossy().to_string(),
        wallet_dir: wallet_dir.to_string_lossy().to_string(),
        rpc_endpoint: rpc_endpoint(network),
        rpc_port: rpc_port_for_network(network),
        daemon_running: false,
    })
}

fn sanitize_wallet_name(wallet: &str) -> Result<String, AppError> {
    let trimmed = wallet.trim();
    if trimmed.is_empty() {
        return Err(AppError::Message("Wallet name is required".into()));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AppError::Message(
            "Wallet name may only contain letters, numbers, dash and underscore".into(),
        ));
    }
    Ok(trimmed.to_string())
}

fn logs_dir(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    let dir = network_root(network)?.join("logs").join(wallet);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn stdout_log_path(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(logs_dir(network, wallet)?.join("qrxd.stdout.log"))
}

fn stderr_log_path(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(logs_dir(network, wallet)?.join("qrxd.stderr.log"))
}

fn rpc_port_for_network(network: &str) -> u16 {
    match network {
        "mainnet" => 37660,
        "alpha" => 37661,
        "testnet" => 37662,
        "regtest" => 37663,
        _ => 37661,
    }
}

fn rpc_endpoint(network: &str) -> String {
    format!("http://127.0.0.1:{}/rpc", rpc_port_for_network(network))
}

fn candidate_paths(app: Option<&tauri::AppHandle>, binary: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let sidecar = current_sidecar_binary_name(binary);
    // Tauri removes the target suffix when packaging sidecars, but Windows
    // still requires .exe for the filesystem existence check below.
    let packaged = if cfg!(target_os = "windows") { format!("{binary}.exe") } else { binary.to_string() };
    let binary = packaged.as_str();

    if let Ok(bin_dir) = std::env::var("QRX_BIN_DIR") {
        paths.push(PathBuf::from(&bin_dir).join(&sidecar));
        paths.push(PathBuf::from(&bin_dir).join(binary));
    }

    if let Some(app) = app {
        if let Some(resource_dir) = app.path_resolver().resource_dir() {
            paths.push(resource_dir.join(&sidecar));
            paths.push(resource_dir.join(binary));
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            paths.push(parent.join(&sidecar));
            paths.push(parent.join(binary));
            paths.push(parent.join("../Resources").join(&sidecar));
            paths.push(parent.join("../Resources").join(binary));
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join("src-tauri").join("bin").join(&sidecar));
        paths.push(cwd.join("src-tauri").join("bin").join(binary));
        paths.push(cwd.join("bin").join(&sidecar));
        paths.push(cwd.join("bin").join(binary));
    }

    paths.push(PathBuf::from(&sidecar));
    paths.push(PathBuf::from(binary));
    paths
}

fn resolve_binary(app: Option<&tauri::AppHandle>, binary: &str) -> Result<PathBuf, AppError> {
    candidate_paths(app, binary)
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            AppError::Message(format!(
                "Could not find sidecar binary: {binary}. Place {} in src-tauri/bin/ or set QRX_BIN_DIR.",
                current_sidecar_binary_name(binary)
            ))
        })
}

fn parse_key_value_lines(output: &str) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
        }
    }
    map
}

fn parse_amount(amount: &str) -> Result<String, AppError> {
    let cleaned = amount.trim().replace(',', ".");
    cleaned
        .parse::<f64>()
        .map_err(|_| AppError::Message("Invalid amount".into()))?;
    Ok(cleaned)
}

fn read_address(wallet_dir: &Path) -> Option<String> {
    let path = wallet_dir.join("address.txt");
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_manifest_address(wallet_dir: &Path) -> Option<String> {
    let text = fs::read_to_string(wallet_dir.join("wallet.json")).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    json.get("address")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn addresses_from_value(value: &Value) -> Vec<String> {
    fn push_unique(out: &mut Vec<String>, raw: &str) {
        let a = raw.trim();
        if !a.is_empty() && !out.iter().any(|x| x == a) { out.push(a.to_string()); }
    }
    let mut out = Vec::new();
    match value {
        Value::Array(items) => {
            for item in items {
                if let Some(a) = item.as_str() { push_unique(&mut out, a); }
                else if let Some(a) = item.get("address").and_then(Value::as_str) { push_unique(&mut out, a); }
            }
        }
        Value::Object(map) => {
            if let Some(items) = map.get("addresses").and_then(Value::as_array) {
                for item in items {
                    if let Some(a) = item.as_str() { push_unique(&mut out, a); }
                    else if let Some(a) = item.get("address").and_then(Value::as_str) { push_unique(&mut out, a); }
                }
            }
            if let Some(result) = map.get("result") {
                for a in addresses_from_value(result) { push_unique(&mut out, &a); }
            }
        }
        Value::String(a) => push_unique(&mut out, a),
        _ => {}
    }
    out
}


const CURRENT_QRX_WALLET_VERSION: u64 = 12;

fn read_wallet_version(wallet_dir: &Path) -> Option<u64> {
    let text = fs::read_to_string(wallet_dir.join("wallet.json")).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    json.get("wallet_version").and_then(|v| v.as_u64())
}

fn wallet_backup_root(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(app_data_dir()?.join("backups").join(network).join(wallet))
}

fn safety_backup_exists(network: &str, wallet: &str) -> bool {
    let Ok(root) = wallet_backup_root(network, wallet) else { return false; };
    if !root.is_dir() { return false; }
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|e| e.path().is_dir() && e.file_name().to_string_lossy().starts_with("pre-0.0.7-"))
}

fn directory_copy_stats(root: &Path) -> Result<(u64, u64), AppError> {
    let mut files = 0u64;
    let mut bytes = 0u64;
    if !root.is_dir() {
        return Ok((0, 0));
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            let (sub_files, sub_bytes) = directory_copy_stats(&path)?;
            files += sub_files;
            bytes += sub_bytes;
        } else if ft.is_file() {
            files += 1;
            bytes += entry.metadata()?.len();
        }
    }
    Ok((files, bytes))
}

fn create_pre_007_safety_backup(network: &str, wallet: &str) -> Result<String, AppError> {
    let source = wallet_dir(network, wallet)?;
    if !source.is_dir() {
        return Err(AppError::Message("Existing wallet directory is missing; backup aborted".into()));
    }
    let (source_files, source_bytes) = directory_copy_stats(&source)?;
    if source_files == 0 {
        return Err(AppError::Message("Existing wallet directory is empty; backup aborted".into()));
    }

    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AppError::Message(format!("System clock error while creating backup: {e}")))?
        .as_secs();
    let root = wallet_backup_root(network, wallet)?;
    fs::create_dir_all(&root)?;

    // Never reuse an existing destination. Even a partial old backup must not be overwritten.
    let mut destination = root.join(format!("pre-0.0.7-{secs}"));
    let mut suffix = 1u32;
    while destination.exists() {
        destination = root.join(format!("pre-0.0.7-{secs}-{suffix}"));
        suffix += 1;
    }

    copy_dir_recursive(&source, &destination)?;

    // Old 0.0.6/legacy wallets may predate wallet.json. Verify the backup by
    // comparing the number and total size of all regular files instead.
    let (backup_files, backup_bytes) = directory_copy_stats(&destination)?;
    if backup_files != source_files || backup_bytes != source_bytes {
        return Err(AppError::Message(format!(
            "Safety backup verification failed: source has {source_files} files/{source_bytes} bytes, backup has {backup_files} files/{backup_bytes} bytes"
        )));
    }

    let manifest = serde_json::json!({
        "purpose": "pre-0.0.7 safety backup",
        "source": source.to_string_lossy(),
        "network": network,
        "wallet": wallet,
        "wallet_version": read_wallet_version(&source),
        "created_unix": secs,
        "source_files": source_files,
        "source_bytes": source_bytes,
        "verification": "regular-file count and total byte size matched before wallet use",
        "policy": "copy-only; original wallet was not modified"
    });
    fs::write(
        destination.join("QRX_BACKUP_MANIFEST.json"),
        serde_json::to_vec_pretty(&manifest)
            .map_err(|e| AppError::Message(format!("Could not serialize backup manifest: {e}")))?,
    )?;

    Ok(destination.to_string_lossy().to_string())
}

fn create_wallet_security_backup(network: &str, wallet: &str, purpose: &str) -> Result<String, AppError> {
    let source = wallet_dir(network, wallet)?;
    if !source.is_dir() { return Err(AppError::Message("Wallet directory is missing; security backup aborted".into())); }
    let (source_files, source_bytes) = directory_copy_stats(&source)?;
    if source_files == 0 { return Err(AppError::Message("Wallet directory is empty; security backup aborted".into())); }
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| AppError::Message(format!("System clock error: {e}")))?.as_secs();
    let root = wallet_backup_root(network, wallet)?;
    fs::create_dir_all(&root)?;
    let safe_purpose: String = purpose.chars().map(|c| if c.is_ascii_alphanumeric() || c=='-' { c } else { '-' }).collect();
    let mut destination = root.join(format!("{safe_purpose}-{secs}"));
    let mut suffix=1u32;
    while destination.exists(){ destination=root.join(format!("{safe_purpose}-{secs}-{suffix}")); suffix+=1; }
    copy_dir_recursive(&source,&destination)?;
    let (backup_files, backup_bytes)=directory_copy_stats(&destination)?;
    if source_files!=backup_files || source_bytes!=backup_bytes {
        return Err(AppError::Message(format!("Security backup verification failed: source {source_files} files/{source_bytes} bytes, backup {backup_files} files/{backup_bytes} bytes")));
    }
    let manifest=serde_json::json!({
        "purpose": purpose, "source": source.to_string_lossy(), "network":network, "wallet":wallet,
        "wallet_version":read_wallet_version(&source), "created_unix":secs, "source_files":source_files, "source_bytes":source_bytes,
        "verification":"regular-file count and total byte size matched before security change",
        "policy":"copy-only backup created before private-key passphrase modification"
    });
    fs::write(destination.join("QRX_BACKUP_MANIFEST.json"),serde_json::to_vec_pretty(&manifest).map_err(|e|AppError::Message(e.to_string()))?)?;
    Ok(destination.to_string_lossy().to_string())
}

fn encrypted_pem_accepts_passphrase(path:&Path, passphrase:&str)->bool {
    let Ok(pem)=fs::read(path) else { return false; };
    PKey::private_key_from_pem_passphrase(&pem,passphrase.as_bytes()).is_ok()
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<Vec<String>, AppError> {
    let mut copied = Vec::new();
    fs::create_dir_all(destination)?;

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let dest = destination.join(entry.file_name());

        if path.is_dir() {
            copied.extend(copy_dir_recursive(&path, &dest)?);
        } else {
            if dest.exists() {
                return Err(AppError::Message(format!(
                    "Refusing to overwrite existing file: {}",
                    dest.to_string_lossy()
                )));
            }
            fs::copy(&path, &dest)?;
            copied.push(dest.to_string_lossy().to_string());
        }
    }

    Ok(copied)
}

fn background_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    command
}

fn run_qrx(
    app: Option<&tauri::AppHandle>,
    args: &[&str],
    passphrase: Option<&str>,
    stdin_text: Option<&str>,
) -> Result<String, AppError> {
    let qrx_bin = resolve_binary(app, "qrx")?;
    let mut cmd = background_command(qrx_bin);
    cmd.args(args);
    if let Some(passphrase) = passphrase {
        cmd.env("QRX_PASSPHRASE", passphrase);
    }
    if stdin_text.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    if let Some(stdin_text) = stdin_text {
        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_text.as_bytes())?;
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if !stderr.is_empty() { stderr } else { stdout };
        return Err(AppError::Message(if message.is_empty() {
            "QRX backend command failed".into()
        } else {
            message
        }));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_cli_raw(
    app: Option<&tauri::AppHandle>,
    network: &str,
    wallet: &str,
    args: &[&str],
    passphrase: Option<&str>,
) -> Result<String, AppError> {
    let data_dir = app_data_dir()?;
    let cli_bin = resolve_binary(app, "qrx-cli")?;
    let output = background_command(cli_bin)
        .arg("--network")
        .arg(network)
        .arg("--datadir")
        .arg(&data_dir)
        .arg("--wallet")
        .arg(wallet)
        .args(args)
        .env("QRX_PASSPHRASE", passphrase.unwrap_or(""))
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if !stderr.is_empty() { stderr } else { stdout };
        return Err(AppError::Message(if message.is_empty() {
            "QRX CLI command failed".into()
        } else {
            message
        }));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn run_cli(
    app: Option<&tauri::AppHandle>,
    network: &str,
    wallet: &str,
    args: &[&str],
    passphrase: Option<&str>,
) -> Result<CommandResult, AppError> {
    let stdout = run_cli_raw(app, network, wallet, args, passphrase)?;
    let json_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| AppError::Message(format!("Unexpected qrx-cli output: {stdout}")))?;
    Ok(serde_json::from_str(json_line)?)
}

fn required_clean(value: &str, label: &str) -> Result<String, String> { let clean=value.trim(); if clean.is_empty(){return Err(format!("{label} is required"));} if clean.chars().any(char::is_whitespace){return Err(format!("{label} must not contain whitespace"));} Ok(clean.to_string()) }
fn positive_u64(value: &str, label: &str) -> Result<String, String> { let parsed=value.trim().parse::<u64>().map_err(|_|format!("{label} must be a whole number"))?; if parsed==0{return Err(format!("{label} must be greater than zero"));} Ok(parsed.to_string()) }

fn sign_and_broadcast_raw(app:&tauri::AppHandle,network:&str,wallet:&str,raw:&str,passphrase:Option<&str>,label:&str)->Result<CommandResult,String>{
    let stamp=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let dir=std::env::temp_dir().join(format!("qrx-{label}-{}-{stamp}",std::process::id()));
    fs::create_dir_all(&dir).map_err(|e|e.to_string())?;
    let raw_path=dir.join("transaction.raw"); let signed_path=dir.join("transaction.signed");
    let result=(||{
        fs::write(&raw_path,raw.as_bytes()).map_err(|e|e.to_string())?;
        let raw_arg=raw_path.to_string_lossy().to_string(); let signed_arg=signed_path.to_string_lossy().to_string();
        run_cli(Some(app),network,wallet,&["signrawtransactionwithwallet",&raw_arg,&signed_arg],passphrase).map_err(|e|e.to_string())?;
        if !signed_path.exists(){return Err("QRX wallet did not create a signed transaction".into());}
        run_cli(Some(app),network,wallet,&["sendrawtransaction",&signed_arg],passphrase).map_err(|e|e.to_string())
    })();
    let _=fs::remove_file(&raw_path); let _=fs::remove_file(&signed_path); let _=fs::remove_dir(&dir);
    result
}

fn sign_raw_to_text(app:&tauri::AppHandle,network:&str,wallet:&str,raw:&str,passphrase:Option<&str>,label:&str)->Result<String,String>{
    let stamp=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let dir=std::env::temp_dir().join(format!("qrx-{label}-{}-{stamp}",std::process::id())); fs::create_dir_all(&dir).map_err(|e|e.to_string())?;
    let raw_path=dir.join("transaction.raw"); let signed_path=dir.join("transaction.signed"); fs::write(&raw_path,raw.as_bytes()).map_err(|e|e.to_string())?;
    let r=run_cli(Some(app),network,wallet,&["signrawtransactionwithwallet",&raw_path.to_string_lossy(),&signed_path.to_string_lossy()],passphrase).map_err(|e|e.to_string());
    if let Err(e)=r{let _=fs::remove_dir_all(&dir);return Err(e)} let signed=fs::read_to_string(&signed_path).map_err(|e|e.to_string())?; let _=fs::remove_dir_all(&dir); Ok(signed)
}

#[tauri::command]
fn generals_prepare_offline_reveal(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,payload:String,not_before_height:i64,expires_height:i64,passphrase:Option<String>)->Result<Value,String>{
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    if not_before_height<1||expires_height<not_before_height{return Err("Invalid offline reveal height window".into())} if payload.len()>8192{return Err("Reveal payload too large".into())}
    let ctx=ensure_context(&network,&wallet).map_err(String::from)?; let address=generals_address(&network,&wallet)?; let (ed,ml)=generals_public_keys(&network,&wallet)?;
    let expiry=expires_height.to_string(); let created=run_cli(Some(&app),&network,&wallet,&["createvelocitytransaction",&address,&address,"0",&ed,&ml,"GAME_ORDER_REVEAL","7",&expiry,&payload],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?; let signed=sign_raw_to_text(&app,&network,&wallet,raw,passphrase.as_deref(),"generals-offline")?;
    let q=PathBuf::from(&ctx.data_dir).join("generals-offline-queue"); fs::create_dir_all(&q).map_err(|e|e.to_string())?; let stamp=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos(); let path=q.join(format!("reveal-{stamp}.scheduled"));
    fs::write(&path,format!("{}\n{}\n{}",not_before_height,expires_height,signed)).map_err(|e|e.to_string())?;
    Ok(serde_json::json!({"queued":true,"not_before_height":not_before_height,"expires_height":expires_height,"path":path.to_string_lossy(),"keyless_relay":true}))
}

fn broadcast_created_transaction(app:&tauri::AppHandle,network:&str,wallet:&str,created:CommandResult,passphrase:Option<&str>,action:&str,agent:&str)->Result<AgentManagerResult,String>{ let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return a raw transaction".to_string())?; let broadcast=sign_and_broadcast_raw(app,network,wallet,raw,passphrase,"agent-manager")?; Ok(AgentManagerResult{action:action.into(),agent:agent.into(),venue:"KRAKEN".into(),raw_transaction_created:true,broadcast}) }

#[tauri::command]
fn agent_manager_list(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:Option<String>,passphrase:Option<String>)->Result<CommandResult,String>{ let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?; let owner=owner.unwrap_or_default(); let args=if owner.trim().is_empty(){vec!["listagents"]}else{vec!["listagents",owner.trim()]}; run_cli(Some(&app),&network,&wallet,&args,passphrase.as_deref()).map_err(|e|e.to_string()) }

#[tauri::command]
fn agent_manager_register(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:String,agent:String,agent_ed_pub:String,agent_mldsa_pub:String,max_trade_atoms:String,daily_limit_atoms:String,markets:String,expires_height:String,owner_ed_pub:String,owner_mldsa_pub:String,lane:String,tx_expiry:String,allow_arbitrage:bool,passphrase:Option<String>)->Result<AgentManagerResult,String>{ let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?; let owner=required_clean(&owner,"Owner address")?; let agent=required_clean(&agent,"Agent address")?; let markets=markets.split(',').map(str::trim).filter(|v|!v.is_empty()).collect::<Vec<_>>().join(","); if markets.is_empty()||markets.split(',').any(|m|!m.contains('/')){return Err("Enter at least one market like BTC/EUR".into());} let max_trade=positive_u64(&max_trade_atoms,"Maximum per trade")?; let daily=positive_u64(&daily_limit_atoms,"Daily limit")?; let expires=positive_u64(&expires_height,"Agent expiry height")?; let tx_expiry=positive_u64(&tx_expiry,"Transaction expiry height")?; let permissions=if allow_arbitrage{"TRADE_EXTERNAL,ARBITRAGE_CROSS_VENUE"}else{"TRADE_EXTERNAL"}; let created=run_cli(Some(&app),&network,&wallet,&["createagentregistertransaction",&owner,&agent,agent_ed_pub.trim(),agent_mldsa_pub.trim(),permissions,&max_trade,&daily,&markets,&expires,owner_ed_pub.trim(),owner_mldsa_pub.trim(),lane.trim(),&tx_expiry],passphrase.as_deref()).map_err(|e|e.to_string())?; broadcast_created_transaction(&app,&network,&wallet,created,passphrase.as_deref(),"register",&agent) }

#[tauri::command]
fn agent_manager_revoke(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:String,agent:String,owner_ed_pub:String,owner_mldsa_pub:String,lane:String,tx_expiry:String,passphrase:Option<String>)->Result<AgentManagerResult,String>{ let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?; let owner=required_clean(&owner,"Owner address")?; let agent=required_clean(&agent,"Agent address")?; let tx_expiry=positive_u64(&tx_expiry,"Transaction expiry height")?; let created=run_cli(Some(&app),&network,&wallet,&["createagentrevoketransaction",&owner,&agent,owner_ed_pub.trim(),owner_mldsa_pub.trim(),lane.trim(),&tx_expiry],passphrase.as_deref()).map_err(|e|e.to_string())?; broadcast_created_transaction(&app,&network,&wallet,created,passphrase.as_deref(),"revoke",&agent) }

fn child_pid(child: &Child) -> u32 {
    child.id()
}

fn daemon_health_inner(
    app: Option<&tauri::AppHandle>,
    state: &tauri::State<DaemonState>,
    network: &str,
    wallet: &str,
    passphrase: Option<&str>,
) -> Result<DaemonHealth, AppError> {
    let data_dir = app_data_dir()?;
    let control_socket = rpc_endpoint(network);
    let stdout_log = stdout_log_path(network, wallet)?;
    let stderr_log = stderr_log_path(network, wallet)?;

    let mut launched_by_app = false;
    let mut pid = None;
    let mut running = false;

    {
        let mut guard = state
            .child
            .lock()
            .map_err(|_| AppError::Message("Daemon mutex poisoned".into()))?;
        let mut clear_child = false;
        if let Some(child) = guard.as_mut() {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    clear_child = true;
                }
                Ok(None) => {
                    launched_by_app = true;
                    pid = Some(child_pid(child));
                    // A live process is not proof that its RPC endpoint works.
                }
                Err(_) => {
                    clear_child = true;
                }
            }
        }
        if clear_child {
            *guard = None;
        }
    }

    let mut info = None;
    if let Ok(res) = run_cli(app, network, wallet, &["getinfo"], passphrase) {
        info = Some(res.result);
        running = true;
        if pid.is_none() {
            pid = info.as_ref().and_then(|v| v.get("node_pid")).and_then(|v| v.as_u64()).map(|v| v as u32);
        }
    }

    let actual_wallet_dir = info.as_ref()
        .and_then(|v| v.get("wallet_dir"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let actual_wallet = actual_wallet_dir.as_ref()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());
    let wallet_mismatch = running && actual_wallet.as_deref().map(|w| w != wallet).unwrap_or(false);
    let data_root_mismatch = running && actual_wallet_dir.as_ref()
        .map(|p| !Path::new(p).starts_with(&data_dir))
        .unwrap_or(false);

    Ok(DaemonHealth {
        running,
        launched_by_app,
        pid,
        network: network.to_string(),
        wallet: wallet.to_string(),
        actual_wallet,
        actual_wallet_dir,
        wallet_mismatch,
        data_root_mismatch,
        data_dir: data_dir.to_string_lossy().to_string(),
        control_socket,
        stdout_log: stdout_log.to_string_lossy().to_string(),
        stderr_log: stderr_log.to_string_lossy().to_string(),
        info,
    })
}

fn enabled_validator_wallets(network: &str, primary_wallet: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(items) = list_wallets(Some(network.to_string())) {
        for item in items {
            if read_validator_mode(network, &item.name).unwrap_or(false) && !out.iter().any(|w| w == &item.name) {
                out.push(item.name);
            }
        }
    }
    if read_validator_mode(network, primary_wallet).unwrap_or(false) && !out.iter().any(|w| w == primary_wallet) {
        out.push(primary_wallet.to_string());
    }
    out
}

fn spawn_daemon(
    app: &tauri::AppHandle,
    network: &str,
    wallet: &str,
    passphrase: Option<&str>,
    validator_enabled: bool,
) -> Result<Child, AppError> {
    let ctx = ensure_context(network, wallet)?;
    let daemon_bin = resolve_binary(Some(app), "qrxd")?;
    let stdout_log = stdout_log_path(network, wallet)?;
    let stderr_log = stderr_log_path(network, wallet)?;

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(stdout_log)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(stderr_log)?;

    let mut cmd = background_command(daemon_bin);
    cmd.arg("--network")
        .arg(network)
        .arg("--datadir")
        .arg(&ctx.data_dir)
        .arg("--wallet")
        .arg(wallet)
        // Security invariant: GUI-managed wallet RPC must never be reachable from LAN/Wi-Fi.
        // P2P networking is a separate listener owned by Core.
        .arg("--rpc-bind")
        .arg(format!("127.0.0.1:{}", rpc_port_for_network(network)));

    if !validator_enabled {
        cmd.arg("--no-block-producer");
    } else {
        /* Phase 7.2.9: a single qrxd/P2P/QRXDB runtime may host many validator
           signer identities. The daemon receives wallet names only; private keys
           remain in their normal local wallet directories. */
        for signer_wallet in enabled_validator_wallets(network, wallet) {
            cmd.arg("--validator-wallet").arg(signer_wallet);
        }
    }

    if let Ok(aura_config) = aura_provider_config_file(network, wallet) {
        if aura_config.exists() {
            cmd.env("QRX_AURA_PROVIDER_CONFIG", aura_config);
        }
    }

    // The public runtime trust root is bundled with the wallet.  qrxd never
    // trusts a publisher key downloaded alongside a runtime package.
    if let Some(catalog) = app.path_resolver().resolve_resource("resources/aura/official-runtime-catalog.qrx") {
        if catalog.exists() { cmd.env("QRX_AURA_RUNTIME_CATALOG", catalog); }
    }
    if let Some(pubkey) = app.path_resolver().resolve_resource("resources/aura/official-runtime-publisher.pem") {
        if pubkey.exists() { cmd.env("QRX_AURA_RUNTIME_PUBLISHER_KEY", pubkey); }
    }

    let child = cmd
        .env("QRX_PASSPHRASE", passphrase.unwrap_or(""))
        .env_remove("QRX_ENABLE_MAINNET_HTLC")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;

    Ok(child)
}


fn pem_encryption_state(path: &Path) -> Option<&'static str> {
    let text = fs::read_to_string(path).ok()?;
    if text.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        Some("encrypted")
    } else if text.contains("BEGIN PRIVATE KEY") || text.contains("BEGIN RSA PRIVATE KEY") || text.contains("BEGIN EC PRIVATE KEY") {
        Some("unencrypted")
    } else {
        Some("unknown")
    }
}

fn inspect_wallet_inner(network: &str, wallet: &str) -> Result<WalletInspection, AppError> {
    let name = sanitize_wallet_name(wallet)?;
    let dir = wallet_dir(network, &name)?;
    if !dir.is_dir() {
        return Err(AppError::Message("Wallet directory does not exist".into()));
    }
    let ed_priv = dir.join("ed25519_priv.pem");
    let ed_pub = dir.join("ed25519_pub.pem");
    let ml_priv = dir.join("mldsa65_priv.pem");
    let ml_pub = dir.join("mldsa65_pub.pem");
    let ep = ed_priv.is_file();
    let epu = ed_pub.is_file();
    let mp = ml_priv.is_file();
    let mpu = ml_pub.is_file();
    let mut states = Vec::new();
    if ep { if let Some(v)=pem_encryption_state(&ed_priv){ states.push(v); } }
    if mp { if let Some(v)=pem_encryption_state(&ml_priv){ states.push(v); } }
    let private_key_encryption = if states.is_empty() {
        "none/watch-only-or-incomplete".to_string()
    } else if states.iter().all(|v| *v == "encrypted") {
        "encrypted".to_string()
    } else if states.iter().all(|v| *v == "unencrypted") {
        "unencrypted".to_string()
    } else {
        "mixed-or-unknown".to_string()
    };
    let encrypted_paths: Vec<&Path> = [ed_priv.as_path(), ml_priv.as_path()].into_iter()
        .filter(|p| p.is_file() && pem_encryption_state(p)==Some("encrypted")).collect();
    // Use Ed25519 as the canonical password probe. The Rust OpenSSL provider on
    // some macOS builds cannot parse ML-DSA65 even though the QRX Core OpenSSL
    // build can. Treating that provider limitation as "password required" made
    // legacy wallets encrypted with an empty PKCS#8 passphrase look locked.
    // The daemon/Core still validates the full hybrid key set when signing.
    let empty_passphrase_works = if ed_priv.is_file() && pem_encryption_state(&ed_priv)==Some("encrypted") {
        encrypted_pem_accepts_passphrase(&ed_priv, "")
    } else {
        !encrypted_paths.is_empty() && encrypted_paths.iter().any(|p| encrypted_pem_accepts_passphrase(p, ""))
    };
    let passphrase_state = match private_key_encryption.as_str() {
        "encrypted" if empty_passphrase_works => "encrypted-container-empty-passphrase-no-user-password",
        "encrypted" => "passphrase-required-to-use-private-keys",
        "unencrypted" => "no-passphrase-required-for-private-keys",
        "none/watch-only-or-incomplete" => "no-private-keys-detected",
        _ => "inspect-manually-mixed-or-unknown",
    }.to_string();
    let canonical_address = read_address(&dir);
    let manifest_address = read_manifest_address(&dir);
    let address_mismatch = canonical_address.is_some() && manifest_address.is_some() && canonical_address != manifest_address;
    Ok(WalletInspection {
        name: name.clone(), path: dir.to_string_lossy().to_string(),
        wallet_version: read_wallet_version(&dir), address: canonical_address,
        manifest_address, address_mismatch,
        has_wallet_manifest: dir.join("wallet.json").is_file(),
        has_recovery_file: dir.join("recovery.qrxseed").is_file(),
        ed25519_private: ep, ed25519_public: epu, mldsa65_private: mp, mldsa65_public: mpu,
        hybrid_ready: ep && epu && mp && mpu, private_key_encryption, passphrase_state,
        safety_backup_exists: safety_backup_exists(network, &name),
    })
}

#[tauri::command]
fn inspect_wallet(network: Option<String>, wallet: String) -> Result<WalletInspection, String> {
    inspect_wallet_inner(network.as_deref().unwrap_or("mainnet"), &wallet).map_err(String::from)
}


#[tauri::command]
fn verify_wallet_passphrase(app: tauri::AppHandle, network: Option<String>, wallet: String, passphrase: String) -> Result<bool, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let inspection = inspect_wallet_inner(&network, &wallet).map_err(String::from)?;
    if inspection.private_key_encryption == "unencrypted" { return Ok(true); }
    if inspection.private_key_encryption != "encrypted" {
        return Err("Wallet key protection is mixed/unknown; passphrase verification is unavailable until the key set is inspected.".into());
    }
    let empty_allowed = inspection.passphrase_state == "encrypted-container-empty-passphrase-no-user-password";
    // Always allow an explicit empty-string verification attempt. This is
    // required for 0.0.6-era wallets whose PKCS#8 containers are encrypted but
    // were created with an empty user passphrase. A wrong empty passphrase is
    // rejected by the key-decryption check below.
    if passphrase.is_empty() && !empty_allowed {
        let dir = wallet_dir(&network, &wallet).map_err(String::from)?;
        let ed = dir.join("ed25519_priv.pem");
        if !(ed.is_file() && pem_encryption_state(&ed)==Some("encrypted") && encrypted_pem_accepts_passphrase(&ed, "")) {
            return Err("Enter the wallet passphrase.".into());
        }
    }
    let dir = wallet_dir(&network, &wallet).map_err(String::from)?;
    let candidates = [dir.join("ed25519_priv.pem"), dir.join("mldsa65_priv.pem")];
    let mut checked = 0usize;
    let mut canonical_ed25519_verified = false;
    for path in candidates.iter().filter(|p| p.is_file()) {
        let pem = fs::read(path).map_err(|e| format!("Could not read {}: {e}", path.display()))?;
        if !String::from_utf8_lossy(&pem).contains("BEGIN ENCRYPTED PRIVATE KEY") {
            continue;
        }
        let is_ed25519 = path.file_name().and_then(|n| n.to_str()) == Some("ed25519_priv.pem");
        match PKey::private_key_from_pem_passphrase(&pem, passphrase.as_bytes()) {
            Ok(_) => { checked += 1; if is_ed25519 { canonical_ed25519_verified = true; } }
            Err(_) if !is_ed25519 && canonical_ed25519_verified => {
                // ML-DSA65 may be unsupported by the Rust OpenSSL provider on
                // macOS. Core/qrxd performs the authoritative hybrid-key check.
                continue;
            }
            Err(_) => return Err("Incorrect wallet passphrase.".to_string()),
        }
    }
    if checked == 0 {
        return Err("No encrypted private key could be verified in this wallet.".into());
    }
    // If qrxd is already running, synchronize the verified session secret into
    // the daemon. Hex encoding keeps spaces/special characters out of the
    // legacy whitespace-delimited CLI command surface. If the daemon is not
    // running yet, start_daemon receives the in-memory passphrase later.
    let passphrase_hex: String = passphrase.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let encoded = if passphrase_hex.is_empty() { "-" } else { passphrase_hex.as_str() };
    let ack = run_cli(Some(&app), &network, &wallet, &["walletpassphrasehexfor", &wallet, encoded], None)
        .map_err(|e| format!("Passphrase is correct, but the running node did not establish the signer session: {e}"))?;
    if ack.result.get("unlocked").and_then(Value::as_bool) != Some(true) { return Err("The node did not confirm the signer session; wallet remains locked.".into()); }
    Ok(true)
}

#[tauri::command]
fn detect_legacy_default_passphrase(network: Option<String>, wallet: String) -> Result<bool, String> {
    let network=network.unwrap_or_else(||"mainnet".into());
    let wallet=sanitize_wallet_name(&wallet).map_err(String::from)?;
    let dir=wallet_dir(&network,&wallet).map_err(String::from)?;
    let ed=dir.join("ed25519_priv.pem");
    if !ed.is_file() || pem_encryption_state(&ed)!=Some("encrypted") { return Ok(false); }
    // Historical alpha/testnet/regtest auto-created wallets used this fixed
    // development credential. Detection is a local decryption probe only; the
    // value is never returned to JavaScript, logs, metadata or configuration.
    Ok(encrypted_pem_accepts_passphrase(&ed,"change-me"))
}

#[tauri::command]
fn change_wallet_passphrase(app: tauri::AppHandle, network: Option<String>, wallet: String, current_passphrase: String, new_passphrase: String) -> Result<WalletPassphraseChangeResult, String> {
    let network=network.unwrap_or_else(||"mainnet".into());
    let wallet=sanitize_wallet_name(&wallet).map_err(String::from)?;
    if new_passphrase.is_empty(){ return Err("New passphrase must not be empty. Use a real passphrase; empty-passphrase legacy wallets are supported for reading but should be upgraded.".into()); }
    if new_passphrase.len()<8 { return Err("New wallet passphrase must be at least 8 characters.".into()); }
    let inspection=inspect_wallet_inner(&network,&wallet).map_err(String::from)?;
    if inspection.private_key_encryption!="encrypted" && inspection.private_key_encryption!="unencrypted" { return Err("Wallet key set is incomplete/mixed; refusing passphrase change.".into()); }
    let dir=wallet_dir(&network,&wallet).map_err(String::from)?;
    let paths=[dir.join("ed25519_priv.pem"),dir.join("mldsa65_priv.pem")];
    if paths.iter().any(|p|!p.is_file()){ return Err("Hybrid private key set is incomplete; refusing passphrase change.".into()); }
    let mut keys=Vec::new();
    for path in &paths {
        let pem=fs::read(path).map_err(|e|format!("Could not read {}: {e}",path.display()))?;
        let key=if pem_encryption_state(path)==Some("encrypted") {
            PKey::private_key_from_pem_passphrase(&pem,current_passphrase.as_bytes()).map_err(|_|"Current wallet passphrase is incorrect.".to_string())?
        } else { PKey::private_key_from_pem(&pem).map_err(|_|format!("Could not parse private key {}",path.display()))? };
        keys.push(key);
    }
    let address_before=fs::read(dir.join("address.txt")).map_err(|e|format!("Could not read canonical wallet address before migration: {e}"))?;
    let public_before:Vec<Vec<u8>>=keys.iter().map(|k|k.public_key_to_der().map_err(|e|format!("Could not fingerprint wallet identity before migration: {e}"))).collect::<Result<_,_>>()?;
    let backup_path=create_wallet_security_backup(&network,&wallet,"pre-passphrase-change").map_err(String::from)?;
    let nonce=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let mut temps=Vec::new();
    for (idx,(path,key)) in paths.iter().zip(keys.iter()).enumerate(){
        let bytes=key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(),new_passphrase.as_bytes()).map_err(|e|format!("Could not re-encrypt {}: {e}",path.display()))?;
        let tmp=dir.join(format!(".qrx-passphrase-{nonce}-{idx}.pem"));
        fs::write(&tmp,&bytes).map_err(|e|format!("Could not write temporary key {}: {e}",tmp.display()))?;
        if !encrypted_pem_accepts_passphrase(&tmp,&new_passphrase){ let _=fs::remove_file(&tmp); return Err("New encrypted private key failed verification; original wallet was not modified.".into()); }
        temps.push(tmp);
    }
    let olds=[dir.join(format!(".qrx-old-ed25519-{nonce}.pem")),dir.join(format!(".qrx-old-mldsa65-{nonce}.pem"))];
    if let Err(e)=fs::rename(&paths[0],&olds[0]){ for t in &temps{let _=fs::remove_file(t);} return Err(format!("Could not stage original Ed25519 key: {e}")); }
    if let Err(e)=fs::rename(&paths[1],&olds[1]){ let _=fs::rename(&olds[0],&paths[0]); for t in &temps{let _=fs::remove_file(t);} return Err(format!("Could not stage original ML-DSA65 key: {e}")); }
    let install = (|| -> Result<(),String>{ fs::rename(&temps[0],&paths[0]).map_err(|e|e.to_string())?; fs::rename(&temps[1],&paths[1]).map_err(|e|e.to_string())?; Ok(()) })();
    if let Err(e)=install { let _=fs::remove_file(&paths[0]); let _=fs::remove_file(&paths[1]); let _=fs::rename(&olds[0],&paths[0]); let _=fs::rename(&olds[1],&paths[1]); for t in &temps{let _=fs::remove_file(t);} return Err(format!("Could not install re-encrypted keys; original keys restored: {e}")); }
    if !encrypted_pem_accepts_passphrase(&paths[0],&new_passphrase) || !encrypted_pem_accepts_passphrase(&paths[1],&new_passphrase){ let _=fs::remove_file(&paths[0]); let _=fs::remove_file(&paths[1]); let _=fs::rename(&olds[0],&paths[0]); let _=fs::rename(&olds[1],&paths[1]); return Err("Post-write verification failed; original keys restored.".into()); }
    let identity_ok=(|| -> Result<bool,String>{
        if fs::read(dir.join("address.txt")).map_err(|e|e.to_string())? != address_before { return Ok(false); }
        for (idx,path) in paths.iter().enumerate(){
            let pem=fs::read(path).map_err(|e|e.to_string())?;
            let key=PKey::private_key_from_pem_passphrase(&pem,new_passphrase.as_bytes()).map_err(|e|e.to_string())?;
            if key.public_key_to_der().map_err(|e|e.to_string())? != public_before[idx] { return Ok(false); }
        }
        Ok(true)
    })().unwrap_or(false);
    if !identity_ok { let _=fs::remove_file(&paths[0]); let _=fs::remove_file(&paths[1]); let _=fs::rename(&olds[0],&paths[0]); let _=fs::rename(&olds[1],&paths[1]); return Err("Identity verification failed after re-encryption; original keys restored.".into()); }
    let _=fs::remove_file(&olds[0]); let _=fs::remove_file(&olds[1]);
    let passphrase_hex:String=new_passphrase.as_bytes().iter().map(|b|format!("{b:02x}")).collect();
    run_cli(Some(&app),&network,&wallet,&["walletpassphrasehexfor",&wallet,&passphrase_hex],None).map_err(|e|format!("Keys were re-encrypted, but the daemon signer session could not be refreshed: {e}"))?;
    Ok(WalletPassphraseChangeResult{wallet,backup_path,passphrase_state:"passphrase-required-to-use-private-keys".into(),changed_files:paths.iter().map(|p|p.to_string_lossy().to_string()).collect()})
}

#[tauri::command]
fn migrate_legacy_default_passphrase(app: tauri::AppHandle, network: Option<String>, wallet: String, new_passphrase: String) -> Result<WalletPassphraseChangeResult, String> {
    let net=network.unwrap_or_else(||"mainnet".into());
    let wallet=sanitize_wallet_name(&wallet).map_err(String::from)?;
    if !detect_legacy_default_passphrase(Some(net.clone()),wallet.clone())? {
        return Err("This wallet was not verified as a historical default-passphrase wallet; no migration was performed.".into());
    }
    change_wallet_passphrase(app,Some(net),wallet,"change-me".into(),new_passphrase)
}

#[tauri::command]
fn wallet_session_status(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<bool, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    match run_cli(Some(&app), &network, &wallet, &["walletsessionstatusfor", &wallet], None) {
        Ok(r) => Ok(r.result.get("unlocked").and_then(Value::as_bool).unwrap_or(false)),
        Err(_) => Ok(false),
    }
}

#[tauri::command]
fn lock_wallet_session(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<bool, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    // An offline daemon is already effectively locked.
    let _ = run_cli(Some(&app), &network, &wallet, &["walletlockfor", &wallet], None);
    Ok(true)
}

#[tauri::command]
fn import_key_set_directory(network: Option<String>, wallet: String, source_dir: String) -> Result<KeySetImportResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let source = PathBuf::from(source_dir);
    if !source.is_dir() { return Err("Key-set source directory not found".into()); }
    let required = ["address.txt","ed25519_priv.pem","ed25519_pub.pem","mldsa65_priv.pem","mldsa65_pub.pem"];
    for name in required { if !source.join(name).is_file() { return Err(format!("Key-set folder is missing required file: {name}")); } }
    let target = wallet_dir(&network, &wallet).map_err(String::from)?;
    if target.exists() { return Err("Target wallet already exists; refusing to overwrite any wallet or key data".into()); }
    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    let mut copied = Vec::new();
    for name in ["address.txt","ed25519_priv.pem","ed25519_pub.pem","mldsa65_priv.pem","mldsa65_pub.pem","recovery.qrxseed"] {
        let src=source.join(name); if src.is_file(){ let dst=target.join(name); fs::copy(&src,&dst).map_err(|e|e.to_string())?; copied.push(dst.to_string_lossy().to_string()); }
    }
    let wallet_json=source.join("wallet.json");
    if wallet_json.is_file(){ let dst=target.join("wallet.json"); fs::copy(wallet_json,&dst).map_err(|e|e.to_string())?; copied.push(dst.to_string_lossy().to_string()); }
    else {
        let address=read_address(&target).ok_or_else(||"Imported key set has no readable address.txt".to_string())?;
        let manifest=serde_json::json!({"wallet_version": CURRENT_QRX_WALLET_VERSION,"address":address,"signature_scheme":"ed25519+mldsa65","recovery_scheme": if target.join("recovery.qrxseed").is_file(){"imported-recovery-file"}else{"none"},"created_unix": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs(),"imported_key_set":true});
        let dst=target.join("wallet.json"); fs::write(&dst,serde_json::to_vec_pretty(&manifest).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?; copied.push(dst.to_string_lossy().to_string());
    }
    let inspection=inspect_wallet_inner(&network,&wallet).map_err(String::from)?;
    Ok(KeySetImportResult{wallet:ensure_context(&network,&wallet).map_err(String::from)?,copied_files:copied,inspection})
}

fn legacy_gui_data_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        #[cfg(target_os = "macos")]
        roots.push(home.join("Library").join("Application Support").join("gui-wallet").join("qrx-data"));
        #[cfg(target_os = "linux")]
        roots.push(home.join(".local").join("share").join("gui-wallet").join("qrx-data"));
    }
    if let Some(local) = dirs::data_local_dir() {
        roots.push(local.join("gui-wallet").join("qrx-data"));
    }
    roots.sort();
    roots.dedup();
    roots
}

#[tauri::command]
fn list_legacy_gui_wallets(network: Option<String>) -> Result<Vec<LegacyGuiWalletCandidate>, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let shared = wallet_root(&network).map_err(String::from)?;
    let mut out = Vec::new();
    for base in legacy_gui_data_roots() {
        let root = base.join(&network).join("wallets");
        if !root.is_dir() { continue; }
        for entry in fs::read_dir(&root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if !path.is_dir() { continue; }
            let name = entry.file_name().to_string_lossy().to_string();
            if !path.join("address.txt").is_file() { continue; }
            out.push(LegacyGuiWalletCandidate {
                name: name.clone(),
                path: path.to_string_lossy().to_string(),
                address: read_address(&path),
                wallet_version: read_wallet_version(&path),
                has_recovery_file: path.join("recovery.qrxseed").is_file(),
                already_in_shared_store: shared.join(&name).exists(),
            });
        }
    }
    out.sort_by(|a,b| a.name.cmp(&b.name).then(a.path.cmp(&b.path)));
    out.dedup_by(|a,b| a.path == b.path);
    Ok(out)
}

#[tauri::command]
async fn import_legacy_gui_wallet(network: Option<String>, wallet: String, source_dir: String) -> Result<ImportResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let source = PathBuf::from(&source_dir);
    let canonical_source = source.canonicalize().map_err(|e| format!("Legacy wallet source is unavailable: {e}"))?;
    let mut allowed = false;
    for base in legacy_gui_data_roots() {
        let root = base.join(&network).join("wallets");
        if let Ok(canon_root) = root.canonicalize() {
            if canonical_source.starts_with(&canon_root) { allowed = true; break; }
        }
    }
    if !allowed { return Err("Refusing legacy import from an unrecognized GUI wallet store".into()); }
    import_wallet_directory_blocking(Some(network), wallet, canonical_source.to_string_lossy().to_string())
}

#[tauri::command]
fn list_legacy_network_wallets() -> Result<Vec<LegacyNetworkWalletGroup>, String> {
    use std::collections::{BTreeMap, BTreeSet};
    let root = app_data_dir().map_err(String::from)?;
    let shared_root = wallet_root("alpha").map_err(String::from)?;
    let mut by_name: BTreeMap<String, Vec<LegacyNetworkWalletCandidate>> = BTreeMap::new();
    for network in ["mainnet", "alpha", "testnet", "regtest"] {
        let wallets_root = root.join(network).join("wallets");
        if !wallets_root.is_dir() { continue; }
        for entry in fs::read_dir(&wallets_root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if !path.is_dir() { continue; }
            let name = entry.file_name().to_string_lossy().to_string();
            if sanitize_wallet_name(&name).is_err() { continue; }
            let hybrid_ready = ["ed25519_priv.pem", "ed25519_pub.pem", "mldsa65_priv.pem", "mldsa65_pub.pem"]
                .iter().all(|f| path.join(f).is_file());
            by_name.entry(name.clone()).or_default().push(LegacyNetworkWalletCandidate {
                name, network: network.to_string(), path: path.to_string_lossy().to_string(),
                address: read_address(&path), has_recovery_file: path.join("recovery.qrxseed").is_file(),
                wallet_version: read_wallet_version(&path), hybrid_ready,
            });
        }
    }
    let mut groups = Vec::new();
    for (name, candidates) in by_name {
        let shared = shared_root.join(&name);
        let shared_exists = shared.is_dir();
        let shared_address = if shared_exists { read_address(&shared) } else { None };
        let mut addresses = BTreeSet::new();
        for c in &candidates { if let Some(a)=&c.address { addresses.insert(a.clone()); } }
        if let Some(a)=&shared_address { addresses.insert(a.clone()); }
        let all_candidates_identified = candidates.iter().all(|c| c.address.is_some());
        let conflict = addresses.len() > 1 || (candidates.len() > 1 && (!all_candidates_identified || addresses.len() != 1));
        groups.push(LegacyNetworkWalletGroup {
            name, shared_exists, shared_address,
            conflict,
            unique_addresses: addresses.into_iter().collect(), candidates,
        });
    }
    Ok(groups)
}

#[tauri::command]
fn migrate_legacy_network_wallet(source_network: String, wallet: String, target_wallet: String) -> Result<WalletInspection, String> {
    let source_network = source_network.to_lowercase();
    if !["mainnet","alpha","testnet","regtest"].contains(&source_network.as_str()) { return Err("Invalid source network".into()); }
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let target_wallet = sanitize_wallet_name(&target_wallet).map_err(String::from)?;
    let root = app_data_dir().map_err(String::from)?;
    let source = root.join(&source_network).join("wallets").join(&wallet);
    if !source.is_dir() { return Err("Selected legacy wallet source no longer exists".into()); }
    let shared_root = wallet_root("alpha").map_err(String::from)?;
    let target = shared_root.join(&target_wallet);
    if target.exists() { return Err(format!("Shared wallet '{}' already exists. Choose a new wallet name; existing identities are never overwritten.", target_wallet)); }
    copy_dir_recursive(&source, &target).map_err(String::from)?;
    let marker = serde_json::json!({
        "migration":"explicit-network-wallet-import",
        "source_network":source_network,
        "source":source.to_string_lossy(),
        "destination":target.to_string_lossy(),
        "source_wallet_name":wallet,
        "target_wallet_name":target_wallet,
        "address":read_address(&target),
        "policy":"explicit user choice; copy-only; source preserved; no overwrite",
        "created_unix":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_secs()
    });
    fs::write(target.join("QRX_SHARED_IDENTITY_MIGRATION.json"), serde_json::to_vec_pretty(&marker).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    inspect_wallet_inner("alpha", &target_wallet).map_err(String::from)
}

fn parse_kv_i64(map: &std::collections::HashMap<String,String>, key: &str) -> i64 {
    map.get(key).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0)
}

fn parse_qrx_kv(text: &str) -> std::collections::HashMap<String,String> {
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k,v)) = line.split_once('=') { out.insert(k.trim().to_string(), v.trim().to_string()); }
    }
    out
}

#[tauri::command]
fn validator_fleet_status(app: tauri::AppHandle, network: Option<String>) -> Result<Vec<ValidatorFleetItem>, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallets = list_wallets(Some(network.clone()))?;
    let chain_dir = app_data_dir().map_err(String::from)?.join(&network).join("chain");
    let mut out = Vec::with_capacity(wallets.len());
    for w in wallets {
        let enabled = read_validator_mode(&network, &w.name).unwrap_or(false);
        let mut item = ValidatorFleetItem {
            wallet: w.name.clone(), address: w.address.clone(), validator_mode_enabled: enabled,
            is_bootstrap:false, bootstrap_lock_active:false, bootstrap_principal_atoms:0,
            bootstrap_lock_until_height:0, liveness_slash_grace_active:false, double_sign_slashing_active:true,
            self_stake_atoms:0, locked_self_stake_atoms:0, freely_unstakeable_self_stake_atoms:0,
            spendable_balance_atoms:0, status_note:String::new()
        };
        if let Some(addr) = w.address.as_deref() {
            if chain_dir.is_dir() {
                let chain_s = chain_dir.to_string_lossy().to_string();
                match run_qrx(Some(&app), &["bootstrap-validator-status", &chain_s, addr], None, None) {
                    Ok(raw) => {
                        let kv = parse_qrx_kv(&raw);
                        item.is_bootstrap = parse_kv_i64(&kv,"is_bootstrap") == 1;
                        item.bootstrap_lock_active = parse_kv_i64(&kv,"bootstrap_lock_active") == 1;
                        item.bootstrap_principal_atoms = parse_kv_i64(&kv,"bootstrap_principal");
                        item.bootstrap_lock_until_height = parse_kv_i64(&kv,"bootstrap_lock_until_height");
                        item.liveness_slash_grace_active = parse_kv_i64(&kv,"liveness_slash_grace_active") == 1;
                        item.double_sign_slashing_active = parse_kv_i64(&kv,"double_sign_slashing_active") == 1;
                        item.self_stake_atoms = parse_kv_i64(&kv,"self_stake");
                        item.locked_self_stake_atoms = parse_kv_i64(&kv,"locked_self_stake");
                        item.freely_unstakeable_self_stake_atoms = parse_kv_i64(&kv,"freely_unstakeable_self_stake");
                        item.spendable_balance_atoms = parse_kv_i64(&kv,"spendable_balance");
                        item.status_note = if item.is_bootstrap && item.bootstrap_lock_active {
                            "Bootstrap principal locked; rewards/incoming QUB remain free. Offline slashing grace active; double-sign slashing active.".into()
                        } else if item.is_bootstrap {
                            "Bootstrap lock ended; normal validator slashing rules apply.".into()
                        } else { "Normal wallet/validator identity.".into() };
                    }
                    Err(e) => item.status_note = format!("Chain status unavailable: {e}"),
                }
            } else { item.status_note = "Chain is not initialized yet.".into(); }
        } else { item.status_note = "Wallet address unavailable.".into(); }
        out.push(item);
    }
    Ok(out)
}

#[tauri::command]
fn set_validator_fleet_modes(app: tauri::AppHandle, state: tauri::State<DaemonState>, network: Option<String>, wallets: Vec<String>, enabled: bool) -> Result<ValidatorFleetModeResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let mut changed = 0usize;
    for wallet in wallets {
        let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
        write_validator_mode(&network, &wallet, enabled).map_err(String::from)?;
        changed += 1;
    }
    let all = list_wallets(Some(network.clone()))?;
    let enabled_wallets: Vec<String> = all.into_iter().filter(|w| read_validator_mode(&network,&w.name).unwrap_or(false)).map(|w|w.name).collect();
    let selected_wallet = enabled_wallets.first().cloned().unwrap_or_else(|| "node1".into());
    let health = daemon_health_inner(Some(&app), &state, &network, &selected_wallet, None).ok();
    let daemon_running = health.as_ref().map(|h|h.running).unwrap_or(false);
    let mut runtime_applied=false; let mut restart_required=false;
    let mut message = if daemon_running { "Validator Mode saved; applying signer fleet to the running node.".to_string() } else { "Validator Mode saved; it will be used when the node starts.".to_string() };
    if daemon_running {
        let csv = if enabled_wallets.is_empty(){"-".to_string()}else{enabled_wallets.join(",")};
        let rpc_wallet = health.as_ref().and_then(|h|h.actual_wallet.clone()).unwrap_or_else(||selected_wallet.clone());
        match run_cli(Some(&app),&network,&rpc_wallet,&["setvalidatorfleet",&csv],None) {
            Ok(_) => { runtime_applied=true; message="Validator signer fleet updated immediately. No node restart was needed and no QUB moved.".into(); },
            Err(e) => { restart_required=true; message=format!("Validator Mode was saved, but the running node could not hot-reload the signer fleet: {e}. Restart the node when convenient."); }
        }
    }
    Ok(ValidatorFleetModeResult{changed,daemon_running,runtime_applied,restart_required,validator_fleet_count:enabled_wallets.len(),message})
}

#[tauri::command]
fn get_context(network: Option<String>, wallet: Option<String>) -> Result<WalletContext, String> {
    ensure_context(
        network.as_deref().unwrap_or("mainnet"),
        wallet.as_deref().unwrap_or("node1"),
    )
    .map_err(Into::into)
}

fn wallet_directory_has_entries(path: &Path) -> std::io::Result<bool> {
    Ok(fs::read_dir(path)?.next().transpose()?.is_some())
}

fn ensure_new_wallet_target(target: &Path) -> Result<(), String> {
    if target.exists() && wallet_directory_has_entries(target).map_err(|e| e.to_string())? {
        return Err("Wallet directory already contains files; refusing to overwrite existing wallet data. Choose another name or open/import the existing wallet.".into());
    }
    Ok(())
}

#[tauri::command]
fn list_wallets(network: Option<String>) -> Result<Vec<WalletListItem>, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let root = wallet_root(&network).map_err(String::from)?;
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    let mut wallets = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // A failed creation in an older build can leave an empty directory.
        // Keep incomplete/nonempty wallets visible, but do not offer empty ones.
        if !wallet_directory_has_entries(&path).map_err(|e| e.to_string())? {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let wallet_version = read_wallet_version(&path);
        let legacy_or_unknown = wallet_version.map(|v| v < CURRENT_QRX_WALLET_VERSION).unwrap_or(true);
        wallets.push(WalletListItem {
            name: name.clone(),
            path: path.to_string_lossy().to_string(),
            address: read_address(&path),
            has_recovery_file: path.join("recovery.qrxseed").exists(),
            wallet_version,
            legacy_or_unknown,
            safety_backup_exists: safety_backup_exists(&network, &name),
        });
    }

    wallets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(wallets)
}

#[tauri::command]
async fn prepare_existing_wallet(
    network: Option<String>,
    wallet: String,
) -> Result<ExistingWalletPrepareResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;

    tauri::async_runtime::spawn_blocking(move || {
        let source = wallet_dir(&network, &wallet).map_err(String::from)?;
        if !source.is_dir() {
            return Err("Existing QRX wallet directory does not exist".into());
        }
        let (source_files, _) = directory_copy_stats(&source).map_err(String::from)?;
        if source_files == 0 {
            return Err("Existing QRX wallet directory is empty".into());
        }

        let wallet_version = read_wallet_version(&source);
        let legacy_or_unknown = wallet_version
            .map(|v| v < CURRENT_QRX_WALLET_VERSION)
            .unwrap_or(true);

        let mut backup_created = false;
        let mut backup_path = None;
        if legacy_or_unknown && !safety_backup_exists(&network, &wallet) {
            let path = create_pre_007_safety_backup(&network, &wallet).map_err(String::from)?;
            backup_created = true;
            backup_path = Some(path);
        } else if legacy_or_unknown {
            // A prior pre-0.0.7 safety backup already exists; never overwrite it.
            backup_path = wallet_backup_root(&network, &wallet)
                .ok()
                .map(|p| p.to_string_lossy().to_string());
        }

        Ok(ExistingWalletPrepareResult {
            wallet: ensure_context(&network, &wallet).map_err(String::from)?,
            wallet_version,
            legacy_or_unknown,
            backup_created,
            backup_path,
        })
    })
    .await
    .map_err(|e| format!("Existing-wallet preparation worker failed: {e}"))?
}

#[tauri::command]
fn create_wallet(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: String,
    passphrase: String,
) -> Result<CreateWalletResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    if passphrase.trim().is_empty() {
        return Err("Passphrase is required".into());
    }

    let target = wallet_dir(&network, &wallet).map_err(String::from)?;
    ensure_new_wallet_target(&target)?;

    // Core creates the directory after the bundled executable has been found.
    let output = run_qrx(
        Some(&app),
        &["seed-new", target.to_string_lossy().as_ref()],
        Some(passphrase.trim()),
        None,
    )
    .map_err(String::from)?;

    let parsed = parse_key_value_lines(&output);
    Ok(CreateWalletResult {
        wallet: ensure_context(&network, &wallet).map_err(String::from)?,
        address: parsed
            .get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        recovery_phrase: parsed
            .get("recovery_phrase")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        output,
    })
}

#[tauri::command]
fn refresh_recovery_backup(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: String,
    passphrase: String,
) -> Result<RecoveryRefreshResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let dir = wallet_dir(&network, &wallet).map_err(String::from)?;
    if !dir.is_dir() { return Err("Wallet directory does not exist".into()); }
    let safety_backup = create_wallet_security_backup(&network, &wallet, "pre-recovery-refresh").map_err(String::from)?;
    let output = run_qrx(
        Some(&app),
        &["wallet-recovery-refresh", dir.to_string_lossy().as_ref()],
        Some(&passphrase),
        None,
    ).map_err(String::from)?;
    let parsed = parse_key_value_lines(&output);
    let phrase = parsed.get("recovery_phrase").and_then(|v|v.as_str()).unwrap_or("").to_string();
    if phrase.is_empty() { return Err("Core did not return a recovery phrase".into()); }
    Ok(RecoveryRefreshResult {
        wallet,
        address: parsed.get("address").and_then(|v|v.as_str()).map(|v|v.to_string()),
        recovery_phrase: phrase,
        recovery_file: dir.join("recovery.qrxseed").to_string_lossy().to_string(),
        safety_backup,
    })
}

#[tauri::command]
fn export_recovery_file(
    network: Option<String>,
    wallet: String,
    destination_file: String,
) -> Result<String, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let source = wallet_dir(&network, &wallet).map_err(String::from)?.join("recovery.qrxseed");
    if !source.is_file() { return Err("This wallet has no recovery.qrxseed yet".into()); }
    let destination = PathBuf::from(destination_file);
    if let Some(parent)=destination.parent(){ fs::create_dir_all(parent).map_err(|e|e.to_string())?; }
    fs::copy(&source,&destination).map_err(|e|format!("Could not save recovery file: {e}"))?;
    let src_len=fs::metadata(&source).map_err(|e|e.to_string())?.len();
    let dst_len=fs::metadata(&destination).map_err(|e|e.to_string())?.len();
    if src_len!=dst_len { return Err("Recovery file verification failed after copy".into()); }
    Ok(destination.to_string_lossy().to_string())
}

#[tauri::command]
fn restore_wallet_from_recovery(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: String,
    recovery_file: String,
    recovery_phrase: String,
    passphrase: String,
) -> Result<WalletContext, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let target = wallet_dir(&network, &wallet).map_err(String::from)?;

    if target.exists() && target.join("wallet.json").exists() {
        return Err("Target wallet already exists".into());
    }
    let recovery = PathBuf::from(&recovery_file);
    if !recovery.exists() {
        return Err("Recovery file not found".into());
    }
    if recovery_phrase.trim().is_empty() {
        return Err("Recovery phrase is required".into());
    }
    if passphrase.trim().is_empty() {
        return Err("New passphrase is required".into());
    }

    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    let input = format!("{}\n", recovery_phrase.trim());
    run_qrx(
        Some(&app),
        &[
            "wallet-recover",
            target.to_string_lossy().as_ref(),
            recovery.to_string_lossy().as_ref(),
        ],
        Some(passphrase.trim()),
        Some(&input),
    )
    .map_err(String::from)?;

    Ok(ensure_context(&network, &wallet).map_err(String::from)?)
}

fn import_wallet_directory_blocking(
    network: Option<String>,
    wallet: String,
    source_dir: String,
) -> Result<ImportResult, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    let source = PathBuf::from(&source_dir);
    if !source.exists() || !source.is_dir() {
        return Err("Source wallet directory not found".into());
    }
    if !source.join("wallet.json").exists() {
        return Err("Source directory does not look like a QUBITCOIN wallet".into());
    }

    let target = wallet_dir(&network, &wallet).map_err(String::from)?;
    // Imports are copy-only and must never overwrite any existing target,
    // even a partially created directory. Existing Core wallets are used
    // directly through the shared ~/.qrx data root and do not need import.
    if target.exists() {
        return Err("Target path already exists; refusing to overwrite any wallet data".into());
    }

    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    let imported_files = copy_dir_recursive(&source, &target).map_err(String::from)?;
    Ok(ImportResult {
        wallet: ensure_context(&network, &wallet).map_err(String::from)?,
        imported_files,
    })
}

#[tauri::command]
async fn import_wallet_directory(
    network: Option<String>,
    wallet: String,
    source_dir: String,
) -> Result<ImportResult, String> {
    // Directory copies can be slow (large wallets, APFS/iCloud/external disks).
    // Keep all filesystem traversal/copy work off the webview/main event loop.
    tauri::async_runtime::spawn_blocking(move || {
        import_wallet_directory_blocking(network, wallet, source_dir)
    })
    .await
    .map_err(|e| format!("Wallet import worker failed: {e}"))?
}

#[tauri::command]
fn export_wallet_directory(
    network: Option<String>,
    wallet: Option<String>,
    destination_dir: String,
) -> Result<String, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let source = wallet_dir(&network, &wallet).map_err(String::from)?;
    if !source.exists() {
        return Err("Wallet directory not found".into());
    }
    let destination = PathBuf::from(destination_dir).join(format!("gui-wallet-backup-{wallet}"));
    if destination.exists() {
        return Err("Destination folder already exists".into());
    }
    copy_dir_recursive(&source, &destination).map_err(String::from)?;
    Ok(destination.to_string_lossy().to_string())
}

#[tauri::command]
fn daemon_health(
    app: tauri::AppHandle,
    state: tauri::State<DaemonState>,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<DaemonHealth, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    daemon_health_inner(Some(&app), &state, &network, &wallet, passphrase.as_deref()).map_err(String::from)
}

#[tauri::command]
fn start_daemon(
    app: tauri::AppHandle,
    state: tauri::State<DaemonState>,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
    validator_enabled: Option<bool>,
) -> Result<WalletContext, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let requested_validator_mode = validator_enabled.unwrap_or(read_validator_mode(&network, &wallet).unwrap_or(false));
    write_validator_mode(&network, &wallet, requested_validator_mode).map_err(String::from)?;
    let mut ctx = ensure_context(&network, &wallet).map_err(String::from)?;

    let health = daemon_health_inner(Some(&app), &state, &network, &wallet, passphrase.as_deref())
        .map_err(String::from)?;
    if health.running {
        if health.wallet_mismatch || health.data_root_mismatch {
            return Err(format!(
                "A different QRX daemon is already using this network RPC port (running wallet: {}, path: {}). Stop that node first, then start wallet {}.",
                health.actual_wallet.as_deref().unwrap_or("unknown"),
                health.actual_wallet_dir.as_deref().unwrap_or("unknown"),
                wallet
            ));
        }
        ctx.daemon_running = true;
        return Ok(ctx);
    }

    let child = spawn_daemon(&app, &network, &wallet, passphrase.as_deref(), requested_validator_mode).map_err(String::from)?;
    {
        let mut guard = state.child.lock().map_err(|_| "Daemon mutex poisoned".to_string())?;
        *guard = Some(child);
    }

    std::thread::sleep(Duration::from_millis(1100));
    let health = daemon_health_inner(Some(&app), &state, &network, &wallet, passphrase.as_deref())
        .map_err(String::from)?;
    ctx.daemon_running = health.running;
    if !health.running {
        return Err(format!(
            "qrxd started but did not answer on the HTTP RPC endpoint. Check logs at {}",
            health.stderr_log
        ));
    }
    Ok(ctx)
}

#[tauri::command]
fn stop_daemon(
    app: tauri::AppHandle,
    state: tauri::State<DaemonState>,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<bool, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let _ = run_cli(Some(&app), &network, &wallet, &["stop"], passphrase.as_deref());

    let mut guard = state.child.lock().map_err(|_| "Daemon mutex poisoned".to_string())?;
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(true)
}

#[tauri::command]
fn get_validator_mode(network: Option<String>, wallet: Option<String>) -> Result<ValidatorModeStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let enabled = read_validator_mode(&network, &wallet).map_err(String::from)?;
    Ok(ValidatorModeStatus {
        validator_enabled: enabled,
        wallet_mode_safe: !enabled,
        min_validator_self_stake_qub: "100 QUB".into(),
        double_sign_slash: "50% of validator power + tombstone".into(),
        offline_penalty: "Home profile: first 72h offline = no liveness slash; then 0.05% per 24h, capped at 1% per continuous outage; temporary 1h jail only after 7 days offline. Bootstrap validators keep their separate 180-day 0-QUB liveness-slash grace.".into(),
        best_practice: "Home Validator Mode is supported: after reconnect QRX pauses signing while catching up, waits until it is within 2 blocks of peer head and stable for 30 seconds, then resumes automatically. Avoid running the same validator keys on two machines at once.".into(),
    })
}

#[tauri::command]
fn set_validator_mode(network: Option<String>, wallet: Option<String>, enabled: bool) -> Result<ValidatorModeStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    write_validator_mode(&network, &wallet, enabled).map_err(String::from)?;
    get_validator_mode(Some(network), Some(wallet))
}

#[tauri::command]
fn get_wallet_info(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getwalletinfo"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_balance(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getbalance"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_new_address(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getnewaddress"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn list_addresses(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["listaddresses"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_wallet_address_set(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<WalletAddressSet, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let dir = wallet_dir(&network, &wallet).map_err(String::from)?;
    if !dir.is_dir() { return Err("Wallet directory does not exist".into()); }

    // address.txt is the canonical wallet identity. Never infer the primary
    // address from listaddresses ordering; 0.0.6 wallets can have a different
    // addresses.txt order after additional receive addresses were generated.
    let primary_address = read_address(&dir);
    let manifest_address = read_manifest_address(&dir);
    let address_mismatch = primary_address.is_some() && manifest_address.is_some() && primary_address != manifest_address;
    let mut warnings = Vec::new();
    if address_mismatch {
        warnings.push("WALLET ADDRESS MISMATCH: address.txt differs from wallet.json. address.txt remains canonical; do not sign until the wallet is inspected.".to_string());
    }

    let mut addresses = Vec::<String>::new();
    if let Some(primary) = primary_address.as_ref() { addresses.push(primary.clone()); }
    match run_cli(Some(&app), &network, &wallet, &["listaddresses"], passphrase.as_deref()) {
        Ok(result) => {
            for addr in addresses_from_value(&result.result) {
                if !addresses.iter().any(|a| a == &addr) { addresses.push(addr); }
            }
        }
        Err(e) => warnings.push(format!("listaddresses unavailable; showing addresses known from wallet files only: {e}")),
    }
    let additional_addresses = addresses.iter()
        .filter(|a| primary_address.as_ref().map(|p| p != *a).unwrap_or(true))
        .cloned().collect();
    Ok(WalletAddressSet { wallet, primary_address, manifest_address, addresses, additional_addresses, address_mismatch, warnings })
}

#[tauri::command]
fn get_address_privacy_context(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let aset = get_wallet_address_set(app.clone(), Some(network.clone()), Some(wallet.clone()), passphrase.clone())?;
    let mut rows = Vec::<Value>::new();
    for (idx, address) in aset.addresses.iter().enumerate() {
        let balance_result = run_cli(Some(&app), &network, &wallet, &["getbalance", address], passphrase.as_deref());
        let balance = balance_result.ok().and_then(|r| {
            if let Some(n)=r.result.as_f64(){Some(n)}
            else if let Some(n)=r.result.get("balance").and_then(Value::as_f64){Some(n)}
            else if let Some(s)=r.result.get("balance").and_then(Value::as_str){s.parse::<f64>().ok()}
            else if let Some(s)=r.result.as_str(){s.parse::<f64>().ok()} else {None}
        });
        let hist = run_cli(Some(&app), &network, &wallet, &["history", address, "200"], passphrase.as_deref()).ok();
        let history_count = hist.as_ref().map(|r| {
            r.result.get("entries").and_then(Value::as_array).map(|a|a.len())
                .or_else(||r.result.as_array().map(|a|a.len())).unwrap_or(0)
        }).unwrap_or(0);
        rows.push(serde_json::json!({
            "address": address,
            "balance": balance,
            "history_count": history_count,
            "primary": aset.primary_address.as_ref().map(|a|a==address).unwrap_or(idx==0),
            "reused": history_count > 1
        }));
    }
    let address_count = rows.len();
    let reused_any = rows.iter().any(|r| r.get("reused").and_then(Value::as_bool).unwrap_or(false));
    Ok(serde_json::json!({
        "wallet": wallet,
        "network": network,
        "addresses": rows,
        "address_count": address_count,
        "privacy_score": if reused_any { 70 } else { 100 }
    }))
}

#[tauri::command]
fn get_history(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    limit: Option<u32>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let limit = limit.unwrap_or(20);
    let res = if limit == 20 {
        run_cli(Some(&app), &network, &wallet, &["history"], passphrase.as_deref())
    } else {
        let info = run_cli(Some(&app), &network, &wallet, &["getwalletinfo"], passphrase.as_deref())?;
        let address = info.result.get("address").and_then(Value::as_str)
            .ok_or_else(|| AppError::Message("getwalletinfo did not return an address".into()))?;
        let limit_s = limit.to_string();
        run_cli(Some(&app), &network, &wallet, &["history", address, &limit_s], passphrase.as_deref())
    }.map_err(String::from)?;
    Ok(res.result)
}

#[tauri::command]
fn get_staking_info(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getstakinginfo"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_validators(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["validator-set"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_tokenomics(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["tokenomics"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_protocol_info(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getprotocolinfo"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn markets_snapshot(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, market: String, depth: Option<u32>, trade_limit: Option<u32>, passphrase: Option<String>) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"mainnet".into());
    let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let market=required_clean(&market,"Market")?; if !market.contains('/') { return Err("Market must look like ASSET/QUB".into()); }
    let depth=depth.unwrap_or(30).clamp(1,200).to_string(); let limit=trade_limit.unwrap_or(500).clamp(1,5000).to_string();
    let book=run_cli(Some(&app),&network,&wallet,&["getorderbook",&market,&depth],passphrase.as_deref()).map_err(String::from)?.result;
    let trades=run_cli(Some(&app),&network,&wallet,&["listtrades",&market,&limit],passphrase.as_deref()).map_err(String::from)?.result;
    Ok(serde_json::json!({"network":network,"market":market,"source":"QRX_CHAIN","verifiable":true,"orderbook":book,"trades":trades}))
}

#[tauri::command]
fn markets_place_order(app:tauri::AppHandle, network:Option<String>, wallet:Option<String>, agent:String, owner:String, market:String, side:String, quantity_atoms:String, limit_price_atoms:String, order_expiry_height:String, agent_ed_pub:String, agent_mldsa_pub:String, lane:String, tx_expiry:String, passphrase:Option<String>) -> Result<CommandResult,String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let side=side.trim().to_uppercase(); if side!="BUY"&&side!="SELL" {return Err("Side must be BUY or SELL".into())} if !market.contains('/') {return Err("Invalid market".into())}
    positive_u64(&quantity_atoms,"Quantity atoms")?; positive_u64(&limit_price_atoms,"Limit price atoms")?; positive_u64(&order_expiry_height,"Order expiry")?; positive_u64(&tx_expiry,"Transaction expiry")?;
    let created=run_cli(Some(&app),&network,&wallet,&["createordertransaction",agent.trim(),owner.trim(),market.trim(),&side,"LIMIT",quantity_atoms.trim(),limit_price_atoms.trim(),order_expiry_height.trim(),agent_ed_pub.trim(),agent_mldsa_pub.trim(),lane.trim(),tx_expiry.trim()],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;
    sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"native-market-order")
}

#[tauri::command]
fn markets_cancel_order(app:tauri::AppHandle, network:Option<String>, wallet:Option<String>, agent:String, owner:String, order_id:String, agent_ed_pub:String, agent_mldsa_pub:String, lane:String, tx_expiry:String, passphrase:Option<String>) -> Result<CommandResult,String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let created=run_cli(Some(&app),&network,&wallet,&["createordercanceltransaction",agent.trim(),owner.trim(),order_id.trim(),agent_ed_pub.trim(),agent_mldsa_pub.trim(),lane.trim(),tx_expiry.trim()],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;
    sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"native-market-cancel")
}

#[tauri::command]
fn get_node_info(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getinfo"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_mainnet_health(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getmainnethealth"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn get_peer_info(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["getpeerinfo"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn list_peers(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        network.as_deref().unwrap_or("mainnet"),
        &wallet,
        &["listpeers"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn send_to_address(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    to: String,
    amount: String,
    memo: Option<String>,
    source_address: Option<String>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    if to.trim().is_empty() {
        return Err("Recipient address is required".into());
    }
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let amount = parse_amount(&amount).map_err(String::from)?;
    let memo = memo.unwrap_or_default();

    let source = source_address.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let res = match (source, memo.trim().is_empty()) {
        (Some(src), true) => run_cli(Some(&app), &network, &wallet, &["sendfromaddress", src, to.trim(), &amount], passphrase.as_deref()),
        (Some(src), false) => run_cli(Some(&app), &network, &wallet, &["sendfromaddress", src, to.trim(), &amount, memo.trim()], passphrase.as_deref()),
        (None, true) => run_cli(Some(&app), &network, &wallet, &["sendtoaddress", to.trim(), &amount], passphrase.as_deref()),
        (None, false) => run_cli(Some(&app), &network, &wallet, &["sendtoaddress", to.trim(), &amount, memo.trim()], passphrase.as_deref()),
    }.map_err(String::from)?;

    Ok(res.result)
}

fn staking_consensus_broadcast(app:&tauri::AppHandle,network:&str,wallet:&str,tx_type:&str,to:Option<&str>,amount:&str,passphrase:Option<&str>)->Result<Value,String>{
    let address=generals_address(network,wallet)?; let (ed,ml)=generals_public_keys(network,wallet)?;
    let height=run_cli(Some(app),network,wallet,&["getblockcount"],passphrase).map_err(|e|e.to_string())?.result.get("count").and_then(Value::as_i64).or_else(||run_cli(Some(app),network,wallet,&["getblockcount"],passphrase).ok().and_then(|x|x.result.as_i64())).unwrap_or(0);
    let expiry=(height+240).to_string(); let target=to.unwrap_or(&address); let payload="phase=7.2.12";
    let created=run_cli(Some(app),network,wallet,&["createvelocitytransaction",&address,target,amount,&ed,&ml,tx_type,"1",&expiry,payload],passphrase).map_err(|e|e.to_string())?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"Core did not return a staking raw transaction".to_string())?;
    let sent=sign_and_broadcast_raw(app,network,wallet,raw,passphrase,"staking-consensus")?; Ok(sent.result)
}

#[tauri::command]
fn stake(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    amount: String,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    if !read_validator_mode(&network, &wallet).unwrap_or(false) {
        return Err("Validator Mode is disabled. Enable Validator Mode first and confirm the slashing/uptime risks.".into());
    }
    let amount = parse_amount(&amount).map_err(String::from)?;
    staking_consensus_broadcast(&app,&network,&wallet,"STAKE_BOND",None,&amount,passphrase.as_deref())
}

#[tauri::command]
fn validator_safe_pause(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, passphrase: Option<String>) -> Result<Value,String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    staking_consensus_broadcast(&app,&network,&wallet,"VALIDATOR_PAUSE",None,"0",passphrase.as_deref())
}

#[tauri::command]
fn validator_safe_resume(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, passphrase: Option<String>) -> Result<Value,String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    staking_consensus_broadcast(&app,&network,&wallet,"VALIDATOR_RESUME",None,"0",passphrase.as_deref())
}

#[tauri::command]
fn delegate(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    validator: String,
    amount: String,
    passphrase: Option<String>,
) -> Result<Value, String> {
    if validator.trim().is_empty() {
        return Err("Validator address is required".into());
    }
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let amount = parse_amount(&amount).map_err(String::from)?;
    staking_consensus_broadcast(&app,&network,&wallet,"DELEGATE_BOND",Some(validator.trim()),&amount,passphrase.as_deref())
}

#[tauri::command]
fn undelegate(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    validator: String,
    amount: String,
    passphrase: Option<String>,
) -> Result<Value, String> {
    if validator.trim().is_empty() { return Err("Validator address is required".into()); }
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let amount = parse_amount(&amount).map_err(String::from)?;
    staking_consensus_broadcast(&app,&network,&wallet,"DELEGATE_UNBOND",Some(validator.trim()),&amount,passphrase.as_deref())
}

#[tauri::command]
fn claim_undelegated(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    validator: String,
    passphrase: Option<String>,
) -> Result<Value, String> {
    if validator.trim().is_empty() { return Err("Validator address is required".into()); }
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    staking_consensus_broadcast(&app,&network,&wallet,"DELEGATE_CLAIM",Some(validator.trim()),"0",passphrase.as_deref())
}

#[tauri::command]
fn dashboard_snapshot(
    app: tauri::AppHandle,
    state: tauri::State<DaemonState>,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<UiStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let mut ctx = ensure_context(&network, &wallet).map_err(String::from)?;
    let daemon = daemon_health_inner(Some(&app), &state, &network, &wallet, passphrase.as_deref())
        .map_err(String::from)?;
    ctx.daemon_running = daemon.running;

    let wallet_info = get_wallet_info(app.clone(), Some(network.clone()), Some(wallet.clone()), passphrase.clone()).ok();
    let staking_info = get_staking_info(app.clone(), Some(network.clone()), Some(wallet.clone()), passphrase.clone()).ok();
    let validators = get_validators(app.clone(), Some(network.clone()), Some(wallet.clone()), passphrase.clone()).ok();
    let history = get_history(app.clone(), Some(network.clone()), Some(wallet.clone()), Some(20), passphrase.clone()).ok();
    let tokenomics = get_tokenomics(app.clone(), Some(network.clone()), Some(wallet.clone()), passphrase.clone()).ok();
    let peers = list_peers(app.clone(), Some(network.clone()), Some(wallet.clone()), passphrase.clone()).ok();
    let node_info = get_node_info(app, Some(network.clone()), Some(wallet.clone()), passphrase).ok();

    Ok(UiStatus {
        wallet: ctx,
        daemon,
        wallet_info,
        staking_info,
        validators,
        history,
        tokenomics,
        peers,
        node_info,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcLightStatus {
    mode: String,
    balance: String,
    confirmed_sats: u64,
    trusted_pending_sats: u64,
    untrusted_pending_sats: u64,
    immature_sats: u64,
    endpoint: String,
    active_endpoint: String,
    endpoints: Vec<String>,
    endpoint_health: Vec<EndpointHealth>,
    fallback_enabled: bool,
    privacy_level: String,
    neutrino_ready: bool,
    full_node_required: bool,
    synced: bool,
    explanation: String,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EndpointHealth {
    endpoint: String,
    status: String,
    latency_ms: Option<u128>,
    note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcReceiveAddress {
    address: String,
    status: String,
    note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcWalletInitResult {
    status: String,
    network: String,
    address: String,
    warning: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcBackupResult {
    status: String,
    mnemonic: String,
    warning: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcRestoreResult {
    status: String,
    network: String,
    first_address: String,
    warning: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcSendResult {
    txid: String,
    amount_sats: u64,
    recipient: String,
    endpoint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuraLocalReply {
    source: String,
    answer: String,
    command: Option<String>,
    needs_cloud: bool,
    token_hint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuraPlanStatus {
    active: bool,
    plan: String,
    days_remaining: u32,
    paid_with: String,
    token_budget_hint: String,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuraCheckoutQuote {
    plan: String,
    price_btc: String,
    price_qub: String,
    duration_days: u32,
    margin_note: String,
    backend_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivacyStatus {
    mode: String,
    level: String,
    active_features: Vec<String>,
    planned_features: Vec<String>,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExchangeReadyStatus {
    mode: String,
    default_transfers: String,
    cex_deposit_policy: String,
    cex_withdraw_policy: String,
    privacy_default: bool,
    compliance_notes: Vec<String>,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShieldedPoolStatus {
    enabled: bool,
    phase: String,
    transparent_balance_label: String,
    shielded_balance_label: String,
    commands_prepared: Vec<String>,
    pool_model: String,
    warning: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrivacyActionPreview {
    action: String,
    title: String,
    summary: String,
    requirements: Vec<String>,
    command_preview: String,
    warning: String,
}

fn qrx_app_settings_dir() -> Result<PathBuf, AppError> {
    let dir = app_data_dir()?.join("settings");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn read_setting(name: &str, default: &str) -> String {
    let path = qrx_app_settings_dir().ok().map(|d| d.join(name));
    path.and_then(|p| fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn write_setting(name: &str, value: &str) -> Result<(), AppError> {
    let path = qrx_app_settings_dir()?.join(name);
    fs::write(path, value.trim())?;
    Ok(())
}

fn is_mainnet_like(network: &str) -> bool {
    let n = network.to_lowercase();
    n.contains("mainnet")
}

fn shared_btc_service<T: serde::de::DeserializeOwned>(app: &tauri::AppHandle, request: Value) -> Result<T, String> {
    let binary=resolve_binary(Some(app),"qrx-btc-wallet-service").map_err(|e|e.to_string())?;
    let mut child=background_command(binary).arg("--data-dir").arg(app_data_dir().map_err(|e|e.to_string())?)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e|format!("Could not start shared BTC wallet service: {e}"))?;
    if let Some(stdin)=child.stdin.as_mut(){stdin.write_all(serde_json::to_string(&request).map_err(|e|e.to_string())?.as_bytes()).map_err(|e|e.to_string())?;}else{return Err("BTC wallet service stdin unavailable".into())}
    drop(child.stdin.take());let output=child.wait_with_output().map_err(|e|e.to_string())?;
    let envelope:Value=serde_json::from_slice(&output.stdout).map_err(|_|format!("BTC wallet service returned invalid JSON: {}",String::from_utf8_lossy(&output.stderr)))?;
    if !output.status.success()||!envelope.get("ok").and_then(Value::as_bool).unwrap_or(false){return Err(envelope.get("error").and_then(Value::as_str).unwrap_or("BTC wallet service failed").to_string())}
    serde_json::from_value(envelope.get("result").cloned().unwrap_or(Value::Null)).map_err(|e|e.to_string())
}

#[tauri::command]
fn btc_get_status(app:tauri::AppHandle,endpoint: Option<String>, passphrase: Option<String>) -> Result<BtcLightStatus, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"status","endpoint":endpoint,"passphrase":passphrase}))
}

#[tauri::command]
fn btc_set_mode(app:tauri::AppHandle,mode: String, endpoint: Option<String>) -> Result<BtcLightStatus, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"set-mode","mode":mode,"endpoint":endpoint}))
}

#[tauri::command]
fn btc_test_endpoints(app:tauri::AppHandle,endpoint: Option<String>) -> Result<Vec<EndpointHealth>, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"test-endpoints","endpoint":endpoint}))
}

#[tauri::command]
fn btc_start_neutrino(app:tauri::AppHandle) -> Result<BtcLightStatus, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"start-neutrino"}))
}


fn kraken_vault_file(network: &str, wallet: &str) -> Result<PathBuf, String> {
    Ok(wallet_settings_dir(network, wallet).map_err(|e| e.to_string())?.join("kraken_credentials.enc.json"))
}

fn kraken_gateway_state_dir(network: &str, wallet: &str) -> Result<PathBuf, String> {
    let dir = wallet_settings_dir(network, wallet).map_err(|e| e.to_string())?.join("kraken-gateway");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn kraken_gateway_log_paths(network: &str, wallet: &str) -> Result<(PathBuf, PathBuf), String> {
    let dir = logs_dir(network, wallet).map_err(|e| e.to_string())?;
    Ok((dir.join("kraken-gateway.stdout.log"), dir.join("kraken-gateway.stderr.log")))
}

fn protect_private_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn derive_secret_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    // Shared Argon2id KDF for encrypted local secret vaults (e.g. Kraken credentials).
    // This helper must remain even when the legacy embedded BTC wallet implementation is removed.
    let params = Params::new(
        64 * 1024, // 64 MiB
        3,         // iterations
        1,         // parallelism
        Some(32),  // output length
    ).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

fn encrypt_kraken_credentials(api_key: &str, api_secret: &str, passphrase: &str) -> Result<KrakenCredentialVault, String> {
    if api_key.trim().is_empty() || api_secret.trim().is_empty() {
        return Err("Kraken API key and API secret are required".into());
    }
    if passphrase.trim().is_empty() {
        return Err("Wallet/session passphrase is required to encrypt Kraken credentials".into());
    }
    let plain = KrakenCredentialPlain { api_key: api_key.trim().to_string(), api_secret: api_secret.trim().to_string() };
    let bytes = serde_json::to_vec(&plain).map_err(|e| e.to_string())?;
    let mut salt = [0u8; 16]; rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_secret_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12]; rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, bytes.as_ref()).map_err(|e| e.to_string())?;
    Ok(KrakenCredentialVault {
        version: 1,
        venue: "KRAKEN".into(),
        kdf: "argon2id-m65536-t3-p1".into(),
        cipher: "aes-256-gcm".into(),
        kdf_salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decrypt_kraken_credentials(vault: &KrakenCredentialVault, passphrase: &str) -> Result<KrakenCredentialPlain, String> {
    if vault.version != 1 || vault.venue != "KRAKEN" || vault.cipher != "aes-256-gcm" {
        return Err("Unsupported Kraken credential vault format".into());
    }
    if passphrase.trim().is_empty() { return Err("Wallet/session passphrase is required".into()); }
    let salt = general_purpose::STANDARD.decode(&vault.kdf_salt).map_err(|e| e.to_string())?;
    let nonce_bytes = general_purpose::STANDARD.decode(&vault.nonce).map_err(|e| e.to_string())?;
    let ciphertext = general_purpose::STANDARD.decode(&vault.ciphertext).map_err(|e| e.to_string())?;
    if nonce_bytes.len() != 12 { return Err("Invalid Kraken vault nonce".into()); }
    let key = derive_secret_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut plain = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Could not decrypt Kraken credentials. Check the wallet/session passphrase.".to_string())?;
    let parsed: KrakenCredentialPlain = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
    plain.fill(0);
    Ok(parsed)
}

fn resolve_kraken_gateway_script(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Ok(p) = std::env::var("QRX_KRAKEN_GATEWAY_SCRIPT") { candidates.push(PathBuf::from(p)); }
    if let Some(r) = app.path_resolver().resource_dir() {
        candidates.push(r.join("qrx-gateway-kraken.py"));
        candidates.push(r.join("resources").join("qrx-gateway-kraken.py"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("src-tauri").join("resources").join("qrx-gateway-kraken.py"));
        candidates.push(cwd.join("..").join("qrx-core").join("gateways").join("qrx-gateway-kraken.py"));
        candidates.push(cwd.join("qrx-core").join("gateways").join("qrx-gateway-kraken.py"));
    }
    candidates.into_iter().find(|p| p.exists()).ok_or_else(|| "Could not find bundled qrx-gateway-kraken.py".to_string())
}

fn resolve_bundled_python_script(app: &tauri::AppHandle, name: &str) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Some(r) = app.path_resolver().resource_dir() { candidates.push(r.join(name)); candidates.push(r.join("resources").join(name)); }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("src-tauri").join("resources").join(name));
        candidates.push(cwd.join("resources").join(name));
    }
    candidates.into_iter().find(|p| p.exists()).ok_or_else(|| format!("Could not find bundled {name}"))
}

fn arbitrage_state_dir(network: &str, wallet: &str) -> Result<PathBuf, String> {
    let dir = wallet_settings_dir(network, wallet).map_err(|e| e.to_string())?.join("arbitrage");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?; Ok(dir)
}

fn run_python_json(app: &tauri::AppHandle, script_name: &str, args: &[String], input: Option<&Value>) -> Result<Value, String> {
    let script = resolve_bundled_python_script(app, script_name)?;
    let (python, prefix) = resolve_python_launcher()?;
    let mut cmd = background_command(python); for a in prefix { cmd.arg(a); } cmd.arg(script).args(args);
    if input.is_some() { cmd.stdin(Stdio::piped()); }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    if let Some(value) = input {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        let mut stdin = child.stdin.take().ok_or_else(|| "Python stdin unavailable".to_string())?;
        stdin.write_all(&bytes).map_err(|e| e.to_string())?; stdin.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() { return Err(String::from_utf8_lossy(&output.stderr).trim().to_string()); }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("Invalid JSON from {script_name}: {e}"))
}

#[tauri::command]
fn arbitrage_evaluate(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, payload: Value, paper: bool) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let state=arbitrage_state_dir(&network,&wallet)?; let args=vec![if paper{"--paper-json".into()}else{"--evaluate-json".into()},"--state-dir".into(),state.to_string_lossy().to_string()];
    run_python_json(&app,"qrx-arbitrage-engine.py",&args,Some(&payload))
}

#[tauri::command]
fn arbitrage_approve(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, arbitrage_id: String) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let state=arbitrage_state_dir(&network,&wallet)?; let args=vec!["--approve".into(),required_clean(&arbitrage_id,"Arbitrage ID")?,"--state-dir".into(),state.to_string_lossy().to_string()];
    run_python_json(&app,"qrx-arbitrage-engine.py",&args,None)
}

fn plan_positive_integer(plan:&Value,path:&str,label:&str)->Result<String,String>{
    let value=plan.pointer(path).ok_or_else(||format!("Approved plan is missing {label}"))?;
    let text=if let Some(n)=value.as_u64(){n.to_string()}else if let Some(s)=value.as_str(){s.to_string()}else{return Err(format!("Approved plan has invalid {label}"));};
    positive_u64(&text,label)
}

#[tauri::command]
fn arbitrage_broadcast_hedge(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,arbitrage_id:String,source_buy_order_id:String,agent:String,owner:String,agent_ed_pub:String,agent_mldsa_pub:String,lane:String,order_expiry:String,tx_expiry:String,passphrase:Option<String>)->Result<Value,String>{
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let arb_id=required_clean(&arbitrage_id,"Arbitrage ID")?; let source=required_clean(&source_buy_order_id,"Matched cross-chain BUY order ID")?;
    let agent=required_clean(&agent,"Agent address")?; let owner=required_clean(&owner,"Owner address")?;
    let agent_ed=required_clean(&agent_ed_pub,"Agent Ed25519 public key")?; let agent_ml=required_clean(&agent_mldsa_pub,"Agent ML-DSA public key")?;
    let lane=required_clean(&lane,"Lane")?; lane.parse::<u32>().map_err(|_|"Lane must be a non-negative whole number".to_string())?;
    let order_expiry=positive_u64(&order_expiry,"Order expiry height")?; let tx_expiry=positive_u64(&tx_expiry,"Transaction expiry height")?;
    if passphrase.as_deref().unwrap_or("").is_empty(){return Err("Unlock the agent wallet with the session passphrase first".into());}
    let state=arbitrage_state_dir(&network,&wallet)?;
    let plan_args=vec!["--approved-plan".into(),arb_id.clone(),"--state-dir".into(),state.to_string_lossy().to_string()];
    let plan=run_python_json(&app,"qrx-arbitrage-engine.py",&plan_args,None)?;
    let quantity=plan_positive_integer(&plan,"/kraken_hedge/quantity_atoms","hedge quantity")?;
    let price=plan_positive_integer(&plan,"/kraken_hedge/limit_price_atoms","hedge limit price")?;
    let created=run_cli(Some(&app),&network,&wallet,&["createarbitragehedgetransaction",&agent,&owner,&source,&arb_id,&quantity,&price,&order_expiry,&agent_ed,&agent_ml,&lane,&tx_expiry],passphrase.as_deref()).map_err(|e|e.to_string())?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return an arbitrage hedge raw transaction".to_string())?;
    let broadcast=sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"arbitrage-hedge")?;
    let hedge_ref=["order_id","txid","id","hash"].iter().find_map(|k|broadcast.result.get(*k)).and_then(|v|v.as_str().map(str::to_string).or_else(||v.as_u64().map(|n|n.to_string()))).unwrap_or_else(||format!("{arb_id}:broadcast"));
    let mark_args=vec!["--mark-broadcast".into(),arb_id.clone(),"--qrx-hedge-order-id".into(),hedge_ref.clone(),"--state-dir".into(),state.to_string_lossy().to_string()];
    let ledger_link=run_python_json(&app,"qrx-arbitrage-engine.py",&mark_args,None).unwrap_or_else(|e|serde_json::json!({"warning":e,"arbitrage_id":arb_id,"qrx_hedge_order_id":hedge_ref}));
    Ok(serde_json::json!({"approved_plan":plan,"source_buy_order_id":source,"broadcast":broadcast,"ledger_link":ledger_link}))
}

#[tauri::command]
fn arbitrage_list(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let state=arbitrage_state_dir(&network,&wallet)?; let args=vec!["--list".into(),"--state-dir".into(),state.to_string_lossy().to_string()];
    run_python_json(&app,"qrx-arbitrage-engine.py",&args,None)
}

#[tauri::command]
fn arbitrage_fetch_kraken_book(app: tauri::AppHandle) -> Result<Value, String> {
    run_python_json(&app,"qrx-arbitrage-engine.py",&["--fetch-book".into()],None)
}

#[tauri::command]
fn arbitrage_get_order(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, order_id: String, passphrase: Option<String>) -> Result<CommandResult, String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let order_id=required_clean(&order_id,"Cross-chain order ID")?;
    run_cli(Some(&app),&network,&wallet,&["getorder",&order_id],passphrase.as_deref()).map_err(|e|e.to_string())
}

#[tauri::command]
fn export_complete_ledger(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, profile: String, from_date: Option<String>, to_date: Option<String>, year: Option<u32>, quarter: Option<u8>) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let profile=if profile=="international"{"international"}else{"de"};
    let epoch=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e|e.to_string())?.as_millis();
    let export_root=wallet_settings_dir(&network,&wallet).map_err(|e|e.to_string())?.join("exports"); fs::create_dir_all(&export_root).map_err(|e|e.to_string())?;
    let period_label=if let Some(y)=year{if let Some(q)=quarter{format!("{y}-Q{q}")}else{y.to_string()}}else if from_date.as_deref().unwrap_or("").is_empty()&&to_date.as_deref().unwrap_or("").is_empty(){"all-time".into()}else{"custom-period".into()};
    let output=export_root.join(format!("ledger-{period_label}-{epoch}-{profile}"));
    let core=resolve_binary(Some(&app),"qrx").map_err(|e|e.to_string())?; let datadir=app_data_dir().map_err(|e|e.to_string())?;
    let chain_dir=datadir.join(&network).join("chain"); let selected_wallet_dir=wallet_dir(&network,&wallet).map_err(|e|e.to_string())?;
    let kdb=kraken_gateway_state_dir(&network,&wallet)?.join("kraken-gateway.sqlite3"); let adb=arbitrage_state_dir(&network,&wallet)?.join("arbitrage.sqlite3");
    let mut args=vec!["--output".into(),output.to_string_lossy().to_string(),"--profile".into(),profile.into(),"--qrx".into(),core.to_string_lossy().to_string(),"--chain-dir".into(),chain_dir.to_string_lossy().to_string(),"--wallet-dir".into(),selected_wallet_dir.to_string_lossy().to_string(),"--network".into(),network,"--datadir".into(),datadir.to_string_lossy().to_string(),"--wallet".into(),wallet,"--kraken-db".into(),kdb.to_string_lossy().to_string(),"--arbitrage-db".into(),adb.to_string_lossy().to_string()];
    if let Some(v)=from_date.filter(|v|!v.trim().is_empty()){args.extend(["--from-date".into(),v]);}if let Some(v)=to_date.filter(|v|!v.trim().is_empty()){args.extend(["--to-date".into(),v]);}if let Some(v)=year{args.extend(["--year".into(),v.to_string()]);}if let Some(v)=quarter{args.extend(["--quarter".into(),v.to_string()]);}
    let mut result=run_python_json(&app,"qrx-complete-ledger-export.py",&args,None)?; if let Some(o)=result.as_object_mut(){o.insert("output_dir".into(),Value::String(output.to_string_lossy().to_string()));} Ok(result)
}

fn resolve_python_launcher() -> Result<(String, Vec<String>), String> {
    if let Ok(p) = std::env::var("QRX_PYTHON") {
        if !p.trim().is_empty() { return Ok((p, Vec::new())); }
    }
    let candidates = if cfg!(target_os = "windows") {
        vec![("py".to_string(), vec!["-3".to_string()]), ("python".to_string(), vec![])]
    } else {
        vec![("python3".to_string(), vec![]), ("python".to_string(), vec![])]
    };
    for (program, prefix) in candidates {
        let mut c = background_command(&program);
        for a in &prefix { c.arg(a); }
        if c.arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) {
            return Ok((program, prefix));
        }
    }
    Err("Python 3 is required for the QRX Kraken gateway MVP and was not found".into())
}

#[tauri::command]
fn kraken_credentials_status(network: Option<String>, wallet: Option<String>) -> Result<KrakenCredentialStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = wallet.unwrap_or_else(|| "node1".into());
    let path = kraken_vault_file(&network, &wallet)?;
    Ok(KrakenCredentialStatus { configured: path.exists(), encrypted_at_rest: path.exists(), venue: "KRAKEN".into(), storage: "Argon2id + AES-256-GCM local vault; no plaintext API secret config".into() })
}

#[tauri::command]
fn kraken_store_credentials(network: Option<String>, wallet: Option<String>, api_key: String, api_secret: String, passphrase: String) -> Result<KrakenCredentialStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = wallet.unwrap_or_else(|| "node1".into());
    let vault = encrypt_kraken_credentials(&api_key, &api_secret, &passphrase)?;
    let path = kraken_vault_file(&network, &wallet)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&vault).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    protect_private_file(&tmp)?;
    #[cfg(windows)]
    if path.exists() { fs::remove_file(&path).map_err(|e| e.to_string())?; }
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    protect_private_file(&path)?;
    Ok(KrakenCredentialStatus { configured: true, encrypted_at_rest: true, venue: "KRAKEN".into(), storage: "Argon2id + AES-256-GCM local vault".into() })
}

#[tauri::command]
fn kraken_delete_credentials(network: Option<String>, wallet: Option<String>) -> Result<KrakenCredentialStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = wallet.unwrap_or_else(|| "node1".into());
    let path = kraken_vault_file(&network, &wallet)?;
    if path.exists() { fs::remove_file(path).map_err(|e| e.to_string())?; }
    Ok(KrakenCredentialStatus { configured: false, encrypted_at_rest: false, venue: "KRAKEN".into(), storage: "No saved credentials".into() })
}

#[tauri::command]
fn kraken_gateway_status(state: tauri::State<KrakenGatewayState>, network: Option<String>, wallet: Option<String>) -> Result<KrakenGatewayStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = wallet.unwrap_or_else(|| "node1".into());
    let mut guard = state.child.lock().map_err(|_| "Kraken gateway state lock poisoned".to_string())?;
    let mut running = false; let mut pid = None;
    if let Some(child) = guard.as_mut() {
        match child.try_wait() {
            Ok(None) => { running = true; pid = Some(child.id()); }
            Ok(Some(_)) | Err(_) => { *guard = None; }
        }
    }
    let wdir = wallet_dir(&network, &wallet).map_err(|e| e.to_string())?;
    let address = read_address(&wdir);
    let (outlog, errlog) = kraken_gateway_log_paths(&network, &wallet)?;
    Ok(KrakenGatewayStatus { running, pid, gateway_address: address, venue: "KRAKEN".into(), stdout_log: outlog.to_string_lossy().to_string(), stderr_log: errlog.to_string_lossy().to_string(), credential_vault_present: kraken_vault_file(&network, &wallet)?.exists() })
}

#[tauri::command]
fn kraken_start_gateway(app: tauri::AppHandle, state: tauri::State<KrakenGatewayState>, network: Option<String>, wallet: Option<String>, passphrase: String, use_saved_credentials: bool, api_key: Option<String>, api_secret: Option<String>) -> Result<KrakenGatewayStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(&wallet.unwrap_or_else(|| "node1".into())).map_err(|e| e.to_string())?;
    let mut guard = state.child.lock().map_err(|_| "Kraken gateway state lock poisoned".to_string())?;
    if let Some(child) = guard.as_mut() {
        if child.try_wait().map_err(|e| e.to_string())?.is_none() { return Err("Kraken gateway is already running".into()); }
        *guard = None;
    }
    let creds = if use_saved_credentials {
        let path = kraken_vault_file(&network, &wallet)?;
        let bytes = fs::read(path).map_err(|_| "No encrypted Kraken credentials saved for this wallet".to_string())?;
        let vault: KrakenCredentialVault = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        decrypt_kraken_credentials(&vault, &passphrase)?
    } else {
        let k = api_key.unwrap_or_default(); let s = api_secret.unwrap_or_default();
        if k.trim().is_empty() || s.trim().is_empty() { return Err("Enter Kraken API key and API secret in the wallet".into()); }
        KrakenCredentialPlain { api_key: k.trim().to_string(), api_secret: s.trim().to_string() }
    };
    let gateway_address = read_address(&wallet_dir(&network, &wallet).map_err(|e| e.to_string())?).ok_or_else(|| "Current wallet has no QRX address".to_string())?;
    let qrx_cli = resolve_binary(Some(&app), "qrx-cli").map_err(|e| e.to_string())?;
    let script = resolve_kraken_gateway_script(&app)?;
    let (python, prefix) = resolve_python_launcher()?;
    let state_dir = kraken_gateway_state_dir(&network, &wallet)?;
    let (outlog, errlog) = kraken_gateway_log_paths(&network, &wallet)?;
    let stdout = OpenOptions::new().create(true).append(true).open(&outlog).map_err(|e| e.to_string())?;
    let stderr = OpenOptions::new().create(true).append(true).open(&errlog).map_err(|e| e.to_string())?;
    let mut cmd = background_command(python);
    for a in prefix { cmd.arg(a); }
    cmd.arg(script)
        .arg("--qrx-cli").arg(qrx_cli)
        .arg("--network").arg(&network)
        .arg("--datadir").arg(app_data_dir().map_err(|e| e.to_string())?)
        .arg("--wallet").arg(&wallet)
        .arg("--gateway-address").arg(&gateway_address)
        .arg("--state-dir").arg(&state_dir)
        .stdin(Stdio::piped()).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr));
    let mut child = cmd.spawn().map_err(|e| format!("Could not start Kraken gateway: {e}"))?;
    let payload = serde_json::json!({"api_key":creds.api_key,"api_secret":creds.api_secret});
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(serde_json::to_string(&payload).map_err(|e| e.to_string())?.as_bytes()).map_err(|e| e.to_string())?;
        stdin.write_all(b"\n").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
    } else { let _ = child.kill(); return Err("Kraken gateway stdin pipe unavailable".into()); }
    drop(child.stdin.take());
    let pid = child.id();
    *guard = Some(child);
    Ok(KrakenGatewayStatus { running: true, pid: Some(pid), gateway_address: Some(gateway_address), venue: "KRAKEN".into(), stdout_log: outlog.to_string_lossy().to_string(), stderr_log: errlog.to_string_lossy().to_string(), credential_vault_present: kraken_vault_file(&network, &wallet)?.exists() })
}

#[tauri::command]
fn kraken_stop_gateway(state: tauri::State<KrakenGatewayState>, network: Option<String>, wallet: Option<String>) -> Result<KrakenGatewayStatus, String> {
    {
        let mut guard = state.child.lock().map_err(|_| "Kraken gateway state lock poisoned".to_string())?;
        if let Some(child) = guard.as_mut() { let _ = child.kill(); let _ = child.wait(); }
        *guard = None;
    }
    kraken_gateway_status(state, network, wallet)
}

#[tauri::command]
fn btc_init_wallet(app:tauri::AppHandle,passphrase: Option<String>) -> Result<BtcWalletInitResult, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"init","passphrase":passphrase}))
}

#[tauri::command]
fn btc_backup_phrase(app:tauri::AppHandle,passphrase: Option<String>) -> Result<BtcBackupResult, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"backup","passphrase":passphrase}))
}

#[tauri::command]
fn btc_restore_wallet(app:tauri::AppHandle,mnemonic: String, passphrase: Option<String>, overwrite: bool) -> Result<BtcRestoreResult, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"restore","mnemonic":mnemonic,"passphrase":passphrase,"overwrite":overwrite}))
}

#[tauri::command]
fn btc_reset_wallet(app:tauri::AppHandle,confirm: String) -> Result<String, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"reset","confirm":confirm}))
}

#[tauri::command]
fn btc_sync(app:tauri::AppHandle,passphrase: Option<String>) -> Result<BtcLightStatus, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"sync","passphrase":passphrase}))
}

#[tauri::command]
fn btc_get_balance(app:tauri::AppHandle,passphrase: Option<String>) -> Result<BtcLightStatus, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"balance","passphrase":passphrase}))
}

#[tauri::command]
fn btc_new_address(app:tauri::AppHandle,passphrase: Option<String>) -> Result<BtcReceiveAddress, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"new-address","passphrase":passphrase}))
}

#[tauri::command]
fn btc_list_addresses(app:tauri::AppHandle,passphrase: Option<String>) -> Result<Vec<String>, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"list-addresses","passphrase":passphrase}))
}

#[tauri::command]
fn btc_send(app:tauri::AppHandle,to_address: String, amount_sats: u64, fee_rate_sat_vb: Option<f32>, passphrase: Option<String>) -> Result<BtcSendResult, String> {
    shared_btc_service(&app,serde_json::json!({"operation":"send","to_address":to_address,"amount_sats":amount_sats,"fee_rate_sat_vb":fee_rate_sat_vb,"passphrase":passphrase}))
}


#[tauri::command]
fn crosschain_place_buy(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:String,btc_sats:String,max_qub_per_btc_atoms:String,order_expiry_height:String,hashlock_hex:String,btc_receive_pubkey_hex:String,qrx_refund_height:String,lane:Option<String>,tx_expiry_height:String,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let agent=generals_address(&network,&wallet)?; if owner.trim().is_empty()||owner.trim()==agent{return Err("Cross-chain orders require a distinct delegated owner address; the active wallet is the authorized agent wallet.".into());}
    positive_u64(&btc_sats,"BTC sats")?; positive_u64(&max_qub_per_btc_atoms,"Max QUB/BTC price atoms")?; positive_u64(&order_expiry_height,"Order expiry")?; positive_u64(&qrx_refund_height,"QUB refund height")?; positive_u64(&tx_expiry_height,"Transaction expiry")?;
    if hashlock_hex.trim().len()!=64||!hashlock_hex.trim().chars().all(|c|c.is_ascii_hexdigit()){return Err("Hashlock must be a 32-byte SHA-256 hex value".into());}
    let (ed,ml)=generals_public_keys(&network,&wallet)?; let lane=lane.unwrap_or_else(||"5".into());
    let created=run_cli(Some(&app),&network,&wallet,&["createcrosschainbuytransaction",&agent,owner.trim(),btc_sats.trim(),max_qub_per_btc_atoms.trim(),order_expiry_height.trim(),hashlock_hex.trim(),btc_receive_pubkey_hex.trim(),qrx_refund_height.trim(),&ed,&ml,lane.trim(),tx_expiry_height.trim()],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?; sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"crosschain-buy")
}

#[tauri::command]
fn crosschain_place_sell(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:String,btc_sats:String,min_qub_per_btc_atoms:String,order_expiry_height:String,btc_refund_pubkey_hex:String,btc_refund_csv_blocks:String,lane:Option<String>,tx_expiry_height:String,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let agent=generals_address(&network,&wallet)?; if owner.trim().is_empty()||owner.trim()==agent{return Err("Cross-chain orders require a distinct delegated owner address; the active wallet is the authorized agent wallet.".into());}
    for (v,l) in [(&btc_sats,"BTC sats"),(&min_qub_per_btc_atoms,"Min QUB/BTC price atoms"),(&order_expiry_height,"Order expiry"),(&btc_refund_csv_blocks,"BTC refund CSV blocks"),(&tx_expiry_height,"Transaction expiry")] {positive_u64(v,l)?;}
    let (ed,ml)=generals_public_keys(&network,&wallet)?; let lane=lane.unwrap_or_else(||"5".into());
    let created=run_cli(Some(&app),&network,&wallet,&["createcrosschainselltransaction",&agent,owner.trim(),btc_sats.trim(),min_qub_per_btc_atoms.trim(),order_expiry_height.trim(),btc_refund_pubkey_hex.trim(),btc_refund_csv_blocks.trim(),&ed,&ml,lane.trim(),tx_expiry_height.trim()],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?; sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"crosschain-sell")
}

#[tauri::command]
fn crosschain_redeem(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,session_id:String,secret_hex:String,lane:Option<String>,tx_expiry_height:String,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"mainnet".into());let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;let owner=generals_address(&network,&wallet)?;let(ed,ml)=generals_public_keys(&network,&wallet)?;let lane=lane.unwrap_or_else(||"5".into());
    let created=run_cli(Some(&app),&network,&wallet,&["createcrosschainredeemtransaction",&owner,session_id.trim(),secret_hex.trim(),&ed,&ml,lane.trim(),tx_expiry_height.trim()],passphrase.as_deref()).map_err(String::from)?;let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"crosschain-redeem")
}

#[tauri::command]
fn crosschain_refund(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,session_id:String,lane:Option<String>,tx_expiry_height:String,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"mainnet".into());let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;let owner=generals_address(&network,&wallet)?;let(ed,ml)=generals_public_keys(&network,&wallet)?;let lane=lane.unwrap_or_else(||"5".into());
    let created=run_cli(Some(&app),&network,&wallet,&["createcrosschainrefundtransaction",&owner,session_id.trim(),&ed,&ml,lane.trim(),tx_expiry_height.trim()],passphrase.as_deref()).map_err(String::from)?;let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"crosschain-refund")
}

#[tauri::command]
fn crosschain_submit_funding_proof(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,session_id:String,rawtx_hex:String,block_hash:String,tx_index:String,branch_csv:String,lane:Option<String>,tx_expiry_height:String,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"mainnet".into());let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;let address=generals_address(&network,&wallet)?;let(ed,ml)=generals_public_keys(&network,&wallet)?;let lane=lane.unwrap_or_else(||"5".into());
    let created=run_cli(Some(&app),&network,&wallet,&["createbtcspvfundingprooftransaction",&address,session_id.trim(),rawtx_hex.trim(),block_hash.trim(),tx_index.trim(),branch_csv.trim(),&ed,&ml,lane.trim(),tx_expiry_height.trim()],passphrase.as_deref()).map_err(String::from)?;let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"btc-spv-funding-proof")
}

#[tauri::command]
fn crosschain_status(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,session_id:Option<String>,passphrase:Option<String>)->Result<Value,String>{
    let network=network.unwrap_or_else(||"mainnet".into());let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let res=if let Some(sid)=session_id.filter(|s|!s.trim().is_empty()){run_cli(Some(&app),&network,&wallet,&["getcrosschainswap",sid.trim()],passphrase.as_deref())}else{run_cli(Some(&app),&network,&wallet,&["listcrosschainswaps"],passphrase.as_deref())}.map_err(String::from)?;Ok(res.result)
}



fn chrono_like_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn aura_history_path() -> Result<PathBuf, AppError> {
    let dir = app_data_dir()?.join("aura");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("local_chat.jsonl"))
}

fn aura_append_local(role: &str, content: &str) {
    if let Ok(path) = aura_history_path() {
        let line = serde_json::json!({
            "ts": chrono_like_timestamp(),
            "role": role,
            "content": content
        }).to_string();
        let _ = OpenOptions::new().create(true).append(true).open(path)
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{}", line)
            });
    }
}

#[tauri::command]
fn aura_plan_status() -> Result<AuraPlanStatus, String> {
    Ok(AuraPlanStatus {
        active: false,
        plan: "none".into(),
        days_remaining: 0,
        paid_with: "none".into(),
        token_budget_hint: "Cloud package not active. Local wallet/CLI help is available without cloud tokens.".into(),
        disclaimer: "Cloud AURA answers will be routed via your Cloudflare backend. Chat history remains local and is sent with continuation requests only after user action.".into(),
    })
}

#[tauri::command]
fn aura_checkout_quote(plan: String) -> Result<AuraCheckoutQuote, String> {
    let plan = if plan.trim().is_empty() { "AURA 30".into() } else { plan };
    Ok(AuraCheckoutQuote {
        plan,
        price_btc: "backend-calculated".into(),
        price_qub: "backend-calculated".into(),
        duration_days: 30,
        margin_note: "Target margin: 50% after taxes. Enforce user and global rate limits in Cloudflare backend.".into(),
        backend_note: "Cloudflare endpoint should create BTC/QUB invoice, confirm payment, activate package, and proxy ChatGPT requests.".into(),
    })
}

#[tauri::command]
fn aura_local_help(message: String) -> Result<AuraLocalReply, String> {
    let msg = message.trim().to_lowercase();
    aura_append_local("user", &message);

    let mut reply = AuraLocalReply {
        source: "local".into(),
        answer: "Ich kann lokale Wallet- und CLI-Hilfe geben. Für allgemeine Fragen oder tiefere Analyse nutze später AURA Cloud über dein 30-Tage-Paket.".into(),
        command: None,
        needs_cloud: false,
        token_hint: "No cloud tokens used.".into(),
    };

    if (msg.contains("offline") || msg.contains("internet") || msg.contains("catch") || msg.contains("sync")) && (msg.contains("validator") || msg.contains("slash") || msg.contains("m1") || msg.contains("home")) {
        reply.answer = "QRX Home Validator protection: a normal outage does not make the node sign while stale. After reconnect, signing stays PAUSED while the node catches up, until it is no more than 2 blocks behind peer head and has remained stable for 30 seconds; then it resumes automatically. Outside the separate 180-day Bootstrap grace, the current home-friendly liveness profile gives the first 72 hours of one continuous outage without liveness slashing. After that, 0.05% of slashable validator power is applied per further 24 hours, with a hard cap of 1% for that continuous outage. A temporary 1-hour jail is only applied after 7 days offline. Once the validator is observed active again, the outage cap resets. Double-signing is different and remains a severe 50% slash + permanent tombstone risk. Never run the same validator keys simultaneously on a second node.".into();
    } else if msg.contains("tombston") || msg.contains("tombstone") || msg.contains("tombstoned") {
        reply.answer = "Tombstoned bedeutet bei QRX: Ein Validator wurde wegen eines nachweisbaren schweren Consensus-Verstoßes dauerhaft aus der aktiven Validator-Menge ausgeschlossen – insbesondere bei Double-Signing, also wenn dieselbe Validator-ID für dieselbe Höhe/Runde widersprüchliche Blöcke oder Votes signiert. Das ist NICHT dasselbe wie 'jailed': Jailed ist eine vorübergehende Sperre, z. B. nach Fehlverhalten oder Ausfall. Tombstoned ist dauerhaft. Bei Double-Signing greift zusätzlich die protokollierte Slashing-Regel; im aktuellen QRX-Profil sind standardmäßig 50 % des slashbaren Stakes vorgesehen. Ein tombstoned Validator kann nicht einfach wieder durch 'Validator Mode ON' aktiviert werden. Für den Nutzer wichtig: Offline sein allein führt nicht zum Tombstone; Double-Signing/Evidence ist der kritische Fall.".into();
        reply.command = Some("Validator Fleet → Details → Status / qrx staking-status <chain-dir> <validator-address>".into());
    } else if msg.contains("jailed") || msg.contains("jail") {
        reply.answer = "Jailed bedeutet: Der Validator ist vorübergehend vom aktiven Consensus ausgeschlossen. Das ist grundsätzlich zeitlich begrenzt und unterscheidet sich von 'tombstoned'. Tombstoned bedeutet dauerhaft ausgeschlossen – typischerweise nach nachweisbarem Double-Signing. Offline-Probleme führen nicht automatisch zu einem Tombstone.".into();
        reply.command = Some("Validator Fleet → Details → Status".into());
    } else if msg.contains("balance") || msg.contains("guthaben") {
        reply.answer = "Balance lokal prüfen: Im Dashboard Refresh klicken oder per CLI getbalance nutzen.".into();
        reply.command = Some("qrx-cli --network alpha --wallet node1 getbalance".into());
    } else if msg.contains("adresse") || msg.contains("address") || msg.contains("receive") || msg.contains("empfangen") {
        reply.answer = "Neue Empfangsadresse lokal erzeugen: im Wallet Receive klicken oder CLI getnewaddress.".into();
        reply.command = Some("qrx-cli --network alpha --wallet node1 getnewaddress".into());
    } else if msg.contains("send") || msg.contains("senden") || msg.contains("überweisen") {
        reply.answer = "QUB senden: Empfängeradresse und Betrag prüfen, dann Send nutzen. Kleine Testbeträge zuerst.".into();
        reply.command = Some("qrx-cli --network alpha --wallet node1 sendtoaddress <address> <amount> [memo]".into());
    } else if msg.contains("staking") || msg.contains("stake") {
        reply.answer = "Staking lokal: Betrag wählen und Stake starten. Prüfe vorher Balance, Netzwerk und Passphrase.".into();
        reply.command = Some("qrx-cli --network alpha --wallet node1 stake <amount>".into());
    } else if msg.contains("delegate") || msg.contains("delegieren") {
        reply.answer = "Delegation lokal: Validator-Adresse und Betrag angeben.".into();
        reply.command = Some("qrx-cli --network alpha --wallet node1 delegate <validator> <amount>".into());
    } else if msg.contains("privacy") || msg.contains("shield") || msg.contains("stealth") || msg.contains("private") {
        reply.answer = "QUB is exchange-ready transparent-by-default with an optional Phase 7.1 consensus-backed shielded pool. The production path is transparent QUB → signed PRIVACY_SHIELD → signed PRIVACY_TRANSFER → signed PRIVACY_UNSHIELD. Verified Privacy credentials and chain-bound proofs are enforced by consensus before QRXDB state is committed atomically. This is not marketed as anonymous or untraceable.".into();
        reply.command = Some("Privacy Center → PRIVACY_SHIELD / PRIVACY_TRANSFER / PRIVACY_UNSHIELD (signed consensus transactions)".into());
    } else if msg.contains("exchange") || msg.contains("cex") || msg.contains("listing") {
        reply.answer = "Exchange-ready mode means transparent transfers are default. Centralized exchanges should use transparent QUB deposits/withdrawals only. Privacy stays optional and local after withdrawal.".into();
        reply.command = Some("Privacy Center → Exchange-ready mode".into());
    } else if msg.contains("swap") || msg.contains("htlc") || msg.contains("quantum") {
        reply.answer = "Quantum Swaps now use the VELOCITY BTC/QUB cross-chain settlement path with SHA-256 P2WSH/CSV and Bitcoin SPV verification. The legacy file-backed createswap/redeemswap/refundswap path is not exposed by the production wallet.".into();
        reply.command = Some("Wallet → Quantum Swaps → VELOCITY Cross-Chain (CROSSCHAIN_* + BTC_SPV_*)".into());
    } else if msg.contains("btc") || msg.contains("bitcoin") {
        reply.answer = "BTC Light nutzt BDK/Electrum. Nutze BTC Backup, Sync, Generate Address und Send. Seed vorher sichern.".into();
        reply.command = Some("BTC Light → Backup Phrase → Verify Backup → Generate BTC address".into());
    } else if msg.contains("cloud") || msg.contains("chatgpt") || msg.contains("ki") || msg.contains("ai") || msg.contains("erklär") || msg.contains("warum") {
        reply.source = "local-router".into();
        reply.answer = "Diese Frage sollte an AURA Cloud gehen. Dafür braucht der User ein aktives 30-Tage-Paket, bezahlt mit BTC oder QUB. Verlauf bleibt lokal und wird bei Fortsetzung an dein Cloudflare-Backend gesendet.".into();
        reply.command = None;
        reply.needs_cloud = true;
        reply.token_hint = "Cloud tokens required: package check via Cloudflare backend.".to_string();
    }

    aura_append_local("assistant", &reply.answer);
    Ok(reply)
}

#[tauri::command]
fn aura_cloud_request_preview(message: String) -> Result<AuraLocalReply, String> {
    aura_append_local("user", &message);
    Ok(AuraLocalReply {
        source: "local-only".into(),
        answer: "AURA Cloud is not configured in this release. No payment or cloud request will be created. Local wallet help remains available.".into(),
        command: None,
        needs_cloud: true,
        token_hint: "Requires active 30-day package and Cloudflare token/rate-limit check.".into(),
    })
}


#[tauri::command]
fn exchange_ready_status() -> Result<ExchangeReadyStatus, String> {
    Ok(ExchangeReadyStatus {
        mode: "exchange-ready-transparent-default".into(),
        default_transfers: "transparent".into(),
        cex_deposit_policy: "Only transparent QUB deposits should be used for centralized exchanges. Shielded deposits should be disabled unless an exchange explicitly supports them.".into(),
        cex_withdraw_policy: "Withdrawals from exchanges should land on transparent QUB addresses first. Users can shield funds locally afterwards.".into(),
        privacy_default: false,
        compliance_notes: vec![
            "Transparent mode is default for listings and accounting.".into(),
            "Privacy features are optional and user-controlled.".into(),
            "Do not market QUB as anonymous, untraceable, or compliance-bypassing.".into(),
            "Use wording like enhanced privacy or optional privacy layer.".into(),
            "Exchange API/listing docs should expose transparent-only deposit guidance.".into(),
        ],
        disclaimer: "Exchange-ready mode is a product/compliance posture, not legal advice. Final listing requirements depend on the exchange and jurisdiction.".into(),
    })
}

#[tauri::command]
fn shielded_pool_status(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, passphrase: Option<String>) -> Result<ShieldedPoolStatus, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let status = run_cli_raw(Some(&app), &network, &wallet, &["privacy-feature-status"], passphrase.as_deref()).map_err(|e| e.to_string())?;
    Ok(ShieldedPoolStatus {
        enabled: true,
        phase: "phase7.1-consensus-backed".into(),
        transparent_balance_label: "Transparent QUB".into(),
        shielded_balance_label: "Shielded QUB".into(),
        commands_prepared: vec!["PRIVACY_SHIELD".into(),"PRIVACY_TRANSFER".into(),"PRIVACY_UNSHIELD".into(),"privacy-consensus-balance".into()],
        pool_model: "Transparent QUB → Shielded Pool → Private Transfer → Transparent QUB. BTC swaps use transparent QUB settlement.".into(),
        warning: format!("{}\nPhase 7.1 GUI actions create, hybrid-sign and broadcast consensus PRIVACY_* transactions; legacy file-backed privacy is never used here.", status),
    })
}

fn extract_core_kv(raw:&str,key:&str)->Option<String>{
    raw.lines().find_map(|line| line.strip_prefix(&format!("{}=",key))).map(|v|v.trim().to_string())
}

#[tauri::command]
fn privacy_action_execute(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, action: String, amount: Option<String>, destination: Option<String>, passphrase: Option<String>) -> Result<Value,String> {
    let network=network.unwrap_or_else(||"mainnet".into());
    let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let action_l=action.trim().to_lowercase();
    let action_core=match action_l.as_str(){"shield"|"privacy_shield"=>"SHIELD","shielded-send"|"privacy_transfer"=>"TRANSFER","unshield"|"privacy_unshield"=>"UNSHIELD",_=>return Err("Unsupported privacy action".into())};
    let amount=positive_u64(amount.as_deref().unwrap_or(""),"Amount")?;
    let destination=destination.unwrap_or_default();
    if (action_core=="TRANSFER"||action_core=="UNSHIELD") && destination.trim().is_empty(){return Err("Destination is required".into());}
    let chain=network_root(&network).map_err(String::from)?;
    let wdir=wallet_dir(&network,&wallet).map_err(String::from)?;
    let chain_s=chain.to_string_lossy().to_string(); let wdir_s=wdir.to_string_lossy().to_string();
    let prep=run_qrx(Some(&app),&["prepare-privacy-payload",&chain_s,&wdir_s,action_core,&amount,destination.trim()],passphrase.as_deref(),None).map_err(String::from)?;
    let payload=extract_core_kv(&prep,"payload").ok_or_else(||"QRX Core did not return a privacy payload".to_string())?;
    let address=generals_address(&network,&wallet)?; let (ed,ml)=generals_public_keys(&network,&wallet)?;
    let hval=run_cli(Some(&app),&network,&wallet,&["getblockcount"],passphrase.as_deref()).map_err(String::from)?.result;
    let h=hval.as_i64().or_else(||hval.as_str().and_then(|x|x.parse().ok())).unwrap_or(0); let expiry=(h+240).to_string();
    let (tx_type,to,public_amount)=match action_core{
        "SHIELD"=>("PRIVACY_SHIELD",address.clone(),amount.clone()),
        "TRANSFER"=>("PRIVACY_TRANSFER",address.clone(),"0".to_string()),
        "UNSHIELD"=>("PRIVACY_UNSHIELD",destination.trim().to_string(),amount.clone()),
        _=>unreachable!()
    };
    let created=run_cli(Some(&app),&network,&wallet,&["createvelocitytransaction",&address,&to,&public_amount,&ed,&ml,tx_type,"6",&expiry,&payload],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;
    let broadcast=sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"privacy-consensus")?;
    Ok(serde_json::json!({"ok":true,"consensus":true,"tx_type":tx_type,"public_amount_atoms":public_amount,"destination":to,"broadcast":broadcast}))
}

#[tauri::command]
fn shielded_address_create(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, passphrase: Option<String>) -> Result<String,String>{
 let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
 run_cli_raw(Some(&app),&network,&wallet,&["shielded-address"],passphrase.as_deref()).map_err(|e|e.to_string())
}

#[tauri::command]
fn privacy_action_preview(action: String, amount: Option<String>, destination: Option<String>) -> Result<PrivacyActionPreview, String> {
    let a=action.trim().to_lowercase(); let amount=amount.unwrap_or_default(); let destination=destination.unwrap_or_default();
    let (title,summary,cmd)=match a.as_str(){
      "privacy_shield"|"shield"=>("Shield transparent QUB",format!("Move {} QUB into the shielded pool.",amount),format!("PRIVACY_SHIELD amount={} destination={}",amount,destination)),
      "privacy_transfer"|"shielded-send"=>("Send shielded QUB",format!("Send {} shielded QUB to {}.",amount,destination),format!("PRIVACY_TRANSFER destination={} amount={}",destination,amount)),
      "privacy_unshield"|"unshield"=>("Unshield QUB",format!("Move {} QUB to transparent address {}.",amount,destination),format!("PRIVACY_UNSHIELD destination={} amount={}",destination,amount)),
      _=>return Err("Choose PRIVACY_SHIELD, PRIVACY_TRANSFER or PRIVACY_UNSHIELD".into())};
    Ok(PrivacyActionPreview{action:a,title:title.into(),summary,requirements:vec!["Wallet unlocked for signing".into(),"Active QRX network selected".into(),"Review amount and destination before execution".into()],command_preview:cmd,warning:"Phase 7.1: creates a chain-bound proof bundle, hybrid-signs a PRIVACY_* VELOCITY transaction and broadcasts it to QRX consensus.".into()})
}

#[tauri::command]
fn privacy_get_status() -> Result<PrivacyStatus, String> {
    let mode=read_setting("privacy_mode.txt","standard");
    Ok(PrivacyStatus{mode,level:"core-backed-optional-privacy".into(),active_features:vec!["local QUB keys".into(),"coin/source control".into(),"address reuse warnings".into(),"shielded QUB commands".into(),"stealth addresses".into()],planned_features:vec![],disclaimer:"Privacy-enhanced does not mean anonymous or untraceable. Network and endpoint metadata can still reveal information.".into()})
}

#[tauri::command]
fn privacy_set_mode(mode: String) -> Result<PrivacyStatus, String> {
 let clean=match mode.as_str(){"standard"|"coin_control"|"shielded"=>mode,_=>"standard".into()}; write_setting("privacy_mode.txt",&clean).map_err(String::from)?; privacy_get_status()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletCliPolicy { ReadOnly, ConfirmOnly, Signing }

fn wallet_cli_policy(command: &str) -> WalletCliPolicy {
    if wallet_cli_is_read_only(command) { return WalletCliPolicy::ReadOnly; }
    // Mutations that do not consume a private wallet key. They still require an
    // explicit confirmation, but never a wallet passphrase merely because they
    // change node/test-chain state.
    if matches!(command,
        "faucet"|"addnode"|"walletlock"|"walletlockfor"|"stop"|
        "createrawtransaction"|"createagentregistertransaction"|
        "createagentupdatetransaction"|"createagentrevoketransaction"|
        "createordertransaction"|"createexternalordertransaction"|
        "createarbitragehedgetransaction"|"creategatewayregistertransaction"|
        "creategatewayrevoketransaction"|"createexecutionreporttransaction"|
        "createbtcspvheadertransaction"|"createbtcspvfundingprooftransaction"|
        "createcrosschainbuytransaction"|"createcrosschainselltransaction"|
        "createcrosschainredeemtransaction"|"createcrosschainrefundtransaction"|
        "createordercanceltransaction"|"createorderreplacetransaction"|
        "createvelocitytransaction"
    ) { return WalletCliPolicy::ConfirmOnly; }
    WalletCliPolicy::Signing
}

fn wallet_cli_is_read_only(command: &str) -> bool {
    matches!(command,
        "getinfo"|"address"|"receive"|"listaddresses"|"getbalance"|"getblockcount"|
        "getaddressnonce"|"getnoncelanes"|"getagent"|"listagents"|"getagentlimits"|
        "getorder"|"listorders"|"gettrade"|"listtrades"|"getorderbook"|"getassetbalance"|
        "listassets"|"gettradinginfo"|"getgateway"|"listgateways"|"getexecutionreport"|
        "getstateroot"|"getsettlement"|"getcrosschaininfo"|"getcrosschainswap"|
        "listcrosschainswaps"|"getcrosschainorderbook"|"getbtchtlctemplate"|"getbtcspvinfo"|
        "getbtcbestheader"|"getbtcheader"|"verifybtcproof"|"getbtcconfirmations"|
        "verifycrosschainfunding"|"getcrosschainfunding"|"getcrosschainsecurity"|
        "getvelocityinfo"|"getvelocityengineinfo"|"getblockchaininfo"|"getnetworkinfo"|
        "getnodestatus"|"getuptime"|"getbuildinfo"|"getmempoolinfo"|"getrecentblocks"|
        "getrecenttransactions"|"getvalidatorstatus"|"getblockproducerinfo"|"getfeeinfo"|
        "getpeerinfo"|"getstakinginfo"|"getwalletinfo"|"getreward"|"getparams"|"getprotocolinfo"|
        "gethalving"|"getforks"|"getactivefork"|"history"|"listpeers"|"peerstatus"|
        "banscores"|"validator-set"|"tokenomics"|"getdevaddress"|"getswap"|"listswaps"|
        "shielded-balance"|"shielded-history"|"stealth-history"|"privacy-feature-status"|
        "decoderawtransaction"|"gettxid"
    )
}

// The GUI already supplies network/datadir/wallet to qrx-cli. Accept those
// familiar global flags in the command box for CLI parity, but strip them before
// command classification/execution so `--network alpha getwalletinfo` is still
// recognised as read-only and cannot override the selected GUI context.
fn wallet_cli_normalize_arguments(arguments: &[String], selected_network: &str, selected_wallet: &str) -> Result<Vec<String>,String> {
    let mut out=Vec::new(); let mut i=0usize;
    while i<arguments.len() {
        match arguments[i].as_str() {
            "--network" => {
                let v=arguments.get(i+1).ok_or_else(||"--network requires a value".to_string())?;
                if v!=selected_network { return Err(format!("Command network '{}' does not match selected GUI network '{}'",v,selected_network)); }
                i+=2;
            },
            "--wallet" => {
                let v=arguments.get(i+1).ok_or_else(||"--wallet requires a value".to_string())?;
                if v!=selected_wallet { return Err(format!("Command wallet '{}' does not match selected GUI wallet '{}'",v,selected_wallet)); }
                i+=2;
            },
            "--datadir" => { if arguments.get(i+1).is_none(){return Err("--datadir requires a value".into());} i+=2; },
            _ => { out.extend_from_slice(&arguments[i..]); break; }
        }
    }
    if out.is_empty(){return Err("Enter a qrx-cli command after global options".into());}
    Ok(out)
}

#[tauri::command]
fn wallet_cli_capabilities() -> Value {
    serde_json::json!({
        "surface":"qrx-cli",
        "coverage":"all qrx-cli commands",
        "policy":"read-only / confirm-only / signing",
        "mutations_require_confirmation":true,
        "signing_commands_require_wallet_passphrase":true,
        "confirm_only_examples":["faucet","addnode","walletlock","stop"],
        "human_unlock_command":"walletpassphrase (normal words; GUI uses masked Wallet Security field; terminal qrx-cli prompts with echo disabled)",
        "advanced_unlock_transport":"walletpassphrasehex is retained for low-level compatibility only; users do not manually convert passphrases to hex",
        "complete_trade_selector":"qrx list-trades <chain-dir> * all",
        "complete_ledger_command":"qrx-wallet-cli export-ledger",
        "note":"Global --network/--wallet/--datadir arguments are normalized; the desktop command center passes command arguments directly without a shell."
    })
}

#[tauri::command]
fn wallet_cli_execute(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,arguments:Vec<String>,confirmed:bool,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    if arguments.is_empty(){return Err("Enter a qrx-cli command".into());}
    if arguments.len()>64{return Err("Too many command arguments".into());}
    for value in &arguments{if value.contains('\0')||value.len()>131072{return Err("Invalid or oversized command argument".into());}}
    let normalized=wallet_cli_normalize_arguments(&arguments,&network,&wallet)?;
    let policy=wallet_cli_policy(normalized[0].as_str());
    if policy!=WalletCliPolicy::ReadOnly&&!confirmed{return Err("This command can change wallet, node or chain state. Confirm it explicitly first.".into());}
    if policy==WalletCliPolicy::Signing&&passphrase.as_deref().unwrap_or("").is_empty(){return Err("This command requires wallet signing. Unlock the wallet first.".into());}
    let refs=normalized.iter().map(String::as_str).collect::<Vec<_>>();
    run_cli(Some(&app),&network,&wallet,&refs,passphrase.as_deref()).map_err(|e|e.to_string())
}


#[tauri::command]
fn generate_qr_svg(payload: String) -> Result<String, String> {
    if payload.trim().is_empty() {
        return Err("cannot generate a QR code for an empty address".to_string());
    }
    let code = qrcode::QrCode::new(payload.as_bytes()).map_err(|e| format!("QR generation failed: {e}"))?;
    Ok(code.render::<qrcode::render::svg::Color>().min_dimensions(220, 220).build())
}



#[derive(Debug, Serialize, Deserialize, Clone)]
struct AddressBookEntry {
    id: String,
    label: String,
    chain: String,
    address: String,
    note: String,
    tags: Vec<String>,
    created_unix: u64,
    updated_unix: u64,
}

fn address_book_path() -> Result<PathBuf, String> {
    Ok(app_data_dir().map_err(|e|e.to_string())?.join("addressbook.json"))
}

fn address_book_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d|d.as_secs()).unwrap_or(0)
}

fn read_address_book() -> Result<Vec<AddressBookEntry>, String> {
    let path=address_book_path()?;
    if !path.exists(){return Ok(Vec::new())}
    let raw=fs::read_to_string(&path).map_err(|e|format!("Could not read address book: {e}"))?;
    serde_json::from_str(&raw).map_err(|e|format!("Address book JSON is invalid: {e}"))
}

fn write_address_book(entries:&[AddressBookEntry]) -> Result<(), String> {
    let path=address_book_path()?;
    if let Some(parent)=path.parent(){fs::create_dir_all(parent).map_err(|e|e.to_string())?;}
    let tmp=path.with_extension(format!("tmp-{}",std::process::id()));
    let data=serde_json::to_vec_pretty(entries).map_err(|e|e.to_string())?;
    {
        let mut options=OpenOptions::new();options.write(true).create(true).truncate(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut f=options.open(&tmp).map_err(|e|e.to_string())?;
        f.write_all(&data).and_then(|_|f.sync_all()).map_err(|e|e.to_string())?;
    }
    #[cfg(windows)] { if path.exists(){fs::remove_file(&path).map_err(|e|e.to_string())?;} }
    fs::rename(&tmp,&path).map_err(|e|e.to_string())?;
    Ok(())
}

fn validate_book_address(chain:&str,address:&str)->Result<(),String>{
    let chain=chain.trim().to_ascii_uppercase();let address=address.trim();
    if chain=="QUB" {
        if !address.starts_with("qrx1") || address.len()<40 || !address.chars().all(|c|c.is_ascii_alphanumeric()) {
            return Err("Invalid QUB address. Expected a qrx1… address.".into())
        }
        return Ok(())
    }
    if chain=="BTC" {
        let parsed=Address::from_str(address).map_err(|e|format!("Invalid BTC address: {e}"))?;
        parsed.require_network(Network::Bitcoin).map_err(|_|"BTC address is not a Bitcoin mainnet address".to_string())?;
        return Ok(())
    }
    Err("Address book chain must be QUB or BTC".into())
}

#[tauri::command]
fn address_book_list() -> Result<Vec<AddressBookEntry>,String>{
    let mut v=read_address_book()?;v.sort_by(|a,b|a.label.to_lowercase().cmp(&b.label.to_lowercase()));Ok(v)
}

#[tauri::command]
fn address_book_upsert(id:Option<String>,label:String,chain:String,address:String,note:Option<String>,tags:Option<String>)->Result<AddressBookEntry,String>{
    let label=label.trim();if label.is_empty(){return Err("Contact name is required".into())}
    let chain=chain.trim().to_ascii_uppercase();let address=address.trim().to_string();validate_book_address(&chain,&address)?;
    let now=address_book_now();let mut entries=read_address_book()?;
    if entries.iter().any(|e|e.address==address && e.chain==chain && id.as_deref()!=Some(e.id.as_str())) {return Err("This address is already saved in the address book".into())}
    let tag_vec=tags.unwrap_or_default().split(',').map(str::trim).filter(|s|!s.is_empty()).map(str::to_string).collect::<Vec<_>>();
    let note=note.unwrap_or_default().trim().to_string();
    let entry=if let Some(idv)=id.filter(|x|!x.trim().is_empty()) {
        let pos=entries.iter().position(|e|e.id==idv).ok_or_else(||"Address book entry not found".to_string())?;
        if entries[pos].address!=address || entries[pos].chain!=chain {return Err("Changing a pinned contact address is blocked. Create a new contact instead.".into())}
        entries[pos].label=label.to_string();entries[pos].note=note;entries[pos].tags=tag_vec;entries[pos].updated_unix=now;entries[pos].clone()
    } else {
        let e=AddressBookEntry{id:format!("contact-{now}-{}",rand::random::<u32>()),label:label.to_string(),chain,address,note,tags:tag_vec,created_unix:now,updated_unix:now};entries.push(e.clone());e
    };
    write_address_book(&entries)?;Ok(entry)
}

#[tauri::command]
fn address_book_delete(id:String)->Result<String,String>{
    let mut entries=read_address_book()?;let before=entries.len();entries.retain(|e|e.id!=id);if entries.len()==before{return Err("Address book entry not found".into())}write_address_book(&entries)?;Ok("Address book entry deleted".into())
}

#[tauri::command]
fn address_book_export()->Result<String,String>{serde_json::to_string_pretty(&read_address_book()?).map_err(|e|e.to_string())}

#[tauri::command]
fn address_book_import_json(payload:String)->Result<usize,String>{
    let incoming:Vec<AddressBookEntry>=serde_json::from_str(&payload).map_err(|e|format!("Invalid address-book JSON: {e}"))?;
    let mut entries=read_address_book()?;let mut added=0usize;
    for mut e in incoming {validate_book_address(&e.chain,&e.address)?;if entries.iter().any(|x|x.chain.eq_ignore_ascii_case(&e.chain)&&x.address==e.address){continue}e.id=format!("contact-{}-{}",address_book_now(),rand::random::<u32>());e.created_unix=address_book_now();e.updated_unix=e.created_unix;entries.push(e);added+=1;}
    write_address_book(&entries)?;Ok(added)
}



fn parse_kv_text(raw:&str)->serde_json::Map<String,Value>{
    let mut m=serde_json::Map::new();
    for line in raw.lines(){if let Some((k,v))=line.split_once('='){m.insert(k.trim().to_string(),Value::String(v.trim().to_string()));}}
    m
}
fn generals_qrx_kv(app:&tauri::AppHandle,args:Vec<String>)->Result<Value,String>{
    let refs=args.iter().map(String::as_str).collect::<Vec<_>>();
    let raw=run_qrx(Some(app),&refs,None,None).map_err(String::from)?;
    Ok(Value::Object(parse_kv_text(&raw)))
}
fn generals_address(network:&str,wallet:&str)->Result<String,String>{
    let dir=wallet_dir(network,wallet).map_err(String::from)?;
    read_address(&dir).ok_or_else(||"Wallet address unavailable".to_string()).map(|s|s.trim().to_string())
}
fn generals_public_keys(network:&str,wallet:&str)->Result<(String,String),String>{
    let dir=wallet_dir(network,wallet).map_err(String::from)?;
    let ed=fs::read(dir.join("ed25519_pub.pem")).map_err(|e|e.to_string())?;
    let p=PKey::public_key_from_pem(&ed).map_err(|e|e.to_string())?;
    let raw=p.raw_public_key().map_err(|e|e.to_string())?;
    if raw.len()!=32{return Err("Ed25519 public key is not 32 bytes".into());}
    let edhex=raw.iter().map(|b|format!("{b:02x}")).collect::<String>();
    let ml=fs::read(dir.join("mldsa65_pub.pem")).map_err(|e|e.to_string())?;
    let mlb64=general_purpose::STANDARD.encode(ml);
    Ok((edhex,mlb64))
}

#[tauri::command]
fn generals_order_commitment(canonical:String)->Result<String,String>{
    if canonical.len()>8192{return Err("Order canonical text too large".into());}
    let mut h=Hasher::new(MessageDigest::sha3_512()).map_err(|e|e.to_string())?;h.update(canonical.as_bytes()).map_err(|e|e.to_string())?;let d=h.finish().map_err(|e|e.to_string())?;
    Ok(d.iter().map(|b|format!("{b:02x}")).collect())
}

#[tauri::command]
fn generals_snapshot(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>)->Result<Value,String>{
    let network=network.unwrap_or_else(||"mainnet".into());
    let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let ctx=ensure_context(&network,&wallet).map_err(String::from)?;
    let address=generals_address(&network,&wallet)?;
    let chain=ctx.data_dir.clone();
    let world=generals_qrx_kv(&app,vec!["generals-world-info".into(),chain.clone()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
    let season=generals_qrx_kv(&app,vec!["generals-season-info".into(),chain.clone()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
    let player=generals_qrx_kv(&app,vec!["generals-player-info".into(),chain.clone(),address.clone()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
    let treasury=generals_qrx_kv(&app,vec!["generals-treasury-info".into(),chain.clone()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
    let sid=world.get("season_id").and_then(Value::as_str).and_then(|x|x.parse::<i64>().ok()).unwrap_or(0);
    let mut units=Vec::new(); let mut army=serde_json::json!({});
    let mut logistics=serde_json::json!({}); let mut economy=serde_json::json!({}); let mut research=serde_json::json!({}); let mut doctrine=serde_json::json!({}); let mut ranking=serde_json::json!({}); let mut clan=serde_json::json!({}); let mut clan_directive=serde_json::json!({}); let mut clan_ranking=serde_json::json!({}); let mut rewards=serde_json::json!({}); let mut tech_tree=serde_json::json!({});
    let mut previous_season=serde_json::json!({});
    let mut region=Vec::<Value>::new();
    if sid>0 && player.get("error").is_none(){
        army=generals_qrx_kv(&app,vec!["generals-player-army-info".into(),chain.clone(),address.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        if let Some(obj)=army.as_object(){
            for (k,v) in obj{if (k.starts_with("unit_")||k.starts_with("support_unit_"))&&!k.ends_with("count"){if let Some(uid)=v.as_str(){if uid.is_empty(){continue} let u=generals_qrx_kv(&app,vec!["generals-unit-info".into(),chain.clone(),uid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e,"unit_id":uid}));units.push(u);}}}
        }
        logistics=generals_qrx_kv(&app,vec!["generals-logistics-info".into(),chain.clone(),address.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        economy=generals_qrx_kv(&app,vec!["generals-economy-info".into(),chain.clone(),address.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        research=generals_qrx_kv(&app,vec!["generals-research-info".into(),chain.clone(),address.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        doctrine=generals_qrx_kv(&app,vec!["generals-doctrine-info".into(),chain.clone(),address.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        ranking=generals_qrx_kv(&app,vec!["generals-ranking-info".into(),chain.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        tech_tree=generals_qrx_kv(&app,vec!["generals-tech-tree".into(),chain.clone(),address.clone(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));
        if let Some(cid)=player.get("clan_id").and_then(Value::as_str).filter(|x|!x.is_empty()){clan=generals_qrx_kv(&app,vec!["generals-clan-info".into(),chain.clone(),cid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));clan_directive=generals_qrx_kv(&app,vec!["generals-clan-directive-info".into(),chain.clone(),cid.to_string(),sid.to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));}
        if sid>1{clan_ranking=generals_qrx_kv(&app,vec!["generals-clan-ranking-info".into(),chain.clone(),(sid-1).to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));rewards=generals_qrx_kv(&app,vec!["generals-season-rewards-info".into(),chain.clone(),(sid-1).to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));previous_season=generals_qrx_kv(&app,vec!["generals-season-result-info".into(),chain.clone(),(sid-1).to_string()]).unwrap_or_else(|e|serde_json::json!({"error":e}));}
        let cx=units.iter().find_map(|u|u.get("type").and_then(Value::as_str).filter(|x|*x=="HQ").and_then(|_|u.get("x").and_then(Value::as_str)).and_then(|x|x.parse::<i64>().ok())).unwrap_or(8);
        let cy=units.iter().find_map(|u|u.get("type").and_then(Value::as_str).filter(|x|*x=="HQ").and_then(|_|u.get("y").and_then(Value::as_str)).and_then(|x|x.parse::<i64>().ok())).unwrap_or(8);
        let args=vec!["generals-region-info".into(),chain.clone(),sid.to_string(),(cx-9).max(0).to_string(),(cy-6).max(0).to_string(),"19".into(),"13".into()];
        let refs=args.iter().map(String::as_str).collect::<Vec<_>>();
        if let Ok(raw)=run_qrx(Some(&app),&refs,None,None){for line in raw.lines(){if let Some(v)=line.strip_prefix("tile="){let parts=v.split(',').collect::<Vec<_>>();if parts.len()>=6{region.push(serde_json::json!({"x":parts[0],"y":parts[1],"terrain":parts[2],"unit_id":parts[3],"owner":parts[4],"feature":parts[5]}));}}}}
    }
    Ok(serde_json::json!({"context":ctx,"address":address,"world":world,"season":season,"player":player,"army":army,"units":units,"logistics":logistics,"economy":economy,"research":research,"doctrine":doctrine,"treasury":treasury,"ranking":ranking,"clan":clan,"clan_directive":clan_directive,"clan_ranking":clan_ranking,"rewards":rewards,"tech_tree":tech_tree,"previous_season":previous_season,"region":region}))
}

#[tauri::command]
fn generals_submit_action(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,tx_type:String,payload:String,amount_atoms:Option<String>,passphrase:Option<String>)->Result<Value,String>{
    let network=network.unwrap_or_else(||"mainnet".into()); let wallet=sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    if !tx_type.starts_with("GAME_"){return Err("Only GAME_* transactions are allowed from Generals".into());}
    if payload.len()>8192{return Err("Generals payload too large".into());}
    let address=generals_address(&network,&wallet)?; let (ed,ml)=generals_public_keys(&network,&wallet)?;
    let height=run_cli(Some(&app),&network,&wallet,&["getblockcount"],passphrase.as_deref()).map_err(String::from)?.result;
    let h=height.as_i64().or_else(||height.as_str().and_then(|x|x.parse().ok())).unwrap_or(0); let expiry=(h+240).to_string(); let amount=amount_atoms.unwrap_or_else(||"0".into());
    let created=run_cli(Some(&app),&network,&wallet,&["createvelocitytransaction",&address,&address,&amount,&ed,&ml,&tx_type,"7",&expiry,&payload],passphrase.as_deref()).map_err(String::from)?;
    let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return raw_tx".to_string())?;
    let body_hash=raw.lines().find_map(|l|l.strip_prefix("body_hash_sha3_512=")).unwrap_or("").to_string();
    let predicted_order_id=if tx_type=="GAME_ORDER_COMMIT" && body_hash.len()>=24{format!("ORD-{}",&body_hash[..24])}else{String::new()};
    let broadcast=sign_and_broadcast_raw(&app,&network,&wallet,raw,passphrase.as_deref(),"generals")?;
    Ok(serde_json::json!({"tx_type":tx_type,"payload":payload,"body_hash":body_hash,"predicted_order_id":predicted_order_id,"broadcast":broadcast}))
}

#[tauri::command]
fn open_aura_window(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<String, String> {
    if let Some(window) = app.get_window("qrx-aura") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok("AURA focused.".to_string());
    }
    tauri::WindowBuilder::new(
        &app,
        "qrx-aura",
        tauri::WindowUrl::App(format!("aura/index.html?network={}&wallet={}", network.unwrap_or_else(|| "mainnet".into()), sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?).into()),
    )
    .title("AURA · QRX Assistant")
    .inner_size(980.0, 760.0)
    .min_inner_size(640.0, 520.0)
    .resizable(true)
    .center()
    .build()
    .map_err(|e| format!("Could not create AURA window: {e}"))?;
    Ok("AURA opened in its own window.".to_string())
}

#[tauri::command]
fn open_generals_window(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, demo: Option<bool>) -> Result<String, String> {
    if let Some(window) = app.get_window("qrx-generals") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok("QRX Generals focused.".to_string());
    }
    tauri::WindowBuilder::new(
        &app,
        "qrx-generals",
        tauri::WindowUrl::App(format!("generals/index.html?network={}&wallet={}&demo={}", network.unwrap_or_else(|| "mainnet".into()), sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?, if demo.unwrap_or(false) { "1" } else { "0" }).into()),
    )
    .title("QRX Generals")
    .inner_size(1440.0, 900.0)
    .min_inner_size(1024.0, 680.0)
    .resizable(true)
    .center()
    .build()
    .map_err(|e| format!("Could not create QRX Generals window: {e}"))?;
    Ok("QRX Generals opened in its own window.".to_string())
}



fn family_policy_path(network:&str,wallet:&str)->Result<PathBuf,String>{
    let dir=wallet_dir(network,wallet).map_err(String::from)?; Ok(dir.join("family-safety.qrxvault"))
}
fn validate_family_policy(p:&FamilySafetyPolicy)->Result<(),String>{
    if p.version!=1 || !matches!(p.profile.as_str(),"adult"|"teen"|"child") || p.max_age_rating>21 || p.session_minutes>1440 || p.allow_domains.len()>32 || p.block_domains.len()>32 {return Err("Invalid Family Safety policy".into());}
    if (p.profile=="child"||p.profile=="teen") && (!p.ads_blocked || !p.viewer_rewards_blocked) {return Err("Youth profiles must keep sponsored ads and viewer rewards disabled".into());}
    Ok(())
}
fn encrypt_family_policy(p:&FamilySafetyPolicy,pin:&str)->Result<FamilySafetyVault,String>{
    if pin.len()<4{return Err("Guardian PIN must contain at least 4 characters".into());} validate_family_policy(p)?;
    let bytes=serde_json::to_vec(p).map_err(|e|e.to_string())?; let mut salt=[0u8;16];rand::thread_rng().fill_bytes(&mut salt);let key=derive_secret_key(pin,&salt)?;let cipher=Aes256Gcm::new_from_slice(&key).map_err(|e|e.to_string())?;let mut nb=[0u8;12];rand::thread_rng().fill_bytes(&mut nb);let ct=cipher.encrypt(Nonce::from_slice(&nb),bytes.as_ref()).map_err(|e|e.to_string())?;
    Ok(FamilySafetyVault{version:1,kdf:"argon2id-m65536-t3-p1".into(),cipher:"aes-256-gcm".into(),kdf_salt:general_purpose::STANDARD.encode(salt),nonce:general_purpose::STANDARD.encode(nb),ciphertext:general_purpose::STANDARD.encode(ct)})
}
fn decrypt_family_policy(v:&FamilySafetyVault,pin:&str)->Result<FamilySafetyPolicy,String>{
    if v.version!=1||v.cipher!="aes-256-gcm"{return Err("Unsupported Family Safety vault".into());}let salt=general_purpose::STANDARD.decode(&v.kdf_salt).map_err(|e|e.to_string())?;let nb=general_purpose::STANDARD.decode(&v.nonce).map_err(|e|e.to_string())?;let ct=general_purpose::STANDARD.decode(&v.ciphertext).map_err(|e|e.to_string())?;if nb.len()!=12{return Err("Invalid Family Safety vault nonce".into());}let key=derive_secret_key(pin,&salt)?;let cipher=Aes256Gcm::new_from_slice(&key).map_err(|e|e.to_string())?;let mut pt=cipher.decrypt(Nonce::from_slice(&nb),ct.as_ref()).map_err(|_|"Guardian PIN incorrect or Family Safety vault was modified".to_string())?;let p:FamilySafetyPolicy=serde_json::from_slice(&pt).map_err(|e|e.to_string())?;pt.fill(0);validate_family_policy(&p)?;Ok(p)
}
#[tauri::command]
fn qrx_family_policy_set(network:String,wallet:String,policy:FamilySafetyPolicy,guardian_pin:String)->Result<Value,String>{
    let path=family_policy_path(&network,&wallet)?;if let Some(parent)=path.parent(){fs::create_dir_all(parent).map_err(|e|e.to_string())?;}let vault=encrypt_family_policy(&policy,&guardian_pin)?;let tmp=path.with_extension("tmp");fs::write(&tmp,serde_json::to_vec_pretty(&vault).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;protect_private_file(&tmp)?;fs::rename(&tmp,&path).map_err(|e|e.to_string())?;protect_private_file(&path)?;Ok(serde_json::json!({"saved":true,"encrypted_at_rest":true,"profile":policy.profile}))
}
#[tauri::command]
fn qrx_family_policy_get(network:String,wallet:String,guardian_pin:String)->Result<Value,String>{
    let path=family_policy_path(&network,&wallet)?;if !path.exists(){return Ok(serde_json::json!({"configured":false}));}let v:FamilySafetyVault=serde_json::from_slice(&fs::read(&path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;let p=decrypt_family_policy(&v,&guardian_pin)?;Ok(serde_json::json!({"configured":true,"policy":p,"encrypted_at_rest":true}))
}
#[tauri::command]
fn qrx_family_policy_status(network:String,wallet:String)->Result<Value,String>{let path=family_policy_path(&network,&wallet)?;Ok(serde_json::json!({"configured":path.exists(),"encrypted_at_rest":path.exists()}))}

#[tauri::command]
fn open_qrx_browser_window(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<String, String> {
    let network = network.unwrap_or_else(|| "mainnet".into());
    if !matches!(network.as_str(), "mainnet" | "alpha" | "testnet" | "regtest") {
        return Err("Unsupported QRX Browser network".into());
    }
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("default")).map_err(String::from)?;
    let browser = resolve_binary(Some(&app), "qrx-browser").map_err(String::from)?;
    Command::new(browser)
        .arg("--network").arg(&network)
        .arg("--wallet").arg(&wallet)
        .env("QRX_BIN_DIR", app.path_resolver().resource_dir().unwrap_or_else(|| PathBuf::from(".")))
        .spawn()
        .map_err(|e| format!("Could not start QRX Browser sidecar: {e}"))?;
    Ok(format!("QRX Browser started for {network}/{wallet}."))
}

#[tauri::command]
fn open_browser_www_window(app: tauri::AppHandle, url: String) -> Result<String, String> {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") { return Err("QRX Browser WWW route permits HTTPS URLs only.".into()); }
    if trimmed.chars().any(|c| c.is_control()) { return Err("Invalid control character in URL.".into()); }
    let parsed = trimmed.parse().map_err(|e| format!("Invalid HTTPS URL: {e}"))?;
    if let Some(w) = app.get_window("qrx-www-content") { let _ = w.close(); }
    tauri::WindowBuilder::new(&app, "qrx-www-content", tauri::WindowUrl::External(parsed))
        .title(format!("QRX Browser · {}", trimmed))
        .inner_size(1200.0, 820.0).min_inner_size(720.0, 520.0).resizable(true).center()
        .build().map_err(|e| format!("Could not open WWW webview: {e}"))?;
    Ok(trimmed.to_string())
}

#[tauri::command]
fn open_qrx_upscaler_window(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<String, String> {
    if let Some(window) = app.get_window("qrx-upscaler") {
        window.show().map_err(|e| e.to_string())?;
        window.set_focus().map_err(|e| e.to_string())?;
        return Ok("QRX Upscaler focused.".to_string());
    }
    tauri::WindowBuilder::new(
        &app,
        "qrx-upscaler",
        tauri::WindowUrl::App(format!("upscaler/index.html?network={}&wallet={}", network.unwrap_or_else(|| "mainnet".into()), sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?).into()),
    )
    .title("QRX Upscaler")
    .inner_size(1280.0, 820.0)
    .min_inner_size(900.0, 620.0)
    .resizable(true)
    .center()
    .build()
    .map_err(|e| format!("Could not create QRX Upscaler window: {e}"))?;
    Ok("QRX Upscaler opened in its own window.".to_string())
}


fn apply_packaged_upscaler_ai_env(app: &tauri::AppHandle, cmd: &mut Command) {
    if let Some(resource_dir) = app.path_resolver().resource_dir() {
        let roots = [resource_dir.join("upscaler"), resource_dir.join("resources").join("upscaler")];
        for root in roots {
            let runtime = root.join("runtime").join(if cfg!(target_os = "windows") { "realesrgan-ncnn-vulkan.exe" } else { "realesrgan-ncnn-vulkan" });
            let models = root.join("models");
            let runtime_hash = root.join("runtime").join("runtime.sha256");
            if runtime.is_file() && models.is_dir() {
                cmd.env("QRX_UPSCALER_NCNN_RUNTIME", &runtime);
                cmd.env("QRX_UPSCALER_MODEL_DIR", &models);
                if let Ok(v) = fs::read_to_string(runtime_hash) {
                    let h = v.trim();
                    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                        cmd.env("QRX_UPSCALER_RUNTIME_SHA256", h);
                    }
                }
                break;
            }
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct UpscalerJobView {
    id: String,
    state: String,
    phase: String,
    progress: u8,
    indeterminate: bool,
    elapsed_ms: u64,
    last_activity_ms: u64,
    output: String,
    error: String,
    log: Vec<String>,
    cancel_requested: bool,
}

struct UpscalerJob {
    view: UpscalerJobView,
    started: Instant,
    last_activity: Instant,
    cancel: Arc<AtomicBool>,
}

static UPSCALER_JOBS: OnceLock<Mutex<HashMap<String, UpscalerJob>>> = OnceLock::new();
fn upscaler_jobs() -> &'static Mutex<HashMap<String, UpscalerJob>> { UPSCALER_JOBS.get_or_init(|| Mutex::new(HashMap::new())) }

fn upscaler_job_update(id: &str, f: impl FnOnce(&mut UpscalerJob)) {
    if let Ok(mut jobs) = upscaler_jobs().lock() { if let Some(j) = jobs.get_mut(id) { f(j); } }
}

#[tauri::command]
fn upscaler_start_local(app: tauri::AppHandle, input: String, output: String, scale: u8, filter: String, engine: Option<String>, tile: Option<u32>, model: Option<String>) -> Result<Value, String> {
    let engine = engine.unwrap_or_else(|| "classical".into()).trim().to_ascii_lowercase();
    let input_path = PathBuf::from(&input);
    if !input_path.is_file() { return Err("Selected media file does not exist.".into()); }
    let output_path = PathBuf::from(&output);
    if input_path == output_path { return Err("Output must not overwrite the input file.".into()); }
    let ext = input_path.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
    let is_video = matches!(ext.as_str(), "mp4" | "mov" | "mkv" | "webm");
    let binary = resolve_binary(Some(&app), "qrx-upscaler").map_err(String::from)?;
    let mut cmd = background_command(binary);
    apply_packaged_upscaler_ai_env(&app, &mut cmd);
    if engine == "ai" {
        if is_video { return Err("AI video uses the Video Pipeline planner in 0.0.9.67; local single-image AI jobs are enabled here.".into()); }
        if !matches!(scale, 2 | 4) { return Err("AI Super Resolution supports 2× or 4×.".into()); }
        let t = tile.unwrap_or(0).min(2048);
        cmd.arg("ai-image").arg(&input_path).arg(&output_path).arg("--scale").arg(scale.to_string()).arg("--tile").arg(t.to_string());
        if let Some(m) = model.as_deref().map(str::trim).filter(|x| !x.is_empty()) { cmd.arg("--model").arg(m); }
    } else {
        if !(1..=8).contains(&scale) { return Err("Upscaler scale must be between 1 and 8.".into()); }
        let filter = filter.trim().to_ascii_lowercase();
        if !matches!(filter.as_str(), "nearest" | "bilinear" | "bicubic" | "lanczos3") { return Err("Unsupported Upscaler filter.".into()); }
        cmd.arg(if is_video { "video" } else { "image" }).arg(&input_path).arg(&output_path).arg("--scale").arg(scale.to_string()).arg("--filter").arg(&filter);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let id = format!("ups-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis());
    let cancel = Arc::new(AtomicBool::new(false));
    let now = Instant::now();
    upscaler_jobs().lock().map_err(|_| "Upscaler job manager lock failed")?.insert(id.clone(), UpscalerJob { view: UpscalerJobView { id:id.clone(), state:"queued".into(), phase:"Starting runtime".into(), progress:3, indeterminate:true, elapsed_ms:0, last_activity_ms:0, output:output.clone(), error:String::new(), log:vec![format!("Queued {} {}× job", engine, scale)] , cancel_requested:false }, started:now, last_activity:now, cancel:cancel.clone() });
    let jid=id.clone();
    std::thread::spawn(move || {
        upscaler_job_update(&jid, |j| { j.view.state="running".into(); j.view.phase=if engine=="ai"{"AI inference".into()}else{"Local processing".into()}; j.view.progress=10; });
        let mut child=match cmd.spawn(){Ok(c)=>c,Err(e)=>{upscaler_job_update(&jid,|j|{j.view.state="failed".into();j.view.error=format!("Could not run QRX Upscaler: {e}");j.view.indeterminate=false;});return;}};
        let (tx,rx)=std::sync::mpsc::channel::<String>();
        if let Some(out)=child.stdout.take(){let tx=tx.clone();std::thread::spawn(move||for l in BufReader::new(out).lines().flatten(){let _=tx.send(l);});}
        if let Some(err)=child.stderr.take(){let tx=tx.clone();std::thread::spawn(move||for l in BufReader::new(err).lines().flatten(){let _=tx.send(l);});}
        loop {
            while let Ok(line)=rx.try_recv(){upscaler_job_update(&jid,|j|{j.last_activity=Instant::now();j.view.log.push(line);if j.view.log.len()>120{j.view.log.remove(0);}});}
            if cancel.load(Ordering::Relaxed){let _=child.kill();let _=child.wait();upscaler_job_update(&jid,|j|{j.view.state="cancelled".into();j.view.phase="Cancelled".into();j.view.indeterminate=false;j.view.cancel_requested=true;});break;}
            match child.try_wait(){Ok(Some(st))=>{while let Ok(line)=rx.try_recv(){upscaler_job_update(&jid,|j|j.view.log.push(line));} if st.success(){upscaler_job_update(&jid,|j|{j.view.state="completed".into();j.view.phase="Complete".into();j.view.progress=100;j.view.indeterminate=false;j.last_activity=Instant::now();});}else{upscaler_job_update(&jid,|j|{j.view.state="failed".into();j.view.phase="Failed".into();j.view.indeterminate=false;j.view.error=format!("Upscaler exited with {st}");});}break;},Ok(None)=>std::thread::sleep(Duration::from_millis(150)),Err(e)=>{upscaler_job_update(&jid,|j|{j.view.state="failed".into();j.view.error=e.to_string();j.view.indeterminate=false;});break;}}
        }
    });
    Ok(serde_json::json!({"ok":true,"job_id":id,"output":output}))
}

#[tauri::command]
fn upscaler_job_status(job_id: String) -> Result<UpscalerJobView, String> {
    let mut jobs=upscaler_jobs().lock().map_err(|_| "Upscaler job manager lock failed")?;
    let j=jobs.get_mut(&job_id).ok_or_else(|| "Upscaler job not found".to_string())?;
    j.view.elapsed_ms=j.started.elapsed().as_millis() as u64;
    j.view.last_activity_ms=j.last_activity.elapsed().as_millis() as u64;
    Ok(j.view.clone())
}

#[tauri::command]
fn upscaler_cancel_job(job_id: String) -> Result<Value, String> {
    let mut jobs=upscaler_jobs().lock().map_err(|_| "Upscaler job manager lock failed")?;
    let j=jobs.get_mut(&job_id).ok_or_else(|| "Upscaler job not found".to_string())?;
    j.cancel.store(true, Ordering::Relaxed); j.view.cancel_requested=true; j.view.phase="Cancelling…".into();
    Ok(serde_json::json!({"ok":true,"job_id":job_id}))
}

#[tauri::command]
fn upscaler_video_pipeline_plan(input: String, scale: u8, batch_frames: Option<u32>, distributed: Option<bool>) -> Result<Value, String> {
    let p=PathBuf::from(&input); if !p.is_file(){return Err("Selected video does not exist.".into());}
    if !matches!(scale,2|4){return Err("AI video pipeline supports 2× or 4×.".into());}
    let batch=batch_frames.unwrap_or(120).clamp(16,2000); let dist=distributed.unwrap_or(false);
    Ok(serde_json::json!({"version":1,"input":input,"scale":scale,"batch_frames":batch,"execution":if dist{"qrx-compute"}else{"local"},"stages":["probe","extract-frames","hash-manifest","batch","upscale","verify-results","ordered-merge","remux-original-audio"],"frame_identity":"sha256(input-id || frame-index || frame-bytes)","result_validation":"dimensions + frame-index + content hash + model id","audio":"copy original audio during final remux","resume":"completed batch journal","compute_protocol":"COMPUTE_POUC_V1","distributed_ready":false,"note":if dist{"Foundation is wired; provider dispatch remains activation-gated and requires explicit opt-in."}else{"Local orchestration foundation ready."}}))
}

#[tauri::command]
fn upscaler_capabilities(app: tauri::AppHandle) -> Result<Value, String> {
    let binary = resolve_binary(Some(&app), "qrx-upscaler").map_err(String::from)?;
    let mut cmd = background_command(binary);
    apply_packaged_upscaler_ai_env(&app, &mut cmd);
    let output = cmd
        .arg("capabilities")
        .output()
        .map_err(|e| format!("Could not run QRX Upscaler capability probe: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "QRX Upscaler capability probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .map_err(|e| format!("Invalid QRX Upscaler capability response: {e}"))
}

#[tauri::command]
fn qrxnet_domain_preflight(app: tauri::AppHandle, network: String, wallet: String, name: String, years: Option<u64>) -> Result<Value, String> {
    let y=years.unwrap_or(1).to_string(); run_cli(Some(&app), &network, &wallet, &["getdomainpreflight", name.as_str(), y.as_str()], None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn qrxnet_register_domain(app: tauri::AppHandle, network: String, wallet: String, name: String, years: u64, qub_address: Option<String>) -> Result<Value, String> {
    let y=years.to_string(); let q=qub_address.unwrap_or_default(); let args=if q.trim().is_empty(){vec!["registerdomain",name.as_str(),y.as_str()]}else{vec!["registerdomain",name.as_str(),y.as_str(),q.as_str()]}; run_cli(Some(&app), &network, &wallet, &args, None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn qrxnet_renew_domain(app: tauri::AppHandle, network: String, wallet: String, name: String, years: u64) -> Result<Value, String> { let y=years.to_string(); run_cli(Some(&app),&network,&wallet,&["renewdomain",name.as_str(),y.as_str()],None).map(|r|r.result).map_err(String::from) }
#[tauri::command]
fn qrxnet_update_domain(app: tauri::AppHandle, network: String, wallet: String, name: String, qub_mode:String, qub_address:String, web_mode:String, web_manifest_root_hex:String, publishing_mode:String, publishing_commitment_hex:String) -> Result<Value,String>{ run_cli(Some(&app),&network,&wallet,&["updatedomain",name.as_str(),qub_mode.as_str(),qub_address.as_str(),web_mode.as_str(),web_manifest_root_hex.as_str(),publishing_mode.as_str(),publishing_commitment_hex.as_str()],None).map(|r|r.result).map_err(String::from) }
#[tauri::command]
fn qrxnet_transfer_domain(app: tauri::AppHandle, network:String, wallet:String, name:String, new_owner:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["transferdomain",name.as_str(),new_owner.as_str()],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_list_domains(app: tauri::AppHandle, network:String, wallet:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["listdomains"],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_domain_history(app: tauri::AppHandle, network:String, wallet:String, name:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["getdomainhistory",name.as_str()],None).map(|r|r.result).map_err(String::from)}

#[tauri::command]
fn qrxnet_ad_policy(app: tauri::AppHandle, network:String, wallet:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["getadpolicy"],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_ad_rewards(app: tauri::AppHandle, network:String, wallet:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["getadrewards"],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_claim_ad_rewards(app: tauri::AppHandle, network:String, wallet:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["claimadrewards"],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_create_ad_campaign(app: tauri::AppHandle, network:String, wallet:String, campaign_id:String, target_url:String, creative_root_hex:String, start_height:u64, end_height:u64, cost_per_impression_atoms:u64, budget_atoms:u64, category:Option<String>)->Result<Value,String>{let a=start_height.to_string();let b=end_height.to_string();let c=cost_per_impression_atoms.to_string();let d=budget_atoms.to_string();let cat=category.unwrap_or_else(||"general".to_string());run_cli(Some(&app),&network,&wallet,&["createadcampaign",campaign_id.as_str(),target_url.as_str(),creative_root_hex.as_str(),a.as_str(),b.as_str(),c.as_str(),d.as_str(),cat.as_str()],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_prepare_site(app: tauri::AppHandle, network:String, wallet:String, name:String, folder:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["prepareqrxsite",name.as_str(),folder.as_str()],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_get_site_publish(app: tauri::AppHandle, network:String, wallet:String, name:String, version:u64)->Result<Value,String>{let v=version.to_string();run_cli(Some(&app),&network,&wallet,&["getqrxsitepublish",name.as_str(),v.as_str()],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_advance_site(app: tauri::AppHandle, network:String, wallet:String, name:String, version:u64)->Result<Value,String>{let v=version.to_string();run_cli(Some(&app),&network,&wallet,&["advanceqrxsite",name.as_str(),v.as_str()],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_site_versions(app: tauri::AppHandle, network:String, wallet:String, name:String)->Result<Value,String>{run_cli(Some(&app),&network,&wallet,&["listqrxsiteversions",name.as_str()],None).map(|r|r.result).map_err(String::from)}
#[tauri::command]
fn qrxnet_rollback_site(app: tauri::AppHandle, network:String, wallet:String, name:String, version:u64)->Result<Value,String>{let v=version.to_string();run_cli(Some(&app),&network,&wallet,&["rollbackqrxsite",name.as_str(),v.as_str()],None).map(|r|r.result).map_err(String::from)}

#[tauri::command]
fn qrxnet_browser_resolve(app: tauri::AppHandle, network:String, wallet:String, input:String)->Result<Value,String>{
    run_cli(Some(&app),&network,&wallet,&["resolvebrowserinput",input.as_str()],None).map(|r|r.result).map_err(String::from)
}
fn qrxnet_mime(path:&str)->&'static str{
    let p=path.to_ascii_lowercase();
    if p.ends_with(".html")||p.ends_with(".htm"){"text/html;charset=utf-8"}
    else if p.ends_with(".css"){"text/css;charset=utf-8"}
    else if p.ends_with(".js")||p.ends_with(".mjs"){"text/javascript;charset=utf-8"}
    else if p.ends_with(".json"){"application/json;charset=utf-8"}
    else if p.ends_with(".svg"){"image/svg+xml"}
    else if p.ends_with(".png"){"image/png"}
    else if p.ends_with(".jpg")||p.ends_with(".jpeg"){"image/jpeg"}
    else if p.ends_with(".webp"){"image/webp"}
    else if p.ends_with(".gif"){"image/gif"}
    else if p.ends_with(".woff2"){"font/woff2"}
    else {"application/octet-stream"}
}
#[tauri::command]
fn qrxnet_browser_fetch(app: tauri::AppHandle, network:String, wallet:String, domain:String, path:String)->Result<Value,String>{
    let mut v=run_cli(Some(&app),&network,&wallet,&["fetchqrxsite",domain.as_str(),path.as_str()],None).map(|r|r.result).map_err(String::from)?;
    let fp=v.get("file_cache_path").and_then(|x|x.as_str()).ok_or_else(||"verified QRX-Net file path missing".to_string())?.to_string();
    let data=fs::read(&fp).map_err(|e|format!("could not read verified QRX-Net cache file: {e}"))?;
    let mime=qrxnet_mime(&fp).to_string();
    if let Some(o)=v.as_object_mut(){o.insert("mime".into(),Value::String(mime));o.insert("content_base64".into(),Value::String(general_purpose::STANDARD.encode(data)));}
    Ok(v)
}

#[tauri::command]
fn resource_dashboard_snapshot(app: tauri::AppHandle, network: String, wallet: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getresourcedashboard"], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn drive_activation_readiness(app: tauri::AppHandle, network: String, wallet: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getdriveactivationreadiness"], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn protocol_activation_readiness(app: tauri::AppHandle, network: String, wallet: String, feature: String) -> Result<Value, String> {
    let f = feature.trim();
    if !matches!(f, "DRIVE_V1" | "QRX_NET_V1" | "ADVERTISING_V1" | "COMPUTE_POUC_V1") {
        return Err("unsupported protocol readiness feature".into());
    }
    run_cli(Some(&app), &network, &wallet, &["getprotocolreadiness", f], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn resource_atlas_snapshot(app: tauri::AppHandle, network: String, wallet: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getresourceatlas"], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn resource_hosting_missions(app: tauri::AppHandle, network: String, wallet: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["gethostingmissions"], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn drive_files_snapshot(app: tauri::AppHandle, network: String, wallet: String, owner: Option<String>) -> Result<Value, String> {
    let owner_arg = owner.as_deref().filter(|s| !s.trim().is_empty()).unwrap_or("-");
    run_cli(Some(&app), &network, &wallet, &["listdrivefiles", owner_arg], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn drive_file_health(app: tauri::AppHandle, network: String, wallet: String, contract_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getdrivefilehealth", contract_id.as_str()], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn drive_shard_routes(app: tauri::AppHandle, network: String, wallet: String, contract_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getdriveshardroutes", contract_id.as_str()], None)
        .map(|r| r.result)
        .map_err(String::from)
}

#[tauri::command]
fn drive_pq_status(app: tauri::AppHandle, network: String, wallet: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getdrivepqstatus"], None).map(|r| r.result).map_err(String::from)
}

#[tauri::command]
fn drive_prepare_upload(app: tauri::AppHandle, network: String, wallet: String, source: String, profile: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["preparedriveupload", source.as_str(), profile.as_str()], None).map(|r| r.result).map_err(String::from)
}

#[tauri::command]
fn drive_start_prepared_upload(app: tauri::AppHandle, network: String, wallet: String, contract_id: String, prepare_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["startpreparedriveupload", contract_id.as_str(), prepare_id.as_str()], None).map(|r| r.result).map_err(String::from)
}

#[tauri::command]
fn drive_advance_prepared_upload(app: tauri::AppHandle, network: String, wallet: String, prepare_id: String, epochs: Option<u64>, rate_atoms_per_gib_epoch: Option<u64>) -> Result<Value, String> {
    let e = epochs.unwrap_or(30).to_string();
    let r = rate_atoms_per_gib_epoch.unwrap_or(10000).to_string();
    run_cli(Some(&app), &network, &wallet, &["advancepreparedriveupload", prepare_id.as_str(), e.as_str(), r.as_str()], None).map(|x| x.result).map_err(String::from)
}

#[tauri::command]
fn drive_decrypt_file(app: tauri::AppHandle, network: String, wallet: String, encrypted_container: String, destination: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["decryptdrivefile", encrypted_container.as_str(), destination.as_str()], None).map(|r| r.result).map_err(String::from)
}

#[tauri::command]
fn drive_start_download(app: tauri::AppHandle, network: String, wallet: String, contract_id: String, destination: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["startdrivedownload", contract_id.as_str(), destination.as_str()], None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn drive_start_upload(app: tauri::AppHandle, network: String, wallet: String, contract_id: String, source: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["startdriveupload", contract_id.as_str(), source.as_str()], None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn drive_transfer(app: tauri::AppHandle, network: String, wallet: String, transfer_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["getdrivetransfer", transfer_id.as_str()], None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn drive_transfer_pause(app: tauri::AppHandle, network: String, wallet: String, transfer_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["pausedrivetransfer", transfer_id.as_str()], None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn drive_transfer_resume(app: tauri::AppHandle, network: String, wallet: String, transfer_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["resumedrivetransfer", transfer_id.as_str()], None).map(|r| r.result).map_err(String::from)
}
#[tauri::command]
fn drive_transfer_cancel(app: tauri::AppHandle, network: String, wallet: String, transfer_id: String) -> Result<Value, String> {
    run_cli(Some(&app), &network, &wallet, &["canceldrivetransfer", transfer_id.as_str()], None).map(|r| r.result).map_err(String::from)
}

fn main() {
    tauri::Builder::default()
        .manage(DaemonState {
            child: Mutex::new(None),
        })
        .manage(KrakenGatewayState {
            child: Mutex::new(None),
        })
        .setup(|app| {
            let _ = app.handle();
            let _ = File::create(app_data_dir()?.join(".boot-ok"));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_context,
            generals_order_commitment,
            generals_prepare_offline_reveal,
            generals_snapshot,
            generals_submit_action,
            open_aura_window,
            open_generals_window,
            qrx_family_policy_set,
            qrx_family_policy_get,
            qrx_family_policy_status,
            open_qrx_browser_window,
            open_browser_www_window,
            open_qrx_upscaler_window,
            upscaler_start_local,
            upscaler_job_status,
            upscaler_cancel_job,
            upscaler_video_pipeline_plan,
            upscaler_capabilities,
            qrx_apps::qrx_app_inspect_package,
            qrx_apps::qrx_app_install,
            qrx_apps::qrx_app_list,
            qrx_apps::qrx_app_uninstall,
            qrx_apps::qrx_app_set_developer_mode,
            qrx_apps::qrx_app_inspect_dev_folder,
            qrx_apps::qrx_app_register_dev,
            qrx_apps::qrx_app_load_bundle,
            qrx_apps::open_qrx_app_window,
            qrx_apps::qrx_app_bridge_call,
            generate_qr_svg,
            address_book_list,
            address_book_upsert,
            address_book_delete,
            address_book_export,
            address_book_import_json,
            kraken_credentials_status,
            kraken_store_credentials,
            kraken_delete_credentials,
            kraken_gateway_status,
            kraken_start_gateway,
            kraken_stop_gateway,
            arbitrage_evaluate,
            arbitrage_approve,
            arbitrage_broadcast_hedge,
            arbitrage_list,
            arbitrage_fetch_kraken_book,
            arbitrage_get_order,
            export_complete_ledger,
            agent_manager_list,
            agent_manager_register,
            agent_manager_revoke,
            list_wallets,
            validator_fleet_status,
            set_validator_fleet_modes,
            list_legacy_network_wallets,
            migrate_legacy_network_wallet,
            list_legacy_gui_wallets,
            import_legacy_gui_wallet,
            inspect_wallet,
            verify_wallet_passphrase,
            detect_legacy_default_passphrase,
            migrate_legacy_default_passphrase,
            change_wallet_passphrase,
            lock_wallet_session,
            wallet_session_status,
            import_key_set_directory,
            prepare_existing_wallet,
            create_wallet,
            refresh_recovery_backup,
            export_recovery_file,
            restore_wallet_from_recovery,
            import_wallet_directory,
            export_wallet_directory,
            daemon_health,
            start_daemon,
            stop_daemon,
            get_validator_mode,
            set_validator_mode,
            get_wallet_info,
            get_balance,
            get_new_address,
            list_addresses,
            get_wallet_address_set,
            get_address_privacy_context,
            get_history,
            get_staking_info,
            get_validators,
            get_tokenomics,
            get_protocol_info,
            get_node_info,
            markets_snapshot,
            markets_place_order,
            markets_cancel_order,
            get_mainnet_health,
            get_peer_info,
            list_peers,
            send_to_address,
            stake,
            validator_safe_pause,
            validator_safe_resume,
            delegate,
            undelegate,
            claim_undelegated,
            btc_get_status,
            btc_init_wallet,
            btc_backup_phrase,
            btc_restore_wallet,
            btc_reset_wallet,
            btc_sync,
            btc_get_balance,
            btc_send,
            btc_test_endpoints,
            btc_set_mode,
            btc_start_neutrino,
            btc_new_address,
            btc_list_addresses,
            crosschain_place_buy,
            crosschain_place_sell,
            crosschain_redeem,
            crosschain_refund,
            crosschain_submit_funding_proof,
            crosschain_status,
            aura_provider_settings_load,
            aura_provider_settings_save,
            aura_plan_status,
            aura_checkout_quote,
            aura_local_help,
            aura_cloud_request_preview,
            exchange_ready_status,
            shielded_pool_status,
            privacy_action_preview,
            privacy_action_execute,
            shielded_address_create,
            privacy_get_status,
            privacy_set_mode,
            wallet_cli_capabilities,
            wallet_cli_execute,
            dashboard_snapshot,
            qrxnet_domain_preflight,
            qrxnet_register_domain,
            qrxnet_renew_domain,
            qrxnet_update_domain,
            qrxnet_transfer_domain,
            qrxnet_list_domains,
            qrxnet_domain_history,
            qrxnet_ad_policy,
            qrxnet_ad_rewards,
            qrxnet_claim_ad_rewards,
            qrxnet_create_ad_campaign,
            qrxnet_prepare_site,
            qrxnet_get_site_publish,
            qrxnet_advance_site,
            qrxnet_site_versions,
            qrxnet_rollback_site,
            qrxnet_browser_resolve,
            qrxnet_browser_fetch,
            resource_dashboard_snapshot,
            drive_activation_readiness,
            protocol_activation_readiness,
            resource_atlas_snapshot,
            resource_hosting_missions,
            drive_files_snapshot,
            drive_file_health,
            drive_shard_routes,
            drive_pq_status,
            drive_prepare_upload,
            drive_start_prepared_upload,
            drive_advance_prepared_upload,
            drive_decrypt_file,
            drive_start_download,
            drive_start_upload,
            drive_transfer,
            drive_transfer_pause,
            drive_transfer_resume,
            drive_transfer_cancel,
        ])
        .run(tauri::generate_context!())
        .expect("error while running QUBITCOIN Wallet");
}
