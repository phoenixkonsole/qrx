#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use std::str::FromStr;
use bdk::bitcoin::{Address, Network};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use argon2::{Algorithm, Argon2, Params, Version};
use openssl::{pkey::PKey, symm::Cipher};

struct DaemonState {
    child: Mutex<Option<Child>>,
}

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
    daemon_running: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommandResult {
    ok: bool,
    method: String,
    result: Value,
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
struct LegacyGuiWalletCandidate {
    name: String,
    path: String,
    address: Option<String>,
    wallet_version: Option<u64>,
    has_recovery_file: bool,
    already_in_shared_store: bool,
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

fn app_data_dir() -> Result<PathBuf, AppError> {
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
    let dir = wallet_dir(network, wallet)?.join("settings");
    fs::create_dir_all(&dir)?;
    Ok(dir)
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

fn wallet_root(network: &str) -> Result<PathBuf, AppError> {
    Ok(network_root(network)?.join("wallets"))
}

fn wallet_dir(network: &str, wallet: &str) -> Result<PathBuf, AppError> {
    Ok(wallet_root(network)?.join(wallet))
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
        .find(|p| p.exists())
        .ok_or_else(|| {
            AppError::Message(format!(
                "Could not find sidecar binary: {binary}. Place {} in src-tauri/bin/ or set QUB_BIN_DIR.",
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

fn run_qrx(
    app: Option<&tauri::AppHandle>,
    args: &[&str],
    passphrase: Option<&str>,
    stdin_text: Option<&str>,
) -> Result<String, AppError> {
    let qrx_bin = resolve_binary(app, "qrx")?;
    let mut cmd = Command::new(qrx_bin);
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
    let output = Command::new(cli_bin)
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

fn run_cli(
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

fn broadcast_created_transaction(app:&tauri::AppHandle,network:&str,wallet:&str,created:CommandResult,passphrase:Option<&str>,action:&str,agent:&str)->Result<AgentManagerResult,String>{ let raw=created.result.get("raw_tx").and_then(Value::as_str).ok_or_else(||"QRX Core did not return a raw transaction".to_string())?; let broadcast=sign_and_broadcast_raw(app,network,wallet,raw,passphrase,"agent-manager")?; Ok(AgentManagerResult{action:action.into(),agent:agent.into(),venue:"KRAKEN".into(),raw_transaction_created:true,broadcast}) }

#[tauri::command]
fn agent_manager_list(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:Option<String>,passphrase:Option<String>)->Result<CommandResult,String>{ let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?; let owner=owner.unwrap_or_default(); let args=if owner.trim().is_empty(){vec!["listagents"]}else{vec!["listagents",owner.trim()]}; run_cli(Some(&app),&network,&wallet,&args,passphrase.as_deref()).map_err(|e|e.to_string()) }

#[tauri::command]
fn agent_manager_register(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:String,agent:String,agent_ed_pub:String,agent_mldsa_pub:String,max_trade_atoms:String,daily_limit_atoms:String,markets:String,expires_height:String,owner_ed_pub:String,owner_mldsa_pub:String,lane:String,tx_expiry:String,allow_arbitrage:bool,passphrase:Option<String>)->Result<AgentManagerResult,String>{ let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?; let owner=required_clean(&owner,"Owner address")?; let agent=required_clean(&agent,"Agent address")?; let markets=markets.split(',').map(str::trim).filter(|v|!v.is_empty()).collect::<Vec<_>>().join(","); if markets.is_empty()||markets.split(',').any(|m|!m.contains('/')){return Err("Enter at least one market like BTC/EUR".into());} let max_trade=positive_u64(&max_trade_atoms,"Maximum per trade")?; let daily=positive_u64(&daily_limit_atoms,"Daily limit")?; let expires=positive_u64(&expires_height,"Agent expiry height")?; let tx_expiry=positive_u64(&tx_expiry,"Transaction expiry height")?; let permissions=if allow_arbitrage{"TRADE_EXTERNAL,ARBITRAGE_CROSS_VENUE"}else{"TRADE_EXTERNAL"}; let created=run_cli(Some(&app),&network,&wallet,&["createagentregistertransaction",&owner,&agent,agent_ed_pub.trim(),agent_mldsa_pub.trim(),permissions,&max_trade,&daily,&markets,&expires,owner_ed_pub.trim(),owner_mldsa_pub.trim(),lane.trim(),&tx_expiry],passphrase.as_deref()).map_err(|e|e.to_string())?; broadcast_created_transaction(&app,&network,&wallet,created,passphrase.as_deref(),"register",&agent) }

#[tauri::command]
fn agent_manager_revoke(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,owner:String,agent:String,owner_ed_pub:String,owner_mldsa_pub:String,lane:String,tx_expiry:String,passphrase:Option<String>)->Result<AgentManagerResult,String>{ let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?; let owner=required_clean(&owner,"Owner address")?; let agent=required_clean(&agent,"Agent address")?; let tx_expiry=positive_u64(&tx_expiry,"Transaction expiry height")?; let created=run_cli(Some(&app),&network,&wallet,&["createagentrevoketransaction",&owner,&agent,owner_ed_pub.trim(),owner_mldsa_pub.trim(),lane.trim(),&tx_expiry],passphrase.as_deref()).map_err(|e|e.to_string())?; broadcast_created_transaction(&app,&network,&wallet,created,passphrase.as_deref(),"revoke",&agent) }

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
                    running = true;
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

    let mut cmd = Command::new(daemon_bin);
    cmd.arg("--network")
        .arg(network)
        .arg("--datadir")
        .arg(&ctx.data_dir)
        .arg("--wallet")
        .arg(wallet);

    if !validator_enabled {
        cmd.arg("--no-block-producer");
    }

    let child = cmd
        .env("QRX_PASSPHRASE", passphrase.unwrap_or(""))
        .env("QRX_ENABLE_MAINNET_HTLC", htlc_env_value_for_network(network))
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
    inspect_wallet_inner(network.as_deref().unwrap_or("alpha"), &wallet).map_err(String::from)
}


#[tauri::command]
fn verify_wallet_passphrase(app: tauri::AppHandle, network: Option<String>, wallet: String, passphrase: String) -> Result<bool, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let _ = run_cli(Some(&app), &network, &wallet, &["walletpassphrasehex", encoded], None);
    Ok(true)
}

#[tauri::command]
fn change_wallet_passphrase(app: tauri::AppHandle, network: Option<String>, wallet: String, current_passphrase: String, new_passphrase: String) -> Result<WalletPassphraseChangeResult, String> {
    let network=network.unwrap_or_else(||"alpha".into());
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
    let _=fs::remove_file(&olds[0]); let _=fs::remove_file(&olds[1]);
    let passphrase_hex:String=new_passphrase.as_bytes().iter().map(|b|format!("{b:02x}")).collect();
    let _=run_cli(Some(&app),&network,&wallet,&["walletpassphrasehex",&passphrase_hex],None);
    Ok(WalletPassphraseChangeResult{wallet,backup_path,passphrase_state:"passphrase-required-to-use-private-keys".into(),changed_files:paths.iter().map(|p|p.to_string_lossy().to_string()).collect()})
}

#[tauri::command]
fn lock_wallet_session(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>) -> Result<bool, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    // An offline daemon is already effectively locked.
    let _ = run_cli(Some(&app), &network, &wallet, &["walletlock"], None);
    Ok(true)
}

#[tauri::command]
fn import_key_set_directory(network: Option<String>, wallet: String, source_dir: String) -> Result<KeySetImportResult, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
fn get_context(network: Option<String>, wallet: Option<String>) -> Result<WalletContext, String> {
    ensure_context(
        network.as_deref().unwrap_or("alpha"),
        wallet.as_deref().unwrap_or("node1"),
    )
    .map_err(Into::into)
}

#[tauri::command]
fn list_wallets(network: Option<String>) -> Result<Vec<WalletListItem>, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let root = wallet_root(&network).map_err(String::from)?;
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;

    let mut wallets = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !path.is_dir() {
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(&wallet).map_err(String::from)?;
    if passphrase.trim().is_empty() {
        return Err("Passphrase is required".into());
    }

    let target = wallet_dir(&network, &wallet).map_err(String::from)?;
    if target.exists() && target.join("wallet.json").exists() {
        return Err("Wallet already exists".into());
    }

    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
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
fn restore_wallet_from_recovery(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: String,
    recovery_file: String,
    recovery_phrase: String,
    passphrase: String,
) -> Result<WalletContext, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
            "qrxd started but did not answer on the control socket. Check logs at {}",
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let enabled = read_validator_mode(&network, &wallet).map_err(String::from)?;
    Ok(ValidatorModeStatus {
        validator_enabled: enabled,
        wallet_mode_safe: !enabled,
        min_validator_self_stake_qub: "100 QUB".into(),
        double_sign_slash: "50% of validator power + tombstone".into(),
        offline_penalty: "1% after 100 missed blocks, then 1h jail".into(),
        best_practice: "Use Wallet/Delegator mode on home computers. Validator mode is for stable 24/7 servers/VPS with reliable uptime.".into(),
    })
}

#[tauri::command]
fn set_validator_mode(network: Option<String>, wallet: Option<String>, enabled: bool) -> Result<ValidatorModeStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
        network.as_deref().unwrap_or("alpha"),
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
        network.as_deref().unwrap_or("alpha"),
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
        network.as_deref().unwrap_or("alpha"),
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
        network.as_deref().unwrap_or("alpha"),
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
fn get_history(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    limit: Option<u32>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
        network.as_deref().unwrap_or("alpha"),
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
        network.as_deref().unwrap_or("alpha"),
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
        network.as_deref().unwrap_or("alpha"),
        &wallet,
        &["tokenomics"],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
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
        network.as_deref().unwrap_or("alpha"),
        &wallet,
        &["getinfo"],
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
        network.as_deref().unwrap_or("alpha"),
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
    passphrase: Option<String>,
) -> Result<Value, String> {
    if to.trim().is_empty() {
        return Err("Recipient address is required".into());
    }
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let amount = parse_amount(&amount).map_err(String::from)?;
    let memo = memo.unwrap_or_default();

    let res = if memo.trim().is_empty() {
        run_cli(
            Some(&app),
            &network,
            &wallet,
            &["sendtoaddress", to.trim(), &amount],
            passphrase.as_deref(),
        )
    } else {
        run_cli(
            Some(&app),
            &network,
            &wallet,
            &["sendtoaddress", to.trim(), &amount, memo.trim()],
            passphrase.as_deref(),
        )
    }
    .map_err(String::from)?;

    Ok(res.result)
}

#[tauri::command]
fn stake(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    amount: String,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    if !read_validator_mode(&network, &wallet).unwrap_or(false) {
        return Err("Validator Mode is disabled. Enable Validator Mode first and confirm the slashing/uptime risks.".into());
    }
    let amount = parse_amount(&amount).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        &network,
        &wallet,
        &["stake", &amount],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
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
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let amount = parse_amount(&amount).map_err(String::from)?;
    Ok(run_cli(
        Some(&app),
        &network,
        &wallet,
        &["delegate", validator.trim(), &amount],
        passphrase.as_deref(),
    )
    .map_err(String::from)?
    .result)
}

#[tauri::command]
fn dashboard_snapshot(
    app: tauri::AppHandle,
    state: tauri::State<DaemonState>,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<UiStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
struct SwapDraft {
    swap_id: String,
    status: String,
    btc_amount: String,
    qrx_address: String,
    mode: String,
    timelock_hours: u32,
    refund_path: String,
    custody: String,
    next_step: String,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HtlcSafetyStatus {
    network: String,
    mainnet_like: bool,
    htlc_enabled: bool,
    env_value: String,
    required_confirmation: String,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreSwapResult {
    ok: bool,
    command: String,
    result_raw: String,
    warning: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuantumGuardPreview {
    action_id: String,
    action: String,
    title: String,
    summary: String,
    risk_level: String,
    required_confirmation: String,
    details: Vec<String>,
    disclaimer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct QuantumGuardAuditEntry {
    timestamp: String,
    action: String,
    action_id: String,
    network: String,
    wallet: String,
    confirmed: bool,
    result: String,
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

fn htlc_setting_key(network: &str) -> String {
    format!("htlc_enabled_{}.txt", network)
}

fn htlc_enabled_for_network(network: &str) -> bool {
    read_setting(&htlc_setting_key(network), "false") == "true"
}

fn htlc_env_value_for_network(network: &str) -> String {
    if is_mainnet_like(network) && htlc_enabled_for_network(network) {
        "I_UNDERSTAND_EXPERIMENTAL".into()
    } else {
        "".into()
    }
}

fn shared_btc_service<T: serde::de::DeserializeOwned>(app: &tauri::AppHandle, request: Value) -> Result<T, String> {
    let binary=resolve_binary(Some(app),"qrx-btc-wallet-service").map_err(|e|e.to_string())?;
    let mut child=Command::new(binary).arg("--data-dir").arg(app_data_dir().map_err(|e|e.to_string())?)
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
    let mut cmd = Command::new(python); for a in prefix { cmd.arg(a); } cmd.arg(script).args(args);
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
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let state=arbitrage_state_dir(&network,&wallet)?; let args=vec![if paper{"--paper-json".into()}else{"--evaluate-json".into()},"--state-dir".into(),state.to_string_lossy().to_string()];
    run_python_json(&app,"qrx-arbitrage-engine.py",&args,Some(&payload))
}

#[tauri::command]
fn arbitrage_approve(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, arbitrage_id: String) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
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
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
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
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let state=arbitrage_state_dir(&network,&wallet)?; let args=vec!["--list".into(),"--state-dir".into(),state.to_string_lossy().to_string()];
    run_python_json(&app,"qrx-arbitrage-engine.py",&args,None)
}

#[tauri::command]
fn arbitrage_fetch_kraken_book(app: tauri::AppHandle) -> Result<Value, String> {
    run_python_json(&app,"qrx-arbitrage-engine.py",&["--fetch-book".into()],None)
}

#[tauri::command]
fn arbitrage_get_order(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, order_id: String, passphrase: Option<String>) -> Result<CommandResult, String> {
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    let order_id=required_clean(&order_id,"Cross-chain order ID")?;
    run_cli(Some(&app),&network,&wallet,&["getorder",&order_id],passphrase.as_deref()).map_err(|e|e.to_string())
}

#[tauri::command]
fn export_complete_ledger(app: tauri::AppHandle, network: Option<String>, wallet: Option<String>, profile: String, from_date: Option<String>, to_date: Option<String>, year: Option<u32>, quarter: Option<u8>) -> Result<Value, String> {
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
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
        let mut c = Command::new(&program);
        for a in &prefix { c.arg(a); }
        if c.arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) {
            return Ok((program, prefix));
        }
    }
    Err("Python 3 is required for the QRX Kraken gateway MVP and was not found".into())
}

#[tauri::command]
fn kraken_credentials_status(network: Option<String>, wallet: Option<String>) -> Result<KrakenCredentialStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = wallet.unwrap_or_else(|| "node1".into());
    let path = kraken_vault_file(&network, &wallet)?;
    Ok(KrakenCredentialStatus { configured: path.exists(), encrypted_at_rest: path.exists(), venue: "KRAKEN".into(), storage: "Argon2id + AES-256-GCM local vault; no plaintext API secret config".into() })
}

#[tauri::command]
fn kraken_store_credentials(network: Option<String>, wallet: Option<String>, api_key: String, api_secret: String, passphrase: String) -> Result<KrakenCredentialStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = wallet.unwrap_or_else(|| "node1".into());
    let path = kraken_vault_file(&network, &wallet)?;
    if path.exists() { fs::remove_file(path).map_err(|e| e.to_string())?; }
    Ok(KrakenCredentialStatus { configured: false, encrypted_at_rest: false, venue: "KRAKEN".into(), storage: "No saved credentials".into() })
}

#[tauri::command]
fn kraken_gateway_status(state: tauri::State<KrakenGatewayState>, network: Option<String>, wallet: Option<String>) -> Result<KrakenGatewayStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let network = network.unwrap_or_else(|| "alpha".into());
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
    let mut cmd = Command::new(python);
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


fn quantum_guard_required_confirmation() -> &'static str {
    "I UNDERSTAND HTLC RISK"
}

fn quantum_guard_action_id(action: &str) -> String {
    format!("qguard_{}_{}", action, chrono_like_timestamp())
}

fn quantum_guard_audit_path() -> Result<PathBuf, AppError> {
    let dir = app_data_dir()?.join("audit");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("quantum_guard.log"))
}

fn append_quantum_guard_audit(entry: &QuantumGuardAuditEntry) {
    if let Ok(path) = quantum_guard_audit_path() {
        if let Ok(line) = serde_json::to_string(entry) {
            let _ = OpenOptions::new().create(true).append(true).open(path)
                .and_then(|mut f| {
                    use std::io::Write;
                    writeln!(f, "{}", line)
                });
        }
    }
}

fn quantum_guard_check(confirmation: Option<String>) -> Result<(), String> {
    let got = confirmation.unwrap_or_default();
    if got.trim() != quantum_guard_required_confirmation() {
        return Err(format!("Quantum Guard confirmation required: {}", quantum_guard_required_confirmation()));
    }
    Ok(())
}

fn quantum_guard_preview_common(action: &str, network: &str, wallet: &str, details: Vec<String>) -> QuantumGuardPreview {
    QuantumGuardPreview {
        action_id: quantum_guard_action_id(action),
        action: action.into(),
        title: "Quantum Guard Request".into(),
        summary: format!("Experimental Quantum Swap action '{}' for wallet '{}' on network '{}'.", action, wallet, network),
        risk_level: if is_mainnet_like(network) { "high-mainnet".into() } else { "experimental-alpha-test".into() },
        required_confirmation: quantum_guard_required_confirmation().into(),
        details,
        disclaimer: "Quantum Swaps / HTLC actions are experimental and not audited. Confirm only for small test amounts. This wallet is non-custodial and cannot recover funds if you make an irreversible mistake.".into(),
    }
}

#[tauri::command]
fn quantum_guard_audit_log() -> Result<Vec<QuantumGuardAuditEntry>, String> {
    let path = quantum_guard_audit_path().map_err(String::from)?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let txt = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for line in txt.lines().rev().take(50) {
        if let Ok(entry) = serde_json::from_str::<QuantumGuardAuditEntry>(line) {
            out.push(entry);
        }
    }
    Ok(out)
}


fn validate_sha256_hashlock(hashlock: &str) -> Result<(), String> {
    let h = hashlock.trim();
    if h.len() != 64 {
        return Err("Hashlock must be exactly 64 hex characters: SHA256(secret).".into());
    }
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Hashlock must be hexadecimal.".into());
    }
    Ok(())
}

#[tauri::command]
fn quantum_guard_preview_create(
    network: Option<String>,
    wallet: Option<String>,
    recipient: String,
    amount: String,
    hashlock: String,
    timelock_seconds: String,
) -> Result<QuantumGuardPreview, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    validate_sha256_hashlock(&hashlock)?;
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let mut details = vec![
        format!("Hash algorithm: SHA256 (BTC-compatible HTLC v1)"),
        format!("Action: Create QUB HTLC lock"),
        format!("Recipient: {}", recipient),
        format!("Amount: {} QUB base units", amount),
        format!("Hashlock: {}", hashlock),
        format!("Timelock: {} seconds", timelock_seconds),
    ];
    if is_mainnet_like(&network) {
        details.push("Mainnet-like network: core HTLC safety gate must also be enabled.".into());
    }
    Ok(quantum_guard_preview_common("create_htlc", &network, &wallet, details))
}

#[tauri::command]
fn quantum_guard_preview_redeem(
    network: Option<String>,
    wallet: Option<String>,
    swap_id: String,
) -> Result<QuantumGuardPreview, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(quantum_guard_preview_common("redeem_htlc", &network, &wallet, vec![
        "Action: Redeem QUB HTLC using secret".into(),
        format!("Swap ID: {}", swap_id),
        "The secret may become visible to the counterparty and can affect the BTC-side swap flow.".into(),
    ]))
}

#[tauri::command]
fn quantum_guard_preview_refund(
    network: Option<String>,
    wallet: Option<String>,
    swap_id: String,
) -> Result<QuantumGuardPreview, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    Ok(quantum_guard_preview_common("refund_htlc", &network, &wallet, vec![
        "Action: Refund QUB HTLC after timelock expiry".into(),
        format!("Swap ID: {}", swap_id),
        "Refund should only be possible after the configured timelock has expired.".into(),
    ]))
}

#[tauri::command]
fn htlc_safety_status(network: Option<String>) -> Result<HtlcSafetyStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let enabled = htlc_enabled_for_network(&network);
    let mainnet_like = is_mainnet_like(&network);
    Ok(HtlcSafetyStatus {
        network: network.clone(),
        mainnet_like,
        htlc_enabled: enabled,
        env_value: htlc_env_value_for_network(&network),
        required_confirmation: "I UNDERSTAND EXPERIMENTAL HTLC RISK".into(),
        disclaimer: if mainnet_like {
            "Mainnet Quantum Swaps / HTLC support is a release-candidate feature and is disabled by default. Enable only after understanding the risk. Use tiny amounts only until audited.".into()
        } else {
            "Quantum Swaps / HTLC support is experimental. Alpha/testnet use is intended for development and small-value testing.".into()
        },
    })
}

#[tauri::command]
fn htlc_set_safety(
    network: Option<String>,
    enable: bool,
    confirmation: Option<String>,
) -> Result<HtlcSafetyStatus, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    if enable && is_mainnet_like(&network) {
        let required = "I UNDERSTAND EXPERIMENTAL HTLC RISK";
        if confirmation.as_deref().unwrap_or("").trim() != required {
            return Err(format!("Mainnet HTLC activation requires exact confirmation: {}", required));
        }
    }
    write_setting(&htlc_setting_key(&network), if enable { "true" } else { "false" }).map_err(String::from)?;
    htlc_safety_status(Some(network))
}

fn run_core_swap_command(
    app: Option<&tauri::AppHandle>,
    network: &str,
    wallet: &str,
    args: &[&str],
    passphrase: Option<&str>,
) -> Result<CoreSwapResult, String> {
    let raw = run_cli_raw(app, network, wallet, args, passphrase).map_err(|e| e.to_string())?;
    Ok(CoreSwapResult {
        ok: true,
        command: args.first().unwrap_or(&"swap").to_string(),
        result_raw: raw,
        warning: "Core HTLC command executed. This is experimental until audited and consensus-hardened.".into(),
    })
}

#[tauri::command]
fn core_create_swap(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    recipient: String,
    amount: String,
    hashlock: String,
    timelock_seconds: String,
    memo: Option<String>,
    passphrase: Option<String>,
    confirmation: Option<String>,
) -> Result<CoreSwapResult, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    validate_sha256_hashlock(&hashlock)?;
    let wallet_raw = wallet.unwrap_or_else(|| "node1".into());
    let wallet = sanitize_wallet_name(wallet_raw.as_str()).map_err(String::from)?;
    let action_id = quantum_guard_action_id("create_htlc");
    quantum_guard_check(confirmation)?;
    if is_mainnet_like(&network) && !htlc_enabled_for_network(&network) {
        return Err("Mainnet HTLC is disabled in GUI safety settings.".into());
    }
    let memo = memo.unwrap_or_else(|| "quantum-swap".into());
    let result = run_core_swap_command(Some(&app), &network, &wallet, &[
        "createswap",
        recipient.as_str(),
        amount.as_str(),
        hashlock.as_str(),
        timelock_seconds.as_str(),
        memo.as_str(),
    ], passphrase.as_deref());
    append_quantum_guard_audit(&QuantumGuardAuditEntry {
        timestamp: chrono_like_timestamp(),
        action: "create_htlc".into(),
        action_id,
        network,
        wallet,
        confirmed: true,
        result: if result.is_ok() { "ok".into() } else { "error".into() },
    });
    result
}

#[tauri::command]
fn core_get_swap(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    swap_id: String,
    passphrase: Option<String>,
) -> Result<CoreSwapResult, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    run_core_swap_command(Some(&app), &network, &wallet, &["getswap", swap_id.as_str()], passphrase.as_deref())
}

#[tauri::command]
fn core_list_swaps(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    passphrase: Option<String>,
) -> Result<CoreSwapResult, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    run_core_swap_command(Some(&app), &network, &wallet, &["listswaps"], passphrase.as_deref())
}

#[tauri::command]
fn core_redeem_swap(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    swap_id: String,
    secret: String,
    passphrase: Option<String>,
    confirmation: Option<String>,
) -> Result<CoreSwapResult, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet_raw = wallet.unwrap_or_else(|| "node1".into());
    let wallet = sanitize_wallet_name(wallet_raw.as_str()).map_err(String::from)?;
    let action_id = quantum_guard_action_id("redeem_htlc");
    quantum_guard_check(confirmation)?;
    if is_mainnet_like(&network) && !htlc_enabled_for_network(&network) {
        return Err("Mainnet HTLC is disabled in GUI safety settings.".into());
    }
    let result = run_core_swap_command(Some(&app), &network, &wallet, &["redeemswap", swap_id.as_str(), secret.as_str()], passphrase.as_deref());
    append_quantum_guard_audit(&QuantumGuardAuditEntry {
        timestamp: chrono_like_timestamp(),
        action: "redeem_htlc".into(),
        action_id,
        network,
        wallet,
        confirmed: true,
        result: if result.is_ok() { "ok".into() } else { "error".into() },
    });
    result
}

#[tauri::command]
fn core_refund_swap(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    swap_id: String,
    passphrase: Option<String>,
    confirmation: Option<String>,
) -> Result<CoreSwapResult, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet_raw = wallet.unwrap_or_else(|| "node1".into());
    let wallet = sanitize_wallet_name(wallet_raw.as_str()).map_err(String::from)?;
    let action_id = quantum_guard_action_id("refund_htlc");
    quantum_guard_check(confirmation)?;
    if is_mainnet_like(&network) && !htlc_enabled_for_network(&network) {
        return Err("Mainnet HTLC is disabled in GUI safety settings.".into());
    }
    let result = run_core_swap_command(Some(&app), &network, &wallet, &["refundswap", swap_id.as_str()], passphrase.as_deref());
    append_quantum_guard_audit(&QuantumGuardAuditEntry {
        timestamp: chrono_like_timestamp(),
        action: "refund_htlc".into(),
        action_id,
        network,
        wallet,
        confirmed: true,
        result: if result.is_ok() { "ok".into() } else { "error".into() },
    });
    result
}

#[tauri::command]
fn swap_create(btc_amount: String, qrx_address: String, mode: String) -> Result<SwapDraft, String> {
    if btc_amount.trim().is_empty() { return Err("BTC amount is required".into()); }
    if qrx_address.trim().is_empty() { return Err("QRX receive address is required".into()); }
    let mode = if mode == "htlc" { "htlc" } else { "coordinated" };
    let swap_id = format!("QSWAP-{}-{}", chrono_like_timestamp(), mode.to_uppercase());
    Ok(SwapDraft {
        swap_id,
        status: if mode == "htlc" { "htlc-design-preview".into() } else { "coordinator-ready-draft".into() },
        btc_amount: btc_amount.trim().into(),
        qrx_address: qrx_address.trim().into(),
        mode: mode.into(),
        timelock_hours: 24,
        refund_path: "Refund path must be available after timeout before production use.".into(),
        custody: "non-custodial-design-target".into(),
        next_step: "Integrate BTC BDK/Electrum monitoring and QUB HTLC commands: createswap, redeemswap, refundswap.".into(),
        disclaimer: "Experimental swap preparation only. This wallet does not custody user funds and does not guarantee execution or price.".into(),
    })
}

fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs().to_string()).unwrap_or_else(|_| "0".into())
}

#[tauri::command]
fn swap_status(swap_id: String) -> Result<SwapDraft, String> {
    Ok(SwapDraft {
        swap_id,
        status: "draft-waiting-for-real-swap-engine".into(),
        btc_amount: "not-locked".into(),
        qrx_address: "not-set".into(),
        mode: "coordinated-or-htlc".into(),
        timelock_hours: 24,
        refund_path: "not-active-until-real-HTLC-integration".into(),
        custody: "no-custody-in-GUI-placeholder".into(),
        next_step: "Connect swap state to a local swap engine or coordinator and QUBITCOIN Core HTLC commands.".into(),
        disclaimer: "Status is placeholder UX until swap backend is integrated.".into(),
    })
}

#[tauri::command]
fn swap_refund(swap_id: String) -> Result<SwapDraft, String> {
    Ok(SwapDraft {
        swap_id,
        status: "refund-path-preview".into(),
        btc_amount: "not-locked".into(),
        qrx_address: "not-set".into(),
        mode: "refund".into(),
        timelock_hours: 24,
        refund_path: "In production, this calls BTC/QRX refund transaction builders after timelock expiry.".into(),
        custody: "user-controlled-keys-required".into(),
        next_step: "Implement actual HTLC timeout checks before enabling refund button for real funds.".into(),
        disclaimer: "Do not treat this placeholder as a real refund transaction.".into(),
    })
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

    if msg.contains("balance") || msg.contains("guthaben") {
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
        reply.answer = "QUB is designed as exchange-ready transparent-by-default, with optional privacy. The recommended path is transparent QUB for exchanges and BTC swaps, then optional shielded pool locally: transparent QUB → shielded pool → private transfer → unshield. This is not marketed as anonymous or untraceable.".into();
        reply.command = Some("Privacy Center → Shield funds / Send private / Unshield (GUI prepared, Core next)".into());
    } else if msg.contains("exchange") || msg.contains("cex") || msg.contains("listing") {
        reply.answer = "Exchange-ready mode means transparent transfers are default. Centralized exchanges should use transparent QUB deposits/withdrawals only. Privacy stays optional and local after withdrawal.".into();
        reply.command = Some("Privacy Center → Exchange-ready mode".into());
    } else if msg.contains("swap") || msg.contains("htlc") || msg.contains("quantum") {
        reply.answer = "Quantum Swaps are experimental. Quantum Swaps v1 uses SHA256 hashlocks for BTC compatibility, while QUBITCOIN can still use SHA3 internally for chain hashing. Use Quantum Guard. Alpha/testnet commands: createswap, getswap, redeemswap, refundswap, listswaps.".into();
        reply.command = Some("qrx-cli --network alpha --wallet node1 createswap <recipient> <amount> <hashlock_hex> <timelock_seconds> [memo]".into());
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
        source: "cloud-preview".into(),
        answer: "AURA Cloud ist vorbereitet, aber noch nicht mit Cloudflare verbunden. Backend-Aufgaben: Auth/User-ID, Paketstatus, BTC/QUB Invoice, Rate Limits, ChatGPT Proxy, lokale Verlaufspayload verarbeiten.".into(),
        command: Some("POST https://<your-cloudflare-worker>/aura/chat".into()),
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
fn shielded_pool_status() -> Result<ShieldedPoolStatus, String> {
    Ok(ShieldedPoolStatus {
        enabled: false,
        phase: "gui-prepared-core-next".into(),
        transparent_balance_label: "Transparent QUB".into(),
        shielded_balance_label: "Shielded QUB (not active until Core support exists)".into(),
        commands_prepared: vec![
            "shielded-address".into(),
            "shield".into(),
            "shielded-balance".into(),
            "shielded-send".into(),
            "unshield".into(),
            "shielded-history".into(),
        ],
        pool_model: "Transparent QUB → Shielded Pool → Private Transfer → Transparent QUB. BTC swaps stay on transparent QUB first.".into(),
        warning: "GUI preparation only. No real shielded funds exist until the Core implements commitments, nullifiers, Merkle tree, encrypted notes, and proof verification.".into(),
    })
}

#[tauri::command]
fn privacy_action_preview(action: String, amount: Option<String>, destination: Option<String>) -> Result<PrivacyActionPreview, String> {
    let action_clean = action.trim().to_lowercase();
    let amount = amount.unwrap_or_else(|| "0".into());
    let destination = destination.unwrap_or_else(|| "not set".into());
    let (title, summary, command_preview, requirements) = match action_clean.as_str() {
        "shield" => (
            "Shield transparent QUB",
            format!("Move {} QUB from transparent balance into the optional shielded pool.", amount),
            format!("qrx-cli shield {} <shielded_address>", amount),
            vec![
                "Transparent funds available".into(),
                "Shielded address generated".into(),
                "Core shield command implemented".into(),
            ],
        ),
        "shielded-send" => (
            "Send shielded QUB",
            format!("Send {} shielded QUB to {}.", amount, destination),
            format!("qrx-cli shielded-send {} {}", destination, amount),
            vec![
                "Shielded balance available".into(),
                "Recipient shielded address".into(),
                "Proof generation available".into(),
            ],
        ),
        "unshield" => (
            "Unshield QUB",
            format!("Withdraw {} QUB from shielded pool to transparent address {}.", amount, destination),
            format!("qrx-cli unshield {} {}", destination, amount),
            vec![
                "Shielded note available".into(),
                "Transparent destination address".into(),
                "Nullifier/proof verification available".into(),
            ],
        ),
        _ => (
            "Privacy action",
            "Unknown privacy action preview.".into(),
            "not available".into(),
            vec!["Choose shield, shielded-send or unshield.".into()],
        ),
    };
    Ok(PrivacyActionPreview {
        action: action_clean,
        title: title.into(),
        summary,
        requirements,
        command_preview,
        warning: "Preview only. This does not move funds until QUB Core shielded pool support is implemented and enabled.".into(),
    })
}

#[tauri::command]
fn privacy_get_status() -> Result<PrivacyStatus, String> {
    let mode = read_setting("privacy_mode.txt", "standard");
    let level = match mode.as_str() {
        "coin_control" => "enhanced-wallet-controls",
        "neutrino" => "enhanced-btc-light-privacy",
        "shielded_future" => "research-planned",
        _ => "standard",
    };
    Ok(PrivacyStatus {
        mode,
        level: level.into(),
        active_features: vec!["local QUB keys".into(), "non-custodial UX".into(), "endpoint choice preparation".into()],
        planned_features: vec!["coin control".into(), "address reuse warnings".into(), "BTC Neutrino/BIP157".into(), "QRX shielded layer research".into()],
        disclaimer: "Privacy-enhanced does not mean anonymous, untraceable or guaranteed private. Network analysis and endpoint metadata may still reveal information.".into(),
    })
}

#[tauri::command]
fn privacy_set_mode(mode: String) -> Result<PrivacyStatus, String> {
    let clean = match mode.as_str() {
        "standard" | "coin_control" | "neutrino" | "shielded_future" => mode,
        _ => "standard".into(),
    };
    write_setting("privacy_mode.txt", &clean).map_err(String::from)?;
    privacy_get_status()
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
        "getpeerinfo"|"getstakinginfo"|"getwalletinfo"|"getreward"|"getparams"|
        "gethalving"|"getforks"|"getactivefork"|"history"|"listpeers"|"peerstatus"|
        "banscores"|"validator-set"|"tokenomics"|"getdevaddress"|"getswap"|"listswaps"|
        "shielded-balance"|"shielded-history"|"stealth-history"|"privacy-feature-status"|
        "decoderawtransaction"|"gettxid"
    )
}

#[tauri::command]
fn wallet_cli_capabilities() -> Value {
    serde_json::json!({
        "surface":"qrx-cli",
        "coverage":"all qrx-cli commands",
        "mutations_require_confirmation":true,
        "mutations_require_wallet_passphrase":true,
        "complete_trade_selector":"qrx list-trades <chain-dir> * all",
        "complete_ledger_command":"qrx-wallet-cli export-ledger",
        "note":"The desktop command center passes argument arrays directly without a shell."
    })
}

#[tauri::command]
fn wallet_cli_execute(app:tauri::AppHandle,network:Option<String>,wallet:Option<String>,arguments:Vec<String>,confirmed:bool,passphrase:Option<String>)->Result<CommandResult,String>{
    let network=network.unwrap_or_else(||"alpha".into()); let wallet=sanitize_wallet_name(wallet.unwrap_or_else(||"node1".into()).as_str()).map_err(String::from)?;
    if arguments.is_empty(){return Err("Enter a qrx-cli command".into());}
    if arguments.len()>64{return Err("Too many command arguments".into());}
    for value in &arguments{if value.contains('\0')||value.len()>131072{return Err("Invalid or oversized command argument".into());}}
    let read_only=wallet_cli_is_read_only(arguments[0].as_str());
    if !read_only&&!confirmed{return Err("This command can change wallet or chain state. Confirm it explicitly first.".into());}
    if !read_only&&passphrase.as_deref().unwrap_or("").is_empty(){return Err("Unlock the wallet before executing a state-changing command".into());}
    let refs=arguments.iter().map(String::as_str).collect::<Vec<_>>();
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
            list_legacy_gui_wallets,
            import_legacy_gui_wallet,
            inspect_wallet,
            verify_wallet_passphrase,
            change_wallet_passphrase,
            lock_wallet_session,
            import_key_set_directory,
            prepare_existing_wallet,
            create_wallet,
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
            get_history,
            get_staking_info,
            get_validators,
            get_tokenomics,
            get_node_info,
            list_peers,
            send_to_address,
            stake,
            delegate,
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
            htlc_safety_status,
            htlc_set_safety,
            quantum_guard_audit_log,
            quantum_guard_preview_create,
            quantum_guard_preview_redeem,
            quantum_guard_preview_refund,
            core_create_swap,
            core_get_swap,
            core_list_swaps,
            core_redeem_swap,
            core_refund_swap,
            swap_create,
            swap_status,
            swap_refund,
            aura_plan_status,
            aura_checkout_quote,
            aura_local_help,
            aura_cloud_request_preview,
            exchange_ready_status,
            shielded_pool_status,
            privacy_action_preview,
            privacy_get_status,
            privacy_set_mode,
            wallet_cli_capabilities,
            wallet_cli_execute,
            dashboard_snapshot,
        ])
        .run(tauri::generate_context!())
        .expect("error while running QUBITCOIN Wallet");
}
