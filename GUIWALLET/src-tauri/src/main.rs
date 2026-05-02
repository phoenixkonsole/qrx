#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use dirs::data_local_dir;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
    net::{TcpStream, ToSocketAddrs},
};
use tauri::Manager;
use thiserror::Error;
use std::str::FromStr;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use argon2::{Algorithm, Argon2, Params, Version};
use bdk::{
    bitcoin::{Address, Network},
    blockchain::{Blockchain, ElectrumBlockchain},
    database::MemoryDatabase,
    electrum_client::Client as ElectrumClient,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
    },
    wallet::AddressIndex,
    FeeRate, SignOptions, SyncOptions, Wallet,
};
use bdk::miniscript::Segwitv0;

struct DaemonState {
    child: Mutex<Option<Child>>,
}

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
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportResult {
    wallet: WalletContext,
    imported_files: Vec<String>,
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

    let base = data_local_dir()
        .ok_or_else(|| AppError::Message("Could not resolve local app data directory".into()))?;
    let dir = base.join("gui-wallet").join("qrx-data");
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

fn control_socket_path(network: &str) -> Result<PathBuf, AppError> {
    Ok(network_root(network)?.join("control.sock"))
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
    let control_socket = control_socket_path(network)?;
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

    Ok(DaemonHealth {
        running,
        launched_by_app,
        pid,
        network: network.to_string(),
        wallet: wallet.to_string(),
        data_dir: data_dir.to_string_lossy().to_string(),
        control_socket: control_socket.to_string_lossy().to_string(),
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
        .arg(wallet)
        .arg("--listen")
        .arg("127.0.0.1:26661");

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
        wallets.push(WalletListItem {
            name: entry.file_name().to_string_lossy().to_string(),
            path: path.to_string_lossy().to_string(),
            address: read_address(&path),
            has_recovery_file: path.join("recovery.qrxseed").exists(),
        });
    }

    wallets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(wallets)
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

#[tauri::command]
fn import_wallet_directory(
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
    if target.exists() && target.join("wallet.json").exists() {
        return Err("Target wallet already exists".into());
    }

    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    let imported_files = copy_dir_recursive(&source, &target).map_err(String::from)?;
    Ok(ImportResult {
        wallet: ensure_context(&network, &wallet).map_err(String::from)?,
        imported_files,
    })
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
fn get_history(
    app: tauri::AppHandle,
    network: Option<String>,
    wallet: Option<String>,
    limit: Option<u32>,
    passphrase: Option<String>,
) -> Result<Value, String> {
    let network = network.unwrap_or_else(|| "alpha".into());
    let wallet = sanitize_wallet_name(wallet.as_deref().unwrap_or("node1")).map_err(String::from)?;
    let limit_s = limit.unwrap_or(20).to_string();
    let res = run_cli(
        Some(&app),
        &network,
        &wallet,
        &["history", "", &limit_s],
        passphrase.as_deref(),
    )
    .or_else(|_| run_cli(Some(&app), &network, &wallet, &["history"], passphrase.as_deref()))
    .map_err(String::from)?;
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
struct BtcWalletFile {
    network: String,
    encrypted_mnemonic: String,
    nonce: String,
    kdf: String,
    kdf_salt: String,
    descriptor: String,
    change_descriptor: String,
    mnemonic_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyBtcWalletFile {
    network: String,
    mnemonic: String,
    descriptor: String,
    change_descriptor: String,
    mnemonic_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyEncryptedBtcWalletFile {
    network: String,
    encrypted_mnemonic: String,
    nonce: String,
    descriptor: String,
    change_descriptor: String,
    mnemonic_note: String,
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

fn default_btc_endpoints(mode: &str) -> Vec<String> {
    match mode {
        "esplora" => vec![
            "https://blockstream.info/api".into(),
            "https://mempool.space/api".into(),
        ],
        "neutrino" => vec!["neutrino://bitcoin-p2p-mainnet".into()],
        _ => vec![
            "ssl://electrum.blockstream.info:50002".into(),
            "ssl://electrum.emzy.de:50002".into(),
            "ssl://electrum.bitaroo.net:50002".into(),
            "tcp://electrum.blockstream.info:50001".into(),
        ],
    }
}

fn normalize_endpoint(raw: &str, mode: &str) -> Option<String> {
    let mut s = raw.trim().trim_matches(',').trim().to_string();
    if s.is_empty() || s.starts_with('#') { return None; }
    if !s.contains("://") {
        if mode == "esplora" || s.starts_with("http") {
            if !s.starts_with("http") { s = format!("https://{s}"); }
        } else {
            s = format!("ssl://{s}");
        }
    }
    Some(s)
}

fn parse_endpoint_list(raw: &str, mode: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in raw.split(|c| c == '\n' || c == ',' || c == ';') {
        if let Some(ep) = normalize_endpoint(part, mode) {
            if !out.contains(&ep) { out.push(ep); }
        }
    }
    if out.is_empty() { default_btc_endpoints(mode) } else { out }
}

fn endpoint_host_port(endpoint: &str) -> Option<String> {
    let ep = endpoint.trim();
    if ep.starts_with("http://") || ep.starts_with("https://") || ep.starts_with("neutrino://") { return None; }
    let ep = ep.strip_prefix("ssl://").or_else(|| ep.strip_prefix("tcp://")).unwrap_or(ep);
    if ep.contains(':') { Some(ep.to_string()) } else { Some(format!("{ep}:50002")) }
}

fn test_endpoint_quick(endpoint: &str) -> EndpointHealth {
    let started = std::time::Instant::now();
    if endpoint.starts_with("https://") || endpoint.starts_with("http://") {
        return EndpointHealth { endpoint: endpoint.into(), status: "configured".into(), latency_ms: None, note: "HTTP/Esplora endpoint saved. Full HTTP test is performed by the future BDK/Esplora module.".into() };
    }
    if endpoint.starts_with("neutrino://") {
        return EndpointHealth { endpoint: endpoint.into(), status: "prepared".into(), latency_ms: None, note: "Neutrino/BIP157 mode prepared. BTC P2P compact-filter client is not bundled yet.".into() };
    }
    let Some(host_port) = endpoint_host_port(endpoint) else {
        return EndpointHealth { endpoint: endpoint.into(), status: "unknown".into(), latency_ms: None, note: "Unsupported endpoint format".into() };
    };
    let timeout = Duration::from_millis(1200);
    let addrs = match host_port.to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => return EndpointHealth { endpoint: endpoint.into(), status: "dns-error".into(), latency_ms: None, note: e.to_string() },
    };
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return EndpointHealth { endpoint: endpoint.into(), status: "reachable".into(), latency_ms: Some(started.elapsed().as_millis()), note: "TCP connection succeeded. Electrum protocol handshake will be handled by the BTC module.".into() };
        }
    }
    EndpointHealth { endpoint: endpoint.into(), status: "unreachable".into(), latency_ms: Some(started.elapsed().as_millis()), note: "No endpoint in this fallback entry accepted a quick TCP connection.".into() }
}

fn choose_active_endpoint(endpoints: &[String]) -> (String, Vec<EndpointHealth>) {
    let mut health = Vec::new();
    let mut active = endpoints.first().cloned().unwrap_or_else(|| "not-configured".into());
    for ep in endpoints {
        let h = test_endpoint_quick(ep);
        let ok = h.status == "reachable" || h.status == "configured" || h.status == "prepared";
        health.push(h);
        if ok { active = ep.clone(); break; }
    }
    for ep in endpoints.iter().skip(health.len()) {
        health.push(EndpointHealth { endpoint: ep.clone(), status: "fallback-standby".into(), latency_ms: None, note: "Not tested because an earlier endpoint was selected.".into() });
    }
    (active, health)
}

#[tauri::command]
fn btc_get_status(endpoint: Option<String>, passphrase: Option<String>) -> Result<BtcLightStatus, String> {
    let mode = read_setting("btc_mode.txt", "electrum");
    if let Some(ep) = endpoint.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let endpoints = parse_endpoint_list(ep, &mode);
        write_setting("btc_endpoints.txt", &endpoints.join("\n")).map_err(String::from)?;
        write_setting("btc_endpoint.txt", endpoints.first().map(String::as_str).unwrap_or("")).map_err(String::from)?;
    }

    let raw = read_setting("btc_endpoints.txt", &default_btc_endpoints(&mode).join("\n"));
    let endpoints = parse_endpoint_list(&raw, &mode);
    let (active_endpoint, endpoint_health) = choose_active_endpoint(&endpoints);
    let endpoint = endpoints.first().cloned().unwrap_or_else(|| active_endpoint.clone());
    let privacy_level = if mode == "neutrino" { "enhanced-local-filter-checks" } else { "medium-server-assisted" };

    let mut confirmed_sats = 0u64;
    let mut trusted_pending_sats = 0u64;
    let mut untrusted_pending_sats = 0u64;
    let mut immature_sats = 0u64;
    let mut synced = false;

    if mode == "electrum" {
        if let Ok((wallet, blockchain)) = open_bdk_wallet(&active_endpoint, passphrase.clone()) {
            if wallet.sync(&blockchain, SyncOptions::default()).is_ok() {
                let b = wallet.get_balance().map_err(|e| e.to_string())?;
                confirmed_sats = b.confirmed;
                trusted_pending_sats = b.trusted_pending;
                untrusted_pending_sats = b.untrusted_pending;
                immature_sats = b.immature;
                synced = true;
            }
        }
    }

    let total_sats = confirmed_sats
        .saturating_add(trusted_pending_sats)
        .saturating_add(untrusted_pending_sats)
        .saturating_add(immature_sats);

    Ok(BtcLightStatus {
        mode: mode.clone(),
        balance: format!("{:.8} BTC", total_sats as f64 / 100_000_000.0),
        confirmed_sats,
        trusted_pending_sats,
        untrusted_pending_sats,
        immature_sats,
        endpoint,
        active_endpoint,
        endpoints,
        endpoint_health,
        fallback_enabled: true,
        privacy_level: privacy_level.into(),
        neutrino_ready: mode == "neutrino",
        full_node_required: false,
        synced,
        explanation: "BTC Light uses BDK + Electrum in this build. No Bitcoin full-node download is required. Endpoint fallback is configurable; the wallet uses the first reachable endpoint.".into(),
        disclaimer: "This is non-custodial wallet software. It does not hold BTC and does not provide exchange, custody, brokerage or investment services. Public endpoints can see network metadata; use your own endpoint or Neutrino when available for better privacy.".into(),
    })
}

#[tauri::command]
fn btc_set_mode(mode: String, endpoint: Option<String>) -> Result<BtcLightStatus, String> {
    let clean = match mode.as_str() { "electrum" | "esplora" | "neutrino" => mode, _ => "electrum".into() };
    write_setting("btc_mode.txt", &clean).map_err(String::from)?;
    if let Some(ep) = endpoint.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let endpoints = parse_endpoint_list(ep, &clean);
        write_setting("btc_endpoints.txt", &endpoints.join("\n")).map_err(String::from)?;
        write_setting("btc_endpoint.txt", endpoints.first().map(String::as_str).unwrap_or("")).map_err(String::from)?;
    } else {
        write_setting("btc_endpoints.txt", &default_btc_endpoints(&clean).join("\n")).map_err(String::from)?;
    }
    btc_get_status(None, None)
}

#[tauri::command]
fn btc_test_endpoints(endpoint: Option<String>) -> Result<Vec<EndpointHealth>, String> {
    let mode = read_setting("btc_mode.txt", "electrum");
    let raw = endpoint.unwrap_or_else(|| read_setting("btc_endpoints.txt", &default_btc_endpoints(&mode).join("\n")));
    let endpoints = parse_endpoint_list(&raw, &mode);
    Ok(endpoints.iter().map(|ep| test_endpoint_quick(ep)).collect())
}

#[tauri::command]
fn btc_start_neutrino() -> Result<BtcLightStatus, String> {
    write_setting("btc_mode.txt", "neutrino").map_err(String::from)?;
    write_setting("btc_endpoints.txt", &default_btc_endpoints("neutrino").join("\n")).map_err(String::from)?;
    btc_get_status(None, None)
}


fn btc_wallet_dir() -> Result<PathBuf, String> {
    let dir = app_data_dir().map_err(|e| e.to_string())?.join("btc-light");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn btc_wallet_file() -> Result<PathBuf, String> {
    Ok(btc_wallet_dir()?.join("btc_wallet.json"))
}

fn btc_network() -> Network {
    // Keep mainnet because the product is BTC Light. Add UI switch later for testnet/signet.
    Network::Bitcoin
}


fn btc_password_file() -> Result<PathBuf, String> {
    Ok(btc_wallet_dir()?.join(".dev_password_hint"))
}

fn btc_password(passphrase: Option<String>) -> Result<String, String> {
    if let Some(p) = passphrase {
        if !p.trim().is_empty() {
            return Ok(p);
        }
    }
    // Development fallback: keep the app usable if UI has not yet been wired to pass a BTC password.
    // Production UI should always pass a user-chosen password.
    let path = btc_password_file()?;
    if path.exists() {
        return fs::read_to_string(path).map(|s| s.trim().to_string()).map_err(|e| e.to_string());
    }
    let generated = format!("dev-btc-pass-{}", chrono_like_timestamp());
    fs::write(&path, &generated).map_err(|e| e.to_string())?;
    Ok(generated)
}

fn derive_btc_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    // Argon2id KDF for BTC seed encryption.
    // Parameters are chosen for desktop UX; increase memory/time before public release testing if acceptable.
    let params = Params::new(
        64 * 1024, // 64 MiB
        3,         // iterations
        1,         // parallelism
        Some(32),  // output length
    ).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

fn encrypt_btc_mnemonic(words: &str, passphrase: &str) -> Result<(String, String, String), String> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_btc_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, words.as_bytes()).map_err(|e| e.to_string())?;
    Ok((
        general_purpose::STANDARD.encode(encrypted),
        general_purpose::STANDARD.encode(nonce_bytes),
        general_purpose::STANDARD.encode(salt),
    ))
}

fn decrypt_btc_mnemonic(wallet: &BtcWalletFile, passphrase: &str) -> Result<String, String> {
    let salt = general_purpose::STANDARD.decode(&wallet.kdf_salt).map_err(|e| e.to_string())?;
    let key = derive_btc_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let nonce_bytes = general_purpose::STANDARD.decode(&wallet.nonce).map_err(|e| e.to_string())?;
    let encrypted = general_purpose::STANDARD.decode(&wallet.encrypted_mnemonic).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted = cipher.decrypt(nonce, encrypted.as_ref()).map_err(|_| "Could not decrypt BTC mnemonic. Check BTC password/passphrase.".to_string())?;
    String::from_utf8(decrypted).map_err(|e| e.to_string())
}

fn btc_derivation_coin_type(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "0",
        _ => "1",
    }
}

fn normalize_electrum_url(endpoint: &str) -> String {
    let ep = endpoint.trim();
    if ep.starts_with("ssl://") || ep.starts_with("tcp://") {
        ep.to_string()
    } else if ep.starts_with("http://") || ep.starts_with("https://") || ep.starts_with("neutrino://") {
        ep.to_string()
    } else {
        format!("ssl://{ep}")
    }
}

fn descriptors_from_generated_mnemonic(mnemonic: Mnemonic, network: Network) -> Result<(String, String, String), String> {
    let words = mnemonic.to_string();
    let xkey: ExtendedKey = mnemonic.into_extended_key().map_err(|e| e.to_string())?;
    let xprv = xkey.into_xprv(network).ok_or_else(|| "Mnemonic did not produce an xprv".to_string())?;
    let coin = btc_derivation_coin_type(network);
    let descriptor = format!("wpkh({xprv}/84h/{coin}h/0h/0/*)");
    let change_descriptor = format!("wpkh({xprv}/84h/{coin}h/0h/1/*)");
    Ok((words, descriptor, change_descriptor))
}


fn wallet_file_from_words(words: &str, passphrase: &str, note: &str) -> Result<BtcWalletFile, String> {
    let mnemonic = Mnemonic::parse_in(Language::English, words).map_err(|e| e.to_string())?;
    let network = btc_network();
    let (_words, descriptor, change_descriptor) = descriptors_from_generated_mnemonic(mnemonic, network)?;
    let (encrypted_mnemonic, nonce, kdf_salt) = encrypt_btc_mnemonic(words, passphrase)?;
    Ok(BtcWalletFile {
        network: "bitcoin".into(),
        encrypted_mnemonic,
        nonce,
        kdf: "argon2id:v=19,m=65536,t=3,p=1".into(),
        kdf_salt,
        descriptor,
        change_descriptor,
        mnemonic_note: note.into(),
    })
}

fn write_btc_wallet(wallet: &BtcWalletFile) -> Result<(), String> {
    let path = btc_wallet_file()?;
    fs::write(&path, serde_json::to_string_pretty(wallet).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn generate_btc_wallet_file(passphrase: &str) -> Result<BtcWalletFile, String> {
    let generated: GeneratedKey<Mnemonic, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English)).map_err(|e| format!("{:?}", e))?;
    let mnemonic = generated.into_key();
    let network = btc_network();
    let (words, descriptor, change_descriptor) = descriptors_from_generated_mnemonic(mnemonic, network)?;
    let (encrypted_mnemonic, nonce, kdf_salt) = encrypt_btc_mnemonic(&words, passphrase)?;
    Ok(BtcWalletFile {
        network: "bitcoin".into(),
        encrypted_mnemonic,
        nonce,
        kdf: "argon2id:v=19,m=65536,t=3,p=1".into(),
        kdf_salt,
        descriptor,
        change_descriptor,
        mnemonic_note: "BTC mnemonic is encrypted locally with the BTC password/passphrase. Do not lose your password or backup phrase.".into(),
    })
}

fn ensure_btc_wallet_file(passphrase: &str) -> Result<BtcWalletFile, String> {
    let path = btc_wallet_file()?;
    if path.exists() {
        let txt = fs::read_to_string(&path).map_err(|e| e.to_string())?;

        if let Ok(wallet) = serde_json::from_str::<BtcWalletFile>(&txt) {
            // Verify password now, so wrong password fails early.
            let _ = decrypt_btc_mnemonic(&wallet, passphrase)?;
            return Ok(wallet);
        }

        if let Ok(_legacy_encrypted) = serde_json::from_str::<LegacyEncryptedBtcWalletFile>(&txt) {
            return Err("Existing BTC wallet uses the previous SHA-256 KDF encryption format. For safety, export/backup funds with the old build, then create a new Argon2id wallet in this build.".into());
        }

        // Migration from previous dev build with plaintext mnemonic.
        if let Ok(legacy) = serde_json::from_str::<LegacyBtcWalletFile>(&txt) {
            let (encrypted_mnemonic, nonce, kdf_salt) = encrypt_btc_mnemonic(&legacy.mnemonic, passphrase)?;
            let wallet = BtcWalletFile {
                network: legacy.network,
                encrypted_mnemonic,
                nonce,
                kdf: "argon2id:v=19,m=65536,t=3,p=1".into(),
                kdf_salt,
                descriptor: legacy.descriptor,
                change_descriptor: legacy.change_descriptor,
                mnemonic_note: "Migrated from plaintext dev wallet. BTC mnemonic is now encrypted locally.".into(),
            };
            fs::write(&path, serde_json::to_string_pretty(&wallet).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            return Ok(wallet);
        }

        // If an old placeholder exists, replace it.
        let wallet = generate_btc_wallet_file(passphrase)?;
        fs::write(&path, serde_json::to_string_pretty(&wallet).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        return Ok(wallet);
    }

    let wallet = generate_btc_wallet_file(passphrase)?;
    fs::write(&path, serde_json::to_string_pretty(&wallet).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(wallet)
}

fn open_bdk_wallet(endpoint: &str, passphrase: Option<String>) -> Result<(Wallet<MemoryDatabase>, ElectrumBlockchain), String> {
    let pass = btc_password(passphrase)?;
    let wallet_file = ensure_btc_wallet_file(&pass)?;
    let _words = decrypt_btc_mnemonic(&wallet_file, &pass)?;
    let network = btc_network();
    let wallet = Wallet::new(
        &wallet_file.descriptor,
        Some(&wallet_file.change_descriptor),
        network,
        MemoryDatabase::default(),
    ).map_err(|e| e.to_string())?;

    let client = ElectrumClient::new(&normalize_electrum_url(endpoint)).map_err(|e| e.to_string())?;
    let blockchain = ElectrumBlockchain::from(client);
    Ok((wallet, blockchain))
}

fn active_btc_endpoint() -> Result<String, String> {
    let mode = read_setting("btc_mode.txt", "electrum");
    let raw = read_setting("btc_endpoints.txt", &default_btc_endpoints(&mode).join("\n"));
    let endpoints = parse_endpoint_list(&raw, &mode);
    let (active_endpoint, _) = choose_active_endpoint(&endpoints);
    Ok(active_endpoint)
}

#[tauri::command]
fn btc_init_wallet(passphrase: Option<String>) -> Result<BtcWalletInitResult, String> {
    let endpoint = active_btc_endpoint()?;
    let (wallet, _blockchain) = open_bdk_wallet(&endpoint, passphrase)?;
    let address = wallet
        .get_address(AddressIndex::Peek(0))
        .map_err(|e| e.to_string())?
        .address
        .to_string();

    Ok(BtcWalletInitResult {
        status: "bdk-wallet-ready".into(),
        network: "bitcoin".into(),
        address,
        warning: "BTC mnemonic is encrypted locally with Argon2id + AES-GCM. Keep backups safe.".into(),
    })
}

#[tauri::command]
fn btc_backup_phrase(passphrase: Option<String>) -> Result<BtcBackupResult, String> {
    let pass = btc_password(passphrase)?;
    let wallet = ensure_btc_wallet_file(&pass)?;
    let words = decrypt_btc_mnemonic(&wallet, &pass)?;
    Ok(BtcBackupResult {
        status: "backup-phrase-decrypted".into(),
        mnemonic: words,
        warning: "Write this recovery phrase down offline. Anyone with these words can spend the BTC wallet. Never share it.".into(),
    })
}

#[tauri::command]
fn btc_restore_wallet(mnemonic: String, passphrase: Option<String>, overwrite: bool) -> Result<BtcRestoreResult, String> {
    let words = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    if words.is_empty() {
        return Err("Recovery phrase is required".into());
    }

    let path = btc_wallet_file()?;
    if path.exists() && !overwrite {
        return Err("BTC wallet already exists. Enable overwrite to replace it after backing up current funds.".into());
    }

    // Validate by parsing and deriving descriptors.
    let pass = btc_password(passphrase)?;
    let wallet = wallet_file_from_words(
        &words,
        &pass,
        "Restored from recovery phrase. BTC mnemonic is encrypted locally with Argon2id + AES-GCM.",
    )?;
    write_btc_wallet(&wallet)?;

    let _ = fs::remove_file(btc_wallet_dir()?.join("address_index.txt"));

    let endpoint = active_btc_endpoint()?;
    let (bdk_wallet, _blockchain) = open_bdk_wallet(&endpoint, Some(pass))?;
    let first_address = bdk_wallet
        .get_address(AddressIndex::Peek(0))
        .map_err(|e| e.to_string())?
        .address
        .to_string();

    Ok(BtcRestoreResult {
        status: "btc-wallet-restored".into(),
        network: "bitcoin".into(),
        first_address,
        warning: "Restored wallet. Run sync to check balance/history.".into(),
    })
}

#[tauri::command]
fn btc_reset_wallet(confirm: String) -> Result<String, String> {
    if confirm.trim() != "DELETE BTC WALLET" {
        return Err("Type DELETE BTC WALLET to confirm reset.".into());
    }
    let path = btc_wallet_file()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    let _ = fs::remove_file(btc_wallet_dir()?.join("address_index.txt"));
    Ok("Local encrypted BTC wallet removed. This does not move funds; you need the recovery phrase to restore access.".into())
}

#[tauri::command]
fn btc_sync(passphrase: Option<String>) -> Result<BtcLightStatus, String> {
    btc_get_status(None, passphrase)
}

#[tauri::command]
fn btc_get_balance(passphrase: Option<String>) -> Result<BtcLightStatus, String> {
    btc_get_status(None, passphrase)
}

#[tauri::command]
fn btc_new_address(passphrase: Option<String>) -> Result<BtcReceiveAddress, String> {
    let endpoint = active_btc_endpoint()?;
    let (wallet, _blockchain) = open_bdk_wallet(&endpoint, passphrase)?;
    let counter_path = btc_wallet_dir()?.join("address_index.txt");
    let current = fs::read_to_string(&counter_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let address = wallet
        .get_address(AddressIndex::Peek(current))
        .map_err(|e| e.to_string())?
        .address
        .to_string();
    fs::write(&counter_path, (current + 1).to_string()).map_err(|e| e.to_string())?;

    Ok(BtcReceiveAddress {
        address,
        status: "bdk-address".into(),
        note: "Real BTC address generated by BDK descriptor wallet. BTC mnemonic is encrypted locally. Keep your password and backup safe.".into(),
    })
}

#[tauri::command]
fn btc_send(to_address: String, amount_sats: u64, fee_rate_sat_vb: Option<f32>, passphrase: Option<String>) -> Result<BtcSendResult, String> {
    if amount_sats == 0 {
        return Err("amount_sats must be greater than zero".into());
    }
    let endpoint = active_btc_endpoint()?;
    let (wallet, blockchain) = open_bdk_wallet(&endpoint, passphrase)?;
    wallet.sync(&blockchain, SyncOptions::default()).map_err(|e| e.to_string())?;

    let address = Address::from_str(to_address.trim()).map_err(|e| e.to_string())?;
    let address = address.require_network(btc_network()).map_err(|e| e.to_string())?;
    let mut builder = wallet.build_tx();
    builder.add_recipient(address.script_pubkey(), amount_sats);
    if let Some(rate) = fee_rate_sat_vb {
        if rate > 0.0 {
            builder.fee_rate(FeeRate::from_sat_per_vb(rate));
        }
    }

    let (mut psbt, _details) = builder.finish().map_err(|e| e.to_string())?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default()).map_err(|e| e.to_string())?;
    if !finalized {
        return Err("Could not finalize BTC transaction".into());
    }
    let tx = psbt.extract_tx();
    blockchain.broadcast(&tx).map_err(|e| e.to_string())?;
    Ok(BtcSendResult {
        txid: tx.txid().to_string(),
        amount_sats,
        recipient: to_address,
        endpoint,
    })
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

fn main() {
    tauri::Builder::default()
        .manage(DaemonState {
            child: Mutex::new(None),
        })
        .setup(|app| {
            let _ = app.handle();
            let _ = File::create(app_data_dir()?.join(".boot-ok"));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_context,
            list_wallets,
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
            dashboard_snapshot,
        ])
        .run(tauri::generate_context!())
        .expect("error while running QUBITCOIN Wallet");
}
