
use crate::qrx_bridge;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WalletConfig {
    pub network: String,
    pub wallet: String,
    pub datadir: Option<String>,
    pub cliPath: Option<String>,
    pub daemonPath: Option<String>,
}

#[tauri::command]
pub fn run_qrx_cli(command: String, args: Vec<String>, config: WalletConfig) -> Result<String, String> {
    qrx_bridge::run_qrx_cli(&config, &command, &args)
}

#[tauri::command]
pub fn start_qrxd(config: WalletConfig) -> Result<String, String> {
    qrx_bridge::start_qrxd(&config)
}
