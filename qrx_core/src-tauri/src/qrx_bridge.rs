
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::commands::WalletConfig;

fn repo_root() -> Result<PathBuf, String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| "failed to locate repository root".to_string())
}

fn default_cli_path() -> Result<PathBuf, String> {
    let root = repo_root()?;
    let release = root.join("vendor").join("qrx-core").join("build").join("Release");
    let normal = root.join("vendor").join("qrx-core").join("build");
    #[cfg(target_os = "windows")]
    {
        let release_bin = release.join("qrx-cli.exe");
        if release_bin.exists() { return Ok(release_bin); }
        Ok(normal.join("qrx-cli.exe"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let release_bin = release.join("qrx-cli");
        if release_bin.exists() { return Ok(release_bin); }
        Ok(normal.join("qrx-cli"))
    }
}

fn default_daemon_path() -> Result<PathBuf, String> {
    let root = repo_root()?;
    let release = root.join("vendor").join("qrx-core").join("build").join("Release");
    let normal = root.join("vendor").join("qrx-core").join("build");
    #[cfg(target_os = "windows")]
    {
        let release_bin = release.join("qrxd.exe");
        if release_bin.exists() { return Ok(release_bin); }
        Ok(normal.join("qrxd.exe"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let release_bin = release.join("qrxd");
        if release_bin.exists() { return Ok(release_bin); }
        Ok(normal.join("qrxd"))
    }
}

fn cli_path(config: &WalletConfig) -> Result<PathBuf, String> {
    if let Some(path) = &config.cliPath {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    default_cli_path()
}

fn daemon_path(config: &WalletConfig) -> Result<PathBuf, String> {
    if let Some(path) = &config.daemonPath {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    default_daemon_path()
}

pub fn run_qrx_cli(config: &WalletConfig, command: &str, args: &[String]) -> Result<String, String> {
    let cli = cli_path(config)?;
    if !cli.exists() {
        return Err(format!(
            "qrx-cli not found at {}. Build QRX core first.",
            cli.display()
        ));
    }

    let mut cmd = Command::new(&cli);
    cmd.arg("--network").arg(&config.network);
    if let Some(datadir) = &config.datadir {
        if !datadir.trim().is_empty() {
            cmd.arg("--datadir").arg(datadir);
        }
    }
    cmd.arg("--wallet").arg(&config.wallet);
    cmd.arg(command);
    for arg in args {
        cmd.arg(arg);
    }

    let output = cmd.output().map_err(|e| format!("failed to run qrx-cli: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

pub fn start_qrxd(config: &WalletConfig) -> Result<String, String> {
    let daemon = daemon_path(config)?;
    if !daemon.exists() {
        return Err(format!(
            "qrxd not found at {}. Build QRX core first.",
            daemon.display()
        ));
    }

    let mut cmd = Command::new(&daemon);
    cmd.arg("--network").arg(&config.network);

    if let Some(datadir) = &config.datadir {
        if !datadir.trim().is_empty() {
            cmd.arg("--datadir").arg(datadir);
        }
    }

    cmd.arg("--wallet").arg(&config.wallet);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = cmd.output().map_err(|e| format!("failed to start qrxd: {e}"))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            Ok("qrxd started".to_string())
        } else {
            Ok(stdout)
        }
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}
