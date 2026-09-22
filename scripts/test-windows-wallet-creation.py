"""Exercise production GUI sidecar resolution and seed-new on Windows.

Usage: python scripts/test-windows-wallet-creation.py PATH/TO/qrx.exe
Requires rustc on PATH. Uses a disposable test wallet, never the user's store.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

assert os.name == "nt", "Windows-only packaging regression"
core = Path(sys.argv[1]).resolve(strict=True)
source_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parents[1] / "GUIWALLET/src-tauri/src/main.rs"
source = source_path.read_text()
functions = []
for name in ("current_sidecar_binary_name", "candidate_paths", "resolve_binary", "background_command", "run_qrx", "wallet_directory_has_entries", "ensure_new_wallet_target"):
    match = re.search(r"^fn " + name + r"\(.*?^\}", source, re.S | re.M)
    assert match, name
    functions.append(match.group())
harness = r'''
use std::{path::{Path, PathBuf}, process::{Command, Stdio}, fs};
#[derive(Debug)] enum AppError { Message(String), Io(std::io::Error) }
impl From<std::io::Error> for AppError { fn from(e: std::io::Error)->Self { Self::Io(e) } }
mod tauri {
    pub struct AppHandle;
    impl AppHandle { pub fn path_resolver(&self)->Self {Self} pub fn resource_dir(&self)->Option<std::path::PathBuf> {None} }
}
'''
harness += "\n".join(functions)
harness += r'''
fn main() {
    let root=std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let resolved=resolve_binary(None,"qrx").expect("packaged qrx.exe must resolve");
    assert_eq!(resolved,root.join("qrx.exe"));
    let wallet=root.join("disposable test wallet");
    assert!(ensure_new_wallet_target(&wallet).is_ok());
    fs::create_dir(&wallet).unwrap();
    assert!(!wallet_directory_has_entries(&wallet).unwrap());
    assert!(ensure_new_wallet_target(&wallet).is_ok());
    let out=run_qrx(None,&["seed-new",wallet.to_str().unwrap()],Some("test-only-no-funds-123"),None).expect("GUI seed-new invocation failed");
    assert!(out.lines().any(|x|x.starts_with("address=")));
    assert!(out.lines().any(|x|x.starts_with("recovery_phrase=") && x.len()>20));
    for name in ["wallet.json","address.txt","ed25519_priv.pem","ed25519_pub.pem","mldsa65_priv.pem","mldsa65_pub.pem","recovery.qrxseed"] {
        assert!(wallet.join(name).is_file(),"missing {}",name);
    }
    assert!(wallet_directory_has_entries(&wallet).unwrap());
    assert!(ensure_new_wallet_target(&wallet).is_err());
    let partial=root.join("partial"); fs::create_dir(&partial).unwrap();
    fs::write(partial.join("ed25519_priv.pem"),b"incomplete test data").unwrap();
    assert!(wallet_directory_has_entries(&partial).unwrap());
    assert!(ensure_new_wallet_target(&partial).is_err());
    assert_eq!(fs::read(partial.join("ed25519_priv.pem")).unwrap(),b"incomplete test data");
    let named=root.join(current_sidecar_binary_name("qrx"));
    fs::rename(root.join("qrx.exe"),&named).unwrap();
    assert_eq!(resolve_binary(None,"qrx").unwrap(),named);
    fs::remove_file(&named).unwrap();
    fs::create_dir(root.join("qrx.exe")).unwrap();
    assert!(resolve_binary(None,"qrx").is_err());
    println!("PASS: packaged and target-suffixed sidecars, GUI seed-new, recovery files, missing binary");
}
'''
base = Path(tempfile.gettempdir()).resolve()
with tempfile.TemporaryDirectory(prefix="qrx GUI regression ", dir=base) as directory:
    root = Path(directory).resolve()
    assert root.parent == base and root.name.startswith("qrx GUI regression ")
    shutil.copy2(core, root / "qrx.exe")
    (root / "test.rs").write_text(harness)
    subprocess.run(["rustc", "--edition=2021", "-A", "dead_code", "test.rs", "-o", "test.exe"], cwd=root, check=True)
    env = os.environ.copy()
    env.pop("QRX_BIN_DIR", None)
    subprocess.run([str(root / "test.exe")], cwd=root, env=env, check=True)
