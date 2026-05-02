#!/usr/bin/env bash
set -euo pipefail
BIN_DIR="$(cd "$(dirname "$0")/../src-tauri/bin" && pwd)"
check_group(){ local group="$1"; shift; echo "[$group]"; local missing=0; for f in "$@"; do if [[ -f "$BIN_DIR/$f" ]]; then echo "  OK      $f"; else echo "  MISSING $f"; missing=1; fi; done; return $missing; }
status=0
check_group "Linux x64" qrx-x86_64-unknown-linux-gnu qrx-cli-x86_64-unknown-linux-gnu qrxd-x86_64-unknown-linux-gnu || status=1
check_group "macOS Intel" qrx-x86_64-apple-darwin qrx-cli-x86_64-apple-darwin qrxd-x86_64-apple-darwin || true
check_group "macOS Apple Silicon" qrx-aarch64-apple-darwin qrx-cli-aarch64-apple-darwin qrxd-aarch64-apple-darwin || true
check_group "Windows x64" qrx-x86_64-pc-windows-msvc.exe qrx-cli-x86_64-pc-windows-msvc.exe qrxd-x86_64-pc-windows-msvc.exe || true
exit $status
