#!/usr/bin/env bash
set -euo pipefail
BIN_DIR="$(cd "$(dirname "$0")/../src-tauri/bin" && pwd)"
echo "Checking QRX sidecars in: $BIN_DIR"
linux_bins=("qrx-x86_64-unknown-linux-gnu" "qrx-cli-x86_64-unknown-linux-gnu" "qrxd-x86_64-unknown-linux-gnu")
for f in "${linux_bins[@]}"; do
  if [[ -f "$BIN_DIR/$f" ]]; then chmod +x "$BIN_DIR/$f"; echo "OK Linux executable: $f"; else echo "Missing Linux sidecar: $f"; fi
done
cat <<'EOF'

Expected additional release sidecars:

macOS Intel:
  qrx-x86_64-apple-darwin
  qrx-cli-x86_64-apple-darwin
  qrxd-x86_64-apple-darwin

macOS Apple Silicon:
  qrx-aarch64-apple-darwin
  qrx-cli-aarch64-apple-darwin
  qrxd-aarch64-apple-darwin

Windows x64:
  qrx-x86_64-pc-windows-msvc.exe
  qrx-cli-x86_64-pc-windows-msvc.exe
  qrxd-x86_64-pc-windows-msvc.exe
EOF
