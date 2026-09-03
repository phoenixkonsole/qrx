#!/usr/bin/env bash
set -euo pipefail
BIN_DIR="$(cd "$(dirname "$0")/../src-tauri/bin" && pwd)"
TAURI_DIR="$(cd "$(dirname "$0")/../src-tauri" && pwd)"
echo "Checking QRX sidecars in: $BIN_DIR"
if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
  target="${CARGO_BUILD_TARGET:-$(rustc -vV | awk '/^host:/{print $2}')}"
  cargo build --manifest-path "$TAURI_DIR/Cargo.toml" --bin qrx-btc-wallet-service --target "$target"
  ext=""; [[ "$target" == *windows* ]] && ext=".exe"
  cp "$TAURI_DIR/target/$target/debug/qrx-btc-wallet-service$ext" "$BIN_DIR/qrx-btc-wallet-service-$target$ext"
fi
linux_bins=("qrx-x86_64-unknown-linux-gnu" "qrx-cli-x86_64-unknown-linux-gnu" "qrxd-x86_64-unknown-linux-gnu" "qrx-btc-wallet-service-x86_64-unknown-linux-gnu" "qrx-aarch64-unknown-linux-gnu" "qrx-cli-aarch64-unknown-linux-gnu" "qrxd-aarch64-unknown-linux-gnu" "qrx-btc-wallet-service-aarch64-unknown-linux-gnu")
for f in "${linux_bins[@]}"; do
  if [[ -f "$BIN_DIR/$f" ]]; then chmod +x "$BIN_DIR/$f"; echo "OK Linux executable: $f"; else echo "Missing Linux sidecar: $f"; fi
done
cat <<'EOF'

Expected additional release sidecars:

Linux ARM64:
  qrx-aarch64-unknown-linux-gnu
  qrx-cli-aarch64-unknown-linux-gnu
  qrxd-aarch64-unknown-linux-gnu
  qrx-btc-wallet-service-aarch64-unknown-linux-gnu

macOS Intel:
  qrx-x86_64-apple-darwin
  qrx-cli-x86_64-apple-darwin
  qrxd-x86_64-apple-darwin
  qrx-btc-wallet-service-x86_64-apple-darwin

macOS Apple Silicon:
  qrx-aarch64-apple-darwin
  qrx-cli-aarch64-apple-darwin
  qrxd-aarch64-apple-darwin
  qrx-btc-wallet-service-aarch64-apple-darwin

Windows x64:
  qrx-x86_64-pc-windows-msvc.exe
  qrx-cli-x86_64-pc-windows-msvc.exe
  qrxd-x86_64-pc-windows-msvc.exe
  qrx-btc-wallet-service-x86_64-pc-windows-msvc.exe
EOF
