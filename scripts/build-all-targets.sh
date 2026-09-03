#!/usr/bin/env bash
set -euo pipefail

# QRX unified release builder.
# One target is built per native host. The GitHub Actions matrix invokes this
# same script on five native runners concurrently.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$ROOT/qrx-core"
WALLET="$ROOT/GUIWALLET"
DIST_ROOT="${QRX_DIST_DIR:-$ROOT/dist}"
BUILD_ROOT="${QRX_BUILD_DIR:-$ROOT/build}"
JOBS="${JOBS:-}"
TARGET=""
PLAN_ONLY=0
ALL_TARGETS=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build-all-targets.sh [--target host|TARGET] [--plan]
  ./scripts/build-all-targets.sh --all [--plan]
  ./scripts/build-all-targets.sh --list-targets

Targets:
  host          Auto-detect the current operating system and CPU architecture
  linux-x64     Linux x86-64: Core, CLI, tools, BTC service, DEB, AppImage
  linux-arm64   Linux ARM64: Core, CLI, tools, BTC service, DEB, AppImage
  macos-x64     macOS Intel: Core, CLI, tools, BTC service, APP, DMG
  macos-arm64   macOS Apple Silicon: Core, CLI, tools, BTC service, APP, DMG
  windows-x64   Windows x86-64 MSVC: Core, CLI, tools, BTC service, MSI, NSIS

Use --plan to validate and print the dependency order without compiling.
All five targets are built concurrently by .github/workflows/build-all-targets.yml.
With --all, this script dispatches that native runner matrix through GitHub CLI.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) [[ $# -ge 2 ]] || { echo "--target needs a value" >&2; exit 2; }; TARGET="$2"; shift 2 ;;
    --all) ALL_TARGETS=1; shift ;;
    --plan) PLAN_ONLY=1; shift ;;
    --list-targets) printf '%s\n' host linux-x64 linux-arm64 macos-x64 macos-arm64 windows-x64; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$ALL_TARGETS" -eq 1 ]]; then
  [[ -z "$TARGET" ]] || { echo "Use either --all or --target, not both" >&2; exit 2; }
  if [[ "$PLAN_ONLY" -eq 1 ]]; then
    for matrix_target in linux-x64 linux-arm64 macos-x64 macos-arm64 windows-x64; do
      "$0" --target "$matrix_target" --plan
    done
    exit 0
  fi
  command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) is required to dispatch all native targets" >&2; exit 4; }
  command -v git >/dev/null 2>&1 || { echo "git is required to determine the workflow ref" >&2; exit 4; }
  git_ref="${QRX_GIT_REF:-$(git -C "$ROOT" branch --show-current)}"
  [[ -n "$git_ref" ]] || { echo "Detached checkout: set QRX_GIT_REF to a pushed branch or tag" >&2; exit 4; }
  gh workflow run build-all-targets.yml --ref "$git_ref"
  echo "Dispatched all five native QRX builds for ref: $git_ref"
  echo "Follow them with: gh run watch"
  exit 0
fi

TARGET="${TARGET:-host}"
if [[ "$TARGET" == "host" ]]; then
  detected_os="$(uname -s)"; detected_arch="$(uname -m)"
  case "$detected_os:$detected_arch" in
    Linux:x86_64|Linux:amd64) TARGET="linux-x64" ;;
    Linux:aarch64|Linux:arm64) TARGET="linux-arm64" ;;
    Darwin:x86_64) TARGET="macos-x64" ;;
    Darwin:arm64|Darwin:aarch64) TARGET="macos-arm64" ;;
    MINGW*:x86_64|MSYS*:x86_64|CYGWIN*:x86_64) TARGET="windows-x64" ;;
    *) echo "Unsupported host: $detected_os $detected_arch" >&2; exit 3 ;;
  esac
  echo "Auto-detected host target: $TARGET"
fi

case "$TARGET" in
  linux-x64)
    RUST_TARGET="x86_64-unknown-linux-gnu"; HOST_OS="Linux"; CORE_EXT=""; CORE_SUBDIR=""; TAURI_CONFIG="src-tauri/tauri.linux.conf.json" ;;
  linux-arm64)
    RUST_TARGET="aarch64-unknown-linux-gnu"; HOST_OS="Linux"; CORE_EXT=""; CORE_SUBDIR=""; TAURI_CONFIG="src-tauri/tauri.linux.conf.json" ;;
  macos-x64)
    RUST_TARGET="x86_64-apple-darwin"; HOST_OS="Darwin"; CORE_EXT=""; CORE_SUBDIR=""; TAURI_CONFIG="src-tauri/tauri.macos.conf.json" ;;
  macos-arm64)
    RUST_TARGET="aarch64-apple-darwin"; HOST_OS="Darwin"; CORE_EXT=""; CORE_SUBDIR=""; TAURI_CONFIG="src-tauri/tauri.macos.conf.json" ;;
  windows-x64)
    RUST_TARGET="x86_64-pc-windows-msvc"; HOST_OS="MINGW"; CORE_EXT=".exe"; CORE_SUBDIR="Release"; TAURI_CONFIG="src-tauri/tauri.windows.conf.json" ;;
  *) echo "Unsupported target: $TARGET" >&2; usage >&2; exit 2 ;;
esac

cat <<EOF
QRX release plan: $TARGET
  1. Build static QRX Core library
  2. Build qrx, qrx-cli, qrxd and QRXDB tools
  3. Stage Python wallet/export/arbitrage/Kraken tools
  4. Build qrx-btc-wallet-service for $RUST_TARGET
  5. Install target-suffixed Core and BTC sidecars
  6. Build Tauri wallet using $TAURI_CONFIG
  7. Verify and package one checksummed release
EOF
[[ "$PLAN_ONLY" -eq 1 ]] && exit 0

echo "[0/7] Auditing GUI <-> Core/CLI compatibility"
python3 "$ROOT/scripts/audit-gui-core-compat.py"

actual_os="$(uname -s)"
actual_arch="$(uname -m)"
case "$HOST_OS" in
  Linux) [[ "$actual_os" == "Linux" ]] || { echo "$TARGET requires a native Linux runner" >&2; exit 3; } ;;
  Darwin) [[ "$actual_os" == "Darwin" ]] || { echo "$TARGET requires a native macOS runner" >&2; exit 3; } ;;
  MINGW) [[ "$actual_os" == MINGW* || "$actual_os" == MSYS* || "$actual_os" == CYGWIN* ]] || { echo "$TARGET requires a native Windows/MSVC runner" >&2; exit 3; } ;;
esac
case "$TARGET:$actual_arch" in
  linux-x64:x86_64|linux-x64:amd64|linux-arm64:aarch64|linux-arm64:arm64|windows-x64:x86_64) ;;
  linux-*:*|windows-x64:*) echo "$TARGET requires a matching native CPU runner; detected $actual_arch" >&2; exit 3 ;;
  *) ;;
esac

for command_name in cmake cargo rustc rustup node npm python3; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "Missing build dependency: $command_name" >&2; exit 4; }
done
if [[ "$TARGET" == "windows-x64" ]]; then
  command -v pwsh >/dev/null 2>&1 || { echo "Missing build dependency: pwsh" >&2; exit 4; }
else
  command -v make >/dev/null 2>&1 || { echo "Missing build dependency: make" >&2; exit 4; }
fi

if [[ -z "$JOBS" ]]; then
  if command -v nproc >/dev/null 2>&1; then JOBS="$(nproc)"; else JOBS="$(sysctl -n hw.ncpu)"; fi
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "JOBS must be a positive integer" >&2; exit 4; }

CORE_BUILD="$BUILD_ROOT/core/$TARGET"
TAURI_TARGET_DIR="$BUILD_ROOT/tauri/$TARGET"
TARGET_OUT="$DIST_ROOT/$TARGET"
case "$CORE_BUILD" in "$ROOT"/build/*) ;; *) echo "Unsafe core build directory: $CORE_BUILD" >&2; exit 5;; esac
case "$TAURI_TARGET_DIR" in "$ROOT"/build/*) ;; *) echo "Unsafe Tauri build directory: $TAURI_TARGET_DIR" >&2; exit 5;; esac
case "$TARGET_OUT" in "$ROOT"/dist/*) ;; *) echo "Unsafe release directory: $TARGET_OUT" >&2; exit 5;; esac

mkdir -p "$BUILD_ROOT/core" "$BUILD_ROOT/tauri" "$DIST_ROOT"
if [[ -e "$TARGET_OUT" ]]; then
  rm -rf -- "$TARGET_OUT"
fi

echo "[1/7] Building Core and native command-line tools"
case "$TARGET" in
  linux-x64|linux-arm64)
    QRX_OPENSSL_PREFIX="${QRX_OPENSSL_PREFIX:-$BUILD_ROOT/deps/openssl-$TARGET}"
    PREFIX="$QRX_OPENSSL_PREFIX" BUILD_DIR="$CORE_BUILD" JOBS="$JOBS" "$CORE/scripts/build-linux-static.sh"
    ;;
  macos-x64|macos-arm64)
    arch="x86_64"; [[ "$TARGET" == "macos-arm64" ]] && arch="arm64"
    QRX_OPENSSL_PREFIX="${QRX_OPENSSL_PREFIX:-$BUILD_ROOT/deps/openssl-macos-$arch}"
    PREFIX="$QRX_OPENSSL_PREFIX" BUILD_DIR="$CORE_BUILD" JOBS="$JOBS" "$CORE/scripts/build-macos-static.sh" "$arch"
    ;;
  windows-x64)
    vcpkg_root="${VCPKG_ROOT:-${VCPKG_INSTALLATION_ROOT:-C:\\vcpkg}}"
    pwsh -NoProfile -File "$CORE/scripts/build-windows-x64-static.ps1" -VcpkgRoot "$vcpkg_root" -BuildDir "$CORE_BUILD"
    ;;
esac

CORE_BIN_DIR="$CORE_BUILD"
[[ -n "$CORE_SUBDIR" ]] && CORE_BIN_DIR="$CORE_BUILD/$CORE_SUBDIR"
for binary in qrx qrx-cli qrxd qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
  [[ -f "$CORE_BIN_DIR/$binary$CORE_EXT" ]] || { echo "Core output missing: $CORE_BIN_DIR/$binary$CORE_EXT" >&2; exit 6; }
done

echo "[2/7] Staging complete CLI and Python tool set"
mkdir -p "$TARGET_OUT/core" "$TARGET_OUT/tools" "$TARGET_OUT/wallet"
for binary in qrx qrx-cli qrxd qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
  cp "$CORE_BIN_DIR/$binary$CORE_EXT" "$TARGET_OUT/core/$binary$CORE_EXT"
done
cp "$CORE/tools/qrx-wallet-cli.py" "$TARGET_OUT/tools/"
cp "$CORE/tools/qrx-complete-ledger-export.py" "$TARGET_OUT/tools/"
cp "$CORE/gateways/qrx-arbitrage-engine.py" "$TARGET_OUT/tools/"
cp "$CORE/gateways/qrx-gateway-kraken.py" "$TARGET_OUT/tools/"

echo "[3/7] Building shared Rust BTC wallet service"
rustup target add "$RUST_TARGET"
export CARGO_TARGET_DIR="$TAURI_TARGET_DIR"
# Keep the BTC service outside src-tauri. Tauri v1 scans src/bin as bundle
# candidates; placing the service there can make it become the macOS app's
# main executable instead of qrx-wallet.
BTC_SERVICE_MANIFEST="$WALLET/btc-wallet-service/Cargo.toml"
[[ -f "$BTC_SERVICE_MANIFEST" ]] || { echo "BTC service manifest missing: $BTC_SERVICE_MANIFEST" >&2; exit 7; }
if [[ -f "$WALLET/btc-wallet-service/Cargo.lock" ]]; then
  cargo build --locked --manifest-path "$BTC_SERVICE_MANIFEST" --release --target "$RUST_TARGET"
else
  cargo build --manifest-path "$BTC_SERVICE_MANIFEST" --release --target "$RUST_TARGET"
fi
BTC_SERVICE="$TAURI_TARGET_DIR/$RUST_TARGET/release/qrx-btc-wallet-service$CORE_EXT"
[[ -f "$BTC_SERVICE" ]] || { echo "BTC wallet service missing: $BTC_SERVICE" >&2; exit 7; }
cp "$BTC_SERVICE" "$TARGET_OUT/core/qrx-btc-wallet-service$CORE_EXT"

echo "[4/7] Installing exact target-suffixed Tauri sidecars"
TAURI_BIN="$WALLET/src-tauri/bin"
mkdir -p "$TAURI_BIN"
cp "$CORE_BIN_DIR/qrx$CORE_EXT" "$TAURI_BIN/qrx-$RUST_TARGET$CORE_EXT"
cp "$CORE_BIN_DIR/qrx-cli$CORE_EXT" "$TAURI_BIN/qrx-cli-$RUST_TARGET$CORE_EXT"
cp "$CORE_BIN_DIR/qrxd$CORE_EXT" "$TAURI_BIN/qrxd-$RUST_TARGET$CORE_EXT"
cp "$BTC_SERVICE" "$TAURI_BIN/qrx-btc-wallet-service-$RUST_TARGET$CORE_EXT"
[[ "$TARGET" == "windows-x64" ]] || chmod +x "$TAURI_BIN/qrx-$RUST_TARGET" "$TAURI_BIN/qrx-cli-$RUST_TARGET" "$TAURI_BIN/qrxd-$RUST_TARGET" "$TAURI_BIN/qrx-btc-wallet-service-$RUST_TARGET"

echo "[5/7] Building Tauri desktop wallet after its Core dependencies"
(
  cd "$WALLET"
  npm install --no-audit --no-fund
  npx tauri build --target "$RUST_TARGET" --config "$TAURI_CONFIG"
)

BUNDLE_DIR="$TAURI_TARGET_DIR/$RUST_TARGET/release/bundle"
[[ -d "$BUNDLE_DIR" ]] || { echo "Tauri bundle directory missing: $BUNDLE_DIR" >&2; exit 8; }

# Tauri 1.x uses Finder/AppleScript while laying out DMGs. That step is
# fragile on current macOS releases and can fail even after the .app bundle
# was produced successfully. Build the .app with Tauri, then create a plain,
# deterministic DMG ourselves with hdiutil (no Finder automation required).
if [[ "$TARGET" == macos-* ]]; then
  APP_DIR="$BUNDLE_DIR/macos/GUI Wallet.app"
  [[ -d "$APP_DIR" ]] || { echo "macOS app bundle missing: $APP_DIR" >&2; exit 8; }

  # Tauri 1.x can occasionally create the .app shell while omitting the main
  # executable when externalBin sidecars and an explicit Cargo target are used.
  # Cargo has already built qrx-wallet successfully, so install that exact
  # target binary into the bundle deterministically instead of accepting a
  # non-launchable .app.
  # Depending on Tauri/Cargo v1 bundle metadata the compiled main executable
  # may be emitted as either the Cargo bin name (qrx-wallet) or product name
  # (GUI Wallet). Prefer qrx-wallet, then fall back to the verified product
  # binary. Both are copied into the final bundle as qrx-wallet so the plist
  # and launch path stay deterministic.
  BUILT_GUI_EXEC="$TAURI_TARGET_DIR/$RUST_TARGET/release/qrx-wallet"
  if [[ ! -f "$BUILT_GUI_EXEC" ]]; then
    ALT_GUI_EXEC="$TAURI_TARGET_DIR/$RUST_TARGET/release/GUI Wallet"
    if [[ -f "$ALT_GUI_EXEC" ]]; then
      BUILT_GUI_EXEC="$ALT_GUI_EXEC"
    else
      echo "Compiled macOS GUI executable missing. Checked:" >&2
      echo "  $TAURI_TARGET_DIR/$RUST_TARGET/release/qrx-wallet" >&2
      echo "  $TAURI_TARGET_DIR/$RUST_TARGET/release/GUI Wallet" >&2
      exit 8
    fi
  fi
  APP_EXEC="$APP_DIR/Contents/MacOS/qrx-wallet"
  mkdir -p "$APP_DIR/Contents/MacOS"
  cp "$BUILT_GUI_EXEC" "$APP_EXEC"
  chmod +x "$APP_EXEC"

  # Make LaunchServices start the binary we just installed. PlistBuddy can
  # update an existing key or create it if Tauri emitted an unexpected value.
  PLIST="$APP_DIR/Contents/Info.plist"
  [[ -f "$PLIST" ]] || { echo "macOS Info.plist missing: $PLIST" >&2; exit 8; }
  if [[ -x /usr/libexec/PlistBuddy ]]; then
    /usr/libexec/PlistBuddy -c 'Set :CFBundleExecutable qrx-wallet' "$PLIST" 2>/dev/null ||       /usr/libexec/PlistBuddy -c 'Add :CFBundleExecutable string qrx-wallet' "$PLIST"
    BUNDLE_EXEC="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$PLIST" 2>/dev/null || true)"
    [[ "$BUNDLE_EXEC" == "qrx-wallet" ]] || { echo "Could not set CFBundleExecutable to qrx-wallet (got ${BUNDLE_EXEC:-<missing>})" >&2; exit 8; }
  else
    echo "Missing required macOS build tool: /usr/libexec/PlistBuddy" >&2
    exit 8
  fi

  # We modify the bundle after Tauri's bundling pass. Apply an ad-hoc signature
  # so modern macOS accepts the final local/test bundle consistently. A proper
  # Developer ID signature/notarization can replace this for public releases.
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$APP_DIR" >/dev/null 2>&1 || {
      echo "Warning: ad-hoc codesign failed; continuing with unsigned local bundle" >&2
    }
  fi

  [[ -f "$APP_EXEC" && -x "$APP_EXEC" ]] || { echo "macOS GUI executable installation failed: $APP_EXEC" >&2; exit 8; }
  command -v hdiutil >/dev/null 2>&1 || { echo "Missing macOS build dependency: hdiutil" >&2; exit 8; }

  DMG_DIR="$BUNDLE_DIR/dmg"
  DMG_STAGE="$TAURI_TARGET_DIR/dmg-stage-$RUST_TARGET"
  DMG_ARCH="x64"; [[ "$TARGET" == "macos-arm64" ]] && DMG_ARCH="aarch64"
  DMG_PATH="$DMG_DIR/GUI_Wallet_1.0.0_${DMG_ARCH}.dmg"
  rm -rf -- "$DMG_STAGE"
  mkdir -p "$DMG_STAGE" "$DMG_DIR"
  cp -R "$APP_DIR" "$DMG_STAGE/GUI Wallet.app"
  ln -s /Applications "$DMG_STAGE/Applications"
  rm -f -- "$DMG_PATH"
  hdiutil create -volname "QRX Wallet" -srcfolder "$DMG_STAGE" -ov -format UDZO "$DMG_PATH"
  rm -rf -- "$DMG_STAGE"
  [[ -f "$DMG_PATH" ]] || { echo "Custom macOS DMG was not produced: $DMG_PATH" >&2; exit 8; }
  echo "Created Finder-free macOS DMG: $DMG_PATH"
fi

cp -R "$BUNDLE_DIR"/. "$TARGET_OUT/wallet/"

echo "[6/7] Verifying staged release"
for binary in qrx qrx-cli qrxd qrx-btc-wallet-service; do
  [[ -f "$TARGET_OUT/core/$binary$CORE_EXT" ]] || { echo "Release binary missing: $binary" >&2; exit 9; }
done
for tool in qrx-wallet-cli.py qrx-complete-ledger-export.py qrx-arbitrage-engine.py qrx-gateway-kraken.py; do
  [[ -f "$TARGET_OUT/tools/$tool" ]] || { echo "Release tool missing: $tool" >&2; exit 9; }
done
find "$TARGET_OUT/wallet" -type f -print -quit | grep -q . || { echo "No Tauri installer was produced" >&2; exit 9; }

echo "[7/7] Creating checksummed manifest and archive"
python3 "$ROOT/scripts/package-target-release.py" --root "$TARGET_OUT" --target "$TARGET" --output "$DIST_ROOT/qrx-0.0.7-$TARGET.zip"

echo "QRX target release complete: $DIST_ROOT/qrx-0.0.7-$TARGET.zip"
