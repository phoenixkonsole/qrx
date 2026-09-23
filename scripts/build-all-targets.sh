#!/usr/bin/env bash
set -euo pipefail

# QRX unified release builder.
# One target is built per native host. The GitHub Actions matrix invokes this
# same script on five native runners concurrently.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$ROOT/qrx-core"
WALLET="$ROOT/GUIWALLET"
BROWSER="$ROOT/QRXBROWSER"
DIST_ROOT="${QRX_DIST_DIR:-$ROOT/dist}"
BUILD_ROOT="${QRX_BUILD_DIR:-$ROOT/build}"
JOBS="${JOBS:-}"
TARGET=""
PLAN_ONLY=0
ALL_TARGETS=0
NODE_ONLY=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build-all-targets.sh [--target host|TARGET] [--node-only] [--plan]
  ./scripts/build-all-targets.sh --all [--plan]
  ./scripts/build-all-targets.sh --list-targets

Modes:
  --node-only    Build/package headless Core node components only (qrx, qrxd, qrx-cli, QRXDB tools).
                 Skips GUI/Tauri, Browser, BTC GUI service, AURA/AI bundle and desktop installers.

Targets:
  host          Auto-detect the current operating system and CPU architecture
  linux-x64     Linux x86-64: Core, CLI, tools, BTC service, DEB, AppImage
  linux-arm64   Linux ARM64: Core, CLI, tools, BTC service, DEB, AppImage
  macos-x64     macOS Intel: Core, CLI, tools, BTC service, APP, DMG
  macos-arm64   macOS Apple Silicon: Core, CLI, tools, BTC service, APP, DMG
  macos-both    macOS: build both Apple Silicon and Intel (Intel cross-build supported on Apple Silicon)
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
    --node-only) NODE_ONLY=1; shift ;;
    --list-targets) printf '%s\n' host linux-x64 linux-arm64 macos-x64 macos-arm64 macos-both windows-x64; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$NODE_ONLY" -eq 1 && "$ALL_TARGETS" -eq 1 ]]; then
  echo "--node-only cannot be combined with --all; select a concrete/native host target." >&2
  exit 2
fi

if [[ "$ALL_TARGETS" -eq 1 ]]; then
  [[ -z "$TARGET" ]] || { echo "Use either --all or --target, not both" >&2; exit 2; }
  if [[ "$PLAN_ONLY" -eq 1 ]]; then
    for matrix_target in linux-x64 linux-arm64 macos-x64 macos-arm64 windows-x64; do
      bash "$0" --target "$matrix_target" --plan
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

# On an Apple Silicon Mac, build both native arm64 and cross-compiled Intel x64
# releases in one command. Each child build keeps its own Core/Tauri/dependency
# directories and therefore cannot accidentally package the other architecture.
if [[ "$TARGET" == "macos-both" ]]; then
  [[ "$(uname -s)" == "Darwin" ]] || { echo "macos-both requires macOS" >&2; exit 3; }
  if [[ "$PLAN_ONLY" -eq 1 ]]; then
    if [[ "$NODE_ONLY" -eq 1 ]]; then
      bash "$0" --target macos-arm64 --node-only --plan
      bash "$0" --target macos-x64 --node-only --plan
    else
      bash "$0" --target macos-arm64 --plan
      bash "$0" --target macos-x64 --plan
    fi
  else
    if [[ "$NODE_ONLY" -eq 1 ]]; then
      bash "$0" --target macos-arm64 --node-only
      bash "$0" --target macos-x64 --node-only
    else
      bash "$0" --target macos-arm64
      bash "$0" --target macos-x64
    fi
    echo "Both macOS QRX releases completed:"
    echo "  $DIST_ROOT/macos-arm64"
    echo "  $DIST_ROOT/macos-x64"
  fi
  exit 0
fi

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

if [[ "$NODE_ONLY" -eq 1 ]]; then
  cat <<EOF
QRX headless node release plan: $TARGET
  1. Build static QRX Core library
  2. Build qrx, qrx-cli, qrxd and QRXDB tools
  3. Stage headless node binaries/tools only
  4. Verify and package checksummed node release
EOF
else
  cat <<EOF
QRX release plan: $TARGET
  1. Build static QRX Core library
  2. Build qrx, qrx-cli, qrxd and QRXDB tools
  3. Stage Python wallet/export/arbitrage/Kraken tools
  4. Build qrx-btc-wallet-service for $RUST_TARGET
  5. Build isolated Tauri 2 QRX Browser multi-WebView sidecar
  6. Install target-suffixed Core/BTC/Browser sidecars
  7. Stage signed AURA runtime trust/catalog resources
  8. Stage verified local AI runtime/model bundle when supported; Linux can fall back to AI-pending GUI
  9. Build Tauri wallet and verify/package the checksummed release
EOF
fi
[[ "$PLAN_ONLY" -eq 1 ]] && exit 0

if [[ "$NODE_ONLY" -eq 0 ]]; then
  echo "[0/8] Auditing GUI <-> Core/CLI compatibility"
  python3 "$ROOT/scripts/audit-gui-core-compat.py"
  python3 "$ROOT/scripts/audit-gui-interactions.py"
  python3 "$ROOT/scripts/audit-gui-polish.py"
  python3 "$ROOT/scripts/audit-tauri2-browser.py"
else
  echo "[0/4] Headless node profile: GUI/AURA/AI audits intentionally skipped"
fi

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

# QRX 0.0.9.85: Linux Rust/Cargo bootstrap.
# A fresh seed-node host should not stop merely because Rust has not been
# installed yet. On Linux, install the official rustup toolchain non-
# interactively with rustup's default profile/toolchain (-y), then load the
# per-user Cargo environment into this build process. No system-wide Rust
# package or persistent shell modification beyond rustup's normal defaults is
# required.
if [[ "$NODE_ONLY" -eq 0 && "$TARGET" == linux-* ]] && ! command -v cargo >/dev/null 2>&1; then
  echo "Cargo not found; installing the default Rust toolchain via rustup..."
  if ! command -v curl >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || { echo "Cannot auto-install Rust: curl is missing and apt-get is unavailable." >&2; exit 4; }
    command -v sudo >/dev/null 2>&1 || { echo "Cannot auto-install curl: sudo is unavailable." >&2; exit 4; }
    sudo apt-get update
    sudo apt-get install -y curl ca-certificates
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  [[ -f "$HOME/.cargo/env" ]] || { echo "rustup completed but $HOME/.cargo/env was not created." >&2; exit 4; }
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  command -v cargo >/dev/null 2>&1 || { echo "Rust bootstrap completed but cargo is still unavailable." >&2; exit 4; }
  echo "Rust/Cargo installed: $(cargo --version)"
elif [[ "$NODE_ONLY" -eq 0 && "$TARGET" == linux-* && -f "$HOME/.cargo/env" ]]; then
  # Ensure rustup-managed cargo/rustc are visible even in non-login shells.
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

# QRX 0.0.9.97: Linux CMake/Python binding bootstrap hardening.
# Some clean Ubuntu 22/26 hosts (and source-built transitive components) need
# pybind11's CMake package metadata even when Python itself is already present.
# Prefer distro packages so builds do not depend on an ad-hoc GitHub clone.
# Verify both Python import and CMake metadata before continuing.
if [[ "$NODE_ONLY" -eq 0 && "$TARGET" == linux-* ]] && command -v apt-get >/dev/null 2>&1; then
  pybind_need=0
  python3 -c 'import pybind11' >/dev/null 2>&1 || pybind_need=1
  if command -v cmake >/dev/null 2>&1; then
    pybind_cmake_dir="$(python3 -m pybind11 --cmakedir 2>/dev/null || true)"
    [[ -n "$pybind_cmake_dir" && -f "$pybind_cmake_dir/pybind11Config.cmake" ]] || pybind_need=1
  else
    pybind_need=1
  fi
  if [[ "$pybind_need" -eq 1 ]]; then
    command -v sudo >/dev/null 2>&1 || { echo "pybind11 bootstrap required but sudo is unavailable." >&2; exit 4; }
    echo "pybind11 Python/CMake metadata incomplete; installing Ubuntu/Debian build packages..."
    sudo apt-get update
    sudo apt-get install -y python3-dev python3-pybind11 pybind11-dev
  fi
  python3 -c 'import pybind11; print("pybind11 Python module:", pybind11.__version__)' || { echo "pybind11 Python module remains unavailable after bootstrap." >&2; exit 4; }
  pybind_cmake_dir="$(python3 -m pybind11 --cmakedir 2>/dev/null || true)"
  if [[ -z "$pybind_cmake_dir" || ! -f "$pybind_cmake_dir/pybind11Config.cmake" ]]; then
    # Debian may install CMake metadata outside the Python wheel's cmakedir.
    pybind_cmake_dir="$(dpkg -L pybind11-dev 2>/dev/null | sed -n 's#/pybind11Config.cmake$##p' | head -n1)"
  fi
  [[ -n "$pybind_cmake_dir" && -f "$pybind_cmake_dir/pybind11Config.cmake" ]] || { echo "pybind11 CMake package metadata is unavailable after bootstrap." >&2; exit 4; }
  export pybind11_DIR="$pybind_cmake_dir"
  echo "pybind11 CMake package: $pybind11_DIR"
fi

# QRX 0.0.9.90: Linux native desktop/Tauri ABI-aware dependency bootstrap.
# Minimal Ubuntu/Debian installations do not ship the GTK/WebKit development
# metadata required by Tauri/wry/gtk-rs. Detect it before Cargo starts so a
# desktop build does not fail late in gdk-sys/atk-sys/cairo-sys/webkit2gtk-sys.
# --node-only deliberately bypasses this entire desktop dependency set.
if [[ "$NODE_ONLY" -eq 0 && "$TARGET" == linux-* ]] && command -v apt-get >/dev/null 2>&1; then
  linux_apt_missing=()
  command -v pkg-config >/dev/null 2>&1 || linux_apt_missing+=(pkg-config)
  command -v patchelf >/dev/null 2>&1 || linux_apt_missing+=(patchelf)

  # One Debian/Ubuntu dev package may satisfy several pkg-config modules; keep
  # package additions unique so apt output remains deterministic.
  add_linux_pkg() {
    local pkg="$1" seen
    for seen in "${linux_apt_missing[@]:-}"; do [[ "$seen" == "$pkg" ]] && return 0; done
    linux_apt_missing+=("$pkg")
  }
  if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --exists 'dbus-1 >= 1.6' >/dev/null 2>&1 || add_linux_pkg libdbus-1-dev
    pkg-config --exists 'gdk-3.0 >= 3.22' >/dev/null 2>&1 || add_linux_pkg libgtk-3-dev
    pkg-config --exists 'atk >= 2.28' >/dev/null 2>&1 || add_linux_pkg libgtk-3-dev
    pkg-config --exists 'cairo >= 1.14' >/dev/null 2>&1 || add_linux_pkg libgtk-3-dev
    # QRX Browser is Tauri 2 (WebKitGTK 4.1/libsoup3), while the current
    # GUI Wallet is Tauri 1.6 (WebKitGTK 4.0/libsoup2). Keep both ABI
    # requirements explicit until the wallet itself is migrated to Tauri 2.
    pkg-config --exists 'webkit2gtk-4.1' >/dev/null 2>&1 || add_linux_pkg libwebkit2gtk-4.1-dev
    pkg-config --exists 'libsoup-2.4 >= 2.62' >/dev/null 2>&1 || add_linux_pkg libsoup2.4-dev
    if ! pkg-config --exists 'javascriptcoregtk-4.0 >= 2.24' >/dev/null 2>&1 || ! pkg-config --exists 'webkit2gtk-4.0 >= 2.22' >/dev/null 2>&1; then
      if apt-cache show libwebkit2gtk-4.0-dev >/dev/null 2>&1; then
        add_linux_pkg libwebkit2gtk-4.0-dev
      fi
    fi
    pkg-config --exists 'librsvg-2.0' >/dev/null 2>&1 || add_linux_pkg librsvg2-dev
    pkg-config --exists 'ayatana-appindicator3-0.1' >/dev/null 2>&1 || add_linux_pkg libayatana-appindicator3-dev
  else
    add_linux_pkg libdbus-1-dev
    add_linux_pkg libgtk-3-dev
    add_linux_pkg libwebkit2gtk-4.1-dev
    add_linux_pkg libsoup2.4-dev
    if apt-cache show libwebkit2gtk-4.0-dev >/dev/null 2>&1; then add_linux_pkg libwebkit2gtk-4.0-dev; fi
    add_linux_pkg librsvg2-dev
    add_linux_pkg libayatana-appindicator3-dev
  fi
  if (( ${#linux_apt_missing[@]} > 0 )); then
    command -v sudo >/dev/null 2>&1 || { echo "Missing Linux desktop build packages: ${linux_apt_missing[*]}; sudo is unavailable." >&2; exit 4; }
    echo "Installing Linux desktop build dependencies: ${linux_apt_missing[*]}"
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${linux_apt_missing[@]}"
  fi
  command -v pkg-config >/dev/null 2>&1 || { echo "pkg-config is still unavailable after dependency bootstrap." >&2; exit 4; }
  for qrx_pc in 'dbus-1 >= 1.6' 'gdk-3.0 >= 3.22' 'atk >= 2.28' 'cairo >= 1.14' 'webkit2gtk-4.1' 'librsvg-2.0'; do
    pkg-config --exists "$qrx_pc" || { echo "Linux desktop development metadata is still unavailable: $qrx_pc" >&2; exit 4; }
  done
  # Tauri 1 wallet ABI. On newer Ubuntu releases the 4.0/libsoup2 ABI is no
  # longer packaged. Keep the current wallet buildable without downgrading the
  # host: build a private, pinned WebKitGTK 4.0 stack from verified sources.
  legacy_missing=0
  for qrx_pc in 'libsoup-2.4 >= 2.62' 'javascriptcoregtk-4.0 >= 2.24' 'webkit2gtk-4.0 >= 2.22'; do
    pkg-config --exists "$qrx_pc" || legacy_missing=1
  done
  if [[ "$legacy_missing" -eq 1 ]]; then
    echo "Legacy WebKitGTK 4.0 ABI unavailable from system packages; building isolated source fallback."
    LEGACY_WEBKIT_PREFIX="$(bash "$ROOT/scripts/build-linux-legacy-webkit4.sh" "$TARGET" | tail -n 1)"
    export PKG_CONFIG_PATH="$LEGACY_WEBKIT_PREFIX/lib/pkgconfig:$LEGACY_WEBKIT_PREFIX/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
    export LD_LIBRARY_PATH="$LEGACY_WEBKIT_PREFIX/lib:$LEGACY_WEBKIT_PREFIX/lib64:${LD_LIBRARY_PATH:-}"
    export CMAKE_PREFIX_PATH="$LEGACY_WEBKIT_PREFIX:${CMAKE_PREFIX_PATH:-}"
  fi
  for qrx_pc in 'libsoup-2.4 >= 2.62' 'javascriptcoregtk-4.0 >= 2.24' 'webkit2gtk-4.0 >= 2.22'; do
    pkg-config --exists "$qrx_pc" || { echo "Legacy WebKitGTK source fallback did not provide: $qrx_pc" >&2; exit 4; }
  done
fi

# QRX 0.0.9.96: Linux Node/Tauri compatibility preflight.
# Tauri CLI 1.6 uses modern JavaScript syntax (including optional chaining), so
# merely finding a `node` executable is insufficient on older Ubuntu installs.
# Require Node >=18 before npm/Tauri is touched. On Debian/Ubuntu desktop build
# hosts, upgrade an obsolete/missing Node through NodeSource's Node 20 LTS
# repository, then re-check the runtime in this same build process.
qrx_node_major() {
  local v
  v="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || true)"
  [[ "$v" =~ ^[0-9]+$ ]] && printf '%s\n' "$v" || printf '0\n'
}
if [[ "$NODE_ONLY" -eq 0 && "$TARGET" == linux-* ]]; then
  node_major="$(qrx_node_major)"
  if (( node_major < 18 )); then
    echo "Node.js >=18 required for the Tauri desktop wallet; detected: $(node --version 2>/dev/null || echo missing)"
    if command -v apt-get >/dev/null 2>&1; then
      command -v sudo >/dev/null 2>&1 || { echo "Cannot bootstrap Node.js 20 LTS: sudo is unavailable." >&2; exit 4; }
      command -v curl >/dev/null 2>&1 || { sudo apt-get update && sudo apt-get install -y curl ca-certificates; }
      echo "Installing Node.js 20 LTS build runtime for QRX desktop..."
      curl -fsSL https://deb.nodesource.com/setup_20.x -o /tmp/qrx-nodesource-setup.sh
      sudo -E bash /tmp/qrx-nodesource-setup.sh
      rm -f /tmp/qrx-nodesource-setup.sh
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
      hash -r
      node_major="$(qrx_node_major)"
    fi
  fi
  (( node_major >= 18 )) || { echo "Node.js >=18 is still unavailable; refusing a late Tauri syntax failure." >&2; exit 4; }
  echo "Node/Tauri preflight: $(node --version), npm $(npm --version 2>/dev/null || echo missing)"
fi

required_commands=(cmake python3)
if [[ "$NODE_ONLY" -eq 0 ]]; then
  required_commands+=(cargo rustc rustup node npm)
fi
for command_name in "${required_commands[@]}"; do
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

echo "[1/8] Building Core and native command-line tools"
case "$TARGET" in
  linux-x64|linux-arm64)
    QRX_NATIVE_DEPS_PREFIX="${QRX_NATIVE_DEPS_PREFIX:-$BUILD_ROOT/deps/$TARGET}"
    QRX_NATIVE_DEPS_PREFIX="$QRX_NATIVE_DEPS_PREFIX" BUILD_DIR="$CORE_BUILD" JOBS="$JOBS" bash "$CORE/scripts/build-linux-static.sh"
    ;;
  macos-x64|macos-arm64)
    arch="x86_64"; [[ "$TARGET" == "macos-arm64" ]] && arch="arm64"
    QRX_NATIVE_DEPS_PREFIX="${QRX_NATIVE_DEPS_PREFIX:-$BUILD_ROOT/deps/macos-$arch}"
    QRX_NATIVE_DEPS_PREFIX="$QRX_NATIVE_DEPS_PREFIX" BUILD_DIR="$CORE_BUILD" JOBS="$JOBS" bash "$CORE/scripts/build-macos-static.sh" "$arch"

    # Rust openssl-sys does not infer a cross-architecture OpenSSL installation
    # from pkg-config on Apple Silicon. Reuse QRX's already verified hermetic
    # OpenSSL prefix and expose it with Cargo's target-specific variables.
    [[ -f "$QRX_NATIVE_DEPS_PREFIX/lib/libcrypto.a" ]] || { echo "Missing target OpenSSL libcrypto: $QRX_NATIVE_DEPS_PREFIX" >&2; exit 6; }
    [[ -f "$QRX_NATIVE_DEPS_PREFIX/lib/libssl.a" ]] || { echo "Missing target OpenSSL libssl: $QRX_NATIVE_DEPS_PREFIX" >&2; exit 6; }
    [[ -f "$QRX_NATIVE_DEPS_PREFIX/include/openssl/ssl.h" ]] || { echo "Missing target OpenSSL headers: $QRX_NATIVE_DEPS_PREFIX" >&2; exit 6; }
    export OPENSSL_STATIC=1
    if [[ "$TARGET" == "macos-x64" ]]; then
      export X86_64_APPLE_DARWIN_OPENSSL_DIR="$QRX_NATIVE_DEPS_PREFIX"
      export X86_64_APPLE_DARWIN_OPENSSL_LIB_DIR="$QRX_NATIVE_DEPS_PREFIX/lib"
      export X86_64_APPLE_DARWIN_OPENSSL_INCLUDE_DIR="$QRX_NATIVE_DEPS_PREFIX/include"
    else
      export AARCH64_APPLE_DARWIN_OPENSSL_DIR="$QRX_NATIVE_DEPS_PREFIX"
      export AARCH64_APPLE_DARWIN_OPENSSL_LIB_DIR="$QRX_NATIVE_DEPS_PREFIX/lib"
      export AARCH64_APPLE_DARWIN_OPENSSL_INCLUDE_DIR="$QRX_NATIVE_DEPS_PREFIX/include"
    fi
    ;;
  windows-x64)
    QRX_NATIVE_DEPS_PREFIX="${QRX_NATIVE_DEPS_PREFIX:-$BUILD_ROOT/deps/windows-x64}"
    pwsh -NoProfile -File "$CORE/scripts/build-windows-x64-static.ps1" -BuildDir "$CORE_BUILD" -DepsPrefix "$QRX_NATIVE_DEPS_PREFIX" -Jobs "$JOBS"
    ;;
esac

CORE_BIN_DIR="$CORE_BUILD"
[[ -n "$CORE_SUBDIR" ]] && CORE_BIN_DIR="$CORE_BUILD/$CORE_SUBDIR"
for binary in qrx qrx-cli qrxd qrx-upscaler qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
  [[ -f "$CORE_BIN_DIR/$binary$CORE_EXT" ]] || { echo "Core output missing: $CORE_BIN_DIR/$binary$CORE_EXT" >&2; exit 6; }
done
if [[ "$TARGET" == macos-* ]]; then
  command -v lipo >/dev/null 2>&1 || { echo "lipo is required to verify macOS release architecture" >&2; exit 4; }
  expected_arch="x86_64"; [[ "$TARGET" == "macos-arm64" ]] && expected_arch="arm64"
  for binary in qrx qrx-cli qrxd qrx-upscaler qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
    binary_path="$CORE_BIN_DIR/$binary"
    # lipo -verify_arch can report failure for a valid thin Mach-O on some
    # macOS/Xcode combinations (while -info correctly reports the arch).
    # -archs works for both thin and universal Mach-O files, so inspect the
    # actual architecture list instead of treating thin files as invalid.
    binary_archs="$(lipo -archs "$binary_path" 2>/dev/null || true)"
    arch_ok=0
    for found_arch in $binary_archs; do
      [[ "$found_arch" == "$expected_arch" ]] && arch_ok=1
    done
    if [[ "$arch_ok" -ne 1 ]]; then
      echo "Architecture mismatch: $binary does not contain $expected_arch (found: ${binary_archs:-unknown})" >&2
      lipo -info "$binary_path" >&2 || true
      exit 6
    fi
    echo "Architecture OK: $binary -> $binary_archs"
  done
fi

if [[ "$NODE_ONLY" -eq 1 ]]; then
  echo "[2/4] Staging headless node binaries"
  mkdir -p "$TARGET_OUT/core" "$TARGET_OUT/tools"
  for binary in qrx qrx-cli qrxd qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
    cp "$CORE_BIN_DIR/$binary$CORE_EXT" "$TARGET_OUT/core/$binary$CORE_EXT"
  done
  cp "$CORE/tools/qrx-wallet-cli.py" "$TARGET_OUT/tools/"
  echo "[3/4] Verifying headless node release"
  for binary in qrx qrx-cli qrxd qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
    [[ -f "$TARGET_OUT/core/$binary$CORE_EXT" ]] || { echo "Node release binary missing: $binary" >&2; exit 9; }
  done
  [[ -f "$TARGET_OUT/tools/qrx-wallet-cli.py" ]] || { echo "Node CLI helper missing" >&2; exit 9; }
  echo "[4/4] Creating checksummed headless node archive"
  NODE_ARCHIVE="$DIST_ROOT/qrx-0.0.9-genesis-$TARGET-node-only.zip"
  python3 "$ROOT/scripts/package-target-release.py" --root "$TARGET_OUT" --target "$TARGET-node-only" --output "$NODE_ARCHIVE"
  echo "QRX headless node release complete: $NODE_ARCHIVE"
  exit 0
fi

echo "[2/8] Staging complete CLI and Python tool set"
mkdir -p "$TARGET_OUT/core" "$TARGET_OUT/tools" "$TARGET_OUT/wallet"
for binary in qrx qrx-cli qrxd qrx-upscaler qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot; do
  cp "$CORE_BIN_DIR/$binary$CORE_EXT" "$TARGET_OUT/core/$binary$CORE_EXT"
done
cp "$CORE/tools/qrx-wallet-cli.py" "$TARGET_OUT/tools/"
cp "$CORE/tools/qrx-complete-ledger-export.py" "$TARGET_OUT/tools/"
cp "$CORE/gateways/qrx-arbitrage-engine.py" "$TARGET_OUT/tools/"
cp "$CORE/gateways/qrx-gateway-kraken.py" "$TARGET_OUT/tools/"

echo "[3/8] Building shared Rust BTC wallet service"
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

echo "[4/9] Building isolated Tauri 2 QRX Browser multi-WebView sidecar"
BROWSER_MANIFEST="$BROWSER/src-tauri/Cargo.toml"
[[ -f "$BROWSER_MANIFEST" ]] || { echo "QRX Browser manifest missing: $BROWSER_MANIFEST" >&2; exit 7; }
BROWSER_TARGET_DIR="$BUILD_ROOT/browser-cargo"
mkdir -p "$BROWSER_TARGET_DIR"
if [[ ! -f "$BROWSER/src-tauri/Cargo.lock" ]]; then
  echo "Generating QRX Browser Cargo.lock for this source checkout"
  CARGO_TARGET_DIR="$BROWSER_TARGET_DIR" cargo generate-lockfile --manifest-path "$BROWSER_MANIFEST"
fi
CARGO_TARGET_DIR="$BROWSER_TARGET_DIR" cargo build --locked --manifest-path "$BROWSER_MANIFEST" --release --target "$RUST_TARGET"
QRX_BROWSER_BIN="$BROWSER_TARGET_DIR/$RUST_TARGET/release/qrx-browser$CORE_EXT"
[[ -f "$QRX_BROWSER_BIN" ]] || { echo "QRX Browser binary missing: $QRX_BROWSER_BIN" >&2; exit 7; }
cp "$QRX_BROWSER_BIN" "$TARGET_OUT/core/qrx-browser$CORE_EXT"

echo "[4/8] Installing exact target-suffixed Tauri sidecars"
TAURI_BIN="$WALLET/src-tauri/bin"
mkdir -p "$TAURI_BIN"
cp "$CORE_BIN_DIR/qrx$CORE_EXT" "$TAURI_BIN/qrx-$RUST_TARGET$CORE_EXT"
cp "$CORE_BIN_DIR/qrx-cli$CORE_EXT" "$TAURI_BIN/qrx-cli-$RUST_TARGET$CORE_EXT"
cp "$CORE_BIN_DIR/qrxd$CORE_EXT" "$TAURI_BIN/qrxd-$RUST_TARGET$CORE_EXT"
cp "$CORE_BIN_DIR/qrx-upscaler$CORE_EXT" "$TAURI_BIN/qrx-upscaler-$RUST_TARGET$CORE_EXT"
cp "$BTC_SERVICE" "$TAURI_BIN/qrx-btc-wallet-service-$RUST_TARGET$CORE_EXT"
cp "$QRX_BROWSER_BIN" "$TAURI_BIN/qrx-browser-$RUST_TARGET$CORE_EXT"
[[ "$TARGET" == "windows-x64" ]] || chmod +x "$TAURI_BIN/qrx-$RUST_TARGET" "$TAURI_BIN/qrx-cli-$RUST_TARGET" "$TAURI_BIN/qrxd-$RUST_TARGET" "$TAURI_BIN/qrx-upscaler-$RUST_TARGET" "$TAURI_BIN/qrx-btc-wallet-service-$RUST_TARGET" "$TAURI_BIN/qrx-browser-$RUST_TARGET"

echo "[5/8] Staging signed AURA runtime catalog + pinned publisher key"
AURA_RES="$WALLET/src-tauri/resources/aura"
mkdir -p "$AURA_RES"
CAT_SRC="${QRX_AURA_RUNTIME_CATALOG:-}"
KEY_SRC="${QRX_AURA_RUNTIME_PUBLISHER_KEY:-}"
if [[ -n "$CAT_SRC" && -n "$KEY_SRC" && -f "$CAT_SRC" && -f "$KEY_SRC" ]]; then
  cp "$CAT_SRC" "$AURA_RES/official-runtime-catalog.qrx"
  cp "$KEY_SRC" "$AURA_RES/official-runtime-publisher.pem"
  openssl pkey -pubin -in "$AURA_RES/official-runtime-publisher.pem" -noout >/dev/null 2>&1 || { echo "Invalid AURA runtime publisher public key" >&2; exit 8; }
  grep -qx 'QRXRUNTIME1' <(head -n 1 "$AURA_RES/official-runtime-catalog.qrx") || { echo "Invalid AURA runtime catalog header" >&2; exit 8; }
else
  rm -f "$AURA_RES/official-runtime-catalog.qrx" "$AURA_RES/official-runtime-publisher.pem"
  if [[ "${QRX_REQUIRE_AURA_RUNTIME_RESOURCES:-0}" == "1" ]]; then
    echo "Release build requires QRX_AURA_RUNTIME_CATALOG and QRX_AURA_RUNTIME_PUBLISHER_KEY" >&2
    exit 8
  fi
  echo "Warning: AURA signed runtime resources not staged (development build; AUTO runtime remains pending)" >&2
fi

echo "[5.5/9] Staging mandatory verified local AI Upscaler bundle for $TARGET"
AI_DEST="$WALLET/src-tauri/resources/upscaler"
# QRX 0.0.9.94: GUI release contents no longer depend on the build host having
# a usable Vulkan/Metal device. The target runtime + reviewed models are always
# prepared and verified. Hardware capability is evaluated only on the client.
rm -rf "$AI_DEST"
bash "$ROOT/scripts/prepare-upscaler-ai-bundle.sh" "$TARGET" "$AI_DEST"
bash "$ROOT/scripts/verify-upscaler-ai-bundle.sh" "$AI_DEST" "$TARGET"
[[ ! -e "$AI_DEST/AI_UNAVAILABLE.txt" ]] || { echo "AI_UNAVAILABLE marker is forbidden in GUI release builds" >&2; exit 8; }

echo "[6/9] Building Tauri desktop wallet after its Core dependencies"
(
  cd "$WALLET"
  # Genesis hardening (Finding 10): reproducible dependency installation.
  # "npm install" can silently resolve to newer transitive versions than the
  # ones a release was tested and audited against. With a committed lock file
  # "npm ci" installs exactly the locked tree and fails instead of drifting.
  if [[ -f package-lock.json || -f npm-shrinkwrap.json ]]; then
    npm ci --no-audit --no-fund
  else
    echo "Warning: no package-lock.json/npm-shrinkwrap.json in $WALLET." >&2
    echo "         Using exact top-level dependency pins; transitive npm resolution is not fully reproducible without a lock file." >&2
    npm install --no-audit --no-fund
  fi
  if [[ "$TARGET" == linux-* ]]; then
    npx tauri build --target "$RUST_TARGET" --config "$TAURI_CONFIG" --bundles deb
    echo "[6.1/9] Attempting optional Linux AppImage bundle"
    if ! npx tauri build --target "$RUST_TARGET" --config "$TAURI_CONFIG" --bundles appimage; then
      echo "Warning: AppImage bundling failed; keeping the successfully built Linux wallet and DEB." >&2
    fi
  else
    npx tauri build --target "$RUST_TARGET" --config "$TAURI_CONFIG"
  fi
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

  echo "[6.5/9] Verifying packaged AI resources inside macOS .app"
  APP_RES="$APP_DIR/Contents/Resources"
  PACKAGED_AI=""
  for cand in "$APP_RES/upscaler" "$APP_RES/resources/upscaler"; do
    if [[ -d "$cand" ]]; then PACKAGED_AI="$cand"; break; fi
  done
  if [[ -z "$PACKAGED_AI" ]]; then
    echo "AI resources missing from final .app bundle" >&2; exit 8
  else
    bash "$ROOT/scripts/verify-upscaler-ai-bundle.sh" "$PACKAGED_AI" "$TARGET"

    # 0.0.9.66: prove Tauri embedded the exact staged AI payload, not merely
    # a structurally valid bundle. Compare a canonical SHA-256 inventory.
    staged_inventory="$(mktemp)"
    packaged_inventory="$(mktemp)"
    (cd "$WALLET/src-tauri/resources/upscaler" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) > "$staged_inventory"
    (cd "$PACKAGED_AI" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) > "$packaged_inventory"
    if ! cmp -s "$staged_inventory" "$packaged_inventory"; then
      echo "Packaged AI resources differ from verified staged resources" >&2
      diff -u "$staged_inventory" "$packaged_inventory" >&2 || true
      rm -f "$staged_inventory" "$packaged_inventory"
      exit 8
    fi
    rm -f "$staged_inventory" "$packaged_inventory"
    echo "AI bundle inside GUI Wallet.app: PASS (staged/package hashes identical)"
  fi

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

# Verify the native installer set before packaging. A successful Cargo/Tauri
# compile is not enough for a release target.
case "$TARGET" in
  macos-*)
    find "$BUNDLE_DIR/dmg" -maxdepth 1 -type f -name '*.dmg' -print -quit | grep -q . || { echo "macOS DMG missing after bundle step" >&2; exit 8; }
    ;;
  linux-*)
    find "$BUNDLE_DIR" -type f -name '*.deb' -print -quit | grep -q . || { echo "Linux DEB missing after Tauri bundle" >&2; exit 8; }
    if ! find "$BUNDLE_DIR" -type f -name '*.AppImage' -print -quit | grep -q .; then
      echo "Warning: Linux AppImage missing; DEB is the authoritative Linux desktop artifact for this build." >&2
    fi
    ;;
  windows-x64)
    find "$BUNDLE_DIR" -type f -name '*.msi' -print -quit | grep -q . || { echo "Windows MSI missing after Tauri bundle" >&2; exit 8; }
    find "$BUNDLE_DIR" -type f -name '*.exe' -print -quit | grep -Eiq 'setup|installer|nsis' || { echo "Windows NSIS installer EXE missing after Tauri bundle" >&2; exit 8; }
    ;;
esac

cp -R "$BUNDLE_DIR"/. "$TARGET_OUT/wallet/"

echo "[7/8] Verifying staged release"
for binary in qrx qrx-cli qrxd qrx-upscaler qrx-btc-wallet-service qrx-browser; do
  [[ -f "$TARGET_OUT/core/$binary$CORE_EXT" ]] || { echo "Release binary missing: $binary" >&2; exit 9; }
done
for tool in qrx-wallet-cli.py qrx-complete-ledger-export.py qrx-arbitrage-engine.py qrx-gateway-kraken.py; do
  [[ -f "$TARGET_OUT/tools/$tool" ]] || { echo "Release tool missing: $tool" >&2; exit 9; }
done
find "$TARGET_OUT/wallet" -type f -print -quit | grep -q . || { echo "No Tauri installer was produced" >&2; exit 9; }

echo "[8/8] Creating checksummed manifest and archive"
python3 "$ROOT/scripts/package-target-release.py" --root "$TARGET_OUT" --target "$TARGET" --output "$DIST_ROOT/qrx-0.0.9-genesis-$TARGET.zip"

echo "QRX target release complete: $DIST_ROOT/qrx-0.0.9-genesis-$TARGET.zip"
