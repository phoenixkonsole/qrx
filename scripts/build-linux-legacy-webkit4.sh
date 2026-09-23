#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-host}"
case "$TARGET" in
  linux-arm64) ARCH=aarch64 ;;
  linux-x64|host) ARCH=x86_64 ;;
  *) echo "Unsupported legacy WebKit target: $TARGET" >&2; exit 2 ;;
esac
PREFIX="$ROOT/build/deps/$TARGET/webkit4"
SRC_CACHE="$ROOT/build/deps/sources"
WORK="$ROOT/build/deps/work/$TARGET/webkit4"
mkdir -p "$PREFIX" "$SRC_CACHE" "$WORK"

# Tauri 1/wry needs webkit2gtk-4.0 = GTK3 + libsoup2. Modern distributions
# may no longer package that ABI. Build it privately; never install legacy
# libraries into /usr.
if command -v apt-get >/dev/null 2>&1; then
  pkgs=(build-essential cmake ninja-build meson pkg-config curl xz-utils python3 perl ruby unifdef
    libglib2.0-dev libgtk-3-dev libxml2-dev libxslt1-dev libsqlite3-dev
    libjpeg-dev libpng-dev libwebp-dev libicu-dev libharfbuzz-dev libfontconfig1-dev
    libfreetype6-dev libsecret-1-dev libenchant-2-dev libhyphen-dev libgcrypt20-dev
    libpsl-dev libnghttp2-dev libbrotli-dev libgnutls28-dev libgirepository1.0-dev)
  miss=(); for p in "${pkgs[@]}"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || miss+=("$p"); done
  if ((${#miss[@]})); then sudo apt-get update; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${miss[@]}"; fi
fi

fetch_verify() {
  local url="$1" out="$2" sha="$3" got
  if [[ -f "$out" ]]; then got="$(sha256sum "$out" | awk '{print $1}')"; [[ "$got" == "$sha" ]] || rm -f "$out"; fi
  if [[ ! -f "$out" ]]; then curl --fail --location --proto '=https' --tlsv1.2 -o "$out.tmp" "$url"; mv "$out.tmp" "$out"; fi
  got="$(sha256sum "$out" | awk '{print $1}')"; [[ "$got" == "$sha" ]] || { echo "SHA256 mismatch: $out expected=$sha actual=$got" >&2; rm -f "$out"; exit 3; }
}

SOUP_VER=2.74.3
SOUP_SHA=e4b77c41cfc4c8c5a035fcdc320c7bc6cfb75ef7c5a034153df1413fa1d92f13
SOUP_TAR="$SRC_CACHE/libsoup-$SOUP_VER.tar.xz"
fetch_verify "https://download.gnome.org/sources/libsoup/2.74/libsoup-$SOUP_VER.tar.xz" "$SOUP_TAR" "$SOUP_SHA"
if ! PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig:${PKG_CONFIG_PATH:-}" pkg-config --exists 'libsoup-2.4 >= 2.62'; then
  rm -rf "$WORK/libsoup" "$WORK/libsoup-build"; mkdir -p "$WORK/libsoup"; tar -xf "$SOUP_TAR" --strip-components=1 -C "$WORK/libsoup"
  meson setup "$WORK/libsoup-build" "$WORK/libsoup" --prefix="$PREFIX" --libdir=lib -Dtests=false -Dgtk_doc=false -Dvapi=disabled -Dintrospection=disabled
  ninja -C "$WORK/libsoup-build" -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" install
fi

WEBKIT_VER=2.44.4
WEBKIT_SHA=2ce4ec1b78413035037aba8326b31ed72696626b7bea7bace5e46ac0d8cbe796
WEBKIT_TAR="$SRC_CACHE/webkitgtk-$WEBKIT_VER.tar.xz"
fetch_verify "https://webkitgtk.org/releases/webkitgtk-$WEBKIT_VER.tar.xz" "$WEBKIT_TAR" "$WEBKIT_SHA"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
export CMAKE_PREFIX_PATH="$PREFIX:${CMAKE_PREFIX_PATH:-}"
if ! pkg-config --exists 'webkit2gtk-4.0 >= 2.22' || ! pkg-config --exists 'javascriptcoregtk-4.0 >= 2.24'; then
  rm -rf "$WORK/webkit" "$WORK/webkit-build"; mkdir -p "$WORK/webkit"; tar -xf "$WEBKIT_TAR" --strip-components=1 -C "$WORK/webkit"
  cmake -S "$WORK/webkit" -B "$WORK/webkit-build" -G Ninja \
    -DPORT=GTK -DUSE_GTK3=ON -DUSE_GTK4=OFF -DUSE_SOUP2=ON \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
    -DENABLE_DOCUMENTATION=OFF -DENABLE_MINIBROWSER=OFF -DENABLE_API_TESTS=OFF \
    -DENABLE_BUBBLEWRAP_SANDBOX=OFF -DENABLE_GAMEPAD=OFF -DENABLE_SPELLCHECK=OFF \
    -DENABLE_VIDEO=OFF -DENABLE_WEB_AUDIO=OFF
  ninja -C "$WORK/webkit-build" -j"${QRX_WEBKIT_JOBS:-2}" install
fi
pkg-config --exists 'libsoup-2.4 >= 2.62'
pkg-config --exists 'javascriptcoregtk-4.0 >= 2.24'
pkg-config --exists 'webkit2gtk-4.0 >= 2.22'
printf '%s\n' "$PREFIX"
