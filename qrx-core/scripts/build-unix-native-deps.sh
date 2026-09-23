#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OS="${1:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
ARCH="${2:-$(uname -m)}"
JOBS="${JOBS:-}"
case "$OS" in darwin|macos) OS=macos ;; linux) ;; *) echo "Unsupported OS: $OS" >&2; exit 2;; esac
case "$ARCH" in arm64|aarch64) ARCH=arm64 ;; x86_64|amd64) ARCH=x86_64 ;; *) echo "Unsupported architecture: $ARCH" >&2; exit 2;; esac
if [[ -z "$JOBS" ]]; then
  if command -v nproc >/dev/null 2>&1; then JOBS="$(nproc)"; else JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"; fi
fi

DEPS_BASE="${QRX_DEPS_ROOT:-$ROOT/../build/deps}"
PREFIX="${QRX_NATIVE_DEPS_PREFIX:-$DEPS_BASE/$OS-$ARCH}"
SRCROOT="${QRX_DEPS_SOURCE_CACHE:-$DEPS_BASE/sources}"
WORKROOT="${QRX_DEPS_WORK_ROOT:-$DEPS_BASE/work/$OS-$ARCH}"
mkdir -p "$PREFIX" "$SRCROOT" "$WORKROOT"

OPENSSL_VERSION="${QRX_OPENSSL_VERSION:-3.6.4}"
ZLIB_VERSION="${QRX_ZLIB_VERSION:-1.3.2}"
LIBPNG_VERSION="${QRX_LIBPNG_VERSION:-1.6.58}"
CURL_VERSION="${QRX_CURL_VERSION:-8.22.0}"
ZLIB_SHA256="${QRX_ZLIB_SHA256:-bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16}"
LIBPNG_SHA256="${QRX_LIBPNG_SHA256:-8c9b05b675ca7301a458df2c2e46f26e1d41ff36b8863f8c33530bc58c2e6225}"
CURL_SHA256="${QRX_CURL_SHA256:-f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7}"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing build tool: $1" >&2; exit 4; }; }
for c in curl perl cmake make cc ar ranlib tar; do need "$c"; done
if command -v shasum >/dev/null 2>&1; then SHA=(shasum -a 256); elif command -v sha256sum >/dev/null 2>&1; then SHA=(sha256sum); else echo "Need shasum or sha256sum" >&2; exit 4; fi

fetch(){ local url="$1" out="$2"; if [[ ! -s "$out" ]]; then echo "Downloading $url"; curl --fail --location --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 -o "$out.tmp" "$url"; mv "$out.tmp" "$out"; fi; }
verify(){ local f="$1" want="$2"; local got got_lc want_lc; got="$(${SHA[@]} "$f" | awk '{print $1}')"; got_lc="$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')"; want_lc="$(printf '%s' "$want" | tr '[:upper:]' '[:lower:]')"; [[ "$got_lc" == "$want_lc" ]] || { echo "SHA256 mismatch: $f" >&2; echo "expected $want" >&2; echo "actual   $got" >&2; exit 5; }; }

# OpenSSL: use the release project's own SHA256 sidecar.
OSSL_TAR="$SRCROOT/openssl-$OPENSSL_VERSION.tar.gz"
OSSL_SHA="$OSSL_TAR.sha256"
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" "$OSSL_TAR"
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz.sha256" "$OSSL_SHA"
OSSL_EXPECTED="$(awk 'NF{print $1;exit}' "$OSSL_SHA")"
[[ "$OSSL_EXPECTED" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Invalid OpenSSL checksum sidecar" >&2; exit 5; }
verify "$OSSL_TAR" "$OSSL_EXPECTED"

ZLIB_TAR="$SRCROOT/zlib-$ZLIB_VERSION.tar.gz"
PNG_TAR="$SRCROOT/libpng-$LIBPNG_VERSION.tar.gz"
CURL_TAR="$SRCROOT/curl-$CURL_VERSION.tar.xz"
fetch "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" "$ZLIB_TAR"
fetch "https://download.sourceforge.net/libpng/libpng-$LIBPNG_VERSION.tar.gz" "$PNG_TAR"
fetch "https://curl.se/download/curl-$CURL_VERSION.tar.xz" "$CURL_TAR"
verify "$ZLIB_TAR" "$ZLIB_SHA256"
verify "$PNG_TAR" "$LIBPNG_SHA256"
verify "$CURL_TAR" "$CURL_SHA256"

case "$OS:$ARCH" in
  macos:arm64) OSSL_TARGET=darwin64-arm64-cc ;;
  macos:x86_64) OSSL_TARGET=darwin64-x86_64-cc ;;
  linux:arm64) OSSL_TARGET=linux-aarch64 ;;
  linux:x86_64) OSSL_TARGET=linux-x86_64 ;;
esac

build_openssl(){
  local stamp="$PREFIX/.qrx-openssl-$OPENSSL_VERSION"
  [[ -f "$stamp" && -f "$PREFIX/lib/libcrypto.a" && -f "$PREFIX/include/openssl/evp.h" ]] && { echo "Reusing OpenSSL $OPENSSL_VERSION"; return; }
  local src="$WORKROOT/openssl-$OPENSSL_VERSION"; rm -rf "$src"; mkdir -p "$src"; tar -xzf "$OSSL_TAR" --strip-components=1 -C "$src"
  ( cd "$src"; ./Configure "$OSSL_TARGET" no-shared no-tests --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib; make -j"$JOBS"; make install_sw )
  touch "$stamp"
}

build_zlib(){
  local stamp="$PREFIX/.qrx-zlib-$ZLIB_VERSION"
  [[ -f "$stamp" && -f "$PREFIX/lib/libz.a" && -f "$PREFIX/include/zlib.h" ]] && { echo "Reusing zlib $ZLIB_VERSION"; return; }
  local src="$WORKROOT/zlib-$ZLIB_VERSION" b="$WORKROOT/zlib-build"; rm -rf "$src" "$b"; mkdir -p "$src" "$b"; tar -xzf "$ZLIB_TAR" --strip-components=1 -C "$src"
  local args=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=OFF -DZLIB_BUILD_TESTING=OFF)
  [[ "$OS" == macos ]] && args+=("-DCMAKE_OSX_ARCHITECTURES=$ARCH")
  cmake -S "$src" -B "$b" "${args[@]}"
  cmake --build "$b" --parallel "$JOBS"; cmake --install "$b"
  touch "$stamp"
}

build_png(){
  local stamp="$PREFIX/.qrx-libpng-$LIBPNG_VERSION"
  [[ -f "$stamp" && -f "$PREFIX/include/png.h" && ( -f "$PREFIX/lib/libpng.a" || -f "$PREFIX/lib/libpng16.a" ) ]] && { echo "Reusing libpng $LIBPNG_VERSION"; return; }
  local src="$WORKROOT/libpng-$LIBPNG_VERSION" b="$WORKROOT/libpng-build"; rm -rf "$src" "$b"; mkdir -p "$src" "$b"; tar -xzf "$PNG_TAR" --strip-components=1 -C "$src"
  local args=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=OFF -DPNG_SHARED=OFF -DPNG_STATIC=ON -DPNG_TESTS=OFF -DPNG_TOOLS=OFF -DZLIB_ROOT="$PREFIX" -DZLIB_LIBRARY="$PREFIX/lib/libz.a" -DZLIB_INCLUDE_DIR="$PREFIX/include")
  [[ "$OS" == macos ]] && args+=("-DCMAKE_OSX_ARCHITECTURES=$ARCH")
  cmake -S "$src" -B "$b" "${args[@]}"; cmake --build "$b" --parallel "$JOBS"; cmake --install "$b"; touch "$stamp"
}

build_curl(){
  local stamp="$PREFIX/.qrx-curl-$CURL_VERSION"
  [[ -f "$stamp" && -f "$PREFIX/include/curl/curl.h" && -f "$PREFIX/lib/libcurl.a" ]] && { echo "Reusing curl $CURL_VERSION"; return; }
  local src="$WORKROOT/curl-$CURL_VERSION" b="$WORKROOT/curl-build"; rm -rf "$src" "$b"; mkdir -p "$src" "$b"; tar -xJf "$CURL_TAR" --strip-components=1 -C "$src"
  local args=(
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=OFF
    -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DCURL_USE_OPENSSL=ON -DCURL_ZLIB=ON
    -DOPENSSL_ROOT_DIR="$PREFIX" -DOPENSSL_USE_STATIC_LIBS=TRUE -DZLIB_ROOT="$PREFIX"
    -DCURL_USE_LIBPSL=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DUSE_LIBIDN2=OFF
    -DUSE_NGHTTP2=OFF -DUSE_NGTCP2=OFF -DUSE_QUICHE=OFF -DCURL_USE_LIBSSH2=OFF
    -DCURL_USE_GSSAPI=OFF -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON
    -DCURL_DISABLE_FTP=ON -DCURL_DISABLE_FILE=ON -DCURL_DISABLE_TELNET=ON -DCURL_DISABLE_TFTP=ON
    -DCURL_DISABLE_DICT=ON -DCURL_DISABLE_GOPHER=ON -DCURL_DISABLE_IMAP=ON -DCURL_DISABLE_POP3=ON
    -DCURL_DISABLE_RTSP=ON -DCURL_DISABLE_SMB=ON -DCURL_DISABLE_SMTP=ON
    -DCURL_DISABLE_MQTT=ON -DCURL_DISABLE_WEBSOCKETS=ON
  )
  [[ "$OS" == macos ]] && args+=("-DCMAKE_OSX_ARCHITECTURES=$ARCH")
  cmake -S "$src" -B "$b" "${args[@]}"; cmake --build "$b" --parallel "$JOBS"; cmake --install "$b"; touch "$stamp"
}

build_openssl
build_zlib
build_png
build_curl

# Required release artifacts.
for f in "$PREFIX/include/openssl/evp.h" "$PREFIX/include/zlib.h" "$PREFIX/include/png.h" "$PREFIX/include/curl/curl.h" "$PREFIX/lib/libcurl.a" "$PREFIX/lib/libz.a"; do [[ -f "$f" ]] || { echo "Dependency artifact missing: $f" >&2; exit 6; }; done
[[ -f "$PREFIX/lib/libcrypto.a" ]] || { echo "Dependency artifact missing: libcrypto.a" >&2; exit 6; }
[[ -f "$PREFIX/lib/libpng.a" || -f "$PREFIX/lib/libpng16.a" ]] || { echo "Dependency artifact missing: static libpng" >&2; exit 6; }

cat > "$PREFIX/qrx-deps.lock" <<LOCK
openssl=$OPENSSL_VERSION sha256=$OSSL_EXPECTED
zlib=$ZLIB_VERSION sha256=$ZLIB_SHA256
libpng=$LIBPNG_VERSION sha256=$LIBPNG_SHA256
curl=$CURL_VERSION sha256=$CURL_SHA256
os=$OS
arch=$ARCH
LOCK

echo "QRX native dependency stack ready: $PREFIX"
cat "$PREFIX/qrx-deps.lock"
