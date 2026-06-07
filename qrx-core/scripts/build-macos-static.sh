#!/usr/bin/env bash
set -euo pipefail

ARCH="${1:-arm64}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.2}"
PREFIX="${PREFIX:-/opt/qrx-openssl-static-${ARCH}}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-macos-${ARCH}-static}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"

if [[ "$ARCH" == "arm64" ]]; then
  OPENSSL_TARGET="darwin64-arm64-cc"
elif [[ "$ARCH" == "x86_64" ]]; then
  OPENSSL_TARGET="darwin64-x86_64-cc"
else
  echo "Usage: $0 arm64|x86_64" >&2
  exit 1
fi

if [[ ! -f "$PREFIX/lib64/libcrypto.a" && ! -f "$PREFIX/lib/libcrypto.a" ]]; then
  cd /tmp
  rm -rf "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}.tar.gz"
  curl -LO "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
  tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
  cd "openssl-${OPENSSL_VERSION}"
  ./Configure "$OPENSSL_TARGET" --prefix="$PREFIX" --openssldir="$PREFIX/ssl" no-shared no-module
  make -j"$JOBS"
  sudo make install_sw install_ssldirs
fi

LIBCRYPTO="$PREFIX/lib64/libcrypto.a"
if [[ ! -f "$LIBCRYPTO" ]]; then
  LIBCRYPTO="$PREFIX/lib/libcrypto.a"
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$ROOT" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DOPENSSL_ROOT_DIR="$PREFIX" \
  -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$LIBCRYPTO"

cmake --build . --parallel "$JOBS"

echo
echo "Built macOS $ARCH static-OpenSSL QRX binaries in: $BUILD_DIR"
echo "Check with:"
echo "  otool -L $BUILD_DIR/qrxd | grep crypto || true"
