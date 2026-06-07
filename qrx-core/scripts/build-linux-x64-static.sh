#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-/opt/qrx-openssl-static}"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-linux-x64-static}"

if [[ ! -f "$PREFIX/lib64/libcrypto.a" && ! -f "$PREFIX/lib/libcrypto.a" ]]; then
  "$ROOT/scripts/build-openssl-3.6.2-linux-static.sh"
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
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DOPENSSL_ROOT_DIR="$PREFIX" \
  -DOPENSSL_INCLUDE_DIR="$PREFIX/include" \
  -DOPENSSL_CRYPTO_LIBRARY="$LIBCRYPTO"

cmake --build . --parallel "$(nproc)"

echo
echo "Built static QRX binaries in: $BUILD_DIR"
echo "Check OpenSSL dynamic dependency with:"
echo "  ldd $BUILD_DIR/qrxd | grep crypto || true"
