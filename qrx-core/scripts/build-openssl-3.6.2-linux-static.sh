#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/opt/qrx-openssl-static}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.2}"
JOBS="${JOBS:-$(nproc)}"

sudo apt update
sudo apt install -y build-essential perl wget ca-certificates

cd /tmp
rm -rf "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}.tar.gz"
wget "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"

./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" no-shared no-module
make -j"$JOBS"
sudo make install_sw install_ssldirs

echo "OpenSSL ${OPENSSL_VERSION} static build installed to: ${PREFIX}"
echo "Static libcrypto should be at: ${PREFIX}/lib64/libcrypto.a or ${PREFIX}/lib/libcrypto.a"
