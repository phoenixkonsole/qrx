#!/usr/bin/env bash
set -euo pipefail

# Builds OpenSSL 3.6.2 into /opt/qrx-openssl for QRX hybrid / ML-DSA support.
# Run on Ubuntu 22.04/24.04 when the system OpenSSL is too old.

PREFIX="${PREFIX:-/opt/qrx-openssl}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.2}"
JOBS="${JOBS:-$(nproc)}"

sudo apt update
sudo apt install -y build-essential perl wget ca-certificates

cd /tmp
rm -rf "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}.tar.gz"
wget "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"

./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" shared
make -j"$JOBS"
sudo make install_sw install_ssldirs

cat <<MSG

OpenSSL ${OPENSSL_VERSION} installed to: ${PREFIX}

Build QRX with:
  cmake .. -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=${PREFIX}

Runtime hint if needed:
  export LD_LIBRARY_PATH=${PREFIX}/lib64:${PREFIX}/lib:\$LD_LIBRARY_PATH

MSG
