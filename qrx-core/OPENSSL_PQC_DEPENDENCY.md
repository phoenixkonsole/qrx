# QRX OpenSSL / PQC Dependency

QRX mainnet hybrid consensus requires OpenSSL with ML-DSA support.
Ubuntu 22.04 ships OpenSSL 3.0.2, which does **not** provide ML-DSA-65.
That version cannot create QRX hybrid wallets and cannot verify hybrid finality votes.

Recommended dependency for release builds:

- OpenSSL 3.6.x
- Build path: `/opt/qrx-openssl`

## Ubuntu 22.04 / 24.04

Run:

```bash
cd qrx-core
./scripts/build-openssl-3.6.2-linux.sh
```

Then build QRX:

```bash
rm -rf build
mkdir build
cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/opt/qrx-openssl
cmake --build . --parallel $(nproc)
```

If the runtime loader cannot find the OpenSSL shared library:

```bash
export LD_LIBRARY_PATH=/opt/qrx-openssl/lib64:/opt/qrx-openssl/lib:$LD_LIBRARY_PATH
```

## Developer-only fallback

For local non-mainnet experiments only, QRX can be configured with:

```bash
cmake .. -DQRX_REQUIRE_PQC=OFF
```

Do not use that for mainnet builds. Mainnet hybrid consensus is intended to fail closed when ML-DSA support is unavailable.
