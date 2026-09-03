# QRX v0.0.6 repository cleanup + OpenSSL link fix

This archive removes the duplicate root `src/` tree and makes the repository layout unambiguous:

- Root `CMakeLists.txt` is now only a wrapper.
- Actual sources live in `qrx-core/src/`.
- Actual QRX Core CMake project lives in `qrx-core/CMakeLists.txt`.

The CMake configuration now prints the OpenSSL include/library paths and links OpenSSL explicitly into all executables. This prevents `undefined symbols` linker errors when a stale CMake cache or wrong OpenSSL path causes `libcrypto` not to be linked.

Recommended clean build:

```bash
cd qrx-core
rm -rf build
mkdir build
cd build

cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DOPENSSL_ROOT_DIR=/opt/qrx-openssl-static \
  -DOPENSSL_INCLUDE_DIR=/opt/qrx-openssl-static/include \
  -DOPENSSL_CRYPTO_LIBRARY=/opt/qrx-openssl-static/lib64/libcrypto.a

cmake --build . --parallel $(nproc)
```

Verify Linux static OpenSSL linking:

```bash
ldd ./qrxd | grep crypto
```

Expected for static OpenSSL: no output.
