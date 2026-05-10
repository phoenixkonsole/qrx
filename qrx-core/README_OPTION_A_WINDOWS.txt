QRX Option A Windows Patch

Replace these files in qrx-core:

CMakeLists.txt
src/qrx.c
src/core_frontend.c
src/qrxd.c
src/qrx_cli.c

What this patch does:
- Keeps macOS/Linux on POSIX paths.
- Adds Windows compatibility guards.
- Replaces qrxd Unix control socket with localhost TCP on Windows.
- Uses ports:
  mainnet 127.0.0.1:37660
  alpha   127.0.0.1:37661
  testnet 127.0.0.1:37662
  regtest 127.0.0.1:37663
- Uses CreateProcessA for Windows backend child processes.
- Uses CreateThread for Windows maintenance and producer loops.
- Links ws2_32 through CMake.

Clean build on Windows PowerShell:

Remove-Item build -Recurse -Force

cmake -S . -B build `
  -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" `
  -DOPENSSL_INCLUDE_DIR="C:\Program Files\OpenSSL-Win64\include" `
  -DOPENSSL_CRYPTO_LIBRARY="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libcrypto.lib" `
  -DOPENSSL_SSL_LIBRARY="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libssl.lib"

cmake --build build --config Release
