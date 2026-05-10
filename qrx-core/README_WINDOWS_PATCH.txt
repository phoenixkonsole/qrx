QRX Windows Compile Patch v2

Replace these files in your qrx-core repo:

src/qrx.c
src/core_frontend.c

This version fixes:
- Windows POSIX include issues
- R_OK missing under MSVC
- strtok_r, strcasecmp and strdup compatibility
- Windows mkdir, setenv, access, unlink, popen/pclose wrappers
- Winsock initialization before socket usage
- Windows socket timeout handling
- Broken backslash char literals in path handling

Build:

Remove-Item build -Recurse -Force

cmake -S . -B build `
  -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" `
  -DOPENSSL_INCLUDE_DIR="C:\Program Files\OpenSSL-Win64\include" `
  -DOPENSSL_CRYPTO_LIBRARY="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libcrypto.lib" `
  -DOPENSSL_SSL_LIBRARY="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libssl.lib"

cmake --build build --config Release
