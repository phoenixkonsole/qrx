QRX Windows Compile Patch

Replace these files in your qrx-core repo:

src/qrx.c
src/core_frontend.c

What changed:
- Windows guards for POSIX-only includes.
- Windows mkdir, env, access, unlink, popen/pclose wrappers.
- Winsock includes and WSAStartup initialization before socket usage.
- Windows-safe socket timeout handling.
- macOS/Linux behavior preserved.

Recommended clean build on Windows:

rmdir /s /q build

cmake -S . -B build ^
  -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" ^
  -DOPENSSL_INCLUDE_DIR="C:\Program Files\OpenSSL-Win64\include" ^
  -DOPENSSL_CRYPTO_LIBRARY="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libcrypto.lib" ^
  -DOPENSSL_SSL_LIBRARY="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libssl.lib"

cmake --build build --config Release
