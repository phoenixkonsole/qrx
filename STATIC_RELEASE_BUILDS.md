# QRX Static Release Builds

QRX v0.0.6 uses OpenSSL 3.6.x for ML-DSA / hybrid wallet support.
For portable releases, build OpenSSL statically and link QRX against `libcrypto.a`.

## Linux x64

```bash
cd qrx-core
./scripts/build-linux-x64-static.sh
ldd build-linux-x64-static/qrxd | grep crypto || true
```

If no `libcrypto` dependency is shown, OpenSSL was linked statically.

## macOS

```bash
cd qrx-core
./scripts/build-macos-static.sh arm64
# or:
./scripts/build-macos-static.sh x86_64
otool -L build-macos-arm64-static/qrxd | grep crypto || true
```

If no `libcrypto` dependency is shown, OpenSSL was linked statically.

## Windows x64

PowerShell:

```powershell
cd qrx-core
powershell -ExecutionPolicy Bypass -File scripts\build-windows-x64-static.ps1
```

Check with:

```powershell
dumpbin /DEPENDENTS .\build-windows-x64-static\Release\qrxd.exe
```

No `libcrypto-3-x64.dll` should be required for a static OpenSSL build.
