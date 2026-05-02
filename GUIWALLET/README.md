# GUI Wallet

QRX desktop GUI wallet based on Tauri.

This archive is separated from the QUBITCOIN Core tree and uses bundled QUBITCOIN Core sidecars.

## Included now

- Linux x64 QUB sidecars:
  - `qrx-x86_64-unknown-linux-gnu`
  - `qrx-cli-x86_64-unknown-linux-gnu`
  - `qrxd-x86_64-unknown-linux-gnu`
- Strict Tauri sidecar config via `bundle.externalBin`
- Platform build configs for Linux, macOS and Windows
- Wallet UI, daemon handling, staking/delegation screens and QUB CLI bridge

## Not included yet

Real macOS and Windows QUBITCOIN Core binaries are not included in this archive. Add them before building releases for those platforms.

Expected Windows files:

```text
src-tauri/bin/qrx-x86_64-pc-windows-msvc.exe
src-tauri/bin/qrx-cli-x86_64-pc-windows-msvc.exe
src-tauri/bin/qrxd-x86_64-pc-windows-msvc.exe
```

Expected macOS files:

```text
src-tauri/bin/qrx-x86_64-apple-darwin
src-tauri/bin/qrx-cli-x86_64-apple-darwin
src-tauri/bin/qrxd-x86_64-apple-darwin
src-tauri/bin/qrx-aarch64-apple-darwin
src-tauri/bin/qrx-cli-aarch64-apple-darwin
src-tauri/bin/qrxd-aarch64-apple-darwin
```

## Build

```bash
npm install
npm run check:sidecars
npm run build:linux
npm run build:macos
npm run build:windows
```

Build each platform on that platform or in a proper CI/cross-build setup.

## Release recommendation

- Linux: `.deb` as main package, AppImage as optional package
- macOS: signed + notarized `.dmg`
- Windows: signed `.msi` and optionally signed NSIS `.exe`
