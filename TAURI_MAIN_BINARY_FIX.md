# QRX 0.0.7 Tauri main-binary fix

The BTC wallet service is now a standalone Rust crate under `GUIWALLET/btc-wallet-service`.
It is deliberately not stored under `GUIWALLET/src-tauri/src/bin`, because Tauri v1 enumerates
additional Cargo binaries during bundling and could package the service as the application's
main executable.

The Tauri crate now has one application binary only (`qrx-wallet`) and declares it as
`default-run`. The unified build script compiles the BTC service separately, stages it with the
required target suffix as an `externalBin`, and verifies on macOS that:

- `GUI Wallet.app/Contents/MacOS/qrx-wallet` exists and is executable.
- `CFBundleExecutable` equals `qrx-wallet` before a DMG is created.

This prevents a release from being reported as successful when the `.app` contains only sidecars.
