# QRX 0.0.7 unified compiler — Tauri sidecar bootstrap fix

## Symptom on macOS Apple Silicon

During the preliminary Rust BTC wallet service build, Cargo ran the package-level
`src-tauri/build.rs`. Because that build script called `tauri_build::build()`
unconditionally, Tauri validated `bundle.externalBin` before the unified compiler
had staged the target-suffixed Core binaries. The build therefore failed with:

    path matching bin/qrx-aarch64-apple-darwin not found

## Fix

The preliminary `qrx-btc-wallet-service` build is now invoked with
`QRX_BUILD_SERVICE_ONLY=1`. `src-tauri/build.rs` detects this flag and skips the
Tauri bundle metadata/sidecar validation for that service-only compilation.

After the service has been compiled, the unified script stages all four exact
Tauri sidecar names for the selected Rust target and only then executes the real
Tauri application build. That final build runs `tauri_build::build()` normally,
so missing sidecars are still detected.
