# QRX 0.0.7 macOS Tauri main executable post-bundle fix

On macOS arm64, Tauri 1.x successfully compiled `qrx-wallet` and created
`GUI Wallet.app`, but in this project configuration the generated app bundle
could contain only the external sidecars and omit the main GUI executable.

The unified build script now treats Cargo's compiled target as authoritative:

1. Tauri builds the application and bundle shell.
2. The script verifies `build/tauri/<target>/<rust-target>/release/qrx-wallet`.
3. That exact binary is copied to `GUI Wallet.app/Contents/MacOS/qrx-wallet`.
4. `CFBundleExecutable` is set to `qrx-wallet` with PlistBuddy.
5. The finished app is ad-hoc signed for local/test use when `codesign` exists.
6. The script verifies the executable before creating the Finder-free DMG.

This prevents a non-launchable `.app` from being released while retaining all
QRX Core and BTC wallet service sidecars.
