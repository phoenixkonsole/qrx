# QRX 0.0.7 macOS DMG build fix

Tauri 1.x successfully produced `GUI Wallet.app` but its `bundle_dmg.sh` failed while using Finder/AppleScript for DMG layout.

The macOS Tauri config now builds only the native `.app`. `scripts/build-all-targets.sh` then creates the distributable DMG directly with Apple `hdiutil`, including an `/Applications` symlink. This avoids Finder automation and keeps `.app` and `.dmg` release artifacts.
