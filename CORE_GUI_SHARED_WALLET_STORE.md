# QRX 0.0.7 Core/GUI shared wallet store

- Core and Tauri GUI now use the same default QRX root: `~/.qrx`.
- Existing Core wallets under `~/.qrx/<network>/wallets/<name>` are detected on the welcome screen.
- Choosing an existing wallet uses it in place; no wallet files are copied.
- Import remains available for external wallet folders, but refuses any existing destination path and refuses per-file overwrite as a second safety barrier.
- macOS packaging now accepts either `release/qrx-wallet` or Tauri's observed `release/GUI Wallet` product executable, then installs it deterministically as `Contents/MacOS/qrx-wallet`.
