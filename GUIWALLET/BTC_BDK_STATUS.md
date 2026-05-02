# BTC / BDK Integration Status

This build fixes the macOS/M1 GUI issues and prepares the BTC-Light/BDK integration path.

## Included now

- GUI no longer clips on 13-inch MacBook screens.
- Tauri global bridge enabled via `withGlobalTauri`.
- macOS dev placeholder sidecars included for Intel and Apple Silicon.
- Valid `src-tauri/icons/icon.png`.
- BTC endpoint multi-fallback remains configurable.
- BTC wallet storage hooks are added:
  - `btc_init_wallet`
  - `btc_new_address`
  - local BTC-light app-data directory
  - deterministic placeholder address generation for UI/dev only

## Important

The generated BTC placeholder address is **not mainnet-spendable** and must not be used for real BTC.

## Next production step

Replace the placeholder internals with BDK:

- `bdk` crate with Electrum backend
- encrypted BIP39 seed storage
- `btc_sync`
- `btc_get_balance`
- `btc_send`
- real address generation from descriptor wallet

The UI/backend API is prepared so the BDK implementation can replace the placeholder without redesigning the wallet screens.
