# Real BTC-Light / BDK Integration

This build adds the first real BDK/Electrum wiring.

## Implemented

Tauri commands:

- `btc_init_wallet`
- `btc_sync`
- `btc_get_balance`
- `btc_new_address`
- `btc_send`
- existing:
  - `btc_get_status`
  - `btc_set_mode`
  - `btc_test_endpoints`

## Backend

The backend now uses:

- `bdk`
- BDK descriptor wallet
- Electrum backend
- configurable multi-endpoint fallback
- real BTC balance sync
- real BDK receive address generation
- real BDK transaction builder/sign/broadcast path

## Important production warning

This build stores the BTC mnemonic encrypted with Argon2id + AES-GCM in app data:

```text
~/Library/Application Support/<app>/btc-light/btc_wallet.json
```

Before any public/mainnet release, replace this with encrypted storage:

- password-derived key
- macOS Keychain / Windows Credential Manager / Linux Secret Service
- encrypted mnemonic file
- explicit backup flow

## Recommended test flow

1. Run `npm install`
2. Run `npm run tauri dev`
3. Open `BTC Light`
4. Test fallback endpoints
5. Init BTC wallet
6. Generate BTC address
7. Send tiny test amount only after reviewing the generated app-data wallet file

## Notes

The QRX/QUB sidecar placeholders for macOS are still dev placeholders unless you provide native macOS QUBITCOIN Core binaries:

- `qrx-aarch64-apple-darwin`
- `qrx-cli-aarch64-apple-darwin`
- `qrxd-aarch64-apple-darwin`

or Intel equivalents.
