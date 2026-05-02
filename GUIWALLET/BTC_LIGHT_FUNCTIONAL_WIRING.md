# BTC Light Functional Wiring

This build wires the existing Rust/BDK BTC backend to the GUI.

## GUI functions now implemented

- `btcInitWallet()`
- `btcNewAddress()`
- `btcSync()`
- `btcSend()`
- `btcShowBackup()`
- `btcRestoreWallet()`
- `btcResetWallet()`
- `testBtcEndpoints()`
- `loadBtcStatus()`
- `setBtcMode()`

## Backend commands already present

- `btc_init_wallet`
- `btc_new_address`
- `btc_sync`
- `btc_get_status`
- `btc_get_balance`
- `btc_send`
- `btc_backup_phrase`
- `btc_restore_wallet`
- `btc_reset_wallet`
- `btc_test_endpoints`
- `btc_set_mode`

## Notes

BTC uses BDK with Electrum fallback endpoints. The BTC mnemonic is encrypted locally with Argon2id + AES-GCM.

Use tiny test amounts first. Production release should still receive a full Bitcoin wallet/security review.
