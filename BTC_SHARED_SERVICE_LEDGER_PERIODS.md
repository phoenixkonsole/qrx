# Shared BTC Wallet Service and Ledger Periods

## One BDK wallet implementation

`GUIWALLET/src-tauri/src/btc_wallet_service.rs` is the implementation used by both wallet surfaces. The headless `qrx-btc-wallet-service` accepts one JSON request on stdin and returns one JSON response. Tauri invokes that service for every BTC Light action, and `qrx-wallet-cli btc ...` invokes the same binary.

Supported operations are status, endpoint test and selection, init, encrypted backup reveal, restore, reset, sync, balance, new address and send. The encrypted mnemonic remains Argon2id + AES-256-GCM protected. Private `xprv`/`tprv` descriptors are never persisted; signing descriptors are derived in memory after unlock. Existing service-readable wallet files containing private descriptors are scrubbed after successful decryption. Address-index reservation is serialized and atomically persisted.

Secrets, passphrases and recovery words are never command-line arguments. Release builds must run `GUIWALLET/scripts/prepare-sidecars.sh` so the target-specific service binary is bundled beside `qrx`, `qrx-cli` and `qrxd`.

## Period exports

The complete ledger supports:

- all-time;
- one UTC calendar year;
- Q1, Q2, Q3 or Q4 of a selected UTC year;
- explicit ISO `from` and `to` boundaries.

Date-only `to` is inclusive. Internally, periods are represented as `[from, to-exclusive)`, avoiding double-counting between adjacent quarters. The normalized boundaries are written into `manifest.json`.

Transactions use their confirmed journal timestamp. Orders, trades and cross-chain sessions use the timestamp of their recorded block height. Kraken execution and arbitrage rows are filtered inside read-only SQLite snapshot queries. If a legacy row has no provable timestamp, a period export fails and leaves no final export directory; an all-time export remains available.
