# BTC Seed Encryption

This build upgrades BTC seed protection to **Argon2id + AES-GCM**.

## Implemented

- BTC password/passphrase field in the GUI.
- Local encrypted BTC mnemonic in app-data.
- Argon2id KDF:
  - version: 0x13
  - memory: 64 MiB
  - iterations: 3
  - parallelism: 1
- AES-256-GCM encryption.
- Per-wallet random salt.
- Per-encryption random nonce.
- Migration from plaintext dev wallet files.
- Wrong BTC password fails before wallet operations.

## Storage

The BTC wallet file is stored under the app data directory:

```text
btc-light/btc_wallet.json
```

It contains:
- encrypted mnemonic
- nonce
- Argon2id KDF metadata
- KDF salt
- descriptors
- note

## Important migration note

If you already created a BTC wallet with the previous SHA-256 KDF build, this build refuses to auto-migrate it for safety. Backup/export funds with the previous build, then create a new BTC wallet here.

## Production hardening still recommended

Before public/mainnet distribution, add:

- explicit seed phrase backup / restore flow
- password change flow
- optional macOS Keychain / Windows Credential Manager / Linux Secret Service
- testnet/signet mode for safe testing

## Practical warning

If the BTC password is lost and the seed phrase was not backed up, BTC funds may be unrecoverable.
