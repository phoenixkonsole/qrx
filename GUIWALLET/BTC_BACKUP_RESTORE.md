# BTC Backup & Restore

This build adds a complete BTC backup/restore flow for the BDK/Electrum wallet.

## New backend commands

- `btc_backup_phrase`
- `btc_restore_wallet`
- `btc_reset_wallet`

## New UI

In **BTC Light → BTC Backup & Restore**:

- Show backup phrase
- Verify backup phrase by checking word positions
- Restore from recovery phrase
- Optional overwrite of existing local BTC wallet
- Reset local encrypted BTC wallet file

## Security model

The BTC mnemonic is encrypted locally with:

- Argon2id KDF
- AES-256-GCM
- random salt
- random nonce

The backup phrase is only decrypted when the user enters the BTC password and clicks **Show backup phrase**.

## Important warning

Anyone with the backup phrase can spend the BTC wallet. The phrase must be written down offline and never shared.

If the BTC password is lost and the phrase was not backed up, BTC funds may be unrecoverable.
