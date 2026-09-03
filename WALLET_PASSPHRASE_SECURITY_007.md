# QRX 0.0.7 Wallet Passphrase Security

## Empty-passphrase encrypted PEM compatibility

Older QRX wallets may contain PKCS#8 files with `BEGIN ENCRYPTED PRIVATE KEY` while the encryption passphrase is the empty string. This is not equivalent to an unencrypted PEM, but it also does not require the user to enter a password.

The GUI now distinguishes:

- encrypted container + empty passphrase: no user password required
- encrypted container + non-empty passphrase: explicit session unlock required
- unencrypted private key: no passphrase required
- incomplete/mixed key sets: signing/security changes refused until inspected

For empty-passphrase wallets the local daemon session is synchronized explicitly through `walletpassphrasehex -`. `-` is the CLI/RPC sentinel for an empty passphrase; it avoids losing an empty argument through the whitespace-delimited command surface.

## Security -> Set / Change wallet passphrase

The Wallets view contains a Security card. A passphrase change:

1. verifies the current Ed25519 and ML-DSA65 private keys (empty current passphrase is supported),
2. creates a full copy-only `pre-passphrase-change-*` backup,
3. verifies source/backup regular-file count and total bytes,
4. writes both new encrypted PKCS#8 keys to temporary files,
5. verifies both temporary files using the new passphrase,
6. stages the originals, installs the new files, and verifies them again,
7. restores the original keys if installation/post-write verification fails,
8. activates the new passphrase only for the current daemon/UI session.

The new passphrase is never written to localStorage, logs, configuration, or wallet metadata.
