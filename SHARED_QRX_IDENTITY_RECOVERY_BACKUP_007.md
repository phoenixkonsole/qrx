# QRX 0.0.7 — Shared QUB Wallet Identity + Recovery Backup

## Wallet identity model

QUB wallet keys are now network-independent. The canonical GUI/Core wallet identity store is:

`~/.qrx/wallets/<wallet>/`

Mainnet, Alpha, Testnet and Regtest keep separate chain/runtime state under `~/.qrx/<network>/`, but the same selected wallet name resolves to the same Ed25519 + ML-DSA65 key set and therefore the same QUB address.

On first access, the GUI performs a copy-only migration. It prefers an existing Alpha wallet under `~/.qrx/alpha/wallets/<wallet>/`, preserving the original directory. This is specifically intended to keep existing pre-0.0.7 Alpha identities instead of creating unrelated keys on another network.

Existing node.conf files are rebound to the shared wallet directory/address without wiping peer files.

## Recovery backup

The Wallets view now has native backup actions, so macOS users do not need to browse into the hidden `.qrx` directory.

- `Save recovery.qrxseed…` opens a native save dialog and verifies the copied file size.
- `Generate fresh recovery phrase` creates a full pre-change safety backup, decrypts the existing private keys using the current session passphrase (including the valid empty-string legacy passphrase), creates a fresh mnemonic, and writes a new `recovery.qrxseed` for the same wallet keys/address.
- The new phrase is shown in the GUI only for the current app session and is not persisted by the GUI.
- The previous wallet backup retains the old recovery file. Older valid recovery phrase/file pairs remain usable if retained.

Important: an old recovery phrase cannot be derived from an encrypted `recovery.qrxseed`. Generating a fresh recovery pair is the safe way to display a new phrase again without changing the wallet identity.

## Core command

`qrx wallet-recovery-refresh <wallet-dir>`

The command verifies the private keys against the existing QUB address, creates a new recovery phrase and encrypted recovery file, and leaves the Ed25519/ML-DSA65 wallet keys unchanged.

Legacy empty-passphrase PKCS#8 wallets are supported by treating the presence of `QRX_PASSPHRASE` as authoritative even when its value is an empty string.

## Validation

- Core compile: PASS
- Fresh recovery refresh with empty legacy passphrase: PASS
- Address unchanged after recovery refresh: PASS
- Restore from fresh phrase + qrxseed reproduces identical address: PASS
- GUI JavaScript syntax: PASS
- GUI/Core compatibility audit: PASS (28 GUI Core commands)
