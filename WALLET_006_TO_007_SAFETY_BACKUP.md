# QRX 0.0.6 -> 0.0.7 wallet safety backup

QRX 0.0.7 GUI and Core share the same wallet root (`~/.qrx`). Existing wallets are used in place.

Before the GUI opens a wallet whose `wallet.json` reports a version older than the current wallet version (12), or whose version cannot be determined, it creates a copy-only safety backup under:

`~/.qrx/backups/<network>/<wallet>/pre-0.0.7-<unix-time>/`

Rules:
- The original wallet is never overwritten by the backup operation.
- Existing backup destinations are never reused or overwritten.
- `wallet.json` must be present in the completed backup or opening is aborted.
- A `QRX_BACKUP_MANIFEST.json` is written into the backup directory with source, version and timestamp metadata.
- If a pre-0.0.7 safety backup already exists, the GUI reuses that protection and does not overwrite it.
- Current v12 wallets are opened directly and do not receive an unnecessary migration backup.

This is a safety layer for compatibility/migration. Any future destructive wallet-format migration must call the same preparation path before changing wallet data.
