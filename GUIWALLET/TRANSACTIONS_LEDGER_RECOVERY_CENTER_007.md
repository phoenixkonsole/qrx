# QRX 0.0.7 GUI Wallet — Transactions, Ledger Export & Full Recovery Center

- Adds a first-class Transactions navigation view with QUB/BTC filtering.
- QUB history is read from the current Core wallet via `get_history`.
- BTC history is shown when the BTC Light service exposes synced transaction records; no history is invented.
- Moves Complete CSV Ledger export into a user-facing Transactions & Ledger screen with All time, Year, Quarter, and bounded From/To periods.
- Adds Wallets → Backup & Restore → Full Recovery Center.
- Recovery restore is create-only and refuses to overwrite an existing wallet.
- Current QRX recovery design requires the matching `recovery.qrxseed` plus the recovery phrase printed at wallet creation. The phrase alone is not sufficient.
- Legacy/0.0.6 wallets remain subject to the pre-0.0.7 verified safety-backup gate before use.
- Wallet directory import/export remains available as a second recovery path.
