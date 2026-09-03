# QRX Core 0.0.7 — Kraken Agent Manager

Built on VELOCITY Phase 4F plus the secure Kraken Spot Gateway.

- Wallet-native agent registration, listing and revocation
- Fixed `TRADE_EXTERNAL` authorization for the Kraken workflow
- Market allowlist, per-trade limit, daily limit and expiry controls
- Explicit real-money acknowledgement and revoke confirmation
- Automatic raw-transaction creation and broadcast
- Public-key-only UI; no private agent/owner keys leave their wallets
- Existing encrypted/session-only Kraken secret flow unchanged

Core 4D/4E/4F scheduling, matching, settlement, WAL, state-root, cross-chain and
SPV behavior is unchanged.
