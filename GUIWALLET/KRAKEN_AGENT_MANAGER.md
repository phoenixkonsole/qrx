# QRX Wallet Kraken Agent Manager

The **Agents & Kraken** wallet page now manages the on-chain `TRADE_EXTERNAL`
authorization without hand-written CLI commands.

## Flow

1. Select the owner wallet and enter the session passphrase.
2. Enter the owner and agent addresses and their public Ed25519/ML-DSA-65 keys.
3. Choose the Kraken Spot market allowlist, per-trade limit, daily limit and
   expiry heights.
4. Confirm the real-trading warning.
5. The wallet creates the hybrid-signed raw registration and broadcasts it.
6. The same page lists agents and can broadcast an on-chain revocation.

Kraken API credentials remain in the separate secure gateway section. They are
never embedded in an agent transaction, QRXDB, a command line, SQLite or a
plaintext configuration file. Private QRX signing keys remain in their wallets;
only public keys are handled by this form.

## Safety invariants

- Permission is fixed to `TRADE_EXTERNAL`.
- Venue is fixed to Kraken by this wallet workflow.
- At least one `BASE/QUOTE` market is required.
- Limits and expiry heights must be positive whole numbers.
- Registration requires an explicit real-trading acknowledgement.
- Revocation requires a separate confirmation.
- Kraken withdrawal permission must remain disabled.

The current form uses protocol atoms so there is no rounding ambiguity at the
consensus boundary. A later fiat quote layer may show an approximate EUR value,
but must never replace the exact atom limits being signed.
