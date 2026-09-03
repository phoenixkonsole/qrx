# QRX Core 0.0.7 — VELOCITY Phase 4F + Kraken Spot Secure Wallet Gateway

This source release extends the validated Phase 4F tree with a real off-chain Kraken Spot execution adapter and secure Wallet credential entry.

## Added

- `qrx-core/gateways/qrx-gateway-kraken.py`
- `GUIWALLET` Agents & Kraken view
- session-only Kraken credential prompt (default)
- optional Argon2id + AES-256-GCM Wallet credential vault
- stdin-only secret delivery to the gateway child process
- Kraken Spot REST authentication / AddOrder / QueryOrders / OpenOrders / ClosedOrders / CancelOrder
- deterministic 32-hex `cl_ord_id` derived from QRX order ID
- non-secret SQLite restart/idempotency mapping
- execution-report replay after restart
- startup API-permission validation with hard refusal of withdrawal-enabled API keys
- external cancel handshake: `submitted -> cancel_pending -> CANCELED report -> canceled`
- tests and setup/validation documentation

## Security defaults

- API key/secret are not accepted through command-line arguments.
- API key/secret are not written to readable `.conf` files.
- API key/secret are not stored in the gateway SQLite database.
- API key/secret are not written to QRX consensus state.
- Session-only mode is the GUI default.
- Optional local persistence is encrypted with the current wallet/session passphrase.
- Unix gateway process uses `umask 077` and disables core dumps where supported.
- Kraken keys with `withdraw-funds` permission are rejected.

## Validation

See `qrx-core/KRAKEN_SPOT_GATEWAY_VALIDATION.md`.
