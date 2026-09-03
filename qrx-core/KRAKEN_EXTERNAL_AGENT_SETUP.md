# QRX Core 0.0.7 — Kraken Spot External Agent + Secure Wallet Gateway

Status: implemented source integration on top of VELOCITY Phase 4F.

## Architecture

```text
QRX owner
  -> authorizes TRADE_EXTERNAL agent (market/per-trade/daily/expiry limits)
QRX agent
  -> signed EXTERNAL_ORDER (venue=KRAKEN)
QRX Core
  -> pending_execution
qrx-gateway-kraken
  -> Kraken Spot REST AddOrder / QueryOrders / OpenOrders / ClosedOrders / CancelOrder
Kraken
  -> venue state
qrx-gateway-kraken
  -> gateway-signed QRX EXECUTION_REPORT
QRX Core
  -> SUBMITTED / PARTIALLY_FILLED / FILLED / REJECTED / CANCELED
```

The Kraken API credential is **off-chain**. It never belongs in an agent transaction, QRX block, mempool record or readable gateway configuration.

## Wallet credential flow

The GUI Wallet now contains **Agents & Kraken**.

Default mode is **session-only**:

1. Start/unlock the QRX wallet/node with the session passphrase.
2. Open `Agents & Kraken`.
3. Paste Kraken API Key and API Secret into password fields.
4. Leave `Store credentials encrypted...` unchecked.
5. Press `Start Kraken gateway`.
6. The Wallet spawns the bundled gateway with a private stdin pipe.
7. The credential JSON is written once to that pipe and stdin is closed.
8. The visible fields are cleared.

The key and secret are **not** command-line arguments, environment variables, `.conf` values or SQLite fields.

Optional persistence is explicit opt-in. When enabled, the Wallet writes only `kraken_credentials.enc.json` containing ciphertext and KDF metadata:

- Argon2id: 64 MiB, t=3, p=1, 32-byte key
- AES-256-GCM
- random 16-byte salt
- random 12-byte nonce
- Unix file mode 0600

The same wallet/session passphrase is required to decrypt the vault. The decrypted byte buffer used during vault decoding is zero-filled after parsing. The running gateway must still retain the actual credential in process memory while it signs Kraken requests; that is unavoidable for an authenticated API client.

On Unix, the gateway sets `umask 077` and disables core dumps where supported.

## Kraken API key permissions

Create a dedicated Kraken **Spot** API key. Recommended QRX gateway permissions:

- Create & modify orders: ON
- Query open orders & trades: ON
- Query closed orders & trades: ON
- Cancel & close orders: optional when Create & modify already permits cancel, but safe to enable
- Query funds: optional; not required by the current MVP
- Withdraw funds: **OFF**
- Funding/deposit/withdraw permissions: OFF unless independently required for another service

The gateway calls Kraken `GetApiKeyInfo` on startup. If Kraken reports `withdraw-funds`, startup fails deliberately. It also refuses a reported permission set missing create/modify or open/closed-order query access.

For a dedicated API key, prefer Kraken IP allowlisting when the gateway runs from a stable public address. The current gateway does not implement Kraken API-key OTP/TOTP, so create the dedicated automation key without API-key 2FA; use QRX limits, Kraken IP allowlisting and withdrawal-disabled permissions as the execution controls.

Current Kraken references checked 2026-09-01:
- https://docs.kraken.com/api-reference/trading/add-order
- https://docs.kraken.com/api-reference/trading/cancel-order
- https://docs.kraken.com/api-reference/account-data/get-api-key-info
- https://docs.kraken.com/exchange/guides/rest/authentication

## Register a QRX external-trading agent

Conceptual policy:

```text
permissions       = TRADE_EXTERNAL
max_trade_atoms   = strict per-order maximum
daily_limit_atoms = strict daily maximum
market_allowlist  = BTC/EUR,ETH/EUR
expires_height    = finite QRX height
```

CLI surface:

```text
qrx create-agent-register-raw-tx \
  <chain-dir> <owner> <agent> \
  <agent-ed25519-pub-hex> <agent-mldsa65-pub-b64> \
  TRADE_EXTERNAL \
  <max-trade-atoms> <daily-limit-atoms> \
  BTC/EUR,ETH/EUR \
  <agent-expires-height> \
  <owner-ed25519-pub-hex> <owner-mldsa65-pub-b64> \
  <lane-id> <tx-expiry-height> [fee] [nonce]
```

The owner signs/submits that transaction. Agent limits remain consensus-enforced before an EXTERNAL_ORDER is accepted.

## Register the Kraken gateway identity

The current gateway process signs QRX execution reports with the selected QRX wallet, so that wallet must already be governance-authorized as an active `KRAKEN` gateway.

```text
qrx create-gateway-register-raw-tx \
  <chain-dir> <gateway-authority> <gateway-address> \
  KRAKEN QRX-Kraken-Gateway \
  <gateway-ed25519-pub-hex> <gateway-mldsa65-pub-b64> \
  <gateway-expires-height> \
  <authority-ed25519-pub-hex> <authority-mldsa65-pub-b64> \
  <lane-id> <tx-expiry-height> [fee] [nonce]
```

The GUI refuses normal operation indirectly because `qrx-gateway-kraken` itself checks `getgateway` and exits unless the selected wallet is active and scoped to venue `KRAKEN`.

## Real Kraken order execution

The implemented service is:

`qrx-core/gateways/qrx-gateway-kraken.py`

The same script is bundled into the GUI Wallet resources.

Implemented Kraken Spot behavior:

- REST API HMAC-SHA512 authentication according to Kraken's documented signature construction
- monotonic millisecond nonce
- `AssetPairs` lookup for pair ID, precision and `ordermin`
- QRX aliases including `BTC -> XBT` and `DOGE -> XDG`
- LIMIT and MARKET orders
- deterministic client-order ID: first 32 hex chars of SHA-256(QRX order ID)
- AddOrder
- QueryOrders
- OpenOrders / ClosedOrders reconciliation
- CancelOrder
- PARTIALLY_FILLED/FILLED/CANCELED/REJECTED translation
- QRX execution-report signing/broadcast through the existing qrx-cli/qrxd wallet pipeline

Kraken documents a short `cl_ord_id` as 32 hexadecimal characters, matching the gateway's deterministic identifier.

## Idempotency and restart safety

SQLite contains only non-secret execution state:

```text
QRX order ID
Kraken cl_ord_id
Kraken txid
last observed status
pending QRX execution-report sequence
pending signed QRX report transaction
```

Before `AddOrder`, the service queries Kraken OpenOrders and ClosedOrders for the deterministic `cl_ord_id`. This means a request that timed out after Kraken accepted it is reconciled instead of blindly submitted a second time.

Pending QRX execution reports are stored as the exact already-signed transaction and replayed until QRX reports that sequence as committed. This avoids constructing a different follow-up report after a local restart.

## Correct external cancellation semantics

QRX Core was adjusted for real exchange behavior:

```text
submitted
  -> QRX ORDER_CANCEL
cancel_pending
  -> gateway calls Kraken CancelOrder
  -> Kraken confirms canceled/closed
  -> signed QRX CANCELED execution report
canceled
```

An external order is therefore never declared `canceled` merely because the agent requested cancellation. Native QRX order cancellation retains its existing immediate local settlement semantics.

## Important scope

This release implements **Kraken Spot execution**. It does not implement Kraken Derivatives/Futures, authenticated WebSocket streaming, or an autonomous trading strategy. The QRX agent is the strategy/intent producer; the Kraken gateway is the execution/reconciliation adapter.

No live private Kraken order was sent during automated validation because no real API credential was provided to the build environment. Live first-run testing should therefore use a tightly limited dedicated account/key and a very small Spot order.
