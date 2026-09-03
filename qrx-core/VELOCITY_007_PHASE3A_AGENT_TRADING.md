# QRX Core 0.0.7 VELOCITY — Phase 3A: Agent-Signed Trading Intents

## Scope

Phase 3A turns the on-chain Agent Key model from Phase 2 into a usable trading authorization layer. It does **not** yet perform native order matching or external exchange execution. Instead, it creates deterministic, signed, permission-checked order state that later matching and execution layers can consume.

## Newly executable VELOCITY transaction types

- `ORDER_CREATE`
- `ORDER_CANCEL`
- `ORDER_REPLACE` (native orders)
- `EXTERNAL_ORDER`

Still reserved/not executable in this phase:

- `ATOMIC_BUNDLE`
- `ORACLE_UPDATE`
- `EXECUTION_REPORT`

## Security model

The owner wallet registers an agent on-chain. Trading transactions are then signed by the agent's own hybrid key pair.

For every trading transaction QRX now verifies:

1. The agent is registered and active.
2. The agent authorization has not expired.
3. The `to` owner matches the registered owner.
4. The transaction Ed25519 public key exactly matches the owner-authorized agent key.
5. The transaction ML-DSA-65 public key exactly matches the owner-authorized agent key.
6. The required trading permission is present.
7. The market is in the agent market allowlist.
8. `max_trade_atoms` is not exceeded.
9. The block-derived 24h usage bucket does not exceed `daily_limit_atoms`.
10. Transaction and order expiry heights are still valid.
11. The normal VELOCITY lane nonce rule remains enforced.

Supported permissions:

- `TRADE` — broad trading permission
- `TRADE_NATIVE` — native QRX order state
- `TRADE_EXTERNAL` — external venue execution intents
- `*` — wildcard

`max_trade_atoms=0` or `daily_limit_atoms=0` means the agent cannot create a positive-size trading order. This is intentionally fail-safe.

## Native order state

A native order is written to:

`state/orders.db`

The transaction hash is used as the deterministic `order_id`.

Typical fields:

- owner
- agent
- kind=`native`
- market
- side
- order_type
- quantity_atoms
- limit_price_atoms
- status
- created_height
- updated_height
- order_expires_height
- last_tx

Initial native status is `open`.

`ORDER_CANCEL` changes it to `canceled`.

`ORDER_REPLACE` marks the previous order as `replaced` and creates a new deterministic order whose ID is the replacement transaction hash.

Native matching is deliberately **not active yet**.

## External trading intents

`EXTERNAL_ORDER` stores a signed execution intent on QRX with a venue such as `KRAKEN`.

Example state:

- kind=`external`
- venue=`KRAKEN`
- market=`BTC/EUR`
- status=`pending_execution`

A future QRX Execution Gateway will read this intent, submit the order to the external venue and report the result back with `EXECUTION_REPORT`.

No exchange API key or exchange custody logic is placed inside consensus.

## Usage limits

Daily agent usage is stored in:

`state/agent_usage.bin`

The "day" is deterministic and chain-derived rather than based on validator wall clocks. QRX derives a roughly 24-hour bucket from the current consensus `block_time_seconds` parameter.

Creating a native order, replacing a native order or creating an external order increases the usage counter by `quantity_atoms`.

Canceling an order does not increase usage.

## New backend commands

- `order-status <chain-dir> <order-id>`
- `list-orders <chain-dir> [owner-or-agent] [status]`
- `agent-limits <chain-dir> <agent-address>`
- `trading-info <chain-dir>`
- `create-order-raw-tx ...`
- `create-external-order-raw-tx ...`
- `create-order-cancel-raw-tx ...`
- `create-order-replace-raw-tx ...`

## New qrx-cli / RPC commands

- `getorder <order_id>`
- `listorders [owner_or_agent] [status]`
- `getagentlimits <agent>`
- `gettradinginfo`
- `createordertransaction ...`
- `createexternalordertransaction ...`
- `createordercanceltransaction ...`
- `createorderreplacetransaction ...`

The existing non-custodial raw transaction flow remains unchanged:

1. Build raw transaction.
2. Sign locally with the owner or agent wallet.
3. Verify locally if desired.
4. Broadcast using `sendrawtransaction`.

## Current limitations / intentional boundaries

Phase 3A does not yet:

- match native BUY and SELL orders,
- settle qBTC/qETH/qUSDT assets,
- execute orders against Kraken/Binance/etc.,
- accept `EXECUTION_REPORT`,
- execute atomic trading bundles,
- implement parallel execution,
- implement the VELOCITY memory mempool.

Those remain later VELOCITY phases.

## Fee behavior

At this stage, an agent-signed order pays the QRX transaction fee from the agent address. The agent therefore needs enough QUB to pay network fees. Owner-sponsored agent fees can be added later as a separate safe fee-sponsorship mechanism.
