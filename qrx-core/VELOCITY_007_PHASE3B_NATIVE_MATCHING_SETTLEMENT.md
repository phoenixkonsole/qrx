# QRX Core 0.0.7 VELOCITY — Phase 3B

## Deterministic Native Matching & Settlement

Phase 3B turns Phase 3A native order intents into an executable deterministic order book for QRX-native assets. It also makes the stablecoin boundary explicit: QRX does **not** currently provide native USDT or USDC.

## USDT / USDC status

- `USDT`, `USDC`, `BTC`, `EUR`, etc. may appear in **external exchange market identifiers**, for example `BTC/USDT` on Kraken or another supported gateway. The external venue owns custody and settlement.
- QRX does **not** currently mint, bridge, custody, or represent real Tether USDT or Circle USDC on-chain.
- Native QRX matching only accepts assets registered in the QRX native asset ledger. `QUB` is built in.
- Phase 3B includes developer/regtest-only asset registration and credit helpers so matching/settlement can be tested without pretending those test assets are real stablecoins.
- The smoke test uses `TUSD` = **TestUSD**, a synthetic regtest asset. It is not USDT.
- A future bridge/issuer phase would be required before assets such as `qUSDC` or `qUSDT` could be honestly advertised as native QRX representations.

## Matching rule

Native orders are matched deterministically using:

1. Best price.
2. Earlier `created_height`.
3. Lexicographically smaller deterministic `order_id` as the final tie-break.

A BUY crosses a SELL when `sell_price <= buy_limit`.
A SELL crosses a BUY when `buy_price >= sell_limit`.

The execution price is the **maker's limit price**. Because every validator sees the same ordered state transition and uses the same comparison rules, the resulting fills and trade IDs are deterministic.

## Settlement model

Phase 3B adds a QRX-native multi-asset balance layer for settlement:

- `QUB` continues to use the existing canonical QUB balance state.
- Additional native assets use `state/asset_balances.bin`.
- Asset metadata uses `state/assets.db`.
- Trades use `state/trades.db`.
- Global deterministic fill sequencing uses `state/trade_sequence.bin`.

All Phase 3B native assets use 8 decimals and a fixed price scale of `100000000`.

Before a native order can enter the book, QRX reserves the required owner funds:

- SELL: reserve the base-asset quantity.
- BUY: reserve quote asset at the order's protection/limit price.

The trading agent signs the order, but the **owner's asset balance** provides settlement collateral. The AI agent therefore never needs custody of the owner's trading inventory.

When orders match, QRX transfers the base asset to the buyer and the quote asset to the seller, updates filled/remaining quantities, refunds unused BUY price-improvement collateral, and records the deterministic trade.

Cancellation releases remaining reserved collateral.

## MARKET orders

For Phase 3B a native `MARKET` order must still provide a positive `limit_price_atoms`. This acts as a protection price and gives consensus a deterministic maximum reserve. Unbounded market orders are deliberately not supported.

## Upgrade safety for Phase 3A orders

Old Phase 3A native orders did not reserve settlement assets. Phase 3B does **not** silently start settling them. Only orders carrying `settlement_version=1` participate in Phase 3B matching. This prevents an upgrade from unexpectedly spending funds for old intent-only orders.

## New read commands / RPC surface

- `gettrade <trade_id>`
- `listtrades [market] [limit]`
- `getorderbook <market> [depth]`
- `getassetbalance <asset> [address]`
- `listassets`

Backend-only regtest helpers:

- `asset-register <chain-dir> <asset> <name>`
- `asset-credit <chain-dir> <asset> <address> <amount>`

Those write helpers are restricted by the existing manual-mint protection and are not exposed as public wallet RPCs.

## Updated status

`gettradinginfo` / `getvelocityinfo` now report:

- `native_matching=true`
- `native_settlement=true`
- `native_asset_ledger=true`
- `native_stablecoins=false`
- `external_stablecoin_markets=true`

## Important durability boundary

Phase 3B provides deterministic consensus settlement semantics, but the current legacy file-state layer does not yet offer a single crash-atomic multi-key database transaction across every order, asset and trade write. `native_settlement_crash_atomic=false` is therefore reported explicitly. Crash-atomic batch commits belong in the later VELOCITY/QRXDB execution-engine phase before claiming production-grade exchange settlement.

## Tests

`tests/velocity_phase3b_matching.sh` verifies:

- native asset registration on regtest,
- owner collateral reservation,
- deterministic best-price matching,
- maker-price execution,
- base/quote settlement,
- BUY price-improvement refund,
- trade records,
- remaining order-book state,
- cancellation collateral release,
- native `QUB/USDT` rejection when USDT is not registered,
- external `BTC/USDT` acceptance as an exchange market identifier.

The previous Phase 3A smoke test was also updated to use a synthetic registered `TUSD` asset and still passes.
