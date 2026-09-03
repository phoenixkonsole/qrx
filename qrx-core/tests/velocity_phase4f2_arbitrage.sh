#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-phase4f2.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" >/dev/null
mkdir -p "$T/node"
"$BIN" history "$T/chain" "" all >/dev/null
"$BIN" list-trades "$T/chain" '*' all 1 2 >/dev/null

INFO="$("$BIN" velocity-engine-info "$T/node")"
grep -q '^phase=4F.2$' <<<"$INFO"
grep -q '^cross_venue_arbitrage=true$' <<<"$INFO"
grep -q '^paper_trading=true$' <<<"$INFO"
grep -q '^complete_csv_ledger=true$' <<<"$INFO"
grep -q '^arbitrage_hedge_tif=IOC$' <<<"$INFO"

TRADING="$("$BIN" trading-info "$T/chain")"
grep -q '^arbitrage_live_requires_confirmation=true$' <<<"$TRADING"
grep -q 'ARBITRAGE_CROSS_VENUE' <<<"$TRADING"

RAW="$("$BIN" create-arbitrage-hedge-raw-tx "$T/chain" agent1 owner1 matched-buy-1 arb_test 100000 7990000000000 100 aa bb 0 100)"
grep -q '^tx_type=EXTERNAL_ORDER$' <<<"$RAW"
grep -q 'venue=KRAKEN;market=BTC/EUR;side=SELL;order_type=LIMIT' <<<"$RAW"
grep -q 'time_in_force=IOC' <<<"$RAW"
grep -q 'arbitrage_id=arb_test' <<<"$RAW"
grep -q 'source_order_id=matched-buy-1' <<<"$RAW"

echo "VELOCITY Phase 4F.2 arbitrage schema, feature flags and IOC raw transaction PASSED"
