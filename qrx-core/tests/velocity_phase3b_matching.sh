#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build-phase3b/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-phase3b.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" 20 5000 2100000000000000 25000000 1000000000 qrx-regtest 1 5152583036 QRX-Velocity-P3B >/dev/null

wallet_new(){ QRX_PASSPHRASE=test "$BIN" seed-new "$1" >/dev/null; }
wallet_info(){
  local W="$1" PREFIX="$2"
  eval "${PREFIX}_ADDR=\$(tr -d '\\r\\n' < '$W/address.txt')"
  eval "${PREFIX}_ED=\$(openssl pkey -pubin -in '$W/ed25519_pub.pem' -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \\n')"
  eval "${PREFIX}_ML=\$(base64 -w0 < '$W/mldsa65_pub.pem')"
}

wallet_new "$T/seller_owner"; wallet_new "$T/seller_agent"; wallet_new "$T/buyer_owner"; wallet_new "$T/buyer_agent"
wallet_info "$T/seller_owner" SO; wallet_info "$T/seller_agent" SA; wallet_info "$T/buyer_owner" BO; wallet_info "$T/buyer_agent" BA

# QUB funds owner registration + seller inventory + agent fees.
"$BIN" faucet "$T/chain" "$SO_ADDR" 500000000 >/dev/null
"$BIN" faucet "$T/chain" "$BO_ADDR" 10000000 >/dev/null
"$BIN" faucet "$T/chain" "$SA_ADDR" 10000000 >/dev/null
"$BIN" faucet "$T/chain" "$BA_ADDR" 10000000 >/dev/null

# TUSD is a synthetic REGTEST-only native asset. It is NOT Tether USDT.
"$BIN" asset-register "$T/chain" TUSD TestUSD >/dev/null
"$BIN" asset-credit "$T/chain" TUSD "$BO_ADDR" 500000000 >/dev/null

# Register trading agents. External BTC/USDT is allowed as a venue market identifier;
# USDT is deliberately NOT registered as a QRX-native settlement asset.
"$BIN" create-agent-register-raw-tx "$T/chain" "$SO_ADDR" "$SA_ADDR" "$SA_ED" "$SA_ML" 'TRADE,TRADE_EXTERNAL' 300000000 1000000000 'QUB/TUSD,BTC/USDT,QUB/USDT' 1000 "$SO_ED" "$SO_ML" 1 1000 > "$T/sareg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_owner" "$T/chain" "$T/sareg.raw" "$T/sareg.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/sareg.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/sareg.signed" >/dev/null

"$BIN" create-agent-register-raw-tx "$T/chain" "$BO_ADDR" "$BA_ADDR" "$BA_ED" "$BA_ML" 'TRADE,TRADE_EXTERNAL' 300000000 1000000000 'QUB/TUSD,BTC/USDT,QUB/USDT' 1000 "$BO_ED" "$BO_ML" 1 1000 > "$T/bareg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/bareg.raw" "$T/bareg.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/bareg.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/bareg.signed" >/dev/null

# Two asks: later 1.90 ask must match before earlier 2.00 ask (price priority).
"$BIN" create-order-raw-tx "$T/chain" "$SA_ADDR" "$SO_ADDR" QUB/TUSD SELL LIMIT 100000000 200000000 500 "$SA_ED" "$SA_ML" 2 500 > "$T/ask1.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_agent" "$T/chain" "$T/ask1.raw" "$T/ask1.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/ask1.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/ask1.signed" >/dev/null
ASK1="$($BIN txid "$T/chain" "$T/ask1.signed")"

"$BIN" create-order-raw-tx "$T/chain" "$SA_ADDR" "$SO_ADDR" QUB/TUSD SELL LIMIT 100000000 190000000 500 "$SA_ED" "$SA_ML" 2 500 > "$T/ask2.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_agent" "$T/chain" "$T/ask2.raw" "$T/ask2.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/ask2.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/ask2.signed" >/dev/null
ASK2="$($BIN txid "$T/chain" "$T/ask2.signed")"

BEFORE_TUSD="$($BIN asset-balance "$T/chain" TUSD "$BO_ADDR")"
BEFORE_QUB="$($BIN balance "$T/chain" "$BO_ADDR")"

# Buyer crosses both asks but only requests 1 QUB. It must fill ASK2 @ 1.90.
"$BIN" create-order-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" QUB/TUSD BUY LIMIT 100000000 250000000 500 "$BA_ED" "$BA_ML" 2 500 > "$T/bid.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/bid.raw" "$T/bid.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/bid.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/bid.signed" >/dev/null
BID="$($BIN txid "$T/chain" "$T/bid.signed")"

"$BIN" order-status "$T/chain" "$ASK1" | grep -q '^status=open$'
"$BIN" order-status "$T/chain" "$ASK2" | grep -q '^status=filled$'
"$BIN" order-status "$T/chain" "$BID" | grep -q '^status=filled$'
TID="$($BIN order-status "$T/chain" "$BID" | awk -F= '$1=="last_trade_id"{print $2}')"
[[ -n "$TID" ]]
"$BIN" trade-status "$T/chain" "$TID" | grep -q "^maker_order_id=$ASK2$"
"$BIN" trade-status "$T/chain" "$TID" | grep -q '^price_atoms=190000000$'
"$BIN" trade-status "$T/chain" "$TID" | grep -q '^quote_atoms=190000000$'
"$BIN" list-trades "$T/chain" QUB/TUSD 10 | grep -q "trade_id=$TID"

AFTER_TUSD="$($BIN asset-balance "$T/chain" TUSD "$BO_ADDR")"
AFTER_QUB="$($BIN balance "$T/chain" "$BO_ADDR")"
[[ $((BEFORE_TUSD-AFTER_TUSD)) -eq 190000000 ]]
[[ $((AFTER_QUB-BEFORE_QUB)) -eq 100000000 ]]
[[ "$($BIN asset-balance "$T/chain" TUSD "$SO_ADDR")" -eq 190000000 ]]

# Remaining ASK1 is still reserved and visible in the deterministic book.
"$BIN" orderbook "$T/chain" QUB/TUSD 10 | grep -q "order_id=$ASK1"

# Native QUB/USDT must fail: USDT is not a registered native QRX asset.
"$BIN" create-order-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" QUB/USDT BUY LIMIT 1000000 100000000 500 "$BA_ED" "$BA_ML" 3 500 > "$T/native-usdt.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/native-usdt.raw" "$T/native-usdt.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/native-usdt.signed" >/dev/null 2>&1; then echo "native unregistered USDT negative test failed" >&2; exit 1; fi

# External BTC/USDT remains valid because settlement belongs to the external venue.
"$BIN" create-external-order-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" KRAKEN BTC/USDT BUY LIMIT 1000000 6500000000000 500 "$BA_ED" "$BA_ML" 3 500 > "$T/ext-usdt.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/ext-usdt.raw" "$T/ext-usdt.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/ext-usdt.signed" >/dev/null

# Cancel ASK1 and verify its QUB reserve is returned.
LOCKED="$($BIN order-status "$T/chain" "$ASK1" | awk -F= '$1=="locked_atoms"{print $2}')"; [[ "$LOCKED" -eq 100000000 ]]
"$BIN" create-order-cancel-raw-tx "$T/chain" "$SA_ADDR" "$SO_ADDR" "$ASK1" "$SA_ED" "$SA_ML" 2 500 > "$T/cancel.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_agent" "$T/chain" "$T/cancel.raw" "$T/cancel.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/cancel.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/cancel.signed" >/dev/null
"$BIN" order-status "$T/chain" "$ASK1" | grep -q '^locked_atoms=0$'
"$BIN" order-status "$T/chain" "$ASK1" | grep -q '^status=canceled$'

"$BIN" trading-info "$T/chain" | grep -q '^native_matching=true$'
"$BIN" trading-info "$T/chain" | grep -q '^native_stablecoins=false$'
echo "VELOCITY Phase 3B deterministic matching + settlement smoke test PASSED"
