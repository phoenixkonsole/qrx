#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build-phase3d/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-phase3d.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" 20 5000 2100000000000000 25000000 1000000000000 qrx-regtest 1 5152583036 QRX-Velocity-P3D >/dev/null

wallet_new(){ QRX_PASSPHRASE=test "$BIN" seed-new "$1" >/dev/null; }
wallet_info(){
  local W="$1" PREFIX="$2"
  eval "${PREFIX}_ADDR=\$(tr -d '\\r\\n' < '$W/address.txt')"
  eval "${PREFIX}_ED=\$(openssl pkey -pubin -in '$W/ed25519_pub.pem' -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \\n')"
  eval "${PREFIX}_ML=\$(base64 -w0 < '$W/mldsa65_pub.pem')"
}
btc_pub_new(){
  local PREFIX="$1"
  openssl ecparam -name secp256k1 -genkey -noout -out "$T/${PREFIX}.btc.pem" 2>/dev/null
  local PUB
  PUB="$(openssl ec -in "$T/${PREFIX}.btc.pem" -pubout -conv_form compressed -outform DER 2>/dev/null | tail -c 33 | od -An -tx1 | tr -d ' \n')"
  eval "${PREFIX}_BTC_PUB='$PUB'"
}

wallet_new "$T/seller_owner"; wallet_new "$T/seller_agent"; wallet_new "$T/buyer_owner"; wallet_new "$T/buyer_agent"
wallet_info "$T/seller_owner" SO; wallet_info "$T/seller_agent" SA; wallet_info "$T/buyer_owner" BO; wallet_info "$T/buyer_agent" BA
btc_pub_new BUYER; btc_pub_new SELLER

# Funding: BTC is deliberately NOT minted on QRX. Only the QUB side exists here.
"$BIN" faucet "$T/chain" "$BO_ADDR" 20000000000 >/dev/null
"$BIN" faucet "$T/chain" "$SO_ADDR" 10000000 >/dev/null
"$BIN" faucet "$T/chain" "$BA_ADDR" 10000000 >/dev/null
"$BIN" faucet "$T/chain" "$SA_ADDR" 10000000 >/dev/null

# Agent authorization is on-chain. The agents may trade only BTC/QUB cross-chain.
"$BIN" create-agent-register-raw-tx "$T/chain" "$BO_ADDR" "$BA_ADDR" "$BA_ED" "$BA_ML" 'TRADE_CROSSCHAIN' 1000000 5000000 'BTC/QUB' 3000 "$BO_ED" "$BO_ML" 1 3000 > "$T/bareg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/bareg.raw" "$T/bareg.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/bareg.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/bareg.signed" >/dev/null
"$BIN" create-agent-register-raw-tx "$T/chain" "$SO_ADDR" "$SA_ADDR" "$SA_ED" "$SA_ML" 'TRADE_CROSSCHAIN' 1000000 5000000 'BTC/QUB' 3000 "$SO_ED" "$SO_ML" 1 3000 > "$T/sareg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_owner" "$T/chain" "$T/sareg.raw" "$T/sareg.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/sareg.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/sareg.signed" >/dev/null

# Check the deterministic Bitcoin P2WSH HTLC template on all Bitcoin networks.
SECRET=616263
HASH="$(printf 'abc' | openssl dgst -sha256 | awk '{print $NF}')"
"$BIN" btc-htlc-template "$HASH" "$BUYER_BTC_PUB" "$SELLER_BTC_PUB" 6 mainnet > "$T/htlc-main"
"$BIN" btc-htlc-template "$HASH" "$BUYER_BTC_PUB" "$SELLER_BTC_PUB" 6 testnet > "$T/htlc-test"
"$BIN" btc-htlc-template "$HASH" "$BUYER_BTC_PUB" "$SELLER_BTC_PUB" 6 regtest > "$T/htlc-reg"
grep -q '^p2wsh_address=bc1' "$T/htlc-main"
grep -q '^p2wsh_address=tb1' "$T/htlc-test"
grep -q '^p2wsh_address=bcrt1' "$T/htlc-reg"

# Unmatched BUY: QUB is reserved and a normal ORDER_CANCEL must return it atomically.
BO_BEFORE_CANCEL="$($BIN balance "$T/chain" "$BO_ADDR")"
"$BIN" create-crosschain-buy-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" 50000 5000000000000 400 "$HASH" "$BUYER_BTC_PUB" 900 "$BA_ED" "$BA_ML" 2 1200 0 > "$T/cbuy.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/cbuy.raw" "$T/cbuy.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/cbuy.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/cbuy.signed" >/dev/null
CBUY="$($BIN txid "$T/chain" "$T/cbuy.signed")"
LOCKED="$($BIN order-status "$T/chain" "$CBUY" | awk -F= '$1=="locked_atoms"{print $2}')"; [[ "$LOCKED" -gt 0 ]]
"$BIN" create-order-cancel-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" "$CBUY" "$BA_ED" "$BA_ML" 2 1200 0 > "$T/cancel.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/cancel.raw" "$T/cancel.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/cancel.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/cancel.signed" >/dev/null
grep -q '^status=canceled$' < <("$BIN" order-status "$T/chain" "$CBUY")
[[ "$($BIN balance "$T/chain" "$BO_ADDR")" -eq "$BO_BEFORE_CANCEL" ]]

# Exact-fill BTC/QUB match. Seller is maker: execution uses seller maker price.
SATS=100000
SELL_PRICE=4800000000000
BUY_LIMIT=5000000000000
# 6 BTC blocks ~3600 sec plus 1h QRX safety => qrx refund must be >=720 QRX blocks away at 10 sec policy.
QREFUND=1000
"$BIN" create-crosschain-sell-raw-tx "$T/chain" "$SA_ADDR" "$SO_ADDR" "$SATS" "$SELL_PRICE" 500 "$SELLER_BTC_PUB" 6 "$SA_ED" "$SA_ML" 3 1500 0 > "$T/sell.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_agent" "$T/chain" "$T/sell.raw" "$T/sell.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/sell.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/sell.signed" >/dev/null
SELL_ID="$($BIN txid "$T/chain" "$T/sell.signed")"

BO_PRE_MATCH="$($BIN balance "$T/chain" "$BO_ADDR")"
"$BIN" create-crosschain-buy-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" "$SATS" "$BUY_LIMIT" 500 "$HASH" "$BUYER_BTC_PUB" "$QREFUND" "$BA_ED" "$BA_ML" 3 1500 0 > "$T/buy.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/buy.raw" "$T/buy.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/buy.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/buy.signed" >/dev/null
BUY_ID="$($BIN txid "$T/chain" "$T/buy.signed")"
SID="$($BIN order-status "$T/chain" "$BUY_ID" | awk -F= '$1=="crosschain_session_id"{print $2}')"
[[ -n "$SID" ]]
"$BIN" order-status "$T/chain" "$SELL_ID" > "$T/sell.status"
"$BIN" order-status "$T/chain" "$BUY_ID" > "$T/buy.status"
grep -q '^status=matched$' "$T/sell.status"; grep -q '^status=matched$' "$T/buy.status"
"$BIN" crosschain-status "$T/chain" "$SID" > "$T/session"
grep -q '^status=awaiting_btc_funding$' "$T/session"
grep -q '^settlement_model=HTLC_SHA256_P2WSH_CSV_SPV$' "$T/session"
grep -q '^bitcoin_spv_verified=false$' "$T/session"
grep -q '^btc_p2wsh_mainnet=bc1' "$T/session"
grep -q '^btc_p2wsh_regtest=bcrt1' "$T/session"
QUB_LOCKED="$($BIN crosschain-status "$T/chain" "$SID" | awk -F= '$1=="qub_atoms"{print $2}')"
[[ "$QUB_LOCKED" -eq 4800000000 ]]
# Buyer max reserve was 5,000,000,000 atoms; matching returns 200,000,000 atoms price improvement.
[[ $((BO_PRE_MATCH-$($BIN balance "$T/chain" "$BO_ADDR"))) -eq "$QUB_LOCKED" ]]

# Early QUB refund must be rejected.
"$BIN" create-crosschain-refund-raw-tx "$T/chain" "$BO_ADDR" "$SID" "$BO_ED" "$BO_ML" 4 1500 0 > "$T/early-refund.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/early-refund.raw" "$T/early-refund.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/early-refund.signed" >/dev/null 2>&1; then echo "early cross-chain refund negative test failed" >&2; exit 1; fi

# Phase 3D.1 hardening: knowing the preimage is no longer enough. Until a
# consensus-committed Bitcoin SPV funding proof reaches the required depth,
# QRX must refuse release of the QUB leg. The dedicated 3D.1 test proves the
# positive SPV/reorg/redeem path end-to-end.
"$BIN" create-crosschain-redeem-raw-tx "$T/chain" "$SO_ADDR" "$SID" "$SECRET" "$SO_ED" "$SO_ML" 4 1500 0 > "$T/redeem.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_owner" "$T/chain" "$T/redeem.raw" "$T/redeem.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/redeem.signed" >/dev/null 2>&1; then echo "cross-chain redeem unexpectedly valid without Bitcoin SPV proof" >&2; exit 1; fi
grep -q '^status=awaiting_btc_funding$' < <("$BIN" crosschain-status "$T/chain" "$SID")

# Refund path: create a second matched session, advance deterministic QRX height, then refund buyer.
SECRET2=646566
HASH2="$(printf 'def' | openssl dgst -sha256 | awk '{print $NF}')"
"$BIN" create-crosschain-sell-raw-tx "$T/chain" "$SA_ADDR" "$SO_ADDR" 60000 "$SELL_PRICE" 400 "$SELLER_BTC_PUB" 1 "$SA_ED" "$SA_ML" 5 1800 0 > "$T/sell2.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_agent" "$T/chain" "$T/sell2.raw" "$T/sell2.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/sell2.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/sell2.signed" >/dev/null
"$BIN" create-crosschain-buy-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" 60000 "$BUY_LIMIT" 400 "$HASH2" "$BUYER_BTC_PUB" 500 "$BA_ED" "$BA_ML" 5 1800 0 > "$T/buy2.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/buy2.raw" "$T/buy2.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/buy2.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/buy2.signed" >/dev/null
BUY2="$($BIN txid "$T/chain" "$T/buy2.signed")"; SID2="$($BIN order-status "$T/chain" "$BUY2" | awk -F= '$1=="crosschain_session_id"{print $2}')"; [[ -n "$SID2" ]]
LOCK2="$($BIN crosschain-status "$T/chain" "$SID2" | awk -F= '$1=="qrx_locked_atoms"{print $2}')"
# Tests only: current_height_from_chain counts regular block files. We do not fabricate this in production.
mkdir -p "$T/chain/blocks"; for i in $(seq -w 1 500); do : > "$T/chain/blocks/test-$i.blk"; done
BO_BEFORE_REFUND="$($BIN balance "$T/chain" "$BO_ADDR")"
"$BIN" create-crosschain-refund-raw-tx "$T/chain" "$BO_ADDR" "$SID2" "$BO_ED" "$BO_ML" 6 1800 0 > "$T/refund.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/refund.raw" "$T/refund.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/refund.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/refund.signed" >/dev/null
"$BIN" crosschain-status "$T/chain" "$SID2" > "$T/refunded"
grep -q '^status=refunded$' "$T/refunded"; grep -q '^qrx_locked_atoms=0$' "$T/refunded"
[[ $(( $($BIN balance "$T/chain" "$BO_ADDR") - BO_BEFORE_REFUND )) -eq "$LOCK2" ]]

"$BIN" crosschain-info "$T/chain" | grep -q '^qbtc_used=false$'
"$BIN" crosschain-info "$T/chain" | grep -q '^bitcoin_spv_consensus=true$'
"$BIN" trading-info "$T/chain" | grep -q '^crosschain_market=BTC/QUB$'
"$BIN" velocity-info "$T/chain" | grep -q '^crosschain_trading=true$'

echo "VELOCITY Phase 3D BTC/QUB cross-chain trading settlement smoke test PASSED"
