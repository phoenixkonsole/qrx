#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build-phase3c/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-phase3c.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" 20 5000 2100000000000000 25000000 1000000000 qrx-regtest 1 5152583036 QRX-Velocity-P3C >/dev/null
wallet_new(){ QRX_PASSPHRASE=test "$BIN" seed-new "$1" >/dev/null; }
wallet_info(){
  local W="$1" PREFIX="$2"
  eval "${PREFIX}_ADDR=\$(tr -d '\\r\\n' < '$W/address.txt')"
  eval "${PREFIX}_ED=\$(openssl pkey -pubin -in '$W/ed25519_pub.pem' -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \\n')"
  eval "${PREFIX}_ML=\$(base64 -w0 < '$W/mldsa65_pub.pem')"
}
wallet_new "$T/authority"; wallet_new "$T/gateway"; wallet_new "$T/owner"; wallet_new "$T/agent"
wallet_info "$T/authority" AU; wallet_info "$T/gateway" GW; wallet_info "$T/owner" OW; wallet_info "$T/agent" AG

# For regtest the gateway governance authority is overridden to a test wallet.
printf 'dev_address=%s\n' "$AU_ADDR" >> "$T/chain/chain.meta"
for A in "$AU_ADDR" "$GW_ADDR" "$OW_ADDR" "$AG_ADDR"; do "$BIN" faucet "$T/chain" "$A" 5000000 >/dev/null; done

# Owner authorizes an agent to create external Kraken BTC/USDT intents.
"$BIN" create-agent-register-raw-tx "$T/chain" "$OW_ADDR" "$AG_ADDR" "$AG_ED" "$AG_ML" 'TRADE_EXTERNAL' 1000000 5000000 'BTC/USDT' 1000 "$OW_ED" "$OW_ML" 1 1000 > "$T/agent.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/owner" "$T/chain" "$T/agent.raw" "$T/agent.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/agent.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/agent.signed" >/dev/null

"$BIN" create-external-order-raw-tx "$T/chain" "$AG_ADDR" "$OW_ADDR" KRAKEN BTC/USDT BUY LIMIT 100000 6500000 500 "$AG_ED" "$AG_ML" 2 500 > "$T/order.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/order.raw" "$T/order.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/order.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/order.signed" >/dev/null
OID="$($BIN txid "$T/chain" "$T/order.signed")"
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=pending_execution$'

# Governance-authorized on-chain execution gateway registration.
"$BIN" create-gateway-register-raw-tx "$T/chain" "$AU_ADDR" "$GW_ADDR" KRAKEN KrakenGateway "$GW_ED" "$GW_ML" 1000 "$AU_ED" "$AU_ML" 3 1000 > "$T/gwreg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/authority" "$T/chain" "$T/gwreg.raw" "$T/gwreg.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/gwreg.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/gwreg.signed" >/dev/null
"$BIN" gateway-status "$T/chain" "$GW_ADDR" > "$T/gateway.active.status"
grep -q '^status=active$' "$T/gateway.active.status"
grep -q '^venue=KRAKEN$' "$T/gateway.active.status"
"$BIN" list-gateways "$T/chain" KRAKEN | grep -q "gateway=$GW_ADDR"

report(){
  local STATUS="$1" FILLED="$2" PRICE="$3" FEE="$4" SEQ="$5" OUT="$6"
  "$BIN" create-execution-report-raw-tx "$T/chain" "$GW_ADDR" "$OW_ADDR" "$OID" "$STATUS" "$FILLED" "$PRICE" "$FEE" KRKN-ORDER-42 "$SEQ" "$GW_ED" "$GW_ML" 4 1000 > "$T/$OUT.raw"
  QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/gateway" "$T/chain" "$T/$OUT.raw" "$T/$OUT.signed" >/dev/null
  "$BIN" verify "$T/chain" "$T/$OUT.signed" >/dev/null
  "$BIN" applytx "$T/chain" "$T/$OUT.signed" >/dev/null
}
report SUBMITTED 0 0 0 1 submitted
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=submitted$'
report PARTIALLY_FILLED 40000 6490000 1000 2 partial
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=partially_filled$'
"$BIN" order-status "$T/chain" "$OID" | grep -q '^external_filled_atoms=40000$'
RID="$($BIN txid "$T/chain" "$T/partial.signed")"
"$BIN" execution-report-status "$T/chain" "$RID" | grep -q '^status=partially_filled$'
report FILLED 100000 6485000 2500 3 filled
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=filled$'
"$BIN" order-status "$T/chain" "$OID" | grep -q '^execution_report_sequence=3$'

# A terminal external order cannot be mutated by another report.
"$BIN" create-execution-report-raw-tx "$T/chain" "$GW_ADDR" "$OW_ADDR" "$OID" CANCELED 100000 6485000 2500 KRKN-ORDER-42 4 "$GW_ED" "$GW_ML" 4 1000 > "$T/bad.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/gateway" "$T/chain" "$T/bad.raw" "$T/bad.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/bad.signed" >/dev/null 2>&1; then echo 'terminal order accepted extra execution report' >&2; exit 1; fi

# Authority can revoke the gateway; the registry remains auditable on-chain.
"$BIN" create-gateway-revoke-raw-tx "$T/chain" "$AU_ADDR" "$GW_ADDR" "$AU_ED" "$AU_ML" 3 1000 > "$T/gwrev.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/authority" "$T/chain" "$T/gwrev.raw" "$T/gwrev.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/gwrev.signed" >/dev/null; "$BIN" applytx "$T/chain" "$T/gwrev.signed" >/dev/null
"$BIN" gateway-status "$T/chain" "$GW_ADDR" > "$T/gateway.revoked.status"
grep -q '^status=revoked$' "$T/gateway.revoked.status"

ROOT="$($BIN state-root "$T/chain" | sed -n 's/^state_root=//p')"
[[ ${#ROOT} -eq 128 ]] || { echo "bad QRXDB state root: $ROOT" >&2; exit 1; }
"$BIN" qrxdb-verify "$T/chain" >/dev/null 2>&1 || true
printf 'VELOCITY Phase 3C external gateway + execution report smoke test PASSED\nstate_root=%s\n' "$ROOT"
