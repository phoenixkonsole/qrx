#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-kraken-cancel.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" 20 5000 2100000000000000 25000000 1000000000 qrx-regtest 1 5152583036 QRX-Kraken-Cancel >/dev/null
wallet_new(){ QRX_PASSPHRASE=test "$BIN" seed-new "$1" >/dev/null; }
wallet_info(){
  local W="$1" PREFIX="$2"
  eval "${PREFIX}_ADDR=\$(tr -d '\\r\\n' < '$W/address.txt')"
  eval "${PREFIX}_ED=\$(openssl pkey -pubin -in '$W/ed25519_pub.pem' -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \\n')"
  eval "${PREFIX}_ML=\$(base64 -w0 < '$W/mldsa65_pub.pem')"
}
wallet_new "$T/authority"; wallet_new "$T/gateway"; wallet_new "$T/owner"; wallet_new "$T/agent"
wallet_info "$T/authority" AU; wallet_info "$T/gateway" GW; wallet_info "$T/owner" OW; wallet_info "$T/agent" AG
printf 'dev_address=%s\n' "$AU_ADDR" >> "$T/chain/chain.meta"
for A in "$AU_ADDR" "$GW_ADDR" "$OW_ADDR" "$AG_ADDR"; do "$BIN" faucet "$T/chain" "$A" 5000000 >/dev/null; done

"$BIN" create-agent-register-raw-tx "$T/chain" "$OW_ADDR" "$AG_ADDR" "$AG_ED" "$AG_ML" 'TRADE_EXTERNAL' 1000000 5000000 'BTC/EUR' 1000 "$OW_ED" "$OW_ML" 1 1000 > "$T/agent.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/owner" "$T/chain" "$T/agent.raw" "$T/agent.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/agent.signed" >/dev/null

"$BIN" create-gateway-register-raw-tx "$T/chain" "$AU_ADDR" "$GW_ADDR" KRAKEN KrakenGateway "$GW_ED" "$GW_ML" 1000 "$AU_ED" "$AU_ML" 3 1000 > "$T/gw.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/authority" "$T/chain" "$T/gw.raw" "$T/gw.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/gw.signed" >/dev/null

"$BIN" create-external-order-raw-tx "$T/chain" "$AG_ADDR" "$OW_ADDR" KRAKEN BTC/EUR BUY LIMIT 100000 6500000 500 "$AG_ED" "$AG_ML" 2 500 > "$T/order.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/order.raw" "$T/order.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/order.signed" >/dev/null
OID="$("$BIN" txid "$T/chain" "$T/order.signed")"

# Kraken gateway confirms the live venue order first.
"$BIN" create-execution-report-raw-tx "$T/chain" "$GW_ADDR" "$OW_ADDR" "$OID" SUBMITTED 0 0 0 KRAKEN-TX-1 1 "$GW_ED" "$GW_ML" 4 1000 > "$T/sub.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/gateway" "$T/chain" "$T/sub.raw" "$T/sub.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/sub.signed" >/dev/null
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=submitted$'

# Owner/agent requests cancellation. External venue state must NOT be declared
# canceled until Kraken confirms it via an authenticated gateway report.
"$BIN" create-order-cancel-raw-tx "$T/chain" "$AG_ADDR" "$OW_ADDR" "$OID" "$AG_ED" "$AG_ML" 2 1000 > "$T/cancel.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/cancel.raw" "$T/cancel.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/cancel.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/cancel.signed" >/dev/null
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=cancel_pending$'
"$BIN" order-status "$T/chain" "$OID" | grep -q '^execution_report_sequence=1$'

# Only the Kraken gateway confirmation makes the cancellation terminal.
"$BIN" create-execution-report-raw-tx "$T/chain" "$GW_ADDR" "$OW_ADDR" "$OID" CANCELED 0 0 0 KRAKEN-TX-1 2 "$GW_ED" "$GW_ML" 4 1000 > "$T/canceled.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/gateway" "$T/chain" "$T/canceled.raw" "$T/canceled.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/canceled.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/canceled.signed" >/dev/null
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=canceled$'
"$BIN" order-status "$T/chain" "$OID" | grep -q '^execution_report_sequence=2$'

ROOT="$("$BIN" state-root "$T/chain" | sed -n 's/^state_root=//p')"
[[ ${#ROOT} -eq 128 ]] || { echo "bad state root: $ROOT" >&2; exit 1; }
printf 'Kraken external cancel_pending -> gateway CANCELED integration test PASSED\nstate_root=%s\n' "$ROOT"
