#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-phase3a.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" 20 5000 2100000000000000 25000000 1000000000 qrx-regtest 1 5152583036 QRX-Velocity-Test >/dev/null
QRX_PASSPHRASE=test "$BIN" seed-new "$T/owner" >/dev/null
QRX_PASSPHRASE=test "$BIN" seed-new "$T/agent" >/dev/null
OWNER="$(tr -d '\r\n' < "$T/owner/address.txt")"
AGENT="$(tr -d '\r\n' < "$T/agent/address.txt")"
OWNER_ED="$(openssl pkey -pubin -in "$T/owner/ed25519_pub.pem" -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n')"
AGENT_ED="$(openssl pkey -pubin -in "$T/agent/ed25519_pub.pem" -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n')"
OWNER_ML="$(base64 -w0 < "$T/owner/mldsa65_pub.pem")"
AGENT_ML="$(base64 -w0 < "$T/agent/mldsa65_pub.pem")"
"$BIN" faucet "$T/chain" "$OWNER" 1000000 >/dev/null
"$BIN" faucet "$T/chain" "$AGENT" 1000000 >/dev/null
"$BIN" asset-register "$T/chain" TUSD TestUSD >/dev/null
"$BIN" asset-credit "$T/chain" TUSD "$OWNER" 1000000000 >/dev/null

"$BIN" create-agent-register-raw-tx "$T/chain" "$OWNER" "$AGENT" "$AGENT_ED" "$AGENT_ML" 'TRADE,TRADE_EXTERNAL' 100000 500000 'QUB/TUSD,BTC/EUR' 1000 "$OWNER_ED" "$OWNER_ML" 1 1000 > "$T/register.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/owner" "$T/chain" "$T/register.raw" "$T/register.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/register.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/register.signed" >/dev/null

"$BIN" create-order-raw-tx "$T/chain" "$AGENT" "$OWNER" QUB/TUSD BUY LIMIT 10000 100000000 500 "$AGENT_ED" "$AGENT_ML" 2 500 > "$T/order.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/order.raw" "$T/order.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/order.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/order.signed" >/dev/null
OID="$("$BIN" txid "$T/chain" "$T/order.signed")"
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=open$'

"$BIN" create-order-cancel-raw-tx "$T/chain" "$AGENT" "$OWNER" "$OID" "$AGENT_ED" "$AGENT_ML" 2 500 > "$T/cancel.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/cancel.raw" "$T/cancel.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/cancel.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/cancel.signed" >/dev/null
"$BIN" order-status "$T/chain" "$OID" | grep -q '^status=canceled$'

"$BIN" create-external-order-raw-tx "$T/chain" "$AGENT" "$OWNER" KRAKEN BTC/EUR BUY LIMIT 20000 6500000 500 "$AGENT_ED" "$AGENT_ML" 3 500 > "$T/ext.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/ext.raw" "$T/ext.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/ext.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/ext.signed" >/dev/null
EOID="$("$BIN" txid "$T/chain" "$T/ext.signed")"
"$BIN" order-status "$T/chain" "$EOID" | grep -q '^status=pending_execution$'
"$BIN" agent-limits "$T/chain" "$AGENT" | grep -q '^usage_atoms=30000$'

# Negative controls: max trade and market allowlist must reject.
"$BIN" create-order-raw-tx "$T/chain" "$AGENT" "$OWNER" QUB/TUSD BUY LIMIT 100001 100000000 500 "$AGENT_ED" "$AGENT_ML" 4 500 > "$T/toobig.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/toobig.raw" "$T/toobig.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/toobig.signed" >/dev/null 2>&1; then echo "max_trade negative test failed" >&2; exit 1; fi
"$BIN" create-order-raw-tx "$T/chain" "$AGENT" "$OWNER" ETH/USD BUY LIMIT 1000 1200 500 "$AGENT_ED" "$AGENT_ML" 4 500 > "$T/badmarket.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/agent" "$T/chain" "$T/badmarket.raw" "$T/badmarket.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/badmarket.signed" >/dev/null 2>&1; then echo "market allowlist negative test failed" >&2; exit 1; fi

echo "VELOCITY Phase 3A trading smoke test PASSED"
