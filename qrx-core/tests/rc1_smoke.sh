#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${QRX_BIN:-$ROOT/build/qrx}"
WORK="$ROOT/test-output/smoke"
rm -rf "$WORK"
mkdir -p "$WORK"
export QRX_PASSPHRASE=testpass
cd "$WORK"
"$BIN" seed-new alice >/dev/null
"$BIN" seed-new bob >/dev/null
ALICE=$("$BIN" address alice | tr -d '\n')
BOB=$("$BIN" address bob | tr -d '\n')
"$BIN" init-chain chain >/dev/null
"$BIN" faucet chain "$ALICE" 1000 >/dev/null
"$BIN" sign alice chain "$BOB" 25 hello tx1.qrxtx >/dev/null
"$BIN" verify chain tx1.qrxtx >/dev/null
"$BIN" applytx chain tx1.qrxtx >/dev/null
A=$("$BIN" balance chain "$ALICE" | tail -n1 | tr -d '\r')
B=$("$BIN" balance chain "$BOB" | tail -n1 | tr -d '\r')
[[ "$A" == "975" ]]
[[ "$B" == "25" ]]
echo "smoke: ok"
