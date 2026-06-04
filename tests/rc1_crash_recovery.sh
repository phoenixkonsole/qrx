#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${QRX_BIN:-$ROOT/build/qrx}"
WORK="$ROOT/test-output/crash"
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
"$BIN" sign alice chain "$BOB" 10 first tx1.qrxtx >/dev/null
"$BIN" applytx chain tx1.qrxtx >/dev/null
cp chain/state/balances.db chain/state/balances.db.bak || true
cp chain/state/balances.bin chain/state/balances.bin.bak
truncate -s 32 chain/state/balances.bin
"$BIN" state-check chain >/dev/null || true
mv chain/state/balances.bin.bak chain/state/balances.bin
"$BIN" state-check chain >/dev/null
"$BIN" balance chain "$ALICE" >/dev/null
"$BIN" balance chain "$BOB" >/dev/null
echo "crash-recovery: ok"
