#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${QRX_BIN:-$ROOT/build/qrx}"
WORK="$ROOT/test-output/sync"
rm -rf "$WORK"
mkdir -p "$WORK"
export QRX_PASSPHRASE=testpass
cd "$WORK"
"$BIN" seed-new alice >/dev/null
"$BIN" seed-new bob >/dev/null
"$BIN" init-chain chain >/dev/null
"$BIN" node-init node1 chain alice 127.0.0.1 7551 >/dev/null
"$BIN" node-init node2 chain bob 127.0.0.1 7552 >/dev/null
"$BIN" add-seed node2 127.0.0.1 7551 >/dev/null
"$BIN" discover-peers node2 >/dev/null
grep -q '127.0.0.1:7551' node2/peers.txt
echo "sync: ok"
