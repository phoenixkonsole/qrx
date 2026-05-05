#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"
export QRX_PASSPHRASE=testpass
$BIN seed-new alice >/dev/null
ALICE="$($BIN address alice | tr -d '\n')"
$BIN init-chain chain >/dev/null
$BIN faucet chain "$ALICE" 1000 >/dev/null
$BIN stake chain alice 400 >/dev/null
$BIN node-init node1 chain alice 127.0.0.1 7201 >/dev/null
BLOCK="$($BIN propose-block node1 1 | tail -n1)"
$BIN verify-block chain "$BLOCK" >/dev/null
echo 'rc6_blockflow: OK'
