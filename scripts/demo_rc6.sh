#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
export QRX_PASSPHRASE=testpass
rm -rf demo_rc6_runtime
mkdir demo_rc6_runtime
cd demo_rc6_runtime
$BIN seed-new alice
$BIN seed-new bob
ALICE="$($BIN address alice | tr -d '\n')"
BOB="$($BIN address bob | tr -d '\n')"
$BIN init-chain chain
$BIN faucet chain "$ALICE" 1000
$BIN faucet chain "$BOB" 500
$BIN stake chain alice 300
$BIN delegate chain bob "$ALICE" 200
$BIN reward-epoch chain 100 1000
$BIN slash chain "$ALICE" 50 double_sign
$BIN staking-status chain "$ALICE"
