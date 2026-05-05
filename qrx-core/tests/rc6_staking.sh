#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"
export QRX_PASSPHRASE=testpass
$BIN seed-new alice >/dev/null
$BIN seed-new bob >/dev/null
ALICE="$($BIN address alice | tr -d '\n')"
BOB="$($BIN address bob | tr -d '\n')"
$BIN init-chain chain >/dev/null
$BIN faucet chain "$ALICE" 1000 >/dev/null
$BIN faucet chain "$BOB" 500 >/dev/null
$BIN stake chain alice 300 | tee out1.txt
$BIN delegate chain bob "$ALICE" 200 | tee out2.txt
$BIN reward-epoch chain 100 1000 | tee out3.txt
$BIN slash chain "$ALICE" 50 double_sign | tee out4.txt
$BIN staking-status chain "$ALICE" | tee out5.txt
grep -q 'self_stake=270' out5.txt
grep -q 'delegated_to_me=180' out5.txt
echo 'rc6_staking: OK'
