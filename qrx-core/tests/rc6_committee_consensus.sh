#!/usr/bin/env bash
set -euo pipefail
BIN=${1:-./build/qrx}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export QRX_PASSPHRASE=testpass
$BIN init-chain "$WORK/chain" 20 5000 >/dev/null
$BIN seed-new "$WORK/alice" >/dev/null
$BIN seed-new "$WORK/bob" >/dev/null
ALICE=$($BIN address "$WORK/alice")
BOB=$($BIN address "$WORK/bob")
$BIN faucet "$WORK/chain" "$ALICE" 1000 >/dev/null
$BIN faucet "$WORK/chain" "$BOB" 1000 >/dev/null
$BIN stake "$WORK/chain" "$WORK/alice" 400 >/dev/null
$BIN stake "$WORK/chain" "$WORK/bob" 300 >/dev/null
$BIN node-init "$WORK/node1" "$WORK/chain" "$WORK/alice" 127.0.0.1 7601 >/dev/null
$BIN node-init "$WORK/node2" "$WORK/chain" "$WORK/bob" 127.0.0.1 7602 >/dev/null
BLOCK=$($BIN propose-block "$WORK/node1" | tail -n1)
$BIN verify-block "$WORK/chain" "$BLOCK" >/dev/null
V1=$($BIN vote-block "$WORK/node1" "$BLOCK" | tail -n1)
V2=$($BIN vote-block "$WORK/node2" "$BLOCK" | tail -n1)
cp "$V1" "$WORK/chain/consensus/votes/"
cp "$V2" "$WORK/chain/consensus/votes/"
$BIN tally-votes "$WORK/chain" "$BLOCK" | grep -q 'quorum=1'
FINAL=$($BIN finalize-block "$WORK/chain" "$BLOCK" | tail -n1)
test -f "$FINAL"
echo "rc6_committee_consensus: OK"
