#!/usr/bin/env bash
set -euo pipefail
BIN=${1:?bin}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export QRX_PASSPHRASE=testpass
$BIN init-chain "$WORK/chain" 20 5000 >/dev/null
$BIN seed-new "$WORK/alice" >/dev/null
$BIN seed-new "$WORK/bob" >/dev/null
A=$($BIN address "$WORK/alice")
B=$($BIN address "$WORK/bob")
$BIN faucet "$WORK/chain" "$A" 1000 >/dev/null
$BIN stake "$WORK/chain" "$WORK/alice" 300 >/dev/null
$BIN node-init "$WORK/node1" "$WORK/chain" "$WORK/alice" 127.0.0.1 7701 >/dev/null
$BIN node-init "$WORK/node2" "$WORK/chain" "$WORK/bob" 127.0.0.1 7702 >/dev/null
$BIN addnode "$WORK/node1" 127.0.0.1 7702 >/dev/null
$BIN addnode "$WORK/node2" 127.0.0.1 7701 >/dev/null
$BIN send "$WORK/alice" "$WORK/chain" "$B" 10 hi >/dev/null
$BIN history "$WORK/chain" "$A" 5 >/dev/null
$BIN slash "$WORK/chain" "$A" 10 test >/dev/null
$BIN banscore "$WORK/node1" >/dev/null
$BIN peer-status "$WORK/node1" >/dev/null
$BIN propose-block "$WORK/node1" 10 >/dev/null
echo rc6_hobby_smoke: OK
