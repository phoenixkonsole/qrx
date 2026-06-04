#!/usr/bin/env bash
set -euo pipefail
BIN=${1:-./build/qrx}
BASE=${2:-alpha-net}
PASS=${QRX_PASSPHRASE:-testpass}
export QRX_PASSPHRASE="$PASS"
mkdir -p "$BASE"
$BIN init-chain "$BASE/chain" 20 5000
for u in alice bob carol; do $BIN seed-new "$BASE/$u" >/dev/null; done
ALICE=$($BIN address "$BASE/alice")
BOB=$($BIN address "$BASE/bob")
CAROL=$($BIN address "$BASE/carol")
$BIN faucet "$BASE/chain" "$ALICE" 5000
$BIN faucet "$BASE/chain" "$BOB" 3000
$BIN faucet "$BASE/chain" "$CAROL" 3000
$BIN stake "$BASE/chain" "$BASE/alice" 1500
$BIN stake "$BASE/chain" "$BASE/bob" 1000
$BIN delegate "$BASE/chain" "$BASE/carol" "$ALICE" 500
$BIN node-init "$BASE/node1" "$BASE/chain" "$BASE/alice" 127.0.0.1 7601
$BIN node-init "$BASE/node2" "$BASE/chain" "$BASE/bob" 127.0.0.1 7602
$BIN node-init "$BASE/node3" "$BASE/chain" "$BASE/carol" 127.0.0.1 7603
$BIN addnode "$BASE/node1" 127.0.0.1 7602
$BIN addnode "$BASE/node1" 127.0.0.1 7603
$BIN addnode "$BASE/node2" 127.0.0.1 7601
$BIN addnode "$BASE/node2" 127.0.0.1 7603
$BIN addnode "$BASE/node3" 127.0.0.1 7601
$BIN addnode "$BASE/node3" 127.0.0.1 7602
printf 'alpha network prepared in %s\n' "$BASE"
