#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
export QRX_PASSPHRASE=testpass

"$BIN" init-chain "$TMPDIR/chain" 20 5000 >/dev/null
"$BIN" seed-new "$TMPDIR/alice" >/dev/null
"$BIN" seed-new "$TMPDIR/bob" >/dev/null
"$BIN" seed-new "$TMPDIR/carol" >/dev/null
ALICE="$($BIN address "$TMPDIR/alice")"
BOB="$($BIN address "$TMPDIR/bob")"
CAROL="$($BIN address "$TMPDIR/carol")"

"$BIN" faucet "$TMPDIR/chain" "$ALICE" 1000 >/dev/null
"$BIN" faucet "$TMPDIR/chain" "$BOB" 500 >/dev/null
"$BIN" faucet "$TMPDIR/chain" "$CAROL" 250 >/dev/null
"$BIN" stake "$TMPDIR/chain" "$TMPDIR/alice" 400 >/dev/null
"$BIN" delegate "$TMPDIR/chain" "$TMPDIR/bob" "$ALICE" 200 >/dev/null
"$BIN" send "$TMPDIR/alice" "$TMPDIR/chain" "$BOB" 10 hello >/dev/null

BAL_BOB="$($BIN balance "$TMPDIR/chain" "$BOB")"
[[ "$BAL_BOB" == "310" ]]

SL1="$($BIN slash "$TMPDIR/chain" "$ALICE" 100 missed 10)"
SL2="$($BIN slash "$TMPDIR/chain" "$ALICE" 100 double 10)"
grep -q 'redistributed=0' <<<"$SL1"
grep -q 'redistributed=50' <<<"$SL2"

HIST="$($BIN history "$TMPDIR/chain" "$ALICE" 10)"
grep -q 'slash validator=' <<<"$HIST"

echo 'rc6_hardened_features: OK'
