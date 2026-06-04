#!/usr/bin/env bash
set -euo pipefail
BIN_DIR="${1:-./build}"
NET="${2:-alpha}"
BASE="${3:-./devnet}"
PASS="${QRX_PASSPHRASE:-testpass}"
export QRX_PASSPHRASE="$PASS"
mkdir -p "$BASE"
"$BIN_DIR/qrxd" --network "$NET" --datadir "$BASE/node1" --wallet node1 --listen 127.0.0.1:26661 >"$BASE/node1.log" 2>&1 &
PID1=$!
sleep 1
"$BIN_DIR/qrxd" --network "$NET" --datadir "$BASE/node2" --wallet node2 --listen 127.0.0.1:26662 --addnode 127.0.0.1:26661 >"$BASE/node2.log" 2>&1 &
PID2=$!
sleep 1
"$BIN_DIR/qrxd" --network "$NET" --datadir "$BASE/node3" --wallet node3 --listen 127.0.0.1:26663 --addnode 127.0.0.1:26661 >"$BASE/node3.log" 2>&1 &
PID3=$!
cat <<MSG
Started 3-node devnet.
PIDs: $PID1 $PID2 $PID3
Logs:
  $BASE/node1.log
  $BASE/node2.log
  $BASE/node3.log
Stop with:
  kill $PID1 $PID2 $PID3
MSG
