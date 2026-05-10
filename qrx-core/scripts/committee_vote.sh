#!/usr/bin/env bash
set -euo pipefail
BIN=${1:?bin}
CHAIN=${2:?chain}
BLOCK=${3:?block}
ROUND=${4:-1}
shift 4
for WALLET in "$@"; do
  ADDR=$($BIN address "$WALLET")
  OUT="$CHAIN/consensus-${ADDR}-r${ROUND}.vote.txt"
  {
    echo "validator=$ADDR"
    echo "round=$ROUND"
    echo "block=$(basename "$BLOCK")"
    echo "ts=$(date +%s)"
  } > "$OUT"
  echo "$OUT"
done
