#!/usr/bin/env bash
set -euo pipefail
BIN=${1:?bin}
CHAIN=${2:?chain}
BLOCK=${3:?block}
ROUND=${4:-1}
BH=$($BIN verify-block "$CHAIN" "$BLOCK" >/dev/null && basename "$BLOCK")
COUNT=$(find "$CHAIN" -maxdepth 1 -type f -name "consensus-*-r${ROUND}.vote.txt" | wc -l | tr -d ' ')
echo "votes=$COUNT block=$BH round=$ROUND"
if [ "$COUNT" -lt 2 ]; then
  echo "not enough committee votes"
  exit 1
fi
mkdir -p "$CHAIN/finalized"
cp "$BLOCK" "$CHAIN/finalized/$(basename "$BLOCK")"
echo "$CHAIN/finalized/$(basename "$BLOCK")"
