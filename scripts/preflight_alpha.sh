#!/usr/bin/env bash
set -euo pipefail
BIN=${1:-./build/qrx}
CHAIN=${2:-./alpha-chain}
NODE=${3:-./alpha-node}
if [[ ! -x "$BIN" ]]; then
  echo "missing binary: $BIN" >&2
  exit 1
fi
for p in "$CHAIN" "$NODE"; do
  mkdir -p "$p"
done
printf 'alpha preflight ok\n'
