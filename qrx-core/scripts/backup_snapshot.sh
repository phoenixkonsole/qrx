#!/usr/bin/env bash
set -euo pipefail
SRC=${1:?datadir required}
DST=${2:-./snapshots}
mkdir -p "$DST"
STAMP=$(date +%Y%m%d-%H%M%S)
TAR="$DST/qrx-snapshot-$STAMP.tar.gz"
tar -czf "$TAR" -C "$(dirname "$SRC")" "$(basename "$SRC")"
echo "$TAR"
