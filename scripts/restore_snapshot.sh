#!/usr/bin/env bash
set -euo pipefail
ARCHIVE=${1:?archive required}
DEST_PARENT=${2:-.}
tar -xzf "$ARCHIVE" -C "$DEST_PARENT"
echo "restored to $DEST_PARENT"
