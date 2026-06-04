#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo "usage: $0 <manifest-file> <signing-command>" >&2
  exit 1
fi
MANIFEST="$1"
shift
"$@" "$MANIFEST"
