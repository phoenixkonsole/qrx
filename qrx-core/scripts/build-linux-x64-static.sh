#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "Compatibility wrapper: using the architecture-neutral Linux builder."
exec "$ROOT/scripts/build-linux-static.sh" "$@"
