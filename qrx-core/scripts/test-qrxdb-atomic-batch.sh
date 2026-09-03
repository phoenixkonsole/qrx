#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-$ROOT/build-phase3c}"
[[ -f "$BUILD/libqrxcore.a" ]] || { echo "missing $BUILD/libqrxcore.a; build QRX first" >&2; exit 1; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CC_BIN="${CC:-cc}"
"$CC_BIN" -I"$ROOT/src" "$ROOT/tests/qrxdb_atomic_batch_test.c" "$BUILD/libqrxcore.a" -lcrypto -lpthread -o "$TMP/qrxdb_atomic_batch_test"
"$TMP/qrxdb_atomic_batch_test" "$TMP/chain"
