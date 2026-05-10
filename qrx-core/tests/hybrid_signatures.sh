#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build/qrx}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pushd "$WORK" >/dev/null
export QRX_PASSPHRASE=testpass
"$BIN" init-chain chain >/dev/null
"$BIN" seed-new alice >/dev/null
"$BIN" hybrid-status alice | grep -q 'hybrid_ready=yes'
ADDR=$("$BIN" address alice)
"$BIN" faucet chain "$ADDR" 100 >/dev/null
"$BIN" sign alice chain "$ADDR" 1 hello tx.qrxtx >/dev/null
grep -q '^sig_ed25519_hex=' tx.qrxtx
grep -q '^sig_mldsa65_hex=' tx.qrxtx
grep -q '^mldsa65_pub_b64=' tx.qrxtx
"$BIN" verify chain tx.qrxtx | grep -q '^OK$'
echo 'hybrid_signatures: OK'
popd >/dev/null
