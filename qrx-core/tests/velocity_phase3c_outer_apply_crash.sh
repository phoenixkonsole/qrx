#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build-phase3c/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-outer-atomic.XXXXXX)"
trap 'rm -rf "$T"' EXIT
export QRX_PASSPHRASE=testpass

"$BIN" seed-new "$T/alice" >/dev/null
"$BIN" seed-new "$T/bob" >/dev/null
ALICE="$($BIN address "$T/alice" | tr -d '\r\n')"
BOB="$($BIN address "$T/bob" | tr -d '\r\n')"
"$BIN" init-chain "$T/base" 20 5000 2100000000000000 25000000 1000000000 qrx-regtest 1 5152583036 QRX-Velocity-Outer-Atomic >/dev/null
"$BIN" faucet "$T/base" "$ALICE" 10000 >/dev/null
"$BIN" sign "$T/alice" "$T/base" "$BOB" 250 atomic-recovery "$T/tx.qrxtx" >/dev/null
"$BIN" verify "$T/base" "$T/tx.qrxtx" >/dev/null
TXID="$($BIN txid "$T/base" "$T/tx.qrxtx")"

# Fork exactly the same pre-transaction state. One side commits normally; the
# other is killed immediately after durable WAL COMMIT and before materializing
# any of the batch's canonical state records.
cp -a "$T/base" "$T/normal"
cp -a "$T/base" "$T/crash"

NORMAL_OUT="$($BIN applytx "$T/normal" "$T/tx.qrxtx")"
NORMAL_ROOT="$(printf '%s\n' "$NORMAL_OUT" | sed -n 's/^state_root=//p')"
[[ ${#NORMAL_ROOT} -eq 128 ]] || { echo "normal apply returned bad state root" >&2; exit 1; }

set +e
QRXDB_TEST_CRASH_AFTER_WAL_COMMIT=1 "$BIN" applytx "$T/crash" "$T/tx.qrxtx" >/dev/null 2>&1
RC=$?
set -e
[[ $RC -eq 86 ]] || { echo "fault injection expected exit 86, got $RC" >&2; exit 1; }

# Opening QRXDB must replay the committed generation atomically.
CRASH_ROOT="$($BIN state-root "$T/crash" | sed -n 's/^state_root=//p')"
[[ "$CRASH_ROOT" == "$NORMAL_ROOT" ]] || {
  echo "recovered state root differs from normal atomic commit" >&2
  echo "normal=$NORMAL_ROOT" >&2
  echo "crash =$CRASH_ROOT" >&2
  exit 1
}

# Verify all externally observable pieces that were staged in the same outer
# apply batch: balances, fee pool, nonce and applied marker/duplicate rejection.
[[ "$($BIN balance "$T/crash" "$ALICE" | tail -n1 | tr -d '\r')" == "8750" ]]
[[ "$($BIN balance "$T/crash" "$BOB" | tail -n1 | tr -d '\r')" == "250" ]]
[[ "$($BIN getnonce "$T/crash" "$ALICE" | tail -n1 | tr -d '\r')" == "1" ]]
"$BIN" feeinfo "$T/crash" > "$T/feeinfo"
grep -q '^pending_fee_pool_atoms=1000$' "$T/feeinfo"
if "$BIN" verify "$T/crash" "$T/tx.qrxtx" >/dev/null 2>&1; then
  echo "recovered applied marker did not reject duplicate tx $TXID" >&2
  exit 1
fi

# Wallet signing must immediately consume authoritative recovered nonce, even
# though a crash prevented the post-commit flat-file compatibility mirror.
"$BIN" sign "$T/alice" "$T/crash" "$BOB" 1 after-recovery "$T/tx2.qrxtx" >/dev/null
"$BIN" verify "$T/crash" "$T/tx2.qrxtx" >/dev/null
NONCE2="$(sed -n 's/^nonce=//p' "$T/tx2.qrxtx")"
[[ "$NONCE2" == "2" ]] || { echo "post-recovery signer did not use nonce 2" >&2; exit 1; }

printf 'VELOCITY Phase 3C outer apply WAL crash recovery PASSED\nstate_root=%s\ntxid=%s\n' "$CRASH_ROOT" "$TXID"
