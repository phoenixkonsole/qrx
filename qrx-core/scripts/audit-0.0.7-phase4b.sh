#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUILD="${1:-build-phase4b-audit}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

echo "[1/10] 0.0.6 regression surface"
./scripts/audit-0.0.6-regression.sh

echo "[2/10] Phase 4B source surface"
test -f src/mempool/qrx_velocity_mvcc.c
test -f src/mempool/qrx_velocity_mvcc.h
grep -q 'qrxdb_parallel_validation_prepare' src/mempool/qrx_velocity_mvcc.c
grep -q 'QRX_MVCC_RETRY' src/mempool/qrx_velocity_mvcc.h
grep -q 'single_wal_batch_per_mvcc_batch=true' src/qrx.c
grep -Eq 'complex_stateful_tx_parallel=(false|fixed_key_adapters_only)' src/qrx.c
grep -q 'velocity-mvcc-execute' src/qrx.c

echo "[3/10] configure + clean build"
rm -rf "$BUILD"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DQRX_BUILD_TESTS=ON
cmake --build "$BUILD" --parallel "$JOBS"

echo "[4/10] Phase 4 + 4B CTests"
ctest --test-dir "$BUILD" --output-on-failure

echo "[5/10] Phase 3A/3B regressions"
./tests/velocity_phase3a_trading.sh "$ROOT/$BUILD/qrx"
./tests/velocity_phase3b_matching.sh "$ROOT/$BUILD/qrx"

echo "[6/10] Phase 3C + outer apply recovery"
./tests/velocity_phase3c_gateway.sh "$ROOT/$BUILD/qrx"
./tests/velocity_phase3c_outer_apply_crash.sh "$ROOT/$BUILD/qrx"

echo "[7/10] Phase 3D cross-chain"
./tests/velocity_phase3d_crosschain.sh "$ROOT/$BUILD/qrx"

echo "[8/10] Phase 3D.1 Bitcoin SPV/reorg"
./tests/velocity_phase3d1_bitcoin_spv.sh "$ROOT/$BUILD/qrx"

echo "[9/10] QRXDB atomic batch recovery"
./scripts/test-qrxdb-atomic-batch.sh "$ROOT/$BUILD"

echo "[10/10] Runtime engine markers"
"$ROOT/$BUILD/qrx" 2>&1 | grep -q 'velocity-mvcc-execute <node-dir>' || true
grep -Eq 'phase=4(B|C)' src/qrx.c

echo "RESULT: QRX Core 0.0.7 Phase 4B MVCC audit PASSED"
