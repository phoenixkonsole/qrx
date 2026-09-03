#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUILD="${1:-build-phase4-audit}"

echo "[1/6] 0.0.6 regression surface"
./scripts/audit-0.0.6-regression.sh

echo "[2/6] Phase 4 source surface"
test -f src/mempool/qrx_velocity_mempool.c
test -f src/mempool/qrx_velocity_mempool.h
grep -q 'QRX_VELOCITY_MEMPOOL_SHARDS 32' src/mempool/qrx_velocity_mempool.h
grep -q 'velocity-engine-info' src/qrx.c
grep -q 'getvelocityengineinfo' src/qrxd.c
grep -q 'getvelocityengineinfo' src/qrx_cli.c
grep -q 'parallel_state_mutation=' src/qrx.c

echo "[3/6] configure + build tests"
rm -rf "$BUILD"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DQRX_BUILD_TESTS=ON
cmake --build "$BUILD" --parallel "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

echo "[4/6] Phase 4 CTest"
ctest --test-dir "$BUILD" --output-on-failure

echo "[5/6] QRXDB atomic batch recovery"
./scripts/test-qrxdb-atomic-batch.sh "$ROOT/$BUILD"

echo "[6/6] SPV reorg regression"
./tests/velocity_phase3d1_bitcoin_spv.sh "$ROOT/$BUILD/qrx"

echo "RESULT: QRX Core 0.0.7 Phase 4 audit PASSED"
