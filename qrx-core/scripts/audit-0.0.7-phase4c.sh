#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUILD="${1:-build-phase4c-audit}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

echo "[1/11] 0.0.6 regression surface"
./scripts/audit-0.0.6-regression.sh

echo "[2/11] Phase 4/4B compatibility surface"
grep -q 'QRX_VELOCITY_MEMPOOL_SHARDS 32' src/mempool/qrx_velocity_mempool.h
grep -q 'qrxdb_parallel_validation_prepare' src/mempool/qrx_velocity_mvcc.c
grep -q 'single_wal_batch_per_mvcc_batch=true' src/qrx.c
grep -q 'velocity-mvcc-execute' src/qrx.c

echo "[3/11] Phase 4C stateful adapter surface"
grep -q 'QRX_VELOCITY_ADAPTER_STATEFUL' src/mempool/qrx_velocity_mempool.h
grep -q 'QRX_VELOCITY_ADAPTER_BARRIER' src/mempool/qrx_velocity_mempool.h
grep -q 'prepare_agent_stateful' src/mempool/qrx_velocity_mvcc.c
grep -q 'prepare_gateway_stateful' src/mempool/qrx_velocity_mvcc.c
grep -q 'stateful_mvcc_adapters=true' src/qrx.c
grep -q 'dynamic_state_barriers=true' src/qrx.c
grep -q 'native_matching_barrier=true' src/qrx.c
grep -q 'crosschain_barrier=true' src/qrx.c
grep -q 'bitcoin_spv_reorg_barrier=true' src/qrx.c

echo "[4/11] configure + clean build"
rm -rf "$BUILD"
cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DQRX_BUILD_TESTS=ON
cmake --build "$BUILD" --parallel "$JOBS"

echo "[5/11] Phase 4/4B/4C CTests"
ctest --test-dir "$BUILD" --output-on-failure

echo "[6/11] Phase 3A + 3B"
./tests/velocity_phase3a_trading.sh "$ROOT/$BUILD/qrx"
./tests/velocity_phase3b_matching.sh "$ROOT/$BUILD/qrx"

echo "[7/11] Phase 3C + crash recovery"
./tests/velocity_phase3c_gateway.sh "$ROOT/$BUILD/qrx"
./tests/velocity_phase3c_outer_apply_crash.sh "$ROOT/$BUILD/qrx"

echo "[8/11] Phase 3D cross-chain"
./tests/velocity_phase3d_crosschain.sh "$ROOT/$BUILD/qrx"

echo "[9/11] Phase 3D.1 Bitcoin SPV/reorg"
./tests/velocity_phase3d1_bitcoin_spv.sh "$ROOT/$BUILD/qrx"

echo "[10/11] QRXDB WAL atomic recovery"
./scripts/test-qrxdb-atomic-batch.sh "$ROOT/$BUILD"

echo "[11/11] Regression audit scripts remain compatible"
./scripts/audit-0.0.7-phase4.sh "${BUILD}-compat4"
# Phase 4B's heavy regressions overlap the checks above; source compatibility is
# verified directly to avoid running the full SPV scenario a second time.
grep -Eq 'complex_stateful_tx_parallel=(false|fixed_key_adapters_only)' src/qrx.c
grep -Eq 'phase=4(B|C)' src/qrx.c

echo "RESULT: QRX Core 0.0.7 Phase 4C Stateful MVCC Adapters audit PASSED"
