# QRX Core 0.0.7 Feature Audit — VELOCITY Phase 4F

## Result

**PASSED**

Phase 4F Deterministic Parallel Block Scheduler / Dependency Graph Execution was added without removing Phase 4E speculative MVCC/OCC, Phase 4D dynamic native matching, Phase 4C stateful adapters, Phase 4B snapshot execution, or the previously implemented trading, cross-chain, Bitcoin SPV, wallet and legacy CLI surfaces.

## New Phase 4F surface

- explicit deterministic block dependency graph
- canonical `fee desc, txid asc` scheduler input
- compact last-accessor static dependency chains
- graph-derived execution levels/waves
- full ordering fences for serial barrier transactions
- no post-barrier wave leapfrogging
- SHA3-512 schedule digest with `QRX-VELOCITY-BLOCK-SCHEDULE-v1` domain
- schedule version 1
- dependency-edge telemetry
- barrier-node/fence telemetry
- critical-path telemetry
- maximum parallel-width telemetry
- scheduler metrics surfaced through VELOCITY CLI execution/info paths
- insertion-order-independent schedule test

## Phase 4E retained

- speculative same-wave preparation
- runtime exact read-set tracking
- runtime predicate/prefix tracking
- deterministic directional OCC
- deterministic winner selection by plan order
- selective retry of losing transactions only
- market-scoped dynamic predicate optimization
- worker-count-independent state-root behavior

Phase 4F supplies the block-wide static graph. Phase 4E remains the runtime correctness backstop for hidden/dynamic conflicts.

## Phase 4D retained

- dynamic `ORDER_CREATE`, `ORDER_CANCEL`, `ORDER_REPLACE`
- snapshot-bound native matching
- price/time/order-ID matching rules
- reserve locks/releases
- price-improvement refunds
- expired-order discovery
- dynamic settlement/trade writes
- stale-generation retry

## Existing authoritative barriers retained

- external order / execution-report state
- cross-chain HTLC/session state
- Bitcoin SPV best-work / reorg state

Their scheduling contract is stronger in Phase 4F because a barrier is now an explicit full graph fence rather than only a singleton wave placement.

## QRXDB hardening retained

`qrxdb_scan_prefix_at()` now avoids calling `qsort()` for zero/one result. This removes an undefined-behavior path found by the Phase 4F UBSan run without changing database semantics.

## Regression evidence

Passed on the Phase 4F source tree:

- `velocity_phase4_engine`
- `velocity_phase4b_mvcc`
- `velocity_phase4c_stateful_mvcc`
- `velocity_phase4d_dynamic_mvcc`
- `velocity_phase4e_speculative_mvcc`
- `velocity_phase4f_block_scheduler`
- all six with ASan + UBSan
- `velocity_phase3a_trading.sh`
- `velocity_phase3b_matching.sh`
- `velocity_phase3c_gateway.sh`
- `velocity_phase3d_crosschain.sh`
- `velocity_phase3d1_bitcoin_spv.sh`
- `scripts/audit-0.0.6-regression.sh`
- `scripts/test-qrxdb-atomic-batch.sh`

The 0.0.6 audit confirms all 59 audited legacy CLI commands, dashboard RPC handlers, mobile-wallet raw-TX RPC pipeline, QRXDB tools, strict nonce safeguards, network handling, OpenSSL/PQC guards and static-release build surfaces remain present.
