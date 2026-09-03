# QRX Core 0.0.7 Feature Audit — VELOCITY Phase 4E

## Result

**PASSED**

Phase 4E Speculative Parallel Execution & Deterministic Conflict Resolution was added without removing the Phase 4D dynamic native matching path, Phase 4C stateful adapters, Phase 4B snapshot executor, or the previously implemented trading, cross-chain, Bitcoin SPV, wallet and legacy CLI surfaces.

## New Phase 4E surface

- speculative multi-transaction MVCC waves
- runtime exact read-set tracking
- runtime predicate/prefix tracking for dynamic discovery
- deterministic directional optimistic conflict control
- deterministic winner selection by plan order, never thread finish order
- write/write conflict detection
- read-after-prior-write conflict detection
- dynamic orderbook phantom conflict detection
- selective re-preparation of losing transactions only
- retry against already accepted predecessor overlay
- market-scoped dynamic order predicate optimization
- new speculative/conflict/retry telemetry
- worker-count-independent state-root determinism test

## Phase 4D retained

- `QRX_VELOCITY_ADAPTER_DYNAMIC`
- `ORDER_CREATE`
- `ORDER_CANCEL`
- `ORDER_REPLACE`
- snapshot-bound native order discovery
- deterministic price/time/order-ID matching
- dynamic maker/taker writes
- price-improvement refunds
- expired-order discovery and reserve release
- atomic cancel/replace reserve handling
- trade and settlement record staging
- stale-generation `QRX_MVCC_RETRY`

The Phase 4D singleton-wave restriction is intentionally superseded by Phase 4E. Dynamic transactions can now share a wave when the static planner allows it, with runtime OCC acting as the correctness backstop.

## Phase 4C retained

- `TRANSFER_FAST`
- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_REVOKE`
- `GATEWAY_REGISTER`
- `GATEWAY_REVOKE`
- deterministic prior-wave overlays
- isolated worker attempt state
- one QRXDB WAL commit per successful MVCC batch
- state-root generation
- barrier all-or-nothing behavior

## Remaining intentional barriers

- external order / execution report transitions
- BTC/QUB cross-chain HTLC transitions
- Bitcoin SPV best-work/reorg transitions

These retain the existing authoritative serial state machines. Phase 4E does not partially speculate them and does not weaken their all-or-nothing fallback/barrier behavior.

## Determinism evidence

The dedicated Phase 4E test prepares two competing same-market BUY transactions in one speculative wave against a maker with five units available. Both initial attempts see the same snapshot. Deterministic plan order accepts the first, recognizes the second as a runtime conflict and re-executes only the second against the accepted overlay.

The final state is exact and the generated state root is byte-for-byte identical with one worker and eight workers.

A separate cross-market case places `TOK/QUB` and `ALT/QUB` native orders in the same speculative wave and verifies zero deterministic conflicts and zero selective retries.

## Regression evidence

Passed on the Phase 4E source tree:

- `velocity_phase4_engine`
- `velocity_phase4b_mvcc`
- `velocity_phase4c_stateful_mvcc`
- `velocity_phase4d_dynamic_mvcc`
- `velocity_phase4e_speculative_mvcc`
- all five tests with ASan + UBSan
- `velocity_phase3a_trading.sh`
- `velocity_phase3b_matching.sh`
- `velocity_phase3c_gateway.sh`
- `velocity_phase3d_crosschain.sh`
- `velocity_phase3d1_bitcoin_spv.sh`
- `scripts/audit-0.0.6-regression.sh`
- `scripts/test-qrxdb-atomic-batch.sh build4e`

The 0.0.6 audit confirms all 59 audited legacy CLI commands, dashboard RPC handlers, mobile-wallet raw-TX RPC pipeline, QRXDB tools, strict nonce safeguards, network handling, OpenSSL/PQC guards and static-release build surfaces remain present.
