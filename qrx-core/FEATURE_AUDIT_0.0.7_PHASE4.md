# QRX Core 0.0.7 Phase 4 Feature / Regression Audit

## Phase 4 additions

- RAM-resident mempool
- 32 deterministic mempool shards
- 50,000-entry bounded default ceiling via `QRX_MAX_MEMPOOL_TX`
- append-only CRC-protected mempool WAL
- WAL recovery and checkpoint/compaction
- duplicate suppression
- deterministic fee-descending / txid-ascending planning
- hybrid signature worker pool
- conflict access-set extraction
- deterministic conflict waves
- block metadata for execution waves / conflicts / verification workers and time
- `velocity-engine-info`
- `velocity-mempool-plan`
- `getvelocityengineinfo` RPC/CLI
- Phase 4 internal CTest executable (`QRX_BUILD_TESTS=ON`)

## Explicit safety boundary

`parallel_state_mutation=false` in Phase 4. Parallel workers do not directly write consensus state. Authoritative mutations retain the Phase 3 deterministic QRXDB WAL atomic-commit + State Root path.

## 0.0.6 preservation result

The repository regression script verifies all 59 audited 0.0.6 CLI commands plus the historical dashboard, mobile raw-TX, QRXDB tool, OpenSSL/PQC, auto-network and nonce-safety surfaces.

Result after Phase 4 implementation:

```text
RESULT: QRX Core 0.0.6 regression feature audit PASSED
```

## Regression tests observed after Phase 4

```text
velocity_phase4_engine                                      PASS
QRXDB multi-key atomic WAL recovery                         PASS
VELOCITY Phase 3A agent trading                             PASS
VELOCITY Phase 3B deterministic native matching             PASS
VELOCITY Phase 3C gateway / execution reports               PASS
VELOCITY Phase 3C outer apply WAL crash recovery             PASS
VELOCITY Phase 3D BTC/QUB cross-chain settlement             PASS (long-running test)
VELOCITY Phase 3D.1 Bitcoin SPV consensus + reorg safety     PASS
```

Windows-specific source paths are maintained, but this audit environment performed the executable build/tests on Linux. macOS/Windows release builds should still be produced and smoke-tested on those target systems before publishing release binaries.
