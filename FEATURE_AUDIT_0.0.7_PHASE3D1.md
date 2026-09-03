# QRX Core 0.0.7 Phase 3D.1 Feature / Regression Audit

## Build

A fresh Release CMake build completed successfully and produced:

- qrx
- qrxd
- qrx-cli
- qrxdb_verify
- qrxdb_salvage
- qrxdb_compact
- qrxdb_snapshot

## 0.0.6 compatibility audit

`scripts/audit-0.0.6-regression.sh` result:

    RESULT: QRX Core 0.0.6 regression feature audit PASSED

The audit confirms all 59 tracked 0.0.6 CLI commands and checks the server-dashboard RPC layer, mobile-wallet raw-TX pipeline, qrxdb tools, static-build scripts, OpenSSL/PQC checks, Windows OpenSSL applink, auto-network detection and strict nonce/amount safety.

## VELOCITY regression checks

- Phase 3A agent trading smoke test: PASS.
- Phase 3B deterministic native matching + settlement smoke test: PASS.
- Phase 3C external gateway + execution report smoke test: PASS.
- Phase 3C outer apply WAL crash recovery: PASS.
- QRXDB multi-key atomic WAL recovery: PASS.
- Phase 3D BTC/QUB cross-chain trading behavior remains present; Phase 3D.1 intentionally hardens the redeem path so a preimage alone can no longer release QUB without valid Bitcoin SPV funding evidence.
- Phase 3D.1 Bitcoin SPV consensus + reorg safety smoke test: PASS.

## Security-relevant Phase 3D.1 fixes

- Fixed aliasing in `load_header_hash()` that corrupted ancestor lookup while walking the header chain.
- Removed node-local wall-clock dependence from consensus SPV validation.
- Added active best-work-chain confirmation gating.
- Added reorg-safe funding status evaluation.
- Added non-trivial Merkle-branch coverage to the SPV smoke test.

