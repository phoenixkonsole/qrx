# QRX Core 0.0.6 Regression Audit — after VELOCITY Phase 3B

## Result

**PASS**

The Phase 3B tree was checked with `qrx-core/scripts/audit-0.0.6-regression.sh`.

Confirmed preserved from QRX Core 0.0.6:

- all 59 audited legacy CLI commands,
- wallet creation/address commands,
- mobile raw-TX create/sign/decode/txid/broadcast pipeline,
- node/dashboard RPCs including node status, recent blocks/transactions, mempool, validator, producer and fee information,
- CLI network auto-detection and `QRX_NETWORK`,
- strict nonce sequencing and amount+fee overflow protection,
- OpenSSL >= 3.5 PQC guard,
- Windows OpenSSL Applink source/CMake wiring,
- QRXDB verify/salvage/compact/snapshot tools,
- QRXDB shutdown files,
- static Linux/macOS/Windows build scripts.

Final audit line:

`RESULT: QRX Core 0.0.6 regression feature audit PASSED`

## Build check

A fresh Linux Release build completed successfully and produced:

- `qrx`
- `qrxd`
- `qrx-cli`
- `qrxdb_verify`
- `qrxdb_salvage`
- `qrxdb_compact`
- `qrxdb_snapshot`

## VELOCITY compatibility tests

Passed:

- `tests/velocity_phase3a_trading.sh`
- `tests/velocity_phase3b_matching.sh`

## File inventory check vs Phase 3A

No Phase 3A source/script file disappeared. Phase 3B intentionally modifies only the VELOCITY-facing core/CLI/RPC/protocol files plus the Phase 3A test compatibility update and adds the new Phase 3B test/documentation.
