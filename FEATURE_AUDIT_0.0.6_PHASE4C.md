# QRX Core 0.0.6 Regression Audit — after VELOCITY Phase 4C

The automated `scripts/audit-0.0.6-regression.sh` passed after Phase 4C.

Confirmed retained:

- all 59 audited QRX Core 0.0.6 CLI commands
- server dashboard RPC handlers
- mobile-wallet raw transaction/sign/decode/TXID/broadcast pipeline
- strict nonce safety
- network auto-detection/current-network handling
- QRXDB verify/salvage/compact/snapshot tools
- Windows OpenSSL Applink source and CMake wiring
- OpenSSL/PQC minimum-version guard
- Linux/macOS/Windows static release build scripts

Regression smoke tests also passed for VELOCITY Phase 3A, 3B, 3C, 3D and 3D.1, including Bitcoin SPV/reorg safety, plus the QRXDB multi-key WAL recovery test.
