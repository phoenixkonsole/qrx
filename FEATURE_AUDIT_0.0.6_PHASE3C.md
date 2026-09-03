# QRX Core 0.0.6 Regression Audit — after VELOCITY Phase 3C

Result from a fresh Release build:

`RESULT: QRX Core 0.0.6 regression feature audit PASSED`

The regression script confirmed all 59 audited 0.0.6 CLI commands and specifically checked that the following families remain present:

- wallet creation / additional addresses / `listaddresses`
- mobile-wallet Raw-TX create/sign/decode/txid/broadcast pipeline
- server dashboard RPC handlers
- node/network/status RPCs
- mempool/recent-block/recent-transaction/validator/block-producer/fee RPCs
- staking and delegation
- swaps
- shielded and stealth privacy commands
- QRXDB verify/salvage/compact/snapshot tools
- static Linux/macOS/Windows build scripts
- OpenSSL >= 3.5 PQC build guard
- Windows OpenSSL `applink` integration
- CLI automatic network detection
- strict nonce = current + 1 protection
- amount + fee overflow checks

Additional VELOCITY tests passed after the same fresh build:

- Phase 3A agent trading smoke test
- Phase 3B deterministic native matching + settlement smoke test
- Phase 3C external gateway + execution report smoke test
- Phase 3C outer `applytx` WAL crash-recovery test
- generic multi-key QRXDB WAL atomic recovery test

The regression audit script remains available at:

`scripts/audit-0.0.6-regression.sh`
