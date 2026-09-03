# QRX Core 0.0.6 Regression Audit — after VELOCITY Phase 4B

The automated `qrx-core/scripts/audit-0.0.6-regression.sh` remains mandatory for Phase 4B and subsequent VELOCITY work.

It verifies preservation of the established 0.0.6 surface, including:

- 59 legacy CLI commands
- wallet address generation and address listing
- mobile-wallet raw transaction create/sign/decode/txid/broadcast pipeline
- server dashboard RPCs
- staking and delegation
- Atomic/Quantum Swaps
- shielded and stealth privacy features
- QRXDB maintenance tools
- static Linux/macOS/Windows build scripts
- Windows OpenSSL applink integration
- OpenSSL/PQC build guard
- CLI network auto-detection
- strict nonce enforcement

Phase 4B adds MVCC files and tests without replacing the legacy command surface.
