# QRX Core v0.0.6 Feature Audit

This archive was checked after repository cleanup to ensure the recent v0.0.6 features are still present.

## Confirmed present

- Dashboard RPCs:
  - getblockchaininfo
  - getnetworkinfo
  - getuptime
  - getbuildinfo
  - getnodestatus
- CLI forwarding for dashboard RPCs
- CLI network auto-detection:
  - explicit --network
  - QRX_NETWORK environment variable
  - ~/.qrx/current_network
  - fallback to alpha
- qrxd writes ~/.qrx/current_network
- getnewaddress now creates an additional wallet address
- listaddresses returns all wallet addresses
- --seednode alias is accepted as --addnode
- OpenSSL/PQC version checks for ML-DSA support
- Hybrid signature verification code path present in qrx_slashing.c
- Windows OpenSSL applink source present
- qrxdb tool sources restored:
  - qrxdb_verify_tool.c
  - qrxdb_salvage_tool.c
  - qrxdb_compact_tool.c
  - qrxdb_snapshot_tool.c
- Static build scripts restored:
  - build-openssl-3.6.2-linux.sh
  - build-openssl-3.6.2-linux-static.sh
  - build-linux-x64-static.sh
  - build-macos-static.sh
  - build-windows-x64-static.ps1
- qrxdb graceful shutdown helper restored:
  - src/storage/qrxdb_shutdown.c
  - src/storage/qrxdb_shutdown.h

## Build check

A local developer build with QRX_REQUIRE_PQC=OFF was verified to configure and compile successfully in the audit environment.
For mainnet/PQC builds, OpenSSL 3.6.x with ML-DSA support is still required.
