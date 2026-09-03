# QRX 0.0.6 Restore Build Fix Notes

This package restores the missing QRX DB tool source files from the last compiling baseline:

- qrx-core/src/qrxdb_verify_tool.c
- qrx-core/src/qrxdb_salvage_tool.c
- qrx-core/src/qrxdb_compact_tool.c
- qrx-core/src/qrxdb_snapshot_tool.c

The active source tree is:

- qrx-core/src/

The root-level duplicate src/ directory was not reintroduced.

A clean Linux configure/build was verified with QRX_REQUIRE_PQC=OFF for compile validation. The CLI help contains the new commands:

- getblockchaininfo
- getnetworkinfo
- getnodestatus
- getuptime
- getbuildinfo
- listaddresses

Always perform a clean rebuild after replacing the source tree:

rm -rf build build-arm64 build-x86_64
mkdir build-x86_64
cd build-x86_64
cmake ..
cmake --build . --parallel
