# QRX Core 0.0.6 Regression Audit — after VELOCITY Phase 3A

## Result

**PASS**

The 0.0.7 Phase 3A source was checked against the available 0.0.6 feature archives and against the last mobile-wallet/raw-TX 0.0.6 baseline.

## Source/file audit

The last mobile-wallet/raw-TX 0.0.6 baseline contains 51 files below `qrx-core/src` and 16 files below `qrx-core/scripts`.

Current 0.0.7 Phase 3A contains:

- 52 files below `qrx-core/src`
- 17 files below `qrx-core/scripts`
- zero missing files from that 0.0.6 baseline

Across the union of source/script files found in the available 0.0.6 feature archives, **zero files are missing** from this Phase 3A package.

The cross-archive audit found one legacy Windows feature file that had disappeared from the later 0.0.6 lineage:

- `src/openssl_applink.c`

It was restored from the dedicated 0.0.6 Windows/OpenSSL Applink fix archive. This prevents the old `OPENSSL_Uplink(...): no OPENSSL_Applink` regression in MSVC builds.

## Intentional source differences vs the mobile-wallet 0.0.6 baseline

Only these common source files differ:

- `src/qrx.c` — VELOCITY transaction, agent and trading state logic
- `src/qrx_cli.c` — VELOCITY/mobile/trading CLI commands and larger command buffer
- `src/qrxd.c` — VELOCITY/trading RPC handlers and larger command parser buffers
- `src/protocol/qrx_protocol_version.h` — VELOCITY feature level advanced to 2

All other common `src` files remain byte-identical to the checked 0.0.6 mobile-wallet baseline.

The original 0.0.6 static build scripts remain present.

## 0.0.6 CLI surface

All 59 commands from the checked 0.0.6 mobile-wallet CLI command surface are still present.

This includes the important groups:

- wallet: `getnewaddress`, `listaddresses`, `getwalletinfo`, `getbalance`, `history`
- raw/mobile TX: `createrawtransaction`, `signrawtransactionwithwallet`, `decoderawtransaction`, `gettxid`, `sendrawtransaction`
- node dashboard: `getblockchaininfo`, `getnetworkinfo`, `getnodestatus`, `getuptime`, `getbuildinfo`
- extended dashboard: `getmempoolinfo`, `getrecentblocks`, `getrecenttransactions`, `getvalidatorstatus`, `getblockproducerinfo`, `getfeeinfo`
- staking, swaps, privacy and peer management commands

## Other preserved 0.0.6 protections

Confirmed present:

- CLI network auto-detection
- `QRX_NETWORK` support
- `current_network` state file support
- strict sequential nonce protection
- amount+fee overflow checks
- OpenSSL >= 3.5 PQC build guard
- static release build scripts
- QRXDB verify/salvage/compact/snapshot tools
- QRXDB shutdown source files
- Windows OpenSSL Applink source and CMake wiring

## Build audit

A fresh Linux Release CMake build completed successfully and generated:

- `qrx`
- `qrxd`
- `qrx-cli`
- `qrxdb_verify`
- `qrxdb_salvage`
- `qrxdb_compact`
- `qrxdb_snapshot`

## VELOCITY Phase 3A functional smoke test

The included `tests/velocity_phase3a_trading.sh` passed end-to-end with OpenSSL 3.5.x.

It verified:

1. owner and agent hybrid wallets,
2. on-chain `AGENT_REGISTER`,
3. native agent-signed `ORDER_CREATE`,
4. native `ORDER_CANCEL`,
5. external `EXTERNAL_ORDER`,
6. deterministic order state,
7. agent usage accounting,
8. rejection above `max_trade_atoms`,
9. rejection of a market outside the allowlist.

## Repeatable audit

Run:

```bash
./scripts/audit-0.0.6-regression.sh
```

Expected final line:

`RESULT: QRX Core 0.0.6 regression feature audit PASSED`
