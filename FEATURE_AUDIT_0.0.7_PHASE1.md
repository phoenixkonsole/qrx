# QRX Core 0.0.7 VELOCITY Phase 1 Feature Audit

Build verification: CMake configure and full build completed successfully on Linux with OpenSSL 3.5.5. All qrx/qrx-cli/qrxd/qrxdb tool targets linked.

## Retained 0.0.6 interfaces

- `getnodestatus`
- `getblockchaininfo`
- `getnetworkinfo`
- `getuptime`
- `getbuildinfo`
- `getmempoolinfo`
- `getrecentblocks`
- `getrecenttransactions`
- `getvalidatorstatus`
- `getblockproducerinfo`
- `getfeeinfo`
- `getwalletinfo`
- `getnewaddress`
- `listaddresses`
- `getaddressnonce`
- `createrawtransaction`
- `signrawtransactionwithwallet`
- `decoderawtransaction`
- `gettxid`

## New 0.0.7 Phase 1 interfaces

- `sendrawtransaction`
- `getnoncelanes`
- `getvelocityinfo`
- `createvelocitytransaction`

## Compatibility guard

Legacy transaction version 2 remains canonicalized and executed through the old path. VELOCITY transaction version 3 uses a separate canonical envelope. Lane 0 maps to the historical account nonce store; additional lanes use `state/nonces_lanes.bin`. Reserved AI/trading transaction types are schema-only and rejected at execution until their consensus semantics are implemented.
