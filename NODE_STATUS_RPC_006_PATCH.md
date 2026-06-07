# QRX 0.0.6 Node Status RPC Patch

This patch adds dashboard-friendly node status RPCs to `qrxd` and exposes them through `qrx-cli`.

## New RPC / CLI commands

```bash
./qrx-cli --network mainnet getblockchaininfo
./qrx-cli --network mainnet getnetworkinfo
./qrx-cli --network mainnet getuptime
./qrx-cli --network mainnet getbuildinfo
./qrx-cli --network mainnet getnodestatus
```

## `getblockchaininfo`

Returns chain name, local block height, highest known header/block height, best block hash, median time, verification progress and initial block download state.

## `getnetworkinfo`

Returns QRX version, subversion, protocol version, connection count, listening state and network activity state.

## `getuptime`

Returns daemon uptime in seconds and a human-readable string.

## `getbuildinfo`

Returns QRX version, build timestamp, OpenSSL runtime version and hybrid/PQC flags.

## `getnodestatus`

Consolidated dashboard endpoint. Returns:

- version/build
- network
- uptime
- connection count
- local height
- best peer height
- highest known block
- blocks behind
- sync percent
- best block hash
- wallet loaded/address
- block producer state
- node PID
- RPC URL
- OpenSSL version
- hybrid/PQC status

This is intended as the primary endpoint for seednode dashboards and QRX: The Node Wars integration.
