# QRX Core 0.0.6 – Mobile Wallet / Raw TX RPC Patch

This patch keeps the existing node-dashboard RPC layer and adds a clean transaction workflow that a non-custodial mobile wallet can use.

## Confirmed dashboard RPCs

The following server/dashboard commands are wired in `qrx-cli` and `qrxd`:

```text
getnodestatus
getblockchaininfo
getnetworkinfo
getuptime
getbuildinfo
getmempoolinfo
getrecentblocks [limit]
getrecenttransactions [limit]
getvalidatorstatus
getblockproducerinfo
getfeeinfo
getwalletinfo
getnewaddress
listaddresses
getbalance [addr]
history [addr] [limit]
```

## New mobile-wallet transaction commands

```text
getaddressnonce <address>
createrawtransaction <from> <to> <amount> <ed25519_pub_hex> <mldsa65_pub_b64> [memo] [fee] [nonce]
signrawtransactionwithwallet <rawtxfile> <signedtxfile>
decoderawtransaction <txfile>
gettxid <txfile>
sendrawtransaction <txfile>
```

## Intended non-custodial iOS flow

1. iOS wallet keeps private keys locally.
2. iOS calls node RPC for chain data:

```bash
./qrx-cli getblockchaininfo
./qrx-cli getfeeinfo
./qrx-cli getaddressnonce <address>
```

3. iOS constructs the canonical transaction body using:

```text
network_id
genesis_hash
protocol_version
from
to
amount
fee
nonce
timestamp
memo
ed25519_pub_hex
mldsa65_pub_b64
```

4. iOS signs locally with Ed25519 + ML-DSA-65.
5. iOS broadcasts via a node using `sendrawtransaction`.

## Local wallet helper flow

For local CLI testing only, QRX Core can sign a raw transaction with the local wallet:

```bash
./qrx-cli createrawtransaction <from> <to> <amount> <ed25519_pub_hex> <mldsa65_pub_b64> payment > raw.qrxtx
./qrx-cli signrawtransactionwithwallet raw.qrxtx signed.qrxtx
./qrx-cli decoderawtransaction signed.qrxtx
./qrx-cli gettxid signed.qrxtx
./qrx-cli sendrawtransaction signed.qrxtx
```

For production mobile wallets, do not use server-side signing. The mobile app should sign locally and only use the node for chain state and broadcasting.

## Build check

A Linux build check was completed with:

```bash
cmake .. -DQRX_REQUIRE_PQC=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel 2
```

The build produced `qrx`, `qrxd`, `qrx-cli` and all `qrxdb_*` tools. OpenSSL/PQC release builds should still use OpenSSL 3.6.2 as before.
