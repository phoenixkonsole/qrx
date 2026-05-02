# QUB RC6.3 Native Core Daemon

## What changed

RC6.3 is no longer a Python-wrapper layout. It now builds three native binaries from C:

- `qrx` — backend/engine CLI
- `qrxd` — daemon-style node launcher
- `qrx-cli` — user-facing CLI

The shared logic is linked through `libqrxcore.a`.

## Network profiles

Built-in profiles:

- `alpha`
- `testnet`
- `regtest`
- `mainnet`

Each profile provides:

- network id
- genesis hash
- protocol version
- magic
- default port
- seednodes
- tokenomics defaults

## Auto-init

On first start, `qrxd` / `qrx-cli` will automatically:

1. create `<datadir>/<network>/chain`
2. initialize chain state if missing
3. write network profile values into `chain.conf`
4. create `<datadir>/<network>/wallets/<wallet>`
5. generate a wallet if missing
6. create `<datadir>/<network>/nodes/<wallet>`
7. initialize node config if missing
8. seed peers from the built-in profile and any `--addnode` values

## Example

```bash
export QUB_PASSPHRASE=testpass
./build/qrxd --network alpha --datadir ./data --wallet node1 --listen 127.0.0.1:26661
```

```bash
./build/qrx-cli --network alpha --datadir ./data --wallet node1 getnewaddress
./build/qrx-cli --network alpha --datadir ./data --wallet node1 getbalance
./build/qrx-cli --network alpha --datadir ./data --wallet node1 listpeers
```

## Current scope

RC6.3 gives a more coin-core-like operator experience, but it is still built on the existing QUB RC6.x engine. It does not yet provide a fully independent background RPC daemon or a full Bitcoin-Core-class sync implementation.
