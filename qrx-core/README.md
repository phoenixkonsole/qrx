# QRX RC6.4 Final Merge — Cleaned & Unified

This repository is the cleaned, unified QRX working tree for a **public alpha / hobby network**.

## What this repo is

- **native C layout** with a shared core library
- **`qrx`** backend binary
- **`qrxd`** daemon frontend
- **`qrx-cli`** control / wallet frontend
- **built-in network profiles**
- **auto-init** for datadir, chain, wallet and node state
- **local control socket / JSON RPC-style responses**
- **staking, delegation, slashing, penalty redistribution**
- **experimental committee/finality/BFT flow** for alpha testing

## What this repo is not

- not audited
- not enterprise-grade
- not a hardened production mainnet

Use it as **public alpha / hobby software on your own risk**.

## Entry points

Only these binaries are the supported entry points:

- `build/qrx`
- `build/qrxd`
- `build/qrx-cli`

Legacy Python wrapper scripts were removed from this cleaned tree to avoid confusion.

## Build

```bash
cmake -S . -B build
cmake --build build -j
```

## Quick start

Terminal 1:

```bash
export QRX_PASSPHRASE=testpass
./build/qrxd --network alpha --datadir ./data --wallet node1 --listen 127.0.0.1:26661
```

Terminal 2:

```bash
./build/qrx-cli --network alpha --datadir ./data --wallet node1 getinfo
./build/qrx-cli --network alpha --datadir ./data --wallet node1 getwalletinfo
./build/qrx-cli --network alpha --datadir ./data --wallet node1 getnewaddress
./build/qrx-cli --network alpha --datadir ./data --wallet node1 tokenomics
```

Start more nodes:

```bash
./build/qrxd --network alpha --datadir ./data2 --wallet node2 --listen 127.0.0.1:26662 --addnode 127.0.0.1:26661
./build/qrxd --network alpha --datadir ./data3 --wallet node3 --listen 127.0.0.1:26663 --addnode 127.0.0.1:26661
```

## Current high-level feature set

- fixed network profiles: `alpha`, `testnet`, `regtest`, `mainnet`
- built-in genesis/profile defaults
- peer bootstrap / peer discovery
- local control socket
- stable JSON RPC-style responses
- send / receive / history
- staking / delegation / validator set
- slashing / penalty points / redistribution threshold
- tokenomics counters and limits
- experimental proposal / prevote / precommit / finalize flow
- alpha ops / backup / restore docs and scripts

## JSON response format

Successful responses:

```json
{"ok":true,"method":"getinfo","result":{...}}
```

Errors:

```json
{"ok":false,"method":"getinfo","error":"..."}
```

## Start reading here

- `docs/START-HERE.md`
- `docs/CORE-DAEMON.md`
- `docs/CONTROL-SOCKET.md`
- `docs/TOKENOMICS.md`
- `docs/STAKING.md`
- `docs/CONSENSUS-INTEGRATION.md`
- `docs/BFT-EXPERIMENTAL.md`
- `docs/ALPHA-MAINNET-GAPS.md`

## Notes

This cleaned tree focuses on a single supported path:

**native C daemon + native CLI + shared C core + alpha/testnet operation**.


## Hybrid signature status

QRX RC6.4 uses a concrete hybrid transaction signature path:

- Ed25519
- ML-DSA-65

Quick check:

```bash
./build/qrx hybrid-status <wallet-dir>
./tests/hybrid_signatures.sh ./build/qrx
```


## Quantum Swaps / HTLC MVP

This patched tree includes a first QUBITCOIN-side HTLC preparation layer for Quantum Swaps.

CLI examples:

```bash
SECRET="supersecret"
HASHLOCK=$(printf "%s" "$SECRET" | shasum -a 256 | awk '{print $1}')

./build/qrx-cli --network alpha --datadir ./data --wallet node1 createswap <QUB_RECIPIENT> 1000 "$HASHLOCK" 86400 "BTC-QUB swap"
./build/qrx-cli --network alpha --datadir ./data --wallet node1 getswap <SWAP_ID>
./build/qrx-cli --network alpha --datadir ./data --wallet node1 redeemswap <SWAP_ID> "$SECRET"
./build/qrx-cli --network alpha --datadir ./data --wallet node1 refundswap <SWAP_ID>
./build/qrx-cli --network alpha --datadir ./data --wallet node1 listswaps
```

See `docs/QUANTUM-SWAPS-HTLC.md`.

Important: this is an alpha state-level HTLC MVP for GUI/swap-flow integration. Before public mainnet usage it must be hardened into consensus-level signed HTLC transactions.


## Shielded Pool Skeleton

This tree includes a first developer skeleton for optional QUB shielded pool flows:

```bash
./build/qrx-cli --network alpha --datadir ./data --wallet node1 shielded-address
./build/qrx-cli --network alpha --datadir ./data --wallet node1 shield <amount>
./build/qrx-cli --network alpha --datadir ./data --wallet node1 shielded-balance
./build/qrx-cli --network alpha --datadir ./data --wallet node1 shielded-send <zqub1...> <amount>
./build/qrx-cli --network alpha --datadir ./data --wallet node1 unshield <qrx...> <amount>
./build/qrx-cli --network alpha --datadir ./data --wallet node1 shielded-history
```

This is not audited zk privacy. It is a skeleton for GUI/Core integration before adding real proof verification.


## Stealth Addresses

This tree includes a developer skeleton for optional QUB stealth receiving:

```bash
./build/qrx-cli --network alpha --datadir ./data --wallet node1 stealth-address
./build/qrx-cli --network alpha --datadir ./data --wallet node2 stealth-send <squb1...> 1000
./build/qrx-cli --network alpha --datadir ./data --wallet node1 stealth-scan
./build/qrx-cli --network alpha --datadir ./data --wallet node1 stealth-history
```

Policy: transparent QUB remains default and exchange-compatible. Stealth addresses are optional wallet-to-wallet privacy and should not be used as centralized exchange deposit addresses.
