# QRX Core v0.0.6 Wallet Address RPC Patch

This patch makes `getnewaddress` behave like users expect from Bitcoin-style nodes.

## Changes

- `qrx-cli getnewaddress` now creates a fresh QRX address instead of returning the primary wallet address.
- New addresses are stored under the active wallet directory in `addresses/<address>/`.
- The wallet keeps an `addresses.txt` index containing the primary address and all generated addresses.
- Added `qrx-cli listaddresses` RPC command.
- `address` and `receive` still return the primary wallet address for compatibility.
- Direct backend commands added:
  - `qrx wallet-new-address <wallet-dir>`
  - `qrx listaddresses <wallet-dir>`

## Usage

Start the daemon:

```bash
./qrxd --network mainnet
```

Create a new receiving address:

```bash
./qrx-cli --network mainnet getnewaddress
```

List all addresses in the active wallet:

```bash
./qrx-cli --network mainnet listaddresses
```

Show the primary wallet address:

```bash
./qrx-cli --network mainnet address
```

## Note

Generated addresses are encrypted with the same wallet passphrase used by the daemon environment.
