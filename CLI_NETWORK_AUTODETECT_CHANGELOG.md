# QRX Core v0.0.6 - CLI Network Auto-Detection Patch

This patch improves daemon/CLI usability for dashboard and community-node setups.

## Added

- `qrxd` now writes the active default network to `~/.qrx/current_network` when started without a custom `--datadir`.
- `qrx-cli` can now run commands without explicitly passing `--network`.
- `qrx-cli` network resolution order is now:
  1. explicit `--network <alpha|testnet|regtest|mainnet>`
  2. `QRX_NETWORK` environment variable
  3. `~/.qrx/current_network` written by the last default-datadir `qrxd` start
  4. fallback to `alpha`
- CLI usage text now marks `--network` as optional.
- `qrxd` usage text now marks `--network` as optional.

## Why

This makes dashboard and node monitoring commands easier to use. After starting a node with:

```bash
./qrxd --network mainnet
```

users can now run:

```bash
./qrx-cli getnodestatus
./qrx-cli getblockchaininfo
./qrx-cli getnetworkinfo
./qrx-cli getwalletinfo
```

without repeating `--network mainnet` every time.

## Notes

- If a user starts `qrxd` with a custom `--datadir`, they should still pass the same `--datadir` and `--network` to `qrx-cli`.
- `QRX_NETWORK=mainnet` can be used to override auto-detection.
- Existing explicit `--network` behavior is unchanged and always takes priority.
