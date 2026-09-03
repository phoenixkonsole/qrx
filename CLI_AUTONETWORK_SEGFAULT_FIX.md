# QRX CLI Auto-Network Segfault Fix

Fixed a crash in `qrx-cli` when called without an explicit `--network` argument.

## Problem

`qrx-cli --network alpha help` worked, but commands like:

```bash
./qrx-cli help
./qrx-cli getnodestatus
```

could crash on macOS with a segmentation fault.

## Cause

The CLI had the auto-detection helper in place, but the resolved network value was not assigned back to the `network` pointer before calling the node path setup and RPC port selection.

## Fix

Network resolution is now applied before `qrx_ensure_node()`:

1. explicit `--network`
2. `QRX_NETWORK` environment variable
3. `~/.qrx/current_network`
4. fallback to `alpha`

This makes the following work as expected:

```bash
./qrx-cli help
./qrx-cli getnodestatus
./qrx-cli getblockchaininfo
```
