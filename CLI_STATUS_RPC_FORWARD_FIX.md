# CLI Status RPC Forward Fix

This patch fixes qrx-cli command dispatch for the dashboard/status RPC commands.

The usage text already listed these commands, and qrxd already implemented them, but qrx-cli did not forward them to the daemon.

Fixed CLI commands:

- getblockchaininfo
- getnetworkinfo
- getnodestatus
- getuptime
- getbuildinfo

Example:

```bash
./qrx-cli getnodestatus
./qrx-cli getblockchaininfo
./qrx-cli getnetworkinfo
```
