# QRX 0.0.7 GUI ↔ Core Compatibility Audit

This release explicitly audits the Tauri GUI against the bundled `qrx-cli` and `qrxd` instead of assuming command parity.

## Result

**PASS after fixes in this patch.** The GUI's release-critical QUB commands are present in the current 0.0.7 CLI/daemon surface: node/wallet info, balance, receive addresses, history, staking, validators, peers, tokenomics, send, Quantum Swaps, agent registration/revocation, arbitrage hedge creation, raw transaction signing/broadcast and daemon stop.

## Incompatibilities found and corrected

1. **Legacy control socket display.** The GUI still constructed `~/.qrx/<network>/control.sock`. Current `qrx-cli` talks to `qrxd` over HTTP JSON-RPC at `/rpc`. The UI now shows an RPC endpoint (`37660` mainnet, `37661` alpha, `37662` testnet, `37663` regtest), matching Core.
2. **Hard-coded alpha P2P port.** GUI-started `qrxd` forced `--listen 127.0.0.1:26661`, even for non-alpha networks. The override is removed; `qrxd` now uses the selected network profile's native P2P settings.
3. **History argument mismatch.** The GUI attempted `history "" <limit>`. The CLI's whitespace command transport drops the empty argument, turning the limit into an address. Default history now uses `history` directly; non-default limits first resolve the wallet address and then call `history <address> <limit>`.
4. **Unlock was UI-only.** A passphrase validated by the Tauri frontend was stored in GUI RAM, but an already-running `qrxd` did not receive it. The Core now exposes `walletpassphrasehex` and `walletlock` via the local CLI/RPC surface. The GUI verifies the encrypted PEM locally, then synchronizes the running daemon using hex encoding so spaces/special characters survive the legacy CLI command framing. Lock clears the daemon session secret as well.
5. **Misleading health semantics retained but bounded.** `daemon_health` may report a GUI-launched child as running even if an individual RPC query fails. The dashboard's Wallet Info and Node Info therefore remain independent timed requests and report explicit errors instead of endless Loading states.

## Data path parity

GUI, `qrx-cli`, and `qrxd` all use the shared root `~/.qrx`, passed as `--datadir ~/.qrx`. Core resolves this to `~/.qrx/<network>`, with wallets under `~/.qrx/<network>/wallets/<name>`.

## Automated release gate

Run:

```bash
python3 scripts/audit-gui-core-compat.py
```

The script fails if a GUI Core command disappears from `qrx-cli`, if the old `control.sock` assumption returns, if alpha's P2P port is hard-coded into GUI daemon startup, if the history empty-address bug returns, or if runtime wallet lock/unlock parity disappears.

This is a static compatibility gate. Native release builds and runtime smoke tests remain required on each target OS.
