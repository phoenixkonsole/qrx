# QRX Core 0.0.7 — Phase 4F.2 Release Notes

## Unified native release builder

`scripts/build-all-targets.sh` now builds the complete dependency chain for one native target: Core and QRXDB executables, CLI and Python tools, the shared Rust BTC wallet service, target-suffixed Tauri sidecars, and finally the Tauri wallet installers. `--target host` automatically selects the local OS and CPU. `.github/workflows/build-all-targets.yml` runs Linux x64, Linux ARM64, Windows x64, macOS Intel and macOS Apple Silicon concurrently on native runners. Each result contains a manifest and SHA-256 checksums.

This release extends Phase 4F + the secure Kraken Spot gateway with cross-venue opportunity analysis, paper trading, a confirmation-only live IOC hedge route and a complete CSV ledger.

Highlights:

- real Kraken BTC/EUR depth is consumed level by level;
- all configured costs and safety buffers are deducted before acceptance;
- paper mode cannot reach the exchange submission path;
- live mode requires prefunded inventory, a fresh approved plan, a matched owner cross-chain BUY and a separately authorized agent;
- Kraken arbitrage orders use `LIMIT IOC`, a short request deadline and deterministic restart reconciliation;
- the Wallet has one-click German or international CSV export;
- the manifest reports row counts, SHA-256 hashes and incomplete data sources;
- the Agent Manager now offers the explicit `ARBITRAGE_CROSS_VENUE` permission;
- the Wallet's raw-transaction broadcast flow now signs a temporary transaction file before submitting it.

Parity and ledger correction:

- Tauri now exposes every `qrx-cli` command through a safe argument-array Command Center; mutations require confirmation and wallet unlock;
- the new `qrx-wallet-cli.py` adds the same Phase 4F.2 arbitrage, paper, Kraken and CSV tooling to the command-line wallet;
- the hard-coded one-million trade ceiling is removed from the local Core reader (`all` means all);
- CSV V3 bypasses bounded interactive RPC buffers, pins QRXDB generation/State Root, filters to the selected wallet, supports all-time/year/quarter/from-to periods and publishes atomically;
- Tauri and `qrx-wallet-cli` now use the same Rust BDK key-store service through a stdin-only JSON protocol;
- persisted BDK private descriptors are removed; signing descriptors exist only in unlocked process memory;
- missing/inconsistent sources now fail the export instead of producing a misleading partial bundle;
- paper profits are estimates and are no longer classified as realized profit.

See `VELOCITY_007_PHASE4F2_CROSS_VENUE_ARBITRAGE_CSV.md` for the design and limitations and `VELOCITY_007_PHASE4F2_VALIDATION.txt` for validation details.
