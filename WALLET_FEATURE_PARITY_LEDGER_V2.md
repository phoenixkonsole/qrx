# QRX Wallet Feature Parity and Complete Ledger V3

## Result

Phase 4F.2 now has one functional capability surface across the desktop and command-line wallets for QRX Core, agents, trading, cross-chain orders, Kraken, arbitrage and ledger export:

- Tauri keeps the guided buttons for everyday operations and adds a safe **Complete Command Center** for every native `qrx-cli` command.
- `qrx-wallet-cli.py` passes every native Core command through unchanged and adds the Phase 4F.2 arbitrage, paper-trading, secure Kraken-start and complete-ledger tools.
- Neither bridge invokes a shell. Desktop state-changing commands require an explicit confirmation and an unlocked wallet.

The interfaces are intentionally different: Tauri presents forms and confirmations, while the command-line wallet presents subcommands and JSON. The underlying QRX Core, agent permissions, order types and state transitions are the same.

The BDK/Electrum **BTC Light wallet** now runs through `qrx-btc-wallet-service`. Tauri and `qrx-wallet-cli btc ...` use the same encrypted wallet file, descriptors, address index, endpoint settings, transaction builder and broadcast path. Passphrases and recovery words are transferred through stdin JSON and never process arguments.

## Why the old one-million limit was wrong

`1,000,000` was a defensive maximum for one in-memory list operation. It was not a statement about the number of trades QRX can contain. A complete ledger must not inherit an interactive response limit, and the daemon's bounded JSON buffers made the old path unsuitable even below that number.

The V3 exporter therefore does not use the interactive list RPC for bulk accounting data. It invokes the local read-only Core surface and requests:

```text
qrx list-trades <chain-dir> * all
```

There is no configured trade-count ceiling. Practical limits are available disk space, memory and processing time, not a hard-coded record count.

## Factual-completeness contract

The exporter now:

1. records QRXDB generation and State Root;
2. reads every selected-wallet address and all matching journal entries;
3. reads all orders, all trades and all cross-chain sessions;
4. filters orders, trades and swaps to the selected wallet's addresses;
5. reads the selected wallet's Kraken and arbitrage databases using SQLite read snapshots;
6. records QRXDB generation and State Root again after all off-chain reads;
7. retries when the chain changed during collection;
8. writes into a temporary directory and publishes it atomically only after success;
9. refuses the export if any required source failed or returned malformed/duplicate identifiers;
10. writes row counts, SHA-256 hashes and the exact half-open UTC period into `manifest.json` using `QRX_COMPLETE_LEDGER_V3`.

Periods can be selected as all-time, calendar year, quarter, or explicit from/to dates. A date-only `to` value is inclusive; the manifest records the normalized exclusive UTC boundary. Height-based records are mapped to actual block timestamps. Missing historical timestamps cause a fail-closed error rather than a guessed inclusion.

The exporter does not create a partial bundle marked as if it were complete. If the state keeps changing or a source cannot be read, it returns an error and leaves no final export directory.

Paper-trading profit remains an estimate and is no longer written as `realized_profit`. Only a completed live arbitrage lifecycle may populate that field.

## Command-line examples

```bash
python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 capabilities

python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 core gettradinginfo

python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 export-ledger --output ./ledger --profile de

python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 export-ledger --output ./ledger-2026 --profile de --year 2026

python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 export-ledger --output ./ledger-q2 --profile de --year 2026 --quarter 2

python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 export-ledger --output ./ledger-custom --profile de --from 2026-04-01 --to 2026-06-30

python3 qrx-core/tools/qrx-wallet-cli.py --network alpha --datadir ./data --wallet node1 arbitrage --list

python3 qrx-core/tools/qrx-wallet-cli.py --datadir ./data btc new-address
```

Kraken credentials for the command-line gateway are requested interactively with hidden input and passed once through stdin, matching the desktop wallet's no-cleartext-configuration rule.
