# QRX 0.0.7 – Wallet/Daemon Identity + Unlock + BTC Cleanup

This patch fixes a dangerous UI/runtime mismatch where the GUI could show wallet `default` while an already-running qrxd on the same network RPC port was still serving another wallet such as `node1` from the former GUI-only data directory.

## Changes

- Daemon health now reports the actual wallet name and wallet directory returned by Core `getinfo`.
- The GUI detects wallet-name and data-root mismatches and shows a prominent WALLET/DAEMON MISMATCH instead of presenting RPC data as if it belonged to the selected GUI wallet.
- Unlock preflight refuses to report a misleading "incorrect passphrase" when the selected GUI wallet and running daemon are different.
- Starting a node no longer silently accepts an already-running daemon for a different wallet/data root.
- Wallet Manager scans the old GUI store (macOS: `~/Library/Application Support/gui-wallet/qrx-data/<network>/wallets/`) and offers a copy-only `Import safely` action into the shared `~/.qrx/<network>/wallets/` store. The source wallet is left untouched.
- Obsolete embedded BDK/BTC wallet implementation was removed from the Tauri frontend backend. BTC operations continue through the shared `qrx-btc-wallet-service`.
- Unused BDK imports and obsolete dead-code helpers were removed; the remaining BDK import is only the Bitcoin address/network parser used by the address book.

## Why this mattered

A screenshot can otherwise show `Current wallet: default` while `getwalletinfo/getinfo` return `wallet_dir: .../wallets/node1`. In that state an empty-passphrase attempt is verified against `default`, so it can correctly fail even though the old `node1` wallet uses an empty legacy PKCS#8 passphrase.
