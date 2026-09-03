# Kraken Agent Manager Validation

Validated in this release workspace:

- Kraken gateway Python unit tests: 8/8 pass
- Wallet JavaScript parse: pass
- Agent Manager command registration and UI wiring: pass
- Register and revoke paths create raw transactions and invoke
  `sendrawtransaction`: static interface check pass
- Input validation for markets, positive integer limits and expiry heights is
  implemented in the trusted Tauri layer (not only JavaScript)
- Original Phase 4F + Kraken archive integrity: pass

Native rebuild limitations of this environment:

- `cargo` / `rustc` unavailable: Tauri Rust changes were not compiled here
- `cmake` unavailable: existing QRX Core C binaries/tests were not rebuilt here

No live Kraken order and no real on-chain agent registration was submitted,
because production credentials and funded wallets are intentionally absent.
