# Compile Fix 2

Fixes reported macOS/Rust build errors:

- `Mnemonic::generate(...).map_err(|e| e.to_string())` changed to debug formatting because BDK 0.29 returns an optional bip39 error in that path.
- BTC send address now calls `require_network(btc_network())` before `script_pubkey()`.
- AURA `token_hint` assignment converted to `String`.
- Removed unused BDK imports.
