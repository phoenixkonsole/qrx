# BDK macOS Build Fix

The previous Cargo configuration used:

```toml
bdk = { version = "0.29", default-features = false, features = ["all-keys", "electrum"] }
```

That disabled `std` in the `miniscript` dependency chain on some Rust/macOS setups, causing:

```text
miniscript: at least one of the `std` or `no-std` features must be enabled
```

This build fixes it by allowing BDK default features and explicitly enabling `miniscript/std`.

## If Cargo still uses old resolution

Run:

```bash
cd gui_wallet
rm -f src-tauri/Cargo.lock
cargo clean --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

Or from inside `src-tauri`:

```bash
rm -f Cargo.lock
cargo clean
cd ..
npm run tauri dev
```
