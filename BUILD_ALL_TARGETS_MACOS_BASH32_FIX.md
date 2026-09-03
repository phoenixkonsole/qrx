# Unified compiler script macOS Bash 3.2 fix

The unified `scripts/build-all-targets.sh` no longer expands an empty Bash array
for Cargo's optional `--locked` flag. macOS ships Bash 3.2, where `set -u` can
report an empty `${array[@]}` as an `unbound variable`.

The BTC wallet service build now uses an explicit conditional:

- with `GUIWALLET/src-tauri/Cargo.lock`: `cargo build --locked ...`
- without a lock file: `cargo build ...`

`GUIWALLET/src-tauri/bin/` now contains no prebuilt or placeholder QRX binaries.
The unified build script stages freshly compiled target-specific sidecars into
that directory before invoking the Tauri build.
