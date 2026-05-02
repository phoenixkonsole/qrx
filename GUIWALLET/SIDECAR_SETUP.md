# Strict Tauri sidecar setup

## Important rule

Do not ship QUBITCOIN Core as loose files or Tauri `resources`. Use `externalBin`.

## Sidecar names

Tauri uses base names in config and target-suffixed files on disk.

Config base name:

```text
bin/qrxd
```

Linux file:

```text
bin/qrxd-x86_64-unknown-linux-gnu
```

Windows file:

```text
bin/qrxd-x86_64-pc-windows-msvc.exe
```

macOS Intel file:

```text
bin/qrxd-x86_64-apple-darwin
```

macOS Apple Silicon file:

```text
bin/qrxd-aarch64-apple-darwin
```

## Current archive status

This archive contains real Linux x64 sidecars only. It intentionally does not include fake Windows/macOS binaries. Add real native QUB binaries before building those platforms.

## Avoid permission friction

### Linux

Use `.deb` for normal users. AppImage is optional.

### macOS

Use signed + notarized + stapled DMG.

### Windows

Use MSI/NSIS with code signing.
