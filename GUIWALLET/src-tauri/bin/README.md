# QUB sidecars

This folder uses Tauri strict sidecar naming.

The app config references only base names:

- `bin/qrx`
- `bin/qrx-cli`
- `bin/qrxd`

For each build target, place the matching binary with the target triple suffix:

```text
qrx-x86_64-unknown-linux-gnu
qrx-cli-x86_64-unknown-linux-gnu
qrxd-x86_64-unknown-linux-gnu

qrx-x86_64-apple-darwin
qrx-cli-x86_64-apple-darwin
qrxd-x86_64-apple-darwin

qrx-aarch64-apple-darwin
qrx-cli-aarch64-apple-darwin
qrxd-aarch64-apple-darwin

qrx-x86_64-pc-windows-msvc.exe
qrx-cli-x86_64-pc-windows-msvc.exe
qrxd-x86_64-pc-windows-msvc.exe
```

Only Linux x64 binaries are included in this archive. macOS and Windows builds should fail until the real native QUB binaries are added. This prevents accidental releases with placeholder executables.
