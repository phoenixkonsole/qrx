# Build notes

## Why strict sidecars?

The QUBITCOIN Core tools are executable sidecars, not normal resources:

- `qrx`
- `qrx-cli`
- `qrxd`

They are referenced through `tauri.bundle.externalBin` using base names only. Tauri then picks the correct target-suffixed binary for the platform being built.

## Linux

```bash
bash scripts/prepare-sidecars.sh
npm run build:linux
```

The Linux config builds `.deb` and `.AppImage`. Prefer `.deb` for non-technical users.

## macOS

Add real macOS QUB binaries first, then build on macOS:

```bash
npm run build:macos
```

For public distribution, sign, notarize and staple the final app/DMG.

## Windows

Add real Windows QUB binaries first, then build on Windows:

```powershell
npm run build:windows
```

For public distribution, use Authenticode/code signing for the installer to reduce SmartScreen friction.
