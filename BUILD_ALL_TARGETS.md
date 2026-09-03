# QRX unified multi-target build

`scripts/build-all-targets.sh` is the single release entry point. For each target it always builds in dependency order:

1. QRX Core and QRXDB;
2. `qrx`, `qrx-cli`, `qrxd` and QRXDB maintenance executables;
3. the complete Python CLI/export/arbitrage/Kraken tool set;
4. the shared Rust `qrx-btc-wallet-service`;
5. target-suffixed sidecars;
6. the Tauri wallet and native installers;
7. a checksummed target release.

The Tauri step cannot run before the Core and BTC-service steps because `externalBin` resolves the exact target-suffixed sidecar files at bundle time.

## All operating systems concurrently

Run the single entry point with `--all`, or start the GitHub Actions workflow **Build all QRX wallets** directly. Its five native jobs run concurrently:

```bash
bash scripts/build-all-targets.sh --all
```

| Target | Native runner | Output |
| --- | --- | --- |
| Linux x64 | Ubuntu 22.04 | DEB, AppImage, Core, CLI and tools |
| Linux ARM64 | Ubuntu 22.04 ARM | DEB, AppImage, Core, CLI and tools |
| macOS Intel | macOS 15 Intel | APP, DMG, Core, CLI and tools |
| macOS Apple Silicon | macOS 15 arm64 | APP, DMG, Core, CLI and tools |
| Windows x64 | Windows 2025 | MSI, NSIS, Core, CLI and tools |

Start it in GitHub under **Actions → Build all QRX wallets → Run workflow**, or push a tag beginning with `v0.0.7`.

## Local build

Build the target matching the current native host:

```bash
bash scripts/build-all-targets.sh
bash scripts/build-all-targets.sh --target host
bash scripts/build-all-targets.sh --target linux-x64
bash scripts/build-all-targets.sh --target linux-arm64
bash scripts/build-all-targets.sh --target macos-arm64
bash scripts/build-all-targets.sh --target macos-x64
bash scripts/build-all-targets.sh --target windows-x64
```

From Windows PowerShell, the equivalent native command is:

```powershell
.\scripts\build-all-targets.ps1 -Target windows-x64
```

With `host`, Linux ARM64/aarch64, Linux x86-64, macOS Intel/ARM and Windows x64 are detected automatically. Validate the complete order without compiling:

```bash
bash scripts/build-all-targets.sh --target linux-x64 --plan
```

Outputs are placed in `dist/`. Every archive contains `manifest.json` and `SHA256SUMS.txt`; the archive itself has a sibling `.sha256` file.

The complete matrix additionally produces `dist/qrx-0.0.7-linux-arm64.zip`. Linux builds are deliberately native: selecting `linux-arm64` on an x86-64 host fails instead of accidentally labelling an x86 binary as ARM.

macOS and Windows code signing credentials are intentionally not stored in the repository. Unsigned development installers can be built without them; public releases should add signing and Apple notarization as protected CI secrets.
