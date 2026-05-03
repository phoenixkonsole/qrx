
# QRX Wallet Desktop (Tauri Core Integration)

Modern, lightweight desktop wallet starter for **Windows, macOS and Linux** with direct **QRX Core integration**.

## Stack

- Tauri v2
- React + TypeScript
- QRX Core CLI bridge via `qrx-cli`
- Bundled QRX core source in `vendor/qrx-core`

## What is included

- modern wallet UI shell
- dashboard, send, receive, activity, stake, settings
- Tauri Rust commands that call the existing QRX core CLI
- build scripts for the included QRX core
- one-zip starter repository

## Integration approach

This starter uses **CLI integration** first:

```text
Tauri UI -> Rust commands -> qrx-cli -> qrxd control socket -> QRX core
```

This is the fastest safe way to get a real wallet running against your current core.

## Build QRX core

### Linux / macOS

```bash
cd vendor/qrx-core
cmake -S . -B build
cmake --build build -j
```

### Windows

Use CMake and a supported OpenSSL install. Example with Visual Studio generator:

```powershell
cd vendor/qrx-core
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## Run the wallet app

```bash
npm install
npm run tauri dev
```

## Core binary paths

The Tauri bridge looks for these binaries by default:

- Linux / macOS:
  - `vendor/qrx-core/build/qrx-cli`
  - `vendor/qrx-core/build/qrxd`
- Windows:
  - `vendor/qrx-core/build/Release/qrx-cli.exe`
  - `vendor/qrx-core/build/Release/qrxd.exe`

You can override them in the Settings screen.

## Commands currently mapped

- getinfo
- getblockcount
- getwalletinfo
- getstakinginfo
- getbalance
- getnewaddress
- history
- sendtoaddress
- stake
- delegate
- validator-set
- tokenomics
- stop

## Alpha warning

This wallet is intended for **QRX alpha / pre-genesis testing**.  
Do not treat it as production-ready custody software.

## Next recommended step

After this CLI-based wallet works end-to-end, the next step is to add a JSON-RPC layer to QRX Core and swap the bridge from subprocess calls to RPC.

