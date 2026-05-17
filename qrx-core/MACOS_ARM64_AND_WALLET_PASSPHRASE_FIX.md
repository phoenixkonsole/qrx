# macOS ARM64 and qrxd wallet passphrase behavior

## macOS Apple Silicon builds

CMake now defaults `CMAKE_OSX_ARCHITECTURES` to `arm64` on Apple Silicon unless you explicitly override it.

If you still get an Intel binary, delete the build directory and ensure the shell is not running under Rosetta:

```bash
uname -m
arch
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
file build/qrxd
```

Expected on M1/M2/M3:

```text
Mach-O 64-bit executable arm64
```

If it still says `x86_64`, your terminal/Homebrew/CMake/OpenSSL toolchain is x86_64.

## qrxd passphrase behavior

`seed-new` encrypts wallet keys and normally asks for a passphrase.

`qrxd` previously auto-created alpha/testnet/regtest wallets with:

```text
QRX_PASSPHRASE=change-me
```

but after restart it did not set that environment variable again. Then the block-producer path called signing commands (`propose-block`, `vote-block`) and `get_passphrase()` prompted interactively.

This build fixes that:

- `--wallet-passphrase PASS` sets the wallet passphrase explicitly.
- `QRX_PASSPHRASE` remains supported.
- alpha/testnet/regtest keep backward compatibility with `change-me`.
- mainnet does **not** silently default to `change-me`.

For mainnet validator use:

```bash
QRX_PASSPHRASE='your strong passphrase' ./qrxd --network mainnet
```

or:

```bash
./qrxd --network mainnet --wallet-passphrase 'your strong passphrase'
```

For node-only mode:

```bash
./qrxd --no-block-producer
```
