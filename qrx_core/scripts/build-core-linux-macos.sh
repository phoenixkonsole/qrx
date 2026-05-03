
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../vendor/qrx-core"
cmake -S . -B build
cmake --build build -j
echo "Built QRX core in vendor/qrx-core/build"
