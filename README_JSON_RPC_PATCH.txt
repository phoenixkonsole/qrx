QRX JSON-RPC Patch

Replace these files in qrx-core:

CMakeLists.txt
src/qrxd.c
src/qrx_cli.c

What is added:
- HTTP JSON-RPC endpoint on qrxd
- --rpc-bind host:port
- --rpc-user USER
- --rpc-password PASS
- HTTP Basic Auth when user/password are provided
- Cross-platform TCP localhost RPC on Windows, macOS, Linux
- qrx-cli now talks to the HTTP JSON-RPC endpoint
- qrx-cli supports --rpc-user and --rpc-password
- qrx-cli also reads QRX_RPC_USER and QRX_RPC_PASSWORD env vars

Default RPC ports:
mainnet: 127.0.0.1:37660
alpha:   127.0.0.1:37661
testnet: 127.0.0.1:37662
regtest: 127.0.0.1:37663

Example qrxd:
./qrxd --network alpha --rpc-bind 127.0.0.1:37661 --rpc-user qrx --rpc-password change-this

Example qrx-cli:
./qrx-cli --network alpha --rpc-user qrx --rpc-password change-this getinfo

Example curl:
curl -u qrx:change-this \
  -H "Content-Type: application/json" \
  -d "{\"method\":\"getinfo\",\"params\":[]}" \
  http://127.0.0.1:37661/rpc

Security:
- Keep --rpc-bind at 127.0.0.1 for local wallet use.
- Do not bind to 0.0.0.0 unless you really know what you are doing.
- Use a strong password before any public or remote exposure.
