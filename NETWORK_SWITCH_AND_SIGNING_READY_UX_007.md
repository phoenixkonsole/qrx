# QRX 0.0.7 – Network switch + signing-ready UX

- Header claim changed to: “Your gateway to QUBITCOIN — secure payments, staking, BTC Light and Quantum Swaps.”
- GUI network selector supports mainnet, alpha, testnet and regtest.
- Network-specific wallet selection is remembered separately.
- Wallet/balance/address/RPC state is cleared and refreshed when switching networks.
- 0.0.6 encrypted PKCS#8 wallets are cryptographically probed with the empty passphrase before the GUI asks for a password.
- If the empty passphrase verifies, the wallet is shown as “Ready · legacy wallet · no password set” and no password prompt is shown.
- A real passphrase-protected wallet remains “Locked · password required to sign”.
- Core development-fund addresses are already network-specific for mainnet, alpha, testnet and regtest.
