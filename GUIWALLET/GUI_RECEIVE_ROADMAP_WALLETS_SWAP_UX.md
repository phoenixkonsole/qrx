# QRX 0.0.7 GUI UX update

## Receive QR
- Replaced the decorative/fingerprint canvas with a real scannable QR code.
- QR SVG is generated locally in the Tauri/Rust backend via the `qrcode` crate.
- No external QR service receives the wallet address.

## Roadmap view
- Added visible 0.0.7, 0.0.8 and 0.0.9 roadmap cards.
- 0.0.8: Proof of Storage, providers/contracts, cryptographic verification, QRX Drive, enterprise backup and AI/document artifact persistence.
- 0.0.9: Distributed AI Compute Fabric, heterogeneous Windows/Linux/macOS x86-64/ARM64 nodes, CPU acceleration, benchmark-driven scheduling, distributed MoE, Kimi K3 reference workload, SeaweedFS model distribution and QUB compute rewards.

## Wallet manager
- Added a real Wallets view backed by `list_wallets`.
- Shows current wallet, shared Core store, wallet version and legacy safety-backup state.
- Switching wallets calls `prepare_existing_wallet` first, retaining the no-overwrite and pre-0.0.7 backup protections.

## Quantum Swaps
- Reorganized the long form into three panels: Swap, Safety & Audit, Status & Legal.
- Advanced HTLC parameters are collapsed under a details element by default.

## Validation
- JavaScript syntax checked with Node.js.
- build-all-targets.sh passed `bash -n`.
- Full Rust compilation must still be performed on a machine with Cargo/Rust installed.
