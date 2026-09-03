# QRX 0.0.7 Kraken Spot Gateway — Validation Report

Date: 2026-09-01
Base: QRX Core 0.0.7 VELOCITY Phase 4F

## New implementation

- `gateways/qrx-gateway-kraken.py`
- Wallet `Agents & Kraken` UI
- session-only credential prompt is default
- optional Argon2id + AES-256-GCM encrypted credential vault
- stdin-only secret handoff to child gateway
- deterministic Kraken `cl_ord_id`
- Kraken Spot Add/Query/Open/Closed/Cancel reconciliation
- local non-secret SQLite idempotency state
- gateway-signed QRX execution reports
- external `cancel_pending` consensus state

## Automated checks passed

- Core release build: PASS
- Kraken Python gateway unit tests: 8/8 PASS
  - official Kraken REST HMAC signature test vector
  - deterministic 32-hex client order ID
  - BTC/XBT and DOGE/XDG market aliasing
  - AssetPairs precision/minimum parsing
  - SQLite pending-report restart persistence
  - atom/decimal conversion
  - API permission response parsing
  - withdrawal-enabled key refusal
- VELOCITY 4A–4F: 6/6 PASS
- VELOCITY 4A–4F under ASan + UBSan: 6/6 PASS
- Phase 3A agent trading: PASS
- Phase 3B native matching/settlement: PASS
- Phase 3C external gateway/reports: PASS
- Kraken `submitted -> cancel_pending -> canceled` integration: PASS
- Phase 3D BTC/QUB cross-chain: PASS
- Phase 3D.1 Bitcoin SPV/reorg safety: PASS
- QRX Core 0.0.6 feature regression audit: PASS, 59/59 legacy CLI commands present
- QRXDB outer-apply WAL crash recovery: PASS
- GUI Wallet inline JavaScript syntax (`node --check`): PASS
- Tauri configuration JSON files: PASS
- Gateway Python bytecode compilation: PASS

## Build-environment limitation

The GUI Wallet's Rust/Tauri layer could not be compiled in this environment because neither `cargo` nor `rustc` is installed. The Rust source was edited consistently with the existing dependencies (`argon2`, `aes-gcm`, `base64`, `rand`, `serde`), while JavaScript and Tauri JSON were statically validated. A normal wallet CI/macOS/Windows/Linux build should compile the Tauri layer before distributing binaries.

## Live-exchange limitation

No private Kraken API credential was available, so the automated test suite did not send a real AddOrder/CancelOrder to Kraken. The authentication algorithm is covered by Kraken's published signature test vector and the endpoint shapes were checked against current Kraken Spot documentation, but a tiny controlled live Spot smoke test remains required before using meaningful funds.
