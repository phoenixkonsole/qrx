# QUB Roadmap: GUI Wallet, Quantum Swaps and Privacy

## Product positioning

- **GUI Wallet**: the main beginner-friendly desktop wallet for QUB.
- **BTC Light**: a compact Bitcoin module that avoids a Bitcoin full-node download.
- **BTC on the Rocks**: the user-facing BTC -> QUB entry experience.
- **Quantum Swaps**: the QUB swap engine/technology brand for non-custodial cross-chain swaps.
- **Privacy**: a staged roadmap, not an overclaim. The app should never imply guaranteed anonymity.

## Phase 1 — GUI Wallet Foundation

Status: prepared in this archive.

- Tauri desktop app
- QUBITCOIN Core sidecars
- wallet create / restore / import / export UX
- QUB send / receive / staking UX
- daemon health and logs
- BTC Light screen
- Quantum Swaps screen
- Privacy screen
- clear non-custodial disclaimers

## Phase 2 — BTC Light MVP

Goal: BTC support without requiring users to download the Bitcoin blockchain.

Recommended implementation:

- Rust backend module using BDK
- Electrum or Esplora backend in easy mode
- optional user-defined endpoint in advanced mode
- local key management
- BTC balance, receive address, transaction building and monitoring

Important: BTC Light is legal as normal non-custodial wallet software when you do not hold user funds, do not control keys and do not operate a custodial exchange.

## Phase 3 — Quantum Swaps MVP

Goal: prepare BTC <-> QUB swaps with a smooth UX.

MVP approach:

- coordinator-ready swap drafts
- quote, fee and timeout display
- lock/redeem/refund status screens
- no custody claims
- no “guaranteed execution” claims

Production target:

- QUBITCOIN Core HTLC support
- Bitcoin HTLC transaction builder
- swap states: quote, lock, redeem, refund, expired

Suggested QUBITCOIN Core commands:

```bash
qrx-cli createswap --hash <h> --amount <amount> --timeout <height>
qrx-cli participateswap --swap <id>
qrx-cli redeemswap --swap <id> --secret <secret>
qrx-cli refundswap --swap <id>
```

## Phase 4 — Neutrino / BIP157

Goal: reduce dependence on public BTC servers.

- compact block filter sync
- local filter matching
- better privacy than server-assisted address lookups
- no BTC full-node requirement

User-facing wording:

> Neutrino mode improves local verification and privacy, but it does not guarantee anonymity.

## Phase 5 — Privacy Layer

Short-term:

- address reuse warnings
- coin control
- endpoint selection
- local-only key handling

Mid-term:

- BTC Neutrino privacy mode
- better swap metadata minimization

Long-term R&D:

- QUB shielded transaction research
- stealth address research
- optional privacy-preserving relay design

## Legal / UX wording

Use:

> This wallet is non-custodial software. You remain in control of your keys and funds.

Use:

> Quantum Swaps are designed around timelocks and refund paths.

Avoid:

> We protect your BTC.
> Guaranteed anonymous swaps.
> Quantum-secured Bitcoin.
> Unhackable swaps.

