# Quantum Guard Requester

This build replaces the simple HTLC hard-toggle UX with a safer request/confirm flow.

## What it adds

- Glass-style Quantum Guard modal/requester.
- Preview step before critical QUB HTLC actions.
- Exact confirmation phrase required:
  - `I UNDERSTAND HTLC RISK`
- Per-action confirmation for:
  - Create QUB HTLC
  - Redeem QUB HTLC
  - Refund QUB HTLC
- Audit log:
  - `audit/quantum_guard.log`
- GUI audit viewer in the Quantum Swaps Safety panel.

## Why this is safer

The mainnet safety toggle still exists, but Quantum Guard now requires explicit confirmation for every dangerous action. This prevents a single global toggle from silently allowing all future HTLC actions.

## Important

This is still release-candidate swap logic. Use alpha/testnet and tiny amounts only until audited.
