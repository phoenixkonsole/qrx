# QRX 0.0.7 — Send balance & self-address safety

The QUB Send screen now loads the active wallet context before review.

- Shows available QUB balance and estimated remaining balance before fees.
- Disables review when the entered amount exceeds the currently loaded balance.
- Shows an explicit insufficient-balance message instead of waiting for broadcast failure.
- Loads the canonical primary address plus all indexed receive addresses from the active wallet.
- Warns when the recipient is the wallet's own primary address or another address owned by the same wallet.
- Requires an additional confirmation for intentional self-transfers.
- Refuses send while a wallet/daemon identity mismatch is active.
- Adds a Max button using the currently loaded spendable balance.
- Refreshes send context after a successful send.

No wallet files, addresses, balances, or keys are modified by these preflight checks.
