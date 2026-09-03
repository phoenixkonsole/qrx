# QRX 0.0.7 — Global QUB Balance Sidebar

The active QUB wallet balance is now persistent UI state and is rendered in the left sidebar on every wallet view.

## Behaviour
- Shows the live balance from `get_wallet_info` for the selected wallet.
- Never substitutes `0` when the balance is unavailable.
- Shows `— QUB` with a reason for node offline, locked wallet, wallet/node mismatch, or unavailable RPC data.
- Shows the current staking amount when the staking RPC exposes a recognized wallet stake field.
- The Dashboard balance and Send balance reuse the same canonical value.
- Wallet switches immediately clear the previous wallet's balance to prevent stale cross-wallet display.
- A successful QUB send refreshes the canonical balance immediately.

This makes wallet name, primary address, QUB balance and wallet lock state persistent wallet identity/status information in the sidebar.
