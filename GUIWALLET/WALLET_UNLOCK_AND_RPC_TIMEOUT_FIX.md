# QRX 0.0.7 GUI Wallet — Explicit Unlock + RPC Timeout Fix

## Wallet unlock UX

- Encrypted wallets start in `Locked` state.
- Typing a passphrase does not unlock the wallet.
- Press Enter or click `Unlock` to verify the passphrase against an encrypted private PEM key.
- Only after successful verification is the passphrase kept in process memory for this app session.
- `Lock wallet` discards the in-memory passphrase immediately.
- Wallet changes discard the previous wallet passphrase.
- The passphrase is not written to localStorage, wallet metadata, config, or logs.
- Unencrypted wallets show `No passphrase required` and hide unlock controls.

## Wallet/Node info loading

Dashboard RPC calls now use bounded UI timeouts. `get_wallet_info` and `get_node_info` are explicitly queried during refresh and always leave the `Loading…` state. Timeout/error states are rendered as readable `unavailable` messages rather than an infinite spinner/text placeholder.

The underlying Tauri invocation cannot be forcibly cancelled by JavaScript, but a stalled RPC can no longer block dashboard presentation indefinitely.
