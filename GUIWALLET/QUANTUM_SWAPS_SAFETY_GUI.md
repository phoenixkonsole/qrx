# Quantum Swaps Safety GUI

This build adds an explicit GUI safety layer for QUBITCOIN Core HTLC / Quantum Swaps.

## Added UI

In **Quantum Swaps**:

- Safety status panel
- Mainnet activation disclaimer
- Exact confirmation field:
  - `I UNDERSTAND EXPERIMENTAL HTLC RISK`
- Enable / disable experimental HTLC
- Reminder to restart daemon after changing mainnet HTLC activation
- Core command buttons:
  - Create QUB HTLC
  - Get swap
  - List swaps
  - Redeem
  - Refund

## Backend commands added

- `htlc_safety_status`
- `htlc_set_safety`
- `core_create_swap`
- `core_get_swap`
- `core_list_swaps`
- `core_redeem_swap`
- `core_refund_swap`

## Mainnet behavior

For mainnet-like networks, the GUI will not enable HTLC unless the user types:

```text
I UNDERSTAND EXPERIMENTAL HTLC RISK
```

When enabled, the GUI starts `qrxd` with:

```bash
QRX_ENABLE_MAINNET_HTLC=I_UNDERSTAND_EXPERIMENTAL
```

## Important

The QUB Core HTLC implementation is still a release-candidate feature. Use alpha/testnet first and tiny values only until audited.
