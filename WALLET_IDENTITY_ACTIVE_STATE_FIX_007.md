# QRX 0.0.7 GUI Wallet — Canonical Wallet Identity & Active-State Fix

## Problem
The GUI could show different QUB addresses for the same apparent wallet because the Receive view treated the first `listaddresses` entry as the primary address. Legacy 0.0.6 wallets may have a different `addresses.txt` ordering after additional receive addresses were generated. The sidebar could also retain `node1` while the Wallet Manager was already using another profile such as `default`.

## Canonical address rule
`address.txt` is now the single canonical wallet identity used by the GUI. `listaddresses` is used only to discover additional receive addresses. Its ordering can never redefine the primary wallet address.

## New Tauri address resolver
`get_wallet_address_set` returns:
- canonical `primary_address` from `address.txt`
- optional `manifest_address` from `wallet.json`
- merged address list with the primary address first
- `additional_addresses`
- an `address_mismatch` flag and warnings

If `address.txt` and `wallet.json` both exist but disagree, the GUI displays `WALLET ADDRESS MISMATCH` and keeps `address.txt` canonical instead of silently choosing one from a list.

## Receive view
Addresses are explicitly labelled:
- `Primary wallet address` — canonical identity from `address.txt`
- `Additional receive address N` — stored receive address, not wallet identity

Selecting an additional receive address only changes the displayed QR/receive target. It never changes the wallet identity shown in the sidebar or Wallet Manager.

## Active wallet state
Wallet selection now uses one state update path. The sidebar and Wallet Manager are synchronized from `appState.wallet` whenever the app boots or the active wallet changes. The previous static `node1` display cannot remain while `default` is active.

## Safety
No wallet file, address or private key is deleted or rewritten by this patch. Existing additional receive addresses remain available. This is a GUI/state-classification fix plus read-only mismatch detection.
