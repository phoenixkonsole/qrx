# QRX 0.0.7 GUI – Empty-passphrase session persistence fix

Fixes a race/state regression where a successfully verified 0.0.6 encrypted PKCS#8 wallet briefly rendered as Unlocked and was immediately reset to Locked by the asynchronous wallet inspector.

- Wallet inspection is now read-only with respect to an already verified session.
- Legacy encrypted-container/empty-passphrase wallets are explicitly synchronized with the Core and marked unlocked after successful verification.
- Unencrypted wallets are represented as requiring no unlock.
- A failed verification still leaves the wallet locked.
