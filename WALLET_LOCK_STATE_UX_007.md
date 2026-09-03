# QRX 0.0.7 — Wallet Lock State UX clarification

This patch separates three independent states that were previously presented as one "locked wallet" condition.

- Password-protected wallet: public wallet data remains readable; private-key signing requires an explicit session unlock.
- Legacy 0.0.6 empty-passphrase PKCS#8 wallet: the GUI verifies the empty passphrase locally and then presents the wallet as `Ready · legacy wallet · no password set`. No password field is shown for normal use.
- Wallet/node mismatch: this is not an unlock failure. The GUI hides daemon-derived wallet balance/address data until the selected GUI wallet and the running daemon wallet agree.

Balance safety was also tightened. A successful `get_wallet_info` response from a mismatched daemon is no longer accepted as the selected wallet's balance. The global balance becomes unavailable instead of misleadingly showing `0 QUB` or another wallet's value.

The lock state now describes signing capability only. It no longer implies that public wallet information is inaccessible.
