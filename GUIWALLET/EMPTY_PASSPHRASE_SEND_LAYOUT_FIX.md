# QRX 0.0.7 – Empty-passphrase unlock + wide Send workspace

## Empty-passphrase wallets

Some legacy 0.0.6 wallets use encrypted PKCS#8 containers with an empty user passphrase. On macOS, the Rust OpenSSL provider may parse Ed25519 but not ML-DSA65, even though the QRX Core OpenSSL build supports ML-DSA65. The GUI therefore uses the Ed25519 private key as the canonical local passphrase probe and leaves the authoritative hybrid-key validation to qrxd/Core when signing.

An explicit empty passphrase verification is allowed. A wrong empty passphrase still fails the Ed25519 decryption check. This prevents `PEM encrypted` from being treated as synonymous with `user password required`.

## Send UI

QUB and BTC Send panels now span the full content width. Recipient and address-book selection sit side-by-side, amount and memo/fee fields use horizontal space, and the primary review action is kept in the same workspace. The layout collapses to two or one column only on smaller windows.
