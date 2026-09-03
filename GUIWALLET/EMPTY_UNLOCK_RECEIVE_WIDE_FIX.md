# QRX 0.0.7 – Empty Unlock + Receive Wide Layout Fix

- Empty passphrase is now always submitted to the Rust verifier instead of being rejected in JavaScript.
- Successful empty-passphrase verification marks the legacy 0.0.6 wallet explicitly unlocked and shows an unlocked padlock state.
- Legacy empty-passphrase wallets remain explicitly lockable for the current GUI session.
- QUB/BTC Receive panels now span the full view width.
- Receive uses a wide address/details + QR layout on desktop and collapses to one column below 980px.
