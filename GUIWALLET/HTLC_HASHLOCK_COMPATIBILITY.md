# HTLC Hashlock Compatibility

Quantum Swaps v1 uses **SHA256 hashlocks** intentionally.

## Why SHA256?

Bitcoin HTLC-style scripts and most BTC atomic swap tooling use SHA256/hash160-style primitives. For a direct BTC ↔ QUB atomic swap, both chains must be able to verify the same secret against the same hashlock.

Therefore:

- QUBITCOIN internal chain hashing can remain SHA3-oriented.
- QUB transaction integrity can continue using SHA3 where defined.
- Cross-chain HTLC hashlocks use SHA256 for BTC compatibility.

## What is not enabled yet

SHA3-native QUB HTLC hashlocks are reserved for a future experimental mode, because they are not directly compatible with BTC atomic swaps without an adapter/bridge layer.

## UI behavior

The GUI now labels this explicitly:

- Hash Algorithm: SHA256 — BTC compatible / required for cross-chain swaps
- Hashlock: SHA256(secret) hex, 64 characters
