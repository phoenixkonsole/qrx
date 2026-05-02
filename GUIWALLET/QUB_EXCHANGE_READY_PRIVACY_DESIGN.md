# QUB Exchange-Ready Privacy Design

## Product posture

QUB is **transparent by default** and **privacy optional**.

This is the exchange-ready model:

```text
Exchange / CEX deposits: transparent QUB only
Exchange / CEX withdrawals: transparent QUB first
User wallet: optional shield locally after withdrawal
BTC swaps: transparent QUB only
Shielded pool: optional local privacy layer
```

## Why this helps listings

This avoids positioning QUB as a pure privacy coin. The transparent layer remains suitable for accounting, deposits, withdrawals, explorers, and exchange integration.

## Privacy Center

The GUI now includes:

- Exchange-ready mode status
- Shielded pool status
- Transparent vs shielded balance labels
- Preview-only shield / shielded-send / unshield actions
- Safe wording guidance

## Core commands planned next

```bash
qrx-cli shielded-address
qrx-cli shield <amount> <shielded_address>
qrx-cli shielded-balance
qrx-cli shielded-send <shielded_address> <amount>
qrx-cli unshield <transparent_address> <amount>
qrx-cli shielded-history
```

## Implementation phases

### Phase 1 — Skeleton

- shielded address format
- note database
- commitments
- nullifiers
- shield/unshield command stubs
- GUI wiring

### Phase 2 — Cryptographic pool

- Merkle tree
- encrypted notes
- nullifier checks
- proof placeholder removed

### Phase 3 — zk verification

- production proof system
- audited circuits
- activation height
- emergency disable
- test vectors

## Safe wording

Use:

- optional privacy layer
- enhanced privacy
- shielded pool

Avoid:

- anonymous
- untraceable
- mixer
- hide from authorities
