# QRX Finality Voting Layer

QRX now includes a basic deterministic BFT-style finality layer.

## Flow

1. Proposer is selected by Deterministic Weighted Rotation.
2. Proposer broadcasts block proposal.
3. Validators verify the block.
4. Validators send `PREVOTE`.
5. If a block receives sufficient prevote support, validators send `PRECOMMIT`.
6. If `PRECOMMIT` voting power reaches `2/3 + 1`, a commit certificate is built.
7. The block is considered finalized.

## Quorum

```text
quorum = floor(total_validator_power * 2 / 3) + 1
```

## Vote Types

- `QRX_VOTE_PREVOTE`
- `QRX_VOTE_PRECOMMIT`

## Commit Certificate

A commit certificate contains:

- height
- round
- block hash
- total validator power
- signed validator power
- vote count

## Required production integration

The module provides the finality engine, but consensus integration must ensure:

- votes are hybrid-signature verified
- duplicate validator votes are counted once
- equivocation is detected and slashed
- validator set snapshots are canonical
- finalized blocks include/verifiably reference the commit certificate
- fork-choice prefers finalized chain state
- timeouts advance rounds deterministically

## Security property

A block finalizes only if more than two thirds of validator power precommits to the same block hash at the same height and round.
