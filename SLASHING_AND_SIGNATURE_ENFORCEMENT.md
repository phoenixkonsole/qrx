# QRX Slashing & Signature Enforcement

QRX now includes:

- vote signature enforcement hooks
- double-prevote detection
- double-precommit detection
- slashing event tracking

## Double voting

A validator is considered malicious if it signs:

- different PREVOTEs
or
- different PRECOMMITS

for the same:
- height
- round

## Current penalty

Default:
- 5% validator penalty

This is configurable later through governance/protocol updates.

## Important

The current implementation includes:

- canonical validator identity matching
- duplicate vote detection
- signature existence enforcement

The next production step is wiring full hybrid signature verification:

- Ed25519
- ML-DSA
- combined hybrid enforcement

## Security improvement

This significantly improves:
- BFT safety
- equivocation resistance
- validator accountability
- fork attack resistance
