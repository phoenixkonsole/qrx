# QRX Deterministic Weighted Rotation

Selection uses:
- previous finalized block hash
- block height
- validator public key
- validator stake weight

Formula:

score = hash(previous_block_hash + height + validator_pubkey)
effective_score = score / validator_stake

Lowest effective score wins.

Properties:
- deterministic
- stake weighted
- no local randomness
- no rand()
- no timestamp manipulation
- fair long-term weighted distribution
