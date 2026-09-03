# QRX Core 0.0.7 VELOCITY — Phase 3D.1 Bitcoin SPV Verification

## Purpose

Phase 3D.1 hardens BTC/QUB cross-chain settlement so QRX no longer has to trust a gateway or wallet assertion that the Bitcoin HTLC was funded. Bitcoin headers and funding proofs that can unlock QUB are verified deterministically by QRX and committed through QRX consensus/QRXDB WAL state.

## Implemented

- Bitcoin 80-byte block header parsing.
- SHA-256d block hash and proof-of-work verification.
- Network PoW limits for Bitcoin mainnet/testnet/regtest.
- Bitcoin difficulty transition validation, including testnet minimum-difficulty handling and 2016-block retarget logic.
- Cumulative chainwork calculation and strict highest-chainwork best-chain selection.
- Median-Time-Past validation.
- Deterministic reorg tracking and active-height remapping.
- Merkle inclusion proof verification with transaction-index ordering.
- Bitcoin legacy/SegWit transaction parsing sufficient to derive txid and inspect outputs.
- Exact P2WSH HTLC scriptPubKey and satoshi amount verification.
- Confirmation counting only on the active highest-work Bitcoin header chain.
- Consensus-committed BTC_SPV_HEADER and BTC_SPV_FUNDING_PROOF VELOCITY transactions.
- Cross-chain settlement safety gate: QUB redeem remains invalid until the committed funding proof is on the active best-work chain and reaches the configured confirmation threshold.
- Reorg safety: a previously valid proof becomes unsafe if its block leaves the active chain; safety is restored deterministically if that branch later regains strictly greater chainwork.
- Bitcoin genesis trust anchors for mainnet, testnet and regtest.

## Important bug fixed

The first implementation could fail while walking from the first post-genesis header back to Bitcoin genesis. `load_header_hash()` was called as:

    load_header_hash(db, network, current.prev_hash, &current)

The lookup string therefore aliased the output struct. The function cleared the output struct before using the lookup string, destroying `current.prev_hash` and causing `best-chain staging failed: new-branch ancestor missing`.

`load_header_hash()` is now alias-safe: it copies the 64-character header hash before clearing the destination. This central fix also protects ancestor walking used by best-chain selection, Median-Time-Past, testnet difficulty lookup and retarget lookup.

## Consensus determinism hardening

The SPV consensus verifier no longer uses `time(NULL)` for Bitcoin's future-time admission policy. Local wall-clock time can differ between QRX validators and therefore must not decide consensus validity. Consensus verification uses deterministic Bitcoin header data: MTP, difficulty and PoW. A transport/policy layer may delay future-looking headers without altering consensus state.

## Cross-chain flow

    BTC/QUB deterministic match
              ↓
    QUB reserved atomically in QRXDB
              ↓
    Bitcoin P2WSH HTLC template
              ↓
    BTC_SPV_HEADER transactions
              ↓
    PoW + difficulty + chainwork verification
              ↓
    BTC_SPV_FUNDING_PROOF transaction
              ↓
    txid + Merkle + P2WSH + amount verification
              ↓
    required confirmations on active best-work chain
              ↓
    safe_to_reveal_secret=true
              ↓
    QUB redeem allowed

No qBTC and no bridge/custodian are required for BTC/QUB atomic-swap settlement.

## Public CLI/RPC surface

- getbtcspvinfo
- getbtcbestheader
- getbtcheader <hash|height>
- verifybtcproof <txid> <block_hash> <tx_index> <branch_csv>
- getbtcconfirmations <txid>
- verifycrosschainfunding <session_id> <rawtx_hex> <block_hash> <tx_index> <branch_csv>
- getcrosschainfunding <session_id>
- getcrosschainsecurity <session_id>
- createbtcspvheadertransaction ...
- createbtcspvfundingprooftransaction ...

## Test coverage

`tests/velocity_phase3d1_bitcoin_spv.sh` verifies:

1. Consensus initialization from Bitcoin regtest genesis.
2. Multiple valid PoW headers.
3. A non-trivial one-level Merkle branch for the BTC funding transaction.
4. Funding transaction txid and exact HTLC output/amount verification.
5. Six-confirmation settlement gate.
6. Refusal to reveal/redeem before an SPV proof exists.
7. Consensus commitment of the funding proof.
8. A higher-chainwork fork that removes the funding block.
9. Immediate settlement safety revocation during the reorg.
10. Restoration when the original funding branch again has strictly greater chainwork.
11. Final QUB redeem after SPV safety is restored.

