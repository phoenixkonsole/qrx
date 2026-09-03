# QRX Core 0.0.7 VELOCITY — Phase 4 High-Throughput Engine

## Scope

Phase 4 introduces a high-throughput transaction admission and scheduling layer without changing the established 0.0.6 transaction surface or weakening the Phase 3 QRXDB atomic state-commit model.

The Phase 4 pipeline is:

```text
P2P transaction admission
        ↓
RAM-resident sharded mempool
        ↓
append-only mempool WAL
        ↓
deterministic fee/txid planner
        ↓
parallel Ed25519 + ML-DSA stateless verification
        ↓
read/write conflict detection
        ↓
conflict-free execution waves
        ↓
deterministic authoritative state application
        ↓
QRXDB WAL atomic commit
        ↓
State Root
```

## RAM mempool

The legacy small file-oriented mempool hot path is replaced by a RAM-resident mempool with 32 deterministic shards. The configured ceiling remains bounded by `QRX_MAX_MEMPOOL_TX` (currently 50,000 entries) so a node cannot consume unbounded memory.

Each entry stores its signed transaction, full signed-TX SHA3-512 identifier, fee, lane/nonce metadata and a compact conflict-access set.

## Mempool WAL

Accepted and removed entries are recorded in `velocity_mempool.wal`. On restart, the node reconstructs the in-memory shards from the WAL.

The mempool WAL uses CRC32-protected records, replay, duplicate suppression and checkpoint/compaction. It intentionally uses group durability rather than a physical `fsync` for every single admitted transaction: the mempool is reconstructible network data, unlike consensus state. A durable flush is performed periodically and at checkpoint/clean shutdown.

This is separate from the Phase 3 consensus-state QRXDB WAL. Consensus state remains subject to the stricter atomic durable commit path.

## Deterministic planning

Candidate transactions are sorted deterministically by:

1. fee descending;
2. full signed transaction id ascending as the tie breaker.

This means validators given the same admissible set can construct the same deterministic candidate order independent of local thread scheduling.

## Parallel hybrid signature verification

Stateless cryptographic validation can be dispatched to a fixed worker pool. The worker count is configurable with:

```bash
export QRX_SIGNATURE_WORKERS=8
```

The worker stage validates the chain/network binding, canonical transaction body hash, Ed25519 address/public-key binding and signature, and ML-DSA-65 public key/signature.

No authoritative balances, nonces or account state are mutated by worker threads.

## Conflict detection and execution waves

Phase 4 extracts access keys for the resources a transaction can touch, including account, nonce, agent, order, gateway, cross-chain session and Bitcoin-SPV global state resources.

Transactions that do not conflict can share the same wave. Transactions that touch an overlapping state resource are deterministically moved to a later wave.

Example:

```text
A -> B       wave 0
C -> D       wave 0
A -> E       wave 1  (conflicts with A -> B)
```

The wave number is committed into a proposed block alongside the transaction reference, which makes the scheduling decision explicit and reproducible.

## State commit safety

Phase 4 deliberately does **not** allow worker threads to mutate authoritative QRXDB state concurrently. Current authoritative state application remains deterministically ordered and uses the Phase 3 QRXDB WAL + atomic commit + State Root path.

Therefore the current model is:

- parallel admission-independent cryptographic verification: YES
- deterministic conflict-aware execution-wave planning: YES
- parallel authoritative QRXDB state mutation: NO
- deterministic atomic state commit: YES

This separation is intentional. A future snapshot/MVCC execution step can execute conflict-free write sets concurrently and merge them before one WAL commit, but it must first prove identical State Roots across validators.

## New diagnostics

Backend:

```bash
qrx velocity-engine-info <node-dir>
qrx velocity-mempool-plan <node-dir> [max_txs] [workers]
```

RPC/CLI:

```bash
qrx-cli getvelocityengineinfo
qrx-cli getmempoolinfo
```

`getvelocityengineinfo` reports the active Phase 4 engine, shard count, mempool bounds, WAL configuration, planning statistics and whether parallel state mutation is enabled.

## Compatibility

The 0.0.6 regression audit remains mandatory for each VELOCITY phase. Phase 4 keeps the existing wallet, staking, delegation, privacy, swaps, dashboard RPCs, mobile raw-transaction flow, QRXDB tools, OpenSSL/PQC guard and 59 audited 0.0.6 CLI commands.

Phase 3A, 3B, 3C and 3D.1 test coverage is also retained.

## Performance claims

Phase 4 is an architectural throughput upgrade. It is **not** a claim that QRX currently achieves a particular end-to-end TPS number or Visa-class throughput. Those claims require multi-node benchmarks of admission, consensus, execution, persistence and finality. A dedicated `qrxbench` suite belongs after the execution engine is sufficiently complete.
