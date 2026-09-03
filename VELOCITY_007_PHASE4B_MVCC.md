# QRX Core 0.0.7 VELOCITY — Phase 4B

## MVCC / Snapshot Parallel Execution

Phase 4B moves QRX beyond parallel signature verification and parallel scheduling into parallel transaction state preparation.

### Execution pipeline

```
RAM mempool
  -> deterministic fee/txid plan
  -> Ed25519 + ML-DSA-65 parallel verification
  -> conflict waves
  -> QRXDB read snapshot
  -> parallel TRANSFER_FAST execution against immutable snapshot + prior-wave overlay
  -> isolated per-transaction write sets
  -> deterministic wave merge
  -> snapshot-generation conflict recheck
  -> ONE QRXDB WAL batch
  -> atomic materialization
  -> Merkle state root
```

### Consensus safety

All workers read the same QRXDB snapshot generation. Transactions in a conflict-free wave are prepared in parallel and cannot mutate canonical state. Later waves see a deterministic in-memory overlay produced by earlier waves. No worker writes QRXDB directly.

Before commit QRX checks that the live QRXDB generation still matches the captured snapshot. A changed generation returns `QRX_MVCC_RETRY`; stale results are never committed.

The merged write set is sorted deterministically and committed as one QRXDB WAL transaction, so worker count does not affect the resulting state root.

### Phase 4B fast path

Actual parallel state execution is enabled for `TRANSFER_FAST` transactions. It includes:

- sender/receiver QUB balances
- self-transfer fee semantics
- nonce lanes
- fee aggregation
- applied-TX marker
- transaction payload/index records
- consensus apply marker

Fee-pool updates are aggregated as a commutative batch delta so independent transfers are not artificially serialized on a global fee key.

### Stateful transaction safety

Agent, native/external trading, gateway, cross-chain and Bitcoin-SPV transaction types retain the existing deterministic serial executor for now. Mixed MVCC batches are not partially committed: the MVCC engine returns `FALLBACK_REQUIRED` / `QRX_MVCC_UNSUPPORTED` and leaves state unchanged.

This is deliberate. Each stateful transaction family will receive an explicit MVCC adapter rather than sharing unsafe generic assumptions.

### New internal backend command

```
qrx velocity-mvcc-execute <node-dir> [max_txs] [workers]
```

For a pure verified `TRANSFER_FAST` batch it performs snapshot preparation and one atomic WAL commit. For mixed/stateful batches it requests deterministic fallback without partial state mutation.

### Engine info

`getvelocityengineinfo` / `velocity-engine-info` now reports:

- `phase=4B`
- `mvcc_snapshot_execution=true`
- `isolated_write_sets=true`
- `parallel_transfer_fast_prepare=true`
- `conflict_recheck_before_commit=true`
- `deterministic_merge=true`
- `single_wal_batch_per_mvcc_batch=true`
- `parallel_state_mutation=transfer_fast_snapshot_prepare`
- `complex_stateful_tx_parallel=false`

### Validation

The Phase 4B CTest verifies:

1. conflicting Alice transfers execute in successive deterministic waves;
2. independent Alice/Carol transfer state is prepared concurrently;
3. 1-worker and 4-worker execution produce the identical Merkle state root;
4. all transactions are committed in exactly one new QRXDB generation;
5. balances, nonce lanes and aggregate fee pool are correct;
6. a concurrent QRXDB generation change causes `QRX_MVCC_RETRY` instead of stale-state commit.

Phase 4B does not claim that all QRX transaction types execute in parallel yet. It establishes the consensus-safe MVCC framework and activates it for the high-volume payment fast path first.
