# QRXDB Atomic applytx / WAL Recovery

QRX Core 0.0.7 VELOCITY uses QRXDB as the authoritative state store for the migrated transaction-application path.

## Atomicity boundary

Before COMMIT:

- all key/value mutations are staged in a `QrxDBBatch`;
- data-map allocation is reserved;
- WAL `BEGIN` and all WAL `PUT` records are persisted.

At COMMIT:

- WAL `COMMIT` is flushed and fsynced on POSIX;
- on Windows, the CRT handle is `_commit`-flushed;
- only after that point are canonical data records materialized.

After COMMIT, failure or process termination is recoverable because the WAL contains the complete committed generation.

## Recovery

On `qrxdb_init()`:

1. scan the valid data tail;
2. rebuild the current index;
3. replay committed WAL generations that are not fully materialized;
4. rebuild the index;
5. recompute the Merkle state root from recovered canonical state;
6. sync the recovered header/state.

A committed multi-key generation therefore appears completely or is replayed completely.

## Tests

- `tests/qrxdb_atomic_batch_test.c`
- `tests/velocity_phase3c_outer_apply_crash.sh`

The outer apply test uses a test-only environment variable:

`QRXDB_TEST_CRASH_AFTER_WAL_COMMIT=1`

This is inactive in normal operation.
