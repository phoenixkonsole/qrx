# QRXDB maintenance tools

This build adds four standalone QRXDB maintenance tools:

```bash
qrxdb_verify <chain-dir>
qrxdb_salvage <chain-dir>
qrxdb_compact <chain-dir>
qrxdb_snapshot <chain-dir> [label]
```

## qrxdb_verify

Validates the QRXDB record tail, generation, CRCs and SHA3-512 Merkle state root.
Returns exit code `0` on success and `1` on failure.

## qrxdb_salvage

Attempts to recover QRXDB after a crash or partial write by scanning for the last valid record tail,
rebuilding the in-memory index, recomputing the SHA3-512 Merkle root and syncing the repaired header.

Run this only while the node is stopped.

## qrxdb_compact

Creates a compacted QRXDB data file containing the latest live value per key, then verifies the result.
Run this only while the node is stopped.

## qrxdb_snapshot

Creates a byte-for-byte QRXDB snapshot up to the current committed write offset and writes metadata with
generation, write offset and SHA3-512 Merkle root.

Snapshots are written below:

```text
<chain-dir>/qrxdb/snapshots/
```

## Build

```bash
cd qrx-core
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The tools are built alongside `qrx`, `qrxd` and `qrx-cli`.
