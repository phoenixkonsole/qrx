# QRXDB Hybrid-Signed Snapshots

This patch connects QRXDB snapshots to the QRX hybrid-signature model.

## What is signed

QRXDB now produces three snapshot artifacts:

- `<label>.qsnap` — raw QRXDB snapshot bytes
- `<label>.meta` — canonical metadata including generation, write offset, SHA3-512 Merkle root and SHA3-512 snapshot hash
- `<label>.sig` — hybrid signature envelope

The signature envelope uses:

- `scheme=ed25519+mldsa65`
- `hash_algo=sha3-512`
- Ed25519 signature
- ML-DSA-65 signature
- embedded public keys for independent verification

## CLI usage

Unsigned snapshot:

```bash
qrxdb_snapshot <chain-dir> [label]
```

Hybrid-signed snapshot:

```bash
QRX_PASSPHRASE='your wallet passphrase' qrxdb_snapshot <chain-dir> <label> <signing-wallet-dir>
```

Verify DB and snapshot signature:

```bash
qrxdb_verify <chain-dir> --snapshot-signature <label>
```

## Security model

QRXDB internal pages continue to use CRC/SHA3/Merkle integrity.
Snapshots and exported state roots are now authenticated with QRX's hybrid signature layer.

This keeps page-level IO fast while making Fast Sync / Snapshot Sync quantum-resilient at the trust boundary.
