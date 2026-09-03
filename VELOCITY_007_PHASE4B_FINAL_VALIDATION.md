# QRX Core 0.0.7 VELOCITY Phase 4B — Final Validation

## New execution capability

Phase 4B introduces consensus-safe MVCC/snapshot parallel state execution for the `TRANSFER_FAST` payment path.

- immutable QRXDB read snapshot per batch
- conflict-wave execution
- parallel transaction preparation within each wave
- isolated per-TX write sets
- deterministic prior-wave overlay
- aggregated fee delta
- deterministic merged write set
- stale snapshot generation recheck
- exactly one QRXDB WAL batch for a successful MVCC batch
- one resulting Merkle state root
- mixed/stateful batches use deterministic fallback with no partial commit

## Safety properties covered by CTest

- 1 worker and 4 workers produce the same final state root
- multiple conflict waves preserve nonce and balance sequencing
- successful 3-TX batch increments QRXDB generation exactly once
- fee pool aggregation is correct
- stale snapshot commit returns `QRX_MVCC_RETRY`
- mixed `TRANSFER_FAST` + stateful batch returns `QRX_MVCC_UNSUPPORTED` and leaves QRXDB unchanged

## Runtime exposure

Internal backend command:

```
qrx velocity-mvcc-execute <node-dir> [max_txs] [workers]
```

Engine diagnostics now report `phase=4B` and the MVCC capability flags through the existing `getvelocityengineinfo` path.

## Compatibility rule

Phase 4B does not replace the existing deterministic executor for Agent, Trading, Gateway, Cross-Chain or Bitcoin-SPV transaction families. Those transaction types remain serial-fallback until explicit MVCC adapters are implemented. This prevents a performance optimization from changing established consensus behavior.

## Regression requirement

`qrx-core/scripts/audit-0.0.6-regression.sh` remains a mandatory gate. It checks all 59 audited 0.0.6 CLI commands plus wallet/mobile raw-TX, server dashboard RPCs, static build scripts, Windows OpenSSL applink, PQC guard, auto-network and nonce safety.
