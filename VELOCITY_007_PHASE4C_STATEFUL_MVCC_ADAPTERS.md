# QRX Core 0.0.7 VELOCITY — Phase 4C Stateful MVCC Adapters

Phase 4C extends the Phase 4B snapshot/write-set executor beyond `TRANSFER_FAST` while keeping deterministic consensus and QRXDB WAL atomicity.

## Execution model

1. Transactions are admitted to the RAM mempool and ordered deterministically by fee descending, then TXID ascending.
2. The planner assigns conflict-free execution waves.
3. Hybrid Ed25519 + ML-DSA-65 signatures are verified in parallel.
4. A QRXDB read snapshot is captured.
5. Supported adapters prepare isolated write sets in parallel against that snapshot plus deterministic overlays from prior waves.
6. The live QRXDB generation is checked again immediately before commit.
7. All merged writes are key-sorted and committed as one QRXDB WAL batch.
8. The resulting QRXDB Merkle state root is returned.

## Fully MVCC-prepared in Phase 4C

- `TRANSFER_FAST`
- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_REVOKE`
- `GATEWAY_REGISTER`
- `GATEWAY_REVOKE`

Agent and gateway adapters re-check mutable snapshot state such as owner/status, sender balance, lane nonce and duplicate/applied markers. Their state updates, fee accounting, nonce update and TX indexing are merged into the same atomic WAL commit.

## Dynamic state barriers

The following transaction families now have explicit deterministic barrier classification:

- Native order matching: `ORDER_CREATE`, `ORDER_CANCEL`, `ORDER_REPLACE`
- External order/report state that depends on live venue/order transitions: `EXTERNAL_ORDER`, `EXECUTION_REPORT`
- BTC/QUB HTLC settlement: `CROSSCHAIN_ORDER`, `CROSSCHAIN_REDEEM`, `CROSSCHAIN_REFUND`
- Bitcoin SPV best-work/reorg state: `BTC_SPV_HEADER`, `BTC_SPV_FUNDING_PROOF`

A barrier is placed in a wave by itself. If a Phase 4C MVCC batch contains a dynamic barrier, the MVCC executor returns `BARRIER_REQUIRED` and does **not** partially commit the already prepared fixed-key write sets. The existing deterministic atomic executor remains authoritative for those dynamic state machines.

This is intentional. Native matching can discover counterpart orders dynamically, cross-chain settlement can touch HTLC/session state, and Bitcoin SPV can rewrite active-chain indexes during a reorg. Parallelizing those paths safely requires dynamic write-set expansion rather than guessing a fixed access set.

## Consensus safety retained

- No direct concurrent QRXDB mutation from workers.
- Snapshot generation is rechecked before commit.
- Fixed-key stateful writes are isolated per transaction.
- Waves observe deterministic overlays from earlier waves.
- Global fee accounting remains a commutative delta and is materialized once.
- One MVCC batch produces one QRXDB WAL commit/generation.
- Dynamic barriers cause all-or-nothing fallback instead of partial mutation.

## Compatibility

The Phase 4B public C API remains available as compatibility wrappers. A dynamic Phase 4C barrier maps to the historical `QRX_MVCC_UNSUPPORTED` result through those wrappers so Phase 4B callers retain their fallback behavior.

## Next performance step

The remaining dynamic barriers can be converted one family at a time using deterministic dynamic read/write-set discovery:

- Native orderbook snapshot + matching write-set expansion
- External order/report transition adapter
- Cross-chain session/HTLC adapter
- Bitcoin SPV branch/reorg adapter

Only after a complete write set can be proven from one snapshot should those families be allowed to mutate state in parallel.
