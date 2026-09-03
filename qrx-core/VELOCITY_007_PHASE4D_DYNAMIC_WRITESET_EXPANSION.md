# QRX Core 0.0.7 VELOCITY — Phase 4D Dynamic Write-Set Expansion

Phase 4D extends the Phase 4B/4C MVCC executor with deterministic, snapshot-bound dynamic access discovery. Native order transactions no longer force the complete VELOCITY batch onto the serial fallback path.

## What is new

### Deterministic snapshot prefix scans

QRXDB now exposes:

```c
int qrxdb_scan_prefix_at(
    QrxDB *db,
    const QrxDBReadTxn *txn,
    const char *prefix,
    QrxDBScanCallback callback,
    void *ctx);
```

Unlike a live prefix scan, this API only exposes records visible to the supplied read transaction. It keeps the newest visible value for each key and emits keys in lexical order. This gives dynamic adapters a deterministic discovery primitive tied to the same MVCC generation used for execution.

### New dynamic adapter class

`QRX_VELOCITY_ADAPTER_DYNAMIC` is introduced in addition to transfer, fixed-key stateful and serial-barrier classes.

Phase 4D classifies the following native transactions as dynamic:

- `ORDER_CREATE`
- `ORDER_CANCEL`
- `ORDER_REPLACE`

The production planner isolates every dynamic transaction in its own deterministic execution wave. This allows its complete read/write set to be discovered safely before it is merged with later waves.

## Native matching in MVCC

A native order adapter now performs the complete state transition against:

1. the immutable QRXDB read snapshot,
2. the deterministic merged overlay from earlier waves, and
3. its own isolated write set.

It does not mutate live QRXDB state while preparing.

The adapter dynamically discovers native orderbook candidates under `velocity:order:` and applies the existing consensus ordering rule:

1. best price,
2. earlier `created_height`,
3. lexicographically smaller order ID.

Execution price remains the maker limit price.

## Dynamically expanded writes

A single native order can discover and stage writes that were not knowable from its static transaction metadata, including:

- matching maker orders,
- maker/taker filled and remaining quantities,
- maker/taker reserve locks,
- buyer/seller asset balances,
- price-improvement refunds,
- trade sequence,
- deterministic trade records,
- settlement records,
- expired order state discovered during the scan,
- released reserves from those expired orders,
- native order `match_pending` completion state.

The expanded writes remain local until the batch commit.

## ORDER_CREATE

`ORDER_CREATE` now:

- rechecks fee balance, nonce and duplicate/applied state from the MVCC view,
- rechecks canonical agent owner/status/permissions/market/expiry/trade limits,
- charges the deterministic daily usage bucket,
- reserves the correct native asset,
- stages the native order,
- discovers counterpart orders,
- matches and settles deterministically,
- writes all resulting state through the MVCC write set.

## ORDER_CANCEL

`ORDER_CANCEL` now:

- dynamically resolves the target order,
- falls back safely if the target is a non-native/legacy state machine,
- rechecks agent ownership, active status, native trading permission, market allowlist and agent expiry from the MVCC view,
- deliberately does **not** consume daily trade volume,
- atomically releases the remaining reserve,
- marks the order canceled in the same write set.

## ORDER_REPLACE

`ORDER_REPLACE` now:

- rechecks the replacement authorization and limits,
- resolves and validates the old native order,
- releases/reuses the old locked asset atomically,
- reserves the new amount,
- marks the old order `replaced`,
- creates the replacement order,
- immediately performs deterministic native matching,
- settles all resulting trades in the same MVCC write set.

## Atomic commit path

The Phase 4D path is:

```text
MVCC snapshot
    ↓
Dynamic orderbook discovery
    ↓
Native matching
    ↓
Expanded isolated write set
    ↓
Deterministic wave merge
    ↓
Generation recheck
    ↓
QRXDB WAL batch
    ↓
Atomic commit
    ↓
State root
```

A successful MVCC batch still produces exactly one QRXDB generation/WAL commit. If the live generation changes between snapshot preparation and commit, Phase 4D returns `QRX_MVCC_RETRY` and none of the staged dynamic writes are applied.

## Safety rules

- Dynamic workers never write directly to live QRXDB.
- A dynamic transaction must be alone in its planner wave.
- A hand-built invalid plan that puts a dynamic transaction beside another transaction in the same wave is rejected by the merge layer.
- Dynamic reads use current-write-set values first, then prior-wave overlay values, then the immutable snapshot.
- Snapshot prefix discovery is lexically ordered and generation-bound.
- Missing canonical state that is needed to safely reproduce an older serial path produces a barrier/fallback instead of guessing.
- External venue, cross-chain HTLC and Bitcoin SPV/reorg state machines remain explicit barriers until they receive equivalent dynamic adapters.

## Phase 4D metrics

`velocity-mvcc-execute` now reports:

- `dynamic_prepared`
- `dynamic_discovered_keys`
- `dynamic_trades`
- `expired_orders`

`velocity-engine-info` reports Phase `4D`, native dynamic matching and the remaining barrier families.

## Compatibility retained

Phase 4D retains all Phase 4C fixed-key MVCC adapters:

- `TRANSFER_FAST`
- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_REVOKE`
- `GATEWAY_REGISTER`
- `GATEWAY_REVOKE`

The older Phase 4B compatibility API remains callable. Remaining serial barriers are still mapped to the historical unsupported/fallback result for those callers.

## Still intentionally serialized

The following families remain barriers in Phase 4D:

- `EXTERNAL_ORDER`
- `EXECUTION_REPORT`
- `CROSSCHAIN_ORDER`
- `CROSSCHAIN_REDEEM`
- `CROSSCHAIN_REFUND`
- `BTC_SPV_HEADER`
- `BTC_SPV_FUNDING_PROOF`

They are not regressions. Their transition sets depend on external-order state, HTLC/session state or Bitcoin best-work/reorg traversal and require their own snapshot-bound expansion adapters.

## Validation performed

The release was validated with:

- Phase 4 VELOCITY engine test
- Phase 4B MVCC snapshot/parallel execution test
- Phase 4C stateful MVCC adapter test
- new Phase 4D dynamic write-set test
- the same four tests under AddressSanitizer + UndefinedBehaviorSanitizer
- Phase 3B deterministic native matching + settlement smoke test
- Phase 3C gateway + execution report smoke test
- Phase 3D BTC/QUB cross-chain settlement smoke test
- Phase 3D.1 Bitcoin SPV consensus + reorg safety smoke test
- QRX Core 0.0.6 feature regression audit (59 legacy CLI commands plus dashboard/mobile-wallet/build surfaces)
- QRXDB multi-key WAL crash-recovery test

The Phase 4D test specifically covers snapshot scan semantics, dynamic classification, native BUY/SELL settlement, price improvement, lock accounting, expired-order discovery, `ORDER_CANCEL`, `ORDER_REPLACE`, stale-generation retry, remaining barriers and planner wave isolation.
