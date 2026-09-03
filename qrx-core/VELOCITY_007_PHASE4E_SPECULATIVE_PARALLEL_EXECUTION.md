# QRX Core 0.0.7 VELOCITY — Phase 4E Speculative Parallel Execution & Deterministic Conflict Resolution

Phase 4E builds directly on Phase 4D Dynamic Write-Set Expansion. Dynamic native transactions are no longer forced into singleton execution waves. QRX may now prepare multiple eligible transactions speculatively from the same MVCC snapshot, discover their real runtime dependencies, resolve conflicts in deterministic plan order and selectively re-execute only losing transactions.

The final authority remains unchanged: successful execution is merged into one deterministic batch, generation-checked, written through the QRXDB WAL, atomically committed and reduced to one state root.

## What is new

### Speculative dynamic execution

The VELOCITY planner may co-pack statically independent `TRANSFER_FAST`, fixed-key stateful and dynamic native transactions into one execution wave. Workers execute against the immutable QRXDB snapshot plus the deterministic overlay from earlier completed waves; each worker produces an isolated attempt write set and never mutates live QRXDB.

For a wave with multiple transactions, the attempts are marked speculative. Worker completion order has no consensus meaning.

### Runtime exact read-set tracking

Phase 4E records exact state keys read by an MVCC adapter while preparing a transaction. This includes reads performed by transfers, agent/gateway adapters and dynamic native order transitions.

Runtime read tracking allows the resolver to detect dependencies that cannot be known from the transaction envelope alone, for example a taker order reading a maker order that another speculative transaction changes.

### Predicate / prefix tracking

Dynamic orderbook discovery is a predicate read, not just a list of currently returned records. Phase 4E therefore tracks the `velocity:order:` scan predicate in addition to exact keys.

This closes the phantom-write hole: if an earlier speculative transaction creates or changes an order that would have been visible to a later transaction's orderbook discovery, the later attempt cannot be accepted merely because the newly written key was absent from its original exact read list.

### Market-scoped dynamic predicates

A global order prefix is mechanically broad. When both dynamic native transactions have a known canonical market and those markets are different, Phase 4E does not create a prefix-only conflict solely because both adapters scanned `velocity:order:`.

Example:

```text
ORDER_CREATE TOK/QUB ─┐
                      ├─ same speculative wave, no prefix-only conflict
ORDER_CREATE ALT/QUB ─┘
```

Exact read/write and write/write conflicts still apply. Same-market dynamic orders retain predicate protection.

This removes a major false-conflict case without weakening deterministic matching semantics.

## Deterministic OCC conflict rule

Attempts are resolved in deterministic VELOCITY plan order, never in CPU/thread completion order.

For an already accepted predecessor `P` and current attempt `C`, `C` loses when Phase 4E detects a serialization dependency such as:

- `C.read ∩ P.write`
- a predicate/prefix read by `C` invalidated by a write from `P`
- `C.write ∩ P.write`

A write performed by the later/current transaction does not retroactively invalidate an earlier predecessor's read. This is directional optimistic concurrency control corresponding to deterministic plan-order serialization.

The deterministic winner is therefore the earlier transaction in the already-defined VELOCITY execution order. The production planner order remains fee descending, then transaction ID ascending; manually constructed internal test plans use their explicit plan index.

## Selective retry

When a speculative attempt loses:

1. only that attempt is discarded,
2. its temporary read/write/predicate sets are freed,
3. the transaction is prepared again,
4. the retry reads the merged overlay containing all already accepted deterministic predecessors,
5. the retried result is then merged before resolving later transactions.

The complete wave and complete batch are not restarted.

A single deterministic retry is sufficient for the current wave algorithm because the retry sees every predecessor that is allowed to affect it, while later plan entries cannot invalidate already accepted earlier entries under plan-order serialization.

## Same-market example

```text
Snapshot: maker SELL 5 TOK @ 2 QUB

TX0: BUY 3 TOK @ 3 QUB
TX1: BUY 3 TOK @ 3 QUB

parallel speculative prepare
        ↓
TX0 and TX1 both initially see the same maker state
        ↓
deterministic resolver
        ↓
TX0 accepted as earlier plan entry
TX1 conflicts with TX0's discovered maker/order/settlement writes
        ↓
only TX1 re-executes against TX0 overlay
        ↓
TX0 fills 3
TX1 fills remaining 2 and leaves 1 open
        ↓
one WAL batch / atomic commit / one state root
```

The result is independent of whether the wave is executed with one worker or many workers.

## Commit path

```text
QRXDB snapshot
    ↓
Static planner prefilter
    ↓
Speculative parallel prepare
    ↓
Runtime exact reads + predicate reads + dynamic writes
    ↓
Deterministic OCC resolver
    ↓
Selective retry of losers only
    ↓
Deterministic merged write set
    ↓
Live generation recheck
    ↓
QRXDB WAL batch
    ↓
Atomic commit
    ↓
State root
```

If the live QRXDB generation changes between preparation and final commit, the batch still returns `QRX_MVCC_RETRY`; no staged speculative write leaks into live state.

## Phase 4E metrics

`velocity-mvcc-execute` now exposes the existing Phase 4D counters plus:

- `speculative_prepared`
- `runtime_read_keys`
- `runtime_read_prefixes`
- `conflict_edges`
- `deterministic_conflicts`
- `selective_retries`
- `speculative_winners`

These counters make it possible to distinguish useful parallelism from conflict-heavy workloads instead of reporting only aggregate throughput.

## `velocity-engine-info`

The engine reports:

- `phase=4E`
- `engine=VELOCITY_SPECULATIVE_OCC_MVCC`
- runtime read-set tracking enabled
- predicate/prefix tracking enabled
- speculative parallel execution enabled
- deterministic conflict resolution enabled
- selective retry enabled
- deterministic conflict winner order based on plan order
- Phase 4C fixed-key stateful adapters retained
- Phase 4D dynamic native matching retained
- dynamic same-wave execution enabled

## Compatibility retained

Phase 4E retains all prior MVCC adapters and native behavior:

- `TRANSFER_FAST`
- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_REVOKE`
- `GATEWAY_REGISTER`
- `GATEWAY_REVOKE`
- `ORDER_CREATE`
- `ORDER_CANCEL`
- `ORDER_REPLACE`
- deterministic native matching
- price improvement/refund accounting
- reserve locks and releases
- trade + settlement records
- dynamic expired-order discovery
- stale snapshot retry
- one atomic QRXDB WAL commit per successful batch

## Still intentionally serialized

Phase 4E does not speculate the following external/consensus-heavy state machines:

- `EXTERNAL_ORDER`
- `EXECUTION_REPORT`
- `CROSSCHAIN_ORDER`
- `CROSSCHAIN_REDEEM`
- `CROSSCHAIN_REFUND`
- `BTC_SPV_HEADER`
- `BTC_SPV_FUNDING_PROOF`

They remain explicit barriers and continue to use their existing authoritative serial transitions. This is deliberate: external execution state, HTLC/session state and Bitcoin best-work/reorg traversal require equivalent snapshot-bound dependency adapters before safe speculative execution.

## Validation performed

The Phase 4E source tree passed:

- Phase 4 VELOCITY engine test
- Phase 4B MVCC snapshot/parallel execution test
- Phase 4C stateful MVCC adapter test
- Phase 4D dynamic write-set regression test
- new Phase 4E speculative OCC test
- all five tests under AddressSanitizer + UndefinedBehaviorSanitizer
- Phase 3A agent trading smoke test
- Phase 3B deterministic native matching + settlement smoke test
- Phase 3C gateway + execution report smoke test
- Phase 3D BTC/QUB cross-chain settlement smoke test
- Phase 3D.1 Bitcoin SPV consensus + reorg safety smoke test
- QRX Core 0.0.6 feature regression audit, including all 59 audited legacy CLI commands
- dashboard/mobile-wallet/build-surface audit
- QRXDB multi-key WAL crash-recovery test

The dedicated Phase 4E test proves two consensus-relevant properties:

1. Two same-market BUY transactions can be prepared speculatively against the same maker; the earlier plan entry wins, only the later conflicting transaction retries, and maker/taker balances, locks, fills, trade sequence and settlement state remain exact.
2. The resulting state root is identical with one worker and eight workers.

It also proves that independent `TOK/QUB` and `ALT/QUB` native order creates can share a speculative wave with zero conflict retry.

## Conservative boundary / next optimization

Phase 4E still scans the canonical order keyspace and then applies market semantics. Exact dependencies on already-existing records can therefore remain more conservative than a future market-indexed scheduler would need to be.

A natural Phase 4F follow-up is a deterministic block dependency scheduler with market/orderbook indexes, execution waves derived from the runtime dependency graph, and broader parallel block execution while preserving the same plan-order/OCC correctness model.
