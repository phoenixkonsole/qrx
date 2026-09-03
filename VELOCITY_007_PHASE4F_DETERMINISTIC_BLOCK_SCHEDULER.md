# QRX Core 0.0.7 VELOCITY — Phase 4F Deterministic Parallel Block Scheduler / Dependency Graph Execution

Phase 4F builds directly on Phase 4E speculative MVCC/OCC. Instead of deriving execution waves with a local greedy packing rule, QRX now constructs an explicit deterministic dependency graph for the canonically ordered candidate block and derives graph levels as execution waves.

The consensus-relevant ordering remains `fee descending, txid ascending`. CPU completion order has no meaning. Phase 4F only decides which canonically ordered transactions may prepare in parallel; Phase 4E runtime read/write/predicate tracking remains the correctness backstop for dependencies that cannot be known statically.

The final state path is unchanged:

```text
canonical candidate order
        ↓
Phase 4F dependency graph
        ↓
deterministic graph levels / waves
        ↓
Phase 4E speculative MVCC prepare + runtime OCC
        ↓
selective retry of conflicts
        ↓
deterministic merged write set
        ↓
QRXDB generation recheck
        ↓
QRXDB WAL batch
        ↓
atomic commit
        ↓
state root
```

## What is new

### Explicit deterministic dependency graph

Each selected transaction is a graph node. Static access-key ordering constraints become directed edges from the latest prior accessor to the current transaction. This creates compact dependency chains instead of pairwise all-to-all conflict edges.

For a canonical sequence such as:

```text
A: touches alice
B: touches carol
C: touches alice
```

the graph contains `A -> C`, while `A` and `B` may occupy the same wave.

### Barrier transactions are real full fences

Phase 4E intentionally kept external execution, cross-chain state machines and Bitcoin SPV/reorg transitions as serial barriers. The previous greedy wave planner could represent a barrier as a singleton wave but did not make the barrier a graph-wide ordering fence. In a sufficiently mixed candidate list, a later statically-independent transaction could theoretically be packed back into an earlier wave.

Phase 4F fixes that scheduling ambiguity.

For each barrier:

1. every transaction in the current pre-barrier segment precedes the barrier,
2. the barrier precedes every later transaction until the next barrier,
3. the static access map is reset after the barrier,
4. graph levels therefore cannot leapfrog the fence.

Conceptually:

```text
parallel prefix
 A ─┐
 B ─┼──► BARRIER ───► E ─┐
 C ─┘                    ├──► later dependent work
                         F ─┘
```

### Deterministic graph levels

Each node receives:

```text
wave(node) = 1 + max(wave(predecessors))
```

Nodes without predecessors use wave 0. All nodes in the same graph level are eligible for Phase 4E speculative execution.

### Schedule hash

Phase 4F computes a SHA3-512 schedule digest over:

- domain `QRX-VELOCITY-BLOCK-SCHEDULE-v1`,
- ordered transaction IDs,
- assigned waves,
- ordered dependency edges.

The resulting 128-character hexadecimal `schedule_hash` allows nodes, tests and future observability tooling to compare not only the resulting state root but also the deterministic execution plan.

### Scheduler telemetry

`QrxVelocityPlan` now exposes:

- `dependency_edges`
- `barrier_nodes`
- `barrier_fences`
- `critical_path_nodes`
- `max_parallel_width`
- `schedule_hash`

`velocity-mempool-plan`, `velocity-mvcc-execute` and `velocity-engine-info` expose the corresponding scheduler information.

## Interaction with Phase 4E

Phase 4F deliberately does not attempt to predict every runtime dependency.

The static graph handles:

- known access-key ordering,
- barrier/fence ordering,
- deterministic block-wide wave construction.

Phase 4E still handles:

- exact runtime read sets,
- runtime write sets,
- dynamic orderbook discovery,
- prefix/predicate phantom protection,
- same-market dynamic conflicts,
- deterministic conflict winner selection,
- selective loser retry.

Therefore a graph wave may still contain transactions that later discover a runtime conflict. That is safe: Phase 4E serializes the conflicting result in deterministic plan order and retries only the loser.

## Complexity model

The scheduler uses a hash map from static access key to the latest accessor. For ordinary non-barrier transactions this avoids a full O(n²) comparison matrix and produces a compact dependency chain per accessed key.

Barrier nodes intentionally add fence edges to the current segment because their purpose is to serialize an authoritative state machine boundary.

## Engine information

`velocity-engine-info` now reports:

- `phase=4F`
- `engine=VELOCITY_DETERMINISTIC_BLOCK_GRAPH_MVCC`
- `dependency_graph=true`
- `barrier_full_fence=true`
- `schedule_version=1`
- `deterministic_graph_levels=true`
- `schedule_hash_sha3_512=...`
- planner dependency-edge count
- barrier node/fence count
- critical path
- maximum parallel width

All Phase 4E MVCC/OCC capabilities are retained.

## Intentional serial barriers retained

Phase 4F does not make the following state machines speculative:

- `EXTERNAL_ORDER`
- `EXECUTION_REPORT`
- `CROSSCHAIN_ORDER`
- `CROSSCHAIN_REDEEM`
- `CROSSCHAIN_REFUND`
- `BTC_SPV_HEADER`
- `BTC_SPV_FUNDING_PROOF`

Instead, it now guarantees that these barriers are represented as proper ordering fences in the block dependency graph.

## Additional QRXDB hardening

The Phase 4F sanitizer pass exposed a pre-existing undefined-behavior edge case in `qrxdb_scan_prefix_at()`: the zero-result path could call `qsort()` with a null base pointer and a count of zero. Normal builds tolerated this, but UBSan correctly reported it.

Phase 4F now sorts only when more than one result exists. This does not change scan semantics; it removes the undefined call and the complete Phase 4A–4F sanitizer suite passes afterward.

## Dedicated Phase 4F determinism test

The scheduler test inserts the same seven transactions into two mempools in opposite insertion order. Canonical fee/txid ordering, graph levels and the SHA3-512 schedule hash must be identical.

The test graph proves:

```text
A + B     wave 0  (independent)
C         wave 1  (depends on A)
BARRIER   wave 2  (full prefix fence)
E + F     wave 3  (independent after barrier)
G         wave 4  (depends on E)
```

Expected metrics:

- 5 waves / critical-path nodes
- maximum parallel width 2
- one barrier node
- one barrier fence
- no post-barrier transaction may appear at or before the barrier wave

The same candidate set inserted in reverse order yields the same canonical schedule and schedule hash.

## Validation performed

The Phase 4F source tree passed:

- Phase 4 VELOCITY engine test
- Phase 4B MVCC snapshot/parallel execution test
- Phase 4C stateful MVCC adapter test
- Phase 4D dynamic write-set test
- Phase 4E speculative OCC test
- new Phase 4F deterministic block scheduler test
- all six tests under AddressSanitizer + UndefinedBehaviorSanitizer
- Phase 3A agent trading smoke test
- Phase 3B native matching + settlement smoke test
- Phase 3C gateway + execution report smoke test
- Phase 3D BTC/QUB cross-chain settlement smoke test
- Phase 3D.1 Bitcoin SPV consensus + reorg safety smoke test
- QRX Core 0.0.6 feature regression audit with all 59 audited legacy CLI commands
- dashboard/mobile-wallet/build-surface audit
- QRXDB multi-key WAL crash-recovery test

## Natural next step

A subsequent Phase 4G can turn the deterministic graph into an adaptive production scheduler: core-count-aware worker pools, hot-key/market statistics, adaptive batch sizing, backpressure, NUMA-aware execution and large-scale reproducible throughput benchmarks while retaining the Phase 4F schedule semantics and Phase 4E OCC correctness model.
