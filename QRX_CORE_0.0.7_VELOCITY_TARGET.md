# QRX Core 0.0.7 — VELOCITY

## Product target

QRX 0.0.7 evolves QRX Blockchain into quantum-resistant execution infrastructure for high-throughput payments and autonomous financial agents. The target is not to claim Visa-class throughput before measurement; the target is to create the architecture and benchmark it honestly.

## Consensus compatibility and Genesis

Genesis may be started with the 0.0.6 chain/profile format. 0.0.7 keeps legacy transaction version 2 readable and executable. The new VELOCITY envelope is transaction version 3 and is versioned separately. Breaking consensus features such as native order matching, parallel commit, microblocks, or changed block format must only be activated by an explicit upgrade height/fork rule after all validators have upgraded.

Do not alter genesis_hash, network_id, chain_id, magic, initial allocation, or historical blocks merely to deploy the 0.0.7 binary.

## 0.0.7 roadmap

### V1 Foundation (implemented in this archive)
- Versioned VELOCITY transaction envelope (`tx_version=3`)
- Deterministic `tx_type` field
- Nonce lanes (`lane_id`, lane 0 maps to legacy account nonce)
- Deterministic `expiry_height` instead of wall-clock expiry
- Generic signed `payload` field
- `TRANSFER_FAST` execution path
- Reserved AI-agent, order, bundle, oracle, external-order and execution-report transaction schemas
- Legacy v2 transaction compatibility
- Mobile/non-custodial raw transaction signing remains supported

New RPC/CLI:
- `getaddressnonce <address> [lane]`
- `getnoncelanes <address>`
- `getvelocityinfo`
- `createvelocitytransaction <from> <to> <amount> <ed25519_pub_hex> <mldsa65_pub_b64> <tx_type> <lane_id> <expiry_height> <payload> [fee] [nonce]`

### V2 Agent authorization
- Agent key registration/revocation by owner-signed on-chain transaction
- Permissions, market allowlists, max-trade and rolling daily limits
- Agent-key hybrid Ed25519 + ML-DSA signatures
- Agent-specific nonce lanes

### V3 Native and external trading
- Native markets and deterministic order state
- ORDER_CREATE/CANCEL/REPLACE execution
- Deterministic matching and atomic settlement
- External-order intent plus execution-report attestation for exchange gateways

### V4 VELOCITY execution
- In-memory WAL-backed sharded mempool
- Conflict graph / access sets
- Parallel signature verification
- Parallel execution with deterministic commit
- Payment fast lane and local resource fee markets

### V5 Finality and benchmarks
- Microblock / macroblock research and activation design
- `qrxbench` for payment, agent-order and mixed workloads
- Publish measured accepted/executed/finalized TPS and P50/P95/P99 latency

## Safety note

Feature level 1 intentionally rejects execution of reserved VELOCITY transaction types other than `TRANSFER_FAST`. Their schemas are present so mobile wallet, SDK and protocol integration can start without silently enabling unfinished trading consensus logic.

## Current VELOCITY implementation: Phase 4E

This archive has progressed beyond the original V4 architecture target through the staged VELOCITY execution program:

- Phase 4A: high-throughput engine foundation
- Phase 4B: MVCC / snapshot parallel execution
- Phase 4C: stateful MVCC adapters
- Phase 4D: dynamic write-set expansion + native matching/settlement in MVCC
- Phase 4E: speculative parallel execution + runtime read/predicate tracking + deterministic conflict resolution + selective retry

Phase 4E keeps external execution reports, cross-chain HTLC transitions and Bitcoin SPV/reorg transitions as explicit serial barriers until equivalent snapshot-bound dependency adapters exist.
