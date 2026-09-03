# QRX Core 0.0.7 VELOCITY — Phase 3C

## External Execution Gateway + Atomic State Commit

Phase 3C connects authorized off-chain execution venues to the QRX agent/trading model and hardens transaction state changes around QRXDB's write-ahead log.

### External execution flow

1. An owner authorizes an AI agent on-chain.
2. The agent creates an `EXTERNAL_ORDER` for an external venue, for example `KRAKEN` and `BTC/USDT`.
3. QRX stores the signed trading intent and its authorization state.
4. A governance-authorized execution gateway is registered on-chain with its own Ed25519 + ML-DSA-65 public keys and venue scope.
5. The external gateway executes the order at the external exchange.
6. The gateway submits signed `EXECUTION_REPORT` transactions.
7. QRX records ordered execution state transitions such as `submitted`, `partially_filled`, `filled`, `rejected`, or `canceled`.

External symbols such as USDT/USDC remain external venue assets. Phase 3C does **not** create native QRX USDT or USDC.

### Gateway / report features

- `GATEWAY_REGISTER`
- `GATEWAY_REVOKE`
- `EXECUTION_REPORT`
- venue-bound gateway authorization
- Ed25519 + ML-DSA-65 gateway keys
- monotonically increasing execution-report sequence
- terminal-state protection
- auditable on-chain execution reports
- gateway status/list commands
- execution-report status command

### Native settlement pipeline

Native deterministic matching continues to use the Phase 3B price/time/order-id rules. A matched trade is settled through:

`Matching -> Settlement Batch -> QRXDB WAL -> Atomic Commit -> State Root`

The settlement batch contains all canonical state mutations required for the trade. QRXDB writes a durable WAL transaction before materializing canonical records. If the process dies after WAL COMMIT, recovery replays the complete generation rather than exposing a partial settlement.

### Outer apply transaction atomicity

The `applytx` state path now stages its authoritative state in one QRXDB generation. Depending on transaction type this includes:

- sender/recipient balance changes
- transaction fee-pool update
- account nonce or nonce-lane update
- applied-transaction marker
- transaction location/payload index
- agent state
- order state
- reserved native asset balances
- agent usage limits
- gateway state
- execution-report state

A successful QRXDB batch produces one resulting Merkle state root and generation.

Legacy flat state files are retained as compatibility mirrors, but QRXDB values are authoritative for the migrated `applytx` state. Wallet signing also reads the authoritative recovered account nonce, preventing stale legacy mirrors from producing a reused nonce after recovery.

### Crash recovery test

A dedicated fault-injection test sets `QRXDB_TEST_CRASH_AFTER_WAL_COMMIT=1`. QRXDB exits immediately after the durable WAL COMMIT and before canonical data records are materialized. On the next open, WAL recovery must reconstruct the entire generation.

The test compares a normally committed chain with an identical chain crashed at the WAL boundary and verifies identical state roots plus:

- sender balance
- recipient balance
- fee pool
- nonce
- duplicate/applied marker protection
- next wallet signature using the recovered nonce

### Scope

The WAL-backed atomicity described here covers the `applytx` path and VELOCITY native settlement batches. Older independent subsystems that perform their own legacy state mutations outside `applytx` are preserved for 0.0.6 compatibility and are not claimed to have been globally converted to a single ACID transaction model in this phase.
