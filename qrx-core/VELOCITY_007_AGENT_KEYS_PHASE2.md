# QRX Core 0.0.7 VELOCITY Phase 2 — On-Chain Agent Keys

This patch extends VELOCITY from schema-only AI-agent transaction types to an initial on-chain Agent Key registry.

## Goal

QRX owner wallets can authorize restricted AI/trading agent keys without exposing the owner wallet private key.

The owner wallet signs the registration/update/revoke transaction. The agent key is stored on-chain with permissions, market limits and expiry metadata.

## New executable VELOCITY TX types

The following transaction types are now executed by the core:

- `AGENT_REGISTER`
- `AGENT_UPDATE`
- `AGENT_REVOKE`

`TRANSFER_FAST` remains executable. Trading order execution is still intentionally not active in this phase.

## Agent registry state

Agent state is stored in:

```text
state/agents.db
```

Per agent, the registry stores:

```text
owner
status
ed25519_pub_hex
mldsa65_pub_b64
permissions
max_trade_atoms
daily_limit_atoms
market_allowlist
expires_height
updated_height
revoked_height
last_tx
```

## Security model

- The owner wallet key signs the agent registration/update/revoke transaction.
- The agent gets its own Ed25519 + ML-DSA-65 public key pair.
- Registration verifies that the agent address matches the submitted agent Ed25519 public key.
- The agent can be revoked by the owner.
- Limits and allowlists are on-chain metadata for the later trading/external-execution layer.
- The owner private key is never shared with an AI agent or server.

## New CLI/RPC commands

```bash
qrx-cli getagent <agent_address>
qrx-cli listagents [owner_address]
```

Create raw agent transactions:

```bash
qrx-cli createagentregistertransaction \
  <owner> <agent> \
  <agent_ed25519_pub_hex> <agent_mldsa65_pub_b64> \
  <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> \
  <owner_ed25519_pub_hex> <owner_mldsa65_pub_b64> \
  <lane_id> <tx_expiry_height> [fee] [nonce]
```

```bash
qrx-cli createagentupdatetransaction \
  <owner> <agent> \
  <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> \
  <owner_ed25519_pub_hex> <owner_mldsa65_pub_b64> \
  <lane_id> <tx_expiry_height> [fee] [nonce]
```

```bash
qrx-cli createagentrevoketransaction \
  <owner> <agent> \
  <owner_ed25519_pub_hex> <owner_mldsa65_pub_b64> \
  <lane_id> <tx_expiry_height> [fee] [nonce]
```

## Generic raw transaction path

The existing generic command also works:

```bash
qrx-cli createvelocitytransaction <from> <to> 0 <owner_ed_pub_hex> <owner_mldsa_pub_b64> AGENT_REGISTER <lane_id> <tx_expiry_height> '<payload>' [fee] [nonce]
```

Payload format is deterministic key-value text separated by semicolons, without spaces/newlines:

```text
agent_ed25519_pub_hex=...;agent_mldsa65_pub_b64=...;permissions=TRADE;max_trade_atoms=1000000;daily_limit_atoms=5000000;market_allowlist=QUB/qUSDT,QUB/qBTC;expires_height=100000
```

## Updated `getvelocityinfo`

`getvelocityinfo` now reports:

```text
agent_execution=true
agent_keys_onchain=true
agent_permissions=true
agent_limits=true
agent_revocation=true
native_matching=false
parallel_execution=false
```

## Not active yet

The following remain reserved for later VELOCITY phases:

- Native order matching
- External exchange execution gateway
- Execution reports
- Agent-signed order execution
- Memory mempool / parallel execution
