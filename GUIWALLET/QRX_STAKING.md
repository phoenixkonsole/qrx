# QUB RC6 Staking

RC6 extends the RC5 staking prototype with three major changes:

1. **Slashing**
2. **Delegator reward splitting**
3. **Validator-set enforcement in block proposal / verification**

## Commands

```bash
./build/qrx stake <chain-dir> <wallet-dir> <amount>
./build/qrx unstake <chain-dir> <wallet-dir> <amount> [unbonding-secs]
./build/qrx claim-unbonded <chain-dir> <wallet-dir>
./build/qrx delegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount>
./build/qrx undelegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount> [unbonding-secs]
./build/qrx claim-undelegated <chain-dir> <delegator-wallet-dir> <validator-address>
./build/qrx staking-status <chain-dir> [address]
./build/qrx validator-set <chain-dir>
./build/qrx reward-epoch <chain-dir> <reward-amount> [validator-commission-bps]
./build/qrx slash <chain-dir> <validator-address> <amount> <reason>
```

## Reward splitting

For each validator with positive power:

- total validator power = `self_stake + delegated_to_me`
- validator epoch share = `epoch_reward * validator_power / total_power`
- validator commission = `validator_epoch_share * commission_bps / 10000`
- remaining reward is split pro-rata by stake weight

Validator receives:
- commission
- plus its self-stake share of the remaining reward

Delegators receive:
- their pro-rata share of the remaining reward credited directly to their balances

Default commission when omitted: **1000 bps**.

## Slashing model

RC6 uses a simple proportional slash model.

A slash amount is distributed across:
- validator self-stake
- active delegated stake to that validator

This keeps delegator exposure visible in tests, but it is still only a prototype economic rule.

## Consensus-path behavior

`propose-block` now requires the node wallet address to have positive validator power.

`verify-block` checks:
- network binding
- block hash and signature
- validator address matches block signing key
- validator is active in the current validator set
- embedded `validator_power` matches current chain state

## Known limitations

- no historical validator-set lookup by block height
- no jail / tombstone logic
- no automatic equivocation detection
- no audited reward or slash economics
- no consensus-final enforcement of stake transitions across distributed nodes
