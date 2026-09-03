# QRX Bootstrap Validators and Dynamic Development Fund

## Development Fund policy

QRX uses one protocol-defined development-fund address per network. There is no separate treasury premine.

The block **subsidy only** is split dynamically by block height:

- Year 1: 20% Development Fund / 80% validator+delegator subsidy
- Year 2: 10% Development Fund / 90% validator+delegator subsidy
- Year 3: 5% Development Fund / 95% validator+delegator subsidy
- Year 4+: 2% Development Fund / 98% validator+delegator subsidy

With a 10 second block time:

- Blocks per day: 8,640
- Blocks per year: 3,153,600

**Transaction fees are not taxed by the Development Fund. 100% of collected transaction fees enter the validator/delegator reward pool.** This avoids a second fee-level protocol tax while keeping the development funding transparent in the issuance schedule.

The canonical policy/address implementation is in:

- `qrx-core/src/economics/qrx_economics.h`
- `qrx-core/src/economics/qrx_economics.c`
- `qrx-core/src/treasury/qrx_dev_addresses.h`
- `qrx-core/src/treasury/qrx_dev_addresses.c`

The automatic reward path in `qrx-core/src/qrx.c` now enforces this split.

## Treasury / premine cleanup

- No separate `treasury_address` is generated.
- No Foundation placeholder address remains.
- Legacy static `alloc_dev_fund_percent`, `alloc_ecosystem_percent`, and `alloc_community_percent` genesis metadata was removed because it implied a premine allocation that is not part of the current design.
- `dev_address` remains the canonical network-specific Development Fund address and is also currently used as the external gateway registry authority.

## Bootstrap Validators

Mainnet bootstrap currently still contains 50 placeholder validator allocation entries. These are intentionally left unchanged for the next step.

Planned allocation:

- 50 bootstrap validator addresses
- 1000 QUB each
- Total bootstrap allocation: 50,000 QUB
- Lock time: 180 days
- Lock height: 1,555,200 blocks
- Staking allowed: yes
- Transfer before unlock: no

Purpose:

- Start consensus without a public treasury premine
- Allow validators to produce initial blocks
- Keep bootstrap allocation transparent and locked

## Mainnet requirement

The 50 bootstrap addresses are still placeholders and MUST be replaced before mainnet genesis with real validator-controlled addresses.
