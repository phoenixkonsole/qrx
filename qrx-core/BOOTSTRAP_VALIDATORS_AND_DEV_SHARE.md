# QRX Bootstrap Validators and Dynamic Dev Share

## Dynamic Dev Share

QRX block rewards are split dynamically by block height:

- Year 1: 20% Dev Share
- Year 2: 10% Dev Share
- Year 3: 5% Dev Share
- Year 4+: 2% Dev Share

With 10 second block time:

- Blocks per day: 8,640
- Blocks per year: 3,153,600

The policy is implemented in:

- `qrx-core/src/economics/qrx_economics.h`
- `qrx-core/src/economics/qrx_economics.c`

## Bootstrap Validators

Mainnet bootstrap uses 50 placeholder validator allocation entries.

Recommended allocation:

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

## Mainnet Treasury

No separate treasury premine is required because development funding comes from the protocol-defined dynamic Dev Share.

## Important

The 50 bootstrap addresses are placeholders and should be replaced before mainnet genesis with real validator-controlled addresses.
