# QRX 0.0.7 — Development Fund / Treasury Cleanup

## Decision

The Development Fund receives a dynamic share of the **block subsidy only**. Transaction fees are not subject to an additional Development Fund cut.

Policy:

| Period | Development Fund | Validator/delegator subsidy | Transaction fees |
|---|---:|---:|---:|
| Year 1 | 20% | 80% | 100% to validators/delegators |
| Year 2 | 10% | 90% | 100% to validators/delegators |
| Year 3 | 5% | 95% | 100% to validators/delegators |
| Year 4+ | 2% | 98% | 100% to validators/delegators |

## Code changes

1. `qrx_economics.c` and `qrx_dev_addresses.c` are now compiled into `qrxcore`; they are no longer documentation-only/dead source files.
2. `reward_epoch_auto_cmd()` splits the subsidy using the dynamic Development Fund schedule, credits `dev_address`, and sends all fees plus the validator portion of the subsidy to validators/delegators.
3. Manual developer-only `reward-epoch` follows the same subsidy split.
4. `getparams` reports:
   - `development_fund_percent`
   - `development_fund_address`
   - `development_fund_basis=block_subsidy_only`
   - `transaction_fee_recipient_policy=validators_and_delegators_100_percent`
5. The duplicate Development Fund implementation and `QRXFOUNDATIONPLACEHOLDER...` were removed from `qrx.c`.
6. Network-specific Development Fund addresses now have one canonical implementation in `src/treasury/qrx_dev_addresses.*`; the duplicate hardcoded copy in `core_frontend.c` was removed.
7. Generated `chain.conf` no longer creates a fake `treasury_address` equal to `dev_address`.
8. Misleading genesis metadata `alloc_dev_fund_percent=2`, `alloc_ecosystem_percent=3`, `alloc_community_percent=95` was removed and replaced by explicit policy metadata.

## Still intentionally pending

The 50 bootstrap validator addresses remain placeholders. They are the next genesis task and must be replaced before mainnet.

## Verification

The C core was configured and compiled successfully with CMake in developer mode (`QRX_REQUIRE_PQC=OFF`). The release/PQC toolchain should still be used for the final production build.
