# Phase 3C verification commands

After building `qrx`, run:

```sh
./scripts/audit-0.0.6-regression.sh . ./build/qrx
./tests/velocity_phase3a_trading.sh ./build/qrx
./tests/velocity_phase3b_matching.sh ./build/qrx
./tests/velocity_phase3c_gateway.sh ./build/qrx
./tests/velocity_phase3c_outer_apply_crash.sh ./build/qrx
```

`tests/qrxdb_atomic_batch_test.c` is the low-level multi-key WAL recovery test.
