# QRX Runtime Hardening

Integrated directly into source tree:
- graceful SIGINT/SIGTERM shutdown
- QRXDB graceful WAL/mmap shutdown
- compaction stop hooks
- generation commit hooks

Recommended next:
- wire qrxdb_graceful_shutdown() into daemon shutdown path
- replace remaining blocking while(1) loops with qrx_running
- add WAL fsync metrics/logging
