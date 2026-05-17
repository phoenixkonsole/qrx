# qrxd Ctrl+C / SIGTERM shutdown fix

Problem:
- SIGINT set the shutdown flag, but the daemon could stay alive at 0% CPU because the RPC listener was still blocked in accept().
- On macOS, signal() may restart blocking syscalls, so accept() did not reliably return.

Fix:
- Added global RPC listener fd tracking.
- Added qrx_close_rpc_listener().
- SIGINT/SIGTERM now set g_running=0 and close the listener to wake accept().
- POSIX now uses sigaction() without SA_RESTART.
- Shutdown path closes listener, stops the node process, and joins worker threads.

Expected behavior:
- Ctrl+C exits qrxd cleanly instead of leaving the process stuck.
- qrx-cli stop still works.
