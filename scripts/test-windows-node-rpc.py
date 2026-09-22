"""Windows integration regression with a disposable regtest wallet, no payments.

Usage: python scripts/test-windows-node-rpc.py build/core/windows-x64/Release
Requires the default regtest RPC port 37663 to be unused.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

assert os.name == "nt", "Windows runtime regression"
binary_dir = Path(sys.argv[1]).resolve(strict=True)
cli = binary_dir / "qrx-cli.exe"
daemon = binary_dir / "qrxd.exe"
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 37663))
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    p2p_port = probe.getsockname()[1]
base = Path(tempfile.gettempdir()).resolve()
with tempfile.TemporaryDirectory(prefix="qrx RPC test ", dir=base) as directory:
    root = Path(directory).resolve()
    assert root.parent == base and root.name.startswith("qrx RPC test ")
    data = root / "data"
    command = [str(cli), "--network", "regtest", "--datadir", str(data), "--wallet", "rpc-test"]
    env = dict(os.environ, QRX_PASSPHRASE="disposable-regtest-only-123")
    def call(*args):
        return subprocess.run(command + list(args), capture_output=True, text=True, timeout=8,
                              env=env, creationflags=subprocess.CREATE_NO_WINDOW)
    offline = call("getinfo")
    assert offline.returncode != 0, "An offline node must not report success"
    assert not data.exists(), "RPC polling must not initialize wallets/chain state"
    started = time.monotonic()
    node_pid = None
    with (root / "stdout.log").open("wb") as out, (root / "stderr.log").open("wb") as err:
        process = subprocess.Popen([str(daemon), "--network", "regtest", "--datadir", str(data),
                                    "--wallet", "rpc-test", "--listen", f"127.0.0.1:{p2p_port}",
                                    "--rpc-bind", "127.0.0.1:37663", "--no-block-producer"],
                                   env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            while True:
                assert process.poll() is None, f"Daemon crashed before readiness: {process.returncode}"
                reply = call("getinfo")
                if reply.returncode == 0:
                    info = json.loads(reply.stdout)
                    if info.get("ok"):
                        node_pid = info["result"]["node_pid"]
                        break
                assert time.monotonic() - started < 20, "Node failed to become ready: " + reply.stdout + reply.stderr
                time.sleep(0.2)
            for _ in range(3):
                for method in ("getinfo", "getnodestatus", "getwalletinfo", "getbalance", "tokenomics"):
                    reply = call(method)
                    assert reply.returncode == 0, method + ": " + reply.stderr
                    payload = json.loads(reply.stdout)
                    assert payload["ok"], method
                    if method == "getwalletinfo":
                        assert Path(payload["result"]["wallet_dir"]) == data / "wallets" / "rpc-test"
                    assert process.poll() is None, "Daemon crashed handling " + method
            secret = env["QRX_PASSPHRASE"].encode().hex()
            unlocked = json.loads(call("walletpassphrasehexfor", "rpc-test", secret).stdout)
            assert unlocked["ok"] and unlocked["result"]["unlocked"]
            locked = json.loads(call("walletlockfor", "rpc-test").stdout)
            assert locked["ok"] and locked["result"]["locked"]
            stopped = json.loads(call("stop").stdout)
            assert stopped["ok"]
            assert process.wait(timeout=15) == 0
        finally:
            if process.poll() is None:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                process.wait(timeout=10)
            # Only the child PID returned by this isolated node may be cleaned up.
            if node_pid:
                subprocess.run(["taskkill", "/PID", str(node_pid), "/T", "/F"], capture_output=True)
        # Short-lived maintenance children can still be closing inherited log
        # handles after the daemon exits. Let Windows release those handles.
        time.sleep(3)
print("PASS: offline polling is read-only; node startup, repeated RPC/JSON, signer unlock/lock and shutdown")
