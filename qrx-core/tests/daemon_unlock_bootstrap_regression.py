#!/usr/bin/env python3
import os
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


PASSPHRASE = "daemon-unlock-bootstrap-regression"


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def recv_frame(conn):
    conn.settimeout(3)
    header = conn.recv(4)
    if not header:
        return None
    if len(header) != 4:
        raise RuntimeError("short frame header")
    length = struct.unpack("!I", header)[0]
    if length > 1024 * 1024:
        raise RuntimeError("oversized frame")
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise RuntimeError("short frame body")
        data.extend(chunk)
    return bytes(data)


def send_frame(conn, payload):
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def run(binary, *args, env=None, check=True):
    return subprocess.run(
        [str(binary), *args], env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check,
    )


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: daemon_unlock_bootstrap_regression.py /path/to/qrx /path/to/qrxd")
    qrx = Path(sys.argv[1]).resolve()
    qrxd = Path(sys.argv[2]).resolve()
    qrx_cli = qrxd.with_name("qrx-cli")
    clean_env = os.environ.copy()
    clean_env.pop("QRX_PASSPHRASE", None)
    wallet_env = clean_env.copy()
    wallet_env["QRX_PASSPHRASE"] = PASSPHRASE

    with tempfile.TemporaryDirectory(prefix="qrx-daemon-unlock-bootstrap-") as tmp:
        root = Path(tmp)
        wallet = root / "wallets" / "node1"
        wallet.parent.mkdir(parents=True)
        run(qrx, "seed-new", str(wallet), env=wallet_env)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(75)
        seed_port = listener.getsockname()[1]
        p2p_port = free_port()
        valid_hello = threading.Event()
        server_errors = []

        def serve():
            deadline = time.time() + 75
            try:
                while time.time() < deadline and not valid_hello.is_set():
                    conn, _ = listener.accept()
                    with conn:
                        hello = recv_frame(conn)
                        # The locked daemon is expected to connect and close
                        # before it can sign HELLO. Keep accepting until the
                        # post-unlock maintenance pass arrives.
                        if hello is None:
                            continue
                        if not hello.startswith(b"type=HELLO\n"):
                            raise RuntimeError(f"unexpected first frame: {hello[:80]!r}")
                        send_frame(conn, b"status=OK\n")
                        if recv_frame(conn) != b"type=GETPEERS\n":
                            raise RuntimeError("missing GETPEERS after signed HELLO")
                        send_frame(conn, b"status=OK\npeers_b64=\n")
                        valid_hello.set()
            except Exception as exc:
                server_errors.append(exc)
            finally:
                listener.close()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        proc = subprocess.Popen(
            [str(qrxd), "--network", "regtest", "--datadir", str(root),
             "--wallet", "node1", "--listen", f"127.0.0.1:{p2p_port}",
             "--addnode", f"127.0.0.1:{seed_port}",
             "--no-block-producer"],
            env=clean_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            token = root / "regtest" / "chain" / "rpc.token"
            deadline = time.time() + 15
            while time.time() < deadline and not token.exists():
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if not token.exists():
                out, err = proc.communicate(timeout=3)
                raise RuntimeError(f"qrxd did not start\nstdout={out}\nstderr={err}")

            unlock = run(
                qrx_cli, "--network", "regtest", "--datadir", str(root),
                "--wallet", "node1", "walletpassphrasehexfor", "node1",
                PASSPHRASE.encode().hex(), env=clean_env,
            )
            if '"unlocked":true' not in unlock.stdout:
                raise AssertionError(f"unlock was not acknowledged: {unlock.stdout!r}")

            if not valid_hello.wait(70):
                raise AssertionError("unlocked daemon never sent a signed HELLO")
            if server_errors:
                raise server_errors[0]
            network = run(
                qrx_cli, "--network", "regtest", "--datadir", str(root),
                "--wallet", "node1", "getnetworkinfo", env=clean_env,
            )
            network_result = json.loads(network.stdout.strip())["result"]
            if network_result.get("connections") != 1:
                raise AssertionError(f"successful HELLO was not counted as live: {network.stdout!r}")
            peers = run(
                qrx_cli, "--network", "regtest", "--datadir", str(root),
                "--wallet", "node1", "getpeerinfo", env=clean_env,
            )
            peer_result = json.loads(peers.stdout.strip())["result"]
            if "[listener]" not in peer_result.get("lines", []):
                raise AssertionError(f"listener section missing from peer info: {peers.stdout!r}")
        finally:
            proc.terminate()
            try:
                proc.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=3)
            server.join(timeout=2)

    print("daemon post-unlock signed bootstrap regression: PASS")


if __name__ == "__main__":
    main()
