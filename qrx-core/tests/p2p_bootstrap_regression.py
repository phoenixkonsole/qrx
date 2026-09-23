#!/usr/bin/env python3
import base64
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


def recv_frame(conn):
    header = conn.recv(4)
    if len(header) != 4:
        raise RuntimeError("short frame header")
    length = struct.unpack("!I", header)[0]
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise RuntimeError("short frame body")
        data.extend(chunk)
    return bytes(data)


def send_frame(conn, payload):
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def run(binary, *args, cwd, env):
    return subprocess.run(
        [binary, *args], cwd=cwd, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: p2p_bootstrap_regression.py /path/to/qrx")
    binary = str(Path(sys.argv[1]).resolve())
    env = os.environ.copy()
    env["QRX_PASSPHRASE"] = "bootstrap-regression-passphrase"

    with tempfile.TemporaryDirectory(prefix="qrx-bootstrap-test-") as tmp:
        root = Path(tmp)
        run(binary, "seed-new", "wallet", cwd=root, env=env)
        run(binary, "init-chain", "chain", cwd=root, env=env)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(10)
        seed_port = listener.getsockname()[1]
        self_port = seed_port + 1 if seed_port < 65535 else seed_port - 1

        run(binary, "node-init", "node", "chain", "wallet", "127.0.0.1", str(self_port), cwd=root, env=env)
        endpoint = f"localhost:{seed_port}\n"
        for name in ("seednodes.txt", "known_peers.txt", "peers.txt"):
            (root / "node" / name).write_text(endpoint, encoding="ascii")

        accepted = []
        failure = []

        def serve():
            try:
                conn, _ = listener.accept()
                accepted.append(1)
                with conn:
                    hello = recv_frame(conn)
                    if not hello.startswith(b"type=HELLO\n"):
                        raise RuntimeError("missing HELLO")
                    send_frame(conn, b"status=OK\n")
                    if recv_frame(conn) != b"type=GETPEERS\n":
                        raise RuntimeError("missing GETPEERS")
                    peers = base64.b64encode(
                        f"127.0.0.1:{self_port}\n0.0.0.0:{self_port}\n".encode("ascii")
                    )
                    send_frame(conn, b"status=OK\npeers_b64=" + peers + b"\n")
                listener.settimeout(1)
                try:
                    conn, _ = listener.accept()
                    accepted.append(1)
                    conn.close()
                except socket.timeout:
                    pass
            except Exception as exc:
                failure.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve)
        thread.start()
        result = run(binary, "bootstrap", "node", cwd=root, env=env)
        thread.join(timeout=12)
        if thread.is_alive():
            raise RuntimeError("mock seed did not finish")
        if failure:
            raise failure[0]
        if accepted != [1]:
            raise AssertionError(f"duplicate seed contacts: {len(accepted)}")
        if "contacted=1\nalive=1\nadded=0" not in result.stdout:
            raise AssertionError(f"unexpected bootstrap result: {result.stdout!r}")
        peers = (root / "node" / "peers.txt").read_text(encoding="ascii")
        if f"127.0.0.1:{self_port}" in peers:
            raise AssertionError("bootstrap imported the node's own endpoint")
        if f"0.0.0.0:{self_port}" in peers:
            raise AssertionError("bootstrap imported a wildcard listener as a peer")

    print("p2p bootstrap DNS/dedup/self-filter regression: PASS")


if __name__ == "__main__":
    main()
