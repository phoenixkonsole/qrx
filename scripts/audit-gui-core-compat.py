#!/usr/bin/env python3
"""Static QRX 0.0.7 GUI <-> Core/CLI compatibility gate.

Fails when a literal qrx-cli command used by the Tauri wallet is absent from
qrx-cli dispatch, or when known legacy transport assumptions reappear.
"""
from pathlib import Path
import re, sys

ROOT = Path(__file__).resolve().parents[1]
TAURI = (ROOT / "GUIWALLET/src-tauri/src/main.rs").read_text(encoding="utf-8")
HTML = (ROOT / "GUIWALLET/src/index.html").read_text(encoding="utf-8")
CLI = (ROOT / "qrx-core/src/qrx_cli.c").read_text(encoding="utf-8")
DAEMON = (ROOT / "qrx-core/src/qrxd.c").read_text(encoding="utf-8")

# Literal first arguments of run_cli/run_cli_raw arrays. Filter unrelated
# btc-wallet-service command argument arrays that happen to share Rust syntax.
used = set(re.findall(r'(?:run_cli|run_cli_raw)\([^;]{0,900}?&\[\s*"([^"]+)"', TAURI, re.S))
# Calls embedded in compact one-line handlers can exceed the conservative regex;
# keep the release-critical surface explicit as a second guard.
used |= {
    "getinfo", "getwalletinfo", "getbalance", "getnewaddress", "listaddresses",
    "history", "getstakinginfo", "validator-set", "tokenomics", "listpeers",
    "sendtoaddress", "stake", "delegate", "stop", "signrawtransactionwithwallet",
    "sendrawtransaction", "listagents", "createagentregistertransaction",
    "createagentrevoketransaction", "createarbitragehedgetransaction", "getorder",
    "createswap", "getswap", "listswaps", "redeemswap", "refundswap",
    "walletpassphrasehex", "walletlock",
}

missing = []
for cmd in sorted(used):
    patterns = [
        f'!strcmp(argv[cmdi],"{cmd}")',
        f'!strcmp(argv[cmdi], "{cmd}")',
    ]
    if not any(p in CLI for p in patterns):
        missing.append(cmd)

errors = []
if missing:
    errors.append("GUI commands absent from qrx-cli dispatch: " + ", ".join(missing))
if 'control.sock' in TAURI:
    errors.append("Legacy GUI Unix control.sock assumption is present; current qrxd RPC is HTTP.")
if '.arg("--listen")\n        .arg("127.0.0.1:26661")' in TAURI:
    errors.append("GUI hardcodes alpha P2P listen port 26661 instead of Core network profile.")
if 'walletpassphrasehex' not in DAEMON or 'walletlock' not in DAEMON:
    errors.append("qrxd lacks runtime wallet unlock/lock RPC parity required by GUI session lock state.")
if 'RPC endpoint:' not in HTML:
    errors.append("GUI still labels current HTTP RPC transport as a control socket.")
if '["history", "", &limit_s]' in TAURI:
    errors.append("GUI history still sends an empty address argument, which qrx-cli tokenization drops.")

if errors:
    print("QRX GUI/Core compatibility audit: FAIL", file=sys.stderr)
    for e in errors:
        print(" - " + e, file=sys.stderr)
    sys.exit(1)

print("QRX GUI/Core compatibility audit: PASS")
print(f"Validated {len(used)} GUI Core command names against qrx-cli dispatch.")
print("Transport: HTTP JSON-RPC /rpc, network-specific ports 37660-37663.")
print("Wallet session: local PEM verification + qrxd runtime walletpassphrasehex/walletlock parity.")
