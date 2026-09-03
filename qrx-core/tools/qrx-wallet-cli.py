#!/usr/bin/env python3
"""Unified QRX command-line wallet surface for Core and Phase 4F.2 tools.

The native qrx-cli remains the JSON-RPC frontend.  This wrapper adds the local
features which the desktop wallet also uses: verified ledger export,
arbitrage/paper trading, and the secure foreground Kraken gateway.  Unknown
Core functionality is not reimplemented: `core ...` passes arguments directly
to qrx-cli without a shell.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


class WalletCliError(RuntimeError):
    pass


def default_datadir()->Path:
    if sys.platform=="darwin":base=Path.home()/"Library"/"Application Support"
    elif os.name=="nt":base=Path(os.environ.get("LOCALAPPDATA") or (Path.home()/"AppData"/"Local"))
    else:base=Path(os.environ.get("XDG_DATA_HOME") or (Path.home()/".local"/"share"))
    return base/"gui-wallet"/"qrx-data"


def resolve_program(explicit: Optional[str], name: str, script_dir: Path) -> str:
    candidates=[]
    if explicit:candidates.append(Path(explicit))
    if os.environ.get("QRX_BIN_DIR"):
        bindir=Path(os.environ["QRX_BIN_DIR"]);candidates.append(bindir/name);candidates.extend(sorted(bindir.glob(name+"-*")))
    found=shutil.which(name)
    if found:candidates.append(Path(found))
    candidates.extend([script_dir.parent/"build"/name,script_dir.parent.parent/"build"/name,script_dir.parent/name,script_dir/name]);candidates.extend(sorted(script_dir.glob(name+"-*")))
    if os.name=="nt":candidates.extend(Path(str(p)+".exe") for p in list(candidates))
    for candidate in candidates:
        if candidate.exists():return str(candidate.resolve())
    raise WalletCliError(f"could not find {name}; pass --{name}")


def resolve_script(script_dir:Path,name:str)->Path:
    candidates=[script_dir/name,script_dir/"qrx-wallet-resources"/name,script_dir.parent/"tools"/name,script_dir.parent/"gateways"/name]
    for candidate in candidates:
        if candidate.exists():return candidate.resolve()
    raise WalletCliError(f"missing wallet resource: {name}")


def run(args: List[str], *, input_text: Optional[str]=None) -> int:
    cp=subprocess.run(args,input=input_text,text=True)
    return int(cp.returncode)


def state_paths(datadir: Path,network: str,wallet: str)->dict:
    root=datadir/network
    wallet_dir=root/"wallets"/wallet
    settings=wallet_dir/"settings"
    return {
        "chain":root/"chain",
        "wallet":wallet_dir,
        "arbitrage":settings/"arbitrage",
        "kraken":settings/"kraken-gateway",
    }


def capabilities()->dict:
    return {
        "format":"QRX_WALLET_CAPABILITIES_V1",
        "core":"all qrx-cli commands through `core`",
        "phase_4f2":["arbitrage evaluation","paper trading","explicit approval","Kraken book fetch","complete CSV ledger","secure foreground Kraken gateway"],
        "ledger":"unbounded local collection with QRXDB generation/state-root verification; all-time, from/to, annual and quarterly periods",
        "secrets":"Kraken credentials are prompted with getpass and passed once through stdin",
        "btc_light":"all BDK key-store operations use qrx-btc-wallet-service shared with Tauri",
    }


def run_btc(service:str,datadir:Path,arguments:List[str])->int:
    if not arguments:raise WalletCliError("btc requires status, init, backup, restore, reset, sync, balance, new-address, send, test-endpoints, set-mode or start-neutrino")
    operation=arguments[0];rest=arguments[1:];request={"operation":operation}
    if operation in {"init","backup","sync","balance","new-address","send","restore"}:
        request["passphrase"]=getpass.getpass("BTC wallet passphrase: ")
        if not request["passphrase"]:raise WalletCliError("BTC wallet passphrase is required")
    if operation=="restore":
        p=argparse.ArgumentParser(prog="qrx-wallet-cli btc restore");p.add_argument("--overwrite",action="store_true");a=p.parse_args(rest)
        request.update({"mnemonic":getpass.getpass("BTC recovery phrase: "),"overwrite":a.overwrite})
    elif operation=="reset":
        if rest:raise WalletCliError("btc reset takes no arguments")
        request["confirm"]=input("Type DELETE BTC WALLET to confirm: ").strip()
    elif operation=="send":
        p=argparse.ArgumentParser(prog="qrx-wallet-cli btc send");p.add_argument("--to",required=True);p.add_argument("--amount-sats",required=True,type=int);p.add_argument("--fee-rate-sat-vb",type=float);a=p.parse_args(rest)
        request.update({"to_address":a.to,"amount_sats":a.amount_sats,"fee_rate_sat_vb":a.fee_rate_sat_vb})
    elif operation in {"status","test-endpoints"}:
        p=argparse.ArgumentParser(prog=f"qrx-wallet-cli btc {operation}");p.add_argument("--endpoint");a=p.parse_args(rest);request["endpoint"]=a.endpoint
    elif operation=="set-mode":
        p=argparse.ArgumentParser(prog="qrx-wallet-cli btc set-mode");p.add_argument("mode",choices=["electrum","esplora","neutrino"]);p.add_argument("--endpoint");a=p.parse_args(rest);request.update({"mode":a.mode,"endpoint":a.endpoint})
    elif operation not in {"init","backup","sync","balance","new-address","start-neutrino"}:
        raise WalletCliError(f"unknown BTC operation: {operation}")
    return run([service,"--data-dir",str(datadir)],input_text=json.dumps(request)+"\n")


def main()->int:
    ap=argparse.ArgumentParser(prog="qrx-wallet-cli",description="Unified QRX Core and Phase 4F.2 command-line wallet")
    ap.add_argument("--network",default="alpha");ap.add_argument("--datadir",default=str(default_datadir()));ap.add_argument("--wallet",default="node1")
    ap.add_argument("--qrx");ap.add_argument("--qrx-cli");ap.add_argument("--btc-service");ap.add_argument("action",choices=["core","btc","arbitrage","export-ledger","kraken-gateway","capabilities"]);ap.add_argument("arguments",nargs=argparse.REMAINDER)
    args=ap.parse_args();script_dir=Path(__file__).resolve().parent;paths=state_paths(Path(args.datadir).resolve(),args.network,args.wallet)
    if args.action=="capabilities":print(json.dumps(capabilities(),indent=2,sort_keys=True));return 0
    if args.action=="core":
        if not args.arguments:raise WalletCliError("core requires a qrx-cli command")
        cli=resolve_program(args.qrx_cli,"qrx-cli",script_dir)
        return run([cli,"--network",args.network,"--datadir",str(Path(args.datadir).resolve()),"--wallet",args.wallet,*args.arguments])
    if args.action=="btc":
        service=resolve_program(args.btc_service,"qrx-btc-wallet-service",script_dir)
        return run_btc(service,Path(args.datadir).resolve(),args.arguments)
    if args.action=="arbitrage":
        engine=resolve_script(script_dir,"qrx-arbitrage-engine.py")
        paths["arbitrage"].mkdir(parents=True,exist_ok=True)
        forwarded=list(args.arguments)
        if "--state-dir" not in forwarded:forwarded.extend(["--state-dir",str(paths["arbitrage"])])
        return run([sys.executable,str(engine),*forwarded])
    if args.action=="export-ledger":
        ep=argparse.ArgumentParser(prog="qrx-wallet-cli export-ledger");ep.add_argument("--output",required=True);ep.add_argument("--profile",choices=["de","international"],default="de");ep.add_argument("--from",dest="from_date");ep.add_argument("--to",dest="to_date");ep.add_argument("--year",type=int);ep.add_argument("--quarter",type=int,choices=[1,2,3,4]);ea=ep.parse_args(args.arguments)
        core=resolve_program(args.qrx,"qrx",script_dir);exporter=resolve_script(script_dir,"qrx-complete-ledger-export.py")
        command=[sys.executable,str(exporter),"--output",str(Path(ea.output).resolve()),"--profile",ea.profile,"--qrx",core,"--chain-dir",str(paths["chain"]),"--wallet-dir",str(paths["wallet"]),"--network",args.network,"--datadir",str(Path(args.datadir).resolve()),"--wallet",args.wallet,"--kraken-db",str(paths["kraken"]/"kraken-gateway.sqlite3"),"--arbitrage-db",str(paths["arbitrage"]/"arbitrage.sqlite3")]
        if ea.from_date:command.extend(["--from-date",ea.from_date])
        if ea.to_date:command.extend(["--to-date",ea.to_date])
        if ea.year is not None:command.extend(["--year",str(ea.year)])
        if ea.quarter is not None:command.extend(["--quarter",str(ea.quarter)])
        return run(command)
    gp=argparse.ArgumentParser(prog="qrx-wallet-cli kraken-gateway");gp.add_argument("--gateway-address",required=True);gp.add_argument("--poll",default="5");gp.add_argument("--lane",default="31");gp.add_argument("--once",action="store_true");ga=gp.parse_args(args.arguments)
    cli=resolve_program(args.qrx_cli,"qrx-cli",script_dir);gateway=resolve_script(script_dir,"qrx-gateway-kraken.py");paths["kraken"].mkdir(parents=True,exist_ok=True)
    api_key=getpass.getpass("Kraken API key: ");api_secret=getpass.getpass("Kraken API secret: ")
    if not api_key or not api_secret:raise WalletCliError("Kraken API key and secret are required")
    command=[sys.executable,str(gateway),"--qrx-cli",cli,"--network",args.network,"--datadir",str(Path(args.datadir).resolve()),"--wallet",args.wallet,"--gateway-address",ga.gateway_address,"--state-dir",str(paths["kraken"]),"--poll",ga.poll,"--lane",ga.lane]
    if ga.once:command.append("--once")
    return run(command,input_text=json.dumps({"api_key":api_key,"api_secret":api_secret})+"\n")


if __name__=="__main__":
    try:raise SystemExit(main())
    except (WalletCliError,ValueError) as exc:print(f"qrx-wallet-cli: {exc}",file=sys.stderr);raise SystemExit(2)
