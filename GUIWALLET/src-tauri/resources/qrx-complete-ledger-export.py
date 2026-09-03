#!/usr/bin/env python3
"""QRX 0.0.7 Phase 4F.2 complete CSV ledger exporter.

Exports normalized, deterministic UTF-8 CSV files without touching wallet or
Kraken secrets. Germany profile uses semicolon + decimal comma; international
profile uses comma + decimal point.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

SCHEMAS = {
  "transactions": ["timestamp_utc","height","txid","event_type","wallet","address","direction","asset","amount_atoms","amount","fee_atoms","fee","memo","status","source"],
  "orders": ["timestamp_utc","created_height","updated_height","order_id","owner","agent","kind","venue","market","side","order_type","quantity_atoms","filled_atoms","remaining_atoms","limit_price_atoms","status","order_expires_height","time_in_force","arbitrage_id","source_order_id","crosschain_session_id","venue_order_id","execution_gateway"],
  "trades": ["timestamp_utc","height","sequence","trade_id","market","maker_order_id","taker_order_id","buyer","seller","quantity_atoms","price_atoms","quote_atoms","source"],
  "crosschain_swaps": ["timestamp_utc","created_height","session_id","status","buyer_order_id","seller_order_id","buyer_owner","seller_owner","btc_sats","qub_atoms","price_atoms","btc_txid","btc_confirmations","bitcoin_spv_verified","qrx_refund_height","hashlock_hex"],
  "kraken_executions": ["qrx_order_id","cl_ord_id","kraken_txid","last_seen_status","pending_qrx_seq","updated_at_utc"],
  "arbitrage_report": ["created_at_utc","updated_at_utc","arbitrage_id","state","decision","reason","mode","qrx_order_id","crosschain_session_id","qrx_hedge_order_id","symbol","quantity_sats","quantity_btc","acquisition_qub","acquisition_eur","kraken_gross_eur","kraken_vwap_eur","kraken_limit_eur","kraken_fee_eur","slippage_buffer_eur","risk_buffer_eur","network_fees_eur","net_profit_eur","net_margin_bps","oracle_source","oracle_timestamp","book_timestamp","approved_at_utc"],
  "complete_ledger": ["timestamp_utc","record_type","primary_id","related_id","wallet","agent","venue","market","side","asset","quantity_atoms","quantity","price_atoms","gross_value","fee_value","net_value","realized_profit","status","source"],
}

class ExportError(RuntimeError): pass

def parse_period(from_date:Optional[str]=None,to_date:Optional[str]=None,year:Optional[int]=None,quarter:Optional[int]=None)->Optional[Dict[str,Any]]:
    if (from_date or to_date) and (year or quarter):raise ExportError("use either --from-date/--to-date or --year/--quarter")
    if quarter and not year:raise ExportError("--quarter requires --year")
    if year and not 1970<=year<=9998:raise ExportError("year must be between 1970 and 9998")
    if quarter and quarter not in {1,2,3,4}:raise ExportError("quarter must be 1, 2, 3 or 4")
    def boundary(value:str,end:bool)->datetime:
        raw=value.strip().replace("Z","+00:00")
        try:dt=datetime.fromisoformat(raw)
        except ValueError:raise ExportError(f"invalid ISO date/time: {value}")
        date_only=len(value.strip())==10
        if dt.tzinfo is None:dt=dt.replace(tzinfo=timezone.utc)
        else:dt=dt.astimezone(timezone.utc)
        if end and date_only:dt+=timedelta(days=1)
        return dt
    if year:
        month=1 if not quarter else (quarter-1)*3+1;start=datetime(year,month,1,tzinfo=timezone.utc)
        if quarter:end=datetime(year+1,1,1,tzinfo=timezone.utc) if quarter==4 else datetime(year,month+3,1,tzinfo=timezone.utc)
        else:end=datetime(year+1,1,1,tzinfo=timezone.utc)
        label=str(year) if not quarter else f"{year}-Q{quarter}"
    elif from_date or to_date:
        start=boundary(from_date,False) if from_date else datetime(1970,1,1,tzinfo=timezone.utc);end=boundary(to_date,True) if to_date else datetime(9999,1,1,tzinfo=timezone.utc);label=f"{from_date or 'begin'}--{to_date or 'open'}"
    else:return None
    if start>=end:raise ExportError("export start must be before export end")
    return {"start_epoch":int(start.timestamp()),"end_epoch_exclusive":int(end.timestamp()),"from_utc":start.isoformat().replace("+00:00","Z"),"to_utc_exclusive":end.isoformat().replace("+00:00","Z"),"label":label}

def value_epoch(value:Any)->Optional[int]:
    if value in (None,""):return None
    try:return int(value)
    except (TypeError,ValueError):
        try:return int(datetime.fromisoformat(str(value).replace("Z","+00:00")).timestamp())
        except ValueError:return None

def block_timestamps(chain_dir:str)->Dict[int,int]:
    out:Dict[int,int]={}
    for path in sorted((Path(chain_dir)/"blocks").glob("*.block")):
        fields:Dict[str,str]={}
        try:
            for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
                if "=" in line:
                    key,value=line.split("=",1)
                    if key in {"height","timestamp"} and key not in fields:fields[key]=value.strip()
        except OSError as exc:raise ExportError(f"cannot read block timestamp from {path.name}: {exc}")
        try:h=int(fields["height"]);ts=int(fields["timestamp"])
        except (KeyError,ValueError):continue
        if h in out and out[h]!=ts:raise ExportError(f"conflicting timestamps for block height {h}")
        out[h]=ts
    return out

def filter_period(data:Dict[str,List[Dict[str,Any]]],period:Optional[Dict[str,Any]],height_times:Dict[int,int])->Dict[str,List[Dict[str,Any]]]:
    if not period:return data
    height_field={"orders":"created_height","trades":"height","crosschain_swaps":"created_height"}
    result:Dict[str,List[Dict[str,Any]]]={};start=period["start_epoch"];end=period["end_epoch_exclusive"]
    for source,rows in data.items():
        selected=[]
        for row in rows:
            ts=value_epoch(row.get("timestamp_utc") or row.get("timestamp") or row.get("created_at_utc") or row.get("updated_at_utc"))
            if ts is None and source in height_field:
                try:h=int(row.get(height_field[source]) or -1)
                except (TypeError,ValueError):h=-1
                ts=height_times.get(h)
            if ts is None:raise ExportError(f"{source} row has no provable timestamp for period export: {row.get('txid') or row.get('order_id') or row.get('trade_id') or row.get('session_id') or 'unknown'}")
            if start<=ts<end:
                item=dict(row);item["timestamp_utc"]=utc(ts);selected.append(item)
        result[source]=selected
    return result

def parse_kv_line(line: str) -> Dict[str,str]:
    out={}
    for token in str(line).strip().split():
        if "=" in token:
            k,v=token.split("=",1);out[k]=v
    return out

def utc(value: Any) -> str:
    try: n=int(value or 0)
    except (TypeError,ValueError): return ""
    if n<=0:return ""
    return datetime.fromtimestamp(n,tz=timezone.utc).isoformat().replace("+00:00","Z")

def decimal_display(value: Any, comma: bool) -> str:
    s=str(value if value is not None else "")
    return s.replace(".",",") if comma and s else s

def normalize_row(row: Dict[str,Any], fields: Sequence[str], decimal_comma: bool) -> Dict[str,str]:
    out={}
    decimal_fields={"amount","fee","quantity","gross_value","fee_value","net_value","realized_profit","quantity_btc","acquisition_qub","acquisition_eur","kraken_gross_eur","kraken_vwap_eur","kraken_limit_eur","kraken_fee_eur","slippage_buffer_eur","risk_buffer_eur","network_fees_eur","net_profit_eur","net_margin_bps"}
    numeric_fields=decimal_fields|{"height","created_height","updated_height","sequence","pending_qrx_seq","order_expires_height","quantity_atoms","filled_atoms","remaining_atoms","limit_price_atoms","amount_atoms","fee_atoms","price_atoms","quote_atoms","btc_sats","qub_atoms","btc_confirmations","quantity_sats"}
    for f in fields:
        v=row.get(f,"")
        if isinstance(v,(dict,list)):v=json.dumps(v,sort_keys=True,separators=(",",":"))
        rendered=decimal_display(v,decimal_comma and f in decimal_fields)
        # Prevent spreadsheet formula execution when an address, memo or venue
        # string is opened in Excel/LibreOffice. The leading apostrophe is the
        # conventional inert-text marker and remains visible in raw CSV.
        if f not in numeric_fields and rendered.startswith(("=","+","-","@","\t","\r")): rendered="'"+rendered
        out[f]=rendered
    return out

def write_csv(path: Path, rows: List[Dict[str,Any]], fields: Sequence[str], profile: str) -> None:
    delimiter=";" if profile=="de" else ",";decimal_comma=profile=="de"
    with path.open("w",encoding="utf-8-sig",newline="") as fh:
        w=csv.DictWriter(fh,fieldnames=fields,delimiter=delimiter,quoting=csv.QUOTE_MINIMAL,lineterminator="\n")
        w.writeheader()
        for row in rows:w.writerow(normalize_row(row,fields,decimal_comma))

class QrxCli:
    def __init__(self,binary:str,network:str,datadir:str,wallet:str):self.base=[binary,"--network",network,"--datadir",datadir,"--wallet",wallet];self.warnings:List[str]=[]
    def call(self,*args:str)->Dict[str,Any]:
        cp=subprocess.run(self.base+list(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=60)
        label=" ".join(args)
        if cp.returncode:self.warnings.append(f"{label}: {cp.stderr.strip() or 'command failed'}");return {}
        try:obj=json.loads(cp.stdout)
        except Exception:self.warnings.append(f"{label}: invalid JSON response");return {}
        if not obj.get("ok",False):self.warnings.append(f"{label}: {obj.get('error') or 'QRX command failed'}");return {}
        return obj.get("result") or {}

class CoreBackend:
    """Unbounded local reader for an authoritative QRX chain snapshot.

    The JSON-RPC daemon deliberately uses bounded response buffers.  That is
    appropriate for interactive pages, but not for a complete accounting
    export.  The exporter therefore invokes the local `qrx` state reader
    directly and proves that the QRXDB generation/state root did not change
    while the data was collected.
    """
    def __init__(self,binary:str,chain_dir:str,wallet_dir:str):
        self.binary=binary;self.chain_dir=chain_dir;self.wallet_dir=wallet_dir
    def lines(self,*args:str)->List[str]:
        cp=subprocess.run([self.binary,*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=3600)
        if cp.returncode:
            raise ExportError(f"qrx {' '.join(args[:1])} failed: {cp.stderr.strip() or cp.stdout.strip() or 'unknown error'}")
        return [line for line in cp.stdout.splitlines() if line.strip()]
    def key_values(self,*args:str)->Dict[str,str]:
        out:Dict[str,str]={}
        for line in self.lines(*args):
            if "=" in line:
                key,value=line.split("=",1);out[key.strip()]=value.strip()
        return out
    def snapshot(self)->Dict[str,str]:
        value=self.key_values("state-root",self.chain_dir)
        if not value.get("generation") or not value.get("state_root"):
            raise ExportError("QRX Core did not return a verifiable generation and state root")
        return {"generation":value["generation"],"state_root":value["state_root"]}

def collect_transactions(qrx: Optional[QrxCli], wallet: str) -> List[Dict[str,Any]]:
    if not qrx:return []
    address_result=qrx.call("listaddresses");addresses=address_result.get("addresses") or []
    if not addresses:
        addresses=[""]
    rows=[];seen=set()
    for address_item in addresses:
        if isinstance(address_item,dict):address=str(address_item.get("address") or "")
        else:address=str(address_item).strip()
        result=qrx.call("history",address,"all") if address else qrx.call("history")
        source=result.get("entries") or result.get("transactions") or result.get("history") or []
        if isinstance(source,dict):source=[source]
        for item in source:
            x=parse_kv_line(item) if isinstance(item,str) else dict(item)
            identity=str(x.get("txid") or x.get("hash") or item)
            if identity in seen:continue
            seen.add(identity);x.setdefault("wallet",wallet);x.setdefault("address",address);x.setdefault("source","qrx-chain");rows.append(x)
    return rows

def _unique_rows(rows:Iterable[Dict[str,Any]],id_key:str,source:str)->List[Dict[str,Any]]:
    out=[];seen=set()
    for row in rows:
        ident=str(row.get(id_key) or "")
        if not ident:raise ExportError(f"{source} returned a row without {id_key}")
        if ident in seen:raise ExportError(f"{source} returned duplicate {id_key}={ident}")
        seen.add(ident);out.append(row)
    return out

def collect_core_transactions(core:CoreBackend,wallet:str,addresses:Sequence[str],period:Optional[Dict[str,Any]]=None)->List[Dict[str,Any]]:
    rows=[];seen=set();owned=set(addresses)
    for address in addresses:
        args=["history",core.chain_dir,address,"all"]
        if period:args.extend([str(period["start_epoch"]),str(period["end_epoch_exclusive"])])
        for line in core.lines(*args):
            item=parse_kv_line(line);tokens=line.split();event_type=(tokens[1] if len(tokens)>1 and tokens[0].startswith("journal_timestamp=") else tokens[0]) if tokens else "event";chain_id=str(item.get("txid") or item.get("body_hash") or item.get("hash") or "");identity=chain_id or "event:"+hashlib.sha256(line.encode()).hexdigest()
            if identity in seen:continue
            seen.add(identity);sender=str(item.get("from") or "");recipient=str(item.get("to") or "")
            if sender in owned and recipient in owned:direction="INTERNAL"
            elif sender in owned:direction="OUT"
            elif recipient in owned:direction="IN"
            else:direction=str(item.get("direction") or event_type.upper())
            item.update({"txid":identity,"event_type":event_type,"wallet":wallet,"address":address,"direction":direction,"asset":item.get("asset","QUB"),"amount_atoms":item.get("amount_atoms",item.get("amount","")),"fee_atoms":item.get("fee_atoms",item.get("fee","")),"timestamp_utc":utc(item.get("journal_timestamp",item.get("timestamp",0))),"status":item.get("status","confirmed"),"source":"qrx-chain-journal"});rows.append(item)
    return rows

def collect_core_detailed(core:CoreBackend,list_args:Sequence[str],id_key:str,detail_command:Optional[str])->List[Dict[str,Any]]:
    rows=[]
    for line in core.lines(*list_args):
        brief=parse_kv_line(line);ident=str(brief.get(id_key) or "")
        if not ident:raise ExportError(f"{list_args[0]} returned a row without {id_key}")
        detail=core.key_values(detail_command,core.chain_dir,ident) if detail_command else {};row=dict(brief);row.update(detail);row[id_key]=ident;rows.append(row)
    return _unique_rows(rows,id_key,list_args[0])

def collect_core_snapshot(core:CoreBackend,wallet:str,max_attempts:int=3,period:Optional[Dict[str,Any]]=None,height_times:Optional[Dict[int,int]]=None)->tuple[Dict[str,List[Dict[str,Any]]],Dict[str,Any]]:
    for attempt in range(1,max_attempts+1):
        before=core.snapshot()
        addresses=[line.strip() for line in core.lines("listaddresses",core.wallet_dir) if line.strip()]
        if not addresses:raise ExportError("selected wallet contains no QRX addresses")
        owned=set(addresses)
        transactions=collect_core_transactions(core,wallet,addresses,period)
        orders=collect_core_detailed(core,["list-orders",core.chain_dir],"order_id","order-status")
        trade_args=["list-trades",core.chain_dir,"*","all"]
        if period and height_times:
            matching=sorted(h for h,ts in height_times.items() if period["start_epoch"]<=ts<period["end_epoch_exclusive"])
            trades=collect_core_detailed(core,trade_args+[str(matching[0]),str(matching[-1])],"trade_id",None) if matching else []
        else:trades=collect_core_detailed(core,trade_args,"trade_id",None)
        swaps=collect_core_detailed(core,["list-crosschain",core.chain_dir],"session_id","crosschain-status")
        # A wallet ledger must never silently include unrelated network users.
        orders=[r for r in orders if str(r.get("owner") or "") in owned or str(r.get("agent") or "") in owned]
        trades=[r for r in trades if str(r.get("buyer") or "") in owned or str(r.get("seller") or "") in owned]
        swaps=[r for r in swaps if str(r.get("buyer_owner") or "") in owned or str(r.get("seller_owner") or "") in owned]
        after=core.snapshot()
        if before==after:
            data={"transactions":transactions,"orders":orders,"trades":trades,"crosschain_swaps":swaps}
            meta={"generation":before["generation"],"state_root":before["state_root"],"attempt":attempt,"wallet_address_count":len(addresses),"source_counts":{k:len(v) for k,v in data.items()}}
            return data,meta
    raise ExportError("QRX state changed during export three times; no inconsistent ledger was written")

def collect_detailed(qrx: Optional[QrxCli], list_command: str, list_key: str, id_key: str, get_command: str, *list_args: str) -> List[Dict[str,Any]]:
    if not qrx:return []
    result=qrx.call(list_command,*list_args);items=result.get(list_key) or []
    rows=[]
    for item in items:
        brief=parse_kv_line(item) if isinstance(item,str) else dict(item)
        ident=str(brief.get(id_key) or "")
        detail=qrx.call(get_command,ident) if ident else {}
        row=dict(brief);row.update(detail);row.setdefault(id_key,ident);rows.append(row)
    return rows

def collect_kraken(path: Optional[Path],period:Optional[Dict[str,Any]]=None) -> List[Dict[str,Any]]:
    if not path or not path.exists():return []
    db=sqlite3.connect(f"file:{path}?mode=ro",uri=True);db.row_factory=sqlite3.Row
    has_events=bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_events'").fetchone())
    if has_events:query="SELECT qrx_order_id,cl_ord_id,kraken_txid,last_seen_status,0 AS pending_qrx_seq,observed_at AS updated_at FROM execution_events"
    else:query="SELECT qrx_order_id,cl_ord_id,kraken_txid,last_seen_status,pending_qrx_seq,updated_at FROM orders"
    params:tuple[Any,...]=()
    if period:query+=" WHERE "+("observed_at" if has_events else "updated_at")+">=? AND "+("observed_at" if has_events else "updated_at")+"<?";params=(period["start_epoch"],period["end_epoch_exclusive"])
    try:rows=[dict(r) for r in db.execute(query+" ORDER BY updated_at",params)]
    finally:db.close()
    for r in rows:r["updated_at_utc"]=utc(r.pop("updated_at",0))
    return rows

def collect_arbitrage(path: Optional[Path],period:Optional[Dict[str,Any]]=None) -> List[Dict[str,Any]]:
    if not path or not path.exists():return []
    db=sqlite3.connect(f"file:{path}?mode=ro",uri=True);db.row_factory=sqlite3.Row;out=[]
    try:
        query="SELECT arbitrage_id,created_at,updated_at,state,decision_json,approved_at,qrx_hedge_order_id FROM opportunities";params:tuple[Any,...]=()
        if period:query+=" WHERE created_at>=? AND created_at<?";params=(period["start_epoch"],period["end_epoch_exclusive"])
        for row in db.execute(query+" ORDER BY created_at",params):
            item=json.loads(row["decision_json"]);item.update({"arbitrage_id":row["arbitrage_id"],"state":row["state"],"created_at_utc":utc(row["created_at"]),"updated_at_utc":utc(row["updated_at"]),"approved_at_utc":utc(row["approved_at"]),"qrx_hedge_order_id":row["qrx_hedge_order_id"] or ""});out.append(item)
    finally:db.close()
    return out

def complete_rows(data: Dict[str,List[Dict[str,Any]]]) -> List[Dict[str,Any]]:
    out=[]
    for r in data["transactions"]:
        out.append({"timestamp_utc":r.get("timestamp_utc",r.get("timestamp","")),"record_type":"transaction","primary_id":r.get("txid",r.get("hash","")),"wallet":r.get("wallet",""),"side":r.get("direction",""),"asset":r.get("asset","QUB"),"quantity_atoms":r.get("amount_atoms",r.get("amount","")),"quantity":r.get("amount",""),"fee_value":r.get("fee",""),"status":r.get("status","confirmed"),"source":r.get("source","qrx-chain")})
    for r in data["orders"]:
        out.append({"timestamp_utc":r.get("timestamp_utc",""),"record_type":"order","primary_id":r.get("order_id",""),"related_id":r.get("arbitrage_id",r.get("crosschain_session_id","")),"wallet":r.get("owner",""),"agent":r.get("agent",""),"venue":r.get("venue","QRX"),"market":r.get("market",""),"side":r.get("side",""),"quantity_atoms":r.get("quantity_atoms",""),"price_atoms":r.get("limit_price_atoms",""),"status":r.get("status",""),"source":"qrx-order-state"})
    for r in data["trades"]:
        out.append({"timestamp_utc":r.get("timestamp_utc",""),"record_type":"trade","primary_id":r.get("trade_id",""),"related_id":r.get("maker_order_id","")+"|"+r.get("taker_order_id",""),"market":r.get("market",""),"quantity_atoms":r.get("quantity_atoms",""),"price_atoms":r.get("price_atoms",""),"gross_value":r.get("quote_atoms",""),"status":"settled","source":"qrx-trade-state"})
    for r in data["crosschain_swaps"]:
        out.append({"timestamp_utc":r.get("timestamp_utc",""),"record_type":"crosschain_swap","primary_id":r.get("session_id",""),"related_id":r.get("btc_txid",""),"market":"BTC/QUB","asset":"BTC","quantity_atoms":r.get("btc_sats",""),"gross_value":r.get("qub_atoms",""),"price_atoms":r.get("price_atoms",""),"status":r.get("status",""),"source":"qrx-crosschain-state"})
    for r in data["kraken_executions"]:
        out.append({"timestamp_utc":r.get("updated_at_utc",""),"record_type":"kraken_execution","primary_id":r.get("kraken_txid",""),"related_id":r.get("qrx_order_id",""),"venue":"KRAKEN","status":r.get("last_seen_status",""),"source":"kraken-gateway"})
    for r in data["arbitrage_report"]:
        out.append({"timestamp_utc":r.get("updated_at_utc",""),"record_type":"arbitrage","primary_id":r.get("arbitrage_id",""),"related_id":r.get("qrx_order_id",""),"venue":"QRX→KRAKEN","market":r.get("symbol","BTC/EUR"),"side":"SELL","asset":"BTC","quantity_atoms":r.get("quantity_sats",""),"quantity":r.get("quantity_btc",""),"gross_value":r.get("kraken_gross_eur",""),"fee_value":r.get("kraken_fee_eur",""),"net_value":r.get("net_profit_eur",""),"realized_profit":r.get("net_profit_eur","") if r.get("state") == "COMPLETED" else "","status":r.get("state",""),"source":"qrx-arbitrage"})
    return sorted(out,key=lambda r:(str(r.get("timestamp_utc","")),str(r.get("record_type","")),str(r.get("primary_id",""))))

def export_bundle(output:Path,profile:str,data:Dict[str,List[Dict[str,Any]]],warnings:Optional[List[str]]=None,snapshot:Optional[Dict[str,Any]]=None,period:Optional[Dict[str,Any]]=None)->Dict[str,Any]:
    if profile not in {"de","international"}:raise ExportError("profile must be de or international")
    warnings=list(warnings or [])
    if warnings:raise ExportError("refusing incomplete ledger export: "+"; ".join(warnings))
    output.mkdir(parents=True,exist_ok=True)
    data=dict(data);data["complete_ledger"]=complete_rows(data)
    files=[]
    for name,fields in SCHEMAS.items():
        path=output/f"{name}.csv";write_csv(path,data.get(name,[]),fields,profile);files.append(path)
    manifest={"format":"QRX_COMPLETE_LEDGER_V3","created_at_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"profile":profile,"complete":True,"export_period":period or {"label":"all-time"},"source_warnings":[],"chain_snapshot":snapshot or {},"source_counts":{k:len(data.get(k,[])) for k in SCHEMAS if k!="complete_ledger"},"files":[]}
    for path in files:manifest["files"].append({"name":path.name,"rows":len(data[path.stem]),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    mp=output/"manifest.json";mp.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8");return manifest

def export_bundle_atomic(output:Path,profile:str,data:Dict[str,List[Dict[str,Any]]],snapshot:Optional[Dict[str,Any]]=None,period:Optional[Dict[str,Any]]=None)->Dict[str,Any]:
    if output.exists():raise ExportError(f"output directory already exists: {output}")
    output.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix=f".{output.name}.partial-",dir=str(output.parent)))
    try:
        manifest=export_bundle(staging,profile,data,snapshot=snapshot,period=period)
        os.replace(staging,output)
        return manifest
    except Exception:
        shutil.rmtree(staging,ignore_errors=True)
        raise

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--output",required=True);ap.add_argument("--profile",choices=["de","international"],default="de");ap.add_argument("--from-date");ap.add_argument("--to-date");ap.add_argument("--year",type=int);ap.add_argument("--quarter",type=int);ap.add_argument("--qrx");ap.add_argument("--chain-dir");ap.add_argument("--wallet-dir");ap.add_argument("--qrx-cli");ap.add_argument("--network",default="alpha");ap.add_argument("--datadir");ap.add_argument("--wallet",default="node1");ap.add_argument("--kraken-db");ap.add_argument("--arbitrage-db");args=ap.parse_args()
    period=parse_period(args.from_date,args.to_date,args.year,args.quarter)
    snapshot:Dict[str,Any]={}
    if not (args.qrx and args.chain_dir and args.wallet_dir):
        raise ExportError("complete export requires the unbounded local --qrx, --chain-dir and --wallet-dir snapshot path")
    core=CoreBackend(args.qrx,args.chain_dir,args.wallet_dir);data:Dict[str,List[Dict[str,Any]]]={};height_times:Dict[int,int]={}
    for attempt in range(1,4):
        height_times=block_timestamps(args.chain_dir)
        core_data,snapshot=collect_core_snapshot(core,args.wallet,period=period,height_times=height_times)
        data=dict(core_data)
        data["kraken_executions"]=collect_kraken(Path(args.kraken_db) if args.kraken_db else None,period)
        data["arbitrage_report"]=collect_arbitrage(Path(args.arbitrage_db) if args.arbitrage_db else None,period)
        # The off-chain journals are read from SQLite snapshot transactions.
        # Recheck QRX after those reads so the published bundle has one exact
        # and explicitly recorded on-chain generation/state root.
        after_height_times=block_timestamps(args.chain_dir)
        if core.snapshot()=={"generation":snapshot["generation"],"state_root":snapshot["state_root"]} and after_height_times==height_times:
            snapshot["final_consistency_attempt"]=attempt
            snapshot["offchain_sources_collected_at_utc"]=datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
            snapshot["block_timestamp_count"]=len(height_times)
            snapshot["block_timestamp_sha256"]=hashlib.sha256("".join(f"{h}:{height_times[h]}\n" for h in sorted(height_times)).encode()).hexdigest()
            break
    else:
        raise ExportError("QRX state changed while off-chain journals were collected; no inconsistent ledger was written")
    data=filter_period(data,period,height_times)
    manifest=export_bundle_atomic(Path(args.output),args.profile,data,snapshot,period);manifest["output_dir"]=str(Path(args.output));print(json.dumps(manifest,sort_keys=True));return 0

if __name__=="__main__":raise SystemExit(main())
