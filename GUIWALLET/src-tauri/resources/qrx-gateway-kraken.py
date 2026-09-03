#!/usr/bin/env python3
"""QRX 0.0.7 Kraken Spot execution gateway.

Secrets are read once from stdin as JSON and never from a plaintext config file.
Expected stdin JSON: {"api_key":"...","api_secret":"..."[,"rpc_user":"...","rpc_password":"..."]}

The gateway watches QRX EXTERNAL_ORDER state through qrx-cli, submits/cancels
Kraken Spot orders, and emits signed QRX EXECUTION_REPORT transactions using the
currently selected QRX wallet (which must be the registered KRAKEN gateway).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass

os.umask(0o077)
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except (ImportError, AttributeError, OSError, ValueError):
    pass
from decimal import Decimal, ROUND_DOWN, ROUND_UP, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

ATOMS = Decimal("100000000")
TERMINAL_QRX = {"filled", "rejected", "canceled"}
WATCH_QRX = {"pending_execution", "submitted", "partially_filled", "cancel_pending"}

class GatewayError(RuntimeError):
    pass

class KrakenError(GatewayError):
    def __init__(self, message: str, errors: Optional[Iterable[str]] = None):
        self.errors = list(errors or [])
        super().__init__(message if not self.errors else f"{message}: {', '.join(self.errors)}")


def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def parse_kv_line(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for token in line.strip().split():
        if "=" in token:
            k, v = token.split("=", 1)
            out[k] = v
    return out


def atoms_to_decimal(value: str | int) -> Decimal:
    return Decimal(str(value)) / ATOMS


def decimal_to_atoms(value: Any) -> int:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise GatewayError(f"invalid decimal value from Kraken: {value}") from exc
    return int((d * ATOMS).to_integral_value(rounding=ROUND_DOWN))


def canonical_client_order_id(qrx_order_id: str) -> str:
    # Kraken short UUID form: exactly 32 hex chars. Hash the complete QRX id so
    # long SHA3-512 ids cannot collide merely because they share a prefix.
    return hashlib.sha256(qrx_order_id.encode("utf-8")).hexdigest()[:32]


def normalize_asset(asset: str) -> str:
    a = asset.strip().upper()
    aliases = {"BTC": "XBT", "DOGE": "XDG"}
    return aliases.get(a, a)


def normalize_market(market: str) -> str:
    parts = [p for p in market.replace("-", "/").split("/") if p]
    if len(parts) != 2:
        raise GatewayError(f"unsupported QRX market format: {market}")
    return f"{normalize_asset(parts[0])}/{normalize_asset(parts[1])}"


@dataclass
class PairInfo:
    pair: str
    wsname: str
    pair_decimals: int
    lot_decimals: int
    ordermin: Decimal


class PairCatalog:
    def __init__(self, result: Dict[str, Any]):
        self.by_market: Dict[str, PairInfo] = {}
        for pair_id, meta in (result or {}).items():
            if not isinstance(meta, dict):
                continue
            alt = str(meta.get("altname") or pair_id)
            ws = str(meta.get("wsname") or "")
            candidates = set()
            if ws and "/" in ws:
                try:
                    candidates.add(normalize_market(ws))
                except GatewayError:
                    pass
            # altname has no separator; still keep exact aliases for fallback.
            info = PairInfo(
                pair=alt,
                wsname=ws,
                pair_decimals=int(meta.get("pair_decimals") or 8),
                lot_decimals=int(meta.get("lot_decimals") or 8),
                ordermin=Decimal(str(meta.get("ordermin") or "0")),
            )
            for c in candidates:
                self.by_market[c] = info

    def resolve(self, market: str) -> PairInfo:
        norm = normalize_market(market)
        if norm in self.by_market:
            return self.by_market[norm]
        # Conservative altname fallback for common Kraken Spot pairs.
        base, quote = norm.split("/", 1)
        return PairInfo(base + quote, norm, 8, 8, Decimal("0"))


class KrakenClient:
    BASE = "https://api.kraken.com"

    def __init__(self, api_key: str, api_secret: str, timeout: int = 20):
        if not api_key or not api_secret:
            raise GatewayError("Kraken API key and secret are required")
        self.api_key = api_key
        self.api_secret = api_secret
        self.timeout = timeout
        self._nonce = int(time.time_ns() // 1_000_000)

    def next_nonce(self) -> str:
        now = int(time.time_ns() // 1_000_000)
        self._nonce = max(now, self._nonce + 1)
        return str(self._nonce)

    @staticmethod
    def signature(urlpath: str, data: Dict[str, Any], secret: str) -> str:
        encoded = urllib.parse.urlencode(data)
        nonce = str(data["nonce"])
        digest = hashlib.sha256((nonce + encoded).encode()).digest()
        message = urlpath.encode() + digest
        mac = hmac.new(base64.b64decode(secret), message, hashlib.sha512)
        return base64.b64encode(mac.digest()).decode()

    def _request(self, path: str, data: Optional[Dict[str, Any]] = None, private: bool = True) -> Dict[str, Any]:
        payload = dict(data or {})
        headers = {"User-Agent": "QRX-Kraken-Gateway/0.0.7"}
        if private:
            payload["nonce"] = self.next_nonce()
        encoded = urllib.parse.urlencode(payload).encode()
        if private:
            headers["API-Key"] = self.api_key
            headers["API-Sign"] = self.signature(path, payload, self.api_secret)
        req = urllib.request.Request(self.BASE + path, data=encoded if payload else None, headers=headers, method="POST" if payload or private else "GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read() if hasattr(exc, "read") else b""
            raise KrakenError(f"Kraken HTTP {exc.code}: {body[:512]!r}") from exc
        except OSError as exc:
            raise KrakenError(f"Kraken network error: {exc}") from exc
        try:
            obj = json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise KrakenError("Kraken returned invalid JSON") from exc
        errors = obj.get("error") or []
        if errors:
            raise KrakenError("Kraken API rejected request", errors)
        return obj.get("result") or {}

    def public_asset_pairs(self) -> Dict[str, Any]:
        return self._request("/0/public/AssetPairs", {}, private=False)

    def api_key_info(self) -> Dict[str, Any]:
        return self._request("/0/private/GetApiKeyInfo", {})

    def add_order(self, pair: str, side: str, ordertype: str, volume: str, price: Optional[str], cl_ord_id: str, time_in_force: str = "GTC") -> str:
        data: Dict[str, Any] = {"pair": pair, "type": side.lower(), "ordertype": ordertype.lower(), "volume": volume, "cl_ord_id": cl_ord_id}
        if ordertype.lower() == "limit":
            data["price"] = price
        tif = str(time_in_force or "GTC").upper()
        if tif not in {"GTC", "GTD", "IOC", "FOK"}:
            raise GatewayError(f"unsupported Kraken time-in-force: {tif}")
        data["timeinforce"] = tif
        if tif in {"IOC", "FOK"}:
            data["deadline"] = datetime.fromtimestamp(time.time() + 5, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        result = self._request("/0/private/AddOrder", data)
        txids = result.get("txid") or []
        if not txids:
            raise KrakenError("Kraken AddOrder returned no txid")
        return str(txids[0])

    def cancel_order(self, txid: Optional[str], cl_ord_id: str) -> None:
        data = {"txid": txid} if txid else {"cl_ord_id": cl_ord_id}
        self._request("/0/private/CancelOrder", data)

    def query_order(self, txid: str) -> Optional[Dict[str, Any]]:
        result = self._request("/0/private/QueryOrders", {"txid": txid, "trades": "false"})
        item = result.get(txid)
        if item is None and result:
            item = next(iter(result.values()))
        return item if isinstance(item, dict) else None

    def find_by_client_id(self, cl_ord_id: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        for path, key in (("/0/private/OpenOrders", "open"), ("/0/private/ClosedOrders", "closed")):
            result = self._request(path, {"trades": "false"})
            entries = result.get(key) or {}
            for txid, order in entries.items():
                if isinstance(order, dict) and str(order.get("cl_ord_id") or "") == cl_ord_id:
                    return str(txid), order
        return None


class GatewayDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS orders(
              qrx_order_id TEXT PRIMARY KEY,
              cl_ord_id TEXT NOT NULL,
              kraken_txid TEXT,
              last_seen_status TEXT,
              pending_qrx_seq INTEGER DEFAULT 0,
              pending_signed_tx TEXT,
              updated_at INTEGER NOT NULL
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS execution_events(
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              qrx_order_id TEXT NOT NULL,
              cl_ord_id TEXT NOT NULL,
              kraken_txid TEXT,
              last_seen_status TEXT NOT NULL,
              observed_at INTEGER NOT NULL,
              UNIQUE(qrx_order_id,last_seen_status,observed_at)
            )
        """)
        self.db.execute("""
            INSERT OR IGNORE INTO execution_events(qrx_order_id,cl_ord_id,kraken_txid,last_seen_status,observed_at)
            SELECT qrx_order_id,cl_ord_id,kraken_txid,last_seen_status,updated_at FROM orders
            WHERE last_seen_status IS NOT NULL AND updated_at IS NOT NULL
        """)
        self.db.commit()

    def get(self, oid: str) -> Dict[str, Any]:
        row = self.db.execute("SELECT cl_ord_id,kraken_txid,last_seen_status,pending_qrx_seq,pending_signed_tx FROM orders WHERE qrx_order_id=?", (oid,)).fetchone()
        if not row:
            return {}
        return {"cl_ord_id": row[0], "kraken_txid": row[1], "last_seen_status": row[2], "pending_qrx_seq": row[3] or 0, "pending_signed_tx": row[4]}

    def upsert(self, oid: str, cl: str, txid: Optional[str] = None, status: Optional[str] = None) -> None:
        previous = self.db.execute("SELECT kraken_txid,last_seen_status FROM orders WHERE qrx_order_id=?", (oid,)).fetchone()
        now = int(time.time())
        self.db.execute("""
          INSERT INTO orders(qrx_order_id,cl_ord_id,kraken_txid,last_seen_status,updated_at)
          VALUES(?,?,?,?,?)
          ON CONFLICT(qrx_order_id) DO UPDATE SET
            cl_ord_id=excluded.cl_ord_id,
            kraken_txid=COALESCE(excluded.kraken_txid,orders.kraken_txid),
            last_seen_status=COALESCE(excluded.last_seen_status,orders.last_seen_status),
            updated_at=excluded.updated_at
        """, (oid, cl, txid, status, now))
        effective_txid = txid or (previous[0] if previous else None)
        effective_status = status or (previous[1] if previous else None)
        if effective_status and (not previous or effective_txid != previous[0] or effective_status != previous[1]):
            self.db.execute("INSERT OR IGNORE INTO execution_events(qrx_order_id,cl_ord_id,kraken_txid,last_seen_status,observed_at) VALUES(?,?,?,?,?)", (oid, cl, effective_txid, effective_status, now))
        self.db.commit()

    def set_pending_report(self, oid: str, seq: int, signed_tx: str) -> None:
        self.db.execute("UPDATE orders SET pending_qrx_seq=?, pending_signed_tx=?, updated_at=? WHERE qrx_order_id=?", (seq, signed_tx, int(time.time()), oid))
        self.db.commit()

    def clear_pending_report(self, oid: str) -> None:
        self.db.execute("UPDATE orders SET pending_qrx_seq=0, pending_signed_tx=NULL, updated_at=? WHERE qrx_order_id=?", (int(time.time()), oid))
        self.db.commit()


class QrxCli:
    def __init__(self, binary: str, network: str, datadir: str, wallet: str, rpc_user: str = "", rpc_password: str = ""):
        self.binary = binary
        self.base = [binary, "--network", network, "--datadir", datadir, "--wallet", wallet]
        self.env = os.environ.copy()
        if rpc_user:
            self.env["QRX_RPC_USER"] = rpc_user
        if rpc_password:
            self.env["QRX_RPC_PASSWORD"] = rpc_password

    def call(self, *args: str) -> Dict[str, Any]:
        cp = subprocess.run(self.base + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env, timeout=30)
        if cp.returncode != 0:
            raise GatewayError(f"qrx-cli {' '.join(args[:1])} failed: {cp.stderr.strip() or cp.stdout.strip()}")
        try:
            obj = json.loads(cp.stdout)
        except Exception as exc:
            raise GatewayError(f"qrx-cli returned invalid JSON for {args[0]}: {cp.stdout[:500]}") from exc
        if obj.get("ok") is False:
            raise GatewayError(f"qrx-cli {args[0]} error: {obj}")
        return obj.get("result") or {}

    def list_orders(self, status: str) -> Iterable[str]:
        # Query all and filter locally. Passing an empty owner filter through the
        # current whitespace-based qrxd RPC shim would collapse the argument.
        result = self.call("listorders")
        for line in result.get("orders") or []:
            kv = parse_kv_line(str(line))
            oid = kv.get("order_id")
            if oid and kv.get("status", "").lower() == status.lower():
                yield oid

    def get_order(self, oid: str) -> Dict[str, str]:
        return {str(k): str(v) for k, v in self.call("getorder", oid).items()}

    def get_gateway(self, gateway: str) -> Dict[str, str]:
        return {str(k): str(v) for k, v in self.call("getgateway", gateway).items()}

    def block_height(self) -> int:
        result = self.call("getblockcount")
        for key in ("blockcount", "height", "count"):
            if key in result:
                return int(result[key])
        # Some qrxd versions return a bare named value inside result.
        vals = list(result.values())
        if vals:
            return int(vals[0])
        raise GatewayError("could not obtain QRX block height")

    def create_signed_report(self, gateway: str, owner: str, oid: str, status: str, filled_atoms: int, price_atoms: int, fee_atoms: int, venue_order_id: str, seq: int, gw: Dict[str, str], lane: int, expiry: int) -> str:
        result = self.call(
            "createexecutionreporttransaction", gateway, owner, oid, status,
            str(filled_atoms), str(price_atoms), str(fee_atoms), venue_order_id, str(seq),
            gw["ed25519_pub_hex"], gw["mldsa65_pub_b64"], str(lane), str(expiry)
        )
        raw = str(result.get("raw_tx") or "")
        if not raw:
            raise GatewayError("QRX did not return execution report raw transaction")
        with tempfile.TemporaryDirectory(prefix="qrxkraken-") as td:
            rawp = Path(td) / "report.raw"
            signedp = Path(td) / "report.signed"
            rawp.write_text(raw)
            self.call("signrawtransactionwithwallet", str(rawp), str(signedp))
            if not signedp.exists():
                raise GatewayError("QRX wallet did not create signed execution report")
            return signedp.read_text()

    def send_signed(self, signed_tx: str) -> None:
        with tempfile.TemporaryDirectory(prefix="qrxkraken-") as td:
            p = Path(td) / "report.signed"
            p.write_text(signed_tx)
            self.call("sendrawtransaction", str(p))


class Gateway:
    def __init__(self, qrx: QrxCli, kraken: KrakenClient, db: GatewayDB, gateway_address: str, poll: float, lane: int):
        self.qrx = qrx
        self.kraken = kraken
        self.db = db
        self.gateway_address = gateway_address
        self.poll = poll
        self.lane = lane
        self.gw = qrx.get_gateway(gateway_address)
        if self.gw.get("status") != "active" or self.gw.get("venue", "").upper() != "KRAKEN":
            raise GatewayError("selected QRX wallet is not an active KRAKEN gateway")
        self.catalog = PairCatalog(kraken.public_asset_pairs())
        self._validate_api_permissions()

    def _validate_api_permissions(self) -> None:
        info = self.kraken.api_key_info()
        perms_obj = info.get("permissions") if isinstance(info, dict) else None
        perms = set()
        if isinstance(perms_obj, list):
            perms.update(str(x) for x in perms_obj)
        elif isinstance(perms_obj, dict):
            perms.update(str(k) for k, v in perms_obj.items() if v)
        # Kraken's GetApiKeyInfo response may expose permission identifiers as
        # top-level booleans instead of nesting them under `permissions`.
        if isinstance(info, dict):
            known = {
                "query-funds", "withdraw-funds", "query-open-trades",
                "query-closed-trades", "modify-trades", "close-trades",
                "deposit-funds", "export-data", "access-websockets",
            }
            for key in known:
                value = info.get(key)
                if value is True or str(value).lower() in {"1", "true", "yes"}:
                    perms.add(key)
        if "withdraw-funds" in perms:
            raise GatewayError("Refusing Kraken key with Withdraw Funds permission. Create a trade-only API key.")
        if perms and "modify-trades" not in perms:
            raise GatewayError("Kraken API key lacks 'Orders and trades - Create & modify orders'")
        if perms and "query-open-trades" not in perms:
            raise GatewayError("Kraken API key lacks 'Query open orders & trades'")
        if perms and "query-closed-trades" not in perms:
            raise GatewayError("Kraken API key lacks 'Query closed orders & trades'")

    def _qrx_report_seq(self, order: Dict[str, str]) -> int:
        return int(order.get("execution_report_sequence") or 0)

    def _flush_pending(self, oid: str, order: Dict[str, str], state: Dict[str, Any]) -> bool:
        pending = int(state.get("pending_qrx_seq") or 0)
        if not pending:
            return False
        current = self._qrx_report_seq(order)
        if current >= pending:
            self.db.clear_pending_report(oid)
            return False
        signed = state.get("pending_signed_tx")
        if signed:
            # Exact signed transaction replay is safe/idempotent at the QRX mempool.
            self.qrx.send_signed(str(signed))
        return True

    def _emit_report(self, order: Dict[str, str], status: str, filled: int, price: int, fee: int, venue_order_id: str) -> None:
        oid = order["order_id"]
        seq = self._qrx_report_seq(order) + 1
        expiry = self.qrx.block_height() + 100
        signed = self.qrx.create_signed_report(self.gateway_address, order["owner"], oid, status, filled, price, fee, venue_order_id, seq, self.gw, self.lane, expiry)
        state = self.db.get(oid)
        cl = state.get("cl_ord_id") or canonical_client_order_id(oid)
        self.db.upsert(oid, cl, venue_order_id if venue_order_id and not venue_order_id.startswith("KRAKEN-") else None, status)
        self.db.set_pending_report(oid, seq, signed)
        self.qrx.send_signed(signed)
        log(f"QRX report queued order={oid[:16]} status={status} seq={seq}")

    def _format_order(self, order: Dict[str, str], pair: PairInfo) -> Tuple[str, Optional[str]]:
        qty = atoms_to_decimal(order["quantity_atoms"])
        quantum_qty = Decimal(1).scaleb(-pair.lot_decimals)
        qty = qty.quantize(quantum_qty, rounding=ROUND_DOWN)
        if qty <= 0 or (pair.ordermin > 0 and qty < pair.ordermin):
            raise GatewayError(f"quantity {qty} below Kraken minimum {pair.ordermin} for {pair.pair}")
        volume = format(qty, "f")
        if order.get("order_type", "LIMIT").upper() == "MARKET":
            return volume, None
        price = atoms_to_decimal(order["limit_price_atoms"])
        quantum_px = Decimal(1).scaleb(-pair.pair_decimals)
        rounding = ROUND_DOWN if order.get("side", "BUY").upper() == "BUY" else ROUND_UP
        price = price.quantize(quantum_px, rounding=rounding)
        if price <= 0:
            raise GatewayError("limit price became non-positive after Kraken precision normalization")
        return volume, format(price, "f")

    def _reconcile_venue_state(self, order: Dict[str, str], state: Dict[str, Any]) -> None:
        oid = order["order_id"]
        txid = state.get("kraken_txid")
        cl = state.get("cl_ord_id") or canonical_client_order_id(oid)
        venue: Optional[Dict[str, Any]] = None
        if txid:
            venue = self.kraken.query_order(str(txid))
        else:
            found = self.kraken.find_by_client_id(cl)
            if found:
                txid, venue = found
                self.db.upsert(oid, cl, str(txid), "reconciled")
        if not venue:
            return
        kstatus = str(venue.get("status") or "open").lower()
        vol_exec = Decimal(str(venue.get("vol_exec") or "0"))
        vol = Decimal(str(venue.get("vol") or "0"))
        filled_atoms = decimal_to_atoms(vol_exec)
        fee_atoms = decimal_to_atoms(venue.get("fee") or "0")
        avg = Decimal(str(venue.get("price") or "0"))
        if avg <= 0 and vol_exec > 0:
            cost = Decimal(str(venue.get("cost") or "0"))
            if cost > 0:
                avg = cost / vol_exec
        price_atoms = decimal_to_atoms(avg) if avg > 0 else 0
        qstatus = order.get("status", "")
        desired: Optional[str] = None
        if kstatus in {"canceled", "expired"}:
            desired = "CANCELED"
        elif kstatus == "closed":
            desired = "FILLED" if vol > 0 and vol_exec >= vol else "CANCELED"
        elif vol_exec > 0:
            desired = "PARTIALLY_FILLED"
        elif qstatus == "pending_execution":
            desired = "SUBMITTED"
        if desired:
            self._emit_report(order, desired, filled_atoms, price_atoms, fee_atoms, str(txid or cl))

    def handle_order(self, oid: str) -> None:
        order = self.qrx.get_order(oid)
        if order.get("kind") != "external" or order.get("venue", "").upper() != "KRAKEN":
            return
        order["order_id"] = oid
        status = order.get("status", "")
        if status in TERMINAL_QRX:
            return
        cl = canonical_client_order_id(oid)
        state = self.db.get(oid)
        if not state:
            self.db.upsert(oid, cl, None, status)
            state = self.db.get(oid)
        if self._flush_pending(oid, order, state):
            return
        # Refresh after a prior report may have landed.
        state = self.db.get(oid)

        if status == "cancel_pending":
            txid = state.get("kraken_txid")
            if not txid:
                found = self.kraken.find_by_client_id(cl)
                if found:
                    txid, _ = found
                    self.db.upsert(oid, cl, str(txid), "cancel-reconcile")
            if txid:
                try:
                    self.kraken.cancel_order(str(txid), cl)
                    log(f"Kraken cancel requested order={oid[:16]} txid={txid}")
                except KrakenError as exc:
                    # Unknown/already-closed is handled by reconciliation below.
                    log(f"Kraken cancel response order={oid[:16]}: {exc}")
                self._reconcile_venue_state(order, self.db.get(oid))
            else:
                # QRX cancel arrived before the order was ever placed at Kraken.
                self._emit_report(order, "CANCELED", 0, 0, 0, "KRAKEN-NOT-SUBMITTED")
            return

        txid = state.get("kraken_txid")
        if not txid:
            found = self.kraken.find_by_client_id(cl)
            if found:
                txid, _ = found
                self.db.upsert(oid, cl, str(txid), "reconciled-before-add")
            else:
                pair = self.catalog.resolve(order["market"])
                volume, price = self._format_order(order, pair)
                try:
                    tif = order.get("time_in_force", "GTC").upper()
                    if order.get("arbitrage_id") and tif != "IOC":
                        raise GatewayError("arbitrage hedge must use IOC time-in-force")
                    txid = self.kraken.add_order(pair.pair, order["side"], order.get("order_type", "LIMIT"), volume, price, cl, tif)
                except KrakenError as exc:
                    # Only definite order/business errors become an on-chain REJECTED
                    # status. Authentication, nonce, service and throttling failures
                    # are gateway/runtime problems and must be retried instead of
                    # permanently rejecting the user's QRX intent.
                    definite = bool(exc.errors) and all(
                        e.startswith("EOrder:")
                        and "Rate limit" not in e
                        and "Unavailable" not in e
                        for e in exc.errors
                    )
                    if definite:
                        self._emit_report(order, "REJECTED", 0, 0, 0, "KRAKEN-REJECTED")
                        log(f"Kraken rejected QRX order={oid[:16]}: {exc}")
                        return
                    raise
                self.db.upsert(oid, cl, str(txid), "submitted")
                log(f"Kraken order submitted qrx={oid[:16]} txid={txid} cl_ord_id={cl}")
                self._emit_report(order, "SUBMITTED", 0, 0, 0, str(txid))
                return

        self._reconcile_venue_state(order, self.db.get(oid))

    def cycle(self) -> None:
        seen = set()
        for status in ("pending_execution", "submitted", "partially_filled", "cancel_pending"):
            for oid in self.qrx.list_orders(status):
                if oid not in seen:
                    seen.add(oid)
                    try:
                        self.handle_order(oid)
                    except Exception as exc:
                        log(f"order={oid[:16]} error={exc}")

    def run(self, once: bool = False) -> None:
        log(f"QRX Kraken Spot Gateway active gateway={self.gateway_address} poll={self.poll}s")
        while True:
            self.cycle()
            if once:
                return
            time.sleep(self.poll)


def read_secret_payload() -> Dict[str, str]:
    line = sys.stdin.readline()
    if not line:
        raise GatewayError("wallet did not provide Kraken credentials on stdin")
    try:
        obj = json.loads(line)
    except Exception as exc:
        raise GatewayError("invalid secret payload from wallet") from exc
    key = str(obj.get("api_key") or "")
    secret = str(obj.get("api_secret") or "")
    if not key or not secret:
        raise GatewayError("missing Kraken API key/secret")
    return {"api_key": key, "api_secret": secret, "rpc_user": str(obj.get("rpc_user") or ""), "rpc_password": str(obj.get("rpc_password") or "")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qrx-cli", required=True)
    ap.add_argument("--network", required=True)
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--wallet", required=True)
    ap.add_argument("--gateway-address", required=True)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--poll", type=float, default=5.0)
    ap.add_argument("--lane", type=int, default=31)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    secrets = read_secret_payload()
    qrx = QrxCli(args.qrx_cli, args.network, args.datadir, args.wallet, secrets.get("rpc_user", ""), secrets.get("rpc_password", ""))
    kraken = KrakenClient(secrets["api_key"], secrets["api_secret"])
    db = GatewayDB(Path(args.state_dir) / "kraken-gateway.sqlite3")
    gateway = Gateway(qrx, kraken, db, args.gateway_address, max(1.0, args.poll), args.lane)
    gateway.run(args.once)
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
    except Exception as exc:
        print(f"qrx-gateway-kraken: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
