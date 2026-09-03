#!/usr/bin/env python3
"""QRX 0.0.7 Phase 4F.2 cross-venue arbitrage decision engine.

The engine compares executable BTC/QUB cross-chain liquidity with Kraken Spot
BTC/EUR depth. It defaults to opportunity-only or paper mode. Confirmed live
execution produces a deterministic two-leg plan; the Kraken leg is deliberately
routed through the existing QRX EXTERNAL_ORDER + Kraken gateway path.

No Kraken secret is read or stored by this process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SATOSHIS = Decimal("100000000")
ATOMS = Decimal("100000000")
BPS = Decimal("10000")
VALID_MODES = {"opportunity", "paper", "confirm"}
LIVE_CROSSCHAIN = {"open", "partially_filled", "matched", "awaiting_btc_funding", "btc_funded"}


class ArbitrageError(RuntimeError):
    pass


def D(value: Any, label: str = "number") -> Decimal:
    try:
        out = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ArbitrageError(f"invalid {label}: {value}") from exc
    if not out.is_finite():
        raise ArbitrageError(f"invalid {label}: {value}")
    return out


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def deterministic_id(order_id: str, symbol: str, book_timestamp: int, quantity_sats: int) -> str:
    body = canonical_json({"order_id": order_id, "symbol": symbol, "book_timestamp": book_timestamp, "quantity_sats": quantity_sats})
    return "arb_" + hashlib.sha256(body.encode()).hexdigest()[:32]


@dataclass(frozen=True)
class ArbitrageConfig:
    mode: str = "opportunity"
    symbol: str = "BTC/EUR"
    qrx_eur_price: Decimal = Decimal("0")
    oracle_timestamp: int = 0
    oracle_source: str = "manual"
    max_oracle_age_seconds: int = 300
    max_book_age_seconds: int = 15
    kraken_taker_fee_bps: Decimal = Decimal("40")
    slippage_buffer_bps: Decimal = Decimal("30")
    risk_buffer_bps: Decimal = Decimal("25")
    bitcoin_fee_eur: Decimal = Decimal("0")
    qrx_fee_eur: Decimal = Decimal("0")
    min_profit_eur: Decimal = Decimal("25")
    min_margin_bps: Decimal = Decimal("75")
    max_quantity_btc: Decimal = Decimal("0.01")
    max_daily_btc: Decimal = Decimal("0.05")
    max_open_exposure_eur: Decimal = Decimal("250")
    prefunded_kraken_btc: Decimal = Decimal("0")
    require_prefunded_live: bool = True

    @classmethod
    def from_dict(cls, obj: Dict[str, Any]) -> "ArbitrageConfig":
        mode = str(obj.get("mode") or "opportunity").lower()
        if mode not in VALID_MODES:
            raise ArbitrageError(f"mode must be one of {sorted(VALID_MODES)}")
        return cls(
            mode=mode,
            symbol=str(obj.get("symbol") or "BTC/EUR").upper().replace("-", "/"),
            qrx_eur_price=D(obj.get("qrx_eur_price", 0), "QUB/EUR oracle price"),
            oracle_timestamp=int(obj.get("oracle_timestamp") or 0),
            oracle_source=str(obj.get("oracle_source") or "manual"),
            max_oracle_age_seconds=int(obj.get("max_oracle_age_seconds") or 300),
            max_book_age_seconds=int(obj.get("max_book_age_seconds") or 15),
            kraken_taker_fee_bps=D(obj.get("kraken_taker_fee_bps", 40), "Kraken fee bps"),
            slippage_buffer_bps=D(obj.get("slippage_buffer_bps", 30), "slippage bps"),
            risk_buffer_bps=D(obj.get("risk_buffer_bps", 25), "risk bps"),
            bitcoin_fee_eur=D(obj.get("bitcoin_fee_eur", 0), "Bitcoin fee"),
            qrx_fee_eur=D(obj.get("qrx_fee_eur", 0), "QRX fee"),
            min_profit_eur=D(obj.get("min_profit_eur", 25), "minimum profit"),
            min_margin_bps=D(obj.get("min_margin_bps", 75), "minimum margin bps"),
            max_quantity_btc=D(obj.get("max_quantity_btc", "0.01"), "maximum BTC quantity"),
            max_daily_btc=D(obj.get("max_daily_btc", "0.05"), "daily BTC limit"),
            max_open_exposure_eur=D(obj.get("max_open_exposure_eur", 250), "open exposure"),
            prefunded_kraken_btc=D(obj.get("prefunded_kraken_btc", 0), "prefunded Kraken BTC"),
            require_prefunded_live=bool(obj.get("require_prefunded_live", True)),
        )

    def validate(self, now: int) -> None:
        if self.symbol not in {"BTC/EUR", "XBT/EUR"}:
            raise ArbitrageError("Phase 4F.2 supports BTC/EUR Kraken hedge only")
        if self.qrx_eur_price <= 0:
            raise ArbitrageError("QUB/EUR reference price must be greater than zero")
        if self.oracle_timestamp <= 0 or now - self.oracle_timestamp > self.max_oracle_age_seconds:
            raise ArbitrageError("QUB/EUR reference price is missing or stale")
        for label, value in (("Kraken fee", self.kraken_taker_fee_bps), ("slippage", self.slippage_buffer_bps), ("risk", self.risk_buffer_bps)):
            if value < 0 or value >= BPS:
                raise ArbitrageError(f"{label} bps outside safe range")
        if self.max_quantity_btc <= 0 or self.max_daily_btc <= 0 or self.max_open_exposure_eur <= 0:
            raise ArbitrageError("risk limits must be greater than zero")


@dataclass(frozen=True)
class CrosschainOrder:
    order_id: str
    market: str
    side: str
    status: str
    quantity_sats: int
    remaining_sats: int
    price_atoms: int
    session_id: str = ""

    @classmethod
    def from_dict(cls, obj: Dict[str, Any]) -> "CrosschainOrder":
        quantity = int(obj.get("quantity_sats") or obj.get("quantity_atoms") or 0)
        remaining = int(obj.get("remaining_sats") or obj.get("remaining_atoms") or quantity)
        return cls(
            order_id=str(obj.get("order_id") or obj.get("id") or ""),
            market=str(obj.get("market") or "").upper(),
            side=str(obj.get("side") or "").upper(),
            status=str(obj.get("status") or "").lower(),
            quantity_sats=quantity,
            remaining_sats=remaining,
            price_atoms=int(obj.get("price_atoms") or obj.get("limit_price_atoms") or 0),
            session_id=str(obj.get("crosschain_session_id") or obj.get("session_id") or ""),
        )

    def validate(self) -> None:
        if not self.order_id:
            raise ArbitrageError("cross-chain order id is required")
        if self.market != "BTC/QUB" or self.side != "SELL":
            raise ArbitrageError("candidate must be a BTC/QUB cross-chain SELL order")
        if self.status not in LIVE_CROSSCHAIN:
            raise ArbitrageError(f"cross-chain order is not live: {self.status}")
        if self.remaining_sats <= 0 or self.price_atoms <= 0:
            raise ArbitrageError("cross-chain order has no executable quantity or price")


@dataclass(frozen=True)
class KrakenBook:
    symbol: str
    bids: Tuple[Tuple[Decimal, Decimal], ...]
    timestamp: int

    @classmethod
    def from_dict(cls, obj: Dict[str, Any]) -> "KrakenBook":
        bids: List[Tuple[Decimal, Decimal]] = []
        for level in obj.get("bids") or []:
            if isinstance(level, dict):
                price, qty = level.get("price"), level.get("qty")
            else:
                price, qty = level[0], level[1]
            p, q = D(price, "book price"), D(qty, "book quantity")
            if p > 0 and q > 0:
                bids.append((p, q))
        bids.sort(key=lambda x: x[0], reverse=True)
        return cls(str(obj.get("symbol") or "BTC/EUR").upper().replace("-", "/"), tuple(bids), int(obj.get("timestamp") or 0))

    def executable_sale(self, quantity_btc: Decimal) -> Tuple[Decimal, Decimal, Decimal]:
        remaining, proceeds, filled = quantity_btc, Decimal(0), Decimal(0)
        worst = Decimal(0)
        for price, available in self.bids:
            take = min(remaining, available)
            if take <= 0:
                continue
            proceeds += take * price
            filled += take
            remaining -= take
            worst = price
            if remaining <= 0:
                break
        if remaining > 0 or filled <= 0:
            raise ArbitrageError("Kraken order book has insufficient executable BTC/EUR bid depth")
        return proceeds, proceeds / filled, worst


@dataclass(frozen=True)
class Decision:
    arbitrage_id: str
    decision: str
    state: str
    reason: str
    mode: str
    qrx_order_id: str
    crosschain_session_id: str
    symbol: str
    quantity_sats: int
    quantity_btc: str
    crosschain_price_qub_per_btc: str
    acquisition_qub: str
    acquisition_eur: str
    kraken_gross_eur: str
    kraken_vwap_eur: str
    kraken_limit_eur: str
    kraken_fee_eur: str
    slippage_buffer_eur: str
    risk_buffer_eur: str
    network_fees_eur: str
    net_profit_eur: str
    net_margin_bps: str
    oracle_source: str
    oracle_timestamp: int
    book_timestamp: int
    requires_confirmation: bool
    live_ready: bool


def money(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.00000001"), rounding=ROUND_DOWN), "f")


class ArbitrageEngine:
    def __init__(self, config: ArbitrageConfig):
        self.config = config

    def evaluate(self, order: CrosschainOrder, book: KrakenBook, now: Optional[int] = None, daily_btc: Decimal = Decimal(0), open_exposure_eur: Decimal = Decimal(0)) -> Decision:
        now = int(now or time.time())
        self.config.validate(now)
        order.validate()
        if book.symbol not in {"BTC/EUR", "XBT/EUR"}:
            raise ArbitrageError("Kraken book must be BTC/EUR")
        if book.timestamp <= 0 or now - book.timestamp > self.config.max_book_age_seconds:
            raise ArbitrageError("Kraken order book is missing or stale")
        qty_btc = Decimal(order.remaining_sats) / SATOSHIS
        arb_id = deterministic_id(order.order_id, book.symbol, book.timestamp, order.remaining_sats)
        reject = ""
        if qty_btc > self.config.max_quantity_btc:
            reject = "quantity exceeds per-opportunity BTC limit"
        elif daily_btc + qty_btc > self.config.max_daily_btc:
            reject = "daily BTC limit would be exceeded"
        price_qub = Decimal(order.price_atoms) / ATOMS
        acquisition_qub = qty_btc * price_qub
        acquisition_eur = acquisition_qub * self.config.qrx_eur_price
        if not reject and open_exposure_eur + acquisition_eur > self.config.max_open_exposure_eur:
            reject = "open EUR exposure limit would be exceeded"
        gross, vwap, worst = book.executable_sale(qty_btc)
        kraken_fee = gross * self.config.kraken_taker_fee_bps / BPS
        slippage = gross * self.config.slippage_buffer_bps / BPS
        risk = acquisition_eur * self.config.risk_buffer_bps / BPS
        network = self.config.bitcoin_fee_eur + self.config.qrx_fee_eur
        profit = gross - acquisition_eur - kraken_fee - slippage - risk - network
        margin_bps = profit / acquisition_eur * BPS if acquisition_eur > 0 else Decimal("-999999")
        if not reject and profit < self.config.min_profit_eur:
            reject = "net profit below configured minimum"
        if not reject and margin_bps < self.config.min_margin_bps:
            reject = "net margin below configured minimum"
        prefunded = self.config.prefunded_kraken_btc >= qty_btc
        live_ready = not reject and (prefunded or not self.config.require_prefunded_live)
        if not reject and self.config.mode == "confirm" and not live_ready:
            reject = "confirmed live mode requires sufficient prefunded Kraken BTC"
        accepted = not reject
        state = "REJECTED"
        if accepted:
            state = {"opportunity": "OPPORTUNITY_DETECTED", "paper": "PAPER_FILLED", "confirm": "AWAITING_CONFIRMATION"}[self.config.mode]
        return Decision(
            arbitrage_id=arb_id, decision="ACCEPT" if accepted else "REJECT", state=state, reason="all thresholds satisfied" if accepted else reject,
            mode=self.config.mode, qrx_order_id=order.order_id, crosschain_session_id=order.session_id, symbol="BTC/EUR",
            quantity_sats=order.remaining_sats, quantity_btc=money(qty_btc), crosschain_price_qub_per_btc=money(price_qub),
            acquisition_qub=money(acquisition_qub), acquisition_eur=money(acquisition_eur), kraken_gross_eur=money(gross),
            kraken_vwap_eur=money(vwap), kraken_limit_eur=money(worst), kraken_fee_eur=money(kraken_fee),
            slippage_buffer_eur=money(slippage), risk_buffer_eur=money(risk), network_fees_eur=money(network),
            net_profit_eur=money(profit), net_margin_bps=money(margin_bps), oracle_source=self.config.oracle_source,
            oracle_timestamp=self.config.oracle_timestamp, book_timestamp=book.timestamp,
            requires_confirmation=accepted and self.config.mode == "confirm", live_ready=live_ready,
        )


class ArbitrageStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS opportunities(
            arbitrage_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
            state TEXT NOT NULL, decision_json TEXT NOT NULL, approved_at INTEGER, qrx_hedge_order_id TEXT
          );
          CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, arbitrage_id TEXT NOT NULL, timestamp INTEGER NOT NULL,
            from_state TEXT, to_state TEXT NOT NULL, detail TEXT NOT NULL
          );
        """)
        self.db.commit()

    def record(self, decision: Decision) -> None:
        now = int(time.time())
        old = self.db.execute("SELECT state FROM opportunities WHERE arbitrage_id=?", (decision.arbitrage_id,)).fetchone()
        old_state = old[0] if old else None
        body = canonical_json(asdict(decision))
        self.db.execute("""INSERT INTO opportunities(arbitrage_id,created_at,updated_at,state,decision_json)
          VALUES(?,?,?,?,?) ON CONFLICT(arbitrage_id) DO UPDATE SET updated_at=excluded.updated_at,state=excluded.state,decision_json=excluded.decision_json""",
          (decision.arbitrage_id, now, now, decision.state, body))
        if old_state != decision.state:
            self.db.execute("INSERT INTO events(arbitrage_id,timestamp,from_state,to_state,detail) VALUES(?,?,?,?,?)", (decision.arbitrage_id, now, old_state, decision.state, decision.reason))
        self.db.commit()

    def risk_totals(self, now: int, exclude_arbitrage_id: str = "") -> Tuple[Decimal, Decimal]:
        daily_btc, open_eur = Decimal(0), Decimal(0)
        cutoff = int(now) - 86400
        for row in self.db.execute("SELECT arbitrage_id,state,decision_json FROM opportunities WHERE created_at>=? AND state IN ('AWAITING_CONFIRMATION','APPROVED','HEDGE_BROADCAST')", (cutoff,)):
            if row["arbitrage_id"] == exclude_arbitrage_id:
                continue
            decision = json.loads(row["decision_json"])
            daily_btc += D(decision.get("quantity_btc", 0))
            open_eur += D(decision.get("acquisition_eur", 0))
        return daily_btc, open_eur

    def approve(self, arb_id: str) -> Dict[str, Any]:
        row = self.db.execute("SELECT state,decision_json FROM opportunities WHERE arbitrage_id=?", (arb_id,)).fetchone()
        if not row:
            raise ArbitrageError("arbitrage opportunity not found")
        if row["state"] != "AWAITING_CONFIRMATION":
            raise ArbitrageError(f"opportunity cannot be approved from state {row['state']}")
        decision = json.loads(row["decision_json"])
        if not decision.get("live_ready"):
            raise ArbitrageError("opportunity is not live-ready")
        self._validate_live_freshness(decision)
        now = int(time.time())
        self.db.execute("UPDATE opportunities SET state='APPROVED',updated_at=?,approved_at=? WHERE arbitrage_id=?", (now, now, arb_id))
        self.db.execute("INSERT INTO events(arbitrage_id,timestamp,from_state,to_state,detail) VALUES(?,?,?,?,?)", (arb_id, now, "AWAITING_CONFIRMATION", "APPROVED", "explicit wallet confirmation"))
        self.db.commit()
        return self.execution_plan(decision)

    @staticmethod
    def _validate_live_freshness(decision: Dict[str, Any]) -> None:
        now = int(time.time())
        if now - int(decision.get("book_timestamp") or 0) > 60:
            raise ArbitrageError("approved Kraken depth is stale; evaluate and confirm again")
        if now - int(decision.get("oracle_timestamp") or 0) > 300:
            raise ArbitrageError("approved QUB/EUR reference is stale; evaluate and confirm again")

    def approved_plan(self, arb_id: str) -> Dict[str, Any]:
        row = self.db.execute("SELECT state,decision_json FROM opportunities WHERE arbitrage_id=?", (arb_id,)).fetchone()
        if not row:
            raise ArbitrageError("arbitrage opportunity not found")
        if row["state"] != "APPROVED":
            raise ArbitrageError(f"live hedge requires APPROVED state, found {row['state']}")
        decision = json.loads(row["decision_json"])
        self._validate_live_freshness(decision)
        return self.execution_plan(decision)

    def mark_broadcast(self, arb_id: str, qrx_hedge_order_id: str) -> Dict[str, Any]:
        hedge_id = str(qrx_hedge_order_id).strip()
        if not hedge_id or len(hedge_id) > 256:
            raise ArbitrageError("valid QRX hedge order/transaction id is required")
        row = self.db.execute("SELECT state FROM opportunities WHERE arbitrage_id=?", (arb_id,)).fetchone()
        if not row:
            raise ArbitrageError("arbitrage opportunity not found")
        if row["state"] not in {"APPROVED", "HEDGE_BROADCAST"}:
            raise ArbitrageError(f"cannot link hedge from state {row['state']}")
        old = row["state"]
        now = int(time.time())
        self.db.execute("UPDATE opportunities SET state='HEDGE_BROADCAST',updated_at=?,qrx_hedge_order_id=? WHERE arbitrage_id=?", (now, hedge_id, arb_id))
        if old != "HEDGE_BROADCAST":
            self.db.execute("INSERT INTO events(arbitrage_id,timestamp,from_state,to_state,detail) VALUES(?,?,?,?,?)", (arb_id, now, old, "HEDGE_BROADCAST", hedge_id))
        self.db.commit()
        return {"arbitrage_id": arb_id, "state": "HEDGE_BROADCAST", "qrx_hedge_order_id": hedge_id}

    @staticmethod
    def execution_plan(decision: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "arbitrage_id": decision["arbitrage_id"],
            "crosschain_leg": {"candidate_sell_order_id": decision["qrx_order_id"], "source_buy_order_id": "", "session_id": decision.get("crosschain_session_id", ""), "required_state": "owner's matched BTC/QUB BUY; Kraken hedge inventory must already be prefunded"},
            "kraken_hedge": {"venue": "KRAKEN", "market": "BTC/EUR", "side": "SELL", "order_type": "LIMIT", "time_in_force": "IOC", "quantity_atoms": decision["quantity_sats"], "limit_price_atoms": int(D(decision["kraken_limit_eur"]) * ATOMS), "client_reference": decision["arbitrage_id"]},
            "routing": "Create QRX EXTERNAL_ORDER with ARBITRAGE_CROSS_VENUE-authorized agent; existing secure Kraken gateway executes it",
        }

    def list(self) -> List[Dict[str, Any]]:
        out = []
        for row in self.db.execute("SELECT arbitrage_id,created_at,updated_at,state,decision_json,approved_at,qrx_hedge_order_id FROM opportunities ORDER BY created_at DESC"):
            item = json.loads(row["decision_json"]); item.update({"state": row["state"], "approved_at": row["approved_at"], "qrx_hedge_order_id": row["qrx_hedge_order_id"]}); out.append(item)
        return out


def evaluate_payload(payload: Dict[str, Any], state_dir: Optional[Path] = None) -> Dict[str, Any]:
    cfg = ArbitrageConfig.from_dict(payload.get("config") or {})
    order = CrosschainOrder.from_dict(payload.get("crosschain_order") or {})
    book = KrakenBook.from_dict(payload.get("kraken_book") or {})
    now = int(payload.get("now") or time.time())
    daily_btc, open_exposure = D(payload.get("daily_btc", 0)), D(payload.get("open_exposure_eur", 0))
    store = ArbitrageStore(state_dir / "arbitrage.sqlite3") if state_dir else None
    if store:
        current_id = deterministic_id(order.order_id, book.symbol, book.timestamp, order.remaining_sats)
        stored_daily, stored_open = store.risk_totals(now, current_id)
        daily_btc += stored_daily; open_exposure += stored_open
    decision = ArbitrageEngine(cfg).evaluate(order, book, now, daily_btc, open_exposure)
    if state_dir:
        store.record(decision)
    return asdict(decision)


def fetch_kraken_book(symbol: str = "BTC/EUR", count: int = 100) -> Dict[str, Any]:
    pair = "XBTEUR" if symbol.upper().replace("-", "/") in {"BTC/EUR", "XBT/EUR"} else ""
    if not pair:
        raise ArbitrageError("Phase 4F.2 public book fetch supports BTC/EUR only")
    query = urllib.parse.urlencode({"pair": pair, "count": max(10, min(500, int(count)))})
    req = urllib.request.Request("https://api.kraken.com/0/public/Depth?" + query, headers={"User-Agent": "QRX-Arbitrage/0.0.7"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response: obj = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ArbitrageError(f"Kraken public order book unavailable: {exc}") from exc
    if obj.get("error"):
        raise ArbitrageError("Kraken public order book rejected request: " + ", ".join(obj["error"]))
    result = obj.get("result") or {}
    data = next(iter(result.values()), {})
    bids = [[str(x[0]), str(x[1])] for x in data.get("bids") or [] if len(x) >= 2]
    if not bids:
        raise ArbitrageError("Kraken returned no BTC/EUR bids")
    return {"symbol": "BTC/EUR", "timestamp": int(time.time()), "bids": bids, "source": "Kraken REST Depth", "levels": len(bids)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evaluate-json", action="store_true")
    ap.add_argument("--paper-json", action="store_true")
    ap.add_argument("--state-dir")
    ap.add_argument("--approve")
    ap.add_argument("--approved-plan")
    ap.add_argument("--mark-broadcast")
    ap.add_argument("--qrx-hedge-order-id")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--fetch-book", action="store_true")
    args = ap.parse_args()
    state = Path(args.state_dir) if args.state_dir else None
    if args.approve:
        if not state: raise ArbitrageError("--state-dir is required")
        print(canonical_json(ArbitrageStore(state / "arbitrage.sqlite3").approve(args.approve))); return 0
    if args.approved_plan:
        if not state: raise ArbitrageError("--state-dir is required")
        print(canonical_json(ArbitrageStore(state / "arbitrage.sqlite3").approved_plan(args.approved_plan))); return 0
    if args.mark_broadcast:
        if not state or not args.qrx_hedge_order_id: raise ArbitrageError("--state-dir and --qrx-hedge-order-id are required")
        print(canonical_json(ArbitrageStore(state / "arbitrage.sqlite3").mark_broadcast(args.mark_broadcast, args.qrx_hedge_order_id))); return 0
    if args.list:
        if not state: raise ArbitrageError("--state-dir is required")
        print(canonical_json({"opportunities": ArbitrageStore(state / "arbitrage.sqlite3").list()})); return 0
    if args.fetch_book:
        print(canonical_json(fetch_kraken_book())); return 0
    if args.evaluate_json or args.paper_json:
        payload = json.load(sys.stdin)
        if args.paper_json:
            payload.setdefault("config", {})["mode"] = "paper"
        print(canonical_json(evaluate_payload(payload, state))); return 0
    ap.error("choose --evaluate-json, --paper-json, --approve, --approved-plan, --mark-broadcast, --list or --fetch-book")
    return 2


if __name__ == "__main__":
    try: raise SystemExit(main())
    except ArbitrageError as exc:
        print(f"qrx-arbitrage-engine: {exc}", file=sys.stderr); raise SystemExit(1)
