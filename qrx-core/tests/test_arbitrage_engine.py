#!/usr/bin/env python3
import importlib.util
import json
import sys
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MOD=ROOT/'gateways'/'qrx-arbitrage-engine.py'
spec=importlib.util.spec_from_file_location('qrx_arbitrage',MOD)
arb=importlib.util.module_from_spec(spec);sys.modules[spec.name]=arb;spec.loader.exec_module(arb)

NOW=2_000_000_000

def payload(mode='opportunity'):
    return {
      'now':NOW,
      'config':{
        'mode':mode,'qrx_eur_price':'1.50','oracle_timestamp':NOW-10,'oracle_source':'signed-test-oracle',
        'kraken_taker_fee_bps':'40','slippage_buffer_bps':'20','risk_buffer_bps':'10',
        'bitcoin_fee_eur':'1','qrx_fee_eur':'0.25','min_profit_eur':'5','min_margin_bps':'20',
        'max_quantity_btc':'0.01','max_daily_btc':'0.05','max_open_exposure_eur':'500',
        'prefunded_kraken_btc':'0.01'
      },
      'crosschain_order':{
        'order_id':'cross-1','market':'BTC/QUB','side':'SELL','status':'open',
        'quantity_atoms':100000,'remaining_atoms':100000,'limit_price_atoms':4800000000000
      },
      'kraken_book':{'symbol':'BTC/EUR','timestamp':NOW-1,'bids':[['80000','0.0004'],['79900','0.001']]}
    }

class ArbitrageTests(unittest.TestCase):
    def test_profitable_executable_depth_is_accepted(self):
        d=arb.evaluate_payload(payload())
        self.assertEqual(d['decision'],'ACCEPT')
        self.assertEqual(d['state'],'OPPORTUNITY_DETECTED')
        self.assertEqual(d['quantity_btc'],'0.00100000')
        self.assertGreater(Decimal(d['net_profit_eur']),Decimal('5'))

    def test_vwap_uses_depth_not_top_ticker(self):
        d=arb.evaluate_payload(payload())
        self.assertEqual(d['kraken_vwap_eur'],'79940.00000000')
        self.assertEqual(d['kraken_limit_eur'],'79900.00000000')

    def test_insufficient_depth_is_rejected_safely(self):
        p=payload();p['kraken_book']['bids']=[['80000','0.0005']]
        with self.assertRaises(arb.ArbitrageError):arb.evaluate_payload(p)

    def test_stale_oracle_is_rejected(self):
        p=payload();p['config']['oracle_timestamp']=NOW-1000
        with self.assertRaisesRegex(arb.ArbitrageError,'stale'):arb.evaluate_payload(p)

    def test_stale_book_is_rejected(self):
        p=payload();p['kraken_book']['timestamp']=NOW-100
        with self.assertRaisesRegex(arb.ArbitrageError,'stale'):arb.evaluate_payload(p)

    def test_quantity_and_exposure_limits(self):
        p=payload();p['config']['max_quantity_btc']='0.0005'
        self.assertEqual(arb.evaluate_payload(p)['decision'],'REJECT')
        p=payload();p['open_exposure_eur']='450'
        self.assertEqual(arb.evaluate_payload(p)['decision'],'REJECT')

    def test_paper_trade_is_persisted(self):
        p=payload('paper')
        with tempfile.TemporaryDirectory() as td:
            d=arb.evaluate_payload(p,Path(td));self.assertEqual(d['state'],'PAPER_FILLED')
            rows=arb.ArbitrageStore(Path(td)/'arbitrage.sqlite3').list()
            self.assertEqual(len(rows),1);self.assertEqual(rows[0]['state'],'PAPER_FILLED')

    def test_confirm_requires_prefunded_inventory(self):
        p=payload('confirm');p['config']['prefunded_kraken_btc']='0'
        d=arb.evaluate_payload(p);self.assertEqual(d['decision'],'REJECT')

    def test_explicit_approval_creates_ioc_plan(self):
        p=payload('confirm')
        with tempfile.TemporaryDirectory() as td:
            d=arb.evaluate_payload(p,Path(td));store=arb.ArbitrageStore(Path(td)/'arbitrage.sqlite3')
            plan=store.approve(d['arbitrage_id'])
            self.assertEqual(plan['kraken_hedge']['time_in_force'],'IOC')
            self.assertEqual(plan['kraken_hedge']['side'],'SELL')
            self.assertEqual(store.approved_plan(d['arbitrage_id']),plan)
            linked=store.mark_broadcast(d['arbitrage_id'],'qrx-hedge-tx-1')
            self.assertEqual(linked['state'],'HEDGE_BROADCAST')
            self.assertEqual(store.list()[0]['qrx_hedge_order_id'],'qrx-hedge-tx-1')

    def test_unapproved_plan_cannot_be_broadcast(self):
        p=payload('confirm')
        with tempfile.TemporaryDirectory() as td:
            d=arb.evaluate_payload(p,Path(td));store=arb.ArbitrageStore(Path(td)/'arbitrage.sqlite3')
            with self.assertRaisesRegex(arb.ArbitrageError,'APPROVED'):
                store.approved_plan(d['arbitrage_id'])

    def test_pending_live_opportunities_reserve_daily_risk(self):
        with tempfile.TemporaryDirectory() as td:
            d=arb.evaluate_payload(payload('confirm'),Path(td));store=arb.ArbitrageStore(Path(td)/'arbitrage.sqlite3')
            btc,eur=store.risk_totals(int(time.time()))
            self.assertEqual(btc,Decimal('0.00100000'));self.assertEqual(eur,Decimal('72.00000000'))
            btc2,eur2=store.risk_totals(int(time.time()),d['arbitrage_id'])
            self.assertEqual((btc2,eur2),(Decimal(0),Decimal(0)))

    def test_deterministic_id(self):
        a=arb.evaluate_payload(payload())['arbitrage_id'];b=arb.evaluate_payload(payload())['arbitrage_id']
        self.assertEqual(a,b)

if __name__=='__main__':unittest.main()
