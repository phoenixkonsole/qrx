#!/usr/bin/env python3
import importlib.util
import tempfile
import sys
import unittest
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD = ROOT / 'gateways' / 'qrx-gateway-kraken.py'
spec = importlib.util.spec_from_file_location('qrx_kraken', MOD)
kg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = kg
spec.loader.exec_module(kg)

class KrakenGatewayTests(unittest.TestCase):
    def test_signature_matches_kraken_documented_vector(self):
        secret='kQH5HW/8p1uGOVjbgWA7FunAmGO8lsSUXNsu3eow76sz84Q18fWxnyRzBHCd3pd5nE9qa99HAZtuZuj6F1huXg=='
        data={'nonce':'1616492376594','ordertype':'limit','pair':'XBTUSD','price':37500,'type':'buy','volume':1.25}
        got=kg.KrakenClient.signature('/0/private/AddOrder', data, secret)
        self.assertEqual(got,'4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ==')

    def test_client_order_id_is_short_uuid_shape_and_deterministic(self):
        oid='a'*128
        a=kg.canonical_client_order_id(oid)
        b=kg.canonical_client_order_id(oid)
        self.assertEqual(a,b)
        self.assertEqual(len(a),32)
        int(a,16)

    def test_market_aliases(self):
        self.assertEqual(kg.normalize_market('BTC/EUR'),'XBT/EUR')
        self.assertEqual(kg.normalize_market('DOGE/USD'),'XDG/USD')

    def test_pair_catalog_uses_assetpairs_precision(self):
        c=kg.PairCatalog({'XXBTZEUR':{'altname':'XBTEUR','wsname':'XBT/EUR','pair_decimals':1,'lot_decimals':8,'ordermin':'0.0001'}})
        p=c.resolve('BTC/EUR')
        self.assertEqual(p.pair,'XBTEUR')
        self.assertEqual(p.pair_decimals,1)
        self.assertEqual(p.ordermin,Decimal('0.0001'))

    def test_gateway_db_persists_pending_signed_report(self):
        with tempfile.TemporaryDirectory() as td:
            db=kg.GatewayDB(Path(td)/'state.sqlite3')
            db.upsert('o1','c1','k1','submitted')
            db.set_pending_report('o1',2,'signed-body')
            x=db.get('o1')
            self.assertEqual(x['kraken_txid'],'k1')
            self.assertEqual(x['pending_qrx_seq'],2)
            self.assertEqual(x['pending_signed_tx'],'signed-body')
            db.clear_pending_report('o1')
            self.assertEqual(db.get('o1')['pending_qrx_seq'],0)

    def test_gateway_keeps_immutable_status_event_history(self):
        with tempfile.TemporaryDirectory() as td:
            db=kg.GatewayDB(Path(td)/'state.sqlite3')
            db.upsert('o1','c1','k1','submitted');db.upsert('o1','c1','k1','submitted');db.upsert('o1','c1','k1','filled')
            rows=db.db.execute('SELECT last_seen_status FROM execution_events WHERE qrx_order_id=? ORDER BY event_id',('o1',)).fetchall()
            self.assertEqual([r[0] for r in rows],['submitted','filled'])

    def test_atom_conversion(self):
        self.assertEqual(kg.atoms_to_decimal(123456789),Decimal('1.23456789'))
        self.assertEqual(kg.decimal_to_atoms('1.23456789'),123456789)

    def test_top_level_permission_shape_is_accepted(self):
        class K:
            def api_key_info(self):
                return {'modify-trades': True, 'query-open-trades': True, 'query-closed-trades': True, 'withdraw-funds': False}
        class G: kraken = K()
        kg.Gateway._validate_api_permissions(G())

    def test_withdraw_permission_is_refused(self):
        class K:
            def api_key_info(self):
                return {'modify-trades': True, 'query-open-trades': True, 'query-closed-trades': True, 'withdraw-funds': True}
        class G: kraken = K()
        with self.assertRaises(kg.GatewayError):
            kg.Gateway._validate_api_permissions(G())

    def test_arbitrage_gateway_forces_supported_tif(self):
        class K(kg.KrakenClient):
            def __init__(self): pass
            def _request(self,path,data=None,private=True):
                self.sent=data
                return {'txid':['K1']}
        k=K()
        self.assertEqual(k.add_order('XBTEUR','SELL','LIMIT','0.001','80000','a'*32,'IOC'),'K1')
        self.assertEqual(k.sent['timeinforce'],'IOC')
        self.assertTrue(k.sent['deadline'].endswith('Z'))

    def test_regular_gtc_order_does_not_get_short_deadline(self):
        class K(kg.KrakenClient):
            def __init__(self): pass
            def _request(self,path,data=None,private=True):
                self.sent=data
                return {'txid':['K2']}
        k=K();k.add_order('XBTEUR','BUY','LIMIT','0.001','70000','b'*32)
        self.assertEqual(k.sent['timeinforce'],'GTC');self.assertNotIn('deadline',k.sent)
        with self.assertRaises(kg.GatewayError):
            k.add_order('XBTEUR','SELL','LIMIT','0.001','80000','a'*32,'DAY')

if __name__=='__main__': unittest.main()
