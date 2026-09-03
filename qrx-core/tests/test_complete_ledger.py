#!/usr/bin/env python3
import csv,importlib.util,json,sqlite3,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];MOD=ROOT/'tools'/'qrx-complete-ledger-export.py'
spec=importlib.util.spec_from_file_location('qrx_ledger',MOD);ledger=importlib.util.module_from_spec(spec);sys.modules[spec.name]=ledger;spec.loader.exec_module(ledger)

def sample():
 return {
  'transactions':[{'timestamp_utc':'2026-09-01T10:00:00Z','txid':'t1','wallet':'w','asset':'QUB','amount_atoms':'100','amount':'1.25','status':'confirmed'}],
  'orders':[{'order_id':'o1','owner':'w','agent':'a','kind':'external','venue':'KRAKEN','market':'BTC/EUR','side':'SELL','quantity_atoms':'100000','limit_price_atoms':'8000000000000','status':'filled','arbitrage_id':'arb1'}],
  'trades':[{'trade_id':'tr1','market':'TOK/QUB','quantity_atoms':'10','price_atoms':'20','quote_atoms':'2'}],
  'crosschain_swaps':[{'session_id':'s1','status':'redeemed','btc_sats':'100000','qub_atoms':'4800000000','price_atoms':'4800000000000'}],
  'kraken_executions':[{'qrx_order_id':'o1','cl_ord_id':'c1','kraken_txid':'k1','last_seen_status':'filled','pending_qrx_seq':0,'updated_at_utc':'2026-09-01T10:01:00Z'}],
  'arbitrage_report':[{'arbitrage_id':'arb1','state':'COMPLETED','decision':'ACCEPT','qrx_order_id':'o1','symbol':'BTC/EUR','quantity_sats':'100000','quantity_btc':'0.001','kraken_gross_eur':'80.00','kraken_fee_eur':'0.32','net_profit_eur':'7.50','updated_at_utc':'2026-09-01T10:01:00Z'}]
 }

class LedgerTests(unittest.TestCase):
 def test_all_seven_csvs_and_manifest(self):
  with tempfile.TemporaryDirectory() as td:
   m=ledger.export_bundle(Path(td),'international',sample())
   self.assertEqual(len(m['files']),7)
   self.assertTrue(m['complete'])
   self.assertEqual(m['format'],'QRX_COMPLETE_LEDGER_V3')
   for name in ledger.SCHEMAS:self.assertTrue((Path(td)/(name+'.csv')).exists())
   self.assertTrue((Path(td)/'manifest.json').exists())
 def test_german_profile_semicolon_decimal_comma_and_bom(self):
  with tempfile.TemporaryDirectory() as td:
   ledger.export_bundle(Path(td),'de',sample());raw=(Path(td)/'transactions.csv').read_bytes()
   self.assertTrue(raw.startswith(b'\xef\xbb\xbf'));text=raw.decode('utf-8-sig')
   self.assertIn(';',text);self.assertIn('1,25',text)
 def test_international_profile_is_rfc_csv(self):
  with tempfile.TemporaryDirectory() as td:
   ledger.export_bundle(Path(td),'international',sample())
   with (Path(td)/'complete_ledger.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
   self.assertEqual(len(rows),6);self.assertIn('arbitrage',{r['record_type'] for r in rows})
 def test_manifest_hashes_match(self):
  import hashlib
  with tempfile.TemporaryDirectory() as td:
   m=ledger.export_bundle(Path(td),'international',sample())
   for x in m['files']:self.assertEqual(x['sha256'],hashlib.sha256((Path(td)/x['name']).read_bytes()).hexdigest())
 def test_csv_formula_injection_is_data_not_formula(self):
  d=sample();d['transactions'][0]['memo']='=CMD()'
  with tempfile.TemporaryDirectory() as td:
   ledger.export_bundle(Path(td),'international',d)
   with (Path(td)/'transactions.csv').open(encoding='utf-8-sig',newline='') as f:row=next(csv.DictReader(f))
   self.assertEqual(row['memo'],"'=CMD()")
 def test_negative_numeric_profit_remains_numeric(self):
  row=ledger.normalize_row({'net_profit_eur':'-1.25','amount_atoms':'-125000000'},['net_profit_eur','amount_atoms'],False)
  self.assertEqual(row['net_profit_eur'],'-1.25');self.assertEqual(row['amount_atoms'],'-125000000')
 def test_source_warning_fails_closed_without_manifest(self):
  with tempfile.TemporaryDirectory() as td:
   with self.assertRaises(ledger.ExportError):ledger.export_bundle(Path(td),'international',sample(),['history unavailable'])
 def test_paper_profit_is_not_reported_as_realized(self):
  data=sample();data['arbitrage_report'][0]['state']='PAPER_FILLED'
  rows=ledger.complete_rows(data);paper=next(r for r in rows if r['record_type']=='arbitrage')
  self.assertEqual(paper['realized_profit'],'')
 def test_core_snapshot_is_unbounded_verified_and_wallet_filtered(self):
  class FakeCore:
   chain_dir='/chain';wallet_dir='/wallet'
   def snapshot(self):return {'generation':'7','state_root':'abc'}
   def lines(self,*args):
    if args[0]=='listaddresses':return ['mine']
    if args[0]=='history':return ['txid=t1 from=other to=mine amount_atoms=10']
    if args[0]=='list-orders':return ['order_id=o1','order_id=o2']
    if args[0]=='list-trades':
     if args[-1]!='all':raise AssertionError('trade history was capped')
     return ['trade_id=tr1 buyer=mine','trade_id=tr2 buyer=other']
    if args[0]=='list-crosschain':return ['session_id=s1','session_id=s2']
    return []
   def key_values(self,*args):
    values={('order-status','o1'):{'owner':'mine'},('order-status','o2'):{'owner':'other'},('trade-status','tr1'):{'buyer':'mine'},('trade-status','tr2'):{'buyer':'other'},('crosschain-status','s1'):{'buyer_owner':'mine'},('crosschain-status','s2'):{'buyer_owner':'other'}}
    return values[(args[0],args[2])]
  data,meta=ledger.collect_core_snapshot(FakeCore(),'wallet')
  self.assertEqual([r['order_id'] for r in data['orders']],['o1']);self.assertEqual([r['trade_id'] for r in data['trades']],['tr1']);self.assertEqual([r['session_id'] for r in data['crosschain_swaps']],['s1']);self.assertEqual(meta['state_root'],'abc')
 def test_year_and_quarter_periods_are_half_open_utc(self):
  annual=ledger.parse_period(year=2026);quarter=ledger.parse_period(year=2026,quarter=4)
  self.assertEqual(annual['from_utc'],'2026-01-01T00:00:00Z');self.assertEqual(annual['to_utc_exclusive'],'2027-01-01T00:00:00Z')
  self.assertEqual(quarter['from_utc'],'2026-10-01T00:00:00Z');self.assertEqual(quarter['to_utc_exclusive'],'2027-01-01T00:00:00Z')
 def test_inclusive_to_date_and_exact_timestamp_filter(self):
  period=ledger.parse_period('2026-04-01','2026-06-30');data={k:[] for k in ledger.SCHEMAS if k!='complete_ledger'}
  data['transactions']=[{'txid':'before','timestamp':'1775001599'},{'txid':'first','timestamp':'1775001600'},{'txid':'last','timestamp':'1782863999'},{'txid':'after','timestamp':'1782864000'}]
  filtered=ledger.filter_period(data,period,{})
  self.assertEqual([r['txid'] for r in filtered['transactions']],['first','last'])
 def test_period_filter_uses_block_timestamp_and_fails_if_unknown(self):
  period=ledger.parse_period(year=2026,quarter=2);data={k:[] for k in ledger.SCHEMAS if k!='complete_ledger'};data['trades']=[{'trade_id':'t','height':'7'}]
  filtered=ledger.filter_period(data,period,{7:1775001600});self.assertEqual(filtered['trades'][0]['timestamp_utc'],'2026-04-01T00:00:00Z')
  with self.assertRaises(ledger.ExportError):ledger.filter_period(data,period,{})
 def test_kraken_period_reads_immutable_event_journal(self):
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'k.sqlite3';db=sqlite3.connect(path);db.execute('CREATE TABLE execution_events(event_id INTEGER PRIMARY KEY,qrx_order_id TEXT,cl_ord_id TEXT,kraken_txid TEXT,last_seen_status TEXT,observed_at INTEGER)');db.executemany('INSERT INTO execution_events VALUES(?,?,?,?,?,?)',[(1,'o1','c1','k1','submitted',1775001600),(2,'o1','c1','k1','filled',1782864000)]);db.commit();db.close()
   rows=ledger.collect_kraken(path,ledger.parse_period('2026-04-01','2026-06-30'))
   self.assertEqual([r['last_seen_status'] for r in rows],['submitted'])

if __name__=='__main__':unittest.main()
