#!/usr/bin/env python3
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

class WalletFeatureParityTests(unittest.TestCase):
 def test_tauri_exposes_safe_full_cli_bridge(self):
  rust=(ROOT/'GUIWALLET'/'src-tauri'/'src'/'main.rs').read_text()
  html=(ROOT/'GUIWALLET'/'src'/'index.html').read_text()
  self.assertIn('fn wallet_cli_execute',rust);self.assertIn('wallet_cli_execute,',rust);self.assertIn('Complete Command Center',html);self.assertIn('runWalletCliCommand',html)
 def test_complete_export_uses_local_core_snapshot(self):
  rust=(ROOT/'GUIWALLET'/'src-tauri'/'src'/'main.rs').read_text()
  self.assertIn('"--qrx".into()',rust);self.assertIn('"--chain-dir".into()',rust);self.assertIn('"--wallet-dir".into()',rust)
 def test_no_one_million_trade_cap_remains(self):
  core=(ROOT/'qrx-core'/'src'/'qrx.c').read_text();exporter=(ROOT/'qrx-core'/'tools'/'qrx-complete-ledger-export.py').read_text()
  self.assertNotIn('if(limit>1000000)',core);self.assertNotIn('"1000000000"',exporter);self.assertIn('!strcmp(argv[4],"all")',core);self.assertIn('!strcmp(argv[4], "all")',core)
 def test_tauri_and_cli_share_rust_bdk_service(self):
  rust=(ROOT/'GUIWALLET'/'src-tauri'/'src'/'main.rs').read_text();service=(ROOT/'GUIWALLET'/'src-tauri'/'src'/'btc_wallet_service.rs').read_text();binary=(ROOT/'GUIWALLET'/'src-tauri'/'src'/'bin'/'qrx-btc-wallet-service.rs').read_text();cli=(ROOT/'qrx-core'/'tools'/'qrx-wallet-cli.py').read_text();config=(ROOT/'GUIWALLET'/'src-tauri'/'tauri.conf.json').read_text()
  self.assertIn('shared_btc_service',rust);self.assertIn('Service::new(data_dir)?.execute(request)',binary);self.assertIn('Argon2id',service);self.assertIn('qrx-btc-wallet-service',cli);self.assertIn('bin/qrx-btc-wallet-service',config)
  self.assertIn('descriptor: String::new()',service);self.assertIn('wallet.descriptor.clear()',service)
 def test_period_controls_exist_in_both_wallets(self):
  rust=(ROOT/'GUIWALLET'/'src-tauri'/'src'/'main.rs').read_text();html=(ROOT/'GUIWALLET'/'src'/'index.html').read_text();cli=(ROOT/'qrx-core'/'tools'/'qrx-wallet-cli.py').read_text();exporter=(ROOT/'qrx-core'/'tools'/'qrx-complete-ledger-export.py').read_text()
  for token in ('from_date','to_date','quarter'):self.assertIn(token,rust);self.assertIn(token,exporter)
  for token in ('ledgerPeriod','ledgerYear','ledgerQuarter','ledgerFrom','ledgerTo'):self.assertIn(token,html)
  for token in ('--from','--to','--year','--quarter'):self.assertIn(token,cli)

if __name__=='__main__':unittest.main()
