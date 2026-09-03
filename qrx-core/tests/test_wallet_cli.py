#!/usr/bin/env python3
import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];MOD=ROOT/'tools'/'qrx-wallet-cli.py'
spec=importlib.util.spec_from_file_location('qrx_wallet_cli',MOD);wallet_cli=importlib.util.module_from_spec(spec);sys.modules[spec.name]=wallet_cli;spec.loader.exec_module(wallet_cli)

class WalletCliTests(unittest.TestCase):
 def test_capabilities_cover_core_and_phase4f2(self):
  value=wallet_cli.capabilities();self.assertIn('all qrx-cli commands',value['core']);self.assertIn('complete CSV ledger',value['phase_4f2']);self.assertIn('state-root',value['ledger'].lower())
 def test_paths_match_tauri_layout(self):
  paths=wallet_cli.state_paths(Path('/data'),'alpha','node1');self.assertEqual(paths['chain'],Path('/data/alpha/chain'));self.assertEqual(paths['arbitrage'],Path('/data/alpha/wallets/node1/settings/arbitrage'));self.assertEqual(paths['kraken'],Path('/data/alpha/wallets/node1/settings/kraken-gateway'))
 def test_resource_resolution_supports_build_bundle(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);resources=root/'qrx-wallet-resources';resources.mkdir();target=resources/'tool.py';target.write_text('ok\n')
   self.assertEqual(wallet_cli.resolve_script(root,'tool.py'),target.resolve())
 def test_btc_passphrase_is_stdin_only(self):
  captured={}
  def fake_run(args,input_text=None):captured.update({'args':args,'input':input_text});return 0
  with patch.object(wallet_cli.getpass,'getpass',return_value='secret pass'),patch.object(wallet_cli,'run',side_effect=fake_run):
   self.assertEqual(wallet_cli.run_btc('/service',Path('/data'),['init']),0)
  self.assertNotIn('secret pass',captured['args']);self.assertEqual(json.loads(captured['input'])['passphrase'],'secret pass')
 def test_btc_capability_declares_shared_service(self):
  self.assertIn('shared with Tauri',wallet_cli.capabilities()['btc_light'])
 def test_default_datadir_matches_tauri_layout(self):
  self.assertEqual(wallet_cli.default_datadir().parts[-2:],('gui-wallet','qrx-data'))

if __name__=='__main__':unittest.main()
