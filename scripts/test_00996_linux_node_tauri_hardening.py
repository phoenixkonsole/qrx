from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'scripts/build-all-targets.sh').read_text()
w=(root/'scripts/build-linux-legacy-webkit4.sh').read_text()
p=(root/'GUIWALLET/package.json').read_text()
checks=[
 ('node major probe', 'qrx_node_major()' in s),
 ('minimum node 18', 'node_major < 18' in s and 'node_major >= 18' in s),
 ('node 20 bootstrap', 'https://deb.nodesource.com/setup_20.x' in s),
 ('same-process refresh', 'hash -r' in s),
 ('node-only excluded', 'NODE_ONLY" -eq 0' in s),
 ('tauri exact pin', '"@tauri-apps/cli": "1.6.0"' in p),
 ('npm ci retained', 'npm ci --no-audit --no-fund' in s),
 ('legacy WebKit unifdef dependency', 'ruby unifdef' in w),
]
failed=[name for name,ok in checks if not ok]
if failed: raise SystemExit('FAIL: '+', '.join(failed))
print('QRX 0.0.9.96 Linux Node/Tauri build hardening audit: PASS')
