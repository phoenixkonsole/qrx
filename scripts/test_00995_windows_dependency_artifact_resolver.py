from pathlib import Path
p=Path(__file__).resolve().parents[1]/'qrx-core/scripts/build-windows-x64-static.ps1'
s=p.read_text(encoding='utf-8')
checks=[
 'cmake --install $Build --config Release --prefix $DepsPrefix',
 'function Resolve-ZlibStatic',
 'install_manifest.txt',
 "Get-ChildItem $Build -Recurse",
 'zlibstatic.lib',
 'zs.lib',
 'ZLIB_BUILD_SHARED=OFF',
 'ZLIB_BUILD_STATIC=ON',
 'Adopting zlib artifact from current build',
 'matching headers from the current build',
]
missing=[x for x in checks if x not in s]
assert not missing, missing
assert 'Get-ChildItem C:\\ -Recurse' not in s
print('QRX 0.0.9.95 Windows dependency artifact resolver audit: PASS')
