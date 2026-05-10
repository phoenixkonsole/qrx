#!/usr/bin/env python3
import hashlib, json, os, platform, sys
from pathlib import Path

root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path('.').resolve()
out = Path(sys.argv[2]) if len(sys.argv) > 2 else root / 'qrx-rc3.sbom.json'

entries = []
for path in sorted(root.rglob('*')):
    if not path.is_file():
        continue
    rel = path.relative_to(root).as_posix()
    if rel.startswith('build/') or rel.startswith('build-asan/') or rel.endswith('.zip'):
        continue
    data = path.read_bytes()
    entries.append({
        'path': rel,
        'sha3_512': hashlib.sha3_512(data).hexdigest(),
        'sha256_legacy': hashlib.sha256(data).hexdigest(),
        'size': len(data),
    })

sbom = {
    'name': 'qrx-rc3',
    'format': 'lightweight-file-sbom',
    'platform': platform.platform(),
    'python': platform.python_version(),
    'files': entries,
}
Path(out).write_text(json.dumps(sbom, indent=2) + '\n')
print(out)
