#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
cd "$ROOT"
python3 - <<'PY'
from pathlib import Path
import hashlib
root = Path('.')
files = []
for path in sorted(root.rglob('*')):
    if not path.is_file():
        continue
    rel = path.relative_to(root).as_posix()
    if rel.startswith('build/') or rel.startswith('build-asan/') or rel.endswith('.zip'):
        continue
    data = path.read_bytes()
    files.append((rel, hashlib.sha3_512(data).hexdigest(), hashlib.sha256(data).hexdigest()))
with open('SHA3SUMS', 'w') as f:
    for rel, h3, _ in files:
        f.write(f"{h3}  {rel}\n")
with open('SHA256SUMS', 'w') as f:
    for rel, _, h2 in files:
        f.write(f"{h2}  {rel}\n")
print('Wrote SHA3SUMS and SHA256SUMS')
PY
