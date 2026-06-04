#!/usr/bin/env python3
import os, random, shutil, subprocess, sys, tempfile
from pathlib import Path

if len(sys.argv) < 2:
    print('usage: tx_stress.py <qrx-binary>')
    sys.exit(1)

qrx = Path(sys.argv[1]).resolve()
root = qrx.parent.parent
work = Path(tempfile.mkdtemp(prefix='qrx-stress-'))
os.environ['QRX_PASSPHRASE'] = 'testpass'

def run(*args, check=True):
    return subprocess.run([str(qrx), *args], cwd=work, capture_output=True, text=True, check=check)

run('seed-new', 'alice')
run('seed-new', 'bob')
alice = run('address', 'alice').stdout.strip()
bob = run('address', 'bob').stdout.strip()
run('init-chain', 'chain')
run('faucet', 'chain', alice, '1000')
run('sign', 'alice', 'chain', bob, '25', 'hello', 'good.qrxtx')
base = (work / 'good.qrxtx').read_bytes()
mutants = 100
for i in range(mutants):
    data = bytearray(base)
    for _ in range(random.randint(1, max(1, len(data)//20))):
        idx = random.randrange(len(data))
        data[idx] = random.randrange(256)
    p = work / f'mut-{i}.qrxtx'
    p.write_bytes(data)
    proc = subprocess.run([str(qrx), 'verify', 'chain', p.name], cwd=work, capture_output=True, text=True)
    if proc.returncode not in (0,1):
        print(proc.stdout)
        print(proc.stderr)
        raise SystemExit(f'unexpected exit code {proc.returncode} for {p.name}')
print(f'tx-stress: ok ({mutants} mutants)')
shutil.rmtree(work)
