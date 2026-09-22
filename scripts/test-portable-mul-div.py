"""Check the actual Core helper against Python's arbitrary-precision integers.

Run from a VS developer shell on Windows, or with a C compiler on Unix.
"""
import os
from pathlib import Path
import random
import re
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "qrx-core/src/qrx.c").read_text()
match = re.search(r"static int mul_div_floor_nonneg\([^\n]+\{.*?^\}", source, re.S | re.M)
assert match, "Core helper not found"
maximum = (1 << 63) - 1
cases = [(0, 360, 100000000), (1, 360, 100000000),
         (100000000, 360, 100000000), (maximum, 360, 100000000),
         (maximum, maximum, maximum), (maximum, maximum, 1),
         (-1, 360, 100000000), (1, -1, 1), (1, 1, 0)]
rng = random.Random(42)
cases += [(rng.randrange(maximum + 1), rng.randrange(maximum + 1),
           rng.randrange(1, maximum + 1)) for _ in range(300)]
checks = []
for a, b, d in cases:
    expected = a * b // d if a >= 0 and b >= 0 and d > 0 else -1
    valid = 0 <= expected <= maximum
    checks.append(f'out=-1; rc=mul_div_floor_nonneg({a}LL,{b}LL,{d}LL,&out);'
                  + (f'if(rc || out!={expected}LL) return {1};' if valid
                     else 'if(rc==0) return 2;'))
program = '#include <limits.h>\n' + match.group() + '\nint main(void){long long out; int rc;\n' + '\n'.join(checks) + '\nreturn 0;}\n'
temp_base = Path(tempfile.gettempdir()).resolve()
with tempfile.TemporaryDirectory(prefix="qrx-mul-div-", dir=temp_base) as directory:
    root = Path(directory).resolve()
    assert root.parent == temp_base and root.name.startswith("qrx-mul-div-")
    (root / "test.c").write_text(program)
    if os.name == "nt":
        command = ["cl", "/nologo", "/std:c11", "test.c", "/Fetest.exe"]
        executable = root / "test.exe"
    else:
        command = [os.environ.get("CC", "cc"), "-std=c11", "test.c", "-o", "test"]
        executable = root / "test"
    subprocess.run(command, cwd=root, check=True)
    subprocess.run([str(executable)], cwd=root, check=True)
print(f"PASS: {len(cases)} exact multiplication/division, boundary and overflow cases")
