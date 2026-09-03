#!/usr/bin/env python3
import argparse, hashlib, json, os, stat, tempfile, zipfile
from datetime import datetime, timezone
from pathlib import Path

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()

ap=argparse.ArgumentParser(description="Package one verified QRX target release")
ap.add_argument("--root",required=True);ap.add_argument("--target",required=True);ap.add_argument("--output",required=True)
args=ap.parse_args();root=Path(args.root).resolve();output=Path(args.output).resolve()
if not root.is_dir():raise SystemExit(f"release root does not exist: {root}")
files=sorted(p for p in root.rglob("*") if p.is_file() and p.name not in {"manifest.json","SHA256SUMS.txt"})
if not files:raise SystemExit("refusing to package an empty release")
records=[{"path":p.relative_to(root).as_posix(),"size":p.stat().st_size,"sha256":digest(p)} for p in files]
manifest={"format":"QRX_MULTI_TARGET_RELEASE_V1","qrx_version":"0.0.7","target":args.target,"created_at_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"files":records}
(root/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
all_files=sorted(p for p in root.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
(root/"SHA256SUMS.txt").write_text("".join(f"{digest(p)}  {p.relative_to(root).as_posix()}\n" for p in all_files),encoding="utf-8")
output.parent.mkdir(parents=True,exist_ok=True)
fd,tmp_name=tempfile.mkstemp(prefix=output.name+".",suffix=".tmp",dir=output.parent);os.close(fd)
try:
    with zipfile.ZipFile(tmp_name,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(x for x in root.rglob("*") if x.is_file()):
            rel=Path(f"qrx-0.0.7-{args.target}")/p.relative_to(root)
            info=zipfile.ZipInfo(rel.as_posix(),date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            mode=p.stat().st_mode;info.external_attr=(stat.S_IMODE(mode)&0xFFFF)<<16
            z.writestr(info,p.read_bytes())
    os.replace(tmp_name,output)
finally:
    if os.path.exists(tmp_name):os.unlink(tmp_name)
sha=output.with_suffix(output.suffix+".sha256")
sha.write_text(f"{digest(output)}  {output.name}\n",encoding="ascii")
print(json.dumps({"archive":str(output),"sha256":digest(output),"file_count":len(all_files)+1}))

