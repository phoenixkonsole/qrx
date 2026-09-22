"""Offline recursive-clone regression; requires Git and Bash (Git Bash on Windows)."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

script = (Path(__file__).resolve().parent / "prepare-upscaler-ai-bundle.sh").read_text(encoding="utf-8")
helper = re.search(r"^runtime_git\(\) \{.*?^\}", script, re.S | re.M).group()
assert 'if runtime_git clone ' in script
assert 'runtime_git -C "$SRC" submodule update' in script
bash = os.environ.get("BASH") or ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))
base = Path(tempfile.gettempdir()).resolve()
with tempfile.TemporaryDirectory(prefix="qrx-submodule-", dir=base) as directory:
    root = Path(directory).resolve()
    assert root.parent == base and root.name.startswith("qrx-submodule-")
    config = root / "gitconfig"
    config.touch()
    env = dict(os.environ, GIT_CONFIG_GLOBAL=str(config), GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="file")
    def git(*args, cwd=None, check=True):
        return subprocess.run(["git", *args], cwd=cwd, env=env, check=check, capture_output=True, text=True)
    def commit(repo, stage="."):
        git("add", stage, cwd=repo)
        git("-c", "user.name=Regression", "-c", "user.email=regression@example.invalid", "commit", "-qm", "fixture", cwd=repo)
        return git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    parent = root / "runtime"
    git("init", "-q", str(parent))
    modules = []
    pins = {}
    for name, owner in (("ncnn", "Tencent"), ("libwebp", "webmproject")):
        repo = root / name
        git("init", "-q", str(repo))
        (repo / "marker").write_text(name)
        pins[name] = commit(repo)
        ssh = f"git@github.com:{owner}/{name}.git"
        https = f"https://github.com/{owner}/{name}.git"
        # Reproduce the reported malformed host, isolated from user config.
        git("config", "--global", "--add", "url.https://github.com.insteadOf", f"git@github.com:{owner}/")
        assert git("ls-remote", "--get-url", ssh).stdout.strip() == f"https://github.com{name}.git"
        git("config", "--global", "--add", f"url.{repo.as_uri()}.insteadOf", https)
        modules.append(f'[submodule "src/{name}"]\n path = src/{name}\n url = {ssh}\n')
        git("update-index", "--add", "--cacheinfo", f"160000,{pins[name]},src/{name}", cwd=parent)
    (parent / ".gitmodules").write_text("\n".join(modules))
    parent_pin = commit(parent, ".gitmodules")
    git("tag", "v0.2.0", cwd=parent)
    before = config.read_bytes()
    common = ["clone", "--quiet", "--depth", "1", "--branch", "v0.2.0", "--recurse-submodules", "--shallow-submodules", parent.as_uri()]
    broken = git(*common, str(root / "broken"), check=False)
    assert broken.returncode != 0, "Broken SSH rewrite must fail"
    destination = root / "fixed"
    def runtime(*args):
        result = subprocess.run([bash, "-c", helper+'\nruntime_git "$@"', "regression", *args], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    runtime(*common, str(destination))
    runtime("-C", str(destination), "submodule", "update", "--init", "--recursive", "--depth", "1")
    assert git("rev-parse", "HEAD", cwd=destination).stdout.strip() == parent_pin
    for name, pin in pins.items():
        assert git("rev-parse", "HEAD", cwd=destination / "src" / name).stdout.strip() == pin
    assert git("status", "--porcelain", cwd=destination).stdout.strip() == ""
    assert config.read_bytes() == before, "Production helper must not change global config"
print("PASS: malformed SSH rewrites reproduced; HTTPS recursive clone/update preserve pinned commits and global config")
