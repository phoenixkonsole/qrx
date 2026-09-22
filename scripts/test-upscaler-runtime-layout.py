"""Exercise the production source-build entry point with an offline CMake fixture."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

script = (Path(__file__).resolve().parent / "prepare-upscaler-ai-bundle.sh").read_text(encoding="utf-8")
block = re.search(r'^  RUNTIME_CMAKE_SRC=.*?^  cmake --build[^\n]*', script, re.M | re.S).group()
bash = os.environ.get("BASH") or ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))
with tempfile.TemporaryDirectory(prefix="qrx-runtime-layout-") as directory:
    root = Path(directory)
    source = root / "runtime-src" / "src"
    source.mkdir(parents=True)
    # Match the pinned upstream layout: no CMakeLists.txt at checkout root.
    cmake_file = source / "CMakeLists.txt"
    cmake_file.write_text('cmake_minimum_required(VERSION 3.15)\nproject(layout_check NONE)\nadd_subdirectory(ncnn)\noption(NCNN_VULKAN "fixture" OFF)\nadd_custom_target(layout_check ALL COMMAND "${CMAKE_COMMAND}" -E touch "${CMAKE_BINARY_DIR}/layout-built")\n')
    legacy = source / "ncnn"
    legacy.mkdir()
    (legacy / "CMakeLists.txt").write_text('cmake_minimum_required(VERSION 2.8.12)\n')
    env = dict(os.environ, TMP=root.as_posix(), SRC=source.parent.as_posix())
    if os.name == "nt":
        env["CMAKE_GENERATOR"] = "Ninja"
        # The fixture has no compiler requirement, but Ninja is needed to build it.
        ninja = shutil.which("ninja")
        if not ninja:
            env["CMAKE_GENERATOR"] = "Visual Studio 17 2022"
    version = subprocess.check_output(["cmake", "--version"], text=True)
    if int(re.search(r"cmake version (\d+)", version).group(1)) >= 4:
        baseline = block.replace("-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "")
        rejected = subprocess.run([bash, "-ec", baseline], env=env, capture_output=True, text=True)
        assert rejected.returncode != 0, "Legacy policy fixture must fail without the override"
        assert "Compatibility with CMake < 3.5" in rejected.stderr
    result = subprocess.run([bash, "-ec", block], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "runtime-build" / "layout-built").is_file()
    cmake_file.unlink()
    missing = subprocess.run([bash, "-ec", block], env=env, capture_output=True, text=True)
    assert missing.returncode == 4, missing.stdout + missing.stderr
    assert 'CMakeLists.txt missing at ' in missing.stderr
    assert '/runtime-src/src' in missing.stderr
print("PASS: production CMake commands build the src/ fixture with a legacy ncnn policy; missing entry point fails clearly")
