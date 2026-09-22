#!/usr/bin/env bash
set -euo pipefail

# QRX 0.0.9.65 supply-chain locked multi-platform AI bundle preparation.
# Targets: macOS arm64/x64, Windows x64, Linux x64 and Linux arm64 (Pi 5 class).
# Official portable v0.2.5.0 release assets are used where upstream publishes them.
# Linux ARM64 has no official portable asset, so the ncnn runtime is built from the
# pinned upstream Real-ESRGAN-ncnn-vulkan v0.2.0 tag/commit and combined with the
# same verified model bytes from the official Real-ESRGAN v0.2.5.0 Ubuntu asset.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-host}"
DEST="${2:-$ROOT/GUIWALLET/src-tauri/resources/upscaler}"
MODEL_TAG="v0.2.5.0"
MODEL_RELEASE_COMMIT_SHORT="685d429"
RUNTIME_TAG="v0.2.0"
RUNTIME_COMMIT_PREFIX="37026f4"
SOURCE_REPO="https://github.com/xinntao/Real-ESRGAN"
RUNTIME_REPO="https://github.com/xinntao/Real-ESRGAN-ncnn-vulkan"
# The pinned runtime declares these public submodules using SSH URLs. Use
# explicit HTTPS URLs for this command only: no SSH key or global insteadOf
# rule is required, and malformed SSH rewrites cannot drop the owner/path.
runtime_git() {
  git -c http.version=HTTP/1.1 \
    -c submodule.src/libwebp.url=https://github.com/webmproject/libwebp.git \
    -c submodule.src/ncnn.url=https://github.com/Tencent/ncnn.git "$@"
}
LOCK_FILE="$ROOT/scripts/upscaler-ai-archives.sha256"
CACHE_DIR="${QRX_AI_DOWNLOAD_CACHE:-$ROOT/.cache/qrx-ai}"
mkdir -p "$CACHE_DIR"
MODEL_ASSET="realesrgan-ncnn-vulkan-20220424-ubuntu.zip"

if [[ "$TARGET" == "host" ]]; then
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64|Darwin:aarch64) TARGET=macos-arm64 ;;
    Darwin:x86_64) TARGET=macos-x64 ;;
    Linux:aarch64|Linux:arm64) TARGET=linux-arm64 ;;
    Linux:x86_64|Linux:amd64) TARGET=linux-x64 ;;
    MINGW*:x86_64|MSYS*:x86_64|CYGWIN*:x86_64) TARGET=windows-x64 ;;
    *) echo "unsupported AI bundle host: $(uname -s) $(uname -m)" >&2; exit 2 ;;
  esac
fi
case "$TARGET" in
  macos-arm64|macos-x64) RUNTIME_ASSET="realesrgan-ncnn-vulkan-20220424-macos.zip" ;;
  windows-x64) RUNTIME_ASSET="realesrgan-ncnn-vulkan-20220424-windows.zip" ;;
  linux-x64) RUNTIME_ASSET="$MODEL_ASSET" ;;
  linux-arm64) RUNTIME_ASSET="source:$RUNTIME_TAG" ;;
  *) echo "unsupported QRX AI target: $TARGET" >&2; exit 2 ;;
esac

for x in curl python3 unzip; do command -v "$x" >/dev/null || { echo "missing required tool: $x" >&2; exit 2; }; done
sha256_file() { python3 - "$1" <<'PY2'
import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1],'rb') as f:
    for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
print(h.hexdigest())
PY2
}
TMP="$(mktemp -d "${TMPDIR:-/tmp}/qrx-upscaler-ai.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

lookup_lock() {
  local asset="$1" env_name="$2" v=""
  if [[ -f "$LOCK_FILE" ]]; then
    v="$(awk -v a="$asset" '$2==a {print $1; exit}' "$LOCK_FILE")"
  fi
  [[ -n "$v" ]] || v="${!env_name:-}"
  [[ "$v" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
  printf '%s' "$v" | tr 'A-F' 'a-f'
}
asset_url() {
  local asset="$1"
  printf 'https://github.com/xinntao/Real-ESRGAN/releases/download/%s/%s' "$MODEL_TAG" "$asset"
}
expected_bytes() {
  case "$1" in
    realesrgan-ncnn-vulkan-20220424-macos.zip) printf '51817124' ;;
    *) printf '' ;;
  esac
}
fetch_once() {
  local asset="$1" out="$2"
  local url; url="$(asset_url "$asset")"
  if [[ "${QRX_AI_OFFLINE:-0}" == "1" ]]; then
    echo "QRX_AI_OFFLINE=1 and verified cache is unavailable for $asset" >&2
    exit 3
  fi
  rm -f "$out.part"
  curl -fL --retry 5 --retry-all-errors --connect-timeout 15 --max-time 900 \
    --proto '=https' --tlsv1.2 \
    -H 'Accept: application/octet-stream' \
    -o "$out.part" "$url"
  mv "$out.part" "$out"
}
validate_zip() {
  python3 - "$1" <<'PY2'
import sys,zipfile,pathlib
with zipfile.ZipFile(sys.argv[1]) as z:
    for i in z.infolist():
        n=pathlib.PurePosixPath(i.filename)
        if n.is_absolute() or '..' in n.parts: raise SystemExit('unsafe archive member: '+i.filename)
PY2
}
fetch_asset() {
  local asset="$1" out="$2" env_name="$3"
  local expected="" got url cached bytes
  url="$(asset_url "$asset")"
  cached="$CACHE_DIR/$asset"
  expected="$(lookup_lock "$asset" "$env_name" || true)"

  # One canonical network fetch per asset. If a verified cache exists, reuse it.
  if [[ -f "$cached" ]]; then
    got="$(sha256_file "$cached")"
    if [[ -n "$expected" && "$got" != "$expected" ]]; then
      echo "Discarding stale AI cache whose digest does not match the reviewed lock: $cached" >&2
      rm -f "$cached"
    fi
  fi
  if [[ ! -f "$cached" ]]; then
    fetch_once "$asset" "$cached"
  fi

  got="$(sha256_file "$cached")"
  bytes="$(wc -c < "$cached" | tr -d ' ')"
  validate_zip "$cached"
  expected_size="$(expected_bytes "$asset")"
  if [[ -n "$expected_size" && "$bytes" != "$expected_size" ]]; then
    echo "Verified AI asset size mismatch before extraction." >&2
    echo "Asset: $asset" >&2
    echo "Downloaded bytes: $bytes" >&2
    echo "Expected bytes: $expected_size" >&2
    echo "Cache: $cached" >&2
    exit 3
  fi

  if [[ -z "$expected" ]]; then
    echo "No reviewed SHA-256 lock for $asset." >&2
    echo "Downloaded the canonical pinned release asset exactly once and retained it in the QRX AI cache." >&2
    echo "Asset: $asset" >&2
    echo "Resolved URL: $url" >&2
    echo "Downloaded bytes: $bytes" >&2
    echo "Actual SHA-256: $got" >&2
    echo "Expected SHA-256: <not reviewed>" >&2
    echo "Cache: $cached" >&2
    echo "Refusing trust-on-first-use. Independently review this digest, then add it to $LOCK_FILE or set $env_name." >&2
    exit 3
  fi
  if [[ "$got" != "$expected" ]]; then
    echo "Verified AI asset digest mismatch." >&2
    echo "Asset: $asset" >&2
    echo "Resolved URL: $url" >&2
    echo "Downloaded bytes: $bytes" >&2
    echo "Actual SHA-256: $got" >&2
    echo "Expected SHA-256: $expected" >&2
    echo "Cache: $cached" >&2
    exit 3
  fi

  cp "$cached" "$out"
  printf '%s' "$expected"
}

# Always source models from one canonical official archive so all targets ship
# byte-identical reviewed models and model provenance.
MODEL_ZIP="$TMP/$MODEL_ASSET"
MODEL_SHA="$(fetch_asset "$MODEL_ASSET" "$MODEL_ZIP" QRX_REAL_ESRGAN_MODEL_ARCHIVE_SHA256)"
mkdir -p "$TMP/models-unpack"
unzip -q "$MODEL_ZIP" -d "$TMP/models-unpack"
M2P="$(find "$TMP/models-unpack" -type f -name 'realesr-animevideov3-x2.param' -print -quit)"
M2B="$(find "$TMP/models-unpack" -type f -name 'realesr-animevideov3-x2.bin' -print -quit)"
M4P="$(find "$TMP/models-unpack" -type f -name 'realesrgan-x4plus.param' -print -quit)"
M4B="$(find "$TMP/models-unpack" -type f -name 'realesrgan-x4plus.bin' -print -quit)"
for f in "$M2P" "$M2B" "$M4P" "$M4B"; do [[ -n "$f" && -f "$f" ]] || { echo "required reviewed model missing from pinned official archive" >&2; exit 4; }; done

RUNTIME_ORIGIN="official-portable"
RUNTIME_ARCHIVE_SHA=""
RUNTIME_SOURCE_COMMIT=""
if [[ "$TARGET" == "linux-arm64" ]]; then
  for x in git cmake; do command -v "$x" >/dev/null || { echo "linux-arm64 source build requires $x" >&2; exit 2; }; done
  RUNTIME_ORIGIN="pinned-source-build"
  SRC="$TMP/runtime-src"
  # Clone the pinned release directly. This avoids a partial default-branch tree
  # followed by a tag checkout and makes submodule state part of the fetch.
  # Retry the pinned upstream source fetch. This handles transient GitHub/TLS
  # failures without asking users to clone dependencies manually. Never fall
  # back to an unpinned branch.
  cloned=0
  for attempt in 1 2 3; do
    rm -rf "$SRC"
    if runtime_git clone --quiet --depth 1 --branch "$RUNTIME_TAG" --recurse-submodules --shallow-submodules "$RUNTIME_REPO" "$SRC"; then
      cloned=1; break
    fi
    echo "Pinned Real-ESRGAN runtime fetch attempt $attempt/3 failed; retrying..." >&2
    sleep $((attempt * 2))
  done
  [[ "$cloned" -eq 1 ]] || { echo "Unable to fetch pinned Real-ESRGAN runtime source after 3 attempts. Check GitHub/TLS connectivity or provide the verified QRX AI cache." >&2; exit 3; }
  runtime_git -C "$SRC" submodule update --init --recursive --depth 1
  RUNTIME_SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
  [[ "$RUNTIME_SOURCE_COMMIT" == "$RUNTIME_COMMIT_PREFIX"* ]] || { echo "runtime tag resolved to unexpected commit: $RUNTIME_SOURCE_COMMIT" >&2; exit 3; }
  # The pinned upstream project keeps its CMake entry point under src/.
  RUNTIME_CMAKE_SRC="$SRC/src"
  [[ -f "$RUNTIME_CMAKE_SRC/CMakeLists.txt" ]] || { echo "Pinned Real-ESRGAN-ncnn-vulkan source is incomplete: CMakeLists.txt missing at $RUNTIME_CMAKE_SRC" >&2; exit 4; }
  # CMake 4 removed legacy policy compatibility used by the pinned ncnn tree.
  cmake -S "$RUNTIME_CMAKE_SRC" -B "$TMP/runtime-build" -DCMAKE_BUILD_TYPE=Release -DNCNN_VULKAN=ON -DCMAKE_POLICY_VERSION_MINIMUM=3.5
  cmake --build "$TMP/runtime-build" --config Release --parallel "${JOBS:-2}"
  RUNTIME="$(find "$TMP/runtime-build" -type f -name 'realesrgan-ncnn-vulkan' -print -quit)"
else
  if [[ "$RUNTIME_ASSET" == "$MODEL_ASSET" ]]; then
    RUNTIME_ZIP="$MODEL_ZIP"; RUNTIME_ARCHIVE_SHA="$MODEL_SHA"
  else
    RUNTIME_ZIP="$TMP/$RUNTIME_ASSET"
    case "$TARGET" in
      macos-arm64) lock=QRX_REAL_ESRGAN_MACOS_ARM64_ARCHIVE_SHA256 ;;
      macos-x64) lock=QRX_REAL_ESRGAN_MACOS_X64_ARCHIVE_SHA256 ;;
      windows-x64) lock=QRX_REAL_ESRGAN_WINDOWS_X64_ARCHIVE_SHA256 ;;
      linux-x64) lock=QRX_REAL_ESRGAN_LINUX_X64_ARCHIVE_SHA256 ;;
    esac
    RUNTIME_ARCHIVE_SHA="$(fetch_asset "$RUNTIME_ASSET" "$RUNTIME_ZIP" "$lock")"
  fi
  mkdir -p "$TMP/runtime-unpack"
  unzip -q "$RUNTIME_ZIP" -d "$TMP/runtime-unpack"
  if [[ "$TARGET" == "windows-x64" ]]; then
    RUNTIME="$(find "$TMP/runtime-unpack" -type f -name 'realesrgan-ncnn-vulkan.exe' -print -quit)"
  else
    RUNTIME="$(find "$TMP/runtime-unpack" -type f -name 'realesrgan-ncnn-vulkan' -print -quit)"
  fi
fi
[[ -n "${RUNTIME:-}" && -f "$RUNTIME" ]] || { echo "runtime not found for $TARGET" >&2; exit 4; }

# Parse executable headers without depending on host-specific file/lipo tools.
python3 - "$RUNTIME" "$TARGET" <<'PY2'
import struct,sys
p,t=sys.argv[1:3]; b=open(p,'rb').read(4096)
def die(s): raise SystemExit(s)
if t.startswith('linux-'):
    if b[:4]!=b'\x7fELF': die('runtime is not ELF')
    endian='<' if b[5]==1 else '>'; machine=struct.unpack(endian+'H',b[18:20])[0]
    want=0x3e if t=='linux-x64' else 0xb7
    if machine!=want: die(f'ELF machine mismatch: {machine:#x} != {want:#x}')
elif t=='windows-x64':
    if b[:2]!=b'MZ': die('runtime is not PE/MZ')
    off=struct.unpack('<I',b[0x3c:0x40])[0]
    bb=open(p,'rb'); bb.seek(off); h=bb.read(6)
    if h[:4]!=b'PE\0\0' or struct.unpack('<H',h[4:6])[0]!=0x8664: die('PE is not x86-64')
elif t.startswith('macos-'):
    # Accept thin target Mach-O or universal FAT containing the requested CPU type.
    raw=open(p,'rb').read(65536); magic=raw[:4]
    want=0x01000007 if t=='macos-x64' else 0x0100000c
    vals=[]
    if magic in (b'\xca\xfe\xba\xbe',b'\xca\xfe\xba\xbf'):
        n=struct.unpack('>I',raw[4:8])[0]; step=20 if magic==b'\xca\xfe\xba\xbe' else 32
        for i in range(n): vals.append(struct.unpack('>I',raw[8+i*step:12+i*step])[0])
    elif magic in (b'\xcf\xfa\xed\xfe',b'\xce\xfa\xed\xfe'):
        vals=[struct.unpack('<I',raw[4:8])[0]]
    elif magic in (b'\xfe\xed\xfa\xcf',b'\xfe\xed\xfa\xce'):
        vals=[struct.unpack('>I',raw[4:8])[0]]
    else: die('runtime is not recognized Mach-O')
    if want not in vals: die(f'Mach-O does not contain requested architecture {t}; cpu types={vals}')
PY2

rm -rf "$DEST"; mkdir -p "$DEST/runtime" "$DEST/models" "$DEST/licenses"
RUNTIME_NAME="realesrgan-ncnn-vulkan"; [[ "$TARGET" == "windows-x64" ]] && RUNTIME_NAME+=".exe"
cp "$RUNTIME" "$DEST/runtime/$RUNTIME_NAME"
[[ "$TARGET" == "windows-x64" ]] || chmod 755 "$DEST/runtime/$RUNTIME_NAME"
cp "$M2P" "$DEST/models/realesr-animevideov3-x2.param"; cp "$M2B" "$DEST/models/realesr-animevideov3-x2.bin"
cp "$M4P" "$DEST/models/realesrgan-x4plus.param"; cp "$M4B" "$DEST/models/realesrgan-x4plus.bin"
RUNTIME_SHA="$(sha256_file "$DEST/runtime/$RUNTIME_NAME")"
M2P_SHA="$(sha256_file "$DEST/models/realesr-animevideov3-x2.param")"; M2B_SHA="$(sha256_file "$DEST/models/realesr-animevideov3-x2.bin")"
M4P_SHA="$(sha256_file "$DEST/models/realesrgan-x4plus.param")"; M4B_SHA="$(sha256_file "$DEST/models/realesrgan-x4plus.bin")"
printf '%s\n' "$RUNTIME_SHA" > "$DEST/runtime/runtime.sha256"

for scale in 2 4; do
  if [[ "$scale" == 2 ]]; then id=realesr-animevideov3; param=realesr-animevideov3-x2.param; weights=realesr-animevideov3-x2.bin; ph=$M2P_SHA; wh=$M2B_SHA; mf=realesrgan-x2plus.qrxmodel; else id=realesrgan-x4plus; param=realesrgan-x4plus.param; weights=realesrgan-x4plus.bin; ph=$M4P_SHA; wh=$M4B_SHA; mf=realesrgan-x4plus.qrxmodel; fi
  cat > "$DEST/models/$mf" <<EOF
format=qrx-upscaler-model-v2
id=$id
scale=$scale
param=$param
weights=$weights
param_sha256=$ph
weights_sha256=$wh
license_id=Real-ESRGAN-BSD-3-Clause
provenance_source_url=$SOURCE_REPO
provenance_release=$MODEL_TAG@$MODEL_RELEASE_COMMIT_SHORT
provenance_archive_sha256=$MODEL_SHA
EOF
done

# Prefer exact license from runtime source/archive, otherwise use model archive.
LIC=""
if [[ -d "${SRC:-}" ]]; then LIC="$(find "$SRC" -maxdepth 2 -type f -name LICENSE -print -quit)"; fi
[[ -n "$LIC" ]] || LIC="$(find "$TMP/runtime-unpack" "$TMP/models-unpack" -maxdepth 4 -type f -name LICENSE -print -quit 2>/dev/null | head -1 || true)"
[[ -n "$LIC" && -f "$LIC" ]] && cp "$LIC" "$DEST/licenses/Real-ESRGAN-ncnn-vulkan-LICENSE.txt"
cat > "$DEST/PROVENANCE.txt" <<EOF
QRX verified AI bundle v3
target=$TARGET
upstream_project=$SOURCE_REPO
runtime_project=$RUNTIME_REPO
model_release=$MODEL_TAG@$MODEL_RELEASE_COMMIT_SHORT
model_asset=$MODEL_ASSET
model_archive_sha256=$MODEL_SHA
runtime_origin=$RUNTIME_ORIGIN
runtime_asset=$RUNTIME_ASSET
runtime_archive_sha256=${RUNTIME_ARCHIVE_SHA:-source-build}
runtime_source_commit=${RUNTIME_SOURCE_COMMIT:-n/a}
runtime_sha256=$RUNTIME_SHA
supply_chain_policy=qrx-0.0.9.65-sha256-release-lock
model_x2=realesr-animevideov3-x2
model_x4=realesrgan-x4plus
backend=ncnn-vulkan
acceleration_macos=Vulkan via MoltenVK/Metal
acceleration_windows=Vulkan (Intel/AMD/NVIDIA driver)
acceleration_linux_x64=Vulkan (Intel/AMD/NVIDIA; Tesla P40 supported when NVIDIA Vulkan driver exposes the GPU)
acceleration_linux_arm64=Vulkan when available; CPU fallback/runtime behavior is platform/driver dependent; Raspberry Pi Vulkan remains experimental upstream
license_models=Real-ESRGAN BSD-3-Clause
EOF
printf '[AI bundle] staged verified %s bundle at %s\n' "$TARGET" "$DEST"
printf '[AI bundle] runtime sha256=%s model archive sha256=%s\n' "$RUNTIME_SHA" "$MODEL_SHA"
