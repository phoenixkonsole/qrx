#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="$ROOT/scripts/build-all-targets.sh"
grep -q -- '--node-only' "$S"
grep -q 'NODE_ONLY=1' "$S"
grep -q 'qrx-0.0.9-genesis-\$TARGET-node-only.zip' "$S"
# Headless packages skip the desktop AI bundle entirely. Desktop releases must
# fail if that bundle is absent instead of silently shipping a degraded GUI.
grep -q 'AI_UNAVAILABLE marker is forbidden in GUI release builds' "$S"
! grep -q 'continuing with GUI wallet without local AI' "$S"
# Plan mode must accept node-only without requiring build dependencies.
out="$(bash "$S" --target host --node-only --plan)"
grep -q 'headless node release plan' <<<"$out"
grep -q 'Stage headless node binaries/tools only' <<<"$out"
! grep -q 'Build Tauri wallet' <<<"$out"
echo 'QRX 0.0.9.88 headless node / Linux AI fallback audit: PASS'
