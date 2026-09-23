#!/usr/bin/env bash
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="$R/scripts/prepare-upscaler-ai-bundle.sh"
L="$R/scripts/upscaler-ai-archives.sha256"
bash -n "$S"
grep -q 'e0ad05580abfeb25f8d8fb55aaf7bedf552c375b5b4d9bd3c8d59764d2cc333a  realesrgan-ncnn-vulkan-20220424-macos.zip' "$L"
grep -q "realesrgan-ncnn-vulkan-20220424-macos.zip) printf '51817124'" "$S"
grep -q 'abc02804e17982a3be33675e4d471e91ea374e65b70167abc09e31acb412802d  realesrgan-ncnn-vulkan-20220424-windows.zip' "$L"
grep -q "realesrgan-ncnn-vulkan-20220424-windows.zip) printf '45474481'" "$S"
grep -q 'QRX_AI_OFFLINE' "$S"
grep -q 'supply_chain_policy=qrx-0.0.9.65-sha256-release-lock' "$S"
grep -q 'does not promote a newly downloaded digest automatically' "$R/AI_SUPPLY_CHAIN_POLICY_0.0.9.65.md"
echo '0.0.9.65 AI supply-chain lock audit: PASS'
