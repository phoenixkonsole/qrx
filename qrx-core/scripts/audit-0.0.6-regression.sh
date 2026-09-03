#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail(){ echo "FAIL: $*" >&2; exit 1; }
pass(){ echo "PASS: $*"; }
need_file(){ [[ -f "$ROOT/$1" ]] || fail "missing $1"; pass "file $1"; }
need_text(){ grep -Fq -- "$2" "$ROOT/$1" || fail "$1 missing marker: $2"; pass "$1 :: $2"; }

# 0.0.6 source/tool inventory that must survive VELOCITY work.
for f in \
  src/qrxdb_verify_tool.c src/qrxdb_salvage_tool.c src/qrxdb_compact_tool.c src/qrxdb_snapshot_tool.c \
  src/storage/qrxdb_shutdown.c src/storage/qrxdb_shutdown.h src/openssl_applink.c \
  scripts/build-linux-x64-static.sh scripts/build-macos-static.sh scripts/build-windows-x64-static.ps1 \
  scripts/build-openssl-3.6.2-linux-static.sh; do need_file "$f"; done

# OpenSSL/PQC and Windows build protection.
need_text CMakeLists.txt 'option(QRX_REQUIRE_PQC'
need_text CMakeLists.txt 'VERSION_LESS "3.5.0"'
need_text CMakeLists.txt 'src/openssl_applink.c'

# CLI auto-network behavior from 0.0.6.
need_text src/qrx_cli.c 'qrx_detect_network'
need_text src/qrx_cli.c 'getenv("QRX_NETWORK")'
need_text src/qrx_cli.c 'current_network'
need_text src/qrxd.c 'qrx_write_current_network'

# Strict nonce protection from 0.0.6.
need_text src/qrx.c 'invalid nonce: expected lane nonce + 1'
need_text src/qrx.c 'amount plus fee'

# 0.0.6 wallet/mobile/dashboard command surface.
commands=(
getinfo getnewaddress listaddresses getbalance getaddressnonce getblockcount
getblockchaininfo getnetworkinfo getnodestatus getuptime getbuildinfo getmempoolinfo
getrecentblocks getrecenttransactions getvalidatorstatus getblockproducerinfo getfeeinfo
getpeerinfo getstakinginfo getwalletinfo getreward getparams gethalving getforks getactivefork
createrawtransaction signrawtransactionwithwallet decoderawtransaction gettxid sendtoaddress
sendrawtransaction history addnode listpeers peerstatus banscores stake delegate validator-set
tokenomics getdevaddress faucet createswap redeemswap refundswap getswap listswaps
shielded-address shield shielded-balance shielded-send unshield shielded-history
stealth-address stealth-send stealth-scan stealth-history privacy-feature-status stop
)
for c in "${commands[@]}"; do
  grep -Fq "$c" "$ROOT/src/qrx_cli.c" || fail "0.0.6 CLI command missing: $c"
done
pass "all ${#commands[@]} legacy 0.0.6 CLI commands still present"

# Dashboard RPC handlers must remain wired into qrxd.
for c in getnodestatus getblockchaininfo getnetworkinfo getuptime getbuildinfo getmempoolinfo getrecentblocks getrecenttransactions getvalidatorstatus getblockproducerinfo getfeeinfo; do
  grep -Fq "\"$c\"" "$ROOT/src/qrxd.c" || fail "0.0.6 dashboard RPC missing: $c"
done
pass "0.0.6 server dashboard RPC handlers still present"

# Mobile wallet raw transaction pipeline.
for c in createrawtransaction signrawtransactionwithwallet decoderawtransaction gettxid sendrawtransaction; do
  grep -Fq "$c" "$ROOT/src/qrxd.c" || fail "0.0.6 mobile-wallet RPC missing: $c"
done
pass "0.0.6 mobile-wallet raw-TX pipeline still present"

echo "RESULT: QRX Core 0.0.6 regression feature audit PASSED"
