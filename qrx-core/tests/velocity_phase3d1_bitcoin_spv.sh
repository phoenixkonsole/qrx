#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./build-p3d1/qrx}"
[[ -x "$BIN" ]] || { echo "qrx binary not executable: $BIN" >&2; exit 1; }
T="$(mktemp -d /tmp/qrx-velocity-phase3d1.XXXXXX)"
trap 'rm -rf "$T"' EXIT

"$BIN" init-chain "$T/chain" 20 5000 2100000000000000 25000000 1000000000000 qrx-regtest 1 5152583036 QRX-Velocity-P3D1 >/dev/null
wallet_new(){ QRX_PASSPHRASE=test "$BIN" seed-new "$1" >/dev/null; }
wallet_info(){
  local W="$1" PREFIX="$2"
  eval "${PREFIX}_ADDR=\$(tr -d '\r\n' < '$W/address.txt')"
  eval "${PREFIX}_ED=\$(openssl pkey -pubin -in '$W/ed25519_pub.pem' -outform DER 2>/dev/null | tail -c 32 | od -An -tx1 | tr -d ' \n')"
  eval "${PREFIX}_ML=\$(base64 -w0 < '$W/mldsa65_pub.pem')"
}
btc_pub_new(){
  local PREFIX="$1"
  openssl ecparam -name secp256k1 -genkey -noout -out "$T/${PREFIX}.btc.pem" 2>/dev/null
  local PUB
  PUB="$(openssl ec -in "$T/${PREFIX}.btc.pem" -pubout -conv_form compressed -outform DER 2>/dev/null | tail -c 33 | od -An -tx1 | tr -d ' \n')"
  eval "${PREFIX}_BTC_PUB='$PUB'"
}
wallet_new "$T/seller_owner"; wallet_new "$T/seller_agent"; wallet_new "$T/buyer_owner"; wallet_new "$T/buyer_agent"
wallet_info "$T/seller_owner" SO; wallet_info "$T/seller_agent" SA; wallet_info "$T/buyer_owner" BO; wallet_info "$T/buyer_agent" BA
btc_pub_new BUYER; btc_pub_new SELLER
"$BIN" faucet "$T/chain" "$BO_ADDR" 20000000000 >/dev/null
"$BIN" faucet "$T/chain" "$SO_ADDR" 10000000 >/dev/null
"$BIN" faucet "$T/chain" "$BA_ADDR" 10000000 >/dev/null
"$BIN" faucet "$T/chain" "$SA_ADDR" 10000000 >/dev/null

# Register narrowly scoped cross-chain trading agents.
"$BIN" create-agent-register-raw-tx "$T/chain" "$BO_ADDR" "$BA_ADDR" "$BA_ED" "$BA_ML" 'TRADE_CROSSCHAIN' 1000000 5000000 'BTC/QUB' 4000 "$BO_ED" "$BO_ML" 1 4000 > "$T/bareg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/bareg.raw" "$T/bareg.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/bareg.signed" >/dev/null
"$BIN" create-agent-register-raw-tx "$T/chain" "$SO_ADDR" "$SA_ADDR" "$SA_ED" "$SA_ML" 'TRADE_CROSSCHAIN' 1000000 5000000 'BTC/QUB' 4000 "$SO_ED" "$SO_ML" 1 4000 > "$T/sareg.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_owner" "$T/chain" "$T/sareg.raw" "$T/sareg.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/sareg.signed" >/dev/null

SECRET=616263
HASH="$(printf 'abc' | openssl dgst -sha256 | awk '{print $NF}')"
SATS=100000
SELL_PRICE=4800000000000
BUY_LIMIT=5000000000000
QREFUND=2000
"$BIN" create-crosschain-sell-raw-tx "$T/chain" "$SA_ADDR" "$SO_ADDR" "$SATS" "$SELL_PRICE" 700 "$SELLER_BTC_PUB" 6 "$SA_ED" "$SA_ML" 3 3000 0 > "$T/sell.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_agent" "$T/chain" "$T/sell.raw" "$T/sell.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/sell.signed" >/dev/null
"$BIN" create-crosschain-buy-raw-tx "$T/chain" "$BA_ADDR" "$BO_ADDR" "$SATS" "$BUY_LIMIT" 700 "$HASH" "$BUYER_BTC_PUB" "$QREFUND" "$BA_ED" "$BA_ML" 3 3000 0 > "$T/buy.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_agent" "$T/chain" "$T/buy.raw" "$T/buy.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/buy.signed" >/dev/null
BUY_ID="$($BIN txid "$T/chain" "$T/buy.signed")"
SID="$($BIN order-status "$T/chain" "$BUY_ID" | awk -F= '$1=="crosschain_session_id"{print $2}')"
[[ -n "$SID" ]]
SPK="$($BIN crosschain-status "$T/chain" "$SID" | awk -F= '$1=="btc_scriptpubkey_hex"{print $2}')"
[[ "$SPK" == 0020* ]]
grep -q '^btc_required_confirmations=6$' < <("$BIN" crosschain-status "$T/chain" "$SID")

# Build a synthetic-but-PoW-valid regtest SPV header tree. The main block at
# height 1 contains exactly the funding transaction as its single Merkle leaf.
python3 - "$SPK" "$SATS" "$T/btc.env" <<'PY'
import hashlib, struct, sys
spk=bytes.fromhex(sys.argv[1]); sats=int(sys.argv[2]); out=sys.argv[3]
gen_hex="0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000"
gen=bytes.fromhex(gen_hex)
def h256(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def disp(d): return d[::-1].hex()
def target(bits):
    e=bits>>24; m=bits&0x007fffff
    return m >> (8*(3-e)) if e<=3 else m << (8*(e-3))
def mine(prev, merkle, ts):
    bits=0x207fffff
    for nonce in range(0, 2_000_000):
        hdr=struct.pack('<I',1)+prev+merkle+struct.pack('<III',ts,bits,nonce)
        d=h256(hdr)
        if int.from_bytes(d,'little') <= target(bits): return hdr,d
    raise RuntimeError('regtest header mining failed')
# Normal serialized transaction with one fake input and one expected P2WSH output.
raw=(struct.pack('<I',2)+b'\x01'+b'\x11'*32+struct.pack('<I',0)+b'\x00'+struct.pack('<I',0xffffffff)+
     b'\x01'+struct.pack('<Q',sats)+bytes([len(spk)])+spk+struct.pack('<I',0))
txd=h256(raw); txid=disp(txd)
# Give the funding transaction a real one-level Merkle branch so the test
# exercises branch ordering/endianness instead of only the single-leaf case.
other=h256(b'QRX-SPV-secondary-merkle-leaf')
funding_merkle=h256(txd+other)
gen_d=h256(gen); t0=1296688602
main=[]; prev=gen_d
for h in range(1,9):
    merkle=funding_merkle if h==1 else hashlib.sha256(f'main-{h}'.encode()).digest()
    hdr,d=mine(prev,merkle,t0+h*600); main.append((hdr,d)); prev=d
fork=[]; prev=gen_d
for h in range(1,8):
    merkle=hashlib.sha256(f'fork-{h}'.encode()).digest()
    hdr,d=mine(prev,merkle,t0+h*601); fork.append((hdr,d)); prev=d
with open(out,'w') as f:
    f.write('GENESIS_HEADER='+gen_hex+'\n')
    f.write('BTCRAW='+raw.hex()+'\n')
    f.write('BTCTXID='+txid+'\n')
    f.write('BTCBRANCH='+disp(other)+'\n')
    f.write('MAIN1_HASH='+disp(main[0][1])+'\n')
    for i,(hdr,d) in enumerate(main,1): f.write(f'MAIN{i}_HEADER={hdr.hex()}\n')
    for i,(hdr,d) in enumerate(fork,1): f.write(f'FORK{i}_HEADER={hdr.hex()}\n')
PY
# shellcheck disable=SC1090
source "$T/btc.env"

submit_header(){
  local H="$1"
  "$BIN" create-btc-spv-header-raw-tx "$T/chain" "$BO_ADDR" "$H" "$BO_ED" "$BO_ML" 20 4000 0 > "$T/spv.raw"
  QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/spv.raw" "$T/spv.signed" >/dev/null
  "$BIN" verify "$T/chain" "$T/spv.signed" >/dev/null
  "$BIN" applytx "$T/chain" "$T/spv.signed" >/dev/null
}

# SPV state must be consensus-initialized by the actual Bitcoin regtest genesis header.
"$BIN" btc-spv-info "$T/chain" | grep -q '^initialized=false$'
submit_header "$GENESIS_HEADER"
for i in 1 2 3 4 5 6; do eval "H=\$MAIN${i}_HEADER"; submit_header "$H"; done
"$BIN" btc-spv-info "$T/chain" > "$T/spv.info"
grep -q '^initialized=true$' "$T/spv.info"; grep -q '^best_height=6$' "$T/spv.info"; grep -q '^consensus_committed=true$' "$T/spv.info"

# A valid header chain alone is NOT enough: no QUB release before funding proof is committed.
"$BIN" create-crosschain-redeem-raw-tx "$T/chain" "$SO_ADDR" "$SID" "$SECRET" "$SO_ED" "$SO_ML" 4 4000 0 > "$T/preproof.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/seller_owner" "$T/chain" "$T/preproof.raw" "$T/preproof.signed" >/dev/null
if "$BIN" verify "$T/chain" "$T/preproof.signed" >/dev/null 2>&1; then echo 'redeem unexpectedly valid before SPV funding proof' >&2; exit 1; fi

# Read-only preflight verifies txid, HTLC output, Merkle inclusion, best chain and confirmations.
"$BIN" crosschain-verify-funding "$T/chain" "$SID" "$BTCRAW" "$MAIN1_HASH" 0 "$BTCBRANCH" > "$T/preflight"
grep -q '^merkle_proof_valid=true$' "$T/preflight"; grep -q '^confirmations=6$' "$T/preflight"; grep -q '^safe_to_reveal_secret=true$' "$T/preflight"; grep -q '^state_mutated=false$' "$T/preflight"

# Commit the proof itself through a signed QRX transaction, so every validator has identical SPV settlement state.
"$BIN" create-btc-spv-funding-proof-raw-tx "$T/chain" "$BO_ADDR" "$SID" "$BTCRAW" "$MAIN1_HASH" 0 "$BTCBRANCH" "$BO_ED" "$BO_ML" 21 4000 0 > "$T/proof.raw"
QRX_PASSPHRASE=test "$BIN" signrawtransactionwithwallet "$T/buyer_owner" "$T/chain" "$T/proof.raw" "$T/proof.signed" >/dev/null
"$BIN" verify "$T/chain" "$T/proof.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/proof.signed" >/dev/null
"$BIN" crosschain-funding "$T/chain" "$SID" > "$T/funding"
grep -q '^bitcoin_spv_verified=true$' "$T/funding"; grep -q '^confirmations=6$' "$T/funding"; grep -q '^safe_to_reveal_secret=true$' "$T/funding"
"$BIN" btc-spv-confirmations "$T/chain" "$BTCTXID" | grep -q '^confirmations=6$'

# Create a higher-work fork that excludes the funding transaction. The stored proof remains cryptographically valid,
# but it is no longer on the active Bitcoin chain and QRX must block settlement.
for i in 1 2 3 4 5 6 7; do eval "H=\$FORK${i}_HEADER"; submit_header "$H"; done
"$BIN" btc-spv-info "$T/chain" | grep -q '^best_height=7$'
"$BIN" crosschain-security "$T/chain" "$SID" > "$T/reorg.sec"
grep -q '^active_best_work_chain=false$' "$T/reorg.sec"; grep -q '^safe_to_reveal_secret=false$' "$T/reorg.sec"
if "$BIN" verify "$T/chain" "$T/preproof.signed" >/dev/null 2>&1; then echo 'redeem unexpectedly valid during Bitcoin reorg' >&2; exit 1; fi

# Extend original funding branch until it again has strictly more chainwork. QRX must restore safety deterministically.
for i in 7 8; do eval "H=\$MAIN${i}_HEADER"; submit_header "$H"; done
"$BIN" btc-spv-info "$T/chain" | grep -q '^best_height=8$'
"$BIN" crosschain-security "$T/chain" "$SID" > "$T/restored.sec"
grep -q '^active_best_work_chain=true$' "$T/restored.sec"; grep -q '^confirmations=8$' "$T/restored.sec"; grep -q '^safe_to_reveal_secret=true$' "$T/restored.sec"

# The QUB recipient may now atomically redeem using the Bitcoin-revealed preimage.
SO_BEFORE="$($BIN balance "$T/chain" "$SO_ADDR")"
"$BIN" verify "$T/chain" "$T/preproof.signed" >/dev/null
"$BIN" applytx "$T/chain" "$T/preproof.signed" >/dev/null
LOCKED="$($BIN crosschain-status "$T/chain" "$SID" | awk -F= '$1=="qub_atoms"{print $2}')"
grep -q '^status=redeemed$' < <("$BIN" crosschain-status "$T/chain" "$SID")
[[ $(( $($BIN balance "$T/chain" "$SO_ADDR") - SO_BEFORE )) -eq "$LOCKED" ]]

"$BIN" crosschain-info "$T/chain" | grep -q '^bitcoin_spv_consensus=true$'
"$BIN" trading-info "$T/chain" | grep -q '^crosschain_bitcoin_spv_consensus=true$'
echo "VELOCITY Phase 3D.1 Bitcoin SPV consensus + reorg safety smoke test PASSED"
