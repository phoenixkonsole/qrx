#!/usr/bin/env bash
set -euo pipefail
BIN=${1:-./build/qrx}
export QRX_PASSPHRASE=testpass
rm -rf tchain alice bob node1 node2
$BIN init-chain tchain 20 5000 1000 10 100 >/dev/null
$BIN seed-new alice >/dev/null
$BIN seed-new bob >/dev/null
ALICE=$($BIN address alice)
BOB=$($BIN address bob)
$BIN faucet tchain "$ALICE" 60 >/dev/null
$BIN faucet tchain "$BOB" 40 >/dev/null
$BIN stake tchain alice 50 >/dev/null
$BIN stake tchain bob 30 >/dev/null
$BIN node-init node1 tchain alice 127.0.0.1 7501 >/dev/null
$BIN node-init node2 tchain bob 127.0.0.1 7502 >/dev/null
BLOCK=$($BIN propose-block node1 | tail -n1)
$BIN verify-block tchain "$BLOCK" >/dev/null
$BIN validator-set-at tchain 1 0 >/dev/null
$BIN vote-block node1 "$BLOCK" >/dev/null
$BIN vote-block node2 "$BLOCK" >/dev/null
cp node1/outbox/votes/*.vote tchain/consensus/votes/
cp node2/outbox/votes/*.vote tchain/consensus/votes/
$BIN finalize-block tchain "$BLOCK" >/dev/null
$BIN reward-epoch-auto tchain 1000 >/dev/null
TOK=$($BIN tokenomics tchain)
[[ "$TOK" == *"minted_supply=110"* ]]
[[ -f node1/consensus.lock ]]
echo rc62_tokenomics_consensus: OK
