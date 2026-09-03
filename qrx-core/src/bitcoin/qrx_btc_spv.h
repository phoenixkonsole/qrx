#ifndef QRX_BTC_SPV_H
#define QRX_BTC_SPV_H

#include <stddef.h>
#include <stdint.h>
#include "qrxdb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QRX_BTC_SPV_HASH_HEX 65
#define QRX_BTC_SPV_CHAINWORK_HEX 96

typedef struct {
    char hash[QRX_BTC_SPV_HASH_HEX];
    char prev_hash[QRX_BTC_SPV_HASH_HEX];
    char merkle_root[QRX_BTC_SPV_HASH_HEX];
    char header_hex[161];
    char chainwork_hex[QRX_BTC_SPV_CHAINWORK_HEX];
    uint64_t height;
    uint32_t version;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    int active;
} QrxBtcSpvHeaderInfo;

typedef struct {
    char txid[QRX_BTC_SPV_HASH_HEX];
    char block_hash[QRX_BTC_SPV_HASH_HEX];
    uint64_t block_height;
    uint64_t confirmations;
    uint64_t merkle_index;
    int merkle_valid;
    int active_chain;
} QrxBtcSpvProofResult;

typedef struct {
    char txid[QRX_BTC_SPV_HASH_HEX];
    int vout;
    int64_t sats;
} QrxBtcTxOutputMatch;

int qrx_btc_spv_network_valid(const char *network);
const char *qrx_btc_spv_genesis_header_hex(const char *network);
int qrx_btc_spv_init(QrxDB *db, const char *network, char *err, size_t err_sz);
int qrx_btc_spv_stage_header(QrxDB *db, QrxDBBatch *batch, const char *network,
                             const char *header_hex, QrxBtcSpvHeaderInfo *out,
                             int *became_best, char *err, size_t err_sz);
int qrx_btc_spv_get_header(QrxDB *db, const char *network, const char *hash_or_height,
                           QrxBtcSpvHeaderInfo *out, char *err, size_t err_sz);
int qrx_btc_spv_get_best(QrxDB *db, const char *network, QrxBtcSpvHeaderInfo *out,
                         char *err, size_t err_sz);
int qrx_btc_spv_confirmations(QrxDB *db, const char *network, const char *block_hash,
                              uint64_t block_height, uint64_t *confirmations,
                              int *active, char *err, size_t err_sz);
int qrx_btc_spv_verify_merkle(QrxDB *db, const char *network, const char *txid,
                              const char *block_hash, uint64_t tx_index,
                              const char *branch_csv, QrxBtcSpvProofResult *out,
                              char *err, size_t err_sz);
int qrx_btc_tx_find_output(const char *rawtx_hex, int64_t expected_sats,
                           const char *expected_scriptpubkey_hex,
                           QrxBtcTxOutputMatch *out, char *err, size_t err_sz);
int qrx_btc_spv_stage_proof(QrxDBBatch *batch, const char *network,
                            const QrxBtcSpvProofResult *proof,
                            int vout, int64_t sats, const char *scriptpubkey_hex,
                            char *err, size_t err_sz);
int qrx_btc_spv_get_stored_proof(QrxDB *db, const char *network, const char *txid,
                                 QrxBtcSpvProofResult *out, int *vout, int64_t *sats,
                                 char *scriptpubkey_hex, size_t script_sz,
                                 char *err, size_t err_sz);

#ifdef __cplusplus
}
#endif

#endif
