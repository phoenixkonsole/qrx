#ifndef QRXDB_H
#define QRXDB_H

#include <stddef.h>
#include <stdint.h>

#define QRXDB_SCHEMA_VERSION 4
#define QRXDB_MAGIC 0x51525844u /* QRXD */
#define QRXDB_DATA_MAGIC 0x51444234u /* QDB4 */
#define QRXDB_WAL_MAGIC  0x51574134u /* QWA4 */
#define QRXDB_DEFAULT_MAP_SIZE (64ULL * 1024ULL * 1024ULL)
#define QRXDB_WAL_SEGMENT_SIZE (64ULL * 1024ULL * 1024ULL)
#define QRXDB_MERKLE_HASH_SIZE 64

typedef struct {
    uint32_t magic;
    uint32_t schema_version;
    uint64_t timestamp;
    uint32_t key_len;
    uint32_t value_len;
    uint32_t crc32;
} QrxDBRecordHeader;

typedef struct {
    uint32_t magic;
    uint32_t schema_version;
    uint64_t header_size;
    uint64_t map_size;
    uint64_t write_offset;
    uint64_t generation;
    uint8_t  merkle_root[QRXDB_MERKLE_HASH_SIZE];
    uint32_t crc32;
} QrxDBFileHeader;

typedef struct {
    const char *key;
    const char *value;
    uint32_t key_len;
    uint32_t value_len;
    uint64_t generation;
    uint64_t offset;
} QrxDBView;

typedef struct {
    uint64_t generation;
    uint64_t write_offset;
    uint8_t merkle_root[QRXDB_MERKLE_HASH_SIZE];
} QrxDBReadTxn;

typedef struct QrxDBIndexEntry {
    char *key;
    uint32_t key_len;
    uint64_t offset;
    uint64_t generation;
} QrxDBIndexEntry;

typedef struct {
    char base_path[1024];
    char data_path[1024];
    char wal_path[1024];      /* Current WAL segment path, kept for compatibility. */
    char wal_dir[1024];
    char index_path[1024];
    char snapshot_path[1024];

    int initialized;

    void *map;
    uint64_t map_size;
    uint64_t write_offset;
    uint64_t generation;
    uint64_t wal_segment_id;
    uint64_t wal_segment_offset;
    uint8_t merkle_root[QRXDB_MERKLE_HASH_SIZE];

    QrxDBIndexEntry *index;
    size_t index_count;
    size_t index_cap;
    uint64_t compacted_until_generation;
    uint64_t recovered_transactions;

#ifdef _WIN32
    void *file_handle;
    void *mapping_handle;
#else
    int fd;
#endif
} QrxDB;

int qrxdb_init(QrxDB *db, const char *chain_dir);
int qrxdb_put(QrxDB *db, const char *key, const char *value);
int qrxdb_get(QrxDB *db, const char *key, char *out, size_t out_sz);
int qrxdb_get_view(QrxDB *db, const char *key, QrxDBView *view);
int qrxdb_snapshot(QrxDB *db, const char *snapshot_name);
int qrxdb_snapshot_signed(QrxDB *db, const char *snapshot_name, const char *wallet_dir, const char *passphrase);
int qrxdb_snapshot_verify_signature(QrxDB *db, const char *snapshot_name);
int qrxdb_recover(QrxDB *db);
int qrxdb_compact(QrxDB *db);
int qrxdb_sync(QrxDB *db);
int qrxdb_close(QrxDB *db);
int qrxdb_read_txn_begin(QrxDB *db, QrxDBReadTxn *txn);
int qrxdb_get_view_at(QrxDB *db, const QrxDBReadTxn *txn, const char *key, QrxDBView *view);
int qrxdb_parallel_validation_prepare(QrxDB *db, QrxDBReadTxn *snapshot);
int qrxdb_verify(QrxDB *db);
int qrxdb_rebuild_index(QrxDB *db);
int qrxdb_salvage(QrxDB *db);
uint64_t qrxdb_generation(QrxDB *db);
uint64_t qrxdb_write_offset(QrxDB *db);
const uint8_t *qrxdb_merkle_root(QrxDB *db);

/* Chain-pipeline integration indexes. All hashes are QRX primary SHA3-512 hex unless stated otherwise. */
int qrxdb_chain_put_block(QrxDB *db, uint64_t height, const char *block_hash, const char *block_text);
int qrxdb_chain_index_tx(QrxDB *db, const char *tx_hash, const char *block_hash, uint64_t height, uint32_t tx_index, const char *tx_text);
int qrxdb_chain_get_block_by_hash(QrxDB *db, const char *block_hash, QrxDBView *view);
int qrxdb_chain_get_block_hash_by_height(QrxDB *db, uint64_t height, char *out_hash, size_t out_sz);
int qrxdb_chain_get_tx_location(QrxDB *db, const char *tx_hash, char *out, size_t out_sz);
int qrxdb_chain_set_balance(QrxDB *db, const char *address, long long value);
int qrxdb_chain_get_balance(QrxDB *db, const char *address, long long *out_value);
int qrxdb_chain_set_nonce(QrxDB *db, const char *address, long long value);
int qrxdb_chain_get_nonce(QrxDB *db, const char *address, long long *out_value);
int qrxdb_chain_mark_applied(QrxDB *db, const char *tx_hash, uint64_t height);
int qrxdb_chain_is_applied(QrxDB *db, const char *tx_hash);
int qrxdb_chain_put_utxo(QrxDB *db, const char *tx_hash, uint32_t vout, const char *owner, long long amount, uint64_t height);
int qrxdb_chain_spend_utxo(QrxDB *db, const char *tx_hash, uint32_t vout, const char *spend_tx_hash, uint64_t height);
int qrxdb_chain_get_utxo(QrxDB *db, const char *tx_hash, uint32_t vout, char *out, size_t out_sz);

uint32_t qrxdb_crc32(const void *data, size_t len);

#endif
