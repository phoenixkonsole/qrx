#ifndef QRX_VELOCITY_MEMPOOL_H
#define QRX_VELOCITY_MEMPOOL_H

#include <stddef.h>
#include <stdint.h>

#define QRX_VELOCITY_MEMPOOL_SHARDS 32u
#define QRX_VELOCITY_MAX_ACCESS_KEYS 12u
#define QRX_VELOCITY_TXID_HEX 128u

#define QRX_VELOCITY_ADAPTER_TRANSFER 0u
#define QRX_VELOCITY_ADAPTER_STATEFUL 1u
#define QRX_VELOCITY_ADAPTER_BARRIER 2u
#define QRX_VELOCITY_ADAPTER_DYNAMIC 3u

typedef struct {
    char txid[QRX_VELOCITY_TXID_HEX + 1];
    char *tx;
    size_t tx_len;
    long long fee;
    long long nonce;
    long long lane;
    uint64_t arrival_seq;
    uint32_t shard;
    uint8_t adapter_class;
    char tx_type[48];
    char from[385];
    char to[385];
    char access[QRX_VELOCITY_MAX_ACCESS_KEYS][512];
    uint32_t access_count;
} QrxVelocityMempoolEntry;

typedef struct QrxVelocityShard QrxVelocityShard;
typedef struct QrxVelocityMempool QrxVelocityMempool;

typedef struct {
    char **txids;
    char **txs;
    uint32_t *waves;
    size_t count;
    uint32_t wave_count;
    uint64_t conflicts;
    uint64_t dependency_edges;
    uint64_t barrier_fences;
    uint64_t barrier_nodes;
    uint32_t critical_path_nodes;
    uint32_t max_parallel_width;
    char schedule_hash[129];
} QrxVelocityPlan;

typedef struct {
    uint64_t accepted;
    uint64_t duplicates;
    uint64_t rejected_full;
    uint64_t wal_records;
    uint64_t recovered_records;
    uint64_t removed;
    uint64_t bytes;
    uint64_t entries;
    uint64_t max_entries;
    uint32_t shards;
} QrxVelocityMempoolStats;

typedef int (*QrxVelocityVerifyFn)(void *ctx, const char *tx_text, char *err, size_t err_sz);

typedef struct {
    uint64_t ok;
    uint64_t failed;
    uint32_t workers;
    uint64_t elapsed_us;
} QrxVelocityVerifyStats;

struct QrxVelocityMempool {
    char node_dir[1024];
    char wal_path[1200];
    QrxVelocityShard *shards;
    size_t max_entries;
    uint64_t next_seq;
    QrxVelocityMempoolStats stats;
#ifdef _WIN32
    void *mutex_handle;
#else
    void *mutex_storage[8];
#endif
    void *wal_file;
    uint64_t wal_since_sync;
    uint64_t wal_syncs;
    int mutex_ready;
    int initialized;
};

int qrx_velocity_mempool_open(QrxVelocityMempool *pool, const char *node_dir, size_t max_entries);
void qrx_velocity_mempool_close(QrxVelocityMempool *pool);
int qrx_velocity_mempool_add(QrxVelocityMempool *pool, const char *tx_text, char out_txid[129]);
int qrx_velocity_mempool_remove(QrxVelocityMempool *pool, const char *txid);
int qrx_velocity_mempool_checkpoint(QrxVelocityMempool *pool);
int qrx_velocity_mempool_plan(QrxVelocityMempool *pool, size_t max_txs, QrxVelocityPlan *plan);
void qrx_velocity_plan_free(QrxVelocityPlan *plan);
int qrx_velocity_parallel_verify(const QrxVelocityPlan *plan, uint32_t workers, QrxVelocityVerifyFn fn, void *ctx, unsigned char **valid_mask, QrxVelocityVerifyStats *stats);
int qrx_velocity_mempool_stats(QrxVelocityMempool *pool, QrxVelocityMempoolStats *out);
int qrx_velocity_tx_metadata(const char *tx_text, QrxVelocityMempoolEntry *out);
uint8_t qrx_velocity_tx_adapter_class(const char *tx_text);
int qrx_velocity_entries_conflict(const QrxVelocityMempoolEntry *a, const QrxVelocityMempoolEntry *b);

#endif
