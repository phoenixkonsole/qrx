#ifndef QRX_VELOCITY_MVCC_H
#define QRX_VELOCITY_MVCC_H

#include <stddef.h>
#include <stdint.h>
#include "../qrxdb.h"
#include "qrx_velocity_mempool.h"

#define QRX_MVCC_OK 0
#define QRX_MVCC_RETRY 1
#define QRX_MVCC_UNSUPPORTED 2
#define QRX_MVCC_BARRIER 3
#define QRX_MVCC_ERROR -1

typedef struct {
    char *key;
    char *value;
} QrxVelocityMvccKV;

typedef struct {
    char txid[129];
    size_t plan_index;
    uint32_t wave;
    int status;
    long long fee_delta;
    uint8_t dynamic;
    uint8_t speculative;
    uint8_t retried;
    uint8_t conflict_loser;
    char dynamic_scope[512];
    uint64_t discovered_keys;
    uint64_t dynamic_trades;
    uint64_t expired_orders;
    QrxVelocityMvccKV *writes;
    size_t write_count;
    size_t write_cap;
    char **reads;
    size_t read_count;
    size_t read_cap;
    char **read_prefixes;
    size_t read_prefix_count;
    size_t read_prefix_cap;
} QrxVelocityMvccWriteSet;

typedef struct {
    QrxDBReadTxn snapshot;
    QrxVelocityMvccWriteSet *sets;
    size_t set_count;
    QrxVelocityMvccKV *merged;
    size_t merged_count;
    size_t merged_cap;
    long long fee_delta_total;
    uint32_t waves;
    uint32_t workers;
    uint64_t prepared;
    uint64_t unsupported;
    uint64_t barriers;
    uint64_t stateful_prepared;
    uint64_t dynamic_prepared;
    uint64_t dynamic_discovered_keys;
    uint64_t dynamic_trades;
    uint64_t expired_orders;
    uint64_t failed;
    uint64_t conflict_rechecks;
    uint64_t speculative_prepared;
    uint64_t runtime_read_keys;
    uint64_t runtime_read_prefixes;
    uint64_t conflict_edges;
    uint64_t deterministic_conflicts;
    uint64_t selective_retries;
    uint64_t speculative_winners;
} QrxVelocityMvccPrepared;

typedef struct {
    uint64_t snapshot_generation;
    uint64_t commit_generation;
    uint64_t prepared;
    uint64_t committed;
    uint64_t unsupported;
    uint64_t barriers;
    uint64_t stateful_prepared;
    uint64_t dynamic_prepared;
    uint64_t dynamic_discovered_keys;
    uint64_t dynamic_trades;
    uint64_t expired_orders;
    uint64_t failed;
    uint64_t merged_writes;
    uint64_t conflict_rechecks;
    uint64_t speculative_prepared;
    uint64_t runtime_read_keys;
    uint64_t runtime_read_prefixes;
    uint64_t conflict_edges;
    uint64_t deterministic_conflicts;
    uint64_t selective_retries;
    uint64_t speculative_winners;
    uint32_t waves;
    uint32_t workers;
    uint64_t prepare_us;
    uint64_t commit_us;
    char state_root[129];
} QrxVelocityMvccStats;

int qrx_velocity_mvcc_prepare_batch(QrxDB *db,
                                             const QrxVelocityPlan *plan,
                                             const unsigned char *valid_mask,
                                             uint32_t workers,
                                             long long height,
                                             QrxVelocityMvccPrepared *out,
                                             QrxVelocityMvccStats *stats);

int qrx_velocity_mvcc_commit(QrxDB *db,
                             QrxVelocityMvccPrepared *prepared,
                             QrxVelocityMvccStats *stats);

int qrx_velocity_mvcc_execute_batch(QrxDB *db,
                                             const QrxVelocityPlan *plan,
                                             const unsigned char *valid_mask,
                                             uint32_t workers,
                                             long long height,
                                             QrxVelocityMvccStats *stats);

/* Phase 4B API compatibility wrappers. They now dispatch through Phase 4E. */
int qrx_velocity_mvcc_prepare_transfer_batch(QrxDB *db,
                                             const QrxVelocityPlan *plan,
                                             const unsigned char *valid_mask,
                                             uint32_t workers,
                                             long long height,
                                             QrxVelocityMvccPrepared *out,
                                             QrxVelocityMvccStats *stats);

int qrx_velocity_mvcc_execute_transfer_batch(QrxDB *db,
                                             const QrxVelocityPlan *plan,
                                             const unsigned char *valid_mask,
                                             uint32_t workers,
                                             long long height,
                                             QrxVelocityMvccStats *stats);

void qrx_velocity_mvcc_prepared_free(QrxVelocityMvccPrepared *prepared);

#endif
