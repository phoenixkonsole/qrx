#ifndef QRX_VELOCITY_SCHEDULER_H
#define QRX_VELOCITY_SCHEDULER_H

#include <stddef.h>
#include <stdint.h>
#include "qrx_velocity_mempool.h"

#define QRX_VELOCITY_SCHEDULER_VERSION 1u

typedef struct {
    size_t from;
    size_t to;
} QrxVelocityDependencyEdge;

typedef struct {
    size_t node_count;
    uint32_t *waves;
    uint32_t wave_count;
    QrxVelocityDependencyEdge *edges;
    size_t edge_count;
    size_t edge_cap;
    uint64_t static_conflicts;
    uint64_t barrier_fences;
    uint64_t barrier_nodes;
    uint32_t critical_path_nodes;
    uint32_t max_parallel_width;
    char schedule_hash[129];
} QrxVelocityBlockSchedule;

/* Build a deterministic dependency graph for an already deterministically
   ordered block/mempool candidate list. Static access-key dependencies are
   represented as chains (last accessor -> current accessor), while barriers
   are full segment fences. Hidden dynamic dependencies are still resolved by
   the Phase 4E runtime OCC layer. */
int qrx_velocity_block_schedule_build(QrxVelocityMempoolEntry *const *entries,
                                      size_t count,
                                      QrxVelocityBlockSchedule *out);

void qrx_velocity_block_schedule_free(QrxVelocityBlockSchedule *schedule);

#endif
