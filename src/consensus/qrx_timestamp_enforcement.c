#include "qrx_timestamp_enforcement.h"

int qrx_verify_consensus_timestamp(
    uint64_t block_ts,
    uint64_t parent_ts,
    uint64_t median_past,
    uint64_t local_time,
    uint64_t max_future_drift)
{
    if(block_ts <= parent_ts) return 0;
    if(block_ts < median_past) return 0;
    if(block_ts > (local_time + max_future_drift)) return 0;
    return 1;
}
