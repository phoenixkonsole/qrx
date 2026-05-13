#include "qrx_timestamp_consensus.h"

int verify_block_timestamp(uint64_t parent_ts,
                           uint64_t candidate_ts,
                           uint64_t median_time_past,
                           uint64_t local_time)
{
    if(candidate_ts <= parent_ts)
        return 0;

    if(candidate_ts < median_time_past)
        return 0;

    if(candidate_ts > (local_time + QRX_MAX_FUTURE_DRIFT_SECONDS))
        return 0;

    return 1;
}
