#pragma once
#include <stdint.h>

int qrx_verify_consensus_timestamp(
    uint64_t block_ts,
    uint64_t parent_ts,
    uint64_t median_past,
    uint64_t local_time,
    uint64_t max_future_drift);
