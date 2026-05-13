#pragma once
#include <stdint.h>

#define QRX_MAX_FUTURE_DRIFT_SECONDS 300
#define QRX_MTP_WINDOW 11

int verify_block_timestamp(uint64_t parent_ts,
                           uint64_t candidate_ts,
                           uint64_t median_time_past,
                           uint64_t local_time);
