#pragma once
#include "qrx_finality.h"

#define QRX_FINALITY_MAX_VOTES 4096

typedef struct {
    int64_t height;
    int32_t round;
    uint8_t proposed_block_hash[QRX_FINALITY_HASH_SIZE];
    qrx_finality_vote_t prevotes[QRX_FINALITY_MAX_VOTES];
    qrx_finality_vote_t precommits[QRX_FINALITY_MAX_VOTES];
    size_t prevote_count;
    size_t precommit_count;
    uint64_t total_power;
    int finalized;
    qrx_commit_certificate_t commit_certificate;
} qrx_finality_state_t;

void qrx_finality_state_init(
    qrx_finality_state_t *st,
    int64_t height,
    int32_t round,
    const uint8_t block_hash[QRX_FINALITY_HASH_SIZE],
    uint64_t total_power
);

int qrx_finality_state_add_vote(
    qrx_finality_state_t *st,
    const qrx_finality_vote_t *vote
);

int qrx_finality_state_try_finalize(
    qrx_finality_state_t *st
);
