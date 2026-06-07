#pragma once
#include <stdint.h>
#include <stddef.h>
#include "qrx_finality.h"

#define QRX_MAX_SLASH_EVENTS 4096

typedef enum {
    QRX_SLASH_DOUBLE_PREVOTE = 1,
    QRX_SLASH_DOUBLE_PRECOMMIT = 2,
    QRX_SLASH_INVALID_SIGNATURE = 3
} qrx_slash_reason_t;

typedef struct {
    uint8_t validator_pubkey[QRX_FINALITY_PUB_SIZE];
    qrx_slash_reason_t reason;
    int64_t height;
    int32_t round;
    uint64_t penalty_atoms;
} qrx_slash_event_t;

typedef struct {
    qrx_slash_event_t events[QRX_MAX_SLASH_EVENTS];
    size_t count;
} qrx_slashing_state_t;

int qrx_vote_signature_verify(
    const qrx_finality_vote_t *vote
);

int qrx_detect_double_vote(
    const qrx_finality_vote_t *existing_votes,
    size_t existing_vote_count,
    const qrx_finality_vote_t *candidate
);

int qrx_apply_slash(
    qrx_slashing_state_t *st,
    const qrx_finality_vote_t *vote,
    qrx_slash_reason_t reason
);
