#pragma once
#include <stdint.h>
#include <stddef.h>

#define QRX_MAX_VALIDATORS 256

typedef struct {
    char address[160];
    uint64_t stake_atoms;
    uint8_t pubkey[32];
    int active;
} qrx_validator_t;

typedef struct {
    int64_t height;
    uint8_t previous_block_hash[32];
} qrx_consensus_round_t;

uint64_t qrx_consensus_validator_score(
    const qrx_consensus_round_t *round,
    const qrx_validator_t *validator
);

int qrx_consensus_select_proposer(
    const qrx_consensus_round_t *round,
    const qrx_validator_t *validators,
    size_t validator_count
);
