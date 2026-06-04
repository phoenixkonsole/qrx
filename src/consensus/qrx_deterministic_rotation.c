#include "qrx_deterministic_rotation.h"
#include <stdint.h>

static uint64_t qrx_mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static uint64_t qrx_hash_round_input(
    const qrx_consensus_round_t *round,
    const qrx_validator_t *validator
) {
    uint64_t v = 0;

    for(int i = 0; i < 8; i++) {
        v <<= 8;
        v |= round->previous_block_hash[i];
    }

    uint64_t pk = 0;

    for(int i = 0; i < 8; i++) {
        pk <<= 8;
        pk |= validator->pubkey[i];
    }

    return qrx_mix64(v ^ pk ^ (uint64_t)round->height);
}

uint64_t qrx_consensus_validator_score(
    const qrx_consensus_round_t *round,
    const qrx_validator_t *validator
) {
    if(!round || !validator) return UINT64_MAX;
    if(!validator->active) return UINT64_MAX;
    if(validator->stake_atoms == 0) return UINT64_MAX;

    uint64_t base = qrx_hash_round_input(round, validator);

    uint64_t weighted = base / validator->stake_atoms;

    if(weighted == 0)
        weighted = 1;

    return weighted;
}

int qrx_consensus_select_proposer(
    const qrx_consensus_round_t *round,
    const qrx_validator_t *validators,
    size_t validator_count
) {
    if(!round || !validators || validator_count == 0)
        return -1;

    uint64_t best_score = UINT64_MAX;
    int best_index = -1;

    for(size_t i = 0; i < validator_count; i++) {
        uint64_t score =
            qrx_consensus_validator_score(round, &validators[i]);

        if(score < best_score) {
            best_score = score;
            best_index = (int)i;
        }
    }

    return best_index;
}
