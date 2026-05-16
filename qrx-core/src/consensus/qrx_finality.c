#include "qrx_finality.h"
#include <string.h>

/*
 * QRX finality rule:
 * A block is final when >= 2/3 + 1 of validator power precommits
 * for the same block hash at the same height and round.
 */

uint64_t qrx_finality_quorum_power(uint64_t total_power) {
    return ((total_power * 2ULL) / 3ULL) + 1ULL;
}

int qrx_finality_has_quorum(
    uint64_t signed_power,
    uint64_t total_power
) {
    if(total_power == 0) return 0;
    return signed_power >= qrx_finality_quorum_power(total_power);
}

int qrx_finality_vote_matches(
    const qrx_finality_vote_t *vote,
    int64_t height,
    int32_t round,
    qrx_vote_type_t type,
    const uint8_t block_hash[QRX_FINALITY_HASH_SIZE]
) {
    if(!vote || !block_hash) return 0;
    if(vote->height != height) return 0;
    if(vote->round != round) return 0;
    if(vote->type != type) return 0;
    if(memcmp(vote->block_hash, block_hash, QRX_FINALITY_HASH_SIZE) != 0) return 0;
    if(vote->validator_power == 0) return 0;
    return 1;
}

int qrx_finality_build_commit_certificate(
    const qrx_finality_vote_t *votes,
    size_t vote_count,
    int64_t height,
    int32_t round,
    const uint8_t block_hash[QRX_FINALITY_HASH_SIZE],
    uint64_t total_power,
    qrx_commit_certificate_t *out
) {
    if(!votes || !block_hash || !out) return 0;

    uint64_t signed_power = 0;
    size_t matched_votes = 0;

    for(size_t i = 0; i < vote_count; i++) {
        if(qrx_finality_vote_matches(
            &votes[i],
            height,
            round,
            QRX_VOTE_PRECOMMIT,
            block_hash
        )) {
            /*
             * NOTE:
             * In the full validator-set integration, duplicate validator pubkeys
             * must be counted only once. This module expects canonicalized vote input
             * or validator-set backed deduplication by caller.
             */
            signed_power += votes[i].validator_power;
            matched_votes++;
        }
    }

    memset(out, 0, sizeof(*out));
    out->height = height;
    out->round = round;
    memcpy(out->block_hash, block_hash, QRX_FINALITY_HASH_SIZE);
    out->total_power = total_power;
    out->signed_power = signed_power;
    out->vote_count = matched_votes;

    return qrx_finality_has_quorum(signed_power, total_power);
}

int qrx_finality_verify_commit_certificate(
    const qrx_commit_certificate_t *cert
) {
    if(!cert) return 0;
    if(cert->total_power == 0) return 0;
    if(cert->signed_power > cert->total_power) return 0;
    return qrx_finality_has_quorum(cert->signed_power, cert->total_power);
}
