#include "qrx_slashing.h"
#include "qrx_finality_state.h"
#include <string.h>

void qrx_finality_state_init(
    qrx_finality_state_t *st,
    int64_t height,
    int32_t round,
    const uint8_t block_hash[QRX_FINALITY_HASH_SIZE],
    uint64_t total_power
) {
    if(!st) return;
    memset(st, 0, sizeof(*st));
    st->height = height;
    st->round = round;
    st->total_power = total_power;
    if(block_hash)
        memcpy(st->proposed_block_hash, block_hash, QRX_FINALITY_HASH_SIZE);
}

int qrx_finality_state_add_vote(
    qrx_finality_state_t *st,
    const qrx_finality_vote_t *vote
) {
    if(!st || !vote) return 0;

    if(!qrx_finality_vote_matches(
        vote,
        st->height,
        st->round,
        vote->type,
        st->proposed_block_hash
    )) {
        return 0;
    }


    /*
     * Signature enforcement.
     */
    if(!qrx_vote_signature_verify(vote)) {
        return 0;
    }

    /*
     * Double-vote detection.
     */
    if(vote->type == QRX_VOTE_PREVOTE &&
       qrx_detect_double_vote(
           st->prevotes,
           st->prevote_count,
           vote
       )) {
        return 0;
    }

    if(vote->type == QRX_VOTE_PRECOMMIT &&
       qrx_detect_double_vote(
           st->precommits,
           st->precommit_count,
           vote
       )) {
        return 0;
    }

    if(vote->type == QRX_VOTE_PREVOTE) {
        if(st->prevote_count >= QRX_FINALITY_MAX_VOTES) return 0;
        st->prevotes[st->prevote_count++] = *vote;
        return 1;
    }

    if(vote->type == QRX_VOTE_PRECOMMIT) {
        if(st->precommit_count >= QRX_FINALITY_MAX_VOTES) return 0;
        st->precommits[st->precommit_count++] = *vote;
        return 1;
    }

    return 0;
}

int qrx_finality_state_try_finalize(
    qrx_finality_state_t *st
) {
    if(!st) return 0;
    if(st->finalized) return 1;

    int ok = qrx_finality_build_commit_certificate(
        st->precommits,
        st->precommit_count,
        st->height,
        st->round,
        st->proposed_block_hash,
        st->total_power,
        &st->commit_certificate
    );

    if(ok) {
        st->finalized = 1;
        return 1;
    }

    return 0;
}
