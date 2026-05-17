#include "qrx_slashing.h"
#include <string.h>

/*
 * Placeholder hybrid signature verification hook.
 *
 * Replace with:
 *  - Ed25519 verify
 *  - ML-DSA verify
 *  - combined hybrid enforcement
 */
int qrx_vote_signature_verify(
    const qrx_finality_vote_t *vote
) {
    if(!vote) return 0;

    /*
     * Current minimal enforcement:
     * signature must exist
     */
    if(vote->signature_len == 0)
        return 0;

    return 1;
}

static int qrx_same_validator(
    const qrx_finality_vote_t *a,
    const qrx_finality_vote_t *b
) {
    return memcmp(
        a->validator_pubkey,
        b->validator_pubkey,
        QRX_FINALITY_PUB_SIZE
    ) == 0;
}

int qrx_detect_double_vote(
    const qrx_finality_vote_t *existing_votes,
    size_t existing_vote_count,
    const qrx_finality_vote_t *candidate
) {
    if(!existing_votes || !candidate)
        return 0;

    for(size_t i = 0; i < existing_vote_count; i++) {

        const qrx_finality_vote_t *v = &existing_votes[i];

        if(!qrx_same_validator(v, candidate))
            continue;

        if(v->height != candidate->height)
            continue;

        if(v->round != candidate->round)
            continue;

        if(v->type != candidate->type)
            continue;

        /*
         * Same validator signed different block hash.
         */
        if(memcmp(
            v->block_hash,
            candidate->block_hash,
            QRX_FINALITY_HASH_SIZE
        ) != 0) {
            return 1;
        }
    }

    return 0;
}

int qrx_apply_slash(
    qrx_slashing_state_t *st,
    const qrx_finality_vote_t *vote,
    qrx_slash_reason_t reason
) {
    if(!st || !vote)
        return 0;

    if(st->count >= QRX_MAX_SLASH_EVENTS)
        return 0;

    qrx_slash_event_t *ev = &st->events[st->count++];

    memset(ev, 0, sizeof(*ev));

    memcpy(
        ev->validator_pubkey,
        vote->validator_pubkey,
        QRX_FINALITY_PUB_SIZE
    );

    ev->reason = reason;
    ev->height = vote->height;
    ev->round = vote->round;

    /*
     * Default penalty:
     * 5% of validator voting power.
     */
    ev->penalty_atoms =
        (vote->validator_power * 5ULL) / 100ULL;

    return 1;
}
