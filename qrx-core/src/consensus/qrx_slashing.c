#include "qrx_slashing.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

/*
 * QRX finality vote hybrid signature enforcement.
 *
 * Encoding used inside qrx_finality_vote_t:
 *
 * validator_pubkey:
 *   [0..31]   Ed25519 raw public key
 *   [32..33]  ML-DSA public key PEM length, big endian
 *   [34..]    ML-DSA public key PEM bytes
 *
 * signature:
 *   [0..1]    Ed25519 signature length, big endian
 *   [...]     Ed25519 signature bytes
 *   [...]     ML-DSA signature length, big endian
 *   [...]     ML-DSA signature bytes
 *
 * The signed vote payload is domain-separated and excludes the signature.
 * This makes finality voting fail closed when either Ed25519 or ML-DSA is
 * missing or invalid.
 */

static unsigned short qrx_be16_read(const uint8_t *p) {
    return (unsigned short)(((unsigned short)p[0] << 8) | (unsigned short)p[1]);
}

static void qrx_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void qrx_u64_be(uint8_t *p, uint64_t v) {
    for(int i = 7; i >= 0; --i) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

static size_t qrx_finality_vote_payload(const qrx_finality_vote_t *vote, uint8_t out[256]) {
    static const char domain[] = "QRX-FINALITY-VOTE-V1";
    size_t off = 0;
    memcpy(out + off, domain, sizeof(domain) - 1); off += sizeof(domain) - 1;
    qrx_u32_be(out + off, vote->protocol_version); off += 4;
    qrx_u32_be(out + off, vote->chain_id_hash); off += 4;
    qrx_u64_be(out + off, (uint64_t)vote->height); off += 8;
    qrx_u32_be(out + off, (uint32_t)vote->round); off += 4;
    qrx_u32_be(out + off, (uint32_t)vote->type); off += 4;
    memcpy(out + off, vote->block_hash, QRX_FINALITY_HASH_SIZE); off += QRX_FINALITY_HASH_SIZE;
    qrx_u64_be(out + off, vote->validator_power); off += 8;
    return off;
}

static int qrx_verify_oneshot(EVP_PKEY *pub, const unsigned char *msg, size_t msglen,
                              const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) return 0;
    if(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    int ok = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);
    EVP_MD_CTX_free(ctx);
    return ok == 1;
}

int qrx_vote_signature_verify(const qrx_finality_vote_t *vote) {
    if(!vote) return 0;
    if(vote->signature_len < 2 + 64 + 2) return 0;

    const uint8_t *pk = vote->validator_pubkey;
    uint8_t ed_raw[32];
    memcpy(ed_raw, pk, sizeof(ed_raw));
    unsigned short ml_pub_len = qrx_be16_read(pk + 32);
    if(ml_pub_len == 0 || 34u + (size_t)ml_pub_len > QRX_FINALITY_PUB_SIZE) return 0;

    char *ml_pem = (char*)malloc((size_t)ml_pub_len + 1);
    if(!ml_pem) return 0;
    memcpy(ml_pem, pk + 34, ml_pub_len);
    ml_pem[ml_pub_len] = 0;

    EVP_PKEY *ed_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed_raw, sizeof(ed_raw));
    BIO *bio = BIO_new_mem_buf(ml_pem, (int)ml_pub_len);
    EVP_PKEY *ml_pub = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    if(bio) BIO_free(bio);
    free(ml_pem);
    if(!ed_pub || !ml_pub) { if(ed_pub) EVP_PKEY_free(ed_pub); if(ml_pub) EVP_PKEY_free(ml_pub); return 0; }

    const uint8_t *sig = vote->signature;
    size_t off = 0;
    unsigned short ed_sig_len = qrx_be16_read(sig + off); off += 2;
    if(ed_sig_len == 0 || off + ed_sig_len + 2 > vote->signature_len) { EVP_PKEY_free(ed_pub); EVP_PKEY_free(ml_pub); return 0; }
    const uint8_t *ed_sig = sig + off; off += ed_sig_len;
    unsigned short ml_sig_len = qrx_be16_read(sig + off); off += 2;
    if(ml_sig_len == 0 || off + ml_sig_len != vote->signature_len) { EVP_PKEY_free(ed_pub); EVP_PKEY_free(ml_pub); return 0; }
    const uint8_t *ml_sig = sig + off;

    uint8_t payload[256];
    size_t payload_len = qrx_finality_vote_payload(vote, payload);

    int ok_ed = qrx_verify_oneshot(ed_pub, payload, payload_len, ed_sig, ed_sig_len);
    int ok_ml = qrx_verify_oneshot(ml_pub, payload, payload_len, ml_sig, ml_sig_len);
    EVP_PKEY_free(ed_pub);
    EVP_PKEY_free(ml_pub);
    return ok_ed && ok_ml;
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
