#pragma once
#include <stdint.h>
#include <stddef.h>

#define QRX_FINALITY_HASH_SIZE 64
#define QRX_FINALITY_SIG_SIZE  128
#define QRX_FINALITY_PUB_SIZE  96

typedef enum {
    QRX_VOTE_PREVOTE   = 1,
    QRX_VOTE_PRECOMMIT = 2
} qrx_vote_type_t;

typedef struct {
    uint32_t protocol_version;
    uint32_t chain_id_hash;
    int64_t height;
    int32_t round;
    qrx_vote_type_t type;
    uint8_t block_hash[QRX_FINALITY_HASH_SIZE];
    uint8_t validator_pubkey[QRX_FINALITY_PUB_SIZE];
    uint64_t validator_power;
    uint8_t signature[QRX_FINALITY_SIG_SIZE];
    size_t signature_len;
} qrx_finality_vote_t;

typedef struct {
    int64_t height;
    int32_t round;
    uint8_t block_hash[QRX_FINALITY_HASH_SIZE];
    uint64_t total_power;
    uint64_t signed_power;
    size_t vote_count;
} qrx_commit_certificate_t;

uint64_t qrx_finality_quorum_power(uint64_t total_power);

int qrx_finality_vote_matches(
    const qrx_finality_vote_t *vote,
    int64_t height,
    int32_t round,
    qrx_vote_type_t type,
    const uint8_t block_hash[QRX_FINALITY_HASH_SIZE]
);

int qrx_finality_has_quorum(
    uint64_t signed_power,
    uint64_t total_power
);

int qrx_finality_build_commit_certificate(
    const qrx_finality_vote_t *votes,
    size_t vote_count,
    int64_t height,
    int32_t round,
    const uint8_t block_hash[QRX_FINALITY_HASH_SIZE],
    uint64_t total_power,
    qrx_commit_certificate_t *out
);

int qrx_finality_verify_commit_certificate(
    const qrx_commit_certificate_t *cert
);
