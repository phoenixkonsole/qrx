#pragma once
#include <stdint.h>
#include "../economics/qrx_economics.h"

#define QRX_BOOTSTRAP_VALIDATOR_COUNT 50
#define QRX_BOOTSTRAP_VALIDATOR_QUB 1000ULL
#define QRX_BOOTSTRAP_VALIDATOR_ATOMS (QRX_BOOTSTRAP_VALIDATOR_QUB * 100000000ULL)
#define QRX_BOOTSTRAP_LOCK_UNTIL_HEIGHT QRX_BOOTSTRAP_LOCK_BLOCKS

typedef struct {
    const char *address;
    uint64_t amount_atoms;
    int64_t locked_until_height;
    int staking_allowed;
    int transfer_allowed_before_unlock;
} qrx_bootstrap_validator_t;

extern const qrx_bootstrap_validator_t QRX_BOOTSTRAP_VALIDATORS[QRX_BOOTSTRAP_VALIDATOR_COUNT];
