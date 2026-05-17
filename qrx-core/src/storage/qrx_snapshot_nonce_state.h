#pragma once
#include <stdint.h>

typedef struct {
    char account[128];
    uint64_t nonce;
} qrx_account_nonce_state_t;
