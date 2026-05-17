#pragma once
#include <stdint.h>

int qrx_verify_account_nonce(uint64_t expected, uint64_t received);
int qrx_reject_duplicate_tx(const char *txid);
int qrx_validate_sequential_nonce(uint64_t last_nonce, uint64_t next_nonce);
