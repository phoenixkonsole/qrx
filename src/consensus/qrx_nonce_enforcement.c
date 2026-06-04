#include "qrx_nonce_enforcement.h"

int qrx_verify_account_nonce(uint64_t expected, uint64_t received) {
    return expected == received;
}

int qrx_reject_duplicate_tx(const char *txid) {
    (void)txid;
    return 1;
}

int qrx_validate_sequential_nonce(uint64_t last_nonce, uint64_t next_nonce) {
    return next_nonce == (last_nonce + 1);
}
