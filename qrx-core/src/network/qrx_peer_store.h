#pragma once
#include <stddef.h>
#define QRX_PEER_ADDR_MAX 128

typedef struct {
    char addr[QRX_PEER_ADDR_MAX];
    long long last_seen;
    int score;
} qrx_peer_store_entry_t;

int qrx_peer_store_load(const char *datadir, qrx_peer_store_entry_t *out, size_t max_entries, size_t *count);
int qrx_peer_store_save(const char *datadir, const qrx_peer_store_entry_t *entries, size_t count);
int qrx_peer_store_add_or_update(qrx_peer_store_entry_t *entries, size_t *count, size_t max_entries, const char *addr);
