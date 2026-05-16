#pragma once
#include "qrx_peer_store.h"
int qrx_peer_relay_export(qrx_peer_store_entry_t *entries, size_t count, char *out, size_t out_len);
int qrx_peer_relay_import(qrx_peer_store_entry_t *entries, size_t *count, size_t max_entries, const char *payload);
