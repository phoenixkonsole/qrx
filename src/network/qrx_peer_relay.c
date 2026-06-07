#include "qrx_peer_relay.h"
#include <stdio.h>
#include <string.h>

int qrx_peer_relay_export(qrx_peer_store_entry_t *entries, size_t count, char *out, size_t out_len) {
    if(!entries || !out || out_len == 0) return -1;
    out[0] = 0;
    size_t used = 0;
    for(size_t i = 0; i < count; i++) {
        if(!entries[i].addr[0]) continue;
        int n = snprintf(out + used, out_len - used, "%s\n", entries[i].addr);
        if(n < 0 || (size_t)n >= out_len - used) break;
        used += (size_t)n;
    }
    return 0;
}

int qrx_peer_relay_import(qrx_peer_store_entry_t *entries, size_t *count, size_t max_entries, const char *payload) {
    if(!entries || !count || !payload) return -1;
    char buf[8192];
    strncpy(buf, payload, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *save = 0;
    char *line = strtok_r(buf, "\n\r,", &save);
    while(line) {
        while(*line == ' ' || *line == '\t') line++;
        if(*line) qrx_peer_store_add_or_update(entries, count, max_entries, line);
        line = strtok_r(0, "\n\r,", &save);
    }
    return 0;
}
