#include "qrx_peer_store.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static void qrx_peer_store_path(const char *datadir, char *out, size_t out_len) {
    snprintf(out, out_len, "%s/peers.dat", datadir ? datadir : ".");
}

int qrx_peer_store_load(const char *datadir, qrx_peer_store_entry_t *out, size_t max_entries, size_t *count) {
    if(count) *count = 0;
    if(!out || !count) return -1;
    char path[1024];
    qrx_peer_store_path(datadir, path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if(!fp) return 0;
    char line[256];
    while(fgets(line, sizeof(line), fp) && *count < max_entries) {
        char addr[QRX_PEER_ADDR_MAX] = {0};
        long long last_seen = 0;
        int score = 0;
        if(sscanf(line, "%127s %lld %d", addr, &last_seen, &score) >= 1) {
            strncpy(out[*count].addr, addr, QRX_PEER_ADDR_MAX - 1);
            out[*count].last_seen = last_seen;
            out[*count].score = score;
            (*count)++;
        }
    }
    fclose(fp);
    return 0;
}

int qrx_peer_store_save(const char *datadir, const qrx_peer_store_entry_t *entries, size_t count) {
    if(!entries) return -1;
    char path[1024];
    qrx_peer_store_path(datadir, path, sizeof(path));
    FILE *fp = fopen(path, "w");
    if(!fp) return -1;
    for(size_t i = 0; i < count; i++) {
        if(entries[i].addr[0])
            fprintf(fp, "%s %lld %d\n", entries[i].addr, entries[i].last_seen, entries[i].score);
    }
    fclose(fp);
    return 0;
}

int qrx_peer_store_add_or_update(qrx_peer_store_entry_t *entries, size_t *count, size_t max_entries, const char *addr) {
    if(!entries || !count || !addr || !addr[0]) return -1;
    long long now = (long long)time(NULL);
    for(size_t i = 0; i < *count; i++) {
        if(strcmp(entries[i].addr, addr) == 0) {
            entries[i].last_seen = now;
            return 0;
        }
    }
    if(*count >= max_entries) return -1;
    strncpy(entries[*count].addr, addr, QRX_PEER_ADDR_MAX - 1);
    entries[*count].last_seen = now;
    entries[*count].score = 0;
    (*count)++;
    return 0;
}
