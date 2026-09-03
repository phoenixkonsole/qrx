#include "qrx_velocity_scheduler.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QRX_SCHED_NONE ((size_t)-1)

typedef struct {
    char *key;
    size_t last;
    uint8_t used;
} AccessSlot;

typedef struct {
    AccessSlot *slots;
    size_t cap;
    size_t used;
} AccessMap;

static uint64_t sched_hash64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; s && *s; ++s) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

static size_t pow2_ge(size_t n) {
    size_t p = 16;
    while (p < n && p <= (SIZE_MAX >> 1)) p <<= 1;
    return p;
}

static int amap_init(AccessMap *m, size_t expected) {
    if (!m) return -1;
    memset(m, 0, sizeof(*m));
    size_t want = expected > (SIZE_MAX / 4) ? SIZE_MAX : expected * 4;
    m->cap = pow2_ge(want < 16 ? 16 : want);
    m->slots = (AccessSlot*)calloc(m->cap, sizeof(*m->slots));
    return m->slots ? 0 : -1;
}

static void amap_clear(AccessMap *m) {
    if (!m || !m->slots) return;
    for (size_t i = 0; i < m->cap; ++i) {
        free(m->slots[i].key);
        m->slots[i].key = NULL;
        m->slots[i].last = 0;
        m->slots[i].used = 0;
    }
    m->used = 0;
}

static void amap_free(AccessMap *m) {
    if (!m) return;
    amap_clear(m);
    free(m->slots);
    memset(m, 0, sizeof(*m));
}

static int amap_rehash(AccessMap *m, size_t new_cap) {
    AccessSlot *old = m->slots;
    size_t old_cap = m->cap;
    AccessSlot *ns = (AccessSlot*)calloc(new_cap, sizeof(*ns));
    if (!ns) return -1;
    m->slots = ns;
    m->cap = new_cap;
    m->used = 0;
    for (size_t i = 0; i < old_cap; ++i) {
        if (!old[i].used) continue;
        size_t pos = (size_t)(sched_hash64(old[i].key) & (uint64_t)(new_cap - 1));
        while (m->slots[pos].used) pos = (pos + 1) & (new_cap - 1);
        m->slots[pos] = old[i];
        m->used++;
    }
    free(old);
    return 0;
}

static int amap_lookup(AccessMap *m, const char *key, size_t *last_out) {
    if (!m || !m->slots || !key || !*key) return 0;
    size_t pos = (size_t)(sched_hash64(key) & (uint64_t)(m->cap - 1));
    size_t start = pos;
    while (m->slots[pos].used) {
        if (!strcmp(m->slots[pos].key, key)) {
            if (last_out) *last_out = m->slots[pos].last;
            return 1;
        }
        pos = (pos + 1) & (m->cap - 1);
        if (pos == start) break;
    }
    return 0;
}

static int amap_set(AccessMap *m, const char *key, size_t last) {
    if (!m || !key || !*key) return -1;
    if ((m->used + 1) * 10 >= m->cap * 7) {
        if (m->cap > (SIZE_MAX >> 1) || amap_rehash(m, m->cap << 1)) return -1;
    }
    size_t pos = (size_t)(sched_hash64(key) & (uint64_t)(m->cap - 1));
    while (m->slots[pos].used) {
        if (!strcmp(m->slots[pos].key, key)) {
            m->slots[pos].last = last;
            return 0;
        }
        pos = (pos + 1) & (m->cap - 1);
    }
    m->slots[pos].key = strdup(key);
    if (!m->slots[pos].key) return -1;
    m->slots[pos].last = last;
    m->slots[pos].used = 1;
    m->used++;
    return 0;
}

static int edge_reserve(QrxVelocityBlockSchedule *s, size_t need) {
    if (need <= s->edge_cap) return 0;
    size_t nc = s->edge_cap ? s->edge_cap * 2 : 64;
    while (nc < need) {
        if (nc > SIZE_MAX / 2) return -1;
        nc *= 2;
    }
    QrxVelocityDependencyEdge *p = (QrxVelocityDependencyEdge*)realloc(s->edges, nc * sizeof(*p));
    if (!p) return -1;
    s->edges = p;
    s->edge_cap = nc;
    return 0;
}

static int edge_add(QrxVelocityBlockSchedule *s, size_t from, size_t to,
                    uint32_t *pred_tags, uint32_t tag) {
    if (from == to || from == QRX_SCHED_NONE) return 0;
    if (pred_tags && pred_tags[from] == tag) return 0;
    if (edge_reserve(s, s->edge_count + 1)) return -1;
    s->edges[s->edge_count].from = from;
    s->edges[s->edge_count].to = to;
    s->edge_count++;
    if (pred_tags) pred_tags[from] = tag;
    return 0;
}

static int digest_u64(EVP_MD_CTX *ctx, uint64_t v) {
    unsigned char b[8];
    for (int i = 0; i < 8; ++i) b[i] = (unsigned char)((v >> (56 - i * 8)) & 0xffu);
    return EVP_DigestUpdate(ctx, b, sizeof(b)) == 1 ? 0 : -1;
}

static int compute_schedule_hash(QrxVelocityMempoolEntry *const *entries,
                                 const QrxVelocityBlockSchedule *s,
                                 char out[129]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) == 1;
    static const char domain[] = "QRX-VELOCITY-BLOCK-SCHEDULE-v1";
    if (ok) ok = EVP_DigestUpdate(ctx, domain, sizeof(domain) - 1) == 1;
    if (ok) ok = digest_u64(ctx, (uint64_t)s->node_count) == 0;
    for (size_t i = 0; ok && i < s->node_count; ++i) {
        const char *txid = entries[i] && entries[i]->txid[0] ? entries[i]->txid : "";
        uint64_t n = (uint64_t)strlen(txid);
        ok = digest_u64(ctx, n) == 0 && EVP_DigestUpdate(ctx, txid, (size_t)n) == 1 &&
             digest_u64(ctx, (uint64_t)s->waves[i]) == 0;
    }
    if (ok) ok = digest_u64(ctx, (uint64_t)s->edge_count) == 0;
    for (size_t i = 0; ok && i < s->edge_count; ++i) {
        ok = digest_u64(ctx, (uint64_t)s->edges[i].from) == 0 &&
             digest_u64(ctx, (uint64_t)s->edges[i].to) == 0;
    }
    unsigned char d[64]; unsigned int dlen = 0;
    if (ok) ok = EVP_DigestFinal_ex(ctx, d, &dlen) == 1 && dlen == 64;
    EVP_MD_CTX_free(ctx);
    if (!ok) return -1;
    for (size_t i = 0; i < 64; ++i) sprintf(out + i * 2, "%02x", d[i]);
    out[128] = 0;
    return 0;
}

int qrx_velocity_block_schedule_build(QrxVelocityMempoolEntry *const *entries,
                                      size_t count,
                                      QrxVelocityBlockSchedule *out) {
    if (!out || (count && !entries)) return -1;
    memset(out, 0, sizeof(*out));
    out->node_count = count;
    if (!count) {
        /* Hash the empty deterministic schedule too. */
        if (compute_schedule_hash(entries, out, out->schedule_hash)) return -1;
        return 0;
    }
    out->waves = (uint32_t*)calloc(count, sizeof(*out->waves));
    uint32_t *pred_tags = (uint32_t*)calloc(count, sizeof(*pred_tags));
    if (!out->waves || !pred_tags) { free(pred_tags); qrx_velocity_block_schedule_free(out); return -1; }

    AccessMap map;
    size_t expected_keys = count > SIZE_MAX / QRX_VELOCITY_MAX_ACCESS_KEYS ? count : count * QRX_VELOCITY_MAX_ACCESS_KEYS;
    if (amap_init(&map, expected_keys ? expected_keys : 1)) { free(pred_tags); qrx_velocity_block_schedule_free(out); return -1; }

    size_t segment_start = 0;
    size_t last_barrier = QRX_SCHED_NONE;
    uint32_t max_wave = 0;

    for (size_t i = 0; i < count; ++i) {
        QrxVelocityMempoolEntry *e = entries[i];
        if (!e) { amap_free(&map); free(pred_tags); qrx_velocity_block_schedule_free(out); return -1; }
        uint32_t wave = 0;
        uint32_t tag = (uint32_t)(i + 1); /* count is bounded by practical block sizes; tag 0 is reserved. */
        if (tag == 0) tag = 1;

        if (e->adapter_class == QRX_VELOCITY_ADAPTER_BARRIER) {
            out->barrier_nodes++;
            /* A barrier is a true fence: every node in the current segment is
               before it. The previous barrier is already a predecessor of all
               segment nodes, so this transitively fences the whole prefix. */
            for (size_t j = segment_start; j < i; ++j) {
                if (edge_add(out, j, i, pred_tags, tag)) goto fail;
                uint32_t w = out->waves[j] + 1;
                if (w > wave) wave = w;
            }
            if (last_barrier != QRX_SCHED_NONE) {
                if (edge_add(out, last_barrier, i, pred_tags, tag)) goto fail;
                uint32_t w = out->waves[last_barrier] + 1;
                if (w > wave) wave = w;
            }
            out->barrier_fences++;
            out->waves[i] = wave;
            if (wave > max_wave) max_wave = wave;
            last_barrier = i;
            segment_start = i + 1;
            amap_clear(&map);
            continue;
        }

        if (last_barrier != QRX_SCHED_NONE) {
            if (edge_add(out, last_barrier, i, pred_tags, tag)) goto fail;
            wave = out->waves[last_barrier] + 1;
        }

        for (uint32_t a = 0; a < e->access_count; ++a) {
            size_t prev = QRX_SCHED_NONE;
            if (amap_lookup(&map, e->access[a], &prev)) {
                if (edge_add(out, prev, i, pred_tags, tag)) goto fail;
                uint32_t w = out->waves[prev] + 1;
                if (w > wave) wave = w;
                out->static_conflicts++;
            }
        }
        out->waves[i] = wave;
        if (wave > max_wave) max_wave = wave;
        for (uint32_t a = 0; a < e->access_count; ++a) if (amap_set(&map, e->access[a], i)) goto fail;
    }

    out->wave_count = max_wave + 1;
    out->critical_path_nodes = out->wave_count;
    if (out->wave_count) {
        size_t *width = (size_t*)calloc(out->wave_count, sizeof(*width));
        if (!width) goto fail;
        for (size_t i = 0; i < count; ++i) width[out->waves[i]]++;
        size_t maxw = 0;
        for (uint32_t w = 0; w < out->wave_count; ++w) if (width[w] > maxw) maxw = width[w];
        out->max_parallel_width = maxw > UINT32_MAX ? UINT32_MAX : (uint32_t)maxw;
        free(width);
    }
    if (compute_schedule_hash(entries, out, out->schedule_hash)) goto fail;
    amap_free(&map);
    free(pred_tags);
    return 0;

fail:
    amap_free(&map);
    free(pred_tags);
    qrx_velocity_block_schedule_free(out);
    return -1;
}

void qrx_velocity_block_schedule_free(QrxVelocityBlockSchedule *s) {
    if (!s) return;
    free(s->waves);
    free(s->edges);
    memset(s, 0, sizeof(*s));
}
