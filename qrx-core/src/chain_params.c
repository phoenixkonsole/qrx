#include "chain_params.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

static int read_file_local(const char *path, char **out, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return -1; }
    buf[sz] = 0;
    *out = buf;
    if (len_out) *len_out = (size_t)sz;
    return 0;
}

static int write_text_local(const char *path, const char *txt) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t len = strlen(txt);
    int rc = fwrite(txt, 1, len, f) == len ? 0 : -1;
    fclose(f);
    return rc;
}

static void sha256_hex_local(const unsigned char *data, size_t len, char out[65]) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(data, len, md);
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out[i * 2] = hex[(md[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[md[i] & 0xF];
    }
    out[64] = 0;
}

static char *cfg_get_local(const char *cfg, const char *key) {
    size_t klen = strlen(key);
    const char *p = cfg;
    while (p && *p) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len > klen + 1 && memcmp(p, key, klen) == 0 && p[klen] == '=') {
            char *v = (char*)malloc(len - klen);
            if (!v) return NULL;
            memcpy(v, p + klen + 1, len - klen - 1);
            v[len - klen - 1] = 0;
            return v;
        }
        p = e ? e + 1 : NULL;
    }
    return NULL;
}

static void path_meta(const char *chain_dir, char out[1024]) {
    snprintf(out, 1024, "%s/chain.meta", chain_dir);
}
static void path_genesis(const char *chain_dir, char out[1024]) {
    snprintf(out, 1024, "%s/genesis.cfg", chain_dir);
}


typedef struct {
    long long height;
    char key[128];
    char value[256];
} fork_override_t;

static int parse_fork_overrides(const char *cfg, fork_override_t **out_arr, int *out_count) {
    int count = 0;
    fork_override_t *arr = NULL;
    const char *p = cfg;
    while (p && *p) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len > 7 && memcmp(p, "fork.", 5) == 0) {
            char line[512];
            if (len >= sizeof(line)) len = sizeof(line) - 1;
            memcpy(line, p, len);
            line[len] = 0;
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = 0;
                const char *val = eq + 1;
                long long height = -1;
                char key[128] = {0};
                if (sscanf(line, "fork.%lld.%127[^=]", &height, key) == 2 && height >= 0 && key[0]) {
                    fork_override_t *tmp = (fork_override_t*)realloc(arr, sizeof(fork_override_t) * (count + 1));
                    if (!tmp) { free(arr); return -1; }
                    arr = tmp;
                    arr[count].height = height;
                    snprintf(arr[count].key, sizeof(arr[count].key), "%s", key);
                    snprintf(arr[count].value, sizeof(arr[count].value), "%s", val);
                    count++;
                }
            }
        }
        p = e ? e + 1 : NULL;
    }
    *out_arr = arr;
    *out_count = count;
    return 0;
}

int qrx_chain_verify_genesis(const char *chain_dir) {
    char meta_path[1024], genesis_path[1024];
    path_meta(chain_dir, meta_path);
    path_genesis(chain_dir, genesis_path);

    char *meta = NULL, *genesis = NULL;
    size_t genesis_len = 0;
    if (read_file_local(meta_path, &meta, NULL) != 0) return -1;
    if (read_file_local(genesis_path, &genesis, &genesis_len) != 0) { free(meta); return -1; }

    char *expected = cfg_get_local(meta, "genesis_hash");
    if (!expected) { free(meta); free(genesis); return -1; }

    char actual[65];
    sha256_hex_local((const unsigned char*)genesis, genesis_len, actual);
    int ok = strcmp(expected, actual) == 0 ? 0 : -1;

    free(expected);
    free(meta);
    free(genesis);
    return ok;
}

int qrx_chain_get_value(const char *chain_dir, const char *key, char *out, unsigned long out_sz) {
    if (!chain_dir || !key || !out || out_sz == 0) return -1;

    char meta_path[1024], genesis_path[1024];
    path_meta(chain_dir, meta_path);
    path_genesis(chain_dir, genesis_path);

    char *txt = NULL;
    char *val = NULL;

    if (read_file_local(meta_path, &txt, NULL) == 0) {
        val = cfg_get_local(txt, key);
        free(txt);
        if (val) {
            snprintf(out, out_sz, "%s", val);
            free(val);
            return 0;
        }
    }

    if (qrx_chain_verify_genesis(chain_dir) != 0) return -1;
    if (read_file_local(genesis_path, &txt, NULL) != 0) return -1;
    val = cfg_get_local(txt, key);
    free(txt);
    if (!val) return -1;
    snprintf(out, out_sz, "%s", val);
    free(val);
    return 0;
}

long long qrx_chain_get_ll_or_default(const char *chain_dir, const char *key, long long dflt) {
    char buf[128];
    if (qrx_chain_get_value(chain_dir, key, buf, sizeof(buf)) != 0) return dflt;
    return atoll(buf);
}


int qrx_chain_get_value_at_height(const char *chain_dir, long long height, const char *key, char *out, unsigned long out_sz) {
    if (!chain_dir || !key || !out || out_sz == 0) return -1;

    char meta_path[1024], genesis_path[1024];
    path_meta(chain_dir, meta_path);
    path_genesis(chain_dir, genesis_path);

    char *txt = NULL;
    char *val = NULL;

    if (read_file_local(meta_path, &txt, NULL) == 0) {
        val = cfg_get_local(txt, key);
        free(txt);
        if (val) {
            snprintf(out, out_sz, "%s", val);
            free(val);
            return 0;
        }
    }

    if (qrx_chain_verify_genesis(chain_dir) != 0) return -1;
    if (read_file_local(genesis_path, &txt, NULL) != 0) return -1;

    val = cfg_get_local(txt, key);
    if (val) {
        snprintf(out, out_sz, "%s", val);
        free(val);
    } else {
        out[0] = 0;
    }

    fork_override_t *forks = NULL; int fork_count = 0;
    if (parse_fork_overrides(txt, &forks, &fork_count) == 0 && fork_count > 0) {
        long long best_height = -1;
        const char *best_val = NULL;
        for (int i = 0; i < fork_count; ++i) {
            if (forks[i].height <= height && strcmp(forks[i].key, key) == 0 && forks[i].height >= best_height) {
                best_height = forks[i].height;
                best_val = forks[i].value;
            }
        }
        if (best_val) snprintf(out, out_sz, "%s", best_val);
    }
    free(forks);
    free(txt);
    return out[0] ? 0 : -1;
}

long long qrx_chain_get_ll_at_height_or_default(const char *chain_dir, long long height, const char *key, long long dflt) {
    char buf[128];
    if (qrx_chain_get_value_at_height(chain_dir, height, key, buf, sizeof(buf)) != 0) return dflt;
    return atoll(buf);
}


long long qrx_chain_get_block_reward_at_height(const char *chain_dir, long long height, long long dflt_initial_reward_atoms, long long dflt_halving_interval_blocks) {
    long long initial_reward = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "initial_reward_atoms",
                              qrx_chain_get_ll_at_height_or_default(chain_dir, height, "epoch_reward_atoms", dflt_initial_reward_atoms));
    long long halving_interval = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "halving_interval_blocks", dflt_halving_interval_blocks);
    if (halving_interval <= 0) return initial_reward;
    long long halvings = height / halving_interval;
    long long reward = initial_reward;
    for (long long i = 0; i < halvings; ++i) {
        reward /= 2;
        if (reward <= 0) return 0;
    }
    return reward;
}

long long qrx_chain_get_next_halving_height(const char *chain_dir, long long height, long long dflt_halving_interval_blocks) {
    long long halving_interval = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "halving_interval_blocks", dflt_halving_interval_blocks);
    if (halving_interval <= 0) return -1;
    return ((height / halving_interval) + 1) * halving_interval;
}

int qrx_chain_write_genesis(const char *chain_dir,
                            const char *network_id,
                            const char *protocol_version,
                            const char *magic,
                            const char *chain_name,
                            long long penalty_threshold,
                            long long redistribute_bps,
                            long long max_supply_atoms,
                            long long epoch_reward_atoms,
                            long long faucet_cap_atoms,
                            long long block_time_seconds,
                            long long max_txs_per_block,
                            long long max_block_bytes,
                            long long max_tx_bytes,
                            long long validator_reward_percent,
                            long long delegator_reward_percent,
                            long long network_pool_percent,
                            long long genesis_time) {
    char meta_path[1024], genesis_path[1024];
    path_meta(chain_dir, meta_path);
    path_genesis(chain_dir, genesis_path);

    char genesis[4096];
    snprintf(genesis, sizeof(genesis),
        "genesis_version=1\n"
        "chain_name=%s\n"
        "genesis_time=%lld\n"
        "block_time_seconds=%lld\n"
        "max_txs_per_block=%lld\n"
        "max_block_bytes=%lld\n"
        "max_tx_bytes=%lld\n"
        "slash_penalty_threshold=%lld\n"
        "slash_redistribute_bps=%lld\n"
        "max_supply_atoms=%lld\n"
        "epoch_reward_atoms=%lld\n"
        "initial_reward_atoms=%lld\n"
        "tx_fee_atoms=1000\n"
        "halving_interval_blocks=12614400\n"
        "faucet_cap_atoms=%lld\n"
        "validator_reward_percent=%lld\n"
        "delegator_reward_percent=%lld\n"
        "network_pool_percent=%lld\n"
        "min_validator_stake_atoms=10000000000\n"
        "double_sign_slash_bps=5000\n"
        "double_sign_jail_seconds=315360000\n"
        "offline_penalty_bps=100\n"
        "offline_penalty_after_blocks=100\n"
        "offline_penalty_interval_blocks=100\n"
        "offline_jail_seconds=3600\n"
        "alloc_dev_fund_percent=2\n"
        "alloc_ecosystem_percent=3\n"
        "alloc_community_percent=95\n"
        "fork.0.block_time_seconds=%lld\n"
        "fork.0.max_txs_per_block=%lld\n"
        "fork.0.max_block_bytes=%lld\n"
        "fork.0.max_tx_bytes=%lld\n"
        "fork.0.epoch_reward_atoms=%lld\n"
        "fork.0.initial_reward_atoms=%lld\n"
        "fork.0.tx_fee_atoms=1000\n"
        "fork.0.halving_interval_blocks=12614400\n"
        "fork.0.validator_reward_percent=%lld\n"
        "fork.0.delegator_reward_percent=%lld\n"
        "fork.0.network_pool_percent=%lld\n"
        "fork.0.min_validator_stake_atoms=10000000000\n"
        "fork.0.double_sign_slash_bps=5000\n"
        "fork.0.double_sign_jail_seconds=315360000\n"
        "fork.0.offline_penalty_bps=100\n"
        "fork.0.offline_penalty_after_blocks=100\n"
        "fork.0.offline_penalty_interval_blocks=100\n"
        "fork.0.offline_jail_seconds=3600\n",
        chain_name,
        genesis_time,
        block_time_seconds,
        max_txs_per_block,
        max_block_bytes,
        max_tx_bytes,
        penalty_threshold,
        redistribute_bps,
        max_supply_atoms,
        epoch_reward_atoms,
        epoch_reward_atoms,
        faucet_cap_atoms,
        validator_reward_percent,
        delegator_reward_percent,
        network_pool_percent,
        block_time_seconds,
        max_txs_per_block,
        max_block_bytes,
        max_tx_bytes,
        epoch_reward_atoms,
        epoch_reward_atoms,
        validator_reward_percent,
        delegator_reward_percent,
        network_pool_percent);

    char genesis_hash[65];
    sha256_hex_local((const unsigned char*)genesis, strlen(genesis), genesis_hash);

    char chain_id_input[2048];
    snprintf(chain_id_input, sizeof(chain_id_input), "%s|%s|%s|%s|%s",
        network_id, protocol_version, magic, chain_name, genesis_hash);
    char chain_id[65];
    sha256_hex_local((const unsigned char*)chain_id_input, strlen(chain_id_input), chain_id);

    char meta[2048];
    snprintf(meta, sizeof(meta),
        "network_id=%s\n"
        "protocol_version=%s\n"
        "consensus_version=1\n"
        "magic=%s\n"
        "genesis_hash=%s\n"
        "chain_id=%s\n",
        network_id,
        protocol_version,
        magic,
        genesis_hash,
        chain_id);

    if (write_text_local(genesis_path, genesis) != 0) return -1;
    if (write_text_local(meta_path, meta) != 0) return -1;
    return 0;
}
