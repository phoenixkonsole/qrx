#ifndef CORE_FRONTEND_H
#define CORE_FRONTEND_H
#include <stddef.h>

typedef struct {
    const char *name;
    const char *chain_name;
    const char *network_id;
    const char *genesis_hash;
    const char *protocol_version;
    const char *magic;
    int default_port;
    const char *seednodes[8];
    const char *slash_penalty_threshold;
    const char *slash_redistribute_bps;
    const char *max_supply_atoms;
    const char *epoch_reward_atoms;
    const char *faucet_cap_atoms;
    int block_time_seconds;
    int max_txs_per_block;
    int max_block_bytes;
    int max_tx_bytes;
    int validator_reward_percent;
    int delegator_reward_percent;
    int network_pool_percent;
    long long default_validator_commission_bps;
    int allow_runtime_overrides;
} QrxProfile;

const QrxProfile *qrx_profile_by_name(const char *name);
int qrx_ensure_node(const char *network, const char *datadir, const char *wallet, const char *listen, const char **addnodes, int addnode_count,
                    char *out_base, size_t out_base_sz,
                    char *out_chain, size_t out_chain_sz,
                    char *out_wallet, size_t out_wallet_sz,
                    char *out_node, size_t out_node_sz);
int qrx_get_wallet_address(const char *wallet_dir, char *out, size_t out_sz);
int qrx_backend_call(int argc, char **argv);
int qrx_parse_hostport(const char *in, char *host, size_t host_sz, char *port, size_t port_sz);
void qrx_default_datadir(const char *network, const char *override_datadir, char *out, size_t out_sz);
const char *qrx_dev_address_for_network(const char *network);
int qrx_network_has_faucet(const char *network);
#endif
