#ifndef QRX_CHAIN_PARAMS_H
#define QRX_CHAIN_PARAMS_H

#ifdef __cplusplus
extern "C" {
#endif

int qrx_chain_get_value(const char *chain_dir, const char *key, char *out, unsigned long out_sz);
long long qrx_chain_get_ll_or_default(const char *chain_dir, const char *key, long long dflt);
int qrx_chain_get_value_at_height(const char *chain_dir, long long height, const char *key, char *out, unsigned long out_sz);
long long qrx_chain_get_ll_at_height_or_default(const char *chain_dir, long long height, const char *key, long long dflt);
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
                            long long genesis_time);
int qrx_chain_verify_genesis(const char *chain_dir);
long long qrx_chain_get_block_reward_at_height(const char *chain_dir, long long height, long long dflt_initial_reward_atoms, long long dflt_halving_interval_blocks);
long long qrx_chain_get_next_halving_height(const char *chain_dir, long long height, long long dflt_halving_interval_blocks);

#ifdef __cplusplus
}
#endif

#endif
