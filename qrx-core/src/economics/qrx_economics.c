#include "qrx_economics.h"

int qrx_dev_fund_percent(int64_t block_height) {
    if(block_height < QRX_BLOCKS_PER_YEAR) return 20;
    if(block_height < QRX_BLOCKS_PER_YEAR * 2LL) return 10;
    if(block_height < QRX_BLOCKS_PER_YEAR * 3LL) return 5;
    return 2;
}

uint64_t qrx_dev_reward_share(uint64_t total_reward_atoms, int64_t block_height) {
    int pct = qrx_dev_fund_percent(block_height);
    return (total_reward_atoms * (uint64_t)pct) / 100ULL;
}

uint64_t qrx_validator_reward_share(uint64_t total_reward_atoms, int64_t block_height) {
    uint64_t dev = qrx_dev_reward_share(total_reward_atoms, block_height);
    if(dev > total_reward_atoms) return 0;
    return total_reward_atoms - dev;
}
