#pragma once
#include <stdint.h>

#define QRX_BLOCK_TIME_SECONDS 10LL
#define QRX_BLOCKS_PER_DAY 8640LL
#define QRX_BLOCKS_PER_YEAR 3153600LL

#define QRX_BOOTSTRAP_LOCK_DAYS 180LL
#define QRX_BOOTSTRAP_LOCK_BLOCKS (QRX_BOOTSTRAP_LOCK_DAYS * QRX_BLOCKS_PER_DAY)

/*
 * Reward policy:
 * Year 1: 20% dev share
 * Year 2: 10% dev share
 * Year 3: 5% dev share
 * Year 4+: 2% dev share
 */
int qrx_dev_fund_percent(int64_t block_height);
uint64_t qrx_dev_reward_share(uint64_t total_reward_atoms, int64_t block_height);
uint64_t qrx_validator_reward_share(uint64_t total_reward_atoms, int64_t block_height);
