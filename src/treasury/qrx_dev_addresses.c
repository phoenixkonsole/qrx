#include <string.h>
#include "qrx_dev_addresses.h"

const char *qrx_dev_address_for_network(const char *network) {
    if(!network) return QRX_ALPHA_DEV_ADDRESS;
    if(strcmp(network, "mainnet") == 0) return QRX_MAINNET_DEV_ADDRESS;
    if(strcmp(network, "alpha") == 0) return QRX_ALPHA_DEV_ADDRESS;
    if(strcmp(network, "testnet") == 0) return QRX_TESTNET_DEV_ADDRESS;
    if(strcmp(network, "regtest") == 0) return QRX_REGTEST_DEV_ADDRESS;
    return QRX_ALPHA_DEV_ADDRESS;
}
