#include "qrx_p2p_config.h"
#include <stdlib.h>
#include <string.h>

const char *QRX_DEFAULT_SEEDNODES[QRX_SEEDNODE_COUNT] = {
    "seed1.qrxchain.org",
    "seed2.qrxchain.org",
    "seed3.qrxchain.org"
};

const char *QRX_COMMUNITY_BOOTSTRAP_IPS[QRX_COMMUNITY_BOOTSTRAP_IP_COUNT] = {
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
    "203.0.113.13"
};

void qrx_p2p_config_defaults(qrx_p2p_runtime_config_t *cfg) {
    if(!cfg) return;
    cfg->max_connections = QRX_DEFAULT_MAX_CONNECTIONS;
    cfg->outbound_connections = QRX_DEFAULT_OUTBOUND_CONNECTIONS;
    cfg->listen_enabled = 1;
    cfg->extra_seednode = 0;
}

int qrx_p2p_config_parse_arg(qrx_p2p_runtime_config_t *cfg, int *i, int argc, char **argv) {
    if(!cfg || !i || !argv || *i >= argc) return 0;
    if(strcmp(argv[*i], "--maxconnections") == 0 && *i + 1 < argc) {
        cfg->max_connections = atoi(argv[++(*i)]);
        if(cfg->max_connections < 0) cfg->max_connections = 0;
        return 1;
    }
    if(strcmp(argv[*i], "--outbound") == 0 && *i + 1 < argc) {
        cfg->outbound_connections = atoi(argv[++(*i)]);
        if(cfg->outbound_connections < 0) cfg->outbound_connections = 0;
        return 1;
    }
    if(strcmp(argv[*i], "--seednode") == 0 && *i + 1 < argc) {
        cfg->extra_seednode = argv[++(*i)];
        return 1;
    }
    if(strcmp(argv[*i], "--nolisten") == 0) {
        cfg->listen_enabled = 0;
        return 1;
    }
    return 0;
}
