#pragma once
#define QRX_DEFAULT_MAX_CONNECTIONS 128
#define QRX_DEFAULT_OUTBOUND_CONNECTIONS 16
#define QRX_SEEDNODE_COUNT 3
#define QRX_COMMUNITY_BOOTSTRAP_IP_COUNT 4

typedef struct {
    int max_connections;
    int outbound_connections;
    int listen_enabled;
    const char *extra_seednode;
} qrx_p2p_runtime_config_t;

extern const char *QRX_DEFAULT_SEEDNODES[QRX_SEEDNODE_COUNT];
extern const char *QRX_COMMUNITY_BOOTSTRAP_IPS[QRX_COMMUNITY_BOOTSTRAP_IP_COUNT];

void qrx_p2p_config_defaults(qrx_p2p_runtime_config_t *cfg);
int qrx_p2p_config_parse_arg(qrx_p2p_runtime_config_t *cfg, int *i, int argc, char **argv);
