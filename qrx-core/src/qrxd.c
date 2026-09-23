#include "network/qrx_p2p_config.h"
#include "network/qrx_peer_store.h"
#include "network/qrx_peer_relay.h"
#define _GNU_SOURCE
#include "core_frontend.h"
#include "resource/qrx_resource_live.h"
#include "resource/qrx_activation_readiness.h"
#include "resource/qrx_drive_live.h"
#include "resource/qrx_storage_consensus.h"
#include "resource/qrx_storage_repair.h"
#include "compute/qrx_aura_fabric_gossip.h"
#include "compute/qrx_compute_provider_identity.h"
#include "compute/qrx_aura_runtime_delivery.h"
#include "storage/qrx_drive_runtime.h"
#include "storage/qrx_drive_prepare.h"
#include "storage/qrx_drive_contract.h"
#include "storage/qrx_drive_private_pq.h"
#include "storage/qrx_storage_discovery.h"
#include "net/qrx_net_registry.h"
#include "net/qrx_net_name.h"
#include "net/qrx_net_consensus.h"
#include "chain_params.h"
#include "net/qrx_net_resolver.h"
#include "net/qrx_net_publisher.h"
#include "net/qrx_net_browser.h"
#include "net/qrx_net_ads.h"
#include "storage/qrx_storage_fs.h"
#include "qrxdb.h"

#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <process.h>
  #include <io.h>
  #include <direct.h>
  #ifndef PATH_MAX
    #define PATH_MAX MAX_PATH
  #endif
  #ifndef R_OK
    #define R_OK 4
  #endif
  #define strtok_r strtok_s
  #define strdup _strdup
  #define sleep(sec) Sleep((DWORD)((sec) * 1000))
  typedef SSIZE_T ssize_t;
  typedef DWORD pid_t;
  typedef HANDLE qrx_thread_t;
  typedef SOCKET qrx_socket_t;
  static HANDLE g_node_handle = NULL;
  static void qrx_wsa_init_once(void) {
      static int done = 0;
      if (!done) {
          WSADATA wsa;
          WSAStartup(MAKEWORD(2, 2), &wsa);
          done = 1;
      }
  }
#else
  #include <dirent.h>
  #include <pthread.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/un.h>
  #include <sys/wait.h>
  #include <unistd.h>
  typedef pthread_t qrx_thread_t;
  typedef int qrx_socket_t;
  static void qrx_wsa_init_once(void) { }
#endif

#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif


static void qrx_hex_bytes_local(const unsigned char *in,size_t n,char *out){static const char*x="0123456789abcdef";for(size_t i=0;i<n;i++){out[i*2]=x[in[i]>>4];out[i*2+1]=x[in[i]&15];}out[n*2]=0;}
static void qrx_trim_line(char *s) {
    if(!s) return;
    s[strcspn(s, "\r\n \t")] = 0;
}

static const char *qrx_strcasestr_local(const char *haystack, const char *needle) {
    if(!haystack || !needle || !*needle) return haystack;
    size_t nl = strlen(needle);
    for(const char *h = haystack; *h; ++h) {
        size_t i = 0;
        while(i < nl && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) i++;
        if(i == nl) return h;
    }
    return NULL;
}

static int qrx_mkdir_simple(const char *path) {
#ifdef _WIN32
    if(_mkdir(path) != 0 && errno != EEXIST) return -1;
#else
    if(mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
#endif
    return 0;
}

static void qrx_global_state_path(char *out, size_t out_sz, const char *leaf) {
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
    if(!home) home = getenv("APPDATA");
#else
    const char *home = getenv("HOME");
#endif
    if(!home) home = ".";
    snprintf(out, out_sz, "%s/.qrx/%s", home, leaf);
}

static int qrx_write_current_network(const char *network) {
    char dir[PATH_MAX], path[PATH_MAX];
    FILE *f;
#ifdef _WIN32
    const char *home = getenv("USERPROFILE");
    if(!home) home = getenv("APPDATA");
#else
    const char *home = getenv("HOME");
#endif
    if(!home) home = ".";
    snprintf(dir, sizeof(dir), "%s/.qrx", home);
    if(qrx_mkdir_simple(dir) != 0) return -1;
    qrx_global_state_path(path, sizeof(path), "current_network");
    f = fopen(path, "wb");
    if(!f) return -1;
    fprintf(f, "%s\n", network ? network : "alpha");
    fclose(f);
    return 0;
}

#ifndef QRX_VERSION
#define QRX_VERSION "0.0.8.2-capacity-accounting"
#endif

#ifndef QRX_BUILD_ID
#define QRX_BUILD_ID __DATE__ " " __TIME__
#endif

static int qrx_control_port_for_network(const char *network) {
    if (!network || !*network) return 37661;
    if (!strcmp(network, "mainnet")) return 37660;
    if (!strcmp(network, "alpha")) return 37661;
    if (!strcmp(network, "testnet")) return 37662;
    if (!strcmp(network, "regtest")) return 37663;
    return 37661;
}

static volatile sig_atomic_t g_running = 1;
static pid_t g_node_pid = -1;
static int g_blocktime_seconds = 10;
static long long g_commission_bps = 1000;
static int g_blocktime_override_set = 0;
static int g_commission_override_set = 0;
static int g_block_producer_enabled = 1;
#define QRX_MAX_VALIDATOR_FLEET 4096
static char g_validator_wallet_names[QRX_MAX_VALIDATOR_FLEET][128];
static int g_validator_wallet_count = 0;
static char g_backend_path[PATH_MAX];
static char g_network[64];
static char g_primary_wallet[128];
static char g_base[PATH_MAX], g_cdir[PATH_MAX], g_wdir[PATH_MAX], g_ndir[PATH_MAX], g_sock[PATH_MAX];
static char g_rpc_bind[128] = "127.0.0.1";
static int g_allow_remote_rpc = 0;
static int g_rpc_port = 0;
#ifdef _WIN32
static qrx_socket_t g_rpc_listen_fd = INVALID_SOCKET;
#else
static qrx_socket_t g_rpc_listen_fd = -1;
#endif
static char g_rpc_user[128] = "";
static char g_rpc_password[256] = "";
static char g_rpc_token[129] = "";
typedef struct { char wallet[128]; char secret[256]; int unlocked; } QrxSignerSession;
static QrxSignerSession g_signer_sessions[QRX_MAX_VALIDATOR_FLEET]; static int g_signer_session_count=0;
static QrxSignerSession* signer_session(const char*w,int create);
static char g_wallet_passphrase[256] = "";
static int g_wallet_passphrase_default_disabled = 0;
static time_t g_start_time = 0;
static QrxDriveRuntime *g_drive_runtime = NULL;
static QrxStorageDiscoveryTable g_drive_discovery;
static uint64_t g_drive_discovery_height = 0;
/* Phase 7.2.13: validator signing is fail-closed while the node is catching up.
   This is runtime safety state only; consensus still decides canonical blocks. */
static volatile int g_validator_signing_paused = 1;
static long long g_validator_blocks_behind = 0;
static time_t g_validator_sync_safe_since = 0;
static char g_validator_pause_reason[96] = "startup_sync_check";

typedef struct {
    const char *node_dir;
    const char *chain_dir;
} MaintCtx;

static void stop_node_process(void) {
#ifdef _WIN32
    if (g_node_handle) {
        TerminateProcess(g_node_handle, 0);
        WaitForSingleObject(g_node_handle, 5000);
        CloseHandle(g_node_handle);
        g_node_handle = NULL;
    }
#else
    if(g_node_pid > 0) kill(g_node_pid, SIGTERM);
#endif
}

static void usage(void){
    puts("qrxd [--network <alpha|testnet|regtest|mainnet>] [--datadir PATH] [--wallet NAME] [--listen host:port] [--addnode host:port]... [--seednode host:port]... [--rpc-bind host:port] [--allow-remote-rpc] [--rpc-user USER] [--rpc-password PASS] [--wallet-passphrase PASS] [--wallet-passphrase-file PATH|--wallet-passphrase-stdin] [--no-wallet-passphrase-default] [--blocktime SECONDS] [--commission-bps BPS] [--no-block-producer] [--validator-wallet NAME]...\nJSON-RPC is local-only by default on 127.0.0.1:3766x. Binding RPC outside IPv4 loopback is rejected unless --allow-remote-rpc is explicitly supplied AND both --rpc-user and --rpc-password are non-empty. P2P --listen is separate from wallet RPC and may be public. SECURITY: --wallet-passphrase puts the secret in the process argument list and is deprecated for normal use. Prefer --wallet-passphrase-file PATH (0600) or --wallet-passphrase-stdin. QRX_PASSPHRASE remains supported for supervised deployments. A wallet passphrase is NOT a recovery phrase; never pass recovery words here. Alpha/testnet/regtest keep backward compatibility with the auto-generated default passphrase unless --no-wallet-passphrase-default is used.");
}

static void qrx_close_rpc_listener(void) {
#ifdef _WIN32
    if(g_rpc_listen_fd != INVALID_SOCKET) {
        closesocket(g_rpc_listen_fd);
        g_rpc_listen_fd = INVALID_SOCKET;
    }
#else
    if(g_rpc_listen_fd >= 0) {
        close(g_rpc_listen_fd);
        g_rpc_listen_fd = -1;
    }
#endif
}

static void on_sig(int sig){
    (void)sig;
    g_running = 0;
    qrx_close_rpc_listener(); /* wake blocking accept() */
#ifndef _WIN32
    if(g_node_pid > 0) kill(g_node_pid, SIGTERM);
#else
    /* Windows shutdown is finalized after the loop. */
#endif
}

static void install_signal_handlers(void) {
#ifdef _WIN32
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    /* Do not set SA_RESTART: accept()/recv() must return on Ctrl+C. */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif
}

static int qrx_set_env(const char *name, const char *value, int overwrite) {
#ifdef _WIN32
    if(!overwrite && getenv(name)) return 0;
    return _putenv_s(name, value ? value : "");
#else
    return setenv(name, value ? value : "", overwrite);
#endif
}

static int qrx_hex_nibble(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int qrx_hex_decode_text(const char *hex, char *out, size_t out_sz) {
    size_t n;
    if(!hex || !out || out_sz == 0) return -1;
    n = strlen(hex);
    if((n & 1u) || (n / 2u) + 1u > out_sz) return -1;
    for(size_t i=0, j=0; i<n; i+=2, ++j) {
        int hi=qrx_hex_nibble(hex[i]), lo=qrx_hex_nibble(hex[i+1]);
        if(hi < 0 || lo < 0) return -1;
        out[j]=(char)((hi<<4)|lo);
    }
    out[n/2u]=0;
    return 0;
}

static int load_wallet_passphrase_file(const char *path) {
    FILE *f;
    size_t n;
#ifndef _WIN32
    struct stat st;
    if(stat(path, &st) != 0) { perror("wallet passphrase file"); return -1; }
    if((st.st_mode & 077u) != 0u) {
        fprintf(stderr,"Refusing wallet passphrase file with group/other permissions; chmod 600 '%s'\n", path);
        return -1;
    }
#endif
    f=fopen(path,"rb");
    if(!f){ perror("wallet passphrase file"); return -1; }
    n=fread(g_wallet_passphrase,1,sizeof(g_wallet_passphrase)-1,f);
    if(ferror(f)){ fclose(f); OPENSSL_cleanse(g_wallet_passphrase,sizeof(g_wallet_passphrase)); return -1; }
    fclose(f);
    while(n && (g_wallet_passphrase[n-1]=='\n' || g_wallet_passphrase[n-1]=='\r')) --n;
    g_wallet_passphrase[n]=0;
    if(!n){ fprintf(stderr,"Wallet passphrase file is empty\n"); return -1; }
    return 0;
}

static int load_wallet_passphrase_stdin(void) {
    size_t n;
#ifdef _WIN32
    if(_isatty(_fileno(stdin))) { fprintf(stderr,"Refusing --wallet-passphrase-stdin on an interactive terminal because input would be echoed. Pipe from a protected secret source instead.\n"); return -1; }
#else
    if(isatty(STDIN_FILENO)) { fprintf(stderr,"Refusing --wallet-passphrase-stdin on an interactive terminal because input would be echoed. Pipe from a protected secret source instead.\n"); return -1; }
#endif
    if(!fgets(g_wallet_passphrase,sizeof(g_wallet_passphrase),stdin)) {
        fprintf(stderr,"Could not read wallet passphrase from stdin\n"); return -1;
    }
    n=strlen(g_wallet_passphrase);
    while(n && (g_wallet_passphrase[n-1]=='\n' || g_wallet_passphrase[n-1]=='\r')) g_wallet_passphrase[--n]=0;
    if(!n){ fprintf(stderr,"Wallet passphrase from stdin is empty\n"); return -1; }
    return 0;
}

static void configure_wallet_passphrase(const char *network) {
    if(getenv("QRX_PASSPHRASE")) return;

    if(g_wallet_passphrase[0]) {
        qrx_set_env("QRX_PASSPHRASE", g_wallet_passphrase, 1);
        return;
    }

    /* 0.0.9.75: never auto-unlock with the historical development
     * passphrase. Existing legacy wallets remain readable and can be
     * explicitly migrated by the GUI, but a daemon start without credentials
     * must stay locked on every network. */
    (void)network;
}

static EVP_PKEY *drive_load_pub(const char *name){char p[PATH_MAX];snprintf(p,sizeof(p),"%s/%s",g_wdir,name);FILE*f=fopen(p,"rb");if(!f)return NULL;EVP_PKEY*k=PEM_read_PUBKEY(f,NULL,NULL,NULL);fclose(f);return k;}
static EVP_PKEY *drive_load_priv(const char *name){char p[PATH_MAX];snprintf(p,sizeof(p),"%s/%s",g_wdir,name);const char*pw=getenv("QRX_PASSPHRASE");char derived[65]={0};if(!strcmp(name,"drive_mlkem768_priv.pem")){char ep[PATH_MAX];snprintf(ep,sizeof(ep),"%s/ed25519_priv.pem",g_wdir);FILE*ef=fopen(ep,"rb");EVP_PKEY*ed=ef?PEM_read_PrivateKey(ef,NULL,NULL,(void*)(pw?pw:"")):NULL;if(ef)fclose(ef);if(!ed)return NULL;unsigned char raw[64],dig[32];size_t rn=sizeof(raw);EVP_MD_CTX*m=NULL;unsigned dn=0;if(EVP_PKEY_get_raw_private_key(ed,raw,&rn)!=1||(m=EVP_MD_CTX_new())==NULL||EVP_DigestInit_ex(m,EVP_sha3_256(),NULL)!=1||EVP_DigestUpdate(m,"QRX-ADDRESS-RECOVERY-EXT-V1",27)!=1||EVP_DigestUpdate(m,raw,rn)!=1||EVP_DigestFinal_ex(m,dig,&dn)!=1||dn!=32){EVP_MD_CTX_free(m);EVP_PKEY_free(ed);OPENSSL_cleanse(raw,sizeof(raw));return NULL;}EVP_MD_CTX_free(m);EVP_PKEY_free(ed);OPENSSL_cleanse(raw,sizeof(raw));static const char*x="0123456789abcdef";for(int i=0;i<32;i++){derived[i*2]=x[dig[i]>>4];derived[i*2+1]=x[dig[i]&15];}OPENSSL_cleanse(dig,sizeof(dig));pw=derived;}FILE*f=fopen(p,"rb");if(!f){OPENSSL_cleanse(derived,sizeof(derived));return NULL;}EVP_PKEY*k=PEM_read_PrivateKey(f,NULL,NULL,(void*)(pw?pw:""));fclose(f);OPENSSL_cleanse(derived,sizeof(derived));return k;}
static void drive_prepare_dir(char out[PATH_MAX],const char*id){snprintf(out,PATH_MAX,"%s/drive/prepared/%s",g_wdir,id?id:"");}
static int handle_command(const char *cmdline, char *resp, size_t resp_sz);

static void dirname_of(const char *path, char *out, size_t out_sz){
    snprintf(out, out_sz, "%s", path && *path ? path : ".");
    char *slash = strrchr(out, '/');
#ifdef _WIN32
    char *bslash = strrchr(out, '\\');
    if(!slash || (bslash && bslash > slash)) slash = bslash;
#endif
    if(slash) { *slash = 0; if(!*out) snprintf(out, out_sz, "/"); }
    else snprintf(out, out_sz, ".");
}


static uint64_t qrxnet_height(void);

static int qrx_path_readable(const char *p) {
    if(!p || !*p) return 0;
#ifdef _WIN32
    return _access(p, 4) == 0;
#else
    return access(p, R_OK) == 0;
#endif
}

static EVP_PKEY *qrx_load_public_key_file(const char *path) {
    if(!path || !*path) return NULL;
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

static QrxAuraPowerProfile qrx_aura_power_profile_from_env(void) {
    const char *v = getenv("QRX_AURA_POWER_PROFILE");
    if(v && !strcmp(v, "eco")) return QRX_AURA_POWER_ECO;
    if(v && !strcmp(v, "performance")) return QRX_AURA_POWER_PERFORMANCE;
    return QRX_AURA_POWER_BALANCED;
}

static void qrx_aura_runtime_resource_defaults(const char *argv0,
                                                char catalog[PATH_MAX],
                                                char pubkey[PATH_MAX]) {
    const char *ce = getenv("QRX_AURA_RUNTIME_CATALOG");
    const char *ke = getenv("QRX_AURA_RUNTIME_PUBLISHER_KEY");
    if(ce && *ce) snprintf(catalog, PATH_MAX, "%s", ce); else catalog[0] = 0;
    if(ke && *ke) snprintf(pubkey, PATH_MAX, "%s", ke); else pubkey[0] = 0;
    if(catalog[0] && pubkey[0]) return;
    char dir[PATH_MAX]; dirname_of(argv0, dir, sizeof(dir));
#ifdef _WIN32
    if(!catalog[0]) snprintf(catalog, PATH_MAX, "%s\\aura\\official-runtime-catalog.qrx", dir);
    if(!pubkey[0]) snprintf(pubkey, PATH_MAX, "%s\\aura\\official-runtime-publisher.pem", dir);
#else
    if(!catalog[0]) snprintf(catalog, PATH_MAX, "%s/aura/official-runtime-catalog.qrx", dir);
    if(!pubkey[0]) snprintf(pubkey, PATH_MAX, "%s/aura/official-runtime-publisher.pem", dir);
#endif
}

/* Best-effort zero-touch AURA runtime bootstrap. A missing release catalog/key
 * never prevents the node from starting; it only leaves AURA AUTO pending.
 * A present but invalid/tampered package fails closed and is not activated. */
static int qrx_aura_runtime_bootstrap_startup(const char *argv0) {
    const char *host_path = getenv("QRX_AURA_PROVIDER_CONFIG");
    if(!host_path || !*host_path || !qrx_path_readable(host_path)) return 1;

    QrxAuraProviderHostConfig host;
    if(qrx_aura_provider_host_config_load(host_path, &host) != 0 || !host.enabled) return 1;
    if(host.runtime_adapter.kind != QRX_AURA_ADAPTER_AUTO && host.runtime_adapter.explicit_path[0]) return 2;

    char catalog[PATH_MAX], pubkey_path[PATH_MAX];
    qrx_aura_runtime_resource_defaults(argv0, catalog, pubkey_path);
    if(!qrx_path_readable(catalog) || !qrx_path_readable(pubkey_path)) {
        fprintf(stderr, "AURA: AUTO runtime catalog/key not packaged yet; provider remains pending\n");
        return 3;
    }

    EVP_PKEY *pubkey = qrx_load_public_key_file(pubkey_path);
    if(!pubkey) {
        fprintf(stderr, "AURA: could not load official runtime publisher key; AUTO runtime disabled\n");
        return -1;
    }

    char cache_dir[PATH_MAX], work_dir[PATH_MAX], install_dir[PATH_MAX];
#ifdef _WIN32
    snprintf(cache_dir, sizeof(cache_dir), "%s\\aura-runtime-cas", g_ndir);
    snprintf(work_dir, sizeof(work_dir), "%s\\aura-runtime-work", g_ndir);
    snprintf(install_dir, sizeof(install_dir), "%s\\aura-runtimes", g_ndir);
#else
    snprintf(cache_dir, sizeof(cache_dir), "%s/aura-runtime-cas", g_ndir);
    snprintf(work_dir, sizeof(work_dir), "%s/aura-runtime-work", g_ndir);
    snprintf(install_dir, sizeof(install_dir), "%s/aura-runtimes", g_ndir);
#endif
    if(qrx_mkdir_simple(cache_dir) || qrx_mkdir_simple(work_dir) || qrx_mkdir_simple(install_dir)) {
        EVP_PKEY_free(pubkey);
        fprintf(stderr, "AURA: could not create runtime directories\n");
        return -2;
    }

    QrxStorageFs *cache = NULL;
    if(qrx_storage_fs_open(cache_dir, 0, 0, &cache) != 0) {
        EVP_PKEY_free(pubkey);
        fprintf(stderr, "AURA: could not open runtime CAS\n");
        return -3;
    }

    QrxAuraRuntimeDeliveryContext delivery;
    qrx_aura_runtime_delivery_defaults(&delivery, work_dir);
    delivery.local_cache = cache;
    delivery.allow_https_origin = 1;
    delivery.allow_file_origin = 0;

    QrxAuraRuntimeProbeActivation probe;
    memset(&probe, 0, sizeof(probe));
    probe.model_cache = NULL; /* plugin ABI probe does not load a model */
    QrxAuraRuntimeSinglePublisherKey key = { "qrx:runtime:official", pubkey };
    QrxAuraRuntimeOneClickResult result;
    memset(&result, 0, sizeof(result));
    uint64_t height = qrxnet_height();
    int rc = qrx_aura_runtime_auto_bootstrap(host_path, catalog, height,
                                              qrx_aura_power_profile_from_env(), install_dir,
                                              qrx_aura_runtime_single_publisher_lookup, &key,
                                              &delivery, &probe, &result);
    if(rc == 0) {
        fprintf(stderr, "AURA: AUTO runtime activated package=%s path=%s\n",
                result.plan.package.package_id, result.installed_path);
    } else if(rc < 0) {
        fprintf(stderr, "AURA: AUTO runtime bootstrap rejected (%d); no unverified runtime activated\n", rc);
    }
    qrx_aura_runtime_probe_activation_close(&probe);
    qrx_storage_fs_close(cache);
    EVP_PKEY_free(pubkey);
    return rc;
}

static void build_backend_path(const char *argv0){
    char dir[PATH_MAX];
    dirname_of(argv0, dir, sizeof(dir));
    #ifdef _WIN32
    snprintf(g_backend_path, sizeof(g_backend_path), "%s\\qrx.exe", dir);
#else
    snprintf(g_backend_path, sizeof(g_backend_path), "%s/qrx", dir);
#endif
}

static void trim_nl(char *s){ if(!s) return; s[strcspn(s, "\r\n")] = 0; }
static void trim_ws_right(char *s){ if(!s) return; size_t n=strlen(s); while(n && (s[n-1]=='\n'||s[n-1]=='\r'||s[n-1]==' '||s[n-1]=='\t')) s[--n]=0; }

static int run_capture(char *const argv[], char *out, size_t out_sz){
#ifdef _WIN32
    if(out_sz) out[0] = 0;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = NULL, wr = NULL;
    if(!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    char cmdline[8192];
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", g_backend_path);
    for(int i=1; argv[i]; ++i){
        strncat(cmdline, " \"", sizeof(cmdline)-strlen(cmdline)-1);
        strncat(cmdline, argv[i], sizeof(cmdline)-strlen(cmdline)-1);
        strncat(cmdline, "\"", sizeof(cmdline)-strlen(cmdline)-1);
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(wr);
    if(!ok){ CloseHandle(rd); return -1; }

    size_t off = 0;
    DWORD got = 0;
    while(ReadFile(rd, out + off, (DWORD)(out_sz > off ? out_sz - off - 1 : 0), &got, NULL) && got > 0){
        off += got;
        if(off + 1 >= out_sz) break;
    }
    if(out_sz) out[off] = 0;
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0 ? 0 : -1;
#else
    int pfd[2];
    if(pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if(pid < 0){ close(pfd[0]); close(pfd[1]); return -1; }
    if(pid == 0){
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]); close(pfd[1]);
        execv(g_backend_path, argv);
        perror("execv");
        _exit(127);
    }
    close(pfd[1]);
    size_t off = 0; ssize_t n;
    while((n = read(pfd[0], out + off, out_sz > off ? out_sz - off - 1 : 0)) > 0){
        off += (size_t)n;
        if(off + 1 >= out_sz) break;
    }
    out[off] = 0;
    close(pfd[0]);
    int st = 0; waitpid(pid, &st, 0);
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
#endif
}


static int run_capture_signer(char *const argv[],const char*wallet_name,char*out,size_t out_sz){QrxSignerSession*ss=signer_session(wallet_name,0);if(!ss||!ss->unlocked)return -1;
#ifndef _WIN32
 int pfd[2];if(pipe(pfd))return -1;pid_t pid=fork();if(pid<0){close(pfd[0]);close(pfd[1]);return -1;}if(pid==0){dup2(pfd[1],STDOUT_FILENO);dup2(pfd[1],STDERR_FILENO);close(pfd[0]);close(pfd[1]);setenv("QRX_PASSPHRASE",ss->secret,1);execv(g_backend_path,argv);_exit(127);}close(pfd[1]);size_t off=0;ssize_t n;while((n=read(pfd[0],out+off,out_sz>off?out_sz-off-1:0))>0){off+=(size_t)n;if(off+1>=out_sz)break;}out[off]=0;close(pfd[0]);int st=0;waitpid(pid,&st,0);return WIFEXITED(st)&&WEXITSTATUS(st)==0?0:-1;
#else
 SetEnvironmentVariableA("QRX_PASSPHRASE",ss->secret);int rc=run_capture(argv,out,out_sz);SetEnvironmentVariableA("QRX_PASSPHRASE",NULL);return rc;
#endif
}

/* Bootstrap signs its HELLO in the qrx child process.  A GUI may start qrxd
 * while the wallet is locked and establish an in-memory signer session later;
 * in that case the original daemon environment has no QRX_PASSPHRASE.  Pass
 * the verified session secret only to the bootstrap child, just as validator
 * signing already does, so unlocking a running wallet also enables discovery. */
static int run_capture_bootstrap(char *const argv[],char*out,size_t out_sz){
    QrxSignerSession*ss=signer_session(g_primary_wallet,0);
    if(ss&&ss->unlocked)return run_capture_signer(argv,g_primary_wallet,out,out_sz);
    return run_capture(argv,out,out_sz);
}
static int copy_file_local(const char *src, const char *dst){
    FILE *in=fopen(src,"rb"); if(!in) return -1;
    FILE *out=fopen(dst,"wb"); if(!out){ fclose(in); return -1; }
    char buf[8192]; size_t n; int rc=0;
    while((n=fread(buf,1,sizeof(buf),in))>0){ if(fwrite(buf,1,n,out)!=n){ rc=-1; break; }}
    fclose(in); fclose(out); return rc;
}
static int parse_last_path_with_suffix(const char *text, const char *suffix, char *out, size_t out_sz){
    if(!text || !suffix || !out || !out_sz) return -1;
    out[0]=0; char *copy=strdup(text); if(!copy) return -1;
    char *save=NULL; char *line=strtok_r(copy,"\n",&save);
    size_t slen=strlen(suffix);
    while(line){ trim_ws_right(line); size_t len=strlen(line); if(len>=slen && strcmp(line+len-slen,suffix)==0) snprintf(out,out_sz,"%s",line); line=strtok_r(NULL,"\n",&save); }
    free(copy); return out[0]?0:-1;
}
static int cfg_get_line_local(const char *path, const char *key, char *out, size_t out_sz){
    FILE *f=fopen(path,"rb"); if(!f) return -1;
    char line[4096]; size_t klen=strlen(key); int rc=-1;
    while(fgets(line,sizeof(line),f)){ trim_nl(line); if(strlen(line)>klen && !strncmp(line,key,klen) && line[klen]=='='){ snprintf(out,out_sz,"%s",line+klen+1); rc=0; break; }}
    fclose(f); return rc;
}

static long long qrx_connection_count(void);
static long long qrx_best_peer_height(long long local_height);
static void qrx_best_block_info(long long *height, char *hash, size_t hash_sz, long long *block_time);

static long long qrx_chain_cfg_ll_local(const char *key, long long defv) {
    char path[PATH_MAX], val[128];
    snprintf(path, sizeof(path), "%s/genesis.cfg", g_cdir);
    if(cfg_get_line_local(path, key, val, sizeof(val)) == 0) return atoll(val);
    return defv;
}

static int validator_catchup_safe(void) {
    long long h=0, bt=0; char bh[256]={0};
    qrx_best_block_info(&h,bh,sizeof(bh),&bt);
    long long peers=qrx_connection_count();
    long long peer_h=qrx_best_peer_height(h);
    long long highest=peer_h>h?peer_h:h;
    long long behind=highest>h?highest-h:0;
    long long max_behind=qrx_chain_cfg_ll_local("validator_catchup_max_blocks",2);
    long long min_peers=qrx_chain_cfg_ll_local("validator_catchup_min_peers",1);
    long long stable=qrx_chain_cfg_ll_local("validator_catchup_stable_seconds",30);
    if(!strcmp(g_network,"regtest")) min_peers=0;
    g_validator_blocks_behind=behind;
    if(peers < min_peers) {
        g_validator_signing_paused=1; g_validator_sync_safe_since=0;
        snprintf(g_validator_pause_reason,sizeof(g_validator_pause_reason),"waiting_for_peers");
        return 0;
    }
    if(behind > max_behind) {
        g_validator_signing_paused=1; g_validator_sync_safe_since=0;
        snprintf(g_validator_pause_reason,sizeof(g_validator_pause_reason),"catching_up");
        return 0;
    }
    time_t now=time(NULL);
    if(g_validator_sync_safe_since==0) g_validator_sync_safe_since=now;
    if(stable>0 && now-g_validator_sync_safe_since < stable) {
        g_validator_signing_paused=1;
        snprintf(g_validator_pause_reason,sizeof(g_validator_pause_reason),"sync_stabilizing");
        return 0;
    }
    g_validator_signing_paused=0;
    snprintf(g_validator_pause_reason,sizeof(g_validator_pause_reason),"ready");
    return 1;
}

static int spawn_node_process(void){
#ifdef _WIN32
    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" \"node-run\" \"%s\"", g_backend_path, g_ndir);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if(!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return -1;

    CloseHandle(pi.hThread);
    g_node_handle = pi.hProcess;
    g_node_pid = pi.dwProcessId;
    return 0;
#else
    pid_t pid = fork();
    if(pid < 0) return -1;
    if(pid == 0){
        char *argv[] = { g_backend_path, "node-run", g_ndir, NULL };
        execv(g_backend_path, argv);
        perror("execv node-run");
        _exit(127);
    }
    g_node_pid = pid;
    return 0;
#endif
}


#ifdef _WIN32
static DWORD WINAPI maint_loop(LPVOID arg){
#else
static void *maint_loop(void *arg){
#endif
    MaintCtx *ctx = (MaintCtx*)arg;
    (void)ctx;
    while(g_running){
        char buf[8192];
        char *discover[] = { g_backend_path, "discover-peers", g_ndir, NULL };
        char *bootstrap[] = { g_backend_path, "bootstrap", g_ndir, NULL };
        char *process[] = { g_backend_path, "node-process-inbox", g_ndir, NULL };
        char *decay[] = { g_backend_path, "decay-bans", g_ndir, "1", NULL };
        run_capture(discover, buf, sizeof(buf));
        run_capture_bootstrap(bootstrap, buf, sizeof(buf));
        run_capture(process, buf, sizeof(buf));
        char *generals_offline[] = { g_backend_path, "generals-offline-process", g_cdir, NULL };
        run_capture(generals_offline, buf, sizeof(buf));
        run_capture(decay, buf, sizeof(buf));
        /* Peer discovery performs signed HELLO + GETPEERS exchanges. Running it
           every five seconds trips the peers' one-minute abuse limits. */
        for(int i=0;i<60 && g_running;i++) sleep(1);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int fleet_wallet_dir(int idx, char *out, size_t out_sz) {
    if(idx < 0 || idx >= g_validator_wallet_count || !out || out_sz == 0) return -1;
    snprintf(out, out_sz, "%s/wallets/%s", g_base, g_validator_wallet_names[idx]);
    return 0;
}

static int fleet_has_name(const char *name) {
    for(int i=0;i<g_validator_wallet_count;i++) if(!strcmp(g_validator_wallet_names[i], name)) return 1;
    return 0;
}

static unsigned long long g_fleet_proposer_cursor = 0;


#ifdef _WIN32
static DWORD WINAPI producer_loop(LPVOID arg){
#else
static void *producer_loop(void *arg){
#endif
    MaintCtx *ctx = (MaintCtx*)arg;
    (void)ctx;
    while(g_running){
        for(int i=0;i<g_blocktime_seconds && g_running;i++) sleep(1);
        if(!g_running) break;
        /* Never propose or vote while behind the peer head, while disconnected on a
           public network, or during the short post-sync stabilization window. */
        if(!validator_catchup_safe()) continue;
        char out[65536], block_path[PATH_MAX], vote_path[PATH_MAX], height_s[64], round_s[64], validator[512], vote_dest[PATH_MAX];
        char max_txs_s[16]; snprintf(max_txs_s,sizeof(max_txs_s),"100");
        /* Phase 7.2.9: one synchronized node, many validator signing identities.
           Proposal identity rotates deterministically by next height. All configured
           signer identities vote on the same proposal, each with its own double-sign lock. */
        int signer_count = g_validator_wallet_count;
        int proposer_idx = -1;
        char proposer_wdir[PATH_MAX]={0};
        int proposed = -1;
        if(signer_count > 0) {
            /* A locked/under-staked fleet wallet must not stall the whole node.
               Try each configured signer once, starting from the round-robin cursor. */
            for(int attempt=0; attempt<signer_count; attempt++) {
                int candidate = (int)((g_fleet_proposer_cursor + (unsigned long long)attempt) % (unsigned long long)signer_count);
                if(fleet_wallet_dir(candidate, proposer_wdir, sizeof(proposer_wdir))!=0) continue;
                char *propose_as[] = { g_backend_path, "propose-block-as", g_ndir, proposer_wdir, max_txs_s, NULL };
                if(run_capture_signer(propose_as,g_validator_wallet_names[candidate],out,sizeof(out))==0) { proposer_idx=candidate; proposed=0; break; }
            }
        } else {
            char *propose[] = { g_backend_path, "propose-block", g_ndir, max_txs_s, NULL };
            proposed = run_capture(propose,out,sizeof(out));
        }
        if(proposed!=0) continue;
        if(parse_last_path_with_suffix(out,".block",block_path,sizeof(block_path))!=0) continue;
        char *verify[] = { g_backend_path, "verify-block", g_cdir, block_path, NULL };
        if(run_capture(verify,out,sizeof(out))!=0) continue;

        int votes_written = 0;
        if(signer_count > 0) {
            for(int si=0; si<signer_count; si++) {
                char signer_wdir[PATH_MAX]={0}; if(fleet_wallet_dir(si, signer_wdir, sizeof(signer_wdir))!=0) continue;
                char *vote_as[] = { g_backend_path, "vote-block-as", g_ndir, signer_wdir, block_path, NULL };
                if(run_capture_signer(vote_as,g_validator_wallet_names[si],out,sizeof(out))!=0) continue;
                if(parse_last_path_with_suffix(out,".vote",vote_path,sizeof(vote_path))==0 &&
                   cfg_get_line_local(vote_path,"height",height_s,sizeof(height_s))==0 &&
                   cfg_get_line_local(vote_path,"round",round_s,sizeof(round_s))==0 &&
                   cfg_get_line_local(vote_path,"validator",validator,sizeof(validator))==0){
                    snprintf(vote_dest,sizeof(vote_dest),"%s/consensus/votes/%s-%s-%s.vote",g_cdir,height_s,round_s,validator);
                    if(copy_file_local(vote_path,vote_dest)==0) votes_written++;
                }
            }
        } else {
            char *vote[] = { g_backend_path, "vote-block", g_ndir, block_path, NULL };
            if(run_capture(vote,out,sizeof(out))==0 && parse_last_path_with_suffix(out,".vote",vote_path,sizeof(vote_path))==0){
                if(cfg_get_line_local(vote_path,"height",height_s,sizeof(height_s))==0 && cfg_get_line_local(vote_path,"round",round_s,sizeof(round_s))==0 && cfg_get_line_local(vote_path,"validator",validator,sizeof(validator))==0){
                    snprintf(vote_dest,sizeof(vote_dest),"%s/consensus/votes/%s-%s-%s.vote",g_cdir,height_s,round_s,validator);
                    if(copy_file_local(vote_path,vote_dest)==0) votes_written++;
                }
            }
        }
        if(votes_written <= 0) continue;
        char *tally[] = { g_backend_path, "tally-votes", g_cdir, block_path, NULL };
        run_capture(tally,out,sizeof(out));
        char *finalize[] = { g_backend_path, "finalize-block", g_cdir, block_path, NULL };
        if(run_capture(finalize,out,sizeof(out))==0){
            if(signer_count > 0 && proposer_idx >= 0) g_fleet_proposer_cursor = (unsigned long long)proposer_idx + 1ULL;
            char bps[32]; snprintf(bps,sizeof(bps),"%lld",g_commission_bps);
            char *reward[] = { g_backend_path, "reward-epoch-auto", g_cdir, bps, "--block-finalized", NULL };
            run_capture(reward,out,sizeof(out));
        }
        char *publish[] = { g_backend_path, "node-publish-block", g_ndir, block_path, NULL };
        run_capture(publish,out,sizeof(out));
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int write_all(qrx_socket_t fd, const char *buf, size_t len){
#ifdef _WIN32
    SOCKET s = fd;
    while(len){
        int n = send(s, buf, (int)len, 0);
        if(n <= 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
#else
    while(len){ ssize_t n = write(fd, buf, len); if(n < 0){ if(errno == EINTR) continue; return -1; } buf += n; len -= (size_t)n; }
    return 0;
#endif
}


static void json_escape_append(char *dst, size_t dst_sz, const char *src){
    size_t off = strlen(dst);
    for(const unsigned char *p=(const unsigned char*)src; *p && off + 8 < dst_sz; ++p){
        unsigned char c = *p;
        if(c == '"' || c == '\\'){ dst[off++]='\\'; dst[off++]=(char)c; }
        else if(c == '\n'){ dst[off++]='\\'; dst[off++]='n'; }
        else if(c == '\r'){ dst[off++]='\\'; dst[off++]='r'; }
        else if(c == '\t'){ dst[off++]='\\'; dst[off++]='t'; }
        else if(c < 32){ off += (size_t)snprintf(dst+off, dst_sz-off, "\\u%04x", c); }
        else dst[off++] = (char)c;
    }
    dst[off] = 0;
}

static void json_string(char *dst, size_t dst_sz, const char *src){
    snprintf(dst, dst_sz, "\"");
    json_escape_append(dst, dst_sz, src ? src : "");
    strncat(dst, "\"", dst_sz - strlen(dst) - 1);
}

static void json_ok_raw(char *resp, size_t resp_sz, const char *method, const char *raw){
    char m[256]={0}, r[60000]={0};
    json_string(m,sizeof(m),method);
    json_string(r,sizeof(r),raw?raw:"");
    snprintf(resp, resp_sz, "{\"ok\":true,\"method\":%s,\"result_raw\":%s}\n", m, r);
}

static void json_error(char *resp, size_t resp_sz, const char *method, const char *msg){
    char m[256]={0}, e[2048]={0};
    json_string(m,sizeof(m),method?method:"error");
    json_string(e,sizeof(e),msg?msg:"error");
    snprintf(resp, resp_sz, "{\"ok\":false,\"method\":%s,\"error\":%s}\n", m, e);
}

static void json_ok_string(char *resp, size_t resp_sz, const char *method, const char *key, const char *val){
    char m[256]={0}, v[4096]={0};
    json_string(m,sizeof(m),method); json_string(v,sizeof(v),val?val:"");
    snprintf(resp, resp_sz, "{\"ok\":true,\"method\":%s,\"result\":{\"%s\":%s}}\n", m, key, v);
}

static void json_ok_number(char *resp, size_t resp_sz, const char *method, const char *key, long long val){
    char m[256]={0}; json_string(m,sizeof(m),method);
    snprintf(resp, resp_sz, "{\"ok\":true,\"method\":%s,\"result\":{\"%s\":%lld}}\n", m, key, val);
}

static void json_keyval_object(char *dst, size_t dst_sz, const char *text){
    snprintf(dst, dst_sz, "{");
    int first = 1;
    char *copy = strdup(text ? text : "");
    if(!copy){ strncat(dst, "}", dst_sz - strlen(dst) - 1); return; }
    char *save = NULL; char *line = strtok_r(copy, "\n", &save);
    while(line){
        char *eq = strchr(line, '=');
        if(eq){
            *eq = 0; const char *k = line; const char *v = eq + 1;
            char jk[512]={0}, jv[4096]={0};
            json_string(jk,sizeof(jk),k);
            int numeric = (*v=='-'||(*v>='0'&&*v<='9'));
            for(const char *p=v; *p; ++p) if(!((*p>='0'&&*p<='9')||*p=='-' )) { numeric = 0; break; }
            if(!first) strncat(dst, ",", dst_sz - strlen(dst) - 1);
            strncat(dst, jk, dst_sz - strlen(dst) - 1);
            strncat(dst, ":", dst_sz - strlen(dst) - 1);
            if(numeric) strncat(dst, v, dst_sz - strlen(dst) - 1);
            else { json_string(jv,sizeof(jv),v); strncat(dst, jv, dst_sz - strlen(dst) - 1); }
            first = 0;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    strncat(dst, "}", dst_sz - strlen(dst) - 1);
}

static void json_lines_array(char *dst, size_t dst_sz, const char *text){
    snprintf(dst, dst_sz, "[");
    int first = 1;
    char *copy = strdup(text ? text : "");
    if(!copy){ strncat(dst, "]", dst_sz - strlen(dst) - 1); return; }
    char *save = NULL; char *line = strtok_r(copy, "\n", &save);
    while(line){
        if(*line){
            char js[4096]={0}; json_string(js,sizeof(js),line);
            if(!first) strncat(dst, ",", dst_sz - strlen(dst) - 1);
            strncat(dst, js, dst_sz - strlen(dst) - 1);
            first = 0;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    strncat(dst, "]", dst_sz - strlen(dst) - 1);
}

static long long count_regular_files(const char *dirpath){
#ifdef _WIN32
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dirpath);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if(h == INVALID_HANDLE_VALUE) return 0;
    long long n = 0;
    do {
        if(fd.cFileName[0] == '.') continue;
        if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) n++;
    } while(FindNextFileA(h, &fd));
    FindClose(h);
    return n;
#else
    DIR *d = opendir(dirpath); if(!d) return 0;
    long long n = 0; struct dirent *de;
    while((de = readdir(d))){ if(de->d_name[0]=='.') continue; if(de->d_type == DT_REG || de->d_type == DT_UNKNOWN) n++; }
    closedir(d); return n;
#endif
}

static char *read_text_file_local(const char *path){
    FILE *f = fopen(path, "rb");
    if(!f) return NULL;
    if(fseek(f, 0, SEEK_END) != 0){ fclose(f); return NULL; }
    long n = ftell(f);
    if(n < 0){ fclose(f); return NULL; }
    rewind(f);
    char *buf = (char*)malloc((size_t)n + 1);
    if(!buf){ fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[r] = 0;
    return buf;
}

static int cfg_value_local(const char *text, const char *key, char *out, size_t out_sz){
    if(!text || !key || !out || out_sz == 0) return -1;
    out[0] = 0;
    size_t klen = strlen(key);
    const char *p = text;
    while(p && *p){
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if(len > klen && !strncmp(p, key, klen) && p[klen] == '='){
            size_t vlen = len - klen - 1;
            if(vlen >= out_sz) vlen = out_sz - 1;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = 0;
            return 0;
        }
        p = e ? e + 1 : NULL;
    }
    return -1;
}

static long long parse_ll_safe(const char *s, long long fallback){
    if(!s || !*s) return fallback;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    return end && end != s ? v : fallback;
}

static void qrx_best_block_info(long long *height, char *hash, size_t hash_sz, long long *block_time){
    if(height) *height = 0;
    if(hash && hash_sz) hash[0] = 0;
    if(block_time) *block_time = 0;
    char bdir[PATH_MAX];
    snprintf(bdir, sizeof(bdir), "%s/blocks", g_cdir);
    long long best_h = -1;
    char best_hash[256] = {0};
    long long best_ts = 0;
#ifdef _WIN32
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", bdir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search, &fd);
    if(h != INVALID_HANDLE_VALUE){
        do {
            if(fd.cFileName[0] == '.' || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s\\%s", bdir, fd.cFileName);
#else
    DIR *d = opendir(bdir);
    if(d){
        struct dirent *fd;
        while((fd = readdir(d))){
            if(fd->d_name[0] == '.') continue;
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", bdir, fd->d_name);
#endif
            char *txt = read_text_file_local(path);
            if(txt){
                char hs[64] = {0}, bh[256] = {0}, ts[64] = {0};
                long long hval = -1;
                if(cfg_value_local(txt, "height", hs, sizeof(hs)) == 0) hval = parse_ll_safe(hs, -1);
                if(hval < 0) hval = 0;
                cfg_value_local(txt, "block_hash", bh, sizeof(bh));
                cfg_value_local(txt, "timestamp", ts, sizeof(ts));
                if(hval > best_h){
                    best_h = hval;
                    snprintf(best_hash, sizeof(best_hash), "%s", bh);
                    best_ts = parse_ll_safe(ts, 0);
                }
                free(txt);
            }
#ifdef _WIN32
        } while(FindNextFileA(h, &fd));
        FindClose(h);
#else
        }
        closedir(d);
#endif
    }
    if(best_h < 0) best_h = 0;
    if(height) *height = best_h;
    if(hash && hash_sz) snprintf(hash, hash_sz, "%s", best_hash);
    if(block_time) *block_time = best_ts;
}

static long long qrx_connection_count(void){
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/peer_state.db", g_ndir);
    char *txt=read_text_file_local(p);if(!txt)return 0;
    const long long cutoff=(long long)time(NULL)-180;
    long long n=0;char *save=NULL,*line=strtok_r(txt,"\n",&save);
    while(line){
        char *eq=strchr(line,'=');
        if(eq){
            *eq=0;size_t klen=strlen(line);long long seen=parse_ll_safe(eq+1,0);
            if(klen>10&&!strcmp(line+klen-10,"_last_seen")&&seen>=cutoff&&strcmp(line,"0_0_0_0_last_seen"))n++;
        }
        line=strtok_r(NULL,"\n",&save);
    }
    free(txt);return n;
}

static long long qrx_best_peer_height(long long local_height){
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/peer_state.db", g_ndir);
    char *txt = read_text_file_local(p);
    if(!txt) return local_height;
    long long best = local_height;
    char *save = NULL;
    char *line = strtok_r(txt, "\n", &save);
    while(line){
        char lower[512];
        size_t i;
        for(i=0; line[i] && i+1<sizeof(lower); ++i){
            char c = line[i];
            lower[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        lower[i] = 0;
        if(strstr(lower, "height") || strstr(lower, "block")){
            char *eq = strchr(line, '=');
            if(eq){
                long long v = parse_ll_safe(eq+1, -1);
                if(v > best) best = v;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(txt);
    return best;
}


typedef struct {
    long long height;
    char hash[256];
    char timestamp[64];
    char tx_count[32];
    char path[PATH_MAX];
} QrxRecentBlock;

static void qrx_insert_recent_block(QrxRecentBlock *arr, int *n, int max, const QrxRecentBlock *b){
    if(max <= 0) return;
    int pos = *n;
    if(pos < max) (*n)++;
    else if(b->height <= arr[max-1].height) return;
    if(pos >= max) pos = max - 1;
    while(pos > 0 && arr[pos-1].height < b->height){ arr[pos] = arr[pos-1]; pos--; }
    arr[pos] = *b;
}

static int qrx_collect_recent_blocks(QrxRecentBlock *arr, int max){
    int n = 0;
    char bdir[PATH_MAX]; snprintf(bdir, sizeof(bdir), "%s/blocks", g_cdir);
#ifdef _WIN32
    char search[MAX_PATH]; snprintf(search, sizeof(search), "%s\\*", bdir);
    WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(search, &fd);
    if(h != INVALID_HANDLE_VALUE){
        do {
            if(fd.cFileName[0] == '.' || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            char path[MAX_PATH]; snprintf(path, sizeof(path), "%s\\%s", bdir, fd.cFileName);
#else
    DIR *d = opendir(bdir);
    if(d){
        struct dirent *fd;
        while((fd = readdir(d))){
            if(fd->d_name[0] == '.') continue;
            char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/%s", bdir, fd->d_name);
#endif
            char *txt = read_text_file_local(path);
            if(txt){
                QrxRecentBlock b; memset(&b, 0, sizeof(b));
                char hs[64] = {0};
                if(cfg_value_local(txt, "height", hs, sizeof(hs)) == 0) b.height = parse_ll_safe(hs, -1);
                cfg_value_local(txt, "block_hash", b.hash, sizeof(b.hash));
                cfg_value_local(txt, "timestamp", b.timestamp, sizeof(b.timestamp));
                cfg_value_local(txt, "tx_count", b.tx_count, sizeof(b.tx_count));
                snprintf(b.path, sizeof(b.path), "%s", path);
                if(b.height >= 0) qrx_insert_recent_block(arr, &n, max, &b);
                free(txt);
            }
#ifdef _WIN32
        } while(FindNextFileA(h, &fd));
        FindClose(h);
#else
        }
        closedir(d);
#endif
    }
    return n;
}

static void qrx_recent_blocks_json(char *out, size_t out_sz, int limit){
    if(limit <= 0) limit = 10; if(limit > 100) limit = 100;
    QrxRecentBlock arr[100]; memset(arr, 0, sizeof(arr));
    int n = qrx_collect_recent_blocks(arr, limit);
    snprintf(out, out_sz, "[");
    for(int i=0;i<n;i++){
        char hjs[512]={0}, tjs[128]={0};
        json_string(hjs, sizeof(hjs), arr[i].hash);
        json_string(tjs, sizeof(tjs), arr[i].timestamp);
        if(i) strncat(out, ",", out_sz - strlen(out) - 1);
        char item[1024];
        snprintf(item, sizeof(item), "{\"height\":%lld,\"hash\":%s,\"timestamp\":%s,\"tx_count\":%lld}", arr[i].height, hjs, tjs, parse_ll_safe(arr[i].tx_count, 0));
        strncat(out, item, out_sz - strlen(out) - 1);
    }
    strncat(out, "]", out_sz - strlen(out) - 1);
}

static void qrx_recent_transactions_json(char *out, size_t out_sz, int limit){
    if(limit <= 0) limit = 10; if(limit > 100) limit = 100;
    QrxRecentBlock blocks[100]; memset(blocks, 0, sizeof(blocks));
    int bn = qrx_collect_recent_blocks(blocks, 100);
    int emitted = 0;
    snprintf(out, out_sz, "[");
    for(int i=0;i<bn && emitted<limit;i++){
        char *txt = read_text_file_local(blocks[i].path);
        if(!txt) continue;
        long long txc = parse_ll_safe(blocks[i].tx_count, 0);
        for(long long j=1; j<=txc && emitted<limit; j++){
            char key[32], txh[256]={0}; snprintf(key, sizeof(key), "tx%lld", j);
            if(cfg_value_local(txt, key, txh, sizeof(txh)) == 0 && txh[0]){
                char txjs[512]={0}, bhjs[512]={0};
                json_string(txjs, sizeof(txjs), txh); json_string(bhjs, sizeof(bhjs), blocks[i].hash);
                if(emitted) strncat(out, ",", out_sz - strlen(out) - 1);
                char item[1024]; snprintf(item, sizeof(item), "{\"txid\":%s,\"block_height\":%lld,\"block_hash\":%s,\"index\":%lld,\"source\":\"block\"}", txjs, blocks[i].height, bhjs, j);
                strncat(out, item, out_sz - strlen(out) - 1);
                emitted++;
            }
        }
        free(txt);
    }
    if(emitted < limit){
        char mdir[PATH_MAX]; snprintf(mdir, sizeof(mdir), "%s/mempool", g_ndir);
#ifdef _WIN32
        char search[MAX_PATH]; snprintf(search, sizeof(search), "%s\\*", mdir);
        WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(search, &fd);
        if(h != INVALID_HANDLE_VALUE){
            do {
                if(fd.cFileName[0] == '.' || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                char path[MAX_PATH]; snprintf(path, sizeof(path), "%s\\%s", mdir, fd.cFileName);
#else
        DIR *d = opendir(mdir);
        if(d){
            struct dirent *fd;
            while((fd = readdir(d)) && emitted < limit){
                if(fd->d_name[0] == '.') continue;
                char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/%s", mdir, fd->d_name);
#endif
                char *txt = read_text_file_local(path);
                if(txt){
                    char txh[256]={0};
                    if(cfg_value_local(txt, "body_hash_sha3_512", txh, sizeof(txh)) != 0) cfg_value_local(txt, "body_hash", txh, sizeof(txh));
                    if(txh[0]){
                        char txjs[512]={0}; json_string(txjs, sizeof(txjs), txh);
                        if(emitted) strncat(out, ",", out_sz - strlen(out) - 1);
                        char item[768]; snprintf(item, sizeof(item), "{\"txid\":%s,\"source\":\"mempool\"}", txjs);
                        strncat(out, item, out_sz - strlen(out) - 1);
                        emitted++;
                    }
                    free(txt);
                }
#ifdef _WIN32
            } while(emitted < limit && FindNextFileA(h, &fd));
            FindClose(h);
#else
            }
            closedir(d);
#endif
        }
    }
    strncat(out, "]", out_sz - strlen(out) - 1);
}

static void qrx_uptime_human(long long sec, char *out, size_t out_sz){
    long long d = sec / 86400; sec %= 86400;
    long long h = sec / 3600; sec %= 3600;
    long long m = sec / 60; sec %= 60;
    snprintf(out, out_sz, "%lldd %lldh %lldm %llds", d, h, m, sec);
}


static int parse_hostport_local(const char *hp, char *host, size_t host_sz, char *port, size_t port_sz){
    return qrx_parse_hostport(hp, host, host_sz, port, port_sz);
}


static void parse_rpc_bind_default(const char *network) {
    snprintf(g_rpc_bind, sizeof(g_rpc_bind), "127.0.0.1");
    g_rpc_port = qrx_control_port_for_network(network);
}

static int parse_rpc_bind_arg(const char *arg) {
    if(!arg || !*arg) return -1;
    const char *colon = strrchr(arg, ':');
    if(!colon || colon == arg || !colon[1]) return -1;
    size_t hlen = (size_t)(colon - arg);
    if(hlen >= sizeof(g_rpc_bind)) return -1;
    memcpy(g_rpc_bind, arg, hlen);
    g_rpc_bind[hlen] = 0;
    g_rpc_port = atoi(colon + 1);
    if(g_rpc_port <= 0 || g_rpc_port > 65535) return -1;
    return 0;
}

/* Genesis hardening (Finding 3): explicit send/receive timeouts on an accepted
 * socket. Listener-level timeouts are not portably inherited by accept(), so a
 * peer that opens a connection and then stalls would otherwise pin the
 * single-threaded RPC loop indefinitely. */
#define QRX_RPC_SOCKET_TIMEOUT_SECS 10

static void qrx_rpc_set_socket_timeouts(qrx_socket_t fd) {
#ifdef _WIN32
    DWORD tv = QRX_RPC_SOCKET_TIMEOUT_SECS * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = QRX_RPC_SOCKET_TIMEOUT_SECS;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv));
#endif
}

static int rpc_bind_is_ipv4_loopback(const char *host) {
    struct in_addr addr;
    if(!host || inet_pton(AF_INET, host, &addr) != 1) return 0;
    const unsigned char *octets = (const unsigned char *)&addr.s_addr;
    return octets[0] == 127;
}

/* Genesis hardening (Finding 2): on Mainnet the wallet RPC is loopback-only.
 * Remote administration must go through an SSH tunnel or VPN, never through a
 * directly exposed RPC port. */
static int qrx_rpc_is_mainnet(void) {
    return g_network[0] && strstr(g_network, "mainnet") == g_network;
}

static int validate_rpc_exposure(void) {
    if(rpc_bind_is_ipv4_loopback(g_rpc_bind)) return 0;
    if(qrx_rpc_is_mainnet()) {
        fprintf(stderr,
            "SECURITY: refusing non-loopback RPC bind %s:%d on Mainnet. "
            "Mainnet wallet RPC is loopback-only; use an SSH tunnel or VPN for remote administration.\n",
            g_rpc_bind, g_rpc_port);
        return -1;
    }
    if(!g_allow_remote_rpc) {
        fprintf(stderr,
            "SECURITY: refusing non-loopback RPC bind %s:%d. "
            "Wallet RPC is local-only by default. If remote RPC is intentionally required, "
            "use --allow-remote-rpc together with non-empty --rpc-user and --rpc-password.\n",
            g_rpc_bind, g_rpc_port);
        return -1;
    }
    if(!g_rpc_user[0] || !g_rpc_password[0]) {
        fprintf(stderr,
            "SECURITY: remote RPC requires BOTH --rpc-user and --rpc-password. "
            "Refusing to expose unauthenticated wallet RPC on %s:%d.\n",
            g_rpc_bind, g_rpc_port);
        return -1;
    }
    fprintf(stderr,
        "WARNING: remote QRX RPC explicitly enabled on %s:%d. "
        "Use a host firewall/VPN and never expose this port directly to the public Internet.\n",
        g_rpc_bind, g_rpc_port);
    return 0;
}

static int qrx_random_token_hex(char*out,size_t out_sz){ unsigned char b[32]; if(out_sz<65)return -1; if(RAND_bytes(b,sizeof(b))!=1)return -1; for(size_t i=0;i<sizeof(b);i++)sprintf(out+i*2,"%02x",b[i]); out[64]=0; return 0;}
static int qrx_write_rpc_token(void){ char p[PATH_MAX]; snprintf(p,sizeof(p),"%s/rpc.token",g_cdir); if(qrx_random_token_hex(g_rpc_token,sizeof(g_rpc_token)))return -1; FILE*f=fopen(p,"wb");if(!f)return -1;fprintf(f,"%s\n",g_rpc_token);fclose(f);
#ifndef _WIN32
 chmod(p,0600);
#endif
 return 0;}
static int rpc_token_ok(const char*req){ if(!g_rpc_token[0])return 0; char exp[256];snprintf(exp,sizeof(exp),"X-QRX-RPC-Token: %s",g_rpc_token); return strstr(req,exp)!=NULL;}
static int header_has_json_content_type(const char*r){ const char*end=strstr(r,"\r\n\r\n");const char*h=qrx_strcasestr_local(r,"Content-Type:");const char*j=h?qrx_strcasestr_local(h,"application/json"):NULL;return end&&h&&j&&j<end;}
static int origin_allowed(const char*r){ const char*o=qrx_strcasestr_local(r,"Origin:"); if(!o)return 1; return !strncmp(o+7," http://localhost",17)||!strncmp(o+7," http://127.0.0.1",17)||!strncmp(o+7," tauri://localhost",18)||!strncmp(o+7," https://tauri.localhost",24);}
static int host_allowed(const char*r){ char want[128];snprintf(want,sizeof(want),"Host: 127.0.0.1:%d",g_rpc_port); if(strstr(r,want))return 1;snprintf(want,sizeof(want),"Host: localhost:%d",g_rpc_port);return strstr(r,want)!=NULL;}
static QrxSignerSession* signer_session(const char*w,int create){for(int i=0;i<g_signer_session_count;i++)if(!strcmp(g_signer_sessions[i].wallet,w))return &g_signer_sessions[i];if(!create||g_signer_session_count>=QRX_MAX_VALIDATOR_FLEET)return NULL;QrxSignerSession*s=&g_signer_sessions[g_signer_session_count++];memset(s,0,sizeof(*s));snprintf(s->wallet,sizeof(s->wallet),"%s",w);return s;}
static int signer_wallet_name_safe(const char *w){if(!w||!*w||strlen(w)>=128)return 0;for(const unsigned char*p=(const unsigned char*)w;*p;p++)if(!(isalnum(*p)||*p=='_'||*p=='-'||*p=='.'))return 0;return strcmp(w,".")&&strcmp(w,"..");}
static int signer_wallet_dir(const char*w,char*out,size_t cap){if(!signer_wallet_name_safe(w))return-1;const char*base=strrchr(g_wdir,'/');base=base?base+1:g_wdir;if(!strcmp(base,w)){snprintf(out,cap,"%s",g_wdir);return 0;}snprintf(out,cap,"%s/wallets/%s",g_base,w);return 0;}
static int signer_verify_secret(const char*w,const char*secret){char wd[PATH_MAX],p[PATH_MAX];if(signer_wallet_dir(w,wd,sizeof(wd)))return-1;snprintf(p,sizeof(p),"%s/ed25519_priv.pem",wd);FILE*f=fopen(p,"rb");if(!f)return-1;EVP_PKEY*k=PEM_read_PrivateKey(f,NULL,NULL,(void*)(secret?secret:""));fclose(f);if(!k)return-1;EVP_PKEY_free(k);return 0;}

static const char *http_status_text(int code) {
    if(code == 200) return "OK";
    if(code == 400) return "Bad Request";
    if(code == 401) return "Unauthorized";
    if(code == 403) return "Forbidden";
    if(code == 404) return "Not Found";
    return "Internal Server Error";
}

static void http_response(char *out, size_t out_sz, int code, const char *body, int auth_required) {
    const char *txt = http_status_text(code);
    const char *b = body ? body : "";
    snprintf(out, out_sz,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: tauri://localhost\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type, X-QRX-RPC-Token\r\n"
        "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
        "%s"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        code, txt,
        auth_required ? "WWW-Authenticate: Basic realm=\"QRX RPC\"\r\n" : "",
        strlen(b), b);
}

static char *qrx_base64_encode_local(const unsigned char *data, size_t len) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((len + 2) / 3) * 4;
    char *out = (char*)malloc(out_len + 1);
    if(!out) return NULL;
    size_t j = 0;
    for(size_t i = 0; i < len; i += 3) {
        unsigned int v = data[i] << 16;
        if(i + 1 < len) v |= data[i + 1] << 8;
        if(i + 2 < len) v |= data[i + 2];
        out[j++] = tbl[(v >> 18) & 63];
        out[j++] = tbl[(v >> 12) & 63];
        out[j++] = (i + 1 < len) ? tbl[(v >> 6) & 63] : '=';
        out[j++] = (i + 2 < len) ? tbl[v & 63] : '=';
    }
    out[j] = 0;
    return out;
}

static int rpc_auth_ok(const char *http_req) {
    if(!g_rpc_user[0] && !g_rpc_password[0]) return 1;
    char pair[512];
    snprintf(pair, sizeof(pair), "%s:%s", g_rpc_user, g_rpc_password);
    char *b64 = qrx_base64_encode_local((const unsigned char*)pair, strlen(pair));
    if(!b64) return 0;
    char expected[768];
    snprintf(expected, sizeof(expected), "Authorization: Basic %s", b64);
    int ok = strstr(http_req, expected) != NULL;
    free(b64);
    return ok;
}

static int json_get_string_field(const char *json, const char *key, char *out, size_t out_sz) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if(!p) return -1;
    p = strchr(p, ':');
    if(!p) return -1;
    p++;
    while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if(*p != '"') return -1;
    p++;
    size_t off = 0;
    while(*p && *p != '"' && off + 1 < out_sz) {
        if(*p == '\\' && p[1]) {
            p++;
            if(*p == 'n') out[off++] = '\n';
            else if(*p == 'r') out[off++] = '\r';
            else if(*p == 't') out[off++] = '\t';
            else out[off++] = *p;
            p++;
        } else {
            out[off++] = *p++;
        }
    }
    out[off] = 0;
    return off > 0 ? 0 : -1;
}

static int json_get_params_as_cmd_tail(const char *json, char *out, size_t out_sz) {
    out[0] = 0;
    const char *p = strstr(json, "\"params\"");
    if(!p) return 0;
    p = strchr(p, '[');
    if(!p) return 0;
    p++;
    int first = 1;
    while(*p && *p != ']') {
        while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') p++;
        char val[1024] = {0};
        size_t off = 0;
        if(*p == '"') {
            p++;
            while(*p && *p != '"' && off + 1 < sizeof(val)) {
                if(*p == '\\' && p[1]) p++;
                val[off++] = *p++;
            }
            if(*p == '"') p++;
        } else {
            while(*p && *p != ',' && *p != ']' && off + 1 < sizeof(val)) {
                if(*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') val[off++] = *p;
                p++;
            }
        }
        val[off] = 0;
        if(val[0]) {
            if(!first) strncat(out, " ", out_sz - strlen(out) - 1);
            strncat(out, val, out_sz - strlen(out) - 1);
            first = 0;
        }
        while(*p && *p != ',' && *p != ']') p++;
        if(*p == ',') p++;
    }
    return 0;
}

static void handle_json_rpc_http(const char *req, char *resp, size_t resp_sz) {
    if(strstr(req, "OPTIONS ") == req) {
        if(!origin_allowed(req) || !host_allowed(req)){http_response(resp,resp_sz,403,"{\"ok\":false,\"error\":\"forbidden origin/host\"}\n",0);return;}
        http_response(resp, resp_sz, 200, "{\"ok\":true}\n", 0); return;
    }
    if(!strstr(req, "POST ") || !strstr(req, " /rpc ")) {
        http_response(resp, resp_sz, 404, "{\"ok\":false,\"error\":\"not found\"}\n", 0);
        return;
    }
    if(!host_allowed(req) || !origin_allowed(req) || !header_has_json_content_type(req)) { http_response(resp,resp_sz,403,"{\"ok\":false,\"error\":\"RPC host/origin/content-type rejected\"}\n",0); return; }
    if(!rpc_token_ok(req)) { http_response(resp,resp_sz,401,"{\"ok\":false,\"error\":\"missing/invalid local RPC session token\"}\n",0); return; }
    if(!rpc_auth_ok(req)) {
        http_response(resp, resp_sz, 401, "{\"ok\":false,\"error\":\"unauthorized\"}\n", 1);
        return;
    }
    const char *body = strstr(req, "\r\n\r\n");
    if(!body) body = strstr(req, "\n\n");
    if(!body) {
        http_response(resp, resp_sz, 400, "{\"ok\":false,\"error\":\"missing body\"}\n", 0);
        return;
    }
    body += (body[1] == '\n') ? 2 : 4;

    char method[128] = {0};
    char tail[131072] = {0};
    char cmd[196608] = {0};
    char raw[131072] = {0};

    if(json_get_string_field(body, "method", method, sizeof(method)) != 0) {
        http_response(resp, resp_sz, 400, "{\"ok\":false,\"error\":\"missing method\"}\n", 0);
        return;
    }
    json_get_params_as_cmd_tail(body, tail, sizeof(tail));
    if(tail[0]) snprintf(cmd, sizeof(cmd), "%s %s\n", method, tail);
    else snprintf(cmd, sizeof(cmd), "%s\n", method);

    handle_command(cmd, raw, sizeof(raw));
    http_response(resp, resp_sz, 200, raw, 0);
}


static int aura_hex32(const char *hex,unsigned char out[32]){
    if(!hex||strlen(hex)!=64)return -1;for(size_t i=0;i<32;i++){char a=hex[i*2],b=hex[i*2+1];int hi=(a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:(a>='A'&&a<='F')?a-'A'+10:-1;int lo=(b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:(b>='A'&&b<='F')?b-'A'+10:-1;if(hi<0||lo<0)return -1;out[i]=(unsigned char)((hi<<4)|lo);}return 0;
}
static int aura_gov_root_lookup_qrxd(const char *chain,const char *id,char pubhex[65]){
    if(!chain||!id||!pubhex)return -1;char cnt[64];if(qrx_chain_get_value(chain,"governance_root_count",cnt,sizeof(cnt))==0){long long n=atoll(cnt);for(long long i=1;i<=n&&i<=32;i++){char kk[128],pkkey[128],kid[128],pk[128];snprintf(kk,sizeof(kk),"governance_root_%lld_key_id",i);snprintf(pkkey,sizeof(pkkey),"governance_root_%lld_public_key_hex",i);if(qrx_chain_get_value(chain,kk,kid,sizeof(kid))==0&&qrx_chain_get_value(chain,pkkey,pk,sizeof(pk))==0&&!strcmp(kid,id)&&strlen(pk)==64){memcpy(pubhex,pk,64);pubhex[64]=0;return 0;}}char net[64]={0};if(qrx_chain_get_value(chain,"network_id",net,sizeof(net))==0&&!strcmp(net,"mainnet"))return -1;}
    char path[PATH_MAX],line[512];snprintf(path,sizeof(path),"%s/governance/governance_roots.db",chain);FILE*f=fopen(path,"rb");if(!f)return -1;int rc=-1;while(fgets(line,sizeof(line),f)){if(line[0]=='#')continue;char k[128]={0},pk[65]={0},fp[33]={0},st[16]={0};if(sscanf(line,"%127[^|]|%64[^|]|%32[^|]|%15s",k,pk,fp,st)==4&&!strcmp(k,id)&&!strcmp(st,"ACTIVE")){snprintf(pubhex,65,"%s",pk);rc=0;break;}}fclose(f);return rc;
}
static int aura_gov_key_lookup_qrxd(void *ctx,const char *id,EVP_PKEY **out){
    char pk[65];unsigned char raw[32];if(!ctx||!id||!out||aura_gov_root_lookup_qrxd((const char*)ctx,id,pk)||aura_hex32(pk,raw))return -1;EVP_PKEY*k=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,raw,sizeof(raw));if(!k)return -1;*out=k;return 0;
}
static int aura_gov_authorize_qrxd(void *ctx,const char *id){char pk[65];return (!ctx||!id||aura_gov_root_lookup_qrxd((const char*)ctx,id,pk))?-1:0;}
static uint64_t aura_live_height_qrxd(void){char b[PATH_MAX];snprintf(b,sizeof(b),"%s/blocks",g_cdir);return (uint64_t)count_regular_files(b);}
static int aura_compute_key_lookup_qrxd(void *ctx,const char *provider_id,EVP_PKEY **out){
    if(!ctx||!provider_id||!out) return -1;
    if(qrx_compute_provider_identity_key_lookup(ctx,provider_id,out)==0) return 0;
    return qrx_storage_provider_discovery_key_lookup(ctx,provider_id,out);
}
static int aura_live_load_qrxd(QrxAuraPodGossipTable *pods,QrxAuraModelGossipTable *models,uint64_t *height){
    if(!pods||!models)return -1;qrx_aura_pod_gossip_init(pods);qrx_aura_model_gossip_init(models);uint64_t h=aura_live_height_qrxd();char pc[PATH_MAX],mc[PATH_MAX];snprintf(pc,sizeof(pc),"%s/aura-pod-gossip.cache",g_cdir);snprintf(mc,sizeof(mc),"%s/aura-model-gossip.cache",g_cdir);QrxDB db;if(qrxdb_init(&db,g_cdir)!=0)return -1;(void)qrx_aura_pod_gossip_cache_load(pods,pc,h,aura_compute_key_lookup_qrxd,&db);qrxdb_close(&db);(void)qrx_aura_model_gossip_cache_load(models,mc,h,aura_gov_key_lookup_qrxd,g_cdir,aura_gov_authorize_qrxd,g_cdir);qrx_aura_pod_gossip_prune(pods,h);qrx_aura_model_gossip_prune(models,h);if(height)*height=h;return 0;
}

static int drive_discovery_reload(QrxDB *db){
    if(!db)return -1; char bdir[PATH_MAX],cache[PATH_MAX];snprintf(bdir,sizeof(bdir),"%s/blocks",g_cdir);g_drive_discovery_height=(uint64_t)count_regular_files(bdir);
    snprintf(cache,sizeof(cache),"%s/storage-discovery.cache",g_cdir);QrxStorageDiscoveryTable fresh;qrx_storage_discovery_init(&fresh);
    int n=qrx_storage_discovery_cache_load(&fresh,db,cache,g_drive_discovery_height,qrx_storage_provider_discovery_key_lookup,db);
    if(n>=0){qrx_storage_discovery_free(&g_drive_discovery);g_drive_discovery=fresh;qrx_storage_discovery_prune(&g_drive_discovery,g_drive_discovery_height);return n;}
    qrx_storage_discovery_free(&fresh);return -1;
}
static int drive_runtime_sync_sources_mode(const char *contract_id,int upload){
    if(!g_drive_runtime || !contract_id || !*contract_id) return -1;
    QrxDB db; if(qrxdb_init(&db,g_cdir)!=0) return -1; drive_discovery_reload(&db);
    QrxShardProviderSource src[QRX_STORAGE_MAX_FETCH_SOURCES]; size_t n=0;
    int rc=upload?qrx_storage_discovery_sources_for_contract_upload(&g_drive_discovery,&db,contract_id,QRX_STORAGE_MAX_FETCH_SOURCES,g_drive_discovery_height,src,QRX_STORAGE_MAX_FETCH_SOURCES,&n)
                 :qrx_storage_discovery_sources_for_contract(&g_drive_discovery,&db,contract_id,QRX_STORAGE_MAX_FETCH_SOURCES,g_drive_discovery_height,src,QRX_STORAGE_MAX_FETCH_SOURCES,&n);
    if(rc==0 && n) rc=qrx_drive_runtime_set_contract_sources(g_drive_runtime,contract_id,src,n);
    qrxdb_close(&db); return rc;
}
static int drive_runtime_sync_sources(const char *contract_id){return drive_runtime_sync_sources_mode(contract_id,0);}
static void drive_job_json(char *resp,size_t sz,const char *method,const QrxDriveJobSnapshot *j){
    char id[300],cid[300],dir[80],path[2200],err[500];json_string(id,sizeof(id),j->transfer_id);json_string(cid,sizeof(cid),j->contract_id);json_string(dir,sizeof(dir),j->direction);json_string(path,sizeof(path),j->path);json_string(err,sizeof(err),j->error);
    snprintf(resp,sz,"{\"ok\":true,\"method\":\"%s\",\"result\":{\"transfer_id\":%s,\"contract_id\":%s,\"direction\":%s,\"path\":%s,\"state\":%u,\"total_bytes\":%llu,\"completed_bytes\":%llu,\"completed_shards\":%u,\"required_shards\":%u,\"total_shards\":%u,\"bytes_received\":%llu,\"sources_started\":%u,\"sources_completed\":%u,\"sources_failed\":%u,\"hedges_started\":%u,\"resumed_ranges\":%u,\"cancelled_sources\":%u,\"error\":%s}}\n",method,id,cid,dir,path,j->state,(unsigned long long)j->total_bytes,(unsigned long long)j->completed_bytes,j->completed_shards,j->required_shards,j->total_shards,(unsigned long long)j->bytes_received,j->sources_started,j->sources_completed,j->sources_failed,j->hedges_started,j->resumed_ranges,j->cancelled_sources,err);
}

static int drive_write_text(const char *path,const char *txt){FILE*f=fopen(path,"wb");if(!f)return-1;size_t n=strlen(txt);int rc=fwrite(txt,1,n,f)==n?0:-1;if(fclose(f)!=0)rc=-1;return rc;}
static int drive_orch_state_read(const char*dir,unsigned*kind,unsigned*shard,unsigned long long*height,char*txid,size_t txcap){char p[PATH_MAX];snprintf(p,sizeof(p),"%s/orchestration.state",dir);FILE*f=fopen(p,"rb");if(!f)return-1;unsigned k=0,s=0;unsigned long long h=0;char t[129]={0};int n=fscanf(f,"kind=%u\nshard=%u\nheight=%llu\ntxid=%128s",&k,&s,&h,t);fclose(f);if(n<3)return-1;if(kind)*kind=k;if(shard)*shard=s;if(height)*height=h;if(txid&&txcap)snprintf(txid,txcap,"%s",t);return 0;}
static int drive_orch_state_write(const char*dir,const QrxDriveContractStep*st,unsigned long long h,const char*txid){char p[PATH_MAX],tmp[PATH_MAX];snprintf(p,sizeof(p),"%s/orchestration.state",dir);snprintf(tmp,sizeof(tmp),"%s.tmp",p);FILE*f=fopen(tmp,"wb");if(!f)return-1;fprintf(f,"kind=%u\nshard=%u\nheight=%llu\ntxid=%s\n",(unsigned)st->kind,st->shard_index,h,txid&&*txid?txid:"submitted");return fclose(f)==0&&rename(tmp,p)==0?0:-1;}
static int drive_orch_is_waiting(const char*dir,const QrxDriveContractStep*st,unsigned long long h,char*txid,size_t cap){unsigned k=0,sh=0;unsigned long long sent=0;if(drive_orch_state_read(dir,&k,&sh,&sent,txid,cap))return 0;return k==(unsigned)st->kind&&sh==st->shard_index&&h<=sent+12;}
static int drive_submit_storage_step(const QrxDriveContractStep *st,char txid_out[129]){
    if(!st||!st->tx_type[0]||!strcmp(st->tx_type,"-"))return -1;char addr[512];if(qrx_get_wallet_address(g_wdir,addr,sizeof(addr)))return -1;
    char blocks[PATH_MAX];snprintf(blocks,sizeof(blocks),"%s/blocks",g_cdir);unsigned long long h=(unsigned long long)count_regular_files(blocks),exp=h+64;
    char amount[32],expiry[32],raw[PATH_MAX],sig[PATH_MAX],out[131072];snprintf(amount,sizeof(amount),"%llu",(unsigned long long)st->amount_atoms);snprintf(expiry,sizeof(expiry),"%llu",exp);
    char odir[PATH_MAX];snprintf(odir,sizeof(odir),"%s/drive/orchestration",g_wdir);qrx_mkdir_simple(odir);snprintf(raw,sizeof(raw),"%s/%s-%llu.raw",odir,st->contract_id,h);snprintf(sig,sizeof(sig),"%s/%s-%llu.signed",odir,st->contract_id,h);
    char *mk[]={g_backend_path,"create-velocity-raw-tx",g_cdir,addr,(char*)st->to,amount,"UNSIGNED","UNSIGNED",(char*)st->tx_type,"0",expiry,(char*)st->payload,NULL};
    if(run_capture(mk,out,sizeof(out))||drive_write_text(raw,out))return -1;char signout[8192];char *sg[]={g_backend_path,"signrawtransactionwithwallet",g_wdir,g_cdir,raw,sig,NULL};if(run_capture(sg,signout,sizeof(signout)))return -1;
    char sendout[16384];char *send[]={g_backend_path,"sendtx",g_ndir,sig,NULL};if(run_capture(send,sendout,sizeof(sendout)))return -1;
    trim_ws_right(sendout);if(txid_out){const char*p=strstr(sendout,"txid=");if(p){p+=5;size_t n=strcspn(p,"\r\n ");if(n>128)n=128;memcpy(txid_out,p,n);txid_out[n]=0;}else snprintf(txid_out,129,"submitted");}return 0;
}


static uint64_t qrxnet_height(void){char b[PATH_MAX];snprintf(b,sizeof(b),"%s/blocks",g_cdir);return (uint64_t)count_regular_files(b);}
static uint64_t qrxnet_base_price(uint64_t h){long long x=qrx_chain_get_ll_at_height_or_default(g_cdir,(long long)h,"qrxnet_domain_base_annual_atoms",(long long)QRX_DOMAIN_DEFAULT_BASE_ANNUAL_ATOMS);return x>0?(uint64_t)x:QRX_DOMAIN_DEFAULT_BASE_ANNUAL_ATOMS;}
typedef struct {uint64_t n;} QrxNetCountCtx;
static int qrxnet_count_cb(const QrxDomainRecord*r,void*vp){(void)r;((QrxNetCountCtx*)vp)->n++;return 0;}
static int qrxnet_submit(const char*tx_type,const char*to,uint64_t amount,const char*payload,char txid_out[129]){
    char from[512];if(qrx_get_wallet_address(g_wdir,from,sizeof(from)))return -1;uint64_t h=qrxnet_height(),exp=h+64;char amount_s[32],expiry[32],raw[PATH_MAX],sig[PATH_MAX],out[131072];snprintf(amount_s,sizeof(amount_s),"%llu",(unsigned long long)amount);snprintf(expiry,sizeof(expiry),"%llu",(unsigned long long)exp);
    char odir[PATH_MAX];snprintf(odir,sizeof(odir),"%s/qrxnet/tx",g_wdir);qrx_mkdir_simple(odir);unsigned char rnd[8];if(RAND_bytes(rnd,sizeof(rnd))!=1)return -1;char tag[17];qrx_hex_bytes_local(rnd,8,tag);snprintf(raw,sizeof(raw),"%s/%s-%s.raw",odir,tx_type,tag);snprintf(sig,sizeof(sig),"%s/%s-%s.signed",odir,tx_type,tag);
    char *mk[]={g_backend_path,"create-velocity-raw-tx",g_cdir,from,(char*)to,amount_s,"UNSIGNED","UNSIGNED",(char*)tx_type,"0",expiry,(char*)payload,NULL};if(run_capture(mk,out,sizeof(out))||drive_write_text(raw,out))return -1;
    char signout[8192];char *sg[]={g_backend_path,"signrawtransactionwithwallet",g_wdir,g_cdir,raw,sig,NULL};if(run_capture(sg,signout,sizeof(signout)))return -1;char sendout[16384];char *send[]={g_backend_path,"sendtx",g_ndir,sig,NULL};if(run_capture(send,sendout,sizeof(sendout)))return -1;trim_ws_right(sendout);if(txid_out){const char*p=strstr(sendout,"txid=");if(p){p+=5;size_t n=strcspn(p,"\r\n ");if(n>128)n=128;memcpy(txid_out,p,n);txid_out[n]=0;}else snprintf(txid_out,129,"submitted");}return 0;
}

static int qrxnet_site_paths(const char*domain,uint64_t seq,char*catalog,size_t ccap,char*journal,size_t jcap,char*cas,size_t scap){char norm[254];if(qrx_domain_normalize(domain,norm))return-1;char qn[PATH_MAX];snprintf(qn,sizeof(qn),"%s/qrxnet",g_wdir);qrx_mkdir_simple(qn);snprintf(catalog,ccap,"%s/sites",qn);qrx_mkdir_simple(catalog);char dd[PATH_MAX];snprintf(dd,sizeof(dd),"%s/%s",catalog,norm);qrx_mkdir_simple(dd);if(journal&&jcap)snprintf(journal,jcap,"%s/%llu.publish",dd,(unsigned long long)seq);snprintf(cas,scap,"%s/site-cas",qn);qrx_mkdir_simple(cas);return 0;}
static const char*qrxnet_publish_status_name(uint32_t s){switch(s){case QRX_NET_PUBLISH_STATUS_PREPARED:return"PREPARED";case QRX_NET_PUBLISH_STATUS_STORING:return"STORING";case QRX_NET_PUBLISH_STATUS_WAITING_STORAGE:return"WAITING_REDUNDANCY";case QRX_NET_PUBLISH_STATUS_READY_TO_ACTIVATE:return"READY_TO_ACTIVATE";case QRX_NET_PUBLISH_STATUS_ACTIVATION_SUBMITTED:return"ACTIVATING";case QRX_NET_PUBLISH_STATUS_ACTIVE:return"ACTIVE";case QRX_NET_PUBLISH_STATUS_FAILED:return"FAILED";default:return"UNKNOWN";}}
static void qrxnet_publish_json(char*resp,size_t cap,const char*method,const QrxNetPublishJob*j){char root[129],dom[600],pkg[2200],dist[2200],prep[2200],cid[300],tid[300],atid[300];qrx_hex_bytes_local(j->manifest_root,64,root);json_string(dom,sizeof(dom),j->domain);json_string(pkg,sizeof(pkg),j->package_path);json_string(dist,sizeof(dist),j->distribution_path);json_string(prep,sizeof(prep),j->prepare_dir);json_string(cid,sizeof(cid),j->storage_contract_id);json_string(tid,sizeof(tid),j->transfer_id);json_string(atid,sizeof(atid),j->activation_txid);snprintf(resp,cap,"{\"ok\":true,\"method\":\"%s\",\"result\":{\"domain\":%s,\"version\":%llu,\"manifest_root_hex\":\"%s\",\"status\":\"%s\",\"active_shards\":%u,\"required_active_shards\":%u,\"total_shards\":%u,\"storage_contract_id\":%s,\"transfer_id\":%s,\"activation_txid\":%s,\"activation_height\":%llu,\"package_path\":%s,\"distribution_path\":%s,\"prepare_dir\":%s}}\n",method,dom,(unsigned long long)j->sequence,root,qrxnet_publish_status_name(j->status),j->active_shards,j->required_active_shards,j->total_shards,cid,tid,atid,(unsigned long long)j->activation_height,pkg,dist,prep);}
static int qrxnet_submit_host_step(const QrxNetHostStep*st,char txid[129]){QrxDriveContractStep x;memset(&x,0,sizeof(x));snprintf(x.contract_id,sizeof(x.contract_id),"%s",st->contract_id);snprintf(x.tx_type,sizeof(x.tx_type),"%s",st->tx_type);snprintf(x.to,sizeof(x.to),"%s",st->to);snprintf(x.payload,sizeof(x.payload),"%s",st->payload);x.amount_atoms=st->amount_atoms;x.end_height=st->end_height;x.base_atoms_per_gib_epoch=st->base_atoms_per_gib_epoch;x.shard_index=st->shard_index;x.kind=st->kind==QRX_NET_HOST_STEP_CREATE?QRX_DRIVE_CONTRACT_CREATE:QRX_DRIVE_CONTRACT_ASSIGN;return drive_submit_storage_step(&x,txid);}
typedef struct {char *buf;size_t cap,len;int first;} QrxNetVersionJsonCtx;
static int qrxnet_version_json_cb(const QrxNetSiteVersion*v,void*vp){QrxNetVersionJsonCtx*c=vp;char root[129],one[700];qrx_hex_bytes_local(v->manifest_root,64,root);int z=snprintf(one,sizeof(one),"%s{\"version\":%llu,\"manifest_root_hex\":\"%s\"}",c->first?"":",",(unsigned long long)v->sequence,root);if(z<0||c->len+(size_t)z+2>=c->cap)return-1;memcpy(c->buf+c->len,one,(size_t)z);c->len+=(size_t)z;c->buf[c->len]=0;c->first=0;return 0;}
typedef struct {char *buf;size_t cap,len;uint64_t h;int first;} QrxNetJsonCtx;
static int qrxnet_json_record_cb(const QrxDomainRecord*r,void*vp){QrxNetJsonCtx*c=vp;char n[600],o[600],q[600],web[129],pub[129],one[2200];json_string(n,sizeof(n),r->name);json_string(o,sizeof(o),r->owner);json_string(q,sizeof(q),r->qub_address);qrx_hex_bytes_local(r->web_manifest_root,64,web);qrx_hex_bytes_local(r->publishing_key_commitment,64,pub);const char*st=qrx_domain_is_active(r,c->h)?"ACTIVE":qrx_domain_in_grace(r,c->h)?"GRACE":"EXPIRED";int z=snprintf(one,sizeof(one),"%s{\"name\":%s,\"owner\":%s,\"qub_address\":%s,\"created_height\":%llu,\"expiry_height\":%llu,\"sequence\":%llu,\"status\":\"%s\",\"web_manifest_root_hex\":\"%s\",\"publishing_key_commitment_hex\":\"%s\"}",c->first?"":",",n,o,q,(unsigned long long)r->created_height,(unsigned long long)r->expiry_height,(unsigned long long)r->sequence,st,web,pub);if(z<0||c->len+(size_t)z+2>=c->cap)return -1;memcpy(c->buf+c->len,one,(size_t)z);c->len+=(size_t)z;c->buf[c->len]=0;c->first=0;return 0;}

static int handle_command(const char *cmdline, char *resp, size_t resp_sz){
    char line[131072]; snprintf(line, sizeof(line), "%s", cmdline); trim_nl(line);
    char *args[32] = {0}; int argc = 0; char *save = NULL; char *tok = strtok_r(line, " ", &save);
    while(tok && argc < 31){ args[argc++] = tok; tok = strtok_r(NULL, " ", &save); }
    if(argc == 0){ json_error(resp, resp_sz, "unknown", "empty command"); return 0; }
    if(!strcmp(args[0], "ping")){ snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"ping\",\"result\":{\"status\":\"PONG\"}}\n"); return 0; }
    if(!strcmp(args[0], "stop")){ snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stop\",\"result\":{\"stopping\":true}}\n"); g_running = 0; stop_node_process(); return 1; }
    if(!strcmp(args[0], "getinfo")){
        char net[256]={0}, datadir[PATH_MAX*2]={0}, chain[PATH_MAX*2]={0}, wallet[PATH_MAX*2]={0}, node[PATH_MAX*2]={0}, sock[PATH_MAX*2]={0};
        json_string(net,sizeof(net),g_network); json_string(datadir,sizeof(datadir),g_base); json_string(chain,sizeof(chain),g_cdir); json_string(wallet,sizeof(wallet),g_wdir); json_string(node,sizeof(node),g_ndir); json_string(sock,sizeof(sock),g_sock);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getinfo\",\"result\":{\"network\":%s,\"datadir\":%s,\"chain_dir\":%s,\"wallet_dir\":%s,\"node_dir\":%s,\"control_socket\":%s,\"node_pid\":%ld}}\n", net, datadir, chain, wallet, node, sock, (long)g_node_pid);
        return 0;
    }
    if(!strcmp(args[0], "getaurafabric")){
        QrxAuraPodGossipTable pods;QrxAuraModelGossipTable models;uint64_t h=0;if(aura_live_load_qrxd(&pods,&models,&h)){json_error(resp,resp_sz,"getaurafabric","AURA gossip state unavailable");return 0;}QrxAuraFabricSnapshot snap;QrxAuraGlobeCell*cells=NULL;size_t cn=0;if(qrx_aura_gossip_live_snapshot(&pods,&models,h,3,&snap,&cells,&cn)){qrx_aura_pod_gossip_free(&pods);qrx_aura_model_gossip_free(&models);json_error(resp,resp_sz,"getaurafabric","AURA fabric snapshot failed");return 0;}
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getaurafabric\",\"result\":{\"height\":%llu,\"providers\":%llu,\"pods\":%llu,\"inference_pods\":%llu,\"utility_pods\":%llu,\"ai_milli_tokens_per_second\":%llu,\"free_memory_bytes\":%llu,\"model_cache_free_bytes\":%llu,\"avg_latency_ms\":%u,\"avg_utilization_bps\":%u,\"avg_reliability_bps\":%u,\"avg_cache_hit_bps\":%u,\"avg_expert_locality_bps\":%u,\"k2_readiness_bps\":%u,\"k3_readiness_bps\":%u,\"max_ready_tier\":\"%s\",\"visible_regions\":%u,\"hidden_regions\":%u,\"active_model_profiles\":%llu}}\n",(unsigned long long)h,(unsigned long long)snap.provider_count,(unsigned long long)snap.total_pods,(unsigned long long)snap.inference_pods,(unsigned long long)snap.utility_pods,(unsigned long long)snap.ai_milli_tokens_per_second,(unsigned long long)snap.free_memory_bytes,(unsigned long long)snap.model_cache_free_bytes,snap.avg_latency_ms,snap.avg_utilization_bps,snap.avg_reliability_bps,snap.avg_cache_hit_bps,snap.avg_expert_locality_bps,snap.k2_readiness_bps,snap.k3_readiness_bps,qrx_aura_tier_name(snap.max_ready_tier),snap.visible_regions,snap.hidden_regions,(unsigned long long)models.count);qrx_aura_globe_free(cells);qrx_aura_pod_gossip_free(&pods);qrx_aura_model_gossip_free(&models);return 0;
    }
    if(!strcmp(args[0], "getauraatlas")){
        QrxAuraPodGossipTable pods;QrxAuraModelGossipTable models;uint64_t h=0;if(aura_live_load_qrxd(&pods,&models,&h)){json_error(resp,resp_sz,"getauraatlas","AURA gossip state unavailable");return 0;}QrxAuraFabricSnapshot snap;QrxAuraGlobeCell*cells=NULL;size_t cn=0;if(qrx_aura_gossip_live_snapshot(&pods,&models,h,3,&snap,&cells,&cn)){qrx_aura_pod_gossip_free(&pods);qrx_aura_model_gossip_free(&models);json_error(resp,resp_sz,"getauraatlas","AURA atlas failed");return 0;}size_t off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"getauraatlas\",\"result\":{\"height\":%llu,\"privacy_min_providers\":3,\"hidden_region_count\":%u,\"regions\":[",(unsigned long long)h,snap.hidden_regions);int first=1;for(size_t i=0;i<cn&&off+900<resp_sz;i++){if(!cells[i].publicly_visible)continue;char rjs[256];json_string(rjs,sizeof(rjs),cells[i].region);off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"region\":%s,\"providers\":%llu,\"pods\":%llu,\"inference_pods\":%llu,\"utility_pods\":%llu,\"free_memory_bytes\":%llu,\"model_cache_free_bytes\":%llu,\"ai_milli_tokens_per_second\":%llu,\"avg_latency_ms\":%u,\"avg_utilization_bps\":%u,\"avg_reliability_bps\":%u,\"avg_cache_hit_bps\":%u,\"avg_expert_locality_bps\":%u,\"k2_readiness_bps\":%u,\"k3_readiness_bps\":%u}",first?"":",",rjs,(unsigned long long)cells[i].provider_count,(unsigned long long)cells[i].pod_count,(unsigned long long)cells[i].inference_pods,(unsigned long long)cells[i].utility_pods,(unsigned long long)cells[i].free_memory_bytes,(unsigned long long)cells[i].model_cache_free_bytes,(unsigned long long)cells[i].ai_milli_tokens_per_second,cells[i].avg_latency_ms,cells[i].avg_utilization_bps,cells[i].avg_reliability_bps,cells[i].avg_cache_hit_bps,cells[i].avg_expert_locality_bps,cells[i].k2_readiness_bps,cells[i].k3_readiness_bps);first=0;}snprintf(resp+off,resp_sz-off,"]}}\n");qrx_aura_globe_free(cells);qrx_aura_pod_gossip_free(&pods);qrx_aura_model_gossip_free(&models);return 0;
    }
    if(!strcmp(args[0], "listauramodels")){
        QrxAuraPodGossipTable pods;QrxAuraModelGossipTable models;uint64_t h=0;if(aura_live_load_qrxd(&pods,&models,&h)){json_error(resp,resp_sz,"listauramodels","AURA gossip state unavailable");return 0;}size_t off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"listauramodels\",\"result\":{\"height\":%llu,\"models\":[",(unsigned long long)h);for(size_t i=0;i<models.count&&off+1100<resp_sz;i++){const QrxAuraModelProfileAnnouncement*a=&models.entries[i].announcement;char id[300],ver[160],fam[256],rt[256],q[128],pub[300],commit[180];json_string(id,sizeof(id),a->profile.model_id);json_string(ver,sizeof(ver),a->profile.model_version);json_string(fam,sizeof(fam),a->profile.family);json_string(rt,sizeof(rt),a->profile.runtime_id);json_string(q,sizeof(q),a->profile.quantization);json_string(pub,sizeof(pub),a->publisher_id);json_string(commit,sizeof(commit),a->model_registry_commitment);off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"model_id\":%s,\"version\":%s,\"family\":%s,\"runtime\":%s,\"quantization\":%s,\"tier\":\"%s\",\"quality_bps\":%u,\"min_memory_bytes\":%llu,\"min_pods\":%u,\"publisher\":%s,\"registry_commitment\":%s,\"valid_until_height\":%llu}",i?",":"",id,ver,fam,rt,q,qrx_aura_tier_name(a->profile.tier),a->profile.quality_bps,(unsigned long long)a->profile.min_memory_bytes,a->profile.min_pods,pub,commit,(unsigned long long)a->valid_until_height);}snprintf(resp+off,resp_sz-off,"]}}\n");qrx_aura_pod_gossip_free(&pods);qrx_aura_model_gossip_free(&models);return 0;
    }
    if(!strcmp(args[0], "getprotocolreadiness")){
        if(argc!=2){json_error(resp,resp_sz,"getprotocolreadiness","usage: getprotocolreadiness FEATURE_FLAG");return 0;}
        char bdir[PATH_MAX];snprintf(bdir,sizeof(bdir),"%s/blocks",g_cdir);uint64_t h=(uint64_t)count_regular_files(bdir);QrxProtocolActivationReadiness r;
        if(qrx_protocol_activation_readiness(g_cdir,args[1],h,(int64_t)time(NULL),&r)!=0){json_error(resp,resp_sz,"getprotocolreadiness","unsupported feature or readiness unavailable");return 0;}
        char fjs[128],why[512];json_string(fjs,sizeof(fjs),r.feature_flag);json_string(why,sizeof(why),r.blocking_reason);
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getprotocolreadiness\",\"result\":{\"feature\":%s,\"status\":\"%s\",\"ready\":%s,\"current_height\":%llu,\"target_time\":%lld,\"activation_height\":%lld,\"dependencies_active\":%u,\"dependencies_required\":%u,\"criteria_passed\":%u,\"criteria_required\":%u,\"readiness_bps\":%u,\"soak_blocks\":%llu,\"required_soak_blocks\":%llu,\"serving_providers\":%llu,\"mature_attested_providers\":%llu,\"independent_operators\":%llu,\"independent_asns\":%llu,\"visible_regions\":%llu,\"proven_bytes\":%llu,\"active_contracts\":%llu,\"active_domains\":%llu,\"compute_providers\":%llu,\"compute_safety_flags\":%u,\"avg_availability_bps\":%u,\"avg_proof_success_bps\":%u,\"health_score\":%u,\"blocking_reason\":%s}}\n",
            fjs,qrx_protocol_readiness_status_name(r.status),r.status==QRX_PROTOCOL_READINESS_READY_FOR_GOVERNANCE?"true":"false",(unsigned long long)r.current_height,(long long)r.target_time,(long long)r.activation_height,r.dependencies_active,r.dependencies_required,r.criteria_passed,r.criteria_required,r.readiness_bps,(unsigned long long)r.soak_blocks,(unsigned long long)r.required_soak_blocks,(unsigned long long)r.serving_providers,(unsigned long long)r.mature_attested_providers,(unsigned long long)r.independent_operators,(unsigned long long)r.independent_asns,(unsigned long long)r.visible_regions,(unsigned long long)r.proven_bytes,(unsigned long long)r.active_contracts,(unsigned long long)r.active_domains,(unsigned long long)r.compute_providers,r.compute_safety_flags,r.avg_availability_bps,r.avg_proof_success_bps,r.health_score,why);return 0;
    }
    if(!strcmp(args[0], "getdriveactivationreadiness")){
        char bdir[PATH_MAX];snprintf(bdir,sizeof(bdir),"%s/blocks",g_cdir);uint64_t h=(uint64_t)count_regular_files(bdir);QrxDriveActivationReadiness r;
        if(qrx_drive_activation_readiness(g_cdir,h,(int64_t)time(NULL),&r)!=0){json_error(resp,resp_sz,"getdriveactivationreadiness","readiness unavailable");return 0;}
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getdriveactivationreadiness\",\"result\":{\"status\":\"%s\",\"ready\":%s,\"current_height\":%llu,\"target_time\":%lld,\"activation_height\":%lld,\"criteria_passed\":%u,\"criteria_required\":%u,\"serving_providers\":%llu,\"required_providers\":%llu,\"mature_attested_providers\":%llu,\"independent_operators\":%llu,\"required_operators\":%llu,\"independent_asns\":%llu,\"required_asns\":%llu,\"visible_regions\":%llu,\"required_regions\":%llu,\"proven_bytes\":%llu,\"required_proven_bytes\":%llu,\"avg_availability_bps\":%u,\"required_availability_bps\":%u,\"avg_proof_success_bps\":%u,\"required_proof_bps\":%u,\"health_score\":%u,\"required_health_score\":%u,\"soak_blocks\":%llu,\"required_soak_blocks\":%llu,\"preflight_only_before_activation\":true}}\n",
            qrx_drive_readiness_status_name(r.status),r.status==QRX_DRIVE_READINESS_READY?"true":"false",(unsigned long long)r.current_height,(long long)r.target_time,(long long)r.activation_height,r.criteria_passed,r.criteria_required,(unsigned long long)r.serving_providers,(unsigned long long)QRX_DRIVE_READINESS_MIN_PROVIDERS,(unsigned long long)r.mature_attested_providers,(unsigned long long)r.independent_operators,(unsigned long long)QRX_DRIVE_READINESS_MIN_OPERATORS,(unsigned long long)r.independent_asns,(unsigned long long)QRX_DRIVE_READINESS_MIN_ASNS,(unsigned long long)r.visible_regions,(unsigned long long)QRX_DRIVE_READINESS_MIN_REGIONS,(unsigned long long)r.proven_bytes,(unsigned long long)QRX_DRIVE_READINESS_MIN_PROVEN_BYTES,r.avg_availability_bps,QRX_DRIVE_READINESS_MIN_AVAILABILITY_BPS,r.avg_proof_success_bps,QRX_DRIVE_READINESS_MIN_PROOF_BPS,r.health_score,QRX_DRIVE_READINESS_MIN_HEALTH_SCORE,(unsigned long long)r.soak_blocks,(unsigned long long)r.soak_blocks_required);return 0;
    }
    if(!strcmp(args[0], "getresourcedashboard")){
        QrxResourceDashboardSnapshot d; QrxStorageAtlasCell *cells=NULL; size_t cn=0;
        if(qrx_resource_live_snapshot(g_cdir,3,&d,&cells,&cn)!=0){json_error(resp,resp_sz,"getresourcedashboard","resource snapshot unavailable");return 0;}
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getresourcedashboard\",\"result\":{\"health_score\":%u,\"demand_factor_bps\":%u,\"avg_proof_success_bps\":%u,\"avg_availability_bps\":%u,\"provider_diversity_bps\":%u,\"serving_providers\":%llu,\"independent_asns\":%llu,\"visible_regions\":%llu,\"hidden_regions\":%llu,\"active_contracts\":%llu,\"purchased_logical_bytes\":%llu,\"active_domains\":%llu,\"hosted_sites\":%llu,\"website_logical_bytes\":%llu,\"website_requests_24h\":%llu,\"website_cache_hit_bps\":%u,\"storage\":{\"configured_bytes\":%llu,\"raw_eligible_bytes\":%llu,\"proven_bytes\":%llu,\"allocated_physical_bytes\":%llu,\"logical_user_bytes\":%llu,\"free_proven_physical_bytes\":%llu,\"available_usable_bytes\":%llu,\"usable_capacity_bytes\":%llu,\"reserve_committed_bytes\":%llu,\"providers_total\":%llu,\"providers_proven\":%llu,\"healthy_shards\":%llu,\"degraded_shards\":%llu,\"repairing_shards\":%llu,\"utilization_bps\":%u,\"resilience_headroom_bps\":%u,\"redundancy_x10000\":%u}}}\n",
          d.health_score,d.demand_factor_bps,d.avg_proof_success_bps,d.avg_availability_bps,d.provider_diversity_bps,
          (unsigned long long)d.serving_providers,(unsigned long long)d.independent_asns,(unsigned long long)d.visible_regions,(unsigned long long)d.hidden_regions,
          (unsigned long long)d.active_contracts,(unsigned long long)d.purchased_logical_bytes,(unsigned long long)d.active_domains,(unsigned long long)d.hosted_sites,
          (unsigned long long)d.website_logical_bytes,(unsigned long long)d.website_requests_24h,d.website_cache_hit_bps,
          (unsigned long long)d.storage.configured_bytes,(unsigned long long)d.storage.raw_eligible_bytes,(unsigned long long)d.storage.proven_bytes,
          (unsigned long long)d.storage.allocated_physical_bytes,(unsigned long long)d.storage.logical_user_bytes,(unsigned long long)d.storage.free_proven_physical_bytes,
          (unsigned long long)d.storage.available_usable_bytes,(unsigned long long)d.storage.usable_capacity_bytes,(unsigned long long)d.storage.reserve_committed_bytes,
          (unsigned long long)d.storage.providers_total,(unsigned long long)d.storage.providers_proven,(unsigned long long)d.storage.healthy_shards,
          (unsigned long long)d.storage.degraded_shards,(unsigned long long)d.storage.repairing_shards,d.storage.utilization_bps,d.storage.resilience_headroom_bps,d.storage.redundancy_x10000);
        qrx_storage_atlas_free(cells);return 0;
    }
    if(!strcmp(args[0], "getresourceatlas")){
        QrxResourceDashboardSnapshot d; QrxStorageAtlasCell *cells=NULL; size_t cn=0;
        if(qrx_resource_live_snapshot(g_cdir,3,&d,&cells,&cn)!=0){json_error(resp,resp_sz,"getresourceatlas","resource atlas unavailable");return 0;}
        size_t off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"getresourceatlas\",\"result\":{\"privacy_min_providers\":3,\"hidden_region_count\":%llu,\"regions\":[",(unsigned long long)d.hidden_regions);
        int first=1;for(size_t i=0;i<cn&&off+1024<resp_sz;i++){if(!cells[i].publicly_visible)continue;char rjs[256];json_string(rjs,sizeof(rjs),cells[i].region);off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"region\":%s,\"provider_count\":%llu,\"proven_bytes\":%llu,\"allocated_bytes\":%llu,\"free_bytes\":%llu,\"unique_asns\":%llu,\"utilization_bps\":%u,\"avg_availability_bps\":%u,\"avg_proof_success_bps\":%u,\"opportunity_score\":%u,\"diversity_bonus_bps\":%u}",first?"":",",rjs,(unsigned long long)cells[i].provider_count,(unsigned long long)cells[i].proven_bytes,(unsigned long long)cells[i].allocated_bytes,(unsigned long long)cells[i].free_bytes,(unsigned long long)cells[i].unique_asns,cells[i].utilization_bps,cells[i].avg_availability_bps,cells[i].avg_proof_success_bps,cells[i].opportunity_score,cells[i].diversity_bonus_bps);first=0;}
        snprintf(resp+off,resp_sz-off,"]}}\n");qrx_storage_atlas_free(cells);return 0;
    }
    if(!strcmp(args[0], "gethostingmissions")){
        QrxResourceDashboardSnapshot d; QrxStorageAtlasCell *cells=NULL; size_t cn=0; QrxStorageMission *missions=NULL; size_t mn=0;
        const uint64_t target_free = 1024ULL*1024ULL*1024ULL; /* 1 GiB privacy-cell reserve target */
        const uint64_t target_providers = 10;
        if(qrx_resource_live_snapshot(g_cdir,3,&d,&cells,&cn)!=0){json_error(resp,resp_sz,"gethostingmissions","resource atlas unavailable");return 0;}
        /* Hidden privacy cells are never turned into public missions. */
        if(qrx_storage_public_missions_from_atlas(cells,cn,target_free,target_providers,&missions,&mn)!=0){qrx_storage_atlas_free(cells);json_error(resp,resp_sz,"gethostingmissions","mission calculation failed");return 0;}
        size_t off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"gethostingmissions\",\"result\":{\"privacy_min_providers\":3,\"target_providers_per_region\":%llu,\"target_free_bytes_per_region\":%llu,\"missions\":[",(unsigned long long)target_providers,(unsigned long long)target_free);
        for(size_t i=0;i<mn&&off+700<resp_sz;i++){char rjs[256];json_string(rjs,sizeof(rjs),missions[i].region);off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"region\":%s,\"wanted_additional_bytes\":%llu,\"wanted_additional_providers\":%llu,\"opportunity_score\":%u,\"incentive_factor_bps\":%u,\"reward_multiplier_x10000\":%u}",i?",":"",rjs,(unsigned long long)missions[i].wanted_additional_bytes,(unsigned long long)missions[i].wanted_additional_providers,missions[i].opportunity_score,missions[i].incentive_factor_bps,missions[i].incentive_factor_bps);}
        snprintf(resp+off,resp_sz-off,"]}}\n");qrx_storage_missions_free(missions);qrx_storage_atlas_free(cells);return 0;
    }
    if(!strcmp(args[0], "listdrivefiles")){
        const char *owner = argc >= 2 && strcmp(args[1], "-") ? args[1] : NULL;
        QrxDriveFileSnapshot *files=NULL; size_t fn=0;
        if(qrx_drive_live_list(g_cdir,owner,&files,&fn)!=0){json_error(resp,resp_sz,"listdrivefiles","drive catalog unavailable");return 0;}
        size_t off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"listdrivefiles\",\"result\":{\"files\":[");
        for(size_t i=0;i<fn&&off+1200<resp_sz;i++){char cjs[300],ojs[360],pjs[80],oidjs[180];json_string(cjs,sizeof(cjs),files[i].contract_id);json_string(ojs,sizeof(ojs),files[i].owner);json_string(pjs,sizeof(pjs),files[i].profile);json_string(oidjs,sizeof(oidjs),files[i].first_object_id);
            off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"contract_id\":%s,\"owner\":%s,\"profile\":%s,\"logical_bytes\":%llu,\"shard_bytes\":%llu,\"shard_count\":%u,\"required_shards\":%u,\"healthy_shards\":%u,\"degraded_shards\":%u,\"repairing_shards\":%u,\"missing_shards\":%u,\"start_height\":%llu,\"end_height\":%llu,\"status\":%u,\"first_object_id\":%s}",i?",":"",cjs,ojs,pjs,(unsigned long long)files[i].logical_bytes,(unsigned long long)files[i].shard_bytes,files[i].shard_count,files[i].required_shards,files[i].healthy_shards,files[i].degraded_shards,files[i].repairing_shards,files[i].missing_shards,(unsigned long long)files[i].start_height,(unsigned long long)files[i].end_height,files[i].status,oidjs);
        }snprintf(resp+off,resp_sz-off,"]}}\n");qrx_drive_live_files_free(files);return 0;
    }
    if(!strcmp(args[0], "getdrivefilehealth")){
        if(argc<2){json_error(resp,resp_sz,"getdrivefilehealth","contract_id required");return 0;}QrxDriveShardRoute *routes=NULL;size_t rn=0;QrxDriveFileSnapshot f;
        if(qrx_drive_live_routes(g_cdir,args[1],3,&routes,&rn,&f)!=0){json_error(resp,resp_sz,"getdrivefilehealth","contract unavailable");return 0;}char cjs[300],ojs[360],pjs[80],oidjs[180];json_string(cjs,sizeof(cjs),f.contract_id);json_string(ojs,sizeof(ojs),f.owner);json_string(pjs,sizeof(pjs),f.profile);json_string(oidjs,sizeof(oidjs),f.first_object_id);
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getdrivefilehealth\",\"result\":{\"contract_id\":%s,\"owner\":%s,\"profile\":%s,\"logical_bytes\":%llu,\"shard_count\":%u,\"required_shards\":%u,\"healthy_shards\":%u,\"degraded_shards\":%u,\"repairing_shards\":%u,\"missing_shards\":%u,\"retrievable\":%s,\"status\":%u,\"first_object_id\":%s}}\n",cjs,ojs,pjs,(unsigned long long)f.logical_bytes,f.shard_count,f.required_shards,f.healthy_shards,f.degraded_shards,f.repairing_shards,f.missing_shards,f.healthy_shards>=f.required_shards?"true":"false",f.status,oidjs);qrx_drive_live_routes_free(routes);return 0;
    }
    if(!strcmp(args[0], "getdriveshardroutes")){
        if(argc<2){json_error(resp,resp_sz,"getdriveshardroutes","contract_id required");return 0;}QrxDriveShardRoute *routes=NULL;size_t rn=0;QrxDriveFileSnapshot f;
        if(qrx_drive_live_routes(g_cdir,args[1],3,&routes,&rn,&f)!=0){json_error(resp,resp_sz,"getdriveshardroutes","contract unavailable");return 0;}size_t off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"getdriveshardroutes\",\"result\":{\"contract_id\":\"");
        char cjs[300];json_string(cjs,sizeof(cjs),f.contract_id);off=0;off+=(size_t)snprintf(resp+off,resp_sz-off,"{\"ok\":true,\"method\":\"getdriveshardroutes\",\"result\":{\"contract_id\":%s,\"privacy_min_providers\":3,\"routes\":[",cjs);
        for(size_t i=0;i<rn&&off+900<resp_sz;i++){char rjs[220],oidjs[180];json_string(rjs,sizeof(rjs),routes[i].region);json_string(oidjs,sizeof(oidjs),routes[i].object_id);off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"shard_index\":%u,\"state\":%u,\"region\":%s,\"region_public\":%s,\"object_id\":%s,\"physical_bytes\":%llu}",i?",":"",routes[i].shard_index,routes[i].state,rjs,routes[i].region_public?"true":"false",oidjs,(unsigned long long)routes[i].physical_bytes);}snprintf(resp+off,resp_sz-off,"]}}\n");qrx_drive_live_routes_free(routes);return 0;
    }
    if(!strcmp(args[0], "getblockcount")){
        char bdir[PATH_MAX]; snprintf(bdir,sizeof(bdir), "%s/blocks", g_cdir);
        return json_ok_number(resp, resp_sz, "getblockcount", "count", count_regular_files(bdir)), 0;
    }
    if(!strcmp(args[0], "getuptime")){
        long long up = g_start_time ? (long long)(time(NULL) - g_start_time) : 0;
        char human[128]; qrx_uptime_human(up, human, sizeof(human));
        char hjs[256]; json_string(hjs, sizeof(hjs), human);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getuptime\",\"result\":{\"uptime\":%lld,\"uptime_human\":%s}}\n", up, hjs);
        return 0;
    }
    if(!strcmp(args[0], "getbuildinfo")){
        char ssl[512], vjs[128], bjs[256], sjs[768];
        json_string(vjs, sizeof(vjs), QRX_VERSION);
        json_string(bjs, sizeof(bjs), QRX_BUILD_ID);
        json_string(sjs, sizeof(sjs), OpenSSL_version(OPENSSL_VERSION));
        snprintf(ssl, sizeof(ssl), "%s", sjs);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getbuildinfo\",\"result\":{\"version\":%s,\"build\":%s,\"openssl\":%s,\"hybrid_crypto\":true,\"mldsa\":true}}\n", vjs, bjs, ssl);
        return 0;
    }
    if(!strcmp(args[0], "getblockchaininfo")){
        long long h=0, bt=0; char bh[256]={0};
        qrx_best_block_info(&h, bh, sizeof(bh), &bt);
        long long peer_h = qrx_best_peer_height(h);
        long long highest = peer_h > h ? peer_h : h;
        double progress = highest > 0 ? ((double)h / (double)highest) : 1.0;
        if(progress > 1.0) progress = 1.0;
        char net[128], hashjs[512]; json_string(net,sizeof(net),g_network); json_string(hashjs,sizeof(hashjs),bh);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getblockchaininfo\",\"result\":{\"chain\":%s,\"blocks\":%lld,\"headers\":%lld,\"bestblockhash\":%s,\"mediantime\":%lld,\"verificationprogress\":%.6f,\"initialblockdownload\":%s}}\n", net, h, highest, hashjs, bt, progress, progress >= 0.999 ? "false" : "true");
        return 0;
    }
    if(!strcmp(args[0], "getnetworkinfo")){
        long long con = qrx_connection_count();
        char vjs[128], subjs[256]; json_string(vjs,sizeof(vjs),QRX_VERSION);
        char sub[128]; snprintf(sub,sizeof(sub),"/QRX:%s/", QRX_VERSION); json_string(subjs,sizeof(subjs),sub);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getnetworkinfo\",\"result\":{\"version\":%s,\"subversion\":%s,\"protocolversion\":6,\"connections\":%lld,\"listen\":true,\"networkactive\":true,\"localservices\":\"NODE_NETWORK\"}}\n", vjs, subjs, con);
        return 0;
    }
    if(!strcmp(args[0], "getmainnethealth")){
        long long h=0, bt=0; char bh[256]={0};
        qrx_best_block_info(&h,bh,sizeof(bh),&bt);
        long long peer_h=qrx_best_peer_height(h), highest=peer_h>h?peer_h:h;
        long long behind=highest>h?highest-h:0, con=qrx_connection_count();
        char srout[8192]={0}, sri[12000]={0}, pout[8192]={0}, pi[12000]={0}, siout[8192]={0}, sii[12000]={0};
        char *srargv[]={g_backend_path,"state-root",g_cdir,NULL};
        char *pargv[]={g_backend_path,"protocol-info",g_cdir,NULL};
        char *siargv[]={g_backend_path,"supply-invariant",g_cdir,NULL};
        int src=run_capture(srargv,srout,sizeof(srout));
        int prc=run_capture(pargv,pout,sizeof(pout));
        int sirc=run_capture(siargv,siout,sizeof(siout));
        if(src==0) json_keyval_object(sri,sizeof(sri),srout); else snprintf(sri,sizeof(sri),"{\"error\":\"state-root unavailable\"}");
        if(prc==0||prc==2) json_keyval_object(pi,sizeof(pi),pout); else snprintf(pi,sizeof(pi),"{\"error\":\"protocol-info unavailable\"}");
        if(sirc==0) json_keyval_object(sii,sizeof(sii),siout); else snprintf(sii,sizeof(sii),"{\"status\":\"FAIL\"}");
        const char *health=(behind>2||con<1||sirc!=0)?"YELLOW":"GREEN";
        char hjs[64], njs[128], bhjs[512]; json_string(hjs,sizeof(hjs),health); json_string(njs,sizeof(njs),g_network); json_string(bhjs,sizeof(bhjs),bh);
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getmainnethealth\",\"result\":{\"health\":%s,\"network\":%s,\"height\":%lld,\"best_peer_height\":%lld,\"blocks_behind\":%lld,\"bestblockhash\":%s,\"connections\":%lld,\"block_time\":%lld,\"state\":%s,\"protocol\":%s,\"supply_invariant\":%s}}\n",hjs,njs,h,peer_h,behind,bhjs,con,bt,sri,pi,sii);
        return 0;
    }
    if(!strcmp(args[0], "getnodestatus")){
        long long h=0, bt=0; char bh[256]={0};
        qrx_best_block_info(&h, bh, sizeof(bh), &bt);
        long long peer_h = qrx_best_peer_height(h);
        long long highest = peer_h > h ? peer_h : h;
        long long behind = highest > h ? highest - h : 0;
        double sync = highest > 0 ? ((double)h * 100.0 / (double)highest) : 100.0;
        if(sync > 100.0) sync = 100.0;
        long long up = g_start_time ? (long long)(time(NULL) - g_start_time) : 0;
        long long con = qrx_connection_count();
        char addr[512]={0}, ajs[1024], net[128], hashjs[512], vjs[128], bjs[256], ssljs[768];
        int wallet_loaded = qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) == 0;
        json_string(ajs,sizeof(ajs),wallet_loaded ? addr : "");
        json_string(net,sizeof(net),g_network);
        json_string(hashjs,sizeof(hashjs),bh);
        json_string(vjs,sizeof(vjs),QRX_VERSION);
        json_string(bjs,sizeof(bjs),QRX_BUILD_ID);
        json_string(ssljs,sizeof(ssljs),OpenSSL_version(OPENSSL_VERSION));
        char pausejs[256]; json_string(pausejs,sizeof(pausejs),g_validator_pause_reason);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getnodestatus\",\"result\":{\"version\":%s,\"build\":%s,\"network\":%s,\"uptime\":%lld,\"connections\":%lld,\"listening\":true,\"networkactive\":true,\"local_height\":%lld,\"best_peer_height\":%lld,\"highest_known_block\":%lld,\"blocks_behind\":%lld,\"sync_percent\":%.2f,\"bestblockhash\":%s,\"wallet_loaded\":%s,\"wallet_address\":%s,\"block_producer\":%s,\"validator_signing_paused\":%s,\"validator_pause_reason\":%s,\"validator_catchup_blocks_behind\":%lld,\"validator_auto_resume\":true,\"node_pid\":%ld,\"rpc\":\"%s\",\"hybrid_crypto\":true,\"mldsa\":true,\"openssl\":%s}}\n", vjs, bjs, net, up, con, h, peer_h, highest, behind, sync, hashjs, wallet_loaded ? "true" : "false", ajs, g_block_producer_enabled ? "true" : "false", g_validator_signing_paused ? "true" : "false", pausejs, g_validator_blocks_behind, (long)g_node_pid, g_sock, ssljs);
        return 0;
    }
    if(!strcmp(args[0], "getmempoolinfo")){
        char out[8192], obj[12000]={0};
        char *argv[] = { g_backend_path, "mempool-status", g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getmempoolinfo", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getmempoolinfo\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getrecentblocks")){
        int limit = argc >= 2 ? atoi(args[1]) : 10;
        char arr[60000]={0}; qrx_recent_blocks_json(arr, sizeof(arr), limit);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getrecentblocks\",\"result\":{\"blocks\":%s}}\n", arr);
        return 0;
    }
    if(!strcmp(args[0], "getrecenttransactions")){
        int limit = argc >= 2 ? atoi(args[1]) : 10;
        char arr[60000]={0}; qrx_recent_transactions_json(arr, sizeof(arr), limit);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getrecenttransactions\",\"result\":{\"transactions\":%s}}\n", arr);
        return 0;
    }
    if(!strcmp(args[0], "getvalidatorstatus")){
        char addr[512]={0}, out[20000], obj[24000]={0}, ajs[1024]={0};
        int has_wallet = qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) == 0;
        if(has_wallet){
            char *argv[] = { g_backend_path, "staking-status", g_cdir, addr, NULL };
            if(run_capture(argv, out, sizeof(out)) == 0) json_keyval_object(obj, sizeof(obj), out);
            else snprintf(obj, sizeof(obj), "{}");
        } else snprintf(obj, sizeof(obj), "{}");
        json_string(ajs, sizeof(ajs), has_wallet ? addr : "");
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getvalidatorstatus\",\"result\":{\"wallet_address\":%s,\"block_producer_enabled\":%s,\"staking\":%s}}\n", ajs, g_block_producer_enabled ? "true" : "false", obj);
        return 0;
    }
    if(!strcmp(args[0], "setvalidatorfleet")){
        /* 7.2.11: hot-reload validator signer identities without restarting the node.
           Argument is a comma-separated list of wallet names; '-' clears the fleet. */
        g_validator_wallet_count = 0;
        if(argc >= 2 && strcmp(args[1], "-") != 0){
            char tmp[32768]; snprintf(tmp,sizeof(tmp),"%s",args[1]);
            for(char *tok=strtok(tmp,","); tok && g_validator_wallet_count<QRX_MAX_VALIDATOR_FLEET; tok=strtok(NULL,",")){
                if(!*tok || strchr(tok,'/') || strchr(tok,'\\') || strstr(tok,"..")) continue;
                if(!fleet_has_name(tok)) snprintf(g_validator_wallet_names[g_validator_wallet_count++],sizeof(g_validator_wallet_names[0]),"%s",tok);
            }
        }
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"setvalidatorfleet\",\"result\":{\"runtime_applied\":true,\"validator_fleet_count\":%d}}\n",g_validator_wallet_count);
        return 0;
    }
    if(!strcmp(args[0], "getblockproducerinfo")){
        char addr[512]={0}, ajs[1024]={0};
        int has_wallet = qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) == 0;
        json_string(ajs, sizeof(ajs), has_wallet ? addr : "");
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getblockproducerinfo\",\"result\":{\"enabled\":%s,\"wallet_address\":%s,\"blocktime_seconds\":%d,\"commission_bps\":%lld,\"node_pid\":%ld,\"validator_fleet_enabled\":%s,\"validator_fleet_count\":%d}}\n", g_block_producer_enabled ? "true" : "false", ajs, g_blocktime_seconds, g_commission_bps, (long)g_node_pid, g_validator_wallet_count>0?"true":"false", g_validator_wallet_count);
        return 0;
    }
    if(!strcmp(args[0], "getfeeinfo")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "feeinfo", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getfeeinfo", "backend failed");
        else { json_keyval_object(obj, sizeof(obj), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getfeeinfo\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getnewaddress")){
        char out[8192], addr[1024]={0};
        char *argv[] = { g_backend_path, "wallet-new-address", g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getnewaddress", "wallet-new-address failed");
        else { trim_ws_right(out); snprintf(addr,sizeof(addr),"%s",out); json_ok_string(resp, resp_sz, "getnewaddress", "address", addr); }
        return 0;
    }
    if(!strcmp(args[0], "address") || !strcmp(args[0], "receive")){
        char addr[512];
        if(qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) != 0) json_error(resp, resp_sz, args[0], "address unavailable");
        else json_ok_string(resp, resp_sz, args[0], "address", addr);
        return 0;
    }
    if(!strcmp(args[0], "listaddresses")){
        char out[32768], arr[40000]={0};
        char *argv[] = { g_backend_path, "listaddresses", g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "listaddresses", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"listaddresses\",\"result\":{\"addresses\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "getaddressnonce") && argc >= 2){
        char out[8192]; char *argv[] = { g_backend_path, "getnonce", g_cdir, args[1], argc >= 3 ? args[2] : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getaddressnonce", "backend failed");
        else { trim_ws_right(out); json_ok_number(resp, resp_sz, "getaddressnonce", "nonce", atoll(out)); }
        return 0;
    }
    if(!strcmp(args[0], "getnoncelanes") && argc >= 2){
        char out[16384], arr[24000]={0}; char *argv[] = { g_backend_path, "getnoncelanes", g_cdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getnoncelanes", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getnoncelanes\",\"result\":{\"lanes\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "getagent") && argc >= 2){
        char out[32768], obj[40000]={0}; char *argv[] = { g_backend_path, "agent-status", g_cdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getagent", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getagent\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "listagents")){
        char out[32768], arr[40000]={0}; char *argv[] = { g_backend_path, "list-agents", g_cdir, argc >= 2 ? args[1] : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "listagents", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"listagents\",\"result\":{\"agents\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "getvelocityinfo")){
        char out[16384], obj[24000]={0}; char *argv[] = { g_backend_path, "velocity-info", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getvelocityinfo", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getvelocityinfo\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getvelocityengineinfo")){
        char out[32768], obj[48000]={0}; char *argv[] = { g_backend_path, "velocity-engine-info", g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getvelocityengineinfo", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getvelocityengineinfo\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getagentlimits") && argc >= 2){
        char out[32768], obj[40000]={0}; char *argv[] = { g_backend_path, "agent-limits", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getagentlimits","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getagentlimits\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getorder") && argc >= 2){
        char out[32768], obj[40000]={0}; char *argv[] = { g_backend_path, "order-status", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getorder","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getorder\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "listorders")){
        char out[65536], arr[90000]={0}; char *argv[] = { g_backend_path, "list-orders", g_cdir, argc>=2?args[1]:NULL, argc>=3?args[2]:NULL, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"listorders","backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listorders\",\"result\":{\"orders\":%s}}\n",arr); } return 0;
    }
    if(!strcmp(args[0], "gettrade") && argc >= 2){
        char out[32768], obj[40000]={0}; char *argv[] = { g_backend_path, "trade-status", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"gettrade","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"gettrade\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "listtrades")){
        char out[65536], arr[90000]={0}; char *argv[] = { g_backend_path, "list-trades", g_cdir, argc>=2?args[1]:NULL, argc>=3?args[2]:NULL, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"listtrades","backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listtrades\",\"result\":{\"trades\":%s}}\n",arr); } return 0;
    }
    if(!strcmp(args[0], "getorderbook") && argc >= 2){
        char out[65536], arr[90000]={0}; char *argv[] = { g_backend_path, "orderbook", g_cdir, args[1], argc>=3?args[2]:NULL, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getorderbook","backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getorderbook\",\"result\":{\"lines\":%s}}\n",arr); } return 0;
    }
    if(!strcmp(args[0], "getassetbalance") && argc >= 2){
        char addr[512],out[8192]; char *argv[] = { g_backend_path, "asset-balance", g_cdir, args[1], NULL, NULL };
        if(argc>=3) argv[4]=args[2]; else { if(qrx_get_wallet_address(g_wdir,addr,sizeof(addr))!=0){json_error(resp,resp_sz,"getassetbalance","address unavailable");return 0;} argv[4]=addr; }
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getassetbalance","backend failed"); else { trim_ws_right(out); json_ok_number(resp,resp_sz,"getassetbalance","balance",atoll(out)); } return 0;
    }
    if(!strcmp(args[0], "listassets")){
        char out[32768],arr[50000]={0}; char *argv[] = { g_backend_path, "list-assets", g_cdir, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"listassets","backend failed"); else { json_lines_array(arr,sizeof(arr),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listassets\",\"result\":{\"assets\":%s}}\n",arr); } return 0;
    }
    if(!strcmp(args[0], "getassetinfo") && argc >= 2){
        char out[32768],obj[48000]={0}; char *argv[] = { g_backend_path, "asset-info-v1", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getassetinfo","backend failed"); else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getassetinfo\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getassettag") && argc >= 3){
        char out[16384],obj[24000]={0}; char *argv[] = { g_backend_path, "asset-tag-check", g_cdir, args[1], args[2], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getassettag","backend failed"); else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getassettag\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getassetrestriction") && argc >= 3){
        char out[16384],obj[24000]={0}; char *argv[] = { g_backend_path, "asset-restriction-check", g_cdir, args[1], args[2], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getassetrestriction","backend failed"); else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getassetrestriction\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getassetburnedfees")){
        char out[8192]; char *argv[] = { g_backend_path, "asset-burned-fees", g_cdir, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getassetburnedfees","backend failed"); else { trim_ws_right(out); json_ok_number(resp,resp_sz,"getassetburnedfees","burned_atoms",atoll(out)); } return 0;
    }
    if(!strcmp(args[0], "gettradinginfo")){
        char out[16384], obj[24000]={0}; char *argv[] = { g_backend_path, "trading-info", g_cdir, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"gettradinginfo","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"gettradinginfo\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getgateway") && argc >= 2){
        char out[32768], obj[48000]={0}; char *argv[] = { g_backend_path, "gateway-status", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getgateway","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getgateway\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "listgateways")){
        char out[65536], arr[90000]={0}; char *argv[] = { g_backend_path, "list-gateways", g_cdir, argc>=2?args[1]:NULL, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"listgateways","backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listgateways\",\"result\":{\"gateways\":%s}}\n",arr); } return 0;
    }
    if(!strcmp(args[0], "getexecutionreport") && argc >= 2){
        char out[32768], obj[48000]={0}; char *argv[] = { g_backend_path, "execution-report-status", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getexecutionreport","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getexecutionreport\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getstateroot")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "state-root", g_cdir, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getstateroot","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getstateroot\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getsettlement") && argc >= 2){
        char out[32768], obj[48000]={0}; char *argv[] = { g_backend_path, "settlement-status", g_cdir, args[1], NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getsettlement","backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getsettlement\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "getcrosschaininfo")){
        char out[16384],obj[24000]={0}; char *argv[]={g_backend_path,"crosschain-info",g_cdir,NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getcrosschaininfo","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getcrosschaininfo\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getcrosschainswap") && argc>=2){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"crosschain-status",g_cdir,args[1],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getcrosschainswap","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getcrosschainswap\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "listcrosschainswaps")){
        char out[65536],arr[90000]={0}; char *argv[]={g_backend_path,"list-crosschain",g_cdir,argc>=2?args[1]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"listcrosschainswaps","backend failed"); else {json_lines_array(arr,sizeof(arr),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listcrosschainswaps\",\"result\":{\"swaps\":%s}}\n",arr);} return 0;
    }
    if(!strcmp(args[0], "getcrosschainorderbook")){
        char out[65536],arr[90000]={0}; char *argv[]={g_backend_path,"crosschain-orderbook",g_cdir,argc>=2?args[1]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getcrosschainorderbook","backend failed"); else {json_lines_array(arr,sizeof(arr),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getcrosschainorderbook\",\"result\":{\"lines\":%s}}\n",arr);} return 0;
    }
    if(!strcmp(args[0], "getbtchtlctemplate") && argc>=5){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"btc-htlc-template",args[1],args[2],args[3],args[4],argc>=6?args[5]:"mainnet",NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getbtchtlctemplate","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getbtchtlctemplate\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getbtcspvinfo")){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"btc-spv-info",g_cdir,NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getbtcspvinfo","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getbtcspvinfo\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getbtcbestheader")){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"btc-spv-best-header",g_cdir,NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getbtcbestheader","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getbtcbestheader\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getbtcheader") && argc>=2){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"btc-spv-header",g_cdir,args[1],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getbtcheader","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getbtcheader\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "verifybtcproof") && argc>=5){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"btc-spv-verify-proof",g_cdir,args[1],args[2],args[3],args[4],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"verifybtcproof","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"verifybtcproof\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getbtcconfirmations") && argc>=2){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"btc-spv-confirmations",g_cdir,args[1],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getbtcconfirmations","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getbtcconfirmations\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "verifycrosschainfunding") && argc>=6){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"crosschain-verify-funding",g_cdir,args[1],args[2],args[3],args[4],args[5],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"verifycrosschainfunding","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"verifycrosschainfunding\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getcrosschainfunding") && argc>=2){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"crosschain-funding",g_cdir,args[1],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getcrosschainfunding","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getcrosschainfunding\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getcrosschainsecurity") && argc>=2){
        char out[32768],obj[48000]={0}; char *argv[]={g_backend_path,"crosschain-security",g_cdir,args[1],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"getcrosschainsecurity","backend failed"); else {json_keyval_object(obj,sizeof(obj),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getcrosschainsecurity\",\"result\":%s}\n",obj);} return 0;
    }
    if(!strcmp(args[0], "getbalance")){
        char addr[512], out[8192];
        char *argv[] = { g_backend_path, "balance", g_cdir, NULL, NULL };
        if(argc >= 2) argv[3] = args[1];
        else { if(qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) != 0){ json_error(resp, resp_sz, "getbalance", "address unavailable"); return 0; } argv[3] = addr; }
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getbalance", "backend failed");
        else { trim_ws_right(out); json_ok_number(resp, resp_sz, "getbalance", "balance", atoll(out)); }
        return 0;
    }
    if(!strcmp(args[0], "history")){
        char addr[512], out[32768];
        char *argv[] = { g_backend_path, "history", g_cdir, NULL, NULL, NULL };
        if(argc >= 2) argv[3] = args[1]; else { if(qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) != 0){ json_error(resp, resp_sz, "history", "address unavailable"); return 0; } argv[3] = addr; }
        argv[4] = argc >= 3 ? args[2] : "20";
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "history", "backend failed");
        else { char arr[60000]={0}; json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"history\",\"result\":{\"entries\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "addnode") && argc >= 2){
        char host[128], port[32], out[8192];
        if(parse_hostport_local(args[1], host, sizeof(host), port, sizeof(port)) != 0){ json_error(resp, resp_sz, "addnode", "bad host:port"); return 0; }
        char *argv[] = { g_backend_path, "add-peer", g_ndir, host, port, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "addnode", "backend failed");
        else json_ok_raw(resp, resp_sz, "addnode", out);
        return 0;
    }
    if(!strcmp(args[0], "listpeers")){
        char out[16384]; char arr[20000]={0};
        char *argv[] = { g_backend_path, "list-peers", g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "listpeers", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"listpeers\",\"result\":{\"lines\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "getpeerinfo")){
        char out1[16384], out2[16384], arr1[20000]={0}, obj2[20000]={0};
        char *argv1[] = { g_backend_path, "list-peers", g_ndir, NULL };
        char *argv2[] = { g_backend_path, "peer-status", g_ndir, NULL };
        if(run_capture(argv1, out1, sizeof(out1)) != 0 || run_capture(argv2, out2, sizeof(out2)) != 0) json_error(resp, resp_sz, "getpeerinfo", "backend failed");
        else { json_lines_array(arr1,sizeof(arr1),out1); json_keyval_object(obj2,sizeof(obj2),out2); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getpeerinfo\",\"result\":{\"lines\":%s,\"connections\":%lld,\"peer_state\":%s}}\n", arr1, qrx_connection_count(), obj2); }
        return 0;
    }
    if(!strcmp(args[0], "peerstatus") || !strcmp(args[0], "banscores")){
        char out[16384], obj[20000]={0};
        char *argv[] = { g_backend_path, "peer-status", g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, args[0], "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"%s\",\"result\":%s}\n", args[0], obj); }
        return 0;
    }

    if(!strcmp(args[0], "getdevaddress")){
        char out[4096], ajs[1024]={0};
        char *argv[] = { g_backend_path, "getdevaddress", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getdevaddress", "backend failed");
        else { trim_ws_right(out); json_string(ajs,sizeof(ajs),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getdevaddress\",\"result\":{\"address\":%s}}\n", ajs); }
        return 0;
    }
    if(!strcmp(args[0], "faucet") && argc >= 3){
        char out[8192];
        char *argv[] = { g_backend_path, "faucet", g_cdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "faucet", "backend failed or faucet disabled on this network");
        else json_ok_raw(resp, resp_sz, "faucet", out);
        return 0;
    }

    if(!strcmp(args[0], "tokenomics")){
        char out[16384], obj[20000]={0};
        char *argv[] = { g_backend_path, "tokenomics", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "tokenomics", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"tokenomics\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getreward")){
        char out[8192], obj[12000]={0};
        char *argv[] = { g_backend_path, "getreward", g_cdir, argc>=2?args[1]:NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getreward", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getreward\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getparams")){
        char out[16384], obj[20000]={0};
        char *argv[] = { g_backend_path, "getparams", g_cdir, argc>=2?args[1]:NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getparams", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getparams\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getprotocolinfo")){
        char out[8192], obj[12000]={0};
        char *argv[] = { g_backend_path, "protocol-info", g_cdir, argc>=2?args[1]:NULL, NULL };
        int rc=run_capture(argv, out, sizeof(out));
        if(rc != 0 && rc != 2) json_error(resp, resp_sz, "getprotocolinfo", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getprotocolinfo\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "gethalving")){
        char out[8192], obj[12000]={0};
        char *argv[] = { g_backend_path, "gethalving", g_cdir, argc>=2?args[1]:NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "gethalving", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"gethalving\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "getforks")){
        char out[8192], arr[12000]={0}; char *argv[] = { g_backend_path, "getforks", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getforks", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getforks\",\"result\":{\"forks\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "getactivefork")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "getactivefork", g_cdir, argc>=2?args[1]:NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getactivefork", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getactivefork\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "validator-set")){
        char out[16384], arr[20000]={0};
        char *argv[] = { g_backend_path, "validator-set", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "validator-set", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"validator-set\",\"result\":{\"validators\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "getstakinginfo")){
        char addr[512], out[20000], obj[24000]={0};
        if(qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) != 0){ json_error(resp, resp_sz, "getstakinginfo", "address unavailable"); return 0; }
        char *argv[] = { g_backend_path, "staking-status", g_cdir, addr, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getstakinginfo", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getstakinginfo\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "walletpassphrasehexfor") && argc >= 3){
        char secret[256]={0};
        if(!signer_wallet_name_safe(args[1])){json_error(resp,resp_sz,"walletpassphrasehexfor","invalid wallet name");return 0;}
        if(strcmp(args[2],"-") && qrx_hex_decode_text(args[2],secret,sizeof(secret))!=0){json_error(resp,resp_sz,"walletpassphrasehexfor","invalid encoding");return 0;}
        if(signer_verify_secret(args[1],secret)!=0){OPENSSL_cleanse(secret,sizeof(secret));json_error(resp,resp_sz,"walletpassphrasehexfor","incorrect passphrase");return 0;}
        QrxSignerSession*ss=signer_session(args[1],1); if(!ss){OPENSSL_cleanse(secret,sizeof(secret));json_error(resp,resp_sz,"walletpassphrasehexfor","signer session limit reached");return 0;}
        OPENSSL_cleanse(ss->secret,sizeof(ss->secret));snprintf(ss->secret,sizeof(ss->secret),"%s",secret);ss->unlocked=1;OPENSSL_cleanse(secret,sizeof(secret));snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"walletpassphrasehexfor\",\"result\":{\"wallet\":\"%s\",\"unlocked\":true,\"verified\":true}}\n",args[1]);return 0;}
    if(!strcmp(args[0], "walletsessionstatusfor") && argc >= 2){QrxSignerSession*ss=signer_session(args[1],0);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"walletsessionstatusfor\",\"result\":{\"wallet\":\"%s\",\"unlocked\":%s}}\n",args[1],(ss&&ss->unlocked)?"true":"false");return 0;}
    if(!strcmp(args[0], "walletlockfor") && argc >= 2){QrxSignerSession*ss=signer_session(args[1],0);if(ss){OPENSSL_cleanse(ss->secret,sizeof(ss->secret));ss->unlocked=0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"walletlockfor\",\"result\":{\"locked\":true}}\n");return 0;}
    /* 0.0.9.74: legacy global unlock must never claim success without
     * verifying the active wallet key. Keep the RPC for compatibility, but
     * route it through the same signer verification/session semantics as the
     * wallet-specific command. */
    if(!strcmp(args[0], "walletpassphrasehex") && argc >= 2){
        char secret[256]={0};
        const char *active_wallet=strrchr(g_wdir,'/'); active_wallet=active_wallet?active_wallet+1:g_wdir;
        if(!signer_wallet_name_safe(active_wallet)){json_error(resp,resp_sz,"walletpassphrasehex","active wallet name invalid");return 0;}
        if(strcmp(args[1],"-") && qrx_hex_decode_text(args[1],secret,sizeof(secret))!=0){json_error(resp,resp_sz,"walletpassphrasehex","invalid passphrase encoding");return 0;}
        if(signer_verify_secret(active_wallet,secret)!=0){OPENSSL_cleanse(secret,sizeof(secret));json_error(resp,resp_sz,"walletpassphrasehex","incorrect passphrase");return 0;}
        QrxSignerSession*ss=signer_session(active_wallet,1); if(!ss){OPENSSL_cleanse(secret,sizeof(secret));json_error(resp,resp_sz,"walletpassphrasehex","signer session limit reached");return 0;}
        OPENSSL_cleanse(ss->secret,sizeof(ss->secret));snprintf(ss->secret,sizeof(ss->secret),"%s",secret);ss->unlocked=1;OPENSSL_cleanse(secret,sizeof(secret));
        snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"walletpassphrasehex\",\"result\":{\"wallet\":\"%s\",\"unlocked\":true,\"verified\":true}}\n",active_wallet);return 0;
    }
    if(!strcmp(args[0], "walletlock")){
        const char *active_wallet=strrchr(g_wdir,'/'); active_wallet=active_wallet?active_wallet+1:g_wdir;
        QrxSignerSession*ss=signer_session(active_wallet,0);if(ss){OPENSSL_cleanse(ss->secret,sizeof(ss->secret));ss->unlocked=0;}
        qrx_set_env("QRX_PASSPHRASE", "", 1);
        snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"walletlock\",\"result\":{\"locked\":true}}\n");
        return 0;
    }
    if(!strcmp(args[0], "getwalletinfo")){
        char addr[512], out[8192], balance[8192], ajs[1024]={0};
        if(qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) != 0){ json_error(resp, resp_sz, "getwalletinfo", "address unavailable"); return 0; }
        char *argv[] = { g_backend_path, "balance", g_cdir, addr, NULL };
        if(run_capture(argv, balance, sizeof(balance)) != 0){ json_error(resp, resp_sz, "getwalletinfo", "balance failed"); return 0; }
        trim_ws_right(balance); json_string(ajs,sizeof(ajs),addr);
        snprintf(out,sizeof(out),"{\"ok\":true,\"method\":\"getwalletinfo\",\"result\":{\"wallet_dir\":\"%s\",\"address\":%s,\"balance\":%lld}}\n", g_wdir, ajs, atoll(balance));
        snprintf(resp, resp_sz, "%s", out);
        return 0;
    }
    if(!strcmp(args[0], "stake") && argc >= 2){
        char out[8192]; char *argv[] = { g_backend_path, "stake", g_cdir, g_wdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stake", "backend failed"); else json_ok_raw(resp, resp_sz, "stake", out); return 0;
    }
    if(!strcmp(args[0], "delegate") && argc >= 3){
        char out[8192]; char *argv[] = { g_backend_path, "delegate", g_cdir, g_wdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "delegate", "backend failed"); else json_ok_raw(resp, resp_sz, "delegate", out); return 0;
    }
    if(!strcmp(args[0], "undelegate") && argc >= 3){
        char out[8192]; char *argv[] = { g_backend_path, "undelegate", g_cdir, g_wdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "undelegate", "backend failed"); else json_ok_raw(resp, resp_sz, "undelegate", out); return 0;
    }
    if(!strcmp(args[0], "claim-undelegated") && argc >= 2){
        char out[8192]; char *argv[] = { g_backend_path, "claim-undelegated", g_cdir, g_wdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "claim-undelegated", "backend failed"); else json_ok_raw(resp, resp_sz, "claim-undelegated", out); return 0;
    }
    if(!strcmp(args[0], "createrawtransaction") && argc >= 6){
        char out[32768], rawjs[60000]={0};
        const char *memo = argc >= 7 ? args[6] : NULL;
        const char *fee = argc >= 8 ? args[7] : NULL;
        const char *nonce = argc >= 9 ? args[8] : NULL;
        char *argv[] = { g_backend_path, "create-raw-tx", g_cdir, args[1], args[2], args[3], args[4], args[5], (char*)memo, (char*)fee, (char*)nonce, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "createrawtransaction", "backend failed");
        else { trim_ws_right(out); json_string(rawjs, sizeof(rawjs), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"createrawtransaction\",\"result\":{\"raw_tx\":%s}}\n", rawjs); }
        return 0;
    }
    if(!strcmp(args[0], "createagentregistertransaction") && argc >= 14){
        char out[65536];
        char *argv[] = { g_backend_path, "create-agent-register-raw-tx", g_cdir, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], argc >= 15 ? args[14] : NULL, argc >= 16 ? args[15] : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "createagentregistertransaction", "backend failed");
        else { char rawjs[70000]; trim_ws_right(out); json_string(rawjs, sizeof(rawjs), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"createagentregistertransaction\",\"result\":{\"raw_tx\":%s}}\n", rawjs); }
        return 0;
    }
    if(!strcmp(args[0], "createagentupdatetransaction") && argc >= 12){
        char out[65536];
        char *argv[] = { g_backend_path, "create-agent-update-raw-tx", g_cdir, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], argc >= 13 ? args[12] : NULL, argc >= 14 ? args[13] : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "createagentupdatetransaction", "backend failed");
        else { char rawjs[70000]; trim_ws_right(out); json_string(rawjs, sizeof(rawjs), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"createagentupdatetransaction\",\"result\":{\"raw_tx\":%s}}\n", rawjs); }
        return 0;
    }
    if(!strcmp(args[0], "createagentrevoketransaction") && argc >= 7){
        char out[65536];
        char *argv[] = { g_backend_path, "create-agent-revoke-raw-tx", g_cdir, args[1], args[2], args[3], args[4], args[5], args[6], argc >= 8 ? args[7] : NULL, argc >= 9 ? args[8] : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "createagentrevoketransaction", "backend failed");
        else { char rawjs[70000]; trim_ws_right(out); json_string(rawjs, sizeof(rawjs), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"createagentrevoketransaction\",\"result\":{\"raw_tx\":%s}}\n", rawjs); }
        return 0;
    }
    if(!strcmp(args[0], "createordertransaction") && argc >= 13){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-order-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],args[12],argc>=14?args[13]:NULL,argc>=15?args[14]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"createordertransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createordertransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "createexternalordertransaction") && argc >= 14){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-external-order-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],args[12],args[13],argc>=15?args[14]:NULL,argc>=16?args[15]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"createexternalordertransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createexternalordertransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "createarbitragehedgetransaction") && argc >= 12){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-arbitrage-hedge-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],argc>=13?args[12]:NULL,argc>=14?args[13]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"createarbitragehedgetransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createarbitragehedgetransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "creategatewayregistertransaction") && argc >= 12){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-gateway-register-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],argc>=13?args[12]:NULL,argc>=14?args[13]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"creategatewayregistertransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"creategatewayregistertransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "creategatewayrevoketransaction") && argc >= 7){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-gateway-revoke-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],argc>=8?args[7]:NULL,argc>=9?args[8]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"creategatewayrevoketransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"creategatewayrevoketransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "createexecutionreporttransaction") && argc >= 14){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-execution-report-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],args[12],args[13],argc>=15?args[14]:NULL,argc>=16?args[15]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"createexecutionreporttransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createexecutionreporttransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "createbtcspvheadertransaction") && argc>=7){
        char out[65536],rawjs[120000]={0}; char *argv[]={g_backend_path,"create-btc-spv-header-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],argc>=8?args[7]:NULL,argc>=9?args[8]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0)json_error(resp,resp_sz,"createbtcspvheadertransaction","backend failed");else{trim_ws_right(out);json_string(rawjs,sizeof(rawjs),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createbtcspvheadertransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs);}return 0;
    }
    if(!strcmp(args[0], "createbtcspvfundingprooftransaction") && argc>=11){
        char out[131072],rawjs[180000]={0}; char *argv[]={g_backend_path,"create-btc-spv-funding-proof-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],argc>=12?args[11]:NULL,argc>=13?args[12]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0)json_error(resp,resp_sz,"createbtcspvfundingprooftransaction","backend failed");else{trim_ws_right(out);json_string(rawjs,sizeof(rawjs),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createbtcspvfundingprooftransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs);}return 0;
    }
    if(!strcmp(args[0], "createcrosschainbuytransaction") && argc>=13){
        char out[65536],rawjs[120000]={0}; char *argv[]={g_backend_path,"create-crosschain-buy-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],args[12],argc>=14?args[13]:NULL,argc>=15?args[14]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0)json_error(resp,resp_sz,"createcrosschainbuytransaction","backend failed");else{trim_ws_right(out);json_string(rawjs,sizeof(rawjs),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createcrosschainbuytransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs);}return 0;
    }
    if(!strcmp(args[0], "createcrosschainselltransaction") && argc>=12){
        char out[65536],rawjs[120000]={0}; char *argv[]={g_backend_path,"create-crosschain-sell-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],argc>=13?args[12]:NULL,argc>=14?args[13]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0)json_error(resp,resp_sz,"createcrosschainselltransaction","backend failed");else{trim_ws_right(out);json_string(rawjs,sizeof(rawjs),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createcrosschainselltransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs);}return 0;
    }
    if(!strcmp(args[0], "createcrosschainredeemtransaction") && argc>=8){
        char out[65536],rawjs[120000]={0}; char *argv[]={g_backend_path,"create-crosschain-redeem-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],argc>=9?args[8]:NULL,argc>=10?args[9]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0)json_error(resp,resp_sz,"createcrosschainredeemtransaction","backend failed");else{trim_ws_right(out);json_string(rawjs,sizeof(rawjs),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createcrosschainredeemtransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs);}return 0;
    }
    if(!strcmp(args[0], "createcrosschainrefundtransaction") && argc>=7){
        char out[65536],rawjs[120000]={0}; char *argv[]={g_backend_path,"create-crosschain-refund-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],argc>=8?args[7]:NULL,argc>=9?args[8]:NULL,NULL};
        if(run_capture(argv,out,sizeof(out))!=0)json_error(resp,resp_sz,"createcrosschainrefundtransaction","backend failed");else{trim_ws_right(out);json_string(rawjs,sizeof(rawjs),out);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createcrosschainrefundtransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs);}return 0;
    }
    if(!strcmp(args[0], "createordercanceltransaction") && argc >= 8){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-order-cancel-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],argc>=9?args[8]:NULL,argc>=10?args[9]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"createordercanceltransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createordercanceltransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "createorderreplacetransaction") && argc >= 14){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path,"create-order-replace-raw-tx",g_cdir,args[1],args[2],args[3],args[4],args[5],args[6],args[7],args[8],args[9],args[10],args[11],args[12],args[13],argc>=15?args[14]:NULL,argc>=16?args[15]:NULL,NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"createorderreplacetransaction","backend failed"); else { trim_ws_right(out); json_string(rawjs,sizeof(rawjs),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createorderreplacetransaction\",\"result\":{\"raw_tx\":%s}}\n",rawjs); } return 0;
    }
    if(!strcmp(args[0], "createvelocitytransaction") && argc >= 10){
        char out[65536], rawjs[120000]={0};
        char *argv[] = { g_backend_path, "create-velocity-raw-tx", g_cdir, args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], argc >= 12 ? args[10] : NULL, argc >= 13 ? args[11] : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "createvelocitytransaction", "backend failed");
        else { trim_ws_right(out); json_string(rawjs, sizeof(rawjs), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"createvelocitytransaction\",\"result\":{\"raw_tx\":%s}}\n", rawjs); }
        return 0;
    }
    if(!strcmp(args[0], "signrawtransactionwithwallet") && argc >= 3){
        char out[8192]; char *argv[] = { g_backend_path, "signrawtransactionwithwallet", g_wdir, g_cdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "signrawtransactionwithwallet", "backend failed");
        else { trim_ws_right(out); json_ok_string(resp, resp_sz, "signrawtransactionwithwallet", "signed_tx_file", out); }
        return 0;
    }
    if(!strcmp(args[0], "decoderawtransaction") && argc >= 2){
        char out[32768], obj[60000]={0}; char *argv[] = { g_backend_path, "decoderawtransaction", g_cdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "decoderawtransaction", "backend failed");
        else { json_keyval_object(obj, sizeof(obj), out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"decoderawtransaction\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "gettxid") && argc >= 2){
        char out[8192]; char *argv[] = { g_backend_path, "txid", g_cdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "gettxid", "backend failed");
        else { trim_ws_right(out); json_ok_string(resp, resp_sz, "gettxid", "txid", out); }
        return 0;
    }
    if(!strcmp(args[0], "sendtoaddress") && argc >= 3){
        char out[8192]; const char *memo = argc >= 4 ? args[3] : "payment";
        char *argv[] = { g_backend_path, "send", g_wdir, g_cdir, args[1], args[2], (char*)memo, g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "sendtoaddress", "backend failed"); else json_ok_raw(resp, resp_sz, "sendtoaddress", out); return 0;
    }
    if(!strcmp(args[0], "sendfromaddress") && argc >= 4){
        char out[8192]; const char *memo = argc >= 5 ? args[4] : "payment";
        char *argv[] = { g_backend_path, "send-from", g_wdir, g_cdir, args[1], args[2], args[3], (char*)memo, g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "sendfromaddress", "backend failed"); else json_ok_raw(resp, resp_sz, "sendfromaddress", out); return 0;
    }
    if(!strcmp(args[0], "createswap") && argc >= 5){
        char out[16384]; const char *memo = argc >= 6 ? args[5] : "quantum-swap";
        char *argv[] = { g_backend_path, "htlc-create", g_cdir, g_wdir, args[1], args[2], args[3], args[4], (char*)memo, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "createswap", "backend failed"); else json_ok_raw(resp, resp_sz, "createswap", out); return 0;
    }
    if(!strcmp(args[0], "redeemswap") && argc >= 3){
        char out[16384]; char *argv[] = { g_backend_path, "htlc-redeem", g_cdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "redeemswap", "backend failed"); else json_ok_raw(resp, resp_sz, "redeemswap", out); return 0;
    }
    if(!strcmp(args[0], "refundswap") && argc >= 2){
        char out[16384]; char *argv[] = { g_backend_path, "htlc-refund", g_cdir, g_wdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "refundswap", "backend failed"); else json_ok_raw(resp, resp_sz, "refundswap", out); return 0;
    }
    if(!strcmp(args[0], "getswap") && argc >= 2){
        char out[16384], obj[20000]={0}; char *argv[] = { g_backend_path, "htlc-get", g_cdir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "getswap", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getswap\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "listswaps")){
        char out[32768], arr[60000]={0}; char *argv[] = { g_backend_path, "htlc-list", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "listswaps", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"listswaps\",\"result\":{\"swaps\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "shielded-address")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "shielded-address", g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "shielded-address", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"shielded-address\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "shield") && argc >= 2){
        char out[16384], obj[20000]={0};
        const char *zaddr = argc >= 3 ? args[2] : "";
        char *argv[] = { g_backend_path, argc >= 3 ? "shield-to" : "shield", g_cdir, g_wdir, args[1], argc >= 3 ? (char*)zaddr : NULL, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "shield", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"shield\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "shielded-balance")){
        char out[8192]; char *argv[] = { g_backend_path, "shielded-balance", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "shielded-balance", "backend failed");
        else { trim_ws_right(out); json_ok_number(resp, resp_sz, "shielded-balance", "balance", atoll(out)); }
        return 0;
    }
    if(!strcmp(args[0], "shielded-send") && argc >= 3){
        char out[16384], obj[20000]={0}; char *argv[] = { g_backend_path, "shielded-send", g_cdir, g_wdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "shielded-send", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"shielded-send\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "unshield") && argc >= 3){
        char out[16384], obj[20000]={0}; char *argv[] = { g_backend_path, "unshield", g_cdir, g_wdir, args[1], args[2], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "unshield", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"unshield\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "shielded-history")){
        char out[32768], arr[60000]={0}; char *argv[] = { g_backend_path, "shielded-history", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "shielded-history", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"shielded-history\",\"result\":{\"entries\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "stealth-address")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "stealth-address", g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stealth-address", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stealth-address\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "stealth-send") && argc >= 3){
        char out[16384], obj[20000]={0}; const char *memo = argc >= 4 ? args[3] : "stealth-transfer";
        char *argv[] = { g_backend_path, "stealth-send", g_cdir, g_wdir, args[1], args[2], (char*)memo, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stealth-send", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stealth-send\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "stealth-scan")){
        char out[32768], arr[60000]={0}; char *argv[] = { g_backend_path, "stealth-scan", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stealth-scan", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stealth-scan\",\"result\":{\"entries\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "stealth-spend") && argc >= 4){
        char out[16384], obj[20000]={0}; char *argv[] = { g_backend_path, "stealth-spend", g_cdir, g_wdir, args[1], args[2], args[3], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stealth-spend", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stealth-spend\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "stealth-history")){
        char out[32768], arr[60000]={0}; char *argv[] = { g_backend_path, "stealth-history", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stealth-history", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stealth-history\",\"result\":{\"entries\":%s}}\n", arr); }
        return 0;
    }
    if(!strcmp(args[0], "privacy-credential-status")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "privacy-credential-status", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "privacy-credential-status", "credential missing, expired, revoked or invalid");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"privacy-credential-status\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "hidden-balance")){
        char out[8192]; char *argv[] = { g_backend_path, "hidden-balance", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "hidden-balance", "verified privacy credential required");
        else { trim_ws_right(out); json_ok_number(resp, resp_sz, "hidden-balance", "balance", atoll(out)); }
        return 0;
    }
    if(!strcmp(args[0], "verified-shield") && argc >= 2){
        char out[16384], obj[20000]={0}; const char *zaddr=argc>=3?args[2]:NULL;
        char *argv[] = { g_backend_path, "verified-shield", g_cdir, g_wdir, args[1], (char*)zaddr, NULL };
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"verified-shield","verified privacy credential required or backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"verified-shield\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "verified-shielded-send") && argc >= 3){
        char out[16384], obj[20000]={0}; char *argv[]={g_backend_path,"verified-shielded-send",g_cdir,g_wdir,args[1],args[2],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"verified-shielded-send","verified privacy credential required or backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"verified-shielded-send\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "verified-unshield") && argc >= 3){
        char out[16384], obj[20000]={0}; char *argv[]={g_backend_path,"verified-unshield",g_cdir,g_wdir,args[1],args[2],NULL};
        if(run_capture(argv,out,sizeof(out))!=0) json_error(resp,resp_sz,"verified-unshield","verified privacy credential required or backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"verified-unshield\",\"result\":%s}\n",obj); } return 0;
    }
    if(!strcmp(args[0], "privacy-feature-status")){
        char out[8192], obj[12000]={0}; char *argv[] = { g_backend_path, "privacy-feature-status", g_cdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "privacy-feature-status", "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"privacy-feature-status\",\"result\":%s}\n", obj); }
        return 0;
    }
    if(!strcmp(args[0], "sendrawtransaction") && argc >= 2){
        char out[8192]; char *argv[] = { g_backend_path, "sendtx", g_ndir, args[1], NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "sendrawtransaction", "backend failed"); else json_ok_raw(resp, resp_sz, "sendrawtransaction", out); return 0;
    }
    if(!strcmp(args[0],"getdrivetransfer")&&argc>=2){QrxDriveJobSnapshot j;if(!g_drive_runtime||qrx_drive_runtime_get(g_drive_runtime,args[1],&j)!=0)json_error(resp,resp_sz,"getdrivetransfer","transfer not found");else drive_job_json(resp,resp_sz,"getdrivetransfer",&j);return 0;}
    if(!strcmp(args[0],"listdrivetransfers")){QrxDriveJobSnapshot js[64];size_t n=g_drive_runtime?qrx_drive_runtime_list(g_drive_runtime,js,64):0;size_t off=snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listdrivetransfers\",\"result\":[");for(size_t i=0;i<n&&off+512<resp_sz;i++){char id[300],cid[300],dir[80],err[500];json_string(id,sizeof(id),js[i].transfer_id);json_string(cid,sizeof(cid),js[i].contract_id);json_string(dir,sizeof(dir),js[i].direction);json_string(err,sizeof(err),js[i].error);off+=(size_t)snprintf(resp+off,resp_sz-off,"%s{\"transfer_id\":%s,\"contract_id\":%s,\"direction\":%s,\"state\":%u,\"total_bytes\":%llu,\"completed_bytes\":%llu,\"completed_shards\":%u,\"required_shards\":%u,\"error\":%s}",i?",":"",id,cid,dir,js[i].state,(unsigned long long)js[i].total_bytes,(unsigned long long)js[i].completed_bytes,js[i].completed_shards,js[i].required_shards,err);}snprintf(resp+off,resp_sz-off,"]}\n");return 0;}
    if(!strcmp(args[0],"pausedrivetransfer")&&argc>=2){if(!g_drive_runtime||qrx_drive_runtime_pause(g_drive_runtime,args[1]))json_error(resp,resp_sz,"pausedrivetransfer","unable to pause transfer");else snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"pausedrivetransfer\",\"result\":true}\n");return 0;}
    if(!strcmp(args[0],"resumedrivetransfer")&&argc>=2){if(!g_drive_runtime||qrx_drive_runtime_resume(g_drive_runtime,args[1]))json_error(resp,resp_sz,"resumedrivetransfer","unable to resume transfer");else snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"resumedrivetransfer\",\"result\":true}\n");return 0;}
    if(!strcmp(args[0],"canceldrivetransfer")&&argc>=2){if(!g_drive_runtime||qrx_drive_runtime_cancel(g_drive_runtime,args[1]))json_error(resp,resp_sz,"canceldrivetransfer","unable to cancel transfer");else snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"canceldrivetransfer\",\"result\":true}\n");return 0;}
    if(!strcmp(args[0],"getdrivepqstatus")){char kp[PATH_MAX],ku[PATH_MAX],mp[PATH_MAX];snprintf(kp,sizeof(kp),"%s/drive_mlkem768_priv.pem",g_wdir);snprintf(ku,sizeof(ku),"%s/drive_mlkem768_pub.pem",g_wdir);snprintf(mp,sizeof(mp),"%s/mldsa65_priv.pem",g_wdir);int ready=!access(kp,R_OK)&&!access(ku,R_OK)&&!access(mp,R_OK);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getdrivepqstatus\",\"result\":{\"ready\":%s,\"at_rest_kem\":\"ML-KEM-768\",\"data_cipher\":\"AES-256-GCM\",\"manifest_signature\":\"ML-DSA-65\",\"recovery_bound\":%s}}\n",ready?"true":"false",ready?"true":"false");return 0;}
    if(!strcmp(args[0],"preparedriveuploadhex")&&argc>=3){char src[PATH_MAX];if(qrx_hex_decode_text(args[1],src,sizeof(src))){json_error(resp,resp_sz,"preparedriveupload","invalid source path encoding");return 0;}const char*profile=args[2];unsigned k=!strcmp(profile,"ARCHIVE")?16:(!strcmp(profile,"FAST")?1:10),m=!strcmp(profile,"ARCHIVE")?4:(!strcmp(profile,"FAST")?2:4);EVP_PKEY*kem=drive_load_pub("drive_mlkem768_pub.pem"),*sign=drive_load_priv("mldsa65_priv.pem");if(!kem||!sign){EVP_PKEY_free(kem);EVP_PKEY_free(sign);json_error(resp,resp_sz,"preparedriveupload","wallet PRIVATE_PQ keys unavailable or wallet locked");return 0;}char root[PATH_MAX];snprintf(root,sizeof(root),"%s/drive/prepared",g_wdir);QrxDrivePreparedUpload p={0};int rc=qrx_drive_prepare_private_upload(root,src,profile,k,m,kem,sign,&p);EVP_PKEY_free(kem);EVP_PKEY_free(sign);if(rc){json_error(resp,resp_sz,"preparedriveupload","PRIVATE_PQ preflight failed");return 0;}char idj[300],dirj[2200],mh[129];qrx_hex_bytes_local(p.manifest_hash,64,mh);json_string(idj,sizeof(idj),p.prepare_id);json_string(dirj,sizeof(dirj),p.package_dir);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"preparedriveupload\",\"result\":{\"prepare_id\":%s,\"package_dir\":%s,\"profile\":\"%s\",\"plaintext_bytes\":%llu,\"ciphertext_bytes\":%llu,\"shard_bytes\":%llu,\"data_shards\":%u,\"parity_shards\":%u,\"manifest_root_hex\":\"%s\",\"crypto_suite\":\"qrx-drive-pq-v1\",\"at_rest_kem\":\"ML-KEM-768\"}}\n",idj,dirj,profile,(unsigned long long)p.plaintext_bytes,(unsigned long long)p.ciphertext_bytes,(unsigned long long)p.shard_bytes,p.data_shards,p.parity_shards,mh);qrx_drive_prepared_upload_free(&p);return 0;}
    if(!strcmp(args[0],"startpreparedriveupload")&&argc>=3){char dir[PATH_MAX];drive_prepare_dir(dir,args[2]);EVP_PKEY*sp=drive_load_pub("mldsa65_pub.pem");QrxDrivePreparedUpload p={0};if(!sp||qrx_drive_prepared_upload_load(dir,sp,&p)){EVP_PKEY_free(sp);json_error(resp,resp_sz,"startpreparedriveupload","prepared package invalid or missing");return 0;}EVP_PKEY_free(sp);if(drive_runtime_sync_sources_mode(args[1],1)){qrx_drive_prepared_upload_free(&p);json_error(resp,resp_sz,"startpreparedriveupload","no currently verified provider discovery sources for contract");return 0;}char id[129];int rc=qrx_drive_runtime_start_prepared_upload(g_drive_runtime,args[1],&p,id);qrx_drive_prepared_upload_free(&p);if(rc){json_error(resp,resp_sz,"startpreparedriveupload","contract assignments do not match prepared shard CAS ids");return 0;}char ijs[300];json_string(ijs,sizeof(ijs),id);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"startpreparedriveupload\",\"result\":{\"transfer_id\":%s}}\n",ijs);return 0;}
    if(!strcmp(args[0],"advancepreparedriveupload")&&argc>=2){
        char dir[PATH_MAX];drive_prepare_dir(dir,args[1]);EVP_PKEY*sp=drive_load_pub("mldsa65_pub.pem");QrxDrivePreparedUpload p={0};if(!sp||qrx_drive_prepared_upload_load(dir,sp,&p)){EVP_PKEY_free(sp);json_error(resp,resp_sz,"advancepreparedriveupload","prepared package invalid or missing");return 0;}EVP_PKEY_free(sp);
        uint64_t epochs=argc>=3?strtoull(args[2],NULL,10):QRX_DRIVE_CONTRACT_DEFAULT_EPOCHS,rate=argc>=4?strtoull(args[3],NULL,10):QRX_DRIVE_CONTRACT_DEFAULT_RATE_ATOMS;char owner[512];if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){qrx_drive_prepared_upload_free(&p);json_error(resp,resp_sz,"advancepreparedriveupload","wallet address unavailable");return 0;}
        char blocks[PATH_MAX];snprintf(blocks,sizeof(blocks),"%s/blocks",g_cdir);uint64_t h=(uint64_t)count_regular_files(blocks);QrxDB db;if(qrxdb_init(&db,g_cdir)){qrx_drive_prepared_upload_free(&p);json_error(resp,resp_sz,"advancepreparedriveupload","chain state unavailable");return 0;}QrxDriveContractStep st={0};int prc=qrx_drive_contract_next_step(&db,owner,&p,h?h:1,epochs,rate,&st);qrxdb_close(&db);if(prc){qrx_drive_prepared_upload_free(&p);json_error(resp,resp_sz,"advancepreparedriveupload","prepared package/contract state mismatch or no eligible provider");return 0;}
        if(st.kind==QRX_DRIVE_CONTRACT_READY_UPLOAD){unsigned sk=0,ss=0;unsigned long long sh=0;char prior[129]={0};if(!drive_orch_state_read(dir,&sk,&ss,&sh,prior,sizeof(prior))&&sk==(unsigned)QRX_DRIVE_CONTRACT_READY_UPLOAD&&prior[0]){char ij[300],cj[300];json_string(ij,sizeof(ij),prior);json_string(cj,sizeof(cj),st.contract_id);QrxDriveJobSnapshot js={0};unsigned active=0;QrxDB adb;if(!qrxdb_init(&adb,g_cdir)){for(unsigned ai=0;ai<p.total_shards;ai++){QrxStorageAssignmentRecord ar;if(!qrx_storage_assignment_get(&adb,st.contract_id,ai,&ar)&&ar.state==QRX_ASSIGN_ACTIVE)active++;}qrxdb_close(&adb);}const char*stage="UPLOAD_ALREADY_STARTED";if(!qrx_drive_runtime_get(g_drive_runtime,prior,&js)&&js.state==QRX_DRIVE_JOB_COMPLETED){stage=active>=p.total_shards?"ACTIVE_REDUNDANCY_COMPLETE":active>=p.data_shards?"HEALTHY_WAITING_REDUNDANCY":"WAITING_PROVIDER_ACCEPT";}unsigned required_healthy=p.data_shards,redundancy_target=p.total_shards;qrx_drive_prepared_upload_free(&p);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"advancepreparedriveupload\",\"result\":{\"stage\":\"%s\",\"contract_id\":%s,\"assignments\":%u,\"active_shards\":%u,\"required_healthy\":%u,\"redundancy_target\":%u,\"transfer_id\":%s}}\n",stage,cj,st.assignments_present,active,required_healthy,redundancy_target,ij);return 0;}if(drive_runtime_sync_sources_mode(st.contract_id,1)){qrx_drive_prepared_upload_free(&p);json_error(resp,resp_sz,"advancepreparedriveupload","assignments exist but verified provider discovery is incomplete");return 0;}char id[129];int rc=qrx_drive_runtime_start_prepared_upload(g_drive_runtime,st.contract_id,&p,id);if(!rc)drive_orch_state_write(dir,&st,(unsigned long long)h,id);qrx_drive_prepared_upload_free(&p);if(rc){json_error(resp,resp_sz,"advancepreparedriveupload","prepared upload start failed");return 0;}char ij[300],cj[300];json_string(ij,sizeof(ij),id);json_string(cj,sizeof(cj),st.contract_id);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"advancepreparedriveupload\",\"result\":{\"stage\":\"UPLOAD_STARTED\",\"contract_id\":%s,\"assignments\":%u,\"transfer_id\":%s}}\n",cj,st.assignments_present,ij);return 0;}
        char pending_tx[129]={0};if(drive_orch_is_waiting(dir,&st,(unsigned long long)h,pending_tx,sizeof(pending_tx))){char cj[300],tj[300];json_string(cj,sizeof(cj),st.contract_id);json_string(tj,sizeof(tj),pending_tx);qrx_drive_prepared_upload_free(&p);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"advancepreparedriveupload\",\"result\":{\"stage\":\"WAITING_CONFIRMATION\",\"contract_id\":%s,\"assignments\":%u,\"required\":%u,\"pending_shard\":%u,\"txid\":%s}}\n",cj,st.assignments_present,st.assignments_required,st.shard_index,tj);return 0;}
        char txid[129]={0};if(drive_submit_storage_step(&st,txid)){qrx_drive_prepared_upload_free(&p);json_error(resp,resp_sz,"advancepreparedriveupload","wallet locked, transaction signing failed, or mempool submission failed");return 0;}drive_orch_state_write(dir,&st,(unsigned long long)h,txid);char cj[300],tj[300],to[400];json_string(cj,sizeof(cj),st.contract_id);json_string(tj,sizeof(tj),txid);json_string(to,sizeof(to),st.to);const char*stage=st.kind==QRX_DRIVE_CONTRACT_CREATE?"CONTRACT_SUBMITTED":"ASSIGNMENT_SUBMITTED";qrx_drive_prepared_upload_free(&p);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"advancepreparedriveupload\",\"result\":{\"stage\":\"%s\",\"contract_id\":%s,\"assignments\":%u,\"required\":%u,\"shard_index\":%u,\"provider\":%s,\"txid\":%s}}\n",stage,cj,st.assignments_present,st.assignments_required,st.shard_index,to,tj);return 0;}
    if(!strcmp(args[0],"decryptdrivefilehex")&&argc>=3){char src[PATH_MAX],dst[PATH_MAX];if(qrx_hex_decode_text(args[1],src,sizeof(src))||qrx_hex_decode_text(args[2],dst,sizeof(dst))){json_error(resp,resp_sz,"decryptdrivefile","invalid path encoding");return 0;}EVP_PKEY*kem=drive_load_priv("drive_mlkem768_priv.pem"),*sig=drive_load_pub("mldsa65_pub.pem");if(!kem||!sig){EVP_PKEY_free(kem);EVP_PKEY_free(sig);json_error(resp,resp_sz,"decryptdrivefile","wallet PRIVATE_PQ keys unavailable or wallet locked");return 0;}uint64_t n=0;int rc=qrx_drive_private_pq_decrypt_file(src,dst,kem,sig,&n);EVP_PKEY_free(kem);EVP_PKEY_free(sig);if(rc){json_error(resp,resp_sz,"decryptdrivefile","signature/KEM/GCM verification failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"decryptdrivefile\",\"result\":{\"plaintext_bytes\":%llu,\"verified\":true}}\n",(unsigned long long)n);return 0;}
    if(!strcmp(args[0],"startdrivedownloadhex")&&argc>=3){char drive_path[PATH_MAX];if(qrx_hex_decode_text(args[2],drive_path,sizeof(drive_path))!=0){json_error(resp,resp_sz,"startdrivedownload","invalid destination path encoding");return 0;}QrxDriveFileSnapshot f;QrxDriveShardRoute*routes=NULL;size_t rn=0;if(qrx_drive_live_routes(g_cdir,args[1],3,&routes,&rn,&f)!=0){json_error(resp,resp_sz,"startdrivedownload","contract unavailable");return 0;}qrx_drive_live_routes_free(routes);unsigned k=!strcmp(f.profile,"ARCHIVE")?16:(!strcmp(f.profile,"FAST")?1:10),m=!strcmp(f.profile,"ARCHIVE")?4:(!strcmp(f.profile,"FAST")?2:4);size_t shard=(size_t)((f.logical_bytes+k-1)/k);if(drive_runtime_sync_sources(args[1])!=0){json_error(resp,resp_sz,"startdrivedownload","no currently verified provider discovery sources for contract");return 0;}char id[129];int rc=qrx_drive_runtime_start_download(g_drive_runtime,args[1],drive_path,f.logical_bytes,shard,k,m,id);if(rc){json_error(resp,resp_sz,"startdrivedownload","transfer start failed");return 0;}char ijs[300];json_string(ijs,sizeof(ijs),id);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"startdrivedownload\",\"result\":{\"transfer_id\":%s}}\n",ijs);return 0;}
    if(!strcmp(args[0],"startdriveuploadhex")&&argc>=3){char drive_path[PATH_MAX];if(qrx_hex_decode_text(args[2],drive_path,sizeof(drive_path))!=0){json_error(resp,resp_sz,"startdriveupload","invalid source path encoding");return 0;}QrxDriveFileSnapshot f;QrxDriveShardRoute*routes=NULL;size_t rn=0;if(qrx_drive_live_routes(g_cdir,args[1],3,&routes,&rn,&f)!=0){json_error(resp,resp_sz,"startdriveupload","contract unavailable");return 0;}qrx_drive_live_routes_free(routes);unsigned k=!strcmp(f.profile,"ARCHIVE")?16:(!strcmp(f.profile,"FAST")?1:10),m=!strcmp(f.profile,"ARCHIVE")?4:(!strcmp(f.profile,"FAST")?2:4);if(drive_runtime_sync_sources(args[1])!=0){json_error(resp,resp_sz,"startdriveupload","no currently verified provider discovery sources for contract");return 0;}char id[129];int rc=qrx_drive_runtime_start_upload(g_drive_runtime,args[1],drive_path,k,m,id);if(rc){json_error(resp,resp_sz,"startdriveupload","transfer start failed");return 0;}char ijs[300];json_string(ijs,sizeof(ijs),id);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"startdriveupload\",\"result\":{\"transfer_id\":%s}}\n",ijs);return 0;}
    if(!strcmp(args[0],"getdomainpreflight")&&argc>=2){
        char norm[254];if(qrx_domain_normalize(args[1],norm)){json_error(resp,resp_sz,"getdomainpreflight","invalid .qrx name");return 0;}uint64_t h=qrxnet_height(),years=argc>=3?strtoull(args[2],NULL,10):1;if(years<1||years>5){json_error(resp,resp_sz,"getdomainpreflight","years must be 1..5");return 0;}char owner[512];if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"getdomainpreflight","wallet unavailable");return 0;}QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"getdomainpreflight","chain state unavailable");return 0;}QrxDomainRecord old;int exists=qrx_net_registry_get(&db,norm,&old)==0;QrxNetCountCtx cc={0};qrx_net_registry_list(&db,owner,qrxnet_count_cb,&cc);qrxdb_close(&db);QrxDomainPrice pr;if(qrx_domain_price(norm,qrxnet_base_price(h+1),cc.n,&pr)){json_error(resp,resp_sz,"getdomainpreflight","pricing failed");return 0;}int available=!exists||(!qrx_domain_is_active(&old,h+1)&&!qrx_domain_in_grace(&old,h+1));uint64_t rent=pr.mode==QRX_DOMAIN_PRICE_FIXED&&pr.annual_atoms<=UINT64_MAX/years?pr.annual_atoms*years:0,total=(UINT64_MAX-rent>=pr.reservation_bond_atoms)?rent+pr.reservation_bond_atoms:0;EVP_PKEY*pk=drive_load_pub("mldsa65_pub.pem");uint8_t pc[64];char phex[129]={0};int pq=pk&&qrx_domain_pubkey_commitment(pk,pc)==0;if(pq)qrx_hex_bytes_local(pc,64,phex);EVP_PKEY_free(pk);char njs[600];json_string(njs,sizeof(njs),norm);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getdomainpreflight\",\"result\":{\"name\":%s,\"available\":%s,\"price_mode\":\"%s\",\"years\":%llu,\"annual_atoms\":%llu,\"rent_atoms\":%llu,\"reservation_bond_atoms\":%llu,\"total_atoms\":%llu,\"owned_domains\":%llu,\"pq_publishing_key_ready\":%s,\"publishing_suite\":\"ML-DSA-65\",\"publishing_key_commitment_hex\":\"%s\"}}\n",njs,available?"true":"false",pr.mode==QRX_DOMAIN_PRICE_FIXED?"FIXED":"AUCTION_REQUIRED",(unsigned long long)years,(unsigned long long)pr.annual_atoms,(unsigned long long)rent,(unsigned long long)pr.reservation_bond_atoms,(unsigned long long)total,(unsigned long long)cc.n,pq?"true":"false",phex);return 0;}
    if(!strcmp(args[0],"registerdomain")&&argc>=3){char norm[254],owner[512];uint64_t years=strtoull(args[2],NULL,10),h=qrxnet_height();if(qrx_domain_normalize(args[1],norm)||years<1||years>5||qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"registerdomain","invalid parameters or wallet unavailable");return 0;}QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"registerdomain","chain unavailable");return 0;}QrxDomainRecord old;int exists=qrx_net_registry_get(&db,norm,&old)==0;QrxNetCountCtx cc={0};qrx_net_registry_list(&db,owner,qrxnet_count_cb,&cc);qrxdb_close(&db);if(exists&&(qrx_domain_is_active(&old,h+1)||qrx_domain_in_grace(&old,h+1))){json_error(resp,resp_sz,"registerdomain","domain unavailable");return 0;}QrxDomainPrice pr;if(qrx_domain_price(norm,qrxnet_base_price(h+1),cc.n,&pr)||pr.mode!=QRX_DOMAIN_PRICE_FIXED||pr.annual_atoms>UINT64_MAX/years){json_error(resp,resp_sz,"registerdomain","domain requires auction or price invalid");return 0;}EVP_PKEY*pk=drive_load_pub("mldsa65_pub.pem");uint8_t pc[64];if(!pk||qrx_domain_pubkey_commitment(pk,pc)){EVP_PKEY_free(pk);json_error(resp,resp_sz,"registerdomain","ML-DSA-65 wallet publishing key unavailable");return 0;}EVP_PKEY_free(pk);char ph[129],payload[1200],txid[129]={0};qrx_hex_bytes_local(pc,64,ph);const char*qub=argc>=4?args[3]:owner;snprintf(payload,sizeof(payload),"name=%s;years=%llu;qub_address=%s;web_manifest_root_hex=-;publishing_commitment_hex=%s",norm,(unsigned long long)years,qub,ph);uint64_t rent=pr.annual_atoms*years,total=rent+pr.reservation_bond_atoms;if(qrxnet_submit("DOMAIN_REGISTER",owner,total,payload,txid)){json_error(resp,resp_sz,"registerdomain","transaction submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"registerdomain\",\"result\":{\"name\":\"%s\",\"txid\":\"%s\",\"amount_atoms\":%llu,\"publishing_suite\":\"ML-DSA-65\"}}\n",norm,txid,(unsigned long long)total);return 0;}
    if(!strcmp(args[0],"renewdomain")&&argc>=3){uint64_t years=strtoull(args[2],NULL,10),h=qrxnet_height();char owner[512];if(years<1||years>5||qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"renewdomain","invalid parameters");return 0;}QrxDB db;QrxDomainRecord r;if(qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,args[1],&r)){json_error(resp,resp_sz,"renewdomain","domain not found");return 0;}QrxNetCountCtx cc={0};qrx_net_registry_list(&db,owner,qrxnet_count_cb,&cc);qrxdb_close(&db);if(strcmp(r.owner,owner)||!qrx_domain_is_active(&r,h+1)){json_error(resp,resp_sz,"renewdomain","wallet is not active owner");return 0;}QrxDomainPrice pr;if(qrx_domain_price(r.name,qrxnet_base_price(h+1),cc.n,&pr)||pr.mode!=QRX_DOMAIN_PRICE_FIXED||pr.annual_atoms>UINT64_MAX/years){json_error(resp,resp_sz,"renewdomain","pricing failed");return 0;}char payload[600],txid[129]={0};snprintf(payload,sizeof(payload),"name=%s;sequence=%llu;years=%llu",r.name,(unsigned long long)r.sequence,(unsigned long long)years);uint64_t amount=pr.annual_atoms*years;if(qrxnet_submit("DOMAIN_RENEW",owner,amount,payload,txid)){json_error(resp,resp_sz,"renewdomain","transaction submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"renewdomain\",\"result\":{\"name\":\"%s\",\"txid\":\"%s\",\"amount_atoms\":%llu}}\n",r.name,txid,(unsigned long long)amount);return 0;}
    if(!strcmp(args[0],"updatedomain")&&argc>=8){char owner[512];uint64_t h=qrxnet_height();if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"updatedomain","wallet unavailable");return 0;}QrxDB db;QrxDomainRecord r;if(qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,args[1],&r)){json_error(resp,resp_sz,"updatedomain","domain not found");return 0;}qrxdb_close(&db);if(strcmp(r.owner,owner)||!qrx_domain_is_active(&r,h+1)){json_error(resp,resp_sz,"updatedomain","wallet is not active owner");return 0;}const char*pm=args[6];char pubhex[129];const char*pub=args[7];if(!strcmp(pm,"SET")&&!strcmp(pub,"WALLET")){EVP_PKEY*pk=drive_load_pub("mldsa65_pub.pem");uint8_t pc[64];if(!pk||qrx_domain_pubkey_commitment(pk,pc)){EVP_PKEY_free(pk);json_error(resp,resp_sz,"updatedomain","ML-DSA-65 wallet publishing key unavailable");return 0;}EVP_PKEY_free(pk);qrx_hex_bytes_local(pc,64,pubhex);pub=pubhex;}char payload[1800],txid[129]={0};snprintf(payload,sizeof(payload),"name=%s;sequence=%llu;qub_mode=%s;qub_address=%s;web_mode=%s;web_manifest_root_hex=%s;publishing_mode=%s;publishing_commitment_hex=%s",r.name,(unsigned long long)r.sequence,args[2],args[3],args[4],args[5],pm,pub);if(qrxnet_submit("DOMAIN_UPDATE",owner,0,payload,txid)){json_error(resp,resp_sz,"updatedomain","transaction submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"updatedomain\",\"result\":{\"name\":\"%s\",\"txid\":\"%s\",\"expected_sequence\":%llu}}\n",r.name,txid,(unsigned long long)r.sequence);return 0;}
    if(!strcmp(args[0],"transferdomain")&&argc>=3){char owner[512];uint64_t h=qrxnet_height();if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"transferdomain","wallet unavailable");return 0;}QrxDB db;QrxDomainRecord r;if(qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,args[1],&r)){json_error(resp,resp_sz,"transferdomain","domain not found");return 0;}qrxdb_close(&db);if(strcmp(r.owner,owner)||!qrx_domain_is_active(&r,h+1)||!strcmp(owner,args[2])){json_error(resp,resp_sz,"transferdomain","invalid owner transfer");return 0;}char payload[600],txid[129]={0};snprintf(payload,sizeof(payload),"name=%s;sequence=%llu",r.name,(unsigned long long)r.sequence);if(qrxnet_submit("DOMAIN_TRANSFER",args[2],0,payload,txid)){json_error(resp,resp_sz,"transferdomain","transaction submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"transferdomain\",\"result\":{\"name\":\"%s\",\"new_owner\":\"%s\",\"txid\":\"%s\",\"records_cleared_on_chain\":true}}\n",r.name,args[2],txid);return 0;}
    if(!strcmp(args[0],"listdomains")){char owner[512]={0};const char*filter=NULL;if(argc>=2&&strcmp(args[1],"-"))filter=args[1];else if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))==0)filter=owner;QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"listdomains","chain unavailable");return 0;}char items[65536]={0};QrxNetJsonCtx jc={items,sizeof(items),0,qrxnet_height(),1};int n=qrx_net_registry_list(&db,filter,qrxnet_json_record_cb,&jc);qrxdb_close(&db);if(n<0){json_error(resp,resp_sz,"listdomains","registry scan failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listdomains\",\"result\":{\"count\":%d,\"domains\":[%s]}}\n",n,items);return 0;}
    if(!strcmp(args[0],"getdomainhistory")&&argc>=2){QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"getdomainhistory","chain unavailable");return 0;}char items[65536]={0};QrxNetJsonCtx jc={items,sizeof(items),0,qrxnet_height(),1};int n=qrx_net_registry_history(&db,args[1],qrxnet_json_record_cb,&jc);qrxdb_close(&db);if(n<0){json_error(resp,resp_sz,"getdomainhistory","history unavailable");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getdomainhistory\",\"result\":{\"count\":%d,\"records\":[%s]}}\n",n,items);return 0;}
    if(!strcmp(args[0],"getadpolicy")){snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getadpolicy\",\"result\":{\"adblock_default\":true,\"sponsored_only\":true,\"third_party_scripts\":false,\"tracking\":false,\"fingerprinting\":false,\"popups\":false,\"reward_bps\":{\"delivery\":%u,\"publisher\":%u,\"viewer\":%u,\"protocol\":%u,\"development\":%u},\"min_provider_receipts\":%u,\"frequency_epoch_blocks\":%u}}\n",QRX_AD_REWARD_DELIVERY_BPS,QRX_AD_REWARD_PUBLISHER_BPS,QRX_AD_REWARD_VIEWER_BPS,QRX_AD_REWARD_PROTOCOL_BPS,QRX_AD_REWARD_DEVELOPMENT_BPS,QRX_AD_MIN_PROVIDER_RECEIPTS,QRX_AD_FREQUENCY_EPOCH_BLOCKS);return 0;}
    if(!strcmp(args[0],"getadcampaign")&&argc>=2){QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"getadcampaign","chain unavailable");return 0;}QrxAdCampaign c;int rc=qrx_ad_campaign_get(&db,args[1],&c);qrxdb_close(&db);if(rc){json_error(resp,resp_sz,"getadcampaign","campaign not found");return 0;}char tj[1100],cj[120];json_string(tj,sizeof(tj),c.target_url);json_string(cj,sizeof(cj),c.category);char rh[129];qrx_hex_bytes_local(c.creative_root,64,rh);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getadcampaign\",\"result\":{\"campaign_id\":\"%s\",\"advertiser\":\"%s\",\"target_url\":%s,\"category\":%s,\"creative_root_hex\":\"%s\",\"start_height\":%llu,\"end_height\":%llu,\"cost_per_impression_atoms\":%llu,\"total_budget_atoms\":%llu,\"remaining_budget_atoms\":%llu,\"settled_impressions\":%llu,\"status\":%u}}\n",c.campaign_id,c.advertiser,tj,cj,rh,(unsigned long long)c.start_height,(unsigned long long)c.end_height,(unsigned long long)c.cost_per_impression_atoms,(unsigned long long)c.total_budget_atoms,(unsigned long long)c.remaining_budget_atoms,(unsigned long long)c.settled_impressions,c.status);return 0;}
    if(!strcmp(args[0],"getadrewards")){char owner[512];if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"getadrewards","wallet unavailable");return 0;}QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"getadrewards","chain unavailable");return 0;}char k[700],v[128];snprintf(k,sizeof(k),"qrxnet/ad/reward/%s",owner);uint64_t atoms=0;if(qrxdb_get(&db,k,v,sizeof(v))==0)atoms=strtoull(v,NULL,10);qrxdb_close(&db);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getadrewards\",\"result\":{\"address\":\"%s\",\"claimable_atoms\":%llu}}\n",owner,(unsigned long long)atoms);return 0;}
    if(!strcmp(args[0],"createadcampaign")&&argc>=8){char owner[512];if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"createadcampaign","wallet unavailable");return 0;}uint64_t start=strtoull(args[4],NULL,10),end=strtoull(args[5],NULL,10),cost=strtoull(args[6],NULL,10),budget=strtoull(args[7],NULL,10);const char*cat=argc>=9?args[8]:"general";if(strlen(args[3])!=128||!start||end<=start||cost<QRX_AD_MIN_IMPRESSION_ATOMS||budget<cost){json_error(resp,resp_sz,"createadcampaign","invalid campaign parameters");return 0;}char payload[2200],txid[129]={0};snprintf(payload,sizeof(payload),"campaign_id=%s;target_url=%s;category=%s;creative_root_hex=%s;start_height=%llu;end_height=%llu;cost_per_impression_atoms=%llu",args[1],args[2],cat,args[3],(unsigned long long)start,(unsigned long long)end,(unsigned long long)cost);if(qrxnet_submit("AD_CAMPAIGN_CREATE",owner,budget,payload,txid)){json_error(resp,resp_sz,"createadcampaign","transaction submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"createadcampaign\",\"result\":{\"campaign_id\":\"%s\",\"txid\":\"%s\",\"budget_atoms\":%llu}}\n",args[1],txid,(unsigned long long)budget);return 0;}
    if(!strcmp(args[0],"claimadrewards")){char owner[512],txid[129]={0};if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))||qrxnet_submit("AD_REWARD_CLAIM",owner,0,"-",txid)){json_error(resp,resp_sz,"claimadrewards","no claimable reward or submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"claimadrewards\",\"result\":{\"txid\":\"%s\"}}\n",txid);return 0;}
    if(!strcmp(args[0],"prepareqrxsitehex")&&argc>=3){
        char webroot[PATH_MAX];if(qrx_hex_decode_text(args[2],webroot,sizeof(webroot))){json_error(resp,resp_sz,"prepareqrxsite","invalid webroot encoding");return 0;}char owner[512];uint64_t h=qrxnet_height();if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"prepareqrxsite","wallet unavailable");return 0;}QrxDB db;QrxDomainRecord r;if(qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,args[1],&r)){json_error(resp,resp_sz,"prepareqrxsite","domain not found");return 0;}qrxdb_close(&db);if(strcmp(r.owner,owner)||!qrx_domain_is_active(&r,h+1)||r.sequence==UINT64_MAX){json_error(resp,resp_sz,"prepareqrxsite","wallet is not active domain owner");return 0;}EVP_PKEY*pub=drive_load_pub("mldsa65_pub.pem"),*priv=drive_load_priv("mldsa65_priv.pem");uint8_t pc[64];if(!pub||!priv||qrx_domain_pubkey_commitment(pub,pc)||CRYPTO_memcmp(pc,r.publishing_key_commitment,64)){EVP_PKEY_free(pub);EVP_PKEY_free(priv);json_error(resp,resp_sz,"prepareqrxsite","wallet ML-DSA publishing key does not match domain commitment");return 0;}EVP_PKEY_free(pub);char catalog[PATH_MAX],journal[PATH_MAX],cas[PATH_MAX];uint64_t ver=r.sequence+1;if(qrxnet_site_paths(r.name,ver,catalog,sizeof(catalog),journal,sizeof(journal),cas,sizeof(cas))){EVP_PKEY_free(priv);json_error(resp,resp_sz,"prepareqrxsite","publisher paths unavailable");return 0;}FILE*e=fopen(journal,"rb");if(e){fclose(e);EVP_PKEY_free(priv);json_error(resp,resp_sz,"prepareqrxsite","version already prepared");return 0;}QrxStorageFs*fs=NULL;if(qrx_storage_fs_open(cas,0,0,&fs)){EVP_PKEY_free(priv);json_error(resp,resp_sz,"prepareqrxsite","site CAS unavailable");return 0;}QrxNetPublishJob j;int rc=qrx_net_publisher_publish_directory(catalog,fs,webroot,r.name,ver,h,priv,&j);qrx_storage_fs_close(fs);EVP_PKEY_free(priv);if(rc){json_error(resp,resp_sz,"prepareqrxsite","directory publish/preparation failed (symlink, unsafe path, duplicate path, key or I/O error)");return 0;}qrxnet_publish_json(resp,resp_sz,"prepareqrxsite",&j);return 0;
    }
    if(!strcmp(args[0],"getqrxsitepublish")&&argc>=3){uint64_t ver=strtoull(args[2],NULL,10);char catalog[PATH_MAX],journal[PATH_MAX],cas[PATH_MAX];if(!ver||qrxnet_site_paths(args[1],ver,catalog,sizeof(catalog),journal,sizeof(journal),cas,sizeof(cas))){json_error(resp,resp_sz,"getqrxsitepublish","invalid site version");return 0;}QrxNetPublishJob j;if(qrx_net_publisher_job_load(journal,&j)){json_error(resp,resp_sz,"getqrxsitepublish","publish job not found");return 0;}EVP_PKEY*pub=drive_load_pub("mldsa65_pub.pem");QrxDrivePreparedUpload prep;if(pub&&qrx_net_publisher_load_prepared(&j,pub,&prep)==0){QrxDB db;if(qrxdb_init(&db,g_cdir)==0){if(j.storage_contract_id[0])qrx_net_publisher_refresh_storage(&db,&j,&prep);qrxdb_close(&db);}qrx_drive_prepared_upload_free(&prep);}EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"getqrxsitepublish",&j);return 0;
    }
    if(!strcmp(args[0],"listqrxsiteversions")&&argc>=2){char catalog[PATH_MAX],journal[PATH_MAX],cas[PATH_MAX];if(qrxnet_site_paths(args[1],1,catalog,sizeof(catalog),journal,sizeof(journal),cas,sizeof(cas))){json_error(resp,resp_sz,"listqrxsiteversions","invalid domain");return 0;}char items[65536]={0};QrxNetVersionJsonCtx vc={items,sizeof(items),0,1};if(qrx_net_publisher_list_versions(catalog,args[1],qrxnet_version_json_cb,&vc)){json_error(resp,resp_sz,"listqrxsiteversions","version catalog unavailable");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"listqrxsiteversions\",\"result\":{\"versions\":[%s]}}\n",items);return 0;}
    if(!strcmp(args[0],"rollbackqrxsite")&&argc>=3){uint64_t target=strtoull(args[2],NULL,10),h=qrxnet_height();char catalog[PATH_MAX],journal[PATH_MAX],cas[PATH_MAX],owner[512];if(!target||qrxnet_site_paths(args[1],target,catalog,sizeof(catalog),journal,sizeof(journal),cas,sizeof(cas))||qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"rollbackqrxsite","invalid parameters");return 0;}QrxNetPublishJob j;if(qrx_net_publisher_job_load(journal,&j)){json_error(resp,resp_sz,"rollbackqrxsite","target version has no local publish journal");return 0;}EVP_PKEY*pub=drive_load_pub("mldsa65_pub.pem");QrxDrivePreparedUpload prep;QrxDB db;QrxDomainRecord r;QrxNetPublishedSite site;if(!pub||qrx_net_publisher_load_prepared(&j,pub,&prep)||qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,args[1],&r)||qrx_net_publisher_load_version(catalog,args[1],target,&site)){EVP_PKEY_free(pub);json_error(resp,resp_sz,"rollbackqrxsite","target verification unavailable");return 0;}uint8_t pc[64];QrxDomainRecord vr=r;memcpy(vr.web_manifest_root,j.manifest_root,64);int bad=strcmp(r.owner,owner)||!qrx_domain_is_active(&r,h+1)||qrx_domain_pubkey_commitment(pub,pc)||CRYPTO_memcmp(pc,r.publishing_key_commitment,64)||qrx_net_site_verify(&site,&vr,pub,h+1)||!j.storage_contract_id[0]||qrx_net_publisher_refresh_storage(&db,&j,&prep)||j.active_shards<j.required_active_shards;qrx_net_published_site_free(&site);qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);if(bad){json_error(resp,resp_sz,"rollbackqrxsite","target is not currently signed/hosted/authorized for rollback");return 0;}char root[129],payload[1800],txid[129]={0};qrx_hex_bytes_local(j.manifest_root,64,root);snprintf(payload,sizeof(payload),"name=%s;sequence=%llu;qub_mode=KEEP;qub_address=-;web_mode=SET;web_manifest_root_hex=%s;publishing_mode=KEEP;publishing_commitment_hex=-",r.name,(unsigned long long)r.sequence,root);if(qrxnet_submit("DOMAIN_UPDATE",owner,0,payload,txid)){json_error(resp,resp_sz,"rollbackqrxsite","rollback transaction submission failed");return 0;}snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"rollbackqrxsite\",\"result\":{\"target_version\":%llu,\"txid\":\"%s\",\"active_shards\":%u}}\n",(unsigned long long)target,txid,j.active_shards);return 0;}
    if(!strcmp(args[0],"advanceqrxsite")&&argc>=3){uint64_t ver=strtoull(args[2],NULL,10),epochs=argc>=4?strtoull(args[3],NULL,10):30,rate=argc>=5?strtoull(args[4],NULL,10):10000,h=qrxnet_height();char catalog[PATH_MAX],journal[PATH_MAX],cas[PATH_MAX];if(!ver||!epochs||!rate||qrxnet_site_paths(args[1],ver,catalog,sizeof(catalog),journal,sizeof(journal),cas,sizeof(cas))){json_error(resp,resp_sz,"advanceqrxsite","invalid parameters");return 0;}QrxNetPublishJob j;if(qrx_net_publisher_job_load(journal,&j)){json_error(resp,resp_sz,"advanceqrxsite","publish job not found");return 0;}char owner[512];if(qrx_get_wallet_address(g_wdir,owner,sizeof(owner))){json_error(resp,resp_sz,"advanceqrxsite","wallet unavailable");return 0;}EVP_PKEY*pub=drive_load_pub("mldsa65_pub.pem");QrxDrivePreparedUpload prep;if(!pub||qrx_net_publisher_load_prepared(&j,pub,&prep)){EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","prepared PUBLIC_SIGNED package failed verification");return 0;}QrxDB db;QrxDomainRecord r;if(qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,j.domain,&r)){qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","domain/chain unavailable");return 0;}uint8_t pc[64];if(strcmp(r.owner,owner)||!qrx_domain_is_active(&r,h+1)||qrx_domain_pubkey_commitment(pub,pc)||CRYPTO_memcmp(pc,r.publishing_key_commitment,64)){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","current domain ownership/publishing key no longer authorizes this publish");return 0;}
        if(j.status==QRX_NET_PUBLISH_STATUS_ACTIVE){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}
        if(j.status==QRX_NET_PUBLISH_STATUS_ACTIVATION_SUBMITTED){if(!CRYPTO_memcmp(r.web_manifest_root,j.manifest_root,64)){j.status=QRX_NET_PUBLISH_STATUS_ACTIVE;qrx_net_publisher_job_save(&j);qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}if(h<=j.activation_height+12){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}j.status=QRX_NET_PUBLISH_STATUS_READY_TO_ACTIVATE;j.activation_txid[0]=0;j.activation_height=0;qrx_net_publisher_job_save(&j);}
        QrxNetHostStep st;if(qrx_net_publisher_host_next_step(&db,owner,&j,&prep,h,epochs,rate,&st)){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","authoritative hosting step unavailable or mismatched");return 0;}if(st.contract_id[0]&&!j.storage_contract_id[0]){snprintf(j.storage_contract_id,sizeof(j.storage_contract_id),"%s",st.contract_id);qrx_net_publisher_job_save(&j);}if(st.kind==QRX_NET_HOST_STEP_CREATE||st.kind==QRX_NET_HOST_STEP_ASSIGN){uint32_t same_shard=(st.kind==QRX_NET_HOST_STEP_ASSIGN&&j.storage_step_shard==st.shard_index);if(j.storage_step_txid[0]&&j.storage_step_kind==(uint32_t)st.kind&&(st.kind==QRX_NET_HOST_STEP_CREATE||same_shard)&&h<=j.storage_step_height+12){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}char txid[129]={0};qrxdb_close(&db);if(qrxnet_submit_host_step(&st,txid)){qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","storage transaction submission failed");return 0;}snprintf(j.storage_step_txid,sizeof(j.storage_step_txid),"%s",txid);j.storage_step_height=h;j.storage_step_kind=(uint32_t)st.kind;j.storage_step_shard=st.shard_index;j.status=QRX_NET_PUBLISH_STATUS_STORING;qrx_net_publisher_job_save(&j);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}
        if(j.storage_step_txid[0]&&(j.storage_step_kind!=(uint32_t)st.kind||(st.kind==QRX_NET_HOST_STEP_ASSIGN&&j.storage_step_shard!=st.shard_index))){j.storage_step_txid[0]=0;j.storage_step_height=0;j.storage_step_kind=0;j.storage_step_shard=0;qrx_net_publisher_job_save(&j);}if(st.kind==QRX_NET_HOST_STEP_READY_UPLOAD&&!j.transfer_id[0]){qrxdb_close(&db);if(drive_runtime_sync_sources_mode(j.storage_contract_id,1)){qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","verified provider discovery for upload unavailable");return 0;}char tid[129]={0};if(qrx_drive_runtime_start_public_signed_upload(g_drive_runtime,j.storage_contract_id,&prep,tid)){qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","PUBLIC_SIGNED provider upload failed to start");return 0;}snprintf(j.transfer_id,sizeof(j.transfer_id),"%s",tid);j.status=QRX_NET_PUBLISH_STATUS_STORING;qrx_net_publisher_job_save(&j);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}
        if(j.storage_contract_id[0]&&qrx_net_publisher_refresh_storage(&db,&j,&prep)){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","storage readiness verification failed");return 0;}if(j.status==QRX_NET_PUBLISH_STATUS_READY_TO_ACTIVATE){if(j.sequence!=r.sequence+1){qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","domain sequence changed; re-prepare site against current owner state");return 0;}char root[129],payload[1800],txid[129]={0};qrx_hex_bytes_local(j.manifest_root,64,root);snprintf(payload,sizeof(payload),"name=%s;sequence=%llu;qub_mode=KEEP;qub_address=-;web_mode=SET;web_manifest_root_hex=%s;publishing_mode=KEEP;publishing_commitment_hex=-",r.name,(unsigned long long)r.sequence,root);qrxdb_close(&db);if(qrxnet_submit("DOMAIN_UPDATE",owner,0,payload,txid)){qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);json_error(resp,resp_sz,"advanceqrxsite","domain activation transaction submission failed");return 0;}snprintf(j.activation_txid,sizeof(j.activation_txid),"%s",txid);j.activation_height=h;j.status=QRX_NET_PUBLISH_STATUS_ACTIVATION_SUBMITTED;qrx_net_publisher_job_save(&j);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;}qrxdb_close(&db);qrx_drive_prepared_upload_free(&prep);EVP_PKEY_free(pub);qrxnet_publish_json(resp,resp_sz,"advanceqrxsite",&j);return 0;
    }
    if(!strcmp(args[0],"getdomain")&&argc>=2){QrxDB db;QrxDomainRecord r;if(qrxdb_init(&db,g_cdir)||qrx_net_registry_get(&db,args[1],&r)){json_error(resp,resp_sz,"getdomain","domain not found");return 0;}qrxdb_close(&db);char njs[600],ojs[600],qjs[600],web[129],pub[129];json_string(njs,sizeof(njs),r.name);json_string(ojs,sizeof(ojs),r.owner);json_string(qjs,sizeof(qjs),r.qub_address);qrx_hex_bytes_local(r.web_manifest_root,64,web);qrx_hex_bytes_local(r.publishing_key_commitment,64,pub);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"getdomain\",\"result\":{\"name\":%s,\"owner\":%s,\"qub_address\":%s,\"created_height\":%llu,\"expiry_height\":%llu,\"sequence\":%llu,\"web_manifest_root_hex\":\"%s\",\"publishing_key_commitment_hex\":\"%s\"}}\n",njs,ojs,qjs,(unsigned long long)r.created_height,(unsigned long long)r.expiry_height,(unsigned long long)r.sequence,web,pub);return 0;}
    if(!strcmp(args[0],"resolvebrowserinputhex")&&argc>=2){char input[QRX_BROWSER_URL_MAX];if(qrx_hex_decode_text(args[1],input,sizeof(input))){json_error(resp,resp_sz,"resolvebrowserinput","invalid input encoding");return 0;}QrxBrowserResolution r;if(qrx_browser_resolve_input(input,&r)){json_error(resp,resp_sz,"resolvebrowserinput","invalid browser input");return 0;}char ujs[2200],njs[600],pjs[1800];json_string(ujs,sizeof(ujs),r.canonical_url);json_string(njs,sizeof(njs),r.qrx_name);json_string(pjs,sizeof(pjs),r.path);const char*route=r.route==QRX_BROWSER_ROUTE_QRX?"QRX":r.route==QRX_BROWSER_ROUTE_WWW?"WWW":"SEARCH";snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"resolvebrowserinput\",\"result\":{\"route\":\"%s\",\"dns_allowed\":%s,\"canonical_url\":%s,\"qrx_name\":%s,\"path\":%s}}\n",route,r.dns_allowed?"true":"false",ujs,njs,pjs);return 0;}
    if(!strcmp(args[0],"fetchqrxsitehex")&&argc>=3){char path[QRX_BROWSER_URL_MAX];if(qrx_hex_decode_text(args[2],path,sizeof(path))){json_error(resp,resp_sz,"fetchqrxsite","invalid path encoding");return 0;}QrxDB db;if(qrxdb_init(&db,g_cdir)){json_error(resp,resp_sz,"fetchqrxsite","chain unavailable");return 0;}drive_discovery_reload(&db);char cache[PATH_MAX];snprintf(cache,sizeof(cache),"%s/qrx-browser-cache",g_ndir);qrx_mkdir_simple(cache);QrxNetBrowserFetchResult br;uint64_t h=qrxnet_height();int rc=qrx_net_browser_fetch(&db,&g_drive_discovery,args[1],path,h,cache,&br);qrxdb_close(&db);if(rc){json_error(resp,resp_sz,"fetchqrxsite","QRX-Net fetch/verification failed or fewer than 10 ACTIVE providers are reachable on cache miss");return 0;}char djs[600],pjs[800],cjs[3000],fjs[3000],cid[300];json_string(djs,sizeof(djs),br.domain);json_string(pjs,sizeof(pjs),br.request_path);json_string(cjs,sizeof(cjs),br.distribution_cache_path);json_string(fjs,sizeof(fjs),br.file_cache_path);json_string(cid,sizeof(cid),br.contract_id);snprintf(resp,resp_sz,"{\"ok\":true,\"method\":\"fetchqrxsite\",\"result\":{\"domain\":%s,\"path\":%s,\"contract_id\":%s,\"manifest_root_hex\":\"%s\",\"site_sequence\":%llu,\"active_sources\":%u,\"from_cache\":%s,\"bytes_received\":%llu,\"distribution_cache_path\":%s,\"file_cache_path\":%s,\"verified\":true,\"dns_allowed\":false}}\n",djs,pjs,cid,br.manifest_root_hex,(unsigned long long)br.site_sequence,br.active_sources,br.from_cache?"true":"false",(unsigned long long)br.bytes_received,cjs,fjs);return 0;}
    json_error(resp, resp_sz, args[0], "unknown command");
    return 0;
}

int main(int argc, char **argv){
    g_start_time = time(NULL);
    const char *network="mainnet", *datadir=NULL, *wallet="default", *listen_arg=NULL; const char *addnodes[64]; int addnode_count=0; const char *rpc_bind_arg=NULL;
    int wallet_passphrase_source_seen=0;
    for(int i=1;i<argc;++i){
        if(!strcmp(argv[i],"--network")&&i+1<argc) network=argv[++i];
        else if(!strcmp(argv[i],"--datadir")&&i+1<argc) datadir=argv[++i];
        else if(!strcmp(argv[i],"--wallet")&&i+1<argc) wallet=argv[++i];
        else if(!strcmp(argv[i],"--listen")&&i+1<argc) listen_arg=argv[++i];
        else if((!strcmp(argv[i],"--addnode") || !strcmp(argv[i],"--seednode"))&&i+1<argc&&addnode_count<64) addnodes[addnode_count++]=argv[++i];
        else if(!strcmp(argv[i],"--rpc-bind")&&i+1<argc) rpc_bind_arg=argv[++i];
        else if(!strcmp(argv[i],"--allow-remote-rpc")) g_allow_remote_rpc=1;
        else if(!strcmp(argv[i],"--rpc-user")&&i+1<argc) snprintf(g_rpc_user,sizeof(g_rpc_user),"%s",argv[++i]);
        else if(!strcmp(argv[i],"--rpc-password")&&i+1<argc) snprintf(g_rpc_password,sizeof(g_rpc_password),"%s",argv[++i]);
        else if(!strcmp(argv[i],"--wallet-passphrase")&&i+1<argc) {
            if(wallet_passphrase_source_seen++){ fprintf(stderr,"Specify only one wallet passphrase source.\n"); return 1; }
            fprintf(stderr,"WARNING: --wallet-passphrase exposes the wallet secret in the process argument list. Prefer --wallet-passphrase-file or --wallet-passphrase-stdin. This value is a wallet unlock passphrase, NOT recovery words.\n");
            snprintf(g_wallet_passphrase,sizeof(g_wallet_passphrase),"%s",argv[++i]);
        }
        else if(!strcmp(argv[i],"--wallet-passphrase-file")&&i+1<argc) { if(wallet_passphrase_source_seen++){ fprintf(stderr,"Specify only one wallet passphrase source.\n"); return 1; } if(load_wallet_passphrase_file(argv[++i])!=0) return 1; }
        else if(!strcmp(argv[i],"--wallet-passphrase-stdin")) { if(wallet_passphrase_source_seen++){ fprintf(stderr,"Specify only one wallet passphrase source.\n"); return 1; } if(load_wallet_passphrase_stdin()!=0) return 1; }
        else if(!strcmp(argv[i],"--no-wallet-passphrase-default")) g_wallet_passphrase_default_disabled = 1;
        else if(!strcmp(argv[i],"--blocktime")&&i+1<argc) { g_blocktime_override_set=1; g_blocktime_seconds=atoi(argv[++i]); if(g_blocktime_seconds<1) g_blocktime_seconds=1; }
        else if(!strcmp(argv[i],"--commission-bps")&&i+1<argc) { g_commission_override_set=1; g_commission_bps=atoll(argv[++i]); if(g_commission_bps<0) g_commission_bps=0; if(g_commission_bps>10000) g_commission_bps=10000; }
        else if(!strcmp(argv[i],"--no-block-producer")) g_block_producer_enabled=0;
        else if(!strcmp(argv[i],"--validator-wallet")&&i+1<argc){
            const char *vn=argv[++i];
            if(g_validator_wallet_count < QRX_MAX_VALIDATOR_FLEET && vn && *vn && !fleet_has_name(vn))
                snprintf(g_validator_wallet_names[g_validator_wallet_count++], sizeof(g_validator_wallet_names[0]), "%s", vn);
        }
        else if(!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")){ usage(); return 0; }
        else { fprintf(stderr,"unknown arg: %s\n",argv[i]); usage(); return 1; }
    }
    snprintf(g_network, sizeof(g_network), "%s", network);
    snprintf(g_primary_wallet, sizeof(g_primary_wallet), "%s", wallet);
    parse_rpc_bind_default(network);
    if(rpc_bind_arg && parse_rpc_bind_arg(rpc_bind_arg)!=0){ fprintf(stderr,"bad --rpc-bind, expected IPv4-host:port\n"); return 1; }
    if(validate_rpc_exposure()!=0) return 1;
    const QrxProfile *profile = qrx_profile_by_name(network);
    if(!profile){ fprintf(stderr,"unknown network profile: %s\n", network); return 1; }
    if(!profile->allow_runtime_overrides && (g_blocktime_override_set || g_commission_override_set)){
        fprintf(stderr,"runtime chain parameter overrides are disabled for network '%s'. Use the profile-coded parameters or regtest.\n", network);
        return 1;
    }
    if(!g_blocktime_override_set) g_blocktime_seconds = profile->block_time_seconds;
    if(!g_commission_override_set) g_commission_bps = profile->default_validator_commission_bps;
    configure_wallet_passphrase(network);
    build_backend_path(argv[0]);
    if(qrx_ensure_node(network,datadir,wallet,listen_arg,addnodes,addnode_count,g_base,sizeof(g_base),g_cdir,sizeof(g_cdir),g_wdir,sizeof(g_wdir),g_ndir,sizeof(g_ndir))!=0){ fprintf(stderr,"qrxd: failed to initialize\n"); return 1; }
    (void)qrx_aura_runtime_bootstrap_startup(argv[0]);
    qrx_storage_discovery_init(&g_drive_discovery);
    {QrxDB ddb;if(qrxdb_init(&ddb,g_cdir)==0){drive_discovery_reload(&ddb);qrxdb_close(&ddb);}}
    char drive_journal_dir[PATH_MAX]; snprintf(drive_journal_dir,sizeof(drive_journal_dir),"%s/drive-transfers",g_ndir);
    if(qrx_drive_runtime_open(g_cdir,drive_journal_dir,&g_drive_runtime)!=0){ fprintf(stderr,"qrxd: failed to initialize Drive transfer runtime\n"); return 1; }
    if(qrx_write_rpc_token()!=0){ fprintf(stderr,"SECURITY: could not create local RPC session token\n"); return 1; }
    snprintf(g_sock, sizeof(g_sock), "http://%s:%d/rpc", g_rpc_bind, g_rpc_port);
    install_signal_handlers();
    if(spawn_node_process()!=0){ fprintf(stderr, "qrxd: failed to start node-run\n"); return 1; }
    MaintCtx ctx = { g_ndir, g_cdir };
#ifdef _WIN32
    qrx_thread_t th = CreateThread(NULL, 0, maint_loop, &ctx, 0, NULL);
    qrx_thread_t prod_th = NULL;
    int prod_started = 0;
    if(g_block_producer_enabled){ prod_th = CreateThread(NULL, 0, producer_loop, &ctx, 0, NULL); prod_started = 1; }
#else
    qrx_thread_t th; pthread_create(&th, NULL, maint_loop, &ctx);
    qrx_thread_t prod_th; int prod_started = 0; if(g_block_producer_enabled){ pthread_create(&prod_th, NULL, producer_loop, &ctx); prod_started = 1; }
#endif


qrx_wsa_init_once();
    qrx_socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    g_rpc_listen_fd = s;
#ifdef _WIN32
    if(s == INVALID_SOCKET){ fprintf(stderr, "rpc socket failed\n"); return 1; }
#else
    if(s < 0){ perror("rpc socket"); return 1; }
#endif
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)g_rpc_port);
    if(inet_pton(AF_INET, g_rpc_bind, &addr.sin_addr) != 1){ fprintf(stderr, "bad rpc bind address: %s\n", g_rpc_bind); return 1; }
    if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0){ fprintf(stderr, "bind rpc failed on %s:%d\n", g_rpc_bind, g_rpc_port); return 1; }
    if(listen(s, 16) != 0){ fprintf(stderr, "listen rpc failed\n"); return 1; }
    printf("qrxd running network=%s datadir=%s node=%s rpc=%s node_pid=%ld blocktime=%d commission_bps=%lld auth=%s overrides=%s validator_fleet=%d\n", g_network, g_base, g_ndir, g_sock, (long)g_node_pid, g_blocktime_seconds, g_commission_bps, (g_rpc_user[0]||g_rpc_password[0]) ? "enabled" : "disabled", profile->allow_runtime_overrides ? "allowed" : "disabled", g_validator_wallet_count);
    while(g_running){
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        qrx_socket_t fd = accept(s, (struct sockaddr*)&peer, &peerlen);
#ifdef _WIN32
        if(fd == INVALID_SOCKET) break;
#else
        if(fd < 0){ if(errno == EINTR) continue; break; }
#endif
        /* Genesis hardening (Finding 3): listener timeouts are not reliably
         * inherited by accepted sockets on every platform. Without an explicit
         * timeout a peer that sends one byte and then stalls blocks this
         * single-threaded RPC loop forever (Slowloris). */
        qrx_rpc_set_socket_timeouts(fd);

        /* Genesis hardening (Finding 2): the legacy plaintext control channel
         * has no authentication whatsoever. Restrict it to loopback peers. */
        int peer_is_loopback = (peer.sin_family == AF_INET) &&
            ((ntohl(peer.sin_addr.s_addr) >> 24) == 127);

        char cmd[196608];
        size_t cmd_off = 0;
        size_t expected_total = 0;
        int oversized_body = 0;
        for(;;){
#ifdef _WIN32
            int n = recv(fd, cmd + cmd_off, (int)(sizeof(cmd)-1-cmd_off), 0);
#else
            ssize_t n = recv(fd, cmd + cmd_off, sizeof(cmd)-1-cmd_off, 0);
#endif
            if(n <= 0) break;
            cmd_off += (size_t)n;
            cmd[cmd_off] = 0;
            if(expected_total == 0 && (strstr(cmd,"POST ")==cmd || strstr(cmd,"OPTIONS ")==cmd || strstr(cmd,"GET ")==cmd)){
                const char *hdr_end = strstr(cmd,"\r\n\r\n");
                size_t hdr_len = 0;
                if(hdr_end) hdr_len = (size_t)(hdr_end-cmd)+4;
                else { hdr_end = strstr(cmd,"\n\n"); if(hdr_end) hdr_len=(size_t)(hdr_end-cmd)+2; }
                if(hdr_len){
                    const char *cl = qrx_strcasestr_local(cmd,"Content-Length:");
                    if(cl && cl < cmd + hdr_len){
                        cl += strlen("Content-Length:");
                        while(*cl==' '||*cl=='\t') cl++;
                        unsigned long long body_len = strtoull(cl,NULL,10);
                        if(body_len > sizeof(cmd)-1-hdr_len){ oversized_body = 1; break; }
                        else expected_total=hdr_len+(size_t)body_len;
                    } else expected_total=hdr_len;
                }
            }
            if(expected_total && cmd_off >= expected_total) break;
            if(cmd_off + 1 >= sizeof(cmd)) break;
            /* Plain-text local control commands have no HTTP length framing. */
            if(expected_total==0 && !(strstr(cmd,"POST ")==cmd || strstr(cmd,"OPTIONS ")==cmd || strstr(cmd,"GET ")==cmd) && strchr(cmd,'\n')) break;
        }
        cmd[cmd_off] = 0;
        char resp[196608];
        int stop_after = 0;
        if(oversized_body) {
            /* Genesis hardening (Finding 2): reject instead of silently
             * truncating an over-long request body. */
            http_response(resp, sizeof(resp), 413,
                          "{\"ok\":false,\"error\":\"request body too large\"}\n", 0);
            write_all(fd, resp, strlen(resp));
#ifdef _WIN32
            closesocket(fd);
#else
            close(fd);
#endif
            continue;
        }
        if(strstr(cmd, "POST ") == cmd || strstr(cmd, "OPTIONS ") == cmd || strstr(cmd, "GET ") == cmd) {
            handle_json_rpc_http(cmd, resp, sizeof(resp));
            if(strstr(cmd, "\"method\"") && strstr(cmd, "\"stop\"")) stop_after = 1;
        } else if(!peer_is_loopback) {
            /* Unauthenticated plaintext control commands must never be served
             * to a remote peer: this path bypasses token and HTTP auth. */
            snprintf(resp, sizeof(resp),
                     "ERR legacy plaintext RPC is loopback-only\n");
        } else if(qrx_rpc_is_mainnet()) {
            /* Disabled entirely on Mainnet; use authenticated HTTP JSON-RPC. */
            snprintf(resp, sizeof(resp),
                     "ERR legacy plaintext RPC is disabled on mainnet; use authenticated HTTP JSON-RPC\n");
        } else {
            stop_after = handle_command(cmd, resp, sizeof(resp));
        }
        write_all(fd, resp, strlen(resp));
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        if(stop_after) break;
    }
    qrx_close_rpc_listener();
    stop_node_process();
#ifdef _WIN32
    g_running = 0;
    if(th){ WaitForSingleObject(th, 2000); CloseHandle(th); }
    if(prod_started && prod_th){ WaitForSingleObject(prod_th, 2000); CloseHandle(prod_th); }
#else
    pthread_cancel(th); pthread_join(th, NULL);
    if(prod_started){ pthread_cancel(prod_th); pthread_join(prod_th, NULL); }
#endif
    qrx_drive_runtime_close(g_drive_runtime); g_drive_runtime=NULL; qrx_storage_discovery_free(&g_drive_discovery);
    return 0;
}

/*
 * P2P runtime options added:
 *   --maxconnections N
 *   --outbound N
 *   --seednode HOST:PORT
 *   --nolisten
 *
 * Default DNS seeds:
 *   seed1.qrxchain.org
 *   seed2.qrxchain.org
 *   seed3.qrxchain.org
 *
 */
