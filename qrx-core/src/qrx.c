
/* === QRX Mainnet Hardening === */
#include "protocol/qrx_protocol_version.h"
#include "protocol/qrx_chainid.h"
#include "protocol/qrx_domain_separation.h"
#include "security/qrx_secure_memory.h"
#include "economics/qrx_economics.h"
#include "genesis/qrx_bootstrap_validators.h"
#include "genesis/qrx_genesis_governance.h"
#include "resource/qrx_resource.h"
#include "resource/qrx_storage_consensus.h"
#include "net/qrx_net_consensus.h"
#include "net/qrx_net_ads.h"
#include "compute/qrx_compute.h"
#include "compute/qrx_pouc_consensus.h"
#include "compute/qrx_pouc_pipeline.h"
#include "compute/qrx_pouc_reorg.h"
#include "compute/qrx_pouc_undo.h"
#include "compute/qrx_aura_fabric_gossip.h"
#include "compute/qrx_compute_provider_identity.h"
#include "storage/qrx_storage_fs.h"
#include "storage/qrx_storage_p2p.h"
#include "storage/qrx_storage_network.h"
#include "storage/qrx_storage_discovery.h"
#include "storage/qrx_storage_activation.h"
#include "storage/qrx_storage_postor_runtime.h"
#include "storage/qrx_storage_repair_runtime.h"
#include "resource/qrx_storage_repair.h"
#include "storage/qrx_drive_crypto.h"

#ifndef QRX_MAX_FUTURE_DRIFT_SECONDS
#define QRX_MAX_FUTURE_DRIFT_SECONDS 300
#endif
/* === End Hardening Section === */

#define _GNU_SOURCE

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
  #include <io.h>
  #include <direct.h>
  #include <process.h>
  #ifndef PATH_MAX
    #define PATH_MAX MAX_PATH
  #endif
  #ifndef F_OK
    #define F_OK 0
  #endif
  #ifndef R_OK
    #define R_OK 4
  #endif
  #ifndef MSG_WAITALL
    #define MSG_WAITALL 0
  #endif
  #define mkdir_qrx(path, mode) _mkdir(path)
  #define access_qrx(path, mode) _access((path), (mode))
  #define unlink_qrx(path) _unlink(path)
  /* Genesis hardening (Finding 7): popen/_popen deliberately not exposed.
     Local chain/wallet paths must never be passed through a shell. */
  #define dup _dup
  #define dup2 _dup2
  #define open _open
  #define strtok_r strtok_s
  #define strcasecmp _stricmp
  #define strncasecmp _strnicmp
  #define strdup _strdup
  typedef SSIZE_T ssize_t;
  typedef int socklen_t;
  static void qrx_net_init_once(void) {
      static int done = 0;
      if (!done) {
          WSADATA wsa;
          WSAStartup(MAKEWORD(2, 2), &wsa);
          done = 1;
      }
  }
  static int qrx_close_socket(int fd) { return closesocket((SOCKET)fd); }
  static int qrx_close_file(int fd) { return _close(fd); }
  static int qrx_set_socket_timeout(int fd, int seconds) {
      DWORD timeout_ms = (DWORD)(seconds * 1000);
      int a = setsockopt((SOCKET)fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
      int b = setsockopt((SOCKET)fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
      return (a == 0 && b == 0) ? 0 : -1;
  }
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <dirent.h>
  #include <unistd.h>
  #define mkdir_qrx(path, mode) mkdir((path), (mode))
  #define access_qrx(path, mode) access((path), (mode))
  #define unlink_qrx(path) unlink(path)
  /* Genesis hardening (Finding 7): popen deliberately not exposed.
     Local chain/wallet paths must never be passed through a shell. */
  static void qrx_net_init_once(void) { }
  static int qrx_close_socket(int fd) { return close(fd); }
  static int qrx_close_file(int fd) { return close(fd); }
  static int qrx_set_socket_timeout(int fd, int seconds) {
      struct timeval tv;
      tv.tv_sec = seconds;
      tv.tv_usec = 0;
      int a = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      int b = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      return (a == 0 && b == 0) ? 0 : -1;
  }
#endif

#include <errno.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include "chain_params.h"
#include "qrxdb.h"
#include "mempool/qrx_mempool_limits.h"
#include "mempool/qrx_velocity_mempool.h"
#include "mempool/qrx_velocity_mvcc.h"
#include "bitcoin/qrx_btc_spv.h"
#include <ctype.h>

#define QRX_MAGIC "5152583036"
#define MEMPOOL_MAX_TXS QRX_MAX_MEMPOOL_TX
#define QRX_VELOCITY_MAX_LANE 65535LL
#define PEER_REP_MIN -100
#define MAX_LINE 16384
#define MAX_TX 65536
#define MAX_MSG 262144
#define MAX_PEERS 128
#define MAX_ITEMS 256
#define RATE_WINDOW_SECS 60
#define RATE_MAX_MSGS 12
#define BAN_THRESHOLD 100
#define SOCKET_IO_TIMEOUT_SECS 5

/* VELOCITY Phase 4: node-run owns the hot in-memory mempool. The append-only
   WAL is the crash-recovery source for proposer subprocesses and restarts. */
static QrxVelocityMempool g_velocity_mempool;
static int g_velocity_mempool_ready = 0;
static QrxStorageFs *g_storage_fs = NULL;
static int g_storage_ready = 0;
static char g_storage_provider_id[129] = {0};
static QrxStorageDiscoveryTable g_storage_discovery;
static int g_storage_discovery_ready = 0;
static char g_storage_discovery_cache_path[1024] = {0};
static QrxAuraPodGossipTable g_aura_pod_gossip;
static QrxAuraModelGossipTable g_aura_model_gossip;
static int g_aura_gossip_ready = 0;
static char g_aura_pod_cache_path[1024] = {0};
static char g_aura_model_cache_path[1024] = {0};
/* Outbound P2P HELLO signing keys are cached for the process lifetime so
 * periodic AURA anti-entropy does not repeatedly ask for the wallet
 * passphrase. The private key is loaded once, remains process-local and is
 * cleansed/freed at node shutdown. */
static EVP_PKEY *g_hello_priv = NULL;
static EVP_PKEY *g_hello_pub = NULL;
static char g_hello_wallet_dir[1024] = {0};

static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addr_len, int seconds) {
#ifdef _WIN32
    u_long nonblocking = 1;
    if (ioctlsocket((SOCKET)fd, FIONBIO, &nonblocking) != 0) return -1;
    int rc = connect((SOCKET)fd, addr, addr_len);
    if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK && WSAGetLastError() != WSAEINPROGRESS) {
        nonblocking = 0; ioctlsocket((SOCKET)fd, FIONBIO, &nonblocking); return -1;
    }
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    int rc = connect(fd, addr, addr_len);
    if (rc != 0 && errno != EINPROGRESS) { fcntl(fd, F_SETFL, flags); return -1; }
#endif
    if (rc != 0) {
        fd_set write_fds; FD_ZERO(&write_fds); FD_SET(fd, &write_fds);
        struct timeval timeout; timeout.tv_sec = seconds; timeout.tv_usec = 0;
#ifdef _WIN32
        rc = select(0, NULL, &write_fds, NULL, &timeout);
#else
        rc = select(fd + 1, NULL, &write_fds, NULL, &timeout);
#endif
        if (rc <= 0) rc = -1;
        else {
            int socket_error = 0; socklen_t error_len = sizeof(socket_error);
            rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&socket_error, &error_len) == 0 && socket_error == 0 ? 0 : -1;
        }
    }
#ifdef _WIN32
    nonblocking = 0;
    if (ioctlsocket((SOCKET)fd, FIONBIO, &nonblocking) != 0) rc = -1;
#else
    if (fcntl(fd, F_SETFL, flags) != 0) rc = -1;
#endif
    return rc;
}


static int connect_to(const char *host, int port);
static int storage_discovery_push_to_peer(const char *node_dir,const char *wire_b64,const char *host,int port);
static int storage_discovery_fanout(const char *node_dir,const char *wire_b64,const char *skip_host);
static int aura_gossip_push_to_peer(const char *node_dir,const char *kind,const char *wire_b64,const char *host,int port);
static int aura_gossip_fanout(const char *node_dir,const char *kind,const char *wire_b64,const char *skip_host);
static int aura_gossip_sync_peer(const char *node_dir,const char *chain_dir,const char *host,int port);
static int aura_gossip_anti_entropy_tick(const char *node_dir,const char *cfg);
static int aura_model_gov_key_lookup(void *ctx,const char *identity,EVP_PKEY **out);
static int aura_model_gov_authorize(void *ctx,const char *publisher_id);
static int aura_compute_provider_key_lookup(void *ctx,const char *provider_id,EVP_PKEY **out);
static int gov_root_lookup(const char *chain,const char *id,char pubhex[65]);
static int build_hello_message(const char *node_dir, char **out_msg);
static int send_framed(int fd, const char *msg);
static char *recv_framed(int fd);
static void state_paths(const char *chain_dir, char *balances, size_t bsz, char *nonces, size_t nsz, char *applied, size_t asz, char *journal, size_t jsz);
static char *cfg_get(const char *text, const char *key);
static long long kv_get_ll_bin(const char *path, const char *key);
static int kv_set_ll_bin(const char *path, const char *key, long long val);
static void journal_append(const char *chain_dir, const char *fmt, ...);
static long long validator_power_total(const char *chain_dir, const char *validator);
static int staking_db_ll_found(const char *chain_dir,const char *key,long long *out);
static long long staking_db_ll(const char *chain_dir,const char *key,long long defv);
static int slash_cmd(const char *chain_dir, const char *validator, long long amount, const char *reason, long long penalty_points);
static int validator_is_tombstoned(const char *chain_dir, const char *validator);
static int validator_is_jailed_now(const char *chain_dir, const char *validator);
static void staking_paths(const char *chain_dir,
                          char *stakes, size_t ssz,
                          char *delegations, size_t dsz,
                          char *delegated_totals, size_t tsz,
                          char *unbonding, size_t ub_sz,
                          char *unbonding_eta, size_t ue_sz,
                          char *undelegations, size_t ud_sz,
                          char *undelegation_eta, size_t ude_sz,
                          char *penalties, size_t psz);
static int verify_block_cmd(const char *chain_dir, const char *block_file);
static int collect_known_users(const char *chain_dir, char users[][385], size_t max_users);
static int velocity_stateless_verify_cb(void *ctx, const char *tx, char *err, size_t err_sz);
static int htlc_create_cmd(const char *chain_dir, const char *wallet_dir, const char *recipient, long long amount, const char *hashlock_hex, long long timelock_seconds, const char *memo);
static int htlc_redeem_cmd(const char *chain_dir, const char *swap_id, const char *secret);
static int htlc_refund_cmd(const char *chain_dir, const char *wallet_dir, const char *swap_id);
static int htlc_get_cmd(const char *chain_dir, const char *swap_id);
static int htlc_list_cmd(const char *chain_dir);
static int shielded_address_cmd(const char *wallet_dir);
static int shield_cmd(const char *chain_dir, const char *wallet_dir, long long amount, const char *shielded_address);
static int shielded_balance_cmd(const char *chain_dir, const char *wallet_dir);
static int shielded_send_cmd(const char *chain_dir, const char *wallet_dir, const char *to_shielded_address, long long amount);
static int unshield_cmd(const char *chain_dir, const char *wallet_dir, const char *to_transparent, long long amount);
static int shielded_history_cmd(const char *chain_dir, const char *wallet_dir);
static int stealth_address_cmd(const char *wallet_dir);
static int stealth_send_cmd(const char *chain_dir, const char *wallet_dir, const char *stealth_address, long long amount, const char *memo);
static int stealth_scan_cmd(const char *chain_dir, const char *wallet_dir);
static int stealth_spend_cmd(const char *chain_dir, const char *wallet_dir, const char *tx_id, const char *to, long long amount);
static int stealth_history_cmd(const char *chain_dir, const char *wallet_dir);
static int privacy_feature_status_cmd(const char *chain_dir);
typedef struct {
    char key[385];
    long long value;
} StateKVRecord;

typedef struct {
    char key[385];
} StateAppliedRecord;

static char *chain_cfg_value(const char *chain_dir, const char *key);
static char *read_file(const char *path, size_t *out_len);
static int kv_load(const char *path, StateKVRecord **out, size_t *count);
static int kv_save(const char *path, const StateKVRecord *arr, size_t count);
static long long kv_get_ll_bin(const char *path, const char *key);
static int kv_set_ll_bin(const char *path, const char *key, long long val);
static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static long long count_regular_files_local(const char *dirpath) {
#ifdef _WIN32
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%s\\*", dirpath);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    long long n = 0;
    do {
        if (fd.cFileName[0] == '.') continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) n++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return n;
#else
    DIR *d = opendir(dirpath);
    if (!d) return 0;
    long long n = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN) n++;
    }
    closedir(d);
    return n;
#endif
}

static long long current_height_from_chain(const char *chain_dir) {
    char bdir[1024];
    snprintf(bdir, sizeof(bdir), "%s/blocks", chain_dir);
    return count_regular_files_local(bdir);
}


/* Phase 7.2.15: consensus height is the finalized-chain height, never the
 * number of proposal files. Multiple competing proposals at one height must
 * not advance the chain. */
typedef struct {
    long long height;
    long long timestamp;
    char block_hash[129];
    char state_root[129];
} QrxFinalizedHead;

static int qrx_parse_finalized_file(const char *path, QrxFinalizedHead *out) {
    char *txt = read_file(path, NULL); if (!txt) return -1;
    char *hs=cfg_get(txt,"height"), *bh=cfg_get(txt,"block_hash"), *ts=cfg_get(txt,"block_timestamp"), *sr=cfg_get(txt,"finalized_state_root");
    int rc=-1;
    if(hs && bh && *bh) {
        memset(out,0,sizeof(*out)); out->height=atoll(hs); out->timestamp=ts?atoll(ts):0;
        snprintf(out->block_hash,sizeof(out->block_hash),"%s",bh);
        if(sr) snprintf(out->state_root,sizeof(out->state_root),"%s",sr);
        rc=0;
    }
    free(txt); if(hs)free(hs); if(bh)free(bh); if(ts)free(ts); if(sr)free(sr); return rc;
}

static int qrx_latest_finalized_head(const char *chain_dir, QrxFinalizedHead *out) {
    memset(out,0,sizeof(*out));
    char dir[1024]; snprintf(dir,sizeof(dir),"%s/consensus/finalized",chain_dir);
    long long best=-1; char bestpath[1200]={0};
#ifdef _WIN32
    char pat[1200]; snprintf(pat,sizeof(pat),"%s\\*.final",dir); WIN32_FIND_DATAA fd; HANDLE h=FindFirstFileA(pat,&fd);
    if(h!=INVALID_HANDLE_VALUE){ do { if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue; long long v=-1; if(sscanf(fd.cFileName,"%lld.final",&v)==1 && v>best){best=v;snprintf(bestpath,sizeof(bestpath),"%s/%s",dir,fd.cFileName);} } while(FindNextFileA(h,&fd)); FindClose(h); }
#else
    DIR *d=opendir(dir); if(d){ struct dirent *de; while((de=readdir(d))){ if(de->d_name[0]=='.')continue; long long v=-1; if(sscanf(de->d_name,"%lld.final",&v)==1 && v>best){best=v;snprintf(bestpath,sizeof(bestpath),"%s/%s",dir,de->d_name);} } closedir(d); }
#endif
    if(best<0) return 1; /* no finalized block yet */
    return qrx_parse_finalized_file(bestpath,out);
}

static int qrx_current_state_root(const char *chain_dir, char out[129]) {
    QrxDB db; if(qrxdb_init(&db,chain_dir)!=0) return -1; int rc=qrxdb_merkle_root_hex(&db,out); qrxdb_close(&db); return rc;
}

static int qrx_expected_parent(const char *chain_dir, long long *next_height, char parent_hash[129], char parent_state_root[129], long long *parent_timestamp) {
    QrxFinalizedHead h; int rc=qrx_latest_finalized_head(chain_dir,&h); if(rc<0)return -1;
    if(rc==1){
        char *gen=chain_cfg_value(chain_dir,"genesis_hash"); if(!gen)return -1;
        *next_height=1; snprintf(parent_hash,129,"%s",gen); free(gen);
        if(qrx_current_state_root(chain_dir,parent_state_root)!=0)return -1;
        if(parent_timestamp)*parent_timestamp=qrx_chain_get_ll_or_default(chain_dir,"genesis_time",0);
        return 0;
    }
    *next_height=h.height+1; snprintf(parent_hash,129,"%s",h.block_hash);
    if(h.state_root[0]) snprintf(parent_state_root,129,"%s",h.state_root); else if(qrx_current_state_root(chain_dir,parent_state_root)!=0)return -1;
    if(parent_timestamp)*parent_timestamp=h.timestamp; return 0;
}

static int qrx_collect_files_suffix(const char *dir, const char *suffix, char files[][1024], int max_files) {
    int n=0; size_t sl=strlen(suffix);
#ifdef _WIN32
    char pat[1200]; snprintf(pat,sizeof(pat),"%s\\*",dir); WIN32_FIND_DATAA fd; HANDLE h=FindFirstFileA(pat,&fd);
    if(h!=INVALID_HANDLE_VALUE){ do { if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)continue; size_t l=strlen(fd.cFileName); if(l>=sl && !strcmp(fd.cFileName+l-sl,suffix) && n<max_files)snprintf(files[n++],1024,"%s/%s",dir,fd.cFileName); }while(FindNextFileA(h,&fd)); FindClose(h); }
#else
    DIR*d=opendir(dir); if(d){struct dirent*de;while((de=readdir(d))){if(de->d_name[0]=='.')continue;size_t l=strlen(de->d_name);if(l>=sl&&!strcmp(de->d_name+l-sl,suffix)&&n<max_files)snprintf(files[n++],1024,"%s/%s",dir,de->d_name);}closedir(d);}
#endif
    return n;
}

static int collect_fork_heights_from_genesis(const char *chain_dir, long long *heights, int max_heights) {
    char gpath[1024];
    snprintf(gpath, sizeof(gpath), "%s/genesis.cfg", chain_dir);
    char *txt = read_file(gpath, NULL);
    if (!txt) return -1;
    int count = 0;
    char *save = NULL;
    char *line = strtok_r(txt, "\n", &save);
    while (line) {
        if (!strncmp(line, "fork.", 5)) {
            long long h = -1;
            if (sscanf(line, "fork.%lld.", &h) == 1 && h >= 0) {
                int exists = 0;
                for (int i = 0; i < count; ++i) if (heights[i] == h) { exists = 1; break; }
                if (!exists && count < max_heights) heights[count++] = h;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(txt);
    return count;
}


/* ---------------------------------------------------------------------------
 * QRX 0.0.9 Genesis hardening - untrusted-input fault barrier.
 *
 * Historically every validation failure in the transaction path called die(),
 * which terminates the process via exit(1). The P2P accept loop dispatches
 * node_handle_client() inline in the daemon process (no fork, no per-connection
 * process), so a single malformed transaction from any unauthenticated peer
 * terminated the whole validator/node. See:
 *   qrx_untrusted_guard_begin() / verify_tx_text_untrusted().
 *
 * The barrier converts a process-fatal die() into a structured error ONLY while
 * a thread is inside an explicitly marked untrusted-input window. Outside that
 * window (CLI commands, local administration, startup) die() keeps its original
 * fatal semantics so that CLI misuse still exits non-zero.
 *
 * The guard state is thread-local: qrx_velocity_parallel_verify() runs
 * validation callbacks on worker threads, and a process-global jmp_buf would be
 * corrupted by concurrent validation.
 * ------------------------------------------------------------------------- */
#if defined(_MSC_VER)
#  define QRX_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#  define QRX_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#  define QRX_THREAD_LOCAL __thread
#else
#  define QRX_THREAD_LOCAL
#endif

#define QRX_UNTRUSTED_REASON_MAX 256

static QRX_THREAD_LOCAL int      g_untrusted_guard_depth = 0;
static QRX_THREAD_LOCAL jmp_buf  g_untrusted_guard_jmp;
static QRX_THREAD_LOCAL char     g_untrusted_guard_reason[QRX_UNTRUSTED_REASON_MAX];

/* Returns 1 while the calling thread is validating untrusted network input. */
static int qrx_untrusted_guard_active(void) { return g_untrusted_guard_depth > 0; }

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    if (g_untrusted_guard_depth > 0) {
        /* Untrusted window: record the reason and unwind to the guard frame
         * instead of terminating the daemon. Never returns. */
        vsnprintf(g_untrusted_guard_reason, sizeof(g_untrusted_guard_reason), fmt, ap);
        va_end(ap);
        g_untrusted_guard_reason[sizeof(g_untrusted_guard_reason)-1] = 0;
        longjmp(g_untrusted_guard_jmp, 1);
    }
    vfprintf(stderr, fmt, ap); va_end(ap); fputc('\n', stderr); exit(1);
}

static long long parse_ll_strict(const char *s, const char *field) {
    if (!s || !*s) die("missing %s", field);
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno == ERANGE || end == s || (end && *end != '\0')) die("invalid %s", field);
    return v;
}

static long long parse_positive_ll_strict(const char *s, const char *field) {
    long long v = parse_ll_strict(s, field);
    if (v <= 0) die("%s must be > 0", field);
    return v;
}

static long long parse_nonnegative_ll_strict(const char *s, const char *field) {
    long long v = parse_ll_strict(s, field);
    if (v < 0) die("%s must be >= 0", field);
    return v;
}

static void checked_add_ll(long long a, long long b, const char *what, long long *out) {
    if (b > 0 && a > LLONG_MAX - b) die("%s overflow", what);
    if (b < 0 && a < LLONG_MIN - b) die("%s underflow", what);
    *out = a + b;
}

static int gov_tx_version_allowed(const char*chain,const char*tx_version);

static void usage(void) {
    puts("qrx 0.0.8.2-capacity-accounting\n"
         "Commands:\n"
         "  keygen <wallet-dir>\n  seed-new <wallet-dir>\n  wallet-info <wallet-dir>\n  wallet-new-address <wallet-dir>\n  listaddresses <wallet-dir>\n  wallet-recover <wallet-dir> <recovery-file>\n  drive-pq-ensure <wallet-dir>\n"
         "  address <wallet-dir>\n  legacy-address <wallet-dir>\n  migrate-address <wallet-dir>\n  state-migrate-address <chain-dir> <old-address> <new-address>\n"
         "  init-chain <chain-dir>\n"
         "  faucet <chain-dir> <address> <amount>\n  getdevaddress <chain-dir>\n"
         "  balance <chain-dir> <address>\n  history <chain-dir> [address] [limit|all] [from-unix] [to-unix-exclusive]\n"
         "  sign <wallet-dir> <chain-dir> <to> <amount> <memo> <tx-file>\n  send-from <wallet-dir> <chain-dir> <source-address> <to> <amount> <memo> [node-dir]\n"
         "  verify <chain-dir> <tx-file>\n"
         "  applytx <chain-dir> <tx-file>\n"
         "  node-init <node-dir> <chain-dir> <wallet-dir> <host> <port>\n"
         "  add-peer <node-dir> <host> <port>\n"
         "  add-seed <node-dir> <host> <port>\n"
         "  set-external <node-dir> <host> <port>\n"
         "  discover-peers <node-dir>\n"
         "  bootstrap <node-dir>\n"
         "  nat-info <node-dir>\n"
         "  peer-top <node-dir> [limit]\n"
         "  node-run <node-dir>\n"
         "  sendtx <node-dir> <tx-file>\n"
         "  propose-block <node-dir> [max_txs]\n  propose-block-as <node-dir> <wallet-dir> [max_txs]\n"
         "  verify-block <chain-dir> <block-file>\n"
         "  peer-status <node-dir>\n"
         "  mempool-status <node-dir>\n"
         "  mempool-prune <node-dir> [max_txs]\n"
         "  velocity-mvcc-execute <node-dir> [max_txs] [workers]\n"
         "  getnonce <chain-dir> <address> [lane]\n"
         "  getnoncelanes <chain-dir> <address>\n"
         "  agent-status <chain-dir> <agent-address>\n  list-agents <chain-dir> [owner-address]\n  create-agent-register-raw-tx <chain-dir> <owner> <agent> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> <owner_ed_pub_hex> <owner_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-agent-update-raw-tx <chain-dir> <owner> <agent> <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> <owner_ed_pub_hex> <owner_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-agent-revoke-raw-tx <chain-dir> <owner> <agent> <owner_ed_pub_hex> <owner_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  order-status <chain-dir> <order-id>\n  list-orders <chain-dir> [owner-or-agent] [status]\n  trade-status <chain-dir> <trade-id>\n  list-trades <chain-dir> [market] [limit]\n  orderbook <chain-dir> <market> [depth]\n  asset-balance <chain-dir> <asset> <address>\n  list-assets <chain-dir>\n  asset-register <chain-dir> <asset> <name>  (dev/regtest manual-mint networks only)\n  asset-credit <chain-dir> <asset> <address> <amount>  (dev/regtest only)\n  agent-limits <chain-dir> <agent-address>\n  trading-info <chain-dir>\n  create-order-raw-tx <chain-dir> <agent> <owner> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-external-order-raw-tx <chain-dir> <agent> <owner> <venue> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-order-cancel-raw-tx <chain-dir> <agent> <owner> <order_id> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-order-replace-raw-tx <chain-dir> <agent> <owner> <order_id> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  velocity-info <chain-dir>\n  resource-info <chain-dir> [height]\n  storage-split <contract-atoms>\n  storage-fs-init <storage-root> <max-usage-bytes> <min-free-space-bytes>\n  storage-fs-info <storage-root>\n  storage-fs-put <storage-root> <source-file>\n  storage-fs-get <storage-root> <object-id> <destination-file>\n  storage-fs-delete <storage-root> <object-id>\n  storage-fs-recover <storage-root>\n"
         "  create-velocity-raw-tx <chain-dir> <from> <to> <amount> <ed_pub_hex> <mldsa_pub_b64> <tx_type> <lane_id> <expiry_height> <payload> [fee] [nonce]\n"
         "  decay-bans <node-dir> [points]\n  state-check <chain-dir>\n  snapshot-state <chain-dir> [label]\n  reindex-state <chain-dir>\n  stake <chain-dir> <wallet-dir> <amount>\n  unstake <chain-dir> <wallet-dir> <amount> [unbonding-secs]\n  claim-unbonded <chain-dir> <wallet-dir>\n  delegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount>\n  undelegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount> [unbonding-secs]\n  claim-undelegated <chain-dir> <delegator-wallet-dir> <validator-address>\n  staking-status <chain-dir> [address]\n  validator-set <chain-dir>\n  reward-epoch <chain-dir> <reward-amount> [validator-commission-bps]\n  bootstrap-validator-status <chain-dir> <validator-address>\n  slash <chain-dir> <validator-address> <amount> <reason>\n");
    puts("Phase 4F.2: create-arbitrage-hedge-raw-tx <chain-dir> <agent> <owner> <matched-crosschain-buy-order> <arbitrage-id> <quantity-sats> <limit-price-atoms> <order-expiry> <agent-ed-pub> <agent-mldsa-pub> <lane> <tx-expiry> [fee] [nonce]");
    puts("QRX governance: governance-keygen <out-dir> <DEV_GOV_N> | governance-vault-init <vault-dir> | governance-vault-add-online <vault-dir> <gov-key-dir> | governance-vault-add-offline <vault-dir> <governance.pub> | governance-vault-status <vault-dir> | governance-vault-sign <vault-dir> <key-id> <proposal-file> <signature-file> | governance-vault-backup-create <backup-vault-dir> <key1> <key2> <key3> <key4> <key5> | governance-vault-restore-online <backup-vault-dir> <key-id> <operational-vault-dir> | governance-genesis-init <chain-dir> <threshold> <pubdesc...> | governance-protocol-propose <proposal-file> <protocol-version> <activation-height> <minimum-tx-version> <minimum-privacy-version> <feature-flags> | governance-sign <gov-key-dir> <proposal-file> <signature-file> | governance-apply <chain-dir> <proposal-file> <signature-files...> | protocol-info <chain-dir> [height]");
    puts("QRX 0.0.7.7 Phase 7.2 KYC: kyc-provider-keygen <out-dir> <provider-id> | kyc-provider-propose-v2 <chain-dir> <proposal-file> <KYC_PROVIDER_ADD|KYC_PROVIDER_DISABLE|KYC_PROVIDER_ROTATE_KEY|KYC_PROVIDER_UPDATE> <provider-id> <authority-qrx-address|-> <provider-public-key-hex|-> <capabilities|-> <activation-height> | kyc-provider-info <chain-dir> <provider-id>");
    puts("QRX 0.0.7.6 assets: signed consensus tx types ASSET_ISSUE, ASSET_REISSUE, ASSET_TRANSFER, ASSET_TAG, ASSET_UNTAG, ASSET_FREEZE_ADDRESS, ASSET_UNFREEZE_ADDRESS, ASSET_GLOBAL_FREEZE, ASSET_GLOBAL_UNFREEZE, ASSET_BROADCAST, ASSET_REVOKE, ASSET_FORCED_TRANSFER; create with create-velocity-raw-tx then signrawtransactionwithwallet + sendtx/applytx");
    puts("QRX 0.0.8.2: DRIVE_V1 is a post-Genesis mandatory protocol-9 upgrade. Mainnet has no hardcoded Storage activation height until the threshold-signed upgrade is scheduled; planned target is around 2026-11-30. Filesystem is the reference backend; SeaweedFS is optional only.");
    puts("QRX Generals 0.0.7.7 Phase 3: deterministic world, starter units, commit/reveal movement orders, seasons/energy/clans/treasury. Wallet = account; state is authoritative QRXDB/WAL consensus state.");
}

static int mkdir_p(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len-1] == '/' || tmp[len-1] == '\\') tmp[len-1] = 0;
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            char old = *p;
            *p = 0;
            mkdir_qrx(tmp, 0700);
            *p = old;
        }
    }
    return mkdir_qrx(tmp, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *buf = malloc((size_t)n + 1); if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
    fclose(f); buf[n] = 0; if (out_len) *out_len = (size_t)n; return buf;
}
static int write_file(const char *path, const void *buf, size_t len) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    size_t w = fwrite(buf, 1, len, f); fclose(f); return w == len ? 0 : -1;
}
static int write_text(const char *path, const char *s) { return write_file(path, s, strlen(s)); }
static int append_text(const char *path, const char *s) {
    FILE *f = fopen(path, "ab"); if (!f) return -1; size_t n = strlen(s); size_t w = fwrite(s, 1, n, f); fclose(f); return w == n ? 0 : -1;
}
static void sha256_hex(const unsigned char *buf, size_t len, char out[65]) {
    unsigned char md[32]; SHA256(buf, len, md); for (int i=0;i<32;i++) sprintf(out + i*2, "%02x", md[i]); out[64]=0;
}
static void sha3_512_hex(const unsigned char *buf, size_t len, char out[129]) {
    unsigned char md[64]; unsigned int mdlen = 0;
    if (EVP_Digest(buf, len, md, &mdlen, EVP_sha3_512(), NULL) != 1 || mdlen != 64) die("sha3-512 failed");
    for (int i=0;i<64;i++) sprintf(out + i*2, "%02x", md[i]);
    out[128]=0;
}
static void hash_primary_hex(const unsigned char *buf, size_t len, char out[129]) { sha3_512_hex(buf, len, out); }
static void hash_legacy_hex(const unsigned char *buf, size_t len, char out[65]) { sha256_hex(buf, len, out); }
static void derive_recovery_key(const char *mnemonic, unsigned char key[32]) {
    unsigned char full[64]; unsigned int mdlen = 0;
    if (EVP_Digest(mnemonic, strlen(mnemonic), full, &mdlen, EVP_sha3_512(), NULL) != 1 || mdlen < 32) die("recovery kdf failed");
    memcpy(key, full, 32);
    OPENSSL_cleanse(full, sizeof(full));
}
static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_sz, size_t *out_len) {
    size_t n = strlen(hex); if (n % 2) return -1; size_t m = n / 2; if (m > out_sz) return -1;
    for (size_t i=0;i<m;i++) { unsigned int v; if (sscanf(hex + i*2, "%2x", &v) != 1) return -1; out[i]=(unsigned char)v; }
    if (out_len) *out_len = m; return 0;
}
static char *bytes_to_hex(const unsigned char *buf, size_t len) {
    char *s = malloc(len*2 + 1); if (!s) return NULL; for (size_t i=0;i<len;i++) sprintf(s+i*2, "%02x", buf[i]); s[len*2]=0; return s;
}

static char *base64_encode(const unsigned char *buf, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64()); BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new(BIO_s_mem()); b64 = BIO_push(b64, mem);
    BIO_write(b64, buf, (int)len); BIO_flush(b64);
    BUF_MEM *bptr; BIO_get_mem_ptr(b64, &bptr);
    char *out = malloc(bptr->length + 1); memcpy(out, bptr->data, bptr->length); out[bptr->length] = 0;
    BIO_free_all(b64); return out;
}
static unsigned char *base64_decode(const char *s, size_t *out_len) {
    BIO *b64 = BIO_new(BIO_f_base64()); BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *mem = BIO_new_mem_buf(s, -1); mem = BIO_push(b64, mem);
    size_t inlen = strlen(s); unsigned char *out = malloc(inlen);
    int n = BIO_read(mem, out, (int)inlen); BIO_free_all(mem); if (n < 0) { free(out); return NULL; }
    *out_len = (size_t)n; return out;
}

static int get_passphrase(char *buf, size_t bufsz, const char *prompt) {
    const char *env = getenv("QRX_PASSPHRASE");
    /* Presence of QRX_PASSPHRASE is authoritative even when it is empty.
       Legacy 0.0.6 PKCS#8 wallets legitimately use an empty passphrase. */
    if (env) { snprintf(buf, bufsz, "%s", env); return 0; }
#if defined(__unix__) || defined(__APPLE__)
    char *p = getpass(prompt);
    if (!p) return -1;
    snprintf(buf, bufsz, "%s", p);
    return 0;
#else
    fprintf(stderr, "%s", prompt);
    if (!fgets(buf, (int)bufsz, stdin)) return -1;
    buf[strcspn(buf, "\r\n")] = 0;
    return 0;
#endif
}

static char *cfg_get(const char *text, const char *key) {
    size_t klen = strlen(key);
    const char *p = text;
    while (p && *p) {
        const char *e = strchr(p, '\n'); size_t len = e ? (size_t)(e-p) : strlen(p);
        if (len > klen + 1 && !strncmp(p, key, klen) && p[klen] == '=') {
            char *out = malloc(len - klen); memcpy(out, p+klen+1, len-klen-1); out[len-klen-1]=0; return out;
        }
        p = e ? e+1 : NULL;
    }
    return NULL;
}

static EVP_PKEY *load_priv_pem(const char *path, const char *pass) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    EVP_PKEY *p = PEM_read_PrivateKey(f, NULL, NULL, (void*)pass); fclose(f); return p;
}
static EVP_PKEY *load_pub_pem(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    EVP_PKEY *p = PEM_read_PUBKEY(f, NULL, NULL, NULL); fclose(f); return p;
}
static int save_priv_pem(const char *path, EVP_PKEY *pkey, const char *pass) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    int ok = PEM_write_PKCS8PrivateKey(f, pkey, EVP_aes_256_cbc(), (char*)pass, (int)strlen(pass), NULL, NULL);
    fclose(f); return ok ? 0 : -1;
}
static int save_pub_pem(const char *path, EVP_PKEY *pkey) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    int ok = PEM_write_PUBKEY(f, pkey); fclose(f); return ok ? 0 : -1;
}
static char *pubkey_to_pem_string(EVP_PKEY *pkey) {
    BIO *mem = BIO_new(BIO_s_mem()); if (!PEM_write_bio_PUBKEY(mem, pkey)) { BIO_free(mem); return NULL; }
    BUF_MEM *b; BIO_get_mem_ptr(mem, &b); char *s = malloc(b->length + 1); memcpy(s, b->data, b->length); s[b->length]=0; BIO_free(mem); return s;
}
static EVP_PKEY *pubkey_from_pem_string(const char *pem) {
    BIO *mem = BIO_new_mem_buf(pem, -1); EVP_PKEY *p = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL); BIO_free(mem); return p;
}
static int ed25519_raw_pub(EVP_PKEY *pkey, unsigned char out[32]) {
    size_t len = 32; return EVP_PKEY_get_raw_public_key(pkey, out, &len) == 1 && len == 32 ? 0 : -1;
}
static int ed25519_raw_priv(EVP_PKEY *pkey, unsigned char out[32]) {
    size_t len = 32; return EVP_PKEY_get_raw_private_key(pkey, out, &len) == 1 && len == 32 ? 0 : -1;
}
static int sign_oneshot(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, unsigned char **sig, size_t *siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); if (!ctx) return -1;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, priv) != 1) { EVP_MD_CTX_free(ctx); return -1; }
    if (EVP_DigestSign(ctx, NULL, siglen, msg, msglen) != 1) { EVP_MD_CTX_free(ctx); return -1; }
    *sig = malloc(*siglen); if (!*sig) { EVP_MD_CTX_free(ctx); return -1; }
    if (EVP_DigestSign(ctx, *sig, siglen, msg, msglen) != 1) { free(*sig); EVP_MD_CTX_free(ctx); return -1; }
    EVP_MD_CTX_free(ctx); return 0;
}
static int verify_oneshot(EVP_PKEY *pub, const unsigned char *msg, size_t msglen, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); if (!ctx) return -1;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) != 1) { EVP_MD_CTX_free(ctx); return -1; }
    int ok = EVP_DigestVerify(ctx, sig, siglen, msg, msglen); EVP_MD_CTX_free(ctx); return ok == 1 ? 0 : -1;
}

static char *wallet_address_legacy_from_pub(EVP_PKEY *ed_pub) {
    unsigned char raw[32]; if (ed25519_raw_pub(ed_pub, raw) != 0) return NULL;
    char hex[65]; hash_legacy_hex(raw, sizeof(raw), hex); return strdup(hex);
}

static char *wallet_address_from_pub(EVP_PKEY *ed_pub) {
    unsigned char raw[32]; if (ed25519_raw_pub(ed_pub, raw) != 0) return NULL;
    char full[129], chk[129];
    hash_primary_hex(raw, sizeof(raw), full);
    hash_primary_hex((unsigned char*)full, strlen(full), chk);
    char *addr = malloc(125);
    if (!addr) return NULL;
    snprintf(addr, 125, "qrx1%.112s%.8s", full, chk);
    return addr;
}

static int address_matches_pub(EVP_PKEY *ed_pub, const char *addr) {
    char *modern = wallet_address_from_pub(ed_pub);
    char *legacy = wallet_address_legacy_from_pub(ed_pub);
    int ok = (modern && strcmp(modern, addr) == 0) || (legacy && strcmp(legacy, addr) == 0);
    free(modern); free(legacy);
    return ok ? 0 : -1;
}

static int ensure_wallet_dir(const char *dir) {
    return mkdir_p(dir);
}
static char *wallet_address(const char *dir);

static const char *mn_pre[16] = {"ba","be","bi","bo","bu","da","de","di","do","du","ka","ke","ki","ko","ku","za"};
static const char *mn_suf[16] = {"lan","mer","ton","ris","vek","nor","sil","pan","dor","ket","mir","fal","zen","vor","lin","qu"};

static const char *word_from_byte(unsigned char b) {
    static char words[4][16];
    static int idx = 0;
    idx = (idx + 1) & 3;
    snprintf(words[idx], sizeof(words[idx]), "%s%s", mn_pre[(b >> 4) & 0x0f], mn_suf[b & 0x0f]);
    return words[idx];
}
static int byte_from_word(const char *w, unsigned char *out) {
    for (int hi=0; hi<16; ++hi) {
        for (int lo=0; lo<16; ++lo) {
            char cand[16];
            snprintf(cand, sizeof(cand), "%s%s", mn_pre[hi], mn_suf[lo]);
            if (strcmp(cand, w) == 0) { *out = (unsigned char)((hi << 4) | lo); return 0; }
        }
    }
    return -1;
}
static char *mnemonic_from_entropy(const unsigned char *ent, size_t entlen) {
    size_t cap = entlen * 16 + 1;
    char *out = malloc(cap); if (!out) return NULL;
    out[0] = 0;
    for (size_t i=0; i<entlen; ++i) {
        if (i) strncat(out, " ", cap - strlen(out) - 1);
        strncat(out, word_from_byte(ent[i]), cap - strlen(out) - 1);
    }
    return out;
}
static int entropy_from_mnemonic(const char *mnemonic, unsigned char *out, size_t outsz, size_t *outlen) {
    char *dup = strdup(mnemonic); if (!dup) return -1;
    size_t n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(dup, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
        if (n >= outsz) { free(dup); return -1; }
        if (byte_from_word(tok, &out[n]) != 0) { free(dup); return -1; }
        n++;
    }
    free(dup);
    if (outlen) *outlen = n;
    return 0;
}
static int get_mnemonic(char *buf, size_t bufsz, const char *prompt) {
    const char *env = getenv("QRX_MNEMONIC");
    if (env && *env) { snprintf(buf, bufsz, "%s", env); return 0; }
    fprintf(stderr, "%s", prompt);
    if (!fgets(buf, (int)bufsz, stdin)) return -1;
    buf[strcspn(buf, "\r\n")] = 0;
    return 0;
}
static int aes256gcm_encrypt(const unsigned char *key, const unsigned char *pt, size_t ptlen,
                             unsigned char **out_ct, size_t *out_ctlen,
                             unsigned char iv[12], unsigned char tag[16]) {
    if (RAND_bytes(iv, 12) != 1) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return -1;
    int ok = 0, len = 0, total = 0;
    *out_ct = malloc(ptlen + 16); if (!*out_ct) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, *out_ct, &len, pt, (int)ptlen) != 1) goto done;
    total += len;
    if (EVP_EncryptFinal_ex(ctx, *out_ct + total, &len) != 1) goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto done;
    *out_ctlen = (size_t)total; ok = 1;
  done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(*out_ct); *out_ct = NULL; return -1; }
    return 0;
}
static int aes256gcm_decrypt(const unsigned char *key, const unsigned char *ct, size_t ctlen,
                             const unsigned char iv[12], const unsigned char tag[16],
                             unsigned char **out_pt, size_t *out_ptlen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return -1;
    int ok = 0, len = 0, total = 0;
    *out_pt = malloc(ctlen + 1); if (!*out_pt) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, *out_pt, &len, ct, (int)ctlen) != 1) goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, *out_pt + total, &len) != 1) goto done;
    total += len;
    (*out_pt)[total] = 0; *out_ptlen = (size_t)total; ok = 1;
  done:
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(*out_pt); *out_pt = NULL; return -1; }
    return 0;
}
static char *privkey_to_unencrypted_pem_string(EVP_PKEY *pkey) {
    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem) return NULL;
    if (!PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL)) { BIO_free(mem); return NULL; }
    BUF_MEM *b; BIO_get_mem_ptr(mem, &b);
    char *s = malloc(b->length + 1); if (!s) { BIO_free(mem); return NULL; }
    memcpy(s, b->data, b->length); s[b->length] = 0; BIO_free(mem); return s;
}
static EVP_PKEY *privkey_from_pem_string(const char *pem) {
    BIO *mem = BIO_new_mem_buf(pem, -1); if (!mem) return NULL;
    EVP_PKEY *p = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL); BIO_free(mem); return p;
}
static int append_dyn(char **buf, size_t *len, size_t *cap, const char *text);
static int derive_address_recovery_key(EVP_PKEY *ed_priv, unsigned char out[32]);

static int drive_pq_key_paths(const char *dir,char *priv,size_t psz,char *pub,size_t usz){
    if(!dir||!priv||!pub)return -1;
    snprintf(priv,psz,"%s/drive_mlkem768_priv.pem",dir);
    snprintf(pub,usz,"%s/drive_mlkem768_pub.pem",dir);
    return 0;
}
static int drive_pq_storage_password(EVP_PKEY *ed,char out[65]){unsigned char k[32];if(derive_address_recovery_key(ed,k))return -1;static const char*x="0123456789abcdef";for(int i=0;i<32;i++){out[i*2]=x[k[i]>>4];out[i*2+1]=x[k[i]&15];}out[64]=0;OPENSSL_cleanse(k,32);return 0;}
static int drive_pq_ensure_keys(const char *dir,const char *passphrase,EVP_PKEY **pub_out){
    char priv[1024],pub[1024],edp[1024],dp[65];drive_pq_key_paths(dir,priv,sizeof(priv),pub,sizeof(pub));snprintf(edp,sizeof(edp),"%s/ed25519_priv.pem",dir);EVP_PKEY*ed=load_priv_pem(edp,passphrase);if(!ed||drive_pq_storage_password(ed,dp)){EVP_PKEY_free(ed);return -1;}EVP_PKEY_free(ed);
    if(access_qrx(priv,F_OK)==0&&access_qrx(pub,F_OK)==0){EVP_PKEY*k=load_priv_pem(priv,dp),*u=load_pub_pem(pub);OPENSSL_cleanse(dp,sizeof(dp));if(!k||!u){EVP_PKEY_free(k);EVP_PKEY_free(u);return -1;}const char*n=EVP_PKEY_get0_type_name(k);if(!n||(strcmp(n,"ML-KEM-768")&&strcmp(n,"MLKEM768"))){EVP_PKEY_free(k);EVP_PKEY_free(u);return -1;}EVP_PKEY_free(k);if(pub_out)*pub_out=u;else EVP_PKEY_free(u);return 0;}
    EVP_PKEY_CTX*ctx=EVP_PKEY_CTX_new_from_name(NULL,"ML-KEM-768",NULL);EVP_PKEY*k=NULL;if(!ctx||EVP_PKEY_keygen_init(ctx)!=1||EVP_PKEY_generate(ctx,&k)!=1){EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(k);OPENSSL_cleanse(dp,sizeof(dp));return -1;}EVP_PKEY_CTX_free(ctx);int bad=save_priv_pem(priv,k,dp)||save_pub_pem(pub,k);OPENSSL_cleanse(dp,sizeof(dp));if(bad){EVP_PKEY_free(k);return -1;}if(pub_out){*pub_out=load_pub_pem(pub);if(!*pub_out){EVP_PKEY_free(k);return -1;}}EVP_PKEY_free(k);return 0;
}
static char *strip_drive_pq_recovery_extension(const char *rf){
    if(!rf)return NULL; size_t cap=strlen(rf)+64,len=0; char*out=calloc(1,cap); if(!out)return NULL;
    const char*p=rf; while(*p){const char*e=strchr(p,'\n');size_t l=e?(size_t)(e-p)+1:strlen(p);
        if(strncmp(p,"drive_pq_ext_format=",20)&&strncmp(p,"drive_pq_ext_iv_b64=",20)&&strncmp(p,"drive_pq_ext_tag_b64=",21)&&strncmp(p,"drive_pq_ext_ct_b64=",20)){
            char*line=malloc(l+1);if(!line){free(out);return NULL;}memcpy(line,p,l);line[l]=0;if(append_dyn(&out,&len,&cap,line)){free(line);free(out);return NULL;}free(line);
        } if(!e)break;p=e+1;
    } return out;
}
static int update_recovery_drive_pq_extension(const char *dir,const char *passphrase){
    char seed[1024],edp[1024],kp[1024],ku[1024];snprintf(seed,sizeof(seed),"%s/recovery.qrxseed",dir);if(access_qrx(seed,F_OK)!=0)return 0;
    snprintf(edp,sizeof(edp),"%s/ed25519_priv.pem",dir);EVP_PKEY*ed=load_priv_pem(edp,passphrase);if(!ed)return -1;
    if(drive_pq_ensure_keys(dir,passphrase,NULL)){EVP_PKEY_free(ed);return -1;}drive_pq_key_paths(dir,kp,sizeof(kp),ku,sizeof(ku));char dp[65];if(drive_pq_storage_password(ed,dp)){EVP_PKEY_free(ed);return -1;}EVP_PKEY*kem=load_priv_pem(kp,dp);OPENSSL_cleanse(dp,sizeof(dp));if(!kem){EVP_PKEY_free(ed);return -1;}
    unsigned char key[32];if(derive_address_recovery_key(ed,key)){EVP_PKEY_free(ed);EVP_PKEY_free(kem);return -1;}EVP_PKEY_free(ed);
    char*pem=privkey_to_unencrypted_pem_string(kem);EVP_PKEY_free(kem);if(!pem){OPENSSL_cleanse(key,32);return -1;}
    unsigned char*ct=NULL,iv[12],tag[16];size_t cn=0;if(aes256gcm_encrypt(key,(unsigned char*)pem,strlen(pem),&ct,&cn,iv,tag)){OPENSSL_cleanse(key,32);OPENSSL_cleanse(pem,strlen(pem));free(pem);return -1;}
    char*ivb=base64_encode(iv,12),*tb=base64_encode(tag,16),*cb=base64_encode(ct,cn),*rf=read_file(seed,NULL),*base=strip_drive_pq_recovery_extension(rf);int rc=-1;
    if(ivb&&tb&&cb&&base){size_t need=strlen(base)+strlen(ivb)+strlen(tb)+strlen(cb)+256;char*out=malloc(need);if(out){snprintf(out,need,"%sdrive_pq_ext_format=qrx-drive-pq-recovery-v1\ndrive_pq_ext_iv_b64=%s\ndrive_pq_ext_tag_b64=%s\ndrive_pq_ext_ct_b64=%s\n",base,ivb,tb,cb);rc=write_text(seed,out);free(out);}}
    OPENSSL_cleanse(key,32);OPENSSL_cleanse(pem,strlen(pem));OPENSSL_cleanse(ct,cn);free(pem);free(ct);free(ivb);free(tb);free(cb);free(rf);free(base);return rc;
}
static int restore_recovery_drive_pq_extension(const char *dir,const char *rf,EVP_PKEY *ed,const char *new_passphrase){
    char*ivb=cfg_get(rf,"drive_pq_ext_iv_b64"),*tb=cfg_get(rf,"drive_pq_ext_tag_b64"),*cb=cfg_get(rf,"drive_pq_ext_ct_b64");if(!ivb&&!tb&&!cb)return 0;if(!ivb||!tb||!cb)return -1;
    unsigned char key[32];if(derive_address_recovery_key(ed,key)){free(ivb);free(tb);free(cb);return -1;}size_t in=0,tn=0,cn=0;unsigned char*iv=base64_decode(ivb,&in),*tag=base64_decode(tb,&tn),*ct=base64_decode(cb,&cn),*pt=NULL;size_t pn=0;int rc=-1;
    if(iv&&tag&&ct&&in==12&&tn==16&&!aes256gcm_decrypt(key,ct,cn,iv,tag,&pt,&pn)){EVP_PKEY*kem=privkey_from_pem_string((char*)pt);if(kem){const char*n=EVP_PKEY_get0_type_name(kem);if(n&&(!strcmp(n,"ML-KEM-768")||!strcmp(n,"MLKEM768"))){char kp[1024],ku[1024],dp[65];drive_pq_key_paths(dir,kp,sizeof(kp),ku,sizeof(ku));if(!drive_pq_storage_password(ed,dp)){if(!save_priv_pem(kp,kem,dp)&&!save_pub_pem(ku,kem))rc=0;OPENSSL_cleanse(dp,sizeof(dp));}}EVP_PKEY_free(kem);}}
    OPENSSL_cleanse(key,32);if(pt){OPENSSL_cleanse(pt,pn);free(pt);}free(iv);free(tag);free(ct);free(ivb);free(tb);free(cb);return rc;
}

static int write_wallet_manifest(const char *dir, const char *address, int has_recovery) {
    char path[1024], manifest[4096];
    snprintf(manifest, sizeof(manifest),
        "{\n"
        "  \"wallet_version\": 13,\n"
        "  \"address\": \"%s\",\n"
        "  \"signature_scheme\": \"ed25519+mldsa65\",\n"
        "  \"recovery_scheme\": \"%s\",\n"
        "  \"created_unix\": %lld\n"
        "}\n",
        address, has_recovery ? "mnemonic-aes256gcm-backup" : "none", (long long)time(NULL));
    snprintf(path, sizeof(path), "%s/wallet.json", dir);
    return write_text(path, manifest);
}
static int write_recovery_blob(const char *dir, const char *address, const char *mnemonic,
                               EVP_PKEY *ed, EVP_PKEY *ml) {
    unsigned char key[32]; derive_recovery_key(mnemonic, key);
    char *ed_priv = privkey_to_unencrypted_pem_string(ed); if (!ed_priv) return -1;
    char *ml_priv = privkey_to_unencrypted_pem_string(ml); if (!ml_priv) { free(ed_priv); return -1; }
    char *ed_pub = pubkey_to_pem_string(ed); if (!ed_pub) { free(ed_priv); free(ml_priv); return -1; }
    char *ml_pub = pubkey_to_pem_string(ml); if (!ml_pub) { free(ed_priv); free(ml_priv); free(ed_pub); return -1; }
    char *ed_priv_b64 = base64_encode((unsigned char*)ed_priv, strlen(ed_priv));
    char *ml_priv_b64 = base64_encode((unsigned char*)ml_priv, strlen(ml_priv));
    char *ed_pub_b64 = base64_encode((unsigned char*)ed_pub, strlen(ed_pub));
    char *ml_pub_b64 = base64_encode((unsigned char*)ml_pub, strlen(ml_pub));
    size_t pkg_cap = strlen(address)+strlen(ed_priv_b64)+strlen(ml_priv_b64)+strlen(ed_pub_b64)+strlen(ml_pub_b64)+512;
    char *pkg = malloc(pkg_cap); if (!pkg) return -1;
    snprintf(pkg, pkg_cap,
        "address=%s\n"
        "ed25519_priv_pem_b64=%s\n"
        "ed25519_pub_pem_b64=%s\n"
        "mldsa65_priv_pem_b64=%s\n"
        "mldsa65_pub_pem_b64=%s\n",
        address, ed_priv_b64, ed_pub_b64, ml_priv_b64, ml_pub_b64);
    unsigned char *ct = NULL, iv[12], tag[16]; size_t ctlen = 0;
    if (aes256gcm_encrypt(key, (unsigned char*)pkg, strlen(pkg), &ct, &ctlen, iv, tag) != 0) return -1;
    char *iv_b64 = base64_encode(iv, sizeof(iv)); char *tag_b64 = base64_encode(tag, sizeof(tag)); char *ct_b64 = base64_encode(ct, ctlen);
    char path[1024], out[65536];
    snprintf(out, sizeof(out),
        "format=qrx-recovery-v12\n"
        "scheme=mnemonic-aes256gcm\n"
        "address=%s\n"
        "iv_b64=%s\n"
        "tag_b64=%s\n"
        "ct_b64=%s\n",
        address, iv_b64, tag_b64, ct_b64);
    snprintf(path, sizeof(path), "%s/recovery.qrxseed", dir);
    int rc = write_text(path, out);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(ed_priv, strlen(ed_priv)); OPENSSL_cleanse(ml_priv, strlen(ml_priv));
    free(ed_priv); free(ml_priv); free(ed_pub); free(ml_pub);
    free(ed_priv_b64); free(ml_priv_b64); free(ed_pub_b64); free(ml_pub_b64);
    free(pkg); free(ct); free(iv_b64); free(tag_b64); free(ct_b64);
    return rc;
}

static char *wallet_address(const char *dir);
static int wallet_addresses_index_add(const char *dir, const char *addr);
static int wallet_index_primary_address(const char *dir);

/* QRX 0.0.7.1 Privacy Layer Phase 1
 * Recovery extension for rotated receive addresses.
 *
 * The original recovery.qrxseed protects the canonical wallet keys with the
 * recovery phrase. Rotated receive keys are additionally stored in an
 * AES-256-GCM extension whose key is derived from the canonical Ed25519
 * private key. This lets an existing recovery phrase + recovery.qrxseed
 * restore all rotated addresses without storing the recovery phrase on disk.
 */
static int derive_address_recovery_key(EVP_PKEY *ed_priv, unsigned char out[32]) {
    unsigned char raw[64]; size_t rawlen = sizeof(raw);
    if(!ed_priv || EVP_PKEY_get_raw_private_key(ed_priv, raw, &rawlen) != 1 || rawlen == 0) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); if(!ctx) return -1;
    unsigned int n = 0; int rc = -1;
    const char *domain = "QRX-ADDRESS-RECOVERY-EXT-V1";
    if(EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) == 1 &&
       EVP_DigestUpdate(ctx, domain, strlen(domain)) == 1 &&
       EVP_DigestUpdate(ctx, raw, rawlen) == 1 &&
       EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 32) rc = 0;
    EVP_MD_CTX_free(ctx); OPENSSL_cleanse(raw, sizeof(raw)); return rc;
}

static int append_dyn(char **buf, size_t *len, size_t *cap, const char *text) {
    size_t add = strlen(text);
    if(*len + add + 1 > *cap) {
        size_t nc = *cap ? *cap : 4096;
        while(nc < *len + add + 1) nc *= 2;
        char *nb = realloc(*buf, nc); if(!nb) return -1;
        *buf = nb; *cap = nc;
    }
    memcpy(*buf + *len, text, add); *len += add; (*buf)[*len] = 0; return 0;
}

static char *strip_address_recovery_extension(const char *rf) {
    if(!rf) return NULL;
    size_t cap = strlen(rf) + 64, len = 0; char *out = calloc(1, cap); if(!out) return NULL;
    const char *p = rf;
    while(*p) {
        const char *e = strchr(p, '\n'); size_t l = e ? (size_t)(e-p)+1 : strlen(p);
        if(strncmp(p,"address_ext_format=",19) && strncmp(p,"address_ext_count=",18) &&
           strncmp(p,"address_ext_iv_b64=",19) && strncmp(p,"address_ext_tag_b64=",20) &&
           strncmp(p,"address_ext_ct_b64=",19)) {
            char *line = malloc(l+1); if(!line){free(out);return NULL;} memcpy(line,p,l); line[l]=0;
            if(append_dyn(&out,&len,&cap,line)!=0){free(line);free(out);return NULL;} free(line);
        }
        if(!e) break; p=e+1;
    }
    return out;
}

static int update_recovery_address_extension(const char *dir, const char *passphrase) {
    char seedpath[1024]; snprintf(seedpath,sizeof(seedpath),"%s/recovery.qrxseed",dir);
    if(access_qrx(seedpath,F_OK)!=0) return 0; /* wallets without recovery remain legacy behavior */
    char primary_path[1024]; snprintf(primary_path,sizeof(primary_path),"%s/ed25519_priv.pem",dir);
    EVP_PKEY *primary = load_priv_pem(primary_path, passphrase); if(!primary) return -1;
    unsigned char key[32]; if(derive_address_recovery_key(primary,key)!=0){EVP_PKEY_free(primary);return -1;}
    EVP_PKEY_free(primary);

    char idxpath[1024]; snprintf(idxpath,sizeof(idxpath),"%s/addresses.txt",dir);
    char *idx = read_file(idxpath,NULL);
    char *primary_addr = wallet_address(dir); if(primary_addr) primary_addr[strcspn(primary_addr,"\r\n")]=0;
    char *pkg=NULL; size_t plen=0, pcap=0; int count=0;
    if(append_dyn(&pkg,&plen,&pcap,"version=1\n")!=0) goto fail;
    if(idx) {
        char *save=NULL; char *line=strtok_r(idx,"\r\n",&save);
        while(line) {
            if(*line && (!primary_addr || strcmp(line,primary_addr)!=0)) {
                char base[1536]; snprintf(base,sizeof(base),"%s/addresses/%s",dir,line);
                char p1[1800],p2[1800],p3[1800],p4[1800];
                snprintf(p1,sizeof(p1),"%s/ed25519_priv.pem",base); snprintf(p2,sizeof(p2),"%s/ed25519_pub.pem",base);
                snprintf(p3,sizeof(p3),"%s/mldsa65_priv.pem",base); snprintf(p4,sizeof(p4),"%s/mldsa65_pub.pem",base);
                EVP_PKEY *ed=load_priv_pem(p1,passphrase), *ml=load_priv_pem(p3,passphrase);
                EVP_PKEY *edp=load_pub_pem(p2), *mlp=load_pub_pem(p4);
                if(!ed||!ml||!edp||!mlp){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(edp);EVP_PKEY_free(mlp);goto fail;}
                char *edpr=privkey_to_unencrypted_pem_string(ed),*mlpr=privkey_to_unencrypted_pem_string(ml);
                char *edpu=pubkey_to_pem_string(edp),*mlpu=pubkey_to_pem_string(mlp);
                EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(edp);EVP_PKEY_free(mlp);
                if(!edpr||!mlpr||!edpu||!mlpu){free(edpr);free(mlpr);free(edpu);free(mlpu);goto fail;}
                char *a=base64_encode((unsigned char*)edpr,strlen(edpr)),*b=base64_encode((unsigned char*)edpu,strlen(edpu));
                char *c=base64_encode((unsigned char*)mlpr,strlen(mlpr)),*d=base64_encode((unsigned char*)mlpu,strlen(mlpu));
                OPENSSL_cleanse(edpr,strlen(edpr)); OPENSSL_cleanse(mlpr,strlen(mlpr)); free(edpr);free(mlpr);free(edpu);free(mlpu);
                if(!a||!b||!c||!d){free(a);free(b);free(c);free(d);goto fail;}
                char *rec=NULL; size_t need=strlen(line)+strlen(a)+strlen(b)+strlen(c)+strlen(d)+256; rec=malloc(need); if(!rec){free(a);free(b);free(c);free(d);goto fail;}
                snprintf(rec,need,"child_%d_address=%s\nchild_%d_ed25519_priv_pem_b64=%s\nchild_%d_ed25519_pub_pem_b64=%s\nchild_%d_mldsa65_priv_pem_b64=%s\nchild_%d_mldsa65_pub_pem_b64=%s\n",count,line,count,a,count,b,count,c,count,d);
                free(a);free(b);free(c);free(d); if(append_dyn(&pkg,&plen,&pcap,rec)!=0){free(rec);goto fail;} free(rec); count++;
            }
            line=strtok_r(NULL,"\r\n",&save);
        }
    }
    {
        unsigned char *ct=NULL,iv[12],tag[16]; size_t ctlen=0;
        if(aes256gcm_encrypt(key,(unsigned char*)pkg,plen,&ct,&ctlen,iv,tag)!=0) goto fail;
        char *ivb=base64_encode(iv,sizeof(iv)),*tagb=base64_encode(tag,sizeof(tag)),*ctb=base64_encode(ct,ctlen);
        char *rf=read_file(seedpath,NULL),*base=strip_address_recovery_extension(rf); free(rf);
        if(!ivb||!tagb||!ctb||!base){free(ivb);free(tagb);free(ctb);free(ct);free(base);goto fail;}
        size_t outcap=strlen(base)+strlen(ivb)+strlen(tagb)+strlen(ctb)+256; char *out=malloc(outcap); if(!out){free(ivb);free(tagb);free(ctb);free(ct);free(base);goto fail;}
        snprintf(out,outcap,"%saddress_ext_format=qrx-address-recovery-v1\naddress_ext_count=%d\naddress_ext_iv_b64=%s\naddress_ext_tag_b64=%s\naddress_ext_ct_b64=%s\n",base,count,ivb,tagb,ctb);
        int rc=write_text(seedpath,out); free(out);free(base);free(ivb);free(tagb);free(ctb);free(ct);free(pkg);free(idx);free(primary_addr);OPENSSL_cleanse(key,sizeof(key));return rc;
    }
fail:
    free(pkg);free(idx);free(primary_addr);OPENSSL_cleanse(key,sizeof(key));return -1;
}

static int restore_recovery_address_extension(const char *dir, const char *rf, EVP_PKEY *primary_ed, const char *new_passphrase) {
    char *fmt=cfg_get(rf,"address_ext_format"); if(!fmt) return 0;
    int supported=!strcmp(fmt,"qrx-address-recovery-v1"); free(fmt); if(!supported) return -1;
    char *ivb=cfg_get(rf,"address_ext_iv_b64"),*tagb=cfg_get(rf,"address_ext_tag_b64"),*ctb=cfg_get(rf,"address_ext_ct_b64");
    if(!ivb||!tagb||!ctb){free(ivb);free(tagb);free(ctb);return -1;}
    size_t il=0,tl=0,cl=0; unsigned char *iv=base64_decode(ivb,&il),*tag=base64_decode(tagb,&tl),*ct=base64_decode(ctb,&cl); free(ivb);free(tagb);free(ctb);
    if(!iv||!tag||!ct||il!=12||tl!=16){free(iv);free(tag);free(ct);return -1;}
    unsigned char key[32]; if(derive_address_recovery_key(primary_ed,key)!=0){free(iv);free(tag);free(ct);return -1;}
    unsigned char *pt=NULL;size_t pl=0;int drc=aes256gcm_decrypt(key,ct,cl,iv,tag,&pt,&pl);free(iv);free(tag);free(ct);OPENSSL_cleanse(key,sizeof(key));if(drc!=0)return -1;
    char *pkg=(char*)pt; char *cs=cfg_get(rf,"address_ext_count"); int count=cs?atoi(cs):0; free(cs);
    wallet_index_primary_address(dir);
    for(int i=0;i<count;i++){
        char k[128]; snprintf(k,sizeof(k),"child_%d_address",i); char *addr=cfg_get(pkg,k); if(!addr) continue;
        char *vals[4]={0}; const char *suf[4]={"ed25519_priv_pem_b64","ed25519_pub_pem_b64","mldsa65_priv_pem_b64","mldsa65_pub_pem_b64"};
        int ok=1; for(int j=0;j<4;j++){snprintf(k,sizeof(k),"child_%d_%s",i,suf[j]);vals[j]=cfg_get(pkg,k);if(!vals[j])ok=0;}
        if(ok){size_t lens[4]={0};unsigned char *pem[4]={0};for(int j=0;j<4;j++)pem[j]=base64_decode(vals[j],&lens[j]);
            EVP_PKEY *ed= pem[0]?privkey_from_pem_string((char*)pem[0]):NULL; EVP_PKEY *ml=pem[2]?privkey_from_pem_string((char*)pem[2]):NULL;
            if(ed&&ml&&address_matches_pub(ed,addr)==0){char base[1536],path[1800];snprintf(base,sizeof(base),"%s/addresses/%s",dir,addr);mkdir_p(base);
                snprintf(path,sizeof(path),"%s/ed25519_priv.pem",base);save_priv_pem(path,ed,new_passphrase);snprintf(path,sizeof(path),"%s/ed25519_pub.pem",base);write_file(path,pem[1],lens[1]);
                snprintf(path,sizeof(path),"%s/mldsa65_priv.pem",base);save_priv_pem(path,ml,new_passphrase);snprintf(path,sizeof(path),"%s/mldsa65_pub.pem",base);write_file(path,pem[3],lens[3]);wallet_addresses_index_add(dir,addr);
            }
            EVP_PKEY_free(ed);EVP_PKEY_free(ml);for(int j=0;j<4;j++)free(pem[j]);
        }
        for(int j=0;j<4;j++)free(vals[j]);free(addr);
    }
    OPENSSL_cleanse(pt,pl);free(pt);return 0;
}

static int wallet_build_core(const char *dir, const char *passphrase, char **out_address, EVP_PKEY **out_ed, EVP_PKEY **out_ml) {
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL); if (!ectx) return -1;
    EVP_PKEY *ed = NULL; if (EVP_PKEY_keygen_init(ectx) != 1 || EVP_PKEY_keygen(ectx, &ed) != 1) { EVP_PKEY_CTX_free(ectx); return -1; }
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX *mctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL); if (!mctx) { fprintf(stderr, "ERROR: ML-DSA-65 is not available in this OpenSSL build (%s). QRX mainnet hybrid wallets require OpenSSL >= 3.5, recommended 3.6.x.\n", OpenSSL_version(OPENSSL_VERSION)); EVP_PKEY_free(ed); return -1; }
    EVP_PKEY *ml = NULL; if (EVP_PKEY_keygen_init(mctx) != 1 || EVP_PKEY_generate(mctx, &ml) != 1) { EVP_PKEY_CTX_free(mctx); EVP_PKEY_free(ed); return -1; }
    EVP_PKEY_CTX_free(mctx);
    char path[1024];
    snprintf(path, sizeof(path), "%s/ed25519_priv.pem", dir); if (save_priv_pem(path, ed, passphrase) != 0) return -1;
    snprintf(path, sizeof(path), "%s/ed25519_pub.pem", dir); if (save_pub_pem(path, ed) != 0) return -1;
    snprintf(path, sizeof(path), "%s/mldsa65_priv.pem", dir); if (save_priv_pem(path, ml, passphrase) != 0) return -1;
    snprintf(path, sizeof(path), "%s/mldsa65_pub.pem", dir); if (save_pub_pem(path, ml) != 0) return -1;
    char *addr = wallet_address_from_pub(ed); if (!addr) return -1;
    snprintf(path, sizeof(path), "%s/address.txt", dir); if (write_text(path, addr) != 0) return -1;
    if (out_address) *out_address = addr; else free(addr);
    if (out_ed) *out_ed = ed; else EVP_PKEY_free(ed);
    if (out_ml) *out_ml = ml; else EVP_PKEY_free(ml);
    return 0;
}
static int wallet_seed_new(const char *dir) {
    if (ensure_wallet_dir(dir) != 0) die("failed to create wallet dir");
    char pass1[256], pass2[256];
    if (get_passphrase(pass1, sizeof(pass1), "Passphrase: ") != 0) die("passphrase failed");
    if (get_passphrase(pass2, sizeof(pass2), "Confirm passphrase: ") != 0) die("passphrase failed");
    if (strcmp(pass1, pass2) != 0) die("passphrases do not match");
    char *addr = NULL; EVP_PKEY *ed = NULL, *ml = NULL;
    if (wallet_build_core(dir, pass1, &addr, &ed, &ml) != 0) die("wallet build failed");
    unsigned char entropy[16]; if (RAND_bytes(entropy, sizeof(entropy)) != 1) die("entropy failed");
    char *mn = mnemonic_from_entropy(entropy, sizeof(entropy)); if (!mn) die("mnemonic failed");
    if (write_recovery_blob(dir, addr, mn, ed, ml) != 0) die("recovery blob failed");
    if (drive_pq_ensure_keys(dir, pass1, NULL) != 0 || update_recovery_drive_pq_extension(dir, pass1) != 0) die("Drive PRIVATE_PQ key/recovery setup failed");
    if (write_wallet_manifest(dir, addr, 1) != 0) die("wallet manifest failed");
    printf("address=%s\n", addr);
    printf("recovery_phrase=%s\n", mn);
    puts("IMPORTANT: Write the recovery phrase down offline. Anyone with the phrase and recovery file can restore the wallet.");
    OPENSSL_cleanse(pass1, sizeof(pass1)); OPENSSL_cleanse(pass2, sizeof(pass2));
    OPENSSL_cleanse(entropy, sizeof(entropy));
    free(mn); free(addr); EVP_PKEY_free(ed); EVP_PKEY_free(ml); return 0;
}
static int wallet_recovery_refresh_cmd(const char *dir) {
    char pass[256], path[1024];
    if (get_passphrase(pass, sizeof(pass), "Wallet passphrase: ") != 0) die("passphrase failed");
    snprintf(path, sizeof(path), "%s/ed25519_priv.pem", dir); EVP_PKEY *ed = load_priv_pem(path, pass); if (!ed) die("wallet passphrase incorrect or Ed25519 key unreadable");
    snprintf(path, sizeof(path), "%s/mldsa65_priv.pem", dir); EVP_PKEY *ml = load_priv_pem(path, pass); if (!ml) { EVP_PKEY_free(ed); die("wallet passphrase incorrect or ML-DSA65 key unreadable"); }
    char *addr = wallet_address(dir); if (!addr) { EVP_PKEY_free(ed); EVP_PKEY_free(ml); die("missing wallet address"); }
    addr[strcspn(addr,"\r\n")]=0;
    if (address_matches_pub(ed, addr) != 0) { free(addr); EVP_PKEY_free(ed); EVP_PKEY_free(ml); die("wallet address does not match Ed25519 key"); }
    unsigned char entropy[16]; if (RAND_bytes(entropy, sizeof(entropy)) != 1) die("entropy failed");
    char *mn = mnemonic_from_entropy(entropy, sizeof(entropy)); if (!mn) die("mnemonic failed");
    if (write_recovery_blob(dir, addr, mn, ed, ml) != 0) die("recovery blob failed");
    if (update_recovery_address_extension(dir, pass) != 0) die("recovery address extension refresh failed");
    if (drive_pq_ensure_keys(dir, pass, NULL) != 0 || update_recovery_drive_pq_extension(dir, pass) != 0) die("Drive PRIVATE_PQ recovery extension refresh failed");
    if (write_wallet_manifest(dir, addr, 1) != 0) die("wallet manifest update failed");
    printf("address=%s\n", addr);
    printf("recovery_phrase=%s\n", mn);
    printf("recovery_file=%s/recovery.qrxseed\n", dir);
    puts("IMPORTANT: This is a newly generated recovery phrase for the same wallet keys. Store it together with the new recovery.qrxseed. Older valid recovery pairs may remain usable if retained.");
    OPENSSL_cleanse(pass, sizeof(pass)); OPENSSL_cleanse(entropy, sizeof(entropy));
    free(mn); free(addr); EVP_PKEY_free(ed); EVP_PKEY_free(ml); return 0;
}

static int drive_pq_ensure_cmd(const char *dir){char pass[256];if(get_passphrase(pass,sizeof(pass),"Wallet passphrase: "))die("passphrase failed");if(drive_pq_ensure_keys(dir,pass,NULL)||update_recovery_drive_pq_extension(dir,pass))die("Drive PRIVATE_PQ key setup failed");OPENSSL_cleanse(pass,sizeof(pass));puts("drive_private_pq=ready\nkem=ML-KEM-768\nrecovery_bound=true");return 0;}
static int wallet_info_cmd(const char *dir) {
    char path[1024]; snprintf(path, sizeof(path), "%s/wallet.json", dir); char *manifest = read_file(path, NULL); if (!manifest) die("missing wallet.json");
    char *addr = wallet_address(dir); if (!addr) die("missing address");
    snprintf(path, sizeof(path), "%s/recovery.qrxseed", dir);
    printf("address=%s\n", addr);
    printf("manifest=%s\n", manifest ? "present" : "missing");
    printf("recovery_file=%s\n", access_qrx(path, F_OK) == 0 ? "present" : "missing");
    { char kp[1024],ku[1024]; drive_pq_key_paths(dir,kp,sizeof(kp),ku,sizeof(ku)); printf("drive_private_pq_key=%s\n", access_qrx(kp,F_OK)==0&&access_qrx(ku,F_OK)==0?"present":"missing"); }
    free(manifest); free(addr); return 0;
}
static int wallet_recover_cmd(const char *dir, const char *recovery_file) {
    if (ensure_wallet_dir(dir) != 0) die("failed to create wallet dir");
    char *rf = read_file(recovery_file, NULL); if (!rf) die("cannot read recovery file");
    char *iv_b64 = cfg_get(rf, "iv_b64"), *tag_b64 = cfg_get(rf, "tag_b64"), *ct_b64 = cfg_get(rf, "ct_b64");
    if (!iv_b64 || !tag_b64 || !ct_b64) die("invalid recovery file");
    char mnemonic[2048]; if (get_mnemonic(mnemonic, sizeof(mnemonic), "Recovery phrase: ") != 0) die("mnemonic failed");
    unsigned char ent[32]; size_t entlen = 0; if (entropy_from_mnemonic(mnemonic, ent, sizeof(ent), &entlen) != 0 || entlen != 16) die("invalid recovery phrase");
    unsigned char key[32]; derive_recovery_key(mnemonic, key);
    size_t iv_len=0, tag_len=0, ct_len=0; unsigned char *iv = base64_decode(iv_b64, &iv_len), *tag = base64_decode(tag_b64, &tag_len), *ct = base64_decode(ct_b64, &ct_len);
    if (!iv || !tag || !ct || iv_len != 12 || tag_len != 16) die("invalid recovery encoding");
    unsigned char *pt = NULL; size_t ptlen = 0; if (aes256gcm_decrypt(key, ct, ct_len, iv, tag, &pt, &ptlen) != 0) die("recovery decrypt failed");
    char *pkg = (char*)pt;
    char *address = cfg_get(pkg, "address"), *ed_priv_b64 = cfg_get(pkg, "ed25519_priv_pem_b64"), *ed_pub_b64 = cfg_get(pkg, "ed25519_pub_pem_b64"), *ml_priv_b64 = cfg_get(pkg, "mldsa65_priv_pem_b64"), *ml_pub_b64 = cfg_get(pkg, "mldsa65_pub_pem_b64");
    if (!address||!ed_priv_b64||!ed_pub_b64||!ml_priv_b64||!ml_pub_b64) die("recovery payload invalid");
    size_t ed_priv_len=0, ed_pub_len=0, ml_priv_len=0, ml_pub_len=0;
    unsigned char *ed_priv_pem = base64_decode(ed_priv_b64, &ed_priv_len), *ed_pub_pem = base64_decode(ed_pub_b64, &ed_pub_len), *ml_priv_pem = base64_decode(ml_priv_b64, &ml_priv_len), *ml_pub_pem = base64_decode(ml_pub_b64, &ml_pub_len);
    EVP_PKEY *ed = privkey_from_pem_string((char*)ed_priv_pem); EVP_PKEY *ml = privkey_from_pem_string((char*)ml_priv_pem);
    if (!ed || !ml) die("recovery key parse failed");
    if (address_matches_pub(ed, address) != 0) die("recovery address mismatch");
    char *new_address = wallet_address_from_pub(ed); if (!new_address) die("recovery address derive failed");
    char pass1[256], pass2[256];
    if (get_passphrase(pass1, sizeof(pass1), "New passphrase: ") != 0) die("passphrase failed");
    if (get_passphrase(pass2, sizeof(pass2), "Confirm new passphrase: ") != 0) die("passphrase failed");
    if (strcmp(pass1, pass2) != 0) die("passphrases do not match");
    char path[1024];
    snprintf(path, sizeof(path), "%s/ed25519_priv.pem", dir); if (save_priv_pem(path, ed, pass1) != 0) die("save ed priv failed");
    snprintf(path, sizeof(path), "%s/ed25519_pub.pem", dir); write_file(path, ed_pub_pem, ed_pub_len);
    snprintf(path, sizeof(path), "%s/mldsa65_priv.pem", dir); if (save_priv_pem(path, ml, pass1) != 0) die("save ml priv failed");
    snprintf(path, sizeof(path), "%s/mldsa65_pub.pem", dir); write_file(path, ml_pub_pem, ml_pub_len);
    snprintf(path, sizeof(path), "%s/address.txt", dir); write_text(path, new_address);
    snprintf(path, sizeof(path), "%s/recovery.qrxseed", dir); write_text(path, rf);
    if (restore_recovery_address_extension(dir, rf, ed, pass1) != 0) die("rotated receive address recovery failed");
    if (restore_recovery_drive_pq_extension(dir, rf, ed, pass1) != 0) die("Drive PRIVATE_PQ recovery extension failed");
    if (drive_pq_ensure_keys(dir, pass1, NULL) != 0) die("Drive PRIVATE_PQ key setup failed");
    if (write_wallet_manifest(dir, new_address, 1) != 0) die("wallet manifest failed");
    printf("address=%s\n", new_address);
    puts("wallet recovered");
    OPENSSL_cleanse(pass1, sizeof(pass1)); OPENSSL_cleanse(pass2, sizeof(pass2)); OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(mnemonic, sizeof(mnemonic)); OPENSSL_cleanse(ent, sizeof(ent));
    free(rf); free(iv_b64); free(tag_b64); free(ct_b64); free(iv); free(tag); free(ct); free(pt);
    free(address); free(new_address); free(ed_priv_b64); free(ed_pub_b64); free(ml_priv_b64); free(ml_pub_b64);
    free(ed_priv_pem); free(ed_pub_pem); free(ml_priv_pem); free(ml_pub_pem); EVP_PKEY_free(ed); EVP_PKEY_free(ml);
    return 0;
}

static int wallet_keygen(const char *dir) {
    if (ensure_wallet_dir(dir) != 0) die("failed to create wallet dir");
    char pass1[256], pass2[256];
    if (get_passphrase(pass1, sizeof(pass1), "Passphrase: ") != 0) die("passphrase failed");
    if (get_passphrase(pass2, sizeof(pass2), "Confirm passphrase: ") != 0) die("passphrase failed");
    if (strcmp(pass1, pass2) != 0) die("passphrases do not match");
    char *addr = NULL; EVP_PKEY *ed = NULL, *ml = NULL;
    if (wallet_build_core(dir, pass1, &addr, &ed, &ml) != 0) die("wallet build failed");
    if (write_wallet_manifest(dir, addr, 0) != 0) die("wallet manifest failed");
    puts(addr);
    free(addr); EVP_PKEY_free(ed); EVP_PKEY_free(ml);
    OPENSSL_cleanse(pass1, sizeof(pass1)); OPENSSL_cleanse(pass2, sizeof(pass2));
    return 0;
}

static char *wallet_address(const char *dir) {
    char path[1024]; snprintf(path, sizeof(path), "%s/address.txt", dir); return read_file(path, NULL);
}

static int address_seen_in_text(const char *txt, const char *addr) {
    if(!txt || !addr || !*addr) return 0;
    size_t alen = strlen(addr);
    const char *p = txt;
    while(p && *p) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        while(len && (p[len-1] == '\r' || p[len-1] == ' ' || p[len-1] == '\t')) len--;
        if(len == alen && !strncmp(p, addr, alen)) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

static int wallet_addresses_index_add(const char *dir, const char *addr) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/addresses.txt", dir);
    char *txt = read_file(path, NULL);
    if(txt && address_seen_in_text(txt, addr)) { free(txt); return 0; }
    free(txt);
    char line[768];
    snprintf(line, sizeof(line), "%s\n", addr);
    return append_text(path, line);
}

static int wallet_addresses_index_remove(const char *dir, const char *addr) {
    char path[1024]; snprintf(path,sizeof(path),"%s/addresses.txt",dir); char *txt=read_file(path,NULL); if(!txt)return 0;
    char *out=NULL;size_t len=0,cap=0;char *save=NULL;char *line=strtok_r(txt,"\r\n",&save);
    while(line){if(strcmp(line,addr)!=0){char rec[1024];snprintf(rec,sizeof(rec),"%s\n",line);if(append_dyn(&out,&len,&cap,rec)!=0){free(out);free(txt);return -1;}}line=strtok_r(NULL,"\r\n",&save);}
    int rc=write_text(path,out?out:"");free(out);free(txt);return rc;
}

static int wallet_index_primary_address(const char *dir) {
    char *primary = wallet_address(dir);
    if(!primary) return 0;
    primary[strcspn(primary, "\r\n")] = 0;
    int rc = wallet_addresses_index_add(dir, primary);
    free(primary);
    return rc;
}

static int wallet_new_address_cmd(const char *dir) {
    if(ensure_wallet_dir(dir) != 0) die("failed to create wallet dir");
    char recovery_path[1024]; snprintf(recovery_path,sizeof(recovery_path),"%s/recovery.qrxseed",dir);
    if(access_qrx(recovery_path,F_OK)!=0) die("recovery.qrxseed required before generating rotated receive addresses; create a Recovery Center backup first");
    wallet_index_primary_address(dir);

    char pass[256];
    if(get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");

    char addrs_dir[1024];
    snprintf(addrs_dir, sizeof(addrs_dir), "%s/addresses", dir);
    if(mkdir_p(addrs_dir) != 0) die("failed to create addresses dir");

    char tmpdir[1024];
    unsigned char rnd[8];
    if(RAND_bytes(rnd, sizeof(rnd)) != 1) die("entropy failed");
    char *rndhex = bytes_to_hex(rnd, sizeof(rnd));
    snprintf(tmpdir, sizeof(tmpdir), "%s/.new-%lld-%s", addrs_dir, (long long)time(NULL), rndhex ? rndhex : "tmp");
    free(rndhex);
    if(mkdir_p(tmpdir) != 0) die("failed to create address dir");

    char *addr = NULL; EVP_PKEY *ed = NULL, *ml = NULL;
    if(wallet_build_core(tmpdir, pass, &addr, &ed, &ml) != 0) die("wallet address build failed");

    char finaldir[1536];
    snprintf(finaldir, sizeof(finaldir), "%s/%s", addrs_dir, addr);
    if(rename(tmpdir, finaldir) != 0) {
        /* If rename fails because the address directory already exists, keep the temp dir readable
           but still return the new address. This is extremely unlikely. */
    }

    /* A rotated address is only announced after it has been added to the
       recovery extension. This keeps automatic address rotation recoverable
       with the same recovery phrase + recovery.qrxseed pair. */
    if(wallet_addresses_index_add(dir, addr) != 0) die("address index write failed");
    if(update_recovery_address_extension(dir, pass) != 0) {
        wallet_addresses_index_remove(dir,addr);
        die("rotated address recovery extension update failed; address was not activated");
    }
    printf("%s\n", addr);

    OPENSSL_cleanse(pass, sizeof(pass));
    free(addr); EVP_PKEY_free(ed); EVP_PKEY_free(ml);
    return 0;
}

static int wallet_list_addresses_cmd(const char *dir) {
    wallet_index_primary_address(dir);
    char path[1024];
    snprintf(path, sizeof(path), "%s/addresses.txt", dir);
    char *txt = read_file(path, NULL);
    if(txt && *txt) {
        printf("%s", txt);
        if(txt[strlen(txt)-1] != '\n') printf("\n");
        free(txt);
        return 0;
    }
    free(txt);
    char *primary = wallet_address(dir);
    if(!primary) die("missing address");
    primary[strcspn(primary, "\r\n")] = 0;
    printf("%s\n", primary);
    free(primary);
    return 0;
}

static int legacy_address_cmd(const char *dir) {
    char pass[8] = {0}; (void)pass;
    char path[1024]; snprintf(path, sizeof(path), "%s/ed25519_pub.pem", dir);
    EVP_PKEY *ed = load_pub_pem(path); if (!ed) die("missing ed25519 pub key");
    char *addr = wallet_address_legacy_from_pub(ed); if (!addr) die("legacy address derive failed");
    puts(addr);
    free(addr); EVP_PKEY_free(ed); return 0;
}

static int migrate_address_cmd(const char *dir) {
    char path[1024]; snprintf(path, sizeof(path), "%s/ed25519_pub.pem", dir);
    EVP_PKEY *ed = load_pub_pem(path); if (!ed) die("missing ed25519 pub key");
    char *modern = wallet_address_from_pub(ed);
    char *legacy = wallet_address_legacy_from_pub(ed);
    if (!modern || !legacy) die("address derive failed");
    snprintf(path, sizeof(path), "%s/address.txt", dir);
    if (write_text(path, modern) != 0) die("address write failed");
    snprintf(path, sizeof(path), "%s/wallet.json", dir);
    char *manifest = read_file(path, NULL);
    if (manifest) {
        char *fmt = cfg_get(manifest, "format"), *hd = cfg_get(manifest, "hd_mode");
        char out[1024];
        snprintf(out, sizeof(out), "format=%s\naddress=%s\naddress_legacy=%s\nhd_mode=%s\n", fmt ? fmt : "qrx-wallet-v12", modern, legacy, hd ? hd : "0");
        write_text(path, out);
        free(fmt); free(hd); free(manifest);
    }
    printf("legacy_address=%s\naddress=%s\n", legacy, modern);
    free(modern); free(legacy); EVP_PKEY_free(ed);
    return 0;
}

static int state_migrate_address_cmd(const char *chain_dir, const char *old_addr, const char *new_addr) {
    char bal[1024], nonce[1024], appl[1024], journal[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    long long bal_old = kv_get_ll_bin(bal, old_addr);
    long long nonce_old = kv_get_ll_bin(nonce, old_addr);
    long long bal_new = kv_get_ll_bin(bal, new_addr);
    long long nonce_new = kv_get_ll_bin(nonce, new_addr);
    kv_set_ll_bin(bal, new_addr, bal_new + bal_old);
    kv_set_ll_bin(nonce, new_addr, nonce_new > nonce_old ? nonce_new : nonce_old);
    kv_set_ll_bin(bal, old_addr, 0);
    kv_set_ll_bin(nonce, old_addr, 0);
    journal_append(chain_dir, "address_migrate old=%s new=%s balance=%lld nonce=%lld", old_addr, new_addr, bal_old, nonce_old);
    printf("migrated_balance=%lld\nmigrated_nonce=%lld\n", bal_old, nonce_old);
    return 0;
}



static void supply_paths(const char *chain_dir, char *supply, size_t ssz) {
    if (supply) snprintf(supply, ssz, "%s/state/supply.bin", chain_dir);
}
static long long chain_cfg_ll_or_default(const char *chain_dir, const char *key, long long dflt) {
    char *v = chain_cfg_value(chain_dir, key); if (!v) return dflt; long long out = atoll(v); free(v); return out;
}
static long long supply_get(const char *chain_dir, const char *key) {
    char p[1024]; supply_paths(chain_dir, p, sizeof(p)); return kv_get_ll_bin(p, key);
}
static int supply_set(const char *chain_dir, const char *key, long long val) {
    char p[1024]; supply_paths(chain_dir, p, sizeof(p)); return kv_set_ll_bin(p, key, val);
}
static int mint_with_cap(const char *chain_dir, const char *bucket, long long amount) {
    if (amount < 0) return -1;
    long long max_supply = chain_cfg_ll_or_default(chain_dir, "max_supply_atoms", (long long)QRX_MAX_SUPPLY_ATOMS);
    long long minted = supply_get(chain_dir, "minted_supply");
    if (minted + amount > max_supply) return -1;
    if (supply_set(chain_dir, "minted_supply", minted + amount) != 0) return -1;
    if (bucket && *bucket) {
        long long cur = supply_get(chain_dir, bucket);
        if (supply_set(chain_dir, bucket, cur + amount) != 0) return -1;
    }
    return 0;
}
static int burn_supply(const char *chain_dir, long long amount) {
    if (amount <= 0) return 0;
    long long cur = supply_get(chain_dir, "burned_supply");
    return supply_set(chain_dir, "burned_supply", cur + amount);
}
static int note_redistributed(const char *chain_dir, long long amount) {
    if (amount <= 0) return 0;
    long long cur = supply_get(chain_dir, "redistributed_supply");
    return supply_set(chain_dir, "redistributed_supply", cur + amount);
}
static void jail_paths(const char *chain_dir, char *jailed, size_t jsz, char *tomb, size_t tsz) {
    if (jailed) snprintf(jailed, jsz, "%s/state/jailed.bin", chain_dir);
    if (tomb) snprintf(tomb, tsz, "%s/state/tombstoned.bin", chain_dir);
}

static void validator_activity_paths(const char *chain_dir, char *last_seen, size_t lsz, char *last_penalty, size_t psz, char *double_signs, size_t dsz) {
    if (last_seen) snprintf(last_seen, lsz, "%s/state/validator_last_seen.bin", chain_dir);
    if (last_penalty) snprintf(last_penalty, psz, "%s/state/validator_last_offline_penalty.bin", chain_dir);
    if (double_signs) snprintf(double_signs, dsz, "%s/state/double_signs.bin", chain_dir);
}

static long long min_validator_stake_at(const char *chain_dir, long long height) {
    return qrx_chain_get_ll_at_height_or_default(chain_dir, height, "min_validator_stake_atoms", 10000000000LL);
}

static int validator_has_min_self_stake_at(const char *chain_dir, const char *validator, long long height) {
    char key[1024]; long long self=0; snprintf(key,sizeof(key),"staking:self:%s",validator);
    if(!staking_db_ll_found(chain_dir,key,&self)){
        char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
        staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
        self=kv_get_ll_bin(stakes,validator);
    }
    return self >= min_validator_stake_at(chain_dir, height);
}

static void record_validator_seen(const char *chain_dir, const char *validator, long long height) {
    char last_seen[1024], outage_bps[1024];
    validator_activity_paths(chain_dir, last_seen, sizeof(last_seen), NULL, 0, NULL, 0);
    snprintf(outage_bps, sizeof(outage_bps), "%s/state/validator_offline_outage_bps.bin", chain_dir);
    kv_set_ll_bin(last_seen, validator, height);
    /* A successfully observed validator ends the previous outage. This resets only
       the liveness-outage cap; double-sign evidence/tombstones are never reset. */
    kv_set_ll_bin(outage_bps, validator, 0);
}

static int bootstrap_validator_lock_info(const char *chain_dir, const char *validator, long long *principal_atoms, long long *locked_until_height) {
    if (principal_atoms) *principal_atoms = 0;
    if (locked_until_height) *locked_until_height = 0;
    if (!chain_dir || !validator || !*validator) return 0;
    QrxDB db;
    if (qrxdb_init(&db, chain_dir) != 0) return 0;
    char key[1024], value[128];
    snprintf(key, sizeof(key), "genesis:validator:%s:amount_atoms", validator);
    if (qrxdb_get(&db, key, value, sizeof(value)) != 0) { qrxdb_close(&db); return 0; }
    long long principal = atoll(value);
    snprintf(key, sizeof(key), "genesis:validator:%s:locked_until_height", validator);
    if (qrxdb_get(&db, key, value, sizeof(value)) != 0) { qrxdb_close(&db); return 0; }
    long long lockh = atoll(value);
    qrxdb_close(&db);
    if (principal <= 0 || lockh <= 0) return 0;
    if (principal_atoms) *principal_atoms = principal;
    if (locked_until_height) *locked_until_height = lockh;
    return 1;
}

static int validator_is_safely_paused(const char *chain_dir, const char *validator) {
    if (!chain_dir || !validator || !*validator) return 0;
    char key[1024]; snprintf(key,sizeof(key),"staking:validator_paused:%s",validator);
    return staking_db_ll(chain_dir,key,0) == 1;
}

static int validator_is_compute_jailed_at(const char *chain_dir, const char *validator, long long height) {
    if (!chain_dir || !validator || !*validator || height < 0) return 0;
    QrxDB db;
    if (qrxdb_init(&db, chain_dir) != 0) return 0;
    int jailed = qrx_pouc_verifier_is_compute_jailed(&db, validator, (uint64_t)height);
    qrxdb_close(&db);
    return jailed;
}

static int bootstrap_liveness_grace_active(const char *chain_dir, const char *validator, long long height) {
    long long principal = 0, lockh = 0;
    return bootstrap_validator_lock_info(chain_dir, validator, &principal, &lockh) && height < lockh;
}

static int apply_offline_penalties(const char *chain_dir, long long height) {
    long long after = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_penalty_after_blocks", 25920);
    long long interval = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_penalty_interval_blocks", 8640);
    long long bps = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_penalty_bps", 5);
    long long max_outage_bps = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_max_slash_bps_per_outage", 100);
    long long jail_after = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_jail_after_blocks", 60480);
    long long jail_secs = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_jail_seconds", 3600);
    if (after <= 0 || interval <= 0 || bps <= 0) return 0;

    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], penalties[1024];
    char last_seen[1024], last_penalty[1024], jailed[1024], tomb[1024], outage_bps[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), penalties, sizeof(penalties));
    validator_activity_paths(chain_dir, last_seen, sizeof(last_seen), last_penalty, sizeof(last_penalty), NULL, 0);
    jail_paths(chain_dir, jailed, sizeof(jailed), tomb, sizeof(tomb));
    snprintf(outage_bps, sizeof(outage_bps), "%s/state/validator_offline_outage_bps.bin", chain_dir);

    StateKVRecord *arr = NULL; size_t n = 0;
    if (kv_load(stakes, &arr, &n) != 0) return 0;
    int applied = 0;
    for (size_t i=0; i<n; ++i) {
        const char *validator = arr[i].key;
        long long self = arr[i].value;
        if (self <= 0) continue;
        if (validator_is_tombstoned(chain_dir, validator)) continue;
        /* SAFE PAUSE removes the validator from liveness expectations. Historical double-sign evidence remains slashable. */
        if (validator_is_safely_paused(chain_dir, validator)) continue;
        if (!validator_has_min_self_stake_at(chain_dir, validator, height)) continue;
        long long seen = kv_get_ll_bin(last_seen, validator);
        if (seen <= 0) {
            kv_set_ll_bin(last_seen, validator, height);
            continue;
        }
        long long missed = height - seen;
        /* Home profile: `after` is a true grace period. The first liveness
           penalty is not due until one full penalty interval has elapsed
           beyond that grace window. */
        if (missed < after + interval) continue;
        long long lastp = kv_get_ll_bin(last_penalty, validator);
        if (lastp > 0 && height - lastp < interval) continue;
        if (bootstrap_liveness_grace_active(chain_dir, validator, height)) {
            long long principal = 0, lockh = 0;
            bootstrap_validator_lock_info(chain_dir, validator, &principal, &lockh);
            kv_set_ll_bin(last_penalty, validator, height);
            journal_append(chain_dir, "bootstrap_liveness_grace validator=%s height=%lld locked_principal=%lld grace_until_height=%lld missed=%lld slash=0 jail=0", validator, height, principal, lockh, missed);
            applied++;
            continue;
        }
        long long already_bps = kv_get_ll_bin(outage_bps, validator);
        if (already_bps < 0) already_bps = 0;
        long long this_bps = bps;
        if (max_outage_bps > 0 && already_bps >= max_outage_bps) {
            kv_set_ll_bin(last_penalty, validator, height);
            journal_append(chain_dir, "offline_penalty_cap validator=%s height=%lld missed=%lld accumulated_bps=%lld cap_bps=%lld", validator, height, missed, already_bps, max_outage_bps);
            continue;
        }
        if (max_outage_bps > 0 && already_bps + this_bps > max_outage_bps) this_bps = max_outage_bps - already_bps;
        long long power = validator_power_total(chain_dir, validator);
        long long amount = (power * this_bps) / 10000;
        if (amount <= 0 && power > 0) amount = 1;
        if (amount <= 0) continue;
        slash_cmd(chain_dir, validator, amount, "offline", 1);
        kv_set_ll_bin(last_penalty, validator, height);
        kv_set_ll_bin(outage_bps, validator, already_bps + this_bps);
        int jailed_now = 0;
        if (jail_secs > 0 && jail_after > 0 && missed >= jail_after) {
            kv_set_ll_bin(jailed, validator, (long long)time(NULL) + jail_secs);
            jailed_now = 1;
        }
        journal_append(chain_dir, "offline_penalty validator=%s height=%lld last_seen=%lld missed=%lld amount=%lld bps=%lld outage_bps=%lld cap_bps=%lld jail=%d jail_seconds=%lld", validator, height, seen, missed, amount, this_bps, already_bps + this_bps, max_outage_bps, jailed_now, jailed_now ? jail_secs : 0);
        applied++;
    }
    free(arr);
    return applied;
}

static int check_and_record_double_sign_block(const char *chain_dir, const char *validator, const char *height_s, const char *round_s, const char *block_hash) {
    char ds[1024]; validator_activity_paths(chain_dir, NULL, 0, NULL, 0, ds, sizeof(ds));
    char key[512]; snprintf(key, sizeof(key), "%s:%s:%s", validator, height_s ? height_s : "0", round_s ? round_s : "0");
    char existing[256] = {0};
    /* The binary KV stores integers only, so keep the hash record in a sidecar text DB. */
    char sidecar[1024]; snprintf(sidecar, sizeof(sidecar), "%s/state/double_sign_blocks.txt", chain_dir);
    char *txt = read_file(sidecar, NULL);
    if (txt) {
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
            if (len > 0) {
                char line[700]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
                char *sep = strchr(line, '=');
                if (sep) {
                    *sep = 0;
                    if (!strcmp(line, key)) {
                        snprintf(existing, sizeof(existing), "%s", sep+1);
                        break;
                    }
                }
            }
            cur = e ? e+1 : NULL;
        }
        free(txt);
    }
    if (existing[0] && strcmp(existing, block_hash) != 0) {
        long long bps = qrx_chain_get_ll_at_height_or_default(chain_dir, atoll(height_s), "double_sign_slash_bps", 5000);
        long long jail_secs = qrx_chain_get_ll_at_height_or_default(chain_dir, atoll(height_s), "double_sign_jail_seconds", 315360000LL);
        long long power = validator_power_total(chain_dir, validator);
        long long amount = (power * bps) / 10000;
        if (amount <= 0 && power > 0) amount = 1;
        char jailed[1024], tomb[1024]; jail_paths(chain_dir, jailed, sizeof(jailed), tomb, sizeof(tomb));
        if (jail_secs > 0) kv_set_ll_bin(jailed, validator, (long long)time(NULL) + jail_secs);
        kv_set_ll_bin(tomb, validator, 1);
        if (amount > 0) slash_cmd(chain_dir, validator, amount, "double_sign", 100);
        journal_append(chain_dir, "double_sign_auto validator=%s height=%s round=%s old_hash=%s new_hash=%s amount=%lld bps=%lld tombstoned=1", validator, height_s, round_s, existing, block_hash, amount, bps);
        return -1;
    }
    if (!existing[0]) {
        char line[900]; snprintf(line, sizeof(line), "%s=%s\n", key, block_hash);
        append_text(sidecar, line);
    }
    return 0;
}

static int validator_is_tombstoned(const char *chain_dir, const char *validator) {
    char jailed[1024], tomb[1024]; jail_paths(chain_dir, jailed, sizeof(jailed), tomb, sizeof(tomb));
    return kv_get_ll_bin(tomb, validator) > 0;
}
static int validator_is_jailed_now(const char *chain_dir, const char *validator) {
    char jailed[1024], tomb[1024]; jail_paths(chain_dir, jailed, sizeof(jailed), tomb, sizeof(tomb));
    long long until = kv_get_ll_bin(jailed, validator); long long now = (long long)time(NULL); return until > now;
}
static int qrx_addr_cmp(const void *a,const void *b){return strcmp((const char*)a,(const char*)b);}
static int validator_snapshot_write(const char *chain_dir, long long height, long long round) {
    char dir[1024]; snprintf(dir,sizeof(dir),"%s/consensus/snapshots",chain_dir); mkdir_p(dir);
    char path[1024]; snprintf(path,sizeof(path),"%s/%lld-%lld.validators",dir,height,round);
    /* Snapshots are immutable once created for a height/round. */
    if(access_qrx(path,F_OK)==0) return 0;
    char users[4096][385]; int n=collect_known_users(chain_dir,users,4096); if(n<0)return -1;
    qsort(users,(size_t)n,sizeof(users[0]),qrx_addr_cmp);
    FILE*f=fopen(path,"wb"); if(!f)return -1;
    for(int i=0;i<n;i++){
        const char*validator=users[i];
        if(validator_is_tombstoned(chain_dir,validator)||validator_is_jailed_now(chain_dir,validator)||validator_is_safely_paused(chain_dir,validator)||validator_is_compute_jailed_at(chain_dir,validator,height))continue;
        if(!validator_has_min_self_stake_at(chain_dir,validator,height))continue;
        char ks[1024],kd[1024]; long long self=0,delegated=0;
        snprintf(ks,sizeof(ks),"staking:self:%s",validator); self=staking_db_ll(chain_dir,ks,0);
        snprintf(kd,sizeof(kd),"staking:delegated_total:%s",validator); delegated=staking_db_ll(chain_dir,kd,0);
        long long power=self+delegated; if(power<=0)continue;
        fprintf(f,"validator=%s self=%lld delegated=%lld power=%lld\n",validator,self,delegated,power);
    }
    fclose(f); return 0;
}

static int expected_proposer_from_snapshot(const char *chain_dir,long long height,long long round,char out[385]){
    char path[1024];snprintf(path,sizeof(path),"%s/consensus/snapshots/%lld-%lld.validators",chain_dir,height,round);
    char*txt=read_file(path,NULL);if(!txt)return -1; long long total=0; const char*cur=txt;
    while(cur&&*cur){const char*e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);char line[512];if(len>=sizeof(line))len=sizeof(line)-1;memcpy(line,cur,len);line[len]=0;char v[385];long long a,b,p;if(sscanf(line,"validator=%384s self=%lld delegated=%lld power=%lld",v,&a,&b,&p)==4&&p>0)total+=p;cur=e?e+1:NULL;}
    if(total<=0){free(txt);return -1;} char*gen=chain_cfg_value(chain_dir,"genesis_hash");if(!gen){free(txt);return -1;}char mat[512],hx[129];snprintf(mat,sizeof(mat),"QRX-PROPOSER-v1|%s|%lld|%lld",gen,height,round);free(gen);hash_primary_hex((unsigned char*)mat,strlen(mat),hx);unsigned long long r=0;for(int i=0;i<16&&hx[i];i++){char c=hx[i];unsigned d=(c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:0;r=(r<<4)|d;} long long target=(long long)(r%(unsigned long long)total); long long acc=0;cur=txt;
    while(cur&&*cur){const char*e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);char line[512];if(len>=sizeof(line))len=sizeof(line)-1;memcpy(line,cur,len);line[len]=0;char v[385];long long a,b,p;if(sscanf(line,"validator=%384s self=%lld delegated=%lld power=%lld",v,&a,&b,&p)==4&&p>0){acc+=p;if(target<acc){snprintf(out,385,"%s",v);free(txt);return 0;}}cur=e?e+1:NULL;}free(txt);return -1;
}
static long long validator_power_from_snapshot(const char *chain_dir, long long height, long long round, const char *validator) {
    char path[1024]; snprintf(path, sizeof(path), "%s/consensus/snapshots/%lld-%lld.validators", chain_dir, height, round);
    char *txt = read_file(path, NULL); if (!txt) return 0;
    long long out = 0; const char *cur = txt;
    while (cur && *cur) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
        if (len > 0) {
            char line[512]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
            char v[200]={0}; long long self=0, delegated=0, power=0;
            if (sscanf(line, "validator=%199s self=%lld delegated=%lld power=%lld", v, &self, &delegated, &power) == 4) {
                if (strcmp(v, validator) == 0) { out = power; break; }
            }
        }
        cur = e ? e+1 : NULL;
    }
    free(txt); return out;
}
static long long snapshot_total_power(const char *chain_dir, long long height, long long round) {
    char path[1024]; snprintf(path, sizeof(path), "%s/consensus/snapshots/%lld-%lld.validators", chain_dir, height, round);
    char *txt = read_file(path, NULL); if (!txt) return 0;
    long long sum = 0; const char *cur = txt;
    while (cur && *cur) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
        if (len > 0) {
            char line[512]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
            char v[200]={0}; long long self=0, delegated=0, power=0;
            if (sscanf(line, "validator=%199s self=%lld delegated=%lld power=%lld", v, &self, &delegated, &power) == 4) sum += power;
        }
        cur = e ? e+1 : NULL;
    }
    free(txt); return sum;
}
static int validator_set_at_cmd(const char *chain_dir, long long height, long long round) {
    char path[1024]; snprintf(path, sizeof(path), "%s/consensus/snapshots/%lld-%lld.validators", chain_dir, height, round);
    char *txt = read_file(path, NULL); if (!txt) die("missing validator snapshot");
    printf("%s", txt); free(txt); return 0;
}
static int node_lock_paths(const char *node_dir, char *lockp, size_t lsz, char *votesp, size_t vsz) {
    if (lockp) snprintf(lockp, lsz, "%s/consensus.lock", node_dir);
    if (votesp) snprintf(votesp, vsz, "%s/local_votes", node_dir);
    return 0;
}
static int lock_status_cmd(const char *node_dir) {
    char p[1024]; node_lock_paths(node_dir, p, sizeof(p), NULL, 0); char *txt = read_file(p, NULL); if (!txt) { puts("unlocked=1"); return 0; } printf("%s", txt); free(txt); return 0;
}
static long long node_timeout_value(const char *node_dir, const char *key, long long defv) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) return defv; char *v = cfg_get(cfg, key); long long out = v ? atoll(v) : defv; if (v) free(v); free(cfg); return out;
}
static int timeout_status_cmd(const char *node_dir) {
    printf("timeout_propose_ms=%lld\n", node_timeout_value(node_dir, "timeout_propose_ms", 3000));
    printf("timeout_prevote_ms=%lld\n", node_timeout_value(node_dir, "timeout_prevote_ms", 3000));
    printf("timeout_precommit_ms=%lld\n", node_timeout_value(node_dir, "timeout_precommit_ms", 3000));
    return 0;
}
static int chain_init(const char *dir, long long penalty_threshold, long long redistribute_bps, long long max_supply_atoms, long long epoch_reward_atoms, long long faucet_cap_atoms, const char *network_id_in, const char *protocol_version_in, const char *magic_in, const char *chain_name_in, long long block_time_seconds, long long max_txs_per_block, long long max_block_bytes, long long max_tx_bytes, long long validator_reward_percent, long long delegator_reward_percent, long long network_pool_percent, const char *dev_address_in) {
    char p[1024]; if (mkdir_p(dir) != 0) die("failed to create chain dir");
    snprintf(p, sizeof(p), "%s/mempool", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/blocks", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/state", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/validators", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/consensus", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/consensus/votes", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/consensus/finalized", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/consensus/snapshots", dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/consensus/certificates", dir); mkdir_p(p);
    long long genesis_time = 1710000000LL;
    const char *network_id = (network_id_in && *network_id_in) ? network_id_in : "qrx-mainnet-community";
    const char *protocol_version = (protocol_version_in && *protocol_version_in) ? protocol_version_in : "1";
    const char *magic = (magic_in && *magic_in) ? magic_in : QRX_MAGIC;
    const char *chain_name = (chain_name_in && *chain_name_in) ? chain_name_in : "QRX RC6.4 Hybrid Alpha";
    int genesis_is_mainnet = network_id && strstr(network_id,"mainnet") != NULL;
    /* Phase 7.2.14.1: QRX Mainnet is scheduled for Tuesday, 2026-09-15 18:00 CEST (16:00 UTC). Nodes may be installed/synced beforehand, but block production is forbidden before this timestamp. */
    if (genesis_is_mainnet) genesis_time = 1789488000LL;
    if(genesis_is_mainnet && (!qrx_bootstrap_validators_material_ready() || !qrx_genesis_governance_material_ready()))
        die("Mainnet Genesis material incomplete: replace all 50 bootstrap validator addresses and all 5 governance public keys before init-chain");
    if (qrx_chain_write_genesis(dir,
        network_id,
        protocol_version,
        magic,
        chain_name,
        penalty_threshold,
        redistribute_bps,
        max_supply_atoms,
        epoch_reward_atoms,
        faucet_cap_atoms,
        block_time_seconds,
        max_txs_per_block,
        max_block_bytes,
        max_tx_bytes,
        validator_reward_percent,
        delegator_reward_percent,
        network_pool_percent,
        dev_address_in,
        genesis_time) != 0) die("write genesis failed");
    snprintf(p, sizeof(p), "%s/chain.conf", dir); if (write_text(p, "runtime_format=2\nmetadata_file=chain.meta\ngenesis_file=genesis.cfg\n") != 0) die("write chain conf failed");
    snprintf(p, sizeof(p), "%s/state/balances.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/nonces.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/applied.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/stakes.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/delegations.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/delegated_totals.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/unbonding.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/unbonding_eta.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/undelegations.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/undelegation_eta.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/penalties.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/validator_last_seen.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/validator_last_offline_penalty.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/validator_offline_outage_bps.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/double_signs.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/double_sign_blocks.txt", dir); write_text(p, "");
    snprintf(p, sizeof(p), "%s/state/jailed.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/tombstoned.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/supply.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/fee_pool.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/journal.log", dir); write_text(p, "");
    supply_set(dir, "minted_supply", 0); supply_set(dir, "faucet_minted", 0); supply_set(dir, "rewards_minted", 0); supply_set(dir, "burned_supply", 0); supply_set(dir, "redistributed_supply", 0);
    if(genesis_is_mainnet){
        char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
        staking_paths(dir,stakes,sizeof(stakes),delegations,sizeof(delegations),totals,sizeof(totals),ub,sizeof(ub),ube,sizeof(ube),ud,sizeof(ud),ude,sizeof(ude),NULL,0);
        QrxDB db; if(qrxdb_init(&db,dir)!=0) die("QRXDB genesis bootstrap init failed");
        unsigned long long minted=0;
        for(int i=0;i<QRX_BOOTSTRAP_VALIDATOR_COUNT;i++){
            const qrx_bootstrap_validator_t *v=&QRX_BOOTSTRAP_VALIDATORS[i];
            if(kv_set_ll_bin(stakes,v->address,(long long)v->amount_atoms)!=0){qrxdb_close(&db);die("bootstrap validator stake init failed");}
            char k[1024],val[128];
            snprintf(k,sizeof(k),"genesis:validator:%s:amount_atoms",v->address);snprintf(val,sizeof(val),"%llu",(unsigned long long)v->amount_atoms);if(qrxdb_put(&db,k,val)!=0){qrxdb_close(&db);die("bootstrap validator QRXDB init failed");}
            snprintf(k,sizeof(k),"genesis:validator:%s:locked_until_height",v->address);snprintf(val,sizeof(val),"%lld",(long long)v->locked_until_height);qrxdb_put(&db,k,val);
            snprintf(k,sizeof(k),"genesis:validator:%s:staking_allowed",v->address);qrxdb_put(&db,k,v->staking_allowed?"1":"0");
            snprintf(k,sizeof(k),"genesis:validator:%s:transfer_allowed_before_unlock",v->address);qrxdb_put(&db,k,v->transfer_allowed_before_unlock?"1":"0");
            minted += v->amount_atoms;
        }
        qrxdb_put(&db,"genesis:bootstrap_validator_count","50");
        qrxdb_put(&db,"genesis:governance_model","developer_threshold_v1");
        qrxdb_close(&db);
        supply_set(dir,"minted_supply",(long long)minted);
        journal_append(dir,"genesis_bootstrap validators=%d amount_each_atoms=%llu total_atoms=%llu lock_until_height=%lld governance_threshold=%d governance_roots=%d",QRX_BOOTSTRAP_VALIDATOR_COUNT,(unsigned long long)QRX_BOOTSTRAP_VALIDATOR_ATOMS,minted,(long long)QRX_BOOTSTRAP_LOCK_UNTIL_HEIGHT,QRX_GENESIS_GOVERNANCE_THRESHOLD,QRX_GENESIS_GOVERNANCE_ROOT_COUNT);
    }
    { char gh[128]; if (qrx_chain_get_value(dir, "genesis_hash", gh, sizeof(gh)) != 0) die("read genesis hash failed"); puts(gh); }
    return 0;
}

static char *chain_cfg_value(const char *chain_dir, const char *key) {
    char buf[512];
    if (qrx_chain_get_value(chain_dir, key, buf, sizeof(buf)) != 0) die("missing key %s", key);
    return strdup(buf);
}

static int chain_network_is(const char *chain_dir, const char *needle) {
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    int ok = network_id && strstr(network_id, needle) != NULL;
    free(network_id);
    return ok;
}

static int chain_allows_manual_mint(const char *chain_dir) {
    return chain_network_is(chain_dir, "regtest");
}

static int chain_allows_faucet(const char *chain_dir) {
    return chain_network_is(chain_dir, "regtest") || chain_network_is(chain_dir, "testnet") || chain_network_is(chain_dir, "alpha");
}

static void require_manual_mint_allowed(const char *chain_dir, const char *cmd) {
    if (!chain_allows_manual_mint(chain_dir)) {
        die("%s disabled on this network; public networks mint only through finalized block producer loop", cmd);
    }
}

static void require_faucet_allowed(const char *chain_dir) {
    if (!chain_allows_faucet(chain_dir)) {
        die("faucet disabled on this network");
    }
}


static int atomic_write_file(const char *path, const void *buf, size_t len) {
    char tmp[1200];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (write_file(tmp, buf, len) != 0) return -1;
    return rename(tmp, path);
}
static void state_paths(const char *chain_dir, char *balances, size_t bsz, char *nonces, size_t nsz, char *applied, size_t asz, char *journal, size_t jsz) {
    if (balances) snprintf(balances, bsz, "%s/state/balances.bin", chain_dir);
    if (nonces) snprintf(nonces, nsz, "%s/state/nonces.bin", chain_dir);
    if (applied) snprintf(applied, asz, "%s/state/applied.bin", chain_dir);
    if (journal) snprintf(journal, jsz, "%s/state/journal.log", chain_dir);
}
static void journal_append(const char *chain_dir, const char *fmt, ...) {
    char journal[1024]; state_paths(chain_dir, NULL, 0, NULL, 0, NULL, 0, journal, sizeof(journal));
    FILE *f = fopen(journal, "ab"); if (!f) return;
    fprintf(f, "journal_timestamp=%lld ", (long long)time(NULL));
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}
static int kv_load(const char *path, StateKVRecord **out, size_t *count) {
    *out = NULL; *count = 0;
    size_t len = 0; char *buf = read_file(path, &len);
    if (!buf) return 0;
    if (len % sizeof(StateKVRecord) != 0) { free(buf); return -1; }
    size_t n = len / sizeof(StateKVRecord);
    StateKVRecord *arr = NULL;
    if (n) {
        arr = malloc(n * sizeof(StateKVRecord)); if (!arr) { free(buf); return -1; }
        memcpy(arr, buf, len);
    }
    free(buf); *out = arr; *count = n; return 0;
}
static int kv_save(const char *path, const StateKVRecord *arr, size_t count) {
    size_t len = count * sizeof(StateKVRecord);
    return atomic_write_file(path, arr, len);
}
static long long kv_get_ll_bin(const char *path, const char *key) {
    StateKVRecord *arr = NULL; size_t n = 0;
    if (kv_load(path, &arr, &n) != 0) return 0;
    long long out = 0;
    for (size_t i=0;i<n;i++) if (strcmp(arr[i].key, key) == 0) { out = arr[i].value; break; }
    free(arr); return out;
}
static int kv_set_ll_bin(const char *path, const char *key, long long val) {
    if (strlen(key) > 384) return -1;
    StateKVRecord *arr = NULL; size_t n = 0;
    if (kv_load(path, &arr, &n) != 0) return -1;
    int found = 0;
    for (size_t i=0;i<n;i++) {
        if (strcmp(arr[i].key, key) == 0) { arr[i].value = val; found = 1; break; }
    }
    if (!found) {
        StateKVRecord *tmp = realloc(arr, (n+1) * sizeof(StateKVRecord)); if (!tmp) { free(arr); return -1; }
        arr = tmp; memset(&arr[n], 0, sizeof(arr[n])); snprintf(arr[n].key, sizeof(arr[n].key), "%s", key); arr[n].value = val; n++;
    }
    int rc = kv_save(path, arr, n); free(arr); return rc;
}
static int applied_load(const char *path, StateAppliedRecord **out, size_t *count) {
    *out = NULL; *count = 0;
    size_t len = 0; char *buf = read_file(path, &len);
    if (!buf) return 0;
    if (len % sizeof(StateAppliedRecord) != 0) { free(buf); return -1; }
    size_t n = len / sizeof(StateAppliedRecord); StateAppliedRecord *arr = NULL;
    if (n) { arr = malloc(n * sizeof(StateAppliedRecord)); if (!arr) { free(buf); return -1; } memcpy(arr, buf, len); }
    free(buf); *out = arr; *count = n; return 0;
}
static int applied_save(const char *path, const StateAppliedRecord *arr, size_t count) {
    return atomic_write_file(path, arr, count * sizeof(StateAppliedRecord));
}
static int applied_has_bin(const char *path, const char *key) {
    StateAppliedRecord *arr = NULL; size_t n = 0; if (applied_load(path, &arr, &n) != 0) return 0;
    int found = 0; for (size_t i=0;i<n;i++) if (strcmp(arr[i].key, key) == 0) { found = 1; break; }
    free(arr); return found;
}
static int applied_add_bin(const char *path, const char *key) {
    if (strlen(key) > 384) return -1;
    StateAppliedRecord *arr = NULL; size_t n = 0; if (applied_load(path, &arr, &n) != 0) return -1;
    for (size_t i=0;i<n;i++) if (strcmp(arr[i].key, key) == 0) { free(arr); return 0; }
    StateAppliedRecord *tmp = realloc(arr, (n+1) * sizeof(StateAppliedRecord)); if (!tmp) { free(arr); return -1; }
    arr = tmp; memset(&arr[n], 0, sizeof(arr[n])); snprintf(arr[n].key, sizeof(arr[n].key), "%s", key); n++;
    int rc = applied_save(path, arr, n); free(arr); return rc;
}
static int applied_has_authoritative(const char *chain_dir,const char *legacy_path,const char *key){
    QrxDB db;
    if(qrxdb_init(&db,chain_dir)==0){ int found=qrxdb_chain_is_applied(&db,key); qrxdb_close(&db); if(found) return 1; }
    return applied_has_bin(legacy_path,key);
}
static int state_check_cmd(const char *chain_dir) {
    char bal[1024], nonce[1024], appl[1024], journal[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    StateKVRecord *b=NULL,*n=NULL; StateAppliedRecord *a=NULL; size_t bc=0,nc=0,ac=0;
    if (kv_load(bal,&b,&bc)!=0 || kv_load(nonce,&n,&nc)!=0 || applied_load(appl,&a,&ac)!=0) die("state corruption detected");
    printf("balances=%zu\nnonces=%zu\napplied=%zu\njournal=%s\n", bc, nc, ac, journal);
    free(b); free(n); free(a); return 0;
}
static int snapshot_state_cmd(const char *chain_dir, const char *label_in) {
    char snaps[1024]; snprintf(snaps, sizeof(snaps), "%s/state/snapshots", chain_dir); mkdir_p(snaps);
    char label[128]; if (label_in && *label_in) snprintf(label, sizeof(label), "%s", label_in); else snprintf(label, sizeof(label), "%lld", (long long)time(NULL));
    char dest[1024]; snprintf(dest, sizeof(dest), "%s/%s", snaps, label); mkdir_p(dest);
    char bal[1024], nonce[1024], appl[1024], journal[1024], out[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    size_t len=0; char *buf=NULL;
    if ((buf=read_file(bal,&len))) { snprintf(out, sizeof(out), "%s/balances.bin", dest); write_file(out, buf, len); free(buf); }
    if ((buf=read_file(nonce,&len))) { snprintf(out, sizeof(out), "%s/nonces.bin", dest); write_file(out, buf, len); free(buf); }
    if ((buf=read_file(appl,&len))) { snprintf(out, sizeof(out), "%s/applied.bin", dest); write_file(out, buf, len); free(buf); }
    if ((buf=read_file(journal,&len))) { snprintf(out, sizeof(out), "%s/journal.log", dest); write_file(out, buf, len); free(buf); }
    printf("%s\n", dest); return 0;
}

static int qrxdb_chain_ingest_block_file(const char *chain_dir, const char *block_file) {
    if (!chain_dir || !block_file) return -1;
    char *blk = read_file(block_file, NULL);
    if (!blk) return -1;
    char *height_s = cfg_get(blk, "height");
    char *block_hash = cfg_get(blk, "block_hash");
    char *tx_count_s = cfg_get(blk, "tx_count");
    if (!height_s || !block_hash) { free(blk); if(height_s) free(height_s); if(block_hash) free(block_hash); if(tx_count_s) free(tx_count_s); return -1; }
    QrxDB db;
    if (qrxdb_init(&db, chain_dir) != 0) { free(blk); free(height_s); free(block_hash); if(tx_count_s) free(tx_count_s); return -1; }
    uint64_t height = (uint64_t)strtoull(height_s, NULL, 10);
    /* 0.0.9.33 canonical compute reorg hook: when recovery/sync replaces an
       already indexed canonical height with a different block hash, roll PoUC
       settlement, liveness/penalty and verification-reward journals back to
       the common parent BEFORE the replacement block is ingested. Normal BFT
       finalization never reaches this branch unless canonical recovery occurs. */
    char previous_at_height[129]={0};
    if(qrxdb_chain_get_block_hash_by_height(&db,height,previous_at_height,sizeof(previous_at_height))==0 && strcmp(previous_at_height,block_hash)){
        QrxPoucCanonicalReorgReport rr;
        if(qrx_pouc_canonical_reorg_hook(&db,height?height-1:0,&rr)!=0){qrxdb_close(&db);free(blk);free(height_s);free(block_hash);if(tx_count_s)free(tx_count_s);return -1;}
    }
    int rc = qrxdb_chain_put_block(&db, height, block_hash, blk);
    int tx_count = tx_count_s ? atoi(tx_count_s) : 0;
    for (int i = 1; rc == 0 && i <= tx_count; i++) {
        char key[32]; snprintf(key, sizeof(key), "tx%d", i);
        char *txhash = cfg_get(blk, key);
        if (txhash) {
            rc = qrxdb_chain_index_tx(&db, txhash, block_hash, height, (uint32_t)i, NULL);
            if (rc == 0) rc = qrxdb_chain_mark_applied(&db, txhash, height);
            free(txhash);
        }
    }
    if (rc == 0) rc = qrxdb_verify(&db);
    qrxdb_close(&db);
    free(blk); free(height_s); free(block_hash); if(tx_count_s) free(tx_count_s);
    return rc;
}

static void qrxdb_chain_sync_account_pair(const char *chain_dir, const char *address, long long balance, long long nonce) {
    if (!chain_dir || !address) return;
    QrxDB db;
    if (qrxdb_init(&db, chain_dir) != 0) return;
    qrxdb_chain_set_balance(&db, address, balance);
    qrxdb_chain_set_nonce(&db, address, nonce);
    qrxdb_close(&db);
}

static void qrxdb_chain_sync_state_files(const char *chain_dir) {
    if (!chain_dir) return;
    char bal[1024], nonce[1024], appl[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), NULL, 0);
    StateKVRecord *b=NULL,*n=NULL; StateAppliedRecord *a=NULL; size_t bc=0,nc=0,ac=0;
    QrxDB db;
    if (qrxdb_init(&db, chain_dir) != 0) return;
    if (kv_load(bal, &b, &bc) == 0) for (size_t i=0;i<bc;i++) qrxdb_chain_set_balance(&db, b[i].key, b[i].value);
    if (kv_load(nonce, &n, &nc) == 0) for (size_t i=0;i<nc;i++) qrxdb_chain_set_nonce(&db, n[i].key, n[i].value);
    if (applied_load(appl, &a, &ac) == 0) for (size_t i=0;i<ac;i++) qrxdb_chain_mark_applied(&db, a[i].key, 0);
    qrxdb_verify(&db);
    qrxdb_close(&db);
    free(b); free(n); free(a);
}

/* ---------------------------------------------------------------------------
 * Genesis hardening (Finding 7): shell-free directory listing.
 *
 * reindex-state and the legacy mempool status previously built shell command
 * lines from a quoted data-directory path (an "ls -1" glob over the blocks
 * directory, and a "find | wc -l" over the mempool directory) and ran them
 * through popen(). A data directory whose path contains a single
 * quote escaped the quoting and executed attacker-chosen commands. The shell
 * pipeline was also non-portable: cmd.exe has no ls/find/wc.
 *
 * Replacement iterates the directory natively:
 *   - Unix  : lstat() + S_ISREG(), so symlinks are ignored rather than followed
 *   - Windows: skips directories and FILE_ATTRIBUTE_REPARSE_POINT entries
 *   - results are sorted deterministically so reindex order is reproducible
 * ------------------------------------------------------------------------- */
typedef struct { char **items; size_t count; } QrxDirList;

static void qrx_dirlist_free(QrxDirList *l) {
    if (!l) return;
    for (size_t i = 0; i < l->count; i++) free(l->items[i]);
    free(l->items);
    l->items = NULL; l->count = 0;
}

static int qrx_dirlist_push(QrxDirList *l, const char *path) {
    char **grown = (char**)realloc(l->items, (l->count + 1) * sizeof(char*));
    if (!grown) return -1;
    l->items = grown;
    l->items[l->count] = strdup(path);
    if (!l->items[l->count]) return -1;
    l->count++;
    return 0;
}

static int qrx_dirlist_cmp(const void *a, const void *b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

/* Collects regular files in `dir`. If `suffix` is non-NULL only names ending
 * in it are returned. Full paths are written into `out`, sorted ascending.
 * Returns 0 on success (including "directory does not exist" -> empty list). */
static int qrx_dirlist_regular_files(const char *dir, const char *suffix, QrxDirList *out) {
    if (!dir || !out) return -1;
    out->items = NULL; out->count = 0;
    size_t suflen = suffix ? strlen(suffix) : 0;

#ifdef _WIN32
    char pattern[1400];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        size_t nlen = strlen(fd.cFileName);
        if (suflen && (nlen < suflen || strcmp(fd.cFileName + nlen - suflen, suffix) != 0)) continue;
        char full[1400];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (qrx_dirlist_push(out, full) != 0) { FindClose(h); qrx_dirlist_free(out); return -1; }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        size_t nlen = strlen(e->d_name);
        if (suflen && (nlen < suflen || strcmp(e->d_name + nlen - suflen, suffix) != 0)) continue;
        char full[1400];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        /* lstat, not stat: a symlink must not be followed out of the datadir. */
        if (lstat(full, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        if (qrx_dirlist_push(out, full) != 0) { closedir(d); qrx_dirlist_free(out); return -1; }
    }
    closedir(d);
#endif
    if (out->count > 1) qsort(out->items, out->count, sizeof(char*), qrx_dirlist_cmp);
    return 0;
}

static int reindex_state_cmd(const char *chain_dir) {
    char bal[1024], nonce[1024], appl[1024], journal[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    atomic_write_file(bal, "", 0); atomic_write_file(nonce, "", 0); atomic_write_file(appl, "", 0); write_text(journal, "");
    char blocks_dir[1200]; snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", chain_dir);
    QrxDirList blocks; 
    if (qrx_dirlist_regular_files(blocks_dir, ".block", &blocks) != 0) die("reindex list failed");
    for (size_t bi = 0; bi < blocks.count; bi++) {
        const char *blkpath = blocks.items[bi];
        char *blk = read_file(blkpath, NULL); if (!blk) continue;
        for (int i=1; i<100000; i++) {
            char key[32]; snprintf(key, sizeof(key), "tx%d", i);
            char *txhash = cfg_get(blk, key); if (!txhash) break;
            applied_add_bin(appl, txhash); free(txhash);
        }
        free(blk);
        qrxdb_chain_ingest_block_file(chain_dir, blkpath);
    }
    qrx_dirlist_free(&blocks);
    qrxdb_chain_sync_state_files(chain_dir);
    journal_append(chain_dir, "reindex_state ts=%lld", (long long)time(NULL));
    puts("OK"); return 0;
}

static long long db_get_ll(const char *path, const char *key) {
    char *db = read_file(path, NULL); if (!db) return 0;
    const char *p = db; size_t klen = strlen(key); long long out = 0;
    while (p && *p) {
        const char *e = strchr(p, '\n'); size_t len = e ? (size_t)(e-p) : strlen(p);
        if (len > klen + 1 && !strncmp(p, key, klen) && p[klen] == '=') { out = atoll(p+klen+1); break; }
        p = e ? e+1 : NULL;
    }
    free(db); return out;
}
static int db_set_ll(const char *path, const char *key, long long val) {
    char *db = read_file(path, NULL); FILE *f = fopen(path, "wb"); if (!f) { free(db); return -1; }
    bool wrote = false; size_t klen = strlen(key);
    if (db) {
        const char *p = db;
        while (p && *p) {
            const char *e = strchr(p, '\n'); size_t len = e ? (size_t)(e-p) : strlen(p);
            if (len > klen + 1 && !strncmp(p, key, klen) && p[klen] == '=') {
                fprintf(f, "%s=%lld\n", key, val); wrote = true;
            } else {
                fwrite(p, 1, len, f); fputc('\n', f);
            }
            p = e ? e+1 : NULL;
        }
        free(db);
    }
    if (!wrote) fprintf(f, "%s=%lld\n", key, val);
    fclose(f); return 0;
}
static int db_has_key(const char *path, const char *key) {
    char *db = read_file(path, NULL); if (!db) return 0; char *v = cfg_get(db, key); free(db); if (v) { free(v); return 1; } return 0;
}
static int db_set_str(const char *path, const char *key, const char *val) { return db_set_ll(path, key, atoll(val)); }

static void db_inc_ll(const char *path, const char *key, long long delta) {
    long long cur = db_get_ll(path, key); db_set_ll(path, key, cur + delta);
}
static void key_from_ip(char *out, size_t outsz, const char *ip, const char *suffix) {
    char tmp[256]; size_t j=0;
    for (size_t i=0; ip[i] && j < sizeof(tmp)-1; ++i) tmp[j++] = (ip[i]=='.' || ip[i]==':') ? '_' : ip[i];
    tmp[j]=0; snprintf(out, outsz, "%s_%s", tmp, suffix);
}
static long long peer_ban_score(const char *node_dir, const char *ip) {
    char db[1024], key[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir); key_from_ip(key, sizeof(key), ip, "ban"); return db_get_ll(db, key);
}
static void peer_add_score(const char *node_dir, const char *ip, long long delta) {
    char db[1024], key[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir); key_from_ip(key, sizeof(key), ip, "ban"); db_inc_ll(db, key, delta);
}
static long long peer_rep_score(const char *node_dir, const char *peer) {
    char db[1024], key[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir); key_from_ip(key, sizeof(key), peer, "rep"); return db_get_ll(db, key);
}
static void peer_rep_add(const char *node_dir, const char *peer, long long delta) {
    char db[1024], key[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir); key_from_ip(key, sizeof(key), peer, "rep"); db_inc_ll(db, key, delta);
}
static int peer_rate_allow(const char *node_dir, const char *ip) {
    char db[1024], keyw[320], keyc[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir);
    key_from_ip(keyw, sizeof(keyw), ip, "rate_window"); key_from_ip(keyc, sizeof(keyc), ip, "rate_count");
    long long now = (long long)time(NULL), win = db_get_ll(db, keyw), cnt = db_get_ll(db, keyc);
    if (now - win >= RATE_WINDOW_SECS || win == 0) { db_set_ll(db, keyw, now); db_set_ll(db, keyc, 1); return 1; }
    if (cnt >= RATE_MAX_MSGS) return 0;
    db_set_ll(db, keyc, cnt + 1); return 1;
}
static int peer_status_cmd(const char *node_dir) {
    char pth[1024]; snprintf(pth, sizeof(pth), "%s/peer_state.db", node_dir); char *db = read_file(pth, NULL); if (!db) { puts("no peer state"); return 0; }
    fputs(db, stdout); free(db); return 0;
}
static int mempool_status_cmd(const char *node_dir) {
    QrxVelocityMempool pool; QrxVelocityMempoolStats st;
    if(qrx_velocity_mempool_open(&pool,node_dir,MEMPOOL_MAX_TXS)==0){
        qrx_velocity_mempool_stats(&pool,&st);
        printf("engine=velocity_ram_sharded\n");
        printf("txs=%llu\nbytes=%llu\nmax_txs=%llu\nshards=%u\nwal_records=%llu\nrecovered_records=%llu\nduplicates=%llu\nrejected_full=%llu\n",
            (unsigned long long)st.entries,(unsigned long long)st.bytes,(unsigned long long)st.max_entries,st.shards,
            (unsigned long long)st.wal_records,(unsigned long long)st.recovered_records,(unsigned long long)st.duplicates,(unsigned long long)st.rejected_full);
        qrx_velocity_mempool_close(&pool); return 0;
    }
    char mempool_dir[1200]; snprintf(mempool_dir, sizeof(mempool_dir), "%s/mempool", node_dir);
    QrxDirList mp;
    if (qrx_dirlist_regular_files(mempool_dir, NULL, &mp) != 0) die("mempool status failed");
    long long count = (long long)mp.count;
    qrx_dirlist_free(&mp);
    printf("engine=legacy_files\ntxs=%lld\n",count); return 0;
}
static int mempool_prune_cmd(const char *node_dir, int max_txs) {
    if(max_txs<1)max_txs=MEMPOOL_MAX_TXS; QrxVelocityMempool pool; QrxVelocityPlan plan; int removed=0;
    if(qrx_velocity_mempool_open(&pool,node_dir,MEMPOOL_MAX_TXS)==0){
        if(qrx_velocity_mempool_plan(&pool,0,&plan)==0 && plan.count>(size_t)max_txs){
            for(size_t i=(size_t)max_txs;i<plan.count;i++) if(qrx_velocity_mempool_remove(&pool,plan.txids[i])==0) removed++;
            qrx_velocity_plan_free(&plan); qrx_velocity_mempool_checkpoint(&pool);
        }
        qrx_velocity_mempool_close(&pool); printf("removed=%d\n",removed); return 0;
    }
    return 1;
}
static int decay_bans_cmd(const char *node_dir, long long points) {
    char pth[1024]; snprintf(pth, sizeof(pth), "%s/peer_state.db", node_dir); char *db = read_file(pth, NULL); if (!db) return 0;
    FILE *f = fopen(pth, "wb"); if (!f) { free(db); return 1; }
    const char *cur = db;
    while (cur && *cur) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
        if (len) {
            char line[512]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
            char *eq = strchr(line, '=');
            if (eq) {
                *eq = 0; long long v = atoll(eq+1);
                if (strlen(line) >= 4 && strcmp(line + strlen(line)-4, "_ban") == 0 && v > 0) v = v > points ? v - points : 0;
                fprintf(f, "%s=%lld\n", line, v);
            }
        }
        cur = e ? e+1 : NULL;
    }
    fclose(f); free(db); return 0;
}

static int faucet_cmd(const char *chain_dir, const char *addr, long long amt) {
    require_faucet_allowed(chain_dir);
    if (amt <= 0) die("faucet amount must be > 0");
    long long faucet_cap = chain_cfg_ll_or_default(chain_dir, "faucet_cap_atoms", 1000000000000LL);
    long long faucet_minted = supply_get(chain_dir, "faucet_minted");
    if (faucet_minted + amt > faucet_cap) die("faucet cap exceeded");
    if (mint_with_cap(chain_dir, "faucet_minted", amt) != 0) die("max supply exceeded");
    char bal[1024]; state_paths(chain_dir, bal, sizeof(bal), NULL, 0, NULL, 0, NULL, 0); long long cur = kv_get_ll_bin(bal, addr); int rc = kv_set_ll_bin(bal, addr, cur + amt); if (rc == 0) { qrxdb_chain_sync_account_pair(chain_dir, addr, cur + amt, 0); journal_append(chain_dir, "faucet addr=%s amount=%lld", addr, amt); } return rc;
}

static int getdevaddress_cmd(const char *chain_dir) {
    char *dev = chain_cfg_value(chain_dir, "dev_address");
    if(!dev || !*dev) die("dev_address not configured");
    printf("%s\n", dev);
    free(dev);
    return 0;
}

static int balance_cmd(const char *chain_dir, const char *addr) {
    QrxDB db; long long v = 0;
    if (qrxdb_init(&db, chain_dir) == 0) {
        if (qrxdb_chain_get_balance(&db, addr, &v) == 0) { qrxdb_close(&db); printf("%lld\n", v); return 0; }
        qrxdb_close(&db);
    }
    char bal[1024]; state_paths(chain_dir, bal, sizeof(bal), NULL, 0, NULL, 0, NULL, 0); printf("%lld\n", kv_get_ll_bin(bal, addr)); return 0;
}

static void fee_pool_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/fee_pool.bin", chain_dir);
}
static long long fee_pool_pending(const char *chain_dir) {
    QrxDB db; char v[128];
    if(qrxdb_init(&db,chain_dir)==0){
        if(qrxdb_get(&db,"consensus:fee_pool:pending",v,sizeof(v))==0){ long long n=atoll(v); qrxdb_close(&db); return n; }
        qrxdb_close(&db);
    }
    char p[1024]; fee_pool_path(chain_dir, p, sizeof(p));
    return kv_get_ll_bin(p, "pending_fees");
}
static int fee_pool_add(const char *chain_dir, long long fee) {
    if (fee <= 0) return 0;
    long long cur=fee_pool_pending(chain_dir), next=0;
    checked_add_ll(cur,fee,"fee pool",&next);
    QrxDB db; if(qrxdb_init(&db,chain_dir)!=0) return -1;
    char v[64]; snprintf(v,sizeof(v),"%lld",next); int rc=qrxdb_put(&db,"consensus:fee_pool:pending",v); qrxdb_close(&db);
    if(rc) return -1;
    char p[1024]; fee_pool_path(chain_dir, p, sizeof(p));
    return kv_set_ll_bin(p, "pending_fees", next);
}
static long long fee_pool_drain(const char *chain_dir) {
    long long cur=fee_pool_pending(chain_dir);
    QrxDB db;if(qrxdb_init(&db,chain_dir)==0){qrxdb_put(&db,"consensus:fee_pool:pending","0");qrxdb_close(&db);}
    char p[1024]; fee_pool_path(chain_dir, p, sizeof(p));
    kv_set_ll_bin(p, "pending_fees", 0);
    return cur;
}

static int feeinfo_cmd(const char *chain_dir) {
    long long h = current_height_from_chain(chain_dir);
    long long fee = qrx_chain_get_ll_at_height_or_default(chain_dir, h + 1, "tx_fee_atoms", 1000LL);
    if(fee < 0) fee = 0;
    printf("tx_fee_atoms=%lld\n", fee);
    printf("next_block_height=%lld\n", h + 1);
    printf("pending_fee_pool_atoms=%lld\n", fee_pool_pending(chain_dir));
    return 0;
}

static long long qrx_balance_get_authoritative(const char *chain_dir,const char *address){
    QrxDB db; long long v=0;
    if(qrxdb_init(&db,chain_dir)==0){ if(qrxdb_chain_get_balance(&db,address,&v)==0){qrxdb_close(&db);return v;} qrxdb_close(&db);}
    char bal[1024];state_paths(chain_dir,bal,sizeof(bal),NULL,0,NULL,0,NULL,0);return kv_get_ll_bin(bal,address);
}


static void velocity_lane_nonce_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/nonces_lanes.bin", chain_dir);
}

static int velocity_parse_lane(const char *lane_s, long long *lane_out) {
    if (!lane_out) return -1;
    if (!lane_s || !*lane_s) { *lane_out = 0; return 0; }
    char *end = NULL;
    errno = 0;
    long long lane = strtoll(lane_s, &end, 10);
    if (errno || !end || *end || lane < 0 || lane > QRX_VELOCITY_MAX_LANE) return -1;
    *lane_out = lane;
    return 0;
}

static long long velocity_get_lane_nonce(const char *chain_dir, const char *address, long long lane) {
    QrxDB db; char qkey[768],buf[128];
    if(lane==0) snprintf(qkey,sizeof(qkey),"acct:nonce:%s",address);
    else snprintf(qkey,sizeof(qkey),"velocity:nonce:%s:%lld",address,lane);
    if(qrxdb_init(&db,chain_dir)==0){
        if(qrxdb_get(&db,qkey,buf,sizeof(buf))==0){ long long n=atoll(buf); qrxdb_close(&db); return n; }
        qrxdb_close(&db);
    }
    if (lane == 0) {
        char noncepath[1024];
        state_paths(chain_dir, NULL, 0, noncepath, sizeof(noncepath), NULL, 0, NULL, 0);
        return kv_get_ll_bin(noncepath, address);
    }
    char path[1024], key[512];
    velocity_lane_nonce_path(chain_dir, path, sizeof(path));
    snprintf(key, sizeof(key), "%s|%lld", address, lane);
    return kv_get_ll_bin(path, key);
}

static int velocity_set_lane_nonce(const char *chain_dir, const char *address, long long lane, long long nonce) {
    if (lane == 0) {
        char noncepath[1024];
        state_paths(chain_dir, NULL, 0, noncepath, sizeof(noncepath), NULL, 0, NULL, 0);
        return kv_set_ll_bin(noncepath, address, nonce);
    }
    char path[1024], key[512];
    velocity_lane_nonce_path(chain_dir, path, sizeof(path));
    snprintf(key, sizeof(key), "%s|%lld", address, lane);
    return kv_set_ll_bin(path, key, nonce);
}

static int velocity_tx_type_supported(const char *tx_type) {
    static const char *types[] = {
        "TRANSFER_FAST", "AGENT_REGISTER", "AGENT_UPDATE", "AGENT_REVOKE",
        "ORDER_CREATE", "ORDER_CANCEL", "ORDER_REPLACE", "ATOMIC_BUNDLE",
        "ORACLE_UPDATE", "EXTERNAL_ORDER", "GATEWAY_REGISTER", "GATEWAY_REVOKE", "EXECUTION_REPORT",
        "CROSSCHAIN_ORDER", "CROSSCHAIN_REDEEM", "CROSSCHAIN_REFUND",
        "BTC_SPV_HEADER", "BTC_SPV_FUNDING_PROOF",
        "STAKE_BOND", "STAKE_UNBOND", "STAKE_CLAIM", "DELEGATE_BOND", "DELEGATE_UNBOND", "DELEGATE_CLAIM", "VALIDATOR_PAUSE", "VALIDATOR_RESUME",
        "PRIVACY_SHIELD", "PRIVACY_TRANSFER", "PRIVACY_UNSHIELD", "PRIVACY_GOVERNANCE", "GOVERNANCE_PROTOCOL",
        "ASSET_ISSUE", "ASSET_REISSUE", "ASSET_TRANSFER", "ASSET_TAG", "ASSET_UNTAG",
        "ASSET_FREEZE_ADDRESS", "ASSET_UNFREEZE_ADDRESS", "ASSET_GLOBAL_FREEZE", "ASSET_GLOBAL_UNFREEZE",
        "ASSET_BROADCAST", "ASSET_REVOKE", "ASSET_FORCED_TRANSFER",
        "GAME_JOIN", "GAME_CLAN_CREATE", "GAME_TREASURY_FUND", "GAME_SEASON_JOIN", "GAME_ENERGY_SPEND", "GAME_CLAN_INVITE", "GAME_CLAN_INVITE_REVOKE", "GAME_CLAN_JOIN", "GAME_CLAN_LEAVE", "GAME_CLAN_OFFICER_SET", "GAME_CLAN_DIRECTIVE", "GAME_CLAN_LEADER_TRANSFER", "GAME_ORDER_COMMIT", "GAME_ORDER_REVEAL", "GAME_MARCH_ADVANCE", "GAME_TURN_RESOLVE", "GAME_INFRA_BUILD", "GAME_PRODUCE_UNIT", "GAME_SUPPLY_TRANSFER", "GAME_REPAIR_UNIT", "GAME_REARM_UNIT", "GAME_INFRA_ATTACK", "GAME_ROAD_REPAIR", "GAME_UNIT_RESUPPLY", "GAME_RECON_SCAN", "GAME_EW_JAM", "GAME_AIR_MISSION", "GAME_RADAR_SCAN", "GAME_SAM_INTERCEPT", "GAME_MISSILE_LAUNCH", "GAME_STRIKE_RESOLVE", "GAME_CAP_MISSION", "GAME_ESCORT_MISSION", "GAME_AIR_INTERCEPT", "GAME_AIR_COMBAT_RESOLVE", "GAME_AIR_FORMATION", "GAME_CAP_AUTO_INTERCEPT", "GAME_AIR_RTB", "GAME_SEAD_MISSION", "GAME_NAVAL_DEPLOY", "GAME_NAVAL_MOVE", "GAME_NAVAL_ATTACK", "GAME_AMPHIBIOUS_LOAD", "GAME_AMPHIBIOUS_LAND", "GAME_SEA_SUPPLY", "GAME_FLEET_CREATE", "GAME_NAVAL_COMBAT_RESOLVE", "GAME_CARRIER_AIR_WING", "GAME_NAVAL_BLOCKADE", "GAME_STRATEGIC_CLAIM", "GAME_ECONOMY_COLLECT", "GAME_CITY_DEVELOP", "GAME_INDUSTRY_INVEST", "GAME_RESEARCH_START", "GAME_RESEARCH_ACCELERATE", "GAME_RESEARCH_COMPLETE", "GAME_DOCTRINE_SELECT", "GAME_TECH_RECON", "GAME_RESEARCH_DISRUPT", "GAME_COUNTERINTEL_ACTIVATE", "GAME_SEASON_FINALIZE", "GAME_REWARD_CLAIM",
        "STORAGE_CAPACITY_COMMIT", "STORAGE_CAPACITY_PROVE", "STORAGE_PROVIDER_BOND", "STORAGE_PROVIDER_BIND_DISCOVERY_KEY", "STORAGE_PROVIDER_ACTIVATE",
        "STORAGE_PROVIDER_EXIT", "STORAGE_PROVIDER_WITHDRAW", "STORAGE_CONTRACT_CREATE", "STORAGE_CONTRACT_COMPLETE",
        "STORAGE_CONTRACT_REFUND", "STORAGE_ASSIGN", "STORAGE_ASSIGN_ACCEPT", "STORAGE_POSTOR", "STORAGE_SETTLE_EPOCH",
        "STORAGE_EGRESS_PAY", "STORAGE_ATTEST", "STORAGE_REPAIR_START", "STORAGE_REPAIR_ACCEPT", "STORAGE_REPAIR_COMPLETE",
        "DOMAIN_REGISTER", "DOMAIN_RENEW", "DOMAIN_UPDATE", "DOMAIN_TRANSFER", "DOMAIN_RELEASE",
        "AD_CAMPAIGN_CREATE", "AD_DELIVERY_RECEIPT", "AD_IMPRESSION_SETTLE", "AD_REWARD_CLAIM", "AD_CAMPAIGN_CLOSE",
        "COMPUTE_ESCROW_LOCK", "COMPUTE_ASSIGN", "COMPUTE_RECEIPT", "COMPUTE_VERIFY", "COMPUTE_CHALLENGE", "COMPUTE_RESELECT", "COMPUTE_PROVIDER_BIND_IDENTITY",
        "POUC_SETTLEMENT", NULL
    };
    if (!tx_type || !*tx_type) return 0;
    for (size_t i = 0; types[i]; ++i) if (!strcmp(types[i], tx_type)) return 1;
    return 0;
}

static int qrx_compute_pipeline_tx_type(const char *tx_type) {
    return tx_type && (!strcmp(tx_type,"COMPUTE_ESCROW_LOCK") || !strcmp(tx_type,"COMPUTE_ASSIGN") || !strcmp(tx_type,"COMPUTE_RECEIPT") || !strcmp(tx_type,"COMPUTE_VERIFY") || !strcmp(tx_type,"COMPUTE_CHALLENGE") || !strcmp(tx_type,"COMPUTE_RESELECT"));
}
static int qrx_compute_identity_tx_type(const char *tx_type) {
    return tx_type && !strcmp(tx_type, QRX_COMPUTE_PROVIDER_BIND_TX);
}

static char *canonical_velocity_tx_body(const char *network_id, const char *genesis_hash, const char *protocol_version,
    const char *tx_type, const char *from, const char *to, const char *amount, const char *fee,
    const char *lane_id, const char *nonce, const char *timestamp, const char *expiry_height, const char *payload,
    const char *ed_pub_hex, const char *mldsa_pub_b64) {
    size_t cap = strlen(network_id)+strlen(genesis_hash)+strlen(protocol_version)+strlen(tx_type)+strlen(from)+strlen(to)+
        strlen(amount)+strlen(fee)+strlen(lane_id)+strlen(nonce)+strlen(timestamp)+strlen(expiry_height)+strlen(payload)+
        strlen(ed_pub_hex)+strlen(mldsa_pub_b64)+768;
    char *buf = malloc(cap);
    if (!buf) die("oom");
    snprintf(buf, cap,
        "tx_version=%d\n"
        "network_id=%s\n"
        "genesis_hash=%s\n"
        "protocol_version=%s\n"
        "tx_type=%s\n"
        "from=%s\n"
        "to=%s\n"
        "amount=%s\n"
        "fee=%s\n"
        "lane_id=%s\n"
        "nonce=%s\n"
        "timestamp=%s\n"
        "expiry_height=%s\n"
        "payload=%s\n"
        "ed25519_pub_hex=%s\n"
        "mldsa65_pub_b64=%s\n",
        QRX_VELOCITY_TX_VERSION, network_id, genesis_hash, protocol_version, tx_type, from, to, amount, fee,
        lane_id, nonce, timestamp, expiry_height, payload, ed_pub_hex, mldsa_pub_b64);
    return buf;
}

static int resource_info_cmd(const char *chain_dir, long long requested_height) {
    long long current = current_height_from_chain(chain_dir);
    long long height = requested_height >= 0 ? requested_height : current;
    long long activation = qrx_resource_activation_height(chain_dir);
    long long target_time = qrx_resource_target_time(chain_dir);
    long long dev_bps = qrx_chain_get_ll_or_default(chain_dir, "storage_dev_share_bps", (long long)QRX_STORAGE_DEV_SHARE_BPS);
    long long reserve_bps = qrx_chain_get_ll_or_default(chain_dir, "storage_resilience_reserve_bps", (long long)QRX_STORAGE_RESILIENCE_RESERVE_BPS);
    long long perf_cap = qrx_chain_get_ll_or_default(chain_dir, "storage_performance_bonus_cap_bps", (long long)QRX_STORAGE_PERFORMANCE_BONUS_CAP_BPS);
    char network_id[128] = {0};
    qrx_chain_get_value(chain_dir, "network_id", network_id, sizeof(network_id));
    printf("software_track=0.0.8.2-capacity-accounting\n");
    printf("resource_protocol_version=%d\n", QRX_RESOURCE_PROTOCOL_VERSION);
    printf("drive_v1_required_protocol=%lld\n", (long long)QRX_DRIVE_V1_MIN_PROTOCOL_VERSION);
    printf("drive_v1_feature_flag=%s\n", QRX_DRIVE_V1_FEATURE_FLAG);
    printf("network_id=%s\n", network_id[0] ? network_id : "unknown");
    printf("chain_height=%lld\n", current);
    printf("query_height=%lld\n", height);
    printf("activation_scheduled=%s\n", qrx_resource_drive_v1_scheduled(chain_dir) ? "true" : "false");
    printf("activation_height=%lld\n", activation);
    printf("planned_target_unix=%lld\n", target_time);
    printf("planned_target_is_consensus=false\n");
    printf("resource_protocol_active=%s\n", qrx_resource_protocol_enabled_at_height(chain_dir, height) ? "true" : "false");
    printf("storage_protocol_active=%s\n", qrx_storage_protocol_enabled_at_height(chain_dir, height) ? "true" : "false");
    printf("reference_backend=filesystem\n");
    printf("seaweedfs_optional=true\n");
    printf("storage_affects_validator_block_chance=false\n");
    printf("storage_dev_share_bps=%lld\n", dev_bps);
    printf("storage_resilience_reserve_bps=%lld\n", reserve_bps);
    printf("storage_performance_bonus_cap_bps=%lld\n", perf_cap);
    printf("redundancy_fast=3x-full-replica\n");
    printf("redundancy_standard=%d+%d\n", QRX_STORAGE_STANDARD_DATA_SHARDS, QRX_STORAGE_STANDARD_PARITY_SHARDS);
    printf("redundancy_archive=%d+%d\n", QRX_STORAGE_ARCHIVE_DATA_SHARDS, QRX_STORAGE_ARCHIVE_PARITY_SHARDS);
    printf("compute_resource_type_reserved=true\n");
    return 0;
}

static int storage_split_cmd(const char *atoms_s) {
    if (!atoms_s || !*atoms_s) die("missing contract atoms");
    char *end = NULL;
    unsigned long long value = strtoull(atoms_s, &end, 10);
    if (!end || *end) die("invalid contract atoms");
    QrxStorageContractSplit split;
    if (qrx_storage_split_contract_value((uint64_t)value, QRX_STORAGE_DEV_SHARE_BPS, QRX_STORAGE_RESILIENCE_RESERVE_BPS, &split) != 0)
        die("cannot split storage contract value");
    printf("contract_atoms=%llu\n", value);
    printf("development_atoms=%llu\n", (unsigned long long)split.development_atoms);
    printf("resilience_atoms=%llu\n", (unsigned long long)split.resilience_atoms);
    printf("provider_budget_atoms=%llu\n", (unsigned long long)split.provider_budget_atoms);
    return 0;
}


static int storage_fs_parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s || !out || *s == '-') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int storage_fs_config_path(const char *root, char out[1024]) {
    if (!root || !*root) return -1;
    return snprintf(out, 1024, "%s/storage.backend.conf", root) < 1024 ? 0 : -1;
}

static int storage_fs_load_config(const char *root, uint64_t *max_usage, uint64_t *min_free) {
    char path[1024];
    if (storage_fs_config_path(root, path) != 0) return -1;
    char *txt = read_file(path, NULL);
    if (!txt) return -1;
    char *fmt = cfg_get(txt, "format");
    char *backend = cfg_get(txt, "backend");
    char *maxs = cfg_get(txt, "max_usage_bytes");
    char *mins = cfg_get(txt, "min_free_space_bytes");
    int rc = -1;
    if (fmt && !strcmp(fmt, "qrx-storage-backend-v1") && backend && !strcmp(backend, "filesystem") &&
        maxs && mins && storage_fs_parse_u64(maxs, max_usage) == 0 && storage_fs_parse_u64(mins, min_free) == 0)
        rc = 0;
    free(fmt); free(backend); free(maxs); free(mins); free(txt);
    return rc;
}

static int storage_fs_init_cmd(const char *root, const char *maxs, const char *mins) {
    uint64_t max_usage = 0, min_free = 0;
    if (storage_fs_parse_u64(maxs, &max_usage) != 0 || max_usage == 0) die("max-usage-bytes must be > 0");
    if (storage_fs_parse_u64(mins, &min_free) != 0) die("invalid min-free-space-bytes");
    mkdir_p(root);
    char path[1024], cfg[1024];
    if (storage_fs_config_path(root, path) != 0) die("storage root path too long");
    snprintf(cfg, sizeof(cfg),
             "format=qrx-storage-backend-v1\nbackend=filesystem\nmax_usage_bytes=%llu\nmin_free_space_bytes=%llu\n",
             (unsigned long long)max_usage, (unsigned long long)min_free);
    write_text(path, cfg);
    QrxStorageFs *fs = NULL;
    if (qrx_storage_fs_open(root, max_usage, min_free, &fs) != 0) die("cannot initialize filesystem storage backend");
    QrxStorageFsStats st; qrx_storage_fs_stats(fs, &st); qrx_storage_fs_close(fs);
    printf("status=initialized\nbackend=filesystem\nroot=%s\nmax_usage_bytes=%llu\nmin_free_space_bytes=%llu\nused_bytes=%llu\n",
           root, (unsigned long long)max_usage, (unsigned long long)min_free, (unsigned long long)st.used_bytes);
    return 0;
}

static QrxStorageFs *storage_fs_open_configured(const char *root) {
    uint64_t max_usage = 0, min_free = 0;
    if (storage_fs_load_config(root, &max_usage, &min_free) != 0) die("storage backend not initialized or config invalid; run storage-fs-init first");
    QrxStorageFs *fs = NULL;
    if (qrx_storage_fs_open(root, max_usage, min_free, &fs) != 0) die("cannot open filesystem storage backend");
    return fs;
}

static int storage_fs_info_cmd(const char *root) {
    QrxStorageFs *fs = storage_fs_open_configured(root); QrxStorageFsStats st;
    if (qrx_storage_fs_stats(fs, &st) != 0) { qrx_storage_fs_close(fs); die("storage stats failed"); }
    printf("backend=%s\nroot=%s\nmax_usage_bytes=%llu\nmin_free_space_bytes=%llu\nused_bytes=%llu\nreserved_bytes=%llu\nquota_available_bytes=%llu\nfilesystem_free_bytes=%llu\nobject_count=%llu\n",
           qrx_storage_fs_backend_name(), root,
           (unsigned long long)st.max_usage_bytes, (unsigned long long)st.min_free_space_bytes,
           (unsigned long long)st.used_bytes, (unsigned long long)st.reserved_bytes,
           (unsigned long long)st.quota_available_bytes, (unsigned long long)st.filesystem_free_bytes,
           (unsigned long long)st.object_count);
    qrx_storage_fs_close(fs); return 0;
}

static int storage_fs_put_cmd(const char *root, const char *source) {
    QrxStorageFs *fs = storage_fs_open_configured(root); char id[65];
    int rc = qrx_storage_fs_put_file(fs, source, id);
    qrx_storage_fs_close(fs);
    if (rc == -2) die("storage max_usage quota exceeded");
    if (rc == -3) die("storage min_free_space reserve would be violated");
    if (rc != 0) die("storage put failed");
    printf("status=stored\nobject_id=%s\nhash=SHA3-256\n", id); return 0;
}

static int storage_fs_get_cmd(const char *root, const char *id, const char *dst) {
    QrxStorageFs *fs = storage_fs_open_configured(root);
    int rc = qrx_storage_fs_get_file(fs, id, dst); qrx_storage_fs_close(fs);
    if (rc != 0) die("storage get failed");
    printf("status=retrieved\nobject_id=%s\ndestination=%s\n", id, dst); return 0;
}

static int storage_fs_delete_cmd(const char *root, const char *id) {
    QrxStorageFs *fs = storage_fs_open_configured(root);
    int rc = qrx_storage_fs_delete(fs, id); qrx_storage_fs_close(fs);
    if (rc != 0) die("storage delete failed");
    printf("status=deleted\nobject_id=%s\n", id); return 0;
}

static int storage_fs_recover_cmd(const char *root) {
    QrxStorageFs *fs = storage_fs_open_configured(root);
    if (qrx_storage_fs_recover(fs) != 0) { qrx_storage_fs_close(fs); die("storage recovery failed"); }
    QrxStorageFsStats st; qrx_storage_fs_stats(fs, &st); qrx_storage_fs_close(fs);
    printf("status=recovered\nused_bytes=%llu\nobject_count=%llu\n", (unsigned long long)st.used_bytes, (unsigned long long)st.object_count);
    return 0;
}

static int velocity_info_cmd(const char *chain_dir) {
    long long height = current_height_from_chain(chain_dir);
    printf("core_track=0.0.7-VELOCITY\n");
    printf("feature_level=%d\n", QRX_VELOCITY_FEATURE_LEVEL);
    printf("legacy_tx_version=%d\n", QRX_TX_VERSION);
    printf("velocity_tx_version=%d\n", QRX_VELOCITY_TX_VERSION);
    printf("chain_height=%lld\n", height);
    printf("legacy_tx_compatible=true\n");
    printf("nonce_lanes=true\n");
    printf("deterministic_expiry_height=true\n");
    printf("transfer_fast_executable=true\n");
    printf("agent_tx_schema=true\n");
    printf("trading_tx_schema=true\n");
    printf("agent_execution=true\n");
    printf("agent_keys_onchain=true\n");
    printf("agent_permissions=true\n");
    printf("agent_limits=true\n");
    printf("agent_revocation=true\n");
    printf("agent_signed_trading=true\n");
    printf("native_order_state=true\n");
    printf("external_order_intents=true\n");
    printf("order_cancel_replace=true\n");
    printf("agent_limit_enforcement=true\n");
    printf("execution_reports=true\n");
    printf("external_gateway_registry=true\n");
    printf("native_matching=true\n");
    printf("native_settlement=true\n");
    printf("native_settlement_crash_atomic=true\n");
    printf("crosschain_trading=true\n");
    printf("crosschain_market=BTC/QUB\n");
    printf("crosschain_htlc=SHA256_P2WSH_CSV\n");
    printf("crosschain_qbtc_required=false\n");
    printf("crosschain_bitcoin_spv_consensus=true\nbitcoin_spv_phase=3D.1\nbitcoin_spv_headers_on_qrx_consensus=true\nbitcoin_spv_merkle_proofs=true\nbitcoin_spv_reorg_tracking=true\n");
    printf("settlement_qrxdb_wal=true\n");
    printf("settlement_state_root=true\n");
    printf("outer_apply_wal_atomic=true\n");
    printf("fee_nonce_applied_atomic=true\n");
    printf("qrxdb_authoritative_apply_state=true\n");
    printf("legacy_state_mirrors_non_authoritative=true\n");
    printf("pending_native_match_recovery=true\n");
    printf("native_asset_ledger=true\n");
    printf("native_stablecoins=false\n");
    printf("velocity_phase=4\n");
    printf("ram_mempool=true\n");
    printf("mempool_wal=true\n");
    printf("mempool_shards=%u\n", QRX_VELOCITY_MEMPOOL_SHARDS);
    printf("mempool_max_txs=%d\n", QRX_MAX_MEMPOOL_TX);
    printf("parallel_signature_verification=true\n");
    printf("conflict_detection=true\n");
    printf("conflict_aware_execution_waves=true\n");
    printf("deterministic_mempool_order=fee_desc_txid_asc\n");
    printf("deterministic_commit=true\n");
    printf("qrxdb_wal_commit=true\n");
    printf("parallel_execution=true\n");
    printf("parallel_state_mutation=false\n");
    printf("parallel_execution_model=parallel_prevalidation_conflict_waves_serial_atomic_state_commit\n");
    return 0;
}

static int getnoncelanes_cmd(const char *chain_dir, const char *addr) {
    if (!addr || !*addr) die("missing address");
    printf("lane=0 nonce=%lld\n", velocity_get_lane_nonce(chain_dir, addr, 0));
    char path[1024];
    velocity_lane_nonce_path(chain_dir, path, sizeof(path));
    StateKVRecord *arr = NULL; size_t count = 0;
    if (kv_load(path, &arr, &count) != 0) return 0;
    size_t prefix_len = strlen(addr);
    for (size_t i = 0; i < count; ++i) {
        if (!strncmp(arr[i].key, addr, prefix_len) && arr[i].key[prefix_len] == '|') {
            const char *lane = arr[i].key + prefix_len + 1;
            printf("lane=%s nonce=%lld\n", lane, arr[i].value);
        }
    }
    free(arr);
    return 0;
}


static int create_velocity_raw_tx_cmd(const char *chain_dir, const char *from, const char *to, const char *amount,
    const char *ed_pub_hex, const char *mldsa_pub_b64, const char *tx_type, const char *lane_s,
    const char *expiry_height_s, const char *payload, const char *fee, const char *nonce);

static char *velocity_qrxdb_get_alloc(const char *chain_dir, const char *key);
static int velocity_qrxdb_put(const char *chain_dir, const char *key, const char *value);
static int velocity_batch_put_ll(QrxDBBatch *b,const char *key,long long value);
static int atomic_batch_put_balance(QrxDBBatch *b,const char *address,long long value);
static int atomic_stage_order_payload(QrxDBBatch *b,const char *order_id,const char *agent,const char *owner,const char *kind,const char *status,const char *payload,const char *body_hash,const char *replaces,long long h);
static int atomic_stage_agent_usage(QrxDBBatch *b,const char *chain_dir,const char *agent,long long qty);
static int atomic_stage_asset_value(QrxDBBatch *b,const char *asset,const char *owner,long long value);
static int mirror_order_from_authoritative(const char *chain_dir,const char *oid);

static void agent_registry_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/agents.db", chain_dir);
}

static int text_db_set(const char *path, const char *key, const char *value) {
    char *txt = read_file(path, NULL);
    FILE *f = fopen(path, "wb");
    if (!f) { if (txt) free(txt); return -1; }
    size_t klen = strlen(key);
    int wrote = 0;
    if (txt) {
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n');
            size_t len = e ? (size_t)(e - cur) : strlen(cur);
            if (len > klen && !strncmp(cur, key, klen) && cur[klen] == '=') {
                fprintf(f, "%s=%s\n", key, value ? value : "");
                wrote = 1;
            } else if (len) {
                fwrite(cur, 1, len, f);
                fputc('\n', f);
            }
            cur = e ? e + 1 : NULL;
        }
        free(txt);
    }
    if (!wrote) fprintf(f, "%s=%s\n", key, value ? value : "");
    fclose(f);
    return 0;
}

static char *text_db_get(const char *path, const char *key) {
    char *txt = read_file(path, NULL);
    if (!txt) return NULL;
    char *v = cfg_get(txt, key);
    free(txt);
    return v;
}

static int agent_make_key(char *out, size_t out_sz, const char *agent, const char *field) {
    if (!agent || !*agent || strchr(agent, '\n') || strchr(agent, '=') || strchr(agent, '|')) return -1;
    snprintf(out, out_sz, "agent.%s.%s", agent, field);
    return 0;
}

static void velocity_agent_key(char *out,size_t out_sz,const char *agent,const char *field){
    snprintf(out,out_sz,"velocity:agent:%s:%s",agent,field);
}

static char *agent_db_get_field(const char *chain_dir, const char *agent, const char *field) {
    char qkey[1024]; velocity_agent_key(qkey,sizeof(qkey),agent,field);
    char *qv=velocity_qrxdb_get_alloc(chain_dir,qkey);
    if(qv) return qv;
    char path[1024], key[768];
    agent_registry_path(chain_dir, path, sizeof(path));
    if (agent_make_key(key, sizeof(key), agent, field) != 0) return NULL;
    return text_db_get(path, key);
}

static int agent_db_set_field(const char *chain_dir, const char *agent, const char *field, const char *value) {
    char path[1024], key[768];
    agent_registry_path(chain_dir, path, sizeof(path));
    if (agent_make_key(key, sizeof(key), agent, field) != 0) return -1;
    return text_db_set(path, key, value ? value : "");
}

static char *payload_get_field(const char *payload, const char *key) {
    if (!payload || !key || !*key) return NULL;
    size_t klen = strlen(key);
    const char *cur = payload;
    while (cur && *cur) {
        while (*cur == ';') cur++;
        const char *e = strchr(cur, ';');
        size_t len = e ? (size_t)(e - cur) : strlen(cur);
        if (len > klen && !strncmp(cur, key, klen) && cur[klen] == '=') {
            size_t vlen = len - klen - 1;
            char *v = malloc(vlen + 1);
            if (!v) die("oom");
            memcpy(v, cur + klen + 1, vlen);
            v[vlen] = 0;
            return v;
        }
        cur = e ? e + 1 : NULL;
    }
    return NULL;
}

static void validate_payload_clean(const char *payload, const char *field) {
    if (!payload || !*payload) die("missing %s", field);
    if (strchr(payload, '\n') || strchr(payload, '\r')) die("invalid %s", field);
}

static void validate_agent_pubkeys_match_address(const char *agent_address, const char *ed_pub_hex, const char *ml_pub_b64) {
    if (!agent_address || !*agent_address) die("missing agent address");
    if (!ed_pub_hex || !*ed_pub_hex) die("missing agent ed25519 pubkey");
    if (!ml_pub_b64 || !*ml_pub_b64) die("missing agent mldsa pubkey");
    unsigned char edraw[32]; size_t edlen = 0;
    if (hex_to_bytes(ed_pub_hex, edraw, sizeof(edraw), &edlen) != 0 || edlen != 32) die("invalid agent ed25519 pubkey");
    EVP_PKEY *ed_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, edraw, edlen);
    if (!ed_pub) die("agent ed25519 pubkey construct failed");
    if (address_matches_pub(ed_pub, agent_address) != 0) die("agent address does not match agent ed25519 pubkey");
    EVP_PKEY_free(ed_pub);
    size_t mlpemlen = 0; unsigned char *mlpem = base64_decode(ml_pub_b64, &mlpemlen);
    if (!mlpem) die("invalid agent mldsa pubkey b64");
    char *mlpemstr = malloc(mlpemlen + 1); if (!mlpemstr) die("oom");
    memcpy(mlpemstr, mlpem, mlpemlen); mlpemstr[mlpemlen] = 0;
    EVP_PKEY *ml_pub = pubkey_from_pem_string(mlpemstr);
    if (!ml_pub) die("agent mldsa pubkey parse failed");
    EVP_PKEY_free(ml_pub);
    free(mlpem); free(mlpemstr);
}

static void validate_agent_fields_common(const char *chain_dir, const char *owner, const char *agent, const char *tx_type, const char *payload) {
    validate_payload_clean(payload, "agent payload");
    long long h = current_height_from_chain(chain_dir);
    char *existing_owner = agent_db_get_field(chain_dir, agent, "owner");
    char *existing_status = agent_db_get_field(chain_dir, agent, "status");
    int exists = existing_owner && *existing_owner;
    int active = exists && (!existing_status || strcmp(existing_status, "revoked") != 0);
    if (!strcmp(tx_type, "AGENT_REGISTER")) {
        if (active) die("agent already registered and active");
        char *ed = payload_get_field(payload, "agent_ed25519_pub_hex");
        char *ml = payload_get_field(payload, "agent_mldsa65_pub_b64");
        char *perm = payload_get_field(payload, "permissions");
        char *max_trade = payload_get_field(payload, "max_trade_atoms");
        char *daily = payload_get_field(payload, "daily_limit_atoms");
        char *markets = payload_get_field(payload, "market_allowlist");
        char *exp = payload_get_field(payload, "expires_height");
        if (!perm || !*perm || !markets || !*markets) die("agent payload missing permissions or market_allowlist");
        parse_nonnegative_ll_strict(max_trade, "max_trade_atoms");
        parse_nonnegative_ll_strict(daily, "daily_limit_atoms");
        long long eh = parse_positive_ll_strict(exp, "agent expires_height");
        if (eh <= h) die("agent expires_height must be greater than current chain height");
        validate_agent_pubkeys_match_address(agent, ed, ml);
        free(ed); free(ml); free(perm); free(max_trade); free(daily); free(markets); free(exp);
    } else if (!strcmp(tx_type, "AGENT_UPDATE")) {
        if (!active) die("agent not active");
        if (!existing_owner || strcmp(existing_owner, owner) != 0) die("agent owner mismatch");
        char *perm = payload_get_field(payload, "permissions");
        char *max_trade = payload_get_field(payload, "max_trade_atoms");
        char *daily = payload_get_field(payload, "daily_limit_atoms");
        char *markets = payload_get_field(payload, "market_allowlist");
        char *exp = payload_get_field(payload, "expires_height");
        if (!perm || !*perm || !markets || !*markets) die("agent update missing permissions or market_allowlist");
        parse_nonnegative_ll_strict(max_trade, "max_trade_atoms");
        parse_nonnegative_ll_strict(daily, "daily_limit_atoms");
        long long eh = parse_positive_ll_strict(exp, "agent expires_height");
        if (eh <= h) die("agent expires_height must be greater than current chain height");
        free(perm); free(max_trade); free(daily); free(markets); free(exp);
    } else if (!strcmp(tx_type, "AGENT_REVOKE")) {
        if (!active) die("agent not active");
        if (!existing_owner || strcmp(existing_owner, owner) != 0) die("agent owner mismatch");
    }
    if (existing_owner) free(existing_owner);
    if (existing_status) free(existing_status);
}

static int agent_apply_tx(const char *chain_dir, const char *owner, const char *agent, const char *tx_type, const char *payload, const char *body_hash) {
    long long h = current_height_from_chain(chain_dir);
    char hbuf[32]; snprintf(hbuf, sizeof(hbuf), "%lld", h);
    if (!strcmp(tx_type, "AGENT_REGISTER") || !strcmp(tx_type, "AGENT_UPDATE")) {
        char *ed = payload_get_field(payload, "agent_ed25519_pub_hex");
        char *ml = payload_get_field(payload, "agent_mldsa65_pub_b64");
        char *perm = payload_get_field(payload, "permissions");
        char *max_trade = payload_get_field(payload, "max_trade_atoms");
        char *daily = payload_get_field(payload, "daily_limit_atoms");
        char *markets = payload_get_field(payload, "market_allowlist");
        char *exp = payload_get_field(payload, "expires_height");
        if (agent_db_set_field(chain_dir, agent, "owner", owner) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "status", "active") != 0) return -1;
        if (ed && agent_db_set_field(chain_dir, agent, "ed25519_pub_hex", ed) != 0) return -1;
        if (ml && agent_db_set_field(chain_dir, agent, "mldsa65_pub_b64", ml) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "permissions", perm) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "max_trade_atoms", max_trade) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "daily_limit_atoms", daily) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "market_allowlist", markets) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "expires_height", exp) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "updated_height", hbuf) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "last_tx", body_hash ? body_hash : "") != 0) return -1;
        if (ed) free(ed); if (ml) free(ml); free(perm); free(max_trade); free(daily); free(markets); free(exp);
        return 0;
    }
    if (!strcmp(tx_type, "AGENT_REVOKE")) {
        if (agent_db_set_field(chain_dir, agent, "status", "revoked") != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "revoked_height", hbuf) != 0) return -1;
        if (agent_db_set_field(chain_dir, agent, "last_tx", body_hash ? body_hash : "") != 0) return -1;
        return 0;
    }
    return -1;
}

static int agent_status_cmd(const char *chain_dir, const char *agent) {
    if (!agent || !*agent) die("missing agent address");
    const char *fields[] = {"owner","status","permissions","max_trade_atoms","daily_limit_atoms","market_allowlist","expires_height","updated_height","revoked_height","last_tx","ed25519_pub_hex","mldsa65_pub_b64",NULL};
    for (int i = 0; fields[i]; ++i) {
        char *v = agent_db_get_field(chain_dir, agent, fields[i]);
        if (v) { printf("%s=%s\n", fields[i], v); free(v); }
    }
    return 0;
}

static int list_agents_cmd(const char *chain_dir, const char *owner_filter) {
    char path[1024]; agent_registry_path(chain_dir, path, sizeof(path));
    char *txt = read_file(path, NULL); if (!txt) return 0;
    const char *cur = txt;
    while (cur && *cur) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e - cur) : strlen(cur);
        const char suffix[] = ".owner=";
        const char *suf = NULL;
        if (len > 6 && !strncmp(cur, "agent.", 6)) {
            for (size_t i = 6; i + strlen(suffix) < len; ++i) {
                if (!strncmp(cur + i, suffix, strlen(suffix))) { suf = cur + i; break; }
            }
        }
        if (suf) {
            size_t agent_len = (size_t)(suf - (cur + 6));
            size_t owner_len = len - ((suf + strlen(suffix)) - cur);
            char agent[512], owner[512];
            if (agent_len >= sizeof(agent)) agent_len = sizeof(agent) - 1;
            if (owner_len >= sizeof(owner)) owner_len = sizeof(owner) - 1;
            memcpy(agent, cur + 6, agent_len); agent[agent_len] = 0;
            memcpy(owner, suf + strlen(suffix), owner_len); owner[owner_len] = 0;
            if (!owner_filter || !*owner_filter || !strcmp(owner_filter, owner)) printf("agent=%s owner=%s\n", agent, owner);
        }
        cur = e ? e + 1 : NULL;
    }
    free(txt); return 0;
}

static int create_agent_register_raw_tx_cmd(const char *chain_dir, const char *owner, const char *agent, const char *agent_ed, const char *agent_ml,
    const char *permissions, const char *max_trade, const char *daily_limit, const char *markets, const char *agent_exp,
    const char *owner_ed, const char *owner_ml, const char *lane, const char *tx_exp, const char *fee, const char *nonce) {
    char payload[8192];
    snprintf(payload, sizeof(payload), "agent_ed25519_pub_hex=%s;agent_mldsa65_pub_b64=%s;permissions=%s;max_trade_atoms=%s;daily_limit_atoms=%s;market_allowlist=%s;expires_height=%s",
        agent_ed, agent_ml, permissions, max_trade, daily_limit, markets, agent_exp);
    return create_velocity_raw_tx_cmd(chain_dir, owner, agent, "0", owner_ed, owner_ml, "AGENT_REGISTER", lane, tx_exp, payload, fee, nonce);
}

static int create_agent_update_raw_tx_cmd(const char *chain_dir, const char *owner, const char *agent,
    const char *permissions, const char *max_trade, const char *daily_limit, const char *markets, const char *agent_exp,
    const char *owner_ed, const char *owner_ml, const char *lane, const char *tx_exp, const char *fee, const char *nonce) {
    char payload[4096];
    snprintf(payload, sizeof(payload), "permissions=%s;max_trade_atoms=%s;daily_limit_atoms=%s;market_allowlist=%s;expires_height=%s",
        permissions, max_trade, daily_limit, markets, agent_exp);
    return create_velocity_raw_tx_cmd(chain_dir, owner, agent, "0", owner_ed, owner_ml, "AGENT_UPDATE", lane, tx_exp, payload, fee, nonce);
}

static int create_agent_revoke_raw_tx_cmd(const char *chain_dir, const char *owner, const char *agent,
    const char *owner_ed, const char *owner_ml, const char *lane, const char *tx_exp, const char *fee, const char *nonce) {
    return create_velocity_raw_tx_cmd(chain_dir, owner, agent, "0", owner_ed, owner_ml, "AGENT_REVOKE", lane, tx_exp, "reason=owner_revoked", fee, nonce);
}

/* === VELOCITY 0.0.7 Phase 3B: deterministic native matching + settlement === */
#define QRX_TRADE_PRICE_SCALE 100000000LL

static void validate_simple_payload_value(const char *value, const char *field);

typedef struct {
    char id[160];
    char owner[512];
    char side[16];
    long long price;
    long long remaining;
    long long created_height;
} QrxMatchOrder;


static char *velocity_qrxdb_get_alloc(const char *chain_dir, const char *key) {
    QrxDB db; char buf[8192];
    if (qrxdb_init(&db, chain_dir) != 0) return NULL;
    int rc = qrxdb_get(&db, key, buf, sizeof(buf));
    qrxdb_close(&db);
    return rc == 0 ? strdup(buf) : NULL;
}

static int velocity_qrxdb_put(const char *chain_dir, const char *key, const char *value) {
    QrxDB db;
    if (qrxdb_init(&db, chain_dir) != 0) return -1;
    int rc = qrxdb_put(&db, key, value ? value : "");
    qrxdb_close(&db);
    return rc;
}

static void velocity_order_key(char *out,size_t out_sz,const char *order_id,const char *field){
    snprintf(out,out_sz,"velocity:order:%s:%s",order_id,field);
}
static void velocity_trade_key(char *out,size_t out_sz,const char *trade_id,const char *field){
    snprintf(out,out_sz,"velocity:trade:%s:%s",trade_id,field);
}
static void velocity_asset_balance_key(char *out,size_t out_sz,const char *asset,const char *address){
    snprintf(out,out_sz,"velocity:asset:balance:%s:%s",asset,address);
}

static void order_registry_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/orders.db", chain_dir);
}

static void trade_registry_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/trades.db", chain_dir);
}

static void asset_registry_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/assets.db", chain_dir);
}

static void asset_balance_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/asset_balances.bin", chain_dir);
}

static void agent_usage_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/agent_usage.bin", chain_dir);
}

static void trade_sequence_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/trade_sequence.bin", chain_dir);
}

static int token_list_contains_ci(const char *list, const char *needle) {
    if (!list || !needle || !*needle) return 0;
    const char *cur = list;
    while (*cur) {
        while (*cur == ',' || *cur == '|' || isspace((unsigned char)*cur)) cur++;
        const char *end = cur;
        while (*end && *end != ',' && *end != '|') end++;
        const char *trim_end = end;
        while (trim_end > cur && isspace((unsigned char)trim_end[-1])) trim_end--;
        size_t n = (size_t)(trim_end - cur);
        if ((n == 1 && cur[0] == '*') || (n == strlen(needle) && !strncasecmp(cur, needle, n))) return 1;
        cur = *end ? end + 1 : end;
    }
    return 0;
}

static int order_make_key(char *out, size_t out_sz, const char *order_id, const char *field) {
    if (!order_id || !*order_id || !field || !*field || strchr(order_id, '\n') || strchr(order_id, '=') || strchr(order_id, '|')) return -1;
    snprintf(out, out_sz, "order.%s.%s", order_id, field);
    return 0;
}

static char *order_db_get_field(const char *chain_dir, const char *order_id, const char *field) {
    char qkey[1024]; velocity_order_key(qkey,sizeof(qkey),order_id,field);
    char *v=velocity_qrxdb_get_alloc(chain_dir,qkey);
    if(v) return v;
    char path[1024], key[768];
    order_registry_path(chain_dir, path, sizeof(path));
    if (order_make_key(key, sizeof(key), order_id, field) != 0) return NULL;
    return text_db_get(path, key);
}

static int order_db_set_field(const char *chain_dir, const char *order_id, const char *field, const char *value) {
    char path[1024], key[768], qkey[1024];
    order_registry_path(chain_dir, path, sizeof(path));
    if (order_make_key(key, sizeof(key), order_id, field) != 0) return -1;
    velocity_order_key(qkey,sizeof(qkey),order_id,field);
    if(velocity_qrxdb_put(chain_dir,qkey,value?value:"")!=0) return -1;
    return text_db_set(path, key, value ? value : "");
}

static int order_db_set_ll(const char *chain_dir, const char *order_id, const char *field, long long value) {
    char buf[64]; snprintf(buf, sizeof(buf), "%lld", value);
    return order_db_set_field(chain_dir, order_id, field, buf);
}

static long long order_db_get_ll(const char *chain_dir, const char *order_id, const char *field, long long fallback) {
    char *v = order_db_get_field(chain_dir, order_id, field);
    if (!v || !*v) { if (v) free(v); return fallback; }
    char *end = NULL; errno = 0; long long n = strtoll(v, &end, 10);
    int ok = !errno && end && !*end; free(v); return ok ? n : fallback;
}

static int trade_make_key(char *out, size_t out_sz, const char *trade_id, const char *field) {
    if (!trade_id || !*trade_id || !field || !*field || strchr(trade_id, '\n') || strchr(trade_id, '=') || strchr(trade_id, '|')) return -1;
    snprintf(out, out_sz, "trade.%s.%s", trade_id, field);
    return 0;
}

static char *trade_db_get_field(const char *chain_dir, const char *trade_id, const char *field) {
    char qkey[1024]; velocity_trade_key(qkey,sizeof(qkey),trade_id,field);
    char *v=velocity_qrxdb_get_alloc(chain_dir,qkey);
    if(v) return v;
    char path[1024], key[768]; trade_registry_path(chain_dir, path, sizeof(path));
    if (trade_make_key(key, sizeof(key), trade_id, field) != 0) return NULL;
    return text_db_get(path, key);
}

static int trade_db_set_field(const char *chain_dir, const char *trade_id, const char *field, const char *value) {
    char path[1024], key[768], qkey[1024]; trade_registry_path(chain_dir, path, sizeof(path));
    if (trade_make_key(key, sizeof(key), trade_id, field) != 0) return -1;
    velocity_trade_key(qkey,sizeof(qkey),trade_id,field);
    if(velocity_qrxdb_put(chain_dir,qkey,value?value:"")!=0) return -1;
    return text_db_set(path, key, value ? value : "");
}

static int asset_id_valid(const char *asset) {
    if (!asset) return 0; size_t n = strlen(asset); if (n < 2 || n > 24) return 0;
    for (size_t i=0;i<n;++i) if (!(isalnum((unsigned char)asset[i]) || asset[i]=='_' || asset[i]=='-')) return 0;
    return 1;
}

static void asset_id_normalize(const char *asset, char *out, size_t out_sz) {
    size_t i=0; if (!out_sz) return;
    for (; asset && asset[i] && i+1<out_sz; ++i) out[i]=(char)toupper((unsigned char)asset[i]);
    out[i]=0;
}

static int asset_exists(const char *chain_dir, const char *asset) {
    char a[128]; snprintf(a,sizeof(a),"%s",asset?asset:"");
    if (!strcasecmp(a,"QUB")) return 1;
    if(!*a || strchr(a,'\n') || strchr(a,'\r') || strchr(a,';') || strchr(a,':')) return 0;
    QrxDB db; char qkey[512],buf[64];
    if(qrxdb_init(&db,chain_dir)==0){snprintf(qkey,sizeof(qkey),"asset76:meta:%s:status",a);if(qrxdb_get(&db,qkey,buf,sizeof(buf))==0){qrxdb_close(&db);return !strcmp(buf,"active");}qrxdb_close(&db);}
    char an[32]; asset_id_normalize(asset,an,sizeof(an));
    if (!asset_id_valid(an)) return 0;
    char path[1024], key[128]; asset_registry_path(chain_dir,path,sizeof(path)); snprintf(key,sizeof(key),"asset.%s.status",an);
    char *v=text_db_get(path,key); int ok=v && !strcmp(v,"active"); if(v)free(v); return ok;
}

static int asset_register_cmd(const char *chain_dir, const char *asset, const char *name) {
    require_manual_mint_allowed(chain_dir, "asset-register");
    char a[32]; asset_id_normalize(asset,a,sizeof(a)); if(!asset_id_valid(a)) die("invalid asset id");
    if(!strcmp(a,"QUB")) die("QUB is built in"); validate_simple_payload_value(name,"asset name");
    char path[1024], key[128]; asset_registry_path(chain_dir,path,sizeof(path));
    snprintf(key,sizeof(key),"asset.%s.status",a); if(text_db_set(path,key,"active")) die("asset registry write failed");
    snprintf(key,sizeof(key),"asset.%s.name",a); if(text_db_set(path,key,name)) die("asset registry write failed");
    snprintf(key,sizeof(key),"asset.%s.decimals",a); if(text_db_set(path,key,"8")) die("asset registry write failed");
    printf("asset=%s\nstatus=active\ndecimals=8\n",a); return 0;
}

static long long asset_balance_get(const char *chain_dir, const char *asset, const char *address) {
    char a[32]; asset_id_normalize(asset,a,sizeof(a));
    QrxDB db; long long qv=0;
    if(qrxdb_init(&db,chain_dir)==0){
        if(!strcmp(a,"QUB")){
            if(qrxdb_chain_get_balance(&db,address,&qv)==0){ qrxdb_close(&db); return qv; }
        } else {
            char qkey[1024],buf[128]; velocity_asset_balance_key(qkey,sizeof(qkey),a,address);
            if(qrxdb_get(&db,qkey,buf,sizeof(buf))==0){ qrxdb_close(&db); return atoll(buf); }
        }
        qrxdb_close(&db);
    }
    if(!strcmp(a,"QUB")){ char bal[1024]; state_paths(chain_dir,bal,sizeof(bal),NULL,0,NULL,0,NULL,0); return kv_get_ll_bin(bal,address); }
    char path[1024], key[768]; asset_balance_path(chain_dir,path,sizeof(path)); snprintf(key,sizeof(key),"%s|%s",a,address); return kv_get_ll_bin(path,key);
}

static int asset_balance_set(const char *chain_dir, const char *asset, const char *address, long long value) {
    if(value<0) return -1; char a[32]; asset_id_normalize(asset,a,sizeof(a));
    QrxDB db; if(qrxdb_init(&db,chain_dir)!=0) return -1;
    int qrc=0;
    if(!strcmp(a,"QUB")) qrc=qrxdb_chain_set_balance(&db,address,value);
    else { char qkey[1024],buf[64]; velocity_asset_balance_key(qkey,sizeof(qkey),a,address); snprintf(buf,sizeof(buf),"%lld",value); qrc=qrxdb_put(&db,qkey,buf); }
    qrxdb_close(&db); if(qrc) return -1;
    if(!strcmp(a,"QUB")){ char bal[1024]; state_paths(chain_dir,bal,sizeof(bal),NULL,0,NULL,0,NULL,0); return kv_set_ll_bin(bal,address,value); }
    char path[1024],key[768]; asset_balance_path(chain_dir,path,sizeof(path)); snprintf(key,sizeof(key),"%s|%s",a,address); return kv_set_ll_bin(path,key,value);
}

static int asset_balance_adjust(const char *chain_dir,const char *asset,const char *address,long long delta){
    long long cur=asset_balance_get(chain_dir,asset,address),next=0; checked_add_ll(cur,delta,"asset balance",&next); if(next<0)return -1; return asset_balance_set(chain_dir,asset,address,next);
}

static int asset_credit_cmd(const char *chain_dir,const char *asset,const char *address,long long amount){
    require_manual_mint_allowed(chain_dir,"asset-credit"); if(amount<=0)die("asset credit amount must be > 0");
    char a[32];asset_id_normalize(asset,a,sizeof(a));if(!strcmp(a,"QUB"))die("use faucet for QUB");if(!asset_exists(chain_dir,a))die("asset is not registered");
    if(asset_balance_adjust(chain_dir,a,address,amount))die("asset credit failed"); printf("%lld\n",asset_balance_get(chain_dir,a,address)); return 0;
}

static int asset_balance_cmd(const char *chain_dir,const char *asset,const char *address){
    if(!asset_exists(chain_dir,asset))die("asset is not registered"); printf("%lld\n",asset_balance_get(chain_dir,asset,address)); return 0;
}

static int a76_list_consensus_cb(const char *key,const char *value,uint32_t value_len,void *ctx){(void)value_len;(void)ctx;const char*pfx="asset76:meta:";size_t pl=strlen(pfx),kl=strlen(key),sl=strlen(":status");if(strncmp(key,pfx,pl)||kl<=pl+sl||strcmp(key+kl-sl,":status")||strcmp(value,"active"))return 0;printf("asset=%.*s status=active consensus_asset=true\n",(int)(kl-pl-sl),key+pl);return 0;}
static int list_assets_cmd(const char *chain_dir){
    puts("asset=QUB name=QUBITCOIN decimals=8 status=active native=true");
    char path[1024];asset_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);const char *cur=txt;const char suffix[]=".status=";
    while(cur&&*cur){const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);if(len>6&&!strncmp(cur,"asset.",6)){
        const char *suf=NULL;for(size_t i=6;i+strlen(suffix)<len;++i)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}
        if(suf){size_t alen=(size_t)(suf-(cur+6));char a[32];if(alen<sizeof(a)){memcpy(a,cur+6,alen);a[alen]=0;if(strncmp(suf+strlen(suffix),"active",6)==0){char key[128];snprintf(key,sizeof(key),"asset.%s.name",a);char *name=text_db_get(path,key);printf("asset=%s name=%s decimals=8 status=active native=true\n",a,name?name:"");if(name)free(name);}}}}
        cur=e?e+1:NULL;
    }if(txt)free(txt);QrxDB adb;if(qrxdb_init(&adb,chain_dir)==0){qrxdb_scan_prefix(&adb,"asset76:meta:",a76_list_consensus_cb,NULL);qrxdb_close(&adb);}return 0;
}

static int parse_native_market(const char *chain_dir,const char *market,char *base,size_t bsz,char *quote,size_t qsz){
    if(!market||!*market)return -1;const char *slash=strchr(market,'/');if(!slash||strchr(slash+1,'/'))return -1;size_t bl=(size_t)(slash-market),ql=strlen(slash+1);if(!bl||!ql||bl>=bsz||ql>=qsz)return -1;
    char rb[32],rq[32];if(bl>=sizeof(rb)||ql>=sizeof(rq))return -1;memcpy(rb,market,bl);rb[bl]=0;memcpy(rq,slash+1,ql+1);asset_id_normalize(rb,base,bsz);asset_id_normalize(rq,quote,qsz);
    if(!asset_id_valid(base)||!asset_id_valid(quote)||!strcmp(base,quote))return -1;if(!asset_exists(chain_dir,base)||!asset_exists(chain_dir,quote))return -2;return 0;
}

/* Exact, overflow-safe floor(a*b/d) for non-negative signed-64 values, without __int128 (MSVC-safe). */
static int mul_div_floor_nonneg(long long a,long long b,long long d,long long *out){
    if(a<0||b<0||d<=0||!out)return -1; unsigned long long q=0,rem=0,ub=(unsigned long long)b,ud=(unsigned long long)d,base_q=ub/ud,base_r=ub%ud,ua=(unsigned long long)a;
    for(int i=62;i>=0;--i){
        if(q>(unsigned long long)LLONG_MAX/2ULL)return -1;q*=2ULL;rem*=2ULL;if(rem>=ud){rem-=ud;if(q>=(unsigned long long)LLONG_MAX)return -1;q++;}
        if((ua>>i)&1ULL){if(q>(unsigned long long)LLONG_MAX-base_q)return -1;q+=base_q;rem+=base_r;if(rem>=ud){rem-=ud;if(q>=(unsigned long long)LLONG_MAX)return -1;q++;}}
    }*out=(long long)q;return 0;
}

static long long quote_for_quantity(long long qty,long long price){long long q=0;if(qty<=0||price<=0||mul_div_floor_nonneg(qty,price,QRX_TRADE_PRICE_SCALE,&q)||q<=0)die("native trade quote amount is zero or overflows");return q;}

static long long agent_usage_epoch_blocks(const char *chain_dir) {
    long long h = current_height_from_chain(chain_dir);
    long long block_time = qrx_chain_get_ll_at_height_or_default(chain_dir, h, "block_time_seconds", 10LL);
    if (block_time <= 0) block_time = 10;
    long long blocks = (86400LL + block_time - 1LL) / block_time;
    return blocks > 0 ? blocks : 1;
}

static long long agent_usage_current(const char *chain_dir, const char *agent, long long *bucket_out, long long *epoch_blocks_out) {
    long long h = current_height_from_chain(chain_dir);
    long long epoch_blocks = agent_usage_epoch_blocks(chain_dir);
    long long bucket = h / epoch_blocks;
    char qkey[768],buf[128]; snprintf(qkey,sizeof(qkey),"velocity:agent_usage:%s:%lld",agent,bucket);
    QrxDB db;if(qrxdb_init(&db,chain_dir)==0){if(qrxdb_get(&db,qkey,buf,sizeof(buf))==0){long long n=atoll(buf);qrxdb_close(&db);if(bucket_out)*bucket_out=bucket;if(epoch_blocks_out)*epoch_blocks_out=epoch_blocks;return n;}qrxdb_close(&db);}
    char path[1024], key[512]; agent_usage_path(chain_dir, path, sizeof(path)); snprintf(key, sizeof(key), "%s|%lld", agent, bucket);
    if (bucket_out) *bucket_out = bucket; if (epoch_blocks_out) *epoch_blocks_out = epoch_blocks; return kv_get_ll_bin(path, key);
}

static int agent_usage_add(const char *chain_dir, const char *agent, long long quantity_atoms) {
    if (quantity_atoms <= 0) return 0; long long bucket = 0; long long cur = agent_usage_current(chain_dir, agent, &bucket, NULL), next = 0;
    checked_add_ll(cur, quantity_atoms, "agent usage", &next); char path[1024], key[512]; agent_usage_path(chain_dir, path, sizeof(path)); snprintf(key, sizeof(key), "%s|%lld", agent, bucket); return kv_set_ll_bin(path, key, next);
}

static int order_status_is_live(const char *status) { return status && (!strcmp(status,"open") || !strcmp(status,"partially_filled") || !strcmp(status,"pending_execution") || !strcmp(status,"submitted")); }
static int native_order_status_is_live(const char *status) { return status && (!strcmp(status,"open") || !strcmp(status,"partially_filled")); }

static void validate_simple_payload_value(const char *value, const char *field) {
    if (!value || !*value) die("missing %s", field);
    if (strchr(value, '\n') || strchr(value, '\r') || strchr(value, ';') || strchr(value, '=')) die("invalid %s", field);
}

static void agent_assert_trade_authorized(const char *chain_dir, const char *agent, const char *owner,
    const char *market, const char *permission, long long quantity_atoms, int enforce_limits,
    const char *tx_ed_pub_hex, const char *tx_ml_pub_b64) {
    char *stored_owner = agent_db_get_field(chain_dir, agent, "owner"); char *status = agent_db_get_field(chain_dir, agent, "status");
    char *permissions = agent_db_get_field(chain_dir, agent, "permissions"); char *markets = agent_db_get_field(chain_dir, agent, "market_allowlist");
    char *max_trade_s = agent_db_get_field(chain_dir, agent, "max_trade_atoms"); char *daily_s = agent_db_get_field(chain_dir, agent, "daily_limit_atoms");
    char *expires_s = agent_db_get_field(chain_dir, agent, "expires_height"); char *stored_ed = agent_db_get_field(chain_dir, agent, "ed25519_pub_hex"); char *stored_ml = agent_db_get_field(chain_dir, agent, "mldsa65_pub_b64");
    if (!stored_owner || !*stored_owner) die("trading agent is not registered"); if (!owner || strcmp(owner, stored_owner) != 0) die("trading agent owner mismatch");
    if (!status || strcmp(status, "active") != 0) die("trading agent is not active"); long long expires = parse_positive_ll_strict(expires_s, "agent expires_height"); if (current_height_from_chain(chain_dir) >= expires) die("trading agent authorization expired");
    int explicit_only = !strcmp(permission, "ARBITRAGE_CROSS_VENUE");
    if (!permissions || !(token_list_contains_ci(permissions, permission) || token_list_contains_ci(permissions, "*") || (!explicit_only && token_list_contains_ci(permissions, "TRADE")))) die("agent lacks trading permission");
    if (!markets || !(token_list_contains_ci(markets, market) || token_list_contains_ci(markets, "*"))) die("market is not in agent allowlist");
    if (!stored_ed || !tx_ed_pub_hex || strcmp(stored_ed, tx_ed_pub_hex) != 0) die("agent ed25519 key differs from owner-authorized key"); if (!stored_ml || !tx_ml_pub_b64 || strcmp(stored_ml, tx_ml_pub_b64) != 0) die("agent ML-DSA key differs from owner-authorized key");
    if (enforce_limits) { long long max_trade=parse_nonnegative_ll_strict(max_trade_s,"max_trade_atoms"),daily_limit=parse_nonnegative_ll_strict(daily_s,"daily_limit_atoms"); if(quantity_atoms<=0)die("trade quantity must be > 0");if(quantity_atoms>max_trade)die("agent max_trade_atoms exceeded");long long used=agent_usage_current(chain_dir,agent,NULL,NULL),next=0;checked_add_ll(used,quantity_atoms,"daily agent usage",&next);if(next>daily_limit)die("agent daily_limit_atoms exceeded"); }
    free(stored_owner);if(status)free(status);if(permissions)free(permissions);if(markets)free(markets);if(max_trade_s)free(max_trade_s);if(daily_s)free(daily_s);if(expires_s)free(expires_s);if(stored_ed)free(stored_ed);if(stored_ml)free(stored_ml);
}

static int native_order_lock_requirements(const char *chain_dir,const char *owner,const char *market,const char *side,long long qty,long long price,char *asset,size_t asz,long long *atoms){
    char base[32],quote[32];int rc=parse_native_market(chain_dir,market,base,sizeof(base),quote,sizeof(quote));if(rc==-2)die("native market contains an unregistered QRX asset");if(rc)die("invalid native market; expected BASE/QUOTE");
    if(!strcasecmp(side,"SELL")){snprintf(asset,asz,"%s",base);*atoms=qty;}else{snprintf(asset,asz,"%s",quote);*atoms=quote_for_quantity(qty,price);} long long bal=asset_balance_get(chain_dir,asset,owner);return bal>=*atoms?0:-1;
}

static void validate_trade_fields_common(const char *chain_dir, const char *agent, const char *owner,
    const char *tx_type, const char *payload, const char *tx_expiry_height,
    const char *tx_ed_pub_hex, const char *tx_ml_pub_b64) {
    validate_payload_clean(payload, "trading payload"); long long tx_exp=parse_positive_ll_strict(tx_expiry_height,"expiry_height"),h=current_height_from_chain(chain_dir);
    if (!strcmp(tx_type,"ORDER_CREATE") || !strcmp(tx_type,"EXTERNAL_ORDER") || !strcmp(tx_type,"ORDER_REPLACE")) {
        char *market=payload_get_field(payload,"market"),*side=payload_get_field(payload,"side"),*otype=payload_get_field(payload,"order_type"),*qty_s=payload_get_field(payload,"quantity_atoms"),*price_s=payload_get_field(payload,"limit_price_atoms"),*order_exp_s=payload_get_field(payload,"order_expires_height");
        if(!market||!side||!otype||!qty_s||!price_s||!order_exp_s)die("trading payload missing order fields");validate_simple_payload_value(market,"market");validate_simple_payload_value(side,"side");validate_simple_payload_value(otype,"order_type");if(strcasecmp(side,"BUY")&&strcasecmp(side,"SELL"))die("side must be BUY or SELL");if(strcasecmp(otype,"LIMIT")&&strcasecmp(otype,"MARKET"))die("order_type must be LIMIT or MARKET");
        long long qty=parse_positive_ll_strict(qty_s,"quantity_atoms"),price=parse_nonnegative_ll_strict(price_s,"limit_price_atoms");if(!strcasecmp(otype,"LIMIT")&&price<=0)die("LIMIT order requires limit_price_atoms > 0");long long order_exp=parse_positive_ll_strict(order_exp_s,"order_expires_height");if(order_exp<=h)die("order_expires_height must be greater than current chain height");if(order_exp>tx_exp)die("order_expires_height cannot exceed transaction expiry_height");
        if(!strcmp(tx_type,"EXTERNAL_ORDER")){char *venue=payload_get_field(payload,"venue"),*arb=payload_get_field(payload,"arbitrage_id"),*source=payload_get_field(payload,"source_order_id"),*tif=payload_get_field(payload,"time_in_force");validate_simple_payload_value(venue,"venue");agent_assert_trade_authorized(chain_dir,agent,owner,market,"TRADE_EXTERNAL",qty,1,tx_ed_pub_hex,tx_ml_pub_b64);if(arb||source||tif){if(!arb||!source||!tif)die("arbitrage hedge metadata incomplete");validate_simple_payload_value(arb,"arbitrage_id");validate_simple_payload_value(source,"source_order_id");if(strlen(arb)>80||strcasecmp(tif,"IOC"))die("arbitrage hedge requires bounded id and IOC time-in-force");agent_assert_trade_authorized(chain_dir,agent,owner,market,"ARBITRAGE_CROSS_VENUE",0,0,tx_ed_pub_hex,tx_ml_pub_b64);char *sk=order_db_get_field(chain_dir,source,"kind"),*sm=order_db_get_field(chain_dir,source,"market"),*ss=order_db_get_field(chain_dir,source,"side"),*st=order_db_get_field(chain_dir,source,"status"),*so=order_db_get_field(chain_dir,source,"owner");if(!sk||strcmp(sk,"crosschain")||!sm||strcasecmp(sm,"BTC/QUB")||!ss||strcasecmp(ss,"BUY")||!st||strcmp(st,"matched")||!so||strcmp(so,owner))die("arbitrage source must be owner's matched BTC/QUB cross-chain BUY order");free(sk);free(sm);free(ss);free(st);free(so);}free(arb);free(source);free(tif);free(venue);}else{
            if(price<=0)die("native LIMIT/MARKET order requires a positive protection price for deterministic settlement");
            agent_assert_trade_authorized(chain_dir,agent,owner,market,"TRADE_NATIVE",qty,1,tx_ed_pub_hex,tx_ml_pub_b64);
            char lock_asset[32];long long lock_atoms=0,available=0;if(native_order_lock_requirements(chain_dir,owner,market,side,qty,price,lock_asset,sizeof(lock_asset),&lock_atoms)!=0)available=asset_balance_get(chain_dir,lock_asset,owner);else available=asset_balance_get(chain_dir,lock_asset,owner);
            if(!strcmp(tx_type,"ORDER_REPLACE")){char *target=payload_get_field(payload,"order_id");if(!target||!*target)die("ORDER_REPLACE missing order_id");char *old_agent=order_db_get_field(chain_dir,target,"agent"),*old_owner=order_db_get_field(chain_dir,target,"owner"),*old_status=order_db_get_field(chain_dir,target,"status"),*old_kind=order_db_get_field(chain_dir,target,"kind"),*old_locked_asset=order_db_get_field(chain_dir,target,"locked_asset");long long old_locked=order_db_get_ll(chain_dir,target,"locked_atoms",0);if(!old_agent||strcmp(old_agent,agent)||!old_owner||strcmp(old_owner,owner))die("cannot replace order owned by another agent");if(!native_order_status_is_live(old_status))die("order is not replaceable");if(!old_kind||strcmp(old_kind,"native"))die("external orders must be canceled and recreated");if(old_locked_asset&&!strcasecmp(old_locked_asset,lock_asset))checked_add_ll(available,old_locked,"replacement available balance",&available);if(available<lock_atoms)die("insufficient owner asset balance for replacement settlement reserve");free(target);if(old_agent)free(old_agent);if(old_owner)free(old_owner);if(old_status)free(old_status);if(old_kind)free(old_kind);if(old_locked_asset)free(old_locked_asset);
            } else if(available<lock_atoms) die("insufficient owner asset balance for native settlement reserve");
        }
        free(market);free(side);free(otype);free(qty_s);free(price_s);free(order_exp_s);return;
    }
    if(!strcmp(tx_type,"ORDER_CANCEL")){char *target=payload_get_field(payload,"order_id");if(!target||!*target)die("ORDER_CANCEL missing order_id");char *old_agent=order_db_get_field(chain_dir,target,"agent"),*old_owner=order_db_get_field(chain_dir,target,"owner"),*old_status=order_db_get_field(chain_dir,target,"status"),*market=order_db_get_field(chain_dir,target,"market"),*kind=order_db_get_field(chain_dir,target,"kind");if(!old_agent||strcmp(old_agent,agent)||!old_owner||strcmp(old_owner,owner))die("cannot cancel order owned by another agent");if(!order_status_is_live(old_status))die("order is not cancelable");if(!market||!kind)die("order state incomplete");agent_assert_trade_authorized(chain_dir,agent,owner,market,!strcmp(kind,"external")?"TRADE_EXTERNAL":(!strcmp(kind,"crosschain")?"TRADE_CROSSCHAIN":"TRADE_NATIVE"),0,0,tx_ed_pub_hex,tx_ml_pub_b64);free(target);if(old_agent)free(old_agent);if(old_owner)free(old_owner);if(old_status)free(old_status);free(market);free(kind);return;} die("unsupported trading tx_type");
}

static int order_write_from_payload(const char *chain_dir, const char *order_id, const char *agent, const char *owner,
    const char *kind, const char *status, const char *payload, const char *body_hash, const char *replaces) {
    const char *fields[]={"market","side","order_type","quantity_atoms","limit_price_atoms","order_expires_height","venue","client_order_id","time_in_force","arbitrage_id","source_order_id",NULL};long long h=current_height_from_chain(chain_dir);char hbuf[32];snprintf(hbuf,sizeof(hbuf),"%lld",h);
    if(order_db_set_field(chain_dir,order_id,"owner",owner)||order_db_set_field(chain_dir,order_id,"agent",agent)||order_db_set_field(chain_dir,order_id,"kind",kind)||order_db_set_field(chain_dir,order_id,"status",status)||order_db_set_field(chain_dir,order_id,"created_height",hbuf)||order_db_set_field(chain_dir,order_id,"updated_height",hbuf)||order_db_set_field(chain_dir,order_id,"last_tx",body_hash?body_hash:order_id))return -1;if(replaces&&*replaces&&order_db_set_field(chain_dir,order_id,"replaces",replaces))return -1;
    for(int i=0;fields[i];++i){char *v=payload_get_field(payload,fields[i]);if(v){int rc=order_db_set_field(chain_dir,order_id,fields[i],v);free(v);if(rc)return -1;}}
    char *q=payload_get_field(payload,"quantity_atoms");if(q){long long qty=parse_positive_ll_strict(q,"quantity_atoms");free(q);if(order_db_set_ll(chain_dir,order_id,"filled_atoms",0)||order_db_set_ll(chain_dir,order_id,"remaining_atoms",qty))return -1;}return 0;
}

static int native_order_reserve(const char *chain_dir,const char *order_id){
    char *owner=order_db_get_field(chain_dir,order_id,"owner"),*market=order_db_get_field(chain_dir,order_id,"market"),*side=order_db_get_field(chain_dir,order_id,"side");long long qty=order_db_get_ll(chain_dir,order_id,"remaining_atoms",0),price=order_db_get_ll(chain_dir,order_id,"limit_price_atoms",0);if(!owner||!market||!side||qty<=0||price<=0){if(owner)free(owner);if(market)free(market);if(side)free(side);return -1;}char asset[32];long long atoms=0;if(native_order_lock_requirements(chain_dir,owner,market,side,qty,price,asset,sizeof(asset),&atoms)!=0){free(owner);free(market);free(side);return -1;}if(asset_balance_adjust(chain_dir,asset,owner,-atoms)){free(owner);free(market);free(side);return -1;}int rc=order_db_set_field(chain_dir,order_id,"locked_asset",asset)||order_db_set_ll(chain_dir,order_id,"locked_atoms",atoms)||order_db_set_field(chain_dir,order_id,"settlement_version","1");free(owner);free(market);free(side);return rc?-1:0;
}

static int native_order_release_locked(const char *chain_dir,const char *order_id){
    char *asset=order_db_get_field(chain_dir,order_id,"locked_asset"),*owner=order_db_get_field(chain_dir,order_id,"owner");long long atoms=order_db_get_ll(chain_dir,order_id,"locked_atoms",0);if(!asset||!owner){if(asset)free(asset);if(owner)free(owner);return 0;}if(atoms>0&&asset_balance_adjust(chain_dir,asset,owner,atoms)){free(asset);free(owner);return -1;}int rc=order_db_set_ll(chain_dir,order_id,"locked_atoms",0);free(asset);free(owner);return rc;
}

static long long trade_sequence_current(const char *chain_dir){
    char *v=velocity_qrxdb_get_alloc(chain_dir,"velocity:trade_sequence:global");
    if(v){ long long n=atoll(v); free(v); return n; }
    char path[1024];trade_sequence_path(chain_dir,path,sizeof(path));return kv_get_ll_bin(path,"global");
}
static long long next_trade_sequence(const char *chain_dir){
    long long cur=trade_sequence_current(chain_dir);if(cur==LLONG_MAX)die("trade sequence overflow");
    char buf[64];snprintf(buf,sizeof(buf),"%lld",cur+1);
    if(velocity_qrxdb_put(chain_dir,"velocity:trade_sequence:global",buf))die("trade sequence qrxdb write failed");
    char path[1024];trade_sequence_path(chain_dir,path,sizeof(path));if(kv_set_ll_bin(path,"global",cur+1))die("trade sequence mirror write failed");
    return cur+1;
}

static int velocity_batch_put_ll(QrxDBBatch *b,const char *key,long long value){char v[64];snprintf(v,sizeof(v),"%lld",value);return qrxdb_batch_put(b,key,v);}
static int velocity_batch_put_order(QrxDBBatch *b,const char *order_id,const char *field,const char *value){char k[1024];velocity_order_key(k,sizeof(k),order_id,field);return qrxdb_batch_put(b,k,value?value:"");}
static int velocity_batch_put_order_ll(QrxDBBatch *b,const char *order_id,const char *field,long long value){char k[1024];velocity_order_key(k,sizeof(k),order_id,field);return velocity_batch_put_ll(b,k,value);}
static int velocity_batch_put_trade(QrxDBBatch *b,const char *trade_id,const char *field,const char *value){char k[1024];velocity_trade_key(k,sizeof(k),trade_id,field);return qrxdb_batch_put(b,k,value?value:"");}
static int velocity_batch_put_trade_ll(QrxDBBatch *b,const char *trade_id,const char *field,long long value){char k[1024];velocity_trade_key(k,sizeof(k),trade_id,field);return velocity_batch_put_ll(b,k,value);}
static int velocity_batch_put_asset_balance(QrxDBBatch *b,const char *asset,const char *address,long long value){
    char a[32],k[1024];asset_id_normalize(asset,a,sizeof(a));
    if(!strcmp(a,"QUB"))snprintf(k,sizeof(k),"acct:balance:%s",address);else velocity_asset_balance_key(k,sizeof(k),a,address);
    return velocity_batch_put_ll(b,k,value);
}
static int mirror_asset_balance_only(const char *chain_dir,const char *asset,const char *address,long long value){
    char a[32];asset_id_normalize(asset,a,sizeof(a));
    if(!strcmp(a,"QUB")){char bal[1024];state_paths(chain_dir,bal,sizeof(bal),NULL,0,NULL,0,NULL,0);return kv_set_ll_bin(bal,address,value);}
    char path[1024],key[768];asset_balance_path(chain_dir,path,sizeof(path));snprintf(key,sizeof(key),"%s|%s",a,address);return kv_set_ll_bin(path,key,value);
}
static int mirror_order_field_only(const char *chain_dir,const char *order_id,const char *field,const char *value){
    char path[1024],key[768];order_registry_path(chain_dir,path,sizeof(path));if(order_make_key(key,sizeof(key),order_id,field))return -1;return text_db_set(path,key,value?value:"");
}
static int mirror_order_ll_only(const char *chain_dir,const char *order_id,const char *field,long long value){char v[64];snprintf(v,sizeof(v),"%lld",value);return mirror_order_field_only(chain_dir,order_id,field,v);}
static int mirror_trade_field_only(const char *chain_dir,const char *trade_id,const char *field,const char *value){
    char path[1024],key[768];trade_registry_path(chain_dir,path,sizeof(path));if(trade_make_key(key,sizeof(key),trade_id,field))return -1;return text_db_set(path,key,value?value:"");
}
static int mirror_trade_ll_only(const char *chain_dir,const char *trade_id,const char *field,long long value){char v[64];snprintf(v,sizeof(v),"%lld",value);return mirror_trade_field_only(chain_dir,trade_id,field,v);}

static int record_trade(const char *chain_dir,const char *market,const char *maker,const char *taker,const char *buyer,const char *seller,long long qty,long long price,long long quote,long long seq,char *trade_id,size_t trade_id_sz){
    char material[2048],hash[129],buf[64];snprintf(material,sizeof(material),"QRX-TRADE-V1|%s|%s|%s|%lld|%lld|%lld",market,maker,taker,seq,qty,price);hash_primary_hex((unsigned char*)material,strlen(material),hash);snprintf(trade_id,trade_id_sz,"%s",hash);long long h=current_height_from_chain(chain_dir);snprintf(buf,sizeof(buf),"%lld",h);if(trade_db_set_field(chain_dir,hash,"market",market)||trade_db_set_field(chain_dir,hash,"maker_order_id",maker)||trade_db_set_field(chain_dir,hash,"taker_order_id",taker)||trade_db_set_field(chain_dir,hash,"buyer",buyer)||trade_db_set_field(chain_dir,hash,"seller",seller))return -1;snprintf(buf,sizeof(buf),"%lld",qty);if(trade_db_set_field(chain_dir,hash,"quantity_atoms",buf))return -1;snprintf(buf,sizeof(buf),"%lld",price);if(trade_db_set_field(chain_dir,hash,"price_atoms",buf))return -1;snprintf(buf,sizeof(buf),"%lld",quote);if(trade_db_set_field(chain_dir,hash,"quote_atoms",buf))return -1;snprintf(buf,sizeof(buf),"%lld",h);if(trade_db_set_field(chain_dir,hash,"height",buf))return -1;snprintf(buf,sizeof(buf),"%lld",seq);if(trade_db_set_field(chain_dir,hash,"sequence",buf))return -1;return 0;
}

static int update_order_after_fill(const char *chain_dir,const char *order_id,long long fill_qty,long long new_locked){long long rem=order_db_get_ll(chain_dir,order_id,"remaining_atoms",0),filled=order_db_get_ll(chain_dir,order_id,"filled_atoms",0);if(fill_qty<=0||fill_qty>rem)return -1;long long nf=0;checked_add_ll(filled,fill_qty,"filled quantity",&nf);long long nr=rem-fill_qty;long long h=current_height_from_chain(chain_dir);if(order_db_set_ll(chain_dir,order_id,"filled_atoms",nf)||order_db_set_ll(chain_dir,order_id,"remaining_atoms",nr)||order_db_set_ll(chain_dir,order_id,"locked_atoms",new_locked)||order_db_set_ll(chain_dir,order_id,"updated_height",h)||order_db_set_field(chain_dir,order_id,"status",nr==0?"filled":"partially_filled"))return -1;return 0;}

static int settle_match(const char *chain_dir,const char *market,const char *maker_id,const char *taker_id,long long qty,long long price){
    char *maker_side=order_db_get_field(chain_dir,maker_id,"side");if(!maker_side)return -1;
    const char *buyer_id=!strcasecmp(maker_side,"BUY")?maker_id:taker_id,*seller_id=!strcasecmp(maker_side,"SELL")?maker_id:taker_id;free(maker_side);
    char *buyer=order_db_get_field(chain_dir,buyer_id,"owner"),*seller=order_db_get_field(chain_dir,seller_id,"owner");
    if(!buyer||!seller){if(buyer)free(buyer);if(seller)free(seller);return -1;}
    if(!strcmp(buyer,seller)){free(buyer);free(seller);return -1;} /* deterministic self-match prevention */

    char base[32],quote_asset[32];
    if(parse_native_market(chain_dir,market,base,sizeof(base),quote_asset,sizeof(quote_asset))!=0){free(buyer);free(seller);return -1;}

    long long quote_amt=quote_for_quantity(qty,price);
    long long buyer_lock=order_db_get_ll(chain_dir,buyer_id,"locked_atoms",0),seller_lock=order_db_get_ll(chain_dir,seller_id,"locked_atoms",0);
    long long buyer_rem_before=order_db_get_ll(chain_dir,buyer_id,"remaining_atoms",0),seller_rem_before=order_db_get_ll(chain_dir,seller_id,"remaining_atoms",0);
    long long buyer_filled_before=order_db_get_ll(chain_dir,buyer_id,"filled_atoms",0),seller_filled_before=order_db_get_ll(chain_dir,seller_id,"filled_atoms",0);
    if(qty<=0||qty>buyer_rem_before||qty>seller_rem_before||buyer_lock<quote_amt||seller_lock<qty){free(buyer);free(seller);return -1;}

    long long buyer_rem=buyer_rem_before-qty,seller_rem=seller_rem_before-qty;
    long long buyer_filled=0,seller_filled=0;
    checked_add_ll(buyer_filled_before,qty,"buyer filled",&buyer_filled);
    checked_add_ll(seller_filled_before,qty,"seller filled",&seller_filled);

    long long buyer_new_lock=buyer_lock-quote_amt,seller_new_lock=seller_lock-qty;
    long long buyer_limit=order_db_get_ll(chain_dir,buyer_id,"limit_price_atoms",0);
    long long buyer_needed=buyer_rem>0?quote_for_quantity(buyer_rem,buyer_limit):0;
    if(buyer_new_lock<buyer_needed||seller_new_lock<seller_rem){free(buyer);free(seller);return -1;}
    long long buyer_refund=buyer_new_lock-buyer_needed,seller_refund=seller_new_lock-seller_rem;
    buyer_new_lock=buyer_needed;seller_new_lock=seller_rem;

    long long buyer_base=asset_balance_get(chain_dir,base,buyer),seller_quote=asset_balance_get(chain_dir,quote_asset,seller);
    long long buyer_quote=asset_balance_get(chain_dir,quote_asset,buyer),seller_base=asset_balance_get(chain_dir,base,seller);
    long long buyer_base_new=0,seller_quote_new=0,buyer_quote_new=0,seller_base_new=0;
    checked_add_ll(buyer_base,qty,"buyer base balance",&buyer_base_new);
    checked_add_ll(seller_quote,quote_amt,"seller quote balance",&seller_quote_new);
    checked_add_ll(buyer_quote,buyer_refund,"buyer price-improvement refund",&buyer_quote_new);
    checked_add_ll(seller_base,seller_refund,"seller reserve refund",&seller_base_new);

    long long seq=trade_sequence_current(chain_dir);if(seq==LLONG_MAX){free(buyer);free(seller);return -1;}seq++;
    char material[2048],trade_id[160];
    snprintf(material,sizeof(material),"QRX-TRADE-V1|%s|%s|%s|%lld|%lld|%lld",market,maker_id,taker_id,seq,qty,price);
    hash_primary_hex((unsigned char*)material,strlen(material),trade_id);
    long long h=current_height_from_chain(chain_dir);

    QrxDB db;QrxDBBatch batch;char pre_root[129]={0},post_root[129]={0},settle_key[1024],settle_val[1024];
    if(qrxdb_init(&db,chain_dir)!=0){free(buyer);free(seller);return -1;}
    qrxdb_merkle_root_hex(&db,pre_root);
    if(qrxdb_batch_begin(&db,&batch)!=0){qrxdb_close(&db);free(buyer);free(seller);return -1;}

    int brc=0;
    brc|=velocity_batch_put_asset_balance(&batch,base,buyer,buyer_base_new);
    brc|=velocity_batch_put_asset_balance(&batch,quote_asset,seller,seller_quote_new);
    brc|=velocity_batch_put_asset_balance(&batch,quote_asset,buyer,buyer_quote_new);
    brc|=velocity_batch_put_asset_balance(&batch,base,seller,seller_base_new);

    brc|=velocity_batch_put_order_ll(&batch,buyer_id,"filled_atoms",buyer_filled);
    brc|=velocity_batch_put_order_ll(&batch,buyer_id,"remaining_atoms",buyer_rem);
    brc|=velocity_batch_put_order_ll(&batch,buyer_id,"locked_atoms",buyer_new_lock);
    brc|=velocity_batch_put_order_ll(&batch,buyer_id,"updated_height",h);
    brc|=velocity_batch_put_order(&batch,buyer_id,"status",buyer_rem==0?"filled":"partially_filled");
    brc|=velocity_batch_put_order(&batch,buyer_id,"last_trade_id",trade_id);

    brc|=velocity_batch_put_order_ll(&batch,seller_id,"filled_atoms",seller_filled);
    brc|=velocity_batch_put_order_ll(&batch,seller_id,"remaining_atoms",seller_rem);
    brc|=velocity_batch_put_order_ll(&batch,seller_id,"locked_atoms",seller_new_lock);
    brc|=velocity_batch_put_order_ll(&batch,seller_id,"updated_height",h);
    brc|=velocity_batch_put_order(&batch,seller_id,"status",seller_rem==0?"filled":"partially_filled");
    brc|=velocity_batch_put_order(&batch,seller_id,"last_trade_id",trade_id);

    brc|=velocity_batch_put_trade(&batch,trade_id,"market",market);
    brc|=velocity_batch_put_trade(&batch,trade_id,"maker_order_id",maker_id);
    brc|=velocity_batch_put_trade(&batch,trade_id,"taker_order_id",taker_id);
    brc|=velocity_batch_put_trade(&batch,trade_id,"buyer",buyer);
    brc|=velocity_batch_put_trade(&batch,trade_id,"seller",seller);
    brc|=velocity_batch_put_trade_ll(&batch,trade_id,"quantity_atoms",qty);
    brc|=velocity_batch_put_trade_ll(&batch,trade_id,"price_atoms",price);
    brc|=velocity_batch_put_trade_ll(&batch,trade_id,"quote_atoms",quote_amt);
    brc|=velocity_batch_put_trade_ll(&batch,trade_id,"height",h);
    brc|=velocity_batch_put_trade_ll(&batch,trade_id,"sequence",seq);
    brc|=velocity_batch_put_ll(&batch,"velocity:trade_sequence:global",seq);

    snprintf(settle_key,sizeof(settle_key),"velocity:settlement:%s",trade_id);
    snprintf(settle_val,sizeof(settle_val),
        "version=1\nmarket=%s\nmaker=%s\ntaker=%s\nquantity_atoms=%lld\nprice_atoms=%lld\nquote_atoms=%lld\nheight=%lld\nsequence=%lld\npre_state_root=%s\n",
        market,maker_id,taker_id,qty,price,quote_amt,h,seq,pre_root);
    brc|=qrxdb_batch_put(&batch,settle_key,settle_val);

    if(brc||qrxdb_batch_commit(&batch)!=0){qrxdb_batch_abort(&batch);qrxdb_close(&db);free(buyer);free(seller);return -1;}
    qrxdb_merkle_root_hex(&db,post_root);
    qrxdb_close(&db);

    /* Compatibility/read-model mirrors are written only after the canonical
       QRXDB WAL transaction committed. A crash here cannot roll back the
       canonical settlement; getters prefer QRXDB and mirrors can be rebuilt. */
    mirror_asset_balance_only(chain_dir,base,buyer,buyer_base_new);
    mirror_asset_balance_only(chain_dir,quote_asset,seller,seller_quote_new);
    mirror_asset_balance_only(chain_dir,quote_asset,buyer,buyer_quote_new);
    mirror_asset_balance_only(chain_dir,base,seller,seller_base_new);
    mirror_order_ll_only(chain_dir,buyer_id,"filled_atoms",buyer_filled);mirror_order_ll_only(chain_dir,buyer_id,"remaining_atoms",buyer_rem);mirror_order_ll_only(chain_dir,buyer_id,"locked_atoms",buyer_new_lock);mirror_order_ll_only(chain_dir,buyer_id,"updated_height",h);mirror_order_field_only(chain_dir,buyer_id,"status",buyer_rem==0?"filled":"partially_filled");mirror_order_field_only(chain_dir,buyer_id,"last_trade_id",trade_id);
    mirror_order_ll_only(chain_dir,seller_id,"filled_atoms",seller_filled);mirror_order_ll_only(chain_dir,seller_id,"remaining_atoms",seller_rem);mirror_order_ll_only(chain_dir,seller_id,"locked_atoms",seller_new_lock);mirror_order_ll_only(chain_dir,seller_id,"updated_height",h);mirror_order_field_only(chain_dir,seller_id,"status",seller_rem==0?"filled":"partially_filled");mirror_order_field_only(chain_dir,seller_id,"last_trade_id",trade_id);
    mirror_trade_field_only(chain_dir,trade_id,"market",market);mirror_trade_field_only(chain_dir,trade_id,"maker_order_id",maker_id);mirror_trade_field_only(chain_dir,trade_id,"taker_order_id",taker_id);mirror_trade_field_only(chain_dir,trade_id,"buyer",buyer);mirror_trade_field_only(chain_dir,trade_id,"seller",seller);mirror_trade_ll_only(chain_dir,trade_id,"quantity_atoms",qty);mirror_trade_ll_only(chain_dir,trade_id,"price_atoms",price);mirror_trade_ll_only(chain_dir,trade_id,"quote_atoms",quote_amt);mirror_trade_ll_only(chain_dir,trade_id,"height",h);mirror_trade_ll_only(chain_dir,trade_id,"sequence",seq);
    {char sp[1024];trade_sequence_path(chain_dir,sp,sizeof(sp));kv_set_ll_bin(sp,"global",seq);}
    journal_append(chain_dir,"velocity_atomic_settlement trade=%s maker=%s taker=%s qty=%lld price=%lld state_root=%s",trade_id,maker_id,taker_id,qty,price,post_root);
    free(buyer);free(seller);return 0;
}

static int order_candidate_better(const QrxMatchOrder *a,const QrxMatchOrder *b,int want_sells){if(a->price!=b->price)return want_sells?a->price<b->price:a->price>b->price;if(a->created_height!=b->created_height)return a->created_height<b->created_height;return strcmp(a->id,b->id)<0;}

static int collect_match_candidates(const char *chain_dir,const char *taker_id,const char *market,const char *taker_side,QrxMatchOrder **out,size_t *count){
    *out=NULL;*count=0;
    char *taker_owner=order_db_get_field(chain_dir,taker_id,"owner");
    if(!taker_owner) return -1;
    char path[1024];order_registry_path(chain_dir,path,sizeof(path));
    char *txt=read_file(path,NULL);if(!txt){free(taker_owner);return 0;}
    const char *cur=txt,suffix[]=".owner=";long long h=current_height_from_chain(chain_dir);
    while(cur&&*cur){
        const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur),idlen=0;const char *suf=NULL;
        if(len>6&&!strncmp(cur,"order.",6)){
            for(size_t i=6;i+strlen(suffix)<len;++i) if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}
        }
        if(suf){
            idlen=(size_t)(suf-(cur+6));
            if(idlen>0&&idlen<160){
                char oid[160];memcpy(oid,cur+6,idlen);oid[idlen]=0;
                if(strcmp(oid,taker_id)){
                    char *kind=order_db_get_field(chain_dir,oid,"kind"),*status=order_db_get_field(chain_dir,oid,"status"),*omarket=order_db_get_field(chain_dir,oid,"market"),*side=order_db_get_field(chain_dir,oid,"side"),*sv=order_db_get_field(chain_dir,oid,"settlement_version");
                    long long exp=order_db_get_ll(chain_dir,oid,"order_expires_height",0);
                    if(kind&&!strcmp(kind,"native")&&status&&native_order_status_is_live(status)&&exp>0&&exp<=h&&sv&&!strcmp(sv,"1")){
                        native_order_release_locked(chain_dir,oid);order_db_set_field(chain_dir,oid,"status","expired");order_db_set_ll(chain_dir,oid,"updated_height",h);
                    } else if(kind&&!strcmp(kind,"native")&&status&&native_order_status_is_live(status)&&omarket&&!strcasecmp(omarket,market)&&side&&strcasecmp(side,taker_side)&&sv&&!strcmp(sv,"1")){
                        char *own=order_db_get_field(chain_dir,oid,"owner");
                        /* Self-trades are skipped at candidate selection time so
                           they cannot block a valid later counterparty order. */
                        if(own && strcmp(own,taker_owner)!=0){
                            QrxMatchOrder *n=realloc(*out,(*count+1)*sizeof(**out));if(!n)die("oom");*out=n;
                            QrxMatchOrder *m=&n[*count];memset(m,0,sizeof(*m));snprintf(m->id,sizeof(m->id),"%s",oid);snprintf(m->owner,sizeof(m->owner),"%s",own);snprintf(m->side,sizeof(m->side),"%s",side);
                            m->price=order_db_get_ll(chain_dir,oid,"limit_price_atoms",0);m->remaining=order_db_get_ll(chain_dir,oid,"remaining_atoms",0);m->created_height=order_db_get_ll(chain_dir,oid,"created_height",0);(*count)++;
                        }
                        if(own)free(own);
                    }
                    if(kind)free(kind);if(status)free(status);if(omarket)free(omarket);if(side)free(side);if(sv)free(sv);
                }
            }
        }
        cur=e?e+1:NULL;
    }
    free(txt);free(taker_owner);
    int want_sells=!strcasecmp(taker_side,"BUY");
    for(size_t i=1;i<*count;++i){QrxMatchOrder key=(*out)[i];size_t j=i;while(j>0&&order_candidate_better(&key,&(*out)[j-1],want_sells)){(*out)[j]=(*out)[j-1];--j;}(*out)[j]=key;}
    return 0;
}

static int match_native_order(const char *chain_dir,const char *taker_id){
    char *market=order_db_get_field(chain_dir,taker_id,"market"),*side=order_db_get_field(chain_dir,taker_id,"side");if(!market||!side){if(market)free(market);if(side)free(side);return -1;}QrxMatchOrder *arr=NULL;size_t count=0;if(collect_match_candidates(chain_dir,taker_id,market,side,&arr,&count)){free(market);free(side);return -1;}long long taker_price=order_db_get_ll(chain_dir,taker_id,"limit_price_atoms",0);
    for(size_t i=0;i<count;++i){long long trem=order_db_get_ll(chain_dir,taker_id,"remaining_atoms",0);if(trem<=0)break;long long mrem=order_db_get_ll(chain_dir,arr[i].id,"remaining_atoms",0);if(mrem<=0)continue;int crosses=!strcasecmp(side,"BUY")?(arr[i].price<=taker_price):(arr[i].price>=taker_price);if(!crosses)break;long long qty=trem<mrem?trem:mrem;if(settle_match(chain_dir,market,arr[i].id,taker_id,qty,arr[i].price)){free(arr);free(market);free(side);return -1;}}
    free(arr);free(market);free(side);return 0;
}

static int trade_apply_tx(const char *chain_dir, const char *agent, const char *owner, const char *tx_type, const char *payload, const char *body_hash) {
    if(!body_hash||!*body_hash)return -1;long long h=current_height_from_chain(chain_dir);
    if(!strcmp(tx_type,"ORDER_CREATE")||!strcmp(tx_type,"EXTERNAL_ORDER")){const int external=!strcmp(tx_type,"EXTERNAL_ORDER");if(order_write_from_payload(chain_dir,body_hash,agent,owner,external?"external":"native",external?"pending_execution":"open",payload,body_hash,NULL))return -1;char *q=payload_get_field(payload,"quantity_atoms");long long qty=parse_positive_ll_strict(q,"quantity_atoms");free(q);if(agent_usage_add(chain_dir,agent,qty))return -1;if(!external){if(native_order_reserve(chain_dir,body_hash))return -1;if(match_native_order(chain_dir,body_hash))return -1;}return 0;}
    if(!strcmp(tx_type,"ORDER_CANCEL")){char *target=payload_get_field(payload,"order_id");if(!target)return -1;char *kind=order_db_get_field(chain_dir,target,"kind");if(kind&&!strcmp(kind,"native")&&native_order_release_locked(chain_dir,target)){free(kind);free(target);return -1;}const char *next_status=(kind&&!strcmp(kind,"external"))?"cancel_pending":"canceled";int rc=order_db_set_field(chain_dir,target,"status",next_status)||order_db_set_ll(chain_dir,target,"updated_height",h)||order_db_set_field(chain_dir,target,"last_tx",body_hash);if(kind)free(kind);free(target);return rc?-1:0;}
    if(!strcmp(tx_type,"ORDER_REPLACE")){char *target=payload_get_field(payload,"order_id");if(!target)return -1;if(native_order_release_locked(chain_dir,target)){free(target);return -1;}if(order_db_set_field(chain_dir,target,"status","replaced")||order_db_set_ll(chain_dir,target,"updated_height",h)||order_db_set_field(chain_dir,target,"replacement_order_id",body_hash)||order_db_set_field(chain_dir,target,"last_tx",body_hash)){free(target);return -1;}if(order_write_from_payload(chain_dir,body_hash,agent,owner,"native","open",payload,body_hash,target)){free(target);return -1;}if(native_order_reserve(chain_dir,body_hash)){free(target);return -1;}char *q=payload_get_field(payload,"quantity_atoms");long long qty=parse_positive_ll_strict(q,"quantity_atoms");free(q);if(agent_usage_add(chain_dir,agent,qty)){free(target);return -1;}int rc=match_native_order(chain_dir,body_hash);free(target);return rc;}
    return -1;
}

static int order_status_cmd(const char *chain_dir, const char *order_id) {
    if(!order_id||!*order_id)die("missing order id");const char *fields[]={"owner","agent","kind","venue","market","side","order_type","quantity_atoms","filled_atoms","remaining_atoms","limit_price_atoms","status","created_height","updated_height","order_expires_height","client_order_id","time_in_force","arbitrage_id","source_order_id","replaces","replacement_order_id","settlement_version","locked_asset","locked_atoms","external_filled_atoms","external_avg_price_atoms","external_venue_fee_atoms","venue_order_id","execution_gateway","execution_report_sequence","last_execution_report","last_trade_id","crosschain_session_id","hashlock_hex","btc_redeem_pubkey_hex","btc_refund_pubkey_hex","btc_refund_csv_blocks","qrx_refund_height","last_tx",NULL};int found=0;printf("order_id=%s\n",order_id);for(int i=0;fields[i];++i){char *v=order_db_get_field(chain_dir,order_id,fields[i]);if(v){printf("%s=%s\n",fields[i],v);found=1;free(v);}}if(!found)die("order not found");return 0;
}

static int list_orders_cmd(const char *chain_dir, const char *filter, const char *status_filter) {
    char path[1024];order_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);if(!txt)return 0;const char *cur=txt;const char suffix[]=".owner=";while(cur&&*cur){const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);const char *suf=NULL;if(len>6&&!strncmp(cur,"order.",6)){for(size_t i=6;i+strlen(suffix)<len;++i)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}}if(suf){size_t idlen=(size_t)(suf-(cur+6));char oid[256];if(idlen>=sizeof(oid))idlen=sizeof(oid)-1;memcpy(oid,cur+6,idlen);oid[idlen]=0;char *owner=order_db_get_field(chain_dir,oid,"owner"),*agent=order_db_get_field(chain_dir,oid,"agent"),*status=order_db_get_field(chain_dir,oid,"status"),*market=order_db_get_field(chain_dir,oid,"market"),*kind=order_db_get_field(chain_dir,oid,"kind");int fok=!filter||!*filter||(owner&&!strcmp(filter,owner))||(agent&&!strcmp(filter,agent)),sok=!status_filter||!*status_filter||(status&&!strcasecmp(status_filter,status));if(fok&&sok)printf("order_id=%s owner=%s agent=%s kind=%s market=%s status=%s remaining_atoms=%lld\n",oid,owner?owner:"",agent?agent:"",kind?kind:"",market?market:"",status?status:"",order_db_get_ll(chain_dir,oid,"remaining_atoms",0));if(owner)free(owner);if(agent)free(agent);if(status)free(status);if(market)free(market);if(kind)free(kind);}cur=e?e+1:NULL;}free(txt);return 0;
}

static int trade_status_cmd(const char *chain_dir,const char *trade_id){if(!trade_id||!*trade_id)die("missing trade id");const char *fields[]={"market","maker_order_id","taker_order_id","buyer","seller","quantity_atoms","price_atoms","quote_atoms","height","sequence",NULL};int found=0;printf("trade_id=%s\n",trade_id);for(int i=0;fields[i];++i){char *v=trade_db_get_field(chain_dir,trade_id,fields[i]);if(v){printf("%s=%s\n",fields[i],v);found=1;free(v);}}if(!found)die("trade not found");return 0;}

static int list_trades_cmd(const char *chain_dir,const char *market_filter,long long limit,long long min_height,long long max_height){
    if(limit<0)limit=50;
    char path[1024];trade_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);if(!txt)return 0;
    const char *cur=txt,suffix[]=".market=";long long shown=0;
    while(cur&&*cur&&(limit==0||shown<limit)){
        const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);const char *suf=NULL;
        if(len>6&&!strncmp(cur,"trade.",6)){for(size_t i=6;i+strlen(suffix)<len;++i)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}}
        if(suf){
            size_t idlen=(size_t)(suf-(cur+6)),mlen=len-(size_t)((suf+strlen(suffix))-cur);
            if(idlen<160&&mlen<64){
                char tid[160],m[64];memcpy(tid,cur+6,idlen);tid[idlen]=0;memcpy(m,suf+strlen(suffix),mlen);m[mlen]=0;
                if(!market_filter||!*market_filter||!strcmp(market_filter,"*")||!strcasecmp(market_filter,m)){
                    char *height=trade_db_get_field(chain_dir,tid,"height");long long h=height?atoll(height):0;
                    if((min_height<=0||h>=min_height)&&(max_height<=0||h<=max_height)){
                        char *q=trade_db_get_field(chain_dir,tid,"quantity_atoms"),*p=trade_db_get_field(chain_dir,tid,"price_atoms"),*qa=trade_db_get_field(chain_dir,tid,"quote_atoms"),*sq=trade_db_get_field(chain_dir,tid,"sequence"),*maker=trade_db_get_field(chain_dir,tid,"maker_order_id"),*taker=trade_db_get_field(chain_dir,tid,"taker_order_id"),*buyer=trade_db_get_field(chain_dir,tid,"buyer"),*seller=trade_db_get_field(chain_dir,tid,"seller");
                        printf("trade_id=%s market=%s maker_order_id=%s taker_order_id=%s buyer=%s seller=%s quantity_atoms=%s price_atoms=%s quote_atoms=%s height=%s sequence=%s\n",tid,m,maker?maker:"",taker?taker:"",buyer?buyer:"",seller?seller:"",q?q:"0",p?p:"0",qa?qa:"0",height?height:"0",sq?sq:"0");
                        if(q)free(q);if(p)free(p);if(qa)free(qa);if(sq)free(sq);if(maker)free(maker);if(taker)free(taker);if(buyer)free(buyer);if(seller)free(seller);shown++;
                    }
                    if(height)free(height);
                }
            }
        }
        cur=e?e+1:NULL;
    }
    free(txt);return 0;
}

static int orderbook_cmd(const char *chain_dir,const char *market,int depth){if(depth<=0)depth=20;if(depth>200)depth=200;char base[32],quote[32];int pr=parse_native_market(chain_dir,market,base,sizeof(base),quote,sizeof(quote));if(pr)die(pr==-2?"native market contains an unregistered QRX asset":"invalid native market");QrxMatchOrder *bids=NULL,*asks=NULL;size_t nb=0,na=0;char path[1024];order_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);if(txt){const char *cur=txt,suffix[]=".owner=";while(cur&&*cur){const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);const char *suf=NULL;if(len>6&&!strncmp(cur,"order.",6)){for(size_t i=6;i+strlen(suffix)<len;++i)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}}if(suf){size_t idlen=(size_t)(suf-(cur+6));if(idlen>0&&idlen<160){char oid[160];memcpy(oid,cur+6,idlen);oid[idlen]=0;char *kind=order_db_get_field(chain_dir,oid,"kind"),*status=order_db_get_field(chain_dir,oid,"status"),*m=order_db_get_field(chain_dir,oid,"market"),*side=order_db_get_field(chain_dir,oid,"side"),*sv=order_db_get_field(chain_dir,oid,"settlement_version");if(kind&&!strcmp(kind,"native")&&status&&native_order_status_is_live(status)&&m&&!strcasecmp(m,market)&&side&&sv&&!strcmp(sv,"1")){QrxMatchOrder **arr=!strcasecmp(side,"BUY")?&bids:&asks;size_t *n=!strcasecmp(side,"BUY")?&nb:&na;QrxMatchOrder *nn=realloc(*arr,(*n+1)*sizeof(**arr));if(!nn)die("oom");*arr=nn;QrxMatchOrder *o=&nn[*n];memset(o,0,sizeof(*o));snprintf(o->id,sizeof(o->id),"%s",oid);snprintf(o->side,sizeof(o->side),"%s",side);o->price=order_db_get_ll(chain_dir,oid,"limit_price_atoms",0);o->remaining=order_db_get_ll(chain_dir,oid,"remaining_atoms",0);o->created_height=order_db_get_ll(chain_dir,oid,"created_height",0);(*n)++;}if(kind)free(kind);if(status)free(status);if(m)free(m);if(side)free(side);if(sv)free(sv);}}cur=e?e+1:NULL;}free(txt);}for(size_t i=1;i<nb;++i){QrxMatchOrder k=bids[i];size_t j=i;while(j>0&&order_candidate_better(&k,&bids[j-1],0)){bids[j]=bids[j-1];--j;}bids[j]=k;}for(size_t i=1;i<na;++i){QrxMatchOrder k=asks[i];size_t j=i;while(j>0&&order_candidate_better(&k,&asks[j-1],1)){asks[j]=asks[j-1];--j;}asks[j]=k;}printf("market=%s base=%s quote=%s price_scale=%lld\n",market,base,quote,(long long)QRX_TRADE_PRICE_SCALE);for(size_t i=0;i<nb&&(int)i<depth;++i)printf("side=BUY price_atoms=%lld remaining_atoms=%lld order_id=%s\n",bids[i].price,bids[i].remaining,bids[i].id);for(size_t i=0;i<na&&(int)i<depth;++i)printf("side=SELL price_atoms=%lld remaining_atoms=%lld order_id=%s\n",asks[i].price,asks[i].remaining,asks[i].id);free(bids);free(asks);return 0;}

static int agent_limits_cmd(const char *chain_dir, const char *agent) {if(!agent||!*agent)die("missing agent address");char *owner=agent_db_get_field(chain_dir,agent,"owner"),*status=agent_db_get_field(chain_dir,agent,"status"),*max_trade=agent_db_get_field(chain_dir,agent,"max_trade_atoms"),*daily=agent_db_get_field(chain_dir,agent,"daily_limit_atoms"),*expires=agent_db_get_field(chain_dir,agent,"expires_height"),*permissions=agent_db_get_field(chain_dir,agent,"permissions"),*markets=agent_db_get_field(chain_dir,agent,"market_allowlist");if(!owner)die("agent not found");long long bucket=0,epoch_blocks=0,used=agent_usage_current(chain_dir,agent,&bucket,&epoch_blocks);printf("agent=%s\nowner=%s\nstatus=%s\npermissions=%s\nmarket_allowlist=%s\nmax_trade_atoms=%s\ndaily_limit_atoms=%s\nusage_atoms=%lld\nusage_bucket=%lld\nusage_epoch_blocks=%lld\nexpires_height=%s\n",agent,owner,status?status:"",permissions?permissions:"",markets?markets:"",max_trade?max_trade:"0",daily?daily:"0",used,bucket,epoch_blocks,expires?expires:"0");free(owner);if(status)free(status);if(max_trade)free(max_trade);if(daily)free(daily);if(expires)free(expires);if(permissions)free(permissions);if(markets)free(markets);return 0;}


/* === VELOCITY 0.0.7 Phase 3C: external execution gateways + reports === */
static void gateway_registry_path(const char *chain_dir,char *out,size_t out_sz){snprintf(out,out_sz,"%s/state/gateways.db",chain_dir);}
static int gateway_make_key(char *out,size_t out_sz,const char *gateway,const char *field){
    if(!gateway||!*gateway||!field||!*field||strchr(gateway,'\n')||strchr(gateway,'=')||strchr(gateway,'|'))return -1;
    snprintf(out,out_sz,"gateway.%s.%s",gateway,field);return 0;
}
static void velocity_gateway_key(char *out,size_t out_sz,const char *gateway,const char *field){snprintf(out,out_sz,"velocity:gateway:%s:%s",gateway,field);}
static char *gateway_db_get_field(const char *chain_dir,const char *gateway,const char *field){
    char qkey[1024];velocity_gateway_key(qkey,sizeof(qkey),gateway,field);char *v=velocity_qrxdb_get_alloc(chain_dir,qkey);if(v)return v;
    char path[1024],key[768];gateway_registry_path(chain_dir,path,sizeof(path));if(gateway_make_key(key,sizeof(key),gateway,field))return NULL;return text_db_get(path,key);
}
static int gateway_db_set_field(const char *chain_dir,const char *gateway,const char *field,const char *value){
    char qkey[1024],path[1024],key[768];velocity_gateway_key(qkey,sizeof(qkey),gateway,field);
    if(velocity_qrxdb_put(chain_dir,qkey,value?value:""))return -1;gateway_registry_path(chain_dir,path,sizeof(path));if(gateway_make_key(key,sizeof(key),gateway,field))return -1;return text_db_set(path,key,value?value:"");
}
static int gateway_db_set_ll(const char *chain_dir,const char *gateway,const char *field,long long value){char v[64];snprintf(v,sizeof(v),"%lld",value);return gateway_db_set_field(chain_dir,gateway,field,v);}
static long long gateway_db_get_ll(const char *chain_dir,const char *gateway,const char *field,long long fallback){char *v=gateway_db_get_field(chain_dir,gateway,field);if(!v)return fallback;char *e=NULL;errno=0;long long n=strtoll(v,&e,10);int ok=!errno&&e&&!*e;free(v);return ok?n:fallback;}

static void validate_gateway_public_keys_for_address(const char *gateway,const char *ed_hex,const char *ml_b64){
    unsigned char edraw[32];size_t edlen=0;if(hex_to_bytes(ed_hex,edraw,sizeof(edraw),&edlen)||edlen!=32)die("invalid gateway ed25519 public key");
    EVP_PKEY *ed=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,edraw,edlen);if(!ed)die("gateway ed25519 key parse failed");
    if(address_matches_pub(ed,gateway)!=0){EVP_PKEY_free(ed);die("gateway address does not match gateway ed25519 key");}EVP_PKEY_free(ed);
    size_t n=0;unsigned char *pem=base64_decode(ml_b64,&n);if(!pem)die("invalid gateway ML-DSA public key");char *s=malloc(n+1);if(!s)die("oom");memcpy(s,pem,n);s[n]=0;EVP_PKEY *ml=pubkey_from_pem_string(s);free(pem);free(s);if(!ml)die("gateway ML-DSA key parse failed");EVP_PKEY_free(ml);
}
static void validate_gateway_management_tx(const char *chain_dir,const char *authority,const char *gateway,const char *tx_type,const char *payload){
    char *dev=chain_cfg_value(chain_dir,"dev_address");if(!dev||!*dev||strcmp(dev,authority)){if(dev)free(dev);die("gateway registry transaction must be signed by configured dev_address authority");}free(dev);
    if(!gateway||!*gateway)die("missing gateway address");
    if(!strcmp(tx_type,"GATEWAY_REGISTER")){
        char *venue=payload_get_field(payload,"venue"),*name=payload_get_field(payload,"name"),*ed=payload_get_field(payload,"gateway_ed25519_pub_hex"),*ml=payload_get_field(payload,"gateway_mldsa65_pub_b64"),*exp=payload_get_field(payload,"expires_height");
        validate_simple_payload_value(venue,"venue");validate_simple_payload_value(name,"gateway name");if(!ed||!ml||!exp)die("gateway registration payload incomplete");
        long long eh=parse_positive_ll_strict(exp,"gateway expires_height");if(eh<=current_height_from_chain(chain_dir))die("gateway expires_height must be in the future");
        validate_gateway_public_keys_for_address(gateway,ed,ml);free(venue);free(name);free(ed);free(ml);free(exp);return;
    }
    if(!strcmp(tx_type,"GATEWAY_REVOKE")){char *status=gateway_db_get_field(chain_dir,gateway,"status");if(!status||strcmp(status,"active"))die("gateway is not active");free(status);return;}
    die("unsupported gateway management transaction");
}
static int mirror_gateway_field_only(const char *chain_dir,const char *gateway,const char *field,const char *value){
    char path[1024],key[768];gateway_registry_path(chain_dir,path,sizeof(path));if(gateway_make_key(key,sizeof(key),gateway,field))return -1;return text_db_set(path,key,value?value:"");
}
static int mirror_gateway_ll_only(const char *chain_dir,const char *gateway,const char *field,long long value){char v[64];snprintf(v,sizeof(v),"%lld",value);return mirror_gateway_field_only(chain_dir,gateway,field,v);}
static int velocity_batch_put_gateway(QrxDBBatch *b,const char *gateway,const char *field,const char *value){char k[1024];velocity_gateway_key(k,sizeof(k),gateway,field);return qrxdb_batch_put(b,k,value?value:"");}
static int velocity_batch_put_gateway_ll(QrxDBBatch *b,const char *gateway,const char *field,long long value){char k[1024];velocity_gateway_key(k,sizeof(k),gateway,field);return velocity_batch_put_ll(b,k,value);}
static int gateway_apply_tx(const char *chain_dir,const char *authority,const char *gateway,const char *tx_type,const char *payload,const char *body_hash){
    long long h=current_height_from_chain(chain_dir);QrxDB db;QrxDBBatch b;char root[129]={0};
    if(qrxdb_init(&db,chain_dir)!=0)return -1;if(qrxdb_batch_begin(&db,&b)!=0){qrxdb_close(&db);return -1;}
    int rc=0;
    if(!strcmp(tx_type,"GATEWAY_REGISTER")){
        char *venue=payload_get_field(payload,"venue"),*name=payload_get_field(payload,"name"),*ed=payload_get_field(payload,"gateway_ed25519_pub_hex"),*ml=payload_get_field(payload,"gateway_mldsa65_pub_b64"),*exp=payload_get_field(payload,"expires_height");
        rc|=velocity_batch_put_gateway(&b,gateway,"authority",authority);rc|=velocity_batch_put_gateway(&b,gateway,"status","active");rc|=velocity_batch_put_gateway(&b,gateway,"venue",venue);rc|=velocity_batch_put_gateway(&b,gateway,"name",name);rc|=velocity_batch_put_gateway(&b,gateway,"ed25519_pub_hex",ed);rc|=velocity_batch_put_gateway(&b,gateway,"mldsa65_pub_b64",ml);rc|=velocity_batch_put_gateway(&b,gateway,"expires_height",exp);rc|=velocity_batch_put_gateway_ll(&b,gateway,"updated_height",h);rc|=velocity_batch_put_gateway(&b,gateway,"last_tx",body_hash);
        if(rc||qrxdb_batch_commit(&b)!=0){qrxdb_batch_abort(&b);qrxdb_close(&db);free(venue);free(name);free(ed);free(ml);free(exp);return -1;}qrxdb_merkle_root_hex(&db,root);qrxdb_close(&db);
        mirror_gateway_field_only(chain_dir,gateway,"authority",authority);mirror_gateway_field_only(chain_dir,gateway,"status","active");mirror_gateway_field_only(chain_dir,gateway,"venue",venue);mirror_gateway_field_only(chain_dir,gateway,"name",name);mirror_gateway_field_only(chain_dir,gateway,"ed25519_pub_hex",ed);mirror_gateway_field_only(chain_dir,gateway,"mldsa65_pub_b64",ml);mirror_gateway_field_only(chain_dir,gateway,"expires_height",exp);mirror_gateway_ll_only(chain_dir,gateway,"updated_height",h);mirror_gateway_field_only(chain_dir,gateway,"last_tx",body_hash);
        journal_append(chain_dir,"velocity_gateway_register gateway=%s venue=%s authority=%s state_root=%s",gateway,venue,authority,root);
        free(venue);free(name);free(ed);free(ml);free(exp);return 0;
    }
    if(!strcmp(tx_type,"GATEWAY_REVOKE")){
        rc|=velocity_batch_put_gateway(&b,gateway,"status","revoked");rc|=velocity_batch_put_gateway_ll(&b,gateway,"revoked_height",h);rc|=velocity_batch_put_gateway_ll(&b,gateway,"updated_height",h);rc|=velocity_batch_put_gateway(&b,gateway,"last_tx",body_hash);
        if(rc||qrxdb_batch_commit(&b)!=0){qrxdb_batch_abort(&b);qrxdb_close(&db);return -1;}qrxdb_merkle_root_hex(&db,root);qrxdb_close(&db);
        mirror_gateway_field_only(chain_dir,gateway,"status","revoked");mirror_gateway_ll_only(chain_dir,gateway,"revoked_height",h);mirror_gateway_ll_only(chain_dir,gateway,"updated_height",h);mirror_gateway_field_only(chain_dir,gateway,"last_tx",body_hash);
        journal_append(chain_dir,"velocity_gateway_revoke gateway=%s authority=%s state_root=%s",gateway,authority,root);return 0;
    }
    qrxdb_batch_abort(&b);qrxdb_close(&db);return -1;
}
static int gateway_status_cmd(const char *chain_dir,const char *gateway){
    const char *fields[]={"authority","status","venue","name","ed25519_pub_hex","mldsa65_pub_b64","expires_height","updated_height","revoked_height","last_tx",NULL};int found=0;printf("gateway=%s\n",gateway);
    for(int i=0;fields[i];i++){char *v=gateway_db_get_field(chain_dir,gateway,fields[i]);if(v){printf("%s=%s\n",fields[i],v);found=1;free(v);}}if(!found)die("gateway not found");return 0;
}
static int list_gateways_cmd(const char *chain_dir,const char *venue_filter){
    char path[1024];gateway_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);if(!txt)return 0;const char *cur=txt,suffix[]=".status=";
    while(cur&&*cur){const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);const char *suf=NULL;if(len>8&&!strncmp(cur,"gateway.",8)){for(size_t i=8;i+strlen(suffix)<len;i++)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}}
        if(suf){size_t glen=(size_t)(suf-(cur+8));if(glen>0&&glen<512){char gw[512];memcpy(gw,cur+8,glen);gw[glen]=0;char *venue=gateway_db_get_field(chain_dir,gw,"venue"),*status=gateway_db_get_field(chain_dir,gw,"status");if((!venue_filter||!*venue_filter||(venue&&!strcasecmp(venue_filter,venue)))&&status)printf("gateway=%s venue=%s status=%s\n",gw,venue?venue:"",status);if(venue)free(venue);if(status)free(status);}}
        cur=e?e+1:NULL;}free(txt);return 0;
}
static void validate_execution_report_tx(const char *chain_dir,const char *gateway,const char *owner,const char *payload,const char *tx_ed,const char *tx_ml){
    char *order_id=payload_get_field(payload,"order_id"),*status=payload_get_field(payload,"status"),*filled_s=payload_get_field(payload,"filled_quantity_atoms"),*price_s=payload_get_field(payload,"avg_price_atoms"),*fee_s=payload_get_field(payload,"venue_fee_atoms"),*venue_order_id=payload_get_field(payload,"venue_order_id"),*seq_s=payload_get_field(payload,"report_sequence");
    if(!order_id||!status||!filled_s||!price_s||!fee_s||!venue_order_id||!seq_s)die("execution report payload incomplete");
    validate_simple_payload_value(order_id,"order_id");validate_simple_payload_value(status,"report status");validate_simple_payload_value(venue_order_id,"venue_order_id");
    if(strcasecmp(status,"SUBMITTED")&&strcasecmp(status,"PARTIALLY_FILLED")&&strcasecmp(status,"FILLED")&&strcasecmp(status,"REJECTED")&&strcasecmp(status,"CANCELED"))die("invalid execution report status");
    char *gw_status=gateway_db_get_field(chain_dir,gateway,"status"),*gw_venue=gateway_db_get_field(chain_dir,gateway,"venue"),*gw_ed=gateway_db_get_field(chain_dir,gateway,"ed25519_pub_hex"),*gw_ml=gateway_db_get_field(chain_dir,gateway,"mldsa65_pub_b64");
    long long gw_exp=gateway_db_get_ll(chain_dir,gateway,"expires_height",0);if(!gw_status||strcmp(gw_status,"active")||gw_exp<=current_height_from_chain(chain_dir))die("execution gateway is not active");if(!gw_ed||strcmp(gw_ed,tx_ed)||!gw_ml||strcmp(gw_ml,tx_ml))die("execution gateway key mismatch");
    char *kind=order_db_get_field(chain_dir,order_id,"kind"),*order_owner=order_db_get_field(chain_dir,order_id,"owner"),*order_venue=order_db_get_field(chain_dir,order_id,"venue"),*order_status=order_db_get_field(chain_dir,order_id,"status");
    if(!kind||strcmp(kind,"external"))die("execution report target is not an external order");if(!order_owner||strcmp(order_owner,owner))die("execution report owner mismatch");if(!order_venue||!gw_venue||strcasecmp(order_venue,gw_venue))die("gateway venue does not match external order venue");
    if(!order_status||(!strcmp(order_status,"filled")||!strcmp(order_status,"rejected")||!strcmp(order_status,"canceled")))die("external order is already terminal");
    long long qty=order_db_get_ll(chain_dir,order_id,"quantity_atoms",0),prev_filled=order_db_get_ll(chain_dir,order_id,"external_filled_atoms",0),prev_seq=order_db_get_ll(chain_dir,order_id,"execution_report_sequence",0);
    long long filled=parse_nonnegative_ll_strict(filled_s,"filled_quantity_atoms"),price=parse_nonnegative_ll_strict(price_s,"avg_price_atoms"),vfee=parse_nonnegative_ll_strict(fee_s,"venue_fee_atoms"),seq=parse_positive_ll_strict(seq_s,"report_sequence");(void)vfee;
    if(seq!=prev_seq+1)die("execution report sequence mismatch");if(filled<prev_filled||filled>qty)die("invalid cumulative external fill quantity");if(filled>0&&price<=0)die("filled execution report requires avg_price_atoms > 0");
    if(!strcasecmp(status,"PARTIALLY_FILLED")&&(filled<=0||filled>=qty))die("PARTIALLY_FILLED requires 0 < filled < quantity");if(!strcasecmp(status,"FILLED")&&filled!=qty)die("FILLED requires filled_quantity_atoms == order quantity");
    free(order_id);free(status);free(filled_s);free(price_s);free(fee_s);free(venue_order_id);free(seq_s);if(gw_status)free(gw_status);if(gw_venue)free(gw_venue);if(gw_ed)free(gw_ed);if(gw_ml)free(gw_ml);if(kind)free(kind);if(order_owner)free(order_owner);if(order_venue)free(order_venue);if(order_status)free(order_status);
}
static int execution_report_apply_tx(const char *chain_dir,const char *gateway,const char *owner,const char *payload,const char *body_hash){
    char *order_id=payload_get_field(payload,"order_id"),*status=payload_get_field(payload,"status"),*filled_s=payload_get_field(payload,"filled_quantity_atoms"),*price_s=payload_get_field(payload,"avg_price_atoms"),*fee_s=payload_get_field(payload,"venue_fee_atoms"),*venue_order_id=payload_get_field(payload,"venue_order_id"),*seq_s=payload_get_field(payload,"report_sequence");
    long long filled=atoll(filled_s),price=atoll(price_s),vfee=atoll(fee_s),seq=atoll(seq_s),h=current_height_from_chain(chain_dir);const char *mapped=!strcasecmp(status,"SUBMITTED")?"submitted":!strcasecmp(status,"PARTIALLY_FILLED")?"partially_filled":!strcasecmp(status,"FILLED")?"filled":!strcasecmp(status,"REJECTED")?"rejected":"canceled";
    QrxDB db;QrxDBBatch b;if(qrxdb_init(&db,chain_dir)!=0)return -1;if(qrxdb_batch_begin(&db,&b)!=0){qrxdb_close(&db);return -1;}char k[1024],report_key[1024],report_val[2048];int rc=0;
    velocity_order_key(k,sizeof(k),order_id,"status");rc|=qrxdb_batch_put(&b,k,mapped);velocity_order_key(k,sizeof(k),order_id,"external_filled_atoms");rc|=velocity_batch_put_ll(&b,k,filled);velocity_order_key(k,sizeof(k),order_id,"external_avg_price_atoms");rc|=velocity_batch_put_ll(&b,k,price);velocity_order_key(k,sizeof(k),order_id,"external_venue_fee_atoms");rc|=velocity_batch_put_ll(&b,k,vfee);velocity_order_key(k,sizeof(k),order_id,"venue_order_id");rc|=qrxdb_batch_put(&b,k,venue_order_id);velocity_order_key(k,sizeof(k),order_id,"execution_gateway");rc|=qrxdb_batch_put(&b,k,gateway);velocity_order_key(k,sizeof(k),order_id,"execution_report_sequence");rc|=velocity_batch_put_ll(&b,k,seq);velocity_order_key(k,sizeof(k),order_id,"updated_height");rc|=velocity_batch_put_ll(&b,k,h);velocity_order_key(k,sizeof(k),order_id,"last_execution_report");rc|=qrxdb_batch_put(&b,k,body_hash);
    snprintf(report_key,sizeof(report_key),"velocity:execution_report:%s",body_hash);snprintf(report_val,sizeof(report_val),"order_id=%s\ngateway=%s\nowner=%s\nstatus=%s\nfilled_quantity_atoms=%lld\navg_price_atoms=%lld\nvenue_fee_atoms=%lld\nvenue_order_id=%s\nreport_sequence=%lld\nheight=%lld\n",order_id,gateway,owner,mapped,filled,price,vfee,venue_order_id,seq,h);rc|=qrxdb_batch_put(&b,report_key,report_val);
    if(rc||qrxdb_batch_commit(&b)!=0){qrxdb_batch_abort(&b);qrxdb_close(&db);return -1;}char root[129];qrxdb_merkle_root_hex(&db,root);qrxdb_close(&db);
    mirror_order_field_only(chain_dir,order_id,"status",mapped);mirror_order_ll_only(chain_dir,order_id,"external_filled_atoms",filled);mirror_order_ll_only(chain_dir,order_id,"external_avg_price_atoms",price);mirror_order_ll_only(chain_dir,order_id,"external_venue_fee_atoms",vfee);mirror_order_field_only(chain_dir,order_id,"venue_order_id",venue_order_id);mirror_order_field_only(chain_dir,order_id,"execution_gateway",gateway);mirror_order_ll_only(chain_dir,order_id,"execution_report_sequence",seq);mirror_order_ll_only(chain_dir,order_id,"updated_height",h);mirror_order_field_only(chain_dir,order_id,"last_execution_report",body_hash);
    journal_append(chain_dir,"velocity_execution_report report=%s order=%s gateway=%s status=%s state_root=%s",body_hash,order_id,gateway,mapped,root);
    free(order_id);free(status);free(filled_s);free(price_s);free(fee_s);free(venue_order_id);free(seq_s);return 0;
}
static int execution_report_status_cmd(const char *chain_dir,const char *report_id){char key[1024];snprintf(key,sizeof(key),"velocity:execution_report:%s",report_id);char *v=velocity_qrxdb_get_alloc(chain_dir,key);if(!v)die("execution report not found");printf("report_id=%s\n%s",report_id,v);free(v);return 0;}
static int state_root_cmd(const char *chain_dir){QrxDB db;if(qrxdb_init(&db,chain_dir)!=0)die("qrxdb init failed");char root[129];qrxdb_merkle_root_hex(&db,root);printf("generation=%llu\nstate_root=%s\n",(unsigned long long)qrxdb_generation(&db),root);qrxdb_close(&db);return 0;}
static int settlement_status_cmd(const char *chain_dir,const char *trade_id){char key[1024];snprintf(key,sizeof(key),"velocity:settlement:%s",trade_id);char *v=velocity_qrxdb_get_alloc(chain_dir,key);if(!v)die("settlement not found");printf("trade_id=%s\n%s",trade_id,v);free(v);return state_root_cmd(chain_dir);}

static int create_gateway_register_raw_tx_cmd(const char *chain_dir,const char *authority,const char *gateway,const char *venue,const char *name,const char *gateway_ed,const char *gateway_ml,const char *gateway_exp,const char *authority_ed,const char *authority_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){
    char payload[8192];snprintf(payload,sizeof(payload),"venue=%s;name=%s;gateway_ed25519_pub_hex=%s;gateway_mldsa65_pub_b64=%s;expires_height=%s",venue,name,gateway_ed,gateway_ml,gateway_exp);return create_velocity_raw_tx_cmd(chain_dir,authority,gateway,"0",authority_ed,authority_ml,"GATEWAY_REGISTER",lane,tx_exp,payload,fee,nonce);
}
static int create_gateway_revoke_raw_tx_cmd(const char *chain_dir,const char *authority,const char *gateway,const char *authority_ed,const char *authority_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){
    return create_velocity_raw_tx_cmd(chain_dir,authority,gateway,"0",authority_ed,authority_ml,"GATEWAY_REVOKE",lane,tx_exp,"reason=authority_revoked",fee,nonce);
}
static int create_execution_report_raw_tx_cmd(const char *chain_dir,const char *gateway,const char *owner,const char *order_id,const char *status,const char *filled,const char *price,const char *venue_fee,const char *venue_order_id,const char *report_seq,const char *gateway_ed,const char *gateway_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){
    char payload[4096];snprintf(payload,sizeof(payload),"order_id=%s;status=%s;filled_quantity_atoms=%s;avg_price_atoms=%s;venue_fee_atoms=%s;venue_order_id=%s;report_sequence=%s",order_id,status,filled,price,venue_fee,venue_order_id,report_seq);return create_velocity_raw_tx_cmd(chain_dir,gateway,owner,"0",gateway_ed,gateway_ml,"EXECUTION_REPORT",lane,tx_exp,payload,fee,nonce);
}
/* === End VELOCITY Phase 3C === */

static int btc_spv_funding_security_current(const char *chain_dir,const char *sid,uint64_t *conf_out,int *active_out,int *safe_out);
#include "velocity/qrx_crosschain.inc"
#include "velocity/qrx_btc_spv.inc"

static int trading_info_cmd(const char *chain_dir) {(void)chain_dir;printf("feature_level=%d\nagent_signed_orders=true\nnative_order_state=true\nnative_matching=true\nnative_settlement=true\nnative_settlement_crash_atomic=true\nsettlement_batch=true\nsettlement_qrxdb_wal=true\nsettlement_state_root=true\nouter_apply_wal_atomic=true\nfee_nonce_applied_atomic=true\nqrxdb_authoritative_apply_state=true\nlegacy_state_mirrors_non_authoritative=true\npending_native_match_recovery=true\nnative_asset_ledger=true\nnative_stablecoins=false\nexternal_stablecoin_markets=true\nexternal_order_intents=true\nexternal_gateway_registry=true\nexternal_execution_reports=true\ncross_venue_arbitrage=true\narbitrage_live_requires_confirmation=true\narbitrage_time_in_force=IOC\nprice_scale_atoms=%lld\nnative_asset_decimals=8\nsupported_native_order_types=LIMIT,MARKET_WITH_PROTECTION_PRICE\nsupported_sides=BUY,SELL\nmatching_rule=price_then_created_height_then_order_id\nexecution_price=maker_limit_price\npermissions=TRADE,TRADE_NATIVE,TRADE_EXTERNAL,TRADE_CROSSCHAIN,ARBITRAGE_CROSS_VENUE\ncrosschain_market=BTC/QUB\ncrosschain_settlement=HTLC_SHA256_P2WSH_CSV\ncrosschain_qbtc=false\ncrosschain_bridge=false\ncrosschain_exact_fill_only=true\ncrosschain_bitcoin_spv_consensus=true\nbitcoin_spv_phase=3D.1\nbitcoin_spv_headers_on_qrx_consensus=true\nbitcoin_spv_merkle_proofs=true\nbitcoin_spv_reorg_tracking=true\ngateway_authority=dev_address\ndaily_limit_basis=block_time_derived_24h_epoch\n",QRX_VELOCITY_FEATURE_LEVEL,(long long)QRX_TRADE_PRICE_SCALE);return 0;}

static int create_order_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *market,const char *side,const char *otype,const char *qty,const char *price,const char *order_exp,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char payload[4096];snprintf(payload,sizeof(payload),"market=%s;side=%s;order_type=%s;quantity_atoms=%s;limit_price_atoms=%s;order_expires_height=%s",market,side,otype,qty,price,order_exp);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"ORDER_CREATE",lane,tx_exp,payload,fee,nonce);}
static int create_external_order_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *venue,const char *market,const char *side,const char *otype,const char *qty,const char *price,const char *order_exp,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char payload[4096];snprintf(payload,sizeof(payload),"venue=%s;market=%s;side=%s;order_type=%s;quantity_atoms=%s;limit_price_atoms=%s;order_expires_height=%s",venue,market,side,otype,qty,price,order_exp);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"EXTERNAL_ORDER",lane,tx_exp,payload,fee,nonce);}
static int create_arbitrage_hedge_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *source_order,const char *arb_id,const char *qty,const char *price,const char *order_exp,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char payload[4096];snprintf(payload,sizeof(payload),"venue=KRAKEN;market=BTC/EUR;side=SELL;order_type=LIMIT;quantity_atoms=%s;limit_price_atoms=%s;order_expires_height=%s;time_in_force=IOC;arbitrage_id=%s;source_order_id=%s",qty,price,order_exp,arb_id,source_order);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"EXTERNAL_ORDER",lane,tx_exp,payload,fee,nonce);}
static int create_order_cancel_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *order_id,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char payload[1024];snprintf(payload,sizeof(payload),"order_id=%s",order_id);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"ORDER_CANCEL",lane,tx_exp,payload,fee,nonce);}
static int create_order_replace_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *order_id,const char *market,const char *side,const char *otype,const char *qty,const char *price,const char *order_exp,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char payload[4096];snprintf(payload,sizeof(payload),"order_id=%s;market=%s;side=%s;order_type=%s;quantity_atoms=%s;limit_price_atoms=%s;order_expires_height=%s",order_id,market,side,otype,qty,price,order_exp);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"ORDER_REPLACE",lane,tx_exp,payload,fee,nonce);}
/* === End VELOCITY Phase 3B === */

static int create_velocity_raw_tx_cmd(const char *chain_dir, const char *from, const char *to, const char *amount,
    const char *ed_pub_hex, const char *mldsa_pub_b64, const char *tx_type, const char *lane_s,
    const char *expiry_height_s, const char *payload, const char *fee, const char *nonce) {
    if (!from || !*from || !to || !*to) die("missing from/to");
    if (!velocity_tx_type_supported(tx_type)) die("unsupported velocity tx_type");
    if (tx_type && strcmp(tx_type, "TRANSFER_FAST") != 0) parse_nonnegative_ll_strict(amount, "amount");
    else parse_positive_ll_strict(amount, "amount");
    long long lane = 0;
    if (velocity_parse_lane(lane_s, &lane) != 0) die("invalid lane_id");
    long long current_height = current_height_from_chain(chain_dir);
    long long expiry_height = parse_positive_ll_strict(expiry_height_s, "expiry_height");
    if (expiry_height <= current_height) die("expiry_height must be greater than current chain height");
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    char *genesis_hash = chain_cfg_value(chain_dir, "genesis_hash");
    char *protocol_version = chain_cfg_value(chain_dir, "protocol_version");
    char fee_s[32], nonce_s[32], ts_s[32], lane_buf[32];
    if (fee && *fee) { parse_nonnegative_ll_strict(fee, "fee"); snprintf(fee_s, sizeof(fee_s), "%s", fee); }
    else {
        long long fee_atoms = qrx_chain_get_ll_at_height_or_default(chain_dir, current_height + 1, "tx_fee_atoms", 1000LL);
        if (fee_atoms < 0) fee_atoms = 0;
        snprintf(fee_s, sizeof(fee_s), "%lld", fee_atoms);
    }
    if (nonce && *nonce) { parse_positive_ll_strict(nonce, "nonce"); snprintf(nonce_s, sizeof(nonce_s), "%s", nonce); }
    else snprintf(nonce_s, sizeof(nonce_s), "%lld", velocity_get_lane_nonce(chain_dir, from, lane) + 1);
    snprintf(ts_s, sizeof(ts_s), "%lld", (long long)time(NULL));
    snprintf(lane_buf, sizeof(lane_buf), "%lld", lane);
    const char *safe_payload = payload && *payload ? payload : "-";
    const char *safe_ed = ed_pub_hex && *ed_pub_hex ? ed_pub_hex : "UNSIGNED";
    const char *safe_ml = mldsa_pub_b64 && *mldsa_pub_b64 ? mldsa_pub_b64 : "UNSIGNED";
    char *body = canonical_velocity_tx_body(network_id, genesis_hash, protocol_version, tx_type, from, to, amount, fee_s,
        lane_buf, nonce_s, ts_s, expiry_height_s, safe_payload, safe_ed, safe_ml);
    char hash3[129], hash2[65]; hash_primary_hex((unsigned char*)body, strlen(body), hash3); hash_legacy_hex((unsigned char*)body, strlen(body), hash2);
    printf("%s", body);
    printf("body_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\nsigned=false\n", hash3, hash2);
    free(network_id); free(genesis_hash); free(protocol_version); free(body);
    return 0;
}

static char *canonical_tx_body(const char *network_id, const char *genesis_hash, const char *protocol_version,
    const char *from, const char *to, const char *amount, const char *fee, const char *nonce, const char *timestamp, const char *memo,
    const char *ed_pub_hex, const char *mldsa_pub_b64) {
    size_t cap = strlen(network_id)+strlen(genesis_hash)+strlen(protocol_version)+strlen(from)+strlen(to)+strlen(amount)+strlen(fee)+strlen(nonce)+strlen(timestamp)+strlen(memo)+strlen(ed_pub_hex)+strlen(mldsa_pub_b64)+512;
    char *buf = malloc(cap);
    snprintf(buf, cap,
        "network_id=%s\n"
        "genesis_hash=%s\n"
        "protocol_version=%s\n"
        "from=%s\n"
        "to=%s\n"
        "amount=%s\n"
        "fee=%s\n"
        "nonce=%s\n"
        "timestamp=%s\n"
        "memo=%s\n"
        "ed25519_pub_hex=%s\n"
        "mldsa65_pub_b64=%s\n",
        network_id, genesis_hash, protocol_version, from, to, amount, fee, nonce, timestamp, memo, ed_pub_hex, mldsa_pub_b64);
    return buf;
}

static int sign_cmd_from(const char *wallet_dir, const char *chain_dir, const char *source_address, const char *to, const char *amount, const char *memo, const char *tx_file) {
    char pass[256]; if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");
    char key_dir[1536]; snprintf(key_dir,sizeof(key_dir),"%s",wallet_dir);
    char *primary = wallet_address(wallet_dir); if (!primary) die("missing wallet address"); primary[strcspn(primary,"\r\n")]=0;
    const char *requested = source_address && *source_address ? source_address : primary;
    if(strcmp(requested,primary)!=0) {
        if(strstr(requested,"/") || strstr(requested,"\\") || strstr(requested,"..")) die("invalid source address");
        snprintf(key_dir,sizeof(key_dir),"%s/addresses/%s",wallet_dir,requested);
        char ap[1800]; snprintf(ap,sizeof(ap),"%s/address.txt",key_dir); char *child_addr=read_file(ap,NULL);
        if(!child_addr) die("source address is not controlled by this wallet"); child_addr[strcspn(child_addr,"\r\n")]=0;
        if(strcmp(child_addr,requested)!=0){free(child_addr);die("source address key directory mismatch");} free(child_addr);
    }
    char p[1800];
    snprintf(p, sizeof(p), "%s/ed25519_priv.pem", key_dir); EVP_PKEY *ed_priv = load_priv_pem(p, pass); if (!ed_priv) die("load ed priv failed");
    snprintf(p, sizeof(p), "%s/mldsa65_priv.pem", key_dir); EVP_PKEY *ml_priv = load_priv_pem(p, pass); if (!ml_priv) die("load mldsa priv failed");
    snprintf(p, sizeof(p), "%s/ed25519_pub.pem", key_dir); EVP_PKEY *ed_pub = load_pub_pem(p); if (!ed_pub) die("load ed pub failed");
    snprintf(p, sizeof(p), "%s/mldsa65_pub.pem", key_dir); EVP_PKEY *ml_pub = load_pub_pem(p); if (!ml_pub) die("load mldsa pub failed");

    char *from = strdup(requested); if (!from) die("source allocation failed");
    if(address_matches_pub(ed_pub,from)!=0) die("source address does not match selected Ed25519 key");
    free(primary);
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    char *genesis_hash = chain_cfg_value(chain_dir, "genesis_hash");
    char *protocol_version = chain_cfg_value(chain_dir, "protocol_version");

    /* QRXDB is authoritative for the account nonce. This also keeps wallet
       signing correct immediately after WAL crash recovery, before legacy flat
       compatibility mirrors have been refreshed. */
    long long nonce = velocity_get_lane_nonce(chain_dir, from, 0) + 1;
    char nonce_s[32], ts_s[32], fee_s[32]; snprintf(nonce_s, sizeof(nonce_s), "%lld", nonce); snprintf(ts_s, sizeof(ts_s), "%lld", (long long)time(NULL));
    long long fee_atoms = qrx_chain_get_ll_at_height_or_default(chain_dir, current_height_from_chain(chain_dir) + 1, "tx_fee_atoms", 1000LL);
    if (fee_atoms < 0) fee_atoms = 0;
    snprintf(fee_s, sizeof(fee_s), "%lld", fee_atoms);

    unsigned char edraw[32]; if (ed25519_raw_pub(ed_pub, edraw) != 0) die("raw ed pub failed");
    char *ed_pub_hex = bytes_to_hex(edraw, sizeof(edraw));
    char *ml_pem = pubkey_to_pem_string(ml_pub); char *ml_pem_b64 = base64_encode((unsigned char*)ml_pem, strlen(ml_pem));
    char *body = canonical_tx_body(network_id, genesis_hash, protocol_version, from, to, amount, fee_s, nonce_s, ts_s, memo, ed_pub_hex, ml_pem_b64);
    unsigned char *sig1=NULL, *sig2=NULL; size_t sig1len=0, sig2len=0;
    if (sign_oneshot(ed_priv, (unsigned char*)body, strlen(body), &sig1, &sig1len) != 0) die("ed25519 sign failed");
    if (sign_oneshot(ml_priv, (unsigned char*)body, strlen(body), &sig2, &sig2len) != 0) die("mldsa sign failed");
    char *sig1_hex = bytes_to_hex(sig1, sig1len); char *sig2_hex = bytes_to_hex(sig2, sig2len);
    char body_hash_sha3[129]; hash_primary_hex((unsigned char*)body, strlen(body), body_hash_sha3);
    char body_hash_sha256[65]; hash_legacy_hex((unsigned char*)body, strlen(body), body_hash_sha256);

    size_t outcap = strlen(body)+strlen(sig1_hex)+strlen(sig2_hex)+512;
    char *out = malloc(outcap);
    snprintf(out, outcap, "%sbody_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\nsig_ed25519_hex=%s\nsig_mldsa65_hex=%s\n", body, body_hash_sha3, body_hash_sha256, sig1_hex, sig2_hex);
    if (write_text(tx_file, out) != 0) die("write tx failed");

    puts(tx_file);
    free(from); free(network_id); free(genesis_hash); free(protocol_version); free(ed_pub_hex); free(ml_pem); free(ml_pem_b64); free(body); free(sig1); free(sig2); free(sig1_hex); free(sig2_hex); free(out);
    EVP_PKEY_free(ed_priv); EVP_PKEY_free(ml_priv); EVP_PKEY_free(ed_pub); EVP_PKEY_free(ml_pub);
    OPENSSL_cleanse(pass, sizeof(pass));
    return 0;
}

static int sign_cmd(const char *wallet_dir, const char *chain_dir, const char *to, const char *amount, const char *memo, const char *tx_file) {
    return sign_cmd_from(wallet_dir,chain_dir,NULL,to,amount,memo,tx_file);
}

static int getnonce_cmd(const char *chain_dir, const char *addr, const char *lane_s) {
    if(!addr || !*addr) die("missing address");
    long long lane = 0;
    if (velocity_parse_lane(lane_s, &lane) != 0) die("invalid lane_id");
    printf("%lld\n", velocity_get_lane_nonce(chain_dir, addr, lane));
    return 0;
}

static int create_raw_tx_cmd(const char *chain_dir, const char *from, const char *to, const char *amount,
                             const char *ed_pub_hex, const char *mldsa_pub_b64,
                             const char *memo, const char *fee, const char *nonce, const char *timestamp) {
    if(!from || !*from || !to || !*to) die("missing from/to");
    parse_positive_ll_strict(amount, "amount");
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    char *genesis_hash = chain_cfg_value(chain_dir, "genesis_hash");
    char *protocol_version = chain_cfg_value(chain_dir, "protocol_version");
    char fee_s[32], nonce_s[32], ts_s[32];
    if(fee && *fee) {
        parse_nonnegative_ll_strict(fee, "fee");
        snprintf(fee_s, sizeof(fee_s), "%s", fee);
    } else {
        long long fee_atoms = qrx_chain_get_ll_at_height_or_default(chain_dir, current_height_from_chain(chain_dir) + 1, "tx_fee_atoms", 1000LL);
        if(fee_atoms < 0) fee_atoms = 0;
        snprintf(fee_s, sizeof(fee_s), "%lld", fee_atoms);
    }
    if(nonce && *nonce) {
        parse_positive_ll_strict(nonce, "nonce");
        snprintf(nonce_s, sizeof(nonce_s), "%s", nonce);
    } else {
        char noncepath_bin[1024];
        state_paths(chain_dir, NULL, 0, noncepath_bin, sizeof(noncepath_bin), NULL, 0, NULL, 0);
        snprintf(nonce_s, sizeof(nonce_s), "%lld", kv_get_ll_bin(noncepath_bin, from) + 1);
    }
    if(timestamp && *timestamp) snprintf(ts_s, sizeof(ts_s), "%s", timestamp);
    else snprintf(ts_s, sizeof(ts_s), "%lld", (long long)time(NULL));
    const char *safe_memo = memo && *memo ? memo : "payment";
    const char *safe_ed = ed_pub_hex && *ed_pub_hex ? ed_pub_hex : "UNSIGNED";
    const char *safe_ml = mldsa_pub_b64 && *mldsa_pub_b64 ? mldsa_pub_b64 : "UNSIGNED";
    char *body = canonical_tx_body(network_id, genesis_hash, protocol_version, from, to, amount, fee_s, nonce_s, ts_s, safe_memo, safe_ed, safe_ml);
    char body_hash_sha3[129]; hash_primary_hex((unsigned char*)body, strlen(body), body_hash_sha3);
    char body_hash_sha256[65]; hash_legacy_hex((unsigned char*)body, strlen(body), body_hash_sha256);
    printf("%s", body);
    printf("body_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\n", body_hash_sha3, body_hash_sha256);
    printf("signed=false\n");
    free(network_id); free(genesis_hash); free(protocol_version); free(body);
    return 0;
}

static int signrawtransactionwithwallet_cmd(const char *wallet_dir, const char *chain_dir, const char *raw_tx_file, const char *signed_tx_file) {
    char *tx = read_file(raw_tx_file, NULL); if(!tx) die("cannot read raw tx");
    char *tx_version = cfg_get(tx, "tx_version");
    char *from_in = cfg_get(tx, "from");
    char *to = cfg_get(tx, "to");
    char *amount = cfg_get(tx, "amount");
    char *fee = cfg_get(tx, "fee");
    char *nonce = cfg_get(tx, "nonce");
    char *timestamp = cfg_get(tx, "timestamp");
    char *memo = cfg_get(tx, "memo");
    char *tx_type = cfg_get(tx, "tx_type");
    char *lane_id = cfg_get(tx, "lane_id");
    char *expiry_height = cfg_get(tx, "expiry_height");
    char *payload = cfg_get(tx, "payload");
    int is_velocity = tx_version && atoi(tx_version) == QRX_VELOCITY_TX_VERSION;
    if (!gov_tx_version_allowed(chain_dir, tx_version)) die("obsolete transaction version: mandatory protocol update required");
    if(!to || !amount || !fee || !nonce || !timestamp) die("raw tx missing required fields");
    if(is_velocity && (!tx_type || !lane_id || !expiry_height || !payload)) die("velocity raw tx missing required fields");
    char *from = wallet_address(wallet_dir); if(!from) die("missing wallet address");
    from[strcspn(from, "\r\n")] = 0;
    if(from_in && *from_in && strcmp(from_in, from) != 0) die("raw tx from does not match wallet address");

    char pass[256]; if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");
    char p[1024];
    snprintf(p, sizeof(p), "%s/ed25519_priv.pem", wallet_dir); EVP_PKEY *ed_priv = load_priv_pem(p, pass); if (!ed_priv) die("load ed priv failed");
    snprintf(p, sizeof(p), "%s/mldsa65_priv.pem", wallet_dir); EVP_PKEY *ml_priv = load_priv_pem(p, pass); if (!ml_priv) die("load mldsa priv failed");
    snprintf(p, sizeof(p), "%s/ed25519_pub.pem", wallet_dir); EVP_PKEY *ed_pub = load_pub_pem(p); if (!ed_pub) die("load ed pub failed");
    snprintf(p, sizeof(p), "%s/mldsa65_pub.pem", wallet_dir); EVP_PKEY *ml_pub = load_pub_pem(p); if (!ml_pub) die("load mldsa pub failed");

    char *network_id = chain_cfg_value(chain_dir, "network_id");
    char *genesis_hash = chain_cfg_value(chain_dir, "genesis_hash");
    char *protocol_version = chain_cfg_value(chain_dir, "protocol_version");
    unsigned char edraw[32]; if (ed25519_raw_pub(ed_pub, edraw) != 0) die("raw ed pub failed");
    char *ed_pub_hex = bytes_to_hex(edraw, sizeof(edraw));
    char *ml_pem = pubkey_to_pem_string(ml_pub); char *ml_pem_b64 = base64_encode((unsigned char*)ml_pem, strlen(ml_pem));
    char *body = is_velocity
        ? canonical_velocity_tx_body(network_id, genesis_hash, protocol_version, tx_type, from, to, amount, fee, lane_id, nonce, timestamp, expiry_height, payload, ed_pub_hex, ml_pem_b64)
        : canonical_tx_body(network_id, genesis_hash, protocol_version, from, to, amount, fee, nonce, timestamp, memo ? memo : "payment", ed_pub_hex, ml_pem_b64);
    unsigned char *sig1=NULL, *sig2=NULL; size_t sig1len=0, sig2len=0;
    if (sign_oneshot(ed_priv, (unsigned char*)body, strlen(body), &sig1, &sig1len) != 0) die("ed25519 sign failed");
    if (sign_oneshot(ml_priv, (unsigned char*)body, strlen(body), &sig2, &sig2len) != 0) die("mldsa sign failed");
    char *sig1_hex = bytes_to_hex(sig1, sig1len); char *sig2_hex = bytes_to_hex(sig2, sig2len);
    char body_hash_sha3[129]; hash_primary_hex((unsigned char*)body, strlen(body), body_hash_sha3);
    char body_hash_sha256[65]; hash_legacy_hex((unsigned char*)body, strlen(body), body_hash_sha256);
    size_t outcap = strlen(body)+strlen(sig1_hex)+strlen(sig2_hex)+512;
    char *out = malloc(outcap); if(!out) die("oom");
    snprintf(out, outcap, "%sbody_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\nsig_ed25519_hex=%s\nsig_mldsa65_hex=%s\nsigned=true\n", body, body_hash_sha3, body_hash_sha256, sig1_hex, sig2_hex);
    if(write_text(signed_tx_file, out) != 0) die("write signed tx failed");
    puts(signed_tx_file);
    OPENSSL_cleanse(pass, sizeof(pass));
    free(tx); if(tx_version) free(tx_version); if(from_in) free(from_in); free(to); free(amount); free(fee); free(nonce); free(timestamp); if(memo) free(memo); if(tx_type) free(tx_type); if(lane_id) free(lane_id); if(expiry_height) free(expiry_height); if(payload) free(payload); free(from);
    free(network_id); free(genesis_hash); free(protocol_version); free(ed_pub_hex); free(ml_pem); free(ml_pem_b64); free(body); free(sig1); free(sig2); free(sig1_hex); free(sig2_hex); free(out);
    EVP_PKEY_free(ed_priv); EVP_PKEY_free(ml_priv); EVP_PKEY_free(ed_pub); EVP_PKEY_free(ml_pub);
    return 0;
}

static int decoderawtransaction_cmd(const char *chain_dir, const char *tx_file) {
    (void)chain_dir;
    char *tx = read_file(tx_file, NULL); if(!tx) die("cannot read tx");
    const char *keys[] = {"tx_version","network_id","genesis_hash","protocol_version","tx_type","from","to","amount","fee","lane_id","nonce","timestamp","expiry_height","payload","memo","ed25519_pub_hex","mldsa65_pub_b64","body_hash_algo","body_hash_sha3_512","body_hash_sha256_legacy","sig_ed25519_hex","sig_mldsa65_hex","signed",NULL};
    for(int i=0; keys[i]; ++i){ char *v = cfg_get(tx, keys[i]); if(v){ printf("%s=%s\n", keys[i], v); free(v); } }
    free(tx); return 0;
}

static int txid_cmd(const char *chain_dir, const char *tx_file) {
    (void)chain_dir;
    char *tx = read_file(tx_file, NULL); if(!tx) die("cannot read tx");
    char *h = cfg_get(tx, "body_hash_sha3_512");
    if(!h) h = cfg_get(tx, "body_hash");
    if(!h) die("tx has no body hash");
    printf("%s\n", h);
    free(h); free(tx); return 0;
}

static int gov_tx_version_allowed(const char*chain,const char*tx_version);
static int validate_privacy_consensus_tx(const char *chain_dir,const char *tx_type,const char *from,const char *to,const char *amount_s,const char *payload);
static int atomic_stage_privacy(QrxDBBatch *b,const char *chain_dir,const char *from,const char *to,const char *tx_type,const char *payload,const char *txid,long long height,long long amount);
static int kyc_provider_id_from_qualifier(const char *qualifier,char out[96]);
static int kyc_provider_active_for_qualifier(const char *chain_dir,const char *qualifier,char *authority,size_t authsz);
static int privacy_mirror_authoritative(const char *chain_dir);
static int verify_tx_text(const char *chain_dir, const char *tx) {
    char *tx_version = cfg_get(tx, "tx_version");
    int is_velocity = tx_version && atoi(tx_version) == QRX_VELOCITY_TX_VERSION;
    if (!gov_tx_version_allowed(chain_dir, tx_version)) die("obsolete transaction version: mandatory protocol update required");
    char *network_id = cfg_get(tx, "network_id");
    char *genesis_hash = cfg_get(tx, "genesis_hash");
    char *protocol_version = cfg_get(tx, "protocol_version");
    char *from = cfg_get(tx, "from"); char *to = cfg_get(tx, "to"); char *amount = cfg_get(tx, "amount");
    char *fee = cfg_get(tx, "fee"); char *nonce = cfg_get(tx, "nonce"); char *timestamp = cfg_get(tx, "timestamp");
    char *memo = cfg_get(tx, "memo"); char *tx_type = cfg_get(tx, "tx_type"); char *lane_id = cfg_get(tx, "lane_id");
    char *expiry_height = cfg_get(tx, "expiry_height"); char *payload = cfg_get(tx, "payload");
    char *ed_pub_hex = cfg_get(tx, "ed25519_pub_hex"); char *ml_pub_b64 = cfg_get(tx, "mldsa65_pub_b64");
    char *body_hash_algo = cfg_get(tx, "body_hash_algo"); char *body_hash_sha3 = cfg_get(tx, "body_hash_sha3_512");
    char *body_hash_sha256_legacy = cfg_get(tx, "body_hash_sha256_legacy"); char *body_hash_legacy = cfg_get(tx, "body_hash");
    char *sig1_hex = cfg_get(tx, "sig_ed25519_hex"); char *sig2_hex = cfg_get(tx, "sig_mldsa65_hex");
    if (!network_id||!genesis_hash||!protocol_version||!from||!to||!amount||!fee||!nonce||!timestamp||!ed_pub_hex||!ml_pub_b64||!sig1_hex||!sig2_hex) die("invalid tx fields");
    if (!is_velocity && !memo) die("legacy tx missing memo");
    if (is_velocity && (!tx_type||!lane_id||!expiry_height||!payload)) die("velocity tx missing fields");
    if (is_velocity && !velocity_tx_type_supported(tx_type)) die("unsupported velocity tx_type");
    if (!(body_hash_algo || body_hash_sha3 || body_hash_legacy)) die("missing tx hash fields");
    char *exp_net = chain_cfg_value(chain_dir, "network_id"); char *exp_gen = chain_cfg_value(chain_dir, "genesis_hash"); char *exp_ver = chain_cfg_value(chain_dir, "protocol_version");
    if (strcmp(network_id, exp_net) || strcmp(genesis_hash, exp_gen) || strcmp(protocol_version, exp_ver)) die("tx network binding mismatch");
    if (!*from || !*to) die("invalid tx addresses");
    long long amt_check = (is_velocity && tx_type && strcmp(tx_type, "TRANSFER_FAST") != 0) ? parse_nonnegative_ll_strict(amount, "amount") : parse_positive_ll_strict(amount, "amount");
    long long fee_check = parse_nonnegative_ll_strict(fee, "fee"); long long debit_check = 0;
    checked_add_ll(amt_check, fee_check, "amount plus fee", &debit_check);
    long long lane = 0;
    if (is_velocity) {
        if (velocity_parse_lane(lane_id, &lane) != 0) die("invalid lane_id");
        long long expiry = parse_positive_ll_strict(expiry_height, "expiry_height");
        if (current_height_from_chain(chain_dir) > expiry) die("transaction expired");
    }
    char *body = is_velocity
        ? canonical_velocity_tx_body(network_id, genesis_hash, protocol_version, tx_type, from, to, amount, fee, lane_id, nonce, timestamp, expiry_height, payload, ed_pub_hex, ml_pub_b64)
        : canonical_tx_body(network_id, genesis_hash, protocol_version, from, to, amount, fee, nonce, timestamp, memo, ed_pub_hex, ml_pub_b64);
    char body_hash_sha3_calc[129]; hash_primary_hex((unsigned char*)body, strlen(body), body_hash_sha3_calc);
    char body_hash_sha256_calc[65]; hash_legacy_hex((unsigned char*)body, strlen(body), body_hash_sha256_calc);
    const char *applied_key = NULL;
    if (body_hash_algo || body_hash_sha3) {
        if (!body_hash_algo || strcmp(body_hash_algo, "sha3-512") != 0) die("unsupported tx hash algo");
        if (!body_hash_sha3 || strcmp(body_hash_sha3, body_hash_sha3_calc) != 0) die("body sha3-512 mismatch");
        if (body_hash_sha256_legacy && strcmp(body_hash_sha256_legacy, body_hash_sha256_calc) != 0) die("body sha256 legacy mismatch");
        applied_key = body_hash_sha3;
    } else { if (strcmp(body_hash_legacy, body_hash_sha256_calc) != 0) die("body hash mismatch"); applied_key = body_hash_legacy; }
    unsigned char edraw[32]; size_t edlen=0; if (hex_to_bytes(ed_pub_hex, edraw, sizeof(edraw), &edlen) != 0 || edlen != 32) die("invalid ed pub hex");
    EVP_PKEY *ed_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, edraw, edlen); if (!ed_pub) die("ed pub construct failed");
    if (address_matches_pub(ed_pub, from) != 0) die("from address mismatch");
    size_t mlpemlen=0; unsigned char *mlpem = base64_decode(ml_pub_b64, &mlpemlen); if (!mlpem) die("bad ML-DSA b64");
    char *mlpemstr = malloc(mlpemlen+1); memcpy(mlpemstr, mlpem, mlpemlen); mlpemstr[mlpemlen]=0;
    EVP_PKEY *ml_pub = pubkey_from_pem_string(mlpemstr); if (!ml_pub) die("ml pub parse failed");
    unsigned char *sig1=malloc(strlen(sig1_hex)/2+1), *sig2=malloc(strlen(sig2_hex)/2+1); size_t sig1len=0,sig2len=0;
    if (hex_to_bytes(sig1_hex, sig1, strlen(sig1_hex)/2+1, &sig1len) != 0) die("bad sig1");
    if (hex_to_bytes(sig2_hex, sig2, strlen(sig2_hex)/2+1, &sig2len) != 0) die("bad sig2");
    if (verify_oneshot(ed_pub, (unsigned char*)body, strlen(body), sig1, sig1len) != 0) die("ed25519 verify failed");
    if (verify_oneshot(ml_pub, (unsigned char*)body, strlen(body), sig2, sig2len) != 0) die("ML-DSA verify failed");
    long long current = velocity_get_lane_nonce(chain_dir, from, lane); long long n = parse_positive_ll_strict(nonce, "nonce");
    if (current == LLONG_MAX) die("nonce overflow"); if (n != current + 1) die("invalid nonce: expected lane nonce + 1");
    char applpath[1024]; state_paths(chain_dir, NULL, 0, NULL, 0, applpath, sizeof(applpath), NULL, 0); if (applied_has_authoritative(chain_dir,applpath, applied_key)) die("already applied tx");
    if (is_velocity && (!strcmp(tx_type, "AGENT_REGISTER") || !strcmp(tx_type, "AGENT_UPDATE") || !strcmp(tx_type, "AGENT_REVOKE"))) validate_agent_fields_common(chain_dir, from, to, tx_type, payload);
    else if (is_velocity && (!strcmp(tx_type, "ORDER_CREATE") || !strcmp(tx_type, "ORDER_CANCEL") || !strcmp(tx_type, "ORDER_REPLACE") || !strcmp(tx_type, "EXTERNAL_ORDER"))) validate_trade_fields_common(chain_dir, from, to, tx_type, payload, expiry_height, ed_pub_hex, ml_pub_b64);
    else if (is_velocity && tx_type && !strcmp(tx_type, "CROSSCHAIN_ORDER")) validate_crosschain_order_fields(chain_dir, from, to, payload, expiry_height, ed_pub_hex, ml_pub_b64);
    else if (is_velocity && tx_type && (!strcmp(tx_type, "CROSSCHAIN_REDEEM") || !strcmp(tx_type, "CROSSCHAIN_REFUND"))) validate_crosschain_action(chain_dir, from, tx_type, payload);
    else if (is_velocity && tx_type && !strcmp(tx_type,"BTC_SPV_HEADER")) validate_btc_spv_header_tx(chain_dir,from,to,payload);
    else if (is_velocity && tx_type && !strcmp(tx_type,"BTC_SPV_FUNDING_PROOF")) validate_btc_spv_funding_proof_tx(chain_dir,from,to,payload);
    else if (is_velocity && (!strcmp(tx_type,"GATEWAY_REGISTER") || !strcmp(tx_type,"GATEWAY_REVOKE"))) validate_gateway_management_tx(chain_dir,from,to,tx_type,payload);
    else if (is_velocity && !strcmp(tx_type,"EXECUTION_REPORT")) validate_execution_report_tx(chain_dir,from,to,payload,ed_pub_hex,ml_pub_b64);
    else if (is_velocity && tx_type && !strncmp(tx_type,"ASSET_",6)) { /* stateful asset validation occurs in atomic WAL staging */ }
    else if (is_velocity && tx_type && !strcmp(tx_type,"GOVERNANCE_PROTOCOL")) { if(validate_privacy_consensus_tx(chain_dir,tx_type,from,to,amount,payload)!=0) die("protocol governance consensus validation failed"); }
    else if (is_velocity && tx_type && !strncmp(tx_type,"PRIVACY_",8)) {
        /* Genesis hardening (Finding 5): PRIVACY_V1 is fail-closed on Mainnet.
         * Shielded value movement requires an external cryptography audit,
         * remediation of its findings, 3-of-5 governance approval and a
         * committed PRIVACY_V1 activation height. Governance and attester
         * preparation stay available beforehand; alpha/testnet are unaffected. */
        long long ph = current_height_from_chain(chain_dir) + 1;
        if (!qrx_privacy_preflight_tx_type(tx_type) &&
            !qrx_privacy_protocol_enabled_at_height(chain_dir, ph))
            die("PRIVACY_V1 not active: external cryptography audit and governance activation required before shielded value movement");
        if(validate_privacy_consensus_tx(chain_dir,tx_type,from,to,amount,payload)!=0) die("privacy consensus validation failed");
    }
    else if (is_velocity && tx_type && !strncmp(tx_type,"GAME_",5)) { /* deterministic Generals validation occurs in atomic WAL staging */ }
    else if (is_velocity && tx_type && (!strncmp(tx_type,"STAKE_",6) || !strncmp(tx_type,"DELEGATE_",9))) { /* deterministic staking/delegation validation occurs in atomic WAL staging */ }
    else if (is_velocity && tx_type && !strncmp(tx_type,"STORAGE_",8)) {
        long long ah=current_height_from_chain(chain_dir)+1; QrxServiceEconomicEffect eff={0};
        if(!qrx_storage_protocol_enabled_at_height(chain_dir,ah)&&!qrx_storage_preflight_tx_type(tx_type)) die("DRIVE_V1 mandatory protocol upgrade not active (provider preflight only)");
        if(qrx_storage_consensus_prepare(chain_dir,tx_type,from,to,(uint64_t)amt_check,payload,applied_key,(uint64_t)ah,&eff)!=0) die("storage consensus validation failed");
    }
    else if (is_velocity && tx_type && !strncmp(tx_type,"DOMAIN_",7)) {
        long long ah=current_height_from_chain(chain_dir)+1; QrxServiceEconomicEffect eff={0};
        if(!qrx_net_protocol_enabled_at_height(chain_dir,ah)) die("QRX_NET_V1 mandatory protocol upgrade not active");
        if(qrx_net_consensus_prepare(chain_dir,tx_type,from,to,(uint64_t)amt_check,payload,applied_key,(uint64_t)ah,&eff)!=0) die("QRX-Net consensus validation failed");
    }
    else if (is_velocity && tx_type && !strncmp(tx_type,"AD_",3)) {
        long long ah=current_height_from_chain(chain_dir)+1; QrxServiceEconomicEffect eff={0};
        if(!qrx_net_protocol_enabled_at_height(chain_dir,ah)) die("QRX_NET_V1 mandatory protocol upgrade not active");
        if(!qrx_advertising_protocol_enabled_at_height(chain_dir,ah)) die("ADVERTISING_V1 mandatory protocol upgrade not active");
        if(qrx_net_consensus_prepare(chain_dir,tx_type,from,to,(uint64_t)amt_check,payload,applied_key,(uint64_t)ah,&eff)!=0) die("QRX advertising consensus validation failed");
    }
    else if (is_velocity && qrx_compute_identity_tx_type(tx_type)) {
        long long ah=current_height_from_chain(chain_dir)+1;QrxDB idb;QrxServiceEconomicEffect ie={0};
        /* Provider identity binding is a non-economic preflight operation. It may
         * run before COMPUTE_POUC_V1 so Mainnet can measure real provider readiness. */
        if(qrxdb_init(&idb,chain_dir)!=0) die("Compute provider identity QRXDB init failed");
        int irc=qrx_compute_provider_identity_prepare(&idb,tx_type,from,to,(uint64_t)amt_check,payload,(uint64_t)ah,&ie);qrxdb_close(&idb);
        if(irc!=0) die("compute provider identity validation failed");
    }
    else if (is_velocity && qrx_compute_pipeline_tx_type(tx_type)) {
        long long ah=current_height_from_chain(chain_dir)+1;QrxDB pdb;QrxPoucPipelineEffect ce={0};
        if(!qrx_compute_pouc_protocol_enabled_at_height(chain_dir,ah))die("COMPUTE_POUC_V1 mandatory protocol upgrade not active");
        if(qrxdb_init(&pdb,chain_dir)!=0)die("Compute pipeline QRXDB init failed");
        int crc=qrx_pouc_pipeline_prepare(&pdb,tx_type,from,to,(uint64_t)amt_check,payload,(uint64_t)ah,&ce);qrxdb_close(&pdb);
        if(crc!=0)die("Compute pipeline consensus validation failed");
    }
    else if (is_velocity && tx_type && !strcmp(tx_type,"POUC_SETTLEMENT")) {
        long long ah=current_height_from_chain(chain_dir)+1;QrxDB pdb;QrxPoucConsensusEffect pe={0};char *cid=chain_cfg_value(chain_dir,"chain_id");
        if(!cid||!*cid)die("PoUC chain_id missing");if(qrxdb_init(&pdb,chain_dir)!=0)die("PoUC QRXDB init failed");
        if(!qrx_compute_pouc_protocol_enabled_at_height(chain_dir,ah))die("COMPUTE_POUC_V1 mandatory protocol upgrade not active");
        int prc=qrx_pouc_consensus_prepare(&pdb,cid,exp_gen,exp_ver,tx_type,from,to,(uint64_t)amt_check,payload,1,(uint64_t)ah,&pe);qrxdb_close(&pdb);free(cid);
        if(prc!=0)die("PoUC settlement consensus validation failed");
    }
    else if (is_velocity && strcmp(tx_type, "TRANSFER_FAST") != 0) die("velocity tx schema reserved: execution not active for this tx_type");
    if(tx_version) free(tx_version); free(network_id); free(genesis_hash); free(protocol_version); free(from); free(to); free(amount); free(fee); free(nonce); free(timestamp); if(memo) free(memo); if(tx_type) free(tx_type); if(lane_id) free(lane_id); if(expiry_height) free(expiry_height); if(payload) free(payload); free(ed_pub_hex); free(ml_pub_b64); if(body_hash_algo) free(body_hash_algo); if(body_hash_sha3) free(body_hash_sha3); if(body_hash_sha256_legacy) free(body_hash_sha256_legacy); if(body_hash_legacy) free(body_hash_legacy); free(sig1_hex); free(sig2_hex); free(exp_net); free(exp_gen); free(exp_ver); free(body); free(mlpem); free(mlpemstr); free(sig1); free(sig2); EVP_PKEY_free(ed_pub); EVP_PKEY_free(ml_pub);
    return 0;
}

static int velocity_stateless_verify_cb(void *ctx, const char *tx, char *err, size_t err_sz) {
    const char *chain_dir=(const char*)ctx; int rc=-1;
    char *tx_version=cfg_get(tx,"tx_version"),*network_id=cfg_get(tx,"network_id"),*genesis_hash=cfg_get(tx,"genesis_hash"),*protocol_version=cfg_get(tx,"protocol_version");
    char *from=cfg_get(tx,"from"),*to=cfg_get(tx,"to"),*amount=cfg_get(tx,"amount"),*fee=cfg_get(tx,"fee"),*nonce=cfg_get(tx,"nonce"),*timestamp=cfg_get(tx,"timestamp"),*memo=cfg_get(tx,"memo");
    char *tx_type=cfg_get(tx,"tx_type"),*lane_id=cfg_get(tx,"lane_id"),*expiry_height=cfg_get(tx,"expiry_height"),*payload=cfg_get(tx,"payload"),*ed_pub_hex=cfg_get(tx,"ed25519_pub_hex"),*ml_pub_b64=cfg_get(tx,"mldsa65_pub_b64");
    char *body_hash_algo=cfg_get(tx,"body_hash_algo"),*body_hash_sha3=cfg_get(tx,"body_hash_sha3_512"),*body_hash_legacy=cfg_get(tx,"body_hash"),*sig1_hex=cfg_get(tx,"sig_ed25519_hex"),*sig2_hex=cfg_get(tx,"sig_mldsa65_hex");
    char *exp_net=NULL,*exp_gen=NULL,*exp_ver=NULL,*body=NULL,*mlpemstr=NULL; unsigned char *mlpem=NULL,*sig1=NULL,*sig2=NULL; EVP_PKEY *ed_pub=NULL,*ml_pub=NULL;
    if(!network_id||!genesis_hash||!protocol_version||!from||!to||!amount||!fee||!nonce||!timestamp||!ed_pub_hex||!ml_pub_b64||!sig1_hex||!sig2_hex){snprintf(err,err_sz,"missing fields");goto done;}
    int is_velocity=tx_version&&atoi(tx_version)==QRX_VELOCITY_TX_VERSION;if(is_velocity&&(!tx_type||!lane_id||!expiry_height||!payload)){snprintf(err,err_sz,"missing velocity fields");goto done;}if(!is_velocity&&!memo){snprintf(err,err_sz,"missing memo");goto done;}
    exp_net=chain_cfg_value(chain_dir,"network_id");exp_gen=chain_cfg_value(chain_dir,"genesis_hash");exp_ver=chain_cfg_value(chain_dir,"protocol_version");if(!exp_net||!exp_gen||!exp_ver||strcmp(network_id,exp_net)||strcmp(genesis_hash,exp_gen)||strcmp(protocol_version,exp_ver)){snprintf(err,err_sz,"network binding");goto done;}
    body=is_velocity?canonical_velocity_tx_body(network_id,genesis_hash,protocol_version,tx_type,from,to,amount,fee,lane_id,nonce,timestamp,expiry_height,payload,ed_pub_hex,ml_pub_b64):canonical_tx_body(network_id,genesis_hash,protocol_version,from,to,amount,fee,nonce,timestamp,memo,ed_pub_hex,ml_pub_b64);
    if(body_hash_algo||body_hash_sha3){char calc[129];hash_primary_hex((unsigned char*)body,strlen(body),calc);if(!body_hash_algo||strcmp(body_hash_algo,"sha3-512")||!body_hash_sha3||strcmp(body_hash_sha3,calc)){snprintf(err,err_sz,"sha3 body hash");goto done;}}else if(body_hash_legacy){char calc[65];hash_legacy_hex((unsigned char*)body,strlen(body),calc);if(strcmp(body_hash_legacy,calc)){snprintf(err,err_sz,"legacy body hash");goto done;}}else{snprintf(err,err_sz,"missing body hash");goto done;}
    unsigned char edraw[32];size_t edlen=0;if(hex_to_bytes(ed_pub_hex,edraw,sizeof(edraw),&edlen)||edlen!=32){snprintf(err,err_sz,"ed pub");goto done;}ed_pub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,edraw,edlen);if(!ed_pub||address_matches_pub(ed_pub,from)!=0){snprintf(err,err_sz,"ed address");goto done;}
    size_t mlpemlen=0;mlpem=base64_decode(ml_pub_b64,&mlpemlen);if(!mlpem){snprintf(err,err_sz,"mldsa b64");goto done;}mlpemstr=(char*)malloc(mlpemlen+1);if(!mlpemstr)goto done;memcpy(mlpemstr,mlpem,mlpemlen);mlpemstr[mlpemlen]=0;ml_pub=pubkey_from_pem_string(mlpemstr);if(!ml_pub){snprintf(err,err_sz,"mldsa pub");goto done;}
    size_t sig1len=0,sig2len=0;sig1=(unsigned char*)malloc(strlen(sig1_hex)/2+1);sig2=(unsigned char*)malloc(strlen(sig2_hex)/2+1);if(!sig1||!sig2||hex_to_bytes(sig1_hex,sig1,strlen(sig1_hex)/2+1,&sig1len)||hex_to_bytes(sig2_hex,sig2,strlen(sig2_hex)/2+1,&sig2len)){snprintf(err,err_sz,"signature encoding");goto done;}
    if(verify_oneshot(ed_pub,(unsigned char*)body,strlen(body),sig1,sig1len)!=0){snprintf(err,err_sz,"ed25519 verify");goto done;}if(verify_oneshot(ml_pub,(unsigned char*)body,strlen(body),sig2,sig2len)!=0){snprintf(err,err_sz,"mldsa verify");goto done;}rc=0;
done:
    if(tx_version)free(tx_version);if(network_id)free(network_id);if(genesis_hash)free(genesis_hash);if(protocol_version)free(protocol_version);if(from)free(from);if(to)free(to);if(amount)free(amount);if(fee)free(fee);if(nonce)free(nonce);if(timestamp)free(timestamp);if(memo)free(memo);if(tx_type)free(tx_type);if(lane_id)free(lane_id);if(expiry_height)free(expiry_height);if(payload)free(payload);if(ed_pub_hex)free(ed_pub_hex);if(ml_pub_b64)free(ml_pub_b64);if(body_hash_algo)free(body_hash_algo);if(body_hash_sha3)free(body_hash_sha3);if(body_hash_legacy)free(body_hash_legacy);if(sig1_hex)free(sig1_hex);if(sig2_hex)free(sig2_hex);if(exp_net)free(exp_net);if(exp_gen)free(exp_gen);if(exp_ver)free(exp_ver);if(body)free(body);if(mlpem)free(mlpem);if(mlpemstr)free(mlpemstr);if(sig1)free(sig1);if(sig2)free(sig2);EVP_PKEY_free(ed_pub);EVP_PKEY_free(ml_pub);return rc;
}

/* ---------------------------------------------------------------------------
 * QRX 0.0.9 Genesis hardening - untrusted transaction ingress.
 *
 * Layered so that unauthenticated peers cannot reach the process-fatal
 * stateful validation paths at all:
 *
 *   untrusted P2P TX
 *        |
 *        v
 *   [1] hard size / shape limits          (no allocation, no die())
 *        |
 *        v
 *   [2] velocity_stateless_verify_cb()    structured errors, self-cleaning.
 *        |                                Rejects malformed fields, wrong
 *        |                                network/genesis binding, bad body
 *        |                                hashes, bad base64, bad public keys
 *        |                                and invalid Ed25519 / ML-DSA
 *        |                                signatures without ever calling die().
 *        v
 *   [3] verify_tx_text() under the fault barrier
 *        |                                Only transactions carrying valid
 *        |                                hybrid signatures over a correctly
 *        |                                bound body reach the stateful checks.
 *        v
 *   VALID  ->  mempool
 *   ERROR  ->  "status=ERR reason=bad_tx" + peer penalty, node stays online.
 *
 * Never calls exit()/abort() on network input.
 * ------------------------------------------------------------------------- */

/* Upper bound for a single decoded transaction accepted from the network. */
#define QRX_UNTRUSTED_TX_MAX_BYTES 131072

static int verify_tx_text_untrusted(const char *chain_dir, const char *tx,
                                    char *err, size_t err_sz) {
    int rc;
    char stateless_err[256];

    if (err && err_sz) err[0] = 0;
    if (!chain_dir || !tx) { if (err && err_sz) snprintf(err, err_sz, "no tx"); return -1; }

    /* [1] Shape limits before any parsing/allocation. */
    {
        size_t n = strlen(tx);
        if (n == 0)                              { if (err && err_sz) snprintf(err, err_sz, "empty tx"); return -1; }
        if (n > QRX_UNTRUSTED_TX_MAX_BYTES)      { if (err && err_sz) snprintf(err, err_sz, "oversized tx"); return -1; }
    }

    /* [2] Leak-free stateless gate. Rejects the bulk of malformed input,
     *     including every unsigned / wrongly signed transaction, without
     *     entering any die()-capable code path. */
    stateless_err[0] = 0;
    if (velocity_stateless_verify_cb((void*)chain_dir, tx, stateless_err, sizeof(stateless_err)) != 0) {
        if (err && err_sz) snprintf(err, err_sz, "%s", stateless_err[0] ? stateless_err : "invalid tx");
        return -1;
    }

    /* [3] Stateful validation under the fault barrier. */
    if (qrx_untrusted_guard_active()) {
        /* Defensive: never nest guards, the jmp_buf would be overwritten. */
        if (err && err_sz) snprintf(err, err_sz, "validation reentry");
        return -1;
    }
    g_untrusted_guard_reason[0] = 0;
    if (setjmp(g_untrusted_guard_jmp) != 0) {
        /* A die() inside the stateful path unwound to here. */
        g_untrusted_guard_depth = 0;
        if (err && err_sz)
            snprintf(err, err_sz, "%s",
                     g_untrusted_guard_reason[0] ? g_untrusted_guard_reason : "invalid tx");
        return -1;
    }
    g_untrusted_guard_depth = 1;
    rc = verify_tx_text(chain_dir, tx);
    g_untrusted_guard_depth = 0;

    if (rc != 0 && err && err_sz) snprintf(err, err_sz, "invalid tx");
    return rc;
}

static int velocity_mempool_plan_cmd(const char *node_dir,int max_txs,int workers){
    char conf[1024];snprintf(conf,sizeof(conf),"%s/node.conf",node_dir);char *cfg=read_file(conf,NULL);if(!cfg)die("missing node.conf");char *chain_dir=cfg_get(cfg,"chain_dir");if(!chain_dir)die("node.conf missing chain_dir");
    QrxVelocityMempool pool;QrxVelocityPlan plan;QrxVelocityMempoolStats ms;QrxVelocityVerifyStats vs;unsigned char *mask=NULL;if(qrx_velocity_mempool_open(&pool,node_dir,MEMPOOL_MAX_TXS)!=0)die("velocity mempool open failed");if(qrx_velocity_mempool_plan(&pool,max_txs>0?(size_t)max_txs:0,&plan)!=0)die("velocity plan failed");
    if(qrx_velocity_parallel_verify(&plan,workers>0?(uint32_t)workers:1,velocity_stateless_verify_cb,chain_dir,&mask,&vs)!=0)die("parallel signature verification failed");qrx_velocity_mempool_stats(&pool,&ms);
    printf("engine=VELOCITY_PHASE4F\nentries=%llu\nselected=%zu\nshards=%u\nwaves=%u\nconflicts=%llu\ndependency_edges=%llu\nbarrier_nodes=%llu\nbarrier_fences=%llu\ncritical_path_nodes=%u\nmax_parallel_width=%u\nschedule_hash=%s\nverify_workers=%u\nverify_ok=%llu\nverify_failed=%llu\nverify_elapsed_us=%llu\n",
      (unsigned long long)ms.entries,plan.count,ms.shards,plan.wave_count,(unsigned long long)plan.conflicts,(unsigned long long)plan.dependency_edges,(unsigned long long)plan.barrier_nodes,(unsigned long long)plan.barrier_fences,plan.critical_path_nodes,plan.max_parallel_width,plan.schedule_hash,vs.workers,(unsigned long long)vs.ok,(unsigned long long)vs.failed,(unsigned long long)vs.elapsed_us);
    for(size_t i=0;i<plan.count;i++){uint8_t ac=qrx_velocity_tx_adapter_class(plan.txs[i]);const char *an=ac==QRX_VELOCITY_ADAPTER_TRANSFER?"transfer":ac==QRX_VELOCITY_ADAPTER_STATEFUL?"stateful":ac==QRX_VELOCITY_ADAPTER_DYNAMIC?"dynamic":"barrier";printf("tx=%s wave=%u valid=%u adapter=%s\n",plan.txids[i],plan.waves[i],mask[i],an);}
    free(mask);qrx_velocity_plan_free(&plan);qrx_velocity_mempool_close(&pool);free(chain_dir);free(cfg);return 0;
}


static int velocity_engine_info_cmd(const char *node_dir){
    QrxVelocityMempool pool;QrxVelocityMempoolStats st;QrxVelocityPlan plan;memset(&plan,0,sizeof(plan));
    if(qrx_velocity_mempool_open(&pool,node_dir,MEMPOOL_MAX_TXS)!=0)die("velocity mempool open failed");
    if(qrx_velocity_mempool_stats(&pool,&st)!=0){qrx_velocity_mempool_close(&pool);return 1;}
    size_t sample=st.entries>2048?2048:(size_t)st.entries;if(qrx_velocity_mempool_plan(&pool,sample,&plan)!=0){qrx_velocity_mempool_close(&pool);return 1;}
    printf("phase=4F.2\nengine=VELOCITY_DETERMINISTIC_BLOCK_GRAPH_MVCC\ncross_venue_arbitrage=true\npaper_trading=true\ncomplete_csv_ledger=true\narbitrage_permission=ARBITRAGE_CROSS_VENUE\narbitrage_live_confirmation=true\narbitrage_hedge_tif=IOC\nram_mempool=true\nwal=true\nwal_group_commit_records=64\nshards=%u\nmax_txs=%llu\ncurrent_txs=%llu\ncurrent_bytes=%llu\nplanner_sample=%zu\nplanner_waves=%u\nplanner_conflicts=%llu\ndependency_graph=true\ndependency_edges=%llu\nbarrier_nodes=%llu\nbarrier_fences=%llu\nbarrier_full_fence=true\ncritical_path_nodes=%u\nmax_parallel_width=%u\nschedule_hash_sha3_512=%s\nschedule_version=1\nparallel_signature_verification=true\nconflict_detection=true\nparallel_execution_waves=true\ndeterministic_graph_levels=true\nmvcc_snapshot_execution=true\nisolated_write_sets=true\nruntime_readset_tracking=true\npredicate_prefix_tracking=true\nspeculative_parallel_execution=true\ndeterministic_conflict_resolution=true\nselective_retry=true\nconflict_winner_order=plan_index\nparallel_transfer_fast_prepare=true\nstateful_mvcc_adapters=true\nparallel_agent_state_prepare=true\nparallel_gateway_state_prepare=true\ndynamic_writeset_expansion=true\ndynamic_native_order_adapter=true\ndynamic_same_wave_allowed=true\nnative_matching_barrier=false\nnative_matching_snapshot_discovery=true\nnative_settlement_same_wal_batch=true\ncrosschain_barrier=true\nexternal_execution_barrier=true\nbitcoin_spv_reorg_barrier=true\nconflict_recheck_before_commit=true\ndeterministic_merge=true\nsingle_wal_batch_per_mvcc_batch=true\ndeterministic_order=fee_desc_txid_asc\ndeterministic_commit=true\nstate_commit=qrxdb_wal_atomic\nstate_root=true\nparallel_state_mutation=dependency_graph_waves_speculative_snapshot_runtime_occ_selective_retry\ncomplex_stateful_tx_parallel=native_dynamic_speculative_wave\n",
        st.shards,(unsigned long long)st.max_entries,(unsigned long long)st.entries,(unsigned long long)st.bytes,plan.count,plan.wave_count,(unsigned long long)plan.conflicts,(unsigned long long)plan.dependency_edges,(unsigned long long)plan.barrier_nodes,(unsigned long long)plan.barrier_fences,plan.critical_path_nodes,plan.max_parallel_width,plan.schedule_hash);
    qrx_velocity_plan_free(&plan);qrx_velocity_mempool_close(&pool);return 0;
}

static int velocity_mvcc_execute_cmd(const char *node_dir,int max_txs,int workers){
    char conf[1024];snprintf(conf,sizeof(conf),"%s/node.conf",node_dir);char *cfg=read_file(conf,NULL);if(!cfg)die("missing node.conf");char *chain_dir=cfg_get(cfg,"chain_dir");if(!chain_dir)die("node.conf missing chain_dir");
    if(max_txs<=0)max_txs=100;if(workers<=0)workers=4;if(workers>64)workers=64;
    QrxVelocityMempool pool;QrxVelocityPlan plan;unsigned char *valid=NULL;QrxVelocityVerifyStats vst;QrxVelocityMvccStats mst;memset(&plan,0,sizeof(plan));memset(&vst,0,sizeof(vst));memset(&mst,0,sizeof(mst));
    if(qrx_velocity_mempool_open(&pool,node_dir,MEMPOOL_MAX_TXS)!=0)die("velocity mempool open failed");
    if(qrx_velocity_mempool_plan(&pool,(size_t)max_txs,&plan)!=0){qrx_velocity_mempool_close(&pool);die("velocity plan failed");}
    if(qrx_velocity_parallel_verify(&plan,(uint32_t)workers,velocity_stateless_verify_cb,chain_dir,&valid,&vst)!=0){qrx_velocity_plan_free(&plan);qrx_velocity_mempool_close(&pool);die("parallel signature verification failed");}
    QrxDB db;if(qrxdb_init(&db,chain_dir)!=0){free(valid);qrx_velocity_plan_free(&plan);qrx_velocity_mempool_close(&pool);die("QRXDB init failed");}
    long long height=current_height_from_chain(chain_dir)+1;int rc=qrx_velocity_mvcc_execute_batch(&db,&plan,valid,(uint32_t)workers,height,&mst);
    if(rc==QRX_MVCC_BARRIER){
        printf("status=BARRIER_REQUIRED\nreason=remaining_serial_adapter\nprepared=%llu\nstateful_prepared=%llu\ndynamic_prepared=%llu\nbarriers=%llu\nstate_unchanged=true\n",(unsigned long long)mst.prepared,(unsigned long long)mst.stateful_prepared,(unsigned long long)mst.dynamic_prepared,(unsigned long long)mst.barriers);
    }else if(rc==QRX_MVCC_UNSUPPORTED){
        printf("status=FALLBACK_REQUIRED\nreason=unsupported_adapter\nprepared=%llu\nunsupported=%llu\nstate_unchanged=true\n",(unsigned long long)mst.prepared,(unsigned long long)mst.unsupported);
    }else if(rc==QRX_MVCC_RETRY){
        printf("status=RETRY\nreason=snapshot_generation_changed\nstate_unchanged=true\n");
    }else if(rc==QRX_MVCC_OK){
        for(size_t i=0;i<plan.count;i++)if(!valid||valid[i])qrx_velocity_mempool_remove(&pool,plan.txids[i]);qrx_velocity_mempool_checkpoint(&pool);
        printf("status=COMMITTED\nprepared=%llu\ncommitted=%llu\nstateful_prepared=%llu\ndynamic_prepared=%llu\ndynamic_discovered_keys=%llu\ndynamic_trades=%llu\nexpired_orders=%llu\nspeculative_prepared=%llu\nruntime_read_keys=%llu\nruntime_read_prefixes=%llu\nconflict_edges=%llu\ndeterministic_conflicts=%llu\nselective_retries=%llu\nspeculative_winners=%llu\nwaves=%u\nworkers=%u\nsnapshot_generation=%llu\ncommit_generation=%llu\nmerged_writes=%llu\nprepare_us=%llu\ncommit_us=%llu\nstate_root=%s\n",
            (unsigned long long)mst.prepared,(unsigned long long)mst.committed,(unsigned long long)mst.stateful_prepared,(unsigned long long)mst.dynamic_prepared,(unsigned long long)mst.dynamic_discovered_keys,(unsigned long long)mst.dynamic_trades,(unsigned long long)mst.expired_orders,(unsigned long long)mst.speculative_prepared,(unsigned long long)mst.runtime_read_keys,(unsigned long long)mst.runtime_read_prefixes,(unsigned long long)mst.conflict_edges,(unsigned long long)mst.deterministic_conflicts,(unsigned long long)mst.selective_retries,(unsigned long long)mst.speculative_winners,mst.waves,mst.workers,(unsigned long long)mst.snapshot_generation,(unsigned long long)mst.commit_generation,(unsigned long long)mst.merged_writes,(unsigned long long)mst.prepare_us,(unsigned long long)mst.commit_us,mst.state_root);
        printf("scheduler_dependency_edges=%llu\nscheduler_barrier_fences=%llu\nscheduler_critical_path_nodes=%u\nscheduler_max_parallel_width=%u\nscheduler_hash=%s\n",(unsigned long long)plan.dependency_edges,(unsigned long long)plan.barrier_fences,plan.critical_path_nodes,plan.max_parallel_width,plan.schedule_hash);
    }else{
        printf("status=ERROR\nfailed=%llu\nstate_unchanged=true\n",(unsigned long long)mst.failed);
    }
    qrxdb_close(&db);free(valid);qrx_velocity_plan_free(&plan);qrx_velocity_mempool_close(&pool);free(chain_dir);free(cfg);return rc==QRX_MVCC_OK?0:((rc==QRX_MVCC_UNSUPPORTED||rc==QRX_MVCC_BARRIER)?2:1);
}

static int verify_cmd(const char *chain_dir, const char *tx_file) {
    char *tx = read_file(tx_file, NULL); if (!tx) die("cannot read tx");
    int rc = verify_tx_text(chain_dir, tx); free(tx); puts(rc == 0 ? "OK" : "FAIL"); return rc;
}

/* === VELOCITY 0.0.7 Phase 3C+ : single WAL-backed outer apply commit === */
static int atomic_batch_put_balance(QrxDBBatch *b,const char *address,long long value){
    char k[768];snprintf(k,sizeof(k),"acct:balance:%s",address);return velocity_batch_put_ll(b,k,value);
}
static int atomic_batch_put_nonce(QrxDBBatch *b,const char *address,long long lane,long long value){
    char k[768];if(lane==0)snprintf(k,sizeof(k),"acct:nonce:%s",address);else snprintf(k,sizeof(k),"velocity:nonce:%s:%lld",address,lane);return velocity_batch_put_ll(b,k,value);
}
static int atomic_batch_put_applied(QrxDBBatch *b,const char *txid,long long height){
    char k[768],v[128];snprintf(k,sizeof(k),"tx:applied:%s",txid);snprintf(v,sizeof(v),"height=%lld\napplied=1\n",height);return qrxdb_batch_put(b,k,v);
}
static int atomic_batch_put_tx_index(QrxDBBatch *b,const char *txid,const char *kind,long long height,const char *tx){
    char k[768],v[2048];snprintf(k,sizeof(k),"tx:loc:%s",txid);snprintf(v,sizeof(v),"tx_hash=%s\nblock_hash=%s\nheight=%lld\nindex=0\n",txid,kind?kind:"applytx",height);if(qrxdb_batch_put(b,k,v))return -1;
    snprintf(k,sizeof(k),"tx:payload:%s",txid);if(qrxdb_batch_put(b,k,tx?tx:""))return -1;
    snprintf(k,sizeof(k),"consensus:applytx:%s",txid);snprintf(v,sizeof(v),"height=%lld\ntype=%s\ncommitted=1\n",height,kind?kind:"LEGACY_TRANSFER");return qrxdb_batch_put(b,k,v);
}
static int atomic_stage_agent(QrxDBBatch *b,const char *owner,const char *agent,const char *tx_type,const char *payload,const char *body_hash,long long h){
    char k[1024],hb[64];snprintf(hb,sizeof(hb),"%lld",h);int rc=0;
#define PUT_AGENT(F,V) do{velocity_agent_key(k,sizeof(k),agent,(F));rc|=qrxdb_batch_put(b,k,(V)?(V):"");}while(0)
    if(!strcmp(tx_type,"AGENT_REGISTER")||!strcmp(tx_type,"AGENT_UPDATE")){
        char *ed=payload_get_field(payload,"agent_ed25519_pub_hex"),*ml=payload_get_field(payload,"agent_mldsa65_pub_b64"),*perm=payload_get_field(payload,"permissions"),*max_trade=payload_get_field(payload,"max_trade_atoms"),*daily=payload_get_field(payload,"daily_limit_atoms"),*markets=payload_get_field(payload,"market_allowlist"),*exp=payload_get_field(payload,"expires_height");
        PUT_AGENT("owner",owner);PUT_AGENT("status","active");if(ed)PUT_AGENT("ed25519_pub_hex",ed);if(ml)PUT_AGENT("mldsa65_pub_b64",ml);PUT_AGENT("permissions",perm);PUT_AGENT("max_trade_atoms",max_trade);PUT_AGENT("daily_limit_atoms",daily);PUT_AGENT("market_allowlist",markets);PUT_AGENT("expires_height",exp);PUT_AGENT("updated_height",hb);PUT_AGENT("last_tx",body_hash);
        free(ed);free(ml);free(perm);free(max_trade);free(daily);free(markets);free(exp);
    } else if(!strcmp(tx_type,"AGENT_REVOKE")){
        PUT_AGENT("status","revoked");PUT_AGENT("revoked_height",hb);PUT_AGENT("updated_height",hb);PUT_AGENT("last_tx",body_hash);
    } else rc=-1;
#undef PUT_AGENT
    return rc? -1:0;
}
static int atomic_stage_order_payload(QrxDBBatch *b,const char *order_id,const char *agent,const char *owner,const char *kind,const char *status,const char *payload,const char *body_hash,const char *replaces,long long h){
    const char *fields[]={"market","side","order_type","quantity_atoms","limit_price_atoms","order_expires_height","venue","client_order_id","time_in_force","arbitrage_id","source_order_id","hashlock_hex","btc_redeem_pubkey_hex","btc_refund_pubkey_hex","btc_refund_csv_blocks","qrx_refund_height",NULL};int rc=0;
    rc|=velocity_batch_put_order(b,order_id,"owner",owner);rc|=velocity_batch_put_order(b,order_id,"agent",agent);rc|=velocity_batch_put_order(b,order_id,"kind",kind);rc|=velocity_batch_put_order(b,order_id,"status",status);rc|=velocity_batch_put_order_ll(b,order_id,"created_height",h);rc|=velocity_batch_put_order_ll(b,order_id,"updated_height",h);rc|=velocity_batch_put_order(b,order_id,"last_tx",body_hash?body_hash:order_id);if(replaces&&*replaces)rc|=velocity_batch_put_order(b,order_id,"replaces",replaces);
    for(int i=0;fields[i];++i){char *v=payload_get_field(payload,fields[i]);if(v){rc|=velocity_batch_put_order(b,order_id,fields[i],v);free(v);}}
    char *q=payload_get_field(payload,"quantity_atoms");if(q){long long qty=parse_positive_ll_strict(q,"quantity_atoms");rc|=velocity_batch_put_order_ll(b,order_id,"filled_atoms",0);rc|=velocity_batch_put_order_ll(b,order_id,"remaining_atoms",qty);free(q);}return rc?-1:0;
}
static int atomic_stage_agent_usage(QrxDBBatch *b,const char *chain_dir,const char *agent,long long qty){
    if(qty<=0)return 0;long long bucket=0,cur=agent_usage_current(chain_dir,agent,&bucket,NULL),next=0;checked_add_ll(cur,qty,"agent usage",&next);char k[768];snprintf(k,sizeof(k),"velocity:agent_usage:%s:%lld",agent,bucket);return velocity_batch_put_ll(b,k,next);
}
static int atomic_stage_asset_value(QrxDBBatch *b,const char *asset,const char *owner,long long value){if(value<0)return -1;return velocity_batch_put_asset_balance(b,asset,owner,value);}
static int atomic_stage_trade(QrxDBBatch *b,const char *chain_dir,const char *agent,const char *owner,const char *tx_type,const char *payload,const char *body_hash,long long h){
    if(!strcmp(tx_type,"ORDER_CREATE")||!strcmp(tx_type,"EXTERNAL_ORDER")){
        int external=!strcmp(tx_type,"EXTERNAL_ORDER");if(atomic_stage_order_payload(b,body_hash,agent,owner,external?"external":"native",external?"pending_execution":"open",payload,body_hash,NULL,h))return -1;
        char *q=payload_get_field(payload,"quantity_atoms");long long qty=parse_positive_ll_strict(q,"quantity_atoms");free(q);if(atomic_stage_agent_usage(b,chain_dir,agent,qty))return -1;
        if(!external){char *market=payload_get_field(payload,"market"),*side=payload_get_field(payload,"side"),*ps=payload_get_field(payload,"limit_price_atoms");long long price=parse_positive_ll_strict(ps,"limit_price_atoms");char asset[32];long long atoms=0;if(native_order_lock_requirements(chain_dir,owner,market,side,qty,price,asset,sizeof(asset),&atoms)) {free(market);free(side);free(ps);return -1;}long long cur=asset_balance_get(chain_dir,asset,owner);if(cur<atoms){free(market);free(side);free(ps);return -1;}if(atomic_stage_asset_value(b,asset,owner,cur-atoms)||velocity_batch_put_order(b,body_hash,"locked_asset",asset)||velocity_batch_put_order_ll(b,body_hash,"locked_atoms",atoms)||velocity_batch_put_order(b,body_hash,"settlement_version","1")){free(market);free(side);free(ps);return -1;}char pk[768];snprintf(pk,sizeof(pk),"velocity:match_pending:%s",body_hash);if(qrxdb_batch_put(b,pk,"1")){free(market);free(side);free(ps);return -1;}free(market);free(side);free(ps);}
        return 0;
    }
    if(!strcmp(tx_type,"ORDER_CANCEL")){
        char *target=payload_get_field(payload,"order_id");if(!target)return -1;char *kind=order_db_get_field(chain_dir,target,"kind");int rc=0;if(kind&&(!strcmp(kind,"native")||!strcmp(kind,"crosschain"))){char *asset=order_db_get_field(chain_dir,target,"locked_asset");long long atoms=order_db_get_ll(chain_dir,target,"locked_atoms",0);if(asset&&atoms>0){long long cur=asset_balance_get(chain_dir,asset,owner),next=0;checked_add_ll(cur,atoms,"cancel release",&next);rc|=atomic_stage_asset_value(b,asset,owner,next);}rc|=velocity_batch_put_order_ll(b,target,"locked_atoms",0);free(asset);}rc|=velocity_batch_put_order(b,target,"status",(kind&&!strcmp(kind,"external"))?"cancel_pending":"canceled");rc|=velocity_batch_put_order_ll(b,target,"updated_height",h);rc|=velocity_batch_put_order(b,target,"last_tx",body_hash);free(kind);free(target);return rc?-1:0;
    }
    if(!strcmp(tx_type,"ORDER_REPLACE")){
        char *target=payload_get_field(payload,"order_id"),*market=payload_get_field(payload,"market"),*side=payload_get_field(payload,"side"),*qs=payload_get_field(payload,"quantity_atoms"),*ps=payload_get_field(payload,"limit_price_atoms");if(!target||!market||!side||!qs||!ps){free(target);free(market);free(side);free(qs);free(ps);return -1;}long long qty=parse_positive_ll_strict(qs,"quantity_atoms"),price=parse_positive_ll_strict(ps,"limit_price_atoms");char *old_asset=order_db_get_field(chain_dir,target,"locked_asset");long long old_atoms=order_db_get_ll(chain_dir,target,"locked_atoms",0);char new_asset[32];long long new_atoms=0;/* validation already established reserve feasibility; compute required asset without relying on its old-balance return code */(void)native_order_lock_requirements(chain_dir,owner,market,side,qty,price,new_asset,sizeof(new_asset),&new_atoms);
        int rc=0;if(old_asset&&!strcasecmp(old_asset,new_asset)){long long cur=asset_balance_get(chain_dir,new_asset,owner),avail=0;checked_add_ll(cur,old_atoms,"replacement release",&avail);if(avail<new_atoms){free(target);free(market);free(side);free(qs);free(ps);free(old_asset);return -1;}rc|=atomic_stage_asset_value(b,new_asset,owner,avail-new_atoms);}else{if(old_asset&&old_atoms>0){long long cur=asset_balance_get(chain_dir,old_asset,owner),next=0;checked_add_ll(cur,old_atoms,"replacement old release",&next);rc|=atomic_stage_asset_value(b,old_asset,owner,next);}long long cur=asset_balance_get(chain_dir,new_asset,owner);if(cur<new_atoms){free(target);free(market);free(side);free(qs);free(ps);free(old_asset);return -1;}rc|=atomic_stage_asset_value(b,new_asset,owner,cur-new_atoms);}
        rc|=velocity_batch_put_order(b,target,"status","replaced");rc|=velocity_batch_put_order_ll(b,target,"updated_height",h);rc|=velocity_batch_put_order_ll(b,target,"locked_atoms",0);rc|=velocity_batch_put_order(b,target,"replacement_order_id",body_hash);rc|=velocity_batch_put_order(b,target,"last_tx",body_hash);rc|=atomic_stage_order_payload(b,body_hash,agent,owner,"native","open",payload,body_hash,target,h);rc|=velocity_batch_put_order(b,body_hash,"locked_asset",new_asset);rc|=velocity_batch_put_order_ll(b,body_hash,"locked_atoms",new_atoms);rc|=velocity_batch_put_order(b,body_hash,"settlement_version","1");rc|=atomic_stage_agent_usage(b,chain_dir,agent,qty);char pk[768];snprintf(pk,sizeof(pk),"velocity:match_pending:%s",body_hash);rc|=qrxdb_batch_put(b,pk,"1");free(target);free(market);free(side);free(qs);free(ps);free(old_asset);return rc?-1:0;
    }
    return -1;
}
static int atomic_stage_gateway(QrxDBBatch *b,const char *authority,const char *gateway,const char *tx_type,const char *payload,const char *body_hash,long long h){
    int rc=0;if(!strcmp(tx_type,"GATEWAY_REGISTER")){char *venue=payload_get_field(payload,"venue"),*name=payload_get_field(payload,"name"),*ed=payload_get_field(payload,"gateway_ed25519_pub_hex"),*ml=payload_get_field(payload,"gateway_mldsa65_pub_b64"),*exp=payload_get_field(payload,"expires_height");rc|=velocity_batch_put_gateway(b,gateway,"authority",authority);rc|=velocity_batch_put_gateway(b,gateway,"status","active");rc|=velocity_batch_put_gateway(b,gateway,"venue",venue);rc|=velocity_batch_put_gateway(b,gateway,"name",name);rc|=velocity_batch_put_gateway(b,gateway,"ed25519_pub_hex",ed);rc|=velocity_batch_put_gateway(b,gateway,"mldsa65_pub_b64",ml);rc|=velocity_batch_put_gateway(b,gateway,"expires_height",exp);rc|=velocity_batch_put_gateway_ll(b,gateway,"updated_height",h);rc|=velocity_batch_put_gateway(b,gateway,"last_tx",body_hash);free(venue);free(name);free(ed);free(ml);free(exp);}else if(!strcmp(tx_type,"GATEWAY_REVOKE")){rc|=velocity_batch_put_gateway(b,gateway,"status","revoked");rc|=velocity_batch_put_gateway_ll(b,gateway,"revoked_height",h);rc|=velocity_batch_put_gateway_ll(b,gateway,"updated_height",h);rc|=velocity_batch_put_gateway(b,gateway,"last_tx",body_hash);}else rc=-1;return rc?-1:0;
}
static int atomic_stage_execution_report(QrxDBBatch *b,const char *gateway,const char *owner,const char *payload,const char *body_hash,long long h){
    char *order_id=payload_get_field(payload,"order_id"),*status=payload_get_field(payload,"status"),*fs=payload_get_field(payload,"filled_quantity_atoms"),*ps=payload_get_field(payload,"avg_price_atoms"),*vfs=payload_get_field(payload,"venue_fee_atoms"),*venue_order_id=payload_get_field(payload,"venue_order_id"),*ss=payload_get_field(payload,"report_sequence");if(!order_id||!status||!fs||!ps||!vfs||!venue_order_id||!ss){free(order_id);free(status);free(fs);free(ps);free(vfs);free(venue_order_id);free(ss);return -1;}long long filled=parse_nonnegative_ll_strict(fs,"filled_quantity_atoms"),price=parse_nonnegative_ll_strict(ps,"avg_price_atoms"),vfee=parse_nonnegative_ll_strict(vfs,"venue_fee_atoms"),seq=parse_positive_ll_strict(ss,"report_sequence");const char *mapped=!strcasecmp(status,"SUBMITTED")?"submitted":!strcasecmp(status,"PARTIALLY_FILLED")?"partially_filled":!strcasecmp(status,"FILLED")?"filled":!strcasecmp(status,"REJECTED")?"rejected":"canceled";int rc=0;rc|=velocity_batch_put_order(b,order_id,"status",mapped);rc|=velocity_batch_put_order_ll(b,order_id,"external_filled_atoms",filled);rc|=velocity_batch_put_order_ll(b,order_id,"external_avg_price_atoms",price);rc|=velocity_batch_put_order_ll(b,order_id,"external_venue_fee_atoms",vfee);rc|=velocity_batch_put_order(b,order_id,"venue_order_id",venue_order_id);rc|=velocity_batch_put_order(b,order_id,"execution_gateway",gateway);rc|=velocity_batch_put_order_ll(b,order_id,"execution_report_sequence",seq);rc|=velocity_batch_put_order_ll(b,order_id,"updated_height",h);rc|=velocity_batch_put_order(b,order_id,"last_execution_report",body_hash);char rk[768],rv[2048];snprintf(rk,sizeof(rk),"velocity:execution_report:%s",body_hash);snprintf(rv,sizeof(rv),"order_id=%s\ngateway=%s\nowner=%s\nstatus=%s\nfilled_quantity_atoms=%lld\navg_price_atoms=%lld\nvenue_fee_atoms=%lld\nvenue_order_id=%s\nreport_sequence=%lld\nheight=%lld\n",order_id,gateway,owner,mapped,filled,price,vfee,venue_order_id,seq,h);rc|=qrxdb_batch_put(b,rk,rv);free(order_id);free(status);free(fs);free(ps);free(vfs);free(venue_order_id);free(ss);return rc?-1:0;
}
static int mirror_agent_from_authoritative(const char *chain_dir,const char *agent){const char *fields[]={"owner","status","permissions","max_trade_atoms","daily_limit_atoms","market_allowlist","expires_height","updated_height","revoked_height","last_tx","ed25519_pub_hex","mldsa65_pub_b64",NULL};char path[1024],key[768];agent_registry_path(chain_dir,path,sizeof(path));for(int i=0;fields[i];i++){char *v=agent_db_get_field(chain_dir,agent,fields[i]);if(v){if(!agent_make_key(key,sizeof(key),agent,fields[i]))text_db_set(path,key,v);free(v);}}return 0;}
static int mirror_order_from_authoritative(const char *chain_dir,const char *oid){const char *fields[]={"owner","agent","kind","venue","market","side","order_type","quantity_atoms","filled_atoms","remaining_atoms","limit_price_atoms","status","created_height","updated_height","order_expires_height","client_order_id","time_in_force","arbitrage_id","source_order_id","replaces","replacement_order_id","settlement_version","locked_asset","locked_atoms","external_filled_atoms","external_avg_price_atoms","external_venue_fee_atoms","venue_order_id","execution_gateway","execution_report_sequence","last_execution_report","last_trade_id","crosschain_session_id","hashlock_hex","btc_redeem_pubkey_hex","btc_refund_pubkey_hex","btc_refund_csv_blocks","qrx_refund_height","last_tx",NULL};for(int i=0;fields[i];i++){char *v=order_db_get_field(chain_dir,oid,fields[i]);if(v){mirror_order_field_only(chain_dir,oid,fields[i],v);free(v);}}return 0;}
static int mirror_gateway_from_authoritative(const char *chain_dir,const char *gw){const char *fields[]={"authority","status","venue","name","ed25519_pub_hex","mldsa65_pub_b64","expires_height","updated_height","revoked_height","last_tx",NULL};for(int i=0;fields[i];i++){char *v=gateway_db_get_field(chain_dir,gw,fields[i]);if(v){mirror_gateway_field_only(chain_dir,gw,fields[i],v);free(v);}}return 0;}
static void mirror_asset_authoritative(const char *chain_dir,const char *asset,const char *owner){if(asset&&*asset&&owner&&*owner)mirror_asset_balance_only(chain_dir,asset,owner,asset_balance_get(chain_dir,asset,owner));}
static void mirror_agent_usage_authoritative(const char *chain_dir,const char *agent){long long bucket=0,used=agent_usage_current(chain_dir,agent,&bucket,NULL);char path[1024],key[512];agent_usage_path(chain_dir,path,sizeof(path));snprintf(key,sizeof(key),"%s|%lld",agent,bucket);kv_set_ll_bin(path,key,used);}
static int clear_match_pending(const char *chain_dir,const char *oid){char k[768];snprintf(k,sizeof(k),"velocity:match_pending:%s",oid);return velocity_qrxdb_put(chain_dir,k,"0");}
static int postcommit_trade(const char *chain_dir,const char *agent,const char *owner,const char *tx_type,const char *payload,const char *body_hash){
    if(!strcmp(tx_type,"ORDER_CREATE")||!strcmp(tx_type,"EXTERNAL_ORDER")){mirror_order_from_authoritative(chain_dir,body_hash);mirror_agent_usage_authoritative(chain_dir,agent);if(!strcmp(tx_type,"ORDER_CREATE")){char *a=order_db_get_field(chain_dir,body_hash,"locked_asset");mirror_asset_authoritative(chain_dir,a,owner);free(a);if(match_native_order(chain_dir,body_hash)==0)clear_match_pending(chain_dir,body_hash);}return 0;}
    if(!strcmp(tx_type,"ORDER_CANCEL")){char *target=payload_get_field(payload,"order_id");if(target){char *a=order_db_get_field(chain_dir,target,"locked_asset");mirror_order_from_authoritative(chain_dir,target);mirror_asset_authoritative(chain_dir,a,owner);free(a);free(target);}return 0;}
    if(!strcmp(tx_type,"ORDER_REPLACE")){char *target=payload_get_field(payload,"order_id");if(target){char *old=order_db_get_field(chain_dir,target,"locked_asset"),*nw=order_db_get_field(chain_dir,body_hash,"locked_asset");mirror_order_from_authoritative(chain_dir,target);mirror_order_from_authoritative(chain_dir,body_hash);mirror_asset_authoritative(chain_dir,old,owner);if(!old||!nw||strcasecmp(old,nw))mirror_asset_authoritative(chain_dir,nw,owner);mirror_agent_usage_authoritative(chain_dir,agent);free(old);free(nw);free(target);if(match_native_order(chain_dir,body_hash)==0)clear_match_pending(chain_dir,body_hash);}return 0;}return 0;
}
typedef struct {char **ids;size_t count,cap;} PendingMatchList;
static int pending_match_collect_cb(const char *key,const char *value,uint32_t value_len,void *ctx){(void)value_len;PendingMatchList *l=(PendingMatchList*)ctx;if(!value||strcmp(value,"1"))return 0;const char *pfx="velocity:match_pending:";size_t pl=strlen(pfx);if(strncmp(key,pfx,pl))return 0;if(l->count==l->cap){size_t nc=l->cap?l->cap*2:8;char **nn=realloc(l->ids,nc*sizeof(*nn));if(!nn)return -1;l->ids=nn;l->cap=nc;}l->ids[l->count++]=strdup(key+pl);return l->ids[l->count-1]?0:-1;}
static void velocity_process_pending_matches(const char *chain_dir){QrxDB db;PendingMatchList l={0};if(qrxdb_init(&db,chain_dir)!=0)return;qrxdb_scan_prefix(&db,"velocity:match_pending:",pending_match_collect_cb,&l);qrxdb_close(&db);for(size_t i=0;i<l.count;i++){mirror_order_from_authoritative(chain_dir,l.ids[i]);if(match_native_order(chain_dir,l.ids[i])==0)clear_match_pending(chain_dir,l.ids[i]);free(l.ids[i]);}free(l.ids);}
static void mirror_common_apply_state(const char *chain_dir,const char *from,const char *to,int has_recipient,long long lane,const char *body_hash){
    char bal[1024],noncepath[1024],appl[1024],fp[1024];state_paths(chain_dir,bal,sizeof(bal),noncepath,sizeof(noncepath),appl,sizeof(appl),NULL,0);kv_set_ll_bin(bal,from,qrx_balance_get_authoritative(chain_dir,from));if(has_recipient&&strcmp(from,to))kv_set_ll_bin(bal,to,qrx_balance_get_authoritative(chain_dir,to));if(lane==0)kv_set_ll_bin(noncepath,from,velocity_get_lane_nonce(chain_dir,from,0));else{char lp[1024],lk[512];velocity_lane_nonce_path(chain_dir,lp,sizeof(lp));snprintf(lk,sizeof(lk),"%s|%lld",from,lane);kv_set_ll_bin(lp,lk,velocity_get_lane_nonce(chain_dir,from,lane));}fee_pool_path(chain_dir,fp,sizeof(fp));kv_set_ll_bin(fp,"pending_fees",fee_pool_pending(chain_dir));applied_add_bin(appl,body_hash);
}


/* QRX 0.0.7.6 Mainnet Native Asset consensus state.  All authoritative
 * mutations below are staged into the same QRXDB WAL batch as nonce/fee/tx index. */
static void a76_key(char*out,size_t n,const char*asset,const char*field){snprintf(out,n,"asset76:meta:%s:%s",asset,field);}
static char *a76_db_get(const char*c,const char*a,const char*f){QrxDB db;char k[768],b[4096];a76_key(k,sizeof(k),a,f);if(qrxdb_init(&db,c)!=0)return NULL;int rc=qrxdb_get(&db,k,b,sizeof(b));qrxdb_close(&db);return rc==0?strdup(b):NULL;}
static long long a76_db_ll(const char*c,const char*a,const char*f,long long d){char*v=a76_db_get(c,a,f);if(!v)return d;char*e=NULL;errno=0;long long x=strtoll(v,&e,10);int ok=!errno&&e&&!*e;free(v);return ok?x:d;}
static int a76_batch_meta(QrxDBBatch*b,const char*a,const char*f,const char*v){char k[768];a76_key(k,sizeof(k),a,f);return qrxdb_batch_put(b,k,v?v:"");}
static int a76_batch_ll(QrxDBBatch*b,const char*a,const char*f,long long v){char x[64];snprintf(x,sizeof(x),"%lld",v);return a76_batch_meta(b,a,f,x);}
static int a76_safe_name_chars(const char*s){if(!s||!*s||strlen(s)>30)return 0;for(;*s;s++){unsigned char c=(unsigned char)*s;if(!(c>='A'&&c<='Z')&&!(c>='0'&&c<='9')&&c!='_'&&c!='.'&&c!='/'&&c!='#'&&c!='$'&&c!='~'&&c!='!')return 0;}return 1;}
static int a76_segment_ok(const char*s,size_t n,int min){if(n<(size_t)min)return 0;if(s[0]=='_'||s[0]=='.'||s[n-1]=='_'||s[n-1]=='.')return 0;for(size_t i=0;i<n;i++){char c=s[i];if(!((c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='.'))return 0;if(i&&((c=='_'||c=='.')&&(s[i-1]=='_'||s[i-1]=='.')))return 0;}return 1;}
static int a76_name_valid(const char*n,const char*kind){if(!a76_safe_name_chars(n)||!kind)return 0;size_t L=strlen(n);if(!strcmp(kind,"MAIN")){return !strpbrk(n,"/#$~!")&&a76_segment_ok(n,L,3);}if(!strcmp(kind,"SUB")){const char*q=strrchr(n,'/');return q&&q!=n&&!strpbrk(n,"#$~!")&&a76_segment_ok(q+1,strlen(q+1),1);}if(!strcmp(kind,"UNIQUE")){const char*q=strrchr(n,'#');return q&&q!=n&&q[1]&&n[0]!='#'&&!strchr(q+1,'/');}if(!strcmp(kind,"CHANNEL")){const char*q=strrchr(n,'~');return q&&q!=n&&q[1]&&n[0]!='~';}if(!strcmp(kind,"QUALIFIER")){return n[0]=='#'&&!strchr(n,'/')&&a76_segment_ok(n+1,L-1,3);}if(!strcmp(kind,"SUBQUALIFIER")){const char*q=strstr(n,"/#");return n[0]=='#'&&q&&q[2]&&a76_segment_ok(q+2,strlen(q+2),1);}if(!strcmp(kind,"RESTRICTED")){return n[0]=='$'&&a76_segment_ok(n+1,L-1,3);}if(!strcmp(kind,"OWNER")){return L>1&&n[L-1]=='!';}return 0;}
static void a76_owner_name(const char*a,char*out,size_t n){snprintf(out,n,"%s!",a);}
static int a76_get_balance_qrxdb(const char*c,const char*a,const char*addr,long long*out){char k[1024],buf[128];velocity_asset_balance_key(k,sizeof(k),a,addr);QrxDB db;if(qrxdb_init(&db,c)!=0)return -1;int rc=qrxdb_get(&db,k,buf,sizeof(buf));qrxdb_close(&db);*out=rc==0?atoll(buf):0;return 0;}
static int a76_batch_balance_delta(QrxDBBatch*b,const char*c,const char*a,const char*addr,long long delta){long long cur=0,next=0;if(a76_get_balance_qrxdb(c,a,addr,&cur))return -1;if(checked_add_ll(cur,delta,"asset balance",&next),next<0)return -1;return atomic_stage_asset_value(b,a,addr,next);}
static int a76_tagged(const char*c,const char*q,const char*addr){if(!kyc_provider_active_for_qualifier(c,q,NULL,0))return 0;QrxDB db;char k[1024],buf[32];snprintf(k,sizeof(k),"asset76:tag:%s:%s",q,addr);if(qrxdb_init(&db,c)!=0)return 0;int rc=qrxdb_get(&db,k,buf,sizeof(buf));qrxdb_close(&db);return rc==0&&atoi(buf)!=0;}
static int a76_blacklisted(const char*c,const char*a,const char*addr){QrxDB db;char k[1024],buf[32];snprintf(k,sizeof(k),"asset76:blacklist:%s:%s",a,addr);if(qrxdb_init(&db,c)!=0)return 0;int rc=qrxdb_get(&db,k,buf,sizeof(buf));qrxdb_close(&db);return rc==0&&atoi(buf)!=0;}
static int a76_global_frozen(const char*c,const char*a){QrxDB db;char k[768],buf[32];snprintf(k,sizeof(k),"asset76:globalfreeze:%s",a);if(qrxdb_init(&db,c)!=0)return 0;int rc=qrxdb_get(&db,k,buf,sizeof(buf));qrxdb_close(&db);return rc==0&&atoi(buf)!=0;}
typedef struct{const char*s;const char*c;const char*addr;}A76Expr;
static void a76_ws(A76Expr*e){while(*e->s==' '||*e->s=='\t')e->s++;}
static int a76_expr_or(A76Expr*e,int*ok);
static int a76_expr_atom(A76Expr*e,int*ok){a76_ws(e);if(*e->s=='!'){e->s++;return !a76_expr_atom(e,ok);}if(*e->s=='('){e->s++;int v=a76_expr_or(e,ok);a76_ws(e);if(*e->s!=')'){*ok=0;return 0;}e->s++;return v;}char q[64];size_t i=0;if(*e->s=='#')e->s++;while((isalnum((unsigned char)*e->s)||*e->s=='_'||*e->s=='.')&&i+1<sizeof(q))q[i++]=*e->s++;q[i]=0;if(!i){*ok=0;return 0;}char full[68];snprintf(full,sizeof(full),"#%s",q);return a76_tagged(e->c,full,e->addr);}
static int a76_expr_and(A76Expr*e,int*ok){int v=a76_expr_atom(e,ok);while(*ok){a76_ws(e);if(*e->s!='&')break;e->s++;int r=a76_expr_atom(e,ok);v=v&&r;}return v;}
static int a76_expr_or(A76Expr*e,int*ok){int v=a76_expr_and(e,ok);while(*ok){a76_ws(e);if(*e->s!='|')break;e->s++;int r=a76_expr_and(e,ok);v=v||r;}return v;}
static int a76_verifier_ok(const char*c,const char*expr,const char*addr){if(!expr||!*expr||!strcasecmp(expr,"true"))return 1;A76Expr e={expr,c,addr};int ok=1,v=a76_expr_or(&e,&ok);a76_ws(&e);return ok&&!*e.s&&v;}
static int a76_restricted_eligible(const char*c,const char*a,const char*addr){if(a76_global_frozen(c,a)||a76_blacklisted(c,a,addr))return 0;char*v=a76_db_get(c,a,"verifier");int ok=a76_verifier_ok(c,v?v:"false",addr);free(v);return ok;}
static int a76_asset_active(const char*c,const char*a){char*v=a76_db_get(c,a,"status");int ok=v&&!strcmp(v,"active");free(v);return ok;}
static int a76_has_owner(const char*c,const char*a,const char*addr){char o[96];a76_owner_name(a,o,sizeof(o));long long b=0;a76_get_balance_qrxdb(c,o,addr,&b);return b>=1;}
static int a76_parent_name(const char*a,const char*kind,char*out,size_t n){if(!strcmp(kind,"SUB")){const char*q=strrchr(a,'/');if(!q)return -1;snprintf(out,n,"%.*s",(int)(q-a),a);return 0;}if(!strcmp(kind,"UNIQUE")||!strcmp(kind,"CHANNEL")){const char sep=!strcmp(kind,"UNIQUE")?'#':'~';const char*q=strrchr(a,sep);if(!q)return -1;snprintf(out,n,"%.*s",(int)(q-a),a);return 0;}if(!strcmp(kind,"SUBQUALIFIER")){const char*q=strstr(a,"/#");if(!q)return -1;snprintf(out,n,"%.*s",(int)(q-a),a);return 0;}return -1;}
static int a76_stage_issue(QrxDBBatch*b,const char*c,const char*from,const char*to,const char*p,long long h,const char*txid){
 char *a=payload_get_field(p,"asset"),*kind=payload_get_field(p,"kind"),*qs=payload_get_field(p,"qty"),*us=payload_get_field(p,"units"),*rs=payload_get_field(p,"reissuable"),*md=payload_get_field(p,"metadata"),*ver=payload_get_field(p,"verifier"),*caps=payload_get_field(p,"capabilities"),*mx=payload_get_field(p,"max_supply");int rc=-1;
 if(!a||!kind||!qs||!us||!rs||!a76_name_valid(a,kind)||a76_asset_active(c,a))goto done;long long q=parse_positive_ll_strict(qs,"qty"),units=parse_nonnegative_ll_strict(us,"units"),re=parse_nonnegative_ll_strict(rs,"reissuable"),maxs=mx&&*mx?parse_nonnegative_ll_strict(mx,"max_supply"):0;if(units>8||re>1)goto done;
 if(!strcmp(kind,"UNIQUE")||!strcmp(kind,"CHANNEL")){if(q!=1||units!=0||re)goto done;}if(!strcmp(kind,"QUALIFIER")||!strcmp(kind,"SUBQUALIFIER")){if(q<1||q>10||units||re)goto done;char kauth[512]={0};char kid[96];if(kyc_provider_id_from_qualifier(a,kid)==0){if(!kyc_provider_active_for_qualifier(c,a,kauth,sizeof(kauth))||strcmp(from,kauth)||strcmp(to,kauth))goto done;}}if(md&&strcmp(md,"-")&&strlen(md)>128)goto done;
 char parent[96]={0};if(!strcmp(kind,"SUB")||!strcmp(kind,"UNIQUE")||!strcmp(kind,"CHANNEL")){if(a76_parent_name(a,kind,parent,sizeof(parent))||!a76_has_owner(c,parent,from))goto done;}if(!strcmp(kind,"SUBQUALIFIER")){if(a76_parent_name(a,kind,parent,sizeof(parent)))goto done;long long pb=0;a76_get_balance_qrxdb(c,parent,from,&pb);if(pb<1)goto done;}
 if(!strcmp(kind,"RESTRICTED")){if(!ver||!*ver||!a76_verifier_ok(c,ver,to))goto done;}
 rc=0;rc|=a76_batch_meta(b,a,"status","active");rc|=a76_batch_meta(b,a,"kind",kind);rc|=a76_batch_meta(b,a,"issuer",from);rc|=a76_batch_ll(b,a,"units",units);rc|=a76_batch_ll(b,a,"reissuable",re);rc|=a76_batch_ll(b,a,"supply",q);rc|=a76_batch_ll(b,a,"max_supply",maxs);rc|=a76_batch_meta(b,a,"metadata",md?md:"-");rc|=a76_batch_meta(b,a,"verifier",ver?ver:"true");rc|=a76_batch_meta(b,a,"capabilities",caps?caps:"NONE");rc|=a76_batch_ll(b,a,"created_height",h);rc|=a76_batch_meta(b,a,"created_tx",txid);rc|=a76_batch_balance_delta(b,c,a,to,q);
 if(strcmp(kind,"UNIQUE")&&strcmp(kind,"CHANNEL")&&strcmp(kind,"QUALIFIER")&&strcmp(kind,"SUBQUALIFIER")){char o[96];a76_owner_name(a,o,sizeof(o));rc|=a76_batch_meta(b,o,"status","active");rc|=a76_batch_meta(b,o,"kind","OWNER");rc|=a76_batch_ll(b,o,"units",0);rc|=a76_batch_ll(b,o,"reissuable",0);rc|=a76_batch_ll(b,o,"supply",1);rc|=a76_batch_balance_delta(b,c,o,from,1);} 
 done:free(a);free(kind);free(qs);free(us);free(rs);free(md);free(ver);free(caps);free(mx);return rc?-1:0;}
static int a76_stage_reissue(QrxDBBatch*b,const char*c,const char*from,const char*to,const char*p,long long h,const char*txid){char*a=payload_get_field(p,"asset"),*qs=payload_get_field(p,"qty"),*us=payload_get_field(p,"units"),*rs=payload_get_field(p,"reissuable"),*md=payload_get_field(p,"metadata"),*ver=payload_get_field(p,"verifier");int rc=-1;if(!a||!qs||!a76_asset_active(c,a)||!a76_has_owner(c,a,from)||a76_db_ll(c,a,"reissuable",0)!=1)goto done;long long add=parse_nonnegative_ll_strict(qs,"qty"),oldU=a76_db_ll(c,a,"units",0),newU=us&&*us?parse_nonnegative_ll_strict(us,"units"):oldU,newR=rs&&*rs?parse_nonnegative_ll_strict(rs,"reissuable"):1,sup=a76_db_ll(c,a,"supply",0),maxs=a76_db_ll(c,a,"max_supply",0),ns=0;if(newU<oldU||newU>8||newR>1)goto done; checked_add_ll(sup,add,"asset supply",&ns); if(maxs>0&&ns>maxs)goto done;char*k=a76_db_get(c,a,"kind");if(k&&(!strcmp(k,"UNIQUE")||!strcmp(k,"CHANNEL")||!strcmp(k,"QUALIFIER")||!strcmp(k,"SUBQUALIFIER"))){free(k);goto done;}if(k&&!strcmp(k,"RESTRICTED")&&ver&&*ver&&!a76_verifier_ok(c,ver,to)){free(k);goto done;}free(k);rc=0;if(add)rc|=a76_batch_balance_delta(b,c,a,to,add);rc|=a76_batch_ll(b,a,"supply",ns);rc|=a76_batch_ll(b,a,"units",newU);rc|=a76_batch_ll(b,a,"reissuable",newR);if(md&&*md)rc|=a76_batch_meta(b,a,"metadata",md);if(ver&&*ver)rc|=a76_batch_meta(b,a,"verifier",ver);rc|=a76_batch_ll(b,a,"updated_height",h);rc|=a76_batch_meta(b,a,"updated_tx",txid);
 done:free(a);free(qs);free(us);free(rs);free(md);free(ver);return rc?-1:0;}
static int a76_stage_transfer(QrxDBBatch*b,const char*c,const char*from,const char*to,const char*p){char*a=payload_get_field(p,"asset"),*qs=payload_get_field(p,"qty");int rc=-1;if(!a||!qs||!a76_asset_active(c,a))goto done;/* Generals and governance-bound KYC qualifier authority are non-transferable through generic asset transfer. */if(!strncmp(a,"GENERAL#",8)||!strncmp(a,"#KYC_",5))goto done;long long q=parse_positive_ll_strict(qs,"qty"),fb=0,tb=0;a76_get_balance_qrxdb(c,a,from,&fb);a76_get_balance_qrxdb(c,a,to,&tb);if(fb<q)goto done;if(!strcmp(from,to)){rc=0;goto done;}char*k=a76_db_get(c,a,"kind");if(k&&!strcmp(k,"RESTRICTED")&&(!a76_restricted_eligible(c,a,from)||!a76_restricted_eligible(c,a,to))){free(k);goto done;}free(k);long long nf=0,nt=0;checked_add_ll(fb,-q,"asset sender",&nf);checked_add_ll(tb,q,"asset recipient",&nt);rc=atomic_stage_asset_value(b,a,from,nf)|atomic_stage_asset_value(b,a,to,nt);done:free(a);free(qs);return rc?-1:0;}
static int a76_stage_tag(QrxDBBatch*b,const char*c,const char*from,const char*p,int add){char*q=payload_get_field(p,"qualifier"),*addr=payload_get_field(p,"address");int rc=-1;if(!q||!addr||q[0]!='#'||!a76_asset_active(c,q))goto done;char kauth[512]={0},kid[96];if(kyc_provider_id_from_qualifier(q,kid)==0&&(!kyc_provider_active_for_qualifier(c,q,kauth,sizeof(kauth))||strcmp(from,kauth)))goto done;long long bal=0;a76_get_balance_qrxdb(c,q,from,&bal);if(bal<1)goto done;char k[1024];snprintf(k,sizeof(k),"asset76:tag:%s:%s",q,addr);rc=qrxdb_batch_put(b,k,add?"1":"0");done:free(q);free(addr);return rc;}
static int a76_stage_restriction(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*mode,int on){char*a=payload_get_field(p,"asset"),*addr=payload_get_field(p,"address");int rc=-1;if(!a||a[0]!='$'||!a76_asset_active(c,a)||!a76_has_owner(c,a,from))goto done;char k[1024];if(!strcmp(mode,"global"))snprintf(k,sizeof(k),"asset76:globalfreeze:%s",a);else{if(!addr)goto done;snprintf(k,sizeof(k),"asset76:blacklist:%s:%s",a,addr);}rc=qrxdb_batch_put(b,k,on?"1":"0");done:free(a);free(addr);return rc;}
static int a76_stage_broadcast(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*a=payload_get_field(p,"asset"),*msg=payload_get_field(p,"message"),*exp=payload_get_field(p,"expire_time");int rc=-1;if(!a||!msg||strlen(msg)>256||!a76_asset_active(c,a))goto done;long long bal=0;a76_get_balance_qrxdb(c,a,from,&bal);char*k=a76_db_get(c,a,"kind");int auth=a76_has_owner(c,a,from)||(k&&!strcmp(k,"CHANNEL")&&bal>=1);free(k);if(!auth)goto done;char key[1024],val[1024];snprintf(key,sizeof(key),"asset76:broadcast:%s:%s",a,txid);snprintf(val,sizeof(val),"height=%lld;expire=%s;message=%s",h,exp?exp:"0",msg);rc=qrxdb_batch_put(b,key,val);done:free(a);free(msg);free(exp);return rc;}
static int a76_stage_admin_balance(QrxDBBatch*b,const char*c,const char*from,const char*to,const char*p,int forced){char*a=payload_get_field(p,"asset"),*qs=payload_get_field(p,"qty");int rc=-1;if(!a||!qs||!a76_asset_active(c,a)||!a76_has_owner(c,a,from))goto done;char*caps=a76_db_get(c,a,"capabilities");const char*need=forced?"ISSUER_FORCED_TRANSFER":"ISSUER_REVOKE";if(!caps||!token_list_contains_ci(caps,need)){free(caps);goto done;}free(caps);char*src=payload_get_field(p,"source");if(!src)goto done;long long q=parse_positive_ll_strict(qs,"qty"),sb=0;a76_get_balance_qrxdb(c,a,src,&sb);if(sb<q){free(src);goto done;}rc=a76_batch_balance_delta(b,c,a,src,-q);if(forced){if(!to||!*to||!strcmp(src,to)||!a76_restricted_eligible(c,a,to)){free(src);goto done;}rc|=a76_batch_balance_delta(b,c,a,to,q);}free(src);done:free(a);free(qs);return rc?-1:0;}
static long long a76_operation_burn(const char*c,const char*t,const char*p,long long h){
    const char*legacy_key=NULL;const char*unit_key=NULL;long long legacy_def=0,unit_def=0;
    if(!strcmp(t,"ASSET_ISSUE")){
        char*k=payload_get_field(p,"kind");
        if(k){
            if(!strcmp(k,"MAIN")){legacy_key="asset_issue_main_burn_atoms";legacy_def=10000000000LL;unit_key="asset_issue_main_burn_reward_units";unit_def=QRX_ASSET_BURN_MAIN_REWARD_UNITS;}
            else if(!strcmp(k,"SUB")){legacy_key="asset_issue_sub_burn_atoms";legacy_def=2500000000LL;unit_key="asset_issue_sub_burn_reward_units";unit_def=QRX_ASSET_BURN_SUB_REWARD_UNITS;}
            else if(!strcmp(k,"UNIQUE")){legacy_key="asset_issue_unique_burn_atoms";legacy_def=250000000LL;unit_key="asset_issue_unique_burn_reward_units";unit_def=QRX_ASSET_BURN_UNIQUE_REWARD_UNITS;}
            else if(!strcmp(k,"CHANNEL")){legacy_key="asset_issue_channel_burn_atoms";legacy_def=2500000000LL;unit_key="asset_issue_channel_burn_reward_units";unit_def=QRX_ASSET_BURN_CHANNEL_REWARD_UNITS;}
            else if(!strcmp(k,"QUALIFIER")){legacy_key="asset_issue_qualifier_burn_atoms";legacy_def=25000000000LL;unit_key="asset_issue_qualifier_burn_reward_units";unit_def=QRX_ASSET_BURN_QUALIFIER_REWARD_UNITS;}
            else if(!strcmp(k,"SUBQUALIFIER")){legacy_key="asset_issue_subqualifier_burn_atoms";legacy_def=2500000000LL;unit_key="asset_issue_subqualifier_burn_reward_units";unit_def=QRX_ASSET_BURN_SUBQUALIFIER_REWARD_UNITS;}
            else if(!strcmp(k,"RESTRICTED")){legacy_key="asset_issue_restricted_burn_atoms";legacy_def=50000000000LL;unit_key="asset_issue_restricted_burn_reward_units";unit_def=QRX_ASSET_BURN_RESTRICTED_REWARD_UNITS;}
            free(k);
        }
    }else if(!strcmp(t,"ASSET_REISSUE")){legacy_key="asset_reissue_burn_atoms";legacy_def=1000000000LL;unit_key="asset_reissue_burn_reward_units";unit_def=QRX_ASSET_BURN_REISSUE_REWARD_UNITS;}
    else if(!strcmp(t,"ASSET_TAG")||!strcmp(t,"ASSET_UNTAG")){legacy_key="asset_tag_burn_atoms";legacy_def=100000000LL;unit_key="asset_tag_burn_reward_units";unit_def=QRX_ASSET_BURN_TAG_REWARD_UNITS;}
    if(!legacy_key)return 0;
    char policy[64]={0};
    if(qrx_chain_get_value_at_height(c,h,"asset_burn_policy",policy,sizeof(policy))==0&&!strcmp(policy,"block_reward_units_v1")){
        long long units=qrx_chain_get_ll_at_height_or_default(c,h,unit_key,unit_def);
        long long reward=qrx_chain_get_block_reward_at_height(c,h,QRX_INITIAL_BLOCK_REWARD_ATOMS,QRX_HALVING_INTERVAL_BLOCKS);
        if(units<0||reward<0)return -1;
        uint64_t burn=qrx_asset_burn_from_reward_units((uint64_t)reward,(uint64_t)units);
        return burn>(uint64_t)LLONG_MAX?-1:(long long)burn;
    }
    return qrx_chain_get_ll_at_height_or_default(c,h,legacy_key,legacy_def);
}
static int atomic_stage_asset76(QrxDBBatch*b,const char*c,const char*from,const char*to,const char*t,const char*p,const char*txid,long long h){long long act=qrx_chain_get_ll_at_height_or_default(c,h+1,"asset_activation_height",0);if(h+1<act)return -1;if(!strcmp(t,"ASSET_ISSUE"))return a76_stage_issue(b,c,from,to,p,h,txid);if(!strcmp(t,"ASSET_REISSUE"))return a76_stage_reissue(b,c,from,to,p,h,txid);if(!strcmp(t,"ASSET_TRANSFER"))return a76_stage_transfer(b,c,from,to,p);if(!strcmp(t,"ASSET_TAG"))return a76_stage_tag(b,c,from,p,1);if(!strcmp(t,"ASSET_UNTAG"))return a76_stage_tag(b,c,from,p,0);if(!strcmp(t,"ASSET_FREEZE_ADDRESS"))return a76_stage_restriction(b,c,from,p,"address",1);if(!strcmp(t,"ASSET_UNFREEZE_ADDRESS"))return a76_stage_restriction(b,c,from,p,"address",0);if(!strcmp(t,"ASSET_GLOBAL_FREEZE"))return a76_stage_restriction(b,c,from,p,"global",1);if(!strcmp(t,"ASSET_GLOBAL_UNFREEZE"))return a76_stage_restriction(b,c,from,p,"global",0);if(!strcmp(t,"ASSET_BROADCAST"))return a76_stage_broadcast(b,c,from,p,txid,h);if(!strcmp(t,"ASSET_REVOKE"))return a76_stage_admin_balance(b,c,from,to,p,0);if(!strcmp(t,"ASSET_FORCED_TRANSFER"))return a76_stage_admin_balance(b,c,from,to,p,1);return -1;}


/* === QRX Generals 0.0.7.7 Phase 1: deterministic serverless game roots ===
 * Authoritative game state is QRXDB/WAL state. No HTTP server, SQL database,
 * operator key, or off-chain account database participates in consensus.
 * GAME_JOIN atomically creates a wallet-bound player identity, a reserved
 * native UNIQUE GENERAL# asset and funds the on-chain Generals treasury.
 */
static int generals_db_get(const char*c,const char*k,char*out,size_t n){QrxDB db;if(qrxdb_init(&db,c)!=0)return -1;int rc=qrxdb_get(&db,k,out,n);qrxdb_close(&db);return rc;}
static long long generals_db_ll(const char*c,const char*k,long long d){char b[128];if(generals_db_get(c,k,b,sizeof(b))!=0)return d;char*e=NULL;errno=0;long long v=strtoll(b,&e,10);return (!errno&&e&&!*e)?v:d;}
static void generals_player_key(char*out,size_t n,const char*addr,const char*field){snprintf(out,n,"generals:player:%s:%s",addr,field);}
static int generals_player_exists(const char*c,const char*addr){char k[768],v[64];generals_player_key(k,sizeof(k),addr,"status");return generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,"active");}
static void generals_identity(const char*addr,char player[35],char general[31]){char pre[1024],h[129];snprintf(pre,sizeof(pre),"QRX-GENERALS-PLAYER-v1|%s",addr);sha3_512_hex((const unsigned char*)pre,strlen(pre),h);snprintf(player,35,"P%.32s",h);snprintf(general,31,"GENERAL#%.16s",h);}
static int generals_safe_token(const char*s,size_t min,size_t max,int spaces){if(!s){return 0;}size_t n=strlen(s);if(n<min||n>max)return 0;for(size_t i=0;i<n;i++){unsigned char c=(unsigned char)s[i];if(isalnum(c)||c=='_'||c=='-'||(spaces&&c==' '))continue;return 0;}return 1;}
static long long generals_treasury_balance(const char*c){return generals_db_ll(c,"generals:treasury:balance_atoms",0);}
static long long generals_treasury_reserved(const char*c){return generals_db_ll(c,"generals:treasury:reserved_atoms",0);}
static int generals_stage_treasury_credit(QrxDBBatch*b,const char*c,long long atoms,long long h,const char*txid,const char*source){if(atoms<=0)return -1;long long old=generals_treasury_balance(c),next=0;checked_add_ll(old,atoms,"Generals treasury",&next);int rc=0;rc|=velocity_batch_put_ll(b,"generals:treasury:balance_atoms",next);rc|=velocity_batch_put_ll(b,"generals:treasury:last_height",h);rc|=qrxdb_batch_put(b,"generals:treasury:last_tx",txid);rc|=qrxdb_batch_put(b,"generals:treasury:last_source",source?source:"");return rc?-1:0;}
static int generals_season_at(const char*c,long long h,long long*sid,long long*ss,long long*se,long long*turn,long long*ts,long long*te){long long first=qrx_chain_get_ll_at_height_or_default(c,h,"generals_season_start_height",0),len=qrx_chain_get_ll_at_height_or_default(c,h,"generals_season_length_blocks",259200),tl=qrx_chain_get_ll_at_height_or_default(c,h,"generals_turn_length_blocks",60);if(len<=0||tl<=0||h<first)return -1;long long off=h-first,id=off/len+1,start=first+(id-1)*len,end=start+len-1,ti=(h-start)/tl+1,tstart=start+(ti-1)*tl,tend=tstart+tl-1;if(tend>end)tend=end;if(sid)*sid=id;if(ss)*ss=start;if(se)*se=end;if(turn)*turn=ti;if(ts)*ts=tstart;if(te)*te=tend;return 0;}
static long long generals_energy_at(const char*c,const char*addr,long long h,long long*base_height){char k[1024];long long max=qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_max",100),regen_blocks=qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_regen_blocks",6),regen_amount=qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_regen_amount",1);if(max<1)max=1;if(regen_blocks<1)regen_blocks=1;if(regen_amount<1)regen_amount=1;generals_player_key(k,sizeof(k),addr,"energy");long long stored=generals_db_ll(c,k,max);generals_player_key(k,sizeof(k),addr,"energy_height");long long last=generals_db_ll(c,k,h);if(last>h)last=h;long long steps=(h-last)/regen_blocks,add=0,next=stored;if(steps>0){if(steps>LLONG_MAX/regen_amount)add=LLONG_MAX;else add=steps*regen_amount;if(add>=max-stored)next=max;else next=stored+add;}if(next>max)next=max;if(next<0)next=0;if(base_height)*base_height=last+steps*regen_blocks;return next;}
static long long generals_operation_cost(const char*c,const char*t,const char*p,long long h,long long amount){(void)p;if(!strcmp(t,"GAME_JOIN"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_join_cost_atoms",1000000000LL);if(!strcmp(t,"GAME_CLAN_CREATE"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_clan_create_cost_atoms",5000000000LL);if(!strcmp(t,"GAME_CLAN_INVITE"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_clan_invite_cost_atoms",100000LL);if(!strcmp(t,"GAME_SEASON_JOIN"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_season_join_cost_atoms",100000000LL);if(!strcmp(t,"GAME_TREASURY_FUND"))return amount;if(!strcmp(t,"GAME_RESEARCH_ACCELERATE"))return amount>0?amount:-1;if(!strcmp(t,"GAME_SEASON_FINALIZE")||!strcmp(t,"GAME_REWARD_CLAIM"))return 0;if(!strcmp(t,"GAME_CLAN_INVITE_REVOKE")||!strcmp(t,"GAME_CLAN_JOIN")||!strcmp(t,"GAME_CLAN_LEAVE")||!strcmp(t,"GAME_CLAN_OFFICER_SET")||!strcmp(t,"GAME_CLAN_DIRECTIVE")||!strcmp(t,"GAME_CLAN_LEADER_TRANSFER"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_clan_membership_cost_atoms",10000LL);if(!strcmp(t,"GAME_ENERGY_SPEND"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_action_cost_atoms",10000LL);if(!strcmp(t,"GAME_ORDER_COMMIT"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_order_commit_cost_atoms",10000LL);if(!strcmp(t,"GAME_ORDER_REVEAL"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_action_cost_atoms",10000LL);if(!strcmp(t,"GAME_MARCH_ADVANCE"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_action_cost_atoms",10000LL);if(!strcmp(t,"GAME_TURN_RESOLVE"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_action_cost_atoms",10000LL);if(!strcmp(t,"GAME_INFRA_BUILD")||!strcmp(t,"GAME_PRODUCE_UNIT")||!strcmp(t,"GAME_SUPPLY_TRANSFER")||!strcmp(t,"GAME_REPAIR_UNIT")||!strcmp(t,"GAME_REARM_UNIT")||!strcmp(t,"GAME_INFRA_ATTACK")||!strcmp(t,"GAME_ROAD_REPAIR")||!strcmp(t,"GAME_UNIT_RESUPPLY")||!strcmp(t,"GAME_RECON_SCAN")||!strcmp(t,"GAME_EW_JAM")||!strcmp(t,"GAME_AIR_MISSION")||!strcmp(t,"GAME_RADAR_SCAN")||!strcmp(t,"GAME_SAM_INTERCEPT")||!strcmp(t,"GAME_MISSILE_LAUNCH")||!strcmp(t,"GAME_STRIKE_RESOLVE")||!strcmp(t,"GAME_CAP_MISSION")||!strcmp(t,"GAME_ESCORT_MISSION")||!strcmp(t,"GAME_AIR_INTERCEPT")||!strcmp(t,"GAME_AIR_COMBAT_RESOLVE")||!strcmp(t,"GAME_AIR_FORMATION")||!strcmp(t,"GAME_CAP_AUTO_INTERCEPT")||!strcmp(t,"GAME_AIR_RTB")||!strcmp(t,"GAME_SEAD_MISSION")||!strcmp(t,"GAME_NAVAL_DEPLOY")||!strcmp(t,"GAME_NAVAL_MOVE")||!strcmp(t,"GAME_NAVAL_ATTACK")||!strcmp(t,"GAME_AMPHIBIOUS_LOAD")||!strcmp(t,"GAME_AMPHIBIOUS_LAND")||!strcmp(t,"GAME_SEA_SUPPLY")||!strcmp(t,"GAME_FLEET_CREATE")||!strcmp(t,"GAME_NAVAL_COMBAT_RESOLVE")||!strcmp(t,"GAME_CARRIER_AIR_WING")||!strcmp(t,"GAME_NAVAL_BLOCKADE")||!strcmp(t,"GAME_STRATEGIC_CLAIM")||!strcmp(t,"GAME_ECONOMY_COLLECT")||!strcmp(t,"GAME_CITY_DEVELOP")||!strcmp(t,"GAME_INDUSTRY_INVEST")||!strcmp(t,"GAME_RESEARCH_START")||!strcmp(t,"GAME_RESEARCH_COMPLETE")||!strcmp(t,"GAME_DOCTRINE_SELECT")||!strcmp(t,"GAME_TECH_RECON")||!strcmp(t,"GAME_RESEARCH_DISRUPT")||!strcmp(t,"GAME_COUNTERINTEL_ACTIVATE")||!strcmp(t,"GAME_SEASON_FINALIZE")||!strcmp(t,"GAME_REWARD_CLAIM"))return qrx_chain_get_ll_at_height_or_default(c,h,"generals_action_cost_atoms",10000LL);return -1;}
static int generals_stage_join(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h,long long cost){char *display=payload_get_field(p,"display_name");if(generals_player_exists(c,from)||cost<=0){free(display);return -1;}if(display&&*display&&!generals_safe_token(display,1,24,1)){free(display);return -1;}char player[35],general[31],k[1024],hb[64];generals_identity(from,player,general);if(a76_asset_active(c,general)){free(display);return -1;}snprintf(hb,sizeof(hb),"%lld",h);int rc=0;
#define GP(F,V) do{generals_player_key(k,sizeof(k),from,(F));rc|=qrxdb_batch_put(b,k,(V));}while(0)
 GP("status","active");GP("player_id",player);GP("wallet",from);GP("general_asset",general);GP("display_name",display&&*display?display:player);GP("joined_height",hb);GP("join_tx",txid);GP("clan_id","");GP("current_season_id","");
 long long emax=qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_max",100);generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,emax);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,h);
#undef GP
 rc|=a76_batch_meta(b,general,"status","active");rc|=a76_batch_meta(b,general,"kind","UNIQUE");rc|=a76_batch_meta(b,general,"issuer","QRX_GENERALS_PROTOCOL");rc|=a76_batch_ll(b,general,"units",0);rc|=a76_batch_ll(b,general,"reissuable",0);rc|=a76_batch_ll(b,general,"supply",1);rc|=a76_batch_ll(b,general,"max_supply",1);rc|=a76_batch_meta(b,general,"metadata","qrx-generals-general-v1");rc|=a76_batch_meta(b,general,"verifier","true");rc|=a76_batch_meta(b,general,"capabilities","GAME_GENERAL_V1");rc|=a76_batch_ll(b,general,"created_height",h);rc|=a76_batch_meta(b,general,"created_tx",txid);rc|=a76_batch_balance_delta(b,c,general,from,1);
 snprintf(k,sizeof(k),"generals:general:%s:player",general);rc|=qrxdb_batch_put(b,k,player);snprintf(k,sizeof(k),"generals:general:%s:owner",general);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:general:%s:created_height",general);rc|=qrxdb_batch_put(b,k,hb);snprintf(k,sizeof(k),"generals:player_id:%s",player);rc|=qrxdb_batch_put(b,k,from);
 long long gp=generals_db_ll(c,"generals:player_count",0);rc|=velocity_batch_put_ll(b,"generals:player_count",gp+1);
 rc|=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_JOIN");free(display);return rc?-1:0;}
static int generals_stage_clan_create(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h,long long cost){if(!generals_player_exists(c,from)||cost<=0)return -1;char *name=payload_get_field(p,"clan_name"),*tag=payload_get_field(p,"clan_tag");if(!name||!tag||!generals_safe_token(name,3,32,1)||!generals_safe_token(tag,2,6,0)){free(name);free(tag);return -1;}char k[1024],v[512];generals_player_key(k,sizeof(k),from,"clan_id");if(generals_db_get(c,k,v,sizeof(v))==0&&*v){free(name);free(tag);return -1;}char nk[1024],tk[1024];snprintf(nk,sizeof(nk),"generals:clan_name:%s",name);snprintf(tk,sizeof(tk),"generals:clan_tag:%s",tag);if(generals_db_get(c,nk,v,sizeof(v))==0||generals_db_get(c,tk,v,sizeof(v))==0){free(name);free(tag);return -1;}char clan[40];snprintf(clan,sizeof(clan),"CLAN-%.24s",txid);int rc=0;snprintf(k,sizeof(k),"generals:clan:%s:status",clan);rc|=qrxdb_batch_put(b,k,"active");snprintf(k,sizeof(k),"generals:clan:%s:name",clan);rc|=qrxdb_batch_put(b,k,name);snprintf(k,sizeof(k),"generals:clan:%s:tag",clan);rc|=qrxdb_batch_put(b,k,tag);snprintf(k,sizeof(k),"generals:clan:%s:founder",clan);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:clan:%s:leader",clan);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:clan:%s:created_height",clan);rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:clan:%s:created_tx",clan);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:clan:%s:member:%s",clan,from);rc|=qrxdb_batch_put(b,k,"FOUNDER");snprintf(k,sizeof(k),"generals:clan:%s:member_count",clan);rc|=velocity_batch_put_ll(b,k,1);rc|=qrxdb_batch_put(b,nk,clan);rc|=qrxdb_batch_put(b,tk,clan);generals_player_key(k,sizeof(k),from,"clan_id");rc|=qrxdb_batch_put(b,k,clan);rc|=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_CREATE");free(name);free(tag);return rc?-1:0;}

static int generals_world_dims(const char*c,long long sid,long long players_hint,long long*w,long long*hh);
static int generals_clan_member_active(const char*c,const char*clan,const char*addr){char k[1024],v[64];snprintf(k,sizeof(k),"generals:clan:%s:member:%s",clan,addr);return generals_db_get(c,k,v,sizeof(v))==0&&strcmp(v,"LEFT");}
static int generals_clan_is_officer(const char*c,const char*clan,const char*addr){char k[1024],v[512];for(int i=1;i<=3;i++){snprintf(k,sizeof(k),"generals:clan:%s:officer:%d",clan,i);if(generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,addr))return 1;}return 0;}
static int generals_clan_can_command(const char*c,const char*clan,const char*addr){char k[1024],v[512];snprintf(k,sizeof(k),"generals:clan:%s:leader",clan);if(generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,addr))return 1;return generals_clan_is_officer(c,clan,addr);}
static int generals_stage_clan_officer_set(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char pk[1024],clan[256],k[1024],leader[512];generals_player_key(pk,sizeof(pk),from,"clan_id");if(generals_db_get(c,pk,clan,sizeof(clan))||!*clan)return -1;snprintf(k,sizeof(k),"generals:clan:%s:leader",clan);if(generals_db_get(c,k,leader,sizeof(leader))||strcmp(leader,from))return -1;char*slot_s=payload_get_field(p,"slot"),*enabled_s=payload_get_field(p,"enabled"),*member=payload_get_field(p,"member");if(!slot_s||!enabled_s){free(slot_s);free(enabled_s);free(member);return -1;}long long slot=atoll(slot_s),enabled=atoll(enabled_s);free(slot_s);free(enabled_s);if(slot<1||slot>3||(enabled!=0&&enabled!=1)){free(member);return -1;}snprintf(k,sizeof(k),"generals:clan:%s:officer:%lld",clan,slot);int rc=0;if(enabled){if(!member||!*member||!strcmp(member,from)||!generals_clan_member_active(c,clan,member)){free(member);return -1;}rc|=qrxdb_batch_put(b,k,member);}else rc|=qrxdb_batch_put(b,k,"");snprintf(k,sizeof(k),"generals:clan:%s:last_officer_tx",clan);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:clan:%s:last_officer_height",clan);rc|=velocity_batch_put_ll(b,k,h);free(member);return rc?-1:0;}
static int generals_stage_clan_leader_transfer(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char pk[1024],clan[256],k[1024],leader[512];generals_player_key(pk,sizeof(pk),from,"clan_id");if(generals_db_get(c,pk,clan,sizeof(clan))||!*clan)return -1;snprintf(k,sizeof(k),"generals:clan:%s:leader",clan);if(generals_db_get(c,k,leader,sizeof(leader))||strcmp(leader,from))return -1;char*member=payload_get_field(p,"member");if(!member||!*member||!strcmp(member,from)||!generals_clan_member_active(c,clan,member)){free(member);return -1;}int rc=0;rc|=qrxdb_batch_put(b,k,member);snprintf(k,sizeof(k),"generals:clan:%s:last_leader_transfer_tx",clan);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:clan:%s:last_leader_transfer_height",clan);rc|=velocity_batch_put_ll(b,k,h);free(member);return rc?-1:0;}
static int generals_stage_clan_directive(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char pk[1024],clan[256];generals_player_key(pk,sizeof(pk),from,"clan_id");if(generals_db_get(c,pk,clan,sizeof(clan))||!*clan||!generals_clan_can_command(c,clan,from))return -1;char*sid_s=payload_get_field(p,"season_id"),*type=payload_get_field(p,"directive"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y"),*exp_s=payload_get_field(p,"expiry_height");if(!sid_s||!type||!xs||!ys){free(sid_s);free(type);free(xs);free(ys);free(exp_s);return -1;}long long sid=atoll(sid_s),x=atoll(xs),y=atoll(ys),cur=0,ss=0,se=0,tr=0,ts=0,te=0;free(sid_s);if(generals_season_at(c,h,&cur,&ss,&se,&tr,&ts,&te)||sid!=cur||x<0||y<0){free(type);free(xs);free(ys);free(exp_s);return -1;}if(strcmp(type,"ATTACK")&&strcmp(type,"DEFEND")&&strcmp(type,"SUPPLY")&&strcmp(type,"RECON")&&strcmp(type,"RALLY")){free(type);free(xs);free(ys);free(exp_s);return -1;}long long w=0,hh=0;generals_world_dims(c,sid,1,&w,&hh);if(x>=w||y>=hh){free(type);free(xs);free(ys);free(exp_s);return -1;}long long exp=exp_s&&*exp_s?atoll(exp_s):h+120;if(exp<=h||exp>se)exp=se;char k[1024];int rc=0;snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:type",sid,clan);rc|=qrxdb_batch_put(b,k,type);snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:x",sid,clan);rc|=velocity_batch_put_ll(b,k,x);snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:y",sid,clan);rc|=velocity_batch_put_ll(b,k,y);snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:issuer",sid,clan);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:expires_height",sid,clan);rc|=velocity_batch_put_ll(b,k,exp);snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:tx",sid,clan);rc|=qrxdb_batch_put(b,k,txid);free(type);free(xs);free(ys);free(exp_s);return rc?-1:0;}
static int generals_stage_clan_invite(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h,long long cost){if(!generals_player_exists(c,from)||cost<0)return -1;char *invitee=payload_get_field(p,"invitee"),*exp=payload_get_field(p,"expiry_height");if(!invitee||!*invitee||!generals_player_exists(c,invitee)){free(invitee);free(exp);return -1;}char pk[1024],clan[256],leaderk[1024],leader[256],v[256];generals_player_key(pk,sizeof(pk),from,"clan_id");if(generals_db_get(c,pk,clan,sizeof(clan))!=0||!*clan){free(invitee);free(exp);return -1;}snprintf(leaderk,sizeof(leaderk),"generals:clan:%s:leader",clan);if(!generals_clan_can_command(c,clan,from)){free(invitee);free(exp);return -1;}generals_player_key(pk,sizeof(pk),invitee,"clan_id");if(generals_db_get(c,pk,v,sizeof(v))==0&&*v){free(invitee);free(exp);return -1;}long long maxlife=qrx_chain_get_ll_at_height_or_default(c,h,"generals_clan_invite_max_blocks",604800),expiry=exp&&*exp?parse_positive_ll_strict(exp,"expiry_height"):h+60480;if(expiry<=h||expiry-h>maxlife){free(invitee);free(exp);return -1;}char iid[40],k[1024],hb[64];snprintf(iid,sizeof(iid),"CINV-%.24s",txid);int rc=0;
 snprintf(k,sizeof(k),"generals:clan_invite:%s:status",iid);rc|=qrxdb_batch_put(b,k,"pending");
 snprintf(k,sizeof(k),"generals:clan_invite:%s:clan_id",iid);rc|=qrxdb_batch_put(b,k,clan);
 snprintf(k,sizeof(k),"generals:clan_invite:%s:inviter",iid);rc|=qrxdb_batch_put(b,k,from);
 snprintf(k,sizeof(k),"generals:clan_invite:%s:invitee",iid);rc|=qrxdb_batch_put(b,k,invitee);
 snprintf(k,sizeof(k),"generals:clan_invite:%s:created_tx",iid);rc|=qrxdb_batch_put(b,k,txid);
 snprintf(hb,sizeof(hb),"%lld",h);snprintf(k,sizeof(k),"generals:clan_invite:%s:created_height",iid);rc|=qrxdb_batch_put(b,k,hb);
 snprintf(hb,sizeof(hb),"%lld",expiry);snprintf(k,sizeof(k),"generals:clan_invite:%s:expiry_height",iid);rc|=qrxdb_batch_put(b,k,hb);
 snprintf(k,sizeof(k),"generals:clan:%s:invite:%s",clan,iid);rc|=qrxdb_batch_put(b,k,"pending");snprintf(k,sizeof(k),"generals:player:%s:invite:%s",invitee,iid);rc|=qrxdb_batch_put(b,k,clan);if(cost>0)rc|=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_INVITE");free(invitee);free(exp);return rc?-1:0;}
static int generals_stage_clan_invite_revoke(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*iid=payload_get_field(p,"invite_id");if(!iid||!generals_safe_token(iid,8,39,0)){free(iid);return -1;}char k[1024],status[64],clan[256],leader[256];snprintf(k,sizeof(k),"generals:clan_invite:%s:status",iid);if(generals_db_get(c,k,status,sizeof(status))!=0||strcmp(status,"pending")){free(iid);return -1;}snprintf(k,sizeof(k),"generals:clan_invite:%s:clan_id",iid);if(generals_db_get(c,k,clan,sizeof(clan))!=0){free(iid);return -1;}snprintf(k,sizeof(k),"generals:clan:%s:leader",clan);if(!generals_clan_can_command(c,clan,from)){free(iid);return -1;}int rc=0;snprintf(k,sizeof(k),"generals:clan_invite:%s:status",iid);rc|=qrxdb_batch_put(b,k,"revoked");snprintf(k,sizeof(k),"generals:clan_invite:%s:resolved_tx",iid);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:clan_invite:%s:resolved_height",iid);rc|=velocity_batch_put_ll(b,k,h);free(iid);return rc?-1:0;}
static int generals_stage_clan_join(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){if(!generals_player_exists(c,from))return -1;char*iid=payload_get_field(p,"invite_id");if(!iid){return -1;}char pk[1024],v[512];generals_player_key(pk,sizeof(pk),from,"clan_id");if(generals_db_get(c,pk,v,sizeof(v))==0&&*v){free(iid);return -1;}char k[1024],status[64],invitee[512],clan[256];snprintf(k,sizeof(k),"generals:clan_invite:%s:status",iid);if(generals_db_get(c,k,status,sizeof(status))!=0||strcmp(status,"pending")){free(iid);return -1;}snprintf(k,sizeof(k),"generals:clan_invite:%s:invitee",iid);if(generals_db_get(c,k,invitee,sizeof(invitee))!=0||strcmp(invitee,from)){free(iid);return -1;}snprintf(k,sizeof(k),"generals:clan_invite:%s:clan_id",iid);if(generals_db_get(c,k,clan,sizeof(clan))!=0){free(iid);return -1;}snprintf(k,sizeof(k),"generals:clan_invite:%s:expiry_height",iid);if(generals_db_ll(c,k,0)<h){free(iid);return -1;}snprintf(k,sizeof(k),"generals:clan:%s:status",clan);if(generals_db_get(c,k,v,sizeof(v))!=0||strcmp(v,"active")){free(iid);return -1;}long long mc;snprintf(k,sizeof(k),"generals:clan:%s:member_count",clan);mc=generals_db_ll(c,k,1);int rc=0;snprintf(k,sizeof(k),"generals:clan:%s:member:%s",clan,from);rc|=qrxdb_batch_put(b,k,"MEMBER");snprintf(k,sizeof(k),"generals:clan:%s:member_count",clan);rc|=velocity_batch_put_ll(b,k,mc+1);generals_player_key(k,sizeof(k),from,"clan_id");rc|=qrxdb_batch_put(b,k,clan);snprintf(k,sizeof(k),"generals:clan_invite:%s:status",iid);rc|=qrxdb_batch_put(b,k,"accepted");snprintf(k,sizeof(k),"generals:clan_invite:%s:resolved_tx",iid);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:clan_invite:%s:resolved_height",iid);rc|=velocity_batch_put_ll(b,k,h);free(iid);return rc?-1:0;}
static int generals_stage_clan_leave(QrxDBBatch*b,const char*c,const char*from,const char*txid,long long h){if(!generals_player_exists(c,from))return -1;char pk[1024],clan[256],k[1024],founder[512],leader[512];generals_player_key(pk,sizeof(pk),from,"clan_id");if(generals_db_get(c,pk,clan,sizeof(clan))!=0||!*clan)return -1;snprintf(k,sizeof(k),"generals:clan:%s:founder",clan);generals_db_get(c,k,founder,sizeof(founder));snprintf(k,sizeof(k),"generals:clan:%s:leader",clan);if(generals_db_get(c,k,leader,sizeof(leader))==0&&!strcmp(leader,from))return -1;snprintf(k,sizeof(k),"generals:clan:%s:member_count",clan);long long mc=generals_db_ll(c,k,1);if(mc<=1)return -1;int rc=0;snprintf(k,sizeof(k),"generals:clan:%s:member:%s",clan,from);rc|=qrxdb_batch_put(b,k,"LEFT");snprintf(k,sizeof(k),"generals:clan:%s:member_count",clan);rc|=velocity_batch_put_ll(b,k,mc-1);generals_player_key(k,sizeof(k),from,"clan_id");rc|=qrxdb_batch_put(b,k,"");generals_player_key(k,sizeof(k),from,"last_clan_leave_tx");rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"last_clan_leave_height");rc|=velocity_batch_put_ll(b,k,h);return rc?-1:0;}
static int generals_hex64(const char*s){if(!s||strlen(s)!=128)return 0;for(size_t i=0;i<128;i++)if(!isxdigit((unsigned char)s[i]))return 0;return 1;}
static unsigned long long generals_hash_u64(const char*s){char h[129],b[17];sha3_512_hex((const unsigned char*)s,strlen(s),h);memcpy(b,h,16);b[16]=0;return strtoull(b,NULL,16);}
static const char* generals_terrain(long long sid,long long x,long long y){char b[128];snprintf(b,sizeof(b),"QRX-GENERALS-TERRAIN-v1|%lld|%lld|%lld",sid,x,y);unsigned long long n=generals_hash_u64(b)%100;return n<12?"WATER":n<37?"FOREST":n<52?"HILLS":"PLAINS";}
/* Phase 3.1 adaptive world sizing. The world grows monotonically at season
 * participation thresholds. Coordinates never move when a tier expands, so
 * already committed orders and units remain consensus-stable. */
static long long generals_world_side_for_players(long long players){if(players<=100)return 128;if(players<=500)return 256;if(players<=2000)return 512;if(players<=8000)return 1024;long long side=2048,cap=32000;while(players>cap&&side<=16384){side*=2;if(cap>LLONG_MAX/4)break;cap*=4;}return side;}
static int generals_world_dims(const char*c,long long sid,long long players_hint,long long*w,long long*hh){char k[256];snprintf(k,sizeof(k),"generals:season:%lld:world_width",sid);long long sw=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:world_height",sid);long long sh=generals_db_ll(c,k,0);if(sw>0&&sh>0){*w=sw;*hh=sh;return 0;}long long side=generals_world_side_for_players(players_hint>0?players_hint:1);*w=side;*hh=side;return 0;}
static long long generals_chunk_size(const char*c,long long h){long long z=qrx_chain_get_ll_at_height_or_default(c,h,"generals_world_chunk_size",64);if(z<16)z=16;if(z>256)z=256;return z;}
static long long generals_season_chunk_size(const char*c,long long sid,long long h){char k[256];snprintf(k,sizeof(k),"generals:season:%lld:world_chunk_size",sid);long long z=generals_db_ll(c,k,0);if(z<=0)z=generals_chunk_size(c,h);if(z<16)z=16;if(z>256)z=256;return z;}
static void generals_tile_key(char*out,size_t n,const char*c,long long sid,long long x,long long y,long long h){long long cs=generals_season_chunk_size(c,sid,h),cx=x/cs,cy=y/cs,lx=x%cs,ly=y%cs;snprintf(out,n,"generals:season:%lld:chunk:%lld:%lld:tile:%lld:%lld:unit",sid,cx,cy,lx,ly);}
static int generals_tile_occupied(const char*c,long long sid,long long x,long long y,char*out,size_t n){char k[384];generals_tile_key(k,sizeof(k),c,sid,x,y,0);if(generals_db_get(c,k,out,n)==0&&out[0])return 1;/* Phase-3 read compatibility for pre-3.1 states. */snprintf(k,sizeof(k),"generals:season:%lld:tile:%lld:%lld:unit",sid,x,y);return generals_db_get(c,k,out,n)==0&&out[0];}
static void generals_unit_id(const char*from,long long sid,long long ord,char out[40]){char b[1024],h[129];snprintf(b,sizeof(b),"QRX-GENERALS-UNIT-v1|%lld|%s|%lld",sid,from,ord);sha3_512_hex((const unsigned char*)b,strlen(b),h);snprintf(out,40,"UNIT-%.24s",h);}
static int generals_stage_unit(QrxDBBatch*b,const char*c,long long sid,const char*from,const char*general,const char*uid,const char*type,long long x,long long y,long long hp,long long move_range,long long energy){char k[1024],z[64];int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:status",uid);rc|=qrxdb_batch_put(b,k,"active");snprintf(k,sizeof(k),"generals:unit:%s:type",uid);rc|=qrxdb_batch_put(b,k,type);snprintf(k,sizeof(k),"generals:unit:%s:owner",uid);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:unit:%s:general",uid);rc|=qrxdb_batch_put(b,k,general);snprintf(z,sizeof(z),"%lld",sid);snprintf(k,sizeof(k),"generals:unit:%s:season_id",uid);rc|=qrxdb_batch_put(b,k,z);snprintf(k,sizeof(k),"generals:unit:%s:x",uid);rc|=velocity_batch_put_ll(b,k,x);snprintf(k,sizeof(k),"generals:unit:%s:y",uid);rc|=velocity_batch_put_ll(b,k,y);snprintf(k,sizeof(k),"generals:unit:%s:hp",uid);rc|=velocity_batch_put_ll(b,k,hp);snprintf(k,sizeof(k),"generals:unit:%s:move_range",uid);rc|=velocity_batch_put_ll(b,k,move_range);snprintf(k,sizeof(k),"generals:unit:%s:move_energy",uid);rc|=velocity_batch_put_ll(b,k,energy);snprintf(k,sizeof(k),"generals:unit:%s:last_move_turn",uid);rc|=velocity_batch_put_ll(b,k,0);generals_tile_key(k,sizeof(k),c,sid,x,y,0);rc|=qrxdb_batch_put(b,k,uid);return rc?-1:0;}
static int generals_hq_far_enough(const char*c,long long sid,long long x,long long y,long long min_dist){char k[384];long long hc;snprintf(k,sizeof(k),"generals:season:%lld:hq_count",sid);hc=generals_db_ll(c,k,0);for(long long i=0;i<hc;i++){char xb[64],yb[64];snprintf(k,sizeof(k),"generals:season:%lld:hq:%lld:x",sid,i);if(generals_db_get(c,k,xb,sizeof(xb))!=0)continue;snprintf(k,sizeof(k),"generals:season:%lld:hq:%lld:y",sid,i);if(generals_db_get(c,k,yb,sizeof(yb))!=0)continue;long long d=llabs(x-atoll(xb))+llabs(y-atoll(yb));if(d<min_dist)return 0;}return 1;}
static int generals_stage_territory(QrxDBBatch*b,const char*c,long long sid,long long x,long long y,const char*owner);
static int generals_spawn_neighbors(const char*c,long long sid,long long hx,long long hy,long long w,long long hh,long long sx[4],long long sy[4]){static const int d[][2]={{1,0},{-1,0},{0,1},{0,-1},{1,1},{1,-1},{-1,1},{-1,-1},{2,0},{-2,0},{0,2},{0,-2},{2,1},{2,-1},{-2,1},{-2,-1},{1,2},{-1,2},{1,-2},{-1,-2}};char occ[256];sx[0]=hx;sy[0]=hy;int got=1;for(size_t i=0;i<sizeof(d)/sizeof(d[0])&&got<4;i++){long long x=hx+d[i][0],y=hy+d[i][1];if(x<0||y<0||x>=w||y>=hh||!strcmp(generals_terrain(sid,x,y),"WATER"))continue;if(generals_tile_occupied(c,sid,x,y,occ,sizeof(occ)))continue;int dup=0;for(int q=0;q<got;q++)if(sx[q]==x&&sy[q]==y){dup=1;break;}if(dup)continue;sx[got]=x;sy[got]=y;got++;}return got==4?0:-1;}
static int generals_stage_spawn(QrxDBBatch*b,const char*c,const char*from,const char*general,long long sid,long long w,long long hh){char k[1024],v[256],occ[256];snprintf(k,sizeof(k),"generals:season:%lld:player:%s:spawned",sid,from);if(generals_db_get(c,k,v,sizeof(v))==0)return -1;if(w<16||hh<16)return -1;long long min_dist=qrx_chain_get_ll_at_height_or_default(c,0,"generals_hq_min_distance",16);if(min_dist<4)min_dist=4;const char*types[4]={"HQ","INFANTRY","INFANTRY","INFANTRY"};long long hp[4]={1000,100,100,100},mr[4]={0,1,1,1},ec[4]={0,1,1,1},sx[4]={0},sy[4]={0};unsigned long long total=(unsigned long long)w*(unsigned long long)hh;char seed[1024];snprintf(seed,sizeof(seed),"QRX-GENERALS-HQ-SPAWN-v2|%lld|%s",sid,from);unsigned long long n=generals_hash_u64(seed);int found=0;for(unsigned long long j=0;j<total;j++){unsigned long long z=(n+j*2654435761ULL)%total;long long x=(long long)(z%(unsigned long long)w),y=(long long)(z/(unsigned long long)w);if(x<2||y<2||x>=w-2||y>=hh-2)continue;if(!strcmp(generals_terrain(sid,x,y),"WATER"))continue;if(generals_tile_occupied(c,sid,x,y,occ,sizeof(occ)))continue;if(!generals_hq_far_enough(c,sid,x,y,min_dist))continue;if(generals_spawn_neighbors(c,sid,x,y,w,hh,sx,sy)!=0)continue;found=1;break;}if(!found)return -1;int rc=0;for(long long ord=0;ord<4;ord++){char uid[40];generals_unit_id(from,sid,ord,uid);rc|=generals_stage_unit(b,c,sid,from,general,uid,types[ord],sx[ord],sy[ord],hp[ord],mr[ord],ec[ord]);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:unit:%lld",sid,from,ord);rc|=qrxdb_batch_put(b,k,uid);if(ord==0){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:hq_unit",sid,from);rc|=qrxdb_batch_put(b,k,uid);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:spawn_x",sid,from);rc|=velocity_batch_put_ll(b,k,sx[ord]);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:spawn_y",sid,from);rc|=velocity_batch_put_ll(b,k,sy[ord]);}}
 /* Phase 4 starter support detachment: keeps the legacy 4-unit starter index intact while adding strategic classes. */
 const char*stypes[3]={"RECON","ARTILLERY","MISSILE_BATTERY"};long long shps[3]={90,120,140},smove[3]={6,2,1},senergy[3]={2,2,3};long long bx=sx[0],by=sy[0];static const int sd[][2]={{2,0},{0,2},{-2,0},{0,-2},{2,-1},{1,1},{-1,2},{-2,1},{-1,-1},{1,-2},{3,0},{0,3},{-3,0},{0,-3}};int sgot=0;for(size_t si=0;si<sizeof(sd)/sizeof(sd[0])&&sgot<3;si++){long long px=bx+sd[si][0],py=by+sd[si][1];if(px<0||py<0||px>=w||py>=hh||!strcmp(generals_terrain(sid,px,py),"WATER"))continue;int dup=0;for(int q=0;q<4;q++)if(sx[q]==px&&sy[q]==py)dup=1;if(dup||generals_tile_occupied(c,sid,px,py,occ,sizeof(occ)))continue;char uid[40];generals_unit_id(from,sid,100+sgot,uid);rc|=generals_stage_unit(b,c,sid,from,general,uid,stypes[sgot],px,py,shps[sgot],smove[sgot],senergy[sgot]);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:support_unit:%d",sid,from,sgot);rc|=qrxdb_batch_put(b,k,uid);sgot++;}if(sgot!=3)return -1;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:support_unit_count",sid,from);rc|=velocity_batch_put_ll(b,k,3);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:army_unit_count",sid,from);rc|=velocity_batch_put_ll(b,k,7);rc|=generals_stage_territory(b,c,sid,bx,by,from);
 snprintf(k,sizeof(k),"generals:season:%lld:hq_count",sid);long long hc=generals_db_ll(c,k,0);rc|=velocity_batch_put_ll(b,k,hc+1);snprintf(k,sizeof(k),"generals:season:%lld:hq:%lld:x",sid,hc);rc|=velocity_batch_put_ll(b,k,sx[0]);snprintf(k,sizeof(k),"generals:season:%lld:hq:%lld:y",sid,hc);rc|=velocity_batch_put_ll(b,k,sy[0]);snprintf(k,sizeof(k),"generals:season:%lld:hq:%lld:owner",sid,hc);rc|=qrxdb_batch_put(b,k,from);
 snprintf(k,sizeof(k),"generals:season:%lld:player:%s:unit_count",sid,from);rc|=velocity_batch_put_ll(b,k,4);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:spawned",sid,from);rc|=qrxdb_batch_put(b,k,"1");return rc?-1:0;}
static int generals_order_phase(const char*c,long long h,long long*sid,long long*turn,int*reveal){long long ss=0,se=0,ts=0,te=0;if(generals_season_at(c,h,sid,&ss,&se,turn,&ts,&te)!=0)return -1;long long len=te-ts+1,split=ts+len/2;*reveal=h>=split;return 0;}
static int generals_stage_order_commit(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*sid_s=payload_get_field(p,"season_id"),*turn_s=payload_get_field(p,"turn_id"),*commit=payload_get_field(p,"commitment");if(!sid_s||!turn_s||!commit){free(sid_s);free(turn_s);free(commit);return -1;}long long sid=parse_positive_ll_strict(sid_s,"season_id"),turn=parse_positive_ll_strict(turn_s,"turn_id"),cs=0,ct=0;int reveal=0;free(sid_s);free(turn_s);if(!generals_hex64(commit)||generals_order_phase(c,h,&cs,&ct,&reveal)!=0||reveal||sid!=cs||turn!=ct){free(commit);return -1;}char k[1024],v[64],z[64],oid[40];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,from);if(generals_db_get(c,k,v,sizeof(v))!=0||strcmp(v,"active")){free(commit);return -1;}snprintf(oid,sizeof(oid),"ORD-%.24s",txid);snprintf(k,sizeof(k),"generals:order:%s:status",oid);if(generals_db_get(c,k,v,sizeof(v))==0){free(commit);return -1;}int rc=0;snprintf(k,sizeof(k),"generals:order:%s:status",oid);rc|=qrxdb_batch_put(b,k,"committed");snprintf(k,sizeof(k),"generals:order:%s:owner",oid);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:order:%s:commitment",oid);rc|=qrxdb_batch_put(b,k,commit);snprintf(z,sizeof(z),"%lld",sid);snprintf(k,sizeof(k),"generals:order:%s:season_id",oid);rc|=qrxdb_batch_put(b,k,z);snprintf(z,sizeof(z),"%lld",turn);snprintf(k,sizeof(k),"generals:order:%s:turn_id",oid);rc|=qrxdb_batch_put(b,k,z);snprintf(k,sizeof(k),"generals:order:%s:commit_height",oid);rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:order:%s:commit_tx",oid);rc|=qrxdb_batch_put(b,k,txid);free(commit);return rc?-1:0;}
static int generals_stage_order_reveal_v1(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*oid=payload_get_field(p,"order_id"),*unit=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"to_x"),*ys=payload_get_field(p,"to_y"),*secret=payload_get_field(p,"secret");if(!oid||!unit||!xs||!ys||!secret){free(oid);free(unit);free(xs);free(ys);free(secret);return -1;}if(strncmp(oid,"ORD-",4)||strlen(secret)<8||strlen(secret)>128)goto fail;char k[1024],v[1024],owner[1024],commit[256],sidb[64],turnb[64];snprintf(k,sizeof(k),"generals:order:%s:status",oid);if(generals_db_get(c,k,v,sizeof(v))!=0||strcmp(v,"committed"))goto fail;snprintf(k,sizeof(k),"generals:order:%s:owner",oid);if(generals_db_get(c,k,owner,sizeof(owner))!=0||strcmp(owner,from))goto fail;snprintf(k,sizeof(k),"generals:order:%s:commitment",oid);if(generals_db_get(c,k,commit,sizeof(commit))!=0)goto fail;snprintf(k,sizeof(k),"generals:order:%s:season_id",oid);if(generals_db_get(c,k,sidb,sizeof(sidb))!=0)goto fail;snprintf(k,sizeof(k),"generals:order:%s:turn_id",oid);if(generals_db_get(c,k,turnb,sizeof(turnb))!=0)goto fail;long long sid=atoll(sidb),turn=atoll(turnb),cs=0,ct=0;int reveal=0;if(generals_order_phase(c,h,&cs,&ct,&reveal)!=0||!reveal||sid!=cs||turn!=ct)goto fail;char*xe=NULL,*ye=NULL;errno=0;long long x=strtoll(xs,&xe,10);if(errno||!xe||*xe)goto fail;errno=0;long long y=strtoll(ys,&ye,10);if(errno||!ye||*ye)goto fail;long long w=0,hh=0;if(generals_world_dims(c,sid,1,&w,&hh)!=0)goto fail;if(x<0||y<0||x>=w||y>=hh)goto fail;char canon[2048],calc[129];snprintf(canon,sizeof(canon),"QRX-GENERALS-ORDER-v1|%lld|%lld|MOVE|%s|%lld|%lld|%s",sid,turn,unit,x,y,secret);sha3_512_hex((const unsigned char*)canon,strlen(canon),calc);if(strcasecmp(calc,commit))goto fail;char uowner[1024],typ[128],xb[64],yb[64],mrb[64],eb[64],ltb[64];snprintf(k,sizeof(k),"generals:unit:%s:owner",unit);if(generals_db_get(c,k,uowner,sizeof(uowner))!=0)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:type",unit);if(generals_db_get(c,k,typ,sizeof(typ))!=0)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:x",unit);if(generals_db_get(c,k,xb,sizeof(xb))!=0)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:y",unit);if(generals_db_get(c,k,yb,sizeof(yb))!=0)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:move_range",unit);if(generals_db_get(c,k,mrb,sizeof(mrb))!=0)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:move_energy",unit);if(generals_db_get(c,k,eb,sizeof(eb))!=0)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:last_move_turn",unit);if(generals_db_get(c,k,ltb,sizeof(ltb))!=0)goto fail;if(strcmp(uowner,from)||!strcmp(typ,"HQ")||atoll(ltb)==turn)goto fail;long long ox=atoll(xb),oy=atoll(yb),mr=atoll(mrb),energy=atoll(eb),dist=llabs(x-ox)+llabs(y-oy);if(dist<1||dist>mr||!strcmp(generals_terrain(sid,x,y),"WATER"))goto fail;char occ[256];if(generals_tile_occupied(c,sid,x,y,occ,sizeof(occ)))goto fail;long long base=0,curE=generals_energy_at(c,from,h,&base);if(energy<1||energy>curE)goto fail;int rc=0;generals_tile_key(k,sizeof(k),c,sid,ox,oy,h);rc|=qrxdb_batch_put(b,k,"");generals_tile_key(k,sizeof(k),c,sid,x,y,h);rc|=qrxdb_batch_put(b,k,unit);snprintf(k,sizeof(k),"generals:unit:%s:x",unit);rc|=velocity_batch_put_ll(b,k,x);snprintf(k,sizeof(k),"generals:unit:%s:y",unit);rc|=velocity_batch_put_ll(b,k,y);snprintf(k,sizeof(k),"generals:unit:%s:last_move_turn",unit);rc|=velocity_batch_put_ll(b,k,turn);snprintf(k,sizeof(k),"generals:unit:%s:last_move_tx",unit);rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,curE-energy);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:order:%s:status",oid);rc|=qrxdb_batch_put(b,k,"executed");snprintf(k,sizeof(k),"generals:order:%s:reveal_height",oid);rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:order:%s:reveal_tx",oid);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:order:%s:unit_id",oid);rc|=qrxdb_batch_put(b,k,unit);snprintf(k,sizeof(k),"generals:order:%s:to_x",oid);rc|=velocity_batch_put_ll(b,k,x);snprintf(k,sizeof(k),"generals:order:%s:to_y",oid);rc|=velocity_batch_put_ll(b,k,y);free(oid);free(unit);free(xs);free(ys);free(secret);return rc?-1:0;fail:free(oid);free(unit);free(xs);free(ys);free(secret);return -1;}

/* QRX Generals 0.0.7.7 Phase 4: hex movement, unit classes, persistent march orders,
   long-range attacks, simultaneous pending-damage resolution and territory state. */
typedef struct {const char*name;long long hp,move,move_energy,attack,defense,min_range,max_range,attack_energy,cooldown,vision,capture;} GeneralsUnitClass;
static const GeneralsUnitClass GENERALS_CLASSES[]={
 {"HQ",1000,0,0,0,80,0,0,0,0,4,0},
 {"INFANTRY",100,2,1,34,22,1,1,2,0,2,1},
 {"MECHANIZED_INFANTRY",180,4,2,48,38,1,1,3,0,3,1},
 {"TANK",260,4,3,72,62,1,1,4,0,3,1},
 {"RECON",90,6,2,24,16,1,1,2,0,6,1},
 {"ARTILLERY",120,2,2,86,18,2,6,5,1,3,0},
 {"MLRS",110,2,2,105,15,3,10,7,2,3,0},
 {"SAM",150,2,2,64,30,2,8,5,1,6,0},
 {"MISSILE_BATTERY",140,1,3,150,20,3,256,10,3,4,0},
 {"HELICOPTER",150,7,4,68,30,1,3,5,1,6,0},
 {"FIGHTER",160,10,5,82,40,1,6,6,1,9,0},
 {"BOMBER",190,8,6,120,30,2,8,8,2,7,0},
 {"TRANSPORT",180,6,3,10,24,1,1,2,0,4,0},
 {"ENGINEER",100,3,2,20,20,1,1,2,0,2,1},
 {"PATROL_BOAT",130,6,2,38,24,1,3,3,0,5,0},
 {"DESTROYER",320,5,4,88,70,1,10,6,1,10,0},
 {"FRIGATE",260,5,3,66,58,1,8,5,1,11,0},
 {"CRUISER",420,4,5,118,86,2,14,8,2,12,0},
 {"AMPHIBIOUS_TRANSPORT",360,5,4,24,54,1,2,3,0,6,0},
 {"SUPPLY_SHIP",300,4,3,18,42,1,2,2,0,6,0},
 {"CARRIER",650,3,7,70,110,2,12,9,2,15,0},
 {NULL,0,0,0,0,0,0,0,0,0,0,0}
};
static const GeneralsUnitClass*generals_class(const char*t){for(int i=0;GENERALS_CLASSES[i].name;i++)if(!strcmp(GENERALS_CLASSES[i].name,t))return &GENERALS_CLASSES[i];return NULL;}
static long long generals_hex_distance(long long ax,long long ay,long long bx,long long by){long long dx=bx-ax,dy=by-ay,dz=-(dx+dy);dx=llabs(dx);dy=llabs(dy);dz=llabs(dz);return dx>dy?(dx>dz?dx:dz):(dy>dz?dy:dz);}
static int generals_hex_adjacent(long long ax,long long ay,long long bx,long long by){return generals_hex_distance(ax,ay,bx,by)==1;}

static int generals_unit_field(const char*c,const char*uid,const char*f,char*out,size_t n);
static long long generals_unit_ll(const char*c,const char*uid,const char*f,long long d);
/* Phase 4.4: consensus-visible reconnaissance/EW state. Note that QRXDB is public;
 * this enforces game knowledge/targeting rules, not cryptographic secrecy of raw state. */
static int generals_contact_visible(const char*c,const char*viewer,const char*target,long long h){
 char to[256],st[64],k[512]; if(generals_unit_field(c,target,"owner",to,sizeof(to)))return 0;if(!strcmp(to,viewer))return 1;
 long long sid=generals_unit_ll(c,target,"season_id",0),tx=generals_unit_ll(c,target,"x",-1),ty=generals_unit_ll(c,target,"y",-1);
 snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:expires_height",sid,viewer,target);if(generals_db_ll(c,k,-1)>=h)return 1;
 /* bounded scan of the viewer's indexed army */
 snprintf(k,sizeof(k),"generals:season:%lld:player:%s:army_unit_count",sid,viewer);long long n=generals_db_ll(c,k,0);if(n>128)n=128;
 for(long long i=0;i<n;i++){char uid[128]="";if(i<4)snprintf(k,sizeof(k),"generals:season:%lld:player:%s:unit:%lld",sid,viewer,i);else if(i<7)snprintf(k,sizeof(k),"generals:season:%lld:player:%s:support_unit:%lld",sid,viewer,i-4);else continue;if(generals_db_get(c,k,uid,sizeof(uid)))continue;if(generals_unit_field(c,uid,"status",st,sizeof(st))||strcmp(st,"active"))continue;char typ[64];if(generals_unit_field(c,uid,"type",typ,sizeof(typ)))continue;const GeneralsUnitClass*cl=generals_class(typ);if(!cl)continue;long long ux=generals_unit_ll(c,uid,"x",-1),uy=generals_unit_ll(c,uid,"y",-1),vis=cl->vision;
   snprintf(k,sizeof(k),"generals:ew:%lld:%s:jam_until",sid,viewer);if(generals_db_ll(c,k,-1)>=h&&vis>1)vis=(vis+1)/2;
   if(generals_hex_distance(ux,uy,tx,ty)<=vis)return 1;}
 return 0;
}
static int generals_stage_recon_scan(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*target=payload_get_field(p,"target_unit_id");if(!uid||!target)goto fail;char o[256],typ[64],to[256],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||generals_unit_field(c,target,"owner",to,sizeof(to))||!strcmp(to,from))goto fail;const GeneralsUnitClass*cl=generals_class(typ);if(!cl||cl->vision<2)goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),d=generals_hex_distance(generals_unit_ll(c,uid,"x",-1),generals_unit_ll(c,uid,"y",-1),generals_unit_ll(c,target,"x",-1),generals_unit_ll(c,target,"y",-1));long long range=cl->vision*2;if(strcmp(typ,"RECON")&&strcmp(typ,"FIGHTER"))range=cl->vision;if(d>range)goto fail;long long ttl=qrx_chain_get_ll_at_height_or_default(c,h,"generals_contact_ttl_blocks",120);int rc=0;snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:expires_height",sid,from,target);rc|=velocity_batch_put_ll(b,k,h+ttl);snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_height",sid,from,target);rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_x",sid,from,target);rc|=velocity_batch_put_ll(b,k,generals_unit_ll(c,target,"x",-1));snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_y",sid,from,target);rc|=velocity_batch_put_ll(b,k,generals_unit_ll(c,target,"y",-1));snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:scan_tx",sid,from,target);rc|=qrxdb_batch_put(b,k,txid);free(uid);free(target);return rc?-1:0;fail:free(uid);free(target);return -1;}
static int generals_stage_ew_jam(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*target=payload_get_field(p,"target_player");if(!uid||!target)goto fail;char o[256],typ[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ)))goto fail;if(strcmp(typ,"RECON")&&strcmp(typ,"FIGHTER"))goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),ttl=qrx_chain_get_ll_at_height_or_default(c,h,"generals_jam_ttl_blocks",60);int rc=0;snprintf(k,sizeof(k),"generals:ew:%lld:%s:jam_until",sid,target);long long old=generals_db_ll(c,k,-1);if(old>h+ttl)ttl=old-h;rc|=velocity_batch_put_ll(b,k,h+ttl);snprintf(k,sizeof(k),"generals:ew:%lld:%s:last_jammer",sid,target);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:ew:%lld:%s:last_jam_tx",sid,target);rc|=qrxdb_batch_put(b,k,txid);free(uid);free(target);return rc?-1:0;fail:free(uid);free(target);return -1;}
static int generals_contact_info_cmd(const char*c,const char*viewer,const char*target,long long h){char k[512];long long sid=generals_unit_ll(c,target,"season_id",0);printf("viewer=%s\ntarget_unit=%s\nvisible=%d\n",viewer,target,generals_contact_visible(c,viewer,target,h));snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_height",sid,viewer,target);printf("last_seen_height=%lld\n",generals_db_ll(c,k,-1));snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_x",sid,viewer,target);printf("last_seen_x=%lld\n",generals_db_ll(c,k,-1));snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_y",sid,viewer,target);printf("last_seen_y=%lld\n",generals_db_ll(c,k,-1));return 0;}
static long long generals_terrain_move_cost(const char*t){if(!strcmp(t,"PLAINS"))return 1;if(!strcmp(t,"FOREST"))return 2;if(!strcmp(t,"HILLS"))return 2;return 999999;}
static long long generals_terrain_defense_bonus(const char*t){if(!strcmp(t,"FOREST"))return 10;if(!strcmp(t,"HILLS"))return 20;return 0;}
static int generals_unit_field(const char*c,const char*uid,const char*f,char*out,size_t n){char k[512];snprintf(k,sizeof(k),"generals:unit:%s:%s",uid,f);return generals_db_get(c,k,out,n);}
static long long generals_unit_ll(const char*c,const char*uid,const char*f,long long d){char v[128];return generals_unit_field(c,uid,f,v,sizeof(v))==0?atoll(v):d;}
static int generals_territory_owner(const char*c,long long sid,long long x,long long y,char*out,size_t n){char k[512];long long cs=generals_season_chunk_size(c,sid,0);snprintf(k,sizeof(k),"generals:season:%lld:chunk:%lld:%lld:tile:%lld:%lld:owner",sid,x/cs,y/cs,x%cs,y%cs);return generals_db_get(c,k,out,n);}
static int generals_stage_territory(QrxDBBatch*b,const char*c,long long sid,long long x,long long y,const char*owner){char k[512];long long cs=generals_season_chunk_size(c,sid,0);snprintf(k,sizeof(k),"generals:season:%lld:chunk:%lld:%lld:tile:%lld:%lld:owner",sid,x/cs,y/cs,x%cs,y%cs);return qrxdb_batch_put(b,k,owner);}
static int generals_parse_path(const char*path,long long xs[],long long ys[],int maxn){if(!path||!*path)return -1;char*tmp=strdup(path),*save=NULL,*tok=strtok_r(tmp,">",&save);int n=0;while(tok&&n<maxn){char*comma=strchr(tok,',');if(!comma){free(tmp);return -1;}*comma=0;char*e1=NULL,*e2=NULL;errno=0;long long x=strtoll(tok,&e1,10);if(errno||!e1||*e1){free(tmp);return -1;}errno=0;long long y=strtoll(comma+1,&e2,10);if(errno||!e2||*e2){free(tmp);return -1;}xs[n]=x;ys[n]=y;n++;tok=strtok_r(NULL,">",&save);}if(tok){free(tmp);return -1;}free(tmp);return n;}
static int generals_validate_path(const char*c,long long sid,const char*uid,const char*path,long long*lastx,long long*lasty,long long*spent,long long budget,int stop_on_budget,int*consumed){long long xs[512],ys[512];int n=generals_parse_path(path,xs,ys,512);if(n<1)return -1;long long ox=generals_unit_ll(c,uid,"x",-1),oy=generals_unit_ll(c,uid,"y",-1),w=0,hh=0,total=0;generals_world_dims(c,sid,1,&w,&hh);char occ[256];int used=0;for(int i=0;i<n;i++){if(xs[i]<0||ys[i]<0||xs[i]>=w||ys[i]>=hh||!generals_hex_adjacent(ox,oy,xs[i],ys[i]))return -1;const char*ter=generals_terrain(sid,xs[i],ys[i]);long long mc=generals_terrain_move_cost(ter);if(mc>=999999)return -1;if(generals_tile_occupied(c,sid,xs[i],ys[i],occ,sizeof(occ))&&strcmp(occ,uid))break;if(stop_on_budget&&total+mc>budget)break;total+=mc;ox=xs[i];oy=ys[i];used++;}if(used<1)return -1;*lastx=ox;*lasty=oy;*spent=total;if(consumed)*consumed=used;return 0;}
static int generals_stage_move_common(QrxDBBatch*b,const char*c,const char*from,const char*uid,long long sid,long long turn,long long h,const char*txid,long long nx,long long ny,long long energy_cost){char k[1024],owner[256],typ[128];if(generals_unit_field(c,uid,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ)))return -1;const GeneralsUnitClass*cl=generals_class(typ);if(!cl||!cl->move||generals_unit_ll(c,uid,"last_move_turn",0)==turn)return -1;long long ox=generals_unit_ll(c,uid,"x",-1),oy=generals_unit_ll(c,uid,"y",-1);char occ[256];if(generals_tile_occupied(c,sid,nx,ny,occ,sizeof(occ))&&strcmp(occ,uid))return -1;long long base=0,e=generals_energy_at(c,from,h,&base);if(energy_cost<1||energy_cost>e)return -1;long long ufuel=generals_unit_ll(c,uid,"fuel",100);long long fuel_cost=cl->move_energy>0?cl->move_energy:1;if(ufuel<fuel_cost)return -1;int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,ufuel-fuel_cost);generals_tile_key(k,sizeof(k),c,sid,ox,oy,h);rc|=qrxdb_batch_put(b,k,"");generals_tile_key(k,sizeof(k),c,sid,nx,ny,h);rc|=qrxdb_batch_put(b,k,uid);snprintf(k,sizeof(k),"generals:unit:%s:x",uid);rc|=velocity_batch_put_ll(b,k,nx);snprintf(k,sizeof(k),"generals:unit:%s:y",uid);rc|=velocity_batch_put_ll(b,k,ny);snprintf(k,sizeof(k),"generals:unit:%s:last_move_turn",uid);rc|=velocity_batch_put_ll(b,k,turn);snprintf(k,sizeof(k),"generals:unit:%s:last_move_tx",uid);rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,e-energy_cost);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,h);if(cl->capture){char old[256]={0};int changed=generals_territory_owner(c,sid,nx,ny,old,sizeof(old))!=0||strcmp(old,from);rc|=generals_stage_territory(b,c,sid,nx,ny,from);if(changed){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:territory_score",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+1);}}return rc?-1:0;}
static int generals_stage_march_reveal(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*oid=payload_get_field(p,"order_id"),*unit=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"to_x"),*ys=payload_get_field(p,"to_y"),*path=payload_get_field(p,"path"),*secret=payload_get_field(p,"secret");if(!oid||!unit||!xs||!ys||!path||!secret)goto fail;char k[1024],st[64],owner[256],commit[256],sb[64],tb[64],typ[128];snprintf(k,sizeof(k),"generals:order:%s:status",oid);if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"committed"))goto fail;snprintf(k,sizeof(k),"generals:order:%s:owner",oid);if(generals_db_get(c,k,owner,sizeof(owner))||strcmp(owner,from))goto fail;snprintf(k,sizeof(k),"generals:order:%s:commitment",oid);if(generals_db_get(c,k,commit,sizeof(commit)))goto fail;snprintf(k,sizeof(k),"generals:order:%s:season_id",oid);if(generals_db_get(c,k,sb,sizeof(sb)))goto fail;snprintf(k,sizeof(k),"generals:order:%s:turn_id",oid);if(generals_db_get(c,k,tb,sizeof(tb)))goto fail;long long sid=atoll(sb),turn=atoll(tb),cs=0,ct=0;int rev=0;if(generals_order_phase(c,h,&cs,&ct,&rev)||!rev||sid!=cs||turn!=ct)goto fail;long long tx=atoll(xs),ty=atoll(ys);char canon[8192],calc[129];snprintf(canon,sizeof(canon),"QRX-GENERALS-ORDER-v2|%lld|%lld|MARCH|%s|%lld|%lld|%s|%s",sid,turn,unit,tx,ty,path,secret);sha3_512_hex((unsigned char*)canon,strlen(canon),calc);if(strcasecmp(calc,commit))goto fail;if(generals_unit_field(c,unit,"type",typ,sizeof(typ)))goto fail;const GeneralsUnitClass*cl=generals_class(typ);if(!cl||cl->move<1)goto fail;long long nx=0,ny=0,spent=0;int consumed=0;if(generals_validate_path(c,sid,unit,path,&nx,&ny,&spent,cl->move,1,&consumed))goto fail;if(generals_stage_move_common(b,c,from,unit,sid,turn,h,txid,nx,ny,cl->move_energy))goto fail;int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:march_target_x",unit);rc|=velocity_batch_put_ll(b,k,tx);snprintf(k,sizeof(k),"generals:unit:%s:march_target_y",unit);rc|=velocity_batch_put_ll(b,k,ty);snprintf(k,sizeof(k),"generals:unit:%s:march_path",unit);rc|=qrxdb_batch_put(b,k,path);snprintf(k,sizeof(k),"generals:unit:%s:march_cursor",unit);rc|=velocity_batch_put_ll(b,k,consumed);snprintf(k,sizeof(k),"generals:unit:%s:march_status",unit);rc|=qrxdb_batch_put(b,k,(nx==tx&&ny==ty)?"arrived":"active");snprintf(k,sizeof(k),"generals:order:%s:status",oid);rc|=qrxdb_batch_put(b,k,"executed_march");snprintf(k,sizeof(k),"generals:order:%s:action",oid);rc|=qrxdb_batch_put(b,k,"MARCH");snprintf(k,sizeof(k),"generals:order:%s:reveal_tx",oid);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:order:%s:reveal_height",oid);rc|=velocity_batch_put_ll(b,k,h);free(oid);free(unit);free(xs);free(ys);free(path);free(secret);return rc?-1:0;fail:free(oid);free(unit);free(xs);free(ys);free(path);free(secret);return -1;}
static int generals_stage_attack_reveal(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*oid=payload_get_field(p,"order_id"),*unit=payload_get_field(p,"unit_id"),*target=payload_get_field(p,"target_unit_id"),*secret=payload_get_field(p,"secret");if(!oid||!unit||!target||!secret)goto fail;char k[1024],st[64],owner[256],commit[256],sb[64],tb[64],aowner[256],towner[256],atype[128],ttype[128];snprintf(k,sizeof(k),"generals:order:%s:status",oid);if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"committed"))goto fail;snprintf(k,sizeof(k),"generals:order:%s:owner",oid);if(generals_db_get(c,k,owner,sizeof(owner))||strcmp(owner,from))goto fail;snprintf(k,sizeof(k),"generals:order:%s:commitment",oid);if(generals_db_get(c,k,commit,sizeof(commit)))goto fail;snprintf(k,sizeof(k),"generals:order:%s:season_id",oid);if(generals_db_get(c,k,sb,sizeof(sb)))goto fail;snprintf(k,sizeof(k),"generals:order:%s:turn_id",oid);if(generals_db_get(c,k,tb,sizeof(tb)))goto fail;long long sid=atoll(sb),turn=atoll(tb),cs=0,ct=0;int rev=0;if(generals_order_phase(c,h,&cs,&ct,&rev)||!rev||sid!=cs||turn!=ct)goto fail;char canon[4096],calc[129];snprintf(canon,sizeof(canon),"QRX-GENERALS-ORDER-v2|%lld|%lld|ATTACK|%s|%s|%s",sid,turn,unit,target,secret);sha3_512_hex((unsigned char*)canon,strlen(canon),calc);if(strcasecmp(calc,commit))goto fail;if(generals_unit_field(c,unit,"owner",aowner,sizeof(aowner))||strcmp(aowner,from)||generals_unit_field(c,target,"owner",towner,sizeof(towner))||!strcmp(towner,from))goto fail;if(!generals_contact_visible(c,from,target,h))goto fail;if(generals_unit_field(c,unit,"type",atype,sizeof(atype))||generals_unit_field(c,target,"type",ttype,sizeof(ttype)))goto fail;const GeneralsUnitClass*ac=generals_class(atype),*dc=generals_class(ttype);if(!ac||!dc||ac->attack<1)goto fail;long long ax=generals_unit_ll(c,unit,"x",-1),ay=generals_unit_ll(c,unit,"y",-1),tx=generals_unit_ll(c,target,"x",-1),ty=generals_unit_ll(c,target,"y",-1),dist=generals_hex_distance(ax,ay,tx,ty);if(dist<ac->min_range||dist>ac->max_range)goto fail;long long last=generals_unit_ll(c,unit,"last_attack_turn",-999999);if(turn-last<=ac->cooldown)goto fail;snprintf(k,sizeof(k),"generals:combat:%lld:%lld:attacker:%s",sid,turn,unit);if(generals_db_get(c,k,st,sizeof(st))==0)goto fail;long long base=0,e=generals_energy_at(c,from,h,&base);if(ac->attack_energy>e)goto fail;long long bonus=generals_terrain_defense_bonus(generals_terrain(sid,tx,ty));long long def=dc->defense+bonus,damage=(ac->attack*100)/(100+def);if(damage<1)damage=1;snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:damage",sid,turn,target);long long pd=generals_db_ll(c,k,0);int rc=0;rc|=velocity_batch_put_ll(b,k,pd+damage);snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:status",sid,turn,target);rc|=qrxdb_batch_put(b,k,"pending");snprintf(k,sizeof(k),"generals:combat:%lld:%lld:attacker:%s",sid,turn,unit);rc|=qrxdb_batch_put(b,k,target);snprintf(k,sizeof(k),"generals:unit:%s:last_attack_turn",unit);rc|=velocity_batch_put_ll(b,k,turn);snprintf(k,sizeof(k),"generals:unit:%s:last_attack_tx",unit);rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,e-ac->attack_energy);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:order:%s:status",oid);rc|=qrxdb_batch_put(b,k,"revealed_attack");snprintf(k,sizeof(k),"generals:order:%s:action",oid);rc|=qrxdb_batch_put(b,k,"ATTACK");snprintf(k,sizeof(k),"generals:order:%s:unit_id",oid);rc|=qrxdb_batch_put(b,k,unit);snprintf(k,sizeof(k),"generals:order:%s:target_unit_id",oid);rc|=qrxdb_batch_put(b,k,target);snprintf(k,sizeof(k),"generals:order:%s:pending_damage",oid);rc|=velocity_batch_put_ll(b,k,damage);snprintf(k,sizeof(k),"generals:order:%s:reveal_tx",oid);rc|=qrxdb_batch_put(b,k,txid);free(oid);free(unit);free(target);free(secret);return rc?-1:0;fail:free(oid);free(unit);free(target);free(secret);return -1;}
static int generals_stage_order_reveal(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*a=payload_get_field(p,"action");int r;if(!a||!*a||!strcmp(a,"MOVE")){free(a);return generals_stage_order_reveal_v1(b,c,from,p,txid,h);}if(!strcmp(a,"MARCH"))r=generals_stage_march_reveal(b,c,from,p,txid,h);else if(!strcmp(a,"ATTACK"))r=generals_stage_attack_reveal(b,c,from,p,txid,h);else r=-1;free(a);return r;}
static int generals_stage_march_advance(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*unit=payload_get_field(p,"unit_id");if(!unit)return -1;char status[64],owner[256],path[8192],typ[128],k[1024];snprintf(k,sizeof(k),"generals:unit:%s:march_status",unit);if(generals_db_get(c,k,status,sizeof(status))||strcmp(status,"active"))goto fail;if(generals_unit_field(c,unit,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_field(c,unit,"march_path",path,sizeof(path))||generals_unit_field(c,unit,"type",typ,sizeof(typ)))goto fail;long long sid=generals_unit_ll(c,unit,"season_id",0),cur=0,ss=0,se=0,turn=0,ts=0,te=0;if(generals_season_at(c,h,&cur,&ss,&se,&turn,&ts,&te)||sid!=cur)goto fail;const GeneralsUnitClass*cl=generals_class(typ);if(!cl||cl->move<1||generals_unit_ll(c,unit,"last_move_turn",0)==turn)goto fail;long long xs[512],ys[512];int n=generals_parse_path(path,xs,ys,512),cursor=(int)generals_unit_ll(c,unit,"march_cursor",0);if(n<1||cursor>=n)goto fail;char rem[8192]={0};size_t off=0;for(int i=cursor;i<n;i++){int z=snprintf(rem+off,sizeof(rem)-off,"%s%lld,%lld",i==cursor?"":">",xs[i],ys[i]);if(z<0||off+(size_t)z>=sizeof(rem))goto fail;off+=(size_t)z;}long long nx=0,ny=0,spent=0;int used=0;if(generals_validate_path(c,sid,unit,rem,&nx,&ny,&spent,cl->move,1,&used))goto fail;if(generals_stage_move_common(b,c,from,unit,sid,turn,h,txid,nx,ny,cl->move_energy))goto fail;int rc=0;cursor+=used;snprintf(k,sizeof(k),"generals:unit:%s:march_cursor",unit);rc|=velocity_batch_put_ll(b,k,cursor);long long tx=generals_unit_ll(c,unit,"march_target_x",nx),ty=generals_unit_ll(c,unit,"march_target_y",ny);snprintf(k,sizeof(k),"generals:unit:%s:march_status",unit);rc|=qrxdb_batch_put(b,k,(nx==tx&&ny==ty)?"arrived":"active");free(unit);return rc?-1:0;fail:free(unit);return -1;}
static int generals_stage_turn_resolve(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*sid_s=payload_get_field(p,"season_id"),*turn_s=payload_get_field(p,"turn_id"),*target=payload_get_field(p,"target_unit_id");if(!sid_s||!turn_s||!target)goto fail;long long sid=atoll(sid_s),turn=atoll(turn_s),cur=0,ss=0,se=0,ct=0,ts=0,te=0;if(generals_season_at(c,h,&cur,&ss,&se,&ct,&ts,&te)||sid!=cur||turn>=ct)goto fail;char k[1024],v[256];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,from);if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"active"))goto fail;snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:status",sid,turn,target);if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"pending"))goto fail;snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:damage",sid,turn,target);long long dmg=generals_db_ll(c,k,0),hp=generals_unit_ll(c,target,"hp",0);if(dmg<1||hp<1)goto fail;long long nh=hp>dmg?hp-dmg:0;int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:hp",target);rc|=velocity_batch_put_ll(b,k,nh);snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:status",sid,turn,target);rc|=qrxdb_batch_put(b,k,"resolved");snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:resolved_tx",sid,turn,target);rc|=qrxdb_batch_put(b,k,txid);if(nh==0){char ux[64],uy[64],uowner[256],utype[128];if(generals_unit_field(c,target,"x",ux,sizeof(ux))||generals_unit_field(c,target,"y",uy,sizeof(uy))||generals_unit_field(c,target,"owner",uowner,sizeof(uowner))||generals_unit_field(c,target,"type",utype,sizeof(utype)))goto fail;snprintf(k,sizeof(k),"generals:unit:%s:status",target);rc|=qrxdb_batch_put(b,k,"destroyed");generals_tile_key(k,sizeof(k),c,sid,atoll(ux),atoll(uy),h);rc|=qrxdb_batch_put(b,k,"");if(!strcmp(utype,"HQ")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,uowner);rc|=qrxdb_batch_put(b,k,"defeated");snprintf(k,sizeof(k),"generals:season:%lld:player:%s:defeated_height",sid,uowner);rc|=velocity_batch_put_ll(b,k,h);}}free(sid_s);free(turn_s);free(target);return rc?-1:0;fail:free(sid_s);free(turn_s);free(target);return -1;}
static int generals_stage_season_join(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h,long long cost){if(!generals_player_exists(c,from)||cost<=0)return -1;char*sid_s=payload_get_field(p,"season_id");if(!sid_s){return -1;}long long wanted=parse_positive_ll_strict(sid_s,"season_id"),sid=0,ss=0,se=0,turn=0,ts=0,te=0;free(sid_s);if(generals_season_at(c,h,&sid,&ss,&se,&turn,&ts,&te)!=0||wanted!=sid)return -1;char k[1024],v[256];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,from);if(generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,"active"))return -1;long long joinwindow=qrx_chain_get_ll_at_height_or_default(c,h,"generals_season_join_window_blocks",0);if(joinwindow>0&&h>=ss+joinwindow)return -1;char gk[1024],general[256];generals_player_key(gk,sizeof(gk),from,"general_asset");if(generals_db_get(c,gk,general,sizeof(general))!=0||!*general)return -1;long long oldpool;snprintf(k,sizeof(k),"generals:season:%lld:prize_pool_atoms",sid);oldpool=generals_db_ll(c,k,0);long long newpool=0;checked_add_ll(oldpool,cost,"Generals season prize pool",&newpool);long long oldres=generals_treasury_reserved(c),newres=0;checked_add_ll(oldres,cost,"Generals reserved treasury",&newres);long long count;snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid);count=generals_db_ll(c,k,0);long long players=count+1,target=generals_world_side_for_players(players),w=0,hh=0;generals_world_dims(c,sid,players,&w,&hh);if(target>w)w=target;if(target>hh)hh=target;long long cs=generals_chunk_size(c,h);int rc=0;rc|=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_SEASON_JOIN");rc|=velocity_batch_put_ll(b,"generals:treasury:reserved_atoms",newres);snprintf(k,sizeof(k),"generals:season:%lld:prize_pool_atoms",sid);rc|=velocity_batch_put_ll(b,k,newpool);snprintf(k,sizeof(k),"generals:season:%lld:treasury_total_atoms",sid);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+cost);snprintf(k,sizeof(k),"generals:season:%lld:entry_atoms",sid);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+cost);snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid);rc|=velocity_batch_put_ll(b,k,players);snprintf(k,sizeof(k),"generals:season:%lld:player_index:%lld",sid,count);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:season:%lld:world_width",sid);rc|=velocity_batch_put_ll(b,k,w);snprintf(k,sizeof(k),"generals:season:%lld:world_height",sid);rc|=velocity_batch_put_ll(b,k,hh);snprintf(k,sizeof(k),"generals:season:%lld:world_chunk_size",sid);rc|=velocity_batch_put_ll(b,k,cs);snprintf(k,sizeof(k),"generals:season:%lld:world_tier_players",sid);rc|=velocity_batch_put_ll(b,k,players);snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,from);rc|=qrxdb_batch_put(b,k,"active");char season_clan[256]={0};generals_player_key(k,sizeof(k),from,"clan_id");if(generals_db_get(c,k,season_clan,sizeof(season_clan))!=0)season_clan[0]=0;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:clan_id",sid,from);rc|=qrxdb_batch_put(b,k,season_clan);if(season_clan[0]){char clk[1024],clv[512]={0};snprintf(clk,sizeof(clk),"generals:season:%lld:clan:%s:leader",sid,season_clan);if(generals_db_get(c,clk,clv,sizeof(clv))!=0||!*clv){snprintf(k,sizeof(k),"generals:clan:%s:leader",season_clan);if(generals_db_get(c,k,clv,sizeof(clv))==0&&*clv)rc|=qrxdb_batch_put(b,clk,clv);}}snprintf(k,sizeof(k),"generals:season:%lld:general:%s",sid,general);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:season:%lld:start_height",sid);rc|=velocity_batch_put_ll(b,k,ss);snprintf(k,sizeof(k),"generals:season:%lld:end_height",sid);rc|=velocity_batch_put_ll(b,k,se);snprintf(k,sizeof(k),"generals:season:%lld:last_join_tx",sid);rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"current_season_id");char sb[64];snprintf(sb,sizeof(sb),"%lld",sid);rc|=qrxdb_batch_put(b,k,sb);generals_player_key(k,sizeof(k),from,"season_join_height");rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:general:%s:season_id",general);rc|=qrxdb_batch_put(b,k,sb);rc|=generals_stage_spawn(b,c,from,general,sid,w,hh);long long eh=0,e=generals_energy_at(c,from,h,&eh);generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,e);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,eh);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:supply",sid,from);rc|=velocity_batch_put_ll(b,k,2000);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:fuel",sid,from);rc|=velocity_batch_put_ll(b,k,1000);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:ammo",sid,from);rc|=velocity_batch_put_ll(b,k,500);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:materials",sid,from);rc|=velocity_batch_put_ll(b,k,1500);return rc?-1:0;}
static int generals_stage_energy_spend(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){if(!generals_player_exists(c,from))return -1;char*sid_s=payload_get_field(p,"season_id"),*turn_s=payload_get_field(p,"turn_id"),*en_s=payload_get_field(p,"energy"),*action=payload_get_field(p,"action");if(!sid_s||!turn_s||!en_s){free(sid_s);free(turn_s);free(en_s);free(action);return -1;}long long sid=parse_positive_ll_strict(sid_s,"season_id"),ti=parse_positive_ll_strict(turn_s,"turn_id"),use=parse_positive_ll_strict(en_s,"energy"),cur=0,ss=0,se=0,turn=0,ts=0,te=0;free(sid_s);free(turn_s);free(en_s);if(generals_season_at(c,h,&cur,&ss,&se,&turn,&ts,&te)!=0||sid!=cur||ti!=turn){free(action);return -1;}char k[1024],v[64];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,from);if(generals_db_get(c,k,v,sizeof(v))!=0||strcmp(v,"active")){free(action);return -1;}long long base=0,e=generals_energy_at(c,from,h,&base);if(use>e){free(action);return -1;}int rc=0;generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,e-use);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,h);generals_player_key(k,sizeof(k),from,"last_energy_tx");rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"last_energy_action");rc|=qrxdb_batch_put(b,k,action&&*action?action:"UNSPECIFIED");generals_player_key(k,sizeof(k),from,"last_energy_turn");rc|=velocity_batch_put_ll(b,k,turn);free(action);return rc?-1:0;}

/* QRX Generals 0.0.7.7 Phase 4.1: deterministic logistics, production and infrastructure. */
typedef struct {const char*name;long long materials;long long defense;long long supply_radius;} GeneralsInfraClass;
static const GeneralsInfraClass GENERALS_INFRA[]={
 {"FACTORY",400,0,4},{"MISSILE_BASE",700,20,5},{"AIRFIELD",600,0,6},{"RADAR_STATION",500,15,12},{"SAM_SITE",550,25,8},{"PORT",500,20,8},{"NAVAL_YARD",800,30,10},{"RESEARCH_LAB",650,10,4},{"UNIVERSITY",900,15,5},{"ROAD",40,0,0},{"SUPPLY_DEPOT",250,0,8},{"FORTIFICATION",180,35,0},{NULL,0,0,0}};
static const GeneralsInfraClass*generals_infra_class(const char*t){for(int i=0;GENERALS_INFRA[i].name;i++)if(!strcmp(GENERALS_INFRA[i].name,t))return &GENERALS_INFRA[i];return NULL;}
static void generals_resource_key(char*out,size_t n,long long sid,const char*owner,const char*r){snprintf(out,n,"generals:season:%lld:player:%s:%s",sid,owner,r);}
static long long generals_resource(const char*c,long long sid,const char*owner,const char*r){char k[512];generals_resource_key(k,sizeof(k),sid,owner,r);return generals_db_ll(c,k,0);}
static int generals_stage_resource(QrxDBBatch*b,long long sid,const char*owner,const char*r,long long v){char k[512];generals_resource_key(k,sizeof(k),sid,owner,r);return velocity_batch_put_ll(b,k,v);}
static void generals_infra_tile_key(char*out,size_t n,const char*c,long long sid,long long x,long long y,const char*f){long long cs=generals_season_chunk_size(c,sid,0);snprintf(out,n,"generals:season:%lld:chunk:%lld:%lld:tile:%lld:%lld:infra_%s",sid,x/cs,y/cs,x%cs,y%cs,f);}
static int generals_stage_infra_build(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*ts=payload_get_field(p,"infra_type"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!ts||!xs||!ys)goto fail;const GeneralsInfraClass*ic=generals_infra_class(ts);if(!ic)goto fail;long long sid=0,ss=0,se=0,turn=0,a=0,z=0;if(generals_season_at(c,h,&sid,&ss,&se,&turn,&a,&z))goto fail;long long x=atoll(xs),y=atoll(ys),w=0,hh=0;generals_world_dims(c,sid,1,&w,&hh);if(x<0||y<0||x>=w||y>=hh||!strcmp(generals_terrain(sid,x,y),"WATER"))goto fail;char owner[256],k[512],v[256];if(generals_territory_owner(c,sid,x,y,owner,sizeof(owner))||strcmp(owner,from))goto fail;generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"type");if(generals_db_get(c,k,v,sizeof(v))==0&&*v)goto fail;long long mat=generals_resource(c,sid,from,"materials");if(mat<ic->materials)goto fail;char iid[40];snprintf(iid,sizeof(iid),"INFRA-%.22s",txid);int rc=0;generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"id");rc|=qrxdb_batch_put(b,k,iid);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"type");rc|=qrxdb_batch_put(b,k,ts);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"owner");rc|=qrxdb_batch_put(b,k,from);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"hp");rc|=velocity_batch_put_ll(b,k,100+ic->defense*5);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"built_turn");rc|=velocity_batch_put_ll(b,k,turn);rc|=generals_stage_resource(b,sid,from,"materials",mat-ic->materials);if(!strcmp(ts,"RESEARCH_LAB")||!strcmp(ts,"UNIVERSITY")){const char*rf=!strcmp(ts,"RESEARCH_LAB")?"research_labs":"universities";snprintf(k,sizeof(k),"generals:season:%lld:player:%s:%s",sid,from,rf);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+1);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_capacity",sid,from);long long add=!strcmp(ts,"RESEARCH_LAB")?5:10;rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+add);}free(ts);free(xs);free(ys);return rc?-1:0;fail:free(ts);free(xs);free(ys);return -1;}
static int generals_find_free_adjacent(const char*c,long long sid,long long x,long long y,long long*outx,long long*outy){static const int d[6][2]={{1,0},{1,-1},{0,-1},{-1,0},{-1,1},{0,1}};long long w=0,h=0;generals_world_dims(c,sid,1,&w,&h);char occ[256];for(int i=0;i<6;i++){long long nx=x+d[i][0],ny=y+d[i][1];if(nx<0||ny<0||nx>=w||ny>=h||!strcmp(generals_terrain(sid,nx,ny),"WATER"))continue;if(!generals_tile_occupied(c,sid,nx,ny,occ,sizeof(occ))){*outx=nx;*outy=ny;return 0;}}return -1;}
static int generals_stage_produce_unit(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*ut=payload_get_field(p,"unit_type"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!ut||!xs||!ys)goto fail;const GeneralsUnitClass*cl=generals_class(ut);if(!cl||!strcmp(ut,"HQ"))goto fail;long long sid=0,ss=0,se=0,turn=0,a=0,z=0;if(generals_season_at(c,h,&sid,&ss,&se,&turn,&a,&z))goto fail;long long x=atoll(xs),y=atoll(ys);char k[512],it[128],io[256];generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"type");if(generals_db_get(c,k,it,sizeof(it)))goto fail;generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"owner");if(generals_db_get(c,k,io,sizeof(io))||strcmp(io,from))goto fail;int air=!strcmp(ut,"HELICOPTER")||!strcmp(ut,"FIGHTER")||!strcmp(ut,"BOMBER")||!strcmp(ut,"TRANSPORT");if((air&&strcmp(it,"AIRFIELD"))||(!air&&strcmp(it,"FACTORY")&&strcmp(it,"MISSILE_BASE")))goto fail;if(!strcmp(it,"MISSILE_BASE")&&strcmp(ut,"MISSILE_BATTERY")&&strcmp(ut,"SAM")&&strcmp(ut,"MLRS"))goto fail;long long supply=generals_resource(c,sid,from,"supply"),fuel=generals_resource(c,sid,from,"fuel"),mat=generals_resource(c,sid,from,"materials");long long sc=40+cl->hp/2,fc=cl->move*8,mc=30+cl->attack*2;if(supply<sc||fuel<fc||mat<mc)goto fail;long long nx,ny;if(generals_find_free_adjacent(c,sid,x,y,&nx,&ny))goto fail;char general[256];generals_player_key(k,sizeof(k),from,"general_asset");if(generals_db_get(c,k,general,sizeof(general)))goto fail;char uid[40];snprintf(uid,sizeof(uid),"UNIT-%.24s",txid);int rc=generals_stage_unit(b,c,sid,from,general,uid,ut,nx,ny,cl->hp,cl->move,cl->move_energy);rc|=generals_stage_resource(b,sid,from,"supply",supply-sc);rc|=generals_stage_resource(b,sid,from,"fuel",fuel-fc);rc|=generals_stage_resource(b,sid,from,"materials",mat-mc);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,100);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,100);free(ut);free(xs);free(ys);return rc?-1:0;fail:free(ut);free(xs);free(ys);return -1;}
static int generals_stage_service_unit(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h,int repair){char*uid=payload_get_field(p,"unit_id");if(!uid)return -1;char owner[256],typ[128],k[512];if(generals_unit_field(c,uid,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))){free(uid);return -1;}const GeneralsUnitClass*cl=generals_class(typ);long long sid=generals_unit_ll(c,uid,"season_id",0),cur=0,a=0,z=0,t=0,bh=0,eh=0;if(!cl||generals_season_at(c,h,&cur,&a,&z,&t,&bh,&eh)||sid!=cur){free(uid);return -1;}long long x=generals_unit_ll(c,uid,"x",-1),y=generals_unit_ll(c,uid,"y",-1);char io[256],it[128];generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"owner");if(generals_db_get(c,k,io,sizeof(io))||strcmp(io,from)){free(uid);return -1;}generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"type");if(generals_db_get(c,k,it,sizeof(it))||strcmp(it,"SUPPLY_DEPOT")){free(uid);return -1;}int rc=0;if(repair){long long hp=generals_unit_ll(c,uid,"hp",0),need=cl->hp-hp,mat=generals_resource(c,sid,from,"materials");if(need<=0||mat<need){free(uid);return -1;}snprintf(k,sizeof(k),"generals:unit:%s:hp",uid);rc|=velocity_batch_put_ll(b,k,cl->hp);rc|=generals_stage_resource(b,sid,from,"materials",mat-need);}else{long long ammo=generals_resource(c,sid,from,"ammo"),fuel=generals_resource(c,sid,from,"fuel");if(ammo<100||fuel<50){free(uid);return -1;}snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,100);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,100);rc|=generals_stage_resource(b,sid,from,"ammo",ammo-100);rc|=generals_stage_resource(b,sid,from,"fuel",fuel-50);}free(uid);return rc?-1:0;}
static int generals_stage_supply_transfer(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h){char*to=payload_get_field(p,"to"),*rs=payload_get_field(p,"resource"),*as=payload_get_field(p,"amount");if(!to||!rs||!as)goto fail;long long amt=atoll(as);if(amt<=0||(!strcmp(rs,"supply")+!strcmp(rs,"fuel")+!strcmp(rs,"ammo")+!strcmp(rs,"materials"))!=1)goto fail;long long sid=0,a=0,z=0,t=0,bh=0,eh=0;if(generals_season_at(c,h,&sid,&a,&z,&t,&bh,&eh))goto fail;char k[512],v[64];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,to);if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"active"))goto fail;long long src=generals_resource(c,sid,from,rs),dst=generals_resource(c,sid,to,rs);if(src<amt||dst>LLONG_MAX-amt)goto fail;int rc=generals_stage_resource(b,sid,from,rs,src-amt)|generals_stage_resource(b,sid,to,rs,dst+amt);free(to);free(rs);free(as);return rc?-1:0;fail:free(to);free(rs);free(as);return -1;}
/* Phase 4.2: road-linked supply and infrastructure warfare. */
static int generals_infra_get(const char*c,long long sid,long long x,long long y,const char*f,char*out,size_t n){char k[512];generals_infra_tile_key(k,sizeof(k),c,sid,x,y,f);return generals_db_get(c,k,out,n);}
static int generals_supply_node(const char*c,long long sid,const char*owner,long long x,long long y){char t[64],o[256],hp[64];if(generals_infra_get(c,sid,x,y,"type",t,sizeof(t))||generals_infra_get(c,sid,x,y,"owner",o,sizeof(o))||strcmp(o,owner))return 0;if(generals_infra_get(c,sid,x,y,"hp",hp,sizeof(hp))==0&&atoll(hp)<=0)return 0;return !strcmp(t,"ROAD")||!strcmp(t,"SUPPLY_DEPOT")||!strcmp(t,"FACTORY")||!strcmp(t,"AIRFIELD")||!strcmp(t,"MISSILE_BASE");}
static int generals_supply_connected(const char*c,long long sid,const char*owner,long long sx,long long sy,long long tx,long long ty){/* bounded deterministic BFS; routes are mutable-state only */enum{MAXQ=8192};typedef struct{long long x,y;}N;N*q=calloc(MAXQ,sizeof(N));if(!q)return 0;int head=0,tail=0;q[tail++]=(N){sx,sy};static const int d[6][2]={{1,0},{1,-1},{0,-1},{-1,0},{-1,1},{0,1}};int ok=0;while(head<tail&&tail<MAXQ){N n=q[head++];if(generals_hex_distance(n.x,n.y,tx,ty)<=1){ok=1;break;}for(int i=0;i<6&&tail<MAXQ;i++){long long x=n.x+d[i][0],y=n.y+d[i][1];if(!generals_supply_node(c,sid,owner,x,y))continue;int seen=0;for(int j=0;j<tail;j++)if(q[j].x==x&&q[j].y==y){seen=1;break;}if(!seen)q[tail++]=(N){x,y};}}free(q);return ok;}
static int generals_stage_infra_attack(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!uid||!xs||!ys)goto fail;char uo[256],ut[128],io[256],it[128],k[512];if(generals_unit_field(c,uid,"owner",uo,sizeof(uo))||strcmp(uo,from)||generals_unit_field(c,uid,"type",ut,sizeof(ut)))goto fail;const GeneralsUnitClass*cl=generals_class(ut);if(!cl||cl->attack<1)goto fail;long long ammo=generals_unit_ll(c,uid,"ammo",100);long long ammo_cost=cl->attack>=100?4:(cl->attack>=70?3:2);if(ammo<ammo_cost)goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),x=atoll(xs),y=atoll(ys),ux=generals_unit_ll(c,uid,"x",-1),uy=generals_unit_ll(c,uid,"y",-1),dist=generals_hex_distance(ux,uy,x,y);if(dist<cl->min_range||dist>cl->max_range)goto fail;if(generals_infra_get(c,sid,x,y,"owner",io,sizeof(io))||!strcmp(io,from)||generals_infra_get(c,sid,x,y,"type",it,sizeof(it)))goto fail;generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"hp");long long hp=generals_db_ll(c,k,0);if(hp<=0)goto fail;const GeneralsInfraClass*ic=generals_infra_class(it);long long dmg=(cl->attack*100)/(100+(ic?ic->defense:0));if(dmg<1)dmg=1;long long nh=hp>dmg?hp-dmg:0;int rc=velocity_batch_put_ll(b,k,nh);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,ammo-ammo_cost);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"last_attack_tx");rc|=qrxdb_batch_put(b,k,txid);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"status");rc|=qrxdb_batch_put(b,k,nh?"damaged":"destroyed");if(!nh){generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"destroyed_height");rc|=velocity_batch_put_ll(b,k,h);if(!strcmp(it,"RESEARCH_LAB")||!strcmp(it,"UNIVERSITY")){const char*rf=!strcmp(it,"RESEARCH_LAB")?"research_labs":"universities";snprintf(k,sizeof(k),"generals:season:%lld:player:%s:%s",sid,io,rf);long long n=generals_db_ll(c,k,0);rc|=velocity_batch_put_ll(b,k,n>0?n-1:0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_capacity",sid,io);long long cap=generals_db_ll(c,k,0),sub=!strcmp(it,"RESEARCH_LAB")?5:10;rc|=velocity_batch_put_ll(b,k,cap>sub?cap-sub:0);}}free(uid);free(xs);free(ys);return rc?-1:0;fail:free(uid);free(xs);free(ys);return -1;}
static int generals_stage_road_repair(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h){(void)h;char*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!xs||!ys)goto fail;long long sid=0,a=0,z=0,t=0,bh=0,eh=0;if(generals_season_at(c,h,&sid,&a,&z,&t,&bh,&eh))goto fail;long long x=atoll(xs),y=atoll(ys);char typ[64],own[256],k[512];if(generals_infra_get(c,sid,x,y,"type",typ,sizeof(typ))||strcmp(typ,"ROAD")||generals_infra_get(c,sid,x,y,"owner",own,sizeof(own))||strcmp(own,from))goto fail;generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"hp");long long hp=generals_db_ll(c,k,0),maxhp=100;if(hp>=maxhp)goto fail;long long need=maxhp-hp,mat=generals_resource(c,sid,from,"materials");if(mat<need)goto fail;int rc=velocity_batch_put_ll(b,k,maxhp)|generals_stage_resource(b,sid,from,"materials",mat-need);generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"status");rc|=qrxdb_batch_put(b,k,"active");free(xs);free(ys);return rc?-1:0;fail:free(xs);free(ys);return -1;}
static int generals_supply_line_info_cmd(const char*c,const char*owner,long long sid,long long sx,long long sy,long long tx,long long ty){int ok=generals_supply_connected(c,sid,owner,sx,sy,tx,ty);printf("season_id=%lld\nowner=%s\nsource=%lld,%lld\ntarget=%lld,%lld\nconnected=%d\n",sid,owner,sx,sy,tx,ty,ok);return ok?0:2;}
static int generals_logistics_info_cmd(const char*c,const char*addr,long long sid){printf("season_id=%lld\nsupply=%lld\nfuel=%lld\nammo=%lld\nmaterials=%lld\n",sid,generals_resource(c,sid,addr,"supply"),generals_resource(c,sid,addr,"fuel"),generals_resource(c,sid,addr,"ammo"),generals_resource(c,sid,addr,"materials"));return 0;}
static int generals_infra_info_cmd(const char*c,long long sid,long long x,long long y){char k[512],v[256];printf("season_id=%lld\nx=%lld\ny=%lld\n",sid,x,y);const char*fs[]={"id","type","owner","hp","built_turn","status","last_attack_tx","destroyed_height",NULL};for(int i=0;fs[i];i++){generals_infra_tile_key(k,sizeof(k),c,sid,x,y,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}

/* Phase 4.3: operational fuel/ammunition, resupply and encirclement. */
static int generals_unit_supply_status(const char*c,const char*uid,char*out,size_t n){char owner[256];if(generals_unit_field(c,uid,"owner",owner,sizeof(owner)))return -1;long long sid=generals_unit_ll(c,uid,"season_id",0),ux=generals_unit_ll(c,uid,"x",-1),uy=generals_unit_ll(c,uid,"y",-1);char k[512],hq[128];snprintf(k,sizeof(k),"generals:season:%lld:player:%s:hq_unit",sid,owner);if(generals_db_get(c,k,hq,sizeof(hq))){snprintf(out,n,"ISOLATED");return 0;}long long hx=generals_unit_ll(c,hq,"x",-1),hy=generals_unit_ll(c,hq,"y",-1);int linked=generals_supply_connected(c,sid,owner,hx,hy,ux,uy);long long fuel=generals_unit_ll(c,uid,"fuel",0),ammo=generals_unit_ll(c,uid,"ammo",0);if(!linked)snprintf(out,n,"ISOLATED");else if(fuel<=0)snprintf(out,n,"OUT_OF_FUEL");else if(ammo<=0)snprintf(out,n,"OUT_OF_AMMO");else if(fuel<25||ammo<25)snprintf(out,n,"LOW_SUPPLY");else snprintf(out,n,"SUPPLIED");return 0;}
static int generals_stage_unit_resupply(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h){(void)h;char*uid=payload_get_field(p,"unit_id");if(!uid)return -1;char owner[256],status[64],k[512];if(generals_unit_field(c,uid,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_supply_status(c,uid,status,sizeof(status))||!strcmp(status,"ISOLATED")){free(uid);return -1;}long long sid=generals_unit_ll(c,uid,"season_id",0),fuel=generals_unit_ll(c,uid,"fuel",0),ammo=generals_unit_ll(c,uid,"ammo",0);long long needf=100-fuel,needa=100-ammo;if(needf<0)needf=0;if(needa<0)needa=0;long long pf=generals_resource(c,sid,from,"fuel"),pa=generals_resource(c,sid,from,"ammo");long long takef=needf<pf?needf:pf,takea=needa<pa?needa:pa;if(takef+takea<=0){free(uid);return -1;}int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,fuel+takef);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,ammo+takea);rc|=generals_stage_resource(b,sid,from,"fuel",pf-takef);rc|=generals_stage_resource(b,sid,from,"ammo",pa-takea);snprintf(k,sizeof(k),"generals:unit:%s:last_resupply_height",uid);rc|=velocity_batch_put_ll(b,k,h);free(uid);return rc?-1:0;}
static int generals_unit_logistics_info_cmd(const char*c,const char*uid){char status[64];if(generals_unit_supply_status(c,uid,status,sizeof(status)))die("Generals unit not found");printf("unit_id=%s\nsupply_status=%s\nfuel=%lld\nammo=%lld\n",uid,status,generals_unit_ll(c,uid,"fuel",0),generals_unit_ll(c,uid,"ammo",0));return 0;}

/* QRX Generals 0.0.7.7 Phase 4.5: air power, radar, SAM and strategic missile warfare. */
static int generals_is_air_type(const char*t){return t&&(!strcmp(t,"FIGHTER")||!strcmp(t,"BOMBER")||!strcmp(t,"HELICOPTER")||!strcmp(t,"TRANSPORT"));}
static void generals_mission_key(char*out,size_t n,const char*mid,const char*f){snprintf(out,n,"generals:mission:%s:%s",mid,f);}
static int generals_stage_air_mission(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"target_x"),*ys=payload_get_field(p,"target_y"),*kind=payload_get_field(p,"mission");if(!uid||!xs||!ys||!kind)goto fail;char owner[256],typ[64],k[512];if(generals_unit_field(c,uid,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||!generals_is_air_type(typ))goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),x=atoll(xs),y=atoll(ys),ux=generals_unit_ll(c,uid,"x",-1),uy=generals_unit_ll(c,uid,"y",-1),dist=generals_hex_distance(ux,uy,x,y),fuel=generals_unit_ll(c,uid,"fuel",100),fc=dist<1?1:dist;if(fuel<fc)goto fail;char mid[40];snprintf(mid,sizeof(mid),"AIR-%.24s",txid);int rc=0;generals_mission_key(k,sizeof(k),mid,"type");rc|=qrxdb_batch_put(b,k,"AIR");generals_mission_key(k,sizeof(k),mid,"status");rc|=qrxdb_batch_put(b,k,"in_flight");generals_mission_key(k,sizeof(k),mid,"owner");rc|=qrxdb_batch_put(b,k,from);generals_mission_key(k,sizeof(k),mid,"unit_id");rc|=qrxdb_batch_put(b,k,uid);generals_mission_key(k,sizeof(k),mid,"mission");rc|=qrxdb_batch_put(b,k,kind);generals_mission_key(k,sizeof(k),mid,"season_id");rc|=velocity_batch_put_ll(b,k,sid);generals_mission_key(k,sizeof(k),mid,"target_x");rc|=velocity_batch_put_ll(b,k,x);generals_mission_key(k,sizeof(k),mid,"target_y");rc|=velocity_batch_put_ll(b,k,y);generals_mission_key(k,sizeof(k),mid,"launch_height");rc|=velocity_batch_put_ll(b,k,h);generals_mission_key(k,sizeof(k),mid,"resolve_height");rc|=velocity_batch_put_ll(b,k,h+(dist/8)+1);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,fuel-fc);free(uid);free(xs);free(ys);free(kind);return rc?-1:0;fail:free(uid);free(xs);free(ys);free(kind);return -1;}
static int generals_stage_radar_scan(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y"),*target=payload_get_field(p,"target_unit_id");if(!xs||!ys||!target)goto fail;long long x=atoll(xs),y=atoll(ys),sid=generals_unit_ll(c,target,"season_id",0),tx=generals_unit_ll(c,target,"x",-1),ty=generals_unit_ll(c,target,"y",-1);char io[256],it[64],k[512];if(generals_infra_get(c,sid,x,y,"owner",io,sizeof(io))||strcmp(io,from)||generals_infra_get(c,sid,x,y,"type",it,sizeof(it))||strcmp(it,"RADAR_STATION"))goto fail;if(generals_hex_distance(x,y,tx,ty)>12)goto fail;long long ttl=qrx_chain_get_ll_at_height_or_default(c,h,"generals_radar_contact_ttl_blocks",180);int rc=0;snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:expires_height",sid,from,target);rc|=velocity_batch_put_ll(b,k,h+ttl);snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_height",sid,from,target);rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_x",sid,from,target);rc|=velocity_batch_put_ll(b,k,tx);snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:last_seen_y",sid,from,target);rc|=velocity_batch_put_ll(b,k,ty);snprintf(k,sizeof(k),"generals:contact:%lld:%s:%s:scan_tx",sid,from,target);rc|=qrxdb_batch_put(b,k,txid);free(xs);free(ys);free(target);return rc?-1:0;fail:free(xs);free(ys);free(target);return -1;}
static int generals_stage_missile_launch(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*target=payload_get_field(p,"target_unit_id");if(!uid||!target)goto fail;char owner[256],typ[64],to[256],k[512];if(generals_unit_field(c,uid,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||strcmp(typ,"MISSILE_BATTERY")||generals_unit_field(c,target,"owner",to,sizeof(to))||!strcmp(to,from)||!generals_contact_visible(c,from,target,h))goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),dist=generals_hex_distance(generals_unit_ll(c,uid,"x",-1),generals_unit_ll(c,uid,"y",-1),generals_unit_ll(c,target,"x",-1),generals_unit_ll(c,target,"y",-1)),ammo=generals_unit_ll(c,uid,"ammo",100);if(dist<3||dist>256||ammo<8)goto fail;char mid[40];snprintf(mid,sizeof(mid),"MSL-%.24s",txid);int rc=0;generals_mission_key(k,sizeof(k),mid,"type");rc|=qrxdb_batch_put(b,k,"MISSILE");generals_mission_key(k,sizeof(k),mid,"status");rc|=qrxdb_batch_put(b,k,"in_flight");generals_mission_key(k,sizeof(k),mid,"owner");rc|=qrxdb_batch_put(b,k,from);generals_mission_key(k,sizeof(k),mid,"unit_id");rc|=qrxdb_batch_put(b,k,uid);generals_mission_key(k,sizeof(k),mid,"target_unit_id");rc|=qrxdb_batch_put(b,k,target);generals_mission_key(k,sizeof(k),mid,"season_id");rc|=velocity_batch_put_ll(b,k,sid);generals_mission_key(k,sizeof(k),mid,"launch_height");rc|=velocity_batch_put_ll(b,k,h);generals_mission_key(k,sizeof(k),mid,"resolve_height");rc|=velocity_batch_put_ll(b,k,h+(dist/16)+1);generals_mission_key(k,sizeof(k),mid,"damage");rc|=velocity_batch_put_ll(b,k,150);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,ammo-8);free(uid);free(target);return rc?-1:0;fail:free(uid);free(target);return -1;}
static int generals_stage_sam_intercept(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*mid=payload_get_field(p,"mission_id"),*uid=payload_get_field(p,"unit_id");if(!mid||!uid)goto fail;char st[64],mo[256],uo[256],ut[64],k[512];generals_mission_key(k,sizeof(k),mid,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"in_flight"))goto fail;generals_mission_key(k,sizeof(k),mid,"owner");if(generals_db_get(c,k,mo,sizeof(mo))||!strcmp(mo,from)||generals_unit_field(c,uid,"owner",uo,sizeof(uo))||strcmp(uo,from)||generals_unit_field(c,uid,"type",ut,sizeof(ut))||strcmp(ut,"SAM"))goto fail;long long ammo=generals_unit_ll(c,uid,"ammo",100);if(ammo<3)goto fail;generals_mission_key(k,sizeof(k),mid,"status");int rc=qrxdb_batch_put(b,k,"intercepted");generals_mission_key(k,sizeof(k),mid,"intercept_tx");rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,ammo-3);free(mid);free(uid);return rc?-1:0;fail:free(mid);free(uid);return -1;}
static int generals_stage_strike_resolve(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){(void)from;char*mid=payload_get_field(p,"mission_id");if(!mid)return -1;char st[64],type[64],target[128],k[512];generals_mission_key(k,sizeof(k),mid,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"in_flight"))goto fail;generals_mission_key(k,sizeof(k),mid,"resolve_height");if(h<generals_db_ll(c,k,LLONG_MAX))goto fail;generals_mission_key(k,sizeof(k),mid,"type");if(generals_db_get(c,k,type,sizeof(type)))goto fail;int rc=0;if(!strcmp(type,"MISSILE")){generals_mission_key(k,sizeof(k),mid,"target_unit_id");if(generals_db_get(c,k,target,sizeof(target)))goto fail;long long hp=generals_unit_ll(c,target,"hp",0);generals_mission_key(k,sizeof(k),mid,"damage");long long dmg=generals_db_ll(c,k,0),nh=hp>dmg?hp-dmg:0;snprintf(k,sizeof(k),"generals:unit:%s:hp",target);rc|=velocity_batch_put_ll(b,k,nh);if(!nh){snprintf(k,sizeof(k),"generals:unit:%s:status",target);rc|=qrxdb_batch_put(b,k,"destroyed");}}generals_mission_key(k,sizeof(k),mid,"status");rc|=qrxdb_batch_put(b,k,"resolved");generals_mission_key(k,sizeof(k),mid,"resolve_tx");rc|=qrxdb_batch_put(b,k,txid);free(mid);return rc?-1:0;fail:free(mid);return -1;}
static int generals_mission_info_cmd(const char*c,const char*mid){char k[512],v[512];printf("mission_id=%s\n",mid);const char*fs[]={"type","status","owner","unit_id","mission","target_unit_id","season_id","target_x","target_y","launch_height","resolve_height","damage","intercept_tx","resolve_tx",NULL};for(int i=0;fs[i];i++){generals_mission_key(k,sizeof(k),mid,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}


/* QRX Generals 0.0.7.7 Phase 4.6: deterministic air superiority. */
static long long generals_air_strength(const char*c,const char*uid){char typ[64];if(generals_unit_field(c,uid,"type",typ,sizeof(typ)))return 0;const GeneralsUnitClass*cl=generals_class(typ);return cl?cl->attack+cl->defense+cl->vision:0;}
static int generals_stage_cap_mission(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y"),*rs=payload_get_field(p,"radius");if(!uid||!xs||!ys)goto fail;char o[256],typ[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||strcmp(typ,"FIGHTER"))goto fail;long long x=atoll(xs),y=atoll(ys),r=rs?atoll(rs):6;if(r<1||r>12)goto fail;char mid[40];snprintf(mid,sizeof(mid),"CAP-%.24s",txid);int rc=0;generals_mission_key(k,sizeof(k),mid,"type");rc|=qrxdb_batch_put(b,k,"CAP");generals_mission_key(k,sizeof(k),mid,"status");rc|=qrxdb_batch_put(b,k,"active");generals_mission_key(k,sizeof(k),mid,"owner");rc|=qrxdb_batch_put(b,k,from);generals_mission_key(k,sizeof(k),mid,"unit_id");rc|=qrxdb_batch_put(b,k,uid);generals_mission_key(k,sizeof(k),mid,"target_x");rc|=velocity_batch_put_ll(b,k,x);generals_mission_key(k,sizeof(k),mid,"target_y");rc|=velocity_batch_put_ll(b,k,y);generals_mission_key(k,sizeof(k),mid,"radius");rc|=velocity_batch_put_ll(b,k,r);generals_mission_key(k,sizeof(k),mid,"launch_height");rc|=velocity_batch_put_ll(b,k,h);generals_mission_key(k,sizeof(k),mid,"resolve_height");rc|=velocity_batch_put_ll(b,k,h+60);free(uid);free(xs);free(ys);free(rs);return rc?-1:0;fail:free(uid);free(xs);free(ys);free(rs);return -1;}
static int generals_stage_escort_mission(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*mid=payload_get_field(p,"mission_id");if(!uid||!mid)goto fail;char o[256],typ[64],mo[256],st[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||strcmp(typ,"FIGHTER"))goto fail;generals_mission_key(k,sizeof(k),mid,"owner");if(generals_db_get(c,k,mo,sizeof(mo))||strcmp(mo,from))goto fail;generals_mission_key(k,sizeof(k),mid,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"in_flight"))goto fail;generals_mission_key(k,sizeof(k),mid,"escort_unit_id");int rc=qrxdb_batch_put(b,k,uid);generals_mission_key(k,sizeof(k),mid,"escort_tx");rc|=qrxdb_batch_put(b,k,txid);free(uid);free(mid);return rc?-1:0;fail:free(uid);free(mid);return -1;}
static int generals_stage_air_intercept(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*mid=payload_get_field(p,"mission_id");if(!uid||!mid)goto fail;char o[256],typ[64],mo[256],st[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||strcmp(typ,"FIGHTER"))goto fail;generals_mission_key(k,sizeof(k),mid,"owner");if(generals_db_get(c,k,mo,sizeof(mo))||!strcmp(mo,from))goto fail;generals_mission_key(k,sizeof(k),mid,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"in_flight"))goto fail;long long fuel=generals_unit_ll(c,uid,"fuel",100),ammo=generals_unit_ll(c,uid,"ammo",100);if(fuel<4||ammo<2)goto fail;generals_mission_key(k,sizeof(k),mid,"interceptor_unit_id");int rc=qrxdb_batch_put(b,k,uid);generals_mission_key(k,sizeof(k),mid,"intercept_status");rc|=qrxdb_batch_put(b,k,"engaged");generals_mission_key(k,sizeof(k),mid,"intercept_tx");rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,fuel-4);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,ammo-2);free(uid);free(mid);return rc?-1:0;fail:free(uid);free(mid);return -1;}
static int generals_stage_air_combat_resolve(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){(void)from;char*mid=payload_get_field(p,"mission_id");if(!mid)return -1;char st[64],iid[128],aid[128],eid[128],k[512];generals_mission_key(k,sizeof(k),mid,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"in_flight"))goto fail;generals_mission_key(k,sizeof(k),mid,"interceptor_unit_id");if(generals_db_get(c,k,iid,sizeof(iid)))goto fail;generals_mission_key(k,sizeof(k),mid,"unit_id");if(generals_db_get(c,k,aid,sizeof(aid)))goto fail;generals_mission_key(k,sizeof(k),mid,"escort_unit_id");int has_escort=!generals_db_get(c,k,eid,sizeof(eid));long long atk=generals_air_strength(c,aid)+(has_escort?generals_air_strength(c,eid):0),def=generals_air_strength(c,iid);/* deterministic: no block-order RNG */int rc=0;generals_mission_key(k,sizeof(k),mid,"air_combat_tx");rc|=qrxdb_batch_put(b,k,txid);generals_mission_key(k,sizeof(k),mid,"air_combat_attack_strength");rc|=velocity_batch_put_ll(b,k,atk);generals_mission_key(k,sizeof(k),mid,"air_combat_defense_strength");rc|=velocity_batch_put_ll(b,k,def);if(def>=atk){generals_mission_key(k,sizeof(k),mid,"status");rc|=qrxdb_batch_put(b,k,"intercepted");generals_mission_key(k,sizeof(k),mid,"air_combat_result");rc|=qrxdb_batch_put(b,k,"defender_wins");}else{generals_mission_key(k,sizeof(k),mid,"intercept_status");rc|=qrxdb_batch_put(b,k,"repelled");generals_mission_key(k,sizeof(k),mid,"air_combat_result");rc|=qrxdb_batch_put(b,k,"attacker_breakthrough");}free(mid);return rc?-1:0;fail:free(mid);return -1;}


/* QRX Generals 0.0.7.7 Phase 4.7: advanced air operations.  Formations are
 * consensus objects; members remain normal units.  CAP auto-intercept is
 * explicit/signed (not a background server action). */
static int generals_stage_air_formation(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*members=payload_get_field(p,"members");if(!members)return -1;char*tmp=strdup(members),*save=NULL,*u=strtok_r(tmp,",",&save);int n=0,rc=0;char fid[40],k[512],o[256],typ[64];snprintf(fid,sizeof(fid),"FORM-%.23s",txid);while(u){if(++n>8||generals_unit_field(c,u,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,u,"type",typ,sizeof(typ))||(strcmp(typ,"FIGHTER")&&strcmp(typ,"BOMBER")&&strcmp(typ,"HELICOPTER")&&strcmp(typ,"TRANSPORT"))){free(tmp);return -1;}snprintf(k,sizeof(k),"generals:formation:%s:unit:%d",fid,n-1);rc|=qrxdb_batch_put(b,k,u);u=strtok_r(NULL,",",&save);}if(n<2){free(tmp);return -1;}snprintf(k,sizeof(k),"generals:formation:%s:owner",fid);rc|=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:formation:%s:unit_count",fid);rc|=velocity_batch_put_ll(b,k,n);snprintf(k,sizeof(k),"generals:formation:%s:status",fid);rc|=qrxdb_batch_put(b,k,"ready");snprintf(k,sizeof(k),"generals:formation:%s:created_height",fid);rc|=velocity_batch_put_ll(b,k,h);free(tmp);return rc?-1:0;}
static int generals_stage_cap_auto_intercept(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*cap=payload_get_field(p,"cap_id"),*mid=payload_get_field(p,"mission_id");if(!cap||!mid)goto fail;char k[512],co[256],cu[128],mo[256],st[64];generals_mission_key(k,sizeof(k),cap,"owner");if(generals_db_get(c,k,co,sizeof(co))||strcmp(co,from))goto fail;generals_mission_key(k,sizeof(k),cap,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"active"))goto fail;generals_mission_key(k,sizeof(k),cap,"resolve_height");if(generals_db_ll(c,k,0)<h)goto fail;generals_mission_key(k,sizeof(k),mid,"owner");if(generals_db_get(c,k,mo,sizeof(mo))||!strcmp(mo,from))goto fail;generals_mission_key(k,sizeof(k),mid,"status");if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"in_flight"))goto fail;generals_mission_key(k,sizeof(k),cap,"unit_id");if(generals_db_get(c,k,cu,sizeof(cu)))goto fail;long long cx,cy,r,tx,ty;generals_mission_key(k,sizeof(k),cap,"target_x");cx=generals_db_ll(c,k,-1);generals_mission_key(k,sizeof(k),cap,"target_y");cy=generals_db_ll(c,k,-1);generals_mission_key(k,sizeof(k),cap,"radius");r=generals_db_ll(c,k,0);generals_mission_key(k,sizeof(k),mid,"target_x");tx=generals_db_ll(c,k,-999);generals_mission_key(k,sizeof(k),mid,"target_y");ty=generals_db_ll(c,k,-999);if(generals_hex_distance(cx,cy,tx,ty)>r)goto fail;long long fuel=generals_unit_ll(c,cu,"fuel",100),ammo=generals_unit_ll(c,cu,"ammo",100);if(fuel<3||ammo<2)goto fail;generals_mission_key(k,sizeof(k),mid,"interceptor_unit_id");int rc=qrxdb_batch_put(b,k,cu);generals_mission_key(k,sizeof(k),mid,"intercept_status");rc|=qrxdb_batch_put(b,k,"cap_engaged");generals_mission_key(k,sizeof(k),mid,"intercept_tx");rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:unit:%s:fuel",cu);rc|=velocity_batch_put_ll(b,k,fuel-3);snprintf(k,sizeof(k),"generals:unit:%s:ammo",cu);rc|=velocity_batch_put_ll(b,k,ammo-2);free(cap);free(mid);return rc?-1:0;fail:free(cap);free(mid);return -1;}
static int generals_stage_air_rtb(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id");if(!uid)return -1;char o[256],typ[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||(strcmp(typ,"FIGHTER")&&strcmp(typ,"BOMBER")&&strcmp(typ,"HELICOPTER")&&strcmp(typ,"TRANSPORT"))){free(uid);return -1;}int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:air_status",uid);rc|=qrxdb_batch_put(b,k,"rtb");snprintf(k,sizeof(k),"generals:unit:%s:rtb_height",uid);rc|=velocity_batch_put_ll(b,k,h);snprintf(k,sizeof(k),"generals:unit:%s:rtb_tx",uid);rc|=qrxdb_batch_put(b,k,txid);free(uid);return rc?-1:0;}
static int generals_stage_sead(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!uid||!xs||!ys)goto fail;char o[256],typ[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||(strcmp(typ,"FIGHTER")&&strcmp(typ,"BOMBER")))goto fail;long long fuel=generals_unit_ll(c,uid,"fuel",100),ammo=generals_unit_ll(c,uid,"ammo",100);if(fuel<6||ammo<4)goto fail;char mid[40];snprintf(mid,sizeof(mid),"SEAD-%.22s",txid);int rc=0;generals_mission_key(k,sizeof(k),mid,"type");rc|=qrxdb_batch_put(b,k,"SEAD");generals_mission_key(k,sizeof(k),mid,"status");rc|=qrxdb_batch_put(b,k,"in_flight");generals_mission_key(k,sizeof(k),mid,"owner");rc|=qrxdb_batch_put(b,k,from);generals_mission_key(k,sizeof(k),mid,"unit_id");rc|=qrxdb_batch_put(b,k,uid);generals_mission_key(k,sizeof(k),mid,"target_x");rc|=velocity_batch_put_ll(b,k,atoll(xs));generals_mission_key(k,sizeof(k),mid,"target_y");rc|=velocity_batch_put_ll(b,k,atoll(ys));generals_mission_key(k,sizeof(k),mid,"launch_height");rc|=velocity_batch_put_ll(b,k,h);generals_mission_key(k,sizeof(k),mid,"resolve_height");rc|=velocity_batch_put_ll(b,k,h+12);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,fuel-6);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,ammo-4);free(uid);free(xs);free(ys);return rc?-1:0;fail:free(uid);free(xs);free(ys);return -1;}

/* Phase 4.8: deterministic naval warfare / amphibious transport. */
static int generals_is_naval_type(const char*t){return t&&(!strcmp(t,"PATROL_BOAT")||!strcmp(t,"DESTROYER")||!strcmp(t,"FRIGATE")||!strcmp(t,"CRUISER")||!strcmp(t,"AMPHIBIOUS_TRANSPORT")||!strcmp(t,"SUPPLY_SHIP")||!strcmp(t,"CARRIER"));}
static int generals_stage_naval_move(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){(void)txid;char*uid=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"to_x"),*ys=payload_get_field(p,"to_y");if(!uid||!xs||!ys)goto fail;char o[256],typ[64],k[512],occ[256];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",typ,sizeof(typ))||!generals_is_naval_type(typ))goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),x=atoll(xs),y=atoll(ys),ox=generals_unit_ll(c,uid,"x",-1),oy=generals_unit_ll(c,uid,"y",-1),fuel=generals_unit_ll(c,uid,"fuel",100);if(!generals_hex_adjacent(ox,oy,x,y)||strcmp(generals_terrain(sid,x,y),"WATER")||generals_tile_occupied(c,sid,x,y,occ,sizeof(occ))||fuel<2)goto fail;int rc=0;generals_tile_key(k,sizeof(k),c,sid,ox,oy,h);rc|=qrxdb_batch_put(b,k,"");generals_tile_key(k,sizeof(k),c,sid,x,y,h);rc|=qrxdb_batch_put(b,k,uid);snprintf(k,sizeof(k),"generals:unit:%s:x",uid);rc|=velocity_batch_put_ll(b,k,x);snprintf(k,sizeof(k),"generals:unit:%s:y",uid);rc|=velocity_batch_put_ll(b,k,y);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,fuel-2);free(uid);free(xs);free(ys);return rc?-1:0;fail:free(uid);free(xs);free(ys);return -1;}
static int generals_stage_amphibious_load(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h){char*ship=payload_get_field(p,"transport_unit_id"),*unit=payload_get_field(p,"unit_id");if(!ship||!unit)goto fail;char so[256],st[64],uo[256],ut[64],k[512],ex[128];if(generals_unit_field(c,ship,"owner",so,sizeof(so))||strcmp(so,from)||generals_unit_field(c,ship,"type",st,sizeof(st))||strcmp(st,"AMPHIBIOUS_TRANSPORT")||generals_unit_field(c,unit,"owner",uo,sizeof(uo))||strcmp(uo,from)||generals_unit_field(c,unit,"type",ut,sizeof(ut))||generals_is_naval_type(ut))goto fail;long long sx=generals_unit_ll(c,ship,"x",-1),sy=generals_unit_ll(c,ship,"y",-1),ux=generals_unit_ll(c,unit,"x",-1),uy=generals_unit_ll(c,unit,"y",-1),sid=generals_unit_ll(c,unit,"season_id",0);if(generals_hex_distance(sx,sy,ux,uy)>1)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:cargo_unit",ship);if(!generals_db_get(c,k,ex,sizeof(ex))&&*ex)goto fail;int rc=qrxdb_batch_put(b,k,unit);snprintf(k,sizeof(k),"generals:unit:%s:embarked_on",unit);rc|=qrxdb_batch_put(b,k,ship);snprintf(k,sizeof(k),"generals:unit:%s:status",unit);rc|=qrxdb_batch_put(b,k,"embarked");generals_tile_key(k,sizeof(k),c,sid,ux,uy,h);rc|=qrxdb_batch_put(b,k,"");free(ship);free(unit);return rc?-1:0;fail:free(ship);free(unit);return -1;}
static int generals_stage_amphibious_land(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h){char*ship=payload_get_field(p,"transport_unit_id"),*xs=payload_get_field(p,"to_x"),*ys=payload_get_field(p,"to_y");if(!ship||!xs||!ys)goto fail;char so[256],st[64],unit[128],k[512],occ[256];if(generals_unit_field(c,ship,"owner",so,sizeof(so))||strcmp(so,from)||generals_unit_field(c,ship,"type",st,sizeof(st))||strcmp(st,"AMPHIBIOUS_TRANSPORT"))goto fail;snprintf(k,sizeof(k),"generals:unit:%s:cargo_unit",ship);if(generals_db_get(c,k,unit,sizeof(unit)))goto fail;long long sid=generals_unit_ll(c,ship,"season_id",0),x=atoll(xs),y=atoll(ys),sx=generals_unit_ll(c,ship,"x",-1),sy=generals_unit_ll(c,ship,"y",-1);if(generals_hex_distance(sx,sy,x,y)>1||!strcmp(generals_terrain(sid,x,y),"WATER")||generals_tile_occupied(c,sid,x,y,occ,sizeof(occ)))goto fail;int rc=qrxdb_batch_put(b,k,"");snprintf(k,sizeof(k),"generals:unit:%s:embarked_on",unit);rc|=qrxdb_batch_put(b,k,"");snprintf(k,sizeof(k),"generals:unit:%s:status",unit);rc|=qrxdb_batch_put(b,k,"active");snprintf(k,sizeof(k),"generals:unit:%s:x",unit);rc|=velocity_batch_put_ll(b,k,x);snprintf(k,sizeof(k),"generals:unit:%s:y",unit);rc|=velocity_batch_put_ll(b,k,y);generals_tile_key(k,sizeof(k),c,sid,x,y,h);rc|=qrxdb_batch_put(b,k,unit);free(ship);free(xs);free(ys);return rc?-1:0;fail:free(ship);free(xs);free(ys);return -1;}
static int generals_stage_sea_supply(QrxDBBatch*b,const char*c,const char*from,const char*p,long long h){(void)h;char*ship=payload_get_field(p,"ship_unit_id"),*target=payload_get_field(p,"target_unit_id");if(!ship||!target)goto fail;char so[256],st[64],to[256],k[512];if(generals_unit_field(c,ship,"owner",so,sizeof(so))||strcmp(so,from)||generals_unit_field(c,ship,"type",st,sizeof(st))||strcmp(st,"SUPPLY_SHIP")||generals_unit_field(c,target,"owner",to,sizeof(to))||strcmp(to,from))goto fail;if(generals_hex_distance(generals_unit_ll(c,ship,"x",-1),generals_unit_ll(c,ship,"y",-1),generals_unit_ll(c,target,"x",-1),generals_unit_ll(c,target,"y",-1))>2)goto fail;long long sid=generals_unit_ll(c,ship,"season_id",0),ammo=generals_resource(c,sid,from,"ammo"),fuel=generals_resource(c,sid,from,"fuel");if(ammo<40||fuel<40)goto fail;int rc=generals_stage_resource(b,sid,from,"ammo",ammo-40);rc|=generals_stage_resource(b,sid,from,"fuel",fuel-40);snprintf(k,sizeof(k),"generals:unit:%s:ammo",target);rc|=velocity_batch_put_ll(b,k,100);snprintf(k,sizeof(k),"generals:unit:%s:fuel",target);rc|=velocity_batch_put_ll(b,k,100);free(ship);free(target);return rc?-1:0;fail:free(ship);free(target);return -1;}

/* Phase 4.9: fleets, carrier operations and deterministic naval combat. */
static void generals_fleet_key(char*out,size_t n,const char*fid,const char*f){snprintf(out,n,"generals:fleet:%s:%s",fid,f);}
static int generals_stage_naval_deploy(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*ut=payload_get_field(p,"unit_type"),*xs=payload_get_field(p,"yard_x"),*ys=payload_get_field(p,"yard_y");if(!ut||!xs||!ys)goto fail;const GeneralsUnitClass*cl=generals_class(ut);if(!cl||!generals_is_naval_type(ut))goto fail;
 long long sid=0,ss=0,se=0,tr=0,a=0,z=0;if(generals_season_at(c,h,&sid,&ss,&se,&tr,&a,&z))goto fail;long long x=atoll(xs),y=atoll(ys);char k[512],typ[64],own[256],occ[256];generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"type");if(generals_db_get(c,k,typ,sizeof(typ))||strcmp(typ,"NAVAL_YARD"))goto fail;generals_infra_tile_key(k,sizeof(k),c,sid,x,y,"owner");if(generals_db_get(c,k,own,sizeof(own))||strcmp(own,from))goto fail;
 static const int d[6][2]={{1,0},{-1,0},{0,1},{0,-1},{1,-1},{-1,1}};long long nx=-1,ny=-1;for(int i=0;i<6;i++){long long xx=x+d[i][0],yy=y+d[i][1];if(!strcmp(generals_terrain(sid,xx,yy),"WATER")&&!generals_tile_occupied(c,sid,xx,yy,occ,sizeof(occ))){nx=xx;ny=yy;break;}}if(nx<0)goto fail;
 long long sup=generals_resource(c,sid,from,"supply"),fuel=generals_resource(c,sid,from,"fuel"),mat=generals_resource(c,sid,from,"materials");long long sc=80+cl->hp/2,fc=80+cl->move*10,mc=100+cl->attack*3;if(sup<sc||fuel<fc||mat<mc)goto fail;char general[256];generals_player_key(k,sizeof(k),from,"general_asset");if(generals_db_get(c,k,general,sizeof(general)))goto fail;char uid[40];snprintf(uid,sizeof(uid),"UNIT-%.24s",txid);int rc=generals_stage_unit(b,c,sid,from,general,uid,ut,nx,ny,cl->hp,cl->move,cl->move_energy);rc|=generals_stage_resource(b,sid,from,"supply",sup-sc);rc|=generals_stage_resource(b,sid,from,"fuel",fuel-fc);rc|=generals_stage_resource(b,sid,from,"materials",mat-mc);snprintf(k,sizeof(k),"generals:unit:%s:ammo",uid);rc|=velocity_batch_put_ll(b,k,100);snprintf(k,sizeof(k),"generals:unit:%s:fuel",uid);rc|=velocity_batch_put_ll(b,k,100);free(ut);free(xs);free(ys);return rc?-1:0;fail:free(ut);free(xs);free(ys);return -1;}
static int generals_stage_fleet_create(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){(void)h;char*members=payload_get_field(p,"unit_ids");if(!members)goto fail;char tmp[2048];snprintf(tmp,sizeof(tmp),"%s",members);char fid[40],k[512],own[256],typ[64];snprintf(fid,sizeof(fid),"FLEET-%.22s",txid);int n=0,rc=0;for(char*q=strtok(tmp,",");q;q=strtok(NULL,",")){if(++n>16)goto fail;if(generals_unit_field(c,q,"owner",own,sizeof(own))||strcmp(own,from)||generals_unit_field(c,q,"type",typ,sizeof(typ))||!generals_is_naval_type(typ))goto fail;snprintf(k,sizeof(k),"generals:unit:%s:fleet_id",q);char ex[64];if(!generals_db_get(c,k,ex,sizeof(ex))&&*ex)goto fail;rc|=qrxdb_batch_put(b,k,fid);generals_fleet_key(k,sizeof(k),fid,"member");size_t l=strlen(k);snprintf(k+l,sizeof(k)-l,":%d",n-1);rc|=qrxdb_batch_put(b,k,q);}if(n<2)goto fail;generals_fleet_key(k,sizeof(k),fid,"owner");rc|=qrxdb_batch_put(b,k,from);generals_fleet_key(k,sizeof(k),fid,"status");rc|=qrxdb_batch_put(b,k,"active");generals_fleet_key(k,sizeof(k),fid,"member_count");rc|=velocity_batch_put_ll(b,k,n);free(members);return rc?-1:0;fail:free(members);return -1;}
static int generals_stage_naval_attack(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*a=payload_get_field(p,"attacker_unit_id"),*t=payload_get_field(p,"target_unit_id");if(!a||!t)goto fail;char ao[256],to[256],at[64],tt[64],k[512];if(generals_unit_field(c,a,"owner",ao,sizeof(ao))||strcmp(ao,from)||generals_unit_field(c,t,"owner",to,sizeof(to))||!strcmp(to,from)||generals_unit_field(c,a,"type",at,sizeof(at))||generals_unit_field(c,t,"type",tt,sizeof(tt))||!generals_is_naval_type(at)||!generals_is_naval_type(tt))goto fail;const GeneralsUnitClass*cl=generals_class(at);long long dist=generals_hex_distance(generals_unit_ll(c,a,"x",-1),generals_unit_ll(c,a,"y",-1),generals_unit_ll(c,t,"x",-1),generals_unit_ll(c,t,"y",-1)),ammo=generals_unit_ll(c,a,"ammo",100);if(!cl||dist<cl->min_range||dist>cl->max_range||ammo<4)goto fail;long long dmg=cl->attack-generals_class(tt)->defense/3;if(dmg<5)dmg=5;long long sid=generals_unit_ll(c,a,"season_id",0),turn=0,ss,se,ts,te;if(generals_season_at(c,h,&sid,&ss,&se,&turn,&ts,&te))goto fail;snprintf(k,sizeof(k),"generals:naval:%lld:%lld:%s:pending_damage",sid,turn,t);long long old=generals_db_ll(c,k,0);int rc=velocity_batch_put_ll(b,k,old+dmg);snprintf(k,sizeof(k),"generals:unit:%s:ammo",a);rc|=velocity_batch_put_ll(b,k,ammo-4);snprintf(k,sizeof(k),"generals:unit:%s:last_naval_attack_tx",a);rc|=qrxdb_batch_put(b,k,txid);free(a);free(t);return rc?-1:0;fail:free(a);free(t);return -1;}
static int generals_stage_naval_resolve(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){(void)from;char*t=payload_get_field(p,"target_unit_id"),*trs=payload_get_field(p,"turn_id");if(!t||!trs)goto fail;long long sid=generals_unit_ll(c,t,"season_id",0),tr=atoll(trs),cur,ss,se,ts,te;if(generals_season_at(c,h,&sid,&ss,&se,&cur,&ts,&te)||cur<=tr)goto fail;char k[512],typ[64];if(generals_unit_field(c,t,"type",typ,sizeof(typ))||!generals_is_naval_type(typ))goto fail;snprintf(k,sizeof(k),"generals:naval:%lld:%lld:%s:pending_damage",sid,tr,t);long long dmg=generals_db_ll(c,k,0);if(dmg<=0)goto fail;long long hp=generals_unit_ll(c,t,"hp",0),nh=hp>dmg?hp-dmg:0;int rc=0;snprintf(k,sizeof(k),"generals:unit:%s:hp",t);rc|=velocity_batch_put_ll(b,k,nh);snprintf(k,sizeof(k),"generals:naval:%lld:%lld:%s:pending_damage",sid,tr,t);rc|=velocity_batch_put_ll(b,k,0);snprintf(k,sizeof(k),"generals:naval:%lld:%lld:%s:resolve_tx",sid,tr,t);rc|=qrxdb_batch_put(b,k,txid);if(!nh){snprintf(k,sizeof(k),"generals:unit:%s:status",t);rc|=qrxdb_batch_put(b,k,"destroyed");long long x=generals_unit_ll(c,t,"x",-1),y=generals_unit_ll(c,t,"y",-1);generals_tile_key(k,sizeof(k),c,sid,x,y,h);rc|=qrxdb_batch_put(b,k,"");}free(t);free(trs);return rc?-1:0;fail:free(t);free(trs);return -1;}
static int generals_stage_carrier_wing(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){(void)txid;(void)h;char*carrier=payload_get_field(p,"carrier_unit_id"),*air=payload_get_field(p,"air_unit_id");if(!carrier||!air)goto fail;char o[256],t[64],ao[256],at[64],k[512];if(generals_unit_field(c,carrier,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,carrier,"type",t,sizeof(t))||strcmp(t,"CARRIER")||generals_unit_field(c,air,"owner",ao,sizeof(ao))||strcmp(ao,from)||generals_unit_field(c,air,"type",at,sizeof(at))||(strcmp(at,"FIGHTER")&&strcmp(at,"HELICOPTER")))goto fail;if(generals_hex_distance(generals_unit_ll(c,carrier,"x",-1),generals_unit_ll(c,carrier,"y",-1),generals_unit_ll(c,air,"x",-1),generals_unit_ll(c,air,"y",-1))>1)goto fail;snprintf(k,sizeof(k),"generals:unit:%s:carrier_id",air);int rc=qrxdb_batch_put(b,k,carrier);snprintf(k,sizeof(k),"generals:unit:%s:air_wing_count",carrier);long long n=generals_unit_ll(c,carrier,"air_wing_count",0);rc|=velocity_batch_put_ll(b,k,n+1);free(carrier);free(air);return rc?-1:0;fail:free(carrier);free(air);return -1;}
static int generals_stage_naval_blockade(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*uid=payload_get_field(p,"unit_id"),*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!uid||!xs||!ys)goto fail;char o[256],t[64],k[512];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",t,sizeof(t))||!generals_is_naval_type(t))goto fail;long long sid=generals_unit_ll(c,uid,"season_id",0),x=atoll(xs),y=atoll(ys);if(generals_hex_distance(generals_unit_ll(c,uid,"x",-1),generals_unit_ll(c,uid,"y",-1),x,y)>2)goto fail;snprintf(k,sizeof(k),"generals:season:%lld:blockade:%lld:%lld:owner",sid,x,y);int rc=qrxdb_batch_put(b,k,from);snprintf(k,sizeof(k),"generals:season:%lld:blockade:%lld:%lld:until",sid,x,y);rc|=velocity_batch_put_ll(b,k,h+60);snprintf(k,sizeof(k),"generals:season:%lld:blockade:%lld:%lld:tx",sid,x,y);rc|=qrxdb_batch_put(b,k,txid);free(uid);free(xs);free(ys);return rc?-1:0;fail:free(uid);free(xs);free(ys);return -1;}
static int generals_fleet_info_cmd(const char*c,const char*fid){char k[512],v[512];printf("fleet_id=%s\n",fid);const char*fs[]={"owner","status","member_count",NULL};for(int i=0;fs[i];i++){generals_fleet_key(k,sizeof(k),fid,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}long long n;generals_fleet_key(k,sizeof(k),fid,"member_count");n=generals_db_ll(c,k,0);for(long long i=0;i<n;i++){snprintf(k,sizeof(k),"generals:fleet:%s:member:%lld",fid,i);printf("member_%lld=%s\n",i,generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}


/* QRX Generals 0.0.7.7 Phase 5: deterministic economy, resources, cities and objectives. */
typedef struct { const char*type; long long supply,fuel,ammo,materials,score; } GeneralsStrategicFeature;
static GeneralsStrategicFeature generals_strategic_feature(long long sid,long long x,long long y){
    GeneralsStrategicFeature f={"NONE",0,0,0,0,0};
    if(!strcmp(generals_terrain(sid,x,y),"WATER"))return f;
    char seed[256],hx[129]; snprintf(seed,sizeof(seed),"QRX-GENERALS-STRATEGIC-v1|%lld|%lld|%lld",sid,x,y);sha3_512_hex((const unsigned char*)seed,strlen(seed),hx);
    unsigned long v=strtoul(hx,NULL,16)%1000;
    if(v<10)f=(GeneralsStrategicFeature){"CITY",50,0,0,25,5};
    else if(v<18)f=(GeneralsStrategicFeature){"OIL_FIELD",0,75,0,0,3};
    else if(v<26)f=(GeneralsStrategicFeature){"MINE",0,0,0,90,3};
    else if(v<32)f=(GeneralsStrategicFeature){"SUPPLY_HUB",100,0,25,0,4};
    else if(v<35)f=(GeneralsStrategicFeature){"COMMAND_CENTER",0,0,0,0,15};
    return f;
}
static int generals_stage_strategic_claim(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
    char *uid=payload_get_field(p,"unit_id"); if(!uid)return -1; char owner[256],status[64],k[768],old[256]={0};
    if(generals_unit_field(c,uid,"owner",owner,sizeof(owner))||strcmp(owner,from)||generals_unit_field(c,uid,"status",status,sizeof(status))||strcmp(status,"active")){free(uid);return -1;}
    long long sid=generals_unit_ll(c,uid,"season_id",0),x=generals_unit_ll(c,uid,"x",-1),y=generals_unit_ll(c,uid,"y",-1); GeneralsStrategicFeature f=generals_strategic_feature(sid,x,y); if(!strcmp(f.type,"NONE")){free(uid);return -1;}
    snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:owner",sid,x,y); if(generals_db_get(c,k,old,sizeof(old))==0&&!strcmp(old,from)){free(uid);return -1;}
    int rc=0; rc|=qrxdb_batch_put(b,k,from); snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:type",sid,x,y);rc|=qrxdb_batch_put(b,k,f.type);
    snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:claim_tx",sid,x,y);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:claim_height",sid,x,y);rc|=velocity_batch_put_ll(b,k,h);
    const char*types[]={"CITY","OIL_FIELD","MINE","SUPPLY_HUB","COMMAND_CENTER"}; for(int i=0;i<5;i++){if(strcmp(f.type,types[i]))continue;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:owned_%s",sid,from,types[i]);long long n=generals_db_ll(c,k,0);rc|=velocity_batch_put_ll(b,k,n+1);if(old[0]&&strcmp(old,from)){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:owned_%s",sid,old,types[i]);long long q=generals_db_ll(c,k,0);rc|=velocity_batch_put_ll(b,k,q>0?q-1:0);}break;}
    snprintf(k,sizeof(k),"generals:season:%lld:player:%s:strategic_score",sid,from);long long sc=generals_db_ll(c,k,0);rc|=velocity_batch_put_ll(b,k,sc+f.score); free(uid);return rc?-1:0;
}
static int generals_stage_economy_collect(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
    (void)p;(void)txid; long long sid=0,ss=0,se=0,turn=0,ts=0,te=0;if(generals_season_at(c,h,&sid,&ss,&se,&turn,&ts,&te)||!generals_player_exists(c,from))return -1;char k[768];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,from);char st[64];if(generals_db_get(c,k,st,sizeof(st))||strcmp(st,"active"))return -1;
    snprintf(k,sizeof(k),"generals:season:%lld:player:%s:last_economy_turn",sid,from);long long last=generals_db_ll(c,k,0);if(last>=turn)return -1;
    const char*types[]={"CITY","OIL_FIELD","MINE","SUPPLY_HUB","COMMAND_CENTER"};long long cnt[5]={0};for(int i=0;i<5;i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:owned_%s",sid,from,types[i]);cnt[i]=generals_db_ll(c,k,0);}
    long long ds=cnt[0]*50+cnt[3]*100,df=cnt[1]*75,da=cnt[3]*25,dm=cnt[0]*25+cnt[2]*90;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:city_supply_bonus",sid,from);ds+=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:city_material_bonus",sid,from);dm+=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:industry_material_bonus",sid,from);dm+=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_supply_bonus",sid,from);ds+=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_material_bonus",sid,from);dm+=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_fuel_bonus",sid,from);df+=generals_db_ll(c,k,0);long long dscore=cnt[0]*5+cnt[1]*3+cnt[2]*3+cnt[3]*4+cnt[4]*15;int rc=0;
    const char*rnames[]={"supply","fuel","ammo","materials"};long long adds[]={ds,df,da,dm};for(int i=0;i<4;i++){long long old=generals_resource(c,sid,from,rnames[i]),nv=0;checked_add_ll(old,adds[i],"Generals economy resource",&nv);rc|=generals_stage_resource(b,sid,from,rnames[i],nv);}
    snprintf(k,sizeof(k),"generals:season:%lld:player:%s:economy_score",sid,from);long long sc=generals_db_ll(c,k,0);rc|=velocity_batch_put_ll(b,k,sc+dscore);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:last_economy_turn",sid,from);rc|=velocity_batch_put_ll(b,k,turn);return rc?-1:0;
}

/* QRX Generals 0.0.7.7 Phase 5.1: city population, industry and economic development. */
static long long generals_city_ll(const char*c,long long sid,long long x,long long y,const char*f,long long d){char k[768];snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:%s",sid,x,y,f);return generals_db_ll(c,k,d);}
static int generals_stage_city_develop(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!xs||!ys)goto fail;long long sid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&sid,&ss,&se,&tr,&ts,&te))goto fail;long long x=atoll(xs),y=atoll(ys);GeneralsStrategicFeature f=generals_strategic_feature(sid,x,y);if(strcmp(f.type,"CITY"))goto fail;char k[768],own[256];snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:owner",sid,x,y);if(generals_db_get(c,k,own,sizeof(own))||strcmp(own,from))goto fail;
 long long lvl=generals_city_ll(c,sid,x,y,"level",1),pop=generals_city_ll(c,sid,x,y,"population",1000),ind=generals_city_ll(c,sid,x,y,"industry",1);if(lvl>=5)goto fail;long long mat=generals_resource(c,sid,from,"materials"),sup=generals_resource(c,sid,from,"supply"),mc=200*lvl,sc=100*lvl;if(mat<mc||sup<sc)goto fail;int rc=0;
 snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:level",sid,x,y);rc|=velocity_batch_put_ll(b,k,lvl+1);snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:population",sid,x,y);rc|=velocity_batch_put_ll(b,k,pop+500*lvl);snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:industry",sid,x,y);rc|=velocity_batch_put_ll(b,k,ind+1);snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:last_develop_turn",sid,x,y);rc|=velocity_batch_put_ll(b,k,tr);snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:last_develop_tx",sid,x,y);rc|=qrxdb_batch_put(b,k,txid);
 rc|=generals_stage_resource(b,sid,from,"materials",mat-mc);rc|=generals_stage_resource(b,sid,from,"supply",sup-sc);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:city_supply_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+25);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:city_material_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+20);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:development_score",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+10*lvl);free(xs);free(ys);return rc?-1:0;fail:free(xs);free(ys);return -1;}
static int generals_stage_industry_invest(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*xs=payload_get_field(p,"x"),*ys=payload_get_field(p,"y");if(!xs||!ys)goto fail;long long sid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&sid,&ss,&se,&tr,&ts,&te))goto fail;long long x=atoll(xs),y=atoll(ys);GeneralsStrategicFeature f=generals_strategic_feature(sid,x,y);if(strcmp(f.type,"CITY"))goto fail;char k[768],own[256];snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:owner",sid,x,y);if(generals_db_get(c,k,own,sizeof(own))||strcmp(own,from))goto fail;long long ind=generals_city_ll(c,sid,x,y,"industry",1);if(ind>=10)goto fail;long long mat=generals_resource(c,sid,from,"materials"),cost=150*ind;if(mat<cost)goto fail;int rc=0;snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:industry",sid,x,y);rc|=velocity_batch_put_ll(b,k,ind+1);snprintf(k,sizeof(k),"generals:season:%lld:city:%lld:%lld:last_industry_tx",sid,x,y);rc|=qrxdb_batch_put(b,k,txid);rc|=generals_stage_resource(b,sid,from,"materials",mat-cost);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:industry_material_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+30);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:industrial_capacity",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+1);free(xs);free(ys);return rc?-1:0;fail:free(xs);free(ys);return -1;}
static int generals_city_info_cmd(const char*c,long long sid,long long x,long long y){GeneralsStrategicFeature f=generals_strategic_feature(sid,x,y);if(strcmp(f.type,"CITY"))die("not a city");char k[768],v[256];snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:owner",sid,x,y);printf("season_id=%lld\nx=%lld\ny=%lld\nowner=%s\nlevel=%lld\npopulation=%lld\nindustry=%lld\n",sid,x,y,generals_db_get(c,k,v,sizeof(v))==0?v:"",generals_city_ll(c,sid,x,y,"level",1),generals_city_ll(c,sid,x,y,"population",1000),generals_city_ll(c,sid,x,y,"industry",1));return 0;}

/* QRX Generals 0.0.7.7 Phase 5.2: technology, research and military doctrine.
   Research is block based. QUB can accelerate only an already-running research
   project, is capped at 50% of its original duration, and is credited to the
   active season treasury. No technology is QUB-exclusive. */
typedef struct { const char*id; const char*branch; const char*prereq; long long blocks,materials,supply; } GeneralsTech;
static const GeneralsTech GENERALS_TECHS[]={
 {"INDUSTRIAL_AUTOMATION_I","ECONOMY","",3600,500,250},
 {"INDUSTRIAL_AUTOMATION_II","ECONOMY","INDUSTRIAL_AUTOMATION_I",7200,900,450},
 {"LOGISTICS_NETWORK_I","LOGISTICS","",3600,350,450},
 {"LOGISTICS_NETWORK_II","LOGISTICS","LOGISTICS_NETWORK_I",7200,650,800},
 {"ADVANCED_ARMOR_I","ARMOR","",5400,650,350},
 {"COMPOSITE_ARMOR_II","ARMOR","ADVANCED_ARMOR_I",9000,1100,550},
 {"PRECISION_ARTILLERY_I","ARTILLERY","",5400,550,400},
 {"COUNTER_BATTERY_II","ARTILLERY","PRECISION_ARTILLERY_I",9000,900,650},
 {"AIRFRAME_SYSTEMS_I","AIR","",5400,600,450},
 {"AIR_SUPERIORITY_II","AIR","AIRFRAME_SYSTEMS_I",9000,1000,700},
 {"GUIDED_MISSILES_I","MISSILE","",7200,800,500},
 {"LONG_RANGE_STRIKE_II","MISSILE","GUIDED_MISSILES_I",10800,1300,800},
 {"NAVAL_SYSTEMS_I","NAVAL","",5400,650,450},
 {"CARRIER_DOCTRINE_II","NAVAL","NAVAL_SYSTEMS_I",9000,1100,700},
 {"ELECTRONIC_WARFARE_I","EW","",5400,500,500},
 {"NETWORKED_SENSORS_II","EW","ELECTRONIC_WARFARE_I",9000,900,750},
 {NULL,NULL,NULL,0,0,0}
};
static const GeneralsTech*generals_tech(const char*id){if(!id)return NULL;for(int i=0;GENERALS_TECHS[i].id;i++)if(!strcmp(GENERALS_TECHS[i].id,id))return &GENERALS_TECHS[i];return NULL;}
static void generals_research_key(char*out,size_t n,long long sid,const char*addr,const char*f){snprintf(out,n,"generals:season:%lld:player:%s:research:%s",sid,addr,f);}
static int generals_player_active_in_season(const char*c,const char*addr,long long sid){char k[768],v[64];snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,addr);return generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,"active");}
static int generals_tech_unlocked(const char*c,long long sid,const char*addr,const char*tech){char k[1024];snprintf(k,sizeof(k),"generals:season:%lld:player:%s:tech:%s",sid,addr,tech);return generals_db_ll(c,k,0)>0;}
static int generals_stage_research_start(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*tid=payload_get_field(p,"tech_id"),*sid_s=payload_get_field(p,"season_id");if(!tid||!sid_s)goto fail;const GeneralsTech*t=generals_tech(tid);if(!t)goto fail;long long sid=atoll(sid_s),csid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&csid,&ss,&se,&tr,&ts,&te)||sid!=csid||!generals_player_active_in_season(c,from,sid)||generals_tech_unlocked(c,sid,from,tid))goto fail;if(t->prereq[0]&&!generals_tech_unlocked(c,sid,from,t->prereq))goto fail;
 char k[1024],v[256];generals_research_key(k,sizeof(k),sid,from,"status");if(generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,"active"))goto fail;long long mat=generals_resource(c,sid,from,"materials"),sup=generals_resource(c,sid,from,"supply");if(mat<t->materials||sup<t->supply)goto fail;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:industrial_capacity",sid,from);long long ic=generals_db_ll(c,k,0),icut=ic>25?25:ic;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_capacity",sid,from);long long rcap=generals_db_ll(c,k,0),rcut=rcap>30?30:rcap;long long cut=icut+rcut;if(cut>45)cut=45;long long dur=t->blocks-(t->blocks*cut/100);if(dur<60)dur=60;long long end=h+dur;int rc=0;
 generals_research_key(k,sizeof(k),sid,from,"status");rc|=qrxdb_batch_put(b,k,"active");generals_research_key(k,sizeof(k),sid,from,"tech_id");rc|=qrxdb_batch_put(b,k,tid);generals_research_key(k,sizeof(k),sid,from,"research_id");char rid[40];snprintf(rid,sizeof(rid),"RSR-%.24s",txid);rc|=qrxdb_batch_put(b,k,rid);generals_research_key(k,sizeof(k),sid,from,"start_height");rc|=velocity_batch_put_ll(b,k,h);generals_research_key(k,sizeof(k),sid,from,"base_duration_blocks");rc|=velocity_batch_put_ll(b,k,dur);generals_research_key(k,sizeof(k),sid,from,"completion_height");rc|=velocity_batch_put_ll(b,k,end);generals_research_key(k,sizeof(k),sid,from,"accelerated_blocks");rc|=velocity_batch_put_ll(b,k,0);generals_research_key(k,sizeof(k),sid,from,"qub_spent_atoms");rc|=velocity_batch_put_ll(b,k,0);generals_research_key(k,sizeof(k),sid,from,"start_tx");rc|=qrxdb_batch_put(b,k,txid);rc|=generals_stage_resource(b,sid,from,"materials",mat-t->materials);rc|=generals_stage_resource(b,sid,from,"supply",sup-t->supply);free(tid);free(sid_s);return rc?-1:0;fail:free(tid);free(sid_s);return -1;}
static int generals_stage_research_accelerate(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h,long long qub_atoms){
 if(qub_atoms<=0)return -1;char*sid_s=payload_get_field(p,"season_id"),*rid=payload_get_field(p,"research_id");if(!sid_s||!rid)goto fail;long long sid=atoll(sid_s),csid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&csid,&ss,&se,&tr,&ts,&te)||sid!=csid||!generals_player_active_in_season(c,from,sid))goto fail;char k[1024],v[256];generals_research_key(k,sizeof(k),sid,from,"status");if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"active"))goto fail;generals_research_key(k,sizeof(k),sid,from,"research_id");if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,rid))goto fail;generals_research_key(k,sizeof(k),sid,from,"completion_height");long long end=generals_db_ll(c,k,0);if(end<=h)goto fail;generals_research_key(k,sizeof(k),sid,from,"base_duration_blocks");long long base=generals_db_ll(c,k,0);generals_research_key(k,sizeof(k),sid,from,"accelerated_blocks");long long used=generals_db_ll(c,k,0),cap=base/2;if(used>=cap)goto fail;long long perqub=qrx_chain_get_ll_at_height_or_default(c,h,"generals_research_accel_blocks_per_qub",360),requested=0;if(perqub<=0||mul_div_floor_nonneg(qub_atoms,perqub,100000000LL,&requested)||requested<1)goto fail;long long room=cap-used;if(requested>room||requested>end-h-1)goto fail;long long actual=requested;if(actual<1)goto fail;long long nend=end-actual;int rc=0;generals_research_key(k,sizeof(k),sid,from,"completion_height");rc|=velocity_batch_put_ll(b,k,nend);generals_research_key(k,sizeof(k),sid,from,"accelerated_blocks");rc|=velocity_batch_put_ll(b,k,used+actual);generals_research_key(k,sizeof(k),sid,from,"qub_spent_atoms");long long spent=generals_db_ll(c,k,0),nspent=0;checked_add_ll(spent,qub_atoms,"Generals research QUB spent",&nspent);rc|=velocity_batch_put_ll(b,k,nspent);generals_research_key(k,sizeof(k),sid,from,"last_accel_tx");rc|=qrxdb_batch_put(b,k,txid);rc|=generals_stage_treasury_credit(b,c,qub_atoms,h,txid,"GAME_RESEARCH_ACCELERATE");snprintf(k,sizeof(k),"generals:season:%lld:treasury_total_atoms",sid);long long st=generals_db_ll(c,k,0),nst=0;checked_add_ll(st,qub_atoms,"Season treasury",&nst);rc|=velocity_batch_put_ll(b,k,nst);snprintf(k,sizeof(k),"generals:season:%lld:research_atoms",sid);long long ra=generals_db_ll(c,k,0),nra=0;checked_add_ll(ra,qub_atoms,"Season research treasury",&nra);rc|=velocity_batch_put_ll(b,k,nra);free(sid_s);free(rid);return rc?-1:0;fail:free(sid_s);free(rid);return -1;}
static int generals_apply_tech_unlock(QrxDBBatch*b,const char*c,long long sid,const char*from,const GeneralsTech*t){char k[1024];int rc=0;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:tech:%s",sid,from,t->id);rc|=velocity_batch_put_ll(b,k,1);if(!strcmp(t->id,"INDUSTRIAL_AUTOMATION_I")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_material_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+30);}else if(!strcmp(t->id,"INDUSTRIAL_AUTOMATION_II")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_material_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+60);}else if(!strcmp(t->id,"LOGISTICS_NETWORK_I")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_supply_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+35);}else if(!strcmp(t->id,"LOGISTICS_NETWORK_II")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_supply_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+70);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_fuel_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+25);}else{snprintf(k,sizeof(k),"generals:season:%lld:player:%s:tech_%s_modifier",sid,from,t->branch);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+10);}return rc?-1:0;}
static int generals_stage_research_complete(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*sid_s=payload_get_field(p,"season_id"),*rid=payload_get_field(p,"research_id");if(!sid_s||!rid)goto fail;long long sid=atoll(sid_s);char k[1024],v[256];generals_research_key(k,sizeof(k),sid,from,"status");if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"active"))goto fail;generals_research_key(k,sizeof(k),sid,from,"research_id");if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,rid))goto fail;generals_research_key(k,sizeof(k),sid,from,"completion_height");if(h<generals_db_ll(c,k,LLONG_MAX))goto fail;generals_research_key(k,sizeof(k),sid,from,"tech_id");if(generals_db_get(c,k,v,sizeof(v)))goto fail;const GeneralsTech*t=generals_tech(v);if(!t||generals_tech_unlocked(c,sid,from,t->id))goto fail;int rc=generals_apply_tech_unlock(b,c,sid,from,t);generals_research_key(k,sizeof(k),sid,from,"status");rc|=qrxdb_batch_put(b,k,"completed");generals_research_key(k,sizeof(k),sid,from,"complete_height");rc|=velocity_batch_put_ll(b,k,h);generals_research_key(k,sizeof(k),sid,from,"complete_tx");rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_score",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+10);free(sid_s);free(rid);return rc?-1:0;fail:free(sid_s);free(rid);return -1;}

/* Phase 5.3: research facilities, universities and technology warfare.
 * Espionage is a game-rule visibility layer over public replicated QRXDB state;
 * it does not make raw blockchain research state cryptographically secret. */
static void generals_intel_key(char*out,size_t n,long long sid,const char*viewer,const char*target,const char*f){snprintf(out,n,"generals:season:%lld:intel:%s:%s:%s",sid,viewer,target,f);}
static int generals_stage_tech_recon(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*sid_s=payload_get_field(p,"season_id"),*uid=payload_get_field(p,"unit_id"),*target=payload_get_field(p,"target_player");if(!sid_s||!uid||!target)goto fail;long long sid=atoll(sid_s),csid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&csid,&ss,&se,&tr,&ts,&te)||sid!=csid||!generals_player_active_in_season(c,from,sid)||!generals_player_active_in_season(c,target,sid)||!strcmp(from,target))goto fail;
 char o[256],ut[64],k[1024],v[256];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",ut,sizeof(ut))||strcmp(ut,"RECON"))goto fail;if(!generals_tech_unlocked(c,sid,from,"ELECTRONIC_WARFARE_I"))goto fail;
 generals_research_key(k,sizeof(k),sid,target,"status");if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"active"))goto fail;char tech[128],branch[64]="UNKNOWN";generals_research_key(k,sizeof(k),sid,target,"tech_id");if(generals_db_get(c,k,tech,sizeof(tech)))goto fail;const GeneralsTech*t=generals_tech(tech);if(t)snprintf(branch,sizeof(branch),"%s",t->branch);
 long long base=0,e=generals_energy_at(c,from,h,&base);if(e<8)goto fail;long long ttl=qrx_chain_get_ll_at_height_or_default(c,h,"generals_tech_intel_ttl_blocks",180);int rc=0;generals_intel_key(k,sizeof(k),sid,from,target,"status");rc|=qrxdb_batch_put(b,k,"active");generals_intel_key(k,sizeof(k),sid,from,target,"tech_id");rc|=qrxdb_batch_put(b,k,tech);generals_intel_key(k,sizeof(k),sid,from,target,"branch");rc|=qrxdb_batch_put(b,k,branch);generals_intel_key(k,sizeof(k),sid,from,target,"seen_height");rc|=velocity_batch_put_ll(b,k,h);generals_intel_key(k,sizeof(k),sid,from,target,"expires_height");rc|=velocity_batch_put_ll(b,k,h+ttl);generals_intel_key(k,sizeof(k),sid,from,target,"scan_tx");rc|=qrxdb_batch_put(b,k,txid);generals_player_key(k,sizeof(k),from,"energy");rc|=velocity_batch_put_ll(b,k,e-8);generals_player_key(k,sizeof(k),from,"energy_height");rc|=velocity_batch_put_ll(b,k,h);free(sid_s);free(uid);free(target);return rc?-1:0;
 fail:free(sid_s);free(uid);free(target);return -1;
}
static int generals_stage_counterintel(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*sid_s=payload_get_field(p,"season_id");if(!sid_s)return -1;long long sid=atoll(sid_s),csid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&csid,&ss,&se,&tr,&ts,&te)||sid!=csid||!generals_player_active_in_season(c,from,sid)){free(sid_s);return -1;}char k[1024];snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_labs",sid,from);long long labs=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:universities",sid,from);long long uni=generals_db_ll(c,k,0);if(labs+uni<1){free(sid_s);return -1;}long long sup=generals_resource(c,sid,from,"supply"),mat=generals_resource(c,sid,from,"materials");if(sup<200||mat<150){free(sid_s);return -1;}long long ttl=qrx_chain_get_ll_at_height_or_default(c,h,"generals_counterintel_ttl_blocks",180);int rc=0;snprintf(k,sizeof(k),"generals:season:%lld:player:%s:counterintel_until",sid,from);rc|=velocity_batch_put_ll(b,k,h+ttl);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:counterintel_tx",sid,from);rc|=qrxdb_batch_put(b,k,txid);rc|=generals_stage_resource(b,sid,from,"supply",sup-200);rc|=generals_stage_resource(b,sid,from,"materials",mat-150);free(sid_s);return rc?-1:0;
}
static int generals_stage_research_disrupt(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
 char*sid_s=payload_get_field(p,"season_id"),*uid=payload_get_field(p,"unit_id"),*target=payload_get_field(p,"target_player");if(!sid_s||!uid||!target)goto fail;long long sid=atoll(sid_s),csid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&csid,&ss,&se,&tr,&ts,&te)||sid!=csid||!generals_player_active_in_season(c,from,sid)||!generals_player_active_in_season(c,target,sid)||!strcmp(from,target))goto fail;char o[256],ut[64],k[1024],v[256];if(generals_unit_field(c,uid,"owner",o,sizeof(o))||strcmp(o,from)||generals_unit_field(c,uid,"type",ut,sizeof(ut))||strcmp(ut,"RECON")||!generals_tech_unlocked(c,sid,from,"ELECTRONIC_WARFARE_I"))goto fail;
 generals_intel_key(k,sizeof(k),sid,from,target,"expires_height");if(generals_db_ll(c,k,-1)<h)goto fail;generals_research_key(k,sizeof(k),sid,target,"status");if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"active"))goto fail;generals_research_key(k,sizeof(k),sid,target,"completion_height");long long end=generals_db_ll(c,k,0);generals_research_key(k,sizeof(k),sid,target,"base_duration_blocks");long long base=generals_db_ll(c,k,0);if(end<=h||base<1)goto fail;generals_research_key(k,sizeof(k),sid,target,"disrupted_blocks");long long used=generals_db_ll(c,k,0),cap=base/4;if(used>=cap)goto fail;
 long long delay=qrx_chain_get_ll_at_height_or_default(c,h,"generals_research_disrupt_blocks",300);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:counterintel_until",sid,target);if(generals_db_ll(c,k,-1)>=h)delay=(delay+1)/2;if(delay>cap-used)delay=cap-used;if(delay<1)goto fail;long long sup=generals_resource(c,sid,from,"supply");if(sup<100)goto fail;int rc=0;generals_research_key(k,sizeof(k),sid,target,"completion_height");rc|=velocity_batch_put_ll(b,k,end+delay);generals_research_key(k,sizeof(k),sid,target,"disrupted_blocks");rc|=velocity_batch_put_ll(b,k,used+delay);generals_research_key(k,sizeof(k),sid,target,"last_disrupt_by");rc|=qrxdb_batch_put(b,k,from);generals_research_key(k,sizeof(k),sid,target,"last_disrupt_tx");rc|=qrxdb_batch_put(b,k,txid);generals_research_key(k,sizeof(k),sid,target,"last_disrupt_height");rc|=velocity_batch_put_ll(b,k,h);rc|=generals_stage_resource(b,sid,from,"supply",sup-100);free(sid_s);free(uid);free(target);return rc?-1:0;
 fail:free(sid_s);free(uid);free(target);return -1;
}
static int generals_research_network_info_cmd(const char*c,const char*addr,long long sid){char k[1024];printf("season_id=%lld\nplayer=%s\n",sid,addr);const char*fs[]={"research_labs","universities","research_capacity","counterintel_until",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:%s",sid,addr,fs[i]);printf("%s=%lld\n",fs[i],generals_db_ll(c,k,0));}return 0;}
static int generals_espionage_info_cmd(const char*c,const char*viewer,const char*target,long long sid){char k[1024],v[256];printf("season_id=%lld\nviewer=%s\ntarget=%s\n",sid,viewer,target);const char*fs[]={"status","tech_id","branch","seen_height","expires_height","scan_tx",NULL};for(int i=0;fs[i];i++){generals_intel_key(k,sizeof(k),sid,viewer,target,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_stage_doctrine_select(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){char*sid_s=payload_get_field(p,"season_id"),*doc=payload_get_field(p,"doctrine");if(!sid_s||!doc)goto fail;long long sid=atoll(sid_s),csid=0,ss=0,se=0,tr=0,ts=0,te=0;if(generals_season_at(c,h,&csid,&ss,&se,&tr,&ts,&te)||sid!=csid||!generals_player_active_in_season(c,from,sid))goto fail;const char*ok[] = {"ARMORED_SPEARHEAD","FORTRESS_DEFENSE","AIR_SUPREMACY","DEEP_LOGISTICS","MARITIME_POWER",NULL};int valid=0;for(int i=0;ok[i];i++)if(!strcmp(doc,ok[i]))valid=1;if(!valid)goto fail;char k[1024],v[256];snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine",sid,from);if(generals_db_get(c,k,v,sizeof(v))==0&&*v)goto fail;long long mat=generals_resource(c,sid,from,"materials"),sup=generals_resource(c,sid,from,"supply");if(mat<500||sup<500)goto fail;int rc=qrxdb_batch_put(b,k,doc);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_tx",sid,from);rc|=qrxdb_batch_put(b,k,txid);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_height",sid,from);rc|=velocity_batch_put_ll(b,k,h);rc|=generals_stage_resource(b,sid,from,"materials",mat-500);rc|=generals_stage_resource(b,sid,from,"supply",sup-500);if(!strcmp(doc,"ARMORED_SPEARHEAD")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_ground_attack_pct",sid,from);rc|=velocity_batch_put_ll(b,k,10);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_move_efficiency_pct",sid,from);rc|=velocity_batch_put_ll(b,k,10);}else if(!strcmp(doc,"FORTRESS_DEFENSE")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_defense_pct",sid,from);rc|=velocity_batch_put_ll(b,k,12);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_infra_defense_pct",sid,from);rc|=velocity_batch_put_ll(b,k,15);}else if(!strcmp(doc,"AIR_SUPREMACY")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_air_strength_pct",sid,from);rc|=velocity_batch_put_ll(b,k,12);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_radar_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,2);}else if(!strcmp(doc,"DEEP_LOGISTICS")){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:research_supply_bonus",sid,from);rc|=velocity_batch_put_ll(b,k,generals_db_ll(c,k,0)+50);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_fuel_efficiency_pct",sid,from);rc|=velocity_batch_put_ll(b,k,10);}else{snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_naval_strength_pct",sid,from);rc|=velocity_batch_put_ll(b,k,12);snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine_sea_supply_pct",sid,from);rc|=velocity_batch_put_ll(b,k,20);}free(sid_s);free(doc);return rc?-1:0;fail:free(sid_s);free(doc);return -1;}
static int generals_research_info_cmd(const char*c,const char*addr,long long sid){char k[1024],v[512];printf("season_id=%lld\nplayer=%s\n",sid,addr);const char*fs[]={"status","research_id","tech_id","start_height","base_duration_blocks","completion_height","accelerated_blocks","disrupted_blocks","qub_spent_atoms","last_disrupt_by","last_disrupt_height","complete_height",NULL};for(int i=0;fs[i];i++){generals_research_key(k,sizeof(k),sid,addr,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}snprintf(k,sizeof(k),"generals:season:%lld:research_atoms",sid);printf("season_research_atoms=%lld\n",generals_db_ll(c,k,0));snprintf(k,sizeof(k),"generals:season:%lld:treasury_total_atoms",sid);printf("season_treasury_total_atoms=%lld\n",generals_db_ll(c,k,0));return 0;}
static int generals_tech_tree_cmd(const char*c,const char*addr,long long sid){(void)c;for(int i=0;GENERALS_TECHS[i].id;i++)printf("tech=%s branch=%s prereq=%s base_blocks=%lld materials=%lld supply=%lld unlocked=%d\n",GENERALS_TECHS[i].id,GENERALS_TECHS[i].branch,GENERALS_TECHS[i].prereq,GENERALS_TECHS[i].blocks,GENERALS_TECHS[i].materials,GENERALS_TECHS[i].supply,generals_tech_unlocked(c,sid,addr,GENERALS_TECHS[i].id));return 0;}
static int generals_doctrine_info_cmd(const char*c,const char*addr,long long sid){char k[1024],v[256];snprintf(k,sizeof(k),"generals:season:%lld:player:%s:doctrine",sid,addr);printf("season_id=%lld\nplayer=%s\ndoctrine=%s\n",sid,addr,generals_db_get(c,k,v,sizeof(v))==0?v:"");const char*fs[]={"doctrine_ground_attack_pct","doctrine_move_efficiency_pct","doctrine_defense_pct","doctrine_infra_defense_pct","doctrine_air_strength_pct","doctrine_radar_bonus","doctrine_fuel_efficiency_pct","doctrine_naval_strength_pct","doctrine_sea_supply_pct",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:%s",sid,addr,fs[i]);printf("%s=%lld\n",fs[i],generals_db_ll(c,k,0));}return 0;}


/* Phase 6 / 6.1: deterministic season finalization and claimable rewards.
   Phase 6.1 splits the season pool 70/30 between top players and top clans.
   Player pool: top 20, descending linear weights. Clan pool: top 3 clans,
   50/30/20 normalized if fewer than three clans qualify, then distributed
   proportionally to that clan's season-member score (minimum weight 1).
   Clan membership is snapshotted at GAME_SEASON_JOIN to prevent end-of-season hopping. */
static long long generals_player_total_score(const char*c,long long sid,const char*addr){
    char k[1024]; long long total=0;
    const char*fs[]={"territory_score","strategic_score","economy_score","development_score",NULL};
    for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:%s",sid,addr,fs[i]); long long v=generals_db_ll(c,k,0); if(v>0 && total<=LLONG_MAX-v) total+=v;}
    snprintf(k,sizeof(k),"generals:season:%lld:player:%s",sid,addr); char st[64]={0};
    if(generals_db_get(c,k,st,sizeof(st))==0 && !strcmp(st,"active")) total+=100;
    return total;
}
static int generals_season_bounds(const char*c,long long sid,long long h,long long*start,long long*end){
    long long first=qrx_chain_get_ll_at_height_or_default(c,h,"generals_season_start_height",0),len=qrx_chain_get_ll_at_height_or_default(c,h,"generals_season_length_blocks",259200);
    if(sid<1||len<=0)return -1; *start=first+(sid-1)*len; *end=*start+len-1; return 0;
}
typedef struct {char addr[256];char clan[256];long long score;long long reward;} GeneralsSeasonRank;
typedef struct {char id[256];long long score;long long members;long long award;} GeneralsClanRank;
static int generals_rank_cmp(const void*a,const void*b){const GeneralsSeasonRank*x=(const GeneralsSeasonRank*)a,*y=(const GeneralsSeasonRank*)b;if(x->score!=y->score)return x->score<y->score?1:-1;return strcmp(x->addr,y->addr);}
static int generals_clan_rank_cmp(const void*a,const void*b){const GeneralsClanRank*x=(const GeneralsClanRank*)a,*y=(const GeneralsClanRank*)b;if(x->score!=y->score)return x->score<y->score?1:-1;return strcmp(x->id,y->id);}
static int generals_stage_season_finalize(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
    (void)from; char*ss=payload_get_field(p,"season_id"); if(!ss)return -1; long long sid=atoll(ss),start=0,end=0; free(ss);
    if(generals_season_bounds(c,sid,h,&start,&end)||h<=end)return -1;
    char k[1024],v[512]; snprintf(k,sizeof(k),"generals:season:%lld:status",sid); if(generals_db_get(c,k,v,sizeof(v))==0&&!strcmp(v,"finalized"))return -1;
    snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid); long long n=generals_db_ll(c,k,0); if(n<1||n>100000)return -1;
    GeneralsSeasonRank*rank=calloc((size_t)n,sizeof(*rank)); if(!rank)return -1; long long ranked=0;
    for(long long i=0;i<n;i++){
        snprintf(k,sizeof(k),"generals:season:%lld:player_index:%lld",sid,i); char a[256]={0}; if(generals_db_get(c,k,a,sizeof(a)))continue;
        snprintf(rank[ranked].addr,sizeof(rank[ranked].addr),"%s",a); rank[ranked].score=generals_player_total_score(c,sid,a);
        snprintf(k,sizeof(k),"generals:season:%lld:player:%s:clan_id",sid,a); if(generals_db_get(c,k,rank[ranked].clan,sizeof(rank[ranked].clan)))rank[ranked].clan[0]=0;
        ranked++;
    }
    if(ranked<1){free(rank);return -1;} qsort(rank,(size_t)ranked,sizeof(*rank),generals_rank_cmp);
    snprintf(k,sizeof(k),"generals:season:%lld:prize_pool_atoms",sid); long long pool=generals_db_ll(c,k,0); if(pool<0){free(rank);return -1;}
    long long player_pool=(pool/100)*70 + ((pool%100)*70)/100, clan_pool=pool-player_pool;
    long long top=ranked<20?ranked:20, wsum=top*(top+1)/2, allocated=0;
    for(long long i=0;i<top;i++){long long weight=top-i;long long share=wsum>0?(player_pool/wsum)*weight + ((player_pool%wsum)*weight)/wsum:0;rank[i].reward+=share;allocated+=share;}
    if(top>0&&allocated<player_pool)rank[0].reward+=player_pool-allocated;

    GeneralsClanRank*clans=calloc((size_t)ranked,sizeof(*clans)); if(!clans){free(rank);return -1;} long long cn=0;
    for(long long i=0;i<ranked;i++)if(rank[i].clan[0]){
        long long ci=-1;for(long long j=0;j<cn;j++)if(!strcmp(clans[j].id,rank[i].clan)){ci=j;break;}
        if(ci<0){ci=cn++;snprintf(clans[ci].id,sizeof(clans[ci].id),"%s",rank[i].clan);}
        if(rank[i].score>0 && clans[ci].score<=LLONG_MAX-rank[i].score)clans[ci].score+=rank[i].score;clans[ci].members++;
    }
    if(cn>0)qsort(clans,(size_t)cn,sizeof(*clans),generals_clan_rank_cmp);
    long long ctop=cn<3?cn:3;const long long cw[3]={50,30,20};long long cwsum=0;for(long long i=0;i<ctop;i++)cwsum+=cw[i];long long callocated=0;
    for(long long ci=0;ci<ctop;ci++){long long share=cwsum>0?(clan_pool/cwsum)*cw[ci]+((clan_pool%cwsum)*cw[ci])/cwsum:0;clans[ci].award=share;callocated+=share;}
    if(ctop>0&&callocated<clan_pool)clans[0].award+=clan_pool-callocated;
    else if(ctop==0&&ranked>0)rank[0].reward+=clan_pool;
    long long clan_command_atoms[3]={0,0,0};char clan_command_leader[3][256]={{0}};
    for(long long ci=0;ci<ctop;ci++){
        char lk[1024],leader[256]={0};snprintf(lk,sizeof(lk),"generals:season:%lld:clan:%s:leader",sid,clans[ci].id);generals_db_get(c,lk,leader,sizeof(leader));
        long long leader_idx=-1;for(long long i=0;i<ranked;i++)if(leader[0]&&!strcmp(rank[i].addr,leader)&&!strcmp(rank[i].clan,clans[ci].id)){leader_idx=i;break;}
        long long command=(leader_idx>=0)?clans[ci].award/20:0; /* 5% commander's share, only for participating season leader */
        clan_command_atoms[ci]=command;if(leader_idx>=0)snprintf(clan_command_leader[ci],sizeof(clan_command_leader[ci]),"%s",leader);
        if(command>0)rank[leader_idx].reward+=command;
        long long member_award=clans[ci].award-command,mw=0;for(long long i=0;i<ranked;i++)if(!strcmp(rank[i].clan,clans[ci].id))mw+=rank[i].score>0?rank[i].score:1;
        long long sent=0,first=-1;for(long long i=0;i<ranked;i++)if(!strcmp(rank[i].clan,clans[ci].id)){if(first<0)first=i;long long w=rank[i].score>0?rank[i].score:1;long long sh=mw>0?(member_award/mw)*w+((member_award%mw)*w)/mw:0;rank[i].reward+=sh;sent+=sh;}
        if(first>=0&&sent<member_award)rank[first].reward+=member_award-sent;
    }

    int rc=0; snprintf(k,sizeof(k),"generals:season:%lld:status",sid);rc|=qrxdb_batch_put(b,k,"finalized");
    snprintf(k,sizeof(k),"generals:season:%lld:winner",sid);rc|=qrxdb_batch_put(b,k,rank[0].addr);
    snprintf(k,sizeof(k),"generals:season:%lld:winner_score",sid);rc|=velocity_batch_put_ll(b,k,rank[0].score);
    snprintf(k,sizeof(k),"generals:season:%lld:finalized_height",sid);rc|=velocity_batch_put_ll(b,k,h);
    snprintf(k,sizeof(k),"generals:season:%lld:finalized_tx",sid);rc|=qrxdb_batch_put(b,k,txid);
    snprintf(k,sizeof(k),"generals:season:%lld:reward_player_pool_atoms",sid);rc|=velocity_batch_put_ll(b,k,player_pool);
    snprintf(k,sizeof(k),"generals:season:%lld:reward_clan_pool_atoms",sid);rc|=velocity_batch_put_ll(b,k,clan_pool);
    long long recipients=0,total_rewards=0;
    for(long long i=0;i<ranked;i++){
        snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:player",sid,i+1);rc|=qrxdb_batch_put(b,k,rank[i].addr);
        snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:score",sid,i+1);rc|=velocity_batch_put_ll(b,k,rank[i].score);
        snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:clan_id",sid,i+1);rc|=qrxdb_batch_put(b,k,rank[i].clan);
        snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:reward_atoms",sid,i+1);rc|=velocity_batch_put_ll(b,k,rank[i].reward);
        if(rank[i].reward>0){snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:atoms",sid,rank[i].addr);rc|=velocity_batch_put_ll(b,k,rank[i].reward);snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:status",sid,rank[i].addr);rc|=qrxdb_batch_put(b,k,"claimable");recipients++;total_rewards+=rank[i].reward;}
    }
    for(long long i=0;i<ctop;i++){snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:clan_id",sid,i+1);rc|=qrxdb_batch_put(b,k,clans[i].id);snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:score",sid,i+1);rc|=velocity_batch_put_ll(b,k,clans[i].score);snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:award_atoms",sid,i+1);rc|=velocity_batch_put_ll(b,k,clans[i].award);snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:command_atoms",sid,i+1);rc|=velocity_batch_put_ll(b,k,clan_command_atoms[i]);snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:leader",sid,i+1);rc|=qrxdb_batch_put(b,k,clan_command_leader[i]);}
    snprintf(k,sizeof(k),"generals:season:%lld:reward_recipient_count",sid);rc|=velocity_batch_put_ll(b,k,recipients);
    snprintf(k,sizeof(k),"generals:season:%lld:reward_total_atoms",sid);rc|=velocity_batch_put_ll(b,k,total_rewards);
    free(clans);free(rank);return rc?-1:0;
}
static long long generals_claimable_reward(const char*c,const char*addr,const char*p){
    char*ss=payload_get_field(p,"season_id"); if(!ss)return 0; long long sid=atoll(ss);free(ss);char k[1024],v[64];
    snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:status",sid,addr); if(generals_db_get(c,k,v,sizeof(v))||strcmp(v,"claimable"))return 0;
    snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:atoms",sid,addr); return generals_db_ll(c,k,0);
}
static int generals_stage_reward_claim(QrxDBBatch*b,const char*c,const char*from,const char*p,const char*txid,long long h){
    char*ss=payload_get_field(p,"season_id"); if(!ss)return -1; long long sid=atoll(ss);free(ss); long long reward=generals_claimable_reward(c,from,p); if(reward<=0)return -1;
    long long bal=generals_treasury_balance(c),res=generals_treasury_reserved(c); if(bal<reward||res<reward)return -1; char k[1024]; int rc=0;
    snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:status",sid,from);rc|=qrxdb_batch_put(b,k,"claimed");
    snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:claimed_height",sid,from);rc|=velocity_batch_put_ll(b,k,h);
    snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:claim_tx",sid,from);rc|=qrxdb_batch_put(b,k,txid);
    rc|=velocity_batch_put_ll(b,"generals:treasury:balance_atoms",bal-reward); rc|=velocity_batch_put_ll(b,"generals:treasury:reserved_atoms",res-reward);
    return rc?-1:0;
}
static int atomic_stage_generals(QrxDBBatch*b,const char*c,const char*from,const char*t,const char*p,const char*txid,long long h,long long cost){long long act=qrx_chain_get_ll_at_height_or_default(c,h+1,"generals_activation_height",0);if(h+1<act)return -1;if(!strcmp(t,"GAME_JOIN"))return generals_stage_join(b,c,from,p,txid,h,cost);if(!strcmp(t,"GAME_CLAN_CREATE"))return generals_stage_clan_create(b,c,from,p,txid,h,cost);if(!strcmp(t,"GAME_CLAN_INVITE"))return generals_stage_clan_invite(b,c,from,p,txid,h,cost);if(!strcmp(t,"GAME_CLAN_INVITE_REVOKE")){int r=generals_stage_clan_invite_revoke(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_INVITE_REVOKE");return r;}if(!strcmp(t,"GAME_CLAN_JOIN")){int r=generals_stage_clan_join(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_JOIN");return r;}if(!strcmp(t,"GAME_CLAN_LEAVE")){int r=generals_stage_clan_leave(b,c,from,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_LEAVE");return r;}if(!strcmp(t,"GAME_CLAN_OFFICER_SET")){int r=generals_stage_clan_officer_set(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_OFFICER_SET");return r;}if(!strcmp(t,"GAME_CLAN_DIRECTIVE")){int r=generals_stage_clan_directive(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_DIRECTIVE");return r;}if(!strcmp(t,"GAME_CLAN_LEADER_TRANSFER")){int r=generals_stage_clan_leader_transfer(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CLAN_LEADER_TRANSFER");return r;}if(!strcmp(t,"GAME_SEASON_JOIN"))return generals_stage_season_join(b,c,from,p,txid,h,cost);if(!strcmp(t,"GAME_ENERGY_SPEND")){int r=generals_stage_energy_spend(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_ENERGY_SPEND");return r;}if(!strcmp(t,"GAME_ORDER_COMMIT")){int r=generals_stage_order_commit(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_ORDER_COMMIT");return r;}if(!strcmp(t,"GAME_ORDER_REVEAL")){int r=generals_stage_order_reveal(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_ORDER_REVEAL");return r;}if(!strcmp(t,"GAME_MARCH_ADVANCE")){int r=generals_stage_march_advance(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_MARCH_ADVANCE");return r;}if(!strcmp(t,"GAME_TURN_RESOLVE")){int r=generals_stage_turn_resolve(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_TURN_RESOLVE");return r;}if(!strcmp(t,"GAME_INFRA_BUILD")){int r=generals_stage_infra_build(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_INFRA_BUILD");return r;}if(!strcmp(t,"GAME_PRODUCE_UNIT")){int r=generals_stage_produce_unit(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_PRODUCE_UNIT");return r;}if(!strcmp(t,"GAME_SUPPLY_TRANSFER")){int r=generals_stage_supply_transfer(b,c,from,p,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_SUPPLY_TRANSFER");return r;}if(!strcmp(t,"GAME_REPAIR_UNIT")){int r=generals_stage_service_unit(b,c,from,p,h,1);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_REPAIR_UNIT");return r;}if(!strcmp(t,"GAME_REARM_UNIT")){int r=generals_stage_service_unit(b,c,from,p,h,0);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_REARM_UNIT");return r;}if(!strcmp(t,"GAME_INFRA_ATTACK")){int r=generals_stage_infra_attack(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_INFRA_ATTACK");return r;}if(!strcmp(t,"GAME_ROAD_REPAIR")){int r=generals_stage_road_repair(b,c,from,p,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_ROAD_REPAIR");return r;}if(!strcmp(t,"GAME_UNIT_RESUPPLY")){int r=generals_stage_unit_resupply(b,c,from,p,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_UNIT_RESUPPLY");return r;}if(!strcmp(t,"GAME_RECON_SCAN")){int r=generals_stage_recon_scan(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_RECON_SCAN");return r;}if(!strcmp(t,"GAME_EW_JAM")){int r=generals_stage_ew_jam(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_EW_JAM");return r;}if(!strcmp(t,"GAME_AIR_MISSION")){int r=generals_stage_air_mission(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AIR_MISSION");return r;}if(!strcmp(t,"GAME_RADAR_SCAN")){int r=generals_stage_radar_scan(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_RADAR_SCAN");return r;}if(!strcmp(t,"GAME_SAM_INTERCEPT")){int r=generals_stage_sam_intercept(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_SAM_INTERCEPT");return r;}if(!strcmp(t,"GAME_MISSILE_LAUNCH")){int r=generals_stage_missile_launch(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_MISSILE_LAUNCH");return r;}if(!strcmp(t,"GAME_STRIKE_RESOLVE")){int r=generals_stage_strike_resolve(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_STRIKE_RESOLVE");return r;}if(!strcmp(t,"GAME_CAP_MISSION")){int r=generals_stage_cap_mission(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CAP_MISSION");return r;}if(!strcmp(t,"GAME_ESCORT_MISSION")){int r=generals_stage_escort_mission(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_ESCORT_MISSION");return r;}if(!strcmp(t,"GAME_AIR_INTERCEPT")){int r=generals_stage_air_intercept(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AIR_INTERCEPT");return r;}if(!strcmp(t,"GAME_AIR_COMBAT_RESOLVE")){int r=generals_stage_air_combat_resolve(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AIR_COMBAT_RESOLVE");return r;}if(!strcmp(t,"GAME_AIR_FORMATION")){int r=generals_stage_air_formation(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AIR_FORMATION");return r;}if(!strcmp(t,"GAME_CAP_AUTO_INTERCEPT")){int r=generals_stage_cap_auto_intercept(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CAP_AUTO_INTERCEPT");return r;}if(!strcmp(t,"GAME_AIR_RTB")){int r=generals_stage_air_rtb(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AIR_RTB");return r;}if(!strcmp(t,"GAME_SEAD_MISSION")){int r=generals_stage_sead(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_SEAD_MISSION");return r;}if(!strcmp(t,"GAME_NAVAL_DEPLOY")){int r=generals_stage_naval_deploy(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_NAVAL_DEPLOY");return r;}if(!strcmp(t,"GAME_FLEET_CREATE")){int r=generals_stage_fleet_create(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_FLEET_CREATE");return r;}if(!strcmp(t,"GAME_NAVAL_ATTACK")){int r=generals_stage_naval_attack(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_NAVAL_ATTACK");return r;}if(!strcmp(t,"GAME_NAVAL_COMBAT_RESOLVE")){int r=generals_stage_naval_resolve(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_NAVAL_COMBAT_RESOLVE");return r;}if(!strcmp(t,"GAME_CARRIER_AIR_WING")){int r=generals_stage_carrier_wing(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CARRIER_AIR_WING");return r;}if(!strcmp(t,"GAME_NAVAL_BLOCKADE")){int r=generals_stage_naval_blockade(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_NAVAL_BLOCKADE");return r;}if(!strcmp(t,"GAME_NAVAL_MOVE")){int r=generals_stage_naval_move(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_NAVAL_MOVE");return r;}if(!strcmp(t,"GAME_AMPHIBIOUS_LOAD")){int r=generals_stage_amphibious_load(b,c,from,p,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AMPHIBIOUS_LOAD");return r;}if(!strcmp(t,"GAME_AMPHIBIOUS_LAND")){int r=generals_stage_amphibious_land(b,c,from,p,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_AMPHIBIOUS_LAND");return r;}if(!strcmp(t,"GAME_SEA_SUPPLY")){int r=generals_stage_sea_supply(b,c,from,p,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_SEA_SUPPLY");return r;}if(!strcmp(t,"GAME_STRATEGIC_CLAIM")){int r=generals_stage_strategic_claim(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_STRATEGIC_CLAIM");return r;}if(!strcmp(t,"GAME_ECONOMY_COLLECT")){int r=generals_stage_economy_collect(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_ECONOMY_COLLECT");return r;}if(!strcmp(t,"GAME_CITY_DEVELOP")){int r=generals_stage_city_develop(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_CITY_DEVELOP");return r;}if(!strcmp(t,"GAME_INDUSTRY_INVEST")){int r=generals_stage_industry_invest(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_INDUSTRY_INVEST");return r;}if(!strcmp(t,"GAME_RESEARCH_START")){int r=generals_stage_research_start(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_RESEARCH_START");return r;}if(!strcmp(t,"GAME_RESEARCH_ACCELERATE"))return generals_stage_research_accelerate(b,c,from,p,txid,h,cost);if(!strcmp(t,"GAME_RESEARCH_COMPLETE")){int r=generals_stage_research_complete(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_RESEARCH_COMPLETE");return r;}if(!strcmp(t,"GAME_DOCTRINE_SELECT")){int r=generals_stage_doctrine_select(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_DOCTRINE_SELECT");return r;}if(!strcmp(t,"GAME_TECH_RECON")){int r=generals_stage_tech_recon(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_TECH_RECON");return r;}if(!strcmp(t,"GAME_RESEARCH_DISRUPT")){int r=generals_stage_research_disrupt(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_RESEARCH_DISRUPT");return r;}if(!strcmp(t,"GAME_COUNTERINTEL_ACTIVATE")){int r=generals_stage_counterintel(b,c,from,p,txid,h);if(!r&&cost>0)r=generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_COUNTERINTEL_ACTIVATE");return r;}if(!strcmp(t,"GAME_SEASON_FINALIZE"))return generals_stage_season_finalize(b,c,from,p,txid,h);if(!strcmp(t,"GAME_REWARD_CLAIM"))return generals_stage_reward_claim(b,c,from,p,txid,h);if(!strcmp(t,"GAME_TREASURY_FUND"))return generals_stage_treasury_credit(b,c,cost,h,txid,"GAME_TREASURY_FUND");return -1;}

static int generals_strategic_info_cmd(const char*c,long long sid,long long x,long long y){GeneralsStrategicFeature f=generals_strategic_feature(sid,x,y);char k[768],v[256];printf("season_id=%lld\nx=%lld\ny=%lld\ntype=%s\nproduction_supply=%lld\nproduction_fuel=%lld\nproduction_ammo=%lld\nproduction_materials=%lld\nscore_per_turn=%lld\n",sid,x,y,f.type,f.supply,f.fuel,f.ammo,f.materials,f.score);snprintf(k,sizeof(k),"generals:season:%lld:strategic:%lld:%lld:owner",sid,x,y);printf("owner=%s\n",generals_db_get(c,k,v,sizeof(v))==0?v:"");return 0;}
static int generals_economy_info_cmd(const char*c,const char*addr,long long sid){char k[768];const char*types[]={"CITY","OIL_FIELD","MINE","SUPPLY_HUB","COMMAND_CENTER"};printf("season_id=%lld\nplayer=%s\n",sid,addr);for(int i=0;i<5;i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:owned_%s",sid,addr,types[i]);printf("owned_%s=%lld\n",types[i],generals_db_ll(c,k,0));}snprintf(k,sizeof(k),"generals:season:%lld:player:%s:economy_score",sid,addr);printf("economy_score=%lld\n",generals_db_ll(c,k,0));snprintf(k,sizeof(k),"generals:season:%lld:player:%s:strategic_score",sid,addr);printf("strategic_score=%lld\n",generals_db_ll(c,k,0));snprintf(k,sizeof(k),"generals:season:%lld:player:%s:development_score",sid,addr);printf("development_score=%lld\n",generals_db_ll(c,k,0));snprintf(k,sizeof(k),"generals:season:%lld:player:%s:industrial_capacity",sid,addr);printf("industrial_capacity=%lld\n",generals_db_ll(c,k,0));return 0;}
static int generals_player_info_cmd(const char*c,const char*addr){char k[1024],v[1024];if(!generals_player_exists(c,addr))die("Generals player not found");const char*fs[]={"status","player_id","wallet","general_asset","display_name","joined_height","join_tx","clan_id","current_season_id",NULL};for(int i=0;fs[i];i++){generals_player_key(k,sizeof(k),addr,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}long long h=current_height_from_chain(c),base=0,e=generals_energy_at(c,addr,h,&base);printf("energy=%lld\nenergy_height=%lld\n",e,base);return 0;}
static int generals_treasury_info_cmd(const char*c){char v[1024];long long bal=generals_treasury_balance(c),res=generals_treasury_reserved(c);printf("balance_atoms=%lld\n",bal);printf("balance_qub=%.8f\n",(double)bal/100000000.0);printf("reserved_atoms=%lld\navailable_atoms=%lld\n",res,bal>=res?bal-res:0);const char*fs[]={"last_height","last_tx","last_source",NULL};for(int i=0;fs[i];i++){char k[256];snprintf(k,sizeof(k),"generals:treasury:%s",fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_clan_info_cmd(const char*c,const char*clan){char k[1024],v[1024];snprintf(k,sizeof(k),"generals:clan:%s:status",clan);if(generals_db_get(c,k,v,sizeof(v))!=0)die("Generals clan not found");const char*fs[]={"status","name","tag","founder","leader","officer:1","officer:2","officer:3","created_height","created_tx","member_count",NULL};printf("clan_id=%s\n",clan);for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:clan:%s:%s",clan,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}

static int generals_clan_directive_info_cmd(const char*c,const char*clan,long long sid){char k[1024],v[1024];printf("clan_id=%s\nseason_id=%lld\n",clan,sid);const char*fs[]={"type","x","y","issuer","expires_height","tx",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:season:%lld:clan:%s:directive:%s",sid,clan,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_clan_invite_info_cmd(const char*c,const char*iid){char k[1024],v[1024];snprintf(k,sizeof(k),"generals:clan_invite:%s:status",iid);if(generals_db_get(c,k,v,sizeof(v))!=0)die("Generals clan invite not found");printf("invite_id=%s\n",iid);const char*fs[]={"status","clan_id","inviter","invitee","created_height","expiry_height","created_tx","resolved_height","resolved_tx",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:clan_invite:%s:%s",iid,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_season_info_cmd(const char*c,long long at){long long h=at>=0?at:current_height_from_chain(c),sid=0,ss=0,se=0,turn=0,ts=0,te=0;if(generals_season_at(c,h,&sid,&ss,&se,&turn,&ts,&te)!=0)die("Generals season not active at height");char k[1024];snprintf(k,sizeof(k),"generals:season:%lld:prize_pool_atoms",sid);long long pool=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid);long long pc=generals_db_ll(c,k,0);printf("height=%lld\nseason_id=%lld\nstart_height=%lld\nend_height=%lld\nturn_id=%lld\nturn_start_height=%lld\nturn_end_height=%lld\nplayer_count=%lld\nprize_pool_atoms=%lld\nprize_pool_qub=%.8f\n",h,sid,ss,se,turn,ts,te,pc,pool,(double)pool/100000000.0);return 0;}
static int generals_energy_info_cmd(const char*c,const char*addr,long long at){if(!generals_player_exists(c,addr))die("Generals player not found");long long h=at>=0?at:current_height_from_chain(c),base=0,e=generals_energy_at(c,addr,h,&base),sid=0,ss=0,se=0,turn=0,ts=0,te=0;printf("height=%lld\nenergy=%lld\nenergy_height=%lld\nenergy_max=%lld\nregen_blocks=%lld\nregen_amount=%lld\n",h,e,base,qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_max",100),qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_regen_blocks",6),qrx_chain_get_ll_at_height_or_default(c,h,"generals_energy_regen_amount",1));if(generals_season_at(c,h,&sid,&ss,&se,&turn,&ts,&te)==0)printf("season_id=%lld\nturn_id=%lld\n",sid,turn);return 0;}
static int generals_player_army_info_cmd(const char*c,const char*addr,long long requested_sid){if(!generals_player_exists(c,addr))die("Generals player not found");long long sid=requested_sid;char k[1024],v[256];if(sid<=0){generals_player_key(k,sizeof(k),addr,"current_season_id");if(generals_db_get(c,k,v,sizeof(v))!=0||!(sid=atoll(v)))die("player has no current season");}snprintf(k,sizeof(k),"generals:season:%lld:player:%s:unit_count",sid,addr);long long count=generals_db_ll(c,k,0);printf("season_id=%lld\nunit_count=%lld\n",sid,count);for(long long i=0;i<count;i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:unit:%lld",sid,addr,i);printf("unit_%lld=%s\n",i,generals_db_get(c,k,v,sizeof(v))==0?v:"");}snprintf(k,sizeof(k),"generals:season:%lld:player:%s:hq_unit",sid,addr);printf("hq_unit=%s\n",generals_db_get(c,k,v,sizeof(v))==0?v:"");snprintf(k,sizeof(k),"generals:season:%lld:player:%s:support_unit_count",sid,addr);long long sc=generals_db_ll(c,k,0);printf("support_unit_count=%lld\n",sc);for(long long i=0;i<sc;i++){snprintf(k,sizeof(k),"generals:season:%lld:player:%s:support_unit:%lld",sid,addr,i);printf("support_unit_%lld=%s\n",i,generals_db_get(c,k,v,sizeof(v))==0?v:"");}snprintf(k,sizeof(k),"generals:season:%lld:player:%s:army_unit_count",sid,addr);printf("army_unit_count=%lld\n",generals_db_ll(c,k,count+sc));return 0;}
static int generals_world_plan_cmd(long long players){if(players<1)die("players must be positive");long long side=generals_world_side_for_players(players),cs=64;printf("players=%lld\nworld_width=%lld\nworld_height=%lld\nchunk_size=%lld\nchunks_x=%lld\nchunks_y=%lld\n",players,side,side,cs,(side+cs-1)/cs,(side+cs-1)/cs);return 0;}
static int generals_world_info_cmd(const char*c,long long at){long long h=at>=0?at:current_height_from_chain(c),sid=0,ss=0,se=0,turn=0,ts=0,te=0;if(generals_season_at(c,h,&sid,&ss,&se,&turn,&ts,&te)!=0)die("Generals season not active");int reveal=0;long long a=0,b=0;if(generals_order_phase(c,h,&a,&b,&reveal)!=0)die("Generals turn unavailable");char k[256];snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid);long long pc=generals_db_ll(c,k,0),w=0,hh=0;generals_world_dims(c,sid,pc,&w,&hh);long long cs=generals_season_chunk_size(c,sid,h);printf("height=%lld\nseason_id=%lld\nturn_id=%lld\nworld_width=%lld\nworld_height=%lld\nchunk_size=%lld\nchunks_x=%lld\nchunks_y=%lld\nhq_min_distance=%lld\nplayer_count=%lld\norder_phase=%s\nturn_start_height=%lld\nturn_end_height=%lld\n",h,sid,turn,w,hh,cs,(w+cs-1)/cs,(hh+cs-1)/cs,qrx_chain_get_ll_at_height_or_default(c,h,"generals_hq_min_distance",16),pc,reveal?"REVEAL":"COMMIT",ts,te);return 0;}
static int generals_unit_info_cmd(const char*c,const char*uid){char k[1024],v[1024];snprintf(k,sizeof(k),"generals:unit:%s:status",uid);if(generals_db_get(c,k,v,sizeof(v))!=0)die("Generals unit not found");printf("unit_id=%s\n",uid);const char*fs[]={"status","type","owner","general","season_id","x","y","hp","move_range","move_energy","last_move_turn","last_move_tx","last_attack_turn","last_attack_tx","march_status","march_target_x","march_target_y","march_cursor",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:unit:%s:%s",uid,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_order_info_cmd(const char*c,const char*oid){char k[1024],v[1024];snprintf(k,sizeof(k),"generals:order:%s:status",oid);if(generals_db_get(c,k,v,sizeof(v))!=0)die("Generals order not found");printf("order_id=%s\n",oid);const char*fs[]={"status","owner","commitment","season_id","turn_id","commit_height","commit_tx","reveal_height","reveal_tx","unit_id","to_x","to_y",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:order:%s:%s",oid,fs[i]);printf("%s=%s\n",fs[i],generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_unit_class_info_cmd(const char*t){const GeneralsUnitClass*c=generals_class(t);if(!c)die("unknown Generals unit class");printf("type=%s\nhp=%lld\nmove_points=%lld\nmove_energy=%lld\nattack=%lld\ndefense=%lld\nmin_range=%lld\nmax_range=%lld\nattack_energy=%lld\ncooldown_turns=%lld\nvision=%lld\ncan_capture=%lld\n",c->name,c->hp,c->move,c->move_energy,c->attack,c->defense,c->min_range,c->max_range,c->attack_energy,c->cooldown,c->vision,c->capture);return 0;}
static int generals_combat_info_cmd(const char*c,long long sid,long long turn,const char*target){char k[1024],v[256];printf("season_id=%lld\nturn_id=%lld\ntarget_unit_id=%s\n",sid,turn,target);snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:status",sid,turn,target);printf("status=%s\n",generals_db_get(c,k,v,sizeof(v))==0?v:"");snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:damage",sid,turn,target);printf("pending_damage=%lld\n",generals_db_ll(c,k,0));return 0;}
static int generals_tile_info_cmd(const char*c,long long sid,long long x,long long y){long long w=0,hh=0;generals_world_dims(c,sid,1,&w,&hh);if(x<0||y<0||x>=w||y>=hh)die("tile outside Generals world");char occ[256]={0};generals_tile_occupied(c,sid,x,y,occ,sizeof(occ));long long cs=generals_season_chunk_size(c,sid,0);char owner[256]={0};generals_territory_owner(c,sid,x,y,owner,sizeof(owner));printf("season_id=%lld\nx=%lld\ny=%lld\nchunk_x=%lld\nchunk_y=%lld\nlocal_x=%lld\nlocal_y=%lld\nterrain=%s\nunit_id=%s\nterritory_owner=%s\n",sid,x,y,x/cs,y/cs,x%cs,y%cs,generals_terrain(sid,x,y),occ,owner);return 0;}

static int generals_region_info_cmd(const char*c,long long sid,long long x0,long long y0,long long w,long long h){
 if(w<1||h<1||w*h>1024)die("region too large"); long long ww=0,hh=0;generals_world_dims(c,sid,1,&ww,&hh);printf("format=qrx-generals-region-v1\nseason_id=%lld\n",sid);
 for(long long y=y0;y<y0+h;y++)for(long long x=x0;x<x0+w;x++){if(x<0||y<0||x>=ww||y>=hh)continue;char occ[256]={0},own[256]={0};generals_tile_occupied(c,sid,x,y,occ,sizeof(occ));generals_territory_owner(c,sid,x,y,own,sizeof(own));GeneralsStrategicFeature f=generals_strategic_feature(sid,x,y);printf("tile=%lld,%lld,%s,%s,%s,%s\n",x,y,generals_terrain(sid,x,y),occ,own,f.type); } return 0;
}
static int generals_season_result_info_cmd(const char*c,long long sid){char k[1024],v[512],winner[512]={0};printf("season_id=%lld\n",sid);const char*fs[]={"status","winner","winner_score","finalized_height","finalized_tx","prize_pool_atoms","reward_player_pool_atoms","reward_clan_pool_atoms","reward_recipient_count","reward_total_atoms",NULL};for(int i=0;fs[i];i++){snprintf(k,sizeof(k),"generals:season:%lld:%s",sid,fs[i]);int ok=generals_db_get(c,k,v,sizeof(v))==0;printf("%s=%s\n",fs[i],ok?v:"");if(ok&&!strcmp(fs[i],"winner"))snprintf(winner,sizeof(winner),"%s",v);}if(winner[0]){snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:atoms",sid,winner);printf("reward_atoms=%lld\n",generals_db_ll(c,k,0));snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:status",sid,winner);printf("reward_status=%s\n",generals_db_get(c,k,v,sizeof(v))==0?v:"");}return 0;}
static int generals_season_rewards_info_cmd(const char*c,long long sid){
 char k[1024],v[512];snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid);long long n=generals_db_ll(c,k,0);printf("season_id=%lld\nplayer_count=%lld\n",sid,n);
 for(long long r=1;r<=n&&r<=1000;r++){char a[256]={0},cl[256]={0};snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:player",sid,r);if(generals_db_get(c,k,a,sizeof(a)))continue;snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:score",sid,r);long long sc=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:reward_atoms",sid,r);long long rew=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:rank:%lld:clan_id",sid,r);if(generals_db_get(c,k,cl,sizeof(cl)))cl[0]=0;snprintf(k,sizeof(k),"generals:season:%lld:reward:%s:status",sid,a);const char*st=generals_db_get(c,k,v,sizeof(v))==0?v:"";printf("rank_%lld=%s,%lld,%lld,%s,%s\n",r,a,sc,rew,cl,st);}
 return 0;
}
static int generals_clan_ranking_info_cmd(const char*c,long long sid){
 char k[1024],id[256];printf("season_id=%lld\n",sid);for(long long r=1;r<=3;r++){snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:clan_id",sid,r);if(generals_db_get(c,k,id,sizeof(id)))continue;snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:score",sid,r);long long sc=generals_db_ll(c,k,0);snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:award_atoms",sid,r);long long aw=generals_db_ll(c,k,0);printf("clan_%lld=%s,%lld,%lld\n",r,id,sc,aw);snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:leader",sid,r);char leader[256]={0};generals_db_get(c,k,leader,sizeof(leader));snprintf(k,sizeof(k),"generals:season:%lld:clan_rank:%lld:command_atoms",sid,r);long long ca=generals_db_ll(c,k,0);printf("clan_%lld_leader=%s\nclan_%lld_command_atoms=%lld\n",r,leader,r,ca);}return 0;
}
static int generals_ranking_info_cmd(const char*c,long long sid){char k[1024],a[256];snprintf(k,sizeof(k),"generals:season:%lld:player_count",sid);long long n=generals_db_ll(c,k,0);printf("season_id=%lld\nplayer_count=%lld\n",sid,n);for(long long i=0;i<n&&i<1000;i++){snprintf(k,sizeof(k),"generals:season:%lld:player_index:%lld",sid,i);if(generals_db_get(c,k,a,sizeof(a)))continue;printf("player_%lld=%s,%lld\n",i,a,generals_player_total_score(c,sid,a));}return 0;}

/* Phase 7.2.10: consensus-native staking/delegation state.
   QRXDB keys are authoritative; legacy staking files are compatibility mirrors only. */
static long long staking_db_ll(const char *chain_dir,const char *key,long long defv){
    QrxDB db; char b[128]; if(qrxdb_init(&db,chain_dir)!=0)return defv;
    int rc=qrxdb_get(&db,key,b,sizeof(b)); qrxdb_close(&db); return rc==0?atoll(b):defv;
}
static int staking_db_ll_found(const char *chain_dir,const char *key,long long *out){
    QrxDB db; char b[128]; if(out)*out=0; if(qrxdb_init(&db,chain_dir)!=0)return 0;
    int rc=qrxdb_get(&db,key,b,sizeof(b)); qrxdb_close(&db); if(rc!=0)return 0; if(out)*out=atoll(b); return 1;
}
static long long staking_claim_amount(const char*c,const char*from,const char*to,const char*t,long long h){
    char k[1024]; long long maturity=LLONG_MAX,amount=0;
    if(!strcmp(t,"STAKE_CLAIM")){
        snprintf(k,sizeof(k),"staking:unbonding_maturity:%s",from); maturity=staking_db_ll(c,k,LLONG_MAX);
        snprintf(k,sizeof(k),"staking:unbonding:%s",from); amount=staking_db_ll(c,k,0);
    } else if(!strcmp(t,"DELEGATE_CLAIM")){
        snprintf(k,sizeof(k),"staking:undelegating_maturity:%s:%s",from,to); maturity=staking_db_ll(c,k,LLONG_MAX);
        snprintf(k,sizeof(k),"staking:undelegating:%s:%s",from,to); amount=staking_db_ll(c,k,0);
    }
    if(amount<=0 || h<maturity) return 0; return amount;
}
static int staking_put_ll(QrxDBBatch*b,const char*key,long long v){return velocity_batch_put_ll(b,key,v);}
static int atomic_stage_staking(QrxDBBatch*b,const char*c,const char*from,const char*to,const char*t,const char*p,const char*txid,long long h,long long amount){
    char k[1024]; long long cur=0,next=0;
    if(!strcmp(t,"STAKE_BOND")){
        if(amount<=0)return -1; snprintf(k,sizeof(k),"staking:self:%s",from);cur=staking_db_ll(c,k,0);checked_add_ll(cur,amount,"self stake",&next);return staking_put_ll(b,k,next);
    }
    if(!strcmp(t,"STAKE_UNBOND")){
        if(amount<=0)return -1; snprintf(k,sizeof(k),"staking:self:%s",from);cur=staking_db_ll(c,k,0);
        long long principal=0,lockh=0,floor=0;
        if(bootstrap_validator_lock_info(c,from,&principal,&lockh) && h<lockh) floor=principal;
        if(cur-amount<floor)return -1;
        if(staking_put_ll(b,k,cur-amount))return -1; snprintf(k,sizeof(k),"staking:unbonding:%s",from);
        long long ub=staking_db_ll(c,k,0);checked_add_ll(ub,amount,"unbonding",&next);if(staking_put_ll(b,k,next))return -1;
        snprintf(k,sizeof(k),"staking:unbonding_maturity:%s",from);return staking_put_ll(b,k,h+qrx_chain_get_ll_at_height_or_default(c,h+1,"staking_unbonding_blocks",120));
    }
    if(!strcmp(t,"STAKE_CLAIM")){
        snprintf(k,sizeof(k),"staking:unbonding_maturity:%s",from);if(h<staking_db_ll(c,k,LLONG_MAX))return -1;
        snprintf(k,sizeof(k),"staking:unbonding:%s",from);cur=staking_db_ll(c,k,0);if(cur<=0)return -1;
        if(staking_put_ll(b,k,0))return -1; snprintf(k,sizeof(k),"staking:unbonding_maturity:%s",from); return staking_put_ll(b,k,0);
    }
    if(!strcmp(t,"DELEGATE_BOND")){
        if(amount<=0||!to||!strcmp(from,to))return -1;
        if(!validator_has_min_self_stake_at(c,to,h+1) || validator_is_tombstoned(c,to) || validator_is_jailed_now(c,to) || validator_is_safely_paused(c,to) || validator_is_compute_jailed_at(c,to,h+1)) return -1;
        snprintf(k,sizeof(k),"staking:delegation:%s:%s",from,to);cur=staking_db_ll(c,k,0);checked_add_ll(cur,amount,"delegation",&next);if(staking_put_ll(b,k,next))return -1;
        snprintf(k,sizeof(k),"staking:delegated_total:%s",to);cur=staking_db_ll(c,k,0);checked_add_ll(cur,amount,"delegated total",&next);return staking_put_ll(b,k,next);
    }
    if(!strcmp(t,"DELEGATE_UNBOND")){
        if(amount<=0)return -1;snprintf(k,sizeof(k),"staking:delegation:%s:%s",from,to);cur=staking_db_ll(c,k,0);if(cur<amount)return -1;
        if(staking_put_ll(b,k,cur-amount))return -1;snprintf(k,sizeof(k),"staking:delegated_total:%s",to);long long tot=staking_db_ll(c,k,0);if(tot<amount)return -1;if(staking_put_ll(b,k,tot-amount))return -1;
        snprintf(k,sizeof(k),"staking:undelegating:%s:%s",from,to);long long ud=staking_db_ll(c,k,0);checked_add_ll(ud,amount,"undelegating",&next);if(staking_put_ll(b,k,next))return -1;
        snprintf(k,sizeof(k),"staking:undelegating_maturity:%s:%s",from,to);return staking_put_ll(b,k,h+qrx_chain_get_ll_at_height_or_default(c,h+1,"delegation_unbonding_blocks",120));
    }
    if(!strcmp(t,"DELEGATE_CLAIM")){
        snprintf(k,sizeof(k),"staking:undelegating_maturity:%s:%s",from,to);if(h<staking_db_ll(c,k,LLONG_MAX))return -1;
        snprintf(k,sizeof(k),"staking:undelegating:%s:%s",from,to);cur=staking_db_ll(c,k,0);if(cur<=0)return -1;
        if(staking_put_ll(b,k,0))return -1;snprintf(k,sizeof(k),"staking:undelegating_maturity:%s:%s",from,to);return staking_put_ll(b,k,0);
    }
    if(!strcmp(t,"VALIDATOR_PAUSE")){
        if(!validator_has_min_self_stake_at(c,from,h+1) || validator_is_tombstoned(c,from)) return -1;
        snprintf(k,sizeof(k),"staking:validator_paused:%s",from);
        if(staking_db_ll(c,k,0)==1) return -1;
        return staking_put_ll(b,k,1);
    }
    if(!strcmp(t,"VALIDATOR_RESUME")){
        if(!validator_has_min_self_stake_at(c,from,h+1) || validator_is_tombstoned(c,from)) return -1;
        snprintf(k,sizeof(k),"staking:validator_paused:%s",from);
        if(staking_db_ll(c,k,0)!=1) return -1;
        /* Runtime catch-up gate still prevents signing until peers/head/stability checks pass. */
        return staking_put_ll(b,k,0);
    }
    (void)p;(void)txid;return -1;
}

static int applytx_cmd(const char *chain_dir, const char *tx_file) {
    /* Finish any native order whose transaction was durably committed before a
       previous process died during post-commit matching/mirroring. The pending
       marker itself is part of the authoritative QRXDB state. */
    velocity_process_pending_matches(chain_dir);
    velocity_process_pending_crosschain_matches(chain_dir);

    char *tx = read_file(tx_file, NULL); if (!tx) die("cannot read tx");
    if (verify_tx_text(chain_dir, tx) != 0) die("verify failed");
    char *tx_version = cfg_get(tx, "tx_version"); int is_velocity = tx_version && atoi(tx_version) == QRX_VELOCITY_TX_VERSION;
    char *tx_type = cfg_get(tx, "tx_type"); char *lane_id = cfg_get(tx, "lane_id"); char *payload_apply = cfg_get(tx, "payload");
    char *from = cfg_get(tx, "from"); char *to = cfg_get(tx, "to"); char *amount = cfg_get(tx, "amount"); char *fee_s = cfg_get(tx, "fee"); char *nonce = cfg_get(tx, "nonce"); char *timestamp = cfg_get(tx, "timestamp");
    char *body_hash_sha3 = cfg_get(tx, "body_hash_sha3_512"); char *body_hash_legacy = cfg_get(tx, "body_hash"); const char *body_hash = body_hash_sha3 ? body_hash_sha3 : body_hash_legacy;
    long long lane = 0; if (is_velocity && velocity_parse_lane(lane_id, &lane) != 0) die("invalid lane_id");
    int is_agent_tx = is_velocity && tx_type && (!strcmp(tx_type, "AGENT_REGISTER") || !strcmp(tx_type, "AGENT_UPDATE") || !strcmp(tx_type, "AGENT_REVOKE"));
    int is_trade_tx = is_velocity && tx_type && (!strcmp(tx_type, "ORDER_CREATE") || !strcmp(tx_type, "ORDER_CANCEL") || !strcmp(tx_type, "ORDER_REPLACE") || !strcmp(tx_type, "EXTERNAL_ORDER"));
    int is_gateway_tx = is_velocity && tx_type && (!strcmp(tx_type,"GATEWAY_REGISTER") || !strcmp(tx_type,"GATEWAY_REVOKE"));
    int is_execution_report = is_velocity && tx_type && !strcmp(tx_type,"EXECUTION_REPORT");
    int is_crosschain_order = is_velocity && tx_type && !strcmp(tx_type,"CROSSCHAIN_ORDER");
    int is_crosschain_action = is_velocity && tx_type && (!strcmp(tx_type,"CROSSCHAIN_REDEEM") || !strcmp(tx_type,"CROSSCHAIN_REFUND"));
    int is_btc_spv_header = is_velocity && tx_type && !strcmp(tx_type,"BTC_SPV_HEADER");
    int is_btc_spv_proof = is_velocity && tx_type && !strcmp(tx_type,"BTC_SPV_FUNDING_PROOF");
    int is_asset76_tx = is_velocity && tx_type && (!strncmp(tx_type,"ASSET_",6));
    int is_protocol_gov_tx = is_velocity && tx_type && !strcmp(tx_type,"GOVERNANCE_PROTOCOL");
    int is_privacy_tx = is_velocity && tx_type && (!strncmp(tx_type,"PRIVACY_",8));
    int is_privacy_shield = is_privacy_tx && !strcmp(tx_type,"PRIVACY_SHIELD");
    int is_privacy_unshield = is_privacy_tx && !strcmp(tx_type,"PRIVACY_UNSHIELD");
    int is_generals_tx = is_velocity && tx_type && (!strncmp(tx_type,"GAME_",5));
    int is_staking_tx = is_velocity && tx_type && (!strncmp(tx_type,"STAKE_",6) || !strncmp(tx_type,"DELEGATE_",9) || !strncmp(tx_type,"VALIDATOR_",10));
    int is_storage_tx = is_velocity && tx_type && !strncmp(tx_type,"STORAGE_",8);
    int is_domain_tx = is_velocity && tx_type && !strncmp(tx_type,"DOMAIN_",7);
    int is_ad_tx = is_velocity && tx_type && !strncmp(tx_type,"AD_",3);
    int is_qrxnet_tx = is_domain_tx || is_ad_tx;
    int is_compute_pipeline_tx = is_velocity && qrx_compute_pipeline_tx_type(tx_type);
    int is_compute_identity_tx = is_velocity && qrx_compute_identity_tx_type(tx_type);
    int is_pouc_tx = is_velocity && tx_type && !strcmp(tx_type,"POUC_SETTLEMENT");
    int is_transfer = !is_compute_pipeline_tx && !is_compute_identity_tx && !is_pouc_tx && !is_agent_tx && !is_trade_tx && !is_gateway_tx && !is_execution_report && !is_crosschain_order && !is_crosschain_action && !is_btc_spv_header && !is_btc_spv_proof && !is_asset76_tx && !is_protocol_gov_tx && !is_privacy_tx && !is_generals_tx && !is_staking_tx && !is_storage_tx && !is_qrxnet_tx;
    if (is_velocity && !is_compute_pipeline_tx && !is_compute_identity_tx && !is_pouc_tx && !is_agent_tx && !is_trade_tx && !is_gateway_tx && !is_execution_report && !is_crosschain_order && !is_crosschain_action && !is_btc_spv_header && !is_btc_spv_proof && !is_asset76_tx && !is_protocol_gov_tx && !is_privacy_tx && !is_generals_tx && !is_staking_tx && !is_storage_tx && !is_qrxnet_tx && (!tx_type || strcmp(tx_type, "TRANSFER_FAST") != 0)) die("velocity execution not active for this tx_type");
    if (!from || !*from || !to || !*to || !body_hash || !*body_hash) die("invalid tx addresses/hash");
    if((is_trade_tx || is_crosschain_order) && !strcmp(from,to)) die("trading agent must use a distinct delegated address from the owner wallet");

    long long amt = is_transfer ? parse_positive_ll_strict(amount, "amount") : parse_nonnegative_ll_strict(amount, "amount");
    long long fee = fee_s ? parse_nonnegative_ll_strict(fee_s, "fee") : 0; long long n = parse_positive_ll_strict(nonce, "nonce");
    long long height=current_height_from_chain(chain_dir);
    QrxServiceEconomicEffect service_effect={0};
    if(is_storage_tx){if(!qrx_storage_protocol_enabled_at_height(chain_dir,height+1)&&!qrx_storage_preflight_tx_type(tx_type))die("DRIVE_V1 mandatory protocol upgrade not active (provider preflight only)");if(qrx_storage_consensus_prepare(chain_dir,tx_type,from,to,(uint64_t)amt,payload_apply,body_hash,(uint64_t)(height+1),&service_effect)!=0)die("storage consensus prepare failed");}
    if(is_qrxnet_tx){if(!qrx_net_protocol_enabled_at_height(chain_dir,height+1))die("QRX_NET_V1 mandatory protocol upgrade not active");if(is_ad_tx&&!qrx_advertising_protocol_enabled_at_height(chain_dir,height+1))die("ADVERTISING_V1 mandatory protocol upgrade not active");if(qrx_net_consensus_prepare(chain_dir,tx_type,from,to,(uint64_t)amt,payload_apply,body_hash,(uint64_t)(height+1),&service_effect)!=0)die(is_ad_tx?"QRX advertising consensus prepare failed":"QRX-Net consensus prepare failed");}
    QrxPoucPipelineEffect compute_effect={0};
    if(is_compute_pipeline_tx){QrxDB cdb;if(!qrx_compute_pouc_protocol_enabled_at_height(chain_dir,height+1))die("COMPUTE_POUC_V1 mandatory protocol upgrade not active");if(qrxdb_init(&cdb,chain_dir)!=0)die("Compute pipeline QRXDB init failed");int crc=qrx_pouc_pipeline_prepare(&cdb,tx_type,from,to,(uint64_t)amt,payload_apply,(uint64_t)(height+1),&compute_effect);qrxdb_close(&cdb);if(crc!=0)die("Compute pipeline prepare failed");}
    if(is_compute_identity_tx){QrxDB idb;QrxServiceEconomicEffect ie={0};/* identity bind is preflight-safe before rewards */if(qrxdb_init(&idb,chain_dir)!=0)die("Compute provider identity QRXDB init failed");int irc=qrx_compute_provider_identity_prepare(&idb,tx_type,from,to,(uint64_t)amt,payload_apply,(uint64_t)(height+1),&ie);qrxdb_close(&idb);if(irc!=0)die("Compute provider identity prepare failed");}
    QrxPoucConsensusEffect pouc_effect={0};
    if(is_pouc_tx){QrxDB pdb;char *cid=chain_cfg_value(chain_dir,"chain_id"),*gh=chain_cfg_value(chain_dir,"genesis_hash"),*pv=chain_cfg_value(chain_dir,"protocol_version");if(!cid||!*cid||!gh||!*gh||!pv||!*pv)die("PoUC chain binding missing");if(qrxdb_init(&pdb,chain_dir)!=0)die("PoUC QRXDB init failed");if(!qrx_compute_pouc_protocol_enabled_at_height(chain_dir,height+1))die("COMPUTE_POUC_V1 mandatory protocol upgrade not active");int prc=qrx_pouc_consensus_prepare(&pdb,cid,gh,pv,tx_type,from,to,(uint64_t)amt,payload_apply,1,(uint64_t)(height+1),&pouc_effect);qrxdb_close(&pdb);free(cid);free(gh);free(pv);if(prc!=0)die("PoUC settlement prepare failed");}
    long long asset_burn=is_asset76_tx?a76_operation_burn(chain_dir,tx_type,payload_apply,height+1):0;if(asset_burn<0)die("invalid asset burn fee");
    long long generals_cost=is_generals_tx?generals_operation_cost(chain_dir,tx_type,payload_apply,height+1,amt):0;if(is_generals_tx&&generals_cost<0)die("invalid Generals operation cost");
    long long debit = 0,tmp_debit=0,tmp_debit2=0,tmp_debit3=0; checked_add_ll((is_transfer || is_privacy_shield || (is_staking_tx && tx_type && (!strcmp(tx_type,"STAKE_BOND") || !strcmp(tx_type,"DELEGATE_BOND")))) ? amt : 0, fee, "amount plus fee", &tmp_debit);checked_add_ll(tmp_debit,asset_burn,"amount plus fee plus asset burn",&tmp_debit2);checked_add_ll(tmp_debit2,generals_cost,"amount plus fee plus asset burn plus Generals treasury contribution",&tmp_debit3);checked_add_ll(tmp_debit3,(long long)service_effect.debit_atoms,"service debit",&debit);if(compute_effect.debit_atoms){long long d2=0;checked_add_ll(debit,(long long)compute_effect.debit_atoms,"compute escrow funding debit",&d2);debit=d2;}
    long long current_nonce = velocity_get_lane_nonce(chain_dir, from, lane); if (current_nonce == LLONG_MAX) die("nonce overflow"); if (n != current_nonce + 1) die("invalid nonce: expected lane nonce + 1");

    long long frombal=qrx_balance_get_authoritative(chain_dir,from),tobal=qrx_balance_get_authoritative(chain_dir,to),new_frombal=0,new_tobal=tobal;
    if(frombal<debit) die("insufficient funds");
    long long staking_claim_credit=0;
    if(is_staking_tx && tx_type && (!strcmp(tx_type,"STAKE_CLAIM")||!strcmp(tx_type,"DELEGATE_CLAIM"))){
        staking_claim_credit=staking_claim_amount(chain_dir,from,to,tx_type,height);
        if(staking_claim_credit<=0) die("staking/delegation claim is not matured or already claimed");
    }
    long long generals_reward_payout=(is_generals_tx&&tx_type&&!strcmp(tx_type,"GAME_REWARD_CLAIM"))?generals_claimable_reward(chain_dir,from,payload_apply):0;
    if(is_generals_tx&&tx_type&&!strcmp(tx_type,"GAME_REWARD_CLAIM")&&generals_reward_payout<=0)die("no claimable Generals reward");
    if(is_transfer && !strcmp(from,to)){
        /* Self transfer must not mint amount back over the sender debit. The
           economic effect is only the fee. Verification still requires the
           wallet to cover amount+fee, preserving the historical admission rule. */
        checked_add_ll(frombal,-fee,"self-transfer fee",&new_frombal);new_tobal=new_frombal;
    }else{
        checked_add_ll(frombal,-debit,"sender balance",&new_frombal);
        if(generals_reward_payout>0) checked_add_ll(new_frombal,generals_reward_payout,"Generals reward payout",&new_frombal);
        if(staking_claim_credit>0) checked_add_ll(new_frombal,staking_claim_credit,"staking/delegation claim",&new_frombal);
        if(is_transfer) checked_add_ll(tobal,amt,"recipient balance",&new_tobal);
    }
    if(is_privacy_unshield){
        if(!strcmp(from,to)){checked_add_ll(new_frombal,amt,"privacy unshield self credit",&new_frombal);new_tobal=new_frombal;}
        else checked_add_ll(tobal,amt,"privacy unshield recipient credit",&new_tobal);
    }
    if(is_compute_pipeline_tx && compute_effect.reward_credit_atoms){
        if(compute_effect.reward_credit_atoms>(uint64_t)LLONG_MAX)die("compute verification reward overflow");
        checked_add_ll(new_frombal,(long long)compute_effect.reward_credit_atoms,"PoUC verifier/challenger reward",&new_frombal);
    }
    if(is_crosschain_action){
        char *sid=payload_get_field(payload_apply,"session_id");
        long long locked=sid?crosschain_get_ll(chain_dir,sid,"qrx_locked_atoms",0):0;
        if(sid)free(sid);
        if(locked<=0)die("cross-chain session has no locked QUB");
        checked_add_ll(new_frombal,locked,"cross-chain QUB release",&new_frombal);
    }
    /* Service credits are staged in the same WAL batch as the service state. */
    long long svc_rec_new=0,svc_dev_new=0; int svc_rec_stage=0,svc_dev_stage=0,svc_to_stage=0; char *svc_dev_addr=NULL;
    if(service_effect.self_credit_atoms) checked_add_ll(new_frombal,(long long)service_effect.self_credit_atoms,"service self credit",&new_frombal);
    if(service_effect.recipient_credit_atoms){
        if(!service_effect.recipient[0])die("service recipient missing");
        if(!strcmp(service_effect.recipient,from)) checked_add_ll(new_frombal,(long long)service_effect.recipient_credit_atoms,"service recipient credit",&new_frombal);
        else if(!strcmp(service_effect.recipient,to)){checked_add_ll(new_tobal,(long long)service_effect.recipient_credit_atoms,"service recipient credit",&new_tobal);svc_to_stage=1;}
        else {long long b=qrx_balance_get_authoritative(chain_dir,service_effect.recipient);checked_add_ll(b,(long long)service_effect.recipient_credit_atoms,"service recipient credit",&svc_rec_new);svc_rec_stage=1;}
    }
    if(service_effect.development_credit_atoms){
        svc_dev_addr=chain_cfg_value(chain_dir,"dev_address"); if(!svc_dev_addr||!*svc_dev_addr)die("development address missing");
        if(!strcmp(svc_dev_addr,from)) checked_add_ll(new_frombal,(long long)service_effect.development_credit_atoms,"development credit",&new_frombal);
        else if(!strcmp(svc_dev_addr,to)){checked_add_ll(new_tobal,(long long)service_effect.development_credit_atoms,"development credit",&new_tobal);svc_to_stage=1;}
        else if(svc_rec_stage && !strcmp(svc_dev_addr,service_effect.recipient)){checked_add_ll(svc_rec_new,(long long)service_effect.development_credit_atoms,"development credit",&svc_rec_new);}
        else {long long b=qrx_balance_get_authoritative(chain_dir,svc_dev_addr);checked_add_ll(b,(long long)service_effect.development_credit_atoms,"development credit",&svc_dev_new);svc_dev_stage=1;}
    }
    /* PoUC payout/refund credits are merged with the ordinary tx fee debit so
       all wallet balances and settlement state land in the same WAL batch. */
    long long pouc_owner_new=0,pouc_dev_new=0;int pouc_owner_stage=0,pouc_dev_stage=0,pouc_to_stage=0;char *pouc_dev_addr=NULL;
    if(is_pouc_tx){
        if(pouc_effect.provider_credit_atoms){if(!strcmp(pouc_effect.provider,from))checked_add_ll(new_frombal,(long long)pouc_effect.provider_credit_atoms,"PoUC provider payout",&new_frombal);else {checked_add_ll(new_tobal,(long long)pouc_effect.provider_credit_atoms,"PoUC provider payout",&new_tobal);pouc_to_stage=1;}}
        if(pouc_effect.owner_credit_atoms){
            if(!strcmp(pouc_effect.owner,from))checked_add_ll(new_frombal,(long long)pouc_effect.owner_credit_atoms,"PoUC owner refund",&new_frombal);
            else if(!strcmp(pouc_effect.owner,to)){checked_add_ll(new_tobal,(long long)pouc_effect.owner_credit_atoms,"PoUC owner refund",&new_tobal);pouc_to_stage=1;}
            else {long long b=qrx_balance_get_authoritative(chain_dir,pouc_effect.owner);checked_add_ll(b,(long long)pouc_effect.owner_credit_atoms,"PoUC owner refund",&pouc_owner_new);pouc_owner_stage=1;}
        }
        if(pouc_effect.development_credit_atoms){
            pouc_dev_addr=chain_cfg_value(chain_dir,"dev_address");if(!pouc_dev_addr||!*pouc_dev_addr)die("PoUC development address missing");
            if(!strcmp(pouc_dev_addr,from))checked_add_ll(new_frombal,(long long)pouc_effect.development_credit_atoms,"PoUC FastTrack development share",&new_frombal);
            else if(!strcmp(pouc_dev_addr,to)){checked_add_ll(new_tobal,(long long)pouc_effect.development_credit_atoms,"PoUC FastTrack development share",&new_tobal);pouc_to_stage=1;}
            else if(pouc_owner_stage&&!strcmp(pouc_dev_addr,pouc_effect.owner))checked_add_ll(pouc_owner_new,(long long)pouc_effect.development_credit_atoms,"PoUC FastTrack development share",&pouc_owner_new);
            else {long long b=qrx_balance_get_authoritative(chain_dir,pouc_dev_addr);checked_add_ll(b,(long long)pouc_effect.development_credit_atoms,"PoUC FastTrack development share",&pouc_dev_new);pouc_dev_stage=1;}
        }
    }
    long long fee_pending=fee_pool_pending(chain_dir),new_fee_pending=0,service_fee_total=0,fee_with_pouc=0;checked_add_ll(fee,(long long)service_effect.protocol_fee_atoms,"fee plus protocol service fee",&service_fee_total);checked_add_ll(service_fee_total,(long long)pouc_effect.network_credit_atoms,"fee plus PoUC network share",&fee_with_pouc);checked_add_ll(fee_pending,fee_with_pouc,"fee pool",&new_fee_pending);

    QrxDB db;QrxDBBatch batch;if(qrxdb_init(&db,chain_dir)!=0)die("QRXDB init failed");if(qrxdb_batch_begin(&db,&batch)!=0){qrxdb_close(&db);die("QRXDB batch begin failed");}
    int brc=0;
    brc|=atomic_batch_put_balance(&batch,from,new_frombal);
    if(((is_transfer || is_privacy_unshield) && strcmp(from,to)) || (svc_to_stage && strcmp(from,to)) || (pouc_to_stage && strcmp(from,to))) brc|=atomic_batch_put_balance(&batch,to,new_tobal);
    if(svc_rec_stage) brc|=atomic_batch_put_balance(&batch,service_effect.recipient,svc_rec_new);
    if(svc_dev_stage) brc|=atomic_batch_put_balance(&batch,svc_dev_addr,svc_dev_new);
    if(pouc_owner_stage) brc|=atomic_batch_put_balance(&batch,pouc_effect.owner,pouc_owner_new);
    if(pouc_dev_stage) brc|=atomic_batch_put_balance(&batch,pouc_dev_addr,pouc_dev_new);
    if(is_agent_tx) brc|=atomic_stage_agent(&batch,from,to,tx_type,payload_apply,body_hash,height);
    if(is_trade_tx) brc|=atomic_stage_trade(&batch,chain_dir,from,to,tx_type,payload_apply,body_hash,height);
    if(is_crosschain_order) brc|=crosschain_stage_order(&batch,chain_dir,from,to,payload_apply,body_hash,height);
    if(is_crosschain_action) brc|=crosschain_stage_action(&batch,chain_dir,from,tx_type,payload_apply,body_hash,height);
    if(is_btc_spv_header) brc|=atomic_stage_btc_spv_header(&db,&batch,chain_dir,payload_apply);
    if(is_btc_spv_proof) brc|=atomic_stage_btc_spv_funding_proof(&batch,chain_dir,from,payload_apply,body_hash,height);
    if(is_gateway_tx) brc|=atomic_stage_gateway(&batch,from,to,tx_type,payload_apply,body_hash,height);
    if(is_asset76_tx) brc|=atomic_stage_asset76(&batch,chain_dir,from,to,tx_type,payload_apply,body_hash,height);
    if(is_protocol_gov_tx) brc|=atomic_stage_privacy(&batch,chain_dir,from,to,tx_type,payload_apply,body_hash,height,amt);
    if(is_privacy_tx) brc|=atomic_stage_privacy(&batch,chain_dir,from,to,tx_type,payload_apply,body_hash,height,amt);
    if(is_generals_tx) brc|=atomic_stage_generals(&batch,chain_dir,from,tx_type,payload_apply,body_hash,height,generals_cost);
    if(is_staking_tx) brc|=atomic_stage_staking(&batch,chain_dir,from,to,tx_type,payload_apply,body_hash,height,amt);
    if(is_storage_tx) brc|=qrx_storage_consensus_stage(&db,&batch,chain_dir,tx_type,from,to,(uint64_t)amt,payload_apply,body_hash,(uint64_t)(height+1));
    if(is_qrxnet_tx) brc|=qrx_net_consensus_stage(&db,&batch,chain_dir,tx_type,from,to,(uint64_t)amt,payload_apply,body_hash,(uint64_t)(height+1));
    if(is_compute_pipeline_tx){
        brc|=qrx_pouc_pipeline_stage(&db,&batch,&compute_effect,body_hash,(uint64_t)(height+1));
        if(compute_effect.reward_credit_atoms) brc|=qrx_pouc_reward_journal_stage(&db,&batch,&compute_effect,body_hash,(uint64_t)(height+1));
    }
    if(is_compute_identity_tx) brc|=qrx_compute_provider_identity_stage(&db,&batch,tx_type,from,to,(uint64_t)amt,payload_apply,(uint64_t)(height+1));
    if(is_pouc_tx) brc|=qrx_pouc_consensus_stage(&db,&batch,&pouc_effect,body_hash,(uint64_t)(height+1));
    if(is_execution_report) brc|=atomic_stage_execution_report(&batch,from,to,payload_apply,body_hash,height);
    brc|=velocity_batch_put_ll(&batch,"consensus:fee_pool:pending",new_fee_pending);
    if(asset_burn>0){long long oldburn=0,newburn=0;QrxDB tdb;if(qrxdb_init(&tdb,chain_dir)==0){char bb[128];if(qrxdb_get(&tdb,"consensus:asset76:burned_qub_atoms",bb,sizeof(bb))==0)oldburn=atoll(bb);qrxdb_close(&tdb);}checked_add_ll(oldburn,asset_burn,"asset burn accumulator",&newburn);brc|=velocity_batch_put_ll(&batch,"consensus:asset76:burned_qub_atoms",newburn);}
    brc|=atomic_batch_put_nonce(&batch,from,lane,n);
    brc|=atomic_batch_put_applied(&batch,body_hash,height);
    const char *kind=is_agent_tx?"velocity-agent":is_crosschain_order?"velocity-crosschain-order":is_crosschain_action?"velocity-crosschain-settlement":is_btc_spv_header?"velocity-btc-spv-header":is_btc_spv_proof?"velocity-btc-spv-funding-proof":is_trade_tx?"velocity-trading-intent":is_gateway_tx?"velocity-gateway":is_execution_report?"velocity-execution-report":is_asset76_tx?"native-asset-consensus":is_protocol_gov_tx?"protocol-governance-consensus":is_privacy_tx?"privacy-consensus":is_generals_tx?"generals-consensus":is_staking_tx?"staking-consensus":is_storage_tx?"storage-consensus":is_qrxnet_tx?"qrxnet-consensus":is_compute_identity_tx?"compute-provider-identity":is_compute_pipeline_tx?"pouc-upstream-consensus":is_pouc_tx?"pouc-settlement-consensus":(is_velocity?"velocity-transfer-fast":"mempool-or-direct-apply");
    brc|=atomic_batch_put_tx_index(&batch,body_hash,kind,height,tx);
    if((is_compute_pipeline_tx||is_compute_identity_tx||is_pouc_tx)&&!brc) brc|=qrx_pouc_tx_undo_stage(&db,&batch,body_hash,tx_type?tx_type:"POUC",(uint64_t)(height+1));
    if(brc){qrxdb_batch_abort(&batch);qrxdb_close(&db);die("atomic state staging failed");}
    if(qrxdb_batch_commit(&batch)!=0){qrxdb_batch_abort(&batch);qrxdb_close(&db);die("atomic WAL commit failed");}
    char state_root[129]={0};qrxdb_merkle_root_hex(&db,state_root);unsigned long long generation=(unsigned long long)qrxdb_generation(&db);qrxdb_close(&db);

    /* Legacy files are compatibility mirrors only from this point onward. They
       are deliberately written after the durable QRXDB commit and are never
       authoritative for consensus validation when a QRXDB value exists. */
    mirror_common_apply_state(chain_dir,from,to,is_transfer,lane,body_hash);
    if(is_agent_tx) mirror_agent_from_authoritative(chain_dir,to);
    if(is_trade_tx) postcommit_trade(chain_dir,from,to,tx_type,payload_apply,body_hash);
    if(is_crosschain_order){ mirror_order_from_authoritative(chain_dir,body_hash); mirror_agent_usage_authoritative(chain_dir,from); {char *a=order_db_get_field(chain_dir,body_hash,"locked_asset"); if(a&&!strcasecmp(a,"QUB")) mirror_asset_authoritative(chain_dir,a,to); free(a);} match_crosschain_order(chain_dir,body_hash); }
    if(is_gateway_tx) mirror_gateway_from_authoritative(chain_dir,to);
    if(is_execution_report){char *oid=payload_get_field(payload_apply,"order_id");if(oid){mirror_order_from_authoritative(chain_dir,oid);free(oid);}}
    if(is_privacy_tx) privacy_mirror_authoritative(chain_dir);

    journal_append(chain_dir, "applytx_atomic generation=%llu state_root=%s height=%lld timestamp=%s tx_version=%s tx_type=%s from=%s to=%s amount=%lld fee=%lld asset_burn=%lld generals_treasury_cost=%lld lane=%lld nonce=%s body_hash=%s", generation,state_root,height,timestamp?timestamp:"0",tx_version?tx_version:"2", tx_type?tx_type:"LEGACY_TRANSFER", from, to, amt, fee, asset_burn, generals_cost, lane, nonce, body_hash);
    printf("APPLIED\nstate_root=%s\nqrxdb_generation=%llu\n",state_root,generation);
    if(svc_dev_addr)free(svc_dev_addr); if(pouc_dev_addr)free(pouc_dev_addr); free(tx); if(tx_version) free(tx_version); if(tx_type) free(tx_type); if(lane_id) free(lane_id); if(payload_apply) free(payload_apply); free(from); free(to); free(amount); if (fee_s) free(fee_s); free(nonce); if(timestamp) free(timestamp); if (body_hash_sha3) free(body_hash_sha3); if (body_hash_legacy) free(body_hash_legacy); return 0;
}

static int node_init_cmd(const char *node_dir, const char *chain_dir, const char *wallet_dir, const char *host, const char *port) {
    mkdir_p(node_dir); char p[1024]; snprintf(p, sizeof(p), "%s/mempool", node_dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/inbox", node_dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/inbox/blocks", node_dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/inbox/votes", node_dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/outbox", node_dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/outbox/votes", node_dir); mkdir_p(p);
    snprintf(p, sizeof(p), "%s/local_votes", node_dir); mkdir_p(p);
    char *network_id = chain_cfg_value(chain_dir, "network_id"); char *genesis_hash = chain_cfg_value(chain_dir, "genesis_hash"); char *protocol_version = chain_cfg_value(chain_dir, "protocol_version"); char *consensus_version = chain_cfg_value(chain_dir, "consensus_version"); char *chain_id = chain_cfg_value(chain_dir, "chain_id"); char *chain_magic = chain_cfg_value(chain_dir, "magic");
    char *address = wallet_address(wallet_dir); if (!address) die("wallet address missing"); address[strcspn(address, "\r\n")]=0;
    const char *magic = (chain_magic && *chain_magic) ? chain_magic : QRX_MAGIC;
    char storage_path[1024]; snprintf(storage_path,sizeof(storage_path),"%s/qrx-drive",node_dir);
    char cfg[6144]; snprintf(cfg, sizeof(cfg),
        "chain_dir=%s\nwallet_dir=%s\nhost=%s\nport=%s\nexternal_host=%s\nexternal_port=%s\nnetwork_id=%s\ngenesis_hash=%s\nprotocol_version=%s\nconsensus_version=%s\nchain_id=%s\nmagic=%s\naddress=%s\nstorage_enabled=0\nstorage_provider_id=%s\nstorage_path=%s\nstorage_max_usage_bytes=0\nstorage_min_free_space_bytes=10737418240\naura_anti_entropy_interval_seconds=15\n",
        chain_dir, wallet_dir, host, port, host, port, network_id, genesis_hash, protocol_version, consensus_version, chain_id, magic, address, address, storage_path);
    snprintf(p, sizeof(p), "%s/node.conf", node_dir); write_text(p, cfg);
    snprintf(p, sizeof(p), "%s/peers.txt", node_dir); write_text(p, "");
    snprintf(p, sizeof(p), "%s/seednodes.txt", node_dir); write_text(p, "");
    snprintf(p, sizeof(p), "%s/known_peers.txt", node_dir); write_text(p, "");
    snprintf(p, sizeof(p), "%s/peer_state.db", node_dir); write_text(p, "");
    snprintf(p, sizeof(p), "%s/bootstrap_cache.txt", node_dir); write_text(p, "");
    free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id); if (chain_magic) free(chain_magic); free(address);
    puts("OK"); return 0;
}
static int unique_append_peerfile(const char *path, const char *host, const char *port) {
    char entry[256]; snprintf(entry, sizeof(entry), "%s:%s", host, port);
    char *txt = read_file(path, NULL);
    if (txt) {
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
            if (len == strlen(entry) && !strncmp(cur, entry, len)) { free(txt); return 0; }
            cur = e ? e+1 : NULL;
        }
        free(txt);
    }
    char line[300]; snprintf(line, sizeof(line), "%s\n", entry);
    return append_text(path, line);
}
static int remember_known_peer(const char *node_dir, const char *host, const char *port) {
    char p[1024]; snprintf(p, sizeof(p), "%s/known_peers.txt", node_dir);
    return unique_append_peerfile(p, host, port);
}
static int peer_endpoint_is_usable(const char *host, const char *port) {
    if (!host || !*host || !port || !*port || strlen(host) > 253) return 0;
    if (!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || !strcmp(host, "[::]") || !strcmp(host, "*")) return 0;
    for (const unsigned char *p=(const unsigned char*)host; *p; ++p)
        if (!(isalnum(*p) || *p=='.' || *p=='-')) return 0;
    char *end=NULL; long n=strtol(port,&end,10);
    return end && *end==0 && n>0 && n<=65535;
}
static int add_peer_cmd(const char *node_dir, const char *host, const char *port) {
    if (!peer_endpoint_is_usable(host, port)) return -1;
    char p[1024]; snprintf(p, sizeof(p), "%s/peers.txt", node_dir);
    if (unique_append_peerfile(p, host, port) != 0) return -1;
    return remember_known_peer(node_dir, host, port);
}
static int add_seed_cmd(const char *node_dir, const char *host, const char *port) {
    if (!peer_endpoint_is_usable(host, port)) return -1;
    char p[1024]; snprintf(p, sizeof(p), "%s/seednodes.txt", node_dir);
    return unique_append_peerfile(p, host, port);
}
static int discover_peers_cmd(const char *node_dir) {
    char seeds[1024], known[1024], peers[1024];
    snprintf(seeds, sizeof(seeds), "%s/seednodes.txt", node_dir);
    snprintf(known, sizeof(known), "%s/known_peers.txt", node_dir);
    snprintf(peers, sizeof(peers), "%s/peers.txt", node_dir);
    int merged = 0;
    for (int pass=0; pass<2; ++pass) {
        char *txt = read_file(pass == 0 ? seeds : known, NULL);
        if (!txt) continue;
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
            if (len > 0) {
                char line[256]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
                char *colon = strrchr(line, ':');
                if (colon) { *colon = 0; if (peer_endpoint_is_usable(line,colon+1) && unique_append_peerfile(peers, line, colon+1) == 0) merged++; }
            }
            cur = e ? e+1 : NULL;
        }
        free(txt);
    }
    printf("merged=%d\n", merged);
    return 0;
}


static int replace_or_append_cfg(const char *path, const char *key, const char *value) {
    char *txt = read_file(path, NULL);
    FILE *f = fopen(path, "wb"); if (!f) { if (txt) free(txt); return -1; }
    size_t klen = strlen(key); bool wrote=false;
    if (txt) {
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
            if (len > klen + 1 && !strncmp(cur, key, klen) && cur[klen] == '=') {
                fprintf(f, "%s=%s\n", key, value); wrote = true;
            } else if (len) {
                fwrite(cur, 1, len, f); fputc('\n', f);
            }
            cur = e ? e+1 : NULL;
        }
        free(txt);
    }
    if (!wrote) fprintf(f, "%s=%s\n", key, value);
    fclose(f); return 0;
}

static int set_external_cmd(const char *node_dir, const char *host, const char *port) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir);
    if (replace_or_append_cfg(p, "external_host", host) != 0) return 1;
    if (replace_or_append_cfg(p, "external_port", port) != 0) return 1;
    puts("OK"); return 0;
}

static int is_private_ipv4(const char *ip) {
    unsigned a,b,c,d; if (sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return 0;
    if (a == 10) return 1;
    if (a == 127) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 169 && b == 254) return 1;
    return 0;
}

static int nat_info_cmd(const char *node_dir) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *host = cfg_get(cfg, "host"), *port = cfg_get(cfg, "port"), *eh = cfg_get(cfg, "external_host"), *ep = cfg_get(cfg, "external_port");
    const char *advh = (eh && *eh) ? eh : host; const char *advp = (ep && *ep) ? ep : port;
    printf("bind=%s:%s\nadvertise=%s:%s\nprivate_bind=%s\nprivate_advertise=%s\n", host, port, advh, advp, is_private_ipv4(host)?"yes":"no", is_private_ipv4(advh)?"yes":"no");
    if (is_private_ipv4(advh)) puts("hint=Set external_host/external_port or port-forward your router for internet peers.");
    else puts("hint=Advertised endpoint looks public.");
    free(cfg); free(host); free(port); if (eh) free(eh); if (ep) free(ep); return 0;
}

static void peer_touch_seen(const char *node_dir, const char *peer, long long ts) {
    char db[1024], key[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir); key_from_ip(key, sizeof(key), peer, "last_seen"); db_set_ll(db, key, ts);
}
static long long peer_last_seen(const char *node_dir, const char *peer) {
    char db[1024], key[320]; snprintf(db, sizeof(db), "%s/peer_state.db", node_dir); key_from_ip(key, sizeof(key), peer, "last_seen"); return db_get_ll(db, key);
}

static int peer_endpoint_is_self(const char *node_dir, const char *host, int port);

static int request_peers_from_peer(const char *node_dir, const char *host, int port, int *added) {
    int fd = connect_to(host, port); if (fd < 0) return -1;
    char *hello = NULL; if (build_hello_message(node_dir, &hello) != 0 || !hello) { free(hello); qrx_close_socket(fd); return -1; } if (send_framed(fd, hello) != 0) { free(hello); qrx_close_socket(fd); return -1; } free(hello);
    char *resp = recv_framed(fd); if (!resp || !strstr(resp, "status=OK")) { free(resp); qrx_close_socket(fd); return -1; } free(resp);
    if (send_framed(fd, "type=GETPEERS\n") != 0) { qrx_close_socket(fd); return -1; }
    resp = recv_framed(fd); if (!resp) { qrx_close_socket(fd); return -1; }
    char *status = cfg_get(resp, "status");
    if (!status || strcmp(status, "OK")) { if (status) free(status); free(resp); qrx_close_socket(fd); return -1; }
    char *peers_b64 = cfg_get(resp, "peers_b64");
    if (added) *added = 0;
    if (peers_b64) {
        size_t blen=0; unsigned char *buf = base64_decode(peers_b64, &blen);
        if (buf) {
            char *txt = malloc(blen+1); memcpy(txt, buf, blen); txt[blen]=0;
            const char *cur = txt;
            while (cur && *cur) {
                const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
                if (len > 0) {
                    char line[256]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
                    char *colon = strrchr(line, ':'); if (colon) { *colon=0; int peer_port=atoi(colon+1); if (peer_endpoint_is_usable(line,colon+1) && !peer_endpoint_is_self(node_dir, line, peer_port) && remember_known_peer(node_dir, line, colon+1) == 0) { char pp[1024]; snprintf(pp, sizeof(pp), "%s/peers.txt", node_dir); unique_append_peerfile(pp, line, colon+1); if (added) (*added)++; } }
                }
                cur = e ? e+1 : NULL;
            }
            free(txt); free(buf);
        }
        free(peers_b64);
    }
    free(status); free(resp); qrx_close_socket(fd); return 0;
}

static int peer_endpoint_is_self(const char *node_dir, const char *host, int port) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/node.conf", node_dir);
    char *cfg = read_file(path, NULL);
    if (!cfg) return 0;
    char *bind_host = cfg_get(cfg, "host");
    char *bind_port = cfg_get(cfg, "port");
    char *external_host = cfg_get(cfg, "external_host");
    char *external_port = cfg_get(cfg, "external_port");
    int is_self = (external_host && external_port && *external_host &&
                   !strcmp(host, external_host) && port == atoi(external_port)) ||
                  (bind_host && bind_port && strcmp(bind_host, "0.0.0.0") &&
                   !strcmp(host, bind_host) && port == atoi(bind_port));
    free(cfg); free(bind_host); free(bind_port); free(external_host); free(external_port);
    return is_self;
}

static int bootstrap_cmd(const char *node_dir) {
    char seeds[1024], known[1024], peers[1024], cache[1024];
    snprintf(seeds, sizeof(seeds), "%s/seednodes.txt", node_dir);
    snprintf(known, sizeof(known), "%s/known_peers.txt", node_dir);
    snprintf(peers, sizeof(peers), "%s/peers.txt", node_dir);
    snprintf(cache, sizeof(cache), "%s/bootstrap_cache.txt", node_dir);
    int contacted = 0, alive = 0, added = 0;
    char attempted[MAX_PEERS * 3][320]; int attempted_count = 0;
    for (int pass=0; pass<3; ++pass) {
        const char *src = pass == 0 ? seeds : (pass == 1 ? known : peers);
        char *txt = read_file(src, NULL); if (!txt) continue;
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
            if (len > 0) {
                char line[256]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
                char *colon = strrchr(line, ':'); if (colon) {
                    *colon = 0; int port = atoi(colon+1);
                    char endpoint[320]; snprintf(endpoint, sizeof(endpoint), "%s:%d", line, port);
                    int duplicate = 0;
                    for (int i=0; i<attempted_count; ++i) if (!strcmp(attempted[i], endpoint)) { duplicate = 1; break; }
                    if (duplicate || !peer_endpoint_is_usable(line,colon+1) || peer_endpoint_is_self(node_dir, line, port)) { cur = e ? e+1 : NULL; continue; }
                    if (attempted_count < (int)(MAX_PEERS * 3)) snprintf(attempted[attempted_count++], sizeof(attempted[0]), "%s", endpoint);
                    contacted++;
                    int local_added = 0;
                    if (request_peers_from_peer(node_dir, line, port, &local_added) == 0) {
                        alive++; added += local_added; remember_known_peer(node_dir, line, colon+1); peer_rep_add(node_dir, line, 1); peer_touch_seen(node_dir, line, (long long)time(NULL));
                    } else {
                        peer_rep_add(node_dir, line, -1);
                    }
                }
            }
            cur = e ? e+1 : NULL;
        }
        free(txt);
    }
    char logline[256]; snprintf(logline, sizeof(logline), "contacted=%d alive=%d added=%d ts=%lld\n", contacted, alive, added, (long long)time(NULL)); append_text(cache, logline);
    printf("contacted=%d\nalive=%d\nadded=%d\n", contacted, alive, added); return 0;
}

static int peer_top_cmd(const char *node_dir, int limit) {
    if (limit < 1) limit = 10; if (limit > 100) limit = 100;
    char known[1024]; snprintf(known, sizeof(known), "%s/known_peers.txt", node_dir); char *txt = read_file(known, NULL); if (!txt) { puts("no known peers"); return 0; }
    struct item { char peer[256]; long long rep; long long seen; } items[256]; int n=0;
    const char *cur = txt;
    while (cur && *cur && n < 256) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
        if (len > 0) {
            if (len >= sizeof(items[n].peer)) len = sizeof(items[n].peer)-1;
            memcpy(items[n].peer, cur, len); items[n].peer[len]=0;
            char host[256]; snprintf(host, sizeof(host), "%s", items[n].peer); char *colon = strrchr(host, ':'); if (colon) *colon = 0;
            items[n].rep = peer_rep_score(node_dir, host); items[n].seen = peer_last_seen(node_dir, host); n++;
        }
        cur = e ? e+1 : NULL;
    }
    free(txt);
    for (int i=0; i<n; ++i) for (int j=i+1; j<n; ++j) if (items[j].rep > items[i].rep || (items[j].rep == items[i].rep && items[j].seen > items[i].seen)) { struct item t = items[i]; items[i]=items[j]; items[j]=t; }
    for (int i=0; i<n && i<limit; ++i) printf("%s rep=%lld last_seen=%lld\n", items[i].peer, items[i].rep, items[i].seen);
    return 0;
}

static int send_framed(int fd, const char *msg) {
    uint32_t n = htonl((uint32_t)strlen(msg));
    if (send(fd, (const char *)&n, 4, 0) != 4) return -1;
    size_t left = strlen(msg); const char *p = msg;
    while (left) { ssize_t w = send(fd, p, left, 0); if (w <= 0) return -1; p += w; left -= (size_t)w; }
    return 0;
}
static char *recv_framed(int fd) {
    uint32_t n; ssize_t r = recv(fd, (char *)&n, 4, MSG_WAITALL); if (r != 4) return NULL; n = ntohl(n); if (n > MAX_MSG) return NULL;
    char *buf = malloc(n+1); if (!buf) return NULL; r = recv(fd, buf, n, MSG_WAITALL); if (r != (ssize_t)n) { free(buf); return NULL; } buf[n]=0; return buf;
}

static char *hello_payload_for_sign(const char *network_id, const char *genesis_hash, const char *protocol_version, const char *consensus_version, const char *chain_id, const char *magic, const char *timestamp, const char *nonce, const char *host, const char *port, const char *pub_hex) {
    size_t cap = strlen(network_id)+strlen(genesis_hash)+strlen(protocol_version)+strlen(consensus_version)+strlen(chain_id)+strlen(magic)+strlen(timestamp)+strlen(nonce)+strlen(host)+strlen(port)+strlen(pub_hex)+320;
    char *s = malloc(cap);
    snprintf(s, cap,
        "type=HELLO\nnetwork_id=%s\ngenesis_hash=%s\nprotocol_version=%s\nconsensus_version=%s\nchain_id=%s\nmagic=%s\ntimestamp=%s\nnonce=%s\nhost=%s\nport=%s\ned25519_pub_hex=%s\n",
        network_id, genesis_hash, protocol_version, consensus_version, chain_id, magic, timestamp, nonce, host, port, pub_hex);
    return s;
}

static void hello_key_cache_clear(void){
    EVP_PKEY_free(g_hello_priv);EVP_PKEY_free(g_hello_pub);g_hello_priv=NULL;g_hello_pub=NULL;OPENSSL_cleanse(g_hello_wallet_dir,sizeof(g_hello_wallet_dir));
}
/* Genesis hardening: build_hello_message() is reachable from the P2P gossip
 * fanout triggered by an incoming peer message
 * (node_handle_client -> aura_gossip_fanout -> aura_gossip_push_to_peer).
 * It previously called die() for purely local conditions such as a locked
 * wallet or a failing passphrase prompt on a headless validator, so a remote
 * peer could trigger daemon termination. It now reports failure to the caller
 * and leaves *out_msg NULL. All callers check the result. */
static int build_hello_message(const char *node_dir, char **out_msg) {
    char path[1024];
    char *cfg=NULL,*wallet_dir=NULL,*network_id=NULL,*genesis_hash=NULL,*protocol_version=NULL;
    char *consensus_version=NULL,*chain_id=NULL,*magic=NULL,*host=NULL,*port=NULL;
    char *external_host=NULL,*external_port=NULL;
    char *pub_hex=NULL,*payload=NULL,*sig_hex=NULL;
    unsigned char *sig=NULL; size_t siglen=0;
    int rc=-1;
    const char *failure=NULL;

    if (out_msg) *out_msg=NULL;
    if (!node_dir || !out_msg) return -1;

    snprintf(path, sizeof(path), "%s/node.conf", node_dir);
    cfg = read_file(path, NULL);
    if (!cfg) { failure="missing node.conf"; goto done; }

    wallet_dir=cfg_get(cfg,"wallet_dir"); network_id=cfg_get(cfg,"network_id");
    genesis_hash=cfg_get(cfg,"genesis_hash"); protocol_version=cfg_get(cfg,"protocol_version");
    consensus_version=cfg_get(cfg,"consensus_version"); chain_id=cfg_get(cfg,"chain_id");
    magic=cfg_get(cfg,"magic"); host=cfg_get(cfg,"host"); port=cfg_get(cfg,"port");
    external_host=cfg_get(cfg,"external_host"); external_port=cfg_get(cfg,"external_port");
    if(!wallet_dir||!network_id||!genesis_hash||!protocol_version||!consensus_version||!chain_id||!magic||!host||!port){
        failure="node.conf incomplete"; goto done;
    }

    if(!g_hello_priv||!g_hello_pub||strcmp(g_hello_wallet_dir,wallet_dir)){
        char pass[256];
        if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) {
            OPENSSL_cleanse(pass,sizeof(pass)); failure="node signing passphrase unavailable"; goto done;
        }
        snprintf(path, sizeof(path), "%s/ed25519_priv.pem", wallet_dir); EVP_PKEY *priv = load_priv_pem(path, pass);
        snprintf(path, sizeof(path), "%s/ed25519_pub.pem", wallet_dir); EVP_PKEY *pub = load_pub_pem(path);
        OPENSSL_cleanse(pass,sizeof(pass));
        if(!priv||!pub){
            EVP_PKEY_free(priv); EVP_PKEY_free(pub);
            failure="load node signing key failed"; goto done;
        }
        hello_key_cache_clear(); g_hello_priv=priv; g_hello_pub=pub;
        snprintf(g_hello_wallet_dir,sizeof(g_hello_wallet_dir),"%s",wallet_dir);
    }

    unsigned char raw[32];
    if (ed25519_raw_pub(g_hello_pub, raw) != 0) { failure="raw pub failed"; goto done; }
    pub_hex = bytes_to_hex(raw, sizeof(raw));
    if (!pub_hex) { failure="pub encode failed"; goto done; }

    char ts[32], nonce[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)time(NULL));
    unsigned char nr[8];
    if (RAND_bytes(nr, sizeof(nr)) != 1) { failure="rng failed"; goto done; }
    for (int i2=0;i2<8;i2++) snprintf(nonce+i2*2, 3, "%02x", nr[i2]);

    {
        const char *adv_host = (external_host && *external_host) ? external_host : host;
        const char *adv_port = (external_port && *external_port) ? external_port : port;
        payload = hello_payload_for_sign(network_id, genesis_hash, protocol_version, consensus_version, chain_id, magic, ts, nonce, adv_host, adv_port, pub_hex);
    }
    if (!payload) { failure="hello payload failed"; goto done; }

    if (sign_oneshot(g_hello_priv, (unsigned char*)payload, strlen(payload), &sig, &siglen) != 0) { failure="hello sign failed"; goto done; }
    sig_hex = bytes_to_hex(sig, siglen);
    if (!sig_hex) { failure="sig encode failed"; goto done; }

    {
        size_t cap = strlen(payload)+strlen(sig_hex)+64;
        *out_msg = malloc(cap);
        if(!*out_msg) { failure="out of memory"; goto done; }
        snprintf(*out_msg, cap, "%ssig_ed25519_hex=%s\n", payload, sig_hex);
    }
    rc=0;

done:
    if (rc != 0 && failure) fprintf(stderr, "hello: %s\n", failure);
    free(cfg); free(wallet_dir); free(network_id); free(genesis_hash); free(protocol_version);
    free(consensus_version); free(chain_id); free(magic); free(host); free(port);
    free(external_host); free(external_port);
    free(pub_hex); free(payload); free(sig); free(sig_hex);
    return rc;
}

/* Genesis hardening: every early rejection path previously returned without
 * freeing the parsed HELLO fields. A peer could repeat malformed handshakes to
 * leak memory in the daemon. All exits now share one cleanup path. */
static int verify_hello_msg(const char *node_conf_text, const char *msg) {
    char *network_id=NULL,*genesis_hash=NULL,*protocol_version=NULL,*consensus_version=NULL;
    char *chain_id=NULL,*magic=NULL,*timestamp=NULL,*nonce=NULL,*host=NULL,*port=NULL;
    char *pub_hex=NULL,*sig_hex=NULL;
    char *exp_net=NULL,*exp_gen=NULL,*exp_ver=NULL,*exp_cons=NULL,*exp_chain=NULL,*exp_magic=NULL;
    char *payload=NULL; unsigned char *sig=NULL; EVP_PKEY *pub=NULL;
    int ok=-1;

    network_id=cfg_get(msg,"network_id"); genesis_hash=cfg_get(msg,"genesis_hash");
    protocol_version=cfg_get(msg,"protocol_version"); consensus_version=cfg_get(msg,"consensus_version");
    chain_id=cfg_get(msg,"chain_id"); magic=cfg_get(msg,"magic"); timestamp=cfg_get(msg,"timestamp");
    nonce=cfg_get(msg,"nonce"); host=cfg_get(msg,"host"); port=cfg_get(msg,"port");
    pub_hex=cfg_get(msg,"ed25519_pub_hex"); sig_hex=cfg_get(msg,"sig_ed25519_hex");
    if(!network_id||!genesis_hash||!protocol_version||!consensus_version||!chain_id||!magic
       ||!timestamp||!nonce||!host||!port||!pub_hex||!sig_hex) goto done;

    exp_net=cfg_get(node_conf_text,"network_id"); exp_gen=cfg_get(node_conf_text,"genesis_hash");
    exp_ver=cfg_get(node_conf_text,"protocol_version"); exp_cons=cfg_get(node_conf_text,"consensus_version");
    exp_chain=cfg_get(node_conf_text,"chain_id"); exp_magic=cfg_get(node_conf_text,"magic");
    if(!exp_net||!exp_gen||!exp_ver||!exp_cons||!exp_chain||!exp_magic) goto done;
    if(strcmp(network_id,exp_net)||strcmp(genesis_hash,exp_gen)||strcmp(protocol_version,exp_ver)
       ||strcmp(consensus_version,exp_cons)||strcmp(chain_id,exp_chain)||strcmp(magic,exp_magic)) goto done;

    { long long ts=atoll(timestamp), now=(long long)time(NULL); if(llabs(now-ts)>300) goto done; }

    { unsigned char raw[32]; size_t rawlen=0;
      if(hex_to_bytes(pub_hex,raw,sizeof(raw),&rawlen)!=0||rawlen!=32) goto done;
      pub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,raw,rawlen); if(!pub) goto done; }

    payload=hello_payload_for_sign(network_id,genesis_hash,protocol_version,consensus_version,
                                   chain_id,magic,timestamp,nonce,host,port,pub_hex);
    if(!payload) goto done;

    { size_t siglen=0, cap=strlen(sig_hex)/2+1;
      sig=(unsigned char*)malloc(cap); if(!sig) goto done;
      if(hex_to_bytes(sig_hex,sig,cap,&siglen)!=0) goto done;
      ok = verify_oneshot(pub,(unsigned char*)payload,strlen(payload),sig,siglen)==0 ? 0 : -1; }

done:
    EVP_PKEY_free(pub); free(sig); free(payload);
    free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version);
    free(chain_id); free(magic); free(timestamp); free(nonce); free(host); free(port);
    free(pub_hex); free(sig_hex);
    free(exp_net); free(exp_gen); free(exp_ver); free(exp_cons); free(exp_chain); free(exp_magic);
    return ok;
}

static int node_store_mempool_tx(const char *node_dir, const char *tx_text) {
    char txid[129]={0};
    if(g_velocity_mempool_ready){
        int rc=qrx_velocity_mempool_add(&g_velocity_mempool,tx_text,txid);
        if(rc==0 || rc==1) return 0; /* duplicates are already safely admitted */
        return -1;
    }
    /* Standalone/fallback path still uses the VELOCITY WAL rather than one file per TX. */
    QrxVelocityMempool pool;
    if(qrx_velocity_mempool_open(&pool,node_dir,MEMPOOL_MAX_TXS)!=0) return -1;
    int rc=qrx_velocity_mempool_add(&pool,tx_text,txid);
    qrx_velocity_mempool_close(&pool);
    return (rc==0||rc==1)?0:-1;
}


/* Phase 6.4: durable, keyless Generals offline relay spool. Files contain an
 * already wallet-signed transaction plus a not-before block height. qrxd never
 * receives wallet keys and can only admit the exact pre-authorized envelope. */
static int generals_offline_process_cmd(const char *chain_dir){
    char dir[1024]; snprintf(dir,sizeof(dir),"%s/generals-offline-queue",chain_dir); mkdir_p(dir);
    long long h=current_height_from_chain(chain_dir); int relayed=0,pending=0,expired=0;
#ifndef _WIN32
    DIR *d=opendir(dir); if(!d){printf("height=%lld\nrelayed=0\npending=0\n",h);return 0;} struct dirent *de;
    while((de=readdir(d))){ if(de->d_name[0]=='.'||!strstr(de->d_name,".scheduled"))continue; char path[1400];snprintf(path,sizeof(path),"%s/%s",dir,de->d_name); char *txt=read_file(path,NULL);if(!txt)continue;
        char *nl=strchr(txt,'\n'); if(!nl){free(txt);continue;} *nl=0; long long nb=atoll(txt); char *nl2=strchr(nl+1,'\n'); if(!nl2){free(txt);continue;} *nl2=0; long long exp=atoll(nl+1); char *tx=nl2+1;
        if(h>exp){char done[1450];snprintf(done,sizeof(done),"%s.expired",path);rename(path,done);expired++;}
        else if(h>=nb){ if(node_store_mempool_tx(chain_dir,tx)==0){char done[1450];snprintf(done,sizeof(done),"%s.relayed",path);rename(path,done);relayed++;} else pending++; }
        else pending++; free(txt);
    } closedir(d);
#else
    char pat[1200];snprintf(pat,sizeof(pat),"%s/*.scheduled",dir);WIN32_FIND_DATAA fd;HANDLE fh=FindFirstFileA(pat,&fd);if(fh!=INVALID_HANDLE_VALUE){do{char path[1400];snprintf(path,sizeof(path),"%s/%s",dir,fd.cFileName);char *txt=read_file(path,NULL);if(!txt)continue;char *nl=strchr(txt,'\n');if(!nl){free(txt);continue;}*nl=0;long long nb=atoll(txt);char *nl2=strchr(nl+1,'\n');if(!nl2){free(txt);continue;}*nl2=0;long long exp=atoll(nl+1);char *tx=nl2+1;if(h>exp){char done[1450];snprintf(done,sizeof(done),"%s.expired",path);MoveFileExA(path,done,MOVEFILE_REPLACE_EXISTING);expired++;}else if(h>=nb&&node_store_mempool_tx(chain_dir,tx)==0){char done[1450];snprintf(done,sizeof(done),"%s.relayed",path);MoveFileExA(path,done,MOVEFILE_REPLACE_EXISTING);relayed++;}else pending++;free(txt);}while(FindNextFileA(fh,&fd));FindClose(fh);}
#endif
    printf("height=%lld\nrelayed=%d\npending=%d\nexpired=%d\n",h,relayed,pending,expired); return 0;
}


/* Phase 6.5: decentralized, keyless scheduled-command relay.  A relay envelope
 * is only a height window plus an already signed transaction.  Peers can copy
 * it, but cannot alter the authorized command without invalidating the tx. */
static int generals_relay_store(const char *node_dir,const char *envelope){
    if(!envelope||strlen(envelope)>65536)return -1;
    char *tmp=strdup(envelope); if(!tmp)return -1;
    char *nl=strchr(tmp,'\n'); if(!nl){free(tmp);return -1;} *nl=0;
    long long nb=atoll(tmp); char *nl2=strchr(nl+1,'\n'); if(!nl2){free(tmp);return -1;} *nl2=0;
    long long exp=atoll(nl+1); char *tx=nl2+1; if(nb<1||exp<nb||!*tx){free(tmp);return -1;}
    /* Phase 6.6 mainnet hardening: relay authorization may not be parked for an
       unbounded period. A normal Generals turn is far below this ceiling. */
    if(exp-nb > 4096){free(tmp);return -1;}
    char *cfgp=NULL,*cfg=NULL,*chain=NULL; cfgp=malloc(strlen(node_dir)+32); sprintf(cfgp,"%s/node.conf",node_dir); cfg=read_file(cfgp,NULL); free(cfgp);
    if(!cfg){free(tmp);return -1;} chain=cfg_get(cfg,"chain_dir"); if(!chain){free(cfg);free(tmp);return -1;}
    /* Mainnet fairness gate: Phase 6.5 envelopes contain the signed reveal TX
       in plaintext. Signatures protect integrity, not secrecy; a relay could
       inspect MOVE/ATTACK targets before reveal height. Keep decentralized
       plaintext relay off on Mainnet until threshold/timelock encryption is
       consensus-specified and independently reviewed. Local keyless scheduling
       remains available without sharing the reveal with third parties. */
    { char network_id[128]={0};
      if(qrx_chain_get_value(chain,"network_id",network_id,sizeof(network_id))==0 && strstr(network_id,"qrx-mainnet")==network_id){
          free(chain);free(cfg);free(tmp);return -1;
      }
    }
    { char relay_err[256];
      if(verify_tx_text_untrusted(chain,tx,relay_err,sizeof(relay_err))!=0){free(chain);free(cfg);free(tmp);return -1;} }
    char hash[129]; hash_primary_hex((unsigned char*)envelope,strlen(envelope),hash);
    char dir[1024],path[1400]; snprintf(dir,sizeof(dir),"%s/generals-relay",node_dir); mkdir_p(dir); snprintf(path,sizeof(path),"%s/%s.scheduled",dir,hash);
    if(access(path,F_OK)==0){free(chain);free(cfg);free(tmp);return 0;}
#ifndef _WIN32
    { int active=0; DIR *qd=opendir(dir); if(qd){struct dirent *qe;while((qe=readdir(qd)))if(strstr(qe->d_name,".scheduled"))active++;closedir(qd);} if(active>=4096){free(chain);free(cfg);free(tmp);return -1;} }
#endif
    if(write_text(path,envelope)!=0){free(chain);free(cfg);free(tmp);return -1;}
    long long h=current_height_from_chain(chain); if(h>=nb&&h<=exp&&node_store_mempool_tx(node_dir,tx)==0){char done[1450];snprintf(done,sizeof(done),"%s.relayed",path);rename(path,done);}
    free(chain);free(cfg);free(tmp);return 0;
}

static int storage_accept_marker_waiting(const char *node_dir,const char *cid,uint32_t shard,long long h){
    char d[1200],p[1500];snprintf(d,sizeof(d),"%s/storage_accept_pending",node_dir);mkdir_p(d);snprintf(p,sizeof(p),"%s/%s-%010u.state",d,cid,shard);char*t=read_file(p,NULL);if(!t)return 0;long long sent=atoll(t);free(t);return h<=sent+12;
}
static void storage_accept_marker_write(const char *node_dir,const char *cid,uint32_t shard,long long h){char d[1200],p[1500],b[64];snprintf(d,sizeof(d),"%s/storage_accept_pending",node_dir);mkdir_p(d);snprintf(p,sizeof(p),"%s/%s-%010u.state",d,cid,shard);snprintf(b,sizeof(b),"%lld\n",h);write_text(p,b);}
static int storage_provider_make_accept_tx(const char *chain_dir,const char *wallet_dir,const char *provider,const char *cid,uint32_t shard,char **tx_out){
    if(!chain_dir||!wallet_dir||!provider||!cid||!tx_out)return-1;*tx_out=NULL;const char*pass=getenv("QRX_PASSPHRASE");if(!pass)return-1;
    char p[1536];snprintf(p,sizeof(p),"%s/ed25519_priv.pem",wallet_dir);EVP_PKEY*ed=load_priv_pem(p,pass);snprintf(p,sizeof(p),"%s/mldsa65_priv.pem",wallet_dir);EVP_PKEY*ml=load_priv_pem(p,pass);snprintf(p,sizeof(p),"%s/ed25519_pub.pem",wallet_dir);EVP_PKEY*ep=load_pub_pem(p);snprintf(p,sizeof(p),"%s/mldsa65_pub.pem",wallet_dir);EVP_PKEY*mp=load_pub_pem(p);if(!ed||!ml||!ep||!mp){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return-1;}
    unsigned char eraw[32];size_t en=sizeof(eraw);if(EVP_PKEY_get_raw_public_key(ep,eraw,&en)!=1||en!=32){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return-1;}char*edhex=bytes_to_hex(eraw,32),*mlpem=pubkey_to_pem_string(mp),*mlb64=mlpem?base64_encode((unsigned char*)mlpem,strlen(mlpem)):NULL;
    char*net=chain_cfg_value(chain_dir,"network_id"),*gen=chain_cfg_value(chain_dir,"genesis_hash"),*proto=chain_cfg_value(chain_dir,"protocol_version");long long h=current_height_from_chain(chain_dir);long long fee=qrx_chain_get_ll_at_height_or_default(chain_dir,h+1,"tx_fee_atoms",1000LL);if(fee<0)fee=0;char fees[32],lane[32],nonce[32],ts[32],exp[32],payload[512];snprintf(fees,sizeof(fees),"%lld",fee);snprintf(lane,sizeof(lane),"%u",(unsigned)(shard+1));snprintf(nonce,sizeof(nonce),"%lld",velocity_get_lane_nonce(chain_dir,provider,(long long)shard+1)+1);snprintf(ts,sizeof(ts),"%lld",(long long)time(NULL));snprintf(exp,sizeof(exp),"%lld",h+64);snprintf(payload,sizeof(payload),"contract_id=%s;shard_index=%u",cid,shard);
    char*body=(edhex&&mlb64&&net&&gen&&proto)?canonical_velocity_tx_body(net,gen,proto,"STORAGE_ASSIGN_ACCEPT",provider,provider,"0",fees,lane,nonce,ts,exp,payload,edhex,mlb64):NULL;unsigned char*s1=NULL,*s2=NULL;size_t n1=0,n2=0;char*h1=NULL,*h2=NULL;int rc=-1;if(body&&sign_oneshot(ed,(unsigned char*)body,strlen(body),&s1,&n1)==0&&sign_oneshot(ml,(unsigned char*)body,strlen(body),&s2,&n2)==0){h1=bytes_to_hex(s1,n1);h2=bytes_to_hex(s2,n2);char bh3[129],bh2[65];hash_primary_hex((unsigned char*)body,strlen(body),bh3);hash_legacy_hex((unsigned char*)body,strlen(body),bh2);size_t cap=strlen(body)+strlen(h1)+strlen(h2)+512;char*out=malloc(cap);if(out){snprintf(out,cap,"%sbody_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\nsig_ed25519_hex=%s\nsig_mldsa65_hex=%s\nsigned=true\n",body,bh3,bh2,h1,h2);*tx_out=out;rc=0;}}
    free(edhex);free(mlpem);free(mlb64);free(net);free(gen);free(proto);free(body);free(s1);free(s2);free(h1);free(h2);EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return rc;
}
static int storage_provider_auto_accept(const char *node_dir,const char *cfg){
    if(!g_storage_ready||!g_storage_fs||!g_storage_provider_id[0]||!cfg)return 0;char*cd=cfg_get(cfg,"chain_dir"),*wd=cfg_get(cfg,"wallet_dir");if(!cd||!wd){free(cd);free(wd);return-1;}QrxDB db;if(qrxdb_init(&db,cd)){free(cd);free(wd);return-1;}QrxStorageReadyAssignment ready[QRX_STORAGE_ACTIVATION_MAX_READY];size_t n=0;int rc=qrx_storage_collect_ready_assignments(&db,g_storage_fs,g_storage_provider_id,ready,QRX_STORAGE_ACTIVATION_MAX_READY,&n);qrxdb_close(&db);long long h=current_height_from_chain(cd);int submitted=0;if(!rc)for(size_t i=0;i<n;i++){if(storage_accept_marker_waiting(node_dir,ready[i].contract_id,ready[i].shard_index,h))continue;char*tx=NULL;if(!storage_provider_make_accept_tx(cd,wd,g_storage_provider_id,ready[i].contract_id,ready[i].shard_index,&tx)&&tx){if(node_store_mempool_tx(node_dir,tx)==0){storage_accept_marker_write(node_dir,ready[i].contract_id,ready[i].shard_index,h);submitted++;}OPENSSL_cleanse(tx,strlen(tx));free(tx);}}
    free(cd);free(wd);return submitted;
}


static int storage_postor_marker_waiting(const char *node_dir,const char *cid,uint32_t shard,uint64_t epoch,long long h){
    char d[1200],p[1500];snprintf(d,sizeof(d),"%s/storage_postor_pending",node_dir);mkdir_p(d);snprintf(p,sizeof(p),"%s/%s-%010u-%020llu.state",d,cid,shard,(unsigned long long)epoch);char*t=read_file(p,NULL);if(!t)return 0;long long sent=atoll(t);free(t);return h<=sent+12;
}
static void storage_postor_marker_write(const char *node_dir,const char *cid,uint32_t shard,uint64_t epoch,long long h){char d[1200],p[1500],b[64];snprintf(d,sizeof(d),"%s/storage_postor_pending",node_dir);mkdir_p(d);snprintf(p,sizeof(p),"%s/%s-%010u-%020llu.state",d,cid,shard,(unsigned long long)epoch);snprintf(b,sizeof(b),"%lld\n",h);write_text(p,b);}
static int storage_provider_make_postor_tx(const char *chain_dir,const char *wallet_dir,const char *provider,const QrxPoStorDueAssignment *due,const char *payload,char **tx_out){
    if(!chain_dir||!wallet_dir||!provider||!due||!payload||!tx_out)return-1;*tx_out=NULL;const char*pass=getenv("QRX_PASSPHRASE");if(!pass)return-1;
    char pth[1536];snprintf(pth,sizeof(pth),"%s/ed25519_priv.pem",wallet_dir);EVP_PKEY*ed=load_priv_pem(pth,pass);snprintf(pth,sizeof(pth),"%s/mldsa65_priv.pem",wallet_dir);EVP_PKEY*ml=load_priv_pem(pth,pass);snprintf(pth,sizeof(pth),"%s/ed25519_pub.pem",wallet_dir);EVP_PKEY*ep=load_pub_pem(pth);snprintf(pth,sizeof(pth),"%s/mldsa65_pub.pem",wallet_dir);EVP_PKEY*mp=load_pub_pem(pth);if(!ed||!ml||!ep||!mp){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return-1;}
    unsigned char eraw[32];size_t en=sizeof(eraw);if(EVP_PKEY_get_raw_public_key(ep,eraw,&en)!=1||en!=32){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return-1;}char*edhex=bytes_to_hex(eraw,32),*mlpem=pubkey_to_pem_string(mp),*mlb64=mlpem?base64_encode((unsigned char*)mlpem,strlen(mlpem)):NULL;
    char*net=chain_cfg_value(chain_dir,"network_id"),*gen=chain_cfg_value(chain_dir,"genesis_hash"),*proto=chain_cfg_value(chain_dir,"protocol_version");long long h=current_height_from_chain(chain_dir);long long fee=qrx_chain_get_ll_at_height_or_default(chain_dir,h+1,"tx_fee_atoms",1000LL);if(fee<0)fee=0;char fees[32],lane[32],nonce[32],ts[32],exp[32];unsigned lane_id=(unsigned)(due->shard_index+1001u);snprintf(fees,sizeof(fees),"%lld",fee);snprintf(lane,sizeof(lane),"%u",lane_id);snprintf(nonce,sizeof(nonce),"%lld",velocity_get_lane_nonce(chain_dir,provider,(long long)lane_id)+1);snprintf(ts,sizeof(ts),"%lld",(long long)time(NULL));snprintf(exp,sizeof(exp),"%lld",h+64);
    char*body=(edhex&&mlb64&&net&&gen&&proto)?canonical_velocity_tx_body(net,gen,proto,"STORAGE_POSTOR",provider,provider,"0",fees,lane,nonce,ts,exp,payload,edhex,mlb64):NULL;unsigned char*s1=NULL,*s2=NULL;size_t n1=0,n2=0;char*h1=NULL,*h2=NULL;int rc=-1;if(body&&sign_oneshot(ed,(unsigned char*)body,strlen(body),&s1,&n1)==0&&sign_oneshot(ml,(unsigned char*)body,strlen(body),&s2,&n2)==0){h1=bytes_to_hex(s1,n1);h2=bytes_to_hex(s2,n2);char bh3[129],bh2[65];hash_primary_hex((unsigned char*)body,strlen(body),bh3);hash_legacy_hex((unsigned char*)body,strlen(body),bh2);size_t cap=strlen(body)+strlen(h1)+strlen(h2)+512;char*out=malloc(cap);if(out){snprintf(out,cap,"%sbody_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\nsig_ed25519_hex=%s\nsig_mldsa65_hex=%s\nsigned=true\n",body,bh3,bh2,h1,h2);*tx_out=out;rc=0;}}
    free(edhex);free(mlpem);free(mlb64);free(net);free(gen);free(proto);free(body);free(s1);free(s2);free(h1);free(h2);EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return rc;
}
static int storage_provider_auto_postor(const char *node_dir,const char *cfg){
    if(!g_storage_ready||!g_storage_fs||!g_storage_provider_id[0]||!cfg)return 0;char*cd=cfg_get(cfg,"chain_dir"),*wd=cfg_get(cfg,"wallet_dir");if(!cd||!wd){free(cd);free(wd);return-1;}QrxDB db;if(qrxdb_init(&db,cd)){free(cd);free(wd);return-1;}long long h=current_height_from_chain(cd);QrxPoStorDueAssignment due[64];size_t n=0;int rc=qrx_storage_postor_collect(&db,g_storage_provider_id,(uint64_t)(h<0?0:h),due,64,&n),submitted=0;if(!rc)for(size_t i=0;i<n;i++){if(due[i].health==QRX_POSTOR_HEALTH_ACTIVE||due[i].health==QRX_POSTOR_HEALTH_REPAIRING)continue;if(storage_postor_marker_waiting(node_dir,due[i].contract_id,due[i].shard_index,due[i].epoch,h))continue;unsigned char*leaf=NULL;size_t leafn=0;QrxMerkleProof proof;char*payload=NULL,*tx=NULL;if(!qrx_storage_postor_build_local(&db,g_storage_fs,g_storage_provider_id,&due[i],&leaf,&leafn,&proof)&&!qrx_storage_postor_payload(&due[i],leaf,leafn,&proof,&payload)&&!storage_provider_make_postor_tx(cd,wd,g_storage_provider_id,&due[i],payload,&tx)&&tx&&node_store_mempool_tx(node_dir,tx)==0){storage_postor_marker_write(node_dir,due[i].contract_id,due[i].shard_index,due[i].epoch,h);submitted++;}if(leaf){OPENSSL_cleanse(leaf,leafn);free(leaf);}if(payload){OPENSSL_cleanse(payload,strlen(payload));free(payload);}if(tx){OPENSSL_cleanse(tx,strlen(tx));free(tx);}}
    qrxdb_close(&db);free(cd);free(wd);return submitted;
}


static int storage_repair_marker_waiting(const char*node_dir,const char*kind,const char*cid,uint32_t shard,long long h){char d[1200],p[1500];snprintf(d,sizeof(d),"%s/storage_repair_pending",node_dir);mkdir_p(d);snprintf(p,sizeof(p),"%s/%s-%s-%010u.state",d,kind,cid,shard);char*t=read_file(p,NULL);if(!t)return 0;long long sent=atoll(t);free(t);return h<=sent+12;}
static void storage_repair_marker_write(const char*node_dir,const char*kind,const char*cid,uint32_t shard,long long h){char d[1200],p[1500],b[64];snprintf(d,sizeof(d),"%s/storage_repair_pending",node_dir);mkdir_p(d);snprintf(p,sizeof(p),"%s/%s-%s-%010u.state",d,kind,cid,shard);snprintf(b,sizeof(b),"%lld\n",h);write_text(p,b);}
static int storage_provider_make_repair_tx(const char*chain_dir,const char*wallet_dir,const char*provider,const char*type,uint32_t lane_id,const char*payload,char**tx_out){
    if(!chain_dir||!wallet_dir||!provider||!type||!payload||!tx_out)return-1;*tx_out=NULL;const char*pass=getenv("QRX_PASSPHRASE");if(!pass)return-1;char pth[1536];snprintf(pth,sizeof(pth),"%s/ed25519_priv.pem",wallet_dir);EVP_PKEY*ed=load_priv_pem(pth,pass);snprintf(pth,sizeof(pth),"%s/mldsa65_priv.pem",wallet_dir);EVP_PKEY*ml=load_priv_pem(pth,pass);snprintf(pth,sizeof(pth),"%s/ed25519_pub.pem",wallet_dir);EVP_PKEY*ep=load_pub_pem(pth);snprintf(pth,sizeof(pth),"%s/mldsa65_pub.pem",wallet_dir);EVP_PKEY*mp=load_pub_pem(pth);if(!ed||!ml||!ep||!mp){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return-1;}
    unsigned char eraw[32];size_t en=sizeof(eraw);if(EVP_PKEY_get_raw_public_key(ep,eraw,&en)!=1||en!=32){EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return-1;}char*edhex=bytes_to_hex(eraw,32),*mlpem=pubkey_to_pem_string(mp),*mlb64=mlpem?base64_encode((unsigned char*)mlpem,strlen(mlpem)):NULL;char*net=chain_cfg_value(chain_dir,"network_id"),*gen=chain_cfg_value(chain_dir,"genesis_hash"),*proto=chain_cfg_value(chain_dir,"protocol_version");long long h=current_height_from_chain(chain_dir),fee=qrx_chain_get_ll_at_height_or_default(chain_dir,h+1,"tx_fee_atoms",1000LL);if(fee<0)fee=0;char fees[32],lane[32],nonce[32],ts[32],exp[32];snprintf(fees,sizeof(fees),"%lld",fee);snprintf(lane,sizeof(lane),"%u",lane_id);snprintf(nonce,sizeof(nonce),"%lld",velocity_get_lane_nonce(chain_dir,provider,(long long)lane_id)+1);snprintf(ts,sizeof(ts),"%lld",(long long)time(NULL));snprintf(exp,sizeof(exp),"%lld",h+64);char*body=(edhex&&mlb64&&net&&gen&&proto)?canonical_velocity_tx_body(net,gen,proto,type,provider,provider,"0",fees,lane,nonce,ts,exp,payload,edhex,mlb64):NULL;unsigned char*s1=NULL,*s2=NULL;size_t n1=0,n2=0;char*h1=NULL,*h2=NULL;int rc=-1;if(body&&!sign_oneshot(ed,(unsigned char*)body,strlen(body),&s1,&n1)&&!sign_oneshot(ml,(unsigned char*)body,strlen(body),&s2,&n2)){h1=bytes_to_hex(s1,n1);h2=bytes_to_hex(s2,n2);char bh3[129],bh2[65];hash_primary_hex((unsigned char*)body,strlen(body),bh3);hash_legacy_hex((unsigned char*)body,strlen(body),bh2);size_t cap=strlen(body)+strlen(h1)+strlen(h2)+512;char*out=malloc(cap);if(out){snprintf(out,cap,"%sbody_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nbody_hash_sha256_legacy=%s\nsig_ed25519_hex=%s\nsig_mldsa65_hex=%s\nsigned=true\n",body,bh3,bh2,h1,h2);*tx_out=out;rc=0;}}free(edhex);free(mlpem);free(mlb64);free(net);free(gen);free(proto);free(body);free(s1);free(s2);free(h1);free(h2);EVP_PKEY_free(ed);EVP_PKEY_free(ml);EVP_PKEY_free(ep);EVP_PKEY_free(mp);return rc;
}
static int storage_provider_auto_repair(const char*node_dir,const char*cfg){
    if(!g_storage_ready||!g_storage_fs||!g_storage_provider_id[0]||!cfg)return 0;char*cd=cfg_get(cfg,"chain_dir"),*wd=cfg_get(cfg,"wallet_dir");if(!cd||!wd){free(cd);free(wd);return-1;}QrxDB db;if(qrxdb_init(&db,cd)){free(cd);free(wd);return-1;}long long h=current_height_from_chain(cd);int submitted=0;
    QrxStorageRepairStartCandidate starts[QRX_STORAGE_REPAIR_MAX];size_t sn=0;if(!qrx_storage_repair_collect_starts(&db,(uint64_t)(h<0?0:h),starts,QRX_STORAGE_REPAIR_MAX,&sn))for(size_t i=0;i<sn&&submitted<1;i++){if(storage_repair_marker_waiting(node_dir,"start",starts[i].contract_id,starts[i].shard_index,h))continue;char*pl=NULL,*tx=NULL;if(!qrx_storage_repair_start_payload(&starts[i],&pl)&&!storage_provider_make_repair_tx(cd,wd,g_storage_provider_id,"STORAGE_REPAIR_START",2001u+starts[i].shard_index,pl,&tx)&&tx&&node_store_mempool_tx(node_dir,tx)==0){storage_repair_marker_write(node_dir,"start",starts[i].contract_id,starts[i].shard_index,h);submitted++;}free(pl);if(tx){OPENSSL_cleanse(tx,strlen(tx));free(tx);}}
    QrxStorageReplacementWork work[QRX_STORAGE_REPAIR_MAX];size_t wn=0;if(!qrx_storage_repair_collect_replacement(&db,g_storage_provider_id,(uint64_t)(h<0?0:h),g_storage_fs,work,QRX_STORAGE_REPAIR_MAX,&wn))for(size_t i=0;i<wn;i++){
        QrxStorageReplacementWork*w=&work[i];if(w->needs_reconstruction&&g_storage_discovery_ready){QrxStorageContractState c;if(!qrx_storage_contract_get(&db,w->contract_id,&c)){const QrxStorageRedundancyProfile*rp=qrx_storage_profile_by_name(c.profile);if(rp&&!rp->full_replicas&&rp->data_shards&&rp->parity_shards){QrxShardProviderSource src[QRX_STORAGE_MAX_FETCH_SOURCES];size_t n=0;if(!qrx_storage_discovery_sources_for_contract(&g_storage_discovery,&db,w->contract_id,c.shard_count,(uint64_t)h,src,QRX_STORAGE_MAX_FETCH_SOURCES,&n)&&n>=rp->data_shards){char rd[1200],tmp[1500],got[65];snprintf(rd,sizeof(rd),"%s/storage_repair_tmp",node_dir);mkdir_p(rd);snprintf(tmp,sizeof(tmp),"%s/%s-%010u.part",rd,w->contract_id,w->shard_index);QrxStorageNetworkFetchCtx fc={w->contract_id,5000,10000};if(!qrx_storage_stream_reconstruct_shard_to_file(src,n,(size_t)w->repair.physical_bytes,rp->data_shards,rp->parity_shards,w->shard_index,QRX_STORAGE_DEFAULT_FETCH_RANGE,qrx_storage_network_fetch_range,&fc,w->repair.object_id,tmp,NULL)){if(!qrx_storage_fs_put_file(g_storage_fs,tmp,got)&&!strcmp(got,w->repair.object_id)){}remove(tmp);}}}}}
        if(w->needs_accept||(!w->needs_reconstruction&&w->repair.state==QRX_ASSIGN_REPAIRING)){if(storage_repair_marker_waiting(node_dir,"accept",w->contract_id,w->shard_index,h))continue;char*pl=NULL,*tx=NULL;if(!qrx_storage_repair_accept_payload(w,&pl)&&!storage_provider_make_repair_tx(cd,wd,g_storage_provider_id,"STORAGE_REPAIR_ACCEPT",3001u+w->shard_index,pl,&tx)&&tx&&node_store_mempool_tx(node_dir,tx)==0){storage_repair_marker_write(node_dir,"accept",w->contract_id,w->shard_index,h);submitted++;}free(pl);if(tx){OPENSSL_cleanse(tx,strlen(tx));free(tx);}continue;}
        if(w->proof_due&&w->repair.state==QRX_ASSIGN_ACTIVE&&!storage_repair_marker_waiting(node_dir,"complete",w->contract_id,w->shard_index,h)){unsigned char*leaf=NULL;size_t leafn=0;QrxMerkleProof mp;char*pl=NULL,*tx=NULL;if(!qrx_storage_repair_build_complete_proof(&db,g_storage_fs,w,&leaf,&leafn,&mp)&&!qrx_storage_repair_complete_payload(w,leaf,leafn,&mp,&pl)&&!storage_provider_make_repair_tx(cd,wd,g_storage_provider_id,"STORAGE_REPAIR_COMPLETE",4001u+w->shard_index,pl,&tx)&&tx&&node_store_mempool_tx(node_dir,tx)==0){storage_repair_marker_write(node_dir,"complete",w->contract_id,w->shard_index,h);submitted++;}if(leaf){OPENSSL_cleanse(leaf,leafn);free(leaf);}free(pl);if(tx){OPENSSL_cleanse(tx,strlen(tx));free(tx);}}
    }
    qrxdb_close(&db);free(cd);free(wd);return submitted;
}

static int generals_relay_process_node(const char *node_dir){
    char cp[1024];snprintf(cp,sizeof(cp),"%s/node.conf",node_dir);char*cfg=read_file(cp,NULL);if(!cfg)return -1;char*chain=cfg_get(cfg,"chain_dir");if(!chain){free(cfg);return -1;}long long h=current_height_from_chain(chain);free(chain);free(cfg);
    char dir[1024];snprintf(dir,sizeof(dir),"%s/generals-relay",node_dir);mkdir_p(dir);int relayed=0;
#ifndef _WIN32
    DIR*d=opendir(dir);if(!d)return 0;struct dirent*de;while((de=readdir(d))){if(de->d_name[0]=='.'||!strstr(de->d_name,".scheduled"))continue;char path[1400];snprintf(path,sizeof(path),"%s/%s",dir,de->d_name);char*t=read_file(path,NULL);if(!t)continue;char*n=strchr(t,'\n');if(!n){free(t);continue;}*n=0;long long nb=atoll(t);char*n2=strchr(n+1,'\n');if(!n2){free(t);continue;}*n2=0;long long ex=atoll(n+1);char*tx=n2+1;if(h>ex){char z[1450];snprintf(z,sizeof(z),"%s.expired",path);rename(path,z);}else if(h>=nb&&node_store_mempool_tx(node_dir,tx)==0){char z[1450];snprintf(z,sizeof(z),"%s.relayed",path);rename(path,z);relayed++;}free(t);}closedir(d);
#endif
    return relayed;
}

static void node_handle_client(int fd, const char *node_dir) {
    char path[1024]; snprintf(path, sizeof(path), "%s/node.conf", node_dir); char *node_cfg = read_file(path, NULL); if (!node_cfg) return;
    struct sockaddr_in peer; socklen_t peerlen = sizeof(peer); char ip[64] = "unknown";
    if (getpeername(fd, (struct sockaddr*)&peer, &peerlen) == 0) inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
    if (peer_ban_score(node_dir, ip) >= BAN_THRESHOLD) { send_framed(fd, "status=ERR\nreason=banned\n"); free(node_cfg); return; }
    if (!peer_rate_allow(node_dir, ip)) { peer_add_score(node_dir, ip, 50); send_framed(fd, "status=ERR\nreason=rate_limited\n"); free(node_cfg); return; }

    char *msg = recv_framed(fd); if (!msg) { free(node_cfg); return; }
    if (strstr(msg, "type=HELLO\n") != msg || verify_hello_msg(node_cfg, msg) != 0) {
        peer_add_score(node_dir, ip, 20); send_framed(fd, "status=ERR\nreason=bad_hello\n"); free(msg); free(node_cfg); return;
    }
    char *ann_host = cfg_get(msg, "host"), *ann_port = cfg_get(msg, "port");
    /* A verified peer behind NAT may honestly announce 0.0.0.0.  Track the
     * source as live, but never gossip an unusable or self endpoint. */
    peer_touch_seen(node_dir, ip, (long long)time(NULL));
    if (ann_host && ann_port && peer_endpoint_is_usable(ann_host,ann_port) && !peer_endpoint_is_self(node_dir,ann_host,atoi(ann_port))) { remember_known_peer(node_dir, ann_host, ann_port); peer_rep_add(node_dir, ann_host, 1); }
    send_framed(fd, "status=OK\n"); free(msg);

    if (!peer_rate_allow(node_dir, ip)) { peer_add_score(node_dir, ip, 50); send_framed(fd, "status=ERR\nreason=rate_limited\n"); if (ann_host) free(ann_host); if (ann_port) free(ann_port); free(node_cfg); return; }
    msg = recv_framed(fd); if (!msg) { if (ann_host) free(ann_host); if (ann_port) free(ann_port); free(node_cfg); return; }
    if (strstr(msg, "type=TX\n") == msg) {
        char *tx_b64 = cfg_get(msg, "tx_b64");
        if (!tx_b64) { peer_add_score(node_dir, ip, 10); send_framed(fd, "status=ERR\nreason=no_tx\n"); free(msg); free(node_cfg); return; }
        size_t txlen=0; unsigned char *txbuf = base64_decode(tx_b64, &txlen);
        if (!txbuf) { peer_add_score(node_dir, ip, 10); send_framed(fd, "status=ERR\nreason=bad_b64\n"); free(tx_b64); free(msg); free(node_cfg); return; }
        if (txlen > QRX_UNTRUSTED_TX_MAX_BYTES) {
            peer_add_score(node_dir, ip, 20); send_framed(fd, "status=ERR\nreason=oversized_tx\n");
            free(tx_b64); free(txbuf); free(msg); free(node_cfg); return;
        }
        char *tx = malloc(txlen+1);
        if (!tx) { send_framed(fd, "status=ERR\nreason=oom\n"); free(tx_b64); free(txbuf); free(msg); free(node_cfg); return; }
        memcpy(tx, txbuf, txlen); tx[txlen]=0;
        char *chain_dir = cfg_get(node_cfg, "chain_dir");
        /* Genesis hardening: untrusted peer data must never reach a
         * process-fatal validation path. verify_tx_text_untrusted() returns a
         * structured error instead of terminating the daemon. */
        char tx_err[256];
        int ok = verify_tx_text_untrusted(chain_dir, tx, tx_err, sizeof(tx_err));
        if (ok == 0 && node_store_mempool_tx(node_dir, tx) == 0) send_framed(fd, "status=OK\nkind=tx\n");
        else { peer_add_score(node_dir, ip, 30); send_framed(fd, "status=ERR\nreason=bad_tx\n"); }
        free(chain_dir); free(tx_b64); free(txbuf); free(tx);
    } else if (strstr(msg, "type=GENERALS_RELAY\n") == msg) {
        char *b64=cfg_get(msg,"data_b64"); size_t n=0; unsigned char *raw=b64?base64_decode(b64,&n):NULL;
        if(!raw){peer_add_score(node_dir,ip,10);send_framed(fd,"status=ERR\nreason=bad_relay\n");}
        else {char *env=malloc(n+1);memcpy(env,raw,n);env[n]=0;if(generals_relay_store(node_dir,env)==0)send_framed(fd,"status=OK\nkind=generals_relay\n");else{peer_add_score(node_dir,ip,20);send_framed(fd,"status=ERR\nreason=invalid_relay\n");}free(env);free(raw);} free(b64);
    } else if (strstr(msg, "type=STORAGE_DISCOVERY_PUSH\n") == msg) {
        char *wb=cfg_get(msg,"wire_b64"), *chain_dir=cfg_get(node_cfg,"chain_dir"); size_t wn=0; unsigned char *wire=wb?base64_decode(wb,&wn):NULL; int accepted=0;
        if(g_storage_discovery_ready&&wire&&chain_dir){QrxStorageProviderAnnouncement a;uint8_t*sig=NULL;size_t sl=0;QrxDB db;long long hh=current_height_from_chain(chain_dir);
            if(!qrx_storage_discovery_wire_decode(wire,wn,&a,&sig,&sl)&&!qrxdb_init(&db,chain_dir)){accepted=qrx_storage_discovery_ingest(&g_storage_discovery,&db,&a,sig,sl,(uint64_t)(hh<0?0:hh),qrx_storage_provider_discovery_key_lookup,&db)==0;qrxdb_close(&db);}
            free(sig); if(accepted&&g_storage_discovery_cache_path[0])qrx_storage_discovery_cache_save(&g_storage_discovery,g_storage_discovery_cache_path);
        }
        if(accepted){send_framed(fd,"status=OK\nkind=storage_discovery\n");storage_discovery_fanout(node_dir,wb,ip);}else{peer_add_score(node_dir,ip,5);send_framed(fd,"status=ERR\nreason=invalid_storage_discovery\n");}
        free(wire);free(wb);free(chain_dir);
    } else if (strstr(msg, "type=STORAGE_DISCOVERY_PULL\n") == msg) {
        if(!g_storage_discovery_ready){send_framed(fd,"status=ERR\nreason=storage_discovery_disabled\n");}
        else {size_t cap=64;for(size_t i=0;i<g_storage_discovery.count;i++)cap+=g_storage_discovery.entries[i].signature_len*2+2048;char *resp=malloc(cap);if(!resp)send_framed(fd,"status=ERR\nreason=oom\n");else{size_t o=(size_t)snprintf(resp,cap,"status=OK\nkind=storage_discovery_pull\ncount=%llu\n",(unsigned long long)g_storage_discovery.count);for(size_t i=0;i<g_storage_discovery.count&&o+32<cap;i++){uint8_t*w=NULL;size_t wn=0;if(!qrx_storage_discovery_wire_encode(&g_storage_discovery.entries[i].announcement,g_storage_discovery.entries[i].signature,g_storage_discovery.entries[i].signature_len,&w,&wn)){char*b=base64_encode(w,wn);o+=(size_t)snprintf(resp+o,cap-o,"entry%llu_b64=%s\n",(unsigned long long)i,b);free(b);free(w);}}send_framed(fd,resp);free(resp);}}
    } else if (strstr(msg, "type=AURA_POD_PUSH\n") == msg) {
        char *wb=cfg_get(msg,"wire_b64"), *chain_dir=cfg_get(node_cfg,"chain_dir"); size_t wn=0; unsigned char *wire=wb?base64_decode(wb,&wn):NULL; int accepted=0;
        if(g_aura_gossip_ready&&wire&&chain_dir){QrxAuraPodAnnouncement a;uint8_t*sig=NULL;size_t sl=0;QrxDB db;long long hh=current_height_from_chain(chain_dir);
            if(!qrx_aura_pod_wire_decode(wire,wn,&a,&sig,&sl)&&!qrxdb_init(&db,chain_dir)){accepted=qrx_aura_pod_gossip_ingest(&g_aura_pod_gossip,&a,sig,sl,(uint64_t)(hh<0?0:hh),aura_compute_provider_key_lookup,&db)==0;qrxdb_close(&db);}
            free(sig);if(accepted&&g_aura_pod_cache_path[0])qrx_aura_pod_gossip_cache_save(&g_aura_pod_gossip,g_aura_pod_cache_path);
        }
        if(accepted){send_framed(fd,"status=OK\nkind=aura_pod_gossip\n");aura_gossip_fanout(node_dir,"AURA_POD_PUSH",wb,ip);}else{peer_add_score(node_dir,ip,5);send_framed(fd,"status=ERR\nreason=invalid_aura_pod_gossip\n");}
        free(wire);free(wb);free(chain_dir);
    } else if (strstr(msg, "type=AURA_MODEL_PUSH\n") == msg) {
        char *wb=cfg_get(msg,"wire_b64"), *chain_dir=cfg_get(node_cfg,"chain_dir"); size_t wn=0; unsigned char *wire=wb?base64_decode(wb,&wn):NULL; int accepted=0;
        if(g_aura_gossip_ready&&wire&&chain_dir){QrxAuraModelProfileAnnouncement a;uint8_t*sig=NULL;size_t sl=0;long long hh=current_height_from_chain(chain_dir);
            if(!qrx_aura_model_wire_decode(wire,wn,&a,&sig,&sl))accepted=qrx_aura_model_gossip_ingest(&g_aura_model_gossip,&a,sig,sl,(uint64_t)(hh<0?0:hh),aura_model_gov_key_lookup,chain_dir,aura_model_gov_authorize,chain_dir)==0;
            free(sig);if(accepted&&g_aura_model_cache_path[0])qrx_aura_model_gossip_cache_save(&g_aura_model_gossip,g_aura_model_cache_path);
        }
        if(accepted){send_framed(fd,"status=OK\nkind=aura_model_gossip\n");aura_gossip_fanout(node_dir,"AURA_MODEL_PUSH",wb,ip);}else{peer_add_score(node_dir,ip,5);send_framed(fd,"status=ERR\nreason=invalid_aura_model_gossip\n");}
        free(wire);free(wb);free(chain_dir);
    } else if (strstr(msg, "type=AURA_SYNC_DIGEST\n") == msg) {
        char *chain_dir=cfg_get(node_cfg,"chain_dir");
        if(!g_aura_gossip_ready||!chain_dir){send_framed(fd,"status=ERR\nreason=aura_gossip_disabled\n");}
        else {
            long long hh=current_height_from_chain(chain_dir);uint64_t h=(uint64_t)(hh<0?0:hh);QrxAuraGossipDigest d;
            if(qrx_aura_gossip_digest(&g_aura_pod_gossip,&g_aura_model_gossip,h,&d)) send_framed(fd,"status=ERR\nreason=aura_digest_failed\n");
            else {char resp[512];snprintf(resp,sizeof(resp),"status=OK\nkind=aura_sync_digest\nheight=%llu\npod_count=%llu\nmodel_count=%llu\npod_root=%s\nmodel_root=%s\ncombined_root=%s\n",(unsigned long long)h,(unsigned long long)d.pod_count,(unsigned long long)d.model_count,d.pod_root,d.model_root,d.combined_root);send_framed(fd,resp);}
        }
        free(chain_dir);
    } else if (strstr(msg, "type=AURA_POD_PULL\n") == msg || strstr(msg, "type=AURA_MODEL_PULL\n") == msg) {
        int want_models=strstr(msg,"type=AURA_MODEL_PULL\n")==msg;char*os=cfg_get(msg,"offset"),*ls=cfg_get(msg,"limit");size_t off=os?(size_t)strtoull(os,NULL,10):0,lim=ls?(size_t)strtoull(ls,NULL,10):16;if(!lim||lim>16)lim=16;free(os);free(ls);
        if(!g_aura_gossip_ready){send_framed(fd,"status=ERR\nreason=aura_gossip_disabled\n");}
        else {char *resp=calloc(1,MAX_MSG);if(!resp)send_framed(fd,"status=ERR\nreason=oom\n");else{size_t o=(size_t)snprintf(resp,MAX_MSG,"status=OK\nkind=%s\noffset=%llu\n",want_models?"aura_model_pull":"aura_pod_pull",(unsigned long long)off);size_t count=want_models?g_aura_model_gossip.count:g_aura_pod_gossip.count,returned=0;
                for(size_t i=off;i<count&&returned<lim;i++){uint8_t*w=NULL;size_t wn=0;int er=want_models?qrx_aura_model_wire_encode(&g_aura_model_gossip.entries[i].announcement,g_aura_model_gossip.entries[i].signature,g_aura_model_gossip.entries[i].signature_len,&w,&wn):qrx_aura_pod_wire_encode(&g_aura_pod_gossip.entries[i].announcement,g_aura_pod_gossip.entries[i].signature,g_aura_pod_gossip.entries[i].signature_len,&w,&wn);if(er)continue;char*b=base64_encode(w,wn);free(w);if(!b)continue;size_t need=strlen(b)+64;if(o+need+128>=MAX_MSG){free(b);break;}o+=(size_t)snprintf(resp+o,MAX_MSG-o,"entry%llu_b64=%s\n",(unsigned long long)returned,b);free(b);returned++;}
                o+=(size_t)snprintf(resp+o,MAX_MSG-o,"returned=%llu\nnext_offset=%llu\ntotal=%llu\n",(unsigned long long)returned,(unsigned long long)(off+returned),(unsigned long long)count);send_framed(fd,resp);free(resp);}}
    } else if (strstr(msg, "type=AURA_FABRIC_STATUS\n") == msg) {
        char *chain_dir=cfg_get(node_cfg,"chain_dir");
        if(!g_aura_gossip_ready||!chain_dir){send_framed(fd,"status=ERR\nreason=aura_gossip_disabled\n");}
        else {long long hh=current_height_from_chain(chain_dir);uint64_t h=(uint64_t)(hh<0?0:hh);QrxAuraFabricSnapshot snap;QrxAuraGlobeCell*cells=NULL;size_t cn=0;if(qrx_aura_gossip_live_snapshot(&g_aura_pod_gossip,&g_aura_model_gossip,h,QRX_GLOBE_DEFAULT_PRIVACY_MIN_PROVIDERS,&snap,&cells,&cn)){send_framed(fd,"status=ERR\nreason=aura_snapshot_failed\n");}
            else {char *resp=calloc(1,MAX_MSG);if(!resp)send_framed(fd,"status=ERR\nreason=oom\n");else{size_t o=(size_t)snprintf(resp,MAX_MSG,"status=OK\nkind=aura_fabric_status\nheight=%llu\nproviders=%llu\npods=%llu\ninference_pods=%llu\nutility_pods=%llu\nai_milli_tokens_per_second=%llu\nmodel_cache_free_bytes=%llu\nk2_readiness_bps=%u\nk3_readiness_bps=%u\nmax_ready_tier=%s\nvisible_regions=%u\nhidden_regions=%u\n",(unsigned long long)h,(unsigned long long)snap.provider_count,(unsigned long long)snap.total_pods,(unsigned long long)snap.inference_pods,(unsigned long long)snap.utility_pods,(unsigned long long)snap.ai_milli_tokens_per_second,(unsigned long long)snap.model_cache_free_bytes,snap.k2_readiness_bps,snap.k3_readiness_bps,qrx_aura_tier_name(snap.max_ready_tier),snap.visible_regions,snap.hidden_regions);size_t pub=0;for(size_t i=0;i<cn&&o+512<MAX_MSG;i++){if(!cells[i].publicly_visible)continue;o+=(size_t)snprintf(resp+o,MAX_MSG-o,"region%llu=%s|providers=%llu|pods=%llu|ai_mtps=%llu|latency_ms=%u|utilization_bps=%u|reliability_bps=%u|k2_bps=%u|k3_bps=%u\n",(unsigned long long)pub++,cells[i].region,(unsigned long long)cells[i].provider_count,(unsigned long long)cells[i].pod_count,(unsigned long long)cells[i].ai_milli_tokens_per_second,cells[i].avg_latency_ms,cells[i].avg_utilization_bps,cells[i].avg_reliability_bps,cells[i].k2_readiness_bps,cells[i].k3_readiness_bps);}send_framed(fd,resp);free(resp);}qrx_aura_globe_free(cells);}}
        free(chain_dir);
    } else if (strstr(msg, "type=STORAGE_GET\n") == msg) {
        char *cid=cfg_get(msg,"contract_id"), *sh=cfg_get(msg,"shard_index"), *oid=cfg_get(msg,"object_id"), *off=cfg_get(msg,"offset"), *ln=cfg_get(msg,"length");
        char *chain_dir=cfg_get(node_cfg,"chain_dir");
        uint32_t shard=sh?(uint32_t)strtoul(sh,NULL,10):UINT32_MAX; uint64_t offset=off?strtoull(off,NULL,10):UINT64_MAX; unsigned long req=ln?strtoul(ln,NULL,10):0;
        unsigned char *data=NULL; size_t data_len=0; int ok=-1;
        if(g_storage_ready && cid&&*cid&&oid&&strlen(oid)==64&&sh&&off&&ln&&req<=QRX_STORAGE_P2P_MAX_RANGE&&chain_dir){
            QrxDB sdb; if(qrxdb_init(&sdb,chain_dir)==0){ok=qrx_storage_p2p_read_authorized(&sdb,g_storage_fs,g_storage_provider_id,cid,shard,oid,offset,(size_t)req,&data,&data_len);qrxdb_close(&sdb);}
        }
        if(ok==0){char *b64=base64_encode(data,data_len); size_t cap=strlen(b64)+256; char *resp=malloc(cap); if(resp){snprintf(resp,cap,"status=OK\nkind=storage_range\noffset=%llu\nbytes=%llu\ndata_b64=%s\n",(unsigned long long)offset,(unsigned long long)data_len,b64);send_framed(fd,resp);free(resp);} else send_framed(fd,"status=ERR\nreason=oom\n"); free(b64);free(data);}
        else {peer_add_score(node_dir,ip,5);send_framed(fd,g_storage_ready?"status=ERR\nreason=storage_denied\n":"status=ERR\nreason=storage_disabled\n");}
        free(cid);free(sh);free(oid);free(off);free(ln);free(chain_dir);
    } else if (strstr(msg, "type=GETPEERS\n") == msg) {
        char peers_path[1024], known_path[1024]; snprintf(peers_path, sizeof(peers_path), "%s/peers.txt", node_dir); snprintf(known_path, sizeof(known_path), "%s/known_peers.txt", node_dir);
        char *peers_txt = read_file(peers_path, NULL); char *known_txt = read_file(known_path, NULL);
        size_t cap = 4096; char *list = malloc(cap); list[0]=0;
        if (peers_txt) strncat(list, peers_txt, cap - strlen(list) - 1);
        if (known_txt) strncat(list, known_txt, cap - strlen(list) - 1);
        char *b64 = base64_encode((unsigned char*)list, strlen(list));
        size_t rcap = strlen(b64) + 64; char *resp = malloc(rcap); snprintf(resp, rcap, "status=OK\npeers_b64=%s\n", b64); send_framed(fd, resp);
        free(peers_txt); free(known_txt); free(list); free(b64); free(resp);
    } else {
        peer_add_score(node_dir, ip, 15); send_framed(fd, "status=ERR\nreason=bad_message\n");
    }
    if (ann_host) free(ann_host); if (ann_port) free(ann_port); free(msg); free(node_cfg);
}

static int connect_to(const char *host, int port) {
    qrx_net_init_once();
    char port_s[16]; snprintf(port_s, sizeof(port_s), "%d", port);
    struct addrinfo hints, *results = NULL, *it;
    memset(&hints, 0, sizeof(hints)); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_s, &hints, &results) != 0) return -1;
    int fd = -1;
    for (it = results; it; it = it->ai_next) {
        fd = (int)socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (connect_with_timeout(fd, it->ai_addr, (socklen_t)it->ai_addrlen, SOCKET_IO_TIMEOUT_SECS) == 0) {
            qrx_set_socket_timeout(fd, SOCKET_IO_TIMEOUT_SECS);
            break;
        }
        qrx_close_socket(fd); fd = -1;
    }
    freeaddrinfo(results);
    return fd;
}

static int storage_discovery_push_to_peer(const char *node_dir,const char *wire_b64,const char *host,int port){
    int fd=connect_to(host,port);if(fd<0)return -1;char*hello=NULL;if(build_hello_message(node_dir,&hello)!=0||!hello){free(hello);qrx_close_socket(fd);return -1;}if(send_framed(fd,hello)){free(hello);qrx_close_socket(fd);return -1;}free(hello);char*r=recv_framed(fd);if(!r||!strstr(r,"status=OK")){free(r);qrx_close_socket(fd);return -1;}free(r);size_t n=strlen(wire_b64)+64;char*m=malloc(n);if(!m){qrx_close_socket(fd);return -1;}snprintf(m,n,"type=STORAGE_DISCOVERY_PUSH\nwire_b64=%s\n",wire_b64);int rc=send_framed(fd,m);free(m);if(!rc){r=recv_framed(fd);rc=r&&strstr(r,"status=OK")?0:-1;free(r);}qrx_close_socket(fd);return rc;
}
static int storage_discovery_fanout(const char *node_dir,const char *wire_b64,const char *skip_host){
    char p[1024];snprintf(p,sizeof(p),"%s/known_peers.txt",node_dir);char*peers=read_file(p,NULL);if(!peers){snprintf(p,sizeof(p),"%s/peers.txt",node_dir);peers=read_file(p,NULL);}if(!peers)return 0;int sent=0;char*save=NULL;for(char*ln=strtok_r(peers,"\n",&save);ln&&sent<4;ln=strtok_r(NULL,"\n",&save)){char*colon=strrchr(ln,':');if(!colon)continue;*colon=0;if(skip_host&&!*skip_host?0:(skip_host&&!strcmp(skip_host,ln)))continue;int port=atoi(colon+1);if(port>0&&peer_rep_score(node_dir,ln)>PEER_REP_MIN&&!storage_discovery_push_to_peer(node_dir,wire_b64,ln,port))sent++;}free(peers);return sent;
}

static int aura_gossip_push_to_peer(const char *node_dir,const char *kind,const char *wire_b64,const char *host,int port){
    if(!kind||(!strcmp(kind,"AURA_POD_PUSH")?0:strcmp(kind,"AURA_MODEL_PUSH"))||!wire_b64) return -1;
    int fd=connect_to(host,port);
    if(fd<0) return -1;
    char*hello=NULL;
    build_hello_message(node_dir,&hello);
    if(!hello||send_framed(fd,hello)){free(hello);qrx_close_socket(fd);return -1;}
    free(hello);
    char*r=recv_framed(fd);
    if(!r||!strstr(r,"status=OK")){free(r);qrx_close_socket(fd);return -1;}
    free(r);
    size_t n=strlen(kind)+strlen(wire_b64)+32;
    char*m=malloc(n);
    if(!m){qrx_close_socket(fd);return -1;}
    snprintf(m,n,"type=%s\nwire_b64=%s\n",kind,wire_b64);
    int rc=send_framed(fd,m);
    free(m);
    if(!rc){r=recv_framed(fd);rc=r&&strstr(r,"status=OK")?0:-1;free(r);}
    qrx_close_socket(fd);
    return rc;
}
static int aura_gossip_fanout(const char *node_dir,const char *kind,const char *wire_b64,const char *skip_host){
    char p[1024];snprintf(p,sizeof(p),"%s/known_peers.txt",node_dir);char*peers=read_file(p,NULL);if(!peers){snprintf(p,sizeof(p),"%s/peers.txt",node_dir);peers=read_file(p,NULL);}if(!peers)return 0;int sent=0;char*save=NULL;for(char*ln=strtok_r(peers,"\n",&save);ln&&sent<4;ln=strtok_r(NULL,"\n",&save)){char*colon=strrchr(ln,':');if(!colon)continue;*colon=0;if(skip_host&&*skip_host&&!strcmp(skip_host,ln))continue;int port=atoi(colon+1);if(port>0&&peer_rep_score(node_dir,ln)>PEER_REP_MIN&&!aura_gossip_push_to_peer(node_dir,kind,wire_b64,ln,port))sent++;}free(peers);return sent;
}

static char *aura_gossip_request_peer(const char *node_dir,const char *host,int port,const char *request){
    if(!node_dir||!host||port<=0||!request) return NULL;
    int fd=connect_to(host,port);if(fd<0) return NULL;
    char *hello=NULL;build_hello_message(node_dir,&hello);
    if(!hello||send_framed(fd,hello)){free(hello);qrx_close_socket(fd);return NULL;}
    free(hello);
    char *r=recv_framed(fd);
    if(!r||!strstr(r,"status=OK")){free(r);qrx_close_socket(fd);return NULL;}
    free(r);
    if(send_framed(fd,request)){qrx_close_socket(fd);return NULL;}
    r=recv_framed(fd);qrx_close_socket(fd);return r;
}
static int aura_pull_remote_kind(const char *node_dir,const char *chain_dir,const char *host,int port,int models,uint64_t h,QrxAuraPodGossipTable *rp,QrxAuraModelGossipTable *rm){
    if(!node_dir||!chain_dir||!host||port<=0||!rp||!rm) return -1;
    size_t offset=0,total=SIZE_MAX;QrxDB db;int have_db=0;
    if(!models){if(qrxdb_init(&db,chain_dir))return -2;have_db=1;}
    for(unsigned page=0;page<300&&offset<total;page++){
        char req[160];snprintf(req,sizeof(req),"type=%s\\noffset=%llu\\nlimit=16\\n",models?"AURA_MODEL_PULL":"AURA_POD_PULL",(unsigned long long)offset);
        char *resp=aura_gossip_request_peer(node_dir,host,port,req);if(!resp||!strstr(resp,"status=OK")){free(resp);if(have_db)qrxdb_close(&db);return -3;}
        char *rs=cfg_get(resp,"returned"),*ns=cfg_get(resp,"next_offset"),*ts=cfg_get(resp,"total");
        if(!rs||!ns||!ts){free(rs);free(ns);free(ts);free(resp);if(have_db)qrxdb_close(&db);return -4;}
        size_t returned=(size_t)strtoull(rs,NULL,10),next=(size_t)strtoull(ns,NULL,10);total=(size_t)strtoull(ts,NULL,10);free(rs);free(ns);free(ts);
        size_t max_total=models?QRX_AURA_GOSSIP_MAX_MODELS:QRX_AURA_GOSSIP_MAX_PODS;
        if(returned>16||total>max_total||next<offset||next>total||(returned&&next<=offset)){free(resp);if(have_db)qrxdb_close(&db);return -5;}
        for(size_t i=0;i<returned;i++){
            char key[64];snprintf(key,sizeof(key),"entry%llu_b64",(unsigned long long)i);char *wb=cfg_get(resp,key);if(!wb){free(resp);if(have_db)qrxdb_close(&db);return -6;}
            size_t wn=0;uint8_t *wire=base64_decode(wb,&wn);free(wb);if(!wire){free(resp);if(have_db)qrxdb_close(&db);return -6;}
            int irc=-1;
            if(models){QrxAuraModelProfileAnnouncement a;uint8_t *sig=NULL;size_t sl=0;if(!qrx_aura_model_wire_decode(wire,wn,&a,&sig,&sl)){irc=qrx_aura_model_gossip_ingest(rm,&a,sig,sl,h,aura_model_gov_key_lookup,(void*)chain_dir,aura_model_gov_authorize,(void*)chain_dir);}free(sig);}
            else {QrxAuraPodAnnouncement a;uint8_t *sig=NULL;size_t sl=0;if(!qrx_aura_pod_wire_decode(wire,wn,&a,&sig,&sl)){irc=qrx_aura_pod_gossip_ingest(rp,&a,sig,sl,h,aura_compute_provider_key_lookup,&db);}free(sig);}
            free(wire);
            if(irc){free(resp);if(have_db)qrxdb_close(&db);return -7;}
        }
        free(resp);
        if(!returned){if(next!=total){if(have_db)qrxdb_close(&db);return -8;}break;}
        offset=next;
    }
    if(have_db)qrxdb_close(&db);
    return offset==total?0:-9;
}
static int aura_gossip_sync_peer(const char *node_dir,const char *chain_dir,const char *host,int port){
    if(!g_aura_gossip_ready||!node_dir||!chain_dir||!host||port<=0) return -1;
    long long hh=current_height_from_chain(chain_dir);uint64_t h=(uint64_t)(hh<0?0:hh);QrxAuraGossipDigest local;
    if(qrx_aura_gossip_digest(&g_aura_pod_gossip,&g_aura_model_gossip,h,&local)) return -2;
    char *resp=aura_gossip_request_peer(node_dir,host,port,"type=AURA_SYNC_DIGEST\\n");if(!resp||!strstr(resp,"status=OK")){free(resp);return -3;}
    char *rh=cfg_get(resp,"height"),*rr=cfg_get(resp,"combined_root");
    if(!rh||!rr||strlen(rr)!=64){free(rh);free(rr);free(resp);return -4;}
    uint64_t peer_h=strtoull(rh,NULL,10);free(rh);int same=!strcmp(rr,local.combined_root);free(rr);free(resp);
    uint64_t delta=peer_h>h?peer_h-h:h-peer_h;if(delta>8) return 1;
    if(same) return 0;
    QrxAuraPodGossipTable rp;QrxAuraModelGossipTable rm;qrx_aura_pod_gossip_init(&rp);qrx_aura_model_gossip_init(&rm);
    int rc=aura_pull_remote_kind(node_dir,chain_dir,host,port,0,h,&rp,&rm);
    if(!rc) rc=aura_pull_remote_kind(node_dir,chain_dir,host,port,1,h,&rp,&rm);
    if(!rc){QrxDB db;if(qrxdb_init(&db,chain_dir))rc=-5;else{size_t pu=0,mu=0;rc=qrx_aura_gossip_anti_entropy_merge(&g_aura_pod_gossip,&g_aura_model_gossip,&rp,&rm,h,aura_compute_provider_key_lookup,&db,aura_model_gov_key_lookup,(void*)chain_dir,aura_model_gov_authorize,(void*)chain_dir,&pu,&mu);qrxdb_close(&db);if(!rc&&(pu||mu)){if(g_aura_pod_cache_path[0])qrx_aura_pod_gossip_cache_save(&g_aura_pod_gossip,g_aura_pod_cache_path);if(g_aura_model_cache_path[0])qrx_aura_model_gossip_cache_save(&g_aura_model_gossip,g_aura_model_cache_path);}}}
    qrx_aura_pod_gossip_free(&rp);qrx_aura_model_gossip_free(&rm);return rc;
}
static int aura_gossip_anti_entropy_tick(const char *node_dir,const char *cfg){
    static time_t last=0;time_t now=time(NULL);
    if(!g_aura_gossip_ready||!node_dir||!cfg)return 0;
    char *is=cfg_get(cfg,"aura_anti_entropy_interval_seconds");long long interval=is?atoll(is):15;free(is);if(interval<=0)return 0;if(interval<5)interval=5;if(interval>3600)interval=3600;
    if(!last){last=now;return 0;}
    if(now-last<interval) return 0;
    last=now;
    char *chain_dir=cfg_get(cfg,"chain_dir");if(!chain_dir)return 0;
    char path[1024];snprintf(path,sizeof(path),"%s/known_peers.txt",node_dir);char *txt=read_file(path,NULL);if(!txt){snprintf(path,sizeof(path),"%s/peers.txt",node_dir);txt=read_file(path,NULL);}if(!txt){free(chain_dir);return 0;}
    char peers[MAX_PEERS][256];int ports[MAX_PEERS];size_t n=0;char *save=NULL;
    for(char *ln=strtok_r(txt,"\\n",&save);ln&&n<MAX_PEERS;ln=strtok_r(NULL,"\\n",&save)){char *colon=strrchr(ln,':');if(!colon)continue;*colon=0;int pt=atoi(colon+1);if(pt<=0||strlen(ln)>=sizeof(peers[n])||peer_rep_score(node_dir,ln)<=PEER_REP_MIN)continue;snprintf(peers[n],sizeof(peers[n]),"%s",ln);ports[n++]=pt;}
    int synced=0;if(n){size_t start=(size_t)((unsigned long long)now/(unsigned long long)interval%n);for(size_t k=0;k<n&&k<2;k++){size_t i=(start+k)%n;int rc=aura_gossip_sync_peer(node_dir,chain_dir,peers[i],ports[i]);if(rc<0)peer_add_score(node_dir,peers[i],rc==-2||rc==-4?10:2);else synced++;}}
    free(txt);free(chain_dir);return synced;
}

static int sendtx_to_peer(const char *node_dir, const char *tx_text, const char *host, int port) {
    int fd = connect_to(host, port); if (fd < 0) return -1;
    char *hello = NULL; if (build_hello_message(node_dir, &hello) != 0 || !hello) { free(hello); qrx_close_socket(fd); return -1; } if (send_framed(fd, hello) != 0) { free(hello); qrx_close_socket(fd); return -1; } free(hello);
    char *resp = recv_framed(fd); if (!resp || !strstr(resp, "status=OK")) { free(resp); qrx_close_socket(fd); return -1; } free(resp);
    char *tx_b64 = base64_encode((unsigned char*)tx_text, strlen(tx_text)); size_t cap = strlen(tx_b64)+32; char *msg = malloc(cap); snprintf(msg, cap, "type=TX\ntx_b64=%s\n", tx_b64);
    int rc = send_framed(fd, msg); free(msg); free(tx_b64); if (rc != 0) { qrx_close_socket(fd); return -1; }
    resp = recv_framed(fd); int ok = resp && strstr(resp, "status=OK") ? 0 : -1; free(resp); qrx_close_socket(fd); return ok;
}

static int node_run_cmd(const char *node_dir) {
    qrx_net_init_once();
    signal(SIGINT, on_sigint);
    if(qrx_velocity_mempool_open(&g_velocity_mempool,node_dir,MEMPOOL_MAX_TXS)!=0) die("VELOCITY mempool init/recovery failed");
    g_velocity_mempool_ready=1;
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *host = cfg_get(cfg, "host"), *port_s = cfg_get(cfg, "port"); int port = atoi(port_s);
    qrx_storage_discovery_init(&g_storage_discovery);g_storage_discovery_ready=1;
    {char *cd=cfg_get(cfg,"chain_dir");if(cd){snprintf(g_storage_discovery_cache_path,sizeof(g_storage_discovery_cache_path),"%s/storage-discovery.cache",cd);QrxDB db;if(!qrxdb_init(&db,cd)){long long hh=current_height_from_chain(cd);qrx_storage_discovery_cache_load(&g_storage_discovery,&db,g_storage_discovery_cache_path,(uint64_t)(hh<0?0:hh),qrx_storage_provider_discovery_key_lookup,&db);qrx_storage_discovery_prune(&g_storage_discovery,(uint64_t)(hh<0?0:hh));qrxdb_close(&db);}free(cd);}}
    qrx_aura_pod_gossip_init(&g_aura_pod_gossip);qrx_aura_model_gossip_init(&g_aura_model_gossip);g_aura_gossip_ready=1;
    {char *cd=cfg_get(cfg,"chain_dir");if(cd){long long hh=current_height_from_chain(cd);uint64_t h=(uint64_t)(hh<0?0:hh);snprintf(g_aura_pod_cache_path,sizeof(g_aura_pod_cache_path),"%s/aura-pod-gossip.cache",cd);snprintf(g_aura_model_cache_path,sizeof(g_aura_model_cache_path),"%s/aura-model-gossip.cache",cd);QrxDB db;if(!qrxdb_init(&db,cd)){qrx_aura_pod_gossip_cache_load(&g_aura_pod_gossip,g_aura_pod_cache_path,h,aura_compute_provider_key_lookup,&db);qrxdb_close(&db);}qrx_aura_model_gossip_cache_load(&g_aura_model_gossip,g_aura_model_cache_path,h,aura_model_gov_key_lookup,cd,aura_model_gov_authorize,cd);qrx_aura_pod_gossip_prune(&g_aura_pod_gossip,h);qrx_aura_model_gossip_prune(&g_aura_model_gossip,h);free(cd);}}
    char *storage_enabled=cfg_get(cfg,"storage_enabled");
    if(storage_enabled && atoi(storage_enabled)!=0){
        char *sp=cfg_get(cfg,"storage_path"), *pid=cfg_get(cfg,"storage_provider_id"), *mx=cfg_get(cfg,"storage_max_usage_bytes"), *mf=cfg_get(cfg,"storage_min_free_space_bytes");
        uint64_t maxu=mx?strtoull(mx,NULL,10):0, minf=mf?strtoull(mf,NULL,10):0;
        if(!sp||!*sp||!pid||!*pid||strlen(pid)>=sizeof(g_storage_provider_id)||qrx_storage_fs_open(sp,maxu,minf,&g_storage_fs)!=0) die("storage provider configuration/init failed");
        snprintf(g_storage_provider_id,sizeof(g_storage_provider_id),"%s",pid);g_storage_ready=1;
        printf("storage provider enabled id=%s backend=%s path=%s\n",g_storage_provider_id,qrx_storage_fs_backend_name(),sp);
        free(sp);free(pid);free(mx);free(mf);
    }
    free(storage_enabled);
    int s = socket(AF_INET, SOCK_STREAM, 0); if (s < 0) die("socket failed");
    int one=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    qrx_set_socket_timeout(s, SOCKET_IO_TIMEOUT_SECS);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port); inet_pton(AF_INET, host, &addr.sin_addr);
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) die("bind failed: %s", strerror(errno));
    if (listen(s, 16) != 0) die("listen failed");
    printf("node listening on %s:%d\n", host, port);
    while (!g_stop) {
        generals_relay_process_node(node_dir);
        storage_provider_auto_accept(node_dir,cfg);
        storage_provider_auto_postor(node_dir,cfg);
        storage_provider_auto_repair(node_dir,cfg);
        if(g_aura_gossip_ready){char*cd=cfg_get(cfg,"chain_dir");if(cd){long long hh=current_height_from_chain(cd);uint64_t h=(uint64_t)(hh<0?0:hh);qrx_aura_pod_gossip_prune(&g_aura_pod_gossip,h);qrx_aura_model_gossip_prune(&g_aura_model_gossip,h);free(cd);}aura_gossip_anti_entropy_tick(node_dir,cfg);}
        fd_set rfds;FD_ZERO(&rfds);FD_SET(s,&rfds);struct timeval tv;tv.tv_sec=1;tv.tv_usec=0;int sr=select(s+1,&rfds,NULL,NULL,&tv);
        if(sr<0){if(errno==EINTR)break;continue;}
        if(sr==0)continue;
        struct sockaddr_in cli; socklen_t clilen = sizeof(cli); int fd = accept(s, (struct sockaddr*)&cli, &clilen);
        if (fd < 0) { if (errno == EINTR) break; continue; }
        char storage_magic[8]={0}; int storage_conn=0;
#ifdef _WIN32
        int pk=recv(fd,storage_magic,7,MSG_PEEK);
#else
        ssize_t pk=recv(fd,storage_magic,7,MSG_PEEK);
#endif
        if(pk==7 && !memcmp(storage_magic,"QRXSTOR",7) && g_storage_ready){
            char *chain_dir=cfg_get(cfg,"chain_dir"); QrxDB sdb;
            if(chain_dir && qrxdb_init(&sdb,chain_dir)==0){ qrx_storage_qrxp2p_serve_fd(fd,&sdb,g_storage_fs,g_storage_provider_id); qrxdb_close(&sdb); storage_conn=1; storage_provider_auto_accept(node_dir,cfg); storage_provider_auto_postor(node_dir,cfg); storage_provider_auto_repair(node_dir,cfg); }
            free(chain_dir);
        }
        if(!storage_conn){ node_handle_client(fd, node_dir); qrx_close_socket(fd); }
    }
    qrx_close_socket(s); free(cfg); free(host); free(port_s);
    if(g_velocity_mempool_ready){qrx_velocity_mempool_checkpoint(&g_velocity_mempool);qrx_velocity_mempool_close(&g_velocity_mempool);g_velocity_mempool_ready=0;}
    if(g_storage_ready){qrx_storage_fs_close(g_storage_fs);g_storage_fs=NULL;g_storage_ready=0;OPENSSL_cleanse(g_storage_provider_id,sizeof(g_storage_provider_id));}
    if(g_storage_discovery_ready){if(g_storage_discovery_cache_path[0])qrx_storage_discovery_cache_save(&g_storage_discovery,g_storage_discovery_cache_path);qrx_storage_discovery_free(&g_storage_discovery);g_storage_discovery_ready=0;g_storage_discovery_cache_path[0]=0;}
    if(g_aura_gossip_ready){if(g_aura_pod_cache_path[0])qrx_aura_pod_gossip_cache_save(&g_aura_pod_gossip,g_aura_pod_cache_path);if(g_aura_model_cache_path[0])qrx_aura_model_gossip_cache_save(&g_aura_model_gossip,g_aura_model_cache_path);qrx_aura_pod_gossip_free(&g_aura_pod_gossip);qrx_aura_model_gossip_free(&g_aura_model_gossip);g_aura_gossip_ready=0;g_aura_pod_cache_path[0]=0;g_aura_model_cache_path[0]=0;}
    hello_key_cache_clear();
    return 0;
}

static int sendtx_cmd(const char *node_dir, const char *tx_file) {
    char *tx = read_file(tx_file, NULL); if (!tx) die("cannot read tx");
    char p[1024]; snprintf(p, sizeof(p), "%s/peers.txt", node_dir); char *peers = read_file(p, NULL); if (!peers) die("missing peers.txt");
    int sent = 0;
    const char *cur = peers;
    while (cur && *cur) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur); if (len > 0) {
            char line[256]; memcpy(line, cur, len); line[len]=0; char *colon = strrchr(line, ':'); if (colon) { *colon=0; int port=atoi(colon+1); if (peer_rep_score(node_dir, line) > PEER_REP_MIN && sendtx_to_peer(node_dir, tx, line, port)==0) sent++; }
        }
        cur = e ? e+1 : NULL;
    }
    printf("sent=%d\n", sent); free(tx); free(peers); return sent > 0 ? 0 : 1;
}


static long long total_validator_power_all(const char *chain_dir) {
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    StateKVRecord *arr = NULL; size_t n = 0; if (kv_load(stakes, &arr, &n) != 0) return 0;
    long long total = 0; for (size_t i=0;i<n;i++) if (arr[i].value > 0) total += arr[i].value + kv_get_ll_bin(totals, arr[i].key);
    free(arr); return total;
}

static int block_consensus_values(const char *block_file, char **block_hash, char **validator, char **height_s, char **round_s) {
    char *blk = read_file(block_file, NULL); if (!blk) return -1;
    *block_hash = cfg_get(blk, "block_hash");
    *validator = cfg_get(blk, "validator");
    *height_s = cfg_get(blk, "height");
    *round_s = cfg_get(blk, "round");
    free(blk);
    return (*block_hash && *validator && *height_s && *round_s) ? 0 : -1;
}

static char *vote_payload_for_sign(const char *network_id, const char *genesis_hash, const char *protocol_version,
                                   const char *block_hash, const char *height_s, const char *round_s,
                                   const char *validator, const char *validator_power_s, const char *timestamp) {
    size_t cap = strlen(network_id)+strlen(genesis_hash)+strlen(protocol_version)+strlen(block_hash)+strlen(height_s)+strlen(round_s)+strlen(validator)+strlen(validator_power_s)+strlen(timestamp)+256;
    char *p = malloc(cap); if (!p) die("oom");
    snprintf(p, cap,
        "network_id=%s\n"
        "genesis_hash=%s\n"
        "protocol_version=%s\n"
        "block_hash=%s\n"
        "height=%s\n"
        "round=%s\n"
        "validator=%s\n"
        "validator_power=%s\n"
        "timestamp=%s\n",
        network_id, genesis_hash, protocol_version, block_hash, height_s, round_s, validator, validator_power_s, timestamp);
    return p;
}

static int verify_vote_file_internal(const char *chain_dir, const char *vote_file,
                                     const char *expected_block_hash, const char *expected_height_s, const char *expected_round_s,
                                     char *out_validator, size_t out_validator_sz, long long *out_power) {
    char *txt = read_file(vote_file, NULL); if (!txt) return -1;
    char *network_id = cfg_get(txt, "network_id"), *genesis_hash = cfg_get(txt, "genesis_hash"), *protocol_version = cfg_get(txt, "protocol_version");
    char *block_hash = cfg_get(txt, "block_hash"), *height_s = cfg_get(txt, "height"), *round_s = cfg_get(txt, "round"), *validator = cfg_get(txt, "validator"), *validator_power_s = cfg_get(txt, "validator_power"), *timestamp = cfg_get(txt, "timestamp"), *pub_hex = cfg_get(txt, "vote_pub_ed25519_hex"), *sig_hex = cfg_get(txt, "vote_sig_ed25519_hex");
    int rc = -1;
    if (!network_id||!genesis_hash||!protocol_version||!block_hash||!height_s||!round_s||!validator||!validator_power_s||!timestamp||!pub_hex||!sig_hex) goto done;
    char *exp_net = chain_cfg_value(chain_dir, "network_id"), *exp_gen = chain_cfg_value(chain_dir, "genesis_hash"), *exp_ver = chain_cfg_value(chain_dir, "protocol_version");
    if (strcmp(network_id, exp_net) || strcmp(genesis_hash, exp_gen) || strcmp(protocol_version, exp_ver)) { free(exp_net); free(exp_gen); free(exp_ver); goto done; }
    free(exp_net); free(exp_gen); free(exp_ver);
    if (expected_block_hash && strcmp(block_hash, expected_block_hash)) goto done;
    if (expected_height_s && strcmp(height_s, expected_height_s)) goto done;
    if (expected_round_s && strcmp(round_s, expected_round_s)) goto done;
    long long vh=atoll(height_s), vts=atoll(timestamp), now=(long long)time(NULL), gt=qrx_chain_get_ll_or_default(chain_dir,"genesis_time",0);
    if(network_id && strstr(network_id,"mainnet") && gt>0 && (now<gt || vts<gt)) goto done;
    if(vts>now+QRX_MAX_FUTURE_DRIFT_SECONDS) goto done;
    if(validator_is_tombstoned(chain_dir,validator)||validator_is_jailed_now(chain_dir,validator)||validator_is_safely_paused(chain_dir,validator)||validator_is_compute_jailed_at(chain_dir,validator,vh)) goto done;
    unsigned char raw[32]; size_t rawlen=0; if (hex_to_bytes(pub_hex, raw, sizeof(raw), &rawlen) != 0 || rawlen != 32) goto done;
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, rawlen); if (!pub) goto done;
    if (address_matches_pub(pub, validator) != 0) { EVP_PKEY_free(pub); goto done; }
    long long current_power = validator_power_from_snapshot(chain_dir, height_s ? atoll(height_s) : 0, round_s ? atoll(round_s) : 0, validator); if (current_power <= 0 || current_power != atoll(validator_power_s)) { EVP_PKEY_free(pub); goto done; }
    char *payload = vote_payload_for_sign(network_id, genesis_hash, protocol_version, block_hash, height_s, round_s, validator, validator_power_s, timestamp);
    unsigned char *sig = malloc(strlen(sig_hex)/2+1); size_t siglen=0; if (hex_to_bytes(sig_hex, sig, strlen(sig_hex)/2+1, &siglen) != 0) { free(payload); EVP_PKEY_free(pub); free(sig); goto done; }
    if (verify_oneshot(pub, (unsigned char*)payload, strlen(payload), sig, siglen) != 0) { free(payload); EVP_PKEY_free(pub); free(sig); goto done; }
    if (out_validator) snprintf(out_validator, out_validator_sz, "%s", validator);
    if (out_power) *out_power = current_power;
    free(payload); EVP_PKEY_free(pub); free(sig); rc = 0;
  done:
    if (network_id) free(network_id); if (genesis_hash) free(genesis_hash); if (protocol_version) free(protocol_version); if (block_hash) free(block_hash); if (height_s) free(height_s); if (round_s) free(round_s); if (validator) free(validator); if (validator_power_s) free(validator_power_s); if (timestamp) free(timestamp); if (pub_hex) free(pub_hex); if (sig_hex) free(sig_hex); free(txt);
    return rc;
}

static int vote_block_cmd_as(const char *node_dir, const char *block_file, const char *wallet_override) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *chain_dir = cfg_get(cfg, "chain_dir"), *wallet_dir = cfg_get(cfg, "wallet_dir"), *network_id = cfg_get(cfg, "network_id"), *genesis_hash = cfg_get(cfg, "genesis_hash"), *protocol_version = cfg_get(cfg, "protocol_version"), *address = cfg_get(cfg, "address");
    if (wallet_override && *wallet_override) {
        if (wallet_dir) free(wallet_dir);
        if (address) free(address);
        wallet_dir = strdup(wallet_override);
        address = wallet_address(wallet_override);
        if (!wallet_dir || !address) die("validator signer wallet override invalid");
        address[strcspn(address, "\r\n")]=0;
    }
    long long genesis_activation = qrx_chain_get_ll_or_default(chain_dir,"genesis_time",0);
    if (network_id && strstr(network_id,"mainnet") && genesis_activation > 0 && (long long)time(NULL) < genesis_activation) die("Mainnet not started yet: voting is disabled until 2026-09-15 16:00 UTC / 18:00 CEST");
    if (verify_block_cmd(chain_dir, block_file) != 0) die("block verify failed");
    if (validator_is_safely_paused(chain_dir,address)) die("validator is SAFE PAUSED on-chain");
    if (validator_is_tombstoned(chain_dir, address)) die("validator tombstoned");
    if (validator_is_jailed_now(chain_dir, address)) die("validator jailed");
    char *block_hash=NULL, *validator=NULL, *height_s=NULL, *round_s=NULL; if (block_consensus_values(block_file, &block_hash, &validator, &height_s, &round_s) != 0) die("block values failed");
    if (validator_is_compute_jailed_at(chain_dir,address,atoll(height_s))) die("validator is compute-fraud jailed on-chain");
    long long power = validator_power_from_snapshot(chain_dir, atoll(height_s), atoll(round_s), address); if (power <= 0) die("validator not active in snapshot");
    char lockp[1024], votesdir[1024]; node_lock_paths(node_dir, lockp, sizeof(lockp), votesdir, sizeof(votesdir)); mkdir_p(votesdir);
    /* Fleet signers share one P2P node but must never share the same local
       double-sign lock. Bind the lock to the validator identity. */
    if (wallet_override && *wallet_override) snprintf(lockp, sizeof(lockp), "%s/consensus-%s.lock", node_dir, address);
    char *locktxt = read_file(lockp, NULL);
    if (locktxt) {
        char *lh = cfg_get(locktxt, "locked_height"), *lr = cfg_get(locktxt, "locked_round"), *lbh = cfg_get(locktxt, "locked_block_hash");
        if (lh && lr && lbh && strcmp(lh, height_s) == 0 && strcmp(lr, round_s) == 0 && strcmp(lbh, block_hash) != 0) die("double-sign lock conflict");
        if (lh) free(lh); if (lr) free(lr); if (lbh) free(lbh); free(locktxt);
    }
    char power_s[64], ts[64]; snprintf(power_s, sizeof(power_s), "%lld", power); snprintf(ts, sizeof(ts), "%lld", (long long)time(NULL));
    char *payload = vote_payload_for_sign(network_id, genesis_hash, protocol_version, block_hash, height_s, round_s, address, power_s, ts);
    char pass[256]; if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");
    snprintf(p, sizeof(p), "%s/ed25519_priv.pem", wallet_dir); EVP_PKEY *priv = load_priv_pem(p, pass); if (!priv) die("load vote signing key failed");
    snprintf(p, sizeof(p), "%s/ed25519_pub.pem", wallet_dir); EVP_PKEY *pub = load_pub_pem(p); if (!pub) die("load vote pub failed");
    unsigned char raw[32]; if (ed25519_raw_pub(pub, raw) != 0) die("raw vote pub failed");
    char *pub_hex = bytes_to_hex(raw, sizeof(raw));
    unsigned char *sig=NULL; size_t siglen=0; if (sign_oneshot(priv, (unsigned char*)payload, strlen(payload), &sig, &siglen) != 0) die("vote sign failed");
    char *sig_hex = bytes_to_hex(sig, siglen);
    char vote[8192]; snprintf(vote, sizeof(vote),
        "network_id=%s\n"
        "genesis_hash=%s\n"
        "protocol_version=%s\n"
        "block_hash=%s\n"
        "height=%s\n"
        "round=%s\n"
        "validator=%s\n"
        "validator_power=%s\n"
        "timestamp=%s\n"
        "vote_pub_ed25519_hex=%s\n"
        "vote_sig_ed25519_hex=%s\n",
        network_id, genesis_hash, protocol_version, block_hash, height_s, round_s, address, power_s, ts, pub_hex, sig_hex);
    snprintf(p, sizeof(p), "%s/outbox/votes/%s-%s.vote", node_dir, height_s, address); if (write_text(p, vote) != 0) die("write vote failed");
    char localp[1024]; snprintf(localp, sizeof(localp), "%s/%s-%s-%s.vote", votesdir, height_s, round_s, address); write_text(localp, vote);
    char lockbuf[512]; snprintf(lockbuf, sizeof(lockbuf), "locked_height=%s\nlocked_round=%s\nlocked_block_hash=%s\nlocked_at=%lld\n", height_s, round_s, block_hash, (long long)time(NULL)); write_text(lockp, lockbuf);
    printf("%s\n", p);
    OPENSSL_cleanse(pass, sizeof(pass));
    free(cfg); free(chain_dir); free(wallet_dir); free(network_id); free(genesis_hash); free(protocol_version); free(address); free(block_hash); free(validator); free(height_s); free(round_s); free(payload); free(pub_hex); free(sig); free(sig_hex); EVP_PKEY_free(priv); EVP_PKEY_free(pub); return 0;
}

static int vote_block_cmd(const char *node_dir, const char *block_file) {
    return vote_block_cmd_as(node_dir, block_file, NULL);
}


static int tally_votes_cmd(const char *chain_dir, const char *block_file) {
    char *block_hash=NULL, *validator=NULL, *height_s=NULL, *round_s=NULL; if (block_consensus_values(block_file, &block_hash, &validator, &height_s, &round_s) != 0) die("block values failed");
    char dir[1024]; snprintf(dir, sizeof(dir), "%s/consensus/votes", chain_dir);
    long long yes_power=0, total_power=snapshot_total_power(chain_dir, atoll(height_s), atoll(round_s)); char seen[512][385]; int seen_n=0;
    char vote_files[2048][1024]; int vote_n=qrx_collect_files_suffix(dir,".vote",vote_files,2048);
    for(int vi=0;vi<vote_n;vi++){ const char *fname=vote_files[vi]; char vaddr[385]=""; long long pwr=0;
        if (verify_vote_file_internal(chain_dir, fname, block_hash, height_s, round_s, vaddr, sizeof(vaddr), &pwr) == 0) {
            int dup=0; for (int i=0;i<seen_n;i++) if (!strcmp(seen[i], vaddr)) { dup=1; break; }
            if (!dup && seen_n < 512) { snprintf(seen[seen_n++], sizeof(seen[0]), "%s", vaddr); yes_power += pwr; }
        }
    }
    printf("block_hash=%s\nheight=%s\nround=%s\nyes_power=%lld\ntotal_power=%lld\nquorum=%s\n", block_hash, height_s, round_s, yes_power, total_power, (yes_power*3 > total_power*2) ? "1" : "0");
    free(block_hash); free(validator); free(height_s); free(round_s); return 0;
}


/* Phase 6.5 consensus maintenance: resolve combat that belongs to a completed
 * turn during block finalization. No player transaction or online game client
 * is required; every validator derives the same transition from finalized
 * height and QRXDB state. */
typedef struct { char **ids; long long *sid,*turn; size_t n,cap; } GenAutoList;
static int generals_auto_collect_cb(const char*k,const char*v,uint32_t vl,void*ctx){(void)vl;GenAutoList*l=ctx;if(strcmp(v,"pending"))return 0;long long sid=0,tr=0;char id[256]={0};if(sscanf(k,"generals:combat:%lld:%lld:target:%255[^:]:status",&sid,&tr,id)!=3)return 0;if(l->n==l->cap){size_t nc=l->cap?l->cap*2:16;char**ni=realloc(l->ids,nc*sizeof(*ni));long long*ns=realloc(l->sid,nc*sizeof(*ns)),*nt=realloc(l->turn,nc*sizeof(*nt));if(!ni||!ns||!nt)return -1;l->ids=ni;l->sid=ns;l->turn=nt;l->cap=nc;}l->ids[l->n]=strdup(id);l->sid[l->n]=sid;l->turn[l->n]=tr;l->n++;return 0;}
static int generals_autonomous_world_resolve(const char*c,long long h){
    long long cs=0,ss=0,se=0,ct=0,ts=0,te=0;if(generals_season_at(c,h,&cs,&ss,&se,&ct,&ts,&te))return 0;
    QrxDB db;if(qrxdb_init(&db,c))return -1;GenAutoList l={0};if(qrxdb_scan_prefix(&db,"generals:combat:",generals_auto_collect_cb,&l)){qrxdb_close(&db);return -1;}int nres=0;
    for(size_t i=0;i<l.n;i++){if(l.sid[i]!=cs||l.turn[i]>=ct){free(l.ids[i]);continue;}char k[1024],buf[256];snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:damage",l.sid[i],l.turn[i],l.ids[i]);long long dmg=0;if(qrxdb_get(&db,k,buf,sizeof(buf))==0)dmg=atoll(buf);snprintf(k,sizeof(k),"generals:unit:%s:hp",l.ids[i]);long long hp=0;if(qrxdb_get(&db,k,buf,sizeof(buf))==0)hp=atoll(buf);if(dmg>0&&hp>0){long long nh=hp>dmg?hp-dmg:0;QrxDBBatch b;if(!qrxdb_batch_begin(&db,&b)){snprintf(k,sizeof(k),"generals:unit:%s:hp",l.ids[i]);velocity_batch_put_ll(&b,k,nh);snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:status",l.sid[i],l.turn[i],l.ids[i]);qrxdb_batch_put(&b,k,"resolved");snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:resolved_by",l.sid[i],l.turn[i],l.ids[i]);qrxdb_batch_put(&b,k,"CONSENSUS_AUTO");snprintf(k,sizeof(k),"generals:combat:%lld:%lld:target:%s:resolved_height",l.sid[i],l.turn[i],l.ids[i]);velocity_batch_put_ll(&b,k,h);if(nh==0){snprintf(k,sizeof(k),"generals:unit:%s:status",l.ids[i]);qrxdb_batch_put(&b,k,"destroyed");}if(qrxdb_batch_commit(&b)==0)nres++;else qrxdb_batch_abort(&b);}}
        free(l.ids[i]);}
    free(l.ids);free(l.sid);free(l.turn);qrxdb_close(&db);return nres;
}

static int finalize_block_cmd(const char *chain_dir, const char *block_file) {
    if(verify_block_cmd(chain_dir,block_file)!=0) die("block verify failed before finalization");
    char *block_hash=NULL,*validator=NULL,*height_s=NULL,*round_s=NULL;if(block_consensus_values(block_file,&block_hash,&validator,&height_s,&round_s)!=0)die("block values failed");
    char *blk=read_file(block_file,NULL); if(!blk)die("cannot read block"); char *bts=cfg_get(blk,"timestamp"); free(blk);
    long long expected_h=0,parent_ts=0;char parent_hash[129],parent_root[129];if(qrx_expected_parent(chain_dir,&expected_h,parent_hash,parent_root,&parent_ts)!=0)die("cannot resolve finalized parent");if(atoll(height_s)!=expected_h)die("finalization height is not exact next finalized height");
    char dir[1024];snprintf(dir,sizeof(dir),"%s/consensus/votes",chain_dir); long long yes_power=0,total_power=snapshot_total_power(chain_dir,atoll(height_s),atoll(round_s));if(total_power<=0)die("empty validator snapshot");char seen[512][385];int seen_n=0;char vote_files[2048][1024];int vote_n=qrx_collect_files_suffix(dir,".vote",vote_files,2048);
    for(int vi=0;vi<vote_n;vi++){char vaddr[385]="";long long pwr=0;if(verify_vote_file_internal(chain_dir,vote_files[vi],block_hash,height_s,round_s,vaddr,sizeof(vaddr),&pwr)==0){int dup=0;for(int i=0;i<seen_n;i++)if(!strcmp(seen[i],vaddr)){dup=1;break;}if(!dup&&seen_n<512){snprintf(seen[seen_n++],sizeof(seen[0]),"%s",vaddr);yes_power+=pwr;}}}
    if (!(yes_power*3 > total_power*2)) die("quorum not reached");
    /* Ingest only after quorum. Proposal creation no longer mutates authoritative chain index. */
    if(qrxdb_chain_ingest_block_file(chain_dir,block_file)!=0)die("qrxdb finalized block ingest failed");
    char final_root[129];if(qrx_current_state_root(chain_dir,final_root)!=0)die("state root unavailable after finalization");
    char out[1024];snprintf(out,sizeof(out),"%s/consensus/finalized/%s.final",chain_dir,height_s);if(access_qrx(out,F_OK)==0)die("height already finalized");
    char final[8192];snprintf(final,sizeof(final),"height=%s\nround=%s\nblock_hash=%s\nprevious_block_hash=%s\nparent_state_root=%s\nfinalized_state_root=%s\nblock_timestamp=%s\nblock_file=%s\nyes_power=%lld\ntotal_power=%lld\nfinalized_at=%lld\n",height_s,round_s,block_hash,parent_hash,parent_root,final_root,bts?bts:"0",block_file,yes_power,total_power,(long long)time(NULL));
    if(write_text(out,final)!=0)die("write finalization failed"); record_validator_seen(chain_dir,validator,atoll(height_s));int offline_penalties=apply_offline_penalties(chain_dir,atoll(height_s));int generals_auto_resolved=generals_autonomous_world_resolve(chain_dir,atoll(height_s));journal_append(chain_dir,"finalize height=%s round=%s block_hash=%s parent=%s yes_power=%lld total_power=%lld state_root=%s offline_penalties=%d generals_auto_resolved=%d",height_s,round_s,block_hash,parent_hash,yes_power,total_power,final_root,offline_penalties,generals_auto_resolved);printf("%s\noffline_penalties=%d\ngenerals_auto_resolved=%d\nstate_root=%s\n",out,offline_penalties,generals_auto_resolved,final_root);
    if(bts)free(bts);free(block_hash);free(validator);free(height_s);free(round_s);return 0;
}

static int send_file_to_peer(const char *node_dir, const char *file_text, const char *kind, const char *host, int port) {
    int fd = connect_to(host, port); if (fd < 0) return -1;
    char *hello = NULL; if (build_hello_message(node_dir, &hello) != 0 || !hello) { free(hello); qrx_close_socket(fd); return -1; } if (send_framed(fd, hello) != 0) { free(hello); qrx_close_socket(fd); return -1; } free(hello);
    char *resp = recv_framed(fd); if (!resp || !strstr(resp, "status=OK")) { free(resp); qrx_close_socket(fd); return -1; } free(resp);
    char *b64 = base64_encode((unsigned char*)file_text, strlen(file_text)); size_t cap = strlen(b64)+64; char *msg = malloc(cap); snprintf(msg, cap, "type=%s\ndata_b64=%s\n", kind, b64);
    int rc = send_framed(fd, msg); free(msg); free(b64); if (rc != 0) { qrx_close_socket(fd); return -1; }
    resp = recv_framed(fd); int ok = resp && strstr(resp, "status=OK") ? 0 : -1; free(resp); qrx_close_socket(fd); return ok;
}

static int publish_generic_cmd(const char *node_dir, const char *file, const char *kind) {
    char *txt = read_file(file, NULL); if (!txt) die("cannot read file");
    char p[1024]; snprintf(p, sizeof(p), "%s/peers.txt", node_dir); char *peers = read_file(p, NULL); if (!peers) die("missing peers.txt");
    int sent = 0; const char *cur = peers;
    while (cur && *cur) {
        const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur); if (len > 0) {
            char line[256]; memcpy(line, cur, len); line[len]=0; char *colon = strrchr(line, ':'); if (colon) { *colon=0; int port=atoi(colon+1); if (peer_rep_score(node_dir, line) > PEER_REP_MIN && send_file_to_peer(node_dir, txt, kind, line, port)==0) sent++; }
        }
        cur = e ? e+1 : NULL;
    }
    printf("sent=%d\n", sent); free(txt); free(peers); return sent > 0 ? 0 : 1;
}

static int node_publish_block_cmd(const char *node_dir, const char *block_file) { return publish_generic_cmd(node_dir, block_file, "BLOCK"); }
static int node_publish_vote_cmd(const char *node_dir, const char *vote_file) { return publish_generic_cmd(node_dir, vote_file, "VOTE"); }
static int generals_relay_publish_cmd(const char *node_dir,const char *file){return publish_generic_cmd(node_dir,file,"GENERALS_RELAY");}

static int node_process_inbox_cmd(const char *node_dir) {
    char p[1024];snprintf(p,sizeof(p),"%s/node.conf",node_dir);char*cfg=read_file(p,NULL);if(!cfg)die("missing node.conf");char*chain_dir=cfg_get(cfg,"chain_dir");int processed_blocks=0,processed_votes=0,finalized=0;
    char dir[1024], files[4096][1024];
    snprintf(dir,sizeof(dir),"%s/inbox/blocks",node_dir);int n=qrx_collect_files_suffix(dir,".block",files,4096);
    for(int i=0;i<n;i++){const char*fname=files[i];if(verify_block_cmd(chain_dir,fname)==0){vote_block_cmd(node_dir,fname);processed_blocks++;}unlink_qrx(fname);}
    snprintf(dir,sizeof(dir),"%s/inbox/votes",node_dir);n=qrx_collect_files_suffix(dir,".vote",files,4096);
    for(int i=0;i<n;i++){const char*fname=files[i];char*txt=read_file(fname,NULL);if(txt){char*height_s=cfg_get(txt,"height"),*validator=cfg_get(txt,"validator");if(height_s&&validator){char dest[1024];snprintf(dest,sizeof(dest),"%s/consensus/votes/%s-%s.vote",chain_dir,height_s,validator);if(write_text(dest,txt)==0)processed_votes++;}if(height_s)free(height_s);if(validator)free(validator);free(txt);}unlink_qrx(fname);}
    /* Only exact-next-height proposals can finalize. Directory iteration is native;
       no shell/find invocation receives a user-controlled path. */
    snprintf(dir,sizeof(dir),"%s/blocks",chain_dir);n=qrx_collect_files_suffix(dir,".block",files,4096);
    for(int i=0;i<n;i++){char *bh=NULL,*v=NULL,*hs=NULL,*rs=NULL;if(block_consensus_values(files[i],&bh,&v,&hs,&rs)==0){long long expected_h=0,pts=0;char ph[129],pr[129];if(qrx_expected_parent(chain_dir,&expected_h,ph,pr,&pts)==0&&atoll(hs)==expected_h){char final_path[1024];snprintf(final_path,sizeof(final_path),"%s/consensus/finalized/%s.final",chain_dir,hs);if(access_qrx(final_path,F_OK)!=0){/* finalize_block_cmd fail-closes internally */if(finalize_block_cmd(chain_dir,files[i])==0)finalized++;}}free(bh);free(v);free(hs);free(rs);}}
    printf("processed_blocks=%d\nprocessed_votes=%d\nfinalized=%d\n",processed_blocks,processed_votes,finalized);free(cfg);free(chain_dir);return 0;
}

static int propose_block_cmd_as(const char *node_dir, int max_txs, const char *wallet_override) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *chain_dir = cfg_get(cfg, "chain_dir"), *address = cfg_get(cfg, "address"), *wallet_dir = cfg_get(cfg, "wallet_dir");
    if (wallet_override && *wallet_override) {
        if (wallet_dir) free(wallet_dir);
        if (address) free(address);
        wallet_dir = strdup(wallet_override);
        address = wallet_address(wallet_override);
        if (!wallet_dir || !address) die("validator proposer wallet override invalid");
        address[strcspn(address, "\r\n")]=0;
    }
    char *network_id = cfg_get(cfg, "network_id"), *genesis_hash = cfg_get(cfg, "genesis_hash"), *protocol_version = cfg_get(cfg, "protocol_version"), *consensus_version = cfg_get(cfg, "consensus_version"), *chain_id = cfg_get(cfg, "chain_id");
    long long genesis_activation = qrx_chain_get_ll_or_default(chain_dir,"genesis_time",0);
    if (network_id && strstr(network_id,"mainnet") && genesis_activation > 0 && (long long)time(NULL) < genesis_activation) die("Mainnet not started yet: Genesis activation is 2026-09-15 16:00 UTC / 18:00 CEST");
    if (validator_is_safely_paused(chain_dir,address)) die("validator is SAFE PAUSED on-chain; resume it before validating");
    long long height=0,parent_ts=0; char previous_block_hash[129],parent_state_root[129];
    if(qrx_expected_parent(chain_dir,&height,previous_block_hash,parent_state_root,&parent_ts)!=0) die("cannot resolve finalized parent");
    if (validator_is_compute_jailed_at(chain_dir,address,height)) die("validator is compute-fraud jailed on-chain");
    long long validator_power = validator_power_total(chain_dir, address);
    if (!validator_has_min_self_stake_at(chain_dir, address, height)) die("validator self stake below minimum");
    if (validator_power <= 0) die("validator not active in current validator set");
    long long round = 0;
    long long chain_max_txs = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "max_txs_per_block", 100);
    if (max_txs <= 0 || max_txs > chain_max_txs) max_txs = (int)chain_max_txs;
    if (validator_snapshot_write(chain_dir, height, round) != 0) die("validator snapshot write failed");
    long long snap_power=validator_power_from_snapshot(chain_dir,height,round,address); if(snap_power<=0)die("validator not active in consensus snapshot"); validator_power=snap_power;
    char expected_proposer[385];if(expected_proposer_from_snapshot(chain_dir,height,round,expected_proposer)!=0)die("cannot derive deterministic proposer");if(strcmp(expected_proposer,address))die("this validator is not the deterministic proposer for this height/round");
    char blockbuf[MAX_MSG]; size_t off = 0; long long now_ts=(long long)time(NULL);
    off += snprintf(blockbuf+off, sizeof(blockbuf)-off,
        "network_id=%s\ngenesis_hash=%s\nprotocol_version=%s\nconsensus_version=%s\nchain_id=%s\nheight=%lld\nround=%lld\nprevious_block_hash=%s\nparent_state_root=%s\nvalidator=%s\nvalidator_power=%lld\ntimestamp=%lld\n",
        network_id, genesis_hash, protocol_version, consensus_version, chain_id, height, round, previous_block_hash,parent_state_root,address, validator_power, now_ts);
    int count = 0;
    QrxVelocityMempool vpool; QrxVelocityPlan vplan; memset(&vplan,0,sizeof(vplan));
    if(qrx_velocity_mempool_open(&vpool,node_dir,MEMPOOL_MAX_TXS)==0){
        if(qrx_velocity_mempool_plan(&vpool,(size_t)max_txs,&vplan)==0){
            char applpath[1024]; state_paths(chain_dir,NULL,0,NULL,0,applpath,sizeof(applpath),NULL,0);
            int workers=4; const char *we=getenv("QRX_SIGNATURE_WORKERS"); if(we&&atoi(we)>0)workers=atoi(we); if(workers>64)workers=64;
            unsigned char *valid=NULL; QrxVelocityVerifyStats vst; memset(&vst,0,sizeof(vst));
            if(qrx_velocity_parallel_verify(&vplan,(uint32_t)workers,velocity_stateless_verify_cb,chain_dir,&valid,&vst)!=0) die("VELOCITY parallel signature verification failed");
            for(size_t i=0;i<vplan.count && count<max_txs;i++){
                if(!valid[i]){continue;}
                char *body_hash=cfg_get(vplan.txs[i],"body_hash_sha3_512");
                if(body_hash && applied_has_authoritative(chain_dir,applpath,body_hash)){free(body_hash);continue;}
                if(body_hash)free(body_hash);
                off += snprintf(blockbuf+off,sizeof(blockbuf)-off,"tx%d=%s\n",count+1,vplan.txids[i]);
                off += snprintf(blockbuf+off,sizeof(blockbuf)-off,"tx%d_wave=%u\n",count+1,vplan.waves[i]);
                count++;
            }
            off += snprintf(blockbuf+off,sizeof(blockbuf)-off,"velocity_execution_waves=%u\nvelocity_conflicts=%llu\nvelocity_sig_workers=%u\nvelocity_sig_verify_us=%llu\n",
                vplan.wave_count,(unsigned long long)vplan.conflicts,vst.workers,(unsigned long long)vst.elapsed_us);
            free(valid); qrx_velocity_plan_free(&vplan);
        }
        qrx_velocity_mempool_close(&vpool);
    }
    off += snprintf(blockbuf+off, sizeof(blockbuf)-off, "tx_count=%d\n", count);
    char block_hash[129]; hash_primary_hex((unsigned char*)blockbuf, off, block_hash);
    char block_hash_legacy[65]; hash_legacy_hex((unsigned char*)blockbuf, off, block_hash_legacy);
    char pass[256]; if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");
    snprintf(p, sizeof(p), "%s/ed25519_priv.pem", wallet_dir); EVP_PKEY *priv = load_priv_pem(p, pass); if (!priv) die("load block signing key failed");
    snprintf(p, sizeof(p), "%s/ed25519_pub.pem", wallet_dir); EVP_PKEY *pub = load_pub_pem(p); if (!pub) die("load block pub failed");
    unsigned char raw[32]; if (ed25519_raw_pub(pub, raw) != 0) die("raw block pub failed");
    char *pub_hex = bytes_to_hex(raw, sizeof(raw));
    unsigned char *sig=NULL; size_t siglen=0; if (sign_oneshot(priv, (unsigned char*)blockbuf, off, &sig, &siglen) != 0) die("block sign failed");
    char *sig_hex = bytes_to_hex(sig, siglen);
    size_t final_cap = off + strlen(block_hash) + strlen(pub_hex) + strlen(sig_hex) + 256; char *final = malloc(final_cap);
    snprintf(final, final_cap, "%shash_algo=sha3-512\nblock_hash=%s\nblock_hash_sha256_legacy=%s\nblock_sig_ed25519_hex=%s\nblock_pub_ed25519_hex=%s\n", blockbuf, block_hash, block_hash_legacy, sig_hex, pub_hex);
    char blk[1024]; snprintf(blk, sizeof(blk), "%s/blocks/%lld-%s.block", chain_dir, (long long)time(NULL), block_hash); write_text(blk, final);
    /* A proposal is not authoritative state. It enters QRXDB only after >2/3 finalization. */
    printf("%s\n", blk);
    free(final); free(pub_hex); free(sig); free(sig_hex); EVP_PKEY_free(priv); EVP_PKEY_free(pub); OPENSSL_cleanse(pass, sizeof(pass));
    free(cfg); free(chain_dir); free(address); free(wallet_dir); free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id); return 0;
}

static int propose_block_cmd(const char *node_dir, int max_txs) {
    return propose_block_cmd_as(node_dir, max_txs, NULL);
}


static int verify_block_cmd(const char *chain_dir, const char *block_file) {
    char *blk=read_file(block_file,NULL);if(!blk)die("cannot read block");
    char *network_id=cfg_get(blk,"network_id"),*genesis_hash=cfg_get(blk,"genesis_hash"),*protocol_version=cfg_get(blk,"protocol_version"),*consensus_version=cfg_get(blk,"consensus_version"),*chain_id=cfg_get(blk,"chain_id");
    char *height_s=cfg_get(blk,"height"),*round_s=cfg_get(blk,"round"),*previous_block_hash=cfg_get(blk,"previous_block_hash"),*parent_state_root=cfg_get(blk,"parent_state_root"),*validator=cfg_get(blk,"validator"),*validator_power_s=cfg_get(blk,"validator_power"),*timestamp_s=cfg_get(blk,"timestamp"),*tx_count_s=cfg_get(blk,"tx_count"),*block_hash=cfg_get(blk,"block_hash"),*hash_algo=cfg_get(blk,"hash_algo"),*block_hash_sha256_legacy=cfg_get(blk,"block_hash_sha256_legacy"),*sig_hex=cfg_get(blk,"block_sig_ed25519_hex"),*pub_hex=cfg_get(blk,"block_pub_ed25519_hex");
    if(!network_id||!genesis_hash||!protocol_version||!consensus_version||!chain_id||!height_s||!round_s||!previous_block_hash||!parent_state_root||!validator||!validator_power_s||!timestamp_s||!block_hash||!hash_algo||!sig_hex||!pub_hex)die("invalid block fields");
    char *exp_net=chain_cfg_value(chain_dir,"network_id"),*exp_gen=chain_cfg_value(chain_dir,"genesis_hash"),*exp_ver=chain_cfg_value(chain_dir,"protocol_version"),*exp_cons=chain_cfg_value(chain_dir,"consensus_version"),*exp_chain=chain_cfg_value(chain_dir,"chain_id");if(strcmp(network_id,exp_net)||strcmp(genesis_hash,exp_gen)||strcmp(protocol_version,exp_ver)||strcmp(consensus_version,exp_cons)||strcmp(chain_id,exp_chain))die("block network binding mismatch");
    long long height=atoll(height_s),round=atoll(round_s),ts=atoll(timestamp_s),expected_h=0,parent_ts=0;char expected_parent[129],expected_root[129];if(height<=0||round<0)die("invalid height/round");if(qrx_expected_parent(chain_dir,&expected_h,expected_parent,expected_root,&parent_ts)!=0)die("cannot resolve finalized parent");if(height!=expected_h)die("block height is not exact next finalized height");if(strcmp(previous_block_hash,expected_parent))die("previous_block_hash does not match finalized parent");if(strcmp(parent_state_root,expected_root))die("parent_state_root mismatch");
    long long genesis_time=qrx_chain_get_ll_or_default(chain_dir,"genesis_time",0),now=(long long)time(NULL);if(network_id&&strstr(network_id,"mainnet")&&genesis_time>0){if(now<genesis_time)die("Mainnet Genesis activation time has not been reached");if(ts<genesis_time)die("block timestamp predates Mainnet Genesis activation");}if(ts>now+QRX_MAX_FUTURE_DRIFT_SECONDS)die("block timestamp too far in future");if(parent_ts>0&&ts<parent_ts)die("block timestamp precedes finalized parent");
    long long max_block_bytes=qrx_chain_get_ll_at_height_or_default(chain_dir,height,"max_block_bytes",524288LL),max_txs=qrx_chain_get_ll_at_height_or_default(chain_dir,height,"max_txs_per_block",100LL);size_t blk_len=strlen(blk);if((long long)blk_len>max_block_bytes)die("block exceeds max_block_bytes");if(tx_count_s&&(atoll(tx_count_s)<0||atoll(tx_count_s)>max_txs))die("block exceeds max_txs_per_block");
    char *sig_line=strstr(blk,"hash_algo=");if(!sig_line)die("invalid block file");size_t body_len=(size_t)(sig_line-blk);char body_hash[129];hash_primary_hex((unsigned char*)blk,body_len,body_hash);if(strcmp(hash_algo,"sha3-512"))die("unsupported block hash algo");if(strcmp(body_hash,block_hash))die("block hash mismatch");if(block_hash_sha256_legacy){char old[65];hash_legacy_hex((unsigned char*)blk,body_len,old);if(strcmp(old,block_hash_sha256_legacy))die("block legacy hash mismatch");}
    unsigned char raw[32];size_t rawlen=0;if(hex_to_bytes(pub_hex,raw,sizeof(raw),&rawlen)!=0||rawlen!=32)die("bad block pub");EVP_PKEY*pub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,raw,rawlen);if(!pub)die("block pub construct failed");if(address_matches_pub(pub,validator)!=0)die("validator address mismatch");
    unsigned char *sig=malloc(strlen(sig_hex)/2+1);size_t siglen=0;if(hex_to_bytes(sig_hex,sig,strlen(sig_hex)/2+1,&siglen)!=0)die("bad block sig");if(verify_oneshot(pub,(unsigned char*)blk,body_len,sig,siglen)!=0)die("block signature verify failed");
    /* Eligibility checks happen only after authenticating the signer. This prevents crafted unauthenticated conflicts from triggering slashing. */
    if(validator_is_tombstoned(chain_dir,validator))die("validator tombstoned");if(validator_is_jailed_now(chain_dir,validator))die("validator jailed");if(validator_is_safely_paused(chain_dir,validator))die("validator SAFE PAUSED");if(validator_is_compute_jailed_at(chain_dir,validator,height))die("validator compute-fraud jailed");if(!validator_has_min_self_stake_at(chain_dir,validator,height))die("validator self stake below minimum");if(validator_snapshot_write(chain_dir,height,round)!=0)die("validator snapshot unavailable");long long current_power=validator_power_from_snapshot(chain_dir,height,round,validator);if(current_power<=0||atoll(validator_power_s)!=current_power)die("validator power mismatch");char expected_proposer[385];if(expected_proposer_from_snapshot(chain_dir,height,round,expected_proposer)!=0)die("cannot derive deterministic proposer");if(strcmp(expected_proposer,validator))die("unexpected proposer for height/round");
    if(check_and_record_double_sign_block(chain_dir,validator,height_s,round_s,block_hash)!=0)die("double sign detected and slashed");
    puts("OK");EVP_PKEY_free(pub);free(sig);free(blk);free(network_id);free(genesis_hash);free(protocol_version);free(consensus_version);free(chain_id);free(height_s);free(round_s);free(previous_block_hash);free(parent_state_root);free(validator);free(validator_power_s);free(timestamp_s);if(tx_count_s)free(tx_count_s);free(block_hash);free(hash_algo);if(block_hash_sha256_legacy)free(block_hash_sha256_legacy);free(sig_hex);free(pub_hex);free(exp_net);free(exp_gen);free(exp_ver);free(exp_cons);free(exp_chain);return 0;
}


typedef struct {
    char validator[385];
    long long self_stake;
    long long delegated;
    long long power;
} ValidatorPower;

static void staking_paths(const char *chain_dir,
                          char *stakes, size_t ssz,
                          char *delegations, size_t dsz,
                          char *delegated_totals, size_t tsz,
                          char *unbonding, size_t ub_sz,
                          char *unbonding_eta, size_t ue_sz,
                          char *undelegations, size_t ud_sz,
                          char *undelegation_eta, size_t ude_sz,
                          char *penalties, size_t psz) {
    if (stakes) snprintf(stakes, ssz, "%s/state/stakes.bin", chain_dir);
    if (delegations) snprintf(delegations, dsz, "%s/state/delegations.bin", chain_dir);
    if (delegated_totals) snprintf(delegated_totals, tsz, "%s/state/delegated_totals.bin", chain_dir);
    if (unbonding) snprintf(unbonding, ub_sz, "%s/state/unbonding.bin", chain_dir);
    if (unbonding_eta) snprintf(unbonding_eta, ue_sz, "%s/state/unbonding_eta.bin", chain_dir);
    if (undelegations) snprintf(undelegations, ud_sz, "%s/state/undelegations.bin", chain_dir);
    if (undelegation_eta) snprintf(undelegation_eta, ude_sz, "%s/state/undelegation_eta.bin", chain_dir);
    if (penalties) snprintf(penalties, psz, "%s/state/penalties.bin", chain_dir);
}

static int adjust_balance(const char *chain_dir, const char *addr, long long delta) {
    char bal[1024], nonce[1024], appl[1024], journal[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    long long cur = kv_get_ll_bin(bal, addr);
    if (delta < 0 && cur < -delta) return -1;
    return kv_set_ll_bin(bal, addr, cur + delta);
}

static long long validator_power_total(const char *chain_dir, const char *validator) {
    char kself[1024],ktotal[1024]; long long self=0,delegated=0; int fs,fd;
    snprintf(kself,sizeof(kself),"staking:self:%s",validator); snprintf(ktotal,sizeof(ktotal),"staking:delegated_total:%s",validator);
    fs=staking_db_ll_found(chain_dir,kself,&self); fd=staking_db_ll_found(chain_dir,ktotal,&delegated);
    if(!fs || !fd){
        char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
        staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
        if(!fs) self=kv_get_ll_bin(stakes,validator); if(!fd) delegated=kv_get_ll_bin(totals,validator);
    }
    return self+delegated;
}

static int validator_is_active(const char *chain_dir, const char *validator) {
    return validator_power_total(chain_dir, validator) > 0 ? 1 : 0;
}


typedef struct { char (*users)[385]; size_t *count; size_t max; } CollectStakeCtx;
static int collect_stake_user_cb(const char*k,const char*v,uint32_t vl,void*opaque){(void)vl;CollectStakeCtx*c=(CollectStakeCtx*)opaque;if(atoll(v)<=0)return 0;const char*addr=NULL;
    if(!strncmp(k,"staking:self:",13))addr=k+13; else if(!strncmp(k,"staking:delegated_total:",24))addr=k+24; else return 0;
    for(size_t j=0;j<*c->count;j++)if(!strcmp(c->users[j],addr))return 0; if(*c->count<c->max){snprintf(c->users[*c->count],385,"%s",addr);(*c->count)++;} return 0;}

static int collect_known_users(const char *chain_dir, char users[][385], size_t max_users) {
    char bal[1024], nonce[1024], appl[1024], journal[1024], stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], penalties[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), penalties, sizeof(penalties));
    size_t count = 0;
    StateKVRecord *arr = NULL; size_t n = 0;
    const char *files[] = { bal, stakes, delegations, totals, ub, ud };
    for (size_t fi = 0; fi < sizeof(files)/sizeof(files[0]); ++fi) {
        arr = NULL; n = 0;
        if (kv_load(files[fi], &arr, &n) != 0) continue;
        for (size_t i = 0; i < n; ++i) {
            if (arr[i].value <= 0) continue;
            char candidate[385];
            if (strstr(arr[i].key, "->")) {
                const char *arrow = strstr(arr[i].key, "->");
                size_t left_len = (size_t)(arrow - arr[i].key);
                if (left_len >= sizeof(candidate)) left_len = sizeof(candidate)-1;
                memcpy(candidate, arr[i].key, left_len); candidate[left_len] = 0;
                int exists = 0;
                for (size_t j = 0; j < count; ++j) if (strcmp(users[j], candidate) == 0) { exists = 1; break; }
                if (!exists && count < max_users) { snprintf(users[count], sizeof(users[count]), "%s", candidate); count++; }
                snprintf(candidate, sizeof(candidate), "%s", arrow + 2);
            } else {
                snprintf(candidate, sizeof(candidate), "%s", arr[i].key);
            }
            int exists = 0;
            for (size_t j = 0; j < count; ++j) if (strcmp(users[j], candidate) == 0) { exists = 1; break; }
            if (!exists && count < max_users) { snprintf(users[count], sizeof(users[count]), "%s", candidate); count++; }
        }
        free(arr);
    }
    /* Phase 7.2.12: consensus-native staking keys must participate in validator discovery even when legacy mirrors do not exist. */
    QrxDB sdb; if(qrxdb_init(&sdb,chain_dir)==0){ CollectStakeCtx cx={users,&count,max_users}; qrxdb_scan_prefix(&sdb,"staking:",collect_stake_user_cb,&cx); qrxdb_close(&sdb); }
    return (int)count;
}


typedef struct {
    char id[129];
    char sender[385];
    char recipient[385];
    long long amount;
    char hashlock[129];
    long long created_at;
    long long timelock_at;
    char status[32];
    char secret_hash[129];
    char memo[256];
} HtlcRecord;

static void htlc_paths(const char *chain_dir, char *swaps, size_t ssz) {
    snprintf(swaps, ssz, "%s/htlc_swaps.db", chain_dir);
}

static int is_hex_string(const char *s, size_t min_len, size_t max_len) {
    size_t n = s ? strlen(s) : 0;
    if (n < min_len || n > max_len) return 0;
    for (size_t i=0;i<n;i++) {
        char c = s[i];
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return 0;
    }
    return 1;
}

static void sha256_hex_local(const char *in, char out[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)in, strlen(in), digest);
    for (int i=0;i<SHA256_DIGEST_LENGTH;i++) sprintf(out + i*2, "%02x", digest[i]);
    out[64] = 0;
}

static void random_hex_local(char *out, size_t bytes) {
    unsigned char buf[64];
    if (bytes > sizeof(buf)) bytes = sizeof(buf);
    if (RAND_bytes(buf, (int)bytes) != 1) {
        unsigned long long fallback = (unsigned long long)time(NULL) ^ (unsigned long long)getpid();
        SHA256((unsigned char*)&fallback, sizeof(fallback), buf);
    }
    for (size_t i=0;i<bytes;i++) sprintf(out + i*2, "%02x", buf[i]);
    out[bytes*2] = 0;
}

static void clean_field(char *s) {
    if (!s) return;
    for (char *p=s; *p; ++p) if (*p=='|' || *p=='\n' || *p=='\r') *p='_';
}

static int privacy_legacy_mainnet_gate(const char *chain_dir) {
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    int is_mainnet = network_id && (strstr(network_id, "mainnet") || strstr(network_id, "Mainnet"));
    free(network_id);
    if (!is_mainnet) return 0;
    fprintf(stderr, "legacy file-backed privacy mutation is disabled on Mainnet; use signed PRIVACY_* consensus transactions\n");
    return -1;
}

static int htlc_mainnet_gate(const char *chain_dir) {
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    int is_mainnet = network_id && (strstr(network_id, "mainnet") || strstr(network_id, "Mainnet"));
    free(network_id);
    if (!is_mainnet) return 0;
    /* Phase 7.1: the legacy file-backed Quantum Swap/HTLC engine is never an
       admissible Mainnet path. There is deliberately no environment-variable
       escape hatch. Mainnet cross-chain settlement must use signed VELOCITY
       CROSSCHAIN_* + BTC_SPV_* transactions and QRXDB atomic state. */
    fprintf(stderr, "legacy HTLC/Quantum Swap path is permanently disabled on Mainnet; use VELOCITY Cross-Chain Settlement\n");
    return -1;
}

static int htlc_parse_line(const char *line, HtlcRecord *r) {
    if (!line || !r) return -1;
    char buf[2048];
    snprintf(buf, sizeof(buf), "%s", line);
    buf[strcspn(buf, "\r\n")] = 0;
    char *fields[10] = {0};
    int n = 0;
    char *cursor = buf;
    while (n < 10) {
        fields[n++] = cursor;
        char *sep = strchr(cursor, '|');
        if (!sep) break;
        *sep = 0;
        cursor = sep + 1;
    }
    if (n < 9) return -1;
    snprintf(r->id, sizeof(r->id), "%s", fields[0] ? fields[0] : "");
    snprintf(r->sender, sizeof(r->sender), "%s", fields[1] ? fields[1] : "");
    snprintf(r->recipient, sizeof(r->recipient), "%s", fields[2] ? fields[2] : "");
    r->amount = atoll(fields[3] ? fields[3] : "0");
    snprintf(r->hashlock, sizeof(r->hashlock), "%s", fields[4] ? fields[4] : "");
    r->created_at = atoll(fields[5] ? fields[5] : "0");
    r->timelock_at = atoll(fields[6] ? fields[6] : "0");
    snprintf(r->status, sizeof(r->status), "%s", fields[7] ? fields[7] : "");
    snprintf(r->secret_hash, sizeof(r->secret_hash), "%s", fields[8] ? fields[8] : "");
    snprintf(r->memo, sizeof(r->memo), "%s", n >= 10 && fields[9] ? fields[9] : "");
    return 0;
}

static void htlc_print_record(const HtlcRecord *r) {
    printf("swap_id=%s\n", r->id);
    printf("sender=%s\n", r->sender);
    printf("recipient=%s\n", r->recipient);
    printf("amount=%lld\n", r->amount);
    printf("hashlock=%s\n", r->hashlock);
    printf("created_at=%lld\n", r->created_at);
    printf("timelock_at=%lld\n", r->timelock_at);
    printf("status=%s\n", r->status);
    printf("secret_hash=%s\n", r->secret_hash);
    printf("memo=%s\n", r->memo);
}

static int htlc_load_all(const char *chain_dir, HtlcRecord **out, size_t *count) {
    char path[1024]; htlc_paths(chain_dir, path, sizeof(path));
    *out = NULL; *count = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t cap = 16, n = 0;
    HtlcRecord *arr = calloc(cap, sizeof(HtlcRecord));
    if (!arr) { fclose(f); return -1; }
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        HtlcRecord r;
        if (htlc_parse_line(line, &r) != 0) continue;
        if (n == cap) {
            cap *= 2;
            HtlcRecord *tmp = realloc(arr, cap * sizeof(HtlcRecord));
            if (!tmp) { free(arr); fclose(f); return -1; }
            arr = tmp;
        }
        arr[n++] = r;
    }
    fclose(f);
    *out = arr; *count = n;
    return 0;
}

static int htlc_save_all(const char *chain_dir, const HtlcRecord *arr, size_t count) {
    char path[1024]; htlc_paths(chain_dir, path, sizeof(path));
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "# id|sender|recipient|amount|hashlock|created_at|timelock_at|status|secret_hash|memo\n");
    for (size_t i=0;i<count;i++) {
        fprintf(f, "%s|%s|%s|%lld|%s|%lld|%lld|%s|%s|%s\n",
            arr[i].id, arr[i].sender, arr[i].recipient, arr[i].amount, arr[i].hashlock,
            arr[i].created_at, arr[i].timelock_at, arr[i].status, arr[i].secret_hash, arr[i].memo);
    }
    fclose(f);
    return 0;
}

static int htlc_create_cmd(const char *chain_dir, const char *wallet_dir, const char *recipient, long long amount, const char *hashlock_hex, long long timelock_seconds, const char *memo) {
    if (htlc_mainnet_gate(chain_dir) != 0) return 1;
    if (amount <= 0) die("htlc amount must be > 0");
    if (!recipient || !*recipient) die("recipient required");
    if (!is_hex_string(hashlock_hex, 64, 128)) die("hashlock must be sha256/sha512 hex");
    if (timelock_seconds < 60) die("timelock must be at least 60 seconds");

    char *sender = wallet_address(wallet_dir);
    if (!sender) die("wallet address unavailable");
    sender[strcspn(sender, "\r\n")] = 0;

    char balpath[1024], noncepath[1024], applpath[1024], journal[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), noncepath, sizeof(noncepath), applpath, sizeof(applpath), journal, sizeof(journal));
    long long frombal = kv_get_ll_bin(balpath, sender);
    if (frombal < amount) die("insufficient funds for htlc lock");

    HtlcRecord *arr = NULL; size_t n = 0;
    if (htlc_load_all(chain_dir, &arr, &n) != 0) die("htlc load failed");
    HtlcRecord *tmp = realloc(arr, (n + 1) * sizeof(HtlcRecord));
    if (!tmp) { free(arr); die("oom"); }
    arr = tmp;
    HtlcRecord *r = &arr[n];
    memset(r, 0, sizeof(*r));
    char rnd[65]; random_hex_local(rnd, 16);
    snprintf(r->id, sizeof(r->id), "qswap_%lld_%s", (long long)time(NULL), rnd);
    snprintf(r->sender, sizeof(r->sender), "%s", sender);
    snprintf(r->recipient, sizeof(r->recipient), "%s", recipient);
    r->amount = amount;
    snprintf(r->hashlock, sizeof(r->hashlock), "%s", hashlock_hex);
    r->created_at = (long long)time(NULL);
    r->timelock_at = r->created_at + timelock_seconds;
    snprintf(r->status, sizeof(r->status), "locked");
    snprintf(r->secret_hash, sizeof(r->secret_hash), "");
    snprintf(r->memo, sizeof(r->memo), "%s", memo ? memo : "");
    clean_field(r->recipient); clean_field(r->memo);

    if (kv_set_ll_bin(balpath, sender, frombal - amount) != 0) { free(sender); free(arr); die("state write failed"); }
    if (htlc_save_all(chain_dir, arr, n + 1) != 0) { free(sender); free(arr); die("htlc save failed"); }

    journal_append(chain_dir, "htlc_create id=%s sender=%s recipient=%s amount=%lld hashlock=%s timelock_at=%lld", r->id, r->sender, r->recipient, r->amount, r->hashlock, r->timelock_at);
    htlc_print_record(r);
    free(sender); free(arr);
    return 0;
}

static int htlc_redeem_cmd(const char *chain_dir, const char *swap_id, const char *secret) {
    if (htlc_mainnet_gate(chain_dir) != 0) return 1;
    if (!swap_id || !*swap_id) die("swap_id required");
    if (!secret || !*secret) die("secret required");
    HtlcRecord *arr = NULL; size_t n = 0;
    if (htlc_load_all(chain_dir, &arr, &n) != 0) die("htlc load failed");
    long long now = (long long)time(NULL);
    int found = -1;
    for (size_t i=0;i<n;i++) if (!strcmp(arr[i].id, swap_id)) { found = (int)i; break; }
    if (found < 0) { free(arr); die("swap not found"); }
    HtlcRecord *r = &arr[found];
    if (strcmp(r->status, "locked")) { free(arr); die("swap not locked"); }
    if (now >= r->timelock_at) { free(arr); die("swap expired; refund path only"); }
    char h[65]; sha256_hex_local(secret, h);
    if (strcasecmp(h, r->hashlock) != 0) { free(arr); die("secret does not match hashlock"); }

    char balpath[1024], journal[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), NULL, 0, NULL, 0, journal, sizeof(journal));
    long long tobal = kv_get_ll_bin(balpath, r->recipient);
    if (kv_set_ll_bin(balpath, r->recipient, tobal + r->amount) != 0) { free(arr); die("state write failed"); }
    snprintf(r->status, sizeof(r->status), "redeemed");
    snprintf(r->secret_hash, sizeof(r->secret_hash), "%s", h);
    if (htlc_save_all(chain_dir, arr, n) != 0) { free(arr); die("htlc save failed"); }
    journal_append(chain_dir, "htlc_redeem id=%s recipient=%s amount=%lld secret_hash=%s", r->id, r->recipient, r->amount, h);
    htlc_print_record(r);
    free(arr);
    return 0;
}

static int htlc_refund_cmd(const char *chain_dir, const char *wallet_dir, const char *swap_id) {
    if (htlc_mainnet_gate(chain_dir) != 0) return 1;
    if (!swap_id || !*swap_id) die("swap_id required");
    char *sender = wallet_address(wallet_dir);
    if (!sender) die("wallet address unavailable");
    sender[strcspn(sender, "\r\n")] = 0;

    HtlcRecord *arr = NULL; size_t n = 0;
    if (htlc_load_all(chain_dir, &arr, &n) != 0) die("htlc load failed");
    long long now = (long long)time(NULL);
    int found = -1;
    for (size_t i=0;i<n;i++) if (!strcmp(arr[i].id, swap_id)) { found = (int)i; break; }
    if (found < 0) { free(sender); free(arr); die("swap not found"); }
    HtlcRecord *r = &arr[found];
    if (strcmp(r->status, "locked")) { free(sender); free(arr); die("swap not locked"); }
    if (strcmp(r->sender, sender)) { free(sender); free(arr); die("only original sender can refund"); }
    if (now < r->timelock_at) { free(sender); free(arr); die("timelock not expired"); }

    char balpath[1024], journal[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), NULL, 0, NULL, 0, journal, sizeof(journal));
    long long frombal = kv_get_ll_bin(balpath, r->sender);
    if (kv_set_ll_bin(balpath, r->sender, frombal + r->amount) != 0) { free(sender); free(arr); die("state write failed"); }
    snprintf(r->status, sizeof(r->status), "refunded");
    if (htlc_save_all(chain_dir, arr, n) != 0) { free(sender); free(arr); die("htlc save failed"); }
    journal_append(chain_dir, "htlc_refund id=%s sender=%s amount=%lld", r->id, r->sender, r->amount);
    htlc_print_record(r);
    free(sender); free(arr);
    return 0;
}

static int htlc_get_cmd(const char *chain_dir, const char *swap_id) {
    HtlcRecord *arr = NULL; size_t n = 0;
    if (htlc_load_all(chain_dir, &arr, &n) != 0) die("htlc load failed");
    for (size_t i=0;i<n;i++) {
        if (!strcmp(arr[i].id, swap_id)) {
            htlc_print_record(&arr[i]);
            free(arr); return 0;
        }
    }
    free(arr);
    die("swap not found");
    return 1;
}

static int htlc_list_cmd(const char *chain_dir) {
    HtlcRecord *arr = NULL; size_t n = 0;
    if (htlc_load_all(chain_dir, &arr, &n) != 0) die("htlc load failed");
    for (size_t i=0;i<n;i++) {
        printf("%s sender=%s recipient=%s amount=%lld status=%s timelock_at=%lld hashlock=%s\n",
            arr[i].id, arr[i].sender, arr[i].recipient, arr[i].amount, arr[i].status, arr[i].timelock_at, arr[i].hashlock);
    }
    free(arr);
    return 0;
}



static void sha3_512_hex_local(const char *in, char out[129]);
static void shielded_random_hex(char *out, size_t bytes);


static void sha3_512_hex_local(const char *in, char out[129]) {
    unsigned char digest[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) die("sha3 ctx failed");
    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, in, strlen(in)) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        die("sha3 failed");
    }
    EVP_MD_CTX_free(ctx);
    for (int i=0;i<64;i++) sprintf(out + i*2, "%02x", digest[i]);
    out[128] = 0;
}

static void shielded_random_hex(char *out, size_t bytes) {
    unsigned char buf[64];
    if (bytes > sizeof(buf)) bytes = sizeof(buf);
    if (RAND_bytes(buf, (int)bytes) != 1) die("cryptographic RNG failure");
    for (size_t i=0;i<bytes;i++) sprintf(out + i*2, "%02x", buf[i]);
    out[bytes*2] = 0;
    OPENSSL_cleanse(buf, sizeof(buf));
}

#define QUB_FEATURE_ACTIVATION_HEIGHT_STEALTH 1
#define QUB_FEATURE_ACTIVATION_HEIGHT_SHIELDED_POOL 1
#define QUB_FEATURE_AUDIT_STATUS "audit-pending"


static void bytes_to_hex_local(const unsigned char *in,size_t n,char *out);
static int hex_to_bytes_local(const char *hex,unsigned char *out,size_t n);
static int gov_read_passphrase(char *out,size_t sz,const char *envname,int confirm);

/* QRX Privacy Layer Phase 4: Hidden Balances + Verified Privacy.
   PII stays off-chain. The chain-side registry contains only accepted issuer
   identifiers/public keys/status and opaque credential revocation hashes. */
static void vp_paths(const char *chain_dir,char *att,size_t asz,char *rev,size_t rsz){
    if(att&&asz)snprintf(att,asz,"%s/privacy_attesters.db",chain_dir);
    if(rev&&rsz)snprintf(rev,rsz,"%s/privacy_credential_revocations.db",chain_dir);
}
static void vp_cred_path(const char *wallet_dir,char *out,size_t sz){char d[1024];snprintf(d,sizeof(d),"%s/privacy",wallet_dir);mkdir_p(d);snprintf(out,sz,"%s/verified_privacy.cred",d);}
static int vp_valid_token(const char*s){if(!s||!*s)return 0;for(;*s;s++)if(!(isalnum((unsigned char)*s)||*s=='_'||*s=='-'||*s=='.'))return 0;return 1;}
static int vp_attester_lookup(const char*chain_dir,const char*issuer,char pubhex[65],int*active){char path[1024],line[1024];vp_paths(chain_dir,path,sizeof(path),NULL,0);FILE*f=fopen(path,"rb");if(!f)return -1;int rc=-1;while(fgets(line,sizeof(line),f)){line[strcspn(line,"\r\n")]=0;if(line[0]=='#'||!line[0])continue;char id[128]={0},pk[65]={0},st[16]={0};long long ts=0;if(sscanf(line,"%127[^|]|%64[^|]|%15[^|]|%lld",id,pk,st,&ts)==4&&!strcmp(id,issuer)){snprintf(pubhex,65,"%s",pk);*active=!strcmp(st,"ACTIVE");rc=0;}}fclose(f);return rc;}
static int vp_attester_register_cmd(const char*chain_dir,const char*issuer,const char*pubpem){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;char gconf[1024];snprintf(gconf,sizeof(gconf),"%s/governance/governance.conf",chain_dir);if(access_qrx(gconf,F_OK)==0)die("direct attester mutation disabled after governance genesis; use threshold-signed governance proposal");if(!vp_valid_token(issuer))die("invalid issuer id");EVP_PKEY*p=load_pub_pem(pubpem);unsigned char raw[32];if(!p||EVP_PKEY_id(p)!=EVP_PKEY_ED25519||ed25519_raw_pub(p,raw)!=0){if(p)EVP_PKEY_free(p);die("issuer key must be Ed25519 public PEM");}char hex[65];bytes_to_hex_local(raw,32,hex);EVP_PKEY_free(p);char path[1024];vp_paths(chain_dir,path,sizeof(path),NULL,0);FILE*f=fopen(path,"ab");if(!f)die("attester registry write failed");fprintf(f,"%s|%s|ACTIVE|%lld\n",issuer,hex,(long long)time(NULL));fclose(f);printf("status=registered\nissuer=%s\npublic_key=%s\npii_on_chain=false\n",issuer,hex);return 0;}
static int vp_attester_disable_cmd(const char*chain_dir,const char*issuer){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;char gconf[1024];snprintf(gconf,sizeof(gconf),"%s/governance/governance.conf",chain_dir);if(access_qrx(gconf,F_OK)==0)die("direct attester mutation disabled after governance genesis; use threshold-signed governance proposal");char pk[65];int a=0;if(vp_attester_lookup(chain_dir,issuer,pk,&a)!=0)die("unknown privacy attester");char path[1024];vp_paths(chain_dir,path,sizeof(path),NULL,0);FILE*f=fopen(path,"ab");if(!f)die("attester registry write failed");fprintf(f,"%s|%s|DISABLED|%lld\n",issuer,pk,(long long)time(NULL));fclose(f);printf("status=disabled\nissuer=%s\n",issuer);return 0;}
static int vp_revoked(const char*chain_dir,const char*serial_hash){char path[1024],line[256];vp_paths(chain_dir,NULL,0,path,sizeof(path));FILE*f=fopen(path,"rb");if(!f)return 0;int hit=0;while(fgets(line,sizeof(line),f)){line[strcspn(line,"\r\n")]=0;if(!strcmp(line,serial_hash)){hit=1;break;}}fclose(f);return hit;}
static int vp_revoke_cmd(const char*chain_dir,const char*serial_hash){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;if(!serial_hash||strlen(serial_hash)!=128)die("credential revocation requires opaque SHA3-512 serial hash");char path[1024];vp_paths(chain_dir,NULL,0,path,sizeof(path));FILE*f=fopen(path,"ab");if(!f)die("revocation state write failed");fprintf(f,"%s\n",serial_hash);fclose(f);printf("status=revoked\nserial_hash=%s\npii_on_chain=false\n",serial_hash);return 0;}
static char*vp_get(const char*txt,const char*key){return cfg_get(txt,key);}
static int vp_issue_cmd(const char*chain_dir,const char*wallet_dir,const char*issuer,const char*privpem,long long valid_until){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;char pkhex[65];int active=0;if(vp_attester_lookup(chain_dir,issuer,pkhex,&active)!=0||!active)die("issuer is not an accepted active privacy attester");if(valid_until<=(long long)time(NULL))die("credential expiry must be in the future");EVP_PKEY*priv=load_priv_pem(privpem,"");if(!priv){char apass[256];if(gov_read_passphrase(apass,sizeof(apass),"QRX_ATTESTER_PASSPHRASE",0)!=0)die("attester passphrase failed");priv=load_priv_pem(privpem,apass);OPENSSL_cleanse(apass,sizeof(apass));}if(!priv||EVP_PKEY_id(priv)!=EVP_PKEY_ED25519){if(priv)EVP_PKEY_free(priv);die("issuer private key must be Ed25519 PEM");}unsigned char raw[32];char got[65];size_t rl=32;if(EVP_PKEY_get_raw_public_key(priv,raw,&rl)!=1){EVP_PKEY_free(priv);die("issuer private key unreadable");}bytes_to_hex_local(raw,32,got);if(strcmp(got,pkhex)){EVP_PKEY_free(priv);die("issuer private key does not match accepted attester registry");}char*addr=wallet_address(wallet_dir);if(!addr){EVP_PKEY_free(priv);die("wallet address unavailable");}addr[strcspn(addr,"\r\n")]=0;char salt[65],serial[65],subject[129],serial_hash[129],pre[2048];shielded_random_hex(salt,32);shielded_random_hex(serial,32);snprintf(pre,sizeof(pre),"QUB-VERIFIED-PRIVACY-SUBJECT-v1|%s|%s",addr,salt);sha3_512_hex_local(pre,subject);snprintf(pre,sizeof(pre),"QUB-VERIFIED-PRIVACY-SERIAL-v1|%s",serial);sha3_512_hex_local(pre,serial_hash);long long issued=(long long)time(NULL);snprintf(pre,sizeof(pre),"QUB-VERIFIED-PRIVACY-CREDENTIAL-v1|issuer=%s|subject=%s|serial_hash=%s|issued=%lld|valid_until=%lld|policy=hidden-balance-v1",issuer,subject,serial_hash,issued,valid_until);unsigned char*sig=NULL;size_t sl=0;if(sign_oneshot(priv,(unsigned char*)pre,strlen(pre),&sig,&sl)!=0){EVP_PKEY_free(priv);free(addr);die("credential signature failed");}char*sighex=malloc(sl*2+1);if(!sighex)die("oom");bytes_to_hex_local(sig,sl,sighex);char path[1024];vp_cred_path(wallet_dir,path,sizeof(path));FILE*f=fopen(path,"wb");if(!f)die("credential write failed");fprintf(f,"format=qrx-verified-privacy-v1\nissuer=%s\nsubject_commitment=%s\nsubject_salt=%s\nserial=%s\nserial_hash=%s\nissued_at=%lld\nvalid_until=%lld\npolicy=hidden-balance-v1\nsignature_hex=%s\n",issuer,subject,salt,serial,serial_hash,issued,valid_until,sighex);fclose(f);OPENSSL_cleanse(serial,sizeof(serial));OPENSSL_cleanse(salt,sizeof(salt));OPENSSL_cleanse(sig,sl);free(sig);free(sighex);EVP_PKEY_free(priv);free(addr);printf("status=issued\nissuer=%s\nvalid_until=%lld\nserial_hash=%s\npii_stored_on_chain=false\n",issuer,valid_until,serial_hash);return 0;}
static int vp_verify(const char*chain_dir,const char*wallet_dir,char*reason,size_t rsz){char path[1024];vp_cred_path(wallet_dir,path,sizeof(path));char*txt=read_file(path,NULL);if(!txt){snprintf(reason,rsz,"credential-missing");return -1;}char*fmt=vp_get(txt,"format"),*issuer=vp_get(txt,"issuer"),*sub=vp_get(txt,"subject_commitment"),*salt=vp_get(txt,"subject_salt"),*serial=vp_get(txt,"serial"),*sh=vp_get(txt,"serial_hash"),*ia=vp_get(txt,"issued_at"),*vu=vp_get(txt,"valid_until"),*pol=vp_get(txt,"policy"),*sighex=vp_get(txt,"signature_hex");int rc=-1;char pubhex[65];int active=0;if(!fmt||strcmp(fmt,"qrx-verified-privacy-v1")||!issuer||!sub||!salt||!serial||!sh||!ia||!vu||!pol||strcmp(pol,"hidden-balance-v1")||!sighex){snprintf(reason,rsz,"credential-malformed");goto done;}if(vp_attester_lookup(chain_dir,issuer,pubhex,&active)!=0||!active){snprintf(reason,rsz,"issuer-not-accepted");goto done;}long long issued=atoll(ia),until=atoll(vu),now=(long long)time(NULL);if(now<issued-300||now>until){snprintf(reason,rsz,"credential-expired-or-not-yet-valid");goto done;}if(vp_revoked(chain_dir,sh)){snprintf(reason,rsz,"credential-revoked");goto done;}char*addr=wallet_address(wallet_dir);if(!addr){snprintf(reason,rsz,"wallet-address-unavailable");goto done;}addr[strcspn(addr,"\r\n")]=0;char pre[2048],calc[129];snprintf(pre,sizeof(pre),"QUB-VERIFIED-PRIVACY-SUBJECT-v1|%s|%s",addr,salt);sha3_512_hex_local(pre,calc);free(addr);if(strcmp(calc,sub)){snprintf(reason,rsz,"subject-binding-failed");goto done;}snprintf(pre,sizeof(pre),"QUB-VERIFIED-PRIVACY-SERIAL-v1|%s",serial);sha3_512_hex_local(pre,calc);if(strcmp(calc,sh)){snprintf(reason,rsz,"serial-binding-failed");goto done;}unsigned char pubraw[32];if(hex_to_bytes_local(pubhex,pubraw,32)!=0){snprintf(reason,rsz,"issuer-key-invalid");goto done;}EVP_PKEY*pub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,pubraw,32);size_t sl=strlen(sighex)/2;unsigned char*sig=malloc(sl);if(!pub||!sig||strlen(sighex)%2||hex_to_bytes_local(sighex,sig,sl)!=0){if(pub)EVP_PKEY_free(pub);free(sig);snprintf(reason,rsz,"signature-malformed");goto done;}snprintf(pre,sizeof(pre),"QUB-VERIFIED-PRIVACY-CREDENTIAL-v1|issuer=%s|subject=%s|serial_hash=%s|issued=%lld|valid_until=%lld|policy=hidden-balance-v1",issuer,sub,sh,issued,until);if(verify_oneshot(pub,(unsigned char*)pre,strlen(pre),sig,sl)!=0){snprintf(reason,rsz,"signature-invalid");EVP_PKEY_free(pub);free(sig);goto done;}EVP_PKEY_free(pub);free(sig);snprintf(reason,rsz,"verified");rc=0;done:free(fmt);free(issuer);free(sub);free(salt);free(serial);free(sh);free(ia);free(vu);free(pol);free(sighex);free(txt);return rc;}
static void vp_require(const char*chain_dir,const char*wallet_dir){char r[128];if(vp_verify(chain_dir,wallet_dir,r,sizeof(r))!=0){fprintf(stderr,"verified privacy credential required: %s\n",r);exit(1);}}
static int vp_status_cmd(const char*chain_dir,const char*wallet_dir){char r[128];int ok=vp_verify(chain_dir,wallet_dir,r,sizeof(r))==0;printf("verified=%s\nreason=%s\npii_on_chain=false\npolicy=hidden-balance-v1\n",ok?"true":"false",r);return ok?0:1;}
static int hidden_balance_cmd(const char*chain_dir,const char*wallet_dir){vp_require(chain_dir,wallet_dir);return shielded_balance_cmd(chain_dir,wallet_dir);}
static int verified_shield_cmd(const char*c,const char*w,long long a,const char*z){if(privacy_legacy_mainnet_gate(c)!=0)return 1;vp_require(c,w);return shield_cmd(c,w,a,z);}
static int verified_shielded_send_cmd(const char*c,const char*w,const char*to,long long a){if(privacy_legacy_mainnet_gate(c)!=0)return 1;vp_require(c,w);return shielded_send_cmd(c,w,to,a);}
static int verified_unshield_cmd(const char*c,const char*w,const char*to,long long a){if(privacy_legacy_mainnet_gate(c)!=0)return 1;vp_require(c,w);return unshield_cmd(c,w,to,a);}



/* QRX 0.0.7.5: Genesis Developer Governance + authenticated Attester Registry.
   Governance private keys never enter chain state. Genesis stores only Ed25519
   public roots and a threshold. All registry/protocol mutations below require
   a threshold of unique root signatures over an immutable proposal file. */
#define QRX_GOV_PROPOSAL_FORMAT "qrx-governance-proposal-v1"
#define QRX_GOV_SIGNATURE_FORMAT "qrx-governance-signature-v1"
#define QRX_GOV_SUPPORTED_PROTOCOL 9
#define QRX_GOV_SUPPORTED_PRIVACY 4

static void gov_paths(const char *chain_dir,char *conf,size_t csz,char *roots,size_t rsz,char *log,size_t lsz,char *upg,size_t usz){
    char d[1024];snprintf(d,sizeof(d),"%s/governance",chain_dir);mkdir_p(d);
    if(conf&&csz)snprintf(conf,csz,"%s/governance.conf",d);
    if(roots&&rsz)snprintf(roots,rsz,"%s/governance_roots.db",d);
    if(log&&lsz)snprintf(log,lsz,"%s/governance_applied.db",d);
    if(upg&&usz)snprintf(upg,usz,"%s/protocol_upgrades.db",d);
}
static void gov_hash_text(const char *domain,const char *txt,char out[129]){char *b=NULL;size_t n=strlen(domain)+strlen(txt)+2;b=malloc(n);if(!b)die("oom");snprintf(b,n,"%s|%s",domain,txt);sha3_512_hex_local(b,out);OPENSSL_cleanse(b,n);free(b);}
static void gov_pub_fingerprint(const char *pubhex,char out[33]){char h[129],pre[256];snprintf(pre,sizeof(pre),"QUB-GOVERNANCE-ROOT-v1|%s",pubhex);sha3_512_hex_local(pre,h);memcpy(out,h,32);out[32]=0;}
static int gov_secure_chmod(const char *path){
#if defined(__unix__) || defined(__APPLE__)
    return chmod(path,0600);
#else
    (void)path;return 0;
#endif
}
static int gov_read_passphrase(char *out,size_t sz,const char *envname,int confirm){const char*e=getenv(envname);if(e){if(strlen(e)<12)die("governance/attester passphrase must be at least 12 characters");snprintf(out,sz,"%s",e);return 0;}char a[256]={0},b[256]={0};
#if defined(__unix__) || defined(__APPLE__)
    char *p=getpass("Private-key passphrase: ");if(!p)return -1;snprintf(a,sizeof(a),"%s",p);if(confirm){p=getpass("Confirm passphrase: ");if(!p)return -1;snprintf(b,sizeof(b),"%s",p);if(strcmp(a,b))die("passphrases do not match");}
#else
    fprintf(stderr,"Private-key passphrase: ");if(!fgets(a,sizeof(a),stdin))return -1;a[strcspn(a,"\r\n")]=0;if(confirm){fprintf(stderr,"Confirm passphrase: ");if(!fgets(b,sizeof(b),stdin))return -1;b[strcspn(b,"\r\n")]=0;if(strcmp(a,b))die("passphrases do not match");}
#endif
    if(strlen(a)<12)die("governance/attester passphrase must be at least 12 characters");snprintf(out,sz,"%s",a);OPENSSL_cleanse(a,sizeof(a));OPENSSL_cleanse(b,sizeof(b));return 0;}
static EVP_PKEY *gov_generate_ed25519(void){EVP_PKEY_CTX*c=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);EVP_PKEY*p=NULL;if(!c||EVP_PKEY_keygen_init(c)!=1||EVP_PKEY_keygen(c,&p)!=1){if(c)EVP_PKEY_CTX_free(c);return NULL;}EVP_PKEY_CTX_free(c);return p;}
static int gov_keygen_cmd(const char*outdir,const char*name){if(!vp_valid_token(name))die("invalid governance key name");if(mkdir_p(outdir)!=0)die("cannot create governance key directory");char pass[256];if(gov_read_passphrase(pass,sizeof(pass),"QRX_GOV_PASSPHRASE",1)!=0)die("passphrase failed");EVP_PKEY*p=gov_generate_ed25519();if(!p)die("Ed25519 governance key generation failed");unsigned char raw[32];if(ed25519_raw_pub(p,raw)!=0)die("governance public key extraction failed");char pubhex[65],fp[33];bytes_to_hex_local(raw,32,pubhex);gov_pub_fingerprint(pubhex,fp);char priv[1024],pub[1024],desc[1024];snprintf(priv,sizeof(priv),"%s/governance.key",outdir);snprintf(pub,sizeof(pub),"%s/governance.pub.pem",outdir);snprintf(desc,sizeof(desc),"%s/governance.pub",outdir);if(save_priv_pem(priv,p,pass)!=0||save_pub_pem(pub,p)!=0)die("governance key save failed");gov_secure_chmod(priv);char txt[1024];snprintf(txt,sizeof(txt),"format=qrx-governance-public-v1\nkey_id=%s\nalgorithm=Ed25519\npublic_key_hex=%s\nfingerprint=%s\n",name,pubhex,fp);if(write_text(desc,txt)!=0)die("descriptor write failed");printf("status=generated\nkey_id=%s\npublic_key=%s\nfingerprint=%s\nprivate_key=%s\npublic_descriptor=%s\n",name,pubhex,fp,priv,desc);OPENSSL_cleanse(pass,sizeof(pass));EVP_PKEY_free(p);return 0;}
static int attester_keygen_cmd(const char*outdir,const char*issuer){if(!vp_valid_token(issuer))die("invalid issuer id");if(mkdir_p(outdir)!=0)die("cannot create attester key directory");char pass[256];if(gov_read_passphrase(pass,sizeof(pass),"QRX_ATTESTER_PASSPHRASE",1)!=0)die("passphrase failed");EVP_PKEY*p=gov_generate_ed25519();if(!p)die("Ed25519 attester key generation failed");unsigned char raw[32];ed25519_raw_pub(p,raw);char pubhex[65],fp[33];bytes_to_hex_local(raw,32,pubhex);gov_pub_fingerprint(pubhex,fp);char priv[1024],pub[1024],desc[1024];snprintf(priv,sizeof(priv),"%s/attester.key",outdir);snprintf(pub,sizeof(pub),"%s/attester.pub.pem",outdir);snprintf(desc,sizeof(desc),"%s/attester.pub",outdir);if(save_priv_pem(priv,p,pass)!=0||save_pub_pem(pub,p)!=0)die("attester key save failed");gov_secure_chmod(priv);char txt[1024];snprintf(txt,sizeof(txt),"format=qrx-privacy-attester-public-v1\nissuer=%s\nalgorithm=Ed25519\npublic_key_hex=%s\nfingerprint=%s\n",issuer,pubhex,fp);write_text(desc,txt);printf("status=generated\nissuer=%s\npublic_key=%s\nfingerprint=%s\nprivate_key=%s\npublic_descriptor=%s\n",issuer,pubhex,fp,priv,desc);OPENSSL_cleanse(pass,sizeof(pass));EVP_PKEY_free(p);return 0;}
static int kyc_provider_keygen_cmd(const char*outdir,const char*provider){if(!vp_valid_token(provider))die("invalid KYC provider id");if(mkdir_p(outdir)!=0)die("cannot create KYC provider key directory");char pass[256];if(gov_read_passphrase(pass,sizeof(pass),"QRX_KYC_PROVIDER_PASSPHRASE",1)!=0)die("passphrase failed");EVP_PKEY*p=gov_generate_ed25519();if(!p)die("Ed25519 KYC provider key generation failed");unsigned char raw[32];if(ed25519_raw_pub(p,raw)!=0)die("KYC provider public key extraction failed");char pubhex[65],fp[33];bytes_to_hex_local(raw,32,pubhex);gov_pub_fingerprint(pubhex,fp);char priv[1024],pub[1024],desc[1024];snprintf(priv,sizeof(priv),"%s/kyc-provider.key",outdir);snprintf(pub,sizeof(pub),"%s/kyc-provider.pub.pem",outdir);snprintf(desc,sizeof(desc),"%s/kyc-provider.pub",outdir);if(save_priv_pem(priv,p,pass)!=0||save_pub_pem(pub,p)!=0)die("KYC provider key save failed");gov_secure_chmod(priv);char txt[1024];snprintf(txt,sizeof(txt),"format=qrx-kyc-provider-public-v1\nprovider_id=%s\nalgorithm=Ed25519\npublic_key_hex=%s\nfingerprint=%s\n",provider,pubhex,fp);if(write_text(desc,txt)!=0)die("KYC provider descriptor write failed");printf("status=generated\nprovider_id=%s\npublic_key=%s\nfingerprint=%s\nprivate_key=%s\npublic_descriptor=%s\n",provider,pubhex,fp,priv,desc);OPENSSL_cleanse(pass,sizeof(pass));EVP_PKEY_free(p);return 0;}

static int gov_descriptor(const char*path,char keyid[128],char pubhex[65],char fp[33]){char*t=read_file(path,NULL);if(!t)return -1;char*f=cfg_get(t,"format"),*k=cfg_get(t,"key_id"),*p=cfg_get(t,"public_key_hex"),*x=cfg_get(t,"fingerprint");char calc[33]={0};int ok=f&&k&&p&&x&&!strcmp(f,"qrx-governance-public-v1")&&vp_valid_token(k)&&strlen(k)<128&&is_hex_string(p,64,64)&&is_hex_string(x,32,32);if(ok){gov_pub_fingerprint(p,calc);ok=!strcmp(calc,x);}if(ok){snprintf(keyid,128,"%s",k);snprintf(pubhex,65,"%s",p);snprintf(fp,33,"%s",x);}free(f);free(k);free(p);free(x);free(t);return ok?0:-1;}
static int gov_genesis_init_cmd(int argc,char**argv){const char*chain=argv[2];if(chain_network_is(chain,"mainnet"))die("Mainnet governance roots are immutable Genesis parameters; edit qrx_genesis_governance.c before Genesis instead");long long threshold=parse_positive_ll_strict(argv[3],"threshold");int n=argc-4;if(n<1||threshold>n)die("threshold must be <= number of governance public descriptors");char conf[1024],roots[1024];gov_paths(chain,conf,sizeof(conf),roots,sizeof(roots),NULL,0,NULL,0);if(access_qrx(conf,F_OK)==0||access_qrx(roots,F_OK)==0)die("governance genesis root already initialized");FILE*r=fopen(roots,"wb");if(!r)die("cannot write governance roots");fprintf(r,"# key_id|public_key_hex|fingerprint|status\n");for(int i=4;i<argc;i++){char id[128],pk[65],fp[33],calc[33];if(gov_descriptor(argv[i],id,pk,fp)!=0){fclose(r);die("invalid governance public descriptor");}gov_pub_fingerprint(pk,calc);if(strcmp(calc,fp)){fclose(r);die("governance descriptor fingerprint mismatch");}fprintf(r,"%s|%s|%s|ACTIVE\n",id,pk,fp);}fclose(r);char c[512];snprintf(c,sizeof(c),"format=qrx-governance-genesis-v1\nthreshold=%lld\nroot_count=%d\ncreated_at=%lld\n",threshold,n,(long long)time(NULL));write_text(conf,c);printf("status=initialized\nthreshold=%lld\nroot_count=%d\nprivate_keys_on_chain=false\n",threshold,n);return 0;}
static int gov_root_lookup(const char*chain,const char*id,char pubhex[65]){
    char cntbuf[64];
    if(qrx_chain_get_value(chain,"governance_root_count",cntbuf,sizeof(cntbuf))==0){
        long long n=atoll(cntbuf);
        for(long long i=1;i<=n&&i<=32;i++){char kk[128],pkkey[128],kid[128],pk[128];snprintf(kk,sizeof(kk),"governance_root_%lld_key_id",i);snprintf(pkkey,sizeof(pkkey),"governance_root_%lld_public_key_hex",i);if(qrx_chain_get_value(chain,kk,kid,sizeof(kid))==0&&qrx_chain_get_value(chain,pkkey,pk,sizeof(pk))==0&&!strcmp(kid,id)&&strlen(pk)==64){memcpy(pubhex,pk,64);pubhex[64]=0;return 0;}}
        if(chain_network_is(chain,"mainnet"))return -1;
    }
    char roots[1024],line[512];gov_paths(chain,NULL,0,roots,sizeof(roots),NULL,0,NULL,0);FILE*f=fopen(roots,"rb");if(!f)return -1;int rc=-1;while(fgets(line,sizeof(line),f)){if(line[0]=='#')continue;char k[128]={0},p[65]={0},fp[33]={0},st[16]={0};if(sscanf(line,"%127[^|]|%64[^|]|%32[^|]|%15s",k,p,fp,st)==4&&!strcmp(k,id)&&!strcmp(st,"ACTIVE")){snprintf(pubhex,65,"%s",p);rc=0;break;}}fclose(f);return rc;
}
static int aura_compute_provider_key_lookup(void *ctx,const char *provider_id,EVP_PKEY **out){
    if(!ctx||!provider_id||!out) return -1;
    if(qrx_compute_provider_identity_key_lookup(ctx,provider_id,out)==0) return 0;
    return qrx_storage_provider_discovery_key_lookup(ctx,provider_id,out);
}

static int aura_model_gov_key_lookup(void *ctx,const char *identity,EVP_PKEY **out){
    if(!ctx||!identity||!out) return -1;
    char pubhex[65];
    if(gov_root_lookup((const char*)ctx,identity,pubhex)) return -1;
    unsigned char raw[32];
    if(hex_to_bytes_local(pubhex,raw,sizeof(raw))) return -1;
    EVP_PKEY*k=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,raw,sizeof(raw));
    if(!k) return -1;
    *out=k;
    return 0;
}
static int aura_model_gov_authorize(void *ctx,const char *publisher_id){char pubhex[65];return (!ctx||!publisher_id||gov_root_lookup((const char*)ctx,publisher_id,pubhex))?-1:0;}

static long long gov_threshold(const char*chain){char b[64];if(qrx_chain_get_value(chain,"governance_threshold",b,sizeof(b))==0){long long x=atoll(b);if(x>0)return x;if(chain_network_is(chain,"mainnet"))return 0;}char conf[1024];gov_paths(chain,conf,sizeof(conf),NULL,0,NULL,0,NULL,0);char*t=read_file(conf,NULL);if(!t)return 0;char*v=cfg_get(t,"threshold");long long x=v?atoll(v):0;free(v);free(t);return x;}
static int gov_proposal_hash(const char*path,char out[129],char**txtout){char*t=read_file(path,NULL);if(!t)return -1;char*f=cfg_get(t,"format");if(!f||strcmp(f,QRX_GOV_PROPOSAL_FORMAT)){free(f);free(t);return -1;}free(f);gov_hash_text("QUB-GOVERNANCE-PROPOSAL-v1",t,out);if(txtout)*txtout=t;else free(t);return 0;}
static int gov_sign_cmd(const char*keydir,const char*proposal,const char*out){char desc[1024],privp[1024],id[128],pk[65],fp[33],ph[129];snprintf(desc,sizeof(desc),"%s/governance.pub",keydir);snprintf(privp,sizeof(privp),"%s/governance.key",keydir);if(gov_descriptor(desc,id,pk,fp)!=0)die("invalid governance key descriptor");char*txt=NULL;if(gov_proposal_hash(proposal,ph,&txt)!=0)die("invalid governance proposal");char pass[256];if(gov_read_passphrase(pass,sizeof(pass),"QRX_GOV_PASSPHRASE",0)!=0)die("passphrase failed");EVP_PKEY*priv=load_priv_pem(privp,pass);if(!priv)die("cannot unlock governance private key");unsigned char*sig=NULL;size_t sl=0;if(sign_oneshot(priv,(unsigned char*)txt,strlen(txt),&sig,&sl)!=0)die("governance signature failed");char*sh=malloc(sl*2+1);bytes_to_hex_local(sig,sl,sh);char b[4096];snprintf(b,sizeof(b),"format=%s\nkey_id=%s\nfingerprint=%s\nproposal_hash=%s\nsignature_hex=%s\n",QRX_GOV_SIGNATURE_FORMAT,id,fp,ph,sh);write_text(out,b);printf("status=signed\nkey_id=%s\nproposal_hash=%s\nsignature_file=%s\n",id,ph,out);OPENSSL_cleanse(pass,sizeof(pass));OPENSSL_cleanse(sig,sl);free(sig);free(sh);free(txt);EVP_PKEY_free(priv);return 0;}

/* Phase 180: Governance Vault V1.
   The consensus threshold remains 3-of-5. This layer only hardens operator UX:
   - an OPERATIONAL vault may contain at most two private signing keys;
   - OFFLINE entries are public descriptors only;
   - an OFFLINE_BACKUP vault may contain all five encrypted private keys, but
     stores them as governance.key.backup so the normal signing command cannot
     consume them accidentally;
   - offline signatures are exchanged as ordinary immutable signature files. */
#define QRX_GOV_VAULT_FORMAT "qrx-governance-vault-v1"
#define QRX_GOV_VAULT_MAX_ROOTS 5
#define QRX_GOV_VAULT_THRESHOLD 3
#define QRX_GOV_VAULT_MAX_ONLINE 2

static void gov_vault_paths(const char*v,char*conf,size_t csz,char*idx,size_t isz){
    if(conf&&csz)snprintf(conf,csz,"%s/vault.conf",v);
    if(idx&&isz)snprintf(idx,isz,"%s/vault.index",v);
}
static int gov_copy_file_secure(const char*src,const char*dst,int secret){size_t n=0;char*b=read_file(src,&n);if(!b)return -1;int rc=write_file(dst,b,n);if(secret&&rc==0)gov_secure_chmod(dst);OPENSSL_cleanse(b,n);free(b);return rc;}
static int gov_vault_read_type(const char*v,char*out,size_t osz){char c[1024];gov_vault_paths(v,c,sizeof(c),NULL,0);char*t=read_file(c,NULL);if(!t)return -1;char*f=cfg_get(t,"format"),*ty=cfg_get(t,"vault_type");int ok=f&&ty&&!strcmp(f,QRX_GOV_VAULT_FORMAT);if(ok)snprintf(out,osz,"%s",ty);free(f);free(ty);free(t);return ok?0:-1;}
static int gov_vault_index_has(const char*v,const char*id,char*role,size_t rsz,int*has_private){char idx[1024],line[512];gov_vault_paths(v,NULL,0,idx,sizeof(idx));FILE*f=fopen(idx,"rb");if(!f)return 0;int hit=0;while(fgets(line,sizeof(line),f)){char kid[128]={0},fp[64]={0},r[32]={0};int hp=0;if(sscanf(line,"%127[^|]|%63[^|]|%31[^|]|%d",kid,fp,r,&hp)==4&&!strcmp(kid,id)){if(role&&rsz)snprintf(role,rsz,"%s",r);if(has_private)*has_private=hp;hit=1;break;}}fclose(f);return hit;}
static int gov_vault_count_online(const char*v){char idx[1024],line[512];gov_vault_paths(v,NULL,0,idx,sizeof(idx));FILE*f=fopen(idx,"rb");if(!f)return 0;int n=0;while(fgets(line,sizeof(line),f)){char kid[128]={0},fp[64]={0},r[32]={0};int hp=0;if(sscanf(line,"%127[^|]|%63[^|]|%31[^|]|%d",kid,fp,r,&hp)==4&&hp&&!strcmp(r,"ONLINE"))n++;}fclose(f);return n;}
static int gov_vault_count_entries(const char*v){char idx[1024],line[512];gov_vault_paths(v,NULL,0,idx,sizeof(idx));FILE*f=fopen(idx,"rb");if(!f)return 0;int n=0;while(fgets(line,sizeof(line),f))if(line[0]&&line[0]!='#')n++;fclose(f);return n;}
static int gov_vault_append_index(const char*v,const char*id,const char*fp,const char*role,int hp){char idx[1024],b[512];gov_vault_paths(v,NULL,0,idx,sizeof(idx));snprintf(b,sizeof(b),"%s|%s|%s|%d\n",id,fp,role,hp);return append_text(idx,b);}
static int gov_vault_init_cmd(const char*v){if(access_qrx(v,F_OK)==0)die("governance vault path already exists");if(mkdir_p(v)!=0)die("cannot create governance vault");char keys[1024];snprintf(keys,sizeof(keys),"%s/keys",v);if(mkdir_p(keys)!=0)die("cannot create governance vault keys directory");char conf[1024],idx[1024],b[1024];gov_vault_paths(v,conf,sizeof(conf),idx,sizeof(idx));snprintf(b,sizeof(b),"format=%s\nvault_type=OPERATIONAL\nroot_count=%d\nthreshold=%d\nmax_online_signers=%d\ncreated_at=%lld\nprivate_key_policy=max-two-online\n",QRX_GOV_VAULT_FORMAT,QRX_GOV_VAULT_MAX_ROOTS,QRX_GOV_VAULT_THRESHOLD,QRX_GOV_VAULT_MAX_ONLINE,(long long)time(NULL));if(write_text(conf,b)||write_text(idx,"# key_id|fingerprint|role|has_private\n"))die("cannot initialize governance vault metadata");gov_secure_chmod(conf);gov_secure_chmod(idx);printf("status=initialized\nvault_type=OPERATIONAL\nthreshold=3\nmax_online_signers=2\npath=%s\n",v);return 0;}
static int gov_vault_add_online_cmd(const char*v,const char*keydir){char ty[32];if(gov_vault_read_type(v,ty,sizeof(ty))||strcmp(ty,"OPERATIONAL"))die("online keys require an OPERATIONAL governance vault");if(gov_vault_count_online(v)>=QRX_GOV_VAULT_MAX_ONLINE)die("operational governance vault already has two online signers; keep remaining roots offline");char d[1024],k[1024],pp[1024],id[128],pk[65],fp[33];snprintf(d,sizeof(d),"%s/governance.pub",keydir);snprintf(k,sizeof(k),"%s/governance.key",keydir);snprintf(pp,sizeof(pp),"%s/governance.pub.pem",keydir);if(gov_descriptor(d,id,pk,fp)!=0||access_qrx(k,F_OK)!=0)die("invalid governance key directory");if(gov_vault_index_has(v,id,NULL,0,NULL))die("governance root already exists in vault");if(gov_vault_count_entries(v)>=QRX_GOV_VAULT_MAX_ROOTS)die("governance vault already has five roots");char slot[1024],dst[1024];snprintf(slot,sizeof(slot),"%s/keys/%s",v,id);if(access_qrx(slot,F_OK)==0)die("governance vault slot path already exists");if(mkdir_p(slot)!=0)die("cannot create governance vault slot");snprintf(dst,sizeof(dst),"%s/governance.pub",slot);if(gov_copy_file_secure(d,dst,0))die("cannot copy governance descriptor");snprintf(dst,sizeof(dst),"%s/governance.key",slot);if(gov_copy_file_secure(k,dst,1))die("cannot copy encrypted governance private key");if(access_qrx(pp,F_OK)==0){snprintf(dst,sizeof(dst),"%s/governance.pub.pem",slot);if(gov_copy_file_secure(pp,dst,0))die("cannot copy governance public PEM");}if(gov_vault_append_index(v,id,fp,"ONLINE",1))die("cannot update governance vault index");printf("status=added\nkey_id=%s\nrole=ONLINE\nonline_signers=%d\nmax_online_signers=2\n",id,gov_vault_count_online(v));return 0;}
static int gov_vault_add_offline_cmd(const char*v,const char*desc){char ty[32];if(gov_vault_read_type(v,ty,sizeof(ty))||strcmp(ty,"OPERATIONAL"))die("offline descriptors require an OPERATIONAL governance vault");char id[128],pk[65],fp[33];if(gov_descriptor(desc,id,pk,fp)!=0)die("invalid governance public descriptor");if(gov_vault_index_has(v,id,NULL,0,NULL))die("governance root already exists in vault");if(gov_vault_count_entries(v)>=QRX_GOV_VAULT_MAX_ROOTS)die("governance vault already has five roots");char slot[1024],dst[1024];snprintf(slot,sizeof(slot),"%s/keys/%s",v,id);if(access_qrx(slot,F_OK)==0)die("governance vault slot path already exists");if(mkdir_p(slot)!=0)die("cannot create governance vault slot");snprintf(dst,sizeof(dst),"%s/governance.pub",slot);if(gov_copy_file_secure(desc,dst,0))die("cannot copy governance descriptor");if(gov_vault_append_index(v,id,fp,"OFFLINE",0))die("cannot update governance vault index");printf("status=added\nkey_id=%s\nrole=OFFLINE\nprivate_key_present=false\n",id);return 0;}
static int gov_vault_status_cmd(const char*v){char ty[32],idx[1024],line[512];if(gov_vault_read_type(v,ty,sizeof(ty)))die("invalid governance vault");printf("format=%s\nvault_type=%s\nthreshold=3\nmax_online_signers=2\nentries=%d\nonline_signers=%d\n",QRX_GOV_VAULT_FORMAT,ty,gov_vault_count_entries(v),gov_vault_count_online(v));gov_vault_paths(v,NULL,0,idx,sizeof(idx));FILE*f=fopen(idx,"rb");if(!f)return 0;while(fgets(line,sizeof(line),f)){if(line[0]=='#')continue;char id[128]={0},fp[64]={0},role[32]={0};int hp=0;if(sscanf(line,"%127[^|]|%63[^|]|%31[^|]|%d",id,fp,role,&hp)==4)printf("root=%s role=%s private=%s fingerprint=%s\n",id,role,hp?"present":"absent",fp);}fclose(f);return 0;}
static int gov_vault_sign_cmd(const char*v,const char*id,const char*proposal,const char*out){char ty[32],role[32];int hp=0;if(gov_vault_read_type(v,ty,sizeof(ty))||strcmp(ty,"OPERATIONAL"))die("signing is disabled for offline backup vaults");if(!gov_vault_index_has(v,id,role,sizeof(role),&hp)||strcmp(role,"ONLINE")||!hp)die("requested governance root is not an online signer in this vault");char kd[1024];snprintf(kd,sizeof(kd),"%s/keys/%s",v,id);return gov_sign_cmd(kd,proposal,out);}
static int gov_vault_backup_create_cmd(int argc,char**argv){const char*v=argv[2];if(argc!=8)die("offline governance backup requires exactly five governance key directories");if(access_qrx(v,F_OK)==0)die("governance backup vault path already exists");if(mkdir_p(v)!=0)die("cannot create offline governance backup vault");char keys[1024];snprintf(keys,sizeof(keys),"%s/keys",v);mkdir_p(keys);char conf[1024],idx[1024],b[1024];gov_vault_paths(v,conf,sizeof(conf),idx,sizeof(idx));snprintf(b,sizeof(b),"format=%s\nvault_type=OFFLINE_BACKUP\nroot_count=5\nthreshold=3\nmax_online_signers=0\ncreated_at=%lld\nsigning_disabled=true\nprivate_key_policy=encrypted-backup-only\n",QRX_GOV_VAULT_FORMAT,(long long)time(NULL));if(write_text(conf,b)||write_text(idx,"# key_id|fingerprint|role|has_private\n"))die("cannot initialize offline governance backup metadata");char seen[5][128];int seen_n=0;for(int i=3;i<8;i++){char srcd[1024],srck[1024],srcp[1024],id[128],pk[65],fp[33];snprintf(srcd,sizeof(srcd),"%s/governance.pub",argv[i]);snprintf(srck,sizeof(srck),"%s/governance.key",argv[i]);snprintf(srcp,sizeof(srcp),"%s/governance.pub.pem",argv[i]);if(gov_descriptor(srcd,id,pk,fp)!=0||access_qrx(srck,F_OK)!=0)die("invalid governance key directory in backup set");for(int j=0;j<seen_n;j++)if(!strcmp(seen[j],id))die("duplicate governance root in backup set");snprintf(seen[seen_n++],sizeof(seen[0]),"%s",id);char slot[1024],dst[1024];snprintf(slot,sizeof(slot),"%s/keys/%s",v,id);mkdir_p(slot);snprintf(dst,sizeof(dst),"%s/governance.pub",slot);if(gov_copy_file_secure(srcd,dst,0))die("backup descriptor copy failed");snprintf(dst,sizeof(dst),"%s/governance.key.backup",slot);if(gov_copy_file_secure(srck,dst,1))die("backup private-key copy failed");if(access_qrx(srcp,F_OK)==0){snprintf(dst,sizeof(dst),"%s/governance.pub.pem",slot);if(gov_copy_file_secure(srcp,dst,0))die("backup public-key copy failed");}if(gov_vault_append_index(v,id,fp,"OFFLINE_BACKUP",1))die("backup index update failed");}gov_secure_chmod(conf);gov_secure_chmod(idx);printf("status=backup-created\nvault_type=OFFLINE_BACKUP\nroots=5\nthreshold=3\nsigning_disabled=true\npath=%s\n",v);return 0;}
static int gov_vault_restore_online_cmd(const char*backup,const char*id,const char*oper){char bty[32],oty[32];if(gov_vault_read_type(backup,bty,sizeof(bty))||strcmp(bty,"OFFLINE_BACKUP"))die("source is not an offline governance backup vault");if(gov_vault_read_type(oper,oty,sizeof(oty))||strcmp(oty,"OPERATIONAL"))die("destination is not an operational governance vault");if(gov_vault_count_online(oper)>=QRX_GOV_VAULT_MAX_ONLINE)die("destination already has two online signers");if(gov_vault_index_has(oper,id,NULL,0,NULL))die("governance root already exists in destination vault");char srcslot[1024],desc[1024],priv[1024],pubpem[1024],fp[33],pk[65],did[128];snprintf(srcslot,sizeof(srcslot),"%s/keys/%s",backup,id);snprintf(desc,sizeof(desc),"%s/governance.pub",srcslot);snprintf(priv,sizeof(priv),"%s/governance.key.backup",srcslot);snprintf(pubpem,sizeof(pubpem),"%s/governance.pub.pem",srcslot);if(gov_descriptor(desc,did,pk,fp)!=0||strcmp(did,id)||access_qrx(priv,F_OK)!=0)die("backup slot missing or invalid");char dstslot[1024],dst[1024];snprintf(dstslot,sizeof(dstslot),"%s/keys/%s",oper,id);if(access_qrx(dstslot,F_OK)==0)die("destination governance vault slot path already exists");if(mkdir_p(dstslot)!=0)die("cannot create destination governance vault slot");snprintf(dst,sizeof(dst),"%s/governance.pub",dstslot);if(gov_copy_file_secure(desc,dst,0))die("restore descriptor failed");snprintf(dst,sizeof(dst),"%s/governance.key",dstslot);if(gov_copy_file_secure(priv,dst,1))die("restore private key failed");if(access_qrx(pubpem,F_OK)==0){snprintf(dst,sizeof(dst),"%s/governance.pub.pem",dstslot);if(gov_copy_file_secure(pubpem,dst,0))die("restore public PEM failed");}if(gov_vault_append_index(oper,id,fp,"ONLINE",1))die("restore index update failed");printf("status=restored-online\nkey_id=%s\nonline_signers=%d\nmax_online_signers=2\n",id,gov_vault_count_online(oper));return 0;}

static int gov_verify_signature(const char*chain,const char*proposal_txt,const char*proposal_hash,const char*sigfile,char keyid_out[128]){char*t=read_file(sigfile,NULL);if(!t)return -1;char*f=cfg_get(t,"format"),*id=cfg_get(t,"key_id"),*fp=cfg_get(t,"fingerprint"),*ph=cfg_get(t,"proposal_hash"),*sh=cfg_get(t,"signature_hex");int rc=-1;char pk[65],calc[33];if(!f||strcmp(f,QRX_GOV_SIGNATURE_FORMAT)||!id||!fp||!ph||strcmp(ph,proposal_hash)||!sh||gov_root_lookup(chain,id,pk)!=0)goto done;gov_pub_fingerprint(pk,calc);if(strcmp(calc,fp)||strlen(sh)%2)goto done;unsigned char raw[32];if(hex_to_bytes_local(pk,raw,32)!=0)goto done;EVP_PKEY*pub=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,raw,32);size_t sl=strlen(sh)/2;unsigned char*sig=malloc(sl);if(!pub||!sig||hex_to_bytes_local(sh,sig,sl)!=0){if(pub)EVP_PKEY_free(pub);free(sig);goto done;}if(verify_oneshot(pub,(unsigned char*)proposal_txt,strlen(proposal_txt),sig,sl)==0){snprintf(keyid_out,128,"%s",id);rc=0;}EVP_PKEY_free(pub);free(sig);done:free(f);free(id);free(fp);free(ph);free(sh);free(t);return rc;}
static int gov_attester_propose_cmd(const char*out,const char*action,const char*issuer,const char*pubdesc,const char*cap,const char*height){if(strcmp(action,"ATTESTER_ADD")&&strcmp(action,"ATTESTER_DISABLE")&&strcmp(action,"ATTESTER_ROTATE_KEY"))die("unsupported attester governance action");if(!vp_valid_token(issuer))die("invalid issuer");char pk[65]="-";if(strcmp(action,"ATTESTER_DISABLE")){char*t=read_file(pubdesc,NULL);if(!t)die("attester public descriptor missing");char*f=cfg_get(t,"format"),*i=cfg_get(t,"issuer"),*p=cfg_get(t,"public_key_hex");if(!f||strcmp(f,"qrx-privacy-attester-public-v1")||!i||strcmp(i,issuer)||!p||strlen(p)!=64)die("attester descriptor mismatch");snprintf(pk,sizeof(pk),"%s",p);free(f);free(i);free(p);free(t);}char nonce[65];shielded_random_hex(nonce,32);char b[2048];snprintf(b,sizeof(b),"format=%s\naction=%s\nissuer=%s\npublic_key_hex=%s\ncapabilities=%s\nactivation_height=%s\nnonce=%s\n",QRX_GOV_PROPOSAL_FORMAT,action,issuer,pk,cap?cap:"verified-privacy,hidden-balance",height?height:"0",nonce);write_text(out,b);char ph[129];gov_hash_text("QUB-GOVERNANCE-PROPOSAL-v1",b,ph);printf("status=proposed\naction=%s\nissuer=%s\nproposal_hash=%s\nproposal_file=%s\n",action,issuer,ph,out);return 0;}
static int gov_protocol_propose_cmd(const char*out,const char*pv,const char*height,const char*mintx,const char*minpriv,const char*flags){parse_positive_ll_strict(pv,"protocol_version");parse_nonnegative_ll_strict(height,"activation_height");parse_positive_ll_strict(mintx,"minimum_tx_version");parse_nonnegative_ll_strict(minpriv,"minimum_privacy_version");char nonce[65];shielded_random_hex(nonce,32);char b[2048];snprintf(b,sizeof(b),"format=%s\naction=PROTOCOL_UPGRADE\nprotocol_version=%s\nactivation_height=%s\nminimum_tx_version=%s\nminimum_privacy_version=%s\nfeature_flags=%s\nnonce=%s\n",QRX_GOV_PROPOSAL_FORMAT,pv,height,mintx,minpriv,flags?flags:"-",nonce);write_text(out,b);char ph[129];gov_hash_text("QUB-GOVERNANCE-PROPOSAL-v1",b,ph);printf("status=proposed\naction=PROTOCOL_UPGRADE\nproposal_hash=%s\nproposal_file=%s\n",ph,out);return 0;}
static int gov_compute_liveness_propose_cmd(const char*out,const char*height,const char*threshold,const char*jail){parse_nonnegative_ll_strict(height,"activation_height");parse_positive_ll_strict(threshold,"verifier_miss_threshold");parse_positive_ll_strict(jail,"verifier_miss_jail_blocks");QrxPoucLivenessParams p={QRX_POUC_LIVENESS_PARAMS_VERSION,(uint64_t)strtoull(threshold,NULL,10),(uint64_t)strtoull(jail,NULL,10)};if(qrx_pouc_liveness_params_validate(&p))die("compute liveness parameters out of range");char nonce[65];shielded_random_hex(nonce,32);char b[2048];snprintf(b,sizeof(b),"format=%s\naction=COMPUTE_LIVENESS_PARAMS\nactivation_height=%s\nverifier_miss_threshold=%s\nverifier_miss_jail_blocks=%s\nnonce=%s\n",QRX_GOV_PROPOSAL_FORMAT,height,threshold,jail,nonce);write_text(out,b);char ph[129];gov_hash_text("QUB-GOVERNANCE-PROPOSAL-v1",b,ph);printf("status=proposed\naction=COMPUTE_LIVENESS_PARAMS\nproposal_hash=%s\nproposal_file=%s\n",ph,out);return 0;}
static int gov_already_applied(const char*chain,const char*ph){char log[1024],line[512];gov_paths(chain,NULL,0,NULL,0,log,sizeof(log),NULL,0);FILE*f=fopen(log,"rb");if(!f)return 0;int hit=0;while(fgets(line,sizeof(line),f)){if(!strncmp(line,ph,128)){hit=1;break;}}fclose(f);return hit;}
static int gov_apply_cmd(int argc,char**argv){const char*chain=argv[2],*proposal=argv[3];long long threshold=gov_threshold(chain);if(threshold<=0)die("governance genesis root not initialized");if(argc-4<threshold)die("not enough governance signatures");char ph[129],*pt=NULL;if(gov_proposal_hash(proposal,ph,&pt)!=0)die("invalid governance proposal");if(gov_already_applied(chain,ph))die("governance proposal replay rejected");char ids[16][128];int valid=0;for(int i=4;i<argc&&i<20;i++){char id[128];if(gov_verify_signature(chain,pt,ph,argv[i],id)!=0)continue;int dup=0;for(int j=0;j<valid;j++)if(!strcmp(ids[j],id))dup=1;if(!dup){snprintf(ids[valid],128,"%s",id);valid++;}}if(valid<threshold){free(pt);die("governance threshold not met with unique valid signatures");}char*action=cfg_get(pt,"action");if(!action)die("proposal missing action");if((!strcmp(action,"ATTESTER_ADD")||!strcmp(action,"ATTESTER_ROTATE_KEY")||!strcmp(action,"ATTESTER_DISABLE"))&&privacy_legacy_mainnet_gate(chain)!=0)die("legacy file-backed privacy governance disabled on Mainnet; submit PRIVACY_GOVERNANCE consensus transaction");long long applied_height=current_height_from_chain(chain);if(!strcmp(action,"ATTESTER_ADD")||!strcmp(action,"ATTESTER_ROTATE_KEY")||!strcmp(action,"ATTESTER_DISABLE")){char*issuer=cfg_get(pt,"issuer"),*pk=cfg_get(pt,"public_key_hex"),*cap=cfg_get(pt,"capabilities"),*ah=cfg_get(pt,"activation_height");if(!issuer||!pk||!ah)die("attester proposal malformed");long long act=atoll(ah);if(applied_height<act)die("attester proposal activation height not reached");char path[1024];vp_paths(chain,path,sizeof(path),NULL,0);FILE*f=fopen(path,"ab");if(!f)die("attester registry state write failed");const char*st=!strcmp(action,"ATTESTER_DISABLE")?"DISABLED":"ACTIVE";char existing[65];int ea=0;if(!strcmp(action,"ATTESTER_DISABLE")&&vp_attester_lookup(chain,issuer,existing,&ea)!=0){fclose(f);die("cannot disable unknown attester");}fprintf(f,"%s|%s|%s|%lld|%s|governance:%s\n",issuer,!strcmp(action,"ATTESTER_DISABLE")?existing:pk,st,(long long)time(NULL),cap?cap:"-",ph);fclose(f);free(issuer);free(pk);free(cap);free(ah);}else if(!strcmp(action,"PROTOCOL_UPGRADE")){if(privacy_legacy_mainnet_gate(chain)!=0)die("legacy file-backed protocol governance disabled on Mainnet; submit GOVERNANCE_PROTOCOL consensus transaction");char*pv=cfg_get(pt,"protocol_version"),*ah=cfg_get(pt,"activation_height"),*mt=cfg_get(pt,"minimum_tx_version"),*mp=cfg_get(pt,"minimum_privacy_version"),*ff=cfg_get(pt,"feature_flags");if(!pv||!ah||!mt||!mp)die("protocol proposal malformed");char upg[1024];gov_paths(chain,NULL,0,NULL,0,NULL,0,upg,sizeof(upg));FILE*f=fopen(upg,"ab");if(!f)die("protocol schedule write failed");fprintf(f,"%s|%s|%s|%s|%s|%s\n",ah,pv,mt,mp,ff?ff:"-",ph);fclose(f);free(pv);free(ah);free(mt);free(mp);free(ff);}else if(!strcmp(action,"COMPUTE_LIVENESS_PARAMS")){char*ah=cfg_get(pt,"activation_height"),*th=cfg_get(pt,"verifier_miss_threshold"),*jb=cfg_get(pt,"verifier_miss_jail_blocks");if(!ah||!th||!jb)die("compute liveness proposal malformed");long long act=parse_nonnegative_ll_strict(ah,"activation_height");if(applied_height<act)die("compute liveness proposal activation height not reached");QrxPoucLivenessParams cp={QRX_POUC_LIVENESS_PARAMS_VERSION,(uint64_t)parse_positive_ll_strict(th,"verifier_miss_threshold"),(uint64_t)parse_positive_ll_strict(jb,"verifier_miss_jail_blocks")};if(qrx_pouc_liveness_params_validate(&cp))die("compute liveness parameters out of range");QrxDB gdb;QrxDBBatch gb;if(qrxdb_init(&gdb,chain)!=0||qrxdb_batch_begin(&gdb,&gb)!=0)die("compute liveness governance QRXDB begin failed");char hk[512],hv[512];snprintf(hk,sizeof(hk),"consensus:compute:params_history:%020lld:%s",applied_height,ph);snprintf(hv,sizeof(hv),"activation_height=%lld|miss_threshold=%llu|miss_jail_blocks=%llu|governance=%s",act,(unsigned long long)cp.verifier_miss_threshold,(unsigned long long)cp.verifier_miss_jail_blocks,ph);if(qrx_pouc_liveness_params_stage(&gb,&cp)||qrxdb_batch_put(&gb,hk,hv)||qrxdb_batch_commit(&gb)){qrxdb_batch_abort(&gb);qrxdb_close(&gdb);die("compute liveness governance QRXDB commit failed");}qrxdb_close(&gdb);free(ah);free(th);free(jb);}else die("unsupported governance action");char log[1024];gov_paths(chain,NULL,0,NULL,0,log,sizeof(log),NULL,0);FILE*lf=fopen(log,"ab");if(!lf)die("governance replay-state write failed");fprintf(lf,"%s|%s|%lld|signers=",ph,action,(long long)time(NULL));for(int i=0;i<valid;i++)fprintf(lf,"%s%s",i?",":"",ids[i]);fprintf(lf,"\n");fclose(lf);printf("status=applied\naction=%s\nproposal_hash=%s\nvalid_unique_signatures=%d\nthreshold=%lld\n",action,ph,valid,threshold);free(action);free(pt);return 0;}
typedef struct{long long height,pv,tx,pr,next;}GovProtocolScan;
static int gov_protocol_scan_cb(const char*k,const char*v,uint32_t vl,void*x){(void)vl;const char*pre="governance:protocol:schedule:";if(strncmp(k,pre,strlen(pre)))return 0;GovProtocolScan*c=x;long long h=atoll(k+strlen(pre));char*t=strdup(v);if(!t)return-1;char*sv=NULL,*a[6];int n=0;for(char*q=strtok_r(t,"|",&sv);q&&n<6;q=strtok_r(NULL,"|",&sv))a[n++]=q;if(n==6){long long p=atoll(a[0]),mt=atoll(a[1]),mp=atoll(a[2]);if(h<=c->height&&p>=c->pv){c->pv=p;c->tx=mt;c->pr=mp;}else if(h>c->height&&(c->next==0||h<c->next))c->next=h;}free(t);return 0;}
static void gov_protocol_active(const char*chain,long long height,long long*outpv,long long*outtx,long long*outpriv,long long*next_h){GovProtocolScan c={height,0,1,0,0};QrxDB db;if(qrxdb_init(&db,chain)==0){qrxdb_scan_prefix(&db,"governance:protocol:schedule:",gov_protocol_scan_cb,&c);qrxdb_close(&db);}if(!qrx_resource_is_mainnet(chain)&&c.pv==0&&c.next==0){char upg[1024],line[1024];gov_paths(chain,NULL,0,NULL,0,NULL,0,upg,sizeof(upg));FILE*f=fopen(upg,"rb");if(f){while(fgets(line,sizeof(line),f)){long long h=0,p=0,t=0,r=0;char flags[256],hash[129];if(sscanf(line,"%lld|%lld|%lld|%lld|%255[^|]|%128s",&h,&p,&t,&r,flags,hash)==6){if(h<=height&&p>=c.pv){c.pv=p;c.tx=t;c.pr=r;}else if(h>height&&(c.next==0||h<c.next))c.next=h;}}fclose(f);}}if(outpv)*outpv=c.pv;if(outtx)*outtx=c.tx;if(outpriv)*outpriv=c.pr;if(next_h)*next_h=c.next;}
static int gov_protocol_info_cmd(const char*chain,long long height){if(height<0)height=current_height_from_chain(chain);long long pv,tx,pr,next;gov_protocol_active(chain,height,&pv,&tx,&pr,&next);int req=pv>QRX_GOV_SUPPORTED_PROTOCOL||pr>QRX_GOV_SUPPORTED_PRIVACY;printf("chain_height=%lld\nactive_protocol=%lld\nminimum_tx_version=%lld\nminimum_privacy_version=%lld\nwallet_supported_protocol=%d\nwallet_supported_privacy=%d\nupdate_required=%s\nnext_activation_height=%lld\n",height,pv,tx,pr,QRX_GOV_SUPPORTED_PROTOCOL,QRX_GOV_SUPPORTED_PRIVACY,req?"true":"false",next);return req?2:0;}
static int gov_tx_version_allowed(const char*chain,const char*tx_version){long long pv,mt,pr,next;gov_protocol_active(chain,current_height_from_chain(chain),&pv,&mt,&pr,&next);(void)pv;(void)pr;(void)next;if(mt<=1)return 1;return tx_version&&atoll(tx_version)>=mt;}

static int privacy_feature_status_cmd(const char *chain_dir) {
    (void)chain_dir;
    printf("transparent_default=true\n");
    printf("exchange_deposits=transparent-only\n");
    printf("stealth_addresses=phase3-squb2-x25519-secp256k1-one-time-spend\n");
    printf("shielded_pool=phase3-ringct-encrypted-notes-pedersen-rangeproofs\n");
    printf("hidden_balances=phase4-verified-privacy-gated-shielded-balance\n");
    printf("verified_privacy=consensus-governance-attester-registry-plus-ed25519-credential-v1\n");
    printf("kyc_pii=off-chain-only-never-in-credential-or-chain-state\n");
    printf("credential_revocation=opaque-serial-hash-only\n");
    printf("developer_governance=genesis-ed25519-threshold-roots-no-private-keys-on-chain\n");
    printf("attester_registry_mutation=threshold-signed-governance-proposals\n");
    printf("protocol_upgrade_enforcement=activation-height-plus-minimum-tx-version\n");
    printf("stealth_activation_height=%d\n", QUB_FEATURE_ACTIVATION_HEIGHT_STEALTH);
    printf("shielded_pool_activation_height=%d\n", QUB_FEATURE_ACTIVATION_HEIGHT_SHIELDED_POOL);
    printf("audit_status=%s\n", QUB_FEATURE_AUDIT_STATUS);
    printf("mainnet_release_gate=external-cryptography-audit-required-before-real-funds\n");
    printf("stealth_key_derivation=private-wallet-material-only\n");
    printf("stealth_public_metadata=recipient-stealth-address-and-shared-secret-not-persisted\n");
    printf("stealth_recovery=deterministic-from-recovered-primary-ed25519-key\n");
    printf("stealth_spend_path=one-time-secp256k1-ownership-proof-atomic-value-and-replay-state\n");
    printf("shielded_note_encryption=aes-256-gcm-x25519-view-key\n");
    printf("shielded_value_commitment=secp256k1-pedersen\n");
    printf("shielded_range_proof=63-bit-fiat-shamir-or-proof\n");
    printf("shielded_input_privacy=ringct-mixed-base-linkable-ring-proof\n");
    printf("shielded_double_spend=key-images\n");
    printf("shielded_change=mandatory-when-inputs-exceed-payment\n");
    printf("hybrid_signatures=ed25519-plus-mldsa65\n");
    printf("post_quantum_posture=quantum-resistant-in-mind-hybrid-signature-direction\n");
    printf("policy=transparent-default-optional-privacy-not-for-cex-deposits\n");
    return 0;
}

typedef struct {
    char tx_id[129];
    char sender[385];
    char one_time_address[385];
    long long amount;
    char ephemeral_pub[129];
    char one_time_pub[129]; /* secp256k1 compressed public key, 33 bytes hex */
    long long created_at;
    char status[32];
    char memo[256];
} StealthRecord;

static void stealth_paths(const char *chain_dir, char *db, size_t dsz, char *journal, size_t jsz) {
    if (db) snprintf(db, dsz, "%s/stealth_transfers.db", chain_dir);
    if (journal) snprintf(journal, jsz, "%s/stealth_journal.log", chain_dir);
}

static void stealth_spend_paths(const char *chain_dir, char *db, size_t dsz, char *nonce_db, size_t nsz) {
    if (db) snprintf(db, dsz, "%s/stealth_spends.db", chain_dir);
    if (nonce_db) snprintf(nonce_db, nsz, "%s/stealth_nonces.db", chain_dir);
}

static void stealth_seed_hash(const char *label, const char *input, char out[129]) {
    char buf[4096];
    snprintf(buf, sizeof(buf), "QUB-STEALTH-v2|%s|%s", label ? label : "", input ? input : "");
    sha3_512_hex_local(buf, out);
}

static void bytes_to_hex_local(const unsigned char *in, size_t len, char *out) {
    for (size_t i=0;i<len;i++) sprintf(out + i*2, "%02x", in[i]);
    out[len*2] = 0;
}

static int hex_to_bytes_local(const char *hex, unsigned char *out, size_t outlen) {
    if (!hex || strlen(hex) != outlen * 2) return -1;
    for (size_t i=0;i<outlen;i++) {
        unsigned int x = 0;
        if (sscanf(hex + i*2, "%02x", &x) != 1) return -1;
        out[i] = (unsigned char)x;
    }
    return 0;
}

static int stealth_x25519_pub_from_priv(const unsigned char priv[32], unsigned char pub[32]) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (!pkey) return -1;
    size_t len = 32;
    int ok = EVP_PKEY_get_raw_public_key(pkey, pub, &len);
    EVP_PKEY_free(pkey);
    return ok == 1 && len == 32 ? 0 : -1;
}

static int stealth_x25519_derive(const unsigned char priv[32], const unsigned char peer_pub[32], unsigned char shared[32]) {
    int ret = -1;
    EVP_PKEY *sk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!sk || !pk) goto done;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
    if (!ctx) goto done;
    size_t outlen = 32;
    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, pk) == 1 &&
        EVP_PKEY_derive(ctx, shared, &outlen) == 1 && outlen == 32) ret = 0;
    EVP_PKEY_CTX_free(ctx);
done:
    if (sk) EVP_PKEY_free(sk);
    if (pk) EVP_PKEY_free(pk);
    return ret;
}

static int stealth_wallet_material(const char *wallet_dir, unsigned char material[32]) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/ed25519_priv.pem", wallet_dir);
    const char *pass = getenv("QRX_PASSPHRASE");
    if (!pass) return -2;
    EVP_PKEY *ed = load_priv_pem(path, pass);
    if (!ed) return -2;
    int rc = ed25519_raw_priv(ed, material);
    EVP_PKEY_free(ed);
    return rc == 0 ? 0 : -1;
}

static int stealth_wallet_scan_keypair(const char *wallet_dir, unsigned char priv[32], unsigned char pub[32]) {
    unsigned char material[32], digest[64]; unsigned int digest_len=0;
    if (stealth_wallet_material(wallet_dir, material) != 0) return -2;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx){OPENSSL_cleanse(material,32);return -1;}
    static const char domain[]="QUB-X25519-STEALTH-SCAN-v4";
    int ok=EVP_DigestInit_ex(ctx,EVP_sha3_512(),NULL)==1 &&
        EVP_DigestUpdate(ctx,domain,sizeof(domain)-1)==1 && EVP_DigestUpdate(ctx,material,32)==1 &&
        EVP_DigestFinal_ex(ctx,digest,&digest_len)==1 && digest_len==64;
    EVP_MD_CTX_free(ctx); OPENSSL_cleanse(material,32); if(!ok)return -1;
    memcpy(priv,digest,32); OPENSSL_cleanse(digest,64);
    priv[0]&=248; priv[31]&=127; priv[31]|=64;
    return stealth_x25519_pub_from_priv(priv,pub);
}

static int stealth_secp_group_order(EC_GROUP **group_out, BIGNUM **order_out) {
    EC_GROUP *g=EC_GROUP_new_by_curve_name(NID_secp256k1); if(!g)return -1;
    BIGNUM *n=BN_new(); BN_CTX *ctx=BN_CTX_new();
    if(!n||!ctx||EC_GROUP_get_order(g,n,ctx)!=1){ if(n)BN_free(n); if(ctx)BN_CTX_free(ctx); EC_GROUP_free(g); return -1; }
    BN_CTX_free(ctx); *group_out=g; *order_out=n; return 0;
}

static int stealth_wallet_spend_scalar(const char *wallet_dir, BIGNUM **priv_out, char pub_hex[129]) {
    unsigned char material[32], digest[64]; unsigned int dlen=0;
    if(stealth_wallet_material(wallet_dir,material)!=0)return -2;
    EVP_MD_CTX *m=EVP_MD_CTX_new(); if(!m){OPENSSL_cleanse(material,32);return -1;}
    static const char dom[]="QUB-SECP256K1-STEALTH-SPEND-v4";
    int ok=EVP_DigestInit_ex(m,EVP_sha3_512(),NULL)==1 && EVP_DigestUpdate(m,dom,sizeof(dom)-1)==1 &&
        EVP_DigestUpdate(m,material,32)==1 && EVP_DigestFinal_ex(m,digest,&dlen)==1 && dlen==64;
    EVP_MD_CTX_free(m); OPENSSL_cleanse(material,32); if(!ok)return -1;
    EC_GROUP *g=NULL; BIGNUM *n=NULL,*d=NULL; BN_CTX *ctx=NULL; EC_POINT *P=NULL; int rc=-1;
    if(stealth_secp_group_order(&g,&n)!=0)goto done;
    d=BN_bin2bn(digest,64,NULL); ctx=BN_CTX_new(); P=EC_POINT_new(g); if(!d||!ctx||!P)goto done;
    if(BN_mod(d,d,n,ctx)!=1)goto done; if(BN_is_zero(d))BN_one(d);
    if(EC_POINT_mul(g,P,d,NULL,NULL,ctx)!=1)goto done;
    unsigned char enc[33]; size_t elen=EC_POINT_point2oct(g,P,POINT_CONVERSION_COMPRESSED,enc,sizeof(enc),ctx);
    if(elen!=33)goto done; bytes_to_hex_local(enc,33,pub_hex); *priv_out=d; d=NULL; rc=0;
done:
    OPENSSL_cleanse(digest,64); if(d)BN_clear_free(d); if(P)EC_POINT_free(P); if(ctx)BN_CTX_free(ctx); if(n)BN_free(n); if(g)EC_GROUP_free(g); return rc;
}

static int stealth_shared_tweak(const unsigned char shared[32], BIGNUM **tweak_out) {
    unsigned char digest[64]; unsigned int dlen=0; EVP_MD_CTX *m=EVP_MD_CTX_new(); if(!m)return -1;
    static const char dom[]="QUB-STEALTH-SECP-TWEAK-v4";
    int ok=EVP_DigestInit_ex(m,EVP_sha3_512(),NULL)==1 && EVP_DigestUpdate(m,dom,sizeof(dom)-1)==1 &&
        EVP_DigestUpdate(m,shared,32)==1 && EVP_DigestFinal_ex(m,digest,&dlen)==1 && dlen==64;
    EVP_MD_CTX_free(m); if(!ok)return -1;
    EC_GROUP *g=NULL; BIGNUM *n=NULL,*t=NULL; BN_CTX *ctx=NULL; int rc=-1;
    if(stealth_secp_group_order(&g,&n)!=0)goto done; ctx=BN_CTX_new(); t=BN_bin2bn(digest,64,NULL); if(!ctx||!t)goto done;
    if(BN_mod(t,t,n,ctx)!=1)goto done; if(BN_is_zero(t))BN_one(t); *tweak_out=t; t=NULL; rc=0;
done: OPENSSL_cleanse(digest,64); if(t)BN_clear_free(t); if(ctx)BN_CTX_free(ctx); if(n)BN_free(n); if(g)EC_GROUP_free(g); return rc;
}

static int stealth_one_time_pub(const char *master_pub_hex, const unsigned char shared[32], char out_hex[129]) {
    unsigned char master_enc[33],out_enc[33]; if(strlen(master_pub_hex)!=66||hex_to_bytes_local(master_pub_hex,master_enc,33)!=0)return -1;
    EC_GROUP *g=NULL; BIGNUM *n=NULL,*t=NULL; BN_CTX *ctx=NULL; EC_POINT *M=NULL,*T=NULL,*O=NULL; int rc=-1;
    if(stealth_secp_group_order(&g,&n)!=0||stealth_shared_tweak(shared,&t)!=0)goto done;
    ctx=BN_CTX_new(); M=EC_POINT_new(g);T=EC_POINT_new(g);O=EC_POINT_new(g); if(!ctx||!M||!T||!O)goto done;
    if(EC_POINT_oct2point(g,M,master_enc,33,ctx)!=1||EC_POINT_mul(g,T,t,NULL,NULL,ctx)!=1||EC_POINT_add(g,O,M,T,ctx)!=1)goto done;
    if(EC_POINT_point2oct(g,O,POINT_CONVERSION_COMPRESSED,out_enc,33,ctx)!=33)goto done;
    bytes_to_hex_local(out_enc,33,out_hex); rc=0;
done: if(O)EC_POINT_free(O);if(T)EC_POINT_free(T);if(M)EC_POINT_free(M);if(ctx)BN_CTX_free(ctx);if(t)BN_clear_free(t);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;
}

static int stealth_one_time_priv(const char *wallet_dir,const unsigned char shared[32],BIGNUM **out_priv,char out_pub[129]){
    BIGNUM *master=NULL,*t=NULL,*n=NULL,*d=NULL; EC_GROUP *g=NULL; BN_CTX *ctx=NULL; EC_POINT *P=NULL; int rc=-1; char master_pub[129];
    if(stealth_wallet_spend_scalar(wallet_dir,&master,master_pub)!=0||stealth_shared_tweak(shared,&t)!=0||stealth_secp_group_order(&g,&n)!=0)goto done;
    ctx=BN_CTX_new();d=BN_new();P=EC_POINT_new(g);if(!ctx||!d||!P)goto done;
    if(BN_mod_add(d,master,t,n,ctx)!=1||BN_is_zero(d)||EC_POINT_mul(g,P,d,NULL,NULL,ctx)!=1)goto done;
    unsigned char enc[33];if(EC_POINT_point2oct(g,P,POINT_CONVERSION_COMPRESSED,enc,33,ctx)!=33)goto done;bytes_to_hex_local(enc,33,out_pub);*out_priv=d;d=NULL;rc=0;
done:if(P)EC_POINT_free(P);if(ctx)BN_CTX_free(ctx);if(d)BN_clear_free(d);if(master)BN_clear_free(master);if(t)BN_clear_free(t);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;
}

static void stealth_address_from_one_time_pub(const char *pub_hex,char out[385]){char h[129],buf[512];snprintf(buf,sizeof(buf),"QUB-STEALTH-OTA-v4|%s",pub_hex);sha3_512_hex_local(buf,h);snprintf(out,385,"qrx1stealth%s",h);}

static int stealth_make_address_from_wallet_dir(const char *wallet_dir, char out[512]) {
    unsigned char scan_priv[32],scan_pub[32]; char scan_hex[65],spend_pub[129]; BIGNUM *spend_priv=NULL;
    if(stealth_wallet_scan_keypair(wallet_dir,scan_priv,scan_pub)!=0)return -1;
    if(stealth_wallet_spend_scalar(wallet_dir,&spend_priv,spend_pub)!=0){OPENSSL_cleanse(scan_priv,32);return -1;}
    bytes_to_hex_local(scan_pub,32,scan_hex); snprintf(out,512,"squb2%s%s",scan_hex,spend_pub);
    BN_clear_free(spend_priv); OPENSSL_cleanse(scan_priv,32); return 0;
}

static int stealth_split_address(const char *saddr, char scan[129], char spend[129]) {
    if(!saddr||strncmp(saddr,"squb2",5)!=0)return -1; const char *p=saddr+5; if(strlen(p)!=130)return -1;
    memcpy(scan,p,64);scan[64]=0;memcpy(spend,p+64,66);spend[66]=0;
    for(size_t i=0;i<64;i++)if(!isxdigit((unsigned char)scan[i]))return -1;
    for(size_t i=0;i<66;i++)if(!isxdigit((unsigned char)spend[i]))return -1; return 0;
}

static int stealth_parse_line(const char *line, StealthRecord *r) {
    if(!line||!r)return -1;char buf[4096];snprintf(buf,sizeof(buf),"%s",line);buf[strcspn(buf,"\r\n")]=0;
    char *fields[10]={0};int n=0;char *cursor=buf;while(n<10){fields[n++]=cursor;char *sep=strchr(cursor,'|');if(!sep)break;*sep=0;cursor=sep+1;}
    memset(r,0,sizeof(*r));
    if(n>=9 && strlen(fields[5])==66){ /* v3 */
        snprintf(r->tx_id,sizeof(r->tx_id),"%s",fields[0]);snprintf(r->sender,sizeof(r->sender),"%s",fields[1]);snprintf(r->one_time_address,sizeof(r->one_time_address),"%s",fields[2]);r->amount=atoll(fields[3]);snprintf(r->ephemeral_pub,sizeof(r->ephemeral_pub),"%s",fields[4]);snprintf(r->one_time_pub,sizeof(r->one_time_pub),"%s",fields[5]);r->created_at=atoll(fields[6]);snprintf(r->status,sizeof(r->status),"%s",fields[7]);snprintf(r->memo,sizeof(r->memo),"%s",fields[8]);return 0;
    }
    if(n>=10){ /* legacy leaky v1 */snprintf(r->tx_id,129,"%s",fields[0]);snprintf(r->sender,385,"%s",fields[1]);snprintf(r->one_time_address,385,"%s",fields[3]);r->amount=atoll(fields[4]);snprintf(r->ephemeral_pub,129,"%s",fields[5]);r->created_at=atoll(fields[7]);snprintf(r->status,32,"%s",fields[8]);snprintf(r->memo,256,"%s",fields[9]);return 0;}
    if(n>=8){ /* phase2 */snprintf(r->tx_id,129,"%s",fields[0]);snprintf(r->sender,385,"%s",fields[1]);snprintf(r->one_time_address,385,"%s",fields[2]);r->amount=atoll(fields[3]);snprintf(r->ephemeral_pub,129,"%s",fields[4]);r->created_at=atoll(fields[5]);snprintf(r->status,32,"%s",fields[6]);snprintf(r->memo,256,"%s",fields[7]);return 0;}
    return -1;
}

static int stealth_load_all(const char *chain_dir, StealthRecord **out, size_t *count) {
    char path[1024];stealth_paths(chain_dir,path,sizeof(path),NULL,0);*out=NULL;*count=0;FILE *f=fopen(path,"rb");if(!f)return 0;
    size_t cap=16,n=0;StealthRecord *arr=calloc(cap,sizeof(*arr));if(!arr){fclose(f);return -1;}char line[4096];
    while(fgets(line,sizeof(line),f)){if(line[0]=='#'||line[0]=='\n')continue;StealthRecord r;if(stealth_parse_line(line,&r)!=0)continue;if(n==cap){cap*=2;StealthRecord *tmp=realloc(arr,cap*sizeof(*arr));if(!tmp){free(arr);fclose(f);return -1;}arr=tmp;}arr[n++]=r;}
    fclose(f);*out=arr;*count=n;return 0;
}

static int stealth_save_all(const char *chain_dir,const StealthRecord *arr,size_t count){char path[1024];stealth_paths(chain_dir,path,sizeof(path),NULL,0);FILE *f=fopen(path,"wb");if(!f)return -1;fprintf(f,"# QRX stealth public metadata v3: tx|sender|one_time|amount|ephemeral_pub|one_time_pub|created_at|status|memo\n");for(size_t i=0;i<count;i++)fprintf(f,"%s|%s|%s|%lld|%s|%s|%lld|%s|%s\n",arr[i].tx_id,arr[i].sender,arr[i].one_time_address,arr[i].amount,arr[i].ephemeral_pub,arr[i].one_time_pub,arr[i].created_at,arr[i].status,arr[i].memo);fclose(f);return 0;}

static int stealth_balance_transfer_atomic(const char *balpath,const char *from,const char *to,long long amount){StateKVRecord *arr=NULL;size_t n=0;if(kv_load(balpath,&arr,&n)!=0)return -1;long long fb=0,tb=0;long fi=-1,ti=-1;for(size_t i=0;i<n;i++){if(!strcmp(arr[i].key,from)){fi=(long)i;fb=arr[i].value;}if(!strcmp(arr[i].key,to)){ti=(long)i;tb=arr[i].value;}}if(fb<amount){free(arr);return -2;}if(fi<0){free(arr);return -2;}arr[fi].value=fb-amount;if(ti>=0)arr[ti].value=tb+amount;else{StateKVRecord *tmp=realloc(arr,(n+1)*sizeof(*arr));if(!tmp){free(arr);return -1;}arr=tmp;snprintf(arr[n].key,sizeof(arr[n].key),"%s",to);arr[n].value=amount;n++;}int rc=kv_save(balpath,arr,n);free(arr);return rc;}

/* Stealth spend replay state deliberately lives in balances.bin so the value move
   and nonce increment are committed by one kv_save(). This avoids a crash window
   where funds move but the replay nonce does not. The key is domain-separated and
   hashed so it cannot collide with a valid qrx address. */
static void stealth_nonce_state_key(const char *one_time_address,char out[160]){char pre[768],h[129];snprintf(pre,sizeof(pre),"QUB-STEALTH-NONCE-STATE-v1|%s",one_time_address);sha3_512_hex_local(pre,h);snprintf(out,160,"__stealth_nonce:%s",h);}
static long long stealth_nonce_from_balances(const char *balpath,const char *one_time_address){char k[160];stealth_nonce_state_key(one_time_address,k);return kv_get_ll_bin(balpath,k);}
static int stealth_spend_state_atomic(const char *balpath,const char *from,const char *to,long long amount,long long expected_nonce){StateKVRecord *arr=NULL;size_t n=0;if(kv_load(balpath,&arr,&n)!=0)return -1;char nk[160];stealth_nonce_state_key(from,nk);long fi=-1,ti=-1,ni=-1;long long fb=0,tb=0,nonce=0;for(size_t i=0;i<n;i++){if(!strcmp(arr[i].key,from)){fi=(long)i;fb=arr[i].value;}else if(!strcmp(arr[i].key,to)){ti=(long)i;tb=arr[i].value;}else if(!strcmp(arr[i].key,nk)){ni=(long)i;nonce=arr[i].value;}}if(fi<0||fb<amount){free(arr);return -2;}if(nonce!=expected_nonce){free(arr);return -3;}size_t extra=(ti<0?1:0)+(ni<0?1:0);if(extra){StateKVRecord *tmp=realloc(arr,(n+extra)*sizeof(*arr));if(!tmp){free(arr);return -1;}arr=tmp;}arr[fi].value=fb-amount;if(ti>=0)arr[ti].value=tb+amount;else{snprintf(arr[n].key,sizeof(arr[n].key),"%s",to);arr[n].value=amount;ti=(long)n++;}if(ni>=0)arr[ni].value=nonce+1;else{snprintf(arr[n].key,sizeof(arr[n].key),"%s",nk);arr[n].value=nonce+1;n++;}int rc=kv_save(balpath,arr,n);free(arr);return rc;}

static int stealth_ecdsa_sign(const BIGNUM *priv,const char *msg,char **sig_hex_out){int rc=-1;EC_KEY *key=EC_KEY_new_by_curve_name(NID_secp256k1);if(!key)return -1;const EC_GROUP *g=EC_KEY_get0_group(key);EC_POINT *P=EC_POINT_new(g);BN_CTX *ctx=BN_CTX_new();if(!P||!ctx||EC_KEY_set_private_key(key,priv)!=1||EC_POINT_mul(g,P,priv,NULL,NULL,ctx)!=1||EC_KEY_set_public_key(key,P)!=1)goto done;unsigned char h[32];SHA256((const unsigned char*)msg,strlen(msg),h);ECDSA_SIG *sig=ECDSA_do_sign(h,32,key);if(!sig)goto done;int len=i2d_ECDSA_SIG(sig,NULL);unsigned char *der=malloc(len),*q=der;if(!der){ECDSA_SIG_free(sig);goto done;}i2d_ECDSA_SIG(sig,&q);char *hex=malloc((size_t)len*2+1);if(!hex){free(der);ECDSA_SIG_free(sig);goto done;}bytes_to_hex_local(der,(size_t)len,hex);*sig_hex_out=hex;free(der);ECDSA_SIG_free(sig);rc=0;done:if(P)EC_POINT_free(P);if(ctx)BN_CTX_free(ctx);EC_KEY_free(key);return rc;}

static int stealth_ecdsa_verify(const char *pub_hex,const char *msg,const char *sig_hex){unsigned char pub[33];if(strlen(pub_hex)!=66||hex_to_bytes_local(pub_hex,pub,33)!=0)return -1;size_t slen=strlen(sig_hex)/2;if(strlen(sig_hex)%2||slen<8||slen>256)return -1;unsigned char *der=malloc(slen);if(!der)return -1;if(hex_to_bytes_local(sig_hex,der,slen)!=0){free(der);return -1;}const unsigned char *q=der;ECDSA_SIG *sig=d2i_ECDSA_SIG(NULL,&q,(long)slen);if(!sig){free(der);return -1;}EC_KEY *key=EC_KEY_new_by_curve_name(NID_secp256k1);const EC_GROUP *g=key?EC_KEY_get0_group(key):NULL;EC_POINT *P=g?EC_POINT_new(g):NULL;BN_CTX *ctx=BN_CTX_new();int rc=-1;if(key&&P&&ctx&&EC_POINT_oct2point(g,P,pub,33,ctx)==1&&EC_KEY_set_public_key(key,P)==1){unsigned char h[32];SHA256((const unsigned char*)msg,strlen(msg),h);rc=ECDSA_do_verify(h,32,sig,key)==1?0:-1;}if(P)EC_POINT_free(P);if(ctx)BN_CTX_free(ctx);if(key)EC_KEY_free(key);ECDSA_SIG_free(sig);free(der);return rc;}

static int stealth_address_cmd(const char *wallet_dir){char saddr[512];if(stealth_make_address_from_wallet_dir(wallet_dir,saddr)!=0)die("wallet unlock required for stealth keys");printf("stealth_address=%s\nformat=squb2_x25519_scan_pub_secp256k1_spend_pub\nclaim_spend=one-time-secp256k1-key-consensus-verifiable\npolicy=optional-privacy-not-for-exchange-deposits-transparent-default\n",saddr);return 0;}

static int stealth_send_cmd(const char *chain_dir,const char *wallet_dir,const char *stealth_address,long long amount,const char *memo){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;if(amount<=0)die("stealth amount must be > 0");char scan[129],spend[129];if(stealth_split_address(stealth_address,scan,spend)!=0)die("invalid squb2 stealth address");char *sender=wallet_address(wallet_dir);if(!sender)die("wallet address unavailable");sender[strcspn(sender,"\r\n")]=0;char balpath[1024],journal[1024],sjpath[1024];state_paths(chain_dir,balpath,sizeof(balpath),NULL,0,NULL,0,journal,sizeof(journal));stealth_paths(chain_dir,NULL,0,sjpath,sizeof(sjpath));if(kv_get_ll_bin(balpath,sender)<amount)die("insufficient transparent funds");
    unsigned char scan_pub[32],eph_priv[32],eph_pub[32],shared[32];char eph_hex[65],ot_pub[129],ot_addr[385],rnd[65];if(hex_to_bytes_local(scan,scan_pub,32)!=0)die("bad stealth scan pub");if(RAND_bytes(eph_priv,32)!=1)die("secure randomness failed");eph_priv[0]&=248;eph_priv[31]&=127;eph_priv[31]|=64;if(stealth_x25519_pub_from_priv(eph_priv,eph_pub)!=0||stealth_x25519_derive(eph_priv,scan_pub,shared)!=0)die("x25519 failed");bytes_to_hex_local(eph_pub,32,eph_hex);if(stealth_one_time_pub(spend,shared,ot_pub)!=0)die("one-time key derivation failed");stealth_address_from_one_time_pub(ot_pub,ot_addr);shielded_random_hex(rnd,16);
    StealthRecord *arr=NULL;size_t n=0;if(stealth_load_all(chain_dir,&arr,&n)!=0)die("stealth load failed");StealthRecord *tmp=realloc(arr,(n+1)*sizeof(*arr));if(!tmp){free(arr);die("oom");}arr=tmp;StealthRecord *r=&arr[n];memset(r,0,sizeof(*r));snprintf(r->tx_id,129,"stx_%lld_%s",(long long)time(NULL),rnd);snprintf(r->sender,385,"%s",sender);snprintf(r->one_time_address,385,"%s",ot_addr);r->amount=amount;snprintf(r->ephemeral_pub,129,"%s",eph_hex);snprintf(r->one_time_pub,129,"%s",ot_pub);r->created_at=(long long)time(NULL);snprintf(r->status,32,"funded");snprintf(r->memo,256,"%s",memo?memo:"stealth-transfer");clean_field(r->memo);
    if(stealth_balance_transfer_atomic(balpath,sender,ot_addr,amount)!=0){free(sender);free(arr);die("atomic stealth funding failed");}if(stealth_save_all(chain_dir,arr,n+1)!=0){free(sender);free(arr);die("stealth metadata save failed");}journal_append(chain_dir,"stealth_send tx_id=%s sender=%s one_time=%s amount=%lld eph=%s one_time_pub=%s",r->tx_id,sender,ot_addr,amount,eph_hex,ot_pub);FILE *sj=fopen(sjpath,"ab");if(sj){fprintf(sj,"stealth_fund tx_id=%s one_time=%s amount=%lld eph=%s pub=%s\n",r->tx_id,ot_addr,amount,eph_hex,ot_pub);fclose(sj);}printf("status=stealth-funded\ntx_id=%s\none_time_address=%s\nephemeral_pub=%s\none_time_pub=%s\namount=%lld\n",r->tx_id,ot_addr,eph_hex,ot_pub,amount);OPENSSL_cleanse(eph_priv,32);OPENSSL_cleanse(shared,32);free(sender);free(arr);return 0;}

static int stealth_record_owned(const StealthRecord *r,const char *wallet_dir,unsigned char shared_out[32],BIGNUM **ot_priv_out){unsigned char scan_priv[32],scan_pub[32],eph[32];char derived_pub[129],addr[385];BIGNUM *priv=NULL;if(strlen(r->ephemeral_pub)!=64||hex_to_bytes_local(r->ephemeral_pub,eph,32)!=0)return 0;if(stealth_wallet_scan_keypair(wallet_dir,scan_priv,scan_pub)!=0)return 0;if(stealth_x25519_derive(scan_priv,eph,shared_out)!=0){OPENSSL_cleanse(scan_priv,32);return 0;}OPENSSL_cleanse(scan_priv,32);if(stealth_one_time_priv(wallet_dir,shared_out,&priv,derived_pub)!=0)return 0;stealth_address_from_one_time_pub(derived_pub,addr);if(strcmp(addr,r->one_time_address)|| (r->one_time_pub[0]&&strcmp(derived_pub,r->one_time_pub))){BN_clear_free(priv);return 0;}if(ot_priv_out)*ot_priv_out=priv;else BN_clear_free(priv);return 1;}

static int stealth_scan_cmd(const char *chain_dir,const char *wallet_dir){StealthRecord *arr=NULL;size_t n=0;if(stealth_load_all(chain_dir,&arr,&n)!=0)die("stealth load failed");int found=0;for(size_t i=0;i<n;i++){unsigned char shared[32];if(stealth_record_owned(&arr[i],wallet_dir,shared,NULL)){found++;printf("%s one_time=%s amount=%lld status=%s eph=%s\n",arr[i].tx_id,arr[i].one_time_address,arr[i].amount,arr[i].status,arr[i].ephemeral_pub);}OPENSSL_cleanse(shared,32);}printf("scan_found=%d\nscan_mutates_chain=false\n",found);free(arr);return 0;}

static int stealth_spend_cmd(const char *chain_dir,const char *wallet_dir,const char *tx_id,const char *to,long long amount){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;if(!tx_id||!to||strncmp(to,"qrx",3)||amount<=0)die("invalid stealth spend arguments");StealthRecord *arr=NULL;size_t n=0;if(stealth_load_all(chain_dir,&arr,&n)!=0)die("stealth load failed");StealthRecord *r=NULL;for(size_t i=0;i<n;i++)if(!strcmp(arr[i].tx_id,tx_id)){r=&arr[i];break;}if(!r){free(arr);die("stealth transfer not found");}unsigned char shared[32];BIGNUM *priv=NULL;if(!stealth_record_owned(r,wallet_dir,shared,&priv)){free(arr);die("wallet does not own stealth output");}char pub[129];BIGNUM *tmppriv=NULL;if(stealth_one_time_priv(wallet_dir,shared,&tmppriv,pub)!=0){BN_clear_free(priv);free(arr);die("one-time key derivation failed");}BN_clear_free(tmppriv);char expected_addr[385];stealth_address_from_one_time_pub(pub,expected_addr);if(strcmp(expected_addr,r->one_time_address)){BN_clear_free(priv);free(arr);die("one-time address/public-key mismatch");}
    char noncepath[1024],spdb[1024],balpath[1024];stealth_spend_paths(chain_dir,spdb,sizeof(spdb),noncepath,sizeof(noncepath));state_paths(chain_dir,balpath,sizeof(balpath),NULL,0,NULL,0,NULL,0);long long nonce=stealth_nonce_from_balances(balpath,r->one_time_address);/* One-time compatibility import for Phase-2 state: if an old split nonce exists, refuse a mismatched state rather than silently replaying. */long long legacy_nonce=kv_get_ll_bin(noncepath,r->one_time_address);if(nonce==0&&legacy_nonce>0)nonce=legacy_nonce;long long bal=kv_get_ll_bin(balpath,r->one_time_address);if(bal<amount){BN_clear_free(priv);free(arr);die("insufficient one-time balance");}char *net=chain_cfg_value(chain_dir,"network_id"),*gen=chain_cfg_value(chain_dir,"genesis_hash");if(!net||!gen){if(net)free(net);if(gen)free(gen);BN_clear_free(priv);free(arr);die("stealth spend chain binding unavailable");}char msg[3072];snprintf(msg,sizeof(msg),"QUB-STEALTH-SPEND-v2|network=%s|genesis=%s|tx=%s|one_time=%s|to=%s|amount=%lld|nonce=%lld",net,gen,r->tx_id,r->one_time_address,to,amount,nonce);char *sig=NULL;if(stealth_ecdsa_sign(priv,msg,&sig)!=0||stealth_ecdsa_verify(pub,msg,sig)!=0){if(sig)free(sig);free(net);free(gen);BN_clear_free(priv);free(arr);die("stealth ownership proof failed");}
    int src=stealth_spend_state_atomic(balpath,r->one_time_address,to,amount,nonce);if(src==-3&&legacy_nonce==nonce&&nonce>0){/* Atomically import legacy replay nonce into balances.bin then spend in one rewrite: build the nonce record first without moving funds. */char nk[160];stealth_nonce_state_key(r->one_time_address,nk);if(kv_set_ll_bin(balpath,nk,nonce)!=0)src=-1;else src=stealth_spend_state_atomic(balpath,r->one_time_address,to,amount,nonce);}if(src!=0){free(sig);free(net);free(gen);BN_clear_free(priv);free(arr);die(src==-3?"stealth replay nonce mismatch":"stealth spend state update failed");}FILE *f=fopen(spdb,"ab");if(!f){free(sig);free(net);free(gen);BN_clear_free(priv);free(arr);die("stealth spend journal failed");}fprintf(f,"v2|%s|%s|%s|%s|%s|%lld|%lld|%s|%s\n",net,gen,r->tx_id,r->one_time_address,to,amount,nonce,pub,sig);fclose(f);snprintf(r->status,sizeof(r->status),kv_get_ll_bin(balpath,r->one_time_address)>0?"partially-spent":"spent");stealth_save_all(chain_dir,arr,n);journal_append(chain_dir,"stealth_spend tx_id=%s one_time=%s to=%s amount=%lld nonce=%lld pub=%s sig=%s",r->tx_id,r->one_time_address,to,amount,nonce,pub,sig);printf("status=stealth-spent\ntx_id=%s\nfrom_one_time=%s\nto=%s\namount=%lld\nnonce=%lld\nchain_binding=network-id-plus-genesis-hash\nownership_proof=secp256k1-ecdsa-verified\n",r->tx_id,r->one_time_address,to,amount,nonce);free(sig);free(net);free(gen);BN_clear_free(priv);OPENSSL_cleanse(shared,32);free(arr);return 0;}

static int stealth_history_cmd(const char *chain_dir,const char *wallet_dir){char *addr=wallet_address(wallet_dir);if(!addr)die("wallet address unavailable");addr[strcspn(addr,"\r\n")]=0;StealthRecord *arr=NULL;size_t n=0;if(stealth_load_all(chain_dir,&arr,&n)!=0)die("stealth load failed");for(size_t i=0;i<n;i++){unsigned char shared[32];int owned=stealth_record_owned(&arr[i],wallet_dir,shared,NULL);if(owned||!strcmp(arr[i].sender,addr))printf("%s direction=%s sender=%s one_time=%s amount=%lld status=%s eph=%s memo=%s\n",arr[i].tx_id,owned?"received":"sent",arr[i].sender,arr[i].one_time_address,arr[i].amount,arr[i].status,arr[i].ephemeral_pub,arr[i].memo);OPENSSL_cleanse(shared,32);}free(addr);free(arr);return 0;}

typedef struct {
    char note_id[129];
    char value_commitment[67];
    char leaf_commitment[129];
    char one_time_pub[67];
    char ephemeral_pub[65];
    char nonce_hex[25];
    char ciphertext_b64[3072];
    char tag_hex[33];
    char proof_hash[129];
    long long created_at;
} ShieldedNoteRecord;

typedef struct {
    long long value;
    char blind_hex[65];
    char rho[65];
    char memo[256];
    BIGNUM *one_time_priv;
} ShieldedOwnedNote;

static void shielded_paths(const char *chain_dir, char *notes, size_t nsz, char *nullifiers, size_t usz, char *journal, size_t jsz) {
    if (notes) snprintf(notes, nsz, "%s/shielded_notes_v3.db", chain_dir);
    if (nullifiers) snprintf(nullifiers, usz, "%s/shielded_nullifiers_v3.db", chain_dir);
    if (journal) snprintf(journal, jsz, "%s/shielded_journal.log", chain_dir);
}

static void shielded_merkle_path(const char *chain_dir,char *out,size_t sz){snprintf(out,sz,"%s/shielded_merkle_leaves_v3.db",chain_dir);}
static void shielded_spend_path(const char *chain_dir,char *out,size_t sz){snprintf(out,sz,"%s/shielded_spends_v3.db",chain_dir);}
static void shielded_proof_dir(const char *chain_dir,char *out,size_t sz){snprintf(out,sz,"%s/shielded_proofs_v3",chain_dir);}

static int shielded_wallet_scan_keypair(const char *wallet_dir,unsigned char priv[32],unsigned char pub[32]){
    unsigned char material[32],digest[64];unsigned int dlen=0;if(stealth_wallet_material(wallet_dir,material)!=0)return -2;EVP_MD_CTX*m=EVP_MD_CTX_new();if(!m){OPENSSL_cleanse(material,32);return -1;}static const char dom[]="QUB-SHIELDED-X25519-VIEW-v1";int ok=EVP_DigestInit_ex(m,EVP_sha3_512(),NULL)==1&&EVP_DigestUpdate(m,dom,sizeof(dom)-1)==1&&EVP_DigestUpdate(m,material,32)==1&&EVP_DigestFinal_ex(m,digest,&dlen)==1&&dlen==64;EVP_MD_CTX_free(m);OPENSSL_cleanse(material,32);if(!ok)return -1;memcpy(priv,digest,32);OPENSSL_cleanse(digest,64);priv[0]&=248;priv[31]&=127;priv[31]|=64;return stealth_x25519_pub_from_priv(priv,pub);
}

static int shielded_wallet_spend_scalar(const char *wallet_dir,BIGNUM **priv_out,char pub_hex[67]){
    unsigned char material[32],digest[64];unsigned int dlen=0;if(stealth_wallet_material(wallet_dir,material)!=0)return -2;EVP_MD_CTX*m=EVP_MD_CTX_new();if(!m){OPENSSL_cleanse(material,32);return -1;}static const char dom[]="QUB-SHIELDED-SECP256K1-SPEND-v1";int ok=EVP_DigestInit_ex(m,EVP_sha3_512(),NULL)==1&&EVP_DigestUpdate(m,dom,sizeof(dom)-1)==1&&EVP_DigestUpdate(m,material,32)==1&&EVP_DigestFinal_ex(m,digest,&dlen)==1&&dlen==64;EVP_MD_CTX_free(m);OPENSSL_cleanse(material,32);if(!ok)return -1;EC_GROUP*g=NULL;BIGNUM*n=NULL,*d=NULL;BN_CTX*ctx=NULL;EC_POINT*P=NULL;int rc=-1;if(stealth_secp_group_order(&g,&n)!=0)goto done;ctx=BN_CTX_new();d=BN_bin2bn(digest,64,NULL);P=EC_POINT_new(g);if(!ctx||!d||!P)goto done;if(BN_mod(d,d,n,ctx)!=1)goto done;if(BN_is_zero(d))BN_one(d);if(EC_POINT_mul(g,P,d,NULL,NULL,ctx)!=1)goto done;unsigned char enc[33];if(EC_POINT_point2oct(g,P,POINT_CONVERSION_COMPRESSED,enc,33,ctx)!=33)goto done;bytes_to_hex_local(enc,33,pub_hex);*priv_out=d;d=NULL;rc=0;done:OPENSSL_cleanse(digest,64);if(P)EC_POINT_free(P);if(ctx)BN_CTX_free(ctx);if(d)BN_clear_free(d);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;
}

static int shielded_split_address(const char*z,char view[65],char spend[67]){if(!z||strncmp(z,"zqub2",5)!=0||strlen(z+5)!=130)return -1;memcpy(view,z+5,64);view[64]=0;memcpy(spend,z+69,66);spend[66]=0;for(int i=0;i<64;i++)if(!isxdigit((unsigned char)view[i]))return -1;for(int i=0;i<66;i++)if(!isxdigit((unsigned char)spend[i]))return -1;return 0;}

static int shielded_make_address_from_wallet(const char*wallet_dir,char out[512]){unsigned char vpriv[32],vpub[32];char vh[65],sp[67];BIGNUM*d=NULL;if(shielded_wallet_scan_keypair(wallet_dir,vpriv,vpub)!=0)return -1;if(shielded_wallet_spend_scalar(wallet_dir,&d,sp)!=0){OPENSSL_cleanse(vpriv,32);return -1;}bytes_to_hex_local(vpub,32,vh);snprintf(out,512,"zqub2%s%s",vh,sp);OPENSSL_cleanse(vpriv,32);BN_clear_free(d);return 0;}

static int shielded_shared_tweak(const unsigned char shared[32],const char*rho,BIGNUM**out){unsigned char digest[64];unsigned int dlen=0;EVP_MD_CTX*m=EVP_MD_CTX_new();if(!m)return -1;static const char dom[]="QUB-SHIELDED-ONE-TIME-TWEAK-v1";int ok=EVP_DigestInit_ex(m,EVP_sha3_512(),NULL)==1&&EVP_DigestUpdate(m,dom,sizeof(dom)-1)==1&&EVP_DigestUpdate(m,shared,32)==1&&EVP_DigestUpdate(m,rho,strlen(rho))==1&&EVP_DigestFinal_ex(m,digest,&dlen)==1&&dlen==64;EVP_MD_CTX_free(m);if(!ok)return -1;EC_GROUP*g=NULL;BIGNUM*n=NULL,*t=NULL;BN_CTX*ctx=NULL;int rc=-1;if(stealth_secp_group_order(&g,&n)!=0)goto done;ctx=BN_CTX_new();t=BN_bin2bn(digest,64,NULL);if(!ctx||!t)goto done;if(BN_mod(t,t,n,ctx)!=1)goto done;if(BN_is_zero(t))BN_one(t);*out=t;t=NULL;rc=0;done:OPENSSL_cleanse(digest,64);if(t)BN_clear_free(t);if(ctx)BN_CTX_free(ctx);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;}

static int shielded_one_time_pub(const char*master_pub,const unsigned char shared[32],const char*rho,char out[67]){unsigned char enc[33],oenc[33];if(strlen(master_pub)!=66||hex_to_bytes_local(master_pub,enc,33)!=0)return -1;EC_GROUP*g=NULL;BIGNUM*n=NULL,*t=NULL;BN_CTX*ctx=NULL;EC_POINT*M=NULL,*T=NULL,*O=NULL;int rc=-1;if(stealth_secp_group_order(&g,&n)!=0||shielded_shared_tweak(shared,rho,&t)!=0)goto done;ctx=BN_CTX_new();M=EC_POINT_new(g);T=EC_POINT_new(g);O=EC_POINT_new(g);if(!ctx||!M||!T||!O)goto done;if(EC_POINT_oct2point(g,M,enc,33,ctx)!=1||EC_POINT_mul(g,T,t,NULL,NULL,ctx)!=1||EC_POINT_add(g,O,M,T,ctx)!=1)goto done;if(EC_POINT_point2oct(g,O,POINT_CONVERSION_COMPRESSED,oenc,33,ctx)!=33)goto done;bytes_to_hex_local(oenc,33,out);rc=0;done:if(O)EC_POINT_free(O);if(T)EC_POINT_free(T);if(M)EC_POINT_free(M);if(ctx)BN_CTX_free(ctx);if(t)BN_clear_free(t);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;}

static int shielded_one_time_priv(const char*wallet_dir,const unsigned char shared[32],const char*rho,BIGNUM**out,char pub[67]){BIGNUM*m=NULL,*t=NULL,*n=NULL,*d=NULL;EC_GROUP*g=NULL;BN_CTX*ctx=NULL;EC_POINT*P=NULL;char mp[67];int rc=-1;if(shielded_wallet_spend_scalar(wallet_dir,&m,mp)!=0||shielded_shared_tweak(shared,rho,&t)!=0||stealth_secp_group_order(&g,&n)!=0)goto done;ctx=BN_CTX_new();d=BN_new();P=EC_POINT_new(g);if(!ctx||!d||!P)goto done;if(BN_mod_add(d,m,t,n,ctx)!=1||BN_is_zero(d)||EC_POINT_mul(g,P,d,NULL,NULL,ctx)!=1)goto done;unsigned char enc[33];if(EC_POINT_point2oct(g,P,POINT_CONVERSION_COMPRESSED,enc,33,ctx)!=33)goto done;bytes_to_hex_local(enc,33,pub);*out=d;d=NULL;rc=0;done:if(P)EC_POINT_free(P);if(ctx)BN_CTX_free(ctx);if(d)BN_clear_free(d);if(m)BN_clear_free(m);if(t)BN_clear_free(t);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;}

static int shielded_pedersen_H(EC_GROUP*g,EC_POINT*H,BN_CTX*ctx){BIGNUM*p=BN_new(),*a=BN_new(),*b=BN_new(),*x=BN_new();if(!p||!a||!b||!x)return -1;if(EC_GROUP_get_curve(g,p,a,b,ctx)!=1)goto fail;for(unsigned ctr=0;ctr<10000;ctr++){char in[128];snprintf(in,sizeof(in),"QUB-PEDERSEN-HASH-TO-CURVE-v1|%u",ctr);unsigned char h[32];EVP_Digest(in,strlen(in),h,NULL,EVP_sha3_256(),NULL);BN_bin2bn(h,32,x);BN_mod(x,x,p,ctx);if(EC_POINT_set_compressed_coordinates(g,H,x,ctr&1,ctx)==1&&!EC_POINT_is_at_infinity(g,H)){BN_free(p);BN_free(a);BN_free(b);BN_free(x);return 0;}}fail:BN_free(p);BN_free(a);BN_free(b);BN_free(x);return -1;}

static int shielded_bn_random(const BIGNUM*n,BIGNUM*out){return BN_priv_rand_range(out,n)==1&&!BN_is_zero(out)?0:-1;}
static void shielded_bn_hex64(const BIGNUM*b,char out[65]){unsigned char x[32]={0};BN_bn2binpad(b,x,32);bytes_to_hex_local(x,32,out);OPENSSL_cleanse(x,32);}
static BIGNUM*shielded_bn_from_hex(const char*h){unsigned char x[32];if(!h||strlen(h)!=64||hex_to_bytes_local(h,x,32)!=0)return NULL;return BN_bin2bn(x,32,NULL);}
static int shielded_point_hex(EC_GROUP*g,const EC_POINT*P,BN_CTX*ctx,char out[67]){unsigned char x[33];if(EC_POINT_point2oct(g,P,POINT_CONVERSION_COMPRESSED,x,33,ctx)!=33)return -1;bytes_to_hex_local(x,33,out);return 0;}
static EC_POINT*shielded_point_from_hex(EC_GROUP*g,const char*h,BN_CTX*ctx){unsigned char x[33];if(!h||strlen(h)!=66||hex_to_bytes_local(h,x,33)!=0)return NULL;EC_POINT*P=EC_POINT_new(g);if(!P||EC_POINT_oct2point(g,P,x,33,ctx)!=1){if(P)EC_POINT_free(P);return NULL;}return P;}

static int shielded_pedersen_commit(long long value,const BIGNUM*r,char out[67]){if(value<0)return -1;EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();EC_POINT*H=g?EC_POINT_new(g):NULL,*C=g?EC_POINT_new(g):NULL;BIGNUM*v=BN_new();int rc=-1;if(!g||!ctx||!H||!C||!v||shielded_pedersen_H(g,H,ctx)!=0)goto done;BN_set_word(v,(BN_ULONG)value);if(EC_POINT_mul(g,C,v,H,r,ctx)!=1)goto done;rc=shielded_point_hex(g,C,ctx,out);done:if(v)BN_free(v);if(C)EC_POINT_free(C);if(H)EC_POINT_free(H);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static BIGNUM*shielded_challenge_scalar(const BIGNUM*n,const char*ctxstr,const char*p1,const char*p2,const char*p3){char buf[1024];snprintf(buf,sizeof(buf),"QUB-ZK-CHALLENGE-v1|%s|%s|%s|%s",ctxstr?ctxstr:"",p1?p1:"",p2?p2:"",p3?p3:"");unsigned char h[64];EVP_Digest(buf,strlen(buf),h,NULL,EVP_sha3_512(),NULL);BIGNUM*c=BN_bin2bn(h,64,NULL);BN_CTX*ctx=BN_CTX_new();if(!c||!ctx||BN_mod(c,c,n,ctx)!=1){if(c)BN_free(c);if(ctx)BN_CTX_free(ctx);return NULL;}BN_CTX_free(ctx);return c;}

static int shielded_schnorr_prove_H(const EC_POINT*P,const BIGNUM*w,const char*context,char Ahex[67],char chex[65],char shex[65]){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BIGNUM*n=BN_new(),*k=BN_new(),*c=NULL,*s=BN_new();BN_CTX*ctx=BN_CTX_new();EC_POINT*H=g?EC_POINT_new(g):NULL,*A=g?EC_POINT_new(g):NULL;char Phex[67];int rc=-1;if(!g||!n||!k||!s||!ctx||!H||!A||EC_GROUP_get_order(g,n,ctx)!=1||shielded_pedersen_H(g,H,ctx)!=0||shielded_bn_random(n,k)!=0||EC_POINT_mul(g,A,NULL,H,k,ctx)!=1||shielded_point_hex(g,P,ctx,Phex)!=0||shielded_point_hex(g,A,ctx,Ahex)!=0)goto done;c=shielded_challenge_scalar(n,context,Phex,Ahex,"");if(!c||BN_mod_mul(s,c,w,n,ctx)!=1||BN_mod_add(s,s,k,n,ctx)!=1)goto done;shielded_bn_hex64(c,chex);shielded_bn_hex64(s,shex);rc=0;done:if(A)EC_POINT_free(A);if(H)EC_POINT_free(H);if(ctx)BN_CTX_free(ctx);if(s)BN_clear_free(s);if(c)BN_free(c);if(k)BN_clear_free(k);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;}

static int shielded_schnorr_verify_H(const EC_POINT*P,const char*context,const char*Ahex,const char*chex,const char*shex){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();BIGNUM*n=BN_new(),*c=shielded_bn_from_hex(chex),*s=shielded_bn_from_hex(shex),*calc=NULL;EC_POINT*H=g?EC_POINT_new(g):NULL,*A=NULL,*L=g?EC_POINT_new(g):NULL,*R=g?EC_POINT_new(g):NULL,*cP=g?EC_POINT_new(g):NULL;char Phex[67];int rc=-1;if(!g||!ctx||!n||!c||!s||!H||!L||!R||!cP||EC_GROUP_get_order(g,n,ctx)!=1||shielded_pedersen_H(g,H,ctx)!=0||(A=shielded_point_from_hex(g,Ahex,ctx))==NULL||shielded_point_hex(g,P,ctx,Phex)!=0)goto done;calc=shielded_challenge_scalar(n,context,Phex,Ahex,"");if(!calc||BN_cmp(calc,c)!=0)goto done;if(EC_POINT_mul(g,L,NULL,H,s,ctx)!=1||EC_POINT_mul(g,cP,NULL,P,c,ctx)!=1||EC_POINT_add(g,R,A,cP,ctx)!=1)goto done;rc=EC_POINT_cmp(g,L,R,ctx)==0?0:-1;done:if(cP)EC_POINT_free(cP);if(R)EC_POINT_free(R);if(L)EC_POINT_free(L);if(A)EC_POINT_free(A);if(H)EC_POINT_free(H);if(calc)BN_free(calc);if(s)BN_clear_free(s);if(c)BN_free(c);if(n)BN_free(n);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

/* 63-bit Borromean-style bit range proof. It is deliberately simple and
   auditable rather than compact: each bit commitment is proven to encode 0
   or 1 using a Fiat-Shamir OR proof, then a Schnorr link proof binds the bit
   decomposition to the value commitment. */
static int shielded_range_prove(long long value,const BIGNUM*blind,const char*C_hex,const char*context,const char*path){if(value<0)return -1;EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();BIGNUM*n=BN_new();EC_POINT*H=g?EC_POINT_new(g):NULL,*G=NULL,*sum=g?EC_POINT_new(g):NULL,*C=NULL;BIGNUM*rsum=BN_new(),*pow2=BN_new();FILE*f=NULL;int rc=-1;if(!g||!ctx||!n||!H||!sum||!rsum||!pow2||EC_GROUP_get_order(g,n,ctx)!=1||shielded_pedersen_H(g,H,ctx)!=0||(G=(EC_POINT*)EC_GROUP_get0_generator(g))==NULL||(C=shielded_point_from_hex(g,C_hex,ctx))==NULL)goto done;EC_POINT_set_to_infinity(g,sum);BN_zero(rsum);BN_one(pow2);f=fopen(path,"wb");if(!f)goto done;fprintf(f,"QRX-RANGEPROOF-v1|bits=63|commitment=%s|context=%s\n",C_hex,context);
 for(int i=0;i<63;i++){int bit=(int)(((unsigned long long)value>>i)&1ULL);BIGNUM*r=BN_new(),*k=BN_new(),*cf=BN_new(),*sf=BN_new(),*cr=BN_new(),*sr=BN_new(),*ctot=NULL,*tmpbn=BN_new();EC_POINT*B=EC_POINT_new(g),*P0=EC_POINT_new(g),*P1=EC_POINT_new(g),*A0=EC_POINT_new(g),*A1=EC_POINT_new(g),*tmpP=EC_POINT_new(g);if(!r||!k||!cf||!sf||!cr||!sr||!tmpbn||!B||!P0||!P1||!A0||!A1||!tmpP||shielded_bn_random(n,r)!=0||shielded_bn_random(n,k)!=0||shielded_bn_random(n,cf)!=0||shielded_bn_random(n,sf)!=0)goto bit_fail;BIGNUM*bv=BN_new();BN_set_word(bv,(BN_ULONG)bit);if(EC_POINT_mul(g,B,bv,H,r,ctx)!=1){BN_free(bv);goto bit_fail;}BN_free(bv);EC_POINT_copy(P0,B);if(EC_POINT_copy(P1,B)!=1)goto bit_fail;
 /* P1 = B-G without mutating generator */ EC_POINT*negG=EC_POINT_dup(G,g);if(!negG)goto bit_fail;EC_POINT_invert(g,negG,ctx);EC_POINT_add(g,P1,B,negG,ctx);EC_POINT_free(negG);
 int fake=1-bit,real=bit;EC_POINT*Pf=fake==0?P0:P1;EC_POINT*Af=fake==0?A0:A1;EC_POINT*Ar=real==0?A0:A1;
 /* Af = sf*H - cf*Pf */if(EC_POINT_mul(g,Af,NULL,H,sf,ctx)!=1||EC_POINT_mul(g,tmpP,NULL,Pf,cf,ctx)!=1||EC_POINT_invert(g,tmpP,ctx)!=1||EC_POINT_add(g,Af,Af,tmpP,ctx)!=1||EC_POINT_mul(g,Ar,NULL,H,k,ctx)!=1)goto bit_fail;
 char Bh[67],A0h[67],A1h[67],idxctx[512];shielded_point_hex(g,B,ctx,Bh);shielded_point_hex(g,A0,ctx,A0h);shielded_point_hex(g,A1,ctx,A1h);snprintf(idxctx,sizeof(idxctx),"%s|bit=%d",context,i);ctot=shielded_challenge_scalar(n,idxctx,Bh,A0h,A1h);if(!ctot)goto bit_fail;if(BN_mod_sub(cr,ctot,cf,n,ctx)!=1||BN_mod_mul(sr,cr,r,n,ctx)!=1||BN_mod_add(sr,sr,k,n,ctx)!=1)goto bit_fail;BIGNUM *c0=real==0?cr:cf,*s0=real==0?sr:sf,*c1=real==1?cr:cf,*s1=real==1?sr:sf;char c0h[65],s0h[65],c1h[65],s1h[65];shielded_bn_hex64(c0,c0h);shielded_bn_hex64(s0,s0h);shielded_bn_hex64(c1,c1h);shielded_bn_hex64(s1,s1h);fprintf(f,"bit|%d|%s|%s|%s|%s|%s|%s|%s\n",i,Bh,A0h,A1h,c0h,s0h,c1h,s1h);
 /* aggregate sum += 2^i B; rsum += 2^i r */if(EC_POINT_mul(g,tmpP,NULL,B,pow2,ctx)!=1||EC_POINT_add(g,sum,sum,tmpP,ctx)!=1||BN_mod_mul(tmpbn,pow2,r,n,ctx)!=1||BN_mod_add(rsum,rsum,tmpbn,n,ctx)!=1||BN_mod_lshift1(pow2,pow2,n,ctx)!=1)goto bit_fail;
 BN_clear_free(r);BN_clear_free(k);BN_free(cf);BN_clear_free(sf);BN_free(cr);BN_clear_free(sr);BN_free(tmpbn);BN_free(ctot);EC_POINT_free(B);EC_POINT_free(P0);EC_POINT_free(P1);EC_POINT_free(A0);EC_POINT_free(A1);EC_POINT_free(tmpP);continue;
bit_fail: if(r)BN_clear_free(r);if(k)BN_clear_free(k);if(cf)BN_free(cf);if(sf)BN_clear_free(sf);if(cr)BN_free(cr);if(sr)BN_clear_free(sr);if(tmpbn)BN_free(tmpbn);if(ctot)BN_free(ctot);if(B)EC_POINT_free(B);if(P0)EC_POINT_free(P0);if(P1)EC_POINT_free(P1);if(A0)EC_POINT_free(A0);if(A1)EC_POINT_free(A1);if(tmpP)EC_POINT_free(tmpP);goto done; }
 /* link point P=C-sum, witness delta=blind-rsum */EC_POINT*P=EC_POINT_dup(C,g),*neg=EC_POINT_dup(sum,g);BIGNUM*delta=BN_new();if(!P||!neg||!delta)goto done;EC_POINT_invert(g,neg,ctx);EC_POINT_add(g,P,P,neg,ctx);BN_mod_sub(delta,blind,rsum,n,ctx);char Ah[67],ch[65],sh[65];char lctx[512];snprintf(lctx,sizeof(lctx),"%s|range-link",context);if(shielded_schnorr_prove_H(P,delta,lctx,Ah,ch,sh)!=0){EC_POINT_free(P);EC_POINT_free(neg);BN_clear_free(delta);goto done;}fprintf(f,"link|%s|%s|%s\n",Ah,ch,sh);EC_POINT_free(P);EC_POINT_free(neg);BN_clear_free(delta);rc=0;
done:if(f)fclose(f);if(C)EC_POINT_free(C);if(pow2)BN_free(pow2);if(rsum)BN_clear_free(rsum);if(sum)EC_POINT_free(sum);if(H)EC_POINT_free(H);if(n)BN_free(n);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static int shielded_range_verify(const char*C_hex,const char*context,const char*path){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();BIGNUM*n=BN_new(),*pow2=BN_new();EC_POINT*H=g?EC_POINT_new(g):NULL,*G=NULL,*sum=g?EC_POINT_new(g):NULL,*C=NULL;FILE*f=NULL;char line[4096];int rc=-1,bits=0;if(!g||!ctx||!n||!pow2||!H||!sum||EC_GROUP_get_order(g,n,ctx)!=1||shielded_pedersen_H(g,H,ctx)!=0||(G=(EC_POINT*)EC_GROUP_get0_generator(g))==NULL||(C=shielded_point_from_hex(g,C_hex,ctx))==NULL)goto done;EC_POINT_set_to_infinity(g,sum);BN_one(pow2);f=fopen(path,"rb");if(!f)goto done;if(!fgets(line,sizeof(line),f)||strncmp(line,"QRX-RANGEPROOF-v1",17))goto done;
 while(fgets(line,sizeof(line),f)){line[strcspn(line,"\r\n")]=0;if(!strncmp(line,"bit|",4)){char *parts[9]={0};int k=0;char*cur=line;while(k<9){parts[k++]=cur;char*sep=strchr(cur,'|');if(!sep)break;*sep=0;cur=sep+1;}if(k!=9)goto done;int i=atoi(parts[1]);if(i!=bits||i>=63)goto done;EC_POINT*B=shielded_point_from_hex(g,parts[2],ctx),*A0=shielded_point_from_hex(g,parts[3],ctx),*A1=shielded_point_from_hex(g,parts[4],ctx);BIGNUM*c0=shielded_bn_from_hex(parts[5]),*s0=shielded_bn_from_hex(parts[6]),*c1=shielded_bn_from_hex(parts[7]),*s1=shielded_bn_from_hex(parts[8]),*ct=NULL,*cs=BN_new();EC_POINT*P0=B?EC_POINT_dup(B,g):NULL,*P1=B?EC_POINT_dup(B,g):NULL,*L=EC_POINT_new(g),*R=EC_POINT_new(g),*tmp=EC_POINT_new(g);if(!B||!A0||!A1||!c0||!s0||!c1||!s1||!cs||!P0||!P1||!L||!R||!tmp)goto bitvfail;EC_POINT*negG=EC_POINT_dup(G,g);EC_POINT_invert(g,negG,ctx);EC_POINT_add(g,P1,P1,negG,ctx);EC_POINT_free(negG);char idxctx[512];snprintf(idxctx,sizeof(idxctx),"%s|bit=%d",context,i);ct=shielded_challenge_scalar(n,idxctx,parts[2],parts[3],parts[4]);if(!ct||BN_mod_add(cs,c0,c1,n,ctx)!=1||BN_cmp(cs,ct)!=0)goto bitvfail;EC_POINT*Ps[2]={P0,P1};EC_POINT*As[2]={A0,A1};BIGNUM*cc[2]={c0,c1};BIGNUM*ss[2]={s0,s1};for(int j=0;j<2;j++){if(EC_POINT_mul(g,L,NULL,H,ss[j],ctx)!=1||EC_POINT_mul(g,tmp,NULL,Ps[j],cc[j],ctx)!=1||EC_POINT_add(g,R,As[j],tmp,ctx)!=1||EC_POINT_cmp(g,L,R,ctx)!=0)goto bitvfail;}if(EC_POINT_mul(g,tmp,NULL,B,pow2,ctx)!=1||EC_POINT_add(g,sum,sum,tmp,ctx)!=1||BN_mod_lshift1(pow2,pow2,n,ctx)!=1)goto bitvfail;bits++;EC_POINT_free(B);EC_POINT_free(A0);EC_POINT_free(A1);BN_free(c0);BN_clear_free(s0);BN_free(c1);BN_clear_free(s1);BN_free(ct);BN_free(cs);EC_POINT_free(P0);EC_POINT_free(P1);EC_POINT_free(L);EC_POINT_free(R);EC_POINT_free(tmp);continue;
bitvfail:if(B)EC_POINT_free(B);if(A0)EC_POINT_free(A0);if(A1)EC_POINT_free(A1);if(c0)BN_free(c0);if(s0)BN_clear_free(s0);if(c1)BN_free(c1);if(s1)BN_clear_free(s1);if(ct)BN_free(ct);if(cs)BN_free(cs);if(P0)EC_POINT_free(P0);if(P1)EC_POINT_free(P1);if(L)EC_POINT_free(L);if(R)EC_POINT_free(R);if(tmp)EC_POINT_free(tmp);goto done;}else if(!strncmp(line,"link|",5)){if(bits!=63)goto done;char Ah[67],ch[65],sh[65];if(sscanf(line,"link|%66[^|]|%64[^|]|%64s",Ah,ch,sh)!=3)goto done;EC_POINT*P=EC_POINT_dup(C,g),*neg=EC_POINT_dup(sum,g);if(!P||!neg)goto done;EC_POINT_invert(g,neg,ctx);EC_POINT_add(g,P,P,neg,ctx);char lctx[512];snprintf(lctx,sizeof(lctx),"%s|range-link",context);int ok=shielded_schnorr_verify_H(P,lctx,Ah,ch,sh);EC_POINT_free(P);EC_POINT_free(neg);if(ok!=0)goto done;rc=0;break;}}
done:if(f)fclose(f);if(C)EC_POINT_free(C);if(sum)EC_POINT_free(sum);if(H)EC_POINT_free(H);if(pow2)BN_free(pow2);if(n)BN_free(n);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static int shielded_aes_key(const unsigned char shared[32],unsigned char key[32]){EVP_MD_CTX*m=EVP_MD_CTX_new();if(!m)return -1;static const char dom[]="QUB-SHIELDED-NOTE-AES256GCM-v1";unsigned int len=0;int ok=EVP_DigestInit_ex(m,EVP_sha3_256(),NULL)==1&&EVP_DigestUpdate(m,dom,sizeof(dom)-1)==1&&EVP_DigestUpdate(m,shared,32)==1&&EVP_DigestFinal_ex(m,key,&len)==1&&len==32;EVP_MD_CTX_free(m);return ok?0:-1;}
static int shielded_aes_encrypt(const unsigned char key[32],const unsigned char nonce[12],const char*aad,const unsigned char*pt,int ptlen,unsigned char**ct,int*ctlen,unsigned char tag[16]){EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();if(!c)return -1;unsigned char*out=malloc((size_t)ptlen+16);int l=0,total=0,ok=0;if(out&&EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1&&EVP_EncryptInit_ex(c,NULL,NULL,key,nonce)==1&&EVP_EncryptUpdate(c,NULL,&l,(const unsigned char*)aad,(int)strlen(aad))==1&&EVP_EncryptUpdate(c,out,&l,pt,ptlen)==1){total=l;if(EVP_EncryptFinal_ex(c,out+total,&l)==1){total+=l;if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)==1)ok=1;}}EVP_CIPHER_CTX_free(c);if(!ok){free(out);return -1;}*ct=out;*ctlen=total;return 0;}
static int shielded_aes_decrypt(const unsigned char key[32],const unsigned char nonce[12],const char*aad,const unsigned char*ct,int ctlen,const unsigned char tag[16],unsigned char**pt,int*ptlen){EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();if(!c)return -1;unsigned char*out=malloc((size_t)ctlen+1);int l=0,total=0,ok=0;if(out&&EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1&&EVP_DecryptInit_ex(c,NULL,NULL,key,nonce)==1&&EVP_DecryptUpdate(c,NULL,&l,(const unsigned char*)aad,(int)strlen(aad))==1&&EVP_DecryptUpdate(c,out,&l,ct,ctlen)==1){total=l;EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)tag);if(EVP_DecryptFinal_ex(c,out+total,&l)==1){total+=l;out[total]=0;ok=1;}}EVP_CIPHER_CTX_free(c);if(!ok){free(out);return -1;}*pt=out;*ptlen=total;return 0;}

static int shielded_parse_line(const char*line,ShieldedNoteRecord*r){if(!line||!r)return -1;char buf[8192];snprintf(buf,sizeof(buf),"%s",line);buf[strcspn(buf,"\r\n")]=0;char*fields[10]={0};int n=0;char*cur=buf;while(n<10){fields[n++]=cur;char*sep=strchr(cur,'|');if(!sep)break;*sep=0;cur=sep+1;}if(n<10)return -1;memset(r,0,sizeof(*r));snprintf(r->note_id,129,"%s",fields[0]);snprintf(r->value_commitment,67,"%s",fields[1]);snprintf(r->leaf_commitment,129,"%s",fields[2]);snprintf(r->one_time_pub,67,"%s",fields[3]);snprintf(r->ephemeral_pub,65,"%s",fields[4]);snprintf(r->nonce_hex,25,"%s",fields[5]);snprintf(r->ciphertext_b64,3072,"%s",fields[6]);snprintf(r->tag_hex,33,"%s",fields[7]);snprintf(r->proof_hash,129,"%s",fields[8]);r->created_at=atoll(fields[9]);return 0;}
static int shielded_load_all(const char*chain_dir,ShieldedNoteRecord**out,size_t*count){char path[1024];shielded_paths(chain_dir,path,sizeof(path),NULL,0,NULL,0);*out=NULL;*count=0;FILE*f=fopen(path,"rb");if(!f)return 0;size_t cap=16,n=0;ShieldedNoteRecord*arr=calloc(cap,sizeof(*arr));if(!arr){fclose(f);return -1;}char line[8192];while(fgets(line,sizeof(line),f)){if(line[0]=='#'||line[0]=='\n')continue;ShieldedNoteRecord r;if(shielded_parse_line(line,&r)!=0)continue;if(n==cap){cap*=2;ShieldedNoteRecord*t=realloc(arr,cap*sizeof(*arr));if(!t){free(arr);fclose(f);return -1;}arr=t;}arr[n++]=r;}fclose(f);*out=arr;*count=n;return 0;}
static int shielded_save_all(const char*chain_dir,const ShieldedNoteRecord*arr,size_t n){char path[1024];shielded_paths(chain_dir,path,sizeof(path),NULL,0,NULL,0);FILE*f=fopen(path,"wb");if(!f)return -1;fprintf(f,"# QRX shielded notes v3 PUBLIC: note_id|value_commitment|leaf_commitment|one_time_pub|ephemeral_pub|nonce|ciphertext_b64|tag|range_proof_hash|created_at\n");for(size_t i=0;i<n;i++)fprintf(f,"%s|%s|%s|%s|%s|%s|%s|%s|%s|%lld\n",arr[i].note_id,arr[i].value_commitment,arr[i].leaf_commitment,arr[i].one_time_pub,arr[i].ephemeral_pub,arr[i].nonce_hex,arr[i].ciphertext_b64,arr[i].tag_hex,arr[i].proof_hash,arr[i].created_at);fclose(f);return 0;}

static int shielded_nullifier_exists(const char*chain_dir,const char*leaf){char path[1024];shielded_paths(chain_dir,NULL,0,path,sizeof(path),NULL,0);FILE*f=fopen(path,"rb");if(!f)return 0;char line[512];int found=0;while(fgets(line,sizeof(line),f)){if(!strncmp(line,leaf,strlen(leaf))&&line[strlen(leaf)]=='|'){found=1;break;}}fclose(f);return found;}
static int shielded_add_nullifier(const char*chain_dir,const char*leaf,const char*nf){if(shielded_nullifier_exists(chain_dir,leaf))return -2;char path[1024];shielded_paths(chain_dir,NULL,0,path,sizeof(path),NULL,0);FILE*f=fopen(path,"ab");if(!f)return -1;fprintf(f,"%s|%s\n",leaf,nf);fclose(f);return 0;}

static void shielded_leaf_hash(const ShieldedNoteRecord*r,char out[129]){char*buf=malloc(strlen(r->value_commitment)+strlen(r->one_time_pub)+strlen(r->ephemeral_pub)+strlen(r->nonce_hex)+strlen(r->ciphertext_b64)+strlen(r->tag_hex)+256);if(!buf)die("oom");sprintf(buf,"QUB-SHIELDED-LEAF-v1|%s|%s|%s|%s|%s|%s",r->value_commitment,r->one_time_pub,r->ephemeral_pub,r->nonce_hex,r->ciphertext_b64,r->tag_hex);sha3_512_hex_local(buf,out);free(buf);}
static int shielded_merkle_append(const char*chain_dir,const char*leaf){char p[1024];shielded_merkle_path(chain_dir,p,sizeof(p));FILE*f=fopen(p,"ab");if(!f)return -1;fprintf(f,"%s\n",leaf);fclose(f);return 0;}
static int shielded_merkle_root(const char*chain_dir,char out[129]){char p[1024];shielded_merkle_path(chain_dir,p,sizeof(p));FILE*f=fopen(p,"rb");if(!f){sha3_512_hex_local("QUB-SHIELDED-EMPTY-MERKLE-v1",out);return 0;}size_t cap=16,n=0;char(*arr)[129]=malloc(cap*129);char line[256];while(fgets(line,sizeof(line),f)){line[strcspn(line,"\r\n")]=0;if(strlen(line)!=128)continue;if(n==cap){cap*=2;void*t=realloc(arr,cap*129);if(!t){free(arr);fclose(f);return -1;}arr=t;}snprintf(arr[n++],129,"%s",line);}fclose(f);if(!n){free(arr);sha3_512_hex_local("QUB-SHIELDED-EMPTY-MERKLE-v1",out);return 0;}while(n>1){size_t m=(n+1)/2;for(size_t i=0;i<m;i++){char buf[320];const char*a=arr[2*i];const char*b=2*i+1<n?arr[2*i+1]:arr[2*i];snprintf(buf,sizeof(buf),"QUB-SHIELDED-MERKLE-NODE-v1|%s|%s",a,b);sha3_512_hex_local(buf,arr[i]);}n=m;}snprintf(out,129,"%s",arr[0]);free(arr);return 0;}

static int shielded_note_decrypt(const ShieldedNoteRecord*r,const char*wallet_dir,ShieldedOwnedNote*out){memset(out,0,sizeof(*out));unsigned char view_priv[32],view_pub[32],eph[32],shared[32],key[32],nonce[12],tag[16];if(shielded_wallet_scan_keypair(wallet_dir,view_priv,view_pub)!=0)return 0;if(strlen(r->ephemeral_pub)!=64||hex_to_bytes_local(r->ephemeral_pub,eph,32)!=0||strlen(r->nonce_hex)!=24||hex_to_bytes_local(r->nonce_hex,nonce,12)!=0||strlen(r->tag_hex)!=32||hex_to_bytes_local(r->tag_hex,tag,16)!=0){OPENSSL_cleanse(view_priv,32);return 0;}if(stealth_x25519_derive(view_priv,eph,shared)!=0||shielded_aes_key(shared,key)!=0){OPENSSL_cleanse(view_priv,32);return 0;}size_t ctl=0;unsigned char*ct=base64_decode(r->ciphertext_b64,&ctl);if(!ct){OPENSSL_cleanse(view_priv,32);return 0;}char aad[512];snprintf(aad,sizeof(aad),"%s|%s|%s",r->value_commitment,r->one_time_pub,r->ephemeral_pub);unsigned char*pt=NULL;int ptl=0;if(shielded_aes_decrypt(key,nonce,aad,ct,(int)ctl,tag,&pt,&ptl)!=0){free(ct);OPENSSL_cleanse(view_priv,32);OPENSSL_cleanse(shared,32);OPENSSL_cleanse(key,32);return 0;}free(ct);long long value=0;char blind[65]={0},rho[65]={0},memo[256]={0};if(sscanf((char*)pt,"value=%lld|blind=%64[^|]|rho=%64[^|]|memo=%255[^\n]",&value,blind,rho,memo)<3){free(pt);OPENSSL_cleanse(view_priv,32);OPENSSL_cleanse(shared,32);OPENSSL_cleanse(key,32);return 0;}BIGNUM*blindbn=shielded_bn_from_hex(blind);char checkC[67],otpub[67];BIGNUM*otpriv=NULL;if(!blindbn||shielded_pedersen_commit(value,blindbn,checkC)!=0||strcmp(checkC,r->value_commitment)||shielded_one_time_priv(wallet_dir,shared,rho,&otpriv,otpub)!=0||strcmp(otpub,r->one_time_pub)){if(blindbn)BN_clear_free(blindbn);if(otpriv)BN_clear_free(otpriv);free(pt);OPENSSL_cleanse(view_priv,32);OPENSSL_cleanse(shared,32);OPENSSL_cleanse(key,32);return 0;}BN_clear_free(blindbn);out->value=value;snprintf(out->blind_hex,65,"%s",blind);snprintf(out->rho,65,"%s",rho);snprintf(out->memo,256,"%s",memo);out->one_time_priv=otpriv;free(pt);OPENSSL_cleanse(view_priv,32);OPENSSL_cleanse(shared,32);OPENSSL_cleanse(key,32);return 1;}

static int shielded_create_note(const char*chain_dir,const char*zaddr,long long value,const char*memo,ShieldedNoteRecord*out,ShieldedOwnedNote*owner_witness){if(value<0)return -1;char viewh[65],spend[67];if(shielded_split_address(zaddr,viewh,spend)!=0)return -1;unsigned char viewpub[32],epriv[32],epub[32],shared[32],key[32],nonce[12],tag[16];if(hex_to_bytes_local(viewh,viewpub,32)!=0||RAND_bytes(epriv,32)!=1||RAND_bytes(nonce,12)!=1)return -1;epriv[0]&=248;epriv[31]&=127;epriv[31]|=64;if(stealth_x25519_pub_from_priv(epriv,epub)!=0||stealth_x25519_derive(epriv,viewpub,shared)!=0||shielded_aes_key(shared,key)!=0)return -1;BIGNUM*n=NULL,*blind=NULL;EC_GROUP*g=NULL;if(stealth_secp_group_order(&g,&n)!=0)return -1;blind=BN_new();if(!blind||shielded_bn_random(n,blind)!=0){if(blind)BN_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}char blindh[65],rho[65],otpub[67],eph[65],nonceh[25],rnd[65];shielded_bn_hex64(blind,blindh);shielded_random_hex(rho,32);if(shielded_one_time_pub(spend,shared,rho,otpub)!=0){BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}memset(out,0,sizeof(*out));shielded_random_hex(rnd,16);snprintf(out->note_id,129,"zn3_%lld_%s",(long long)time(NULL),rnd);if(shielded_pedersen_commit(value,blind,out->value_commitment)!=0){BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}bytes_to_hex_local(epub,32,eph);snprintf(out->ephemeral_pub,65,"%s",eph);snprintf(out->one_time_pub,67,"%s",otpub);bytes_to_hex_local(nonce,12,nonceh);snprintf(out->nonce_hex,25,"%s",nonceh);char cleanmemo[256];snprintf(cleanmemo,sizeof(cleanmemo),"%s",memo?memo:"");clean_field(cleanmemo);char pt[1024];snprintf(pt,sizeof(pt),"value=%lld|blind=%s|rho=%s|memo=%s",value,blindh,rho,cleanmemo);char aad[512];snprintf(aad,sizeof(aad),"%s|%s|%s",out->value_commitment,out->one_time_pub,out->ephemeral_pub);unsigned char*ct=NULL;int ctl=0;if(shielded_aes_encrypt(key,nonce,aad,(unsigned char*)pt,(int)strlen(pt),&ct,&ctl,tag)!=0){BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}char*ctb64=base64_encode(ct,(size_t)ctl);free(ct);if(!ctb64){BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}snprintf(out->ciphertext_b64,sizeof(out->ciphertext_b64),"%s",ctb64);free(ctb64);bytes_to_hex_local(tag,16,out->tag_hex);shielded_leaf_hash(out,out->leaf_commitment);char pdir[1024],proofp[1300];shielded_proof_dir(chain_dir,pdir,sizeof(pdir));mkdir_p(pdir);snprintf(proofp,sizeof(proofp),"%s/%s.range",pdir,out->leaf_commitment);char context[512];snprintf(context,sizeof(context),"leaf=%s|C=%s",out->leaf_commitment,out->value_commitment);if(shielded_range_prove(value,blind,out->value_commitment,context,proofp)!=0||shielded_range_verify(out->value_commitment,context,proofp)!=0){unlink_qrx(proofp);BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}size_t psz=0;char*proof=read_file(proofp,&psz);if(!proof){BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);return -1;}sha3_512_hex_local(proof,out->proof_hash);free(proof);out->created_at=(long long)time(NULL);if(owner_witness){owner_witness->value=value;snprintf(owner_witness->blind_hex,65,"%s",blindh);snprintf(owner_witness->rho,65,"%s",rho);snprintf(owner_witness->memo,256,"%s",cleanmemo);owner_witness->one_time_priv=NULL;}BN_clear_free(blind);BN_free(n);EC_GROUP_free(g);OPENSSL_cleanse(epriv,32);OPENSSL_cleanse(shared,32);OPENSSL_cleanse(key,32);return 0;}

static int shielded_verify_public_note(const char*chain_dir,const ShieldedNoteRecord*r){char leaf[129];shielded_leaf_hash(r,leaf);if(strcmp(leaf,r->leaf_commitment))return -1;char pdir[1024],proofp[1300],context[512];shielded_proof_dir(chain_dir,pdir,sizeof(pdir));snprintf(proofp,sizeof(proofp),"%s/%s.range",pdir,r->leaf_commitment);snprintf(context,sizeof(context),"leaf=%s|C=%s",r->leaf_commitment,r->value_commitment);if(shielded_range_verify(r->value_commitment,context,proofp)!=0)return -1;char*proof=read_file(proofp,NULL);if(!proof)return -1;char h[129];sha3_512_hex_local(proof,h);free(proof);return strcmp(h,r->proof_hash)?-1:0;}

static void shielded_make_nullifier_v3(const ShieldedNoteRecord*r,const ShieldedOwnedNote*w,char out[129]){char privh[65];shielded_bn_hex64(w->one_time_priv,privh);char buf[1024];snprintf(buf,sizeof(buf),"QUB-SHIELDED-NULLIFIER-v3|%s|%s|%s",r->leaf_commitment,w->rho,privh);sha3_512_hex_local(buf,out);OPENSSL_cleanse(privh,65);}


static int shielded_hash_to_point(EC_GROUP*g,const char*domain,const char*input,EC_POINT*out,BN_CTX*ctx){BIGNUM*p=BN_new(),*a=BN_new(),*b=BN_new(),*x=BN_new();if(!p||!a||!b||!x)return -1;if(EC_GROUP_get_curve(g,p,a,b,ctx)!=1)goto fail;for(unsigned ctr=0;ctr<10000;ctr++){char buf[1024];snprintf(buf,sizeof(buf),"%s|%s|%u",domain,input?input:"",ctr);unsigned char h[32];EVP_Digest(buf,strlen(buf),h,NULL,EVP_sha3_256(),NULL);BN_bin2bn(h,32,x);BN_mod(x,x,p,ctx);if(EC_POINT_set_compressed_coordinates(g,out,x,ctr&1,ctx)==1&&!EC_POINT_is_at_infinity(g,out)){BN_free(p);BN_free(a);BN_free(b);BN_free(x);return 0;}}fail:if(p)BN_free(p);if(a)BN_free(a);if(b)BN_free(b);if(x)BN_free(x);return -1;}

static int shielded_key_image(const char*pub_hex,const BIGNUM*priv,char out[67]){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();EC_POINT*Hp=g?EC_POINT_new(g):NULL,*I=g?EC_POINT_new(g):NULL;int rc=-1;if(!g||!ctx||!Hp||!I||shielded_hash_to_point(g,"QUB-SHIELDED-KEYIMAGE-Hp-v1",pub_hex,Hp,ctx)!=0||EC_POINT_mul(g,I,NULL,Hp,priv,ctx)!=1)goto done;rc=shielded_point_hex(g,I,ctx,out);done:if(I)EC_POINT_free(I);if(Hp)EC_POINT_free(Hp);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static int shielded_note_spent_for_wallet(const char*chain_dir,const ShieldedNoteRecord*r,const ShieldedOwnedNote*w){char ki[67];if(!w||!w->one_time_priv||shielded_key_image(r->one_time_pub,w->one_time_priv,ki)!=0)return 1;return shielded_nullifier_exists(chain_dir,ki);}

static BIGNUM*shielded_ring_challenge(const BIGNUM*n,const char*message,const char*ring_digest,const char*pseudo,const char*L0,const char*R0,const char*L1){char*buf=malloc(strlen(message)+strlen(ring_digest)+strlen(pseudo)+strlen(L0)+strlen(R0)+strlen(L1)+128);if(!buf)return NULL;sprintf(buf,"QUB-RINGCT-MIXED-CHALLENGE-v1|%s|%s|%s|%s|%s|%s",message,ring_digest,pseudo,L0,R0,L1);unsigned char h[64];EVP_Digest(buf,strlen(buf),h,NULL,EVP_sha3_512(),NULL);free(buf);BIGNUM*c=BN_bin2bn(h,64,NULL);BN_CTX*ctx=BN_CTX_new();if(!c||!ctx||BN_mod(c,c,n,ctx)!=1){if(c)BN_free(c);if(ctx)BN_CTX_free(ctx);return NULL;}BN_CTX_free(ctx);return c;}

static void shielded_ring_digest(const ShieldedNoteRecord*arr,const size_t*ring,size_t ringn,char out[129]){size_t cap=64+ringn*160;char*buf=malloc(cap);if(!buf)die("oom");snprintf(buf,cap,"QUB-RINGCT-RING-v1");for(size_t i=0;i<ringn;i++){strncat(buf,"|",cap-strlen(buf)-1);strncat(buf,arr[ring[i]].leaf_commitment,cap-strlen(buf)-1);}sha3_512_hex_local(buf,out);free(buf);}

static int shielded_select_ring(const ShieldedNoteRecord*arr,size_t n,size_t real,size_t**ring_out,size_t*ringn_out,size_t*realpos_out){if(real>=n||n==0)return -1;size_t target=n<8?n:8;if(target>16)target=16;size_t*ring=calloc(target,sizeof(size_t));if(!ring)return -1;size_t c=0;ring[c++]=real;unsigned char rb[8];size_t guard=0;while(c<target&&guard++<10000){if(RAND_bytes(rb,sizeof(rb))!=1){free(ring);return -1;}unsigned long long x=0;for(int k=0;k<8;k++)x=(x<<8)|rb[k];size_t j=(size_t)(x%n);int dup=0;for(size_t k=0;k<c;k++)if(ring[k]==j){dup=1;break;}if(!dup)ring[c++]=j;}if(c!=target){free(ring);return -1;}/* Shuffle so the real member is not pinned to a fixed position. */for(size_t i=target-1;i>0;i--){if(RAND_bytes(rb,sizeof(rb))!=1){free(ring);return -1;}unsigned long long x=0;for(int k=0;k<8;k++)x=(x<<8)|rb[k];size_t j=(size_t)(x%(i+1));size_t t=ring[i];ring[i]=ring[j];ring[j]=t;}size_t rp=0;for(size_t i=0;i<c;i++)if(ring[i]==real){rp=i;break;}*ring_out=ring;*ringn_out=c;*realpos_out=rp;return 0;}

static int shielded_ring_prove(const ShieldedNoteRecord*arr,size_t n,size_t real_idx,const ShieldedOwnedNote*w,const BIGNUM*pseudo_blind,const char*pseudo_hex,const char*message,const char*proof_path,char key_image_out[67]){size_t*ring=NULL,ringn=0,realpos=0;if(shielded_select_ring(arr,n,real_idx,&ring,&ringn,&realpos)!=0)return -1;EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();BIGNUM*order=BN_new(),*realblind=shielded_bn_from_hex(w->blind_hex),*z=BN_new(),*alpha0=BN_new(),*alpha1=BN_new();EC_POINT*H=g?EC_POINT_new(g):NULL,*I=g?EC_POINT_new(g):NULL;int rc=-1;if(!g||!ctx||!order||!realblind||!z||!alpha0||!alpha1||!H||!I||EC_GROUP_get_order(g,order,ctx)!=1||shielded_pedersen_H(g,H,ctx)!=0||BN_mod_sub(z,realblind,pseudo_blind,order,ctx)!=1||shielded_bn_random(order,alpha0)!=0||shielded_bn_random(order,alpha1)!=0||shielded_key_image(arr[real_idx].one_time_pub,w->one_time_priv,key_image_out)!=0)goto done;I=shielded_point_from_hex(g,key_image_out,ctx);if(!I)goto done;BIGNUM**ss0=calloc(ringn,sizeof(BIGNUM*)),**ss1=calloc(ringn,sizeof(BIGNUM*)),**cc=calloc(ringn,sizeof(BIGNUM*));if(!ss0||!ss1||!cc)goto done2;for(size_t i=0;i<ringn;i++){ss0[i]=BN_new();ss1[i]=BN_new();cc[i]=BN_new();if(!ss0[i]||!ss1[i]||!cc[i])goto done3;}char ringdig[129];shielded_ring_digest(arr,ring,ringn,ringdig);
 /* Real alpha commitments seed c at next index */EC_POINT*Preal=shielded_point_from_hex(g,arr[real_idx].one_time_pub,ctx),*Hpreal=EC_POINT_new(g),*L0=EC_POINT_new(g),*R0=EC_POINT_new(g),*L1=EC_POINT_new(g);if(!Preal||!Hpreal||!L0||!R0||!L1||shielded_hash_to_point(g,"QUB-SHIELDED-KEYIMAGE-Hp-v1",arr[real_idx].one_time_pub,Hpreal,ctx)!=0||EC_POINT_mul(g,L0,alpha0,NULL,NULL,ctx)!=1||EC_POINT_mul(g,R0,NULL,Hpreal,alpha0,ctx)!=1||EC_POINT_mul(g,L1,NULL,H,alpha1,ctx)!=1)goto done4;char l0h[67],r0h[67],l1h[67];shielded_point_hex(g,L0,ctx,l0h);shielded_point_hex(g,R0,ctx,r0h);shielded_point_hex(g,L1,ctx,l1h);size_t next=(realpos+1)%ringn;BIGNUM*cnext=shielded_ring_challenge(order,message,ringdig,pseudo_hex,l0h,r0h,l1h);if(!cnext)goto done4;BN_copy(cc[next],cnext);BN_free(cnext);
 size_t j=next;while(j!=realpos){if(shielded_bn_random(order,ss0[j])!=0||shielded_bn_random(order,ss1[j])!=0)goto done4;size_t ridx=ring[j];EC_POINT*P=shielded_point_from_hex(g,arr[ridx].one_time_pub,ctx),*Hp=EC_POINT_new(g),*C=shielded_point_from_hex(g,arr[ridx].value_commitment,ctx),*Cp=shielded_point_from_hex(g,pseudo_hex,ctx),*Q=EC_POINT_new(g),*tmp=EC_POINT_new(g);if(!P||!Hp||!C||!Cp||!Q||!tmp||shielded_hash_to_point(g,"QUB-SHIELDED-KEYIMAGE-Hp-v1",arr[ridx].one_time_pub,Hp,ctx)!=0)goto loopfail;EC_POINT_invert(g,Cp,ctx);EC_POINT_add(g,Q,C,Cp,ctx);/* L0=sG+cP */EC_POINT_mul(g,L0,ss0[j],P,cc[j],ctx);/* R0=sHp+cI */EC_POINT_mul(g,R0,NULL,Hp,ss0[j],ctx);EC_POINT_mul(g,tmp,NULL,I,cc[j],ctx);EC_POINT_add(g,R0,R0,tmp,ctx);/* L1=sH+cQ */EC_POINT_mul(g,L1,NULL,H,ss1[j],ctx);EC_POINT_mul(g,tmp,NULL,Q,cc[j],ctx);EC_POINT_add(g,L1,L1,tmp,ctx);shielded_point_hex(g,L0,ctx,l0h);shielded_point_hex(g,R0,ctx,r0h);shielded_point_hex(g,L1,ctx,l1h);size_t nj=(j+1)%ringn;BIGNUM*cn=shielded_ring_challenge(order,message,ringdig,pseudo_hex,l0h,r0h,l1h);if(!cn)goto loopfail;BN_copy(cc[nj],cn);BN_free(cn);EC_POINT_free(P);EC_POINT_free(Hp);EC_POINT_free(C);EC_POINT_free(Cp);EC_POINT_free(Q);EC_POINT_free(tmp);j=nj;continue;loopfail:if(P)EC_POINT_free(P);if(Hp)EC_POINT_free(Hp);if(C)EC_POINT_free(C);if(Cp)EC_POINT_free(Cp);if(Q)EC_POINT_free(Q);if(tmp)EC_POINT_free(tmp);goto done4;}
 /* real responses */BIGNUM*tmpbn=BN_new();if(!tmpbn||BN_mod_mul(tmpbn,cc[realpos],w->one_time_priv,order,ctx)!=1||BN_mod_sub(ss0[realpos],alpha0,tmpbn,order,ctx)!=1||BN_mod_mul(tmpbn,cc[realpos],z,order,ctx)!=1||BN_mod_sub(ss1[realpos],alpha1,tmpbn,order,ctx)!=1){if(tmpbn)BN_free(tmpbn);goto done4;}BN_clear_free(tmpbn);
 FILE*f=fopen(proof_path,"wb");if(!f)goto done4;char c0h[65];shielded_bn_hex64(cc[0],c0h);fprintf(f,"QRX-RINGCT-MIXED-v1|ring=%zu|pseudo=%s|key_image=%s|c0=%s|message_hash=",ringn,pseudo_hex,key_image_out,c0h);char mh[129];sha3_512_hex_local(message,mh);fprintf(f,"%s\n",mh);for(size_t k=0;k<ringn;k++){char a[65],b[65];shielded_bn_hex64(ss0[k],a);shielded_bn_hex64(ss1[k],b);fprintf(f,"member|%s|%s|%s\n",arr[ring[k]].leaf_commitment,a,b);}fclose(f);rc=0;
done4:if(L1)EC_POINT_free(L1);if(R0)EC_POINT_free(R0);if(L0)EC_POINT_free(L0);if(Hpreal)EC_POINT_free(Hpreal);if(Preal)EC_POINT_free(Preal);
done3:if(ss0){for(size_t i=0;i<ringn;i++)if(ss0[i])BN_clear_free(ss0[i]);free(ss0);}if(ss1){for(size_t i=0;i<ringn;i++)if(ss1[i])BN_clear_free(ss1[i]);free(ss1);}if(cc){for(size_t i=0;i<ringn;i++)if(cc[i])BN_free(cc[i]);free(cc);}done2:;
done:free(ring);if(I)EC_POINT_free(I);if(H)EC_POINT_free(H);if(alpha1)BN_clear_free(alpha1);if(alpha0)BN_clear_free(alpha0);if(z)BN_clear_free(z);if(realblind)BN_clear_free(realblind);if(order)BN_free(order);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static long shielded_find_leaf(const ShieldedNoteRecord*arr,size_t n,const char*leaf){for(size_t i=0;i<n;i++)if(!strcmp(arr[i].leaf_commitment,leaf))return (long)i;return -1;}

static int shielded_ring_verify(const ShieldedNoteRecord*arr,size_t n,const char*message,const char*proof_path,char key_image_out[67],char pseudo_out[67]){FILE*f=fopen(proof_path,"rb");if(!f)return -1;char head[2048],mh_exp[129];if(!fgets(head,sizeof(head),f)){fclose(f);return -1;}head[strcspn(head,"\r\n")]=0;size_t ringn=0;char pseudo[67],ki[67],c0h[65],mh[129];if(sscanf(head,"QRX-RINGCT-MIXED-v1|ring=%zu|pseudo=%66[^|]|key_image=%66[^|]|c0=%64[^|]|message_hash=%128s",&ringn,pseudo,ki,c0h,mh)!=5||ringn==0||ringn>16){fclose(f);return -1;}sha3_512_hex_local(message,mh_exp);if(strcmp(mh,mh_exp)){fclose(f);return -1;}size_t*ring=calloc(ringn,sizeof(size_t));BIGNUM**s0=calloc(ringn,sizeof(BIGNUM*)),**s1=calloc(ringn,sizeof(BIGNUM*));if(!ring||!s0||!s1){fclose(f);free(ring);free(s0);free(s1);return -1;}char line[1024];for(size_t i=0;i<ringn;i++){if(!fgets(line,sizeof(line),f)){fclose(f);goto fail;}char leaf[129],a[65],b[65];if(sscanf(line,"member|%128[^|]|%64[^|]|%64s",leaf,a,b)!=3)goto fail;long idx=shielded_find_leaf(arr,n,leaf);if(idx<0)goto fail;ring[i]=(size_t)idx;s0[i]=shielded_bn_from_hex(a);s1[i]=shielded_bn_from_hex(b);if(!s0[i]||!s1[i])goto fail;}fclose(f);f=NULL;EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();BIGNUM*order=BN_new(),*c=shielded_bn_from_hex(c0h),*cstart=shielded_bn_from_hex(c0h);EC_POINT*H=g?EC_POINT_new(g):NULL,*I=g?shielded_point_from_hex(g,ki,ctx):NULL,*Cp=g?shielded_point_from_hex(g,pseudo,ctx):NULL;int rc=-1;if(!g||!ctx||!order||!c||!cstart||!H||!I||!Cp||EC_GROUP_get_order(g,order,ctx)!=1||shielded_pedersen_H(g,H,ctx)!=0)goto vdone;char ringdig[129];shielded_ring_digest(arr,ring,ringn,ringdig);for(size_t j=0;j<ringn;j++){size_t ridx=ring[j];EC_POINT*P=shielded_point_from_hex(g,arr[ridx].one_time_pub,ctx),*Hp=EC_POINT_new(g),*C=shielded_point_from_hex(g,arr[ridx].value_commitment,ctx),*Q=EC_POINT_new(g),*negCp=EC_POINT_dup(Cp,g),*L0=EC_POINT_new(g),*R0=EC_POINT_new(g),*L1=EC_POINT_new(g),*tmp=EC_POINT_new(g);if(!P||!Hp||!C||!Q||!negCp||!L0||!R0||!L1||!tmp||shielded_hash_to_point(g,"QUB-SHIELDED-KEYIMAGE-Hp-v1",arr[ridx].one_time_pub,Hp,ctx)!=0)goto vloopfail;EC_POINT_invert(g,negCp,ctx);EC_POINT_add(g,Q,C,negCp,ctx);EC_POINT_mul(g,L0,s0[j],P,c,ctx);EC_POINT_mul(g,R0,NULL,Hp,s0[j],ctx);EC_POINT_mul(g,tmp,NULL,I,c,ctx);EC_POINT_add(g,R0,R0,tmp,ctx);EC_POINT_mul(g,L1,NULL,H,s1[j],ctx);EC_POINT_mul(g,tmp,NULL,Q,c,ctx);EC_POINT_add(g,L1,L1,tmp,ctx);char l0[67],r0[67],l1[67];shielded_point_hex(g,L0,ctx,l0);shielded_point_hex(g,R0,ctx,r0);shielded_point_hex(g,L1,ctx,l1);BIGNUM*cn=shielded_ring_challenge(order,message,ringdig,pseudo,l0,r0,l1);if(!cn)goto vloopfail;BN_free(c);c=cn;EC_POINT_free(P);EC_POINT_free(Hp);EC_POINT_free(C);EC_POINT_free(Q);EC_POINT_free(negCp);EC_POINT_free(L0);EC_POINT_free(R0);EC_POINT_free(L1);EC_POINT_free(tmp);continue;vloopfail:if(P)EC_POINT_free(P);if(Hp)EC_POINT_free(Hp);if(C)EC_POINT_free(C);if(Q)EC_POINT_free(Q);if(negCp)EC_POINT_free(negCp);if(L0)EC_POINT_free(L0);if(R0)EC_POINT_free(R0);if(L1)EC_POINT_free(L1);if(tmp)EC_POINT_free(tmp);goto vdone;}if(BN_cmp(c,cstart)==0){snprintf(key_image_out,67,"%s",ki);snprintf(pseudo_out,67,"%s",pseudo);rc=0;}vdone:if(Cp)EC_POINT_free(Cp);if(I)EC_POINT_free(I);if(H)EC_POINT_free(H);if(c)BN_free(c);if(cstart)BN_free(cstart);if(order)BN_free(order);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);for(size_t i=0;i<ringn;i++){if(s0[i])BN_clear_free(s0[i]);if(s1[i])BN_clear_free(s1[i]);}free(s0);free(s1);free(ring);return rc;fail:if(f)fclose(f);for(size_t i=0;i<ringn;i++){if(s0[i])BN_clear_free(s0[i]);if(s1[i])BN_clear_free(s1[i]);}free(s0);free(s1);free(ring);return -1;}

static int shielded_global_balance_equation(const char**pseudo,size_t inc,const ShieldedNoteRecord*outs,size_t outc,long long public_amount){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();EC_POINT*D=g?EC_POINT_new(g):NULL,*P=NULL,*neg=NULL;int rc=-1;if(!g||!ctx||!D)goto done;EC_POINT_set_to_infinity(g,D);for(size_t i=0;i<inc;i++){P=shielded_point_from_hex(g,pseudo[i],ctx);if(!P)goto done;EC_POINT_add(g,D,D,P,ctx);EC_POINT_free(P);P=NULL;}for(size_t i=0;i<outc;i++){P=shielded_point_from_hex(g,outs[i].value_commitment,ctx);if(!P)goto done;neg=EC_POINT_dup(P,g);EC_POINT_invert(g,neg,ctx);EC_POINT_add(g,D,D,neg,ctx);EC_POINT_free(neg);neg=NULL;EC_POINT_free(P);P=NULL;}if(public_amount>0){BIGNUM*v=BN_new();EC_POINT*VG=EC_POINT_new(g);BN_set_word(v,(BN_ULONG)public_amount);EC_POINT_mul(g,VG,v,NULL,NULL,ctx);EC_POINT_invert(g,VG,ctx);EC_POINT_add(g,D,D,VG,ctx);EC_POINT_free(VG);BN_free(v);}rc=EC_POINT_is_at_infinity(g,D)?0:-1;done:if(neg)EC_POINT_free(neg);if(P)EC_POINT_free(P);if(D)EC_POINT_free(D);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static int shielded_address_cmd(const char*wallet_dir){char z[512];if(shielded_make_address_from_wallet(wallet_dir,z)!=0)die("wallet unlock required for shielded keys");printf("shielded_address=%s\nformat=zqub2_x25519_view_pub_secp256k1_spend_pub\nnotes=encrypted-aes256-gcm\ncommitments=secp256k1-pedersen\nrange_proof=63-bit-fiat-shamir-or-proof\n",z);return 0;}

static int shield_cmd(const char*chain_dir,const char*wallet_dir,long long amount,const char*zaddr){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;if(amount<=0)die("shield amount must be > 0");char selfz[512];if(!zaddr||strncmp(zaddr,"zqub2",5)){if(shielded_make_address_from_wallet(wallet_dir,selfz)!=0)die("wallet unlock required for shielded keys");zaddr=selfz;}char*from=wallet_address(wallet_dir);if(!from)die("wallet address unavailable");from[strcspn(from,"\r\n")]=0;char balpath[1024];state_paths(chain_dir,balpath,sizeof(balpath),NULL,0,NULL,0,NULL,0);long long bal=kv_get_ll_bin(balpath,from);if(bal<amount){free(from);die("insufficient transparent funds");}ShieldedNoteRecord r;if(shielded_create_note(chain_dir,zaddr,amount,"shield-from-transparent",&r,NULL)!=0){free(from);die("shielded note/proof creation failed");}if(shielded_verify_public_note(chain_dir,&r)!=0){free(from);die("shielded proof self-verification failed");}ShieldedNoteRecord*arr=NULL;size_t n=0;if(shielded_load_all(chain_dir,&arr,&n)!=0){free(from);die("shielded load failed");}ShieldedNoteRecord*t=realloc(arr,(n+1)*sizeof(*arr));if(!t){free(from);free(arr);die("oom");}arr=t;arr[n]=r;if(kv_set_ll_bin(balpath,from,bal-amount)!=0||shielded_save_all(chain_dir,arr,n+1)!=0||shielded_merkle_append(chain_dir,r.leaf_commitment)!=0){free(from);free(arr);die("shield state commit failed");}char root[129];shielded_merkle_root(chain_dir,root);journal_append(chain_dir,"shield_v3 from=%s public_amount=%lld leaf=%s root=%s",from,amount,r.leaf_commitment,root);printf("status=shielded-v3\nleaf_commitment=%s\nvalue_commitment=%s\nmerkle_root=%s\npublic_amount=%lld\n",r.leaf_commitment,r.value_commitment,root,amount);free(from);free(arr);return 0;}

static int shielded_balance_cmd(const char*chain_dir,const char*wallet_dir){ShieldedNoteRecord*arr=NULL;size_t n=0;if(shielded_load_all(chain_dir,&arr,&n)!=0)die("shielded load failed");long long total=0;for(size_t i=0;i<n;i++){if(shielded_verify_public_note(chain_dir,&arr[i])!=0)die("invalid shielded public note/range proof");ShieldedOwnedNote w;if(shielded_note_decrypt(&arr[i],wallet_dir,&w)){if(!shielded_note_spent_for_wallet(chain_dir,&arr[i],&w)&&w.value>0&&LLONG_MAX-total>=w.value)total+=w.value;if(w.one_time_priv)BN_clear_free(w.one_time_priv);}}printf("%lld\n",total);free(arr);return 0;}

static int shielded_collect_owned(const char*chain_dir,const char*wallet_dir,long long needed,ShieldedNoteRecord*arr,size_t n,size_t**idx_out,ShieldedOwnedNote**wit_out,size_t*cnt_out,long long*sum_out){size_t*idx=calloc(n,sizeof(size_t));ShieldedOwnedNote*w=calloc(n,sizeof(*w));if(!idx||!w){free(idx);free(w);return -1;}size_t c=0;long long sum=0;for(size_t i=0;i<n&&sum<needed;i++){if(shielded_verify_public_note(chain_dir,&arr[i])!=0){for(size_t j=0;j<c;j++)if(w[j].one_time_priv)BN_clear_free(w[j].one_time_priv);free(idx);free(w);return -1;}ShieldedOwnedNote tmp;if(shielded_note_decrypt(&arr[i],wallet_dir,&tmp)&&tmp.value>0){if(shielded_note_spent_for_wallet(chain_dir,&arr[i],&tmp)){if(tmp.one_time_priv)BN_clear_free(tmp.one_time_priv);continue;}idx[c]=i;w[c]=tmp;if(LLONG_MAX-sum<tmp.value){for(size_t j=0;j<=c;j++)if(w[j].one_time_priv)BN_clear_free(w[j].one_time_priv);free(idx);free(w);return -1;}sum+=tmp.value;c++;}}if(sum<needed){for(size_t j=0;j<c;j++)if(w[j].one_time_priv)BN_clear_free(w[j].one_time_priv);free(idx);free(w);return -2;}*idx_out=idx;*wit_out=w;*cnt_out=c;*sum_out=sum;return 0;}

static int shielded_conservation_proof(const char*context,const ShieldedNoteRecord*arr,const size_t*idx,const ShieldedOwnedNote*w,size_t inc,const ShieldedNoteRecord*outnotes,const ShieldedOwnedNote*outw,size_t outc,char A[67],char c[65],char s[65]){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();BIGNUM*n=BN_new(),*rdiff=BN_new(),*tmp=BN_new();EC_POINT*D=g?EC_POINT_new(g):NULL,*P=NULL,*neg=NULL;int rc=-1;if(!g||!ctx||!n||!rdiff||!tmp||!D||EC_GROUP_get_order(g,n,ctx)!=1)goto done;EC_POINT_set_to_infinity(g,D);BN_zero(rdiff);for(size_t i=0;i<inc;i++){P=shielded_point_from_hex(g,arr[idx[i]].value_commitment,ctx);BIGNUM*r=shielded_bn_from_hex(w[i].blind_hex);if(!P||!r)goto done;EC_POINT_add(g,D,D,P,ctx);BN_mod_add(rdiff,rdiff,r,n,ctx);EC_POINT_free(P);P=NULL;BN_clear_free(r);}for(size_t i=0;i<outc;i++){P=shielded_point_from_hex(g,outnotes[i].value_commitment,ctx);BIGNUM*r=shielded_bn_from_hex(outw[i].blind_hex);if(!P||!r)goto done;neg=EC_POINT_dup(P,g);EC_POINT_invert(g,neg,ctx);EC_POINT_add(g,D,D,neg,ctx);BN_mod_sub(rdiff,rdiff,r,n,ctx);EC_POINT_free(neg);neg=NULL;EC_POINT_free(P);P=NULL;BN_clear_free(r);}rc=shielded_schnorr_prove_H(D,rdiff,context,A,c,s);done:if(neg)EC_POINT_free(neg);if(P)EC_POINT_free(P);if(D)EC_POINT_free(D);if(tmp)BN_free(tmp);if(rdiff)BN_clear_free(rdiff);if(n)BN_free(n);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static int shielded_verify_conservation(const char*context,const ShieldedNoteRecord*arr,const size_t*idx,size_t inc,const ShieldedNoteRecord*outnotes,size_t outc,const char*A,const char*c,const char*s){EC_GROUP*g=EC_GROUP_new_by_curve_name(NID_secp256k1);BN_CTX*ctx=BN_CTX_new();EC_POINT*D=g?EC_POINT_new(g):NULL,*P=NULL,*neg=NULL;int rc=-1;if(!g||!ctx||!D)goto done;EC_POINT_set_to_infinity(g,D);for(size_t i=0;i<inc;i++){P=shielded_point_from_hex(g,arr[idx[i]].value_commitment,ctx);if(!P)goto done;EC_POINT_add(g,D,D,P,ctx);EC_POINT_free(P);P=NULL;}for(size_t i=0;i<outc;i++){P=shielded_point_from_hex(g,outnotes[i].value_commitment,ctx);if(!P)goto done;neg=EC_POINT_dup(P,g);EC_POINT_invert(g,neg,ctx);EC_POINT_add(g,D,D,neg,ctx);EC_POINT_free(neg);neg=NULL;EC_POINT_free(P);P=NULL;}rc=shielded_schnorr_verify_H(D,context,A,c,s);done:if(neg)EC_POINT_free(neg);if(P)EC_POINT_free(P);if(D)EC_POINT_free(D);if(ctx)BN_CTX_free(ctx);if(g)EC_GROUP_free(g);return rc;}

static int shielded_prepare_pseudo_blinds(const ShieldedOwnedNote *inputs,size_t inc,const ShieldedOwnedNote *outs,size_t outc,BIGNUM ***blinds_out,char ***commits_out){EC_GROUP*g=NULL;BIGNUM*n=NULL;BN_CTX*ctx=NULL;BIGNUM**blinds=NULL;char**commits=NULL;BIGNUM *sumout=NULL,*sumprev=NULL,*tmp=NULL;int rc=-1;if(inc==0||stealth_secp_group_order(&g,&n)!=0)goto done;ctx=BN_CTX_new();sumout=BN_new();sumprev=BN_new();tmp=BN_new();blinds=calloc(inc,sizeof(*blinds));commits=calloc(inc,sizeof(*commits));if(!ctx||!sumout||!sumprev||!tmp||!blinds||!commits)goto done;BN_zero(sumout);BN_zero(sumprev);for(size_t i=0;i<outc;i++){BIGNUM*r=shielded_bn_from_hex(outs[i].blind_hex);if(!r)goto done;if(BN_mod_add(sumout,sumout,r,n,ctx)!=1){BN_clear_free(r);goto done;}BN_clear_free(r);}for(size_t i=0;i<inc;i++){blinds[i]=BN_new();commits[i]=calloc(67,1);if(!blinds[i]||!commits[i])goto done;if(i+1<inc){if(shielded_bn_random(n,blinds[i])!=0||BN_mod_add(sumprev,sumprev,blinds[i],n,ctx)!=1)goto done;}else{if(BN_mod_sub(blinds[i],sumout,sumprev,n,ctx)!=1)goto done;}if(shielded_pedersen_commit(inputs[i].value,blinds[i],commits[i])!=0)goto done;}*blinds_out=blinds;*commits_out=commits;blinds=NULL;commits=NULL;rc=0;done:if(blinds){for(size_t i=0;i<inc;i++)if(blinds[i])BN_clear_free(blinds[i]);free(blinds);}if(commits){for(size_t i=0;i<inc;i++)free(commits[i]);free(commits);}if(tmp)BN_free(tmp);if(sumprev)BN_clear_free(sumprev);if(sumout)BN_clear_free(sumout);if(ctx)BN_CTX_free(ctx);if(n)BN_free(n);if(g)EC_GROUP_free(g);return rc;}

static void shielded_free_pseudo(size_t inc,BIGNUM **blinds,char **commits){if(blinds){for(size_t i=0;i<inc;i++)if(blinds[i])BN_clear_free(blinds[i]);free(blinds);}if(commits){for(size_t i=0;i<inc;i++)free(commits[i]);free(commits);}}

static int shielded_send_cmd(const char*chain_dir,const char*wallet_dir,const char*to,long long amount){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;if(amount<=0||!to||strncmp(to,"zqub2",5))die("invalid shielded-send");char selfz[512];if(shielded_make_address_from_wallet(wallet_dir,selfz)!=0)die("wallet unlock required");ShieldedNoteRecord*arr=NULL;size_t n=0;if(shielded_load_all(chain_dir,&arr,&n)!=0)die("shielded load failed");size_t*idx=NULL,cnt=0;ShieldedOwnedNote*w=NULL;long long sum=0;int cr=shielded_collect_owned(chain_dir,wallet_dir,amount,arr,n,&idx,&w,&cnt,&sum);if(cr==-2)die("insufficient shielded funds");if(cr!=0)die("shielded input selection failed");size_t outc=sum>amount?2:1;ShieldedNoteRecord outs[2];ShieldedOwnedNote outw[2];memset(outw,0,sizeof(outw));if(shielded_create_note(chain_dir,to,amount,"shielded-payment",&outs[0],&outw[0])!=0)die("payment output proof failed");if(outc==2&&shielded_create_note(chain_dir,selfz,sum-amount,"shielded-change",&outs[1],&outw[1])!=0)die("change output proof failed");for(size_t j=0;j<outc;j++)if(shielded_verify_public_note(chain_dir,&outs[j])!=0)die("range proof verify failed");
 char root[129];shielded_merkle_root(chain_dir,root);char context[2048];snprintf(context,sizeof(context),"QUB-RINGCT-SHIELDED-SPEND-v1|root=%s|out0=%s|out1=%s|outputs=%zu",root,outs[0].leaf_commitment,outc==2?outs[1].leaf_commitment:"-",outc);BIGNUM**pblinds=NULL;char**pcom=NULL;if(shielded_prepare_pseudo_blinds(w,cnt,outw,outc,&pblinds,&pcom)!=0)die("pseudo-output construction failed");const char**pc=(const char**)pcom;if(shielded_global_balance_equation(pc,cnt,outs,outc,0)!=0)die("RingCT global balance equation failed");
 char pdir[1024];shielded_proof_dir(chain_dir,pdir,sizeof(pdir));mkdir_p(pdir);char **proofpaths=calloc(cnt,sizeof(char*)),**keyimages=calloc(cnt,sizeof(char*)),**proofhashes=calloc(cnt,sizeof(char*));if(!proofpaths||!keyimages||!proofhashes)die("oom");for(size_t i=0;i<cnt;i++){proofpaths[i]=calloc(1400,1);keyimages[i]=calloc(67,1);proofhashes[i]=calloc(129,1);if(!proofpaths[i]||!keyimages[i]||!proofhashes[i])die("oom");char rid[65];shielded_random_hex(rid,16);snprintf(proofpaths[i],1400,"%s/ring_%s_%s.proof",pdir,outs[0].note_id,rid);if(shielded_ring_prove(arr,n,idx[i],&w[i],pblinds[i],pcom[i],context,proofpaths[i],keyimages[i])!=0)die("RingCT membership/ownership proof generation failed");char vk[67],vp[67];if(shielded_ring_verify(arr,n,context,proofpaths[i],vk,vp)!=0||strcmp(vk,keyimages[i])||strcmp(vp,pcom[i]))die("RingCT proof verification failed");if(shielded_nullifier_exists(chain_dir,keyimages[i]))die("RingCT key image already spent");char*pf=read_file(proofpaths[i],NULL);if(!pf)die("RingCT proof read failed");sha3_512_hex_local(pf,proofhashes[i]);free(pf);char finalp[1400];snprintf(finalp,sizeof(finalp),"%s/ring_%s.proof",pdir,proofhashes[i]);if(rename(proofpaths[i],finalp)!=0)die("RingCT proof finalization failed");snprintf(proofpaths[i],1400,"%s",finalp);}/* Commit nullifiers only after every proof is verified. */for(size_t i=0;i<cnt;i++)if(shielded_add_nullifier(chain_dir,keyimages[i],proofhashes[i])!=0)die("RingCT key-image commit failed");ShieldedNoteRecord*t=realloc(arr,(n+outc)*sizeof(*arr));if(!t)die("oom");arr=t;for(size_t j=0;j<outc;j++){arr[n+j]=outs[j];if(shielded_merkle_append(chain_dir,outs[j].leaf_commitment)!=0)die("merkle append failed");}if(shielded_save_all(chain_dir,arr,n+outc)!=0)die("shielded state save failed");char newroot[129];shielded_merkle_root(chain_dir,newroot);char sp[1024];shielded_spend_path(chain_dir,sp,sizeof(sp));FILE*f=fopen(sp,"ab");if(f){fprintf(f,"tx=ringct|root_before=%s|root_after=%s|inputs=%zu|outputs=%zu|amount_hidden=1|recipient_hidden=1",root,newroot,cnt,outc);for(size_t i=0;i<cnt;i++)fprintf(f,"|ki%zu=%s|pseudo%zu=%s|proof%zu=%s",i,keyimages[i],i,pcom[i],i,proofhashes[i]);fprintf(f,"|out0=%s|out1=%s\n",outs[0].leaf_commitment,outc==2?outs[1].leaf_commitment:"-");fclose(f);}journal_append(chain_dir,"shielded_ringct_send root_before=%s root_after=%s input_count=%zu output_count=%zu ring_size_policy=min8-max16 amount_hidden=true recipient_hidden=true real_input_hidden=true change_note=%s",root,newroot,cnt,outc,outc==2?"yes":"no");printf("status=shielded-ringct-v1\namount=hidden-on-chain\nrecipient=hidden-on-chain\nreal_inputs=hidden-in-rings\ninput_count=%zu\noutput_count=%zu\nchange_note=%s\nmerkle_root=%s\nrange_proofs=verified\nring_membership_proofs=verified\nkey_images=verified\nglobal_balance_equation=verified\n",cnt,outc,outc==2?"yes":"no",newroot);for(size_t i=0;i<cnt;i++){if(w[i].one_time_priv)BN_clear_free(w[i].one_time_priv);free(proofpaths[i]);free(keyimages[i]);free(proofhashes[i]);}free(proofpaths);free(keyimages);free(proofhashes);free(w);free(idx);shielded_free_pseudo(cnt,pblinds,pcom);free(arr);return 0;}

static int shielded_prepare_pseudo_blinds_unshield(const ShieldedOwnedNote*inputs,size_t inc,const ShieldedOwnedNote*change,size_t outc,BIGNUM***blinds_out,char***commits_out){ShieldedOwnedNote dummy[1];memset(dummy,0,sizeof(dummy));if(outc)dummy[0]=*change;return shielded_prepare_pseudo_blinds(inputs,inc,dummy,outc,blinds_out,commits_out);}

static int unshield_cmd(const char*chain_dir,const char*wallet_dir,const char*to,long long amount){if(privacy_legacy_mainnet_gate(chain_dir)!=0)return 1;if(amount<=0||!to||strncmp(to,"qrx",3))die("invalid unshield");char selfz[512];if(shielded_make_address_from_wallet(wallet_dir,selfz)!=0)die("wallet unlock required");ShieldedNoteRecord*arr=NULL;size_t n=0;if(shielded_load_all(chain_dir,&arr,&n)!=0)die("shielded load failed");size_t*idx=NULL,cnt=0;ShieldedOwnedNote*w=NULL;long long sum=0;int cr=shielded_collect_owned(chain_dir,wallet_dir,amount,arr,n,&idx,&w,&cnt,&sum);if(cr==-2)die("insufficient shielded funds");if(cr!=0)die("shielded input selection failed");size_t outc=sum>amount?1:0;ShieldedNoteRecord change;ShieldedOwnedNote cw;memset(&cw,0,sizeof(cw));if(outc&&shielded_create_note(chain_dir,selfz,sum-amount,"unshield-change",&change,&cw)!=0)die("change proof failed");if(outc&&shielded_verify_public_note(chain_dir,&change)!=0)die("change range proof verify failed");char root[129];shielded_merkle_root(chain_dir,root);char context[2048];snprintf(context,sizeof(context),"QUB-RINGCT-UNSHIELD-v1|root=%s|to=%s|public_amount=%lld|change=%s",root,to,amount,outc?change.leaf_commitment:"-");BIGNUM**pblinds=NULL;char**pcom=NULL;if(shielded_prepare_pseudo_blinds_unshield(w,cnt,&cw,outc,&pblinds,&pcom)!=0)die("pseudo-output construction failed");const char**pc=(const char**)pcom;ShieldedNoteRecord outs[1];if(outc)outs[0]=change;if(shielded_global_balance_equation(pc,cnt,outs,outc,amount)!=0)die("RingCT unshield balance equation failed");char pdir[1024];shielded_proof_dir(chain_dir,pdir,sizeof(pdir));mkdir_p(pdir);char**proofpaths=calloc(cnt,sizeof(char*)),**keyimages=calloc(cnt,sizeof(char*)),**proofhashes=calloc(cnt,sizeof(char*));if(!proofpaths||!keyimages||!proofhashes)die("oom");for(size_t i=0;i<cnt;i++){proofpaths[i]=calloc(1400,1);keyimages[i]=calloc(67,1);proofhashes[i]=calloc(129,1);char rid[65];shielded_random_hex(rid,16);snprintf(proofpaths[i],1400,"%s/unring_%lld_%s.proof",pdir,(long long)time(NULL),rid);if(shielded_ring_prove(arr,n,idx[i],&w[i],pblinds[i],pcom[i],context,proofpaths[i],keyimages[i])!=0)die("RingCT unshield proof generation failed");char vk[67],vp[67];if(shielded_ring_verify(arr,n,context,proofpaths[i],vk,vp)!=0||strcmp(vk,keyimages[i])||strcmp(vp,pcom[i]))die("RingCT unshield proof verify failed");if(shielded_nullifier_exists(chain_dir,keyimages[i]))die("RingCT key image already spent");char*pf=read_file(proofpaths[i],NULL);if(!pf)die("proof read failed");sha3_512_hex_local(pf,proofhashes[i]);free(pf);char finalp[1400];snprintf(finalp,sizeof(finalp),"%s/ring_%s.proof",pdir,proofhashes[i]);if(rename(proofpaths[i],finalp)!=0)die("RingCT proof finalization failed");snprintf(proofpaths[i],1400,"%s",finalp);}/* State commit: key images, transparent credit, optional shielded change. */for(size_t i=0;i<cnt;i++)if(shielded_add_nullifier(chain_dir,keyimages[i],proofhashes[i])!=0)die("key-image commit failed");char balpath[1024];state_paths(chain_dir,balpath,sizeof(balpath),NULL,0,NULL,0,NULL,0);long long tb=kv_get_ll_bin(balpath,to);if(LLONG_MAX-tb<amount||kv_set_ll_bin(balpath,to,tb+amount)!=0)die("transparent credit failed");if(outc){ShieldedNoteRecord*t=realloc(arr,(n+1)*sizeof(*arr));if(!t)die("oom");arr=t;arr[n]=change;if(shielded_merkle_append(chain_dir,change.leaf_commitment)!=0)die("merkle append failed");n++;}if(shielded_save_all(chain_dir,arr,n)!=0)die("shielded state save failed");char newroot[129];shielded_merkle_root(chain_dir,newroot);char sp[1024];shielded_spend_path(chain_dir,sp,sizeof(sp));FILE*f=fopen(sp,"ab");if(f){fprintf(f,"tx=unshield-ringct|root_before=%s|root_after=%s|public_to=%s|public_amount=%lld|inputs=%zu|change=%s",root,newroot,to,amount,cnt,outc?change.leaf_commitment:"-");for(size_t i=0;i<cnt;i++)fprintf(f,"|ki%zu=%s|pseudo%zu=%s|proof%zu=%s",i,keyimages[i],i,pcom[i],i,proofhashes[i]);fprintf(f,"\n");fclose(f);}journal_append(chain_dir,"unshield_ringct to=%s public_amount=%lld input_count=%zu real_inputs_hidden=true change=%s root=%s",to,amount,cnt,outc?"yes":"no",newroot);printf("status=unshielded-ringct-v1\npublic_amount=%lld\nto=%s\nreal_inputs=hidden-in-rings\nchange_note=%s\nmerkle_root=%s\nring_membership_proofs=verified\nkey_images=verified\nglobal_balance_equation=verified\n",amount,to,outc?"yes":"no",newroot);for(size_t i=0;i<cnt;i++){if(w[i].one_time_priv)BN_clear_free(w[i].one_time_priv);free(proofpaths[i]);free(keyimages[i]);free(proofhashes[i]);}free(proofpaths);free(keyimages);free(proofhashes);free(w);free(idx);shielded_free_pseudo(cnt,pblinds,pcom);free(arr);return 0;}

static int shielded_history_cmd(const char*chain_dir,const char*wallet_dir){ShieldedNoteRecord*arr=NULL;size_t n=0;if(shielded_load_all(chain_dir,&arr,&n)!=0)die("shielded load failed");for(size_t i=0;i<n;i++){ShieldedOwnedNote w;if(shielded_note_decrypt(&arr[i],wallet_dir,&w)){printf("%s value=%lld status=%s leaf=%s value_commitment=%s created_at=%lld memo=%s\n",arr[i].note_id,w.value,shielded_note_spent_for_wallet(chain_dir,&arr[i],&w)?"spent":"unspent",arr[i].leaf_commitment,arr[i].value_commitment,arr[i].created_at,w.memo);if(w.one_time_priv)BN_clear_free(w.one_time_priv);}}free(arr);return 0;}


#include "privacy/qrx_privacy_consensus.inc"

static int gov_vault_sign_v2_cmd(const char*chain,const char*v,const char*id,const char*proposal,const char*out){
    char ty[32],role[32];int hp=0;if(gov_vault_read_type(v,ty,sizeof(ty))||strcmp(ty,"OPERATIONAL"))die("signing is disabled for offline backup vaults");
    if(!gov_vault_index_has(v,id,role,sizeof(role),&hp)||strcmp(role,"ONLINE")||!hp)die("requested governance root is not an online signer in this vault");
    char kd[1024];snprintf(kd,sizeof(kd),"%s/keys/%s",v,id);return privacy_gov_sign_v2_cmd(chain,proposal,kd,out);
}


static long long history_timestamp(const char *line) {
    const char *p = strstr(line, "journal_timestamp=");
    if (!p) p = strstr(line, "timestamp=");
    if (!p) return 0;
    p = strchr(p, '='); return p ? atoll(p + 1) : 0;
}

static int history_cmd(const char *chain_dir, const char *address, size_t limit, long long from_ts, long long to_ts) {
    char journal[1024]; state_paths(chain_dir, NULL, 0, NULL, 0, NULL, 0, journal, sizeof(journal));
    char *txt = read_file(journal, NULL); if (!txt) die("missing journal");
    size_t lines_cap = 256, lines_n = 0; char **lines = calloc(lines_cap, sizeof(char*)); if (!lines) die("oom");
    char *save = NULL; char *line = strtok_r(txt, "\n", &save);
    while (line) {
        int match = 1;
        if (address && *address) match = strstr(line, address) != NULL;
        if (match && (from_ts > 0 || to_ts > 0)) {
            long long ts = history_timestamp(line);
            if (ts <= 0) { free(lines); free(txt); die("history row without timestamp cannot be date-filtered; use an all-time export for legacy journal rows"); }
            if ((from_ts > 0 && ts < from_ts) || (to_ts > 0 && ts >= to_ts)) match = 0;
        }
        if (match) {
            if (lines_n == lines_cap) {
                lines_cap *= 2;
                char **tmp = realloc(lines, lines_cap * sizeof(char*));
                if (!tmp) die("oom");
                lines = tmp;
            }
            lines[lines_n++] = line;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    if (limit == 0 || limit > lines_n) limit = lines_n;
    size_t start = lines_n - limit;
    for (size_t i = start; i < lines_n; ++i) puts(lines[i]);
    free(lines); free(txt); return 0;
}

static int list_peers_cmd(const char *node_dir) {
    char p1[1024], p2[1024], conf[1024];
    snprintf(p1, sizeof(p1), "%s/peers.txt", node_dir);
    snprintf(p2, sizeof(p2), "%s/known_peers.txt", node_dir);
    char *a = read_file(p1, NULL), *b = read_file(p2, NULL);
    if (a) { printf("[peers]\n%s", a); if (strlen(a) && a[strlen(a)-1] != '\n') puts(""); }
    if (b) { printf("[known]\n%s", b); if (strlen(b) && b[strlen(b)-1] != '\n') puts(""); }
    snprintf(conf, sizeof(conf), "%s/node.conf", node_dir);
    char *cfg=read_file(conf,NULL), *host=cfg?cfg_get(cfg,"host"):NULL, *port=cfg?cfg_get(cfg,"port"):NULL;
    if(host&&port)printf("[listener]\n%s:%s\n",host,port);
    free(cfg);free(host);free(port);
    if (!a && !b) puts("no peers");
    free(a); free(b); return 0;
}

static int banscore_cmd(const char *node_dir, const char *peer) {
    if (!peer || !*peer) return peer_status_cmd(node_dir);
    printf("peer=%s\nban=%lld\nrep=%lld\nlast_seen=%lld\n", peer, peer_ban_score(node_dir, peer), peer_rep_score(node_dir, peer), peer_last_seen(node_dir, peer));
    return 0;
}

static int ban_peer_cmd(const char *node_dir, const char *peer, long long points) {
    if (points <= 0) points = BAN_THRESHOLD;
    peer_add_score(node_dir, peer, points);
    printf("peer=%s\nban=%lld\n", peer, peer_ban_score(node_dir, peer));
    return 0;
}

static int unban_peer_cmd(const char *node_dir, const char *peer) {
    char db[1024], key[320];
    snprintf(db, sizeof(db), "%s/peer_state.db", node_dir);
    key_from_ip(key, sizeof(key), peer, "ban");
    db_set_ll(db, key, 0);
    printf("peer=%s\nban=0\n", peer);
    return 0;
}

static int send_cmd_from(const char *wallet_dir, const char *chain_dir, const char *source_address, const char *to, const char *amount, const char *memo, const char *node_dir) {
    char tmp[1024]; snprintf(tmp, sizeof(tmp), "%s/.send-%ld.qrxtx", wallet_dir, (long)time(NULL));
    if (sign_cmd_from(wallet_dir, chain_dir, source_address, to, amount, memo, tmp) != 0) return 1;
    int rc = 0;
    if (node_dir && *node_dir) rc = sendtx_cmd(node_dir, tmp);
    else rc = applytx_cmd(chain_dir, tmp);
    unlink_qrx(tmp);
    return rc;
}

static int send_cmd(const char *wallet_dir, const char *chain_dir, const char *to, const char *amount, const char *memo, const char *node_dir) {
    return send_cmd_from(wallet_dir,chain_dir,NULL,to,amount,memo,node_dir);
}

static int slash_cmd(const char *chain_dir, const char *validator, long long amount, const char *reason, long long penalty_points) {
    if (amount <= 0) die("slash amount must be > 0");
    if (penalty_points <= 0) penalty_points = 10;
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], penalties[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), penalties, sizeof(penalties));
    long long self = kv_get_ll_bin(stakes, validator);
    long long delegated_total = kv_get_ll_bin(totals, validator);
    long long total = self + delegated_total;
    if (total <= 0) die("validator has no active power");
    long long slash_amt = amount > total ? total : amount;
    long long slash_self = (self > 0) ? (slash_amt * self) / total : 0;
    if (slash_self > self) slash_self = self;
    long long slash_deleg = slash_amt - slash_self;
    if (slash_self > 0 && kv_set_ll_bin(stakes, validator, self - slash_self) != 0) die("slash self failed");

    StateKVRecord *arr = NULL; size_t n = 0;
    if (slash_deleg > 0 && kv_load(delegations, &arr, &n) != 0) die("failed to load delegations");
    long long removed_from_delegations = 0;
    if (slash_deleg > 0 && arr) {
        char suffix[512]; snprintf(suffix, sizeof(suffix), "->%s", validator);
        size_t slen = strlen(suffix);
        long long running = 0;
        for (size_t i=0;i<n;i++) {
            size_t klen = strlen(arr[i].key);
            if (klen <= slen || strcmp(arr[i].key + klen - slen, suffix) != 0 || arr[i].value <= 0) continue;
            long long part = (slash_deleg * arr[i].value) / delegated_total;
            if (part > arr[i].value) part = arr[i].value;
            if (part > 0) { arr[i].value -= part; running += part; }
        }
        long long remainder = slash_deleg - running;
        if (remainder > 0) {
            for (size_t i=0;i<n && remainder>0;i++) {
                size_t klen = strlen(arr[i].key);
                if (klen <= slen || strcmp(arr[i].key + klen - slen, suffix) != 0 || arr[i].value <= 0) continue;
                long long take = remainder < arr[i].value ? remainder : arr[i].value;
                arr[i].value -= take; running += take; remainder -= take;
            }
        }
        for (size_t i=0;i<n;i++) if (kv_set_ll_bin(delegations, arr[i].key, arr[i].value) != 0) die("delegation slash update failed");
        removed_from_delegations = running;
    }
    if (kv_set_ll_bin(totals, validator, delegated_total - removed_from_delegations) != 0) die("delegated total slash update failed");

    long long new_penalty = kv_get_ll_bin(penalties, validator) + penalty_points;
    if (kv_set_ll_bin(penalties, validator, new_penalty) != 0) die("penalty update failed");

    char *threshold_s = chain_cfg_value(chain_dir, "slash_penalty_threshold");
    char *redistribute_s = chain_cfg_value(chain_dir, "slash_redistribute_bps");
    long long threshold = threshold_s ? atoll(threshold_s) : 20;
    long long redistribute_bps = redistribute_s ? atoll(redistribute_s) : 5000;
    if (redistribute_bps < 0) redistribute_bps = 0;
    if (redistribute_bps > 10000) redistribute_bps = 10000;
    free(threshold_s); free(redistribute_s);

    long long redistributed = 0;
    if (new_penalty >= threshold && redistribute_bps > 0) {
        long long pot = (slash_amt * redistribute_bps) / 10000;
        char users[512][385]; int user_count = collect_known_users(chain_dir, users, 512);
        int eligible = 0; for (int i=0;i<user_count;i++) if (strcmp(users[i], validator) != 0) eligible++;
        if (pot > 0 && eligible > 0) {
            long long each = pot / eligible;
            long long rem = pot % eligible;
            for (int i=0;i<user_count;i++) {
                if (strcmp(users[i], validator) == 0) continue;
                long long credit = each + (rem > 0 ? 1 : 0);
                if (credit > 0) {
                    if (adjust_balance(chain_dir, users[i], credit) != 0) die("redistribution failed");
                    redistributed += credit;
                    if (rem > 0) rem--;
                }
            }
        }
    }
    long long burned = slash_amt - redistributed;
    note_redistributed(chain_dir, redistributed);
    burn_supply(chain_dir, burned);
    journal_append(chain_dir, "slash validator=%s amount=%lld self_slashed=%lld delegated_slashed=%lld reason=%s penalty_points=%lld penalty_total=%lld redistributed=%lld burned=%lld", validator, slash_amt, slash_self, removed_from_delegations, reason ? reason : "unspecified", penalty_points, new_penalty, redistributed, burned);
    printf("validator=%s\nslashed=%lld\nself_slashed=%lld\ndelegated_slashed=%lld\npenalty_total=%lld\nredistributed=%lld\nburned=%lld\nremaining_power=%lld\n", validator, slash_amt, slash_self, removed_from_delegations, new_penalty, redistributed, burned, validator_power_total(chain_dir, validator));
    free(arr);
    return 0;
}

static int stake_cmd(const char *chain_dir, const char *wallet_dir, long long amount) {
    die("SECURITY: legacy direct staking mutation disabled in Phase 7.2.12; create, sign and broadcast the consensus-native staking transaction instead");
    if (amount <= 0) die("amount must be > 0");
    char *addr = wallet_address(wallet_dir); if (!addr) die("wallet address failed");
    char bal[1024], nonce[1024], appl[1024], journal[1024], stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    long long cur = kv_get_ll_bin(bal, addr);
    if (cur < amount) die("insufficient balance");
    if (kv_set_ll_bin(bal, addr, cur - amount) != 0) die("balance update failed");
    long long s = kv_get_ll_bin(stakes, addr);
    if (kv_set_ll_bin(stakes, addr, s + amount) != 0) die("stake update failed");
    journal_append(chain_dir, "stake addr=%s amount=%lld total=%lld", addr, amount, s + amount);
    printf("address=%s\nself_stake=%lld\nvalidator_power=%lld\n", addr, s + amount, validator_power_total(chain_dir, addr));
    free(addr); return 0;
}

static int unstake_cmd(const char *chain_dir, const char *wallet_dir, long long amount, long long unbond_secs) {
    die("SECURITY: legacy direct staking mutation disabled in Phase 7.2.12; create, sign and broadcast the consensus-native staking transaction instead");
    if (amount <= 0) die("amount must be > 0");
    if (unbond_secs <= 0) unbond_secs = 86400;
    char *addr = wallet_address(wallet_dir); if (!addr) die("wallet address failed");
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    long long s = kv_get_ll_bin(stakes, addr);
    if (s < amount) die("insufficient self stake");
    {
        long long principal = 0, lockh = 0;
        long long height = current_height_from_chain(chain_dir);
        if (bootstrap_validator_lock_info(chain_dir, addr, &principal, &lockh) && height < lockh) {
            long long freely_unstakeable = s > principal ? s - principal : 0;
            if (amount > freely_unstakeable) {
                free(addr);
                die("bootstrap principal remains locked until height %lld; currently %lld self-stake is locked and only %lld may be unstaked", lockh, principal < s ? principal : s, freely_unstakeable);
            }
        }
    }
    if (kv_set_ll_bin(stakes, addr, s - amount) != 0) die("stake update failed");
    long long pending = kv_get_ll_bin(ub, addr);
    kv_set_ll_bin(ub, addr, pending + amount);
    kv_set_ll_bin(ube, addr, (long long)time(NULL) + unbond_secs);
    journal_append(chain_dir, "unstake addr=%s amount=%lld remaining=%lld pending=%lld eta=%lld", addr, amount, s - amount, pending + amount, (long long)time(NULL) + unbond_secs);
    printf("address=%s\npending_unbond=%lld\nclaim_after=%lld\n", addr, pending + amount, kv_get_ll_bin(ube, addr));
    free(addr); return 0;
}

static int claim_unbonded_cmd(const char *chain_dir, const char *wallet_dir) {
    die("SECURITY: legacy direct staking mutation disabled in Phase 7.2.12; create, sign and broadcast the consensus-native staking transaction instead");
    char *addr = wallet_address(wallet_dir); if (!addr) die("wallet address failed");
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    long long pending = kv_get_ll_bin(ub, addr);
    long long eta = kv_get_ll_bin(ube, addr);
    long long now = (long long)time(NULL);
    if (pending <= 0) die("nothing to claim");
    if (eta > now) die("unbonding not matured yet");
    if (adjust_balance(chain_dir, addr, pending) != 0) die("balance update failed");
    kv_set_ll_bin(ub, addr, 0); kv_set_ll_bin(ube, addr, 0);
    journal_append(chain_dir, "claim_unbonded addr=%s amount=%lld", addr, pending);
    printf("address=%s\nclaimed=%lld\n", addr, pending);
    free(addr); return 0;
}

static void delegation_key(char *out, size_t outsz, const char *delegator, const char *validator) {
    snprintf(out, outsz, "%s->%s", delegator, validator);
}

static int delegate_cmd(const char *chain_dir, const char *wallet_dir, const char *validator, long long amount) {
    die("SECURITY: legacy direct staking mutation disabled in Phase 7.2.12; create, sign and broadcast the consensus-native staking transaction instead");
    if (amount <= 0) die("amount must be > 0");
    char *delegator = wallet_address(wallet_dir); if (!delegator) die("wallet address failed");
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], key[300];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    if (!validator_has_min_self_stake_at(chain_dir, validator, current_height_from_chain(chain_dir))) die("validator self stake below minimum");
    if (validator_is_tombstoned(chain_dir, validator) || validator_is_jailed_now(chain_dir, validator)) die("validator jailed or tombstoned");
    if (adjust_balance(chain_dir, delegator, -amount) != 0) die("insufficient balance");
    delegation_key(key, sizeof(key), delegator, validator);
    long long cur = kv_get_ll_bin(delegations, key);
    long long tot = kv_get_ll_bin(totals, validator);
    kv_set_ll_bin(delegations, key, cur + amount);
    kv_set_ll_bin(totals, validator, tot + amount);
    journal_append(chain_dir, "delegate delegator=%s validator=%s amount=%lld total=%lld", delegator, validator, amount, cur + amount);
    printf("delegator=%s\nvalidator=%s\ndelegated=%lld\nvalidator_power=%lld\n", delegator, validator, cur + amount, validator_power_total(chain_dir, validator));
    free(delegator); return 0;
}

static int undelegate_cmd(const char *chain_dir, const char *wallet_dir, const char *validator, long long amount, long long unbond_secs) {
    die("SECURITY: legacy direct staking mutation disabled in Phase 7.2.12; create, sign and broadcast the consensus-native staking transaction instead");
    if (amount <= 0) die("amount must be > 0");
    if (unbond_secs <= 0) unbond_secs = 86400;
    char *delegator = wallet_address(wallet_dir); if (!delegator) die("wallet address failed");
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], key[300];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    delegation_key(key, sizeof(key), delegator, validator);
    long long cur = kv_get_ll_bin(delegations, key);
    if (cur < amount) die("insufficient delegated amount");
    kv_set_ll_bin(delegations, key, cur - amount);
    long long tot = kv_get_ll_bin(totals, validator);
    kv_set_ll_bin(totals, validator, tot - amount);
    long long pending = kv_get_ll_bin(ud, key);
    kv_set_ll_bin(ud, key, pending + amount);
    kv_set_ll_bin(ude, key, (long long)time(NULL) + unbond_secs);
    journal_append(chain_dir, "undelegate delegator=%s validator=%s amount=%lld remaining=%lld pending=%lld", delegator, validator, amount, cur - amount, pending + amount);
    printf("delegator=%s\nvalidator=%s\npending_undelegation=%lld\nclaim_after=%lld\n", delegator, validator, pending + amount, kv_get_ll_bin(ude, key));
    free(delegator); return 0;
}

static int claim_undelegated_cmd(const char *chain_dir, const char *wallet_dir, const char *validator) {
    die("SECURITY: legacy direct staking mutation disabled in Phase 7.2.12; create, sign and broadcast the consensus-native staking transaction instead");
    char *delegator = wallet_address(wallet_dir); if (!delegator) die("wallet address failed");
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], key[300];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    delegation_key(key, sizeof(key), delegator, validator);
    long long pending = kv_get_ll_bin(ud, key);
    long long eta = kv_get_ll_bin(ude, key);
    long long now = (long long)time(NULL);
    if (pending <= 0) die("nothing to claim");
    if (eta > now) die("undelegation not matured yet");
    if (adjust_balance(chain_dir, delegator, pending) != 0) die("balance update failed");
    kv_set_ll_bin(ud, key, 0); kv_set_ll_bin(ude, key, 0);
    journal_append(chain_dir, "claim_undelegated delegator=%s validator=%s amount=%lld", delegator, validator, pending);
    printf("delegator=%s\nvalidator=%s\nclaimed=%lld\n", delegator, validator, pending);
    free(delegator); return 0;
}

static int cmp_validator_power_desc(const void *a, const void *b) {
    const ValidatorPower *x = (const ValidatorPower*)a, *y = (const ValidatorPower*)b;
    if (x->power < y->power) return 1;
    if (x->power > y->power) return -1;
    return strcmp(x->validator, y->validator);
}

static int validator_set_cmd(const char *chain_dir) {
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    StateKVRecord *arr = NULL; size_t n = 0;
    if (kv_load(stakes, &arr, &n) != 0) die("failed to load stakes");
    ValidatorPower *vals = calloc(n ? n : 1, sizeof(ValidatorPower)); if (!vals) die("oom");
    size_t m = 0;
    for (size_t i=0;i<n;i++) {
        if (arr[i].value <= 0) continue;
        snprintf(vals[m].validator, sizeof(vals[m].validator), "%s", arr[i].key);
        vals[m].self_stake = arr[i].value;
        vals[m].delegated = kv_get_ll_bin(totals, arr[i].key);
        vals[m].power = vals[m].self_stake + vals[m].delegated;
        m++;
    }
    qsort(vals, m, sizeof(ValidatorPower), cmp_validator_power_desc);
    for (size_t i=0;i<m;i++) printf("%zu validator=%s self=%lld delegated=%lld power=%lld\n", i+1, vals[i].validator, vals[i].self_stake, vals[i].delegated, vals[i].power);
    if (m == 0) puts("no_validators=1");
    free(vals); free(arr); return 0;
}

static int staking_status_cmd(const char *chain_dir, const char *address) {
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    if (address && *address) {
        char b[1024], npath[1024], apath[1024], jpath[1024];
        state_paths(chain_dir, b, sizeof(b), npath, sizeof(npath), apath, sizeof(apath), jpath, sizeof(jpath));
        printf("address=%s\n", address);
        printf("balance=%lld\n", qrx_balance_get_authoritative(chain_dir,address));
        char skey[1024]; long long self_auth=0,deleg_auth=0; snprintf(skey,sizeof(skey),"staking:self:%s",address); if(!staking_db_ll_found(chain_dir,skey,&self_auth))self_auth=kv_get_ll_bin(stakes,address);
        snprintf(skey,sizeof(skey),"staking:delegated_total:%s",address); if(!staking_db_ll_found(chain_dir,skey,&deleg_auth))deleg_auth=kv_get_ll_bin(totals,address);
        printf("self_stake=%lld\n", self_auth);
        printf("delegated_to_me=%lld\n", deleg_auth);
        printf("validator_power=%lld\n", validator_power_total(chain_dir, address));
        snprintf(skey,sizeof(skey),"staking:unbonding:%s",address); long long ub_auth=staking_db_ll(chain_dir,skey,kv_get_ll_bin(ub,address));
        snprintf(skey,sizeof(skey),"staking:unbonding_maturity:%s",address); long long ue_auth=staking_db_ll(chain_dir,skey,kv_get_ll_bin(ube,address));
        printf("pending_unbond=%lld\n", ub_auth);
        printf("pending_unbond_eta=%lld\n", ue_auth);
        {
            long long principal=0, lockh=0, height=current_height_from_chain(chain_dir);
            int is_bootstrap=bootstrap_validator_lock_info(chain_dir,address,&principal,&lockh);
            long long self=self_auth;
            long long locked=(is_bootstrap && height<lockh)?(self<principal?self:principal):0;
            printf("is_bootstrap=%d\n",is_bootstrap?1:0);
            printf("bootstrap_principal=%lld\n",principal);
            printf("bootstrap_lock_until_height=%lld\n",lockh);
            printf("bootstrap_lock_active=%d\n",is_bootstrap&&height<lockh?1:0);
            printf("bootstrap_liveness_slash_grace=%d\n",bootstrap_liveness_grace_active(chain_dir,address,height)?1:0);
            printf("double_sign_slashing_active=1\n");
            printf("locked_self_stake=%lld\n",locked);
            printf("freely_unstakeable_self_stake=%lld\n",self>locked?self-locked:0);
        }
        StateKVRecord *arr=NULL; size_t n=0; if (kv_load(delegations, &arr, &n)==0) {
            size_t alen = strlen(address);
            for (size_t i=0;i<n;i++) {
                if (strncmp(arr[i].key, address, alen) == 0 && strncmp(arr[i].key + alen, "->", 2) == 0) printf("delegation %s amount=%lld\n", arr[i].key, arr[i].value);
            }
            free(arr);
        }
        return 0;
    }
    return validator_set_cmd(chain_dir);
}

static int reward_epoch_distribute_cmd(const char *chain_dir, long long reward, long long mint_amount, long long dev_share, long long commission_bps) {
    if (reward <= 0) die("reward must be > 0");
    if (dev_share < 0) die("dev share must be >= 0");
    if (mint_amount > 0 && mint_with_cap(chain_dir, "rewards_minted", mint_amount) != 0) die("max supply exceeded");
    if (commission_bps < 0 || commission_bps > 10000) die("commission bps must be between 0 and 10000");
    if (dev_share > 0) {
        char *dev = chain_cfg_value(chain_dir, "dev_address");
        if (!dev || !*dev) { if (dev) free(dev); die("dev_address not configured"); }
        if (adjust_balance(chain_dir, dev, dev_share) != 0) { free(dev); die("development fund reward credit failed"); }
        journal_append(chain_dir, "development_fund address=%s reward=%lld policy=subsidy_only", dev, dev_share);
        printf("development_fund=%s reward=%lld\n", dev, dev_share);
        free(dev);
    }
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    StateKVRecord *stakes_arr = NULL; size_t stakes_n = 0; if (kv_load(stakes, &stakes_arr, &stakes_n) != 0) die("failed to load stakes");
    StateKVRecord *deleg_arr = NULL; size_t deleg_n = 0; if (kv_load(delegations, &deleg_arr, &deleg_n) != 0) { free(stakes_arr); die("failed to load delegations"); }
    long long total_power = 0;
    for (size_t i=0;i<stakes_n;i++) if (stakes_arr[i].value > 0) total_power += stakes_arr[i].value + kv_get_ll_bin(totals, stakes_arr[i].key);
    if (total_power <= 0) die("no validator power");
    for (size_t i=0;i<stakes_n;i++) {
        const char *validator = stakes_arr[i].key;
        long long self = stakes_arr[i].value;
        if (self <= 0) continue;
        long long delegated_total = kv_get_ll_bin(totals, validator);
        long long power = self + delegated_total;
        if (power <= 0) continue;
        long long share = (reward * power) / total_power;
        if (share <= 0) continue;
        long long commission = (share * commission_bps) / 10000;
        long long remaining = share - commission;
        long long validator_self_share = (remaining * self) / power;
        long long validator_credit = commission + validator_self_share;
        if (validator_credit > 0 && adjust_balance(chain_dir, validator, validator_credit) != 0) die("validator reward credit failed");
        long long distributed_to_delegators = 0;
        if (delegated_total > 0) {
            char suffix[512]; snprintf(suffix, sizeof(suffix), "->%s", validator);
            size_t slen = strlen(suffix);
            for (size_t j=0;j<deleg_n;j++) {
                size_t klen = strlen(deleg_arr[j].key);
                if (klen <= slen || strcmp(deleg_arr[j].key + klen - slen, suffix) != 0 || deleg_arr[j].value <= 0) continue;
                long long dshare = (remaining * deleg_arr[j].value) / power;
                if (dshare <= 0) continue;
                char delegator[200];
                const char *arrow = strstr(deleg_arr[j].key, "->");
                size_t dlen = arrow ? (size_t)(arrow - deleg_arr[j].key) : 0;
                if (dlen >= sizeof(delegator)) dlen = sizeof(delegator)-1;
                memcpy(delegator, deleg_arr[j].key, dlen); delegator[dlen] = 0;
                if (adjust_balance(chain_dir, delegator, dshare) != 0) die("delegator reward credit failed");
                distributed_to_delegators += dshare;
                journal_append(chain_dir, "reward_epoch delegator=%s validator=%s reward=%lld delegated=%lld total_power=%lld", delegator, validator, dshare, deleg_arr[j].value, total_power);
            }
        }
        long long dust = share - validator_credit - distributed_to_delegators;
        if (dust > 0) {
            if (adjust_balance(chain_dir, validator, dust) != 0) die("validator dust reward credit failed");
            validator_credit += dust;
        }
        journal_append(chain_dir, "reward_epoch validator=%s reward=%lld commission_bps=%lld power=%lld total_power=%lld", validator, validator_credit, commission_bps, power, total_power);
        printf("validator=%s reward=%lld delegators_reward=%lld power=%lld\n", validator, validator_credit, distributed_to_delegators, power);
    }
    free(stakes_arr); free(deleg_arr); return 0;
}

static int bootstrap_validator_status_cmd(const char *chain_dir, const char *address) {
    long long height = current_height_from_chain(chain_dir);
    long long principal = 0, lockh = 0;
    if (!address || !*address) die("bootstrap validator address required");
    int is_bootstrap = bootstrap_validator_lock_info(chain_dir, address, &principal, &lockh);
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    long long self = kv_get_ll_bin(stakes, address);
    long long balance = qrx_balance_get_authoritative(chain_dir, address);
    long long locked_now = (is_bootstrap && height < lockh) ? (self < principal ? self : principal) : 0;
    long long freely_unstakeable = self > locked_now ? self - locked_now : 0;
    printf("address=%s\n", address);
    printf("is_bootstrap=%d\n", is_bootstrap ? 1 : 0);
    printf("height=%lld\n", height);
    printf("bootstrap_principal=%lld\n", principal);
    printf("bootstrap_lock_until_height=%lld\n", lockh);
    printf("bootstrap_lock_active=%d\n", is_bootstrap && height < lockh ? 1 : 0);
    printf("liveness_slash_grace_active=%d\n", bootstrap_liveness_grace_active(chain_dir,address,height) ? 1 : 0);
    printf("double_sign_slashing_active=1\n");
    printf("self_stake=%lld\n", self);
    printf("locked_self_stake=%lld\n", locked_now);
    printf("freely_unstakeable_self_stake=%lld\n", freely_unstakeable);
    printf("spendable_balance=%lld\n", balance);
    printf("reward_policy=rewards_and_later_incoming_QUB_are_spendable_and_not_part_of_genesis_principal_lock\n");
    return 0;
}

static int reward_epoch_cmd(const char *chain_dir, long long reward, long long commission_bps) {
    require_manual_mint_allowed(chain_dir, "reward-epoch");
    long long height = current_height_from_chain(chain_dir);
    long long dev_share = (long long)qrx_dev_reward_share((uint64_t)reward, height);
    long long validator_reward = reward - dev_share;
    return reward_epoch_distribute_cmd(chain_dir, validator_reward, reward, dev_share, commission_bps);
}


static int getreward_cmd(const char *chain_dir, long long height) {
    long long h = height >= 0 ? height : current_height_from_chain(chain_dir);
    long long reward = qrx_chain_get_block_reward_at_height(chain_dir, h, (long long)QRX_INITIAL_BLOCK_REWARD_ATOMS, QRX_HALVING_INTERVAL_BLOCKS);
    printf("height=%lld\nreward_atoms=%lld\n", h, reward);
    return 0;
}

static int getparams_cmd(const char *chain_dir, long long height) {
    long long h = height >= 0 ? height : current_height_from_chain(chain_dir);
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    char *genesis_hash = chain_cfg_value(chain_dir, "genesis_hash");
    char *protocol_version = chain_cfg_value(chain_dir, "protocol_version");
    char *consensus_version = chain_cfg_value(chain_dir, "consensus_version");
    char *chain_id = chain_cfg_value(chain_dir, "chain_id");
    printf("height=%lld\n", h);
    printf("network_id=%s\n", network_id);
    printf("genesis_hash=%s\n", genesis_hash);
    printf("protocol_version=%s\n", protocol_version);
    printf("consensus_version=%s\n", consensus_version);
    printf("chain_id=%s\n", chain_id);
    free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id);
    printf("block_time_seconds=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "block_time_seconds", 10));
    printf("max_txs_per_block=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "max_txs_per_block", 100));
    printf("max_block_bytes=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "max_block_bytes", 524288));
    printf("max_tx_bytes=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "max_tx_bytes", 8192));
    printf("initial_reward_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "initial_reward_atoms", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "epoch_reward_atoms", (long long)QRX_INITIAL_BLOCK_REWARD_ATOMS)));
    printf("halving_interval_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "halving_interval_blocks", QRX_HALVING_INTERVAL_BLOCKS));
    printf("validator_reward_percent=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "validator_reward_percent", 30));
    printf("delegator_reward_percent=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "delegator_reward_percent", 70));
    printf("network_pool_percent=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "network_pool_percent", 0));
    printf("tx_fee_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "tx_fee_atoms", 1000));
    printf("asset_activation_height=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_activation_height", 0));
    printf("asset_issue_main_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_main_burn_atoms", 10000000000LL));
    printf("asset_issue_sub_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_sub_burn_atoms", 2500000000LL));
    printf("asset_issue_unique_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_unique_burn_atoms", 250000000LL));
    printf("asset_issue_channel_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_channel_burn_atoms", 2500000000LL));
    printf("asset_issue_qualifier_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_qualifier_burn_atoms", 25000000000LL));
    printf("asset_issue_subqualifier_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_subqualifier_burn_atoms", 2500000000LL));
    printf("asset_issue_restricted_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_issue_restricted_burn_atoms", 50000000000LL));
    printf("asset_reissue_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_reissue_burn_atoms", 1000000000LL));
    printf("asset_tag_burn_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "asset_tag_burn_atoms", 100000000LL));
    printf("generals_activation_height=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_activation_height", 0));
    printf("generals_join_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_join_cost_atoms", 1000000000LL));
    printf("generals_clan_create_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_clan_create_cost_atoms", 5000000000LL));
    printf("generals_clan_invite_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_clan_invite_cost_atoms", 100000LL));
    printf("generals_clan_invite_max_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_clan_invite_max_blocks", 604800LL));
    printf("generals_clan_membership_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_clan_membership_cost_atoms", 10000LL));
    printf("generals_action_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_action_cost_atoms", 10000LL));
    printf("generals_season_start_height=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_season_start_height", 0));
    printf("generals_season_length_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_season_length_blocks", 259200LL));
    printf("generals_turn_length_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_turn_length_blocks", 60LL));
    printf("generals_season_join_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_season_join_cost_atoms", 100000000LL));
    printf("generals_season_join_window_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_season_join_window_blocks", 0LL));
    printf("generals_energy_max=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_energy_max", 100LL));
    printf("generals_energy_regen_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_energy_regen_blocks", 6LL));
    printf("generals_energy_regen_amount=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_energy_regen_amount", 1LL));
    printf("generals_world_base_size=%lld\n", 128LL);
    printf("generals_world_chunk_size=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_world_chunk_size", 64LL));
    printf("generals_hq_min_distance=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_hq_min_distance", 16LL));
    printf("generals_order_commit_cost_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "generals_order_commit_cost_atoms", 10000LL));
    printf("generals_account_model=wallet-signed-player-identity\n");
    printf("generals_state_backend=qrxdb-wal-consensus\n");
    printf("development_fund_percent=%d\n", qrx_dev_fund_percent(h));
    { char *dev = chain_cfg_value(chain_dir, "dev_address"); printf("development_fund_address=%s\n", dev ? dev : ""); if (dev) free(dev); }
    printf("development_fund_basis=block_subsidy_only\n");
    printf("transaction_fee_recipient_policy=validators_and_delegators_100_percent\n");
    printf("pending_fee_pool_atoms=%lld\n", fee_pool_pending(chain_dir));
    printf("min_validator_stake_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "min_validator_stake_atoms", 10000000000LL));
    printf("double_sign_slash_bps=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "double_sign_slash_bps", 5000));
    printf("double_sign_jail_seconds=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "double_sign_jail_seconds", 315360000LL));
    printf("offline_penalty_bps=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_penalty_bps", 5));
    printf("offline_penalty_after_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_penalty_after_blocks", 25920));
    printf("offline_penalty_interval_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_penalty_interval_blocks", 8640));
    printf("offline_max_slash_bps_per_outage=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_max_slash_bps_per_outage", 100));
    printf("offline_jail_after_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_jail_after_blocks", 60480));
    printf("validator_catchup_max_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "validator_catchup_max_blocks", 2));
    printf("validator_catchup_min_peers=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "validator_catchup_min_peers", 1));
    printf("validator_catchup_stable_seconds=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "validator_catchup_stable_seconds", 30));
    printf("offline_jail_seconds=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_jail_seconds", 3600));
    return 0;
}

static int gethalving_cmd(const char *chain_dir, long long height) {
    long long h = height >= 0 ? height : current_height_from_chain(chain_dir);
    long long next = qrx_chain_get_next_halving_height(chain_dir, h, QRX_HALVING_INTERVAL_BLOCKS);
    printf("height=%lld\nnext_halving_height=%lld\nblocks_remaining=%lld\n", h, next, next >= 0 ? (next - h) : -1);
    return 0;
}

static int getforks_cmd(const char *chain_dir) {
    long long heights[512];
    int count = collect_fork_heights_from_genesis(chain_dir, heights, 512);
    if (count < 0) die("cannot read genesis");
    for (int i = 0; i < count; ++i) printf("fork_height=%lld\n", heights[i]);
    return 0;
}

static int getactivefork_cmd(const char *chain_dir, long long height) {
    long long h = height >= 0 ? height : current_height_from_chain(chain_dir);
    long long heights[512];
    int count = collect_fork_heights_from_genesis(chain_dir, heights, 512);
    if (count < 0) die("cannot read genesis");
    long long active = 0;
    for (int i = 0; i < count; ++i) if (heights[i] <= h && heights[i] > active) active = heights[i];
    printf("height=%lld\nactive_fork_height=%lld\n", h, active);
    return 0;
}

static int tokenomics_cmd(const char *chain_dir) {
    long long current_height = current_height_from_chain(chain_dir);
    long long max_supply = chain_cfg_ll_or_default(chain_dir, "max_supply_atoms", (long long)QRX_MAX_SUPPLY_ATOMS);
    long long initial_reward = qrx_chain_get_ll_at_height_or_default(chain_dir, current_height, "initial_reward_atoms", qrx_chain_get_ll_at_height_or_default(chain_dir, current_height, "epoch_reward_atoms", (long long)QRX_INITIAL_BLOCK_REWARD_ATOMS));
    long long faucet_cap = chain_cfg_ll_or_default(chain_dir, "faucet_cap_atoms", 1000000000000LL);
    long long current_reward = qrx_chain_get_block_reward_at_height(chain_dir, current_height, (long long)QRX_INITIAL_BLOCK_REWARD_ATOMS, QRX_HALVING_INTERVAL_BLOCKS);
    long long next_halving = qrx_chain_get_next_halving_height(chain_dir, current_height, QRX_HALVING_INTERVAL_BLOCKS);
    printf("max_supply_atoms=%lld\n"
           "initial_reward_atoms=%lld\n"
           "faucet_cap_atoms=%lld\n"
           "current_height=%lld\n"
           "current_reward_atoms=%lld\n"
           "next_halving_height=%lld\n"
           "minted_supply=%lld\n"
           "faucet_minted=%lld\n"
           "rewards_minted=%lld\n"
           "burned_supply=%lld\n"
           "redistributed_supply=%lld\n"
           "pending_fee_pool_atoms=%lld\n"
           "tx_fee_atoms=%lld\n"
           "remaining_supply=%lld\n"
           "service_reward_mint_policy=user_funded_no_additional_mint\n"
           "storage_provider_bps=%llu\n"
           "storage_resilience_bps=%llu\n"
           "storage_development_bps=%llu\n"
           "compute_fasttrack_provider_bps=%u\n"
           "compute_fasttrack_network_bps=%u\n"
           "compute_fasttrack_development_bps=%u\n"
           "compute_fasttrack_max_premium_bps=%u\n"
           "advertising_delivery_bps=%u\n"
           "advertising_publisher_bps=%u\n"
           "advertising_viewer_bps=%u\n"
           "advertising_protocol_bps=%u\n"
           "advertising_development_bps=%u\n",
           max_supply, initial_reward, faucet_cap, current_height, current_reward, next_halving,
           supply_get(chain_dir, "minted_supply"),
           supply_get(chain_dir, "faucet_minted"),
           supply_get(chain_dir, "rewards_minted"),
           supply_get(chain_dir, "burned_supply"),
           supply_get(chain_dir, "redistributed_supply"),
           fee_pool_pending(chain_dir),
           qrx_chain_get_ll_at_height_or_default(chain_dir, current_height, "tx_fee_atoms", 1000),
           max_supply - supply_get(chain_dir, "minted_supply"),
           (unsigned long long)QRX_STORAGE_PROVIDER_BUDGET_BPS,
           (unsigned long long)QRX_STORAGE_RESILIENCE_RESERVE_BPS,
           (unsigned long long)QRX_STORAGE_DEV_SHARE_BPS,
           QRX_FASTTRACK_PROVIDER_SHARE_BPS,
           QRX_FASTTRACK_NETWORK_SHARE_BPS,
           QRX_FASTTRACK_DEV_SHARE_BPS,
           QRX_FASTTRACK_MAX_PREMIUM_BPS,
           QRX_AD_REWARD_DELIVERY_BPS,
           QRX_AD_REWARD_PUBLISHER_BPS,
           QRX_AD_REWARD_VIEWER_BPS,
           QRX_AD_REWARD_PROTOCOL_BPS,
           QRX_AD_REWARD_DEVELOPMENT_BPS);
    return 0;
}
static int reward_epoch_auto_cmd(const char *chain_dir, long long commission_bps, int from_finalized_block_loop) {
    if (!from_finalized_block_loop) require_manual_mint_allowed(chain_dir, "reward-epoch-auto");
    long long height = current_height_from_chain(chain_dir);
    long long subsidy = qrx_chain_get_block_reward_at_height(chain_dir, height, (long long)QRX_INITIAL_BLOCK_REWARD_ATOMS, QRX_HALVING_INTERVAL_BLOCKS);
    long long fees = fee_pool_pending(chain_dir);
    long long dev_share = (long long)qrx_dev_reward_share((uint64_t)subsidy, height);
    long long validator_subsidy = subsidy - dev_share;
    long long validator_reward = validator_subsidy + fees;
    long long total = subsidy + fees;
    if (total <= 0) die("no block subsidy or fees to distribute");
    if (validator_reward <= 0) die("no validator/delegator reward to distribute");
    int rc = reward_epoch_distribute_cmd(chain_dir, validator_reward, subsidy, dev_share, commission_bps);
    if (rc == 0 && fees > 0) {
        long long drained = fee_pool_drain(chain_dir);
        journal_append(chain_dir, "fee_pool_drained amount=%lld height=%lld", drained, height);
        printf("fees_distributed=%lld\n", drained);
    }
    printf("block_subsidy=%lld\n", subsidy);
    printf("development_fund_share=%lld\n", dev_share);
    printf("validator_subsidy=%lld\n", validator_subsidy);
    printf("transaction_fees_to_validators=%lld\n", fees);
    printf("validator_reward_total=%lld\n", validator_reward);
    printf("reward_total=%lld\n", total);
    return rc;
}
static int evidence_double_sign_cmd(const char *chain_dir, const char *vote_a, const char *vote_b, long long slash_amount, long long penalty_points) {
    char v1[200]={0}, v2[200]={0}; long long p1=0,p2=0;
    if (verify_vote_file_internal(chain_dir, vote_a, NULL, NULL, NULL, v1, sizeof(v1), &p1) != 0) die("vote A invalid");
    if (verify_vote_file_internal(chain_dir, vote_b, NULL, NULL, NULL, v2, sizeof(v2), &p2) != 0) die("vote B invalid");
    if (strcmp(v1, v2) != 0) die("different validators");
    char *txta = read_file(vote_a, NULL), *txtb = read_file(vote_b, NULL); if (!txta || !txtb) die("cannot read votes");
    char *ha = cfg_get(txta, "height"), *ra = cfg_get(txta, "round"), *bha = cfg_get(txta, "block_hash");
    char *hb = cfg_get(txtb, "height"), *rb = cfg_get(txtb, "round"), *bhb = cfg_get(txtb, "block_hash");
    if (!ha||!ra||!bha||!hb||!rb||!bhb) die("invalid vote fields");
    if (strcmp(ha,hb) || strcmp(ra,rb)) die("not same height/round");
    if (!strcmp(bha,bhb)) die("not conflicting votes");
    long long bps = qrx_chain_get_ll_at_height_or_default(chain_dir, atoll(ha), "double_sign_slash_bps", 5000);
    long long jail_secs = qrx_chain_get_ll_at_height_or_default(chain_dir, atoll(ha), "double_sign_jail_seconds", 315360000LL);
    if (slash_amount <= 0) {
        long long power = validator_power_total(chain_dir, v1);
        slash_amount = (power * bps) / 10000;
        if (slash_amount <= 0 && power > 0) slash_amount = 1;
    }
    char jailed[1024], tomb[1024]; jail_paths(chain_dir, jailed, sizeof(jailed), tomb, sizeof(tomb));
    kv_set_ll_bin(jailed, v1, (long long)time(NULL) + jail_secs);
    kv_set_ll_bin(tomb, v1, 1);
    slash_cmd(chain_dir, v1, slash_amount, "double_sign", penalty_points);
    char eviddir[1024]; snprintf(eviddir, sizeof(eviddir), "%s/consensus/evidence", chain_dir); mkdir_p(eviddir);
    char out[1024]; snprintf(out, sizeof(out), "%s/%s-h%s-r%s.ev", eviddir, v1, ha, ra);
    char buf[4096]; snprintf(buf, sizeof(buf), "type=double_sign\nvalidator=%s\nheight=%s\nround=%s\nvote_a=%s\nvote_b=%s\ncreated_at=%lld\n", v1, ha, ra, vote_a, vote_b, (long long)time(NULL));
    write_text(out, buf);
    printf("%s\n", out);
    free(txta); free(txtb); free(ha); free(ra); free(bha); free(hb); free(rb); free(bhb); return 0;
}

static int hybrid_status_cmd(const char *wallet_dir) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/ed25519_priv.pem", wallet_dir); int has_ed_priv = access_qrx(p, R_OK) == 0;
    snprintf(p, sizeof(p), "%s/ed25519_pub.pem", wallet_dir); int has_ed_pub = access_qrx(p, R_OK) == 0;
    snprintf(p, sizeof(p), "%s/mldsa65_priv.pem", wallet_dir); int has_ml_priv = access_qrx(p, R_OK) == 0;
    snprintf(p, sizeof(p), "%s/mldsa65_pub.pem", wallet_dir); int has_ml_pub = access_qrx(p, R_OK) == 0;
    char *addr = wallet_address(wallet_dir);
    printf("wallet_dir=%s\n", wallet_dir);
    printf("address=%s\n", addr ? addr : "");
    printf("signature_scheme=ed25519+mldsa65\n");
    printf("ed25519_private=%s\n", has_ed_priv ? "yes" : "no");
    printf("ed25519_public=%s\n", has_ed_pub ? "yes" : "no");
    printf("mldsa65_private=%s\n", has_ml_priv ? "yes" : "no");
    printf("mldsa65_public=%s\n", has_ml_pub ? "yes" : "no");
    printf("hybrid_ready=%s\n", (has_ed_priv && has_ed_pub && has_ml_priv && has_ml_pub) ? "yes" : "no");
    free(addr);
    return (has_ed_priv && has_ed_pub && has_ml_priv && has_ml_pub) ? 0 : 1;
}


/* QRX 0.0.7.6 Native Assets & Regulated Tokenization Layer.
 * Additive state layer: existing QUB keys/addresses/tx semantics are untouched. */
static void asset76_policy_path(const char*c,char*out,size_t n){snprintf(out,n,"%s/state/regulated_assets.db",c);}
static void asset76_allow_path(const char*c,char*out,size_t n){snprintf(out,n,"%s/state/asset_allowlist.bin",c);}
static void asset76_freeze_path(const char*c,char*out,size_t n){snprintf(out,n,"%s/state/asset_freeze.bin",c);}
static char *asset76_get(const char*c,const char*a,const char*f){char p[1024],k[256],an[32];asset_id_normalize(a,an,sizeof(an));asset76_policy_path(c,p,sizeof(p));snprintf(k,sizeof(k),"asset.%s.%s",an,f);return text_db_get(p,k);}
static int asset76_set(const char*c,const char*a,const char*f,const char*v){char p[1024],k[256],an[32];asset_id_normalize(a,an,sizeof(an));asset76_policy_path(c,p,sizeof(p));snprintf(k,sizeof(k),"asset.%s.%s",an,f);return text_db_set(p,k,v?v:"");}
static int asset76_cap(const char*c,const char*a,const char*cap){char*v=asset76_get(c,a,"capabilities");int ok=v&&token_list_contains_ci(v,cap);free(v);return ok;}
static int asset76_flag(const char*c,const char*a,const char*addr,int freeze){char p[1024],k[768],an[32];asset_id_normalize(a,an,sizeof(an));if(freeze)asset76_freeze_path(c,p,sizeof(p));else asset76_allow_path(c,p,sizeof(p));snprintf(k,sizeof(k),"%s|%s",an,addr);return kv_get_ll_bin(p,k)>0;}
static int asset76_setflag(const char*c,const char*a,const char*addr,int freeze,int value){char p[1024],k[768],an[32];asset_id_normalize(a,an,sizeof(an));if(freeze)asset76_freeze_path(c,p,sizeof(p));else asset76_allow_path(c,p,sizeof(p));snprintf(k,sizeof(k),"%s|%s",an,addr);return kv_set_ll_bin(p,k,value?1:0);}
static int asset76_is_regulated(const char*c,const char*a){char*v=asset76_get(c,a,"class");int r=v&&!strcmp(v,"REGULATED");free(v);return r;}
static int asset76_eligible(const char*c,const char*a,const char*addr,const char*walletdir){
 char*m=asset76_get(c,a,"whitelist_mode");int explicit_required=m&&(!strcmp(m,"EXPLICIT_ALLOWLIST")||!strcmp(m,"BOTH"));int cred_required=m&&(!strcmp(m,"CREDENTIAL_POLICY")||!strcmp(m,"BOTH"));free(m);
 if(explicit_required&&!asset76_flag(c,a,addr,0))return 0;
 if(cred_required){if(!walletdir||!*walletdir)return 0;char*r=wallet_address(walletdir);if(!r)return 0;r[strcspn(r,"\r\n")]=0;int same=!strcmp(r,addr);free(r);if(!same)return 0;char reason[128];if(vp_verify(c,walletdir,reason,sizeof(reason))!=0)return 0;}
 return 1;
}
static int asset76_create_cmd(const char*c,const char*a,const char*name,const char*klass,const char*issuer,int decimals,long long maxs,const char*caps,const char*wm){
 require_manual_mint_allowed(c,"asset-create-v1");char an[32];asset_id_normalize(a,an,sizeof(an));if(!asset_id_valid(an)||!strcmp(an,"QUB"))die("invalid asset id");if(asset_exists(c,an))die("asset already exists");if(strcmp(klass,"STANDARD")&&strcmp(klass,"REGULATED"))die("class must be STANDARD or REGULATED");if(decimals<0||decimals>8||maxs<=0)die("invalid decimals/max supply");if(!issuer||strncmp(issuer,"qrx1",4))die("issuer must be a QRX address");
 char p[1024],k[128],buf[64];asset_registry_path(c,p,sizeof(p));snprintf(k,sizeof(k),"asset.%s.status",an);text_db_set(p,k,"active");snprintf(k,sizeof(k),"asset.%s.name",an);text_db_set(p,k,name);snprintf(k,sizeof(k),"asset.%s.decimals",an);snprintf(buf,sizeof(buf),"%d",decimals);text_db_set(p,k,buf);
 asset76_set(c,an,"class",klass);asset76_set(c,an,"issuer",issuer);asset76_set(c,an,"capabilities",caps?caps:"NONE");asset76_set(c,an,"whitelist_mode",wm?wm:"NONE");snprintf(buf,sizeof(buf),"%lld",maxs);asset76_set(c,an,"max_supply",buf);asset76_set(c,an,"minted_supply","0");asset76_set(c,an,"policy_locked","true");
 journal_append(c,"asset_create_v1 asset=%s class=%s issuer=%s max_supply=%lld capabilities=%s whitelist_mode=%s",an,klass,issuer,maxs,caps,wm);printf("asset=%s\nclass=%s\nissuer=%s\nmax_supply=%lld\ncapabilities=%s\nwhitelist_mode=%s\naddress_format_unchanged=true\nqub_semantics_unchanged=true\n",an,klass,issuer,maxs,caps,wm);return 0;}
static void asset76_require_issuer(const char*c,const char*a,const char*issuer){char*v=asset76_get(c,a,"issuer");if(!v||strcmp(v,issuer)){free(v);die("issuer authority mismatch");}free(v);}
static int asset76_allow_cmd(const char*c,const char*a,const char*issuer,const char*addr,int allow){require_manual_mint_allowed(c,"asset-allow-v1");if(!asset_exists(c,a)||!asset76_is_regulated(c,a))die("regulated asset required");asset76_require_issuer(c,a,issuer);if(asset76_setflag(c,a,addr,0,allow))die("allowlist update failed");journal_append(c,"asset_%s asset=%s address=%s issuer=%s",allow?"allow":"deny",a,addr,issuer);printf("status=%s\n",allow?"allowed":"denied");return 0;}
static int asset76_freeze_cmd(const char*c,const char*a,const char*issuer,const char*addr,int freeze){require_manual_mint_allowed(c,"asset-freeze-v1");if(!asset76_cap(c,a,"ISSUER_FREEZE"))die("asset does not permit issuer freeze");asset76_require_issuer(c,a,issuer);if(asset76_setflag(c,a,addr,1,freeze))die("freeze update failed");journal_append(c,"asset_%s asset=%s address=%s issuer=%s",freeze?"freeze":"unfreeze",a,addr,issuer);printf("status=%s\n",freeze?"frozen":"unfrozen");return 0;}
static int asset76_mint_cmd(const char*c,const char*a,const char*issuer,const char*to,long long amt,const char*walletdir){require_manual_mint_allowed(c,"asset-mint-v1");if(amt<=0)die("amount must be > 0");asset76_require_issuer(c,a,issuer);if(asset76_is_regulated(c,a)&&!asset76_eligible(c,a,to,walletdir))die("ASSET_RECIPIENT_NOT_ELIGIBLE");char*ms=asset76_get(c,a,"max_supply"),*cur=asset76_get(c,a,"minted_supply");long long max=ms?atoll(ms):0,m=cur?atoll(cur):0;free(ms);free(cur);if(m>max-amt)die("asset max supply exceeded");if(asset_balance_adjust(c,a,to,amt))die("mint failed");char b[64];snprintf(b,sizeof(b),"%lld",m+amt);asset76_set(c,a,"minted_supply",b);journal_append(c,"asset_mint asset=%s to=%s amount=%lld issuer=%s",a,to,amt,issuer);printf("minted=%lld\n",amt);return 0;}
static int asset76_transfer_cmd(const char*c,const char*a,const char*from,const char*to,long long amt,const char*recipient_wallet){require_manual_mint_allowed(c,"asset-transfer-v1");if(amt<=0||!asset_exists(c,a)||!strcmp(a,"QUB"))die("invalid asset transfer");if(asset76_flag(c,a,from,1)||asset76_flag(c,a,to,1))die("ASSET_ADDRESS_FROZEN");if(asset76_is_regulated(c,a)&&!asset76_eligible(c,a,to,recipient_wallet))die("ASSET_RECIPIENT_NOT_ELIGIBLE");if(asset_balance_get(c,a,from)<amt)die("insufficient asset balance");if(asset_balance_adjust(c,a,from,-amt)||asset_balance_adjust(c,a,to,amt))die("asset transfer failed");journal_append(c,"asset_transfer asset=%s from=%s to=%s amount=%lld",a,from,to,amt);printf("status=transferred\namount=%lld\n",amt);return 0;}
static int asset76_revoke_cmd(const char*c,const char*a,const char*issuer,const char*from,long long amt){require_manual_mint_allowed(c,"asset-revoke-v1");if(!asset76_cap(c,a,"ISSUER_REVOKE"))die("asset does not permit issuer revoke");asset76_require_issuer(c,a,issuer);if(amt<=0||asset_balance_get(c,a,from)<amt)die("invalid revoke amount");if(asset_balance_adjust(c,a,from,-amt))die("revoke failed");journal_append(c,"asset_revoke asset=%s from=%s amount=%lld issuer=%s",a,from,amt,issuer);printf("status=revoked\namount=%lld\n",amt);return 0;}
static int asset76_forced_cmd(const char*c,const char*a,const char*issuer,const char*from,const char*to,long long amt,const char*recipient_wallet){require_manual_mint_allowed(c,"asset-forced-transfer-v1");if(!asset76_cap(c,a,"ISSUER_FORCED_TRANSFER"))die("asset does not permit forced transfer");asset76_require_issuer(c,a,issuer);if(asset76_is_regulated(c,a)&&!asset76_eligible(c,a,to,recipient_wallet))die("ASSET_RECIPIENT_NOT_ELIGIBLE");if(amt<=0||asset_balance_get(c,a,from)<amt)die("invalid forced transfer amount");if(asset_balance_adjust(c,a,from,-amt)||asset_balance_adjust(c,a,to,amt))die("forced transfer failed");journal_append(c,"asset_forced_transfer asset=%s from=%s to=%s amount=%lld issuer=%s",a,from,to,amt,issuer);printf("status=forced-transferred\namount=%lld\n",amt);return 0;}
static int asset76_info_cmd(const char*c,const char*a){if(!asset_exists(c,a))die("asset not found");char*st=a76_db_get(c,a,"status");if(st){free(st);const char*fs[]={"kind","issuer","units","reissuable","supply","max_supply","metadata","verifier","capabilities","created_height","created_tx","updated_height","updated_tx"};printf("asset=%s\nconsensus_asset=true\n",a);for(size_t i=0;i<sizeof(fs)/sizeof(fs[0]);i++){char*v=a76_db_get(c,a,fs[i]);printf("%s=%s\n",fs[i],v?v:"");free(v);}printf("global_frozen=%s\n",a76_global_frozen(c,a)?"true":"false");return 0;}const char*fs[]={"class","issuer","capabilities","whitelist_mode","max_supply","minted_supply","policy_locked"};printf("asset=%s\nconsensus_asset=false\n",a);for(size_t i=0;i<sizeof(fs)/sizeof(fs[0]);i++){char*v=asset76_get(c,a,fs[i]);printf("%s=%s\n",fs[i],v?v:"");free(v);}return 0;}
static int asset76_tag_check_cmd(const char*c,const char*q,const char*addr){printf("qualifier=%s\naddress=%s\ntagged=%s\n",q,addr,a76_tagged(c,q,addr)?"true":"false");return 0;}
static int asset76_restriction_check_cmd(const char*c,const char*a,const char*addr){printf("asset=%s\naddress=%s\nblacklisted=%s\nglobal_frozen=%s\neligible=%s\n",a,addr,a76_blacklisted(c,a,addr)?"true":"false",a76_global_frozen(c,a)?"true":"false",a76_restricted_eligible(c,a,addr)?"true":"false");return 0;}
static int asset76_burned_cmd(const char*c){QrxDB db;char b[128]="0";if(qrxdb_init(&db,c)!=0)die("QRXDB init failed");if(qrxdb_get(&db,"consensus:asset76:burned_qub_atoms",b,sizeof(b))!=0)snprintf(b,sizeof(b),"0");qrxdb_close(&db);printf("%s\n",b);return 0;}




typedef struct { long long balances,bonded,unbonding,protocol; int overflow; } SupplyInvariantAcc;
static int supply_inv_add(long long *dst,long long x){if(x<0||*dst>LLONG_MAX-x)return -1;*dst+=x;return 0;}
static int supply_inv_cb(const char*k,const char*v,uint32_t vl,void*ctx){(void)vl;SupplyInvariantAcc*a=ctx;long long x=atoll(v);if(x<0)return -1;
    if(!strncmp(k,"acct:balance:",13)) return supply_inv_add(&a->balances,x);
    if(!strncmp(k,"staking:self:",13)||!strncmp(k,"staking:delegation:",19)) return supply_inv_add(&a->bonded,x);
    if(!strncmp(k,"staking:unbonding:",18)||!strncmp(k,"staking:undelegating:",21)) return supply_inv_add(&a->unbonding,x);
    if(!strncmp(k,"consensus:fee_pool:",19)||strstr(k,"treasury")||strstr(k,"prize_pool_atoms")||
       !strcmp(k,"consensus:storage:provider_bonds")||!strcmp(k,"consensus:storage:provider_escrow")||
       !strcmp(k,"consensus:storage:resilience")||!strcmp(k,"consensus:qrxnet:domain_bonds")||
       !strcmp(k,"consensus:compute:escrow_pool")||!strcmp(k,"consensus:compute:slashing_pool")) return supply_inv_add(&a->protocol,x); return 0;}
static int supply_invariant_cmd(const char*c){QrxDB db;if(qrxdb_init(&db,c))die("QRXDB init failed");SupplyInvariantAcc a={0};if(qrxdb_scan_prefix(&db,"",supply_inv_cb,&a)){qrxdb_close(&db);die("supply invariant scan failed");}qrxdb_close(&db);
 long long accounted=0,t=0;checked_add_ll(a.balances,a.bonded,"supply accounted",&t);checked_add_ll(t,a.unbonding,"supply accounted",&accounted);checked_add_ll(accounted,a.protocol,"supply accounted",&accounted);
 long long minted=supply_get(c,"minted_supply"),burned=supply_get(c,"burned_supply"),expected=minted-burned;
 printf("minted=%lld\nburned=%lld\nbalances=%lld\nbonded=%lld\nunbonding=%lld\nprotocol_pools=%lld\naccounted=%lld\nexpected=%lld\ninvariant_ok=%d\n",minted,burned,a.balances,a.bonded,a.unbonding,a.protocol,accounted,expected,accounted==expected); return accounted==expected?0:2;}
int qrx_backend_main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();
    if (argc < 2) { usage(); return 1; }
    if (!strcmp(argv[1], "governance-keygen") && argc == 4) return gov_keygen_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "governance-vault-init") && argc == 3) return gov_vault_init_cmd(argv[2]);
    if (!strcmp(argv[1], "governance-vault-add-online") && argc == 4) return gov_vault_add_online_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "governance-vault-add-offline") && argc == 4) return gov_vault_add_offline_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "governance-vault-status") && argc == 3) return gov_vault_status_cmd(argv[2]);
    if (!strcmp(argv[1], "governance-vault-sign") && argc == 6) return gov_vault_sign_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (!strcmp(argv[1], "governance-vault-backup-create") && argc == 8) return gov_vault_backup_create_cmd(argc, argv);
    if (!strcmp(argv[1], "governance-vault-restore-online") && argc == 5) return gov_vault_restore_online_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "privacy-attester-keygen") && argc == 4) return attester_keygen_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "kyc-provider-keygen") && argc == 4) return kyc_provider_keygen_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "governance-genesis-init") && argc >= 6) return gov_genesis_init_cmd(argc, argv);
    if (!strcmp(argv[1], "governance-sign") && argc == 5) return gov_sign_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "governance-attester-propose") && argc == 8) return gov_attester_propose_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    if (!strcmp(argv[1], "governance-protocol-propose") && argc == 8) return gov_protocol_propose_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    if (!strcmp(argv[1], "governance-compute-liveness-propose") && argc == 6) return gov_compute_liveness_propose_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (!strcmp(argv[1], "governance-apply") && argc >= 7) return gov_apply_cmd(argc, argv);
    if (!strcmp(argv[1], "protocol-info") && (argc == 3 || argc == 4)) return gov_protocol_info_cmd(argv[2], argc==4?atoll(argv[3]):-1);
    if (!strcmp(argv[1], "keygen") && argc == 3) return wallet_keygen(argv[2]);
    if (!strcmp(argv[1], "seed-new") && argc == 3) return wallet_seed_new(argv[2]);
    if (!strcmp(argv[1], "wallet-info") && argc == 3) return wallet_info_cmd(argv[2]);
    if (!strcmp(argv[1], "drive-pq-ensure") && argc == 3) return drive_pq_ensure_cmd(argv[2]);
    if (!strcmp(argv[1], "wallet-recovery-refresh") && argc == 3) return wallet_recovery_refresh_cmd(argv[2]);
    if (!strcmp(argv[1], "wallet-new-address") && argc == 3) return wallet_new_address_cmd(argv[2]);
    if (!strcmp(argv[1], "listaddresses") && argc == 3) return wallet_list_addresses_cmd(argv[2]);
    if (!strcmp(argv[1], "hybrid-status") && argc == 3) return hybrid_status_cmd(argv[2]);
    if (!strcmp(argv[1], "wallet-recover") && argc == 4) return wallet_recover_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "address") && argc == 3) { char *a = wallet_address(argv[2]); if (!a) return 1; printf("%s", a); free(a); return 0; }
    if (!strcmp(argv[1], "legacy-address") && argc == 3) return legacy_address_cmd(argv[2]);
    if (!strcmp(argv[1], "migrate-address") && argc == 3) return migrate_address_cmd(argv[2]);
    if (!strcmp(argv[1], "state-migrate-address") && argc == 5) return state_migrate_address_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "init-chain") && (argc == 3 || argc == 5 || argc == 8 || argc == 12 || argc == 19 || argc == 20)) return chain_init(argv[2], argc >= 4 ? atoll(argv[3]) : 20, argc >= 5 ? atoll(argv[4]) : 5000, argc >= 8 ? atoll(argv[5]) : (long long)QRX_MAX_SUPPLY_ATOMS, argc >= 8 ? atoll(argv[6]) : (long long)QRX_INITIAL_BLOCK_REWARD_ATOMS, argc >= 8 ? atoll(argv[7]) : 0LL, argc >= 12 ? argv[8] : NULL, argc >= 12 ? argv[9] : NULL, argc >= 12 ? argv[10] : NULL, argc >= 12 ? argv[11] : NULL, argc >= 19 ? atoll(argv[12]) : 10, argc >= 19 ? atoll(argv[13]) : 100, argc >= 19 ? atoll(argv[14]) : 524288, argc >= 19 ? atoll(argv[15]) : 8192, argc >= 19 ? atoll(argv[16]) : 70, argc >= 19 ? atoll(argv[17]) : 30, argc >= 19 ? atoll(argv[18]) : 0, argc == 20 ? argv[19] : NULL);
    if (!strcmp(argv[1], "getreward") && (argc == 3 || argc == 4)) return getreward_cmd(argv[2], argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "getparams") && (argc == 3 || argc == 4)) return getparams_cmd(argv[2], argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "gethalving") && (argc == 3 || argc == 4)) return gethalving_cmd(argv[2], argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "getforks") && argc == 3) return getforks_cmd(argv[2]);
    if (!strcmp(argv[1], "getactivefork") && (argc == 3 || argc == 4)) return getactivefork_cmd(argv[2], argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "tokenomics") && argc == 3) return tokenomics_cmd(argv[2]);
    if (!strcmp(argv[1], "reward-epoch-auto") && (argc == 3 || argc == 4 || argc == 5)) return reward_epoch_auto_cmd(argv[2], argc >= 4 ? atoll(argv[3]) : 1000, argc == 5 && !strcmp(argv[4], "--block-finalized"));
    if (!strcmp(argv[1], "faucet") && argc == 5) return faucet_cmd(argv[2], argv[3], atoll(argv[4]));
    if (!strcmp(argv[1], "getdevaddress") && argc == 3) return getdevaddress_cmd(argv[2]);
    if (!strcmp(argv[1], "feeinfo") && argc == 3) return feeinfo_cmd(argv[2]);
    if (!strcmp(argv[1], "balance") && argc == 4) return balance_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "history") && (argc >= 3 && argc <= 7)) return history_cmd(argv[2], argc >= 4 ? argv[3] : NULL, argc >= 5 ? (!strcmp(argv[4], "all") ? 0 : (size_t)strtoull(argv[4], NULL, 10)) : 50, argc >= 6 ? atoll(argv[5]) : 0, argc >= 7 ? atoll(argv[6]) : 0);
    if (!strcmp(argv[1], "htlc-create") && (argc == 8 || argc == 9)) return htlc_create_cmd(argv[2], argv[3], argv[4], atoll(argv[5]), argv[6], atoll(argv[7]), argc == 9 ? argv[8] : NULL);
    if (!strcmp(argv[1], "htlc-redeem") && argc == 5) return htlc_redeem_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "htlc-refund") && argc == 5) return htlc_refund_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "htlc-get") && argc == 4) return htlc_get_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "htlc-list") && argc == 3) return htlc_list_cmd(argv[2]);
    if (!strcmp(argv[1], "shielded-address") && argc == 3) return shielded_address_cmd(argv[2]);
    if (!strcmp(argv[1], "shield") && argc == 5) return shield_cmd(argv[2], argv[3], atoll(argv[4]), NULL);
    if (!strcmp(argv[1], "shield-to") && argc == 6) return shield_cmd(argv[2], argv[3], atoll(argv[4]), argv[5]);
    if (!strcmp(argv[1], "shielded-balance") && argc == 4) return shielded_balance_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "shielded-send") && argc == 6) return shielded_send_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "unshield") && argc == 6) return unshield_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "shielded-history") && argc == 4) return shielded_history_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "stealth-address") && argc == 3) return stealth_address_cmd(argv[2]);
    if (!strcmp(argv[1], "stealth-send") && (argc == 6 || argc == 7)) return stealth_send_cmd(argv[2], argv[3], argv[4], atoll(argv[5]), argc == 7 ? argv[6] : NULL);
    if (!strcmp(argv[1], "stealth-scan") && argc == 4) return stealth_scan_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "stealth-spend") && argc == 7) return stealth_spend_cmd(argv[2], argv[3], argv[4], argv[5], atoll(argv[6]));
    if (!strcmp(argv[1], "stealth-history") && argc == 4) return stealth_history_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "privacy-attester-register") && argc == 5) return vp_attester_register_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "privacy-attester-disable") && argc == 4) return vp_attester_disable_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "privacy-credential-issue") && argc == 7) return vp_issue_cmd(argv[2], argv[3], argv[4], argv[5], atoll(argv[6]));
    if (!strcmp(argv[1], "privacy-credential-status") && argc == 4) return vp_status_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "privacy-credential-revoke") && argc == 4) return vp_revoke_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "hidden-balance") && argc == 4) return hidden_balance_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "verified-shield") && (argc == 5 || argc == 6)) return verified_shield_cmd(argv[2], argv[3], atoll(argv[4]), argc == 6 ? argv[5] : NULL);
    if (!strcmp(argv[1], "verified-shielded-send") && argc == 6) return verified_shielded_send_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "verified-unshield") && argc == 6) return verified_unshield_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "privacy-feature-status") && argc == 3) return privacy_feature_status_cmd(argv[2]);
    if (!strcmp(argv[1], "prepare-privacy-payload") && argc == 7) return privacy_prepare_payload_cmd(argv[2], argv[3], argv[4], atoll(argv[5]), argv[6]);
    if (!strcmp(argv[1], "privacy-consensus-balance") && argc == 4) return privacy_consensus_balance_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "privacy-credential-issue-v2") && argc == 7) return privacy_credential_issue_v2_cmd(argv[2], argv[3], argv[4], argv[5], atoll(argv[6]));
    if (!strcmp(argv[1], "governance-protocol-propose-v2") && argc == 9) return gov_protocol_propose_v2_cmd(argv[2], argv[3], atoll(argv[4]), atoll(argv[5]), atoll(argv[6]), atoll(argv[7]), argv[8]);
    if (!strcmp(argv[1], "privacy-governance-propose-v2") && argc == 8) return privacy_gov_propose_v2_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], atoll(argv[7]));
    if (!strcmp(argv[1], "kyc-provider-propose-v2") && argc == 10) return kyc_provider_propose_v2_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], atoll(argv[9]));
    if (!strcmp(argv[1], "kyc-provider-info") && argc == 4) return kyc_provider_info_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "governance-sign-v2") && argc == 6) return privacy_gov_sign_v2_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (!strcmp(argv[1], "governance-vault-sign-v2") && argc == 7) return gov_vault_sign_v2_cmd(argv[2], argv[3], argv[4], argv[5], argv[6]);
    if (!strcmp(argv[1], "governance-payload-v2") && argc >= 4) return privacy_gov_payload_v2_cmd(argv[2], argc-3, &argv[3]);
    if (!strcmp(argv[1], "privacy-governance-sign-v2") && argc == 6) return privacy_gov_sign_v2_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (!strcmp(argv[1], "privacy-governance-payload-v2") && argc >= 4) return privacy_gov_payload_v2_cmd(argv[2], argc-3, &argv[3]);
    if (!strcmp(argv[1], "getnonce") && (argc == 4 || argc == 5)) return getnonce_cmd(argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    if (!strcmp(argv[1], "getnoncelanes") && argc == 4) return getnoncelanes_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "agent-status") && argc == 4) return agent_status_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "list-agents") && (argc == 3 || argc == 4)) return list_agents_cmd(argv[2], argc == 4 ? argv[3] : NULL);
    if (!strcmp(argv[1], "create-agent-register-raw-tx") && (argc == 16 || argc == 17 || argc == 18)) return create_agent_register_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10], argv[11], argv[12], argv[13], argv[14], argv[15], argc >= 17 ? argv[16] : NULL, argc == 18 ? argv[17] : NULL);
    if (!strcmp(argv[1], "create-agent-update-raw-tx") && (argc == 14 || argc == 15 || argc == 16)) return create_agent_update_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10], argv[11], argv[12], argv[13], argc >= 15 ? argv[14] : NULL, argc == 16 ? argv[15] : NULL);
    if (!strcmp(argv[1], "create-agent-revoke-raw-tx") && (argc == 9 || argc == 10 || argc == 11)) return create_agent_revoke_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argc >= 10 ? argv[9] : NULL, argc == 11 ? argv[10] : NULL);
    if (!strcmp(argv[1], "order-status") && argc == 4) return order_status_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "list-orders") && (argc == 3 || argc == 4 || argc == 5)) return list_orders_cmd(argv[2], argc >= 4 ? argv[3] : NULL, argc == 5 ? argv[4] : NULL);
    if (!strcmp(argv[1], "trade-status") && argc == 4) return trade_status_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "list-trades") && (argc >= 3 && argc <= 7)) return list_trades_cmd(argv[2], argc >= 4 ? argv[3] : NULL, argc >= 5 ? (!strcmp(argv[4],"all") ? 0 : atoll(argv[4])) : 50, argc >= 6 ? atoll(argv[5]) : 0, argc >= 7 ? atoll(argv[6]) : 0);
    if (!strcmp(argv[1], "orderbook") && (argc == 4 || argc == 5)) return orderbook_cmd(argv[2], argv[3], argc == 5 ? atoi(argv[4]) : 20);
    if (!strcmp(argv[1], "asset-create-v1") && argc == 11) return asset76_create_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],atoi(argv[7]),atoll(argv[8]),argv[9],argv[10]);
    if (!strcmp(argv[1], "asset-tag-check") && argc == 5) return asset76_tag_check_cmd(argv[2],argv[3],argv[4]);
    if (!strcmp(argv[1], "asset-restriction-check") && argc == 5) return asset76_restriction_check_cmd(argv[2],argv[3],argv[4]);
    if (!strcmp(argv[1], "asset-burned-fees") && argc == 3) return asset76_burned_cmd(argv[2]);
    if (!strcmp(argv[1], "asset-info-v1") && argc == 4) return asset76_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-strategic-info") && argc == 6) return generals_strategic_info_cmd(argv[2],atoll(argv[3]),atoll(argv[4]),atoll(argv[5]));
    if (!strcmp(argv[1], "generals-economy-info") && argc == 5) return generals_economy_info_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-city-info") && argc == 6) return generals_city_info_cmd(argv[2],atoll(argv[3]),atoll(argv[4]),atoll(argv[5]));
    if (!strcmp(argv[1], "generals-research-info") && argc == 5) return generals_research_info_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-research-network-info") && argc == 5) return generals_research_network_info_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-espionage-info") && argc == 6) return generals_espionage_info_cmd(argv[2],argv[3],argv[4],atoll(argv[5]));
    if (!strcmp(argv[1], "generals-tech-tree") && argc == 5) return generals_tech_tree_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-doctrine-info") && argc == 5) return generals_doctrine_info_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-player-info") && argc == 4) return generals_player_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-treasury-info") && argc == 3) return generals_treasury_info_cmd(argv[2]);
    if (!strcmp(argv[1], "generals-clan-info") && argc == 4) return generals_clan_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-clan-directive-info") && argc == 5) return generals_clan_directive_info_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-clan-invite-info") && argc == 4) return generals_clan_invite_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-season-info") && (argc == 3 || argc == 4)) return generals_season_info_cmd(argv[2],argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "generals-energy-info") && (argc == 4 || argc == 5)) return generals_energy_info_cmd(argv[2],argv[3],argc == 5 ? atoll(argv[4]) : -1);
    if (!strcmp(argv[1], "generals-player-army-info") && (argc == 4 || argc == 5)) return generals_player_army_info_cmd(argv[2],argv[3],argc == 5 ? atoll(argv[4]) : 0);
    if (!strcmp(argv[1], "generals-unit-class-info") && argc == 3) return generals_unit_class_info_cmd(argv[2]);
    if (!strcmp(argv[1], "generals-combat-info") && argc == 6) return generals_combat_info_cmd(argv[2],atoll(argv[3]),atoll(argv[4]),argv[5]);
    if (!strcmp(argv[1], "generals-logistics-info") && argc == 5) return generals_logistics_info_cmd(argv[2],argv[3],atoll(argv[4]));
    if (!strcmp(argv[1], "generals-infra-info") && argc == 6) return generals_infra_info_cmd(argv[2],atoll(argv[3]),atoll(argv[4]),atoll(argv[5]));
    if (!strcmp(argv[1], "generals-supply-line-info") && argc == 8) return generals_supply_line_info_cmd(argv[2],argv[3],atoll(argv[4]),atoll(argv[5]),atoll(argv[6]),atoll(argv[7]),atoll(argv[8]));
    if (!strcmp(argv[1], "generals-unit-logistics-info") && argc == 4) return generals_unit_logistics_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-world-plan") && argc == 3) return generals_world_plan_cmd(atoll(argv[2]));
    if (!strcmp(argv[1], "generals-world-info") && (argc == 3 || argc == 4)) return generals_world_info_cmd(argv[2],argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "generals-contact-info") && argc == 6) return generals_contact_info_cmd(argv[2],argv[3],argv[4],atoll(argv[5]));
    if (!strcmp(argv[1], "generals-mission-info") && argc == 4) return generals_mission_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-fleet-info") && argc == 4) return generals_fleet_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-unit-info") && argc == 4) return generals_unit_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-order-info") && argc == 4) return generals_order_info_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-tile-info") && argc == 6) return generals_tile_info_cmd(argv[2],atoll(argv[3]),atoll(argv[4]),atoll(argv[5]));
    if (!strcmp(argv[1], "generals-region-info") && argc == 8) return generals_region_info_cmd(argv[2],atoll(argv[3]),atoll(argv[4]),atoll(argv[5]),atoll(argv[6]),atoll(argv[7]));
    if (!strcmp(argv[1], "generals-season-result-info") && argc == 4) return generals_season_result_info_cmd(argv[2],atoll(argv[3]));
    if (!strcmp(argv[1], "generals-season-rewards-info") && argc == 4) return generals_season_rewards_info_cmd(argv[2],atoll(argv[3]));
    if (!strcmp(argv[1], "generals-clan-ranking-info") && argc == 4) return generals_clan_ranking_info_cmd(argv[2],atoll(argv[3]));
    if (!strcmp(argv[1], "generals-ranking-info") && argc == 4) return generals_ranking_info_cmd(argv[2],atoll(argv[3]));
    if (!strcmp(argv[1], "asset-allow-v1") && argc == 6) return asset76_allow_cmd(argv[2],argv[3],argv[4],argv[5],1);
    if (!strcmp(argv[1], "asset-deny-v1") && argc == 6) return asset76_allow_cmd(argv[2],argv[3],argv[4],argv[5],0);
    if (!strcmp(argv[1], "asset-freeze-v1") && argc == 6) return asset76_freeze_cmd(argv[2],argv[3],argv[4],argv[5],1);
    if (!strcmp(argv[1], "asset-unfreeze-v1") && argc == 6) return asset76_freeze_cmd(argv[2],argv[3],argv[4],argv[5],0);
    if (!strcmp(argv[1], "asset-mint-v1") && (argc == 7 || argc == 8)) return asset76_mint_cmd(argv[2],argv[3],argv[4],argv[5],atoll(argv[6]),argc==8?argv[7]:NULL);
    if (!strcmp(argv[1], "asset-transfer-v1") && (argc == 7 || argc == 8)) return asset76_transfer_cmd(argv[2],argv[3],argv[4],argv[5],atoll(argv[6]),argc==8?argv[7]:NULL);
    if (!strcmp(argv[1], "asset-revoke-v1") && argc == 7) return asset76_revoke_cmd(argv[2],argv[3],argv[4],argv[5],atoll(argv[6]));
    if (!strcmp(argv[1], "asset-forced-transfer-v1") && (argc == 8 || argc == 9)) return asset76_forced_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],atoll(argv[7]),argc==9?argv[8]:NULL);
    if (!strcmp(argv[1], "asset-balance") && argc == 5) return asset_balance_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "list-assets") && argc == 3) return list_assets_cmd(argv[2]);
    if (!strcmp(argv[1], "asset-register") && argc == 5) return asset_register_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "asset-credit") && argc == 6) return asset_credit_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "agent-limits") && argc == 4) return agent_limits_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "trading-info") && argc == 3) return trading_info_cmd(argv[2]);
    if (!strcmp(argv[1], "create-order-raw-tx") && (argc == 15 || argc == 16 || argc == 17)) return create_order_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argv[14],argc>=16?argv[15]:NULL,argc==17?argv[16]:NULL);
    if (!strcmp(argv[1], "create-external-order-raw-tx") && (argc == 16 || argc == 17 || argc == 18)) return create_external_order_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argv[14],argv[15],argc>=17?argv[16]:NULL,argc==18?argv[17]:NULL);
    if (!strcmp(argv[1], "create-arbitrage-hedge-raw-tx") && (argc == 14 || argc == 15 || argc == 16)) return create_arbitrage_hedge_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argc>=15?argv[14]:NULL,argc==16?argv[15]:NULL);
    if (!strcmp(argv[1], "create-order-cancel-raw-tx") && (argc == 10 || argc == 11 || argc == 12)) return create_order_cancel_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argc>=11?argv[10]:NULL,argc==12?argv[11]:NULL);
    if (!strcmp(argv[1], "create-order-replace-raw-tx") && (argc == 16 || argc == 17 || argc == 18)) return create_order_replace_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argv[14],argv[15],argc>=17?argv[16]:NULL,argc==18?argv[17]:NULL);
    if (!strcmp(argv[1], "gateway-status") && argc == 4) return gateway_status_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "list-gateways") && (argc == 3 || argc == 4)) return list_gateways_cmd(argv[2],argc==4?argv[3]:NULL);
    if (!strcmp(argv[1], "execution-report-status") && argc == 4) return execution_report_status_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "state-root") && argc == 3) return state_root_cmd(argv[2]);
    if (!strcmp(argv[1], "settlement-status") && argc == 4) return settlement_status_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "create-gateway-register-raw-tx") && (argc == 14 || argc == 15 || argc == 16)) return create_gateway_register_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argc>=15?argv[14]:NULL,argc==16?argv[15]:NULL);
    if (!strcmp(argv[1], "create-gateway-revoke-raw-tx") && (argc == 9 || argc == 10 || argc == 11)) return create_gateway_revoke_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argc>=10?argv[9]:NULL,argc==11?argv[10]:NULL);
    if (!strcmp(argv[1], "create-execution-report-raw-tx") && (argc == 16 || argc == 17 || argc == 18)) return create_execution_report_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argv[14],argv[15],argc>=17?argv[16]:NULL,argc==18?argv[17]:NULL);
    if (!strcmp(argv[1], "crosschain-info") && argc == 3) return crosschain_info_cmd(argv[2]);
    if (!strcmp(argv[1], "crosschain-status") && argc == 4) return crosschain_status_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "list-crosschain") && (argc == 3 || argc == 4)) return list_crosschain_cmd(argv[2],argc==4?argv[3]:NULL);
    if (!strcmp(argv[1], "crosschain-orderbook") && (argc == 3 || argc == 4)) return crosschain_orderbook_cmd(argv[2],argc==4?atoi(argv[3]):20);
    if (!strcmp(argv[1], "btc-htlc-template") && argc == 7) return btc_htlc_template_cmd(argv[2],argv[3],argv[4],atoll(argv[5]),argv[6]);
    if (!strcmp(argv[1], "btc-spv-info") && argc == 3) return btc_spv_info_cmd(argv[2]);
    if (!strcmp(argv[1], "btc-spv-best-header") && argc == 3) return btc_spv_best_header_cmd(argv[2]);
    if (!strcmp(argv[1], "btc-spv-header") && argc == 4) return btc_spv_header_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "btc-spv-verify-proof") && argc == 7) return btc_spv_verify_proof_cmd(argv[2],argv[3],argv[4],argv[5],argv[6]);
    if (!strcmp(argv[1], "btc-spv-confirmations") && argc == 4) return btc_spv_confirmations_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "crosschain-verify-funding") && argc == 8) return crosschain_verify_funding_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7]);
    if (!strcmp(argv[1], "crosschain-funding") && argc == 4) return crosschain_funding_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "crosschain-security") && argc == 4) return crosschain_security_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "create-btc-spv-header-raw-tx") && (argc == 9 || argc == 10 || argc == 11)) return create_btc_spv_header_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argc>=10?argv[9]:NULL,argc==11?argv[10]:NULL);
    if (!strcmp(argv[1], "create-btc-spv-funding-proof-raw-tx") && (argc == 13 || argc == 14 || argc == 15)) return create_btc_spv_funding_proof_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argc>=14?argv[13]:NULL,argc==15?argv[14]:NULL);
    if (!strcmp(argv[1], "create-crosschain-buy-raw-tx") && (argc == 15 || argc == 16 || argc == 17)) return create_crosschain_buy_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argv[14],argc>=16?argv[15]:NULL,argc==17?argv[16]:NULL);
    if (!strcmp(argv[1], "create-crosschain-sell-raw-tx") && (argc == 14 || argc == 15 || argc == 16)) return create_crosschain_sell_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argc>=15?argv[14]:NULL,argc==16?argv[15]:NULL);
    if (!strcmp(argv[1], "create-crosschain-redeem-raw-tx") && (argc == 10 || argc == 11 || argc == 12)) return create_crosschain_redeem_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argc>=11?argv[10]:NULL,argc==12?argv[11]:NULL);
    if (!strcmp(argv[1], "create-crosschain-refund-raw-tx") && (argc == 9 || argc == 10 || argc == 11)) return create_crosschain_refund_raw_tx_cmd(argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argc>=10?argv[9]:NULL,argc==11?argv[10]:NULL);
    if (!strcmp(argv[1], "velocity-info") && argc == 3) return velocity_info_cmd(argv[2]);
    if (!strcmp(argv[1], "resource-info") && (argc == 3 || argc == 4)) return resource_info_cmd(argv[2], argc == 4 ? atoll(argv[3]) : -1);
    if (!strcmp(argv[1], "storage-split") && argc == 3) return storage_split_cmd(argv[2]);
    if (!strcmp(argv[1], "storage-fs-init") && argc == 5) return storage_fs_init_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "storage-fs-info") && argc == 3) return storage_fs_info_cmd(argv[2]);
    if (!strcmp(argv[1], "storage-fs-put") && argc == 4) return storage_fs_put_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "storage-fs-get") && argc == 5) return storage_fs_get_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "storage-fs-delete") && argc == 4) return storage_fs_delete_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "storage-fs-recover") && argc == 3) return storage_fs_recover_cmd(argv[2]);
    if (!strcmp(argv[1], "create-velocity-raw-tx") && (argc == 12 || argc == 13 || argc == 14)) return create_velocity_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10], argv[11], argc >= 13 ? argv[12] : NULL, argc == 14 ? argv[13] : NULL);
    if (!strcmp(argv[1], "create-raw-tx") && (argc >= 8 && argc <= 12)) return create_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argc >= 9 ? argv[8] : NULL, argc >= 10 ? argv[9] : NULL, argc >= 11 ? argv[10] : NULL, argc >= 12 ? argv[11] : NULL);
    if (!strcmp(argv[1], "signrawtransactionwithwallet") && argc == 6) return signrawtransactionwithwallet_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (!strcmp(argv[1], "decoderawtransaction") && argc == 4) return decoderawtransaction_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "txid") && argc == 4) return txid_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "sign") && argc == 8) return sign_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    if (!strcmp(argv[1], "send") && (argc == 7 || argc == 8)) return send_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argc == 8 ? argv[7] : NULL);
    if (!strcmp(argv[1], "send-from") && (argc == 8 || argc == 9)) return send_cmd_from(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argc == 9 ? argv[8] : NULL);
    if (!strcmp(argv[1], "verify") && argc == 4) return verify_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "applytx") && argc == 4) return applytx_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "receive") && argc == 3) { char *a = wallet_address(argv[2]); if (!a) return 1; printf("%s", a); free(a); return 0; }
    if (!strcmp(argv[1], "node-init") && argc == 7) return node_init_cmd(argv[2], argv[3], argv[4], argv[5], argv[6]);
    if (!strcmp(argv[1], "add-peer") && argc == 5) return add_peer_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "addnode") && argc == 5) return add_peer_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "addnodes") && argc == 5) return add_peer_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "add-seed") && argc == 5) return add_seed_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "set-external") && argc == 5) return set_external_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "discover-peers") && argc == 3) return discover_peers_cmd(argv[2]);
    if (!strcmp(argv[1], "bootstrap") && argc == 3) return bootstrap_cmd(argv[2]);
    if (!strcmp(argv[1], "nat-info") && argc == 3) return nat_info_cmd(argv[2]);
    if (!strcmp(argv[1], "peer-top") && (argc == 3 || argc == 4)) return peer_top_cmd(argv[2], argc == 4 ? atoi(argv[3]) : 10);
    if (!strcmp(argv[1], "node-run") && argc == 3) return node_run_cmd(argv[2]);
    if (!strcmp(argv[1], "sendtx") && argc == 4) return sendtx_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "propose-block") && (argc == 3 || argc == 4)) return propose_block_cmd(argv[2], argc == 4 ? atoi(argv[3]) : 100);
    if (!strcmp(argv[1], "propose-block-as") && (argc == 4 || argc == 5)) return propose_block_cmd_as(argv[2], argc == 5 ? atoi(argv[4]) : 100, argv[3]);
    if (!strcmp(argv[1], "verify-block") && argc == 4) return verify_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "validator-set-at") && argc == 5) return validator_set_at_cmd(argv[2], atoll(argv[3]), atoll(argv[4]));
    if (!strcmp(argv[1], "lock-status") && argc == 3) return lock_status_cmd(argv[2]);
    if (!strcmp(argv[1], "evidence-double-sign") && (argc == 5 || argc == 7)) return evidence_double_sign_cmd(argv[2], argv[3], argv[4], argc >= 6 ? atoll(argv[5]) : 0, argc == 7 ? atoll(argv[6]) : 100);
    if (!strcmp(argv[1], "vote-block") && argc == 4) return vote_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "vote-block-as") && argc == 5) return vote_block_cmd_as(argv[2], argv[4], argv[3]);
    if (!strcmp(argv[1], "prevote-block") && argc == 4) return vote_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "precommit-block") && argc == 4) return vote_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "verify-proposal") && argc == 4) return verify_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "tally-votes") && argc == 4) return tally_votes_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "tally-precommits") && argc == 4) return tally_votes_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "finalize-block") && argc == 4) return finalize_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "timeout-status") && argc == 3) return timeout_status_cmd(argv[2]);
    if (!strcmp(argv[1], "node-process-inbox") && argc == 3) return node_process_inbox_cmd(argv[2]);
    if (!strcmp(argv[1], "generals-offline-process") && argc == 3) return generals_offline_process_cmd(argv[2]);
    if (!strcmp(argv[1], "generals-relay-publish") && argc == 4) return generals_relay_publish_cmd(argv[2],argv[3]);
    if (!strcmp(argv[1], "generals-relay-process") && argc == 3) return generals_relay_process_node(argv[2]);
    if (!strcmp(argv[1], "node-publish-block") && argc == 4) return node_publish_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "node-publish-vote") && argc == 4) return node_publish_vote_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "peer-status") && argc == 3) return peer_status_cmd(argv[2]);
    if (!strcmp(argv[1], "list-peers") && argc == 3) return list_peers_cmd(argv[2]);
    if (!strcmp(argv[1], "banscore") && (argc == 3 || argc == 4)) return banscore_cmd(argv[2], argc == 4 ? argv[3] : NULL);
    if (!strcmp(argv[1], "ban-peer") && (argc == 4 || argc == 5)) return ban_peer_cmd(argv[2], argv[3], argc == 5 ? atoll(argv[4]) : BAN_THRESHOLD);
    if (!strcmp(argv[1], "unban-peer") && argc == 4) return unban_peer_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "mempool-status") && argc == 3) return mempool_status_cmd(argv[2]);
    if (!strcmp(argv[1], "mempool-prune") && (argc == 3 || argc == 4)) return mempool_prune_cmd(argv[2], argc == 4 ? atoi(argv[3]) : MEMPOOL_MAX_TXS);
    if (!strcmp(argv[1], "velocity-mempool-plan") && (argc >= 3 && argc <= 5)) return velocity_mempool_plan_cmd(argv[2], argc >= 4 ? atoi(argv[3]) : 0, argc == 5 ? atoi(argv[4]) : 4);
    if (!strcmp(argv[1], "velocity-mvcc-execute") && (argc >= 3 && argc <= 5)) return velocity_mvcc_execute_cmd(argv[2], argc >= 4 ? atoi(argv[3]) : 100, argc == 5 ? atoi(argv[4]) : 4);
    if (!strcmp(argv[1], "velocity-engine-info") && argc == 3) return velocity_engine_info_cmd(argv[2]);
    if (!strcmp(argv[1], "decay-bans") && (argc == 3 || argc == 4)) return decay_bans_cmd(argv[2], argc == 4 ? atoll(argv[3]) : 10);
    if (!strcmp(argv[1], "state-check") && argc == 3) return state_check_cmd(argv[2]);
    if (!strcmp(argv[1], "snapshot-state") && (argc == 3 || argc == 4)) return snapshot_state_cmd(argv[2], argc == 4 ? argv[3] : NULL);
    if (!strcmp(argv[1], "reindex-state") && argc == 3) return reindex_state_cmd(argv[2]);
    if (!strcmp(argv[1], "supply-invariant") && argc == 3) return supply_invariant_cmd(argv[2]);
    if (!strcmp(argv[1], "stake") && argc == 5) return stake_cmd(argv[2], argv[3], atoll(argv[4]));
    if (!strcmp(argv[1], "unstake") && (argc == 5 || argc == 6)) return unstake_cmd(argv[2], argv[3], atoll(argv[4]), argc == 6 ? atoll(argv[5]) : 86400);
    if (!strcmp(argv[1], "claim-unbonded") && argc == 4) return claim_unbonded_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "delegate") && argc == 6) return delegate_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "undelegate") && (argc == 6 || argc == 7)) return undelegate_cmd(argv[2], argv[3], argv[4], atoll(argv[5]), argc == 7 ? atoll(argv[6]) : 86400);
    if (!strcmp(argv[1], "claim-undelegated") && argc == 5) return claim_undelegated_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "staking-status") && (argc == 3 || argc == 4)) return staking_status_cmd(argv[2], argc == 4 ? argv[3] : NULL);
    if (!strcmp(argv[1], "validator-set") && argc == 3) return validator_set_cmd(argv[2]);
    if (!strcmp(argv[1], "reward-epoch") && (argc == 4 || argc == 5)) return reward_epoch_cmd(argv[2], atoll(argv[3]), argc == 5 ? atoll(argv[4]) : 1000);
    if (!strcmp(argv[1], "bootstrap-validator-status") && argc == 4) return bootstrap_validator_status_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "slash") && (argc == 6 || argc == 7)) return slash_cmd(argv[2], argv[3], atoll(argv[4]), argv[5], argc == 7 ? atoll(argv[6]) : 10);
    usage(); return 1;
}
