
/* === QRX Mainnet Hardening === */
#include "protocol/qrx_protocol_version.h"
#include "protocol/qrx_chainid.h"
#include "protocol/qrx_domain_separation.h"
#include "security/qrx_secure_memory.h"
#include "economics/qrx_economics.h"

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
  #define popen_qrx(cmd, mode) _popen((cmd), (mode))
  #define pclose_qrx(fp) _pclose(fp)
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
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <dirent.h>
  #include <unistd.h>
  #define mkdir_qrx(path, mode) mkdir((path), (mode))
  #define access_qrx(path, mode) access((path), (mode))
  #define unlink_qrx(path) unlink(path)
  #define popen_qrx(cmd, mode) popen((cmd), (mode))
  #define pclose_qrx(fp) pclose(fp)
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

#define QRX_PROTOCOL_VERSION 6
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


static int connect_to(const char *host, int port);
static int build_hello_message(const char *node_dir, char **out_msg);
static int send_framed(int fd, const char *msg);
static char *recv_framed(int fd);
static void state_paths(const char *chain_dir, char *balances, size_t bsz, char *nonces, size_t nsz, char *applied, size_t asz, char *journal, size_t jsz);
static long long kv_get_ll_bin(const char *path, const char *key);
static int kv_set_ll_bin(const char *path, const char *key, long long val);
static void journal_append(const char *chain_dir, const char *fmt, ...);
static long long validator_power_total(const char *chain_dir, const char *validator);
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


static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); fputc('\n', stderr); exit(1);
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

static void usage(void) {
    puts("qrx rc6.2-tokenomics\n"
         "Commands:\n"
         "  keygen <wallet-dir>\n  seed-new <wallet-dir>\n  wallet-info <wallet-dir>\n  wallet-new-address <wallet-dir>\n  listaddresses <wallet-dir>\n  wallet-recover <wallet-dir> <recovery-file>\n"
         "  address <wallet-dir>\n  legacy-address <wallet-dir>\n  migrate-address <wallet-dir>\n  state-migrate-address <chain-dir> <old-address> <new-address>\n"
         "  init-chain <chain-dir>\n"
         "  faucet <chain-dir> <address> <amount>\n  getdevaddress <chain-dir>\n"
         "  balance <chain-dir> <address>\n  history <chain-dir> [address] [limit|all] [from-unix] [to-unix-exclusive]\n"
         "  sign <wallet-dir> <chain-dir> <to> <amount> <memo> <tx-file>\n"
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
         "  propose-block <node-dir> [max_txs]\n"
         "  verify-block <chain-dir> <block-file>\n"
         "  peer-status <node-dir>\n"
         "  mempool-status <node-dir>\n"
         "  mempool-prune <node-dir> [max_txs]\n"
         "  velocity-mvcc-execute <node-dir> [max_txs] [workers]\n"
         "  getnonce <chain-dir> <address> [lane]\n"
         "  getnoncelanes <chain-dir> <address>\n"
         "  agent-status <chain-dir> <agent-address>\n  list-agents <chain-dir> [owner-address]\n  create-agent-register-raw-tx <chain-dir> <owner> <agent> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> <owner_ed_pub_hex> <owner_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-agent-update-raw-tx <chain-dir> <owner> <agent> <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> <owner_ed_pub_hex> <owner_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-agent-revoke-raw-tx <chain-dir> <owner> <agent> <owner_ed_pub_hex> <owner_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  order-status <chain-dir> <order-id>\n  list-orders <chain-dir> [owner-or-agent] [status]\n  trade-status <chain-dir> <trade-id>\n  list-trades <chain-dir> [market] [limit]\n  orderbook <chain-dir> <market> [depth]\n  asset-balance <chain-dir> <asset> <address>\n  list-assets <chain-dir>\n  asset-register <chain-dir> <asset> <name>  (dev/regtest manual-mint networks only)\n  asset-credit <chain-dir> <asset> <address> <amount>  (dev/regtest only)\n  agent-limits <chain-dir> <agent-address>\n  trading-info <chain-dir>\n  create-order-raw-tx <chain-dir> <agent> <owner> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-external-order-raw-tx <chain-dir> <agent> <owner> <venue> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-order-cancel-raw-tx <chain-dir> <agent> <owner> <order_id> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  create-order-replace-raw-tx <chain-dir> <agent> <owner> <order_id> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]\n  velocity-info <chain-dir>\n"
         "  create-velocity-raw-tx <chain-dir> <from> <to> <amount> <ed_pub_hex> <mldsa_pub_b64> <tx_type> <lane_id> <expiry_height> <payload> [fee] [nonce]\n"
         "  decay-bans <node-dir> [points]\n  state-check <chain-dir>\n  snapshot-state <chain-dir> [label]\n  reindex-state <chain-dir>\n  stake <chain-dir> <wallet-dir> <amount>\n  unstake <chain-dir> <wallet-dir> <amount> [unbonding-secs]\n  claim-unbonded <chain-dir> <wallet-dir>\n  delegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount>\n  undelegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount> [unbonding-secs]\n  claim-undelegated <chain-dir> <delegator-wallet-dir> <validator-address>\n  staking-status <chain-dir> [address]\n  validator-set <chain-dir>\n  reward-epoch <chain-dir> <reward-amount> [validator-commission-bps]\n  slash <chain-dir> <validator-address> <amount> <reason>\n");
    puts("Phase 4F.2: create-arbitrage-hedge-raw-tx <chain-dir> <agent> <owner> <matched-crosschain-buy-order> <arbitrage-id> <quantity-sats> <limit-price-atoms> <order-expiry> <agent-ed-pub> <agent-mldsa-pub> <lane> <tx-expiry> [fee] [nonce]");
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
    if (env && *env) { snprintf(buf, bufsz, "%s", env); return 0; }
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
static int write_wallet_manifest(const char *dir, const char *address, int has_recovery) {
    char path[1024], manifest[4096];
    snprintf(manifest, sizeof(manifest),
        "{\n"
        "  \"wallet_version\": 12,\n"
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
    if (write_wallet_manifest(dir, addr, 1) != 0) die("wallet manifest failed");
    printf("address=%s\n", addr);
    printf("recovery_phrase=%s\n", mn);
    puts("IMPORTANT: Write the recovery phrase down offline. Anyone with the phrase and recovery file can restore the wallet.");
    OPENSSL_cleanse(pass1, sizeof(pass1)); OPENSSL_cleanse(pass2, sizeof(pass2));
    OPENSSL_cleanse(entropy, sizeof(entropy));
    free(mn); free(addr); EVP_PKEY_free(ed); EVP_PKEY_free(ml); return 0;
}
static int wallet_info_cmd(const char *dir) {
    char path[1024]; snprintf(path, sizeof(path), "%s/wallet.json", dir); char *manifest = read_file(path, NULL); if (!manifest) die("missing wallet.json");
    char *addr = wallet_address(dir); if (!addr) die("missing address");
    snprintf(path, sizeof(path), "%s/recovery.qrxseed", dir);
    printf("address=%s\n", addr);
    printf("manifest=%s\n", manifest ? "present" : "missing");
    printf("recovery_file=%s\n", access_qrx(path, F_OK) == 0 ? "present" : "missing");
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

    if(wallet_addresses_index_add(dir, addr) != 0) die("address index write failed");
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
    long long max_supply = chain_cfg_ll_or_default(chain_dir, "max_supply_atoms", 2100000000000000LL);
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
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    long long self = kv_get_ll_bin(stakes, validator);
    return self >= min_validator_stake_at(chain_dir, height);
}

static void record_validator_seen(const char *chain_dir, const char *validator, long long height) {
    char last_seen[1024]; validator_activity_paths(chain_dir, last_seen, sizeof(last_seen), NULL, 0, NULL, 0);
    kv_set_ll_bin(last_seen, validator, height);
}

static int apply_offline_penalties(const char *chain_dir, long long height) {
    long long after = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_penalty_after_blocks", 100);
    long long interval = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_penalty_interval_blocks", 100);
    long long bps = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_penalty_bps", 100);
    long long jail_secs = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "offline_jail_seconds", 3600);
    if (after <= 0 || interval <= 0 || bps <= 0) return 0;

    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024], penalties[1024];
    char last_seen[1024], last_penalty[1024], jailed[1024], tomb[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), penalties, sizeof(penalties));
    validator_activity_paths(chain_dir, last_seen, sizeof(last_seen), last_penalty, sizeof(last_penalty), NULL, 0);
    jail_paths(chain_dir, jailed, sizeof(jailed), tomb, sizeof(tomb));

    StateKVRecord *arr = NULL; size_t n = 0;
    if (kv_load(stakes, &arr, &n) != 0) return 0;
    int applied = 0;
    for (size_t i=0; i<n; ++i) {
        const char *validator = arr[i].key;
        long long self = arr[i].value;
        if (self <= 0) continue;
        if (validator_is_tombstoned(chain_dir, validator)) continue;
        if (!validator_has_min_self_stake_at(chain_dir, validator, height)) continue;
        long long seen = kv_get_ll_bin(last_seen, validator);
        if (seen <= 0) {
            kv_set_ll_bin(last_seen, validator, height);
            continue;
        }
        long long missed = height - seen;
        if (missed < after) continue;
        long long lastp = kv_get_ll_bin(last_penalty, validator);
        if (lastp > 0 && height - lastp < interval) continue;
        long long power = validator_power_total(chain_dir, validator);
        long long amount = (power * bps) / 10000;
        if (amount <= 0 && power > 0) amount = 1;
        if (amount <= 0) continue;
        slash_cmd(chain_dir, validator, amount, "offline", 1);
        kv_set_ll_bin(last_penalty, validator, height);
        if (jail_secs > 0) kv_set_ll_bin(jailed, validator, (long long)time(NULL) + jail_secs);
        journal_append(chain_dir, "offline_penalty validator=%s height=%lld last_seen=%lld missed=%lld amount=%lld bps=%lld jail_seconds=%lld", validator, height, seen, missed, amount, bps, jail_secs);
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
static int validator_snapshot_write(const char *chain_dir, long long height, long long round) {
    char dir[1024]; snprintf(dir, sizeof(dir), "%s/consensus/snapshots", chain_dir); mkdir_p(dir);
    char path[1024]; snprintf(path, sizeof(path), "%s/%lld-%lld.validators", dir, height, round);
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    StateKVRecord *arr = NULL; size_t n = 0; if (kv_load(stakes, &arr, &n) != 0) return -1;
    FILE *f = fopen(path, "wb"); if (!f) { free(arr); return -1; }
    for (size_t i=0;i<n;i++) {
        if (arr[i].value <= 0) continue;
        const char *validator = arr[i].key;
        if (validator_is_tombstoned(chain_dir, validator) || validator_is_jailed_now(chain_dir, validator)) continue;
        if (!validator_has_min_self_stake_at(chain_dir, validator, height)) continue;
        long long self = arr[i].value, delegated = kv_get_ll_bin(totals, validator), power = self + delegated;
        if (power <= 0) continue;
        fprintf(f, "validator=%s self=%lld delegated=%lld power=%lld\n", validator, self, delegated, power);
    }
    fclose(f); free(arr); return 0;
}
static long long validator_power_from_snapshot(const char *chain_dir, long long height, long long round, const char *validator) {
    char path[1024]; snprintf(path, sizeof(path), "%s/consensus/snapshots/%lld-%lld.validators", chain_dir, height, round);
    char *txt = read_file(path, NULL); if (!txt) return validator_power_total(chain_dir, validator);
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
static int chain_init(const char *dir, long long penalty_threshold, long long redistribute_bps, long long max_supply_atoms, long long epoch_reward_atoms, long long faucet_cap_atoms, const char *network_id_in, const char *protocol_version_in, const char *magic_in, const char *chain_name_in, long long block_time_seconds, long long max_txs_per_block, long long max_block_bytes, long long max_tx_bytes, long long validator_reward_percent, long long delegator_reward_percent, long long network_pool_percent) {
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
    snprintf(p, sizeof(p), "%s/state/double_signs.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/double_sign_blocks.txt", dir); write_text(p, "");
    snprintf(p, sizeof(p), "%s/state/jailed.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/tombstoned.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/supply.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/fee_pool.bin", dir); write_file(p, "", 0);
    snprintf(p, sizeof(p), "%s/state/journal.log", dir); write_text(p, "");
    supply_set(dir, "minted_supply", 0); supply_set(dir, "faucet_minted", 0); supply_set(dir, "rewards_minted", 0); supply_set(dir, "burned_supply", 0); supply_set(dir, "redistributed_supply", 0);
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

static int reindex_state_cmd(const char *chain_dir) {
    char bal[1024], nonce[1024], appl[1024], journal[1024];
    state_paths(chain_dir, bal, sizeof(bal), nonce, sizeof(nonce), appl, sizeof(appl), journal, sizeof(journal));
    atomic_write_file(bal, "", 0); atomic_write_file(nonce, "", 0); atomic_write_file(appl, "", 0); write_text(journal, "");
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "ls -1 '%s/blocks'/*.block 2>/dev/null | sort", chain_dir);
    FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("reindex list failed");
    char blkpath[1024];
    while (fgets(blkpath, sizeof(blkpath), fp)) {
        blkpath[strcspn(blkpath, "\r\n")] = 0; if (!*blkpath) continue;
        char *blk = read_file(blkpath, NULL); if (!blk) continue;
        for (int i=1; i<100000; i++) {
            char key[32]; snprintf(key, sizeof(key), "tx%d", i);
            char *txhash = cfg_get(blk, key); if (!txhash) break;
            applied_add_bin(appl, txhash); free(txhash);
        }
        free(blk);
        qrxdb_chain_ingest_block_file(chain_dir, blkpath);
    }
    pclose_qrx(fp);
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
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "find '%s/mempool' -maxdepth 1 -type f 2>/dev/null | wc -l", node_dir);
    FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("mempool status failed"); long long count=0;fscanf(fp,"%lld",&count);pclose_qrx(fp);
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
        "BTC_SPV_HEADER", "BTC_SPV_FUNDING_PROOF", NULL
    };
    if (!tx_type || !*tx_type) return 0;
    for (size_t i = 0; types[i]; ++i) if (!strcmp(types[i], tx_type)) return 1;
    return 0;
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
    char a[32]; asset_id_normalize(asset,a,sizeof(a));
    if (!strcmp(a,"QUB")) return 1;
    if (!asset_id_valid(a)) return 0;
    char path[1024], key[128]; asset_registry_path(chain_dir,path,sizeof(path)); snprintf(key,sizeof(key),"asset.%s.status",a);
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

static int list_assets_cmd(const char *chain_dir){
    puts("asset=QUB name=QUBITCOIN decimals=8 status=active native=true");
    char path[1024];asset_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);if(!txt)return 0;const char *cur=txt;const char suffix[]=".status=";
    while(cur&&*cur){const char *e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);if(len>6&&!strncmp(cur,"asset.",6)){
        const char *suf=NULL;for(size_t i=6;i+strlen(suffix)<len;++i)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}
        if(suf){size_t alen=(size_t)(suf-(cur+6));char a[32];if(alen<sizeof(a)){memcpy(a,cur+6,alen);a[alen]=0;if(strncmp(suf+strlen(suffix),"active",6)==0){char key[128];snprintf(key,sizeof(key),"asset.%s.name",a);char *name=text_db_get(path,key);printf("asset=%s name=%s decimals=8 status=active native=true\n",a,name?name:"");if(name)free(name);}}}}
        cur=e?e+1:NULL;
    }free(txt);return 0;
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

static int sign_cmd(const char *wallet_dir, const char *chain_dir, const char *to, const char *amount, const char *memo, const char *tx_file) {
    char pass[256]; if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");
    char p[1024];
    snprintf(p, sizeof(p), "%s/ed25519_priv.pem", wallet_dir); EVP_PKEY *ed_priv = load_priv_pem(p, pass); if (!ed_priv) die("load ed priv failed");
    snprintf(p, sizeof(p), "%s/mldsa65_priv.pem", wallet_dir); EVP_PKEY *ml_priv = load_priv_pem(p, pass); if (!ml_priv) die("load mldsa priv failed");
    snprintf(p, sizeof(p), "%s/ed25519_pub.pem", wallet_dir); EVP_PKEY *ed_pub = load_pub_pem(p); if (!ed_pub) die("load ed pub failed");
    snprintf(p, sizeof(p), "%s/mldsa65_pub.pem", wallet_dir); EVP_PKEY *ml_pub = load_pub_pem(p); if (!ml_pub) die("load mldsa pub failed");

    char *from = wallet_address(wallet_dir); if (!from) die("missing wallet address");
    from[strcspn(from, "\r\n")] = 0;
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

static int verify_tx_text(const char *chain_dir, const char *tx) {
    char *tx_version = cfg_get(tx, "tx_version");
    int is_velocity = tx_version && atoi(tx_version) == QRX_VELOCITY_TX_VERSION;
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
    int is_transfer = !is_agent_tx && !is_trade_tx && !is_gateway_tx && !is_execution_report && !is_crosschain_order && !is_crosschain_action && !is_btc_spv_header && !is_btc_spv_proof;
    if (is_velocity && !is_agent_tx && !is_trade_tx && !is_gateway_tx && !is_execution_report && !is_crosschain_order && !is_crosschain_action && !is_btc_spv_header && !is_btc_spv_proof && (!tx_type || strcmp(tx_type, "TRANSFER_FAST") != 0)) die("velocity execution not active for this tx_type");
    if (!from || !*from || !to || !*to || !body_hash || !*body_hash) die("invalid tx addresses/hash");
    if((is_trade_tx || is_crosschain_order) && !strcmp(from,to)) die("trading agent must use a distinct delegated address from the owner wallet");

    long long amt = is_transfer ? parse_positive_ll_strict(amount, "amount") : parse_nonnegative_ll_strict(amount, "amount");
    long long fee = fee_s ? parse_nonnegative_ll_strict(fee_s, "fee") : 0; long long n = parse_positive_ll_strict(nonce, "nonce");
    long long debit = 0; checked_add_ll(is_transfer ? amt : 0, fee, "amount plus fee", &debit);
    long long height=current_height_from_chain(chain_dir);
    long long current_nonce = velocity_get_lane_nonce(chain_dir, from, lane); if (current_nonce == LLONG_MAX) die("nonce overflow"); if (n != current_nonce + 1) die("invalid nonce: expected lane nonce + 1");

    long long frombal=qrx_balance_get_authoritative(chain_dir,from),tobal=qrx_balance_get_authoritative(chain_dir,to),new_frombal=0,new_tobal=tobal;
    if(frombal<debit) die("insufficient funds");
    if(is_transfer && !strcmp(from,to)){
        /* Self transfer must not mint amount back over the sender debit. The
           economic effect is only the fee. Verification still requires the
           wallet to cover amount+fee, preserving the historical admission rule. */
        checked_add_ll(frombal,-fee,"self-transfer fee",&new_frombal);new_tobal=new_frombal;
    }else{
        checked_add_ll(frombal,-debit,"sender balance",&new_frombal);
        if(is_transfer) checked_add_ll(tobal,amt,"recipient balance",&new_tobal);
    }
    if(is_crosschain_action){
        char *sid=payload_get_field(payload_apply,"session_id");
        long long locked=sid?crosschain_get_ll(chain_dir,sid,"qrx_locked_atoms",0):0;
        if(sid)free(sid);
        if(locked<=0)die("cross-chain session has no locked QUB");
        checked_add_ll(new_frombal,locked,"cross-chain QUB release",&new_frombal);
    }
    long long fee_pending=fee_pool_pending(chain_dir),new_fee_pending=0;checked_add_ll(fee_pending,fee,"fee pool",&new_fee_pending);

    QrxDB db;QrxDBBatch batch;if(qrxdb_init(&db,chain_dir)!=0)die("QRXDB init failed");if(qrxdb_batch_begin(&db,&batch)!=0){qrxdb_close(&db);die("QRXDB batch begin failed");}
    int brc=0;
    brc|=atomic_batch_put_balance(&batch,from,new_frombal);
    if(is_transfer && strcmp(from,to)) brc|=atomic_batch_put_balance(&batch,to,new_tobal);
    if(is_agent_tx) brc|=atomic_stage_agent(&batch,from,to,tx_type,payload_apply,body_hash,height);
    if(is_trade_tx) brc|=atomic_stage_trade(&batch,chain_dir,from,to,tx_type,payload_apply,body_hash,height);
    if(is_crosschain_order) brc|=crosschain_stage_order(&batch,chain_dir,from,to,payload_apply,body_hash,height);
    if(is_crosschain_action) brc|=crosschain_stage_action(&batch,chain_dir,from,tx_type,payload_apply,body_hash,height);
    if(is_btc_spv_header) brc|=atomic_stage_btc_spv_header(&db,&batch,chain_dir,payload_apply);
    if(is_btc_spv_proof) brc|=atomic_stage_btc_spv_funding_proof(&batch,chain_dir,from,payload_apply,body_hash,height);
    if(is_gateway_tx) brc|=atomic_stage_gateway(&batch,from,to,tx_type,payload_apply,body_hash,height);
    if(is_execution_report) brc|=atomic_stage_execution_report(&batch,from,to,payload_apply,body_hash,height);
    brc|=velocity_batch_put_ll(&batch,"consensus:fee_pool:pending",new_fee_pending);
    brc|=atomic_batch_put_nonce(&batch,from,lane,n);
    brc|=atomic_batch_put_applied(&batch,body_hash,height);
    const char *kind=is_agent_tx?"velocity-agent":is_crosschain_order?"velocity-crosschain-order":is_crosschain_action?"velocity-crosschain-settlement":is_btc_spv_header?"velocity-btc-spv-header":is_btc_spv_proof?"velocity-btc-spv-funding-proof":is_trade_tx?"velocity-trading-intent":is_gateway_tx?"velocity-gateway":is_execution_report?"velocity-execution-report":(is_velocity?"velocity-transfer-fast":"mempool-or-direct-apply");
    brc|=atomic_batch_put_tx_index(&batch,body_hash,kind,height,tx);
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

    journal_append(chain_dir, "applytx_atomic generation=%llu state_root=%s height=%lld timestamp=%s tx_version=%s tx_type=%s from=%s to=%s amount=%lld fee=%lld lane=%lld nonce=%s body_hash=%s", generation,state_root,height,timestamp?timestamp:"0",tx_version?tx_version:"2", tx_type?tx_type:"LEGACY_TRANSFER", from, to, amt, fee, lane, nonce, body_hash);
    printf("APPLIED\nstate_root=%s\nqrxdb_generation=%llu\n",state_root,generation);
    free(tx); if(tx_version) free(tx_version); if(tx_type) free(tx_type); if(lane_id) free(lane_id); if(payload_apply) free(payload_apply); free(from); free(to); free(amount); if (fee_s) free(fee_s); free(nonce); if(timestamp) free(timestamp); if (body_hash_sha3) free(body_hash_sha3); if (body_hash_legacy) free(body_hash_legacy); return 0;
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
    char cfg[4096]; snprintf(cfg, sizeof(cfg),
        "chain_dir=%s\nwallet_dir=%s\nhost=%s\nport=%s\nexternal_host=%s\nexternal_port=%s\nnetwork_id=%s\ngenesis_hash=%s\nprotocol_version=%s\nconsensus_version=%s\nchain_id=%s\nmagic=%s\naddress=%s\n",
        chain_dir, wallet_dir, host, port, host, port, network_id, genesis_hash, protocol_version, consensus_version, chain_id, magic, address);
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
static int add_peer_cmd(const char *node_dir, const char *host, const char *port) {
    char p[1024]; snprintf(p, sizeof(p), "%s/peers.txt", node_dir);
    if (unique_append_peerfile(p, host, port) != 0) return -1;
    return remember_known_peer(node_dir, host, port);
}
static int add_seed_cmd(const char *node_dir, const char *host, const char *port) {
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
                if (colon) { *colon = 0; if (unique_append_peerfile(peers, line, colon+1) == 0) merged++; }
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

static int request_peers_from_peer(const char *node_dir, const char *host, int port, int *added) {
    int fd = connect_to(host, port); if (fd < 0) return -1;
    char *hello = NULL; build_hello_message(node_dir, &hello); if (send_framed(fd, hello) != 0) { free(hello); qrx_close_socket(fd); return -1; } free(hello);
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
                    char *colon = strrchr(line, ':'); if (colon) { *colon=0; if (remember_known_peer(node_dir, line, colon+1) == 0) { char pp[1024]; snprintf(pp, sizeof(pp), "%s/peers.txt", node_dir); unique_append_peerfile(pp, line, colon+1); if (added) (*added)++; } }
                }
                cur = e ? e+1 : NULL;
            }
            free(txt); free(buf);
        }
        free(peers_b64);
    }
    free(status); free(resp); qrx_close_socket(fd); return 0;
}

static int bootstrap_cmd(const char *node_dir) {
    char seeds[1024], known[1024], peers[1024], cache[1024];
    snprintf(seeds, sizeof(seeds), "%s/seednodes.txt", node_dir);
    snprintf(known, sizeof(known), "%s/known_peers.txt", node_dir);
    snprintf(peers, sizeof(peers), "%s/peers.txt", node_dir);
    snprintf(cache, sizeof(cache), "%s/bootstrap_cache.txt", node_dir);
    int contacted = 0, alive = 0, added = 0;
    for (int pass=0; pass<3; ++pass) {
        const char *src = pass == 0 ? seeds : (pass == 1 ? known : peers);
        char *txt = read_file(src, NULL); if (!txt) continue;
        const char *cur = txt;
        while (cur && *cur) {
            const char *e = strchr(cur, '\n'); size_t len = e ? (size_t)(e-cur) : strlen(cur);
            if (len > 0) {
                char line[256]; if (len >= sizeof(line)) len = sizeof(line)-1; memcpy(line, cur, len); line[len]=0;
                char *colon = strrchr(line, ':'); if (colon) {
                    *colon = 0; int port = atoi(colon+1); contacted++;
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

static int build_hello_message(const char *node_dir, char **out_msg) {
    char path[1024]; snprintf(path, sizeof(path), "%s/node.conf", node_dir); char *cfg = read_file(path, NULL); if (!cfg) die("missing node.conf");
    char *wallet_dir = cfg_get(cfg, "wallet_dir"), *network_id = cfg_get(cfg, "network_id"), *genesis_hash = cfg_get(cfg, "genesis_hash"), *protocol_version = cfg_get(cfg, "protocol_version"), *consensus_version = cfg_get(cfg, "consensus_version"), *chain_id = cfg_get(cfg, "chain_id"), *magic = cfg_get(cfg, "magic"), *host = cfg_get(cfg, "host"), *port = cfg_get(cfg, "port"), *external_host = cfg_get(cfg, "external_host"), *external_port = cfg_get(cfg, "external_port");
    char pass[256]; if (get_passphrase(pass, sizeof(pass), "Passphrase: ") != 0) die("passphrase failed");
    snprintf(path, sizeof(path), "%s/ed25519_priv.pem", wallet_dir); EVP_PKEY *priv = load_priv_pem(path, pass); if (!priv) die("load node signing key failed");
    snprintf(path, sizeof(path), "%s/ed25519_pub.pem", wallet_dir); EVP_PKEY *pub = load_pub_pem(path); if (!pub) die("load node pub failed");
    unsigned char raw[32]; if (ed25519_raw_pub(pub, raw) != 0) die("raw pub failed");
    char *pub_hex = bytes_to_hex(raw, sizeof(raw));
    char ts[32], nonce[32]; snprintf(ts, sizeof(ts), "%lld", (long long)time(NULL)); unsigned char nr[8]; RAND_bytes(nr, sizeof(nr)); for (int i=0;i<8;i++) snprintf(nonce+i*2, 3, "%02x", nr[i]);
    const char *adv_host = (external_host && *external_host) ? external_host : host;
    const char *adv_port = (external_port && *external_port) ? external_port : port;
    char *payload = hello_payload_for_sign(network_id, genesis_hash, protocol_version, consensus_version, chain_id, magic, ts, nonce, adv_host, adv_port, pub_hex);
    unsigned char *sig=NULL; size_t siglen=0; if (sign_oneshot(priv, (unsigned char*)payload, strlen(payload), &sig, &siglen) != 0) die("hello sign failed");
    char *sig_hex = bytes_to_hex(sig, siglen); size_t cap = strlen(payload)+strlen(sig_hex)+64; *out_msg = malloc(cap); snprintf(*out_msg, cap, "%ssig_ed25519_hex=%s\n", payload, sig_hex);
    free(cfg); free(wallet_dir); free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id); free(magic); free(host); free(port); if (external_host) free(external_host); if (external_port) free(external_port); free(pub_hex); free(payload); free(sig); free(sig_hex); EVP_PKEY_free(priv); EVP_PKEY_free(pub); OPENSSL_cleanse(pass, sizeof(pass));
    return 0;
}

static int verify_hello_msg(const char *node_conf_text, const char *msg) {
    char *network_id = cfg_get(msg, "network_id"), *genesis_hash = cfg_get(msg, "genesis_hash"), *protocol_version = cfg_get(msg, "protocol_version"), *consensus_version = cfg_get(msg, "consensus_version"), *chain_id = cfg_get(msg, "chain_id"), *magic = cfg_get(msg, "magic"), *timestamp = cfg_get(msg, "timestamp"), *nonce = cfg_get(msg, "nonce"), *host = cfg_get(msg, "host"), *port = cfg_get(msg, "port"), *pub_hex = cfg_get(msg, "ed25519_pub_hex"), *sig_hex = cfg_get(msg, "sig_ed25519_hex");
    if (!network_id||!genesis_hash||!protocol_version||!consensus_version||!chain_id||!magic||!timestamp||!nonce||!host||!port||!pub_hex||!sig_hex) return -1;
    char *exp_net = cfg_get(node_conf_text, "network_id"), *exp_gen = cfg_get(node_conf_text, "genesis_hash"), *exp_ver = cfg_get(node_conf_text, "protocol_version"), *exp_cons = cfg_get(node_conf_text, "consensus_version"), *exp_chain = cfg_get(node_conf_text, "chain_id"), *exp_magic = cfg_get(node_conf_text, "magic");
    if (strcmp(network_id, exp_net) || strcmp(genesis_hash, exp_gen) || strcmp(protocol_version, exp_ver) || strcmp(consensus_version, exp_cons) || strcmp(chain_id, exp_chain) || strcmp(magic, exp_magic)) return -1;
    long long ts = atoll(timestamp), now = (long long)time(NULL); if (llabs(now - ts) > 300) return -1;
    char *payload = hello_payload_for_sign(network_id, genesis_hash, protocol_version, consensus_version, chain_id, magic, timestamp, nonce, host, port, pub_hex);
    unsigned char raw[32]; size_t rawlen=0; if (hex_to_bytes(pub_hex, raw, sizeof(raw), &rawlen) != 0 || rawlen != 32) return -1;
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, rawlen); if (!pub) return -1;
    unsigned char *sig = malloc(strlen(sig_hex)/2+1); size_t siglen=0; if (hex_to_bytes(sig_hex, sig, strlen(sig_hex)/2+1, &siglen) != 0) return -1;
    int ok = verify_oneshot(pub, (unsigned char*)payload, strlen(payload), sig, siglen) == 0 ? 0 : -1;
    EVP_PKEY_free(pub); free(sig); free(payload); free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id); free(magic); free(timestamp); free(nonce); free(host); free(port); free(pub_hex); free(sig_hex); free(exp_net); free(exp_gen); free(exp_ver); free(exp_cons); free(exp_chain); free(exp_magic);
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
    if (ann_host && ann_port) { remember_known_peer(node_dir, ann_host, ann_port); peer_rep_add(node_dir, ann_host, 1); peer_touch_seen(node_dir, ann_host, (long long)time(NULL)); }
    send_framed(fd, "status=OK\n"); free(msg);

    if (!peer_rate_allow(node_dir, ip)) { peer_add_score(node_dir, ip, 50); send_framed(fd, "status=ERR\nreason=rate_limited\n"); if (ann_host) free(ann_host); if (ann_port) free(ann_port); free(node_cfg); return; }
    msg = recv_framed(fd); if (!msg) { if (ann_host) free(ann_host); if (ann_port) free(ann_port); free(node_cfg); return; }
    if (strstr(msg, "type=TX\n") == msg) {
        char *tx_b64 = cfg_get(msg, "tx_b64");
        if (!tx_b64) { peer_add_score(node_dir, ip, 10); send_framed(fd, "status=ERR\nreason=no_tx\n"); free(msg); free(node_cfg); return; }
        size_t txlen=0; unsigned char *txbuf = base64_decode(tx_b64, &txlen);
        if (!txbuf) { peer_add_score(node_dir, ip, 10); send_framed(fd, "status=ERR\nreason=bad_b64\n"); free(tx_b64); free(msg); free(node_cfg); return; }
        char *tx = malloc(txlen+1); memcpy(tx, txbuf, txlen); tx[txlen]=0;
        char *chain_dir = cfg_get(node_cfg, "chain_dir");
        int ok = verify_tx_text(chain_dir, tx);
        if (ok == 0 && node_store_mempool_tx(node_dir, tx) == 0) send_framed(fd, "status=OK\nkind=tx\n");
        else { peer_add_score(node_dir, ip, 30); send_framed(fd, "status=ERR\nreason=bad_tx\n"); }
        free(chain_dir); free(tx_b64); free(txbuf); free(tx);
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
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
    qrx_set_socket_timeout(fd, SOCKET_IO_TIMEOUT_SECS);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { qrx_close_socket(fd); return -1; }
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { qrx_close_socket(fd); return -1; }
    return fd;
}

static int sendtx_to_peer(const char *node_dir, const char *tx_text, const char *host, int port) {
    int fd = connect_to(host, port); if (fd < 0) return -1;
    char *hello = NULL; build_hello_message(node_dir, &hello); if (send_framed(fd, hello) != 0) { free(hello); qrx_close_socket(fd); return -1; } free(hello);
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
    int s = socket(AF_INET, SOCK_STREAM, 0); if (s < 0) die("socket failed");
    int one=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    qrx_set_socket_timeout(s, SOCKET_IO_TIMEOUT_SECS);
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port); inet_pton(AF_INET, host, &addr.sin_addr);
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) die("bind failed: %s", strerror(errno));
    if (listen(s, 16) != 0) die("listen failed");
    printf("node listening on %s:%d\n", host, port);
    while (!g_stop) {
        struct sockaddr_in cli; socklen_t clilen = sizeof(cli); int fd = accept(s, (struct sockaddr*)&cli, &clilen);
        if (fd < 0) { if (errno == EINTR) break; continue; }
        node_handle_client(fd, node_dir); qrx_close_socket(fd);
    }
    qrx_close_socket(s); free(cfg); free(host); free(port_s);
    if(g_velocity_mempool_ready){qrx_velocity_mempool_checkpoint(&g_velocity_mempool);qrx_velocity_mempool_close(&g_velocity_mempool);g_velocity_mempool_ready=0;}
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

static int vote_block_cmd(const char *node_dir, const char *block_file) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *chain_dir = cfg_get(cfg, "chain_dir"), *wallet_dir = cfg_get(cfg, "wallet_dir"), *network_id = cfg_get(cfg, "network_id"), *genesis_hash = cfg_get(cfg, "genesis_hash"), *protocol_version = cfg_get(cfg, "protocol_version"), *address = cfg_get(cfg, "address");
    if (verify_block_cmd(chain_dir, block_file) != 0) die("block verify failed");
    if (validator_is_tombstoned(chain_dir, address)) die("validator tombstoned");
    if (validator_is_jailed_now(chain_dir, address)) die("validator jailed");
    char *block_hash=NULL, *validator=NULL, *height_s=NULL, *round_s=NULL; if (block_consensus_values(block_file, &block_hash, &validator, &height_s, &round_s) != 0) die("block values failed");
    long long power = validator_power_from_snapshot(chain_dir, atoll(height_s), atoll(round_s), address); if (power <= 0) die("validator not active in snapshot");
    char lockp[1024], votesdir[1024]; node_lock_paths(node_dir, lockp, sizeof(lockp), votesdir, sizeof(votesdir)); mkdir_p(votesdir);
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

static int tally_votes_cmd(const char *chain_dir, const char *block_file) {
    char *block_hash=NULL, *validator=NULL, *height_s=NULL, *round_s=NULL; if (block_consensus_values(block_file, &block_hash, &validator, &height_s, &round_s) != 0) die("block values failed");
    char dir[1024]; snprintf(dir, sizeof(dir), "%s/consensus/votes", chain_dir);
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "find '%s' -maxdepth 1 -type f -name '*.vote' 2>/dev/null", dir); FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("vote list failed");
    long long yes_power=0, total_power=snapshot_total_power(chain_dir, atoll(height_s), atoll(round_s)); char seen[512][385]; int seen_n=0; char fname[1024];
    while (fgets(fname, sizeof(fname), fp)) {
        fname[strcspn(fname, "\r\n")]=0; if (!*fname) continue; char vaddr[385]=""; long long pwr=0;
        if (verify_vote_file_internal(chain_dir, fname, block_hash, height_s, round_s, vaddr, sizeof(vaddr), &pwr) == 0) {
            int dup=0; for (int i=0;i<seen_n;i++) if (!strcmp(seen[i], vaddr)) { dup=1; break; }
            if (!dup && seen_n < 512) { snprintf(seen[seen_n++], sizeof(seen[0]), "%s", vaddr); yes_power += pwr; }
        }
    }
    pclose_qrx(fp);
    printf("block_hash=%s\nheight=%s\nround=%s\nyes_power=%lld\ntotal_power=%lld\nquorum=%s\n", block_hash, height_s, round_s, yes_power, total_power, (yes_power*3 > total_power*2) ? "1" : "0");
    free(block_hash); free(validator); free(height_s); free(round_s); return 0;
}

static int finalize_block_cmd(const char *chain_dir, const char *block_file) {
    char *block_hash=NULL, *validator=NULL, *height_s=NULL, *round_s=NULL; if (block_consensus_values(block_file, &block_hash, &validator, &height_s, &round_s) != 0) die("block values failed");
    char dir[1024]; snprintf(dir, sizeof(dir), "%s/consensus/votes", chain_dir);
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "find '%s' -maxdepth 1 -type f -name '*.vote' 2>/dev/null", dir); FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("vote list failed");
    long long yes_power=0, total_power=snapshot_total_power(chain_dir, atoll(height_s), atoll(round_s)); char seen[512][385]; int seen_n=0; char fname[1024];
    while (fgets(fname, sizeof(fname), fp)) {
        fname[strcspn(fname, "\r\n")]=0; if (!*fname) continue; char vaddr[385]=""; long long pwr=0;
        if (verify_vote_file_internal(chain_dir, fname, block_hash, height_s, round_s, vaddr, sizeof(vaddr), &pwr) == 0) {
            int dup=0; for (int i=0;i<seen_n;i++) if (!strcmp(seen[i], vaddr)) { dup=1; break; }
            if (!dup && seen_n < 512) { snprintf(seen[seen_n++], sizeof(seen[0]), "%s", vaddr); yes_power += pwr; }
        }
    }
    pclose_qrx(fp);
    if (!(yes_power*3 > total_power*2)) die("quorum not reached");
    char out[1024]; snprintf(out, sizeof(out), "%s/consensus/finalized/%s.final", chain_dir, height_s);
    char final[4096]; snprintf(final, sizeof(final), "height=%s\nround=%s\nblock_hash=%s\nblock_file=%s\nyes_power=%lld\ntotal_power=%lld\nfinalized_at=%lld\n", height_s, round_s, block_hash, block_file, yes_power, total_power, (long long)time(NULL));
    if (write_text(out, final) != 0) die("write finalization failed");
    record_validator_seen(chain_dir, validator, atoll(height_s));
    int offline_penalties = apply_offline_penalties(chain_dir, atoll(height_s));
    qrxdb_chain_ingest_block_file(chain_dir, block_file);
    journal_append(chain_dir, "finalize height=%s round=%s block_hash=%s yes_power=%lld total_power=%lld offline_penalties=%d", height_s, round_s, block_hash, yes_power, total_power, offline_penalties);
    printf("%s\noffline_penalties=%d\n", out, offline_penalties);
    free(block_hash); free(validator); free(height_s); free(round_s); return 0;
}

static int send_file_to_peer(const char *node_dir, const char *file_text, const char *kind, const char *host, int port) {
    int fd = connect_to(host, port); if (fd < 0) return -1;
    char *hello = NULL; build_hello_message(node_dir, &hello); if (send_framed(fd, hello) != 0) { free(hello); qrx_close_socket(fd); return -1; } free(hello);
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

static int node_process_inbox_cmd(const char *node_dir) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *chain_dir = cfg_get(cfg, "chain_dir");
    int processed_blocks=0, processed_votes=0, finalized=0;
    char cmd[2048], fname[1024];
    snprintf(cmd, sizeof(cmd), "find '%s/inbox/blocks' -maxdepth 1 -type f -name '*.block' 2>/dev/null", node_dir); FILE *fp = popen_qrx(cmd, "r");
    if (fp) {
        while (fgets(fname, sizeof(fname), fp)) {
            fname[strcspn(fname, "\r\n")]=0; if (!*fname) continue;
            if (verify_block_cmd(chain_dir, fname) == 0) {
                vote_block_cmd(node_dir, fname);
                processed_blocks++;
            }
            unlink_qrx(fname);
        }
        pclose_qrx(fp);
    }
    snprintf(cmd, sizeof(cmd), "find '%s/inbox/votes' -maxdepth 1 -type f -name '*.vote' 2>/dev/null", node_dir); fp = popen_qrx(cmd, "r");
    if (fp) {
        while (fgets(fname, sizeof(fname), fp)) {
            fname[strcspn(fname, "\r\n")]=0; if (!*fname) continue;
            char dest[1024], *txt = read_file(fname, NULL); if (txt) {
                char *height_s = cfg_get(txt, "height"), *validator = cfg_get(txt, "validator");
                if (height_s && validator) { snprintf(dest, sizeof(dest), "%s/consensus/votes/%s-%s.vote", chain_dir, height_s, validator); write_text(dest, txt); processed_votes++; }
                if (height_s) free(height_s); if (validator) free(validator); free(txt);
            }
            unlink_qrx(fname);
        }
        pclose_qrx(fp);
    }
    snprintf(cmd, sizeof(cmd), "find '%s/blocks' -maxdepth 1 -type f -name '*.block' 2>/dev/null | sort", chain_dir); fp = popen_qrx(cmd, "r");
    if (fp) {
        while (fgets(fname, sizeof(fname), fp)) {
            fname[strcspn(fname, "\r\n")]=0; if (!*fname) continue;
            char *block_hash=NULL, *validator=NULL, *height_s=NULL, *round_s=NULL; if (block_consensus_values(fname, &block_hash, &validator, &height_s, &round_s)==0) {
                char final_path[1024]; snprintf(final_path, sizeof(final_path), "%s/consensus/finalized/%s.final", chain_dir, height_s);
                if (access_qrx(final_path, F_OK) != 0) {
                    char outbuf[8192]; FILE *cap = NULL;
                    int oldfd = dup(1); int tmpfd = open("/tmp/qrx_null", O_WRONLY|O_CREAT|O_TRUNC, 0600); if (tmpfd >= 0) dup2(tmpfd,1);
                    int rc = finalize_block_cmd(chain_dir, fname); if (oldfd >= 0) { dup2(oldfd,1); qrx_close_file(oldfd); } if (tmpfd >= 0) qrx_close_file(tmpfd); unlink_qrx("/tmp/qrx_null");
                    if (rc == 0) finalized++;
                }
                free(block_hash); free(validator); free(height_s); free(round_s);
            }
        }
        pclose_qrx(fp);
    }
    printf("processed_blocks=%d\nprocessed_votes=%d\nfinalized=%d\n", processed_blocks, processed_votes, finalized);
    free(cfg); free(chain_dir); return 0;
}

static int propose_block_cmd(const char *node_dir, int max_txs) {
    char p[1024]; snprintf(p, sizeof(p), "%s/node.conf", node_dir); char *cfg = read_file(p, NULL); if (!cfg) die("missing node.conf");
    char *chain_dir = cfg_get(cfg, "chain_dir"), *address = cfg_get(cfg, "address"), *wallet_dir = cfg_get(cfg, "wallet_dir");
    char *network_id = cfg_get(cfg, "network_id"), *genesis_hash = cfg_get(cfg, "genesis_hash"), *protocol_version = cfg_get(cfg, "protocol_version"), *consensus_version = cfg_get(cfg, "consensus_version"), *chain_id = cfg_get(cfg, "chain_id");
    long long validator_power = validator_power_total(chain_dir, address);
    if (!validator_has_min_self_stake_at(chain_dir, address, current_height_from_chain(chain_dir) + 1)) die("validator self stake below minimum");
    if (validator_power <= 0) die("validator not active in current validator set");
    char height_cmd[2048]; snprintf(height_cmd, sizeof(height_cmd), "find '%s/blocks' -maxdepth 1 -type f -name '*.block' 2>/dev/null | wc -l", chain_dir);
    FILE *hfp = popen_qrx(height_cmd, "r"); long long cur_blocks = 0; if (hfp) { fscanf(hfp, "%lld", &cur_blocks); pclose_qrx(hfp); }
    long long height = cur_blocks + 1;
    long long round = 0;
    long long chain_max_txs = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "max_txs_per_block", 100);
    if (max_txs <= 0 || max_txs > chain_max_txs) max_txs = (int)chain_max_txs;
    if (validator_snapshot_write(chain_dir, height, round) != 0) die("validator snapshot write failed");
    char blockbuf[MAX_MSG]; size_t off = 0;
    off += snprintf(blockbuf+off, sizeof(blockbuf)-off,
        "network_id=%s\ngenesis_hash=%s\nprotocol_version=%s\nconsensus_version=%s\nchain_id=%s\nheight=%lld\nround=%lld\nvalidator=%s\nvalidator_power=%lld\ntimestamp=%lld\n",
        network_id, genesis_hash, protocol_version, consensus_version, chain_id, height, round, address, validator_power, (long long)time(NULL));
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
    qrxdb_chain_ingest_block_file(chain_dir, blk);
    printf("%s\n", blk);
    free(final); free(pub_hex); free(sig); free(sig_hex); EVP_PKEY_free(priv); EVP_PKEY_free(pub); OPENSSL_cleanse(pass, sizeof(pass));
    free(cfg); free(chain_dir); free(address); free(wallet_dir); free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id); return 0;
}

static int verify_block_cmd(const char *chain_dir, const char *block_file) {
    char *blk = read_file(block_file, NULL); if (!blk) die("cannot read block");
    char *network_id = cfg_get(blk, "network_id"), *genesis_hash = cfg_get(blk, "genesis_hash"), *protocol_version = cfg_get(blk, "protocol_version"), *consensus_version = cfg_get(blk, "consensus_version"), *chain_id = cfg_get(blk, "chain_id");
    char *height_s = cfg_get(blk, "height"), *round_s = cfg_get(blk, "round"), *validator = cfg_get(blk, "validator"), *validator_power_s = cfg_get(blk, "validator_power"), *tx_count_s = cfg_get(blk, "tx_count"), *block_hash = cfg_get(blk, "block_hash"), *hash_algo = cfg_get(blk, "hash_algo"), *block_hash_sha256_legacy = cfg_get(blk, "block_hash_sha256_legacy"), *sig_hex = cfg_get(blk, "block_sig_ed25519_hex"), *pub_hex = cfg_get(blk, "block_pub_ed25519_hex");
    if (!network_id||!genesis_hash||!protocol_version||!consensus_version||!chain_id||!validator||!validator_power_s||!block_hash||!sig_hex||!pub_hex||!height_s) die("invalid block fields");
    char *exp_net = chain_cfg_value(chain_dir, "network_id"), *exp_gen = chain_cfg_value(chain_dir, "genesis_hash"), *exp_ver = chain_cfg_value(chain_dir, "protocol_version"), *exp_cons = chain_cfg_value(chain_dir, "consensus_version"), *exp_chain = chain_cfg_value(chain_dir, "chain_id");
    if (strcmp(network_id, exp_net) || strcmp(genesis_hash, exp_gen) || strcmp(protocol_version, exp_ver) || strcmp(consensus_version, exp_cons) || strcmp(chain_id, exp_chain)) die("block network binding mismatch");
    long long height = atoll(height_s);
    long long max_block_bytes = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "max_block_bytes", 524288LL);
    long long max_txs_per_block = qrx_chain_get_ll_at_height_or_default(chain_dir, height, "max_txs_per_block", 100LL);
    size_t blk_len = strlen(blk);
    if ((long long)blk_len > max_block_bytes) die("block exceeds max_block_bytes");
    if (tx_count_s && atoll(tx_count_s) > max_txs_per_block) die("block exceeds max_txs_per_block");
    char *sig_line = strstr(blk, hash_algo ? "hash_algo=" : "block_hash="); if (!sig_line) die("invalid block file");
    size_t body_len = (size_t)(sig_line - blk);
    if (hash_algo) {
        char body_hash[129]; hash_primary_hex((unsigned char*)blk, body_len, body_hash); if (strcmp(body_hash, block_hash)) die("block hash mismatch");
        if (strcmp(hash_algo, "sha3-512") != 0) die("unsupported block hash algo");
        if (block_hash_sha256_legacy) { char body_hash_old[65]; hash_legacy_hex((unsigned char*)blk, body_len, body_hash_old); if (strcmp(body_hash_old, block_hash_sha256_legacy)) die("block legacy hash mismatch"); }
    } else {
        char body_hash[65]; hash_legacy_hex((unsigned char*)blk, body_len, body_hash); if (strcmp(body_hash, block_hash)) die("block hash mismatch");
    }
    unsigned char raw[32]; size_t rawlen=0; if (hex_to_bytes(pub_hex, raw, sizeof(raw), &rawlen) != 0 || rawlen != 32) die("bad block pub");
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, rawlen); if (!pub) die("block pub construct failed");
    if (address_matches_pub(pub, validator) != 0) die("validator address mismatch");
    long long current_power = validator_power_total(chain_dir, validator);
    if (!validator_has_min_self_stake_at(chain_dir, validator, height)) die("validator self stake below minimum");
    if (current_power <= 0) die("validator is not active in validator set");
    if (check_and_record_double_sign_block(chain_dir, validator, height_s, round_s ? round_s : "0", block_hash) != 0) die("double sign detected and slashed");
    if (atoll(validator_power_s) != current_power) die("validator power mismatch");
    unsigned char *sig = malloc(strlen(sig_hex)/2+1); size_t siglen=0; if (hex_to_bytes(sig_hex, sig, strlen(sig_hex)/2+1, &siglen) != 0) die("bad block sig");
    if (verify_oneshot(pub, (unsigned char*)blk, body_len, sig, siglen) != 0) die("block signature verify failed");
    puts("OK");
    EVP_PKEY_free(pub); free(sig); free(blk); free(network_id); free(genesis_hash); free(protocol_version); free(consensus_version); free(chain_id); if (height_s) free(height_s); if (round_s) free(round_s); if (tx_count_s) free(tx_count_s); free(validator); free(validator_power_s); free(block_hash); if (hash_algo) free(hash_algo); if (block_hash_sha256_legacy) free(block_hash_sha256_legacy); free(sig_hex); free(pub_hex); free(exp_net); free(exp_gen); free(exp_ver); free(exp_cons); free(exp_chain);
    return 0;
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
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    return kv_get_ll_bin(stakes, validator) + kv_get_ll_bin(totals, validator);
}

static int validator_is_active(const char *chain_dir, const char *validator) {
    return validator_power_total(chain_dir, validator) > 0 ? 1 : 0;
}


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

static int htlc_mainnet_gate(const char *chain_dir) {
    char *network_id = chain_cfg_value(chain_dir, "network_id");
    int is_mainnet = network_id && (strstr(network_id, "mainnet") || strstr(network_id, "Mainnet"));
    free(network_id);
    if (!is_mainnet) return 0;
    const char *enabled = getenv("QRX_ENABLE_MAINNET_HTLC");
    if (enabled && strcmp(enabled, "I_UNDERSTAND_EXPERIMENTAL") == 0) return 0;
    fprintf(stderr, "HTLC/Quantum Swaps are disabled on mainnet by default. Set QRX_ENABLE_MAINNET_HTLC=I_UNDERSTAND_EXPERIMENTAL only after audit/release approval.\n");
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


#define QUB_FEATURE_ACTIVATION_HEIGHT_STEALTH 1
#define QUB_FEATURE_ACTIVATION_HEIGHT_SHIELDED_POOL 1
#define QUB_FEATURE_AUDIT_STATUS "audit-pending"

static int privacy_feature_status_cmd(const char *chain_dir) {
    (void)chain_dir;
    printf("transparent_default=true\n");
    printf("exchange_deposits=transparent-only\n");
    printf("stealth_addresses=enabled-from-block-1\n");
    printf("shielded_pool=enabled-from-block-1-proof-audit-pending\n");
    printf("stealth_activation_height=%d\n", QUB_FEATURE_ACTIVATION_HEIGHT_STEALTH);
    printf("shielded_pool_activation_height=%d\n", QUB_FEATURE_ACTIVATION_HEIGHT_SHIELDED_POOL);
    printf("audit_status=%s\n", QUB_FEATURE_AUDIT_STATUS);
    printf("hybrid_signatures=ed25519-plus-mldsa65\n");
    printf("post_quantum_posture=quantum-resistant-in-mind-hybrid-signature-direction\n");
    printf("policy=transparent-default-optional-privacy-not-for-cex-deposits\n");
    return 0;
}

typedef struct {
    char tx_id[129];
    char sender[385];
    char stealth_address[512];
    char one_time_address[385];
    long long amount;
    char ephemeral_pub[129];
    char shared_tag[129];
    long long created_at;
    char status[32];
    char memo[256];
} StealthRecord;

static void stealth_paths(const char *chain_dir, char *db, size_t dsz, char *journal, size_t jsz) {
    if (db) snprintf(db, dsz, "%s/stealth_transfers.db", chain_dir);
    if (journal) snprintf(journal, jsz, "%s/stealth_journal.log", chain_dir);
}

static void stealth_seed_hash(const char *label, const char *input, char out[129]) {
    char buf[4096];
    snprintf(buf, sizeof(buf), "QUB-STEALTH-v1|%s|%s", label ? label : "", input ? input : "");
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
        EVP_PKEY_derive(ctx, shared, &outlen) == 1 &&
        outlen == 32) ret = 0;
    EVP_PKEY_CTX_free(ctx);
done:
    if (sk) EVP_PKEY_free(sk);
    if (pk) EVP_PKEY_free(pk);
    return ret;
}

static int stealth_wallet_keypair(const char *wallet_dir, const char *label, unsigned char priv[32], unsigned char pub[32]) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/ed25519_priv.pem", wallet_dir);
    const char *pass = getenv("QRX_PASSPHRASE");
    EVP_PKEY *ed = pass ? load_priv_pem(path, pass) : NULL;

    unsigned char material[128];
    size_t material_len = 0;
    if (ed && ed25519_raw_priv(ed, material) == 0) {
        material_len = 32;
        EVP_PKEY_free(ed);
    } else {
        if (ed) EVP_PKEY_free(ed);
        char *addr = wallet_address(wallet_dir);
        if (!addr) return -1;
        snprintf((char*)material, sizeof(material), "%s", addr);
        material_len = strlen((char*)material);
        free(addr);
    }

    unsigned char digest[64];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, "QUB-X25519-STEALTH-v2|", 24) != 1 ||
        EVP_DigestUpdate(ctx, label, strlen(label)) != 1 ||
        EVP_DigestUpdate(ctx, material, material_len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    memcpy(priv, digest, 32);
    /* X25519 private key clamping */
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    return stealth_x25519_pub_from_priv(priv, pub);
}

static int stealth_make_address_from_wallet_dir(const char *wallet_dir, char out[512]) {
    unsigned char scan_priv[32], scan_pub[32], spend_priv[32], spend_pub[32];
    char scan_hex[65], spend_hex[65];
    if (stealth_wallet_keypair(wallet_dir, "scan", scan_priv, scan_pub) != 0) return -1;
    if (stealth_wallet_keypair(wallet_dir, "spend", spend_priv, spend_pub) != 0) return -1;
    bytes_to_hex_local(scan_pub, 32, scan_hex);
    bytes_to_hex_local(spend_pub, 32, spend_hex);
    snprintf(out, 512, "squb1%s%s", scan_hex, spend_hex);
    return 0;
}

static void stealth_make_address_from_wallet(const char *wallet_addr, char out[512]) {
    char scan[129], spend[129];
    stealth_seed_hash("scan-pub-legacy", wallet_addr, scan);
    stealth_seed_hash("spend-pub-legacy", wallet_addr, spend);
    snprintf(out, 512, "squb1%s%s", scan, spend);
}

static int stealth_split_address(const char *saddr, char scan[129], char spend[129]) {
    if (!saddr || strncmp(saddr, "squb1", 5) != 0) return -1;
    size_t n = strlen(saddr + 5);
    if (n != 128 && n != 256) return -1;
    size_t half = n / 2;
    memcpy(scan, saddr + 5, half); scan[half] = 0;
    memcpy(spend, saddr + 5 + half, half); spend[half] = 0;
    for (size_t i=0;i<half;i++) {
        if (!isxdigit((unsigned char)scan[i]) || !isxdigit((unsigned char)spend[i])) return -1;
    }
    return 0;
}

static void stealth_make_shared(const char *scan_pub, const char *ephemeral_secret, char out[129]) {
    char buf[2048];
    snprintf(buf, sizeof(buf), "shared|%s|%s", scan_pub, ephemeral_secret);
    stealth_seed_hash("shared-secret", buf, out);
}

static void stealth_make_one_time_address(const char *spend_pub, const char *shared, char out[385]) {
    char h[129];
    char buf[2048];
    snprintf(buf, sizeof(buf), "one-time|%s|%s", spend_pub, shared);
    stealth_seed_hash("one-time-address", buf, h);
    snprintf(out, 385, "qrx1stealth%s", h);
}

static int stealth_parse_line(const char *line, StealthRecord *r) {
    if (!line || !r) return -1;
    char buf[4096];
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
    snprintf(r->tx_id, sizeof(r->tx_id), "%s", fields[0] ? fields[0] : "");
    snprintf(r->sender, sizeof(r->sender), "%s", fields[1] ? fields[1] : "");
    snprintf(r->stealth_address, sizeof(r->stealth_address), "%s", fields[2] ? fields[2] : "");
    snprintf(r->one_time_address, sizeof(r->one_time_address), "%s", fields[3] ? fields[3] : "");
    r->amount = atoll(fields[4] ? fields[4] : "0");
    snprintf(r->ephemeral_pub, sizeof(r->ephemeral_pub), "%s", fields[5] ? fields[5] : "");
    snprintf(r->shared_tag, sizeof(r->shared_tag), "%s", fields[6] ? fields[6] : "");
    r->created_at = atoll(fields[7] ? fields[7] : "0");
    snprintf(r->status, sizeof(r->status), "%s", fields[8] ? fields[8] : "");
    snprintf(r->memo, sizeof(r->memo), "%s", n >= 10 && fields[9] ? fields[9] : "");
    return 0;
}

static int stealth_load_all(const char *chain_dir, StealthRecord **out, size_t *count) {
    char path[1024]; stealth_paths(chain_dir, path, sizeof(path), NULL, 0);
    *out = NULL; *count = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t cap = 16, n = 0;
    StealthRecord *arr = calloc(cap, sizeof(StealthRecord));
    if (!arr) { fclose(f); return -1; }
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        StealthRecord r;
        if (stealth_parse_line(line, &r) != 0) continue;
        if (n == cap) {
            cap *= 2;
            StealthRecord *tmp = realloc(arr, cap * sizeof(StealthRecord));
            if (!tmp) { free(arr); fclose(f); return -1; }
            arr = tmp;
        }
        arr[n++] = r;
    }
    fclose(f);
    *out = arr; *count = n;
    return 0;
}

static int stealth_save_all(const char *chain_dir, const StealthRecord *arr, size_t count) {
    char path[1024]; stealth_paths(chain_dir, path, sizeof(path), NULL, 0);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "# tx_id|sender|stealth_address|one_time_address|amount|ephemeral_pub|shared_tag|created_at|status|memo\n");
    for (size_t i=0;i<count;i++) {
        fprintf(f, "%s|%s|%s|%s|%lld|%s|%s|%lld|%s|%s\n",
            arr[i].tx_id, arr[i].sender, arr[i].stealth_address, arr[i].one_time_address,
            arr[i].amount, arr[i].ephemeral_pub, arr[i].shared_tag, arr[i].created_at,
            arr[i].status, arr[i].memo);
    }
    fclose(f);
    return 0;
}

static int stealth_address_cmd(const char *wallet_dir) {
    char saddr[512];
    if (stealth_make_address_from_wallet_dir(wallet_dir, saddr) != 0) die("stealth key derivation failed");
    printf("stealth_address=%s\n", saddr);
    printf("format=squb1_x25519_scan_pub_x25519_spend_pub\n");
    printf("policy=optional-privacy-not-for-exchange-deposits-transparent-default\n");
    printf("warning=Use transparent QUB addresses for centralized exchange deposits and withdrawals. Stealth is optional wallet-to-wallet privacy.\n");
    return 0;
}

static int stealth_send_cmd(const char *chain_dir, const char *wallet_dir, const char *stealth_address, long long amount, const char *memo) {
    if (amount <= 0) die("stealth amount must be > 0");
    char scan[129], spend[129];
    if (stealth_split_address(stealth_address, scan, spend) != 0) die("invalid stealth address");
    char *sender = wallet_address(wallet_dir);
    if (!sender) die("wallet address unavailable");
    sender[strcspn(sender, "\r\n")] = 0;

    char balpath[1024], journal[1024], stealth_journal[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), NULL, 0, NULL, 0, journal, sizeof(journal));
    stealth_paths(chain_dir, NULL, 0, stealth_journal, sizeof(stealth_journal));
    long long frombal = kv_get_ll_bin(balpath, sender);
    if (frombal < amount) die("insufficient transparent funds");

    char eph_pub[129], shared[129], one_time[385], rnd[65];
    unsigned char eph_priv_b[32], eph_pub_b[32], scan_pub_b[32], shared_b[32];
    if (strlen(scan) != 64 || hex_to_bytes_local(scan, scan_pub_b, 32) != 0) die("stealth address must contain X25519 scan pubkey");
    RAND_bytes(eph_priv_b, 32);
    eph_priv_b[0] &= 248; eph_priv_b[31] &= 127; eph_priv_b[31] |= 64;
    if (stealth_x25519_pub_from_priv(eph_priv_b, eph_pub_b) != 0) die("ephemeral x25519 failed");
    if (stealth_x25519_derive(eph_priv_b, scan_pub_b, shared_b) != 0) die("x25519 derive failed");
    bytes_to_hex_local(eph_pub_b, 32, eph_pub);
    bytes_to_hex_local(shared_b, 32, shared);
    stealth_make_one_time_address(spend, shared, one_time);
    shielded_random_hex(rnd, 16);

    StealthRecord *arr = NULL; size_t n = 0;
    if (stealth_load_all(chain_dir, &arr, &n) != 0) die("stealth load failed");
    StealthRecord *tmp = realloc(arr, (n + 1) * sizeof(StealthRecord));
    if (!tmp) { free(sender); free(arr); die("oom"); }
    arr = tmp;
    StealthRecord *r = &arr[n];
    memset(r, 0, sizeof(*r));
    snprintf(r->tx_id, sizeof(r->tx_id), "stx_%lld_%s", (long long)time(NULL), rnd);
    snprintf(r->sender, sizeof(r->sender), "%s", sender);
    snprintf(r->stealth_address, sizeof(r->stealth_address), "%s", stealth_address);
    snprintf(r->one_time_address, sizeof(r->one_time_address), "%s", one_time);
    r->amount = amount;
    snprintf(r->ephemeral_pub, sizeof(r->ephemeral_pub), "%s", eph_pub);
    snprintf(r->shared_tag, sizeof(r->shared_tag), "%s", shared);
    r->created_at = (long long)time(NULL);
    snprintf(r->status, sizeof(r->status), "pending-scan");
    snprintf(r->memo, sizeof(r->memo), "%s", memo ? memo : "stealth-transfer");
    clean_field(r->memo);

    if (kv_set_ll_bin(balpath, sender, frombal - amount) != 0) { free(sender); free(arr); die("state write failed"); }
    if (stealth_save_all(chain_dir, arr, n + 1) != 0) { free(sender); free(arr); die("stealth save failed"); }

    journal_append(chain_dir, "stealth_send tx_id=%s sender=%s one_time=%s amount=%lld eph=%s policy=optional-not-cex", r->tx_id, sender, one_time, amount, eph_pub);
    FILE *sj = fopen(stealth_journal, "ab"); if (sj) { fprintf(sj, "stealth_send tx_id=%s amount=%lld one_time=%s eph=%s\n", r->tx_id, amount, one_time, eph_pub); fclose(sj); }
    printf("status=stealth-sent\n");
    printf("tx_id=%s\n", r->tx_id);
    printf("one_time_address=%s\n", one_time);
    printf("ephemeral_pub=%s\n", eph_pub);
    printf("amount=%lld\n", amount);
    printf("policy=not-for-exchange-deposits-transparent-default\n");
    printf("warning=Stealth uses X25519 shared-secret one-time addressing. Transparent QUB remains default. Audit pending before public-funds recommendation.\n");
    free(sender); free(arr);
    return 0;
}

static int stealth_scan_cmd(const char *chain_dir, const char *wallet_dir) {
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char own_saddr[512]; if (stealth_make_address_from_wallet_dir(wallet_dir, own_saddr) != 0) die("stealth key derivation failed");

    StealthRecord *arr = NULL; size_t n = 0;
    if (stealth_load_all(chain_dir, &arr, &n) != 0) die("stealth load failed");
    int changed = 0, found = 0;
    unsigned char scan_priv_b[32], scan_pub_b[32], spend_priv_b[32], spend_pub_b[32];
    char spend_hex[65];
    if (stealth_wallet_keypair(wallet_dir, "scan", scan_priv_b, scan_pub_b) != 0) die("scan key failed");
    if (stealth_wallet_keypair(wallet_dir, "spend", spend_priv_b, spend_pub_b) != 0) die("spend key failed");
    bytes_to_hex_local(spend_pub_b, 32, spend_hex);
    for (size_t i=0;i<n;i++) {
        unsigned char eph_pub_b[32], shared_b[32];
        char shared_hex[65], expected_one_time[385];
        if (strlen(arr[i].ephemeral_pub) != 64 || hex_to_bytes_local(arr[i].ephemeral_pub, eph_pub_b, 32) != 0) continue;
        if (stealth_x25519_derive(scan_priv_b, eph_pub_b, shared_b) != 0) continue;
        bytes_to_hex_local(shared_b, 32, shared_hex);
        stealth_make_one_time_address(spend_hex, shared_hex, expected_one_time);
        if (!strcmp(arr[i].one_time_address, expected_one_time)) {
            found++;
            if (!strcmp(arr[i].status, "pending-scan")) {
                char balpath[1024]; state_paths(chain_dir, balpath, sizeof(balpath), NULL, 0, NULL, 0, NULL, 0);
                long long bal = kv_get_ll_bin(balpath, arr[i].one_time_address);
                if (kv_set_ll_bin(balpath, arr[i].one_time_address, bal + arr[i].amount) != 0) { free(addr); free(arr); die("state write failed"); }
                snprintf(arr[i].status, sizeof(arr[i].status), "claimed");
                changed++;
            }
            printf("%s one_time=%s amount=%lld status=%s eph=%s\n", arr[i].tx_id, arr[i].one_time_address, arr[i].amount, arr[i].status, arr[i].ephemeral_pub);
        }
    }
    if (changed && stealth_save_all(chain_dir, arr, n) != 0) { free(addr); free(arr); die("stealth save failed"); }
    printf("scan_found=%d\nscan_claimed=%d\npolicy=optional-wallet-privacy-transparent-exchange-default-mainnet-from-block-1\n", found, changed);
    free(addr); free(arr);
    return 0;
}

static int stealth_history_cmd(const char *chain_dir, const char *wallet_dir) {
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char own_saddr[512]; if (stealth_make_address_from_wallet_dir(wallet_dir, own_saddr) != 0) die("stealth key derivation failed");
    StealthRecord *arr = NULL; size_t n = 0;
    if (stealth_load_all(chain_dir, &arr, &n) != 0) die("stealth load failed");
    for (size_t i=0;i<n;i++) {
        if (!strcmp(arr[i].stealth_address, own_saddr) || !strcmp(arr[i].sender, addr)) {
            printf("%s sender=%s one_time=%s amount=%lld status=%s eph=%s memo=%s\n",
                arr[i].tx_id, arr[i].sender, arr[i].one_time_address, arr[i].amount, arr[i].status, arr[i].ephemeral_pub, arr[i].memo);
        }
    }
    free(addr); free(arr);
    return 0;
}

typedef struct {
    char note_id[129];
    char owner[385];
    long long value;
    char rho[129];
    char randomness[129];
    char commitment[129];
    char status[32];
    char nullifier[129];
    long long created_at;
    char memo[256];
} ShieldedNoteRecord;

static void shielded_paths(const char *chain_dir, char *notes, size_t nsz, char *nullifiers, size_t usz, char *journal, size_t jsz) {
    if (notes) snprintf(notes, nsz, "%s/shielded_notes.db", chain_dir);
    if (nullifiers) snprintf(nullifiers, usz, "%s/shielded_nullifiers.db", chain_dir);
    if (journal) snprintf(journal, jsz, "%s/shielded_journal.log", chain_dir);
}

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
    if (RAND_bytes(buf, (int)bytes) != 1) {
        unsigned long long fallback = (unsigned long long)time(NULL) ^ (unsigned long long)getpid();
        SHA256((unsigned char*)&fallback, sizeof(fallback), buf);
    }
    for (size_t i=0;i<bytes;i++) sprintf(out + i*2, "%02x", buf[i]);
    out[bytes*2] = 0;
}

static int shielded_parse_line(const char *line, ShieldedNoteRecord *r) {
    if (!line || !r) return -1;
    char buf[4096];
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
    snprintf(r->note_id, sizeof(r->note_id), "%s", fields[0] ? fields[0] : "");
    snprintf(r->owner, sizeof(r->owner), "%s", fields[1] ? fields[1] : "");
    r->value = atoll(fields[2] ? fields[2] : "0");
    snprintf(r->rho, sizeof(r->rho), "%s", fields[3] ? fields[3] : "");
    snprintf(r->randomness, sizeof(r->randomness), "%s", fields[4] ? fields[4] : "");
    snprintf(r->commitment, sizeof(r->commitment), "%s", fields[5] ? fields[5] : "");
    snprintf(r->status, sizeof(r->status), "%s", fields[6] ? fields[6] : "");
    snprintf(r->nullifier, sizeof(r->nullifier), "%s", fields[7] ? fields[7] : "");
    r->created_at = atoll(fields[8] ? fields[8] : "0");
    snprintf(r->memo, sizeof(r->memo), "%s", n >= 10 && fields[9] ? fields[9] : "");
    return 0;
}

static int shielded_load_all(const char *chain_dir, ShieldedNoteRecord **out, size_t *count) {
    char path[1024]; shielded_paths(chain_dir, path, sizeof(path), NULL, 0, NULL, 0);
    *out = NULL; *count = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t cap = 16, n = 0;
    ShieldedNoteRecord *arr = calloc(cap, sizeof(ShieldedNoteRecord));
    if (!arr) { fclose(f); return -1; }
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        ShieldedNoteRecord r;
        if (shielded_parse_line(line, &r) != 0) continue;
        if (n == cap) {
            cap *= 2;
            ShieldedNoteRecord *tmp = realloc(arr, cap * sizeof(ShieldedNoteRecord));
            if (!tmp) { free(arr); fclose(f); return -1; }
            arr = tmp;
        }
        arr[n++] = r;
    }
    fclose(f);
    *out = arr; *count = n;
    return 0;
}

static int shielded_save_all(const char *chain_dir, const ShieldedNoteRecord *arr, size_t count) {
    char path[1024]; shielded_paths(chain_dir, path, sizeof(path), NULL, 0, NULL, 0);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "# note_id|owner|value|rho|randomness|commitment|status|nullifier|created_at|memo\n");
    for (size_t i=0;i<count;i++) {
        fprintf(f, "%s|%s|%lld|%s|%s|%s|%s|%s|%lld|%s\n",
            arr[i].note_id, arr[i].owner, arr[i].value, arr[i].rho, arr[i].randomness,
            arr[i].commitment, arr[i].status, arr[i].nullifier, arr[i].created_at, arr[i].memo);
    }
    fclose(f);
    return 0;
}

static void shielded_make_address(const char *wallet_addr, char out[512]) {
    char seed[1024], h[129];
    snprintf(seed, sizeof(seed), "QUB-SHIELDED-ADDRESS-v1|%s", wallet_addr ? wallet_addr : "");
    sha3_512_hex_local(seed, h);
    snprintf(out, 512, "zqub1%s", h);
}

static void shielded_make_commitment(long long value, const char *owner, const char *rho, const char *randomness, char out[129]) {
    char buf[2048];
    snprintf(buf, sizeof(buf), "QUB-NOTE-COMMITMENT-v1|%lld|%s|%s|%s", value, owner, rho, randomness);
    sha3_512_hex_local(buf, out);
}

static void shielded_make_nullifier(const char *owner, const char *rho, char out[129]) {
    char buf[2048];
    snprintf(buf, sizeof(buf), "QUB-NOTE-NULLIFIER-v1|%s|%s", owner, rho);
    sha3_512_hex_local(buf, out);
}

static int shielded_address_cmd(const char *wallet_dir) {
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char zaddr[512]; shielded_make_address(addr, zaddr);
    printf("shielded_address=%s\n", zaddr);
    printf("viewing_key=dev-preview-local-wallet-derived\n");
    printf("warning=Shielded pool proof system audit pending. Use transparent QUB for exchange deposits.\n");
    free(addr);
    return 0;
}

static int shield_cmd(const char *chain_dir, const char *wallet_dir, long long amount, const char *shielded_address) {
    if (amount <= 0) die("shield amount must be > 0");
    if (!shielded_address || strncmp(shielded_address, "zqub1", 5) != 0) die("invalid shielded address");
    char *from = wallet_address(wallet_dir);
    if (!from) die("wallet address unavailable");
    from[strcspn(from, "\r\n")] = 0;

    char balpath[1024], journal[1024], shield_journal[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), NULL, 0, NULL, 0, journal, sizeof(journal));
    shielded_paths(chain_dir, NULL, 0, NULL, 0, shield_journal, sizeof(shield_journal));
    long long frombal = kv_get_ll_bin(balpath, from);
    if (frombal < amount) die("insufficient transparent funds");

    ShieldedNoteRecord *arr = NULL; size_t n = 0;
    if (shielded_load_all(chain_dir, &arr, &n) != 0) die("shielded load failed");
    ShieldedNoteRecord *tmp = realloc(arr, (n+1)*sizeof(ShieldedNoteRecord));
    if (!tmp) { free(arr); die("oom"); }
    arr = tmp;
    ShieldedNoteRecord *r = &arr[n];
    memset(r, 0, sizeof(*r));
    char rnd[65]; shielded_random_hex(rnd, 16);
    snprintf(r->note_id, sizeof(r->note_id), "znote_%lld_%s", (long long)time(NULL), rnd);
    snprintf(r->owner, sizeof(r->owner), "%s", shielded_address);
    r->value = amount;
    shielded_random_hex(r->rho, 32);
    shielded_random_hex(r->randomness, 32);
    shielded_make_commitment(r->value, r->owner, r->rho, r->randomness, r->commitment);
    snprintf(r->status, sizeof(r->status), "unspent");
    snprintf(r->nullifier, sizeof(r->nullifier), "");
    r->created_at = (long long)time(NULL);
    snprintf(r->memo, sizeof(r->memo), "shield-from-transparent");

    if (kv_set_ll_bin(balpath, from, frombal - amount) != 0) { free(from); free(arr); die("state write failed"); }
    if (shielded_save_all(chain_dir, arr, n+1) != 0) { free(from); free(arr); die("shielded save failed"); }

    journal_append(chain_dir, "shield note_id=%s from=%s amount=%lld commitment=%s", r->note_id, from, amount, r->commitment);
    FILE *sj = fopen(shield_journal, "ab"); if (sj) { fprintf(sj, "shield note_id=%s amount=%lld owner=%s commitment=%s\n", r->note_id, amount, r->owner, r->commitment); fclose(sj); }
    printf("status=shielded\nnote_id=%s\ncommitment=%s\namount=%lld\nwarning=shielded-pool-zk-audit-pending\n", r->note_id, r->commitment, amount);
    free(from); free(arr);
    return 0;
}

static int shielded_balance_cmd(const char *chain_dir, const char *wallet_dir) {
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char zaddr[512]; shielded_make_address(addr, zaddr);
    ShieldedNoteRecord *arr = NULL; size_t n = 0;
    if (shielded_load_all(chain_dir, &arr, &n) != 0) die("shielded load failed");
    long long bal = 0;
    for (size_t i=0;i<n;i++) {
        if (!strcmp(arr[i].owner, zaddr) && !strcmp(arr[i].status, "unspent")) bal += arr[i].value;
    }
    printf("%lld\n", bal);
    free(addr); free(arr);
    return 0;
}

static int shielded_send_cmd(const char *chain_dir, const char *wallet_dir, const char *to_shielded_address, long long amount) {
    if (amount <= 0) die("shielded-send amount must be > 0");
    if (!to_shielded_address || strncmp(to_shielded_address, "zqub1", 5) != 0) die("invalid shielded address");
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char from_zaddr[512]; shielded_make_address(addr, from_zaddr);

    ShieldedNoteRecord *arr = NULL; size_t n = 0;
    if (shielded_load_all(chain_dir, &arr, &n) != 0) die("shielded load failed");
    long long remaining = amount;
    for (size_t i=0;i<n && remaining>0;i++) {
        if (!strcmp(arr[i].owner, from_zaddr) && !strcmp(arr[i].status, "unspent")) {
            char nf[129]; shielded_make_nullifier(arr[i].owner, arr[i].rho, nf);
            snprintf(arr[i].status, sizeof(arr[i].status), "spent");
            snprintf(arr[i].nullifier, sizeof(arr[i].nullifier), "%s", nf);
            remaining -= arr[i].value;
        }
    }
    if (remaining > 0) { free(addr); free(arr); die("insufficient shielded funds"); }

    ShieldedNoteRecord *tmp = realloc(arr, (n+1)*sizeof(ShieldedNoteRecord));
    if (!tmp) { free(addr); free(arr); die("oom"); }
    arr = tmp;
    ShieldedNoteRecord *r = &arr[n];
    memset(r, 0, sizeof(*r));
    char rnd[65]; shielded_random_hex(rnd, 16);
    snprintf(r->note_id, sizeof(r->note_id), "znote_%lld_%s", (long long)time(NULL), rnd);
    snprintf(r->owner, sizeof(r->owner), "%s", to_shielded_address);
    r->value = amount;
    shielded_random_hex(r->rho, 32);
    shielded_random_hex(r->randomness, 32);
    shielded_make_commitment(r->value, r->owner, r->rho, r->randomness, r->commitment);
    snprintf(r->status, sizeof(r->status), "unspent");
    r->created_at = (long long)time(NULL);
    snprintf(r->memo, sizeof(r->memo), "shielded-transfer");
    if (shielded_save_all(chain_dir, arr, n+1) != 0) { free(addr); free(arr); die("shielded save failed"); }
    journal_append(chain_dir, "shielded_send from=%s to=%s amount=%lld commitment=%s warning=skeleton", from_zaddr, to_shielded_address, amount, r->commitment);
    printf("status=shielded-sent\namount=%lld\nnew_commitment=%s\nwarning=shielded-pool-zk-audit-pending\n", amount, r->commitment);
    free(addr); free(arr);
    return 0;
}

static int unshield_cmd(const char *chain_dir, const char *wallet_dir, const char *to_transparent, long long amount) {
    if (amount <= 0) die("unshield amount must be > 0");
    if (!to_transparent || strncmp(to_transparent, "qrx", 3) != 0) die("invalid transparent QUB address");
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char from_zaddr[512]; shielded_make_address(addr, from_zaddr);

    ShieldedNoteRecord *arr = NULL; size_t n = 0;
    if (shielded_load_all(chain_dir, &arr, &n) != 0) die("shielded load failed");
    long long remaining = amount;
    for (size_t i=0;i<n && remaining>0;i++) {
        if (!strcmp(arr[i].owner, from_zaddr) && !strcmp(arr[i].status, "unspent")) {
            char nf[129]; shielded_make_nullifier(arr[i].owner, arr[i].rho, nf);
            snprintf(arr[i].status, sizeof(arr[i].status), "spent");
            snprintf(arr[i].nullifier, sizeof(arr[i].nullifier), "%s", nf);
            remaining -= arr[i].value;
        }
    }
    if (remaining > 0) { free(addr); free(arr); die("insufficient shielded funds"); }

    char balpath[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), NULL, 0, NULL, 0, NULL, 0);
    long long tobal = kv_get_ll_bin(balpath, to_transparent);
    if (kv_set_ll_bin(balpath, to_transparent, tobal + amount) != 0) { free(addr); free(arr); die("state write failed"); }
    if (shielded_save_all(chain_dir, arr, n) != 0) { free(addr); free(arr); die("shielded save failed"); }
    journal_append(chain_dir, "unshield from=%s to=%s amount=%lld warning=skeleton", from_zaddr, to_transparent, amount);
    printf("status=unshielded\namount=%lld\nto=%s\nwarning=shielded-pool-zk-audit-pending\n", amount, to_transparent);
    free(addr); free(arr);
    return 0;
}

static int shielded_history_cmd(const char *chain_dir, const char *wallet_dir) {
    char *addr = wallet_address(wallet_dir);
    if (!addr) die("wallet address unavailable");
    addr[strcspn(addr, "\r\n")] = 0;
    char zaddr[512]; shielded_make_address(addr, zaddr);
    ShieldedNoteRecord *arr = NULL; size_t n = 0;
    if (shielded_load_all(chain_dir, &arr, &n) != 0) die("shielded load failed");
    for (size_t i=0;i<n;i++) {
        if (!strcmp(arr[i].owner, zaddr)) {
            printf("%s owner=%s value=%lld status=%s commitment=%s nullifier=%s created_at=%lld memo=%s\n",
                arr[i].note_id, arr[i].owner, arr[i].value, arr[i].status, arr[i].commitment, arr[i].nullifier, arr[i].created_at, arr[i].memo);
        }
    }
    free(addr); free(arr);
    return 0;
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
    char p1[1024], p2[1024];
    snprintf(p1, sizeof(p1), "%s/peers.txt", node_dir);
    snprintf(p2, sizeof(p2), "%s/known_peers.txt", node_dir);
    char *a = read_file(p1, NULL), *b = read_file(p2, NULL);
    if (a) { printf("[peers]\n%s", a); if (strlen(a) && a[strlen(a)-1] != '\n') puts(""); }
    if (b) { printf("[known]\n%s", b); if (strlen(b) && b[strlen(b)-1] != '\n') puts(""); }
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

static int send_cmd(const char *wallet_dir, const char *chain_dir, const char *to, const char *amount, const char *memo, const char *node_dir) {
    char tmp[1024]; snprintf(tmp, sizeof(tmp), "%s/.send-%ld.qrxtx", wallet_dir, (long)time(NULL));
    if (sign_cmd(wallet_dir, chain_dir, to, amount, memo, tmp) != 0) return 1;
    int rc = 0;
    if (node_dir && *node_dir) rc = sendtx_cmd(node_dir, tmp);
    else rc = applytx_cmd(chain_dir, tmp);
    unlink_qrx(tmp);
    return rc;
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
    if (amount <= 0) die("amount must be > 0");
    if (unbond_secs <= 0) unbond_secs = 86400;
    char *addr = wallet_address(wallet_dir); if (!addr) die("wallet address failed");
    char stakes[1024], delegations[1024], totals[1024], ub[1024], ube[1024], ud[1024], ude[1024];
    staking_paths(chain_dir, stakes, sizeof(stakes), delegations, sizeof(delegations), totals, sizeof(totals), ub, sizeof(ub), ube, sizeof(ube), ud, sizeof(ud), ude, sizeof(ude), NULL, 0);
    long long s = kv_get_ll_bin(stakes, addr);
    if (s < amount) die("insufficient self stake");
    if (kv_set_ll_bin(stakes, addr, s - amount) != 0) die("stake update failed");
    long long pending = kv_get_ll_bin(ub, addr);
    kv_set_ll_bin(ub, addr, pending + amount);
    kv_set_ll_bin(ube, addr, (long long)time(NULL) + unbond_secs);
    journal_append(chain_dir, "unstake addr=%s amount=%lld remaining=%lld pending=%lld eta=%lld", addr, amount, s - amount, pending + amount, (long long)time(NULL) + unbond_secs);
    printf("address=%s\npending_unbond=%lld\nclaim_after=%lld\n", addr, pending + amount, kv_get_ll_bin(ube, addr));
    free(addr); return 0;
}

static int claim_unbonded_cmd(const char *chain_dir, const char *wallet_dir) {
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
        printf("balance=%lld\n", kv_get_ll_bin(b, address));
        printf("self_stake=%lld\n", kv_get_ll_bin(stakes, address));
        printf("delegated_to_me=%lld\n", kv_get_ll_bin(totals, address));
        printf("validator_power=%lld\n", validator_power_total(chain_dir, address));
        printf("pending_unbond=%lld\n", kv_get_ll_bin(ub, address));
        printf("pending_unbond_eta=%lld\n", kv_get_ll_bin(ube, address));
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

static int reward_epoch_cmd(const char *chain_dir, long long reward, long long commission_bps) {
    require_manual_mint_allowed(chain_dir, "reward-epoch");
    long long height = current_height_from_chain(chain_dir);
    long long dev_share = (long long)qrx_dev_reward_share((uint64_t)reward, height);
    long long validator_reward = reward - dev_share;
    return reward_epoch_distribute_cmd(chain_dir, validator_reward, reward, dev_share, commission_bps);
}


static int getreward_cmd(const char *chain_dir, long long height) {
    long long h = height >= 0 ? height : current_height_from_chain(chain_dir);
    long long reward = qrx_chain_get_block_reward_at_height(chain_dir, h, 25000000LL, 12614400LL);
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
    printf("initial_reward_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "initial_reward_atoms", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "epoch_reward_atoms", 25000000LL)));
    printf("halving_interval_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "halving_interval_blocks", 12614400LL));
    printf("validator_reward_percent=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "validator_reward_percent", 30));
    printf("delegator_reward_percent=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "delegator_reward_percent", 70));
    printf("network_pool_percent=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "network_pool_percent", 0));
    printf("tx_fee_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "tx_fee_atoms", 1000));
    printf("development_fund_percent=%d\n", qrx_dev_fund_percent(h));
    { char *dev = chain_cfg_value(chain_dir, "dev_address"); printf("development_fund_address=%s\n", dev ? dev : ""); if (dev) free(dev); }
    printf("development_fund_basis=block_subsidy_only\n");
    printf("transaction_fee_recipient_policy=validators_and_delegators_100_percent\n");
    printf("pending_fee_pool_atoms=%lld\n", fee_pool_pending(chain_dir));
    printf("min_validator_stake_atoms=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "min_validator_stake_atoms", 10000000000LL));
    printf("double_sign_slash_bps=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "double_sign_slash_bps", 5000));
    printf("double_sign_jail_seconds=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "double_sign_jail_seconds", 315360000LL));
    printf("offline_penalty_bps=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_penalty_bps", 100));
    printf("offline_penalty_after_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_penalty_after_blocks", 100));
    printf("offline_penalty_interval_blocks=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_penalty_interval_blocks", 100));
    printf("offline_jail_seconds=%lld\n", qrx_chain_get_ll_at_height_or_default(chain_dir, h, "offline_jail_seconds", 3600));
    return 0;
}

static int gethalving_cmd(const char *chain_dir, long long height) {
    long long h = height >= 0 ? height : current_height_from_chain(chain_dir);
    long long next = qrx_chain_get_next_halving_height(chain_dir, h, 12614400LL);
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
    long long max_supply = chain_cfg_ll_or_default(chain_dir, "max_supply_atoms", 2100000000000000LL);
    long long initial_reward = qrx_chain_get_ll_at_height_or_default(chain_dir, current_height, "initial_reward_atoms", qrx_chain_get_ll_at_height_or_default(chain_dir, current_height, "epoch_reward_atoms", 25000000LL));
    long long faucet_cap = chain_cfg_ll_or_default(chain_dir, "faucet_cap_atoms", 1000000000000LL);
    long long current_reward = qrx_chain_get_block_reward_at_height(chain_dir, current_height, 25000000LL, 12614400LL);
    long long next_halving = qrx_chain_get_next_halving_height(chain_dir, current_height, 12614400LL);
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
           "remaining_supply=%lld\n",
           max_supply, initial_reward, faucet_cap, current_height, current_reward, next_halving,
           supply_get(chain_dir, "minted_supply"),
           supply_get(chain_dir, "faucet_minted"),
           supply_get(chain_dir, "rewards_minted"),
           supply_get(chain_dir, "burned_supply"),
           supply_get(chain_dir, "redistributed_supply"),
           fee_pool_pending(chain_dir),
           qrx_chain_get_ll_at_height_or_default(chain_dir, current_height, "tx_fee_atoms", 1000),
           max_supply - supply_get(chain_dir, "minted_supply"));
    return 0;
}
static int reward_epoch_auto_cmd(const char *chain_dir, long long commission_bps, int from_finalized_block_loop) {
    if (!from_finalized_block_loop) require_manual_mint_allowed(chain_dir, "reward-epoch-auto");
    long long height = current_height_from_chain(chain_dir);
    long long subsidy = qrx_chain_get_block_reward_at_height(chain_dir, height, 25000000LL, 12614400LL);
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


int qrx_backend_main(int argc, char **argv) {
    OpenSSL_add_all_algorithms();
    if (argc < 2) { usage(); return 1; }
    if (!strcmp(argv[1], "keygen") && argc == 3) return wallet_keygen(argv[2]);
    if (!strcmp(argv[1], "seed-new") && argc == 3) return wallet_seed_new(argv[2]);
    if (!strcmp(argv[1], "wallet-info") && argc == 3) return wallet_info_cmd(argv[2]);
    if (!strcmp(argv[1], "wallet-new-address") && argc == 3) return wallet_new_address_cmd(argv[2]);
    if (!strcmp(argv[1], "listaddresses") && argc == 3) return wallet_list_addresses_cmd(argv[2]);
    if (!strcmp(argv[1], "hybrid-status") && argc == 3) return hybrid_status_cmd(argv[2]);
    if (!strcmp(argv[1], "wallet-recover") && argc == 4) return wallet_recover_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "address") && argc == 3) { char *a = wallet_address(argv[2]); if (!a) return 1; printf("%s", a); free(a); return 0; }
    if (!strcmp(argv[1], "legacy-address") && argc == 3) return legacy_address_cmd(argv[2]);
    if (!strcmp(argv[1], "migrate-address") && argc == 3) return migrate_address_cmd(argv[2]);
    if (!strcmp(argv[1], "state-migrate-address") && argc == 5) return state_migrate_address_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "init-chain") && (argc == 3 || argc == 5 || argc == 8 || argc == 12 || argc == 19)) return chain_init(argv[2], argc >= 4 ? atoll(argv[3]) : 20, argc >= 5 ? atoll(argv[4]) : 5000, argc >= 8 ? atoll(argv[5]) : 2100000000000000LL, argc >= 8 ? atoll(argv[6]) : 25000000LL, argc >= 8 ? atoll(argv[7]) : 0LL, argc >= 12 ? argv[8] : NULL, argc >= 12 ? argv[9] : NULL, argc >= 12 ? argv[10] : NULL, argc >= 12 ? argv[11] : NULL, argc == 19 ? atoll(argv[12]) : 10, argc == 19 ? atoll(argv[13]) : 100, argc == 19 ? atoll(argv[14]) : 524288, argc == 19 ? atoll(argv[15]) : 8192, argc == 19 ? atoll(argv[16]) : 70, argc == 19 ? atoll(argv[17]) : 30, argc == 19 ? atoll(argv[18]) : 0);
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
    if (!strcmp(argv[1], "shield") && argc == 5) return shield_cmd(argv[2], argv[3], atoll(argv[4]), argv[3]);
    if (!strcmp(argv[1], "shield-to") && argc == 6) return shield_cmd(argv[2], argv[3], atoll(argv[4]), argv[5]);
    if (!strcmp(argv[1], "shielded-balance") && argc == 4) return shielded_balance_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "shielded-send") && argc == 6) return shielded_send_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "unshield") && argc == 6) return unshield_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "shielded-history") && argc == 4) return shielded_history_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "stealth-address") && argc == 3) return stealth_address_cmd(argv[2]);
    if (!strcmp(argv[1], "stealth-send") && (argc == 6 || argc == 7)) return stealth_send_cmd(argv[2], argv[3], argv[4], atoll(argv[5]), argc == 7 ? argv[6] : NULL);
    if (!strcmp(argv[1], "stealth-scan") && argc == 4) return stealth_scan_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "stealth-history") && argc == 4) return stealth_history_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "privacy-feature-status") && argc == 3) return privacy_feature_status_cmd(argv[2]);
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
    if (!strcmp(argv[1], "create-velocity-raw-tx") && (argc == 12 || argc == 13 || argc == 14)) return create_velocity_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10], argv[11], argc >= 13 ? argv[12] : NULL, argc == 14 ? argv[13] : NULL);
    if (!strcmp(argv[1], "create-raw-tx") && (argc >= 8 && argc <= 12)) return create_raw_tx_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argc >= 9 ? argv[8] : NULL, argc >= 10 ? argv[9] : NULL, argc >= 11 ? argv[10] : NULL, argc >= 12 ? argv[11] : NULL);
    if (!strcmp(argv[1], "signrawtransactionwithwallet") && argc == 6) return signrawtransactionwithwallet_cmd(argv[2], argv[3], argv[4], argv[5]);
    if (!strcmp(argv[1], "decoderawtransaction") && argc == 4) return decoderawtransaction_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "txid") && argc == 4) return txid_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "sign") && argc == 8) return sign_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    if (!strcmp(argv[1], "send") && (argc == 7 || argc == 8)) return send_cmd(argv[2], argv[3], argv[4], argv[5], argv[6], argc == 8 ? argv[7] : NULL);
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
    if (!strcmp(argv[1], "verify-block") && argc == 4) return verify_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "validator-set-at") && argc == 5) return validator_set_at_cmd(argv[2], atoll(argv[3]), atoll(argv[4]));
    if (!strcmp(argv[1], "lock-status") && argc == 3) return lock_status_cmd(argv[2]);
    if (!strcmp(argv[1], "evidence-double-sign") && (argc == 5 || argc == 7)) return evidence_double_sign_cmd(argv[2], argv[3], argv[4], argc >= 6 ? atoll(argv[5]) : 0, argc == 7 ? atoll(argv[6]) : 100);
    if (!strcmp(argv[1], "vote-block") && argc == 4) return vote_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "prevote-block") && argc == 4) return vote_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "precommit-block") && argc == 4) return vote_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "verify-proposal") && argc == 4) return verify_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "tally-votes") && argc == 4) return tally_votes_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "tally-precommits") && argc == 4) return tally_votes_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "finalize-block") && argc == 4) return finalize_block_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "timeout-status") && argc == 3) return timeout_status_cmd(argv[2]);
    if (!strcmp(argv[1], "node-process-inbox") && argc == 3) return node_process_inbox_cmd(argv[2]);
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
    if (!strcmp(argv[1], "stake") && argc == 5) return stake_cmd(argv[2], argv[3], atoll(argv[4]));
    if (!strcmp(argv[1], "unstake") && (argc == 5 || argc == 6)) return unstake_cmd(argv[2], argv[3], atoll(argv[4]), argc == 6 ? atoll(argv[5]) : 86400);
    if (!strcmp(argv[1], "claim-unbonded") && argc == 4) return claim_unbonded_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "delegate") && argc == 6) return delegate_cmd(argv[2], argv[3], argv[4], atoll(argv[5]));
    if (!strcmp(argv[1], "undelegate") && (argc == 6 || argc == 7)) return undelegate_cmd(argv[2], argv[3], argv[4], atoll(argv[5]), argc == 7 ? atoll(argv[6]) : 86400);
    if (!strcmp(argv[1], "claim-undelegated") && argc == 5) return claim_undelegated_cmd(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "staking-status") && (argc == 3 || argc == 4)) return staking_status_cmd(argv[2], argc == 4 ? argv[3] : NULL);
    if (!strcmp(argv[1], "validator-set") && argc == 3) return validator_set_cmd(argv[2]);
    if (!strcmp(argv[1], "reward-epoch") && (argc == 4 || argc == 5)) return reward_epoch_cmd(argv[2], atoll(argv[3]), argc == 5 ? atoll(argv[4]) : 1000);
    if (!strcmp(argv[1], "slash") && (argc == 6 || argc == 7)) return slash_cmd(argv[2], argv[3], atoll(argv[4]), argv[5], argc == 7 ? atoll(argv[6]) : 10);
    usage(); return 1;
}
