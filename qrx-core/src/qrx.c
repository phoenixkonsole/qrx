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
      return setsockopt((SOCKET)fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms)) == 0 &&
             setsockopt((SOCKET)fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms)) == 0 ? 0 : -1;
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
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include "chain_params.h"
#include <ctype.h>

#define QRX_PROTOCOL_VERSION 6
#define QRX_MAGIC "5152583036"
#define MEMPOOL_MAX_TXS 256
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
    snprintf(pattern, sizeof(pattern), "%s\*", dirpath);
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
static void usage(void) {
    puts("qrx rc6.2-tokenomics\n"
         "Commands:\n"
         "  keygen <wallet-dir>\n  seed-new <wallet-dir>\n  wallet-info <wallet-dir>\n  wallet-recover <wallet-dir> <recovery-file>\n"
         "  address <wallet-dir>\n  legacy-address <wallet-dir>\n  migrate-address <wallet-dir>\n  state-migrate-address <chain-dir> <old-address> <new-address>\n"
         "  init-chain <chain-dir>\n"
         "  faucet <chain-dir> <address> <amount>\n"
         "  balance <chain-dir> <address>\n"
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
         "  decay-bans <node-dir> [points]\n  state-check <chain-dir>\n  snapshot-state <chain-dir> [label]\n  reindex-state <chain-dir>\n  stake <chain-dir> <wallet-dir> <amount>\n  unstake <chain-dir> <wallet-dir> <amount> [unbonding-secs]\n  claim-unbonded <chain-dir> <wallet-dir>\n  delegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount>\n  undelegate <chain-dir> <delegator-wallet-dir> <validator-address> <amount> [unbonding-secs]\n  claim-undelegated <chain-dir> <delegator-wallet-dir> <validator-address>\n  staking-status <chain-dir> [address]\n  validator-set <chain-dir>\n  reward-epoch <chain-dir> <reward-amount> [validator-commission-bps]\n  slash <chain-dir> <validator-address> <amount> <reason>\n");
}

static int mkdir_p(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len-1] == '/' || tmp[len-1] == '\') tmp[len-1] = 0;
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/' || *p == '\') {
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
    EVP_PKEY_CTX *mctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL); if (!mctx) { EVP_PKEY_free(ed); return -1; }
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
    return chain_network_is(chain_dir, "regtest") || chain_network_is(chain_dir, "testnet");
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
    }
    pclose_qrx(fp);
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
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "find '%s/mempool' -maxdepth 1 -type f 2>/dev/null | wc -l", node_dir);
    FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("mempool status failed");
    long long count = 0; fscanf(fp, "%lld", &count); pclose_qrx(fp);
    snprintf(cmd, sizeof(cmd), "du -sb '%s/mempool' 2>/dev/null | awk '{print $1}'", node_dir);
    fp = popen_qrx(cmd, "r"); long long bytes = 0; if (fp) { fscanf(fp, "%lld", &bytes); pclose_qrx(fp); }
    printf("txs=%lld\nbytes=%lld\n", count, bytes);
    return 0;
}
static int mempool_prune_cmd(const char *node_dir, int max_txs) {
    if (max_txs < 1) max_txs = MEMPOOL_MAX_TXS;
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "bash -lc \"cd '%s/mempool' 2>/dev/null || exit 0; ls -1tr *.qrxtx 2>/dev/null | head -n -%d\"", node_dir, max_txs);
    FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("mempool prune failed");
    char fname[512]; int removed = 0;
    while (fgets(fname, sizeof(fname), fp)) {
        fname[strcspn(fname, "\r\n")] = 0; if (!*fname) continue;
        char path[1024]; snprintf(path, sizeof(path), "%s/mempool/%s", node_dir, fname); if (unlink_qrx(path) == 0) removed++;
    }
    pclose_qrx(fp); printf("removed=%d\n", removed); return 0;
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
    char bal[1024]; state_paths(chain_dir, bal, sizeof(bal), NULL, 0, NULL, 0, NULL, 0); long long cur = kv_get_ll_bin(bal, addr); int rc = kv_set_ll_bin(bal, addr, cur + amt); if (rc == 0) journal_append(chain_dir, "faucet addr=%s amount=%lld", addr, amt); return rc;
}
static int balance_cmd(const char *chain_dir, const char *addr) {
    char bal[1024]; state_paths(chain_dir, bal, sizeof(bal), NULL, 0, NULL, 0, NULL, 0); printf("%lld\n", kv_get_ll_bin(bal, addr)); return 0;
}

static void fee_pool_path(const char *chain_dir, char *out, size_t out_sz) {
    snprintf(out, out_sz, "%s/state/fee_pool.bin", chain_dir);
}
static long long fee_pool_pending(const char *chain_dir) {
    char p[1024]; fee_pool_path(chain_dir, p, sizeof(p));
    return kv_get_ll_bin(p, "pending_fees");
}
static int fee_pool_add(const char *chain_dir, long long fee) {
    if (fee <= 0) return 0;
    char p[1024]; fee_pool_path(chain_dir, p, sizeof(p));
    long long cur = kv_get_ll_bin(p, "pending_fees");
    return kv_set_ll_bin(p, "pending_fees", cur + fee);
}
static long long fee_pool_drain(const char *chain_dir) {
    char p[1024]; fee_pool_path(chain_dir, p, sizeof(p));
    long long cur = kv_get_ll_bin(p, "pending_fees");
    kv_set_ll_bin(p, "pending_fees", 0);
    return cur;
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

    char noncepath_bin[1024]; state_paths(chain_dir, NULL, 0, noncepath_bin, sizeof(noncepath_bin), NULL, 0, NULL, 0); long long nonce = kv_get_ll_bin(noncepath_bin, from) + 1;
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

static int verify_tx_text(const char *chain_dir, const char *tx) {
    char *network_id = cfg_get(tx, "network_id");
    char *genesis_hash = cfg_get(tx, "genesis_hash");
    char *protocol_version = cfg_get(tx, "protocol_version");
    char *from = cfg_get(tx, "from");
    char *to = cfg_get(tx, "to");
    char *amount = cfg_get(tx, "amount");
    char *fee = cfg_get(tx, "fee");
    char *nonce = cfg_get(tx, "nonce");
    char *timestamp = cfg_get(tx, "timestamp");
    char *memo = cfg_get(tx, "memo");
    char *ed_pub_hex = cfg_get(tx, "ed25519_pub_hex");
    char *ml_pub_b64 = cfg_get(tx, "mldsa65_pub_b64");
    char *body_hash_algo = cfg_get(tx, "body_hash_algo");
    char *body_hash_sha3 = cfg_get(tx, "body_hash_sha3_512");
    char *body_hash_sha256_legacy = cfg_get(tx, "body_hash_sha256_legacy");
    char *body_hash_legacy = cfg_get(tx, "body_hash");
    char *sig1_hex = cfg_get(tx, "sig_ed25519_hex");
    char *sig2_hex = cfg_get(tx, "sig_mldsa65_hex");
    if (!network_id||!genesis_hash||!protocol_version||!from||!to||!amount||!fee||!nonce||!timestamp||!memo||!ed_pub_hex||!ml_pub_b64||!sig1_hex||!sig2_hex) die("invalid tx fields");
    if (!(body_hash_algo || body_hash_sha3 || body_hash_legacy)) die("missing tx hash fields");
    char *exp_net = chain_cfg_value(chain_dir, "network_id");
    char *exp_gen = chain_cfg_value(chain_dir, "genesis_hash");
    char *exp_ver = chain_cfg_value(chain_dir, "protocol_version");
    if (strcmp(network_id, exp_net) || strcmp(genesis_hash, exp_gen) || strcmp(protocol_version, exp_ver)) die("tx network binding mismatch");

    char *body = canonical_tx_body(network_id, genesis_hash, protocol_version, from, to, amount, fee, nonce, timestamp, memo, ed_pub_hex, ml_pub_b64);
    char body_hash_sha3_calc[129]; hash_primary_hex((unsigned char*)body, strlen(body), body_hash_sha3_calc);
    char body_hash_sha256_calc[65]; hash_legacy_hex((unsigned char*)body, strlen(body), body_hash_sha256_calc);
    const char *applied_key = NULL;
    if (body_hash_algo || body_hash_sha3) {
        if (!body_hash_algo || strcmp(body_hash_algo, "sha3-512") != 0) die("unsupported tx hash algo");
        if (!body_hash_sha3 || strcmp(body_hash_sha3, body_hash_sha3_calc) != 0) die("body sha3-512 mismatch");
        if (body_hash_sha256_legacy && strcmp(body_hash_sha256_legacy, body_hash_sha256_calc) != 0) die("body sha256 legacy mismatch");
        applied_key = body_hash_sha3;
    } else {
        if (strcmp(body_hash_legacy, body_hash_sha256_calc) != 0) die("body hash mismatch");
        applied_key = body_hash_legacy;
    }

    unsigned char edraw[32]; size_t edlen=0; if (hex_to_bytes(ed_pub_hex, edraw, sizeof(edraw), &edlen) != 0 || edlen != 32) die("invalid ed pub hex");
    EVP_PKEY *ed_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, edraw, edlen); if (!ed_pub) die("ed pub construct failed");
    if (address_matches_pub(ed_pub, from) != 0) die("from address mismatch");
    size_t mlpemlen=0; unsigned char *mlpem = base64_decode(ml_pub_b64, &mlpemlen); if (!mlpem) die("bad ML-DSA b64");
    char *mlpemstr = malloc(mlpemlen+1); memcpy(mlpemstr, mlpem, mlpemlen); mlpemstr[mlpemlen]=0;
    EVP_PKEY *ml_pub = pubkey_from_pem_string(mlpemstr); if (!ml_pub) die("ml pub parse failed");
    unsigned char *sig1=NULL,*sig2=NULL; size_t sig1len=0,sig2len=0; sig1 = malloc(strlen(sig1_hex)/2+1); sig2 = malloc(strlen(sig2_hex)/2+1);
    if (hex_to_bytes(sig1_hex, sig1, strlen(sig1_hex)/2+1, &sig1len) != 0) die("bad sig1");
    if (hex_to_bytes(sig2_hex, sig2, strlen(sig2_hex)/2+1, &sig2len) != 0) die("bad sig2");
    if (verify_oneshot(ed_pub, (unsigned char*)body, strlen(body), sig1, sig1len) != 0) die("ed25519 verify failed");
    if (verify_oneshot(ml_pub, (unsigned char*)body, strlen(body), sig2, sig2len) != 0) die("ML-DSA verify failed");

    char noncepath[1024], applpath[1024];
    state_paths(chain_dir, NULL, 0, noncepath, sizeof(noncepath), applpath, sizeof(applpath), NULL, 0);
    long long current = kv_get_ll_bin(noncepath, from);
    long long n = atoll(nonce);
    if (n <= current) die("stale nonce");
    if (applied_has_bin(applpath, applied_key)) die("already applied tx");

    free(network_id); free(genesis_hash); free(protocol_version); free(from); free(to); free(amount); free(fee); free(nonce); free(timestamp); free(memo); free(ed_pub_hex); free(ml_pub_b64); if (body_hash_algo) free(body_hash_algo); if (body_hash_sha3) free(body_hash_sha3); if (body_hash_sha256_legacy) free(body_hash_sha256_legacy); if (body_hash_legacy) free(body_hash_legacy); free(sig1_hex); free(sig2_hex); free(exp_net); free(exp_gen); free(exp_ver); free(body); free(mlpem); free(mlpemstr); free(sig1); free(sig2);
    EVP_PKEY_free(ed_pub); EVP_PKEY_free(ml_pub);
    return 0;
}

static int verify_cmd(const char *chain_dir, const char *tx_file) {
    char *tx = read_file(tx_file, NULL); if (!tx) die("cannot read tx");
    int rc = verify_tx_text(chain_dir, tx); free(tx); puts(rc == 0 ? "OK" : "FAIL"); return rc;
}

static int applytx_cmd(const char *chain_dir, const char *tx_file) {
    char *tx = read_file(tx_file, NULL); if (!tx) die("cannot read tx");
    if (verify_tx_text(chain_dir, tx) != 0) die("verify failed");
    char *from = cfg_get(tx, "from"); char *to = cfg_get(tx, "to"); char *amount = cfg_get(tx, "amount"); char *fee_s = cfg_get(tx, "fee"); char *nonce = cfg_get(tx, "nonce");
    char *body_hash_sha3 = cfg_get(tx, "body_hash_sha3_512"); char *body_hash_legacy = cfg_get(tx, "body_hash");
    const char *body_hash = body_hash_sha3 ? body_hash_sha3 : body_hash_legacy;
    long long amt = atoll(amount); long long fee = fee_s ? atoll(fee_s) : 0; if (fee < 0) die("invalid fee");
    char balpath[1024], noncepath[1024], applpath[1024];
    state_paths(chain_dir, balpath, sizeof(balpath), noncepath, sizeof(noncepath), applpath, sizeof(applpath), NULL, 0);
    long long frombal = kv_get_ll_bin(balpath, from); if (frombal < amt + fee) die("insufficient funds");
    long long tobal = kv_get_ll_bin(balpath, to);
    if (kv_set_ll_bin(balpath, from, frombal - amt - fee) != 0) die("state write failed");
    if (kv_set_ll_bin(balpath, to, tobal + amt) != 0) die("state write failed");
    if (fee_pool_add(chain_dir, fee) != 0) die("fee pool update failed");
    if (kv_set_ll_bin(noncepath, from, atoll(nonce)) != 0) die("state write failed");
    if (applied_add_bin(applpath, body_hash) != 0) die("state write failed");
    journal_append(chain_dir, "applytx from=%s to=%s amount=%lld fee=%lld nonce=%s body_hash=%s", from, to, amt, fee, nonce, body_hash);
    puts("APPLIED");
    free(tx); free(from); free(to); free(amount); if (fee_s) free(fee_s); free(nonce); if (body_hash_sha3) free(body_hash_sha3); if (body_hash_legacy) free(body_hash_legacy); return 0;
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
    if (send(fd, &n, 4, 0) != 4) return -1;
    size_t left = strlen(msg); const char *p = msg;
    while (left) { ssize_t w = send(fd, p, left, 0); if (w <= 0) return -1; p += w; left -= (size_t)w; }
    return 0;
}
static char *recv_framed(int fd) {
    uint32_t n; ssize_t r = recv(fd, &n, 4, MSG_WAITALL); if (r != 4) return NULL; n = ntohl(n); if (n > MAX_MSG) return NULL;
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
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "find '%s/mempool' -maxdepth 1 -type f 2>/dev/null | wc -l", node_dir);
    FILE *fp = popen_qrx(cmd, "r"); long long count = 0; if (fp) { fscanf(fp, "%lld", &count); pclose_qrx(fp); }
    if (count >= MEMPOOL_MAX_TXS) mempool_prune_cmd(node_dir, MEMPOOL_MAX_TXS - 16);
    char hash[129]; hash_primary_hex((unsigned char*)tx_text, strlen(tx_text), hash);
    char p[1024]; snprintf(p, sizeof(p), "%s/mempool/%s.qrxtx", node_dir, hash); return write_text(p, tx_text);
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
    qrx_close_socket(s); free(cfg); free(host); free(port_s); return 0;
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
    char cmd[2048]; snprintf(cmd, sizeof(cmd), "ls -1 '%s/mempool' 2>/dev/null", node_dir); FILE *fp = popen_qrx(cmd, "r"); if (!fp) die("mempool list failed");
    char blockbuf[MAX_MSG]; size_t off = 0;
    off += snprintf(blockbuf+off, sizeof(blockbuf)-off,
        "network_id=%s\ngenesis_hash=%s\nprotocol_version=%s\nconsensus_version=%s\nchain_id=%s\nheight=%lld\nround=%lld\nvalidator=%s\nvalidator_power=%lld\ntimestamp=%lld\n",
        network_id, genesis_hash, protocol_version, consensus_version, chain_id, height, round, address, validator_power, (long long)time(NULL));
    int count = 0; char fname[512];
    while (count < max_txs && fgets(fname, sizeof(fname), fp)) {
        fname[strcspn(fname, "\r\n")] = 0; if (!*fname) continue;
        char txp[1024]; snprintf(txp, sizeof(txp), "%s/mempool/%s", node_dir, fname); char *tx = read_file(txp, NULL); if (!tx) continue;
        char h[129]; hash_primary_hex((unsigned char*)tx, strlen(tx), h); off += snprintf(blockbuf+off, sizeof(blockbuf)-off, "tx%d=%s\n", count+1, h); count++; free(tx);
    }
    pclose_qrx(fp);
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

static int history_cmd(const char *chain_dir, const char *address, int limit) {
    char journal[1024]; state_paths(chain_dir, NULL, 0, NULL, 0, NULL, 0, journal, sizeof(journal));
    char *txt = read_file(journal, NULL); if (!txt) die("missing journal");
    size_t lines_cap = 256, lines_n = 0; char **lines = calloc(lines_cap, sizeof(char*)); if (!lines) die("oom");
    char *save = NULL; char *line = strtok_r(txt, "\n", &save);
    while (line) {
        int match = 1;
        if (address && *address) match = strstr(line, address) != NULL;
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
    if (limit <= 0 || limit > (int)lines_n) limit = (int)lines_n;
    int start = (int)lines_n - limit;
    for (int i = start; i < (int)lines_n; ++i) puts(lines[i]);
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

static int reward_epoch_distribute_cmd(const char *chain_dir, long long reward, long long mint_amount, long long commission_bps) {
    if (reward <= 0) die("reward must be > 0");
    if (mint_amount > 0 && mint_with_cap(chain_dir, "rewards_minted", mint_amount) != 0) die("max supply exceeded");
    if (commission_bps < 0 || commission_bps > 10000) die("commission bps must be between 0 and 10000");
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
    return reward_epoch_distribute_cmd(chain_dir, reward, reward, commission_bps);
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
    long long total = subsidy + fees;
    if (total <= 0) die("no block subsidy or fees to distribute");
    int rc = reward_epoch_distribute_cmd(chain_dir, total, subsidy, commission_bps);
    if (rc == 0 && fees > 0) {
        long long drained = fee_pool_drain(chain_dir);
        journal_append(chain_dir, "fee_pool_drained amount=%lld height=%lld", drained, height);
        printf("fees_distributed=%lld\n", drained);
    }
    printf("block_subsidy=%lld\n", subsidy);
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
    if (!strcmp(argv[1], "balance") && argc == 4) return balance_cmd(argv[2], argv[3]);
    if (!strcmp(argv[1], "history") && (argc == 3 || argc == 4 || argc == 5)) return history_cmd(argv[2], argc >= 4 ? argv[3] : NULL, argc == 5 ? atoi(argv[4]) : 50);
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
