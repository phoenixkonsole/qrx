#define _GNU_SOURCE
#include "core_frontend.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
static char g_backend_path[PATH_MAX];
static char g_network[64];
static char g_base[PATH_MAX], g_cdir[PATH_MAX], g_wdir[PATH_MAX], g_ndir[PATH_MAX], g_sock[PATH_MAX];
static char g_rpc_bind[128] = "127.0.0.1";
static int g_rpc_port = 0;
static char g_rpc_user[128] = "";
static char g_rpc_password[256] = "";

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
    puts("qrxd --network <alpha|testnet|regtest|mainnet> [--datadir PATH] [--wallet NAME] [--listen host:port] [--addnode host:port]... [--rpc-bind host:port] [--rpc-user USER] [--rpc-password PASS] [--blocktime SECONDS] [--commission-bps BPS] [--no-block-producer]\nJSON-RPC is served over HTTP on --rpc-bind. Default: 127.0.0.1:3766x based on network. Auth is enabled when --rpc-user and --rpc-password are provided.");
}

static void on_sig(int sig){ (void)sig; g_running = 0; stop_node_process(); }
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
        run_capture(bootstrap, buf, sizeof(buf));
        run_capture(process, buf, sizeof(buf));
        run_capture(decay, buf, sizeof(buf));
        for(int i=0;i<5 && g_running;i++) sleep(1);
    }
    return NULL;
}

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
        char out[65536], block_path[PATH_MAX], vote_path[PATH_MAX], height_s[64], round_s[64], validator[512], vote_dest[PATH_MAX];
        char max_txs_s[16]; snprintf(max_txs_s,sizeof(max_txs_s),"100");
        char *propose[] = { g_backend_path, "propose-block", g_ndir, max_txs_s, NULL };
        if(run_capture(propose,out,sizeof(out))!=0) continue;
        if(parse_last_path_with_suffix(out,".block",block_path,sizeof(block_path))!=0) continue;
        char *verify[] = { g_backend_path, "verify-block", g_cdir, block_path, NULL };
        run_capture(verify,out,sizeof(out));
        char *vote[] = { g_backend_path, "vote-block", g_ndir, block_path, NULL };
        if(run_capture(vote,out,sizeof(out))!=0) continue;
        if(parse_last_path_with_suffix(out,".vote",vote_path,sizeof(vote_path))==0){
            if(cfg_get_line_local(vote_path,"height",height_s,sizeof(height_s))==0 && cfg_get_line_local(vote_path,"round",round_s,sizeof(round_s))==0 && cfg_get_line_local(vote_path,"validator",validator,sizeof(validator))==0){
                snprintf(vote_dest,sizeof(vote_dest),"%s/consensus/votes/%s-%s-%s.vote",g_cdir,height_s,round_s,validator);
                copy_file_local(vote_path,vote_dest);
            }
        }
        char *tally[] = { g_backend_path, "tally-votes", g_cdir, block_path, NULL };
        run_capture(tally,out,sizeof(out));
        char *finalize[] = { g_backend_path, "finalize-block", g_cdir, block_path, NULL };
        if(run_capture(finalize,out,sizeof(out))==0){
            char bps[32]; snprintf(bps,sizeof(bps),"%lld",g_commission_bps);
            char *reward[] = { g_backend_path, "reward-epoch-auto", g_cdir, bps, "--block-finalized", NULL };
            run_capture(reward,out,sizeof(out));
        }
        char *publish[] = { g_backend_path, "node-publish-block", g_ndir, block_path, NULL };
        run_capture(publish,out,sizeof(out));
    }
    return NULL;
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
    snprintf(search, sizeof(search), "%s\*", dirpath);
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
        "Access-Control-Allow-Origin: http://localhost\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
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
        http_response(resp, resp_sz, 200, "{\"ok\":true}\n", 0);
        return;
    }
    if(!strstr(req, "POST ") || (!strstr(req, " /rpc ") && !strstr(req, " / "))) {
        http_response(resp, resp_sz, 404, "{\"ok\":false,\"error\":\"not found\"}\n", 0);
        return;
    }
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
    char tail[3072] = {0};
    char cmd[4096] = {0};
    char raw[65536] = {0};

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

static int handle_command(const char *cmdline, char *resp, size_t resp_sz){
    char line[4096]; snprintf(line, sizeof(line), "%s", cmdline); trim_nl(line);
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
    if(!strcmp(args[0], "getblockcount")){
        char bdir[PATH_MAX]; snprintf(bdir,sizeof(bdir), "%s/blocks", g_cdir);
        return json_ok_number(resp, resp_sz, "getblockcount", "count", count_regular_files(bdir)), 0;
    }
    if(!strcmp(args[0], "getnewaddress") || !strcmp(args[0], "address") || !strcmp(args[0], "receive")){
        char addr[512];
        if(qrx_get_wallet_address(g_wdir, addr, sizeof(addr)) != 0) json_error(resp, resp_sz, args[0], "address unavailable");
        else json_ok_string(resp, resp_sz, args[0], "address", addr);
        return 0;
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
        else { json_lines_array(arr1,sizeof(arr1),out1); json_keyval_object(obj2,sizeof(obj2),out2); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"getpeerinfo\",\"result\":{\"peers\":%s,\"peer_state\":%s}}\n", arr1, obj2); }
        return 0;
    }
    if(!strcmp(args[0], "peerstatus") || !strcmp(args[0], "banscores")){
        char out[16384], obj[20000]={0};
        char *argv[] = { g_backend_path, "peer-status", g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, args[0], "backend failed");
        else { json_keyval_object(obj,sizeof(obj),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"%s\",\"result\":%s}\n", args[0], obj); }
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
    if(!strcmp(args[0], "sendtoaddress") && argc >= 3){
        char out[8192]; const char *memo = argc >= 4 ? args[3] : "payment";
        char *argv[] = { g_backend_path, "send", g_wdir, g_cdir, args[1], args[2], (char*)memo, g_ndir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "sendtoaddress", "backend failed"); else json_ok_raw(resp, resp_sz, "sendtoaddress", out); return 0;
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
    if(!strcmp(args[0], "stealth-history")){
        char out[32768], arr[60000]={0}; char *argv[] = { g_backend_path, "stealth-history", g_cdir, g_wdir, NULL };
        if(run_capture(argv, out, sizeof(out)) != 0) json_error(resp, resp_sz, "stealth-history", "backend failed");
        else { json_lines_array(arr,sizeof(arr),out); snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stealth-history\",\"result\":{\"entries\":%s}}\n", arr); }
        return 0;
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
    json_error(resp, resp_sz, args[0], "unknown command");
    return 0;
}

int main(int argc, char **argv){
    const char *network="alpha", *datadir=NULL, *wallet="default", *listen_arg=NULL; const char *addnodes[64]; int addnode_count=0; const char *rpc_bind_arg=NULL;
    for(int i=1;i<argc;++i){
        if(!strcmp(argv[i],"--network")&&i+1<argc) network=argv[++i];
        else if(!strcmp(argv[i],"--datadir")&&i+1<argc) datadir=argv[++i];
        else if(!strcmp(argv[i],"--wallet")&&i+1<argc) wallet=argv[++i];
        else if(!strcmp(argv[i],"--listen")&&i+1<argc) listen_arg=argv[++i];
        else if(!strcmp(argv[i],"--addnode")&&i+1<argc&&addnode_count<64) addnodes[addnode_count++]=argv[++i];
        else if(!strcmp(argv[i],"--rpc-bind")&&i+1<argc) rpc_bind_arg=argv[++i];
        else if(!strcmp(argv[i],"--rpc-user")&&i+1<argc) snprintf(g_rpc_user,sizeof(g_rpc_user),"%s",argv[++i]);
        else if(!strcmp(argv[i],"--rpc-password")&&i+1<argc) snprintf(g_rpc_password,sizeof(g_rpc_password),"%s",argv[++i]);
        else if(!strcmp(argv[i],"--blocktime")&&i+1<argc) { g_blocktime_override_set=1; g_blocktime_seconds=atoi(argv[++i]); if(g_blocktime_seconds<1) g_blocktime_seconds=1; }
        else if(!strcmp(argv[i],"--commission-bps")&&i+1<argc) { g_commission_override_set=1; g_commission_bps=atoll(argv[++i]); if(g_commission_bps<0) g_commission_bps=0; if(g_commission_bps>10000) g_commission_bps=10000; }
        else if(!strcmp(argv[i],"--no-block-producer")) g_block_producer_enabled=0;
        else if(!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")){ usage(); return 0; }
        else { fprintf(stderr,"unknown arg: %s\n",argv[i]); usage(); return 1; }
    }
    snprintf(g_network, sizeof(g_network), "%s", network);
    parse_rpc_bind_default(network);
    if(rpc_bind_arg && parse_rpc_bind_arg(rpc_bind_arg)!=0){ fprintf(stderr,"bad --rpc-bind, expected host:port\n"); return 1; }
    const QrxProfile *profile = qrx_profile_by_name(network);
    if(!profile){ fprintf(stderr,"unknown network profile: %s\n", network); return 1; }
    if(!profile->allow_runtime_overrides && (g_blocktime_override_set || g_commission_override_set)){
        fprintf(stderr,"runtime chain parameter overrides are disabled for network '%s'. Use the profile-coded parameters or regtest.\n", network);
        return 1;
    }
    if(!g_blocktime_override_set) g_blocktime_seconds = profile->block_time_seconds;
    if(!g_commission_override_set) g_commission_bps = profile->default_validator_commission_bps;
    build_backend_path(argv[0]);
    if(qrx_ensure_node(network,datadir,wallet,listen_arg,addnodes,addnode_count,g_base,sizeof(g_base),g_cdir,sizeof(g_cdir),g_wdir,sizeof(g_wdir),g_ndir,sizeof(g_ndir))!=0){ fprintf(stderr,"qrxd: failed to initialize\n"); return 1; }
    snprintf(g_sock, sizeof(g_sock), "http://%s:%d/rpc", g_rpc_bind, g_rpc_port);
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
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
    printf("qrxd running network=%s datadir=%s node=%s rpc=%s node_pid=%ld blocktime=%d commission_bps=%lld auth=%s overrides=%s\n", g_network, g_base, g_ndir, g_sock, (long)g_node_pid, g_blocktime_seconds, g_commission_bps, (g_rpc_user[0]||g_rpc_password[0]) ? "enabled" : "disabled", profile->allow_runtime_overrides ? "allowed" : "disabled");
    while(g_running){
        qrx_socket_t fd = accept(s, NULL, NULL);
#ifdef _WIN32
        if(fd == INVALID_SOCKET) break;
#else
        if(fd < 0){ if(errno == EINTR) continue; break; }
#endif
        char cmd[65536];
#ifdef _WIN32
        int n = recv(fd, cmd, sizeof(cmd)-1, 0);
#else
        ssize_t n = recv(fd, cmd, sizeof(cmd)-1, 0);
#endif
        if(n < 0) n = 0;
        cmd[n] = 0;
        char resp[131072];
        int stop_after = 0;
        if(strstr(cmd, "POST ") == cmd || strstr(cmd, "OPTIONS ") == cmd || strstr(cmd, "GET ") == cmd) {
            handle_json_rpc_http(cmd, resp, sizeof(resp));
            if(strstr(cmd, "\"method\"") && strstr(cmd, "\"stop\"")) stop_after = 1;
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
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    stop_node_process();
#ifdef _WIN32
    g_running = 0;
    if(th){ WaitForSingleObject(th, 2000); CloseHandle(th); }
    if(prod_started && prod_th){ WaitForSingleObject(prod_th, 2000); CloseHandle(prod_th); }
#else
    pthread_cancel(th); pthread_join(th, NULL);
    if(prod_started){ pthread_cancel(prod_th); pthread_join(prod_th, NULL); }
#endif
    return 0;
}
