#define _GNU_SOURCE
#include "core_frontend.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

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

typedef struct {
    const char *node_dir;
    const char *chain_dir;
} MaintCtx;

static void usage(void){
    puts("qrxd --network <alpha|testnet|regtest|mainnet> [--datadir PATH] [--wallet NAME] [--listen host:port] [--addnode host:port]... [--blocktime SECONDS] [--commission-bps BPS] [--no-block-producer]\nChain parameters are profile-coded. --blocktime/--commission-bps are accepted only on profiles that allow runtime overrides, currently regtest.");
}

static void on_sig(int sig){ (void)sig; g_running = 0; if(g_node_pid > 0) kill(g_node_pid, SIGTERM); }

static void dirname_of(const char *path, char *out, size_t out_sz){
    snprintf(out, out_sz, "%s", path && *path ? path : ".");
    char *slash = strrchr(out, '/');
    if(slash) { *slash = 0; if(!*out) snprintf(out, out_sz, "/"); }
    else snprintf(out, out_sz, ".");
}

static void build_backend_path(const char *argv0){
    char dir[PATH_MAX];
    dirname_of(argv0, dir, sizeof(dir));
    snprintf(g_backend_path, sizeof(g_backend_path), "%s/qrx", dir);
}

static void trim_nl(char *s){ if(!s) return; s[strcspn(s, "\r\n")] = 0; }
static void trim_ws_right(char *s){ if(!s) return; size_t n=strlen(s); while(n && (s[n-1]=='\n'||s[n-1]=='\r'||s[n-1]==' '||s[n-1]=='\t')) s[--n]=0; }

static int run_capture(char *const argv[], char *out, size_t out_sz){
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
}

static void *maint_loop(void *arg){
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

static void *producer_loop(void *arg){
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

static int write_all(int fd, const char *buf, size_t len){
    while(len){ ssize_t n = write(fd, buf, len); if(n < 0){ if(errno == EINTR) continue; return -1; } buf += n; len -= (size_t)n; }
    return 0;
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
    DIR *d = opendir(dirpath); if(!d) return 0;
    long long n = 0; struct dirent *de;
    while((de = readdir(d))){ if(de->d_name[0]=='.') continue; if(de->d_type == DT_REG || de->d_type == DT_UNKNOWN) n++; }
    closedir(d); return n;
}

static int parse_hostport_local(const char *hp, char *host, size_t host_sz, char *port, size_t port_sz){
    return qrx_parse_hostport(hp, host, host_sz, port, port_sz);
}

static int handle_command(const char *cmdline, char *resp, size_t resp_sz){
    char line[4096]; snprintf(line, sizeof(line), "%s", cmdline); trim_nl(line);
    char *args[32] = {0}; int argc = 0; char *save = NULL; char *tok = strtok_r(line, " ", &save);
    while(tok && argc < 31){ args[argc++] = tok; tok = strtok_r(NULL, " ", &save); }
    if(argc == 0){ json_error(resp, resp_sz, "unknown", "empty command"); return 0; }
    if(!strcmp(args[0], "ping")){ snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"ping\",\"result\":{\"status\":\"PONG\"}}\n"); return 0; }
    if(!strcmp(args[0], "stop")){ snprintf(resp, resp_sz, "{\"ok\":true,\"method\":\"stop\",\"result\":{\"stopping\":true}}\n"); g_running = 0; if(g_node_pid > 0) kill(g_node_pid, SIGTERM); return 1; }
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
    const char *network="alpha", *datadir=NULL, *wallet="default", *listen_arg=NULL; const char *addnodes[64]; int addnode_count=0;
    for(int i=1;i<argc;++i){
        if(!strcmp(argv[i],"--network")&&i+1<argc) network=argv[++i];
        else if(!strcmp(argv[i],"--datadir")&&i+1<argc) datadir=argv[++i];
        else if(!strcmp(argv[i],"--wallet")&&i+1<argc) wallet=argv[++i];
        else if(!strcmp(argv[i],"--listen")&&i+1<argc) listen_arg=argv[++i];
        else if(!strcmp(argv[i],"--addnode")&&i+1<argc&&addnode_count<64) addnodes[addnode_count++]=argv[++i];
        else if(!strcmp(argv[i],"--blocktime")&&i+1<argc) { g_blocktime_override_set=1; g_blocktime_seconds=atoi(argv[++i]); if(g_blocktime_seconds<1) g_blocktime_seconds=1; }
        else if(!strcmp(argv[i],"--commission-bps")&&i+1<argc) { g_commission_override_set=1; g_commission_bps=atoll(argv[++i]); if(g_commission_bps<0) g_commission_bps=0; if(g_commission_bps>10000) g_commission_bps=10000; }
        else if(!strcmp(argv[i],"--no-block-producer")) g_block_producer_enabled=0;
        else if(!strcmp(argv[i],"--help")||!strcmp(argv[i],"-h")){ usage(); return 0; }
        else { fprintf(stderr,"unknown arg: %s\n",argv[i]); usage(); return 1; }
    }
    snprintf(g_network, sizeof(g_network), "%s", network);
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
    snprintf(g_sock, sizeof(g_sock), "%s/control.sock", g_base);
    unlink(g_sock);
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    if(spawn_node_process()!=0){ fprintf(stderr, "qrxd: failed to start node-run\n"); return 1; }
    MaintCtx ctx = { g_ndir, g_cdir }; pthread_t th; pthread_create(&th, NULL, maint_loop, &ctx);
    pthread_t prod_th; int prod_started = 0; if(g_block_producer_enabled){ pthread_create(&prod_th, NULL, producer_loop, &ctx); prod_started = 1; }

    int s = socket(AF_UNIX, SOCK_STREAM, 0); if(s < 0){ perror("socket"); return 1; }
    struct sockaddr_un sun; memset(&sun,0,sizeof(sun)); sun.sun_family = AF_UNIX; snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", g_sock);
    if(bind(s, (struct sockaddr*)&sun, sizeof(sun)) != 0){ perror("bind control"); return 1; }
    if(listen(s, 8) != 0){ perror("listen control"); return 1; }
    printf("qrxd running network=%s datadir=%s node=%s control=%s node_pid=%ld blocktime=%d commission_bps=%lld overrides=%s\n", g_network, g_base, g_ndir, g_sock, (long)g_node_pid, g_blocktime_seconds, g_commission_bps, profile->allow_runtime_overrides ? "allowed" : "disabled");
    while(g_running){
        int fd = accept(s, NULL, NULL);
        if(fd < 0){ if(errno == EINTR) continue; break; }
        char cmd[4096]; ssize_t n = read(fd, cmd, sizeof(cmd)-1); if(n < 0) n = 0; cmd[n] = 0;
        char resp[65536]; int stop_after = handle_command(cmd, resp, sizeof(resp));
        write_all(fd, resp, strlen(resp));
        close(fd);
        if(stop_after) break;
    }
    close(s); unlink(g_sock);
    if(g_node_pid > 0){ kill(g_node_pid, SIGTERM); waitpid(g_node_pid, NULL, 0); }
    pthread_cancel(th); pthread_join(th, NULL);
    if(prod_started){ pthread_cancel(prod_th); pthread_join(prod_th, NULL); }
    return 0;
}
