#define _GNU_SOURCE
#include "core_frontend.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  #ifndef PATH_MAX
    #define PATH_MAX MAX_PATH
  #endif
  typedef SSIZE_T ssize_t;
  #define strtok_r strtok_s
  static void qrx_wsa_init_once(void) {
      static int done = 0;
      if (!done) {
          WSADATA wsa;
          WSAStartup(MAKEWORD(2, 2), &wsa);
          done = 1;
      }
  }
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <unistd.h>
  static void qrx_wsa_init_once(void) { }
#endif

#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif

static void qrx_trim_line(char *s) {
    if(!s) return;
    s[strcspn(s, "\r\n \t")] = 0;
}

static int qrx_read_file_first_line(const char *path, char *out, size_t out_sz) {
    FILE *f;
    if(!path || !out || out_sz == 0) return -1;
    f = fopen(path, "rb");
    if(!f) return -1;
    if(!fgets(out, (int)out_sz, f)) { fclose(f); return -1; }
    fclose(f);
    qrx_trim_line(out);
    return out[0] ? 0 : -1;
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

static const char *qrx_detect_network(char *buf, size_t buf_sz) {
    const char *env = getenv("QRX_NETWORK");
    char path[PATH_MAX];
    if(env && *env) {
        snprintf(buf, buf_sz, "%s", env);
        qrx_trim_line(buf);
        return buf;
    }
    qrx_global_state_path(path, sizeof(path), "current_network");
    if(qrx_read_file_first_line(path, buf, buf_sz) == 0) return buf;
    snprintf(buf, buf_sz, "alpha");
    return buf;
}

static int qrx_control_port_for_network(const char *network) {
    if (!network || !*network) return 37661;
    if (!strcmp(network, "mainnet")) return 37660;
    if (!strcmp(network, "alpha")) return 37661;
    if (!strcmp(network, "testnet")) return 37662;
    if (!strcmp(network, "regtest")) return 37663;
    return 37661;
}

static char g_rpc_user[128] = "";
static char g_rpc_password[256] = "";

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

static void make_auth_header(char *out, size_t out_sz) {
    out[0] = 0;
    const char *eu = getenv("QRX_RPC_USER");
    const char *ep = getenv("QRX_RPC_PASSWORD");
    if(!g_rpc_user[0] && eu) snprintf(g_rpc_user, sizeof(g_rpc_user), "%s", eu);
    if(!g_rpc_password[0] && ep) snprintf(g_rpc_password, sizeof(g_rpc_password), "%s", ep);
    if(!g_rpc_user[0] && !g_rpc_password[0]) return;
    char pair[512];
    snprintf(pair, sizeof(pair), "%s:%s", g_rpc_user, g_rpc_password);
    char *b64 = qrx_base64_encode_local((const unsigned char*)pair, strlen(pair));
    if(!b64) return;
    snprintf(out, out_sz, "Authorization: Basic %s\r\n", b64);
    free(b64);
}

static void usage(void){
    puts("qrx-cli [--network <alpha|testnet|regtest|mainnet>] [--datadir PATH] [--wallet NAME] [--rpc-user USER] [--rpc-password PASS] <command>\nCommands: getinfo|getnewaddress|listaddresses|getbalance [addr]|getaddressnonce <addr> [lane]|getnoncelanes <addr>|getagent <agent>|listagents [owner]|getagentlimits <agent>|getorder <order_id>|listorders [owner_or_agent] [status]|gettrade <trade_id>|listtrades [market] [limit]|getorderbook <market> [depth]|getassetbalance <asset> [address]|listassets|gettradinginfo|getgateway <gateway>|listgateways [venue]|getexecutionreport <report_id>|getstateroot|getsettlement <trade_id>|getcrosschaininfo|getcrosschainswap <session_id>|listcrosschainswaps [status]|getcrosschainorderbook [depth]|getbtchtlctemplate <hashlock_hex> <buyer_btc_pubkey_hex> <seller_btc_refund_pubkey_hex> <csv_blocks> [mainnet|testnet|regtest]|getbtcspvinfo|getbtcbestheader|getbtcheader <hash|height>|verifybtcproof <txid> <block_hash> <tx_index> <branch_csv>|getbtcconfirmations <txid>|verifycrosschainfunding <session_id> <rawtx_hex> <block_hash> <tx_index> <branch_csv>|getcrosschainfunding <session_id>|getcrosschainsecurity <session_id>|getvelocityinfo|getvelocityengineinfo|getblockcount|getblockchaininfo|getnetworkinfo|getnodestatus|getuptime|getbuildinfo|getmempoolinfo|getrecentblocks [limit]|getrecenttransactions [limit]|getvalidatorstatus|getblockproducerinfo|getfeeinfo|getpeerinfo|getstakinginfo|getwalletinfo|getreward [height]|getparams [height]|gethalving [height]|getforks|getactivefork [height]|createrawtransaction <from> <to> <amount> <ed25519_pub_hex> <mldsa65_pub_b64> [memo] [fee] [nonce]|createvelocitytransaction <from> <to> <amount> <ed25519_pub_hex> <mldsa65_pub_b64> <tx_type> <lane_id> <expiry_height> <payload> [fee] [nonce]|createagentregistertransaction <owner> <agent> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> <owner_ed_pub_hex> <owner_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createagentupdatetransaction <owner> <agent> <permissions> <max_trade_atoms> <daily_limit_atoms> <market_allowlist> <agent_expires_height> <owner_ed_pub_hex> <owner_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createagentrevoketransaction <owner> <agent> <owner_ed_pub_hex> <owner_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createordertransaction <agent> <owner> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createexternalordertransaction <agent> <owner> <venue> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|creategatewayregistertransaction <authority> <gateway> <venue> <name> <gateway_ed_pub_hex> <gateway_mldsa65_pub_b64> <gateway_expires_height> <authority_ed_pub_hex> <authority_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|creategatewayrevoketransaction <authority> <gateway> <authority_ed_pub_hex> <authority_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createexecutionreporttransaction <gateway> <owner> <order_id> <SUBMITTED|PARTIALLY_FILLED|FILLED|REJECTED|CANCELED> <filled_quantity_atoms> <avg_price_atoms> <venue_fee_atoms> <venue_order_id> <report_sequence> <gateway_ed_pub_hex> <gateway_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createcrosschainbuytransaction <agent> <owner> <btc_sats> <max_qub_per_btc_atoms> <order_expiry_height> <hashlock_hex> <btc_receive_pubkey_hex> <qrx_refund_height> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createcrosschainselltransaction <agent> <owner> <btc_sats> <min_qub_per_btc_atoms> <order_expiry_height> <btc_refund_pubkey_hex> <btc_refund_csv_blocks> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createcrosschainredeemtransaction <seller_owner> <session_id> <secret_hex> <owner_ed_pub_hex> <owner_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createcrosschainrefundtransaction <buyer_owner> <session_id> <owner_ed_pub_hex> <owner_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createbtcspvheadertransaction <address> <header_hex> <ed_pub_hex> <mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createbtcspvfundingprooftransaction <address> <session_id> <rawtx_hex> <block_hash> <tx_index> <branch_csv> <ed_pub_hex> <mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createordercanceltransaction <agent> <owner> <order_id> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|createorderreplacetransaction <agent> <owner> <order_id> <market> <BUY|SELL> <LIMIT|MARKET> <quantity_atoms> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]|signrawtransactionwithwallet <rawtxfile> <signedtxfile>|decoderawtransaction <txfile>|gettxid <txfile>|sendtoaddress <addr> <amount> [memo]|sendrawtransaction <txfile>|history [addr] [limit]|addnode <host:port>|listpeers|peerstatus|banscores|stake <amount>|delegate <validator> <amount>|validator-set|tokenomics|getdevaddress|faucet <addr> <amount>|createswap <recipient> <amount> <hashlock_hex> <timelock_seconds> [memo]|redeemswap <swap_id> <secret>|refundswap <swap_id>|getswap <swap_id>|listswaps|shielded-address|shield <amount> [shielded_address]|shielded-balance|shielded-send <shielded_address> <amount>|unshield <transparent_address> <amount>|shielded-history|stealth-address|stealth-send <stealth_address> <amount> [memo]|stealth-scan|stealth-history|privacy-feature-status|stop");
    puts("Phase 4F.2: createarbitragehedgetransaction <agent> <owner> <matched_crosschain_buy_order_id> <arbitrage_id> <quantity_sats> <limit_price_atoms> <order_expiry_height> <agent_ed_pub_hex> <agent_mldsa65_pub_b64> <lane_id> <tx_expiry_height> [fee] [nonce]");
    puts("Complete history: the local Core reader accepts `qrx list-trades <chain-dir> * all`; use qrx-wallet-cli export-ledger for an unbounded verified CSV export");
}

static int socket_call(const char *sock_path, const char *cmd, char *out, size_t out_sz){
    qrx_wsa_init_once();

    int port = 37661;
    const char *p = strstr(sock_path ? sock_path : "", "http://127.0.0.1:");
    if (!p) p = strstr(sock_path ? sock_path : "", "tcp://127.0.0.1:");
    if (p) {
        const char *colon = strrchr(sock_path, ':');
        if(colon) port = atoi(colon + 1);
    }

#ifdef _WIN32
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd == INVALID_SOCKET) return -1;
#else
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0) return -1;
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0){
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        return -1;
    }

    char method[128] = {0};
    char params[32768] = {0};
    char tmp[32768];
    snprintf(tmp, sizeof(tmp), "%s", cmd);
    tmp[strcspn(tmp, "\r\n")] = 0;
    char *save = NULL;
    char *tok = strtok_r(tmp, " ", &save);
    if(tok) snprintf(method, sizeof(method), "%s", tok);

    int first = 1;
    snprintf(params, sizeof(params), "[");
    while((tok = strtok_r(NULL, " ", &save)) != NULL){
        if(!first) strncat(params, ",", sizeof(params)-strlen(params)-1);
        strncat(params, "\"", sizeof(params)-strlen(params)-1);
        strncat(params, tok, sizeof(params)-strlen(params)-1);
        strncat(params, "\"", sizeof(params)-strlen(params)-1);
        first = 0;
    }
    strncat(params, "]", sizeof(params)-strlen(params)-1);

    char body[65536];
    snprintf(body, sizeof(body), "{\"method\":\"%s\",\"params\":%s}", method, params);

    char auth_header[1024];
    make_auth_header(auth_header, sizeof(auth_header));

    char req[131072];
    snprintf(req, sizeof(req),
        "POST /rpc HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Content-Type: application/json\r\n"
        "%s"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        port, auth_header, strlen(body), body);

#ifdef _WIN32
    if(send(fd, req, (int)strlen(req), 0) < 0){ closesocket(fd); return -1; }
    int n;
#else
    if(send(fd, req, strlen(req), 0) < 0){ close(fd); return -1; }
    ssize_t n;
#endif

    size_t off=0;
    while((n = recv(fd, out+off, (int)(out_sz>off?out_sz-off-1:0), 0)) > 0){
        off += (size_t)n;
        if(off + 1 >= out_sz) break;
    }
    out[off]=0;

#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif

    char *body_start = strstr(out, "\r\n\r\n");
    if(body_start) {
        body_start += 4;
        memmove(out, body_start, strlen(body_start)+1);
    }
    return 0;
}


int main(int argc,char **argv){
    char detected_network[64];
    const char *network=NULL, *datadir=NULL, *wallet="default"; int cmdi=-1;
    char base[PATH_MAX], cdir[PATH_MAX], wdir[PATH_MAX], ndir[PATH_MAX], sock[PATH_MAX];
    for(int i=1;i<argc;++i){
        if(!strcmp(argv[i],"--network")&&i+1<argc){network=argv[++i]; continue;}
        if(!strcmp(argv[i],"--datadir")&&i+1<argc){datadir=argv[++i]; continue;}
        if(!strcmp(argv[i],"--wallet")&&i+1<argc){wallet=argv[++i]; continue;}
        if(!strcmp(argv[i],"--rpc-user")&&i+1<argc){snprintf(g_rpc_user,sizeof(g_rpc_user),"%s",argv[++i]); continue;}
        if(!strcmp(argv[i],"--rpc-password")&&i+1<argc){snprintf(g_rpc_password,sizeof(g_rpc_password),"%s",argv[++i]); continue;}
        cmdi=i; break;
    }
    if(cmdi<0){ usage(); return 1; }
    if(!strcmp(argv[cmdi], "help") || !strcmp(argv[cmdi], "--help") || !strcmp(argv[cmdi], "-help") || !strcmp(argv[cmdi], "-h")) {
        usage();
        return 0;
    }
    if(!network || !*network) {
        network = qrx_detect_network(detected_network, sizeof(detected_network));
    }
    if(qrx_ensure_node(network,datadir,wallet,NULL,NULL,0,base,sizeof(base),cdir,sizeof(cdir),wdir,sizeof(wdir),ndir,sizeof(ndir))!=0){ fprintf(stderr,"qrx-cli: failed to initialize\n"); return 1; }
    snprintf(sock, sizeof(sock), "http://127.0.0.1:%d/rpc", qrx_control_port_for_network(network));
    char cmd[131072] = {0};
    if(!strcmp(argv[cmdi],"getinfo")) snprintf(cmd,sizeof(cmd),"getinfo\n");
    else if(!strcmp(argv[cmdi],"getnewaddress")) snprintf(cmd,sizeof(cmd),"getnewaddress\n");
    else if(!strcmp(argv[cmdi],"address")||!strcmp(argv[cmdi],"receive")) snprintf(cmd,sizeof(cmd),"address\n");
    else if(!strcmp(argv[cmdi],"listaddresses")) snprintf(cmd,sizeof(cmd),"listaddresses\n");
    else if(!strcmp(argv[cmdi],"getbalance")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getbalance %s\n" : "getbalance\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getblockcount")) snprintf(cmd,sizeof(cmd),"getblockcount\n");
    else if(!strcmp(argv[cmdi],"getaddressnonce") && cmdi+1<argc) snprintf(cmd,sizeof(cmd), cmdi+2<argc ? "getaddressnonce %s %s\n" : "getaddressnonce %s\n", argv[cmdi+1], cmdi+2<argc?argv[cmdi+2]:"");
    else if(!strcmp(argv[cmdi],"getnoncelanes") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getnoncelanes %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getagent") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getagent %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listagents")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "listagents %s\n" : "listagents\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getagentlimits") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getagentlimits %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getorder") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getorder %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listorders")) { if(cmdi+2<argc) snprintf(cmd,sizeof(cmd),"listorders %s %s\n",argv[cmdi+1],argv[cmdi+2]); else if(cmdi+1<argc) snprintf(cmd,sizeof(cmd),"listorders %s\n",argv[cmdi+1]); else snprintf(cmd,sizeof(cmd),"listorders\n"); }
    else if(!strcmp(argv[cmdi],"gettrade") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"gettrade %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listtrades")) { if(cmdi+2<argc) snprintf(cmd,sizeof(cmd),"listtrades %s %s\n",argv[cmdi+1],argv[cmdi+2]); else if(cmdi+1<argc) snprintf(cmd,sizeof(cmd),"listtrades %s\n",argv[cmdi+1]); else snprintf(cmd,sizeof(cmd),"listtrades\n"); }
    else if(!strcmp(argv[cmdi],"getorderbook") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),cmdi+2<argc?"getorderbook %s %s\n":"getorderbook %s\n",argv[cmdi+1],cmdi+2<argc?argv[cmdi+2]:"");
    else if(!strcmp(argv[cmdi],"getassetbalance") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),cmdi+2<argc?"getassetbalance %s %s\n":"getassetbalance %s\n",argv[cmdi+1],cmdi+2<argc?argv[cmdi+2]:"");
    else if(!strcmp(argv[cmdi],"listassets")) snprintf(cmd,sizeof(cmd),"listassets\n");
    else if(!strcmp(argv[cmdi],"gettradinginfo")) snprintf(cmd,sizeof(cmd),"gettradinginfo\n");
    else if(!strcmp(argv[cmdi],"getgateway") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getgateway %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listgateways")) snprintf(cmd,sizeof(cmd),cmdi+1<argc?"listgateways %s\n":"listgateways\n",cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getexecutionreport") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getexecutionreport %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getstateroot")) snprintf(cmd,sizeof(cmd),"getstateroot\n");
    else if(!strcmp(argv[cmdi],"getsettlement") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getsettlement %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getcrosschaininfo")) snprintf(cmd,sizeof(cmd),"getcrosschaininfo\n");
    else if(!strcmp(argv[cmdi],"getcrosschainswap") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getcrosschainswap %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listcrosschainswaps")) snprintf(cmd,sizeof(cmd),cmdi+1<argc?"listcrosschainswaps %s\n":"listcrosschainswaps\n",cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getcrosschainorderbook")) snprintf(cmd,sizeof(cmd),cmdi+1<argc?"getcrosschainorderbook %s\n":"getcrosschainorderbook\n",cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getbtchtlctemplate") && cmdi+4<argc) snprintf(cmd,sizeof(cmd),cmdi+5<argc?"getbtchtlctemplate %s %s %s %s %s\n":"getbtchtlctemplate %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],cmdi+5<argc?argv[cmdi+5]:"");
    else if(!strcmp(argv[cmdi],"getbtcspvinfo")) snprintf(cmd,sizeof(cmd),"getbtcspvinfo\n");
    else if(!strcmp(argv[cmdi],"getbtcbestheader")) snprintf(cmd,sizeof(cmd),"getbtcbestheader\n");
    else if(!strcmp(argv[cmdi],"getbtcheader") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getbtcheader %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"verifybtcproof") && cmdi+4<argc) snprintf(cmd,sizeof(cmd),"verifybtcproof %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4]);
    else if(!strcmp(argv[cmdi],"getbtcconfirmations") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getbtcconfirmations %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"verifycrosschainfunding") && cmdi+5<argc) snprintf(cmd,sizeof(cmd),"verifycrosschainfunding %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5]);
    else if(!strcmp(argv[cmdi],"getcrosschainfunding") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getcrosschainfunding %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getcrosschainsecurity") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getcrosschainsecurity %s\n",argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getvelocityinfo")) snprintf(cmd,sizeof(cmd),"getvelocityinfo\n");
    else if(!strcmp(argv[cmdi],"getvelocityengineinfo")) snprintf(cmd,sizeof(cmd),"getvelocityengineinfo\n");
    else if(!strcmp(argv[cmdi],"getblockchaininfo")) snprintf(cmd,sizeof(cmd),"getblockchaininfo\n");
    else if(!strcmp(argv[cmdi],"getnetworkinfo")) snprintf(cmd,sizeof(cmd),"getnetworkinfo\n");
    else if(!strcmp(argv[cmdi],"getnodestatus")) snprintf(cmd,sizeof(cmd),"getnodestatus\n");
    else if(!strcmp(argv[cmdi],"getuptime")) snprintf(cmd,sizeof(cmd),"getuptime\n");
    else if(!strcmp(argv[cmdi],"getbuildinfo")) snprintf(cmd,sizeof(cmd),"getbuildinfo\n");
    else if(!strcmp(argv[cmdi],"getmempoolinfo")) snprintf(cmd,sizeof(cmd),"getmempoolinfo\n");
    else if(!strcmp(argv[cmdi],"getrecentblocks")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getrecentblocks %s\n" : "getrecentblocks\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getrecenttransactions")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getrecenttransactions %s\n" : "getrecenttransactions\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getvalidatorstatus")) snprintf(cmd,sizeof(cmd),"getvalidatorstatus\n");
    else if(!strcmp(argv[cmdi],"getblockproducerinfo")) snprintf(cmd,sizeof(cmd),"getblockproducerinfo\n");
    else if(!strcmp(argv[cmdi],"getfeeinfo")) snprintf(cmd,sizeof(cmd),"getfeeinfo\n");
    else if(!strcmp(argv[cmdi],"getpeerinfo")) snprintf(cmd,sizeof(cmd),"getpeerinfo\n");
    else if(!strcmp(argv[cmdi],"getstakinginfo")) snprintf(cmd,sizeof(cmd),"getstakinginfo\n");
    else if(!strcmp(argv[cmdi],"getwalletinfo")) snprintf(cmd,sizeof(cmd),"getwalletinfo\n");
    else if(!strcmp(argv[cmdi],"history")) {
        if(cmdi+2<argc) snprintf(cmd,sizeof(cmd),"history %s %s\n", argv[cmdi+1], argv[cmdi+2]);
        else if(cmdi+1<argc) snprintf(cmd,sizeof(cmd),"history %s\n", argv[cmdi+1]);
        else snprintf(cmd,sizeof(cmd),"history\n");
    }
    else if(!strcmp(argv[cmdi],"addnode") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"addnode %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listpeers")) snprintf(cmd,sizeof(cmd),"listpeers\n");
    else if(!strcmp(argv[cmdi],"peerstatus")||!strcmp(argv[cmdi],"banscores")) snprintf(cmd,sizeof(cmd),"%s\n", argv[cmdi]);
    else if(!strcmp(argv[cmdi],"tokenomics")) snprintf(cmd,sizeof(cmd),"tokenomics\n");
    else if(!strcmp(argv[cmdi],"getdevaddress")) snprintf(cmd,sizeof(cmd),"getdevaddress\n");
    else if(!strcmp(argv[cmdi],"faucet") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"faucet %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    else if(!strcmp(argv[cmdi],"getreward")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getreward %s\n" : "getreward\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getparams")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getparams %s\n" : "getparams\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"gethalving")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "gethalving %s\n" : "gethalving\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getforks")) snprintf(cmd,sizeof(cmd),"getforks\n");
    else if(!strcmp(argv[cmdi],"getactivefork")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getactivefork %s\n" : "getactivefork\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"validator-set")) snprintf(cmd,sizeof(cmd),"validator-set\n");
    else if(!strcmp(argv[cmdi],"stake") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"stake %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"delegate") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"delegate %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    else if(!strcmp(argv[cmdi],"createswap") && cmdi+4<argc) {
        if(cmdi+5<argc) snprintf(cmd,sizeof(cmd),"createswap %s %s %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3], argv[cmdi+4], argv[cmdi+5]);
        else snprintf(cmd,sizeof(cmd),"createswap %s %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3], argv[cmdi+4]);
    }
    else if(!strcmp(argv[cmdi],"redeemswap") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"redeemswap %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    else if(!strcmp(argv[cmdi],"refundswap") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"refundswap %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"getswap") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"getswap %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"listswaps")) snprintf(cmd,sizeof(cmd),"listswaps\n");
    else if(!strcmp(argv[cmdi],"shielded-address")) snprintf(cmd,sizeof(cmd),"shielded-address\n");
    else if(!strcmp(argv[cmdi],"shield") && cmdi+1<argc) {
        if(cmdi+2<argc) snprintf(cmd,sizeof(cmd),"shield %s %s\n", argv[cmdi+1], argv[cmdi+2]);
        else snprintf(cmd,sizeof(cmd),"shield %s\n", argv[cmdi+1]);
    }
    else if(!strcmp(argv[cmdi],"shielded-balance")) snprintf(cmd,sizeof(cmd),"shielded-balance\n");
    else if(!strcmp(argv[cmdi],"shielded-send") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"shielded-send %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    else if(!strcmp(argv[cmdi],"unshield") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"unshield %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    else if(!strcmp(argv[cmdi],"shielded-history")) snprintf(cmd,sizeof(cmd),"shielded-history\n");
    else if(!strcmp(argv[cmdi],"stealth-address")) snprintf(cmd,sizeof(cmd),"stealth-address\n");
    else if(!strcmp(argv[cmdi],"stealth-send") && cmdi+2<argc) {
        if(cmdi+3<argc) snprintf(cmd,sizeof(cmd),"stealth-send %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3]);
        else snprintf(cmd,sizeof(cmd),"stealth-send %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    }
    else if(!strcmp(argv[cmdi],"stealth-scan")) snprintf(cmd,sizeof(cmd),"stealth-scan\n");
    else if(!strcmp(argv[cmdi],"stealth-history")) snprintf(cmd,sizeof(cmd),"stealth-history\n");
    else if(!strcmp(argv[cmdi],"privacy-feature-status")) snprintf(cmd,sizeof(cmd),"privacy-feature-status\n");
    else if(!strcmp(argv[cmdi],"createrawtransaction") && cmdi+5<argc) {
        if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"createrawtransaction %s %s %s %s %s %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3], argv[cmdi+4], argv[cmdi+5], argv[cmdi+6], argv[cmdi+7], argv[cmdi+8]);
        else if(cmdi+7<argc) snprintf(cmd,sizeof(cmd),"createrawtransaction %s %s %s %s %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3], argv[cmdi+4], argv[cmdi+5], argv[cmdi+6], argv[cmdi+7]);
        else if(cmdi+6<argc) snprintf(cmd,sizeof(cmd),"createrawtransaction %s %s %s %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3], argv[cmdi+4], argv[cmdi+5], argv[cmdi+6]);
        else snprintf(cmd,sizeof(cmd),"createrawtransaction %s %s %s %s %s\n", argv[cmdi+1], argv[cmdi+2], argv[cmdi+3], argv[cmdi+4], argv[cmdi+5]);
    }
    else if(!strcmp(argv[cmdi],"createvelocitytransaction") && cmdi+9<argc) {
        if(cmdi+11<argc) snprintf(cmd,sizeof(cmd),"createvelocitytransaction %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11]);
        else if(cmdi+10<argc) snprintf(cmd,sizeof(cmd),"createvelocitytransaction %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10]);
        else snprintf(cmd,sizeof(cmd),"createvelocitytransaction %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9]);
    }
    else if(!strcmp(argv[cmdi],"createagentregistertransaction") && cmdi+13<argc) {
        if(cmdi+15<argc) snprintf(cmd,sizeof(cmd),"createagentregistertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14],argv[cmdi+15]);
        else if(cmdi+14<argc) snprintf(cmd,sizeof(cmd),"createagentregistertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14]);
        else snprintf(cmd,sizeof(cmd),"createagentregistertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
    }
    else if(!strcmp(argv[cmdi],"createagentupdatetransaction") && cmdi+11<argc) {
        if(cmdi+13<argc) snprintf(cmd,sizeof(cmd),"createagentupdatetransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
        else if(cmdi+12<argc) snprintf(cmd,sizeof(cmd),"createagentupdatetransaction %s %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
        else snprintf(cmd,sizeof(cmd),"createagentupdatetransaction %s %s %s %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11]);
    }
    else if(!strcmp(argv[cmdi],"createagentrevoketransaction") && cmdi+6<argc) {
        if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"createagentrevoketransaction %s %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8]);
        else if(cmdi+7<argc) snprintf(cmd,sizeof(cmd),"createagentrevoketransaction %s %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7]);
        else snprintf(cmd,sizeof(cmd),"createagentrevoketransaction %s %s %s %s %s %s\n", argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6]);
    }
    else if(!strcmp(argv[cmdi],"createordertransaction") && cmdi+12<argc) {
        if(cmdi+14<argc) snprintf(cmd,sizeof(cmd),"createordertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14]);
        else if(cmdi+13<argc) snprintf(cmd,sizeof(cmd),"createordertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
        else snprintf(cmd,sizeof(cmd),"createordertransaction %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
    }
    else if(!strcmp(argv[cmdi],"createexternalordertransaction") && cmdi+13<argc) {
        if(cmdi+15<argc) snprintf(cmd,sizeof(cmd),"createexternalordertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14],argv[cmdi+15]);
        else if(cmdi+14<argc) snprintf(cmd,sizeof(cmd),"createexternalordertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14]);
        else snprintf(cmd,sizeof(cmd),"createexternalordertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
    }
    else if(!strcmp(argv[cmdi],"createarbitragehedgetransaction") && cmdi+11<argc) {
        if(cmdi+13<argc) snprintf(cmd,sizeof(cmd),"createarbitragehedgetransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
        else if(cmdi+12<argc) snprintf(cmd,sizeof(cmd),"createarbitragehedgetransaction %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
        else snprintf(cmd,sizeof(cmd),"createarbitragehedgetransaction %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11]);
    }
    else if(!strcmp(argv[cmdi],"creategatewayregistertransaction") && cmdi+11<argc) {
        if(cmdi+13<argc) snprintf(cmd,sizeof(cmd),"creategatewayregistertransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
        else if(cmdi+12<argc) snprintf(cmd,sizeof(cmd),"creategatewayregistertransaction %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
        else snprintf(cmd,sizeof(cmd),"creategatewayregistertransaction %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11]);
    }
    else if(!strcmp(argv[cmdi],"creategatewayrevoketransaction") && cmdi+6<argc) {
        if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"creategatewayrevoketransaction %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8]);
        else if(cmdi+7<argc) snprintf(cmd,sizeof(cmd),"creategatewayrevoketransaction %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7]);
        else snprintf(cmd,sizeof(cmd),"creategatewayrevoketransaction %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6]);
    }
    else if(!strcmp(argv[cmdi],"createexecutionreporttransaction") && cmdi+13<argc) {
        if(cmdi+15<argc) snprintf(cmd,sizeof(cmd),"createexecutionreporttransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14],argv[cmdi+15]);
        else if(cmdi+14<argc) snprintf(cmd,sizeof(cmd),"createexecutionreporttransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14]);
        else snprintf(cmd,sizeof(cmd),"createexecutionreporttransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
    }
    else if(!strcmp(argv[cmdi],"createcrosschainbuytransaction") && cmdi+12<argc) {
        if(cmdi+14<argc) snprintf(cmd,sizeof(cmd),"createcrosschainbuytransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14]);
        else if(cmdi+13<argc) snprintf(cmd,sizeof(cmd),"createcrosschainbuytransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
        else snprintf(cmd,sizeof(cmd),"createcrosschainbuytransaction %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
    }
    else if(!strcmp(argv[cmdi],"createcrosschainselltransaction") && cmdi+11<argc) {
        if(cmdi+13<argc) snprintf(cmd,sizeof(cmd),"createcrosschainselltransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
        else if(cmdi+12<argc) snprintf(cmd,sizeof(cmd),"createcrosschainselltransaction %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
        else snprintf(cmd,sizeof(cmd),"createcrosschainselltransaction %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11]);
    }
    else if(!strcmp(argv[cmdi],"createcrosschainredeemtransaction") && cmdi+7<argc) {
        if(cmdi+9<argc) snprintf(cmd,sizeof(cmd),"createcrosschainredeemtransaction %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9]);
        else if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"createcrosschainredeemtransaction %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8]);
        else snprintf(cmd,sizeof(cmd),"createcrosschainredeemtransaction %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7]);
    }
    else if(!strcmp(argv[cmdi],"createcrosschainrefundtransaction") && cmdi+6<argc) {
        if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"createcrosschainrefundtransaction %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8]);
        else if(cmdi+7<argc) snprintf(cmd,sizeof(cmd),"createcrosschainrefundtransaction %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7]);
        else snprintf(cmd,sizeof(cmd),"createcrosschainrefundtransaction %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6]);
    }
    else if(!strcmp(argv[cmdi],"createbtcspvheadertransaction") && cmdi+6<argc) {
        if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"createbtcspvheadertransaction %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8]);
        else if(cmdi+7<argc) snprintf(cmd,sizeof(cmd),"createbtcspvheadertransaction %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7]);
        else snprintf(cmd,sizeof(cmd),"createbtcspvheadertransaction %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6]);
    }
    else if(!strcmp(argv[cmdi],"createbtcspvfundingprooftransaction") && cmdi+10<argc) {
        if(cmdi+12<argc) snprintf(cmd,sizeof(cmd),"createbtcspvfundingprooftransaction %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12]);
        else if(cmdi+11<argc) snprintf(cmd,sizeof(cmd),"createbtcspvfundingprooftransaction %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11]);
        else snprintf(cmd,sizeof(cmd),"createbtcspvfundingprooftransaction %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10]);
    }
    else if(!strcmp(argv[cmdi],"createordercanceltransaction") && cmdi+7<argc) {
        if(cmdi+9<argc) snprintf(cmd,sizeof(cmd),"createordercanceltransaction %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9]);
        else if(cmdi+8<argc) snprintf(cmd,sizeof(cmd),"createordercanceltransaction %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8]);
        else snprintf(cmd,sizeof(cmd),"createordercanceltransaction %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7]);
    }
    else if(!strcmp(argv[cmdi],"createorderreplacetransaction") && cmdi+13<argc) {
        if(cmdi+15<argc) snprintf(cmd,sizeof(cmd),"createorderreplacetransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14],argv[cmdi+15]);
        else if(cmdi+14<argc) snprintf(cmd,sizeof(cmd),"createorderreplacetransaction %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13],argv[cmdi+14]);
        else snprintf(cmd,sizeof(cmd),"createorderreplacetransaction %s %s %s %s %s %s %s %s %s %s %s %s %s\n",argv[cmdi+1],argv[cmdi+2],argv[cmdi+3],argv[cmdi+4],argv[cmdi+5],argv[cmdi+6],argv[cmdi+7],argv[cmdi+8],argv[cmdi+9],argv[cmdi+10],argv[cmdi+11],argv[cmdi+12],argv[cmdi+13]);
    }
    else if(!strcmp(argv[cmdi],"signrawtransactionwithwallet") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"signrawtransactionwithwallet %s %s\n", argv[cmdi+1], argv[cmdi+2]);
    else if(!strcmp(argv[cmdi],"decoderawtransaction") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"decoderawtransaction %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"gettxid") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"gettxid %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"sendtoaddress") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"sendtoaddress %s %s %s\n", argv[cmdi+1], argv[cmdi+2], cmdi+3<argc?argv[cmdi+3]:"payment");
    else if(!strcmp(argv[cmdi],"sendrawtransaction") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"sendrawtransaction %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"stop")) snprintf(cmd,sizeof(cmd),"stop\n");
    else { usage(); return 1; }

    char out[131072];
    if(socket_call(sock, cmd, out, sizeof(out)) == 0){ fputs(out, stdout); return 0; }
    fprintf(stderr, "qrx-cli: daemon control socket unavailable at %s\n", sock);
    return 1;
}
