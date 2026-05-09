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
  #include <sys/un.h>
  #include <unistd.h>
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

static void usage(void){
    puts("qrx-cli --network <alpha|testnet|regtest|mainnet> [--datadir PATH] [--wallet NAME] <command>\nCommands: getinfo|getnewaddress|getbalance [addr]|getblockcount|getpeerinfo|getstakinginfo|getwalletinfo|getreward [height]|getparams [height]|gethalving [height]|getforks|getactivefork [height]|sendtoaddress <addr> <amount> [memo]|sendrawtransaction <txfile>|history [addr] [limit]|addnode <host:port>|listpeers|peerstatus|banscores|stake <amount>|delegate <validator> <amount>|validator-set|tokenomics|createswap <recipient> <amount> <hashlock_hex> <timelock_seconds> [memo]|redeemswap <swap_id> <secret>|refundswap <swap_id>|getswap <swap_id>|listswaps|shielded-address|shield <amount> [shielded_address]|shielded-balance|shielded-send <shielded_address> <amount>|unshield <transparent_address> <amount>|shielded-history|stealth-address|stealth-send <stealth_address> <amount> [memo]|stealth-scan|stealth-history|privacy-feature-status|stop");
}

static int socket_call(const char *sock_path, const char *cmd, char *out, size_t out_sz){
#ifdef _WIN32
    (void)sock_path;
    qrx_wsa_init_once();

    int port = 37661;
    const char *p = strstr(sock_path ? sock_path : "", "tcp://127.0.0.1:");
    if (p) port = atoi(p + strlen("tcp://127.0.0.1:"));

    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd == INVALID_SOCKET) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if(connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0){ closesocket(fd); return -1; }
    if(send(fd, cmd, (int)strlen(cmd), 0) < 0){ closesocket(fd); return -1; }

    int n;
    size_t off = 0;
    while((n = recv(fd, out + off, (int)(out_sz > off ? out_sz - off - 1 : 0), 0)) > 0){
        off += (size_t)n;
        if(off + 1 >= out_sz) break;
    }
    out[off]=0;
    closesocket(fd);
    return 0;
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); if(fd < 0) return -1;
    struct sockaddr_un sun; memset(&sun,0,sizeof(sun)); sun.sun_family = AF_UNIX; snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", sock_path);
    if(connect(fd, (struct sockaddr*)&sun, sizeof(sun)) != 0){ close(fd); return -1; }
    if(write(fd, cmd, strlen(cmd)) < 0){ close(fd); return -1; }
    ssize_t n; size_t off=0; while((n = read(fd, out+off, out_sz>off?out_sz-off-1:0)) > 0){ off += (size_t)n; if(off + 1 >= out_sz) break; }
    out[off]=0; close(fd); return 0;
#endif
}


int main(int argc,char **argv){
    const char *network="alpha", *datadir=NULL, *wallet="default"; int cmdi=-1;
    char base[PATH_MAX], cdir[PATH_MAX], wdir[PATH_MAX], ndir[PATH_MAX], sock[PATH_MAX];
    for(int i=1;i<argc;++i){ if(!strcmp(argv[i],"--network")&&i+1<argc){network=argv[++i]; continue;} if(!strcmp(argv[i],"--datadir")&&i+1<argc){datadir=argv[++i]; continue;} if(!strcmp(argv[i],"--wallet")&&i+1<argc){wallet=argv[++i]; continue;} cmdi=i; break; }
    if(cmdi<0){ usage(); return 1; }
    if(qrx_ensure_node(network,datadir,wallet,NULL,NULL,0,base,sizeof(base),cdir,sizeof(cdir),wdir,sizeof(wdir),ndir,sizeof(ndir))!=0){ fprintf(stderr,"qrx-cli: failed to initialize\n"); return 1; }
    #ifdef _WIN32
    snprintf(sock, sizeof(sock), "tcp://127.0.0.1:%d", qrx_control_port_for_network(network));
#else
    snprintf(sock, sizeof(sock), "%s/control.sock", base);
#endif
    char cmd[4096] = {0};
    if(!strcmp(argv[cmdi],"getinfo")) snprintf(cmd,sizeof(cmd),"getinfo\n");
    else if(!strcmp(argv[cmdi],"getnewaddress")||!strcmp(argv[cmdi],"address")||!strcmp(argv[cmdi],"receive")) snprintf(cmd,sizeof(cmd),"getnewaddress\n");
    else if(!strcmp(argv[cmdi],"getbalance")) snprintf(cmd,sizeof(cmd), cmdi+1<argc ? "getbalance %s\n" : "getbalance\n", cmdi+1<argc?argv[cmdi+1]:"");
    else if(!strcmp(argv[cmdi],"getblockcount")) snprintf(cmd,sizeof(cmd),"getblockcount\n");
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
    else if(!strcmp(argv[cmdi],"sendtoaddress") && cmdi+2<argc) snprintf(cmd,sizeof(cmd),"sendtoaddress %s %s %s\n", argv[cmdi+1], argv[cmdi+2], cmdi+3<argc?argv[cmdi+3]:"payment");
    else if(!strcmp(argv[cmdi],"sendrawtransaction") && cmdi+1<argc) snprintf(cmd,sizeof(cmd),"sendrawtransaction %s\n", argv[cmdi+1]);
    else if(!strcmp(argv[cmdi],"stop")) snprintf(cmd,sizeof(cmd),"stop\n");
    else { usage(); return 1; }

    char out[65536];
    if(socket_call(sock, cmd, out, sizeof(out)) == 0){ fputs(out, stdout); return 0; }
    fprintf(stderr, "qrx-cli: daemon control socket unavailable at %s\n", sock);
    return 1;
}
