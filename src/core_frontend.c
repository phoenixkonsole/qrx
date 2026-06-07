#define _GNU_SOURCE
#include "core_frontend.h"
#include "qrx_core.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
  #include <windows.h>
  #include <direct.h>
  #include <io.h>
  #ifndef PATH_MAX
    #define PATH_MAX MAX_PATH
  #endif
  #define mkdir_qrx(path, mode) _mkdir(path)
  #define setenv_qrx(name, value, overwrite) _putenv_s((name), (value))
#else
  #include <unistd.h>
  #define mkdir_qrx(path, mode) mkdir((path), (mode))
  #define setenv_qrx(name, value, overwrite) setenv((name), (value), (overwrite))
#endif

#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif

static const QrxProfile PROFILES[] = {
    /* name, chain_name, network_id, genesis_hash, protocol_version, magic, port, seeds, slash_threshold, redistribute_bps, max_supply, epoch_reward, faucet_cap,
       block_time, max_txs, max_block_bytes, max_tx_bytes, validator_pct, delegator_pct, network_pool_pct, default_commission_bps, allow_overrides */
    {"alpha","QRX Public Alpha","qrx-alpha","9f1ad2e9e8c9f9b8a1d7e2c3456f7890abcdeffedcba09876543210fedcba98700112233445566778899aabbccddeeff11223344556677889900aabbccdd","62","QRXA62",26661,{"127.0.0.1:26661","127.0.0.1:26662","127.0.0.1:26663",NULL},"20","5000","2100000000000000","25000000","1000000000000",10,100,524288,8192,30,70,0,1000,0},
    {"testnet","QRX Testnet","qrx-testnet","7c10c4f0a7ee488da5021d31f6b5f42423f94f8c1055d4e0c2a0f1e2d3c4b5a6112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","62","QRXT62",26662,{"127.0.0.1:26662",NULL},"20","5000","2100000000000000","25000000","1000000000000",10,100,524288,8192,30,70,0,1000,0},
    {"regtest","QRX Regtest","qrx-regtest","5b7f9c2a4e6d8b0c1f3a597b2d4e6f8091a2b3c4d5e6f77889900aabbccddeeff1234567890abcdef11223344556677889900aabbccddeeff001122334455","62","QRXR62",26663,{"127.0.0.1:26663",NULL},"10","5000","1000000000000","1000000","1000000000",2,100,262144,8192,30,70,0,1000,1},
    {"mainnet","QRX Mainnet Preview","qrx-mainnet-preview","f0e1d2c3b4a5968778695a4b3c2d1e0ffedcba98765432100123456789abcdeffedcba98765432100123456789abcdeffedcba98765432100123456789abcd","62","QRXM62",26660,{NULL},"20","5000","2100000000000000","50000000","0",10,100,524288,8192,30,70,0,1000,0}
};

static int path_exists(const char *p){struct stat st; return stat(p,&st)==0;}
static int mkdir_p(const char *path){
    char tmp[PATH_MAX];
    size_t len;
    if(!path||!*path) return -1;
    snprintf(tmp,sizeof(tmp),"%s",path);
    len=strlen(tmp);
    if(len && (tmp[len-1]=='/' || tmp[len-1]=='\\')) tmp[len-1]=0;
    for(char *p=tmp+1; *p; ++p){
        if(*p=='/' || *p=='\\'){
            char old=*p;
            *p=0;
            if(mkdir_qrx(tmp,0700)!=0 && errno!=EEXIST) return -1;
            *p=old;
        }
    }
    if(mkdir_qrx(tmp,0700)!=0 && errno!=EEXIST) return -1;
    return 0;
}
static char *read_file_simple(const char *path){FILE *f=fopen(path,"rb"); long sz; char *buf; if(!f) return NULL; if(fseek(f,0,SEEK_END)!=0){fclose(f); return NULL;} sz=ftell(f); if(sz<0){fclose(f); return NULL;} rewind(f); buf=calloc((size_t)sz+1,1); if(!buf){fclose(f); return NULL;} if(fread(buf,1,(size_t)sz,f)!=(size_t)sz){fclose(f); free(buf); return NULL;} fclose(f); return buf;}
static int append_unique_line(const char *path, const char *entry){char *txt=read_file_simple(path); FILE *f; size_t elen=strlen(entry); const char *p=txt; if(txt){ while(p&&*p){ const char *e=strchr(p,'\n'); size_t len=e?(size_t)(e-p):strlen(p); if(len==elen && !strncmp(p,entry,len)){ free(txt); return 0;} p=e?e+1:NULL; } free(txt);} f=fopen(path,"ab"); if(!f) return -1; fprintf(f,"%s\n",entry); fclose(f); return 0;}

const QrxProfile *qrx_profile_by_name(const char *name){ size_t i; for(i=0;i<sizeof(PROFILES)/sizeof(PROFILES[0]);++i) if(!strcmp(PROFILES[i].name,name)) return &PROFILES[i]; return NULL; }

const char *qrx_dev_address_for_network(const char *network){
    if(!network) return "";
    if(!strcmp(network, "alpha")) return "qrx135710236209946eb1f26ec165f5cbfa2ed4d03f2fb224e4304404e69dc3d87b968ba72d448caf46d46727fdddf32b097920a4783926cb7444eabd08f";
    if(!strcmp(network, "testnet")) return "qrx1e4982fc3caf9c0f0b614b933760a6e7fddf9344fd5199531095afdb42607e038847172227cb5db795e86602862b5f09d891a09caf544743c6e9c612f";
    if(!strcmp(network, "mainnet")) return "qrx165b33aec7ea7b23fd20b61b7de53715b39bca6428531e80a6e9aaae89bdef9470a23fd4024c5f9de0f5386bdfbf239cccec1b79837c2a97aba8296d5";
    if(!strcmp(network, "regtest")) return "qrx1c2c759e4d32dba25f7f812dfd5919462fca1ac6ff867f588605e0438d709044eb3b05bd99380d688fee632a3b2879c9d9b32341fff9a905ad3ce6a90";
    return "";
}
int qrx_network_has_faucet(const char *network){
    return network && (!strcmp(network, "alpha") || !strcmp(network, "testnet") || !strcmp(network, "regtest"));
}

int qrx_backend_call(int argc, char **argv){ return qrx_backend_main(argc, argv); }
void qrx_default_datadir(const char *network, const char *override_datadir, char *out, size_t out_sz){
#ifdef _WIN32
    const char *home=getenv("USERPROFILE");
    if(!home) home=getenv("APPDATA");
#else
    const char *home=getenv("HOME");
#endif
    if(!home) home=".";
    if(override_datadir&&*override_datadir) snprintf(out,out_sz,"%s/%s",override_datadir,network);
    else snprintf(out,out_sz,"%s/.qrx/%s",home,network);
}
int qrx_parse_hostport(const char *in, char *host, size_t host_sz, char *port, size_t port_sz){ const char *c=strrchr(in,':'); size_t hlen; if(!c||c==in||!c[1]) return -1; hlen=(size_t)(c-in); if(hlen+1>host_sz || strlen(c+1)+1>port_sz) return -1; memcpy(host,in,hlen); host[hlen]=0; snprintf(port,port_sz,"%s",c+1); return 0; }
static int ensure_chain(const char *base, const QrxProfile *p, char *out_chain, size_t out_chain_sz){
    char cdir[PATH_MAX], conf[PATH_MAX], seedf[PATH_MAX];
    FILE *f;
    char block_time[32], max_txs[32], max_block[32], max_tx[32], val_pct[32], del_pct[32], net_pct[32];

    snprintf(cdir,sizeof(cdir),"%s/chain",base);
    if(mkdir_p(cdir)!=0) return -1;

    /* Stable future-proof directories */
    {
        char snapshots[PATH_MAX], wal[PATH_MAX], indexes[PATH_MAX];
        snprintf(snapshots,sizeof(snapshots),"%s/snapshots",cdir);
        snprintf(wal,sizeof(wal),"%s/wal",cdir);
        snprintf(indexes,sizeof(indexes),"%s/indexes",cdir);
        mkdir_p(snapshots);
        mkdir_p(wal);
        mkdir_p(indexes);
    }

    snprintf(block_time,sizeof(block_time),"%d",p->block_time_seconds);
    snprintf(max_txs,sizeof(max_txs),"%d",p->max_txs_per_block);
    snprintf(max_block,sizeof(max_block),"%d",p->max_block_bytes);
    snprintf(max_tx,sizeof(max_tx),"%d",p->max_tx_bytes);
    snprintf(val_pct,sizeof(val_pct),"%d",p->validator_reward_percent);
    snprintf(del_pct,sizeof(del_pct),"%d",p->delegator_reward_percent);
    snprintf(net_pct,sizeof(net_pct),"%d",p->network_pool_percent);

    snprintf(conf,sizeof(conf),"%s/chain.conf",cdir);
    if(!path_exists(conf)){
        char *argv_init[20];
        argv_init[0]="qrx";
        argv_init[1]="init-chain";
        argv_init[2]=cdir;
        argv_init[3]=(char*)p->slash_penalty_threshold;
        argv_init[4]=(char*)p->slash_redistribute_bps;
        argv_init[5]=(char*)p->max_supply_atoms;
        argv_init[6]=(char*)p->epoch_reward_atoms;
        argv_init[7]=(char*)p->faucet_cap_atoms;
        argv_init[8]=(char*)p->network_id;
        argv_init[9]=(char*)p->protocol_version;
        argv_init[10]=(char*)p->magic;
        argv_init[11]=(char*)p->chain_name;
        argv_init[12]=block_time;
        argv_init[13]=max_txs;
        argv_init[14]=max_block;
        argv_init[15]=max_tx;
        argv_init[16]=val_pct;
        argv_init[17]=del_pct;
        argv_init[18]=net_pct;
        argv_init[19]=NULL;
        if(qrx_backend_call(19,argv_init)!=0) return -1;
    }

    f=fopen(conf,"wb");
    if(!f) return -1;
    fprintf(f,
        "network_id=%s\n"
        "genesis_hash=%s\n"
        "protocol_version=%s\n"
        "magic=%s\n"
        "hash_primary=sha3-512\n"
        "hash_legacy=sha256\n"
        "chain_name=%s\n"
        "slash_penalty_threshold=%s\n"
        "slash_redistribute_bps=%s\n"
        "max_supply_atoms=%s\n"
        "epoch_reward_atoms=%s\n"
        "faucet_cap_atoms=%s\n"
        "block_time_seconds=%d\n"
        "max_txs_per_block=%d\n"
        "max_block_bytes=%d\n"
        "max_tx_bytes=%d\n"
        "validator_reward_percent=%d\n"
        "delegator_reward_percent=%d\n"
        "network_pool_percent=%d\n"
        "default_validator_commission_bps=%lld\n"
        "allow_runtime_overrides=%d\n"
        "storage_format=qrx-stable-v1\n"
        "snapshot_format=qrx-snapshot-v1\n"
        "state_schema_version=1\n"
        "supports_snapshot_import_export=1\n"
        "dev_address=%s\n"
        "treasury_address=%s\n"
        "faucet_enabled=%d\n",
        p->network_id,p->genesis_hash,p->protocol_version,p->magic,p->chain_name,
        p->slash_penalty_threshold,p->slash_redistribute_bps,p->max_supply_atoms,p->epoch_reward_atoms,p->faucet_cap_atoms,
        p->block_time_seconds,p->max_txs_per_block,p->max_block_bytes,p->max_tx_bytes,
        p->validator_reward_percent,p->delegator_reward_percent,p->network_pool_percent,
        p->default_validator_commission_bps,p->allow_runtime_overrides,
        qrx_dev_address_for_network(p->name), qrx_dev_address_for_network(p->name), qrx_network_has_faucet(p->name));
    fclose(f);

    snprintf(seedf,sizeof(seedf),"%s/seednodes.txt",cdir);
    f=fopen(seedf,"wb");
    if(!f) return -1;
    for(int i=0;p->seednodes[i];++i) fprintf(f,"%s\n",p->seednodes[i]);
    fclose(f);
    snprintf(out_chain,out_chain_sz,"%s",cdir);
    return 0;
}
static int ensure_wallet(const char *base, const char *wallet, char *out_wallet, size_t out_wallet_sz){ char wdir[PATH_MAX], apath[PATH_MAX]; char *argv_new[3]; snprintf(wdir,sizeof(wdir),"%s/wallets/%s",base,wallet); if(mkdir_p(wdir)!=0) return -1; snprintf(apath,sizeof(apath),"%s/address.txt",wdir); if(!path_exists(apath)){ if(!getenv("QRX_PASSPHRASE")) setenv_qrx("QRX_PASSPHRASE","change-me",1); argv_new[0]="qrx"; argv_new[1]="seed-new"; argv_new[2]=wdir; if(qrx_backend_call(3,argv_new)!=0) return -1; } snprintf(out_wallet,out_wallet_sz,"%s",wdir); return 0; }
int qrx_get_wallet_address(const char *wallet_dir, char *out, size_t out_sz){ char apath[PATH_MAX]; char *txt; snprintf(apath,sizeof(apath),"%s/address.txt",wallet_dir); txt=read_file_simple(apath); if(!txt) return -1; txt[strcspn(txt,"\r\n")]=0; snprintf(out,out_sz,"%s",txt); free(txt); return 0; }
static int ensure_node_conf(const char *base, const QrxProfile *p, const char *wallet, const char *listen, const char **addnodes, int addnode_count, char *out_node, size_t out_node_sz, const char *chain_dir, const char *wallet_dir){ char ndir[PATH_MAX], nconf[PATH_MAX], peers[PATH_MAX], seedf[PATH_MAX], host[128]="0.0.0.0", port[32], ep[256], self[256]; char *argv_node[7]; snprintf(port,sizeof(port),"%d",p->default_port); if(listen&&*listen && qrx_parse_hostport(listen,host,sizeof(host),port,sizeof(port))!=0) return -1; snprintf(ndir,sizeof(ndir),"%s/nodes/%s",base,wallet); if(mkdir_p(ndir)!=0) return -1; snprintf(nconf,sizeof(nconf),"%s/node.conf",ndir); if(!path_exists(nconf)){ argv_node[0]="qrx"; argv_node[1]="node-init"; argv_node[2]=ndir; argv_node[3]=(char*)chain_dir; argv_node[4]=(char*)wallet_dir; argv_node[5]=host; argv_node[6]=port; if(qrx_backend_call(7,argv_node)!=0) return -1; }
 snprintf(peers,sizeof(peers),"%s/peers.txt",ndir); snprintf(seedf,sizeof(seedf),"%s/seednodes.txt",ndir); snprintf(self,sizeof(self),"%s:%s",host,port); for(int i=0;p->seednodes[i];++i){ snprintf(ep,sizeof(ep),"%s",p->seednodes[i]); if(strcmp(ep,self)!=0){ append_unique_line(peers,ep); append_unique_line(seedf,ep);} }
 for(int i=0;i<addnode_count;++i){ char h[128], prt[32]; char *argv_add[5]; if(qrx_parse_hostport(addnodes[i],h,sizeof(h),prt,sizeof(prt))!=0) continue; argv_add[0]="qrx"; argv_add[1]="add-peer"; argv_add[2]=ndir; argv_add[3]=h; argv_add[4]=prt; qrx_backend_call(5,argv_add);} snprintf(out_node,out_node_sz,"%s",ndir); return 0; }
int qrx_ensure_node(const char *network, const char *datadir, const char *wallet, const char *listen, const char **addnodes, int addnode_count, char *out_base, size_t out_base_sz, char *out_chain, size_t out_chain_sz, char *out_wallet, size_t out_wallet_sz, char *out_node, size_t out_node_sz){ const QrxProfile *p=qrx_profile_by_name(network); if(!p) return -1; qrx_default_datadir(network,datadir,out_base,out_base_sz); if(mkdir_p(out_base)!=0) return -1; if(ensure_chain(out_base,p,out_chain,out_chain_sz)!=0) return -1; if(ensure_wallet(out_base,wallet,out_wallet,out_wallet_sz)!=0) return -1; if(ensure_node_conf(out_base,p,wallet,listen,addnodes,addnode_count,out_node,out_node_sz,out_chain,out_wallet)!=0) return -1; return 0; }
