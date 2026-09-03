#include "qrx_velocity_mvcc.h"

#include <errno.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

static uint64_t mvcc_now_us(void){
#ifdef _WIN32
    LARGE_INTEGER f,c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart*1000000ULL)/f.QuadPart);
#else
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return (uint64_t)ts.tv_sec*1000000ULL+(uint64_t)ts.tv_nsec/1000ULL;
#endif
}

static int field(const char *tx,const char *key,char *out,size_t out_sz){
    if(!tx||!key||!out||out_sz==0)return -1; size_t kl=strlen(key); const char *p=tx;
    while(*p){const char *e=strchr(p,'\n');size_t n=e?(size_t)(e-p):strlen(p);if(n>kl+1&&!memcmp(p,key,kl)&&p[kl]=='='){size_t v=n-kl-1;if(v>=out_sz)v=out_sz-1;memcpy(out,p+kl+1,v);out[v]=0;return 0;}if(!e)break;p=e+1;}out[0]=0;return -1;
}

static int parse_ll(const char *s,long long *out,int positive){
    if(!s||!*s||!out)return -1; errno=0; char *end=NULL; long long v=strtoll(s,&end,10);
    if(errno||!end||*end)return -1; if(positive ? v<=0 : v<0)return -1; *out=v; return 0;
}

static int add_ll(long long a,long long b,long long *out){
    if(!out)return -1;
    if((b>0&&a>LLONG_MAX-b)||(b<0&&a<LLONG_MIN-b))return -1;
    *out=a+b; return 0;
}

static int kv_reserve(QrxVelocityMvccKV **arr,size_t *cap,size_t need){
    if(need<=*cap)return 0; size_t nc=*cap?*cap*2:16; while(nc<need)nc*=2;
    QrxVelocityMvccKV *p=(QrxVelocityMvccKV*)realloc(*arr,nc*sizeof(**arr)); if(!p)return -1;
    *arr=p; *cap=nc; return 0;
}

static int kv_set(QrxVelocityMvccKV **arr,size_t *count,size_t *cap,const char *key,const char *value){
    if(!arr||!count||!cap||!key||!value)return -1;
    for(size_t i=0;i<*count;i++) if(!strcmp((*arr)[i].key,key)){
        char *v=strdup(value); if(!v)return -1; free((*arr)[i].value); (*arr)[i].value=v; return 0;
    }
    if(kv_reserve(arr,cap,*count+1))return -1;
    (*arr)[*count].key=strdup(key); (*arr)[*count].value=strdup(value);
    if(!(*arr)[*count].key||!(*arr)[*count].value){free((*arr)[*count].key);free((*arr)[*count].value);return -1;}
    (*count)++; return 0;
}

static const char *kv_find(const QrxVelocityMvccKV *arr,size_t count,const char *key){
    for(size_t i=count;i>0;i--)if(!strcmp(arr[i-1].key,key))return arr[i-1].value; return NULL;
}

static void kv_free(QrxVelocityMvccKV *arr,size_t count){if(!arr)return;for(size_t i=0;i<count;i++){free(arr[i].key);free(arr[i].value);}free(arr);}

static int strset_add(char ***arr,size_t *count,size_t *cap,const char *value){
    if(!arr||!count||!cap||!value||!*value)return -1;for(size_t i=0;i<*count;i++)if(!strcmp((*arr)[i],value))return 0;
    if(*count>=*cap){size_t nc=*cap?*cap*2:16;char **nn=(char**)realloc(*arr,nc*sizeof(*nn));if(!nn)return -1;*arr=nn;*cap=nc;}
    (*arr)[*count]=strdup(value);if(!(*arr)[*count])return -1;(*count)++;return 0;
}
static void strset_free(char **arr,size_t count){if(!arr)return;for(size_t i=0;i<count;i++)free(arr[i]);free(arr);}
static int ws_track_read(QrxVelocityMvccWriteSet *ws,const char *key){return ws?strset_add(&ws->reads,&ws->read_count,&ws->read_cap,key):0;}
static int ws_track_prefix(QrxVelocityMvccWriteSet *ws,const char *prefix){return ws?strset_add(&ws->read_prefixes,&ws->read_prefix_count,&ws->read_prefix_cap,prefix):0;}

static int snapshot_get(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *key,char *out,size_t out_sz,int *found){
    if(ws_track_read(ws,key))return -1;const char *ov=kv_find(overlay,overlay_count,key); if(ov){snprintf(out,out_sz,"%s",ov);if(found)*found=1;return 0;}
    QrxDBView v; if(qrxdb_get_view_at(db,snap,key,&v)==0){size_t n=v.value_len<out_sz-1?v.value_len:out_sz-1;memcpy(out,v.value,n);out[n]=0;if(found)*found=1;return 0;}
    if(out_sz)out[0]=0;if(found)*found=0;return 0;
}

static int snapshot_get_ll(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *key,long long def,long long *out){
    char buf[128];int found=0;if(snapshot_get(db,snap,overlay,overlay_count,ws,key,buf,sizeof(buf),&found))return -1;if(!found){*out=def;return 0;}
    errno=0;char *end=NULL;long long v=strtoll(buf,&end,10);if(errno||!end||*end)return -1;*out=v;return 0;
}

static int ws_put(QrxVelocityMvccWriteSet *ws,const char *key,const char *value){return kv_set(&ws->writes,&ws->write_count,&ws->write_cap,key,value);}
static int ws_put_ll(QrxVelocityMvccWriteSet *ws,const char *key,long long value){char b[64];snprintf(b,sizeof(b),"%lld",value);return ws_put(ws,key,b);}

static int prepare_transfer(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,QrxVelocityMvccWriteSet *ws);

static int payload_field_mvcc(const char *payload,const char *key,char *out,size_t out_sz){
    if(!payload||!key||!out||!out_sz)return -1;size_t kl=strlen(key);const char *p=payload;
    while(*p){const char *e=strchr(p,';');size_t n=e?(size_t)(e-p):strlen(p);if(n>kl+1&&!memcmp(p,key,kl)&&p[kl]=='='){size_t v=n-kl-1;if(v>=out_sz)v=out_sz-1;memcpy(out,p+kl+1,v);out[v]=0;return 0;}if(!e)break;p=e+1;}out[0]=0;return -1;
}

static void ws_init(QrxVelocityMvccWriteSet *ws,const char *txid,size_t plan_index,uint32_t wave){
    memset(ws,0,sizeof(*ws));ws->plan_index=plan_index;ws->wave=wave;snprintf(ws->txid,sizeof(ws->txid),"%s",txid?txid:"");
}

/* Common Phase 4C outer-state adapter. Admission has already performed hybrid
   signature + chain binding checks. The snapshot adapter re-checks the pieces
   that can change while a transaction waits in the mempool: applied marker,
   sender balance and lane nonce. The resulting writes are still isolated. */
static int prepare_common_nontransfer(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,
                                      const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,
                                      QrxVelocityMvccWriteSet *ws,char type[64],char from[512],char to[512],char payload[16384],char body_hash[160]){
    char version[32],fee_s[64],nonce_s[64],lane_s[64];long long fee=0,nonce=0,lane=0;
    ws_init(ws,txid,plan_index,wave);
    if(field(tx,"tx_version",version,sizeof(version))||strcmp(version,"3")||field(tx,"tx_type",type,64))goto bad;
    if(field(tx,"from",from,512)||field(tx,"to",to,512)||field(tx,"fee",fee_s,sizeof(fee_s))||field(tx,"nonce",nonce_s,sizeof(nonce_s))||field(tx,"lane_id",lane_s,sizeof(lane_s))||field(tx,"payload",payload,16384))goto bad;
    if(field(tx,"body_hash_sha3_512",body_hash,160)!=0&&field(tx,"body_hash",body_hash,160)!=0)goto bad;
    if(parse_ll(fee_s,&fee,0)||parse_ll(nonce_s,&nonce,1)||parse_ll(lane_s,&lane,0))goto bad;
    char k_from[1024],k_nonce[1024],k_applied[1024],k_loc[1024],k_payload[1024],k_consensus[1024],tmp[512];int found=0;
    snprintf(k_from,sizeof(k_from),"acct:balance:%s",from);if(lane==0)snprintf(k_nonce,sizeof(k_nonce),"acct:nonce:%s",from);else snprintf(k_nonce,sizeof(k_nonce),"velocity:nonce:%s:%lld",from,lane);
    snprintf(k_applied,sizeof(k_applied),"tx:applied:%s",body_hash);snprintf(k_loc,sizeof(k_loc),"tx:loc:%s",body_hash);snprintf(k_payload,sizeof(k_payload),"tx:payload:%s",body_hash);snprintf(k_consensus,sizeof(k_consensus),"consensus:applytx:%s",body_hash);
    if(snapshot_get(db,snap,overlay,overlay_count,ws,k_applied,tmp,sizeof(tmp),&found)||found)goto bad;
    long long bal=0,current_nonce=0,newbal=0;if(snapshot_get_ll(db,snap,overlay,overlay_count,ws,k_from,0,&bal)||snapshot_get_ll(db,snap,overlay,overlay_count,ws,k_nonce,0,&current_nonce))goto bad;
    if(current_nonce==LLONG_MAX||nonce!=current_nonce+1||bal<fee||add_ll(bal,-fee,&newbal))goto bad;
    if(ws_put_ll(ws,k_from,newbal)||ws_put_ll(ws,k_nonce,nonce))goto oom;
    snprintf(tmp,sizeof(tmp),"height=%lld\napplied=1\n",height);if(ws_put(ws,k_applied,tmp))goto oom;
    snprintf(tmp,sizeof(tmp),"tx_hash=%s\nblock_hash=velocity-mvcc\nheight=%lld\nindex=%zu\n",body_hash,height,plan_index);if(ws_put(ws,k_loc,tmp))goto oom;
    if(ws_put(ws,k_payload,tx))goto oom;snprintf(tmp,sizeof(tmp),"height=%lld\ntype=velocity-%s-mvcc\ncommitted=1\n",height,type);if(ws_put(ws,k_consensus,tmp))goto oom;
    ws->fee_delta=fee;return QRX_MVCC_OK;
bad:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
oom:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
}

static int agent_key(char *out,size_t out_sz,const char *agent,const char *f){snprintf(out,out_sz,"velocity:agent:%s:%s",agent,f);return 0;}
static int gateway_key(char *out,size_t out_sz,const char *gw,const char *f){snprintf(out,out_sz,"velocity:gateway:%s:%s",gw,f);return 0;}
static int snapshot_entity(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *key,char *out,size_t out_sz){int found=0;if(snapshot_get(db,snap,overlay,overlay_count,ws,key,out,out_sz,&found))return -1;return found?0:1;}

static int prepare_agent_stateful(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,QrxVelocityMvccWriteSet *ws){
    char type[64],owner[512],agent[512],payload[16384],body_hash[160];int rc=prepare_common_nontransfer(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws,type,owner,agent,payload,body_hash);if(rc)return rc;
    if(strcmp(type,"AGENT_REGISTER")&&strcmp(type,"AGENT_UPDATE")&&strcmp(type,"AGENT_REVOKE")){ws->status=QRX_MVCC_UNSUPPORTED;return QRX_MVCC_UNSUPPORTED;}
    char k[1200],status[128]="",existing_owner[512]="";agent_key(k,sizeof(k),agent,"status");int hs=snapshot_entity(db,snap,overlay,overlay_count,ws,k,status,sizeof(status));agent_key(k,sizeof(k),agent,"owner");int ho=snapshot_entity(db,snap,overlay,overlay_count,ws,k,existing_owner,sizeof(existing_owner));
    int active=hs==0&&!strcmp(status,"active");
    if(!strcmp(type,"AGENT_REGISTER")){if(active)goto bad;}
    else {if(!active||ho!=0||strcmp(existing_owner,owner))goto bad;}
    char hb[64];snprintf(hb,sizeof(hb),"%lld",height);
#define APUT(F,V) do{agent_key(k,sizeof(k),agent,(F));if(ws_put(ws,k,(V)))goto oom;}while(0)
    if(!strcmp(type,"AGENT_REGISTER")||!strcmp(type,"AGENT_UPDATE")){
        char ed[4096],ml[8192],perm[1024],mx[64],daily[64],markets[4096],exp[64];
        if(payload_field_mvcc(payload,"permissions",perm,sizeof(perm))||payload_field_mvcc(payload,"max_trade_atoms",mx,sizeof(mx))||payload_field_mvcc(payload,"daily_limit_atoms",daily,sizeof(daily))||payload_field_mvcc(payload,"market_allowlist",markets,sizeof(markets))||payload_field_mvcc(payload,"expires_height",exp,sizeof(exp)))goto bad;
        if(!strcmp(type,"AGENT_REGISTER")){
            if(payload_field_mvcc(payload,"agent_ed25519_pub_hex",ed,sizeof(ed))||payload_field_mvcc(payload,"agent_mldsa65_pub_b64",ml,sizeof(ml)))goto bad;APUT("ed25519_pub_hex",ed);APUT("mldsa65_pub_b64",ml);
        }
        APUT("owner",owner);APUT("status","active");APUT("permissions",perm);APUT("max_trade_atoms",mx);APUT("daily_limit_atoms",daily);APUT("market_allowlist",markets);APUT("expires_height",exp);APUT("updated_height",hb);APUT("last_tx",body_hash);
    }else{
        APUT("status","revoked");APUT("revoked_height",hb);APUT("updated_height",hb);APUT("last_tx",body_hash);
    }
#undef APUT
    ws->status=QRX_MVCC_OK;return QRX_MVCC_OK;
bad:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
oom:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
}

static int prepare_gateway_stateful(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,QrxVelocityMvccWriteSet *ws){
    char type[64],authority[512],gateway[512],payload[16384],body_hash[160];int rc=prepare_common_nontransfer(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws,type,authority,gateway,payload,body_hash);if(rc)return rc;
    if(strcmp(type,"GATEWAY_REGISTER")&&strcmp(type,"GATEWAY_REVOKE")){ws->status=QRX_MVCC_UNSUPPORTED;return QRX_MVCC_UNSUPPORTED;}
    char k[1200],status[128]="";gateway_key(k,sizeof(k),gateway,"status");int hs=snapshot_entity(db,snap,overlay,overlay_count,ws,k,status,sizeof(status));if(!strcmp(type,"GATEWAY_REVOKE")&&(hs!=0||strcmp(status,"active")))goto bad;
    char hb[64];snprintf(hb,sizeof(hb),"%lld",height);
#define GPUT(F,V) do{gateway_key(k,sizeof(k),gateway,(F));if(ws_put(ws,k,(V)))goto oom;}while(0)
    if(!strcmp(type,"GATEWAY_REGISTER")){
        char venue[512],name[1024],ed[4096],ml[8192],exp[64];if(payload_field_mvcc(payload,"venue",venue,sizeof(venue))||payload_field_mvcc(payload,"name",name,sizeof(name))||payload_field_mvcc(payload,"gateway_ed25519_pub_hex",ed,sizeof(ed))||payload_field_mvcc(payload,"gateway_mldsa65_pub_b64",ml,sizeof(ml))||payload_field_mvcc(payload,"expires_height",exp,sizeof(exp)))goto bad;
        GPUT("authority",authority);GPUT("status","active");GPUT("venue",venue);GPUT("name",name);GPUT("ed25519_pub_hex",ed);GPUT("mldsa65_pub_b64",ml);GPUT("expires_height",exp);GPUT("updated_height",hb);GPUT("last_tx",body_hash);
    }else{GPUT("status","revoked");GPUT("revoked_height",hb);GPUT("updated_height",hb);GPUT("last_tx",body_hash);}
#undef GPUT
    ws->status=QRX_MVCC_OK;return QRX_MVCC_OK;
bad:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
oom:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
}

#include "qrx_velocity_dynamic.inc"

static int prepare_phase4c_tx(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,QrxVelocityMvccWriteSet *ws){
    uint8_t cls=qrx_velocity_tx_adapter_class(tx);char type[64]="";field(tx,"tx_type",type,sizeof(type));
    if(cls==QRX_VELOCITY_ADAPTER_TRANSFER)return prepare_transfer(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws);
    if(cls==QRX_VELOCITY_ADAPTER_STATEFUL){
        if(!strncmp(type,"AGENT_",6))return prepare_agent_stateful(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws);
        if(!strncmp(type,"GATEWAY_",8))return prepare_gateway_stateful(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws);
    }
    if(cls==QRX_VELOCITY_ADAPTER_DYNAMIC)return mvcc_prepare_native_dynamic(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws);
    ws_init(ws,txid,plan_index,wave);ws->status=QRX_MVCC_BARRIER;return QRX_MVCC_BARRIER;
}

static int prepare_transfer(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,QrxVelocityMvccWriteSet *ws){
    memset(ws,0,sizeof(*ws));ws->plan_index=plan_index;ws->wave=wave;snprintf(ws->txid,sizeof(ws->txid),"%s",txid?txid:"");
    char version[32],type[64],from[512],to[512],amount_s[64],fee_s[64],nonce_s[64],lane_s[64],body_hash[160];
    if(field(tx,"tx_version",version,sizeof(version))||strcmp(version,"3")||field(tx,"tx_type",type,sizeof(type))||strcmp(type,"TRANSFER_FAST")){ws->status=QRX_MVCC_UNSUPPORTED;return QRX_MVCC_UNSUPPORTED;}
    if(field(tx,"from",from,sizeof(from))||field(tx,"to",to,sizeof(to))||field(tx,"amount",amount_s,sizeof(amount_s))||field(tx,"fee",fee_s,sizeof(fee_s))||field(tx,"nonce",nonce_s,sizeof(nonce_s))||field(tx,"lane_id",lane_s,sizeof(lane_s))){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    if(field(tx,"body_hash_sha3_512",body_hash,sizeof(body_hash))!=0 && field(tx,"body_hash",body_hash,sizeof(body_hash))!=0){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    long long amount=0,fee=0,nonce=0,lane=0;if(parse_ll(amount_s,&amount,1)||parse_ll(fee_s,&fee,0)||parse_ll(nonce_s,&nonce,1)||parse_ll(lane_s,&lane,0)){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    char k_from[1024],k_to[1024],k_nonce[1024],k_applied[1024],k_loc[1024],k_payload[1024],k_consensus[1024];
    snprintf(k_from,sizeof(k_from),"acct:balance:%s",from);snprintf(k_to,sizeof(k_to),"acct:balance:%s",to);
    if(lane==0)snprintf(k_nonce,sizeof(k_nonce),"acct:nonce:%s",from);else snprintf(k_nonce,sizeof(k_nonce),"velocity:nonce:%s:%lld",from,lane);
    snprintf(k_applied,sizeof(k_applied),"tx:applied:%s",body_hash);snprintf(k_loc,sizeof(k_loc),"tx:loc:%s",body_hash);snprintf(k_payload,sizeof(k_payload),"tx:payload:%s",body_hash);snprintf(k_consensus,sizeof(k_consensus),"consensus:applytx:%s",body_hash);
    char tmp[256];int found=0;if(snapshot_get(db,snap,overlay,overlay_count,ws,k_applied,tmp,sizeof(tmp),&found)||found){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    long long frombal=0,tobal=0,current_nonce=0;if(snapshot_get_ll(db,snap,overlay,overlay_count,ws,k_from,0,&frombal)||snapshot_get_ll(db,snap,overlay,overlay_count,ws,k_to,0,&tobal)||snapshot_get_ll(db,snap,overlay,overlay_count,ws,k_nonce,0,&current_nonce)){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    if(current_nonce==LLONG_MAX||nonce!=current_nonce+1){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    long long debit=0;if(add_ll(amount,fee,&debit)||frombal<debit){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}
    long long new_from=0,new_to=tobal;
    if(!strcmp(from,to)){if(add_ll(frombal,-fee,&new_from)){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}new_to=new_from;}
    else {if(add_ll(frombal,-debit,&new_from)||add_ll(tobal,amount,&new_to)){ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;}}
    if(ws_put_ll(ws,k_from,new_from))goto oom;if(strcmp(from,to)&&ws_put_ll(ws,k_to,new_to))goto oom;if(ws_put_ll(ws,k_nonce,nonce))goto oom;
    snprintf(tmp,sizeof(tmp),"height=%lld\napplied=1\n",height);if(ws_put(ws,k_applied,tmp))goto oom;
    snprintf(tmp,sizeof(tmp),"tx_hash=%s\nblock_hash=velocity-mvcc\nheight=%lld\nindex=%zu\n",body_hash,height,plan_index);if(ws_put(ws,k_loc,tmp))goto oom;
    if(ws_put(ws,k_payload,tx))goto oom;snprintf(tmp,sizeof(tmp),"height=%lld\ntype=velocity-transfer-fast-mvcc\ncommitted=1\n",height);if(ws_put(ws,k_consensus,tmp))goto oom;
    ws->fee_delta=fee;ws->status=QRX_MVCC_OK;return QRX_MVCC_OK;
oom: ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
}

typedef struct {
    QrxDB *db; const QrxDBReadTxn *snap; const QrxVelocityPlan *plan; const unsigned char *valid_mask;
    const QrxVelocityMvccKV *overlay; size_t overlay_count; long long height; uint32_t wave;
    QrxVelocityMvccWriteSet *sets; size_t *indices; size_t count; size_t next; uint8_t speculative;
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} PrepWork;

static size_t prep_take(PrepWork *w){size_t n;
#ifdef _WIN32
EnterCriticalSection(&w->lock);
#else
pthread_mutex_lock(&w->lock);
#endif
n=w->next++;
#ifdef _WIN32
LeaveCriticalSection(&w->lock);
#else
pthread_mutex_unlock(&w->lock);
#endif
return n;}

#ifdef _WIN32
static DWORD WINAPI prep_worker(LPVOID arg)
#else
static void *prep_worker(void *arg)
#endif
{
    PrepWork *w=(PrepWork*)arg;for(;;){size_t n=prep_take(w);if(n>=w->count)break;size_t i=w->indices[n];QrxVelocityMvccWriteSet *ws=&w->sets[i];if(w->valid_mask&&!w->valid_mask[i]){ws->status=QRX_MVCC_ERROR;continue;}prepare_phase4c_tx(w->db,w->snap,w->overlay,w->overlay_count,w->plan->txs[i],w->plan->txids[i],i,w->wave,w->height,ws);ws->speculative=w->speculative;}
#ifdef _WIN32
return 0;
#else
return NULL;
#endif
}

static void ws_attempt_free(QrxVelocityMvccWriteSet *ws){
    if(!ws)return;kv_free(ws->writes,ws->write_count);strset_free(ws->reads,ws->read_count);strset_free(ws->read_prefixes,ws->read_prefix_count);memset(ws,0,sizeof(*ws));
}

static int key_has_prefix(const char *key,const char *prefix){size_t n=prefix?strlen(prefix):0;return key&&prefix&&n&&strncmp(key,prefix,n)==0;}

/* Directional OCC dependency test. Earlier deterministic transactions are
   allowed to have read state that a later transaction overwrites. A later
   speculative transaction must be retried only when an earlier accepted write
   invalidates one of its reads/predicate reads, or when both attempts write the
   same key. This reproduces plan-order serial semantics without depending on
   thread completion order. */
static int ws_runtime_conflict(const QrxVelocityMvccWriteSet *current,const QrxVelocityMvccWriteSet *prior){
    if(!current||!prior)return 1;
    for(size_t r=0;r<current->read_count;r++)for(size_t w=0;w<prior->write_count;w++)if(!strcmp(current->reads[r],prior->writes[w].key))return 1;
    for(size_t p=0;p<current->read_prefix_count;p++)for(size_t w=0;w<prior->write_count;w++)if(key_has_prefix(prior->writes[w].key,current->read_prefixes[p])){
        /* The Phase 4D matcher physically scans velocity:order:, but a newly
           created order in another known market is not a semantic phantom for
           this transaction. Preserve exact W/W and exact R/W checks, while
           scoping the broad orderbook predicate when both dynamic markets are
           known. */
        if(!strcmp(current->read_prefixes[p],"velocity:order:")&&current->dynamic_scope[0]&&prior->dynamic_scope[0]&&!mvcc_ieq(current->dynamic_scope,prior->dynamic_scope))continue;return 1;
    }
    for(size_t a=0;a<current->write_count;a++)for(size_t b=0;b<prior->write_count;b++)if(!strcmp(current->writes[a].key,prior->writes[b].key))return 1;
    return 0;
}

static int merge_final_ws(QrxVelocityMvccPrepared *out,const QrxVelocityPlan *plan,size_t i){
    QrxVelocityMvccWriteSet *ws=&out->sets[i];
    for(size_t k=0;k<ws->write_count;k++)if(kv_set(&out->merged,&out->merged_count,&out->merged_cap,ws->writes[k].key,ws->writes[k].value))return -1;
    if(add_ll(out->fee_delta_total,ws->fee_delta,&out->fee_delta_total))return -1;out->prepared++;
    if(ws->dynamic){out->dynamic_prepared++;out->dynamic_discovered_keys+=ws->discovered_keys;out->dynamic_trades+=ws->dynamic_trades;out->expired_orders+=ws->expired_orders;}
    else {char tt[64]="";field(plan->txs[i],"tx_type",tt,sizeof(tt));if(strcmp(tt,"TRANSFER_FAST"))out->stateful_prepared++;}
    return 0;
}

static int resolve_wave(QrxDB *db,QrxVelocityMvccPrepared *out,const QrxVelocityPlan *plan,const unsigned char *valid_mask,uint32_t wave,long long height,const size_t *indices,size_t cnt){
    size_t *accepted=(size_t*)calloc(cnt?cnt:1,sizeof(*accepted));if(!accepted)return -1;size_t accepted_count=0;
    for(size_t pos=0;pos<cnt;pos++){
        size_t i=indices[pos];QrxVelocityMvccWriteSet *ws=&out->sets[i];
        out->runtime_read_keys+=ws->read_count;out->runtime_read_prefixes+=ws->read_prefix_count;if(ws->speculative)out->speculative_prepared++;
        if(ws->status==QRX_MVCC_UNSUPPORTED){out->unsupported++;continue;}
        if(ws->status==QRX_MVCC_BARRIER){out->barriers++;continue;}
        if(ws->status!=QRX_MVCC_OK){out->failed++;free(accepted);return -1;}
        int conflict=0;for(size_t a=0;a<accepted_count;a++)if(ws_runtime_conflict(ws,&out->sets[accepted[a]])){out->conflict_edges++;conflict=1;}
        if(conflict){
            out->deterministic_conflicts++;out->selective_retries++;ws_attempt_free(ws);
            int rc=prepare_phase4c_tx(db,&out->snapshot,out->merged,out->merged_count,plan->txs[i],plan->txids[i],i,wave,height,ws);ws->speculative=1;ws->retried=1;ws->conflict_loser=1;out->runtime_read_keys+=ws->read_count;out->runtime_read_prefixes+=ws->read_prefix_count;
            if(valid_mask&&!valid_mask[i])rc=QRX_MVCC_ERROR;
            if(rc==QRX_MVCC_UNSUPPORTED||ws->status==QRX_MVCC_UNSUPPORTED){out->unsupported++;continue;}
            if(rc==QRX_MVCC_BARRIER||ws->status==QRX_MVCC_BARRIER){out->barriers++;continue;}
            if(rc!=QRX_MVCC_OK||ws->status!=QRX_MVCC_OK){out->failed++;free(accepted);return -1;}
        }else if(ws->speculative)out->speculative_winners++;
        if(merge_final_ws(out,plan,i)){free(accepted);return -1;}accepted[accepted_count++]=i;
    }
    free(accepted);return 0;
}

int qrx_velocity_mvcc_prepare_batch(QrxDB *db,const QrxVelocityPlan *plan,const unsigned char *valid_mask,uint32_t workers,long long height,QrxVelocityMvccPrepared *out,QrxVelocityMvccStats *stats){
    if(!db||!plan||!out)return QRX_MVCC_ERROR;memset(out,0,sizeof(*out));if(stats)memset(stats,0,sizeof(*stats));if(workers<1)workers=1;if(workers>64)workers=64;
    uint64_t t0=mvcc_now_us();if(qrxdb_parallel_validation_prepare(db,&out->snapshot))return QRX_MVCC_ERROR;out->sets=(QrxVelocityMvccWriteSet*)calloc(plan->count?plan->count:1,sizeof(*out->sets));if(!out->sets)return QRX_MVCC_ERROR;out->set_count=plan->count;out->waves=plan->wave_count;out->workers=workers;
    for(uint32_t wave=0;wave<plan->wave_count;wave++){
        size_t cnt=0;for(size_t i=0;i<plan->count;i++)if(plan->waves[i]==wave)cnt++;if(!cnt)continue;size_t *indices=(size_t*)malloc(cnt*sizeof(*indices));if(!indices){qrx_velocity_mvcc_prepared_free(out);return QRX_MVCC_ERROR;}size_t p=0;for(size_t i=0;i<plan->count;i++)if(plan->waves[i]==wave)indices[p++]=i;
        PrepWork w;memset(&w,0,sizeof(w));w.db=db;w.snap=&out->snapshot;w.plan=plan;w.valid_mask=valid_mask;w.overlay=out->merged;w.overlay_count=out->merged_count;w.height=height;w.wave=wave;w.sets=out->sets;w.indices=indices;w.count=cnt;w.speculative=(uint8_t)(cnt>1);
        uint32_t wc=workers;if(wc>cnt)wc=(uint32_t)cnt;if(wc<1)wc=1;
#ifdef _WIN32
        InitializeCriticalSection(&w.lock);HANDLE *ths=(HANDLE*)calloc(wc,sizeof(HANDLE));if(!ths){DeleteCriticalSection(&w.lock);free(indices);qrx_velocity_mvcc_prepared_free(out);return QRX_MVCC_ERROR;}for(uint32_t i=0;i<wc;i++)ths[i]=CreateThread(NULL,0,prep_worker,&w,0,NULL);for(uint32_t i=0;i<wc;i++){WaitForSingleObject(ths[i],INFINITE);CloseHandle(ths[i]);}free(ths);DeleteCriticalSection(&w.lock);
#else
        pthread_mutex_init(&w.lock,NULL);pthread_t *ths=(pthread_t*)calloc(wc,sizeof(pthread_t));if(!ths){pthread_mutex_destroy(&w.lock);free(indices);qrx_velocity_mvcc_prepared_free(out);return QRX_MVCC_ERROR;}for(uint32_t i=0;i<wc;i++)pthread_create(&ths[i],NULL,prep_worker,&w);for(uint32_t i=0;i<wc;i++)pthread_join(ths[i],NULL);free(ths);pthread_mutex_destroy(&w.lock);
#endif
        if(resolve_wave(db,out,plan,valid_mask,wave,height,indices,cnt)){free(indices);qrx_velocity_mvcc_prepared_free(out);return QRX_MVCC_ERROR;}free(indices);
    }
    if(out->fee_delta_total){long long fee_base=0,fee_new=0;if(snapshot_get_ll(db,&out->snapshot,out->merged,out->merged_count,NULL,"consensus:fee_pool:pending",0,&fee_base)||add_ll(fee_base,out->fee_delta_total,&fee_new) ) {qrx_velocity_mvcc_prepared_free(out);return QRX_MVCC_ERROR;}char b[64];snprintf(b,sizeof(b),"%lld",fee_new);if(kv_set(&out->merged,&out->merged_count,&out->merged_cap,"consensus:fee_pool:pending",b)){qrx_velocity_mvcc_prepared_free(out);return QRX_MVCC_ERROR;}}
    if(stats){stats->snapshot_generation=out->snapshot.generation;stats->prepared=out->prepared;stats->unsupported=out->unsupported;stats->barriers=out->barriers;stats->stateful_prepared=out->stateful_prepared;stats->dynamic_prepared=out->dynamic_prepared;stats->dynamic_discovered_keys=out->dynamic_discovered_keys;stats->dynamic_trades=out->dynamic_trades;stats->expired_orders=out->expired_orders;stats->failed=out->failed;stats->merged_writes=out->merged_count;stats->speculative_prepared=out->speculative_prepared;stats->runtime_read_keys=out->runtime_read_keys;stats->runtime_read_prefixes=out->runtime_read_prefixes;stats->conflict_edges=out->conflict_edges;stats->deterministic_conflicts=out->deterministic_conflicts;stats->selective_retries=out->selective_retries;stats->speculative_winners=out->speculative_winners;stats->waves=out->waves;stats->workers=workers;stats->prepare_us=mvcc_now_us()-t0;}
    if(out->failed) return QRX_MVCC_ERROR;
    /* Phase 4E retains Phase 4D dynamic expansion and adds speculative parallel
       execution with deterministic runtime conflict resolution + selective retry.
       Remaining external/cross-chain/SPV families are explicit serial barriers,
       and a plan containing such a barrier is never partially committed. */
    if(out->barriers) return QRX_MVCC_BARRIER;
    if(out->unsupported) return QRX_MVCC_UNSUPPORTED;
    return QRX_MVCC_OK;
}

static int cmp_kv(const void *aa,const void *bb){const QrxVelocityMvccKV *a=(const QrxVelocityMvccKV*)aa,*b=(const QrxVelocityMvccKV*)bb;return strcmp(a->key,b->key);}

int qrx_velocity_mvcc_commit(QrxDB *db,QrxVelocityMvccPrepared *prepared,QrxVelocityMvccStats *stats){
    if(!db||!prepared)return QRX_MVCC_ERROR;uint64_t t0=mvcc_now_us();prepared->conflict_rechecks++;
    if(qrxdb_generation(db)!=prepared->snapshot.generation){if(stats)stats->conflict_rechecks=prepared->conflict_rechecks;return QRX_MVCC_RETRY;}
    if(!prepared->merged_count){if(stats){stats->commit_generation=qrxdb_generation(db);qrxdb_merkle_root_hex(db,stats->state_root);stats->conflict_rechecks=prepared->conflict_rechecks;stats->commit_us=mvcc_now_us()-t0;}return QRX_MVCC_OK;}
    qsort(prepared->merged,prepared->merged_count,sizeof(prepared->merged[0]),cmp_kv);
    QrxDBBatch batch;if(qrxdb_batch_begin(db,&batch))return QRX_MVCC_ERROR;for(size_t i=0;i<prepared->merged_count;i++)if(qrxdb_batch_put(&batch,prepared->merged[i].key,prepared->merged[i].value)){qrxdb_batch_abort(&batch);return QRX_MVCC_ERROR;}
    if(qrxdb_generation(db)!=prepared->snapshot.generation){qrxdb_batch_abort(&batch);if(stats)stats->conflict_rechecks=prepared->conflict_rechecks;return QRX_MVCC_RETRY;}
    if(qrxdb_batch_commit(&batch)){qrxdb_batch_abort(&batch);return QRX_MVCC_ERROR;}
    if(stats){stats->snapshot_generation=prepared->snapshot.generation;stats->commit_generation=qrxdb_generation(db);stats->prepared=prepared->prepared;stats->committed=prepared->prepared;stats->unsupported=prepared->unsupported;stats->barriers=prepared->barriers;stats->stateful_prepared=prepared->stateful_prepared;stats->dynamic_prepared=prepared->dynamic_prepared;stats->dynamic_discovered_keys=prepared->dynamic_discovered_keys;stats->dynamic_trades=prepared->dynamic_trades;stats->expired_orders=prepared->expired_orders;stats->failed=prepared->failed;stats->merged_writes=prepared->merged_count;stats->conflict_rechecks=prepared->conflict_rechecks;stats->speculative_prepared=prepared->speculative_prepared;stats->runtime_read_keys=prepared->runtime_read_keys;stats->runtime_read_prefixes=prepared->runtime_read_prefixes;stats->conflict_edges=prepared->conflict_edges;stats->deterministic_conflicts=prepared->deterministic_conflicts;stats->selective_retries=prepared->selective_retries;stats->speculative_winners=prepared->speculative_winners;stats->waves=prepared->waves;stats->workers=prepared->workers;stats->commit_us=mvcc_now_us()-t0;qrxdb_merkle_root_hex(db,stats->state_root);}return QRX_MVCC_OK;
}

int qrx_velocity_mvcc_execute_batch(QrxDB *db,const QrxVelocityPlan *plan,const unsigned char *valid_mask,uint32_t workers,long long height,QrxVelocityMvccStats *stats){
    QrxVelocityMvccPrepared p;QrxVelocityMvccStats local;QrxVelocityMvccStats *s=stats?stats:&local;int rc=qrx_velocity_mvcc_prepare_batch(db,plan,valid_mask,workers,height,&p,s);if(rc!=QRX_MVCC_OK){qrx_velocity_mvcc_prepared_free(&p);return rc;}rc=qrx_velocity_mvcc_commit(db,&p,s);qrx_velocity_mvcc_prepared_free(&p);return rc;
}

int qrx_velocity_mvcc_prepare_transfer_batch(QrxDB *db,const QrxVelocityPlan *plan,const unsigned char *valid_mask,uint32_t workers,long long height,QrxVelocityMvccPrepared *out,QrxVelocityMvccStats *stats){int rc=qrx_velocity_mvcc_prepare_batch(db,plan,valid_mask,workers,height,out,stats);return rc==QRX_MVCC_BARRIER?QRX_MVCC_UNSUPPORTED:rc;}

int qrx_velocity_mvcc_execute_transfer_batch(QrxDB *db,const QrxVelocityPlan *plan,const unsigned char *valid_mask,uint32_t workers,long long height,QrxVelocityMvccStats *stats){int rc=qrx_velocity_mvcc_execute_batch(db,plan,valid_mask,workers,height,stats);return rc==QRX_MVCC_BARRIER?QRX_MVCC_UNSUPPORTED:rc;}

void qrx_velocity_mvcc_prepared_free(QrxVelocityMvccPrepared *p){if(!p)return;if(p->sets){for(size_t i=0;i<p->set_count;i++){kv_free(p->sets[i].writes,p->sets[i].write_count);strset_free(p->sets[i].reads,p->sets[i].read_count);strset_free(p->sets[i].read_prefixes,p->sets[i].read_prefix_count);}free(p->sets);}kv_free(p->merged,p->merged_count);memset(p,0,sizeof(*p));}
