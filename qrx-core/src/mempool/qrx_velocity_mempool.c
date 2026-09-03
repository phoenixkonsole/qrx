#include "qrx_velocity_mempool.h"
#include "qrx_velocity_scheduler.h"
#include "qrx_mempool_limits.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

#define QV_WAL_MAGIC 0x51565734u /* QVW4 */
#define QV_WAL_VERSION 1u
#define QV_WAL_ADD 1u
#define QV_WAL_REMOVE 2u

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t op;
    uint32_t payload_len;
    uint32_t crc32;
    char txid[129];
} QvWalHeader;

struct QrxVelocityShard {
    QrxVelocityMempoolEntry *items;
    size_t count;
    size_t cap;
};

static uint32_t crc32_local(const void *data, size_t len) {
    const unsigned char *p=(const unsigned char*)data; uint32_t crc=0xFFFFFFFFu;
    for(size_t i=0;i<len;i++){crc^=p[i];for(int j=0;j<8;j++)crc=(crc>>1)^((0u-(crc&1u))&0xEDB88320u);} return ~crc;
}

static int mkdir_if_missing(const char *p){
#ifdef _WIN32
    if(CreateDirectoryA(p,NULL) || GetLastError()==ERROR_ALREADY_EXISTS) return 0; return -1;
#else
    if(mkdir(p,0700)==0 || errno==EEXIST) return 0; return -1;
#endif
}

static void lock_pool(QrxVelocityMempool *p){
#ifdef _WIN32
    WaitForSingleObject((HANDLE)p->mutex_handle,INFINITE);
#else
    pthread_mutex_lock((pthread_mutex_t*)p->mutex_storage);
#endif
}
static void unlock_pool(QrxVelocityMempool *p){
#ifdef _WIN32
    ReleaseMutex((HANDLE)p->mutex_handle);
#else
    pthread_mutex_unlock((pthread_mutex_t*)p->mutex_storage);
#endif
}

static uint64_t fnv1a64(const char *s){uint64_t h=1469598103934665603ULL;for(;s&&*s;s++){h^=(unsigned char)*s;h*=1099511628211ULL;}return h;}

static int field(const char *tx,const char *key,char *out,size_t out_sz){
    if(!tx||!key||!out||out_sz==0)return -1; size_t kl=strlen(key); const char *p=tx;
    while(*p){const char *e=strchr(p,'\n');size_t n=e?(size_t)(e-p):strlen(p);if(n>kl+1&&!memcmp(p,key,kl)&&p[kl]=='='){size_t v=n-kl-1;if(v>=out_sz)v=out_sz-1;memcpy(out,p+kl+1,v);out[v]=0;return 0;}if(!e)break;p=e+1;} out[0]=0;return -1;
}

static int payload_field(const char *payload,const char *key,char *out,size_t out_sz){
    if(!payload||!key||!out||!out_sz)return -1;size_t kl=strlen(key);const char *p=payload;
    while(*p){const char *e=strchr(p,';');size_t n=e?(size_t)(e-p):strlen(p);if(n>kl+1&&!memcmp(p,key,kl)&&p[kl]=='='){size_t v=n-kl-1;if(v>=out_sz)v=out_sz-1;memcpy(out,p+kl+1,v);out[v]=0;return 0;}if(!e)break;p=e+1;}out[0]=0;return -1;
}

static int hash_tx(const char *tx,char out[129]){
    /* Preserve the historical mempool/block identifier: SHA3-512 over the full
       serialized signed transaction, not the canonical body hash. */
    unsigned char digest[64];unsigned int dlen=0;EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return -1;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha3_512(),NULL)==1&&EVP_DigestUpdate(ctx,tx,strlen(tx))==1&&EVP_DigestFinal_ex(ctx,digest,&dlen)==1;EVP_MD_CTX_free(ctx);if(!ok||dlen!=64)return -1;
    for(size_t i=0;i<64;i++)sprintf(out+i*2,"%02x",digest[i]);out[128]=0;return 0;
}

uint8_t qrx_velocity_tx_adapter_class(const char *tx){
    char type[64]="";
    if(!tx||field(tx,"tx_type",type,sizeof(type))!=0)return QRX_VELOCITY_ADAPTER_BARRIER;
    if(!strcmp(type,"TRANSFER_FAST"))return QRX_VELOCITY_ADAPTER_TRANSFER;
    if(!strcmp(type,"AGENT_REGISTER")||!strcmp(type,"AGENT_UPDATE")||!strcmp(type,"AGENT_REVOKE")||
       !strcmp(type,"GATEWAY_REGISTER")||!strcmp(type,"GATEWAY_REVOKE"))return QRX_VELOCITY_ADAPTER_STATEFUL;
    /* Phase 4E: native order transactions discover their complete runtime
       read/write set from the MVCC snapshot. The planner may now place
       statically independent dynamic transactions in the same speculative wave;
       the executor deterministically resolves any hidden runtime conflicts. */
    if(!strcmp(type,"ORDER_CREATE")||!strcmp(type,"ORDER_CANCEL")||!strcmp(type,"ORDER_REPLACE"))return QRX_VELOCITY_ADAPTER_DYNAMIC;
    /* External venue transitions, cross-chain HTLC state and Bitcoin SPV
       branch/reorg traversal remain explicit barriers until they receive their
       own dynamic snapshot adapters. */
    return QRX_VELOCITY_ADAPTER_BARRIER;
}

static void add_access(QrxVelocityMempoolEntry *e,const char *prefix,const char *value){
    if(!value||!*value||e->access_count>=QRX_VELOCITY_MAX_ACCESS_KEYS)return;char *dst=e->access[e->access_count++];snprintf(dst,512,"%s%s",prefix?prefix:"",value);
}

int qrx_velocity_tx_metadata(const char *tx,QrxVelocityMempoolEntry *e){
    if(!tx||!e)return -1;memset(e,0,sizeof(*e));if(hash_tx(tx,e->txid)!=0)return -1;
    char fee[64]="0",nonce[64]="0",lane[64]="0",payload[8192]="",tmp[512]="";
    field(tx,"from",e->from,sizeof(e->from));field(tx,"to",e->to,sizeof(e->to));field(tx,"tx_type",e->tx_type,sizeof(e->tx_type));field(tx,"fee",fee,sizeof(fee));field(tx,"nonce",nonce,sizeof(nonce));field(tx,"lane_id",lane,sizeof(lane));field(tx,"payload",payload,sizeof(payload));
    e->fee=strtoll(fee,NULL,10);e->nonce=strtoll(nonce,NULL,10);e->lane=strtoll(lane,NULL,10);e->adapter_class=qrx_velocity_tx_adapter_class(tx);e->shard=(uint32_t)(fnv1a64(e->from[0]?e->from:e->txid)%QRX_VELOCITY_MEMPOOL_SHARDS);
    add_access(e,"acct:",e->from);add_access(e,"nonce:",e->from);add_access(e,"acct:",e->to);
    if(strstr(e->tx_type,"AGENT_")==e->tx_type)add_access(e,"agent:",e->to);
    if(!strcmp(e->tx_type,"ORDER_CREATE")||!strcmp(e->tx_type,"EXTERNAL_ORDER")||!strcmp(e->tx_type,"CROSSCHAIN_ORDER")){add_access(e,"order:",e->txid);add_access(e,"agent:",e->from);}
    if(!strcmp(e->tx_type,"ORDER_CANCEL")||!strcmp(e->tx_type,"ORDER_REPLACE")){if(payload_field(payload,"order_id",tmp,sizeof(tmp))==0)add_access(e,"order:",tmp);add_access(e,"agent:",e->from);}
    if(!strcmp(e->tx_type,"GATEWAY_REGISTER")||!strcmp(e->tx_type,"GATEWAY_REVOKE"))add_access(e,"gateway:",e->to);
    if(!strcmp(e->tx_type,"EXECUTION_REPORT")){add_access(e,"gateway:",e->from);if(payload_field(payload,"order_id",tmp,sizeof(tmp))==0)add_access(e,"order:",tmp);}
    if(!strcmp(e->tx_type,"CROSSCHAIN_REDEEM")||!strcmp(e->tx_type,"CROSSCHAIN_REFUND")){if(payload_field(payload,"session_id",tmp,sizeof(tmp))==0)add_access(e,"xswap:",tmp);}
    if(!strcmp(e->tx_type,"BTC_SPV_HEADER")||!strcmp(e->tx_type,"BTC_SPV_FUNDING_PROOF"))add_access(e,"btcspv:","bestchain");
    return 0;
}

int qrx_velocity_entries_conflict(const QrxVelocityMempoolEntry *a,const QrxVelocityMempoolEntry *b){
    if(!a||!b)return 1;for(uint32_t i=0;i<a->access_count;i++)for(uint32_t j=0;j<b->access_count;j++)if(!strcmp(a->access[i],b->access[j]))return 1;return 0;
}

static int shard_find(QrxVelocityShard *s,const char *txid){for(size_t i=0;i<s->count;i++)if(!strcmp(s->items[i].txid,txid))return (int)i;return -1;}
static int shard_reserve(QrxVelocityShard *s,size_t n){if(n<=s->cap)return 0;size_t nc=s->cap?s->cap*2:64;while(nc<n)nc*=2;QrxVelocityMempoolEntry *p=(QrxVelocityMempoolEntry*)realloc(s->items,nc*sizeof(*p));if(!p)return -1;s->items=p;s->cap=nc;return 0;}

static int durable(FILE *f){if(fflush(f)!=0)return -1;
#ifdef _WIN32
 return _commit(_fileno(f));
#else
 return fsync(fileno(f));
#endif
}

static int wal_append(QrxVelocityMempool *p,uint16_t op,const char *txid,const char *payload,size_t len){
    FILE *f=(FILE*)p->wal_file;if(!f)return -1;QvWalHeader h;memset(&h,0,sizeof(h));h.magic=QV_WAL_MAGIC;h.version=QV_WAL_VERSION;h.op=op;h.payload_len=(uint32_t)len;h.crc32=crc32_local(payload?payload:"",len);snprintf(h.txid,sizeof(h.txid),"%s",txid?txid:"");
    if(fwrite(&h,sizeof(h),1,f)!=1 || (len&&fwrite(payload,1,len,f)!=len))return -1;
    /* The mempool is reconstructible from peers, so Phase 4 uses WAL group
       durability instead of an fsync per transaction. Flush userspace buffers
       immediately; force storage every 64 records. */
    if(fflush(f)!=0)return -1;p->wal_since_sync++;if(p->wal_since_sync>=64){if(durable(f)!=0)return -1;p->wal_since_sync=0;p->wal_syncs++;}
    p->stats.wal_records++;return 0;
}

static size_t total_count_unlocked(QrxVelocityMempool *p){size_t n=0;for(uint32_t i=0;i<QRX_VELOCITY_MEMPOOL_SHARDS;i++)n+=p->shards[i].count;return n;}

static int add_unlocked(QrxVelocityMempool *p,const char *tx,const char *forced_txid,int persist,char out[129]){
    QrxVelocityMempoolEntry e;if(qrx_velocity_tx_metadata(tx,&e)!=0)return -1;if(forced_txid&&*forced_txid)snprintf(e.txid,sizeof(e.txid),"%s",forced_txid);QrxVelocityShard *s=&p->shards[e.shard];if(shard_find(s,e.txid)>=0){p->stats.duplicates++;if(out)snprintf(out,129,"%s",e.txid);return 1;}if(total_count_unlocked(p)>=p->max_entries){p->stats.rejected_full++;return -2;}if(shard_reserve(s,s->count+1)!=0)return -1;e.tx=strdup(tx);if(!e.tx)return -1;e.tx_len=strlen(tx);e.arrival_seq=p->next_seq++;if(persist&&wal_append(p,QV_WAL_ADD,e.txid,tx,e.tx_len)!=0){free(e.tx);return -1;}s->items[s->count++]=e;p->stats.accepted++;p->stats.bytes+=e.tx_len;if(out)snprintf(out,129,"%s",e.txid);return 0;
}

static int remove_unlocked(QrxVelocityMempool *p,const char *txid,int persist){
    for(uint32_t sidx=0;sidx<QRX_VELOCITY_MEMPOOL_SHARDS;sidx++){QrxVelocityShard *s=&p->shards[sidx];int idx=shard_find(s,txid);if(idx>=0){if(persist&&wal_append(p,QV_WAL_REMOVE,txid,NULL,0)!=0)return -1;size_t i=(size_t)idx;p->stats.bytes-=s->items[i].tx_len;free(s->items[i].tx);if(i+1<s->count)s->items[i]=s->items[s->count-1];s->count--;p->stats.removed++;return 0;}}return 1;
}

static int replay(QrxVelocityMempool *p){
    FILE *f=fopen(p->wal_path,"rb");if(!f){if(errno==ENOENT)return 0;return -1;}for(;;){QvWalHeader h;size_t hr=fread(&h,1,sizeof(h),f);if(hr==0&&feof(f))break;if(hr!=sizeof(h)){/* another process may currently be appending the tail */break;}if(h.magic!=QV_WAL_MAGIC||h.version!=QV_WAL_VERSION||h.payload_len>QRX_MAX_TX_SIZE){fclose(f);return -1;}char *buf=NULL;if(h.payload_len){buf=(char*)malloc((size_t)h.payload_len+1);if(!buf){fclose(f);return -1;}size_t pr=fread(buf,1,h.payload_len,f);if(pr!=h.payload_len){free(buf);break;}buf[h.payload_len]=0;if(crc32_local(buf,h.payload_len)!=h.crc32){free(buf);if(feof(f))break;fclose(f);return -1;}}
        if(h.op==QV_WAL_ADD&&buf){int rc=add_unlocked(p,buf,h.txid,0,NULL);if(rc<0&&rc!=-2){free(buf);fclose(f);return -1;}}
        else if(h.op==QV_WAL_REMOVE)remove_unlocked(p,h.txid,0);free(buf);p->stats.recovered_records++;}
    fclose(f);return 0;
}

int qrx_velocity_mempool_open(QrxVelocityMempool *p,const char *node_dir,size_t max_entries){
    if(!p||!node_dir)return -1;memset(p,0,sizeof(*p));snprintf(p->node_dir,sizeof(p->node_dir),"%s",node_dir);mkdir_if_missing(node_dir);snprintf(p->wal_path,sizeof(p->wal_path),"%s/velocity_mempool.wal",node_dir);p->max_entries=max_entries?max_entries:QRX_MAX_MEMPOOL_TX;p->shards=(QrxVelocityShard*)calloc(QRX_VELOCITY_MEMPOOL_SHARDS,sizeof(QrxVelocityShard));if(!p->shards)return -1;
#ifdef _WIN32
    p->mutex_handle=CreateMutexA(NULL,FALSE,NULL);if(!p->mutex_handle){free(p->shards);return -1;}
#else
    if(sizeof(pthread_mutex_t)>sizeof(p->mutex_storage)){free(p->shards);return -1;}if(pthread_mutex_init((pthread_mutex_t*)p->mutex_storage,NULL)!=0){free(p->shards);return -1;}
#endif
    p->mutex_ready=1;p->next_seq=1;p->stats.max_entries=p->max_entries;p->stats.shards=QRX_VELOCITY_MEMPOOL_SHARDS;if(replay(p)!=0){qrx_velocity_mempool_close(p);return -1;}p->wal_file=fopen(p->wal_path,"ab");if(!p->wal_file){qrx_velocity_mempool_close(p);return -1;}p->initialized=1;return 0;
}

void qrx_velocity_mempool_close(QrxVelocityMempool *p){if(!p)return;if(p->wal_file){durable((FILE*)p->wal_file);fclose((FILE*)p->wal_file);p->wal_file=NULL;}if(p->shards){for(uint32_t s=0;s<QRX_VELOCITY_MEMPOOL_SHARDS;s++){for(size_t i=0;i<p->shards[s].count;i++)free(p->shards[s].items[i].tx);free(p->shards[s].items);}free(p->shards);}if(p->mutex_ready){
#ifdef _WIN32
 CloseHandle((HANDLE)p->mutex_handle);
#else
 pthread_mutex_destroy((pthread_mutex_t*)p->mutex_storage);
#endif
 }memset(p,0,sizeof(*p));}

int qrx_velocity_mempool_add(QrxVelocityMempool *p,const char *tx,char out[129]){if(!p||!p->initialized)return -1;lock_pool(p);int rc=add_unlocked(p,tx,NULL,1,out);unlock_pool(p);return rc;}
int qrx_velocity_mempool_remove(QrxVelocityMempool *p,const char *txid){if(!p||!p->initialized)return -1;lock_pool(p);int rc=remove_unlocked(p,txid,1);unlock_pool(p);return rc;}

int qrx_velocity_mempool_checkpoint(QrxVelocityMempool *p){
    if(!p||!p->initialized)return -1;lock_pool(p);char tmp[1300];snprintf(tmp,sizeof(tmp),"%s.tmp",p->wal_path);FILE *f=fopen(tmp,"wb");if(!f){unlock_pool(p);return -1;}int rc=0;for(uint32_t s=0;s<QRX_VELOCITY_MEMPOOL_SHARDS&&!rc;s++)for(size_t i=0;i<p->shards[s].count;i++){QrxVelocityMempoolEntry *e=&p->shards[s].items[i];QvWalHeader h;memset(&h,0,sizeof(h));h.magic=QV_WAL_MAGIC;h.version=QV_WAL_VERSION;h.op=QV_WAL_ADD;h.payload_len=(uint32_t)e->tx_len;h.crc32=crc32_local(e->tx,e->tx_len);snprintf(h.txid,sizeof(h.txid),"%s",e->txid);if(fwrite(&h,sizeof(h),1,f)!=1||fwrite(e->tx,1,e->tx_len,f)!=e->tx_len)rc=-1;}if(!rc&&durable(f)!=0)rc=-1;fclose(f);if(!rc){if(p->wal_file){durable((FILE*)p->wal_file);fclose((FILE*)p->wal_file);p->wal_file=NULL;}
#ifdef _WIN32
        remove(p->wal_path);
#endif
        if(rename(tmp,p->wal_path)!=0)rc=-1;}if(rc)remove(tmp);p->wal_file=fopen(p->wal_path,"ab");if(!p->wal_file)rc=-1;p->wal_since_sync=0;unlock_pool(p);return rc;
}

static int cmp_entries(const void *aa,const void *bb){const QrxVelocityMempoolEntry *a=*(const QrxVelocityMempoolEntry* const*)aa,*b=*(const QrxVelocityMempoolEntry* const*)bb;if(a->fee>b->fee)return -1;if(a->fee<b->fee)return 1;return strcmp(a->txid,b->txid);}

int qrx_velocity_mempool_plan(QrxVelocityMempool *p,size_t max,QrxVelocityPlan *plan){
    if(!p||!p->initialized||!plan)return -1;memset(plan,0,sizeof(*plan));lock_pool(p);size_t total=total_count_unlocked(p);if(max&&total>max)total=max;QrxVelocityMempoolEntry **all=(QrxVelocityMempoolEntry**)malloc((total_count_unlocked(p)?total_count_unlocked(p):1)*sizeof(*all));if(!all){unlock_pool(p);return -1;}size_t n=0;for(uint32_t s=0;s<QRX_VELOCITY_MEMPOOL_SHARDS;s++)for(size_t i=0;i<p->shards[s].count;i++)all[n++]=&p->shards[s].items[i];qsort(all,n,sizeof(*all),cmp_entries);if(max&&n>max)n=max;
    plan->txids=(char**)calloc(n?n:1,sizeof(char*));plan->txs=(char**)calloc(n?n:1,sizeof(char*));plan->waves=(uint32_t*)calloc(n?n:1,sizeof(uint32_t));if(!plan->txids||!plan->txs||!plan->waves){free(all);unlock_pool(p);qrx_velocity_plan_free(plan);return -1;}
    for(size_t i=0;i<n;i++){
        plan->txids[i]=strdup(all[i]->txid);plan->txs[i]=strdup(all[i]->tx);if(!plan->txids[i]||!plan->txs[i]){free(all);unlock_pool(p);qrx_velocity_plan_free(plan);return -1;}
    }
    /* Phase 4F: build a deterministic block dependency graph from the already
       canonical fee-desc/txid-asc order. Static access-key dependencies become
       explicit graph edges, barriers are true full fences, and graph levels are
       the execution waves consumed by the Phase 4E speculative MVCC executor. */
    QrxVelocityBlockSchedule sched;
    if(qrx_velocity_block_schedule_build(all,n,&sched)!=0){free(all);unlock_pool(p);qrx_velocity_plan_free(plan);return -1;}
    for(size_t i=0;i<n;i++)plan->waves[i]=sched.waves[i];
    plan->wave_count=sched.wave_count;
    plan->conflicts=sched.static_conflicts;
    plan->dependency_edges=sched.edge_count;
    plan->barrier_fences=sched.barrier_fences;
    plan->barrier_nodes=sched.barrier_nodes;
    plan->critical_path_nodes=sched.critical_path_nodes;
    plan->max_parallel_width=sched.max_parallel_width;
    snprintf(plan->schedule_hash,sizeof(plan->schedule_hash),"%s",sched.schedule_hash);
    qrx_velocity_block_schedule_free(&sched);
    plan->count=n;free(all);unlock_pool(p);return 0;
}
void qrx_velocity_plan_free(QrxVelocityPlan *p){if(!p)return;for(size_t i=0;i<p->count;i++){free(p->txids?p->txids[i]:NULL);free(p->txs?p->txs[i]:NULL);}free(p->txids);free(p->txs);free(p->waves);memset(p,0,sizeof(*p));}

int qrx_velocity_mempool_stats(QrxVelocityMempool *p,QrxVelocityMempoolStats *out){if(!p||!out)return -1;lock_pool(p);*out=p->stats;out->entries=total_count_unlocked(p);out->max_entries=p->max_entries;out->shards=QRX_VELOCITY_MEMPOOL_SHARDS;unlock_pool(p);return 0;}

typedef struct {const QrxVelocityPlan *plan;QrxVelocityVerifyFn fn;void *ctx;unsigned char *mask;size_t next;uint64_t ok,failed;
#ifdef _WIN32
 CRITICAL_SECTION lock;
#else
 pthread_mutex_t lock;
#endif
} VerifyWork;
static size_t work_take(VerifyWork *w){size_t i;
#ifdef _WIN32
 EnterCriticalSection(&w->lock);
#else
 pthread_mutex_lock(&w->lock);
#endif
 i=w->next++;
#ifdef _WIN32
 LeaveCriticalSection(&w->lock);
#else
 pthread_mutex_unlock(&w->lock);
#endif
 return i;}
static void work_result(VerifyWork *w,int ok){
#ifdef _WIN32
 EnterCriticalSection(&w->lock);
#else
 pthread_mutex_lock(&w->lock);
#endif
 if(ok)w->ok++;else w->failed++;
#ifdef _WIN32
 LeaveCriticalSection(&w->lock);
#else
 pthread_mutex_unlock(&w->lock);
#endif
}
#ifdef _WIN32
static DWORD WINAPI verify_worker(LPVOID arg)
#else
static void *verify_worker(void *arg)
#endif
{VerifyWork *w=(VerifyWork*)arg;for(;;){size_t i=work_take(w);if(i>=w->plan->count)break;char err[256]={0};int ok=w->fn(w->ctx,w->plan->txs[i],err,sizeof(err))==0;w->mask[i]=(unsigned char)(ok?1:0);work_result(w,ok);}
#ifdef _WIN32
 return 0;
#else
 return NULL;
#endif
}
static uint64_t mono_us(void){
#ifdef _WIN32
 LARGE_INTEGER f,c;QueryPerformanceFrequency(&f);QueryPerformanceCounter(&c);return (uint64_t)((c.QuadPart*1000000ULL)/f.QuadPart);
#else
 struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000ULL+(uint64_t)ts.tv_nsec/1000ULL;
#endif
}
int qrx_velocity_parallel_verify(const QrxVelocityPlan *plan,uint32_t workers,QrxVelocityVerifyFn fn,void *ctx,unsigned char **valid_mask,QrxVelocityVerifyStats *stats){
    if(!plan||!fn||!valid_mask)return -1;if(workers<1)workers=1;if(workers>64)workers=64;if(plan->count&&workers>plan->count)workers=(uint32_t)plan->count;if(!workers)workers=1;unsigned char *mask=(unsigned char*)calloc(plan->count?plan->count:1,1);if(!mask)return -1;VerifyWork w;memset(&w,0,sizeof(w));w.plan=plan;w.fn=fn;w.ctx=ctx;w.mask=mask;
#ifdef _WIN32
 InitializeCriticalSection(&w.lock);HANDLE *ths=(HANDLE*)calloc(workers,sizeof(HANDLE));
#else
 pthread_mutex_init(&w.lock,NULL);pthread_t *ths=(pthread_t*)calloc(workers,sizeof(pthread_t));
#endif
 if(!ths){free(mask);return -1;}uint64_t t0=mono_us();for(uint32_t i=0;i<workers;i++){
#ifdef _WIN32
 ths[i]=CreateThread(NULL,0,verify_worker,&w,0,NULL);
#else
 pthread_create(&ths[i],NULL,verify_worker,&w);
#endif
 }for(uint32_t i=0;i<workers;i++){
#ifdef _WIN32
 WaitForSingleObject(ths[i],INFINITE);CloseHandle(ths[i]);
#else
 pthread_join(ths[i],NULL);
#endif
 }uint64_t t1=mono_us();
#ifdef _WIN32
 DeleteCriticalSection(&w.lock);
#else
 pthread_mutex_destroy(&w.lock);
#endif
 free(ths);*valid_mask=mask;if(stats){stats->ok=w.ok;stats->failed=w.failed;stats->workers=workers;stats->elapsed_us=t1-t0;}return 0;
}
