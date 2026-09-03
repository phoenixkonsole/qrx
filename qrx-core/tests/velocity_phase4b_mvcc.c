#include "mempool/qrx_velocity_mempool.h"
#include "mempool/qrx_velocity_mvcc.h"
#include "qrxdb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

static void die(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(1);}
static void mkhash(char out[129], char c){for(int i=0;i<128;i++)out[i]=(i%17==0)?c:"0123456789abcdef"[(i+(unsigned char)c)%16];out[128]=0;}
static void mk(char *out,size_t n,const char *from,const char *to,long long amount,long long fee,long long nonce,long long lane,const char *hash){
    snprintf(out,n,"tx_version=3\nnetwork_id=test\ngenesis_hash=g\nprotocol_version=62\ntx_type=TRANSFER_FAST\nfrom=%s\nto=%s\namount=%lld\nfee=%lld\nlane_id=%lld\nnonce=%lld\ntimestamp=1\nexpiry_height=999999\npayload=test\ned25519_pub_hex=00\nmldsa65_pub_b64=x\nbody_hash_algo=sha3-512\nbody_hash_sha3_512=%s\nsig_ed25519_hex=00\nsig_mldsa65_hex=00\n",from,to,amount,fee,lane,nonce,hash);
}
static long long getll(QrxDB *db,const char *key){char b[128];if(qrxdb_get(db,key,b,sizeof(b))!=0)return 0;return atoll(b);}
static void putll(QrxDB *db,const char *key,long long v){char b[64];snprintf(b,sizeof(b),"%lld",v);if(qrxdb_put(db,key,b)!=0)die("putll");}
static void init_state(QrxDB *db){
    putll(db,"acct:balance:alice",1000);putll(db,"acct:balance:bob",0);putll(db,"acct:balance:erin",0);
    putll(db,"acct:balance:carol",1000);putll(db,"acct:balance:dave",0);
    putll(db,"velocity:nonce:alice:1",0);putll(db,"velocity:nonce:carol:1",0);putll(db,"consensus:fee_pool:pending",0);
}
static void make_dir(char *out,size_t n,const char *tag){
#ifdef _WIN32
    snprintf(out,n,"velocity-p4b-%s-%lu",tag,(unsigned long)GetCurrentProcessId());CreateDirectoryA(out,NULL);
#else
    snprintf(out,n,"/tmp/qrx-velocity-p4b-%s-%ld",tag,(long)getpid());mkdir(out,0700);
#endif
}
static void build_plan(const char *dir,QrxVelocityPlan *plan){
    QrxVelocityMempool p;if(qrx_velocity_mempool_open(&p,dir,100)!=0)die("mempool open");
    char h1[129],h2[129],h3[129],a[4096],b[4096],c[4096];mkhash(h1,'a');mkhash(h2,'b');mkhash(h3,'c');
    /* Fee order: carol first, alice->bob second, alice->erin third. The two Alice txs must land in separate waves. */
    mk(a,sizeof(a),"alice","bob",100,10,1,1,h1);mk(b,sizeof(b),"carol","dave",200,20,1,1,h2);mk(c,sizeof(c),"alice","erin",50,5,2,1,h3);
    if(qrx_velocity_mempool_add(&p,a,NULL)<0||qrx_velocity_mempool_add(&p,b,NULL)<0||qrx_velocity_mempool_add(&p,c,NULL)<0)die("mempool add");
    if(qrx_velocity_mempool_plan(&p,100,plan)!=0)die("mempool plan");qrx_velocity_mempool_close(&p);
    if(plan->count!=3||plan->wave_count<2)die("plan waves");
}
static void assert_state(QrxDB *db){
    if(getll(db,"acct:balance:alice")!=835)die("alice balance");
    if(getll(db,"acct:balance:bob")!=100)die("bob balance");
    if(getll(db,"acct:balance:erin")!=50)die("erin balance");
    if(getll(db,"acct:balance:carol")!=780)die("carol balance");
    if(getll(db,"acct:balance:dave")!=200)die("dave balance");
    if(getll(db,"velocity:nonce:alice:1")!=2)die("alice nonce");
    if(getll(db,"velocity:nonce:carol:1")!=1)die("carol nonce");
    if(getll(db,"consensus:fee_pool:pending")!=35)die("fee pool");
}
int main(void){
    char d1[512],d2[512],m1[512],m2[512];make_dir(d1,sizeof(d1),"db1");make_dir(d2,sizeof(d2),"db2");make_dir(m1,sizeof(m1),"mp1");make_dir(m2,sizeof(m2),"mp2");
    QrxDB db1,db2;if(qrxdb_init(&db1,d1)!=0||qrxdb_init(&db2,d2)!=0)die("db init");init_state(&db1);init_state(&db2);
    QrxVelocityPlan p1,p2;build_plan(m1,&p1);build_plan(m2,&p2);unsigned char mask[3]={1,1,1};
    uint64_t g1=qrxdb_generation(&db1),g2=qrxdb_generation(&db2);QrxVelocityMvccStats s1,s2;
    if(qrx_velocity_mvcc_execute_transfer_batch(&db1,&p1,mask,1,100,&s1)!=QRX_MVCC_OK)die("single-worker execute");
    if(qrx_velocity_mvcc_execute_transfer_batch(&db2,&p2,mask,4,100,&s2)!=QRX_MVCC_OK)die("multi-worker execute");
    if(qrxdb_generation(&db1)!=g1+1||qrxdb_generation(&db2)!=g2+1)die("not one WAL generation");assert_state(&db1);assert_state(&db2);
    if(strcmp(s1.state_root,s2.state_root)!=0)die("worker-count state-root divergence");if(!s1.committed||s1.committed!=3||s2.committed!=3)die("commit stats");
    /* Stale snapshot must never overwrite a concurrent generation. Use a fresh state so the nonce sequence is valid at prepare time. */
    QrxVelocityMvccPrepared prep;QrxVelocityMvccStats rs;QrxVelocityPlan retry_plan;char mr[512],d3[512];make_dir(mr,sizeof(mr),"mpr");make_dir(d3,sizeof(d3),"db3");build_plan(mr,&retry_plan);QrxDB db3;if(qrxdb_init(&db3,d3)!=0)die("retry db init");init_state(&db3);
    if(qrx_velocity_mvcc_prepare_transfer_batch(&db3,&retry_plan,mask,4,101,&prep,&rs)!=QRX_MVCC_OK)die("retry prepare");
    if(qrxdb_put(&db3,"test:concurrent-generation","1")!=0)die("concurrent mutation");
    if(qrx_velocity_mvcc_commit(&db3,&prep,&rs)!=QRX_MVCC_RETRY)die("stale snapshot was committed");qrx_velocity_mvcc_prepared_free(&prep);
    qrxdb_close(&db3);qrx_velocity_plan_free(&retry_plan);
    /* Mixed/stateful batches must never partially commit the transfer subset. */
    char d4[512],m4[512];make_dir(d4,sizeof(d4),"db4");make_dir(m4,sizeof(m4),"mp4");QrxDB db4;if(qrxdb_init(&db4,d4)!=0)die("mixed db init");init_state(&db4);QrxVelocityMempool mp4;if(qrx_velocity_mempool_open(&mp4,m4,100)!=0)die("mixed mempool open");char hh1[129],hh2[129],tfast[4096],stateful[4096];mkhash(hh1,'d');mkhash(hh2,'e');mk(tfast,sizeof(tfast),"alice","bob",10,1,1,1,hh1);snprintf(stateful,sizeof(stateful),"tx_version=3\nfrom=agent\nto=owner\nfee=1\nnonce=1\nlane_id=1\ntx_type=EXTERNAL_ORDER\npayload=venue=KRAKEN;market=BTC/QUB;side=BUY;order_type=LIMIT;quantity_atoms=1;limit_price_atoms=100000000;order_expires_height=999999\nbody_hash_sha3_512=%s\n",hh2);if(qrx_velocity_mempool_add(&mp4,tfast,NULL)<0||qrx_velocity_mempool_add(&mp4,stateful,NULL)<0)die("mixed add");QrxVelocityPlan mix;if(qrx_velocity_mempool_plan(&mp4,10,&mix)!=0)die("mixed plan");qrx_velocity_mempool_close(&mp4);unsigned char mm[2]={1,1};uint64_t mg=qrxdb_generation(&db4);QrxVelocityMvccStats ms;if(qrx_velocity_mvcc_execute_transfer_batch(&db4,&mix,mm,4,102,&ms)!=QRX_MVCC_UNSUPPORTED)die("mixed batch did not request fallback");if(qrxdb_generation(&db4)!=mg||getll(&db4,"acct:balance:alice")!=1000)die("mixed batch partially committed");qrx_velocity_plan_free(&mix);qrxdb_close(&db4);
    qrx_velocity_plan_free(&p1);qrx_velocity_plan_free(&p2);qrxdb_close(&db1);qrxdb_close(&db2);
    printf("VELOCITY Phase 4B MVCC snapshot parallel TRANSFER_FAST execution + isolated write sets + deterministic one-WAL merge + stale-generation retry + mixed-batch fallback PASSED\n");
    return 0;
}
