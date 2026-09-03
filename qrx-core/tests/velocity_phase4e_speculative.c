#include "mempool/qrx_velocity_mempool.h"
#include "mempool/qrx_velocity_mvcc.h"
#include "qrxdb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void die(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(1);} 
static void put(QrxDB *db,const char *k,const char *v){if(qrxdb_put(db,k,v))die("put");}
static void putll(QrxDB *db,const char *k,long long v){char b[64];snprintf(b,sizeof(b),"%lld",v);put(db,k,b);}
static long long getll(QrxDB *db,const char *k){char b[128];if(qrxdb_get(db,k,b,sizeof(b)))return -999999;return strtoll(b,NULL,10);} 
static void expect(QrxDB *db,const char *k,const char *want){char b[4096];if(qrxdb_get(db,k,b,sizeof(b))||strcmp(b,want)){fprintf(stderr,"FAIL: %s expected=%s got=%s\n",k,want,qrxdb_get(db,k,b,sizeof(b))?"<missing>":b);exit(1);}}
static void mkhash(char out[129],char c){for(int i=0;i<128;i++)out[i]=c;out[128]=0;}
static void mk_tx(char *out,size_t n,const char *from,const char *to,long long nonce,char hc){char h[129];mkhash(h,hc);snprintf(out,n,"tx_version=3\nfrom=%s\nto=%s\namount=0\nfee=1\nnonce=%lld\nlane_id=0\ntx_type=ORDER_CREATE\npayload=market=TOK/QUB;side=BUY;order_type=LIMIT;quantity_atoms=3;limit_price_atoms=300000000;order_expires_height=9999\nbody_hash_sha3_512=%s\n",from,to,nonce,h);}
static void mk_tx_market(char *out,size_t n,const char *from,const char *to,long long nonce,char hc,const char *market){char h[129];mkhash(h,hc);snprintf(out,n,"tx_version=3\nfrom=%s\nto=%s\namount=0\nfee=1\nnonce=%lld\nlane_id=0\ntx_type=ORDER_CREATE\npayload=market=%s;side=BUY;order_type=LIMIT;quantity_atoms=3;limit_price_atoms=300000000;order_expires_height=9999\nbody_hash_sha3_512=%s\n",from,to,nonce,market,h);}

static void seed_agent(QrxDB *db,const char *agent,const char *owner){char k[1024];
    snprintf(k,sizeof(k),"velocity:agent:%s:owner",agent);put(db,k,owner);
    snprintf(k,sizeof(k),"velocity:agent:%s:status",agent);put(db,k,"active");
    snprintf(k,sizeof(k),"velocity:agent:%s:permissions",agent);put(db,k,"TRADE,TRADE_NATIVE");
    snprintf(k,sizeof(k),"velocity:agent:%s:market_allowlist",agent);put(db,k,"TOK/QUB,ALT/QUB");
    snprintf(k,sizeof(k),"velocity:agent:%s:max_trade_atoms",agent);putll(db,k,1000);
    snprintf(k,sizeof(k),"velocity:agent:%s:daily_limit_atoms",agent);putll(db,k,10000);
    snprintf(k,sizeof(k),"velocity:agent:%s:expires_height",agent);putll(db,k,9999);
}
static void seed_state(QrxDB *db){
    putll(db,"acct:balance:agentA",10);putll(db,"acct:nonce:agentA",0);
    putll(db,"acct:balance:agentB",10);putll(db,"acct:nonce:agentB",0);
    putll(db,"acct:balance:buyerA",10);putll(db,"acct:balance:buyerB",10);putll(db,"acct:balance:seller",0);
    putll(db,"velocity:asset:balance:TOK:buyerA",0);putll(db,"velocity:asset:balance:TOK:buyerB",0);putll(db,"velocity:asset:balance:TOK:seller",0);
    putll(db,"consensus:fee_pool:pending",0);seed_agent(db,"agentA","buyerA");seed_agent(db,"agentB","buyerB");
    put(db,"velocity:order:maker:owner","seller");put(db,"velocity:order:maker:agent","makerAgent");put(db,"velocity:order:maker:kind","native");put(db,"velocity:order:maker:status","open");put(db,"velocity:order:maker:market","TOK/QUB");put(db,"velocity:order:maker:side","SELL");put(db,"velocity:order:maker:order_type","LIMIT");
    putll(db,"velocity:order:maker:quantity_atoms",5);putll(db,"velocity:order:maker:filled_atoms",0);putll(db,"velocity:order:maker:remaining_atoms",5);putll(db,"velocity:order:maker:limit_price_atoms",200000000LL);putll(db,"velocity:order:maker:created_height",10);putll(db,"velocity:order:maker:updated_height",10);putll(db,"velocity:order:maker:order_expires_height",9999);put(db,"velocity:order:maker:settlement_version","1");put(db,"velocity:order:maker:locked_asset","TOK");putll(db,"velocity:order:maker:locked_atoms",5);
}
static void plan2(QrxVelocityPlan *p,const char *a,const char *b){memset(p,0,sizeof(*p));p->count=2;p->wave_count=1;p->txs=calloc(2,sizeof(char*));p->txids=calloc(2,sizeof(char*));p->waves=calloc(2,sizeof(uint32_t));if(!p->txs||!p->txids||!p->waves)die("plan alloc");p->txs[0]=strdup(a);p->txs[1]=strdup(b);p->txids[0]=strdup("plan-a");p->txids[1]=strdup("plan-b");if(!p->txs[0]||!p->txs[1]||!p->txids[0]||!p->txids[1])die("plan strdup");}

static void run_case(uint32_t workers,char root[129]){
    char tmp[]="/tmp/qrx4eXXXXXX";if(!mkdtemp(tmp))die("mkdtemp");QrxDB db;if(qrxdb_init(&db,tmp))die("db init");seed_state(&db);
    char a[20000],b[20000],aid[129],bid[129],k[1024];mk_tx(a,sizeof(a),"agentA","buyerA",1,'a');mk_tx(b,sizeof(b),"agentB","buyerB",1,'b');mkhash(aid,'a');mkhash(bid,'b');
    QrxVelocityPlan p;plan2(&p,a,b);unsigned char mask[2]={1,1};QrxVelocityMvccPrepared prep;QrxVelocityMvccStats st;uint64_t gen=qrxdb_generation(&db);
    int rc=qrx_velocity_mvcc_prepare_batch(&db,&p,mask,workers,100,&prep,&st);if(rc!=QRX_MVCC_OK)die("4E prepare");
    if(st.speculative_prepared!=2||st.deterministic_conflicts!=1||st.selective_retries!=1||st.conflict_edges<1||st.runtime_read_prefixes<3||st.speculative_winners!=1)die("4E OCC stats");
    if(!prep.sets[0].speculative||prep.sets[0].retried||!prep.sets[1].speculative||!prep.sets[1].retried||!prep.sets[1].conflict_loser)die("deterministic winner/retry flags");
    if(qrx_velocity_mvcc_commit(&db,&prep,&st)!=QRX_MVCC_OK)die("4E commit");if(qrxdb_generation(&db)!=gen+1)die("4E must use one WAL generation");if(st.committed!=2||st.dynamic_prepared!=2||st.dynamic_trades!=2)die("4E commit stats");
    if(getll(&db,"velocity:order:maker:filled_atoms")!=5||getll(&db,"velocity:order:maker:remaining_atoms")!=0||getll(&db,"velocity:order:maker:locked_atoms")!=0)die("maker over/under fill");expect(&db,"velocity:order:maker:status","filled");
    snprintf(k,sizeof(k),"velocity:order:%s:status",aid);expect(&db,k,"filled");snprintf(k,sizeof(k),"velocity:order:%s:filled_atoms",aid);if(getll(&db,k)!=3)die("winner fill");
    snprintf(k,sizeof(k),"velocity:order:%s:status",bid);expect(&db,k,"partially_filled");snprintf(k,sizeof(k),"velocity:order:%s:filled_atoms",bid);if(getll(&db,k)!=2)die("retried fill");snprintf(k,sizeof(k),"velocity:order:%s:remaining_atoms",bid);if(getll(&db,k)!=1)die("retried remaining");snprintf(k,sizeof(k),"velocity:order:%s:locked_atoms",bid);if(getll(&db,k)!=3)die("retried reserve");
    if(getll(&db,"velocity:asset:balance:TOK:buyerA")!=3||getll(&db,"velocity:asset:balance:TOK:buyerB")!=2||getll(&db,"acct:balance:seller")!=10||getll(&db,"acct:balance:buyerA")!=4||getll(&db,"acct:balance:buyerB")!=3)die("settlement balances");
    if(getll(&db,"acct:balance:agentA")!=9||getll(&db,"acct:balance:agentB")!=9||getll(&db,"acct:nonce:agentA")!=1||getll(&db,"acct:nonce:agentB")!=1||getll(&db,"consensus:fee_pool:pending")!=2)die("outer fee nonce");if(getll(&db,"velocity:trade_sequence:global")!=2)die("trade sequence");
    snprintf(root,129,"%s",st.state_root);qrx_velocity_mvcc_prepared_free(&prep);qrx_velocity_plan_free(&p);qrxdb_close(&db);
}


static void run_cross_market_case(void){
    char tmp[]="/tmp/qrx4emarketsXXXXXX";if(!mkdtemp(tmp))die("market mkdtemp");QrxDB db;if(qrxdb_init(&db,tmp))die("market db init");
    putll(&db,"acct:balance:agentA",10);putll(&db,"acct:nonce:agentA",0);putll(&db,"acct:balance:agentB",10);putll(&db,"acct:nonce:agentB",0);putll(&db,"acct:balance:buyerA",10);putll(&db,"acct:balance:buyerB",10);putll(&db,"consensus:fee_pool:pending",0);seed_agent(&db,"agentA","buyerA");seed_agent(&db,"agentB","buyerB");
    char a[20000],b[20000];mk_tx_market(a,sizeof(a),"agentA","buyerA",1,'c',"TOK/QUB");mk_tx_market(b,sizeof(b),"agentB","buyerB",1,'d',"ALT/QUB");QrxVelocityPlan p;plan2(&p,a,b);unsigned char mask[2]={1,1};QrxVelocityMvccStats st;if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,8,100,&st)!=QRX_MVCC_OK)die("cross-market execute");
    if(st.speculative_prepared!=2||st.selective_retries!=0||st.deterministic_conflicts!=0||st.speculative_winners!=2)die("cross-market false conflict");
    char cid[129],did[129],k[1024];mkhash(cid,'c');mkhash(did,'d');snprintf(k,sizeof(k),"velocity:order:%s:status",cid);expect(&db,k,"open");snprintf(k,sizeof(k),"velocity:order:%s:status",did);expect(&db,k,"open");qrx_velocity_plan_free(&p);qrxdb_close(&db);
}

int main(void){
    /* Production planner: independent dynamic orders can now enter one wave. */
    char tmp[]="/tmp/qrx4eplanXXXXXX";if(!mkdtemp(tmp))die("plan mkdtemp");char a[20000],b[20000];mk_tx(a,sizeof(a),"agentA","buyerA",1,'a');mk_tx(b,sizeof(b),"agentB","buyerB",1,'b');QrxVelocityMempool mp;if(qrx_velocity_mempool_open(&mp,tmp,100))die("mempool open");if(qrx_velocity_mempool_add(&mp,a,NULL)<0||qrx_velocity_mempool_add(&mp,b,NULL)<0)die("mempool add");QrxVelocityPlan pp;if(qrx_velocity_mempool_plan(&mp,10,&pp))die("mempool plan");if(pp.count!=2||pp.wave_count!=1||pp.waves[0]!=pp.waves[1])die("dynamic speculative co-pack");qrx_velocity_plan_free(&pp);qrx_velocity_mempool_close(&mp);

    run_cross_market_case();
    char r1[129],r8[129];run_case(1,r1);run_case(8,r8);if(strcmp(r1,r8))die("worker-count changed deterministic state root");
    puts("VELOCITY Phase 4E speculative parallel execution + deterministic conflict resolution test PASSED");return 0;
}
