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
static void mk_tx(char *out,size_t n,const char *type,const char *from,const char *to,long long fee,long long nonce,const char *payload,char hc){char h[129];mkhash(h,hc);snprintf(out,n,"tx_version=3\nfrom=%s\nto=%s\namount=0\nfee=%lld\nnonce=%lld\nlane_id=0\ntx_type=%s\npayload=%s\nbody_hash_sha3_512=%s\n",from,to,fee,nonce,type,payload,h);} 
static void plan1(QrxVelocityPlan *p,const char *tx){memset(p,0,sizeof(*p));p->count=1;p->wave_count=1;p->txs=calloc(1,sizeof(char*));p->txids=calloc(1,sizeof(char*));p->waves=calloc(1,sizeof(uint32_t));if(!p->txs||!p->txids||!p->waves)die("plan alloc");p->txs[0]=strdup(tx);p->txids[0]=strdup("dynamic-0");if(!p->txs[0]||!p->txids[0])die("plan strdup");}

typedef struct {char keys[8][128];char vals[8][128];size_t n;} ScanCtx;
static int scan_cb(const char *key,const char *value,uint32_t value_len,void *ctxp){ScanCtx *c=(ScanCtx*)ctxp;if(c->n>=8)return -1;snprintf(c->keys[c->n],sizeof(c->keys[c->n]),"%s",key);size_t n=value_len<sizeof(c->vals[c->n])-1?value_len:sizeof(c->vals[c->n])-1;memcpy(c->vals[c->n],value,n);c->vals[c->n][n]=0;c->n++;return 0;}
typedef struct {size_t n;} CountCtx;
static int count_cb(const char *key,const char *value,uint32_t value_len,void *ctxp){(void)key;(void)value;(void)value_len;((CountCtx*)ctxp)->n++;return 0;}

static void seed_agent(QrxDB *db){
    put(db,"velocity:agent:agentBuyer:owner","buyer");
    put(db,"velocity:agent:agentBuyer:status","active");
    put(db,"velocity:agent:agentBuyer:permissions","TRADE,TRADE_NATIVE");
    put(db,"velocity:agent:agentBuyer:market_allowlist","TOK/QUB");
    putll(db,"velocity:agent:agentBuyer:max_trade_atoms",1000);
    putll(db,"velocity:agent:agentBuyer:daily_limit_atoms",10000);
    putll(db,"velocity:agent:agentBuyer:expires_height",9999);
}
static void seed_maker(QrxDB *db){
    put(db,"velocity:order:maker:owner","seller");
    put(db,"velocity:order:maker:agent","makerAgent");
    put(db,"velocity:order:maker:kind","native");
    put(db,"velocity:order:maker:status","open");
    put(db,"velocity:order:maker:market","TOK/QUB");
    put(db,"velocity:order:maker:side","SELL");
    put(db,"velocity:order:maker:order_type","LIMIT");
    putll(db,"velocity:order:maker:quantity_atoms",5);
    putll(db,"velocity:order:maker:filled_atoms",0);
    putll(db,"velocity:order:maker:remaining_atoms",5);
    putll(db,"velocity:order:maker:limit_price_atoms",200000000LL);
    putll(db,"velocity:order:maker:created_height",10);
    putll(db,"velocity:order:maker:updated_height",10);
    putll(db,"velocity:order:maker:order_expires_height",9999);
    put(db,"velocity:order:maker:settlement_version","1");
    put(db,"velocity:order:maker:locked_asset","TOK");
    putll(db,"velocity:order:maker:locked_atoms",5);
}

int main(void){
    char tmp[]="/tmp/qrx4dXXXXXX";if(!mkdtemp(tmp))die("mkdtemp");QrxDB db;if(qrxdb_init(&db,tmp))die("db init");

    /* Snapshot prefix discovery must see exactly the historical generation and sort keys. */
    put(&db,"scan:test:b","old-b");put(&db,"scan:test:a","old-a");QrxDBReadTxn old;if(qrxdb_read_txn_begin(&db,&old))die("read txn");put(&db,"scan:test:a","new-a");put(&db,"scan:test:c","new-c");ScanCtx sc={0};if(qrxdb_scan_prefix_at(&db,&old,"scan:test:",scan_cb,&sc))die("snapshot scan");if(sc.n!=2||strcmp(sc.keys[0],"scan:test:a")||strcmp(sc.vals[0],"old-a")||strcmp(sc.keys[1],"scan:test:b")||strcmp(sc.vals[1],"old-b"))die("snapshot scan semantics/order");

    putll(&db,"acct:balance:agentBuyer",50);putll(&db,"acct:nonce:agentBuyer",0);putll(&db,"acct:balance:buyer",100);putll(&db,"acct:balance:seller",0);putll(&db,"velocity:asset:balance:TOK:buyer",0);putll(&db,"velocity:asset:balance:TOK:seller",0);putll(&db,"consensus:fee_pool:pending",0);seed_agent(&db);seed_maker(&db);
    putll(&db,"velocity:asset:balance:TOK:staleSeller",0);put(&db,"velocity:order:expired:owner","staleSeller");put(&db,"velocity:order:expired:agent","staleAgent");put(&db,"velocity:order:expired:kind","native");put(&db,"velocity:order:expired:status","open");putll(&db,"velocity:order:expired:order_expires_height",90);put(&db,"velocity:order:expired:locked_asset","TOK");putll(&db,"velocity:order:expired:locked_atoms",1);

    char tx[20000],oid[129];mkhash(oid,'a');mk_tx(tx,sizeof(tx),"ORDER_CREATE","agentBuyer","buyer",1,1,"market=TOK/QUB;side=BUY;order_type=LIMIT;quantity_atoms=3;limit_price_atoms=300000000;order_expires_height=9999",'a');
    if(qrx_velocity_tx_adapter_class(tx)!=QRX_VELOCITY_ADAPTER_DYNAMIC)die("dynamic classification");
    QrxVelocityPlan p;plan1(&p,tx);unsigned char mask[1]={1};QrxVelocityMvccStats st;uint64_t gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,4,100,&st)!=QRX_MVCC_OK)die("dynamic execute");if(qrxdb_generation(&db)!=gen+1)die("dynamic not one WAL generation");
    if(st.dynamic_prepared!=1||st.dynamic_trades!=1||st.dynamic_discovered_keys==0||st.expired_orders!=1||st.barriers!=0||st.committed!=1)die("dynamic stats");
    if(getll(&db,"acct:balance:agentBuyer")!=49||getll(&db,"acct:nonce:agentBuyer")!=1||getll(&db,"consensus:fee_pool:pending")!=1)die("outer fee/nonce");
    if(getll(&db,"acct:balance:buyer")!=94||getll(&db,"acct:balance:seller")!=6||getll(&db,"velocity:asset:balance:TOK:buyer")!=3||getll(&db,"velocity:asset:balance:TOK:seller")!=0)die("asset settlement balances");expect(&db,"velocity:order:expired:status","expired");if(getll(&db,"velocity:order:expired:locked_atoms")!=0||getll(&db,"velocity:asset:balance:TOK:staleSeller")!=1)die("dynamic expiry expansion");
    char k[512];snprintf(k,sizeof(k),"velocity:order:%s:status",oid);expect(&db,k,"filled");snprintf(k,sizeof(k),"velocity:order:%s:filled_atoms",oid);if(getll(&db,k)!=3)die("taker filled");snprintf(k,sizeof(k),"velocity:order:%s:remaining_atoms",oid);if(getll(&db,k)!=0)die("taker remaining");snprintf(k,sizeof(k),"velocity:order:%s:locked_atoms",oid);if(getll(&db,k)!=0)die("taker lock");
    expect(&db,"velocity:order:maker:status","partially_filled");if(getll(&db,"velocity:order:maker:filled_atoms")!=3||getll(&db,"velocity:order:maker:remaining_atoms")!=2||getll(&db,"velocity:order:maker:locked_atoms")!=2)die("maker state");if(getll(&db,"velocity:trade_sequence:global")!=1)die("trade seq");snprintf(k,sizeof(k),"velocity:match_pending:%s",oid);expect(&db,k,"0");
    QrxDBReadTxn now;if(qrxdb_read_txn_begin(&db,&now))die("now snapshot");CountCtx tc={0},sett={0};if(qrxdb_scan_prefix_at(&db,&now,"velocity:trade:",count_cb,&tc)||qrxdb_scan_prefix_at(&db,&now,"velocity:settlement:",count_cb,&sett))die("trade scan");if(tc.n<10||sett.n!=1)die("trade/settlement records");qrx_velocity_plan_free(&p);

    /* ORDER_CANCEL is dynamic too: permissions are rechecked but daily usage is not consumed. */
    putll(&db,"velocity:asset:balance:TOK:buyer",2);put(&db,"velocity:order:cancelme:owner","buyer");put(&db,"velocity:order:cancelme:agent","agentBuyer");put(&db,"velocity:order:cancelme:kind","native");put(&db,"velocity:order:cancelme:status","open");put(&db,"velocity:order:cancelme:market","TOK/QUB");put(&db,"velocity:order:cancelme:side","SELL");putll(&db,"velocity:order:cancelme:quantity_atoms",1);putll(&db,"velocity:order:cancelme:filled_atoms",0);putll(&db,"velocity:order:cancelme:remaining_atoms",1);put(&db,"velocity:order:cancelme:locked_asset","TOK");putll(&db,"velocity:order:cancelme:locked_atoms",1);putll(&db,"velocity:order:cancelme:order_expires_height",9999);
    char cancel[20000];mk_tx(cancel,sizeof(cancel),"ORDER_CANCEL","agentBuyer","buyer",1,2,"order_id=cancelme",'d');if(qrx_velocity_tx_adapter_class(cancel)!=QRX_VELOCITY_ADAPTER_DYNAMIC)die("cancel dynamic classification");plan1(&p,cancel);gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,2,101,&st)!=QRX_MVCC_OK||qrxdb_generation(&db)!=gen+1)die("dynamic cancel");expect(&db,"velocity:order:cancelme:status","canceled");if(getll(&db,"velocity:order:cancelme:locked_atoms")!=0||getll(&db,"velocity:asset:balance:TOK:buyer")!=3||getll(&db,"velocity:agent_usage:agentBuyer:0")!=3)die("cancel release/usage");qrx_velocity_plan_free(&p);

    /* ORDER_REPLACE atomically releases old reserve, reserves the replacement, then matches it. */
    putll(&db,"acct:balance:buyer",92);put(&db,"velocity:order:replaceOld:owner","buyer");put(&db,"velocity:order:replaceOld:agent","agentBuyer");put(&db,"velocity:order:replaceOld:kind","native");put(&db,"velocity:order:replaceOld:status","open");put(&db,"velocity:order:replaceOld:market","TOK/QUB");put(&db,"velocity:order:replaceOld:side","BUY");put(&db,"velocity:order:replaceOld:order_type","LIMIT");putll(&db,"velocity:order:replaceOld:quantity_atoms",1);putll(&db,"velocity:order:replaceOld:filled_atoms",0);putll(&db,"velocity:order:replaceOld:remaining_atoms",1);putll(&db,"velocity:order:replaceOld:limit_price_atoms",200000000LL);putll(&db,"velocity:order:replaceOld:created_height",20);putll(&db,"velocity:order:replaceOld:updated_height",20);putll(&db,"velocity:order:replaceOld:order_expires_height",9999);put(&db,"velocity:order:replaceOld:settlement_version","1");put(&db,"velocity:order:replaceOld:locked_asset","QUB");putll(&db,"velocity:order:replaceOld:locked_atoms",2);
    char repl[20000],roid[129];mkhash(roid,'e');mk_tx(repl,sizeof(repl),"ORDER_REPLACE","agentBuyer","buyer",1,3,"order_id=replaceOld;market=TOK/QUB;side=BUY;order_type=LIMIT;quantity_atoms=2;limit_price_atoms=300000000;order_expires_height=9999",'e');if(qrx_velocity_tx_adapter_class(repl)!=QRX_VELOCITY_ADAPTER_DYNAMIC)die("replace dynamic classification");plan1(&p,repl);gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,2,102,&st)!=QRX_MVCC_OK||qrxdb_generation(&db)!=gen+1)die("dynamic replace");expect(&db,"velocity:order:replaceOld:status","replaced");snprintf(k,sizeof(k),"velocity:order:%s:status",roid);expect(&db,k,"filled");if(getll(&db,"acct:balance:buyer")!=90||getll(&db,"acct:balance:seller")!=10||getll(&db,"velocity:asset:balance:TOK:buyer")!=5||getll(&db,"velocity:order:maker:remaining_atoms")!=0||getll(&db,"velocity:agent_usage:agentBuyer:0")!=5||getll(&db,"velocity:trade_sequence:global")!=2)die("replace settlement");qrx_velocity_plan_free(&p);

    /* A stale dynamic snapshot must retry and must not leak any staged write. */
    char tx2[20000];mk_tx(tx2,sizeof(tx2),"ORDER_CREATE","agentBuyer","buyer",1,4,"market=TOK/QUB;side=BUY;order_type=LIMIT;quantity_atoms=1;limit_price_atoms=100000000;order_expires_height=9999",'b');plan1(&p,tx2);QrxVelocityMvccPrepared prep;memset(&prep,0,sizeof(prep));memset(&st,0,sizeof(st));if(qrx_velocity_mvcc_prepare_batch(&db,&p,mask,2,101,&prep,&st)!=QRX_MVCC_OK)die("dynamic retry prepare");put(&db,"test:concurrent","1");if(qrx_velocity_mvcc_commit(&db,&prep,&st)!=QRX_MVCC_RETRY)die("dynamic stale generation");char oid2[129];mkhash(oid2,'b');snprintf(k,sizeof(k),"velocity:order:%s:owner",oid2);char v[64];if(qrxdb_get(&db,k,v,sizeof(v))==0)die("stale dynamic write leaked");qrx_velocity_mvcc_prepared_free(&prep);qrx_velocity_plan_free(&p);

    /* External/cross-chain/SPV families are still explicit barriers in 4D. */
    char ext[20000];mk_tx(ext,sizeof(ext),"EXTERNAL_ORDER","agentBuyer","buyer",1,4,"venue=KRAKEN;market=BTC/QUB;side=BUY;order_type=LIMIT;quantity_atoms=1;limit_price_atoms=100000000;order_expires_height=9999",'c');if(qrx_velocity_tx_adapter_class(ext)!=QRX_VELOCITY_ADAPTER_BARRIER)die("remaining barrier classification");plan1(&p,ext);gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,2,102,&st)!=QRX_MVCC_BARRIER||qrxdb_generation(&db)!=gen)die("remaining barrier mutation");qrx_velocity_plan_free(&p);

    /* Phase 4E may co-pack a dynamic transaction with statically independent
       work; Phase 4D's regression contract is that the dynamic adapter is still
       preserved and planned, not that it remains artificially isolated. */
    char mpdir[1200],fast[20000];snprintf(mpdir,sizeof(mpdir),"%s/mp",tmp);mk_tx(fast,sizeof(fast),"TRANSFER_FAST","otherA","otherB",1,1,"test",'f');QrxVelocityMempool mp;if(qrx_velocity_mempool_open(&mp,mpdir,100))die("planner mempool open");if(qrx_velocity_mempool_add(&mp,tx,NULL)<0||qrx_velocity_mempool_add(&mp,fast,NULL)<0)die("planner mempool add");QrxVelocityPlan pp;if(qrx_velocity_mempool_plan(&mp,10,&pp))die("planner plan");int saw_dynamic=0;for(size_t i=0;i<pp.count;i++)if(qrx_velocity_tx_adapter_class(pp.txs[i])==QRX_VELOCITY_ADAPTER_DYNAMIC)saw_dynamic=1;if(!saw_dynamic)die("planner lost dynamic tx");qrx_velocity_plan_free(&pp);qrx_velocity_mempool_close(&mp);

    qrxdb_close(&db);puts("VELOCITY Phase 4D dynamic write-set expansion + native matching/settlement test PASSED");return 0;
}
