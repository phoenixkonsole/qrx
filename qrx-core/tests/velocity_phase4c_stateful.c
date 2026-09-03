#include "mempool/qrx_velocity_mvcc.h"
#include "mempool/qrx_velocity_mempool.h"
#include "qrxdb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void die(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(1);} 
static long long getll(QrxDB *db,const char *k){char b[128];if(qrxdb_get(db,k,b,sizeof(b)))return -999999;return strtoll(b,NULL,10);} 
static void putll(QrxDB *db,const char*k,long long v){char b[64];snprintf(b,sizeof(b),"%lld",v);if(qrxdb_put(db,k,b))die("putll");}
static void mkhash(char out[129],char c){for(int i=0;i<128;i++)out[i]=c;out[128]=0;}
static void mk_tx(char *out,size_t n,const char *type,const char *from,const char *to,long long fee,long long nonce,const char *payload,char hc){char h[129];mkhash(h,hc);snprintf(out,n,"tx_version=3\nfrom=%s\nto=%s\namount=0\nfee=%lld\nnonce=%lld\nlane_id=0\ntx_type=%s\npayload=%s\nbody_hash_sha3_512=%s\n",from,to,fee,nonce,type,payload,h);} 
static void plan2(QrxVelocityPlan *p,char *a,char *b){memset(p,0,sizeof(*p));p->count=2;p->wave_count=1;p->txs=calloc(2,sizeof(char*));p->txids=calloc(2,sizeof(char*));p->waves=calloc(2,sizeof(uint32_t));p->txs[0]=strdup(a);p->txs[1]=strdup(b);p->txids[0]=strdup("a");p->txids[1]=strdup("b");}
static void plan1(QrxVelocityPlan *p,char *a){memset(p,0,sizeof(*p));p->count=1;p->wave_count=1;p->txs=calloc(1,sizeof(char*));p->txids=calloc(1,sizeof(char*));p->waves=calloc(1,sizeof(uint32_t));p->txs[0]=strdup(a);p->txids[0]=strdup("c");}
int main(void){
    char tmp[]="/tmp/qrx4cXXXXXX";if(!mkdtemp(tmp))die("mkdtemp");QrxDB db;if(qrxdb_init(&db,tmp))die("db init");
    putll(&db,"acct:balance:owner1",100);putll(&db,"acct:nonce:owner1",0);putll(&db,"acct:balance:owner2",100);putll(&db,"acct:nonce:owner2",0);putll(&db,"consensus:fee_pool:pending",0);
    char a[20000],g[20000];
    mk_tx(a,sizeof(a),"AGENT_REGISTER","owner1","agent1",1,1,"agent_ed25519_pub_hex=aa;agent_mldsa65_pub_b64=bb;permissions=TRADE;max_trade_atoms=1000;daily_limit_atoms=5000;market_allowlist=BTC/QUB;expires_height=999",'1');
    mk_tx(g,sizeof(g),"GATEWAY_REGISTER","owner2","gateway1",1,1,"venue=KRAKEN;name=gw;gateway_ed25519_pub_hex=cc;gateway_mldsa65_pub_b64=dd;expires_height=999",'2');
    if(qrx_velocity_tx_adapter_class(a)!=QRX_VELOCITY_ADAPTER_STATEFUL||qrx_velocity_tx_adapter_class(g)!=QRX_VELOCITY_ADAPTER_STATEFUL)die("stateful classification");
    QrxVelocityPlan p;plan2(&p,a,g);unsigned char mask[2]={1,1};QrxVelocityMvccStats st;uint64_t gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,4,100,&st)!=QRX_MVCC_OK)die("stateful execute");if(st.stateful_prepared!=2||qrxdb_generation(&db)!=gen+1)die("single batch generation");
    char v[256];if(qrxdb_get(&db,"velocity:agent:agent1:status",v,sizeof(v))||strcmp(v,"active"))die("agent active");if(qrxdb_get(&db,"velocity:gateway:gateway1:status",v,sizeof(v))||strcmp(v,"active"))die("gateway active");if(getll(&db,"acct:balance:owner1")!=99||getll(&db,"acct:balance:owner2")!=99||getll(&db,"consensus:fee_pool:pending")!=2)die("fee/balance state");qrx_velocity_plan_free(&p);
    char u[20000],r[20000];mk_tx(u,sizeof(u),"AGENT_UPDATE","owner1","agent1",1,2,"permissions=TRADE,TRADE_NATIVE;max_trade_atoms=2000;daily_limit_atoms=6000;market_allowlist=BTC/QUB;expires_height=1000",'3');mk_tx(r,sizeof(r),"GATEWAY_REVOKE","owner2","gateway1",1,2,"reason=operator-request",'4');plan2(&p,u,r);gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,mask,4,101,&st)!=QRX_MVCC_OK)die("stateful update execute");if(qrxdb_generation(&db)!=gen+1)die("stateful update one generation");if(qrxdb_get(&db,"velocity:agent:agent1:permissions",v,sizeof(v))||strcmp(v,"TRADE,TRADE_NATIVE"))die("agent update");if(qrxdb_get(&db,"velocity:gateway:gateway1:status",v,sizeof(v))||strcmp(v,"revoked"))die("gateway revoke");qrx_velocity_plan_free(&p);
    char order[4096];mk_tx(order,sizeof(order),"EXTERNAL_ORDER","agent1","owner1",1,1,"venue=KRAKEN;market=BTC/QUB;side=BUY;order_type=LIMIT;quantity_atoms=1;limit_price_atoms=100000000;order_expires_height=999",'5');if(qrx_velocity_tx_adapter_class(order)!=QRX_VELOCITY_ADAPTER_BARRIER)die("barrier classification");plan1(&p,order);unsigned char one[1]={1};gen=qrxdb_generation(&db);if(qrx_velocity_mvcc_execute_batch(&db,&p,one,4,102,&st)!=QRX_MVCC_BARRIER)die("barrier result");if(qrxdb_generation(&db)!=gen)die("barrier mutated state");qrx_velocity_plan_free(&p);
    qrxdb_close(&db);
    /* Planner invariant: a remaining serial barrier never shares a wave. */
    char mpdir[1024];snprintf(mpdir,sizeof(mpdir),"%s/mp",tmp);QrxVelocityMempool mp;if(qrx_velocity_mempool_open(&mp,mpdir,100))die("mempool open");if(qrx_velocity_mempool_add(&mp,a,NULL)<0||qrx_velocity_mempool_add(&mp,order,NULL)<0||qrx_velocity_mempool_add(&mp,g,NULL)<0)die("mempool add");if(qrx_velocity_mempool_plan(&mp,10,&p))die("mempool plan");for(size_t i=0;i<p.count;i++)if(qrx_velocity_tx_adapter_class(p.txs[i])==QRX_VELOCITY_ADAPTER_BARRIER)for(size_t j=0;j<p.count;j++)if(i!=j&&p.waves[i]==p.waves[j])die("barrier shared wave");qrx_velocity_plan_free(&p);qrx_velocity_mempool_close(&mp);
    puts("VELOCITY Phase 4C stateful MVCC adapter test PASSED");return 0;
}
