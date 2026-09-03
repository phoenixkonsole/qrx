#include "mempool/qrx_velocity_mempool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static void die(const char *m){fprintf(stderr,"FAIL: %s\n",m);exit(1);} 
static void mk(char *out,size_t n,const char *from,const char *to,long long fee,long long nonce,const char *type){
    snprintf(out,n,"tx_version=3\nfrom=%s\nto=%s\namount=0\nfee=%lld\nnonce=%lld\nlane_id=0\ntx_type=%s\npayload=market=TOK/QUB;side=BUY;quantity_atoms=1\n",from,to,fee,nonce,type);
}
static void mk_dir(char *out,size_t n,const char *tag){
#ifdef _WIN32
    snprintf(out,n,"qrx4f-%s-%lu",tag,(unsigned long)GetCurrentProcessId());CreateDirectoryA(out,NULL);
#else
    snprintf(out,n,"/tmp/qrx4f-%s-XXXXXX",tag);if(!mkdtemp(out))die("mkdtemp");
#endif
}
static void add_all(QrxVelocityMempool *p,char tx[][2048],const int *order,size_t count){
    for(size_t i=0;i<count;i++)if(qrx_velocity_mempool_add(p,tx[order?order[i]:(int)i],NULL)<0)die("mempool add");
}
int main(void){
    enum {N=7};char tx[N][2048];
    /* Canonical fee order: A,B,C,BARRIER,E,F,G. */
    mk(tx[0],sizeof(tx[0]),"alice","bob",70,1,"TRANSFER_FAST");
    mk(tx[1],sizeof(tx[1]),"carol","dave",60,1,"TRANSFER_FAST");
    mk(tx[2],sizeof(tx[2]),"alice","erin",50,2,"TRANSFER_FAST");
    mk(tx[3],sizeof(tx[3]),"agentX","ownerX",40,1,"EXTERNAL_ORDER");
    mk(tx[4],sizeof(tx[4]),"xavier","yara",30,1,"TRANSFER_FAST");
    mk(tx[5],sizeof(tx[5]),"uma","victor",20,1,"TRANSFER_FAST");
    mk(tx[6],sizeof(tx[6]),"xavier","zoe",10,2,"TRANSFER_FAST");

    char d1[512],d2[512];mk_dir(d1,sizeof(d1),"a");mk_dir(d2,sizeof(d2),"b");
    QrxVelocityMempool a,b;if(qrx_velocity_mempool_open(&a,d1,100))die("open a");if(qrx_velocity_mempool_open(&b,d2,100))die("open b");
    int forward[N]={0,1,2,3,4,5,6};int reverse[N]={6,5,4,3,2,1,0};add_all(&a,tx,forward,N);add_all(&b,tx,reverse,N);
    QrxVelocityPlan pa,pb;if(qrx_velocity_mempool_plan(&a,N,&pa)||qrx_velocity_mempool_plan(&b,N,&pb))die("plan");
    if(pa.count!=N||pb.count!=N)die("plan count");
    for(size_t i=0;i<N;i++){if(strcmp(pa.txids[i],pb.txids[i]))die("canonical order changed with insertion order");if(pa.waves[i]!=pb.waves[i])die("wave changed with insertion order");}
    if(strcmp(pa.schedule_hash,pb.schedule_hash))die("schedule hash not deterministic");

    if(pa.waves[0]!=0||pa.waves[1]!=0)die("independent prefix not parallel");
    if(pa.waves[2]!=1)die("static dependency chain wrong");
    if(pa.waves[3]!=2)die("barrier did not fence complete prefix");
    if(pa.waves[4]!=3||pa.waves[5]!=3)die("post-barrier independent nodes not parallel");
    if(pa.waves[6]!=4)die("post-barrier dependency chain wrong");
    if(pa.wave_count!=5||pa.critical_path_nodes!=5)die("critical path/wave count wrong");
    if(pa.max_parallel_width!=2)die("max parallel width wrong");
    if(pa.barrier_nodes!=1||pa.barrier_fences!=1)die("barrier graph stats wrong");
    if(pa.dependency_edges<7)die("dependency graph unexpectedly sparse");
    if(!pa.schedule_hash[0]||strlen(pa.schedule_hash)!=128)die("schedule hash missing");

    /* Most important Phase 4F regression: a transaction after a barrier can no
       longer be greedily packed back into wave 0, even when statically independent. */
    if(pa.waves[4]<=pa.waves[3]||pa.waves[5]<=pa.waves[3])die("barrier leapfrog regression");

    printf("VELOCITY Phase 4F deterministic parallel block scheduler PASSED waves=%u edges=%llu critical_path=%u max_parallel=%u schedule_hash=%s\n",
           pa.wave_count,(unsigned long long)pa.dependency_edges,pa.critical_path_nodes,pa.max_parallel_width,pa.schedule_hash);
    qrx_velocity_plan_free(&pa);qrx_velocity_plan_free(&pb);qrx_velocity_mempool_close(&a);qrx_velocity_mempool_close(&b);return 0;
}
