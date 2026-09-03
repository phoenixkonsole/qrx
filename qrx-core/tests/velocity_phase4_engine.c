#include "mempool/qrx_velocity_mempool.h"
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
static int fake_verify(void *ctx,const char *tx,char *err,size_t err_sz){(void)ctx;if(strstr(tx,"signed=true"))return 0;snprintf(err,err_sz,"not signed");return -1;}
static void mk(char *out,size_t n,const char *from,const char *to,long long fee,long long nonce,const char *type){snprintf(out,n,"tx_version=3\nfrom=%s\nto=%s\nfee=%lld\nnonce=%lld\nlane_id=1\ntx_type=%s\npayload=x=1\nsigned=true\n",from,to,fee,nonce,type);}
int main(void){
    char dir[512];
#ifdef _WIN32
    snprintf(dir,sizeof(dir),"velocity-p4-test-%lu",(unsigned long)GetCurrentProcessId());CreateDirectoryA(dir,NULL);
#else
    snprintf(dir,sizeof(dir),"/tmp/qrx-velocity-p4-%ld",(long)getpid());mkdir(dir,0700);
#endif
    QrxVelocityMempool p; if(qrx_velocity_mempool_open(&p,dir,1000)!=0)die("open");
    char a[2048],b[2048],c[2048],id1[129],id2[129],id3[129];
    mk(a,sizeof(a),"alice","bob",30,1,"TRANSFER_FAST");mk(b,sizeof(b),"carol","dave",20,1,"TRANSFER_FAST");mk(c,sizeof(c),"alice","erin",10,2,"TRANSFER_FAST");
    if(qrx_velocity_mempool_add(&p,a,id1)!=0)die("add a");if(qrx_velocity_mempool_add(&p,b,id2)!=0)die("add b");if(qrx_velocity_mempool_add(&p,c,id3)!=0)die("add c");if(qrx_velocity_mempool_add(&p,a,NULL)!=1)die("duplicate not detected");
    QrxVelocityPlan plan;if(qrx_velocity_mempool_plan(&p,100,&plan)!=0)die("plan");if(plan.count!=3)die("plan count");if(plan.wave_count<2)die("conflict wave missing");
    /* fee order is A, B, C; A and B independent, C conflicts with A */
    if(plan.waves[0]!=0||plan.waves[1]!=0||plan.waves[2]==0)die("wrong conflict scheduling");
    unsigned char *mask=NULL;QrxVelocityVerifyStats vs;if(qrx_velocity_parallel_verify(&plan,4,fake_verify,NULL,&mask,&vs)!=0)die("parallel verify");if(vs.ok!=3||vs.failed!=0)die("verify stats");free(mask);qrx_velocity_plan_free(&plan);
    /* Exercise sharding/WAL with independent transactions. */
    for(int i=0;i<250;i++){char tx[2048],from[64],to[64];snprintf(from,sizeof(from),"u%04d",i);snprintf(to,sizeof(to),"v%04d",i);mk(tx,sizeof(tx),from,to,i%17+1,1,"TRANSFER_FAST");int rc=qrx_velocity_mempool_add(&p,tx,NULL);if(rc<0)die("bulk add");}
    QrxVelocityMempoolStats st;qrx_velocity_mempool_stats(&p,&st);if(st.entries!=253)die("entry stats");if(st.shards!=QRX_VELOCITY_MEMPOOL_SHARDS)die("shards");
    if(qrx_velocity_mempool_remove(&p,id2)!=0)die("remove");if(qrx_velocity_mempool_checkpoint(&p)!=0)die("checkpoint");qrx_velocity_mempool_close(&p);
    if(qrx_velocity_mempool_open(&p,dir,1000)!=0)die("reopen");qrx_velocity_mempool_stats(&p,&st);if(st.entries!=252)die("WAL recovery count");
    if(qrx_velocity_mempool_plan(&p,300,&plan)!=0)die("replan");if(plan.count!=252)die("replan count");qrx_velocity_plan_free(&plan);qrx_velocity_mempool_close(&p);
    printf("VELOCITY Phase 4 RAM mempool + WAL + sharding + conflict waves + parallel validation PASSED\n");
    return 0;
}
