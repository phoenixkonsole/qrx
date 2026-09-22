#include "storage/qrx_storage_transport.h"
#include "storage/qrx_erasure.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#endif

typedef struct {QrxErasureSet *encoded;size_t calls[14];} Fixture;
static int fetch_cb(void *v,const QrxShardProviderSource *src,const uint8_t oid[64],uint64_t off,size_t want,uint8_t **out,size_t *out_len){
    (void)oid;Fixture*f=v;unsigned i=src->source.shard_index;if(i==1)return -1; /* dead provider */
    if(i==2){ /* force hedge */
#ifdef _WIN32
        Sleep(220);
#else
        struct timespec t={0,220000000L};nanosleep(&t,NULL);
#endif
    }
    if(off>=f->encoded->shard_size)return -1;size_t n=f->encoded->shard_size-(size_t)off;if(n>want)n=want;if(n>37)n=37; /* force resume */
    *out=malloc(n);assert(*out);memcpy(*out,f->encoded->shards[i]+off,n);*out_len=n;f->calls[i]++;return 0;
}
static int verify_cb(void *v,uint32_t i,const uint8_t*d,size_t n){Fixture*f=v;return n==f->encoded->shard_size&&memcmp(d,f->encoded->shards[i],n)==0?0:-1;}
int main(void){
    uint8_t original[4097];for(size_t i=0;i<sizeof(original);i++)original[i]=(uint8_t)(i*31u+7u);QrxErasureSet e;assert(qrx_erasure_encode(original,sizeof(original),10,4,&e)==0);
    QrxShardProviderSource s[14];char ids[14][16];for(unsigned i=0;i<14;i++){snprintf(ids[i],sizeof(ids[i]),"provider-%u",i);s[i].provider_id=ids[i];s[i].source=(QrxShardSource){i,(uint32_t)(20+i),100000000-i*1000000,9900};}
    Fixture f={&e,{0}};uint8_t oid[64]={0};QrxMultiFetchOptions o={10,10,2,128,25,1};uint8_t*out=NULL;size_t outn=0;QrxMultiFetchStats st;
    assert(qrx_storage_multi_provider_fetch(s,14,oid,e.shard_size,10,4,sizeof(original),&o,fetch_cb,verify_cb,&f,&out,&outn,&st)==0);
    assert(outn==sizeof(original)&&memcmp(out,original,outn)==0);assert(st.successful_shards>=10);assert(st.sources_started>10);assert(st.hedges_started>0);assert(st.resumed_ranges>0);free(out);qrx_erasure_free(&e);return 0;
}
