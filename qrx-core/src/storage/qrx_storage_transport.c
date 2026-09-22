#include "storage/qrx_storage_transport.h"
#include <string.h>
static uint64_t score(const QrxShardSource *s){uint64_t rel=s->reliability_bps>10000?10000:s->reliability_bps;uint64_t lat=s->expected_latency_ms?1000000ULL/s->expected_latency_ms:1000000ULL;uint64_t th=s->throughput_bps/1000000ULL;if(th>100000)th=100000;return rel*1000000ULL+lat*1000ULL+th;}
int qrx_storage_fetch_plan(const QrxShardSource *s,size_t n,size_t k,size_t hedge,QrxShardFetchPlan *o){if(!s||!o||!n||n>QRX_STORAGE_MAX_FETCH_SOURCES||!k||k>n)return -1;memset(o,0,sizeof(*o));uint8_t used[QRX_STORAGE_MAX_FETCH_SOURCES]={0};for(size_t pos=0;pos<n;pos++){int found=-1;uint64_t best=0;for(size_t i=0;i<n;i++)if(!used[i]){uint64_t v=score(&s[i]);if(found<0||v>best){found=(int)i;best=v;}}used[found]=1;o->ordered_shards[pos]=s[found].shard_index;}o->source_count=n;o->required_successes=k;o->initial_parallel=k+hedge<n?k+hedge:n;o->hedge_after_failures=1;o->cancel_remaining_after_k=1;return 0;}
static void p32(uint8_t *o,uint32_t v){o[0]=v>>24;o[1]=v>>16;o[2]=v>>8;o[3]=v;}static void p64(uint8_t *o,uint64_t v){for(int i=7;i>=0;i--){o[i]=(uint8_t)v;v>>=8;}}static uint32_t g32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}static uint64_t g64(const uint8_t *p){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|p[i];return v;}
int qrx_storage_range_serialize(const QrxShardRangeRequest *r,uint8_t out[88]){if(!r||!out||!r->length)return -1;memcpy(out,"QRXSRNG1",8);memcpy(out+8,r->object_id,64);p32(out+72,r->shard_index);p64(out+76,r->offset);p32(out+84,r->length);return 0;}
int qrx_storage_range_parse(const uint8_t in[88],QrxShardRangeRequest *r){if(!in||!r||memcmp(in,"QRXSRNG1",8)!=0)return -1;memset(r,0,sizeof(*r));memcpy(r->object_id,in+8,64);r->shard_index=g32(in+72);r->offset=g64(in+76);r->length=g32(in+84);return r->length?0:-1;}

#include "storage/qrx_erasure.h"
#include "platform/qrx_threads.h"
#include <stdlib.h>
#include <time.h>

typedef struct QrxFetchShared QrxFetchShared;
typedef struct {QrxFetchShared *s;size_t source_pos;} QrxFetchWorker;
struct QrxFetchShared {
    const QrxShardProviderSource *sources; size_t source_count; uint8_t object_id[64]; size_t shard_size;
    QrxMultiFetchOptions opt; QrxShardFetchRangeFn fetch; QrxShardVerifyFn verify; void *ctx;
    qrx_mutex_t mu; qrx_cond_t cv; int stop; size_t successes; size_t completed;
    uint8_t **shards; uint8_t *present; QrxMultiFetchStats stats;
};
static void *fetch_worker(void *arg){
    QrxFetchWorker *w=(QrxFetchWorker*)arg; QrxFetchShared *s=w->s; const QrxShardProviderSource *src=&s->sources[w->source_pos];
    uint32_t si=src->source.shard_index; uint8_t *whole=NULL; size_t have=0; int failed=0; size_t retries=0;
    whole=(uint8_t*)malloc(s->shard_size?s->shard_size:1); if(!whole) failed=1;
    while(!failed&&have<s->shard_size){
        qrx_mutex_lock(&s->mu); int stop=s->stop; qrx_mutex_unlock(&s->mu); if(stop){free(whole);whole=NULL;break;}
        size_t want=s->shard_size-have; if(want>s->opt.range_bytes)want=s->opt.range_bytes;
        uint8_t *part=NULL; size_t got=0; int rc=s->fetch(s->ctx,src,s->object_id,have,want,&part,&got);
        if(rc!=0||!part||got==0||got>want){free(part);if(++retries>s->opt.max_range_retries){failed=1;break;}continue;}
        memcpy(whole+have,part,got);free(part);
        qrx_mutex_lock(&s->mu);s->stats.bytes_received+=got;if(have>0||got<want)s->stats.resumed_ranges++;qrx_mutex_unlock(&s->mu);
        have+=got; retries=0;
    }
    if(!failed&&whole&&have==s->shard_size&&s->verify&&s->verify(s->ctx,si,whole,have)!=0)failed=1;
    qrx_mutex_lock(&s->mu);
    if(!s->stop&&!failed&&whole&&si<s->source_count&&!s->present[si]){s->shards[si]=whole;whole=NULL;s->present[si]=1;s->successes++;s->stats.successful_shards=s->successes;if(s->successes>=s->opt.required_successes)s->stop=1;}
    else if(failed)s->stats.sources_failed++;
    else if(s->stop)s->stats.cancelled_sources++;
    s->completed++;s->stats.sources_completed=s->completed;qrx_cond_broadcast(&s->cv);qrx_mutex_unlock(&s->mu);free(whole);return NULL;
}
static void deadline_after_ms(struct timespec *ts,uint32_t ms){timespec_get(ts,TIME_UTC);ts->tv_sec+=ms/1000;ts->tv_nsec+=(long)(ms%1000)*1000000L;if(ts->tv_nsec>=1000000000L){ts->tv_sec++;ts->tv_nsec-=1000000000L;}}
int qrx_storage_multi_provider_fetch(const QrxShardProviderSource *sources,size_t n,const uint8_t object_id[64],size_t shard_size,unsigned k,unsigned m,size_t original_size,const QrxMultiFetchOptions *options,QrxShardFetchRangeFn fetch,QrxShardVerifyFn verify,void *ctx,uint8_t **data_out,size_t *data_len_out,QrxMultiFetchStats *stats_out){
    if(!sources||!n||n>QRX_STORAGE_MAX_FETCH_SOURCES||!object_id||!shard_size||!k||k+m>n||!fetch||!data_out||!data_len_out)return -1;
    QrxMultiFetchOptions o={k,k,2,QRX_STORAGE_DEFAULT_FETCH_RANGE,150,2};if(options)o=*options;if(!o.required_successes)o.required_successes=k;if(o.required_successes<k||o.required_successes>n)return -1;if(!o.initial_parallel)o.initial_parallel=o.required_successes;if(o.initial_parallel>n)o.initial_parallel=n;if(!o.range_bytes)o.range_bytes=QRX_STORAGE_DEFAULT_FETCH_RANGE;if(!o.hedge_delay_ms)o.hedge_delay_ms=150;
    QrxShardSource metrics[QRX_STORAGE_MAX_FETCH_SOURCES];for(size_t i=0;i<n;i++){if(sources[i].source.shard_index>=k+m)return -1;metrics[i]=sources[i].source;for(size_t j=0;j<i;j++)if(metrics[j].shard_index==metrics[i].shard_index)return -1;}
    QrxShardFetchPlan plan;if(qrx_storage_fetch_plan(metrics,n,o.required_successes,o.hedge_extra,&plan)!=0)return -1;
    QrxShardProviderSource ordered[QRX_STORAGE_MAX_FETCH_SOURCES];for(size_t p=0;p<n;p++){size_t found=n;for(size_t i=0;i<n;i++)if(sources[i].source.shard_index==plan.ordered_shards[p]){found=i;break;}if(found==n)return -1;ordered[p]=sources[found];}
    QrxFetchShared s;memset(&s,0,sizeof(s));s.sources=ordered;s.source_count=k+m;memcpy(s.object_id,object_id,64);s.shard_size=shard_size;s.opt=o;s.fetch=fetch;s.verify=verify;s.ctx=ctx;s.shards=calloc(k+m,sizeof(uint8_t*));s.present=calloc(k+m,1);if(!s.shards||!s.present){free(s.shards);free(s.present);return -1;}qrx_mutex_init(&s.mu,NULL);qrx_cond_init(&s.cv,NULL);
    qrx_thread_t threads[QRX_STORAGE_MAX_FETCH_SOURCES];QrxFetchWorker workers[QRX_STORAGE_MAX_FETCH_SOURCES];size_t launched=0,joined=0;size_t initial=o.initial_parallel; if(initial>n)initial=n;
    while(launched<initial){workers[launched]=(QrxFetchWorker){&s,launched};if(qrx_thread_create(&threads[launched],NULL,fetch_worker,&workers[launched])!=0)break;launched++;s.stats.sources_started++;}
    while(1){qrx_mutex_lock(&s.mu);if(s.successes>=o.required_successes||s.completed>=n||(s.completed==launched&&launched>=n)){qrx_mutex_unlock(&s.mu);break;}size_t before=s.completed;struct timespec ts;deadline_after_ms(&ts,o.hedge_delay_ms);qrx_cond_timedwait(&s.cv,&s.mu,&ts);int need_hedge=!s.stop&&s.successes<o.required_successes&&launched<n&&(s.completed>before||s.completed==launched||1);qrx_mutex_unlock(&s.mu);
        if(need_hedge){size_t add=o.hedge_extra?o.hedge_extra:1;while(add--&&launched<n){workers[launched]=(QrxFetchWorker){&s,launched};if(qrx_thread_create(&threads[launched],NULL,fetch_worker,&workers[launched])!=0)break;launched++;qrx_mutex_lock(&s.mu);s.stats.sources_started++;s.stats.hedges_started++;qrx_mutex_unlock(&s.mu);}}
    }
    qrx_mutex_lock(&s.mu);if(s.successes>=o.required_successes)s.stop=1;qrx_cond_broadcast(&s.cv);qrx_mutex_unlock(&s.mu);for(joined=0;joined<launched;joined++)qrx_thread_join(threads[joined],NULL);
    int rc=-1;if(s.successes>=k){QrxErasureSet es;memset(&es,0,sizeof(es));es.data_shards=k;es.parity_shards=m;es.shard_size=shard_size;es.original_size=original_size;es.shards=s.shards;es.present=s.present;if(qrx_erasure_reconstruct(&es)==0&&qrx_erasure_join(&es,data_out,data_len_out)==0)rc=0;qrx_erasure_free(&es);s.shards=NULL;s.present=NULL;}
    if(stats_out)*stats_out=s.stats;for(size_t i=0;s.shards&&i<k+m;i++)free(s.shards[i]);free(s.shards);free(s.present);qrx_cond_destroy(&s.cv);qrx_mutex_destroy(&s.mu);return rc;
}


#include <stdio.h>
#include <openssl/evp.h>
#ifdef _WIN32
#define QRX_TRANSPORT_FSEEK64(f,o,w) _fseeki64((f),(__int64)(o),(w))
#else
#define QRX_TRANSPORT_FSEEK64(f,o,w) fseeko((f),(off_t)(o),(w))
#endif
static int oid_matches_ctx(EVP_MD_CTX *m,const char *want){
    if(!m||!want||strlen(want)!=64)return -1;unsigned char h[32];unsigned int hn=0;
    EVP_MD_CTX *copy=EVP_MD_CTX_new();if(!copy)return -1;int ok=EVP_MD_CTX_copy_ex(copy,m)==1&&EVP_DigestFinal_ex(copy,h,&hn)==1&&hn==32;EVP_MD_CTX_free(copy);if(!ok)return -1;
    static const char*x="0123456789abcdef";char got[65];for(int i=0;i<32;i++){got[i*2]=x[h[i]>>4];got[i*2+1]=x[h[i]&15];}got[64]=0;return strcmp(got,want)?-1:0;
}
int qrx_storage_stream_reconstruct_to_file(const QrxShardProviderSource*sources,size_t n,size_t shard_size,unsigned k,unsigned m,size_t original,size_t stripe,QrxShardFetchRangeFn fetch,void*ctx,const char*out,QrxMultiFetchStats*stats){
    if(!sources||!n||n<k||!shard_size||!k||!m||k+m>n||!fetch||!out)return -1;if(!stripe)stripe=QRX_STORAGE_DEFAULT_FETCH_RANGE;if(stripe>shard_size)stripe=shard_size;
    FILE*f=fopen(out,"wb+");if(!f)return -1;QrxMultiFetchStats st={0};uint8_t zero[64]={0};size_t chosen[255];unsigned chosen_n=0;EVP_MD_CTX*hashes[255]={0};
    /* Probe/fix a provider set on the first stripe. Keeping a stable provider per
     * shard allows full CAS verification while still bounding memory. */
    size_t first=shard_size<stripe?shard_size:stripe;QrxErasureSet probe={0};probe.data_shards=k;probe.parity_shards=m;probe.shard_size=first;probe.original_size=(size_t)k*first;probe.shards=calloc(k+m,sizeof(uint8_t*));probe.present=calloc(k+m,1);if(!probe.shards||!probe.present){qrx_erasure_free(&probe);fclose(f);return -1;}
    for(size_t i=0;i<n&&chosen_n<k;i++){uint32_t si=sources[i].source.shard_index;if(si>=k+m||probe.present[si])continue;uint8_t*b=NULL;size_t bn=0;st.sources_started++;if(!fetch(ctx,&sources[i],zero,0,first,&b,&bn)&&b&&bn==first){probe.shards[si]=b;probe.present[si]=1;chosen[chosen_n]=i;hashes[chosen_n]=EVP_MD_CTX_new();if(!hashes[chosen_n]||EVP_DigestInit_ex(hashes[chosen_n],EVP_sha3_256(),NULL)!=1||EVP_DigestUpdate(hashes[chosen_n],b,bn)!=1){free(b);probe.shards[si]=NULL;probe.present[si]=0;EVP_MD_CTX_free(hashes[chosen_n]);hashes[chosen_n]=NULL;fclose(f);remove(out);qrx_erasure_free(&probe);return -1;}chosen_n++;st.successful_shards++;st.bytes_received+=bn;}else{free(b);st.sources_failed++;}st.sources_completed++;}
    if(chosen_n<k||qrx_erasure_reconstruct(&probe)){for(unsigned i=0;i<chosen_n;i++)EVP_MD_CTX_free(hashes[i]);qrx_erasure_free(&probe);fclose(f);remove(out);return -1;}
    for(unsigned d=0;d<k;d++){uint64_t pos=(uint64_t)d*shard_size; if(pos>=original)break;size_t wr=first;if(pos+wr>original)wr=(size_t)(original-pos);if(QRX_TRANSPORT_FSEEK64(f,pos,SEEK_SET)||fwrite(probe.shards[d],1,wr,f)!=wr){for(unsigned i=0;i<chosen_n;i++)EVP_MD_CTX_free(hashes[i]);qrx_erasure_free(&probe);fclose(f);remove(out);return -1;}}
    qrx_erasure_free(&probe);
    for(size_t off=first;off<shard_size;off+=stripe){size_t want=shard_size-off;if(want>stripe)want=stripe;QrxErasureSet es={0};es.data_shards=k;es.parity_shards=m;es.shard_size=want;es.original_size=(size_t)k*want;es.shards=calloc(k+m,sizeof(uint8_t*));es.present=calloc(k+m,1);if(!es.shards||!es.present){qrx_erasure_free(&es);goto fail;}
        for(unsigned c=0;c<chosen_n;c++){size_t i=chosen[c];uint32_t si=sources[i].source.shard_index;uint8_t*b=NULL;size_t bn=0;st.sources_started++;if(fetch(ctx,&sources[i],zero,off,want,&b,&bn)||!b||bn!=want){free(b);st.sources_failed++;st.sources_completed++;qrx_erasure_free(&es);goto fail;}if(EVP_DigestUpdate(hashes[c],b,bn)!=1){free(b);qrx_erasure_free(&es);goto fail;}es.shards[si]=b;es.present[si]=1;st.bytes_received+=bn;st.sources_completed++;}
        if(qrx_erasure_reconstruct(&es)){qrx_erasure_free(&es);goto fail;}for(unsigned d=0;d<k;d++){uint64_t pos=(uint64_t)d*shard_size+off;if(pos>=original)break;size_t wr=want;if(pos+wr>original)wr=(size_t)(original-pos);if(QRX_TRANSPORT_FSEEK64(f,pos,SEEK_SET)||fwrite(es.shards[d],1,wr,f)!=wr){qrx_erasure_free(&es);goto fail;}}qrx_erasure_free(&es);
    }
    for(unsigned c=0;c<chosen_n;c++){if(oid_matches_ctx(hashes[c],sources[chosen[c]].object_id_hex)){goto fail;}EVP_MD_CTX_free(hashes[c]);hashes[c]=NULL;}
    if(fclose(f)){remove(out);return -1;}if(stats)*stats=st;return 0;
fail: for(unsigned c=0;c<chosen_n;c++)EVP_MD_CTX_free(hashes[c]);fclose(f);remove(out);if(stats)*stats=st;return -1;
}

int qrx_storage_stream_reconstruct_shard_to_file(const QrxShardProviderSource*sources,size_t n,size_t shard_size,unsigned k,unsigned m,uint32_t target,size_t stripe,QrxShardFetchRangeFn fetch,void*ctx,const char*want_oid,const char*out,QrxMultiFetchStats*stats){
    if(!sources||n<k||!shard_size||!k||!m||target>=k+m||!fetch||!want_oid||strlen(want_oid)!=64||!out)return -1;
    if(!stripe)stripe=QRX_STORAGE_DEFAULT_FETCH_RANGE;if(stripe>shard_size)stripe=shard_size;
    FILE*f=fopen(out,"wb");if(!f)return -1;QrxMultiFetchStats st={0};size_t chosen[255];unsigned cn=0;EVP_MD_CTX*src_hash[255]={0};EVP_MD_CTX*tgt_hash=EVP_MD_CTX_new();if(!tgt_hash||EVP_DigestInit_ex(tgt_hash,EVP_sha3_256(),NULL)!=1){EVP_MD_CTX_free(tgt_hash);fclose(f);remove(out);return -1;}
    size_t first=shard_size<stripe?shard_size:stripe;QrxErasureSet probe={0};probe.data_shards=k;probe.parity_shards=m;probe.shard_size=first;probe.original_size=(size_t)k*first;probe.shards=calloc(k+m,sizeof(uint8_t*));probe.present=calloc(k+m,1);if(!probe.shards||!probe.present)goto fail;
    uint8_t zero[64]={0};for(size_t i=0;i<n&&cn<k;i++){uint32_t si=sources[i].source.shard_index;if(si>=k+m||si==target||probe.present[si])continue;uint8_t*b=NULL;size_t bn=0;st.sources_started++;if(!fetch(ctx,&sources[i],zero,0,first,&b,&bn)&&b&&bn==first){probe.shards[si]=b;probe.present[si]=1;chosen[cn]=i;src_hash[cn]=EVP_MD_CTX_new();if(!src_hash[cn]||EVP_DigestInit_ex(src_hash[cn],EVP_sha3_256(),NULL)!=1||EVP_DigestUpdate(src_hash[cn],b,bn)!=1){free(b);probe.shards[si]=NULL;probe.present[si]=0;goto fail;}cn++;st.successful_shards++;st.bytes_received+=bn;}else{free(b);st.sources_failed++;}st.sources_completed++;}
    if(cn<k||qrx_erasure_reconstruct(&probe)||!probe.shards[target]||EVP_DigestUpdate(tgt_hash,probe.shards[target],first)!=1||fwrite(probe.shards[target],1,first,f)!=first)goto fail;qrx_erasure_free(&probe);
    for(size_t off=first;off<shard_size;off+=stripe){size_t want=shard_size-off;if(want>stripe)want=stripe;QrxErasureSet es={0};es.data_shards=k;es.parity_shards=m;es.shard_size=want;es.original_size=(size_t)k*want;es.shards=calloc(k+m,sizeof(uint8_t*));es.present=calloc(k+m,1);if(!es.shards||!es.present){qrx_erasure_free(&es);goto fail;}
        for(unsigned c=0;c<cn;c++){size_t i=chosen[c];uint32_t si=sources[i].source.shard_index;uint8_t*b=NULL;size_t bn=0;st.sources_started++;if(fetch(ctx,&sources[i],zero,off,want,&b,&bn)||!b||bn!=want){free(b);st.sources_failed++;st.sources_completed++;qrx_erasure_free(&es);goto fail;}if(EVP_DigestUpdate(src_hash[c],b,bn)!=1){free(b);qrx_erasure_free(&es);goto fail;}es.shards[si]=b;es.present[si]=1;st.bytes_received+=bn;st.sources_completed++;}
        if(qrx_erasure_reconstruct(&es)||!es.shards[target]||EVP_DigestUpdate(tgt_hash,es.shards[target],want)!=1||fwrite(es.shards[target],1,want,f)!=want){qrx_erasure_free(&es);goto fail;}qrx_erasure_free(&es);
    }
    for(unsigned c=0;c<cn;c++){if(oid_matches_ctx(src_hash[c],sources[chosen[c]].object_id_hex))goto fail;EVP_MD_CTX_free(src_hash[c]);src_hash[c]=NULL;}if(oid_matches_ctx(tgt_hash,want_oid))goto fail;EVP_MD_CTX_free(tgt_hash);if(fclose(f)){remove(out);return -1;}if(stats)*stats=st;return 0;
fail: qrx_erasure_free(&probe);for(unsigned c=0;c<cn;c++)EVP_MD_CTX_free(src_hash[c]);EVP_MD_CTX_free(tgt_hash);fclose(f);remove(out);if(stats)*stats=st;return -1;
}
