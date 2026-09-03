#include "bitcoin/qrx_btc_spv.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strtok_r strtok_s
#endif

#define BTC_HEADER_BYTES 80
#define BTC_RETARGET_INTERVAL 2016ULL
#define BTC_TARGET_TIMESPAN 1209600ULL
#define BTC_TARGET_SPACING 600ULL
#define BTC_TX_MAX_BYTES (4U * 1024U * 1024U)

static void seterr(char *err,size_t sz,const char *msg){if(err&&sz)snprintf(err,sz,"%s",msg?msg:"error");}
static void seterrf(char *err,size_t sz,const char *fmt,unsigned long long v){if(err&&sz)snprintf(err,sz,fmt,v);}

static int hexval(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int hex_decode(const char *hex,unsigned char *out,size_t cap,size_t *n){if(!hex)return -1;size_t len=strlen(hex);if((len&1)||len/2>cap)return -1;for(size_t i=0;i<len/2;i++){int a=hexval(hex[2*i]),b=hexval(hex[2*i+1]);if(a<0||b<0)return -1;out[i]=(unsigned char)((a<<4)|b);}if(n)*n=len/2;return 0;}
static void hex_encode(const unsigned char *in,size_t n,char *out){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[2*i]=h[in[i]>>4];out[2*i+1]=h[in[i]&15];}out[2*n]=0;}
static void reverse32(const unsigned char in[32],unsigned char out[32]){for(int i=0;i<32;i++)out[i]=in[31-i];}
static void hash_display_hex(const unsigned char digest[32],char out[65]){unsigned char r[32];reverse32(digest,r);hex_encode(r,32,out);}
static int display_hex_to_internal(const char *hex,unsigned char out[32]){unsigned char b[32];size_t n=0;if(!hex||strlen(hex)!=64||hex_decode(hex,b,sizeof(b),&n)||n!=32)return -1;reverse32(b,out);return 0;}
static void sha256d(const unsigned char *data,size_t n,unsigned char out[32]){unsigned char t[32];SHA256(data,n,t);SHA256(t,32,out);}
static uint32_t rd32le(const unsigned char *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t rd64le(const unsigned char *p){uint64_t v=0;for(int i=7;i>=0;i--)v=(v<<8)|p[i];return v;}

static int db_get(QrxDB *db,const char *key,char *out,size_t out_sz){return qrxdb_get(db,key,out,out_sz);}
static int db_get_u64(QrxDB *db,const char *key,uint64_t *out){char b[128];if(db_get(db,key,b,sizeof(b)))return -1;char *e=NULL;errno=0;unsigned long long v=strtoull(b,&e,10);if(errno||!e||*e)return -1;*out=(uint64_t)v;return 0;}
static int db_get_u32(QrxDB *db,const char *key,uint32_t *out){uint64_t v=0;if(db_get_u64(db,key,&v)||v>UINT32_MAX)return -1;*out=(uint32_t)v;return 0;}
static int batch_put_u64(QrxDBBatch *b,const char *k,uint64_t v){char x[64];snprintf(x,sizeof(x),"%llu",(unsigned long long)v);return qrxdb_batch_put(b,k,x);}
static int batch_put_u32(QrxDBBatch *b,const char *k,uint32_t v){char x[32];snprintf(x,sizeof(x),"%u",v);return qrxdb_batch_put(b,k,x);}

static const char *normnet(const char *n){if(!n)return NULL;if(!strcasecmp(n,"mainnet")||!strcasecmp(n,"bitcoin"))return "mainnet";if(!strcasecmp(n,"testnet")||!strcasecmp(n,"testnet3"))return "testnet";if(!strcasecmp(n,"regtest"))return "regtest";return NULL;}
int qrx_btc_spv_network_valid(const char *network){return normnet(network)!=NULL;}

const char *qrx_btc_spv_genesis_header_hex(const char *network){
    const char *n=normnet(network);if(!n)return NULL;
    if(!strcmp(n,"mainnet"))return "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    if(!strcmp(n,"testnet"))return "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18";
    return "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000";
}

static uint32_t powlimit_bits(const char *network){const char*n=normnet(network);return n&&!strcmp(n,"regtest")?0x207fffffU:0x1d00ffffU;}

static int compact_to_bn(uint32_t compact,BIGNUM **out){
    uint32_t size=compact>>24,word=compact&0x007fffffU;int neg=(compact&0x00800000U)!=0;
    if(neg||word==0)return -1;
    if(size>34 || (word>0xffU&&size>33) || (word>0xffffU&&size>32))return -1;
    BIGNUM *bn=BN_new();if(!bn)return -1;BN_set_word(bn,word);
    if(size<=3){BN_rshift(bn,bn,8*(3-size));}else{BN_lshift(bn,bn,8*(size-3));}
    if(BN_is_zero(bn)||BN_is_negative(bn)){BN_free(bn);return -1;}*out=bn;return 0;
}

static uint32_t bn_to_compact(const BIGNUM *bn){
    if(!bn||BN_is_zero(bn))return 0;int size=(BN_num_bits(bn)+7)/8;uint32_t compact=0;
    BIGNUM *t=BN_dup(bn);if(!t)return 0;
    if(size<=3){BN_lshift(t,t,8*(3-size));compact=(uint32_t)BN_get_word(t);}else{BN_rshift(t,t,8*(size-3));compact=(uint32_t)BN_get_word(t);}
    BN_free(t);compact&=0x00ffffffU;if(compact&0x00800000U){compact>>=8;size++;}compact|=(uint32_t)size<<24;return compact;
}

static int work_from_bits(uint32_t bits,BIGNUM **out){BIGNUM*t=NULL,*den=NULL,*num=NULL,*work=NULL;if(compact_to_bn(bits,&t))return -1;BN_CTX*ctx=BN_CTX_new();den=BN_dup(t);num=BN_new();work=BN_new();if(!ctx||!den||!num||!work)goto fail;BN_add_word(den,1);BN_one(num);BN_lshift(num,num,256);if(!BN_div(work,NULL,num,den,ctx))goto fail;BN_free(t);BN_free(den);BN_free(num);BN_CTX_free(ctx);*out=work;return 0;fail:BN_free(t);BN_free(den);BN_free(num);BN_free(work);BN_CTX_free(ctx);return -1;}

static int bn_to_hex(const BIGNUM *bn,char *out,size_t sz){char *x=BN_bn2hex(bn);if(!x)return -1;size_t n=strlen(x);if(n+1>sz){OPENSSL_free(x);return -1;}for(size_t i=0;i<n;i++)out[i]=(char)tolower((unsigned char)x[i]);out[n]=0;OPENSSL_free(x);return 0;}
static int hex_to_bn(const char *hex,BIGNUM **out){BIGNUM*b=NULL;if(!hex||!BN_hex2bn(&b,hex))return -1;*out=b;return 0;}

static void hkey(char*out,size_t sz,const char*n,const char*hash,const char*f){snprintf(out,sz,"btcspv:%s:header:%s:%s",n,hash,f);}
static void akey(char*out,size_t sz,const char*n,uint64_t h){snprintf(out,sz,"btcspv:%s:active:%llu",n,(unsigned long long)h);}
static void pkey(char*out,size_t sz,const char*n,const char*txid,const char*f){snprintf(out,sz,"btcspv:%s:proof:%s:%s",n,txid,f);}
static void nkey(char*out,size_t sz,const char*n,const char*f){snprintf(out,sz,"btcspv:%s:%s",n,f);}

static int header_exists(QrxDB*db,const char*n,const char*hash){char k[256],v[16];hkey(k,sizeof(k),n,hash,"height");return db_get(db,k,v,sizeof(v))==0;}

static int load_header_hash(QrxDB*db,const char*n,const char*hash,QrxBtcSpvHeaderInfo*out){
    /* Alias-safe by design: callers frequently walk a chain with
       load_header_hash(db, n, cur.prev_hash, &cur).  Copy the lookup key
       before clearing the destination, otherwise memset(out, ...) also
       destroys hash when hash points inside *out. */
    if(!db||!n||!hash||!out)return -1;
    char hash_copy[QRX_BTC_SPV_HASH_HEX];
    if(strlen(hash)!=64)return -1;
    memcpy(hash_copy,hash,64);hash_copy[64]=0;
    memset(out,0,sizeof(*out));snprintf(out->hash,sizeof(out->hash),"%s",hash_copy);char k[320],v[256];
#define GH(F,BUF) do{hkey(k,sizeof(k),n,hash_copy,(F));if(db_get(db,k,(BUF),sizeof(BUF)))return -1;}while(0)
    GH("prev",out->prev_hash);GH("merkle",out->merkle_root);GH("header",out->header_hex);GH("chainwork",out->chainwork_hex);
    hkey(k,sizeof(k),n,hash_copy,"height");if(db_get_u64(db,k,&out->height))return -1;
    hkey(k,sizeof(k),n,hash_copy,"version");if(db_get_u32(db,k,&out->version))return -1;
    hkey(k,sizeof(k),n,hash_copy,"time");if(db_get_u32(db,k,&out->timestamp))return -1;
    hkey(k,sizeof(k),n,hash_copy,"bits");if(db_get_u32(db,k,&out->bits))return -1;
    hkey(k,sizeof(k),n,hash_copy,"nonce");if(db_get_u32(db,k,&out->nonce))return -1;
    akey(k,sizeof(k),n,out->height);if(db_get(db,k,v,sizeof(v))==0&&strcmp(v,hash_copy)==0)out->active=1;
#undef GH
    return 0;
}

int qrx_btc_spv_get_header(QrxDB *db,const char *network,const char *hash_or_height,QrxBtcSpvHeaderInfo*out,char*err,size_t err_sz){
    const char*n=normnet(network);if(!n||!hash_or_height||!out){seterr(err,err_sz,"invalid arguments");return -1;}char hash[65]={0};int all_digits=1;for(const char*p=hash_or_height;*p;p++)if(!isdigit((unsigned char)*p)){all_digits=0;break;}
    if(all_digits&&*hash_or_height){char k[256];akey(k,sizeof(k),n,strtoull(hash_or_height,NULL,10));if(db_get(db,k,hash,sizeof(hash))||!strcmp(hash,"-")){seterr(err,err_sz,"active header height not found");return -1;}}
    else{if(strlen(hash_or_height)!=64){seterr(err,err_sz,"header hash must be 64 hex chars");return -1;}snprintf(hash,sizeof(hash),"%s",hash_or_height);}
    if(load_header_hash(db,n,hash,out)){seterr(err,err_sz,"header not found");return -1;}return 0;
}

int qrx_btc_spv_get_best(QrxDB *db,const char *network,QrxBtcSpvHeaderInfo*out,char*err,size_t err_sz){const char*n=normnet(network);char k[128],h[65];if(!n){seterr(err,err_sz,"invalid Bitcoin network");return -1;}nkey(k,sizeof(k),n,"best_hash");if(db_get(db,k,h,sizeof(h))){seterr(err,err_sz,"SPV not initialized");return -1;}return qrx_btc_spv_get_header(db,n,h,out,err,err_sz);}

static int header_hash_from_raw(const unsigned char raw[80],char out[65]){unsigned char d[32];sha256d(raw,80,d);hash_display_hex(d,out);return 0;}
static void field_hash_display(const unsigned char raw[32],char out[65]){unsigned char r[32];reverse32(raw,r);hex_encode(r,32,out);}

static int pow_valid(const unsigned char header[80],uint32_t bits,const char*network,char*err,size_t err_sz){BIGNUM*t=NULL,*limit=NULL,*hv=NULL;if(compact_to_bn(bits,&t)||compact_to_bn(powlimit_bits(network),&limit)){seterr(err,err_sz,"invalid compact target");goto fail;}if(BN_cmp(t,limit)>0){seterr(err,err_sz,"target exceeds network pow limit");goto fail;}unsigned char d[32],r[32];sha256d(header,80,d);reverse32(d,r);hv=BN_bin2bn(r,32,NULL);if(!hv){seterr(err,err_sz,"hash bignum failed");goto fail;}if(BN_cmp(hv,t)>0){seterr(err,err_sz,"header proof of work invalid");goto fail;}BN_free(t);BN_free(limit);BN_free(hv);return 0;fail:BN_free(t);BN_free(limit);BN_free(hv);return -1;}

static int get_ancestor(QrxDB*db,const char*n,const char*start,uint64_t target,QrxBtcSpvHeaderInfo*out){QrxBtcSpvHeaderInfo cur;if(load_header_hash(db,n,start,&cur))return -1;while(cur.height>target){if(load_header_hash(db,n,cur.prev_hash,&cur))return -1;}if(cur.height!=target)return -1;*out=cur;return 0;}

static int expected_bits(QrxDB*db,const char*n,const QrxBtcSpvHeaderInfo*prev,uint64_t new_height,uint32_t new_time,uint32_t*out,char*err,size_t err_sz){
    if(!strcmp(n,"regtest")){*out=prev->bits;return 0;}
    if(new_height%BTC_RETARGET_INTERVAL!=0){
        if(!strcmp(n,"testnet")){
            if((uint64_t)new_time>(uint64_t)prev->timestamp+20ULL*60ULL){*out=powlimit_bits(n);return 0;}
            QrxBtcSpvHeaderInfo cur=*prev;while(cur.height%BTC_RETARGET_INTERVAL!=0 && cur.bits==powlimit_bits(n)){if(load_header_hash(db,n,cur.prev_hash,&cur)){seterr(err,err_sz,"testnet difficulty ancestor missing");return -1;}}*out=cur.bits;return 0;
        }
        *out=prev->bits;return 0;
    }
    QrxBtcSpvHeaderInfo first;if(get_ancestor(db,n,prev->hash,new_height-BTC_RETARGET_INTERVAL,&first)){seterr(err,err_sz,"retarget ancestor missing");return -1;}
    int64_t span=(int64_t)prev->timestamp-(int64_t)first.timestamp;int64_t min=(int64_t)BTC_TARGET_TIMESPAN/4,max=(int64_t)BTC_TARGET_TIMESPAN*4;if(span<min)span=min;if(span>max)span=max;
    BIGNUM*t=NULL,*limit=NULL;if(compact_to_bn(prev->bits,&t)||compact_to_bn(powlimit_bits(n),&limit)){BN_free(t);BN_free(limit);seterr(err,err_sz,"retarget target invalid");return -1;}BN_mul_word(t,(BN_ULONG)span);BN_div_word(t,(BN_ULONG)BTC_TARGET_TIMESPAN);if(BN_cmp(t,limit)>0)BN_copy(t,limit);*out=bn_to_compact(t);BN_free(t);BN_free(limit);return 0;
}

static int median_time_past(QrxDB*db,const char*n,const char*prev_hash,uint32_t*out){uint32_t t[11];size_t count=0;QrxBtcSpvHeaderInfo cur;if(load_header_hash(db,n,prev_hash,&cur))return -1;while(count<11){t[count++]=cur.timestamp;if(cur.height==0)break;if(load_header_hash(db,n,cur.prev_hash,&cur))return -1;}for(size_t i=1;i<count;i++){uint32_t x=t[i];size_t j=i;while(j&&t[j-1]>x){t[j]=t[j-1];j--;}t[j]=x;}*out=t[count/2];return 0;}

static int stage_header_fields(QrxDBBatch*b,const char*n,const QrxBtcSpvHeaderInfo*h){char k[320];int rc=0;
#define PH(F,V) do{hkey(k,sizeof(k),n,h->hash,(F));rc|=qrxdb_batch_put(b,k,(V));}while(0)
    PH("prev",h->prev_hash);PH("merkle",h->merkle_root);PH("header",h->header_hex);PH("chainwork",h->chainwork_hex);
    hkey(k,sizeof(k),n,h->hash,"height");rc|=batch_put_u64(b,k,h->height);hkey(k,sizeof(k),n,h->hash,"version");rc|=batch_put_u32(b,k,h->version);hkey(k,sizeof(k),n,h->hash,"time");rc|=batch_put_u32(b,k,h->timestamp);hkey(k,sizeof(k),n,h->hash,"bits");rc|=batch_put_u32(b,k,h->bits);hkey(k,sizeof(k),n,h->hash,"nonce");rc|=batch_put_u32(b,k,h->nonce);
#undef PH
    return rc?-1:0;
}

static int stage_best_chain(QrxDB*db,QrxDBBatch*b,const char*n,const QrxBtcSpvHeaderInfo*newh,char*err,size_t err_sz){
    char k[256],oldhash[65];QrxBtcSpvHeaderInfo oldh;int have_old=0;nkey(k,sizeof(k),n,"best_hash");if(db_get(db,k,oldhash,sizeof(oldhash))==0&&load_header_hash(db,n,oldhash,&oldh)==0)have_old=1;
    BIGNUM*nw=NULL,*ow=NULL;if(hex_to_bn(newh->chainwork_hex,&nw)){seterr(err,err_sz,"new chainwork invalid");return -1;}if(have_old&&hex_to_bn(oldh.chainwork_hex,&ow)){BN_free(nw);seterr(err,err_sz,"best chainwork invalid");return -1;}if(have_old&&BN_cmp(nw,ow)<=0){BN_free(nw);BN_free(ow);return 0;}BN_free(nw);BN_free(ow);
    char **path=NULL;size_t pn=0,pc=0;QrxBtcSpvHeaderInfo a=*newh,bh;if(have_old)bh=oldh;else memset(&bh,0,sizeof(bh));
    while(!have_old || a.height>bh.height){if(pn==pc){size_t nc=pc?pc*2:16;char**nn=realloc(path,nc*sizeof(*nn));if(!nn)goto oom;path=nn;pc=nc;}path[pn++]=strdup(a.hash);if(a.height==0)break;if(load_header_hash(db,n,a.prev_hash,&a)){seterr(err,err_sz,"best-chain staging failed: new-branch ancestor missing");goto fail;}}
    if(have_old){while(bh.height>a.height){if(bh.height==0)break;if(load_header_hash(db,n,bh.prev_hash,&bh)){seterr(err,err_sz,"best-chain staging failed: old-branch ancestor missing");goto fail;}}while(strcmp(a.hash,bh.hash)){if(pn==pc){size_t nc=pc?pc*2:16;char**nn=realloc(path,nc*sizeof(*nn));if(!nn)goto oom;path=nn;pc=nc;}path[pn++]=strdup(a.hash);if(a.height==0||bh.height==0)goto bad;if(load_header_hash(db,n,a.prev_hash,&a)||load_header_hash(db,n,bh.prev_hash,&bh)){seterr(err,err_sz,"best-chain staging failed: fork ancestor missing");goto fail;}}}
    for(size_t i=pn;i>0;i--){QrxBtcSpvHeaderInfo x;if(!strcmp(path[i-1],newh->hash))x=*newh;else if(load_header_hash(db,n,path[i-1],&x)){seterr(err,err_sz,"best-chain staging failed: path header missing");goto fail;}akey(k,sizeof(k),n,x.height);if(qrxdb_batch_put(b,k,x.hash)){seterr(err,err_sz,"best-chain staging failed: active-height put failed");goto fail;}}
    if(have_old&&oldh.height>newh->height){for(uint64_t h=newh->height+1;h<=oldh.height;h++){akey(k,sizeof(k),n,h);if(qrxdb_batch_put(b,k,"-")){seterr(err,err_sz,"best-chain staging failed: active-height clear failed");goto fail;}}}
    nkey(k,sizeof(k),n,"best_hash");if(qrxdb_batch_put(b,k,newh->hash)){seterr(err,err_sz,"best-chain staging failed: best_hash put failed");goto fail;}nkey(k,sizeof(k),n,"best_height");if(batch_put_u64(b,k,newh->height)){seterr(err,err_sz,"best-chain staging failed: best_height put failed");goto fail;}nkey(k,sizeof(k),n,"best_chainwork");if(qrxdb_batch_put(b,k,newh->chainwork_hex)){seterr(err,err_sz,"best-chain staging failed: best_chainwork put failed");goto fail;}
    for(size_t i=0;i<pn;i++)free(path[i]);free(path);return 1;
oom:seterr(err,err_sz,"out of memory");goto fail;
bad:seterr(err,err_sz,"best-chain staging failed");
fail:for(size_t i=0;i<pn;i++)free(path[i]);free(path);return -1;
}

int qrx_btc_spv_init(QrxDB *db,const char *network,char*err,size_t err_sz){
    const char*n=normnet(network);if(!db||!n){seterr(err,err_sz,"invalid Bitcoin network");return -1;}char k[128],v[65];nkey(k,sizeof(k),n,"best_hash");if(db_get(db,k,v,sizeof(v))==0)return 0;
    const char*gh=qrx_btc_spv_genesis_header_hex(n);unsigned char raw[80];size_t rn=0;if(hex_decode(gh,raw,sizeof(raw),&rn)||rn!=80){seterr(err,err_sz,"embedded genesis header invalid");return -1;}QrxBtcSpvHeaderInfo h;memset(&h,0,sizeof(h));header_hash_from_raw(raw,h.hash);memset(h.prev_hash,'0',64);h.prev_hash[64]=0;field_hash_display(raw+36,h.merkle_root);snprintf(h.header_hex,sizeof(h.header_hex),"%s",gh);h.height=0;h.version=rd32le(raw);h.timestamp=rd32le(raw+68);h.bits=rd32le(raw+72);h.nonce=rd32le(raw+76);if(pow_valid(raw,h.bits,n,err,err_sz))return -1;BIGNUM*w=NULL;if(work_from_bits(h.bits,&w)||bn_to_hex(w,h.chainwork_hex,sizeof(h.chainwork_hex))){BN_free(w);seterr(err,err_sz,"genesis chainwork failed");return -1;}BN_free(w);
    QrxDBBatch b;if(qrxdb_batch_begin(db,&b)){seterr(err,err_sz,"SPV init batch failed");return -1;}if(stage_header_fields(&b,n,&h)){qrxdb_batch_abort(&b);seterr(err,err_sz,"SPV genesis staging failed");return -1;}akey(k,sizeof(k),n,0);qrxdb_batch_put(&b,k,h.hash);nkey(k,sizeof(k),n,"best_hash");qrxdb_batch_put(&b,k,h.hash);nkey(k,sizeof(k),n,"best_height");batch_put_u64(&b,k,0);nkey(k,sizeof(k),n,"best_chainwork");qrxdb_batch_put(&b,k,h.chainwork_hex);nkey(k,sizeof(k),n,"initialized");qrxdb_batch_put(&b,k,"1");if(qrxdb_batch_commit(&b)){qrxdb_batch_abort(&b);seterr(err,err_sz,"SPV genesis commit failed");return -1;}return 0;
}

int qrx_btc_spv_stage_header(QrxDB *db,QrxDBBatch *batch,const char *network,const char *header_hex,QrxBtcSpvHeaderInfo*out,int*became_best,char*err,size_t err_sz){
    const char*n=normnet(network);if(!db||!batch||!n||!header_hex){seterr(err,err_sz,"invalid SPV header arguments");return -1;}if(strlen(header_hex)!=160){seterr(err,err_sz,"Bitcoin header must be exactly 80 bytes / 160 hex chars");return -1;}unsigned char raw[80];size_t rn=0;if(hex_decode(header_hex,raw,sizeof(raw),&rn)||rn!=80){seterr(err,err_sz,"invalid Bitcoin header hex");return -1;}QrxBtcSpvHeaderInfo h;memset(&h,0,sizeof(h));header_hash_from_raw(raw,h.hash);field_hash_display(raw+4,h.prev_hash);field_hash_display(raw+36,h.merkle_root);snprintf(h.header_hex,sizeof(h.header_hex),"%s",header_hex);h.version=rd32le(raw);h.timestamp=rd32le(raw+68);h.bits=rd32le(raw+72);h.nonce=rd32le(raw+76);
    if(header_exists(db,n,h.hash)){if(load_header_hash(db,n,h.hash,&h)){seterr(err,err_sz,"existing header corrupt");return -1;}if(out)*out=h;if(became_best)*became_best=0;return 0;}
    char bestkey[128],bestbuf[65];nkey(bestkey,sizeof(bestkey),n,"best_hash");int initialized=(db_get(db,bestkey,bestbuf,sizeof(bestbuf))==0);
    if(!initialized){
        const char *gen=qrx_btc_spv_genesis_header_hex(n);if(!gen||strcasecmp(gen,header_hex)){seterr(err,err_sz,"SPV chain not initialized: first on-chain Bitcoin header must be the network genesis header");return -1;}
        h.height=0;if(pow_valid(raw,h.bits,n,err,err_sz))return -1;BIGNUM*w=NULL;if(work_from_bits(h.bits,&w)||bn_to_hex(w,h.chainwork_hex,sizeof(h.chainwork_hex))){BN_free(w);seterr(err,err_sz,"genesis chainwork failed");return -1;}BN_free(w);
        if(stage_header_fields(batch,n,&h)){seterr(err,err_sz,"Bitcoin genesis state staging failed");return -1;}char k[256];akey(k,sizeof(k),n,0);if(qrxdb_batch_put(batch,k,h.hash))return -1;nkey(k,sizeof(k),n,"best_hash");if(qrxdb_batch_put(batch,k,h.hash))return -1;nkey(k,sizeof(k),n,"best_height");if(batch_put_u64(batch,k,0))return -1;nkey(k,sizeof(k),n,"best_chainwork");if(qrxdb_batch_put(batch,k,h.chainwork_hex))return -1;nkey(k,sizeof(k),n,"initialized");if(qrxdb_batch_put(batch,k,"1"))return -1;if(out)*out=h;if(became_best)*became_best=1;return 0;
    }
    QrxBtcSpvHeaderInfo prev;if(load_header_hash(db,n,h.prev_hash,&prev)){seterr(err,err_sz,"previous Bitcoin header not found");return -1;}h.height=prev.height+1;uint32_t mtp=0;if(median_time_past(db,n,prev.hash,&mtp)==0&&h.timestamp<=mtp){seterr(err,err_sz,"Bitcoin header timestamp is not greater than median-time-past");return -1;}
    /* Do not use time(NULL) in QRX consensus validation. Bitcoin Core's
       future-time admission rule is based on node-local adjusted time and is
       therefore unsuitable as a deterministic rule inside QRX consensus.
       Consensus here enforces MTP, difficulty and PoW; transport/policy code
       may additionally delay obviously future headers without changing state. */
    uint32_t expbits=0;if(expected_bits(db,n,&prev,h.height,h.timestamp,&expbits,err,err_sz))return -1;if(h.bits!=expbits){seterr(err,err_sz,"Bitcoin header difficulty bits mismatch");return -1;}if(pow_valid(raw,h.bits,n,err,err_sz))return -1;
    BIGNUM*pw=NULL,*cw=NULL,*pp=NULL;if(work_from_bits(h.bits,&pw)||hex_to_bn(prev.chainwork_hex,&pp)){BN_free(pw);BN_free(pp);seterr(err,err_sz,"Bitcoin chainwork computation failed");return -1;}cw=BN_dup(pp);if(!cw||!BN_add(cw,cw,pw)||bn_to_hex(cw,h.chainwork_hex,sizeof(h.chainwork_hex))){BN_free(pw);BN_free(pp);BN_free(cw);seterr(err,err_sz,"Bitcoin chainwork overflow/encode failed");return -1;}BN_free(pw);BN_free(pp);BN_free(cw);
    if(stage_header_fields(batch,n,&h)){seterr(err,err_sz,"Bitcoin header state staging failed");return -1;}int best=stage_best_chain(db,batch,n,&h,err,err_sz);if(best<0)return -1;if(became_best)*became_best=best>0;if(out)*out=h;return 0;
}

int qrx_btc_spv_confirmations(QrxDB *db,const char *network,const char *block_hash,uint64_t block_height,uint64_t*confirmations,int*active,char*err,size_t err_sz){
    const char*n=normnet(network);if(!n||!block_hash){seterr(err,err_sz,"invalid confirmation arguments");return -1;}QrxBtcSpvHeaderInfo best; if(qrx_btc_spv_get_best(db,n,&best,err,err_sz))return -1;char k[256],h[65];akey(k,sizeof(k),n,block_height);int act=db_get(db,k,h,sizeof(h))==0&&!strcmp(h,block_hash);if(active)*active=act;if(confirmations)*confirmations=(act&&best.height>=block_height)?best.height-block_height+1:0;return 0;
}

int qrx_btc_spv_verify_merkle(QrxDB *db,const char *network,const char *txid,const char *block_hash,uint64_t tx_index,const char *branch_csv,QrxBtcSpvProofResult*out,char*err,size_t err_sz){
    const char*n=normnet(network);if(!n||!txid||strlen(txid)!=64||!block_hash||strlen(block_hash)!=64){seterr(err,err_sz,"invalid Merkle proof arguments");return -1;}QrxBtcSpvHeaderInfo hdr;if(qrx_btc_spv_get_header(db,n,block_hash,&hdr,err,err_sz))return -1;unsigned char cur[32];if(display_hex_to_internal(txid,cur)){seterr(err,err_sz,"invalid txid hex");return -1;}uint64_t idx=tx_index;char *copy=strdup(branch_csv&&*branch_csv?branch_csv:"-");if(!copy){seterr(err,err_sz,"out of memory");return -1;}if(strcmp(copy,"-")&&*copy){char *save=NULL,*tok=strtok_r(copy,",",&save);while(tok){while(*tok&&isspace((unsigned char)*tok))tok++;char *end=tok+strlen(tok);while(end>tok&&isspace((unsigned char)end[-1]))*--end=0;unsigned char sib[32],buf[64],d[32];if(display_hex_to_internal(tok,sib)){free(copy);seterr(err,err_sz,"invalid Merkle branch hash");return -1;}if(idx&1){memcpy(buf,sib,32);memcpy(buf+32,cur,32);}else{memcpy(buf,cur,32);memcpy(buf+32,sib,32);}sha256d(buf,64,d);memcpy(cur,d,32);idx>>=1;tok=strtok_r(NULL,",",&save);}}
    free(copy);char root[65];field_hash_display(cur,root);if(strcasecmp(root,hdr.merkle_root)){seterr(err,err_sz,"Merkle proof does not match Bitcoin header root");return -1;}uint64_t conf=0;int act=0;if(qrx_btc_spv_confirmations(db,n,block_hash,hdr.height,&conf,&act,err,err_sz))return -1;if(!act){seterr(err,err_sz,"Merkle proof block is not on active best-work Bitcoin chain");return -1;}if(out){memset(out,0,sizeof(*out));snprintf(out->txid,sizeof(out->txid),"%s",txid);snprintf(out->block_hash,sizeof(out->block_hash),"%s",block_hash);out->block_height=hdr.height;out->confirmations=conf;out->merkle_index=tx_index;out->merkle_valid=1;out->active_chain=1;}return 0;
}

static int read_varint(const unsigned char *b,size_t n,size_t *off,uint64_t *v){if(*off>=n)return -1;unsigned char c=b[(*off)++];if(c<0xfd){*v=c;return 0;}size_t need=c==0xfd?2:c==0xfe?4:8;if(*off+need>n)return -1;uint64_t x=0;for(size_t i=0;i<need;i++)x|=(uint64_t)b[*off+i]<<(8*i);*off+=need;if((c==0xfd&&x<0xfd)||(c==0xfe&&x<=0xffffULL)||(c==0xff&&x<=0xffffffffULL))return -1;*v=x;return 0;}

int qrx_btc_tx_find_output(const char *rawtx_hex,int64_t expected_sats,const char *expected_scriptpubkey_hex,QrxBtcTxOutputMatch*out,char*err,size_t err_sz){
    if(!rawtx_hex||!expected_scriptpubkey_hex||expected_sats<0){seterr(err,err_sz,"invalid Bitcoin transaction arguments");return -1;}size_t hl=strlen(rawtx_hex);if((hl&1)||hl/2>BTC_TX_MAX_BYTES||hl<20){seterr(err,err_sz,"invalid Bitcoin transaction size");return -1;}size_t n=hl/2;unsigned char *b=malloc(n),*spk=malloc(strlen(expected_scriptpubkey_hex)/2+1);size_t bn=0,sn=0;if(!b||!spk||hex_decode(rawtx_hex,b,n,&bn)||bn!=n||hex_decode(expected_scriptpubkey_hex,spk,strlen(expected_scriptpubkey_hex)/2+1,&sn)){free(b);free(spk);seterr(err,err_sz,"invalid Bitcoin transaction/script hex");return -1;}size_t off=0;if(n<8){free(b);free(spk);seterr(err,err_sz,"truncated Bitcoin transaction");return -1;}off=4;int segwit=0;if(off+2<=n&&b[off]==0x00&&b[off+1]!=0x00){segwit=1;off+=2;}size_t vin_count_off=off;uint64_t vin=0;if(read_varint(b,n,&off,&vin)||vin>100000){goto parsefail;}for(uint64_t i=0;i<vin;i++){if(off+36>n)goto parsefail;off+=36;uint64_t sl=0;if(read_varint(b,n,&off,&sl)||sl>n-off)goto parsefail;off+=(size_t)sl;if(off+4>n)goto parsefail;off+=4;}uint64_t voutc=0;if(read_varint(b,n,&off,&voutc)||voutc>100000)goto parsefail;int found=-1;for(uint64_t i=0;i<voutc;i++){if(off+8>n)goto parsefail;uint64_t val=rd64le(b+off);off+=8;uint64_t pl=0;if(read_varint(b,n,&off,&pl)||pl>n-off)goto parsefail;if(val<=(uint64_t)INT64_MAX&&(int64_t)val==expected_sats&&pl==sn&&!memcmp(b+off,spk,sn)&&found<0)found=(int)i;off+=(size_t)pl;}size_t outputs_end=off;if(segwit){for(uint64_t i=0;i<vin;i++){uint64_t items=0;if(read_varint(b,n,&off,&items)||items>100000)goto parsefail;for(uint64_t j=0;j<items;j++){uint64_t wl=0;if(read_varint(b,n,&off,&wl)||wl>n-off)goto parsefail;off+=(size_t)wl;}}}if(off+4!=n)goto parsefail;size_t lockoff=off;unsigned char d[32];if(segwit){size_t stripped_n=4+(outputs_end-vin_count_off)+4;unsigned char *s=malloc(stripped_n);if(!s)goto parsefail;memcpy(s,b,4);memcpy(s+4,b+vin_count_off,outputs_end-vin_count_off);memcpy(s+4+(outputs_end-vin_count_off),b+lockoff,4);sha256d(s,stripped_n,d);free(s);}else sha256d(b,n,d);char txid[65];hash_display_hex(d,txid);if(found<0){free(b);free(spk);seterr(err,err_sz,"expected Bitcoin HTLC output not found");return -1;}if(out){memset(out,0,sizeof(*out));snprintf(out->txid,sizeof(out->txid),"%s",txid);out->vout=found;out->sats=expected_sats;}free(b);free(spk);return 0;
parsefail:free(b);free(spk);seterr(err,err_sz,"malformed Bitcoin transaction serialization");return -1;
}

int qrx_btc_spv_stage_proof(QrxDBBatch *b,const char *network,const QrxBtcSpvProofResult*p,int vout,int64_t sats,const char*spk,char*err,size_t err_sz){const char*n=normnet(network);if(!b||!n||!p){seterr(err,err_sz,"invalid proof staging arguments");return -1;}char k[320];int rc=0;pkey(k,sizeof(k),n,p->txid,"block_hash");rc|=qrxdb_batch_put(b,k,p->block_hash);pkey(k,sizeof(k),n,p->txid,"block_height");rc|=batch_put_u64(b,k,p->block_height);pkey(k,sizeof(k),n,p->txid,"merkle_index");rc|=batch_put_u64(b,k,p->merkle_index);pkey(k,sizeof(k),n,p->txid,"vout");rc|=batch_put_u64(b,k,(uint64_t)vout);pkey(k,sizeof(k),n,p->txid,"sats");rc|=batch_put_u64(b,k,(uint64_t)sats);pkey(k,sizeof(k),n,p->txid,"scriptpubkey");rc|=qrxdb_batch_put(b,k,spk?spk:"");pkey(k,sizeof(k),n,p->txid,"verified");rc|=qrxdb_batch_put(b,k,"1");if(rc){seterr(err,err_sz,"proof state staging failed");return -1;}return 0;}

int qrx_btc_spv_get_stored_proof(QrxDB *db,const char *network,const char *txid,QrxBtcSpvProofResult*out,int*vout,int64_t*sats,char*spk,size_t script_sz,char*err,size_t err_sz){const char*n=normnet(network);if(!n||!txid||strlen(txid)!=64){seterr(err,err_sz,"invalid stored proof arguments");return -1;}char k[320],v[256];QrxBtcSpvProofResult p;memset(&p,0,sizeof(p));snprintf(p.txid,sizeof(p.txid),"%s",txid);pkey(k,sizeof(k),n,txid,"verified");if(db_get(db,k,v,sizeof(v))||strcmp(v,"1")){seterr(err,err_sz,"stored Bitcoin proof not found");return -1;}pkey(k,sizeof(k),n,txid,"block_hash");if(db_get(db,k,p.block_hash,sizeof(p.block_hash)))return -1;pkey(k,sizeof(k),n,txid,"block_height");if(db_get_u64(db,k,&p.block_height))return -1;pkey(k,sizeof(k),n,txid,"merkle_index");if(db_get_u64(db,k,&p.merkle_index))return -1;uint64_t vv=0,ss=0;pkey(k,sizeof(k),n,txid,"vout");if(db_get_u64(db,k,&vv))return -1;pkey(k,sizeof(k),n,txid,"sats");if(db_get_u64(db,k,&ss))return -1;if(vout)*vout=(int)vv;if(sats)*sats=(int64_t)ss;if(spk&&script_sz){pkey(k,sizeof(k),n,txid,"scriptpubkey");if(db_get(db,k,spk,script_sz))spk[0]=0;}uint64_t conf=0;int act=0;if(qrx_btc_spv_confirmations(db,n,p.block_hash,p.block_height,&conf,&act,err,err_sz))return -1;p.confirmations=conf;p.active_chain=act;p.merkle_valid=1;if(out)*out=p;return 0;}
