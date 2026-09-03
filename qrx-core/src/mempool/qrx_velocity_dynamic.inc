/* QRX 0.0.7 VELOCITY Phase 4E - speculative dynamic MVCC with deterministic conflict resolution.
   Included by qrx_velocity_mvcc.c after the fixed-key Phase 4C adapters. Phase 4D dynamic expansion semantics are retained. */

#define QRX_MVCC_TRADE_PRICE_SCALE 100000000LL

typedef struct {
    char **ids;
    size_t count;
    size_t cap;
    uint64_t scanned_keys;
} MvccOrderIdList;

typedef struct {
    char id[160];
    char owner[512];
    char side[16];
    long long price;
    long long remaining;
    long long created_height;
} MvccMatchOrder;

static int mvcc_ascii_tolower(int c){return (c>='A'&&c<='Z')?c+('a'-'A'):c;}
static int mvcc_ieq(const char *a,const char *b){if(!a||!b)return 0;while(*a&&*b){if(mvcc_ascii_tolower((unsigned char)*a)!=mvcc_ascii_tolower((unsigned char)*b))return 0;a++;b++;}return *a==0&&*b==0;}

static int mvcc_token_list_contains_ci(const char *list,const char *needle){
    if(!list||!needle||!*needle)return 0;const char *cur=list;size_t nl=strlen(needle);
    while(*cur){while(*cur==','||*cur=='|'||*cur==' '||*cur=='\t')cur++;const char *end=cur;while(*end&&*end!=','&&*end!='|')end++;const char *trim=end;while(trim>cur&&(trim[-1]==' '||trim[-1]=='\t'))trim--;size_t n=(size_t)(trim-cur);
        if(n==1&&cur[0]=='*')return 1;if(n==nl){size_t i=0;for(;i<n;i++)if(mvcc_ascii_tolower((unsigned char)cur[i])!=mvcc_ascii_tolower((unsigned char)needle[i]))break;if(i==n)return 1;}cur=*end?end+1:end;
    }return 0;
}

static int mvcc_sha3_512_hex(const char *text,char out[129]){
    unsigned char d[64];unsigned int n=0;if(!text||!out)return -1;
    if(EVP_Digest(text,strlen(text),d,&n,EVP_sha3_512(),NULL)!=1||n!=64)return -1;
    for(size_t i=0;i<64;i++)sprintf(out+i*2,"%02x",d[i]);out[128]=0;return 0;
}

static void mvcc_snapshot_root_hex(const QrxDBReadTxn *snap,char out[129]){for(size_t i=0;i<64;i++)sprintf(out+i*2,"%02x",snap->merkle_root[i]);out[128]=0;}

static int mvcc_order_key(char *out,size_t out_sz,const char *id,const char *f){if(!out||!id||!f)return -1;snprintf(out,out_sz,"velocity:order:%s:%s",id,f);return 0;}
static int mvcc_trade_key(char *out,size_t out_sz,const char *id,const char *f){if(!out||!id||!f)return -1;snprintf(out,out_sz,"velocity:trade:%s:%s",id,f);return 0;}
static int mvcc_asset_key(char *out,size_t out_sz,const char *asset,const char *owner){if(!out||!asset||!owner)return -1;if(!strcmp(asset,"QUB"))snprintf(out,out_sz,"acct:balance:%s",owner);else snprintf(out,out_sz,"velocity:asset:balance:%s:%s",asset,owner);return 0;}

static int mvcc_local_get(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *key,char *out,size_t out_sz,int *found){
    const char *v=ws?kv_find(ws->writes,ws->write_count,key):NULL;if(v){snprintf(out,out_sz,"%s",v);if(found)*found=1;return 0;}return snapshot_get(db,snap,overlay,overlay_count,ws,key,out,out_sz,found);
}
static int mvcc_local_get_ll(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *key,long long def,long long *out){
    char b[128];int found=0;if(mvcc_local_get(db,snap,overlay,overlay_count,ws,key,b,sizeof(b),&found))return -1;if(!found){*out=def;return 0;}errno=0;char *e=NULL;long long v=strtoll(b,&e,10);if(errno||!e||*e)return -1;*out=v;return 0;
}
static int mvcc_order_get(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *id,const char *f,char *out,size_t out_sz,int *found){char k[1024];mvcc_order_key(k,sizeof(k),id,f);return mvcc_local_get(db,snap,overlay,overlay_count,ws,k,out,out_sz,found);}
static int mvcc_order_get_ll(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *id,const char *f,long long def,long long *out){char k[1024];mvcc_order_key(k,sizeof(k),id,f);return mvcc_local_get_ll(db,snap,overlay,overlay_count,ws,k,def,out);}
static int mvcc_order_put(QrxVelocityMvccWriteSet *ws,const char *id,const char *f,const char *v){char k[1024];mvcc_order_key(k,sizeof(k),id,f);return ws_put(ws,k,v?v:"");}
static int mvcc_order_put_ll(QrxVelocityMvccWriteSet *ws,const char *id,const char *f,long long v){char k[1024];mvcc_order_key(k,sizeof(k),id,f);return ws_put_ll(ws,k,v);}
static int mvcc_trade_put(QrxVelocityMvccWriteSet *ws,const char *id,const char *f,const char *v){char k[1024];mvcc_trade_key(k,sizeof(k),id,f);return ws_put(ws,k,v?v:"");}
static int mvcc_trade_put_ll(QrxVelocityMvccWriteSet *ws,const char *id,const char *f,long long v){char k[1024];mvcc_trade_key(k,sizeof(k),id,f);return ws_put_ll(ws,k,v);}

static void mvcc_asset_normalize(const char *in,char out[32]){size_t n=0;if(!in){out[0]=0;return;}for(;*in&&n<31;in++){unsigned char c=(unsigned char)*in;if(c>='a'&&c<='z')c=(unsigned char)(c-('a'-'A'));out[n++]=(char)c;}out[n]=0;}
static int mvcc_parse_market(const char *market,char base[32],char quote[32]){if(!market)return -1;const char *s=strchr(market,'/');if(!s||strchr(s+1,'/'))return -1;size_t bl=(size_t)(s-market),ql=strlen(s+1);if(!bl||!ql||bl>=32||ql>=32)return -1;char rb[32],rq[32];memcpy(rb,market,bl);rb[bl]=0;memcpy(rq,s+1,ql+1);mvcc_asset_normalize(rb,base);mvcc_asset_normalize(rq,quote);return !*base||!*quote||!strcmp(base,quote)?-1:0;}

/* Exact floor(a*b/d), copied from the consensus matching path to keep order
   reserve and price-improvement arithmetic bit-for-bit deterministic. */
static int mvcc_mul_div_floor_nonneg(long long a,long long b,long long d,long long *out){
    if(a<0||b<0||d<=0||!out)return -1;unsigned long long q=0,rem=0,ub=(unsigned long long)b,ud=(unsigned long long)d,base_q=ub/ud,base_r=ub%ud,ua=(unsigned long long)a;
    for(int i=62;i>=0;--i){if(q>(unsigned long long)LLONG_MAX/2ULL)return -1;q*=2ULL;rem*=2ULL;if(rem>=ud){rem-=ud;if(q>=(unsigned long long)LLONG_MAX)return -1;q++;}if((ua>>i)&1ULL){if(q>(unsigned long long)LLONG_MAX-base_q)return -1;q+=base_q;rem+=base_r;if(rem>=ud){rem-=ud;if(q>=(unsigned long long)LLONG_MAX)return -1;q++;}}}*out=(long long)q;return 0;
}
static int mvcc_quote_for_quantity(long long qty,long long price,long long *out){if(qty<=0||price<=0||mvcc_mul_div_floor_nonneg(qty,price,QRX_MVCC_TRADE_PRICE_SCALE,out)||*out<=0)return -1;return 0;}

static int mvcc_asset_get_ll(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *asset,const char *owner,long long *out){char a[32],k[1024];mvcc_asset_normalize(asset,a);mvcc_asset_key(k,sizeof(k),a,owner);return mvcc_local_get_ll(db,snap,overlay,overlay_count,ws,k,0,out);}
static int mvcc_asset_put_ll(QrxVelocityMvccWriteSet *ws,const char *asset,const char *owner,long long value){char a[32],k[1024];if(value<0)return -1;mvcc_asset_normalize(asset,a);mvcc_asset_key(k,sizeof(k),a,owner);return ws_put_ll(ws,k,value);}
static int mvcc_asset_adjust(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *asset,const char *owner,long long delta){long long cur=0,next=0;if(mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,asset,owner,&cur)||add_ll(cur,delta,&next)||next<0)return -1;return mvcc_asset_put_ll(ws,asset,owner,next);}

static int mvcc_order_id_add(MvccOrderIdList *l,const char *id,size_t n){if(!l||!id||!n||n>=160)return 0;for(size_t i=0;i<l->count;i++)if(strlen(l->ids[i])==n&&!memcmp(l->ids[i],id,n))return 0;if(l->count==l->cap){size_t nc=l->cap?l->cap*2:32;char **nn=(char**)realloc(l->ids,nc*sizeof(*nn));if(!nn)return -1;l->ids=nn;l->cap=nc;}char *s=(char*)malloc(n+1);if(!s)return -1;memcpy(s,id,n);s[n]=0;l->ids[l->count++]=s;return 0;}
static int mvcc_collect_order_key_cb(const char *key,const char *value,uint32_t value_len,void *ctx){(void)value;(void)value_len;MvccOrderIdList *l=(MvccOrderIdList*)ctx;const char *pfx="velocity:order:";size_t pl=strlen(pfx);if(strncmp(key,pfx,pl))return 0;l->scanned_keys++;const char *p=key+pl,*c=strchr(p,':');if(!c)return 0;if(strcmp(c+1,"owner"))return 0;return mvcc_order_id_add(l,p,(size_t)(c-p));}
static void mvcc_order_ids_free(MvccOrderIdList *l){if(!l)return;for(size_t i=0;i<l->count;i++)free(l->ids[i]);free(l->ids);memset(l,0,sizeof(*l));}
static int mvcc_collect_order_ids(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,MvccOrderIdList *l){
    memset(l,0,sizeof(*l));if(ws_track_prefix(ws,"velocity:order:"))return -1;if(qrxdb_scan_prefix_at(db,snap,"velocity:order:",mvcc_collect_order_key_cb,l))return -1;
    const char *pfx="velocity:order:";size_t pl=strlen(pfx);for(size_t i=0;i<overlay_count;i++){const char *key=overlay[i].key;if(strncmp(key,pfx,pl))continue;l->scanned_keys++;const char *p=key+pl,*c=strchr(p,':');if(c&&!strcmp(c+1,"owner")&&mvcc_order_id_add(l,p,(size_t)(c-p)))return -1;}
    return 0;
}

static long long mvcc_chain_block_time(QrxDB *db){
    long long v=10;if(!db||!*db->base_path)return v;char path[1200];snprintf(path,sizeof(path),"%s",db->base_path);size_t n=strlen(path);while(n&&path[n-1]!='/'&&path[n-1]!='\\')n--;if(!n)return v;path[n-1]=0;size_t used=strlen(path);snprintf(path+used,sizeof(path)-used,"/chain.conf");FILE *f=fopen(path,"rb");if(!f)return v;char line[1024];while(fgets(line,sizeof(line),f)){const char *k="block_time_seconds=";if(!strncmp(line,k,strlen(k))){char *e=NULL;errno=0;long long x=strtoll(line+strlen(k),&e,10);if(!errno&&e&&x>0)v=x;break;}}fclose(f);return v;
}
static long long mvcc_agent_usage_bucket(QrxDB *db,long long height){long long bt=mvcc_chain_block_time(db);long long blocks=(86400LL+bt-1)/bt;if(blocks<=0)blocks=1;if(height<0)height=0;return height/blocks;}

/* Returns 0 authorized, 1 means canonical QRXDB state is insufficient and the
   caller must retain the serial fallback, -1 means the snapshot state rejects
   the transaction. */
static int mvcc_required_ll(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *key,long long *out){
    char b[128];int found=0;if(mvcc_local_get(db,snap,overlay,overlay_count,ws,key,b,sizeof(b),&found)||!found)return 1;errno=0;char *e=NULL;long long v=strtoll(b,&e,10);if(errno||!e||*e)return -1;*out=v;return 0;
}

static int mvcc_authorize_native_agent(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *agent,const char *owner,const char *market,long long qty,long long height,int consume_usage,char usage_key[1024]){
    char k[1200],v[4096];int found=0;snprintf(k,sizeof(k),"velocity:agent:%s:owner",agent);if(mvcc_local_get(db,snap,overlay,overlay_count,ws,k,v,sizeof(v),&found)||!found)return 1;if(strcmp(v,owner))return -1;
    snprintf(k,sizeof(k),"velocity:agent:%s:status",agent);if(mvcc_local_get(db,snap,overlay,overlay_count,ws,k,v,sizeof(v),&found)||!found)return 1;if(strcmp(v,"active"))return -1;
    snprintf(k,sizeof(k),"velocity:agent:%s:permissions",agent);if(mvcc_local_get(db,snap,overlay,overlay_count,ws,k,v,sizeof(v),&found)||!found)return 1;if(!(mvcc_token_list_contains_ci(v,"TRADE_NATIVE")||mvcc_token_list_contains_ci(v,"TRADE")))return -1;
    snprintf(k,sizeof(k),"velocity:agent:%s:market_allowlist",agent);if(mvcc_local_get(db,snap,overlay,overlay_count,ws,k,v,sizeof(v),&found)||!found)return 1;if(!mvcc_token_list_contains_ci(v,market))return -1;
    long long expires=0;snprintf(k,sizeof(k),"velocity:agent:%s:expires_height",agent);int rr=mvcc_required_ll(db,snap,overlay,overlay_count,ws,k,&expires);if(rr)return rr>0?1:-1;if(expires<=0||height>=expires)return -1;
    if(!consume_usage)return 0;
    long long max_trade=0,daily=0;snprintf(k,sizeof(k),"velocity:agent:%s:max_trade_atoms",agent);rr=mvcc_required_ll(db,snap,overlay,overlay_count,ws,k,&max_trade);if(rr)return rr>0?1:-1;snprintf(k,sizeof(k),"velocity:agent:%s:daily_limit_atoms",agent);rr=mvcc_required_ll(db,snap,overlay,overlay_count,ws,k,&daily);if(rr)return rr>0?1:-1;
    if(qty<=0||max_trade<=0||qty>max_trade||daily<=0)return -1;
    long long bucket=mvcc_agent_usage_bucket(db,height),used=0,next=0;snprintf(usage_key,1024,"velocity:agent_usage:%s:%lld",agent,bucket);if(mvcc_local_get_ll(db,snap,overlay,overlay_count,ws,usage_key,0,&used)||add_ll(used,qty,&next)||next>daily)return -1;return ws_put_ll(ws,usage_key,next)?-1:0;
}

static int mvcc_stage_order_payload(QrxVelocityMvccWriteSet *ws,const char *id,const char *agent,const char *owner,const char *payload,const char *body_hash,const char *replaces,long long height){
    char hb[64];snprintf(hb,sizeof(hb),"%lld",height);if(mvcc_order_put(ws,id,"owner",owner)||mvcc_order_put(ws,id,"agent",agent)||mvcc_order_put(ws,id,"kind","native")||mvcc_order_put(ws,id,"status","open")||mvcc_order_put(ws,id,"created_height",hb)||mvcc_order_put(ws,id,"updated_height",hb)||mvcc_order_put(ws,id,"last_tx",body_hash))return -1;if(replaces&&*replaces&&mvcc_order_put(ws,id,"replaces",replaces))return -1;
    const char *fields[]={"market","side","order_type","quantity_atoms","limit_price_atoms","order_expires_height","venue","client_order_id",NULL};char v[4096];for(int i=0;fields[i];i++)if(payload_field_mvcc(payload,fields[i],v,sizeof(v))==0&&mvcc_order_put(ws,id,fields[i],v))return -1;long long qty=0;if(payload_field_mvcc(payload,"quantity_atoms",v,sizeof(v))||parse_ll(v,&qty,1)||mvcc_order_put_ll(ws,id,"filled_atoms",0)||mvcc_order_put_ll(ws,id,"remaining_atoms",qty))return -1;return 0;
}

static int mvcc_release_locked(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *id){
    char asset[64]="",owner[512]="";int fa=0,fo=0;long long atoms=0;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"locked_asset",asset,sizeof(asset),&fa)||mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"owner",owner,sizeof(owner),&fo)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,id,"locked_atoms",0,&atoms))return -1;if(fa&&fo&&atoms>0&&mvcc_asset_adjust(db,snap,overlay,overlay_count,ws,asset,owner,atoms))return -1;return mvcc_order_put_ll(ws,id,"locked_atoms",0);
}

static int mvcc_candidate_better(const MvccMatchOrder *a,const MvccMatchOrder *b,int want_sells){if(a->price!=b->price)return want_sells?a->price<b->price:a->price>b->price;if(a->created_height!=b->created_height)return a->created_height<b->created_height;return strcmp(a->id,b->id)<0;}

static int mvcc_collect_candidates(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *taker_id,const char *market,const char *taker_side,long long height,MvccMatchOrder **out,size_t *count){
    *out=NULL;*count=0;char taker_owner[512];int tf=0;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,taker_id,"owner",taker_owner,sizeof(taker_owner),&tf)||!tf)return -1;MvccOrderIdList ids;if(mvcc_collect_order_ids(db,snap,overlay,overlay_count,ws,&ids))return -1;ws->discovered_keys+=ids.scanned_keys;
    for(size_t i=0;i<ids.count;i++){
        const char *id=ids.ids[i];if(!strcmp(id,taker_id))continue;char kind[64]="",status[64]="",omarket[512]="",side[32]="",sv[32]="",owner[512]="";int fk=0,fs=0,fm=0,fside=0,fsv=0,fo=0;long long exp=0;
        if(mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"kind",kind,sizeof(kind),&fk)||mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"status",status,sizeof(status),&fs)||!fk||!fs)continue;if(strcmp(kind,"native"))continue;
        int live=!strcmp(status,"open")||!strcmp(status,"partially_filled");if(!live)continue;if(mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,id,"order_expires_height",0,&exp))goto fail;
        if(exp>0&&exp<=height){if(mvcc_release_locked(db,snap,overlay,overlay_count,ws,id)||mvcc_order_put(ws,id,"status","expired")||mvcc_order_put_ll(ws,id,"updated_height",height))goto fail;ws->expired_orders++;continue;}
        if(mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"market",omarket,sizeof(omarket),&fm)||mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"side",side,sizeof(side),&fside)||mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"settlement_version",sv,sizeof(sv),&fsv)||mvcc_order_get(db,snap,overlay,overlay_count,ws,id,"owner",owner,sizeof(owner),&fo))goto fail;
        if(!fm||!fside||!fsv||!fo||!mvcc_ieq(omarket,market)||mvcc_ieq(side,taker_side)||strcmp(sv,"1")||!strcmp(owner,taker_owner))continue;
        MvccMatchOrder *nn=(MvccMatchOrder*)realloc(*out,(*count+1)*sizeof(**out));if(!nn)goto fail;*out=nn;MvccMatchOrder *m=&nn[*count];memset(m,0,sizeof(*m));snprintf(m->id,sizeof(m->id),"%s",id);snprintf(m->owner,sizeof(m->owner),"%s",owner);snprintf(m->side,sizeof(m->side),"%s",side);if(mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,id,"limit_price_atoms",0,&m->price)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,id,"remaining_atoms",0,&m->remaining)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,id,"created_height",0,&m->created_height))goto fail;(*count)++;
    }
    mvcc_order_ids_free(&ids);{int want_sells=mvcc_ieq(taker_side,"BUY");for(size_t i=1;i<*count;i++){MvccMatchOrder key=(*out)[i];size_t j=i;while(j>0&&mvcc_candidate_better(&key,&(*out)[j-1],want_sells)){(*out)[j]=(*out)[j-1];j--;}(*out)[j]=key;}}return 0;
fail:mvcc_order_ids_free(&ids);free(*out);*out=NULL;*count=0;return -1;
}

static int mvcc_settle_match(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *market,const char *maker_id,const char *taker_id,long long qty,long long price,long long height){
    char maker_side[32];int f=0;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,maker_id,"side",maker_side,sizeof(maker_side),&f)||!f)return -1;const char *buyer_id=mvcc_ieq(maker_side,"BUY")?maker_id:taker_id,*seller_id=mvcc_ieq(maker_side,"SELL")?maker_id:taker_id;char buyer[512],seller[512];int fb=0,fs=0;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,buyer_id,"owner",buyer,sizeof(buyer),&fb)||mvcc_order_get(db,snap,overlay,overlay_count,ws,seller_id,"owner",seller,sizeof(seller),&fs)||!fb||!fs||!strcmp(buyer,seller))return -1;
    char base[32],quote_asset[32];if(mvcc_parse_market(market,base,quote_asset))return -1;long long quote_amt=0;if(mvcc_quote_for_quantity(qty,price,&quote_amt))return -1;
    long long buyer_lock=0,seller_lock=0,buyer_rem_before=0,seller_rem_before=0,buyer_filled_before=0,seller_filled_before=0,buyer_limit=0;
    if(mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,buyer_id,"locked_atoms",0,&buyer_lock)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,seller_id,"locked_atoms",0,&seller_lock)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,buyer_id,"remaining_atoms",0,&buyer_rem_before)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,seller_id,"remaining_atoms",0,&seller_rem_before)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,buyer_id,"filled_atoms",0,&buyer_filled_before)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,seller_id,"filled_atoms",0,&seller_filled_before)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,buyer_id,"limit_price_atoms",0,&buyer_limit))return -1;
    if(qty<=0||qty>buyer_rem_before||qty>seller_rem_before||buyer_lock<quote_amt||seller_lock<qty)return -1;long long buyer_rem=buyer_rem_before-qty,seller_rem=seller_rem_before-qty,buyer_filled=0,seller_filled=0;if(add_ll(buyer_filled_before,qty,&buyer_filled)||add_ll(seller_filled_before,qty,&seller_filled))return -1;
    long long buyer_new_lock=buyer_lock-quote_amt,seller_new_lock=seller_lock-qty,buyer_needed=0;if(buyer_rem>0&&mvcc_quote_for_quantity(buyer_rem,buyer_limit,&buyer_needed))return -1;if(buyer_new_lock<buyer_needed||seller_new_lock<seller_rem)return -1;long long buyer_refund=buyer_new_lock-buyer_needed,seller_refund=seller_new_lock-seller_rem;buyer_new_lock=buyer_needed;seller_new_lock=seller_rem;
    long long buyer_base=0,seller_quote=0,buyer_quote=0,seller_base=0;if(mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,base,buyer,&buyer_base)||mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,quote_asset,seller,&seller_quote)||mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,quote_asset,buyer,&buyer_quote)||mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,base,seller,&seller_base))return -1;long long buyer_base_new=0,seller_quote_new=0,buyer_quote_new=0,seller_base_new=0;if(add_ll(buyer_base,qty,&buyer_base_new)||add_ll(seller_quote,quote_amt,&seller_quote_new)||add_ll(buyer_quote,buyer_refund,&buyer_quote_new)||add_ll(seller_base,seller_refund,&seller_base_new))return -1;
    long long seq=0;if(mvcc_local_get_ll(db,snap,overlay,overlay_count,ws,"velocity:trade_sequence:global",0,&seq)||seq==LLONG_MAX)return -1;seq++;char material[2048],trade_id[129];snprintf(material,sizeof(material),"QRX-TRADE-V1|%s|%s|%s|%lld|%lld|%lld",market,maker_id,taker_id,seq,qty,price);if(mvcc_sha3_512_hex(material,trade_id))return -1;
    if(mvcc_asset_put_ll(ws,base,buyer,buyer_base_new)||mvcc_asset_put_ll(ws,quote_asset,seller,seller_quote_new)||mvcc_asset_put_ll(ws,quote_asset,buyer,buyer_quote_new)||mvcc_asset_put_ll(ws,base,seller,seller_base_new))return -1;
#define OLL(ID,F,V) do{if(mvcc_order_put_ll(ws,(ID),(F),(V)))return -1;}while(0)
#define OS(ID,F,V) do{if(mvcc_order_put(ws,(ID),(F),(V)))return -1;}while(0)
    OLL(buyer_id,"filled_atoms",buyer_filled);OLL(buyer_id,"remaining_atoms",buyer_rem);OLL(buyer_id,"locked_atoms",buyer_new_lock);OLL(buyer_id,"updated_height",height);OS(buyer_id,"status",buyer_rem==0?"filled":"partially_filled");OS(buyer_id,"last_trade_id",trade_id);
    OLL(seller_id,"filled_atoms",seller_filled);OLL(seller_id,"remaining_atoms",seller_rem);OLL(seller_id,"locked_atoms",seller_new_lock);OLL(seller_id,"updated_height",height);OS(seller_id,"status",seller_rem==0?"filled":"partially_filled");OS(seller_id,"last_trade_id",trade_id);
#undef OLL
#undef OS
    if(mvcc_trade_put(ws,trade_id,"market",market)||mvcc_trade_put(ws,trade_id,"maker_order_id",maker_id)||mvcc_trade_put(ws,trade_id,"taker_order_id",taker_id)||mvcc_trade_put(ws,trade_id,"buyer",buyer)||mvcc_trade_put(ws,trade_id,"seller",seller)||mvcc_trade_put_ll(ws,trade_id,"quantity_atoms",qty)||mvcc_trade_put_ll(ws,trade_id,"price_atoms",price)||mvcc_trade_put_ll(ws,trade_id,"quote_atoms",quote_amt)||mvcc_trade_put_ll(ws,trade_id,"height",height)||mvcc_trade_put_ll(ws,trade_id,"sequence",seq)||ws_put_ll(ws,"velocity:trade_sequence:global",seq))return -1;
    char pre_root[129],sk[1024],sv[1400];mvcc_snapshot_root_hex(snap,pre_root);snprintf(sk,sizeof(sk),"velocity:settlement:%s",trade_id);snprintf(sv,sizeof(sv),"version=1\nmarket=%s\nmaker=%s\ntaker=%s\nquantity_atoms=%lld\nprice_atoms=%lld\nquote_atoms=%lld\nheight=%lld\nsequence=%lld\npre_state_root=%s\nmvcc_snapshot_generation=%llu\n",market,maker_id,taker_id,qty,price,quote_amt,height,seq,pre_root,(unsigned long long)snap->generation);if(ws_put(ws,sk,sv))return -1;ws->dynamic_trades++;return 0;
}

static int mvcc_match_taker(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,QrxVelocityMvccWriteSet *ws,const char *taker_id,long long height){
    char market[512],side[32];int fm=0,fs=0;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,taker_id,"market",market,sizeof(market),&fm)||mvcc_order_get(db,snap,overlay,overlay_count,ws,taker_id,"side",side,sizeof(side),&fs)||!fm||!fs)return -1;long long taker_price=0;if(mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,taker_id,"limit_price_atoms",0,&taker_price)||taker_price<=0)return -1;MvccMatchOrder *arr=NULL;size_t count=0;if(mvcc_collect_candidates(db,snap,overlay,overlay_count,ws,taker_id,market,side,height,&arr,&count))return -1;
    for(size_t i=0;i<count;i++){long long trem=0,mrem=0;if(mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,taker_id,"remaining_atoms",0,&trem)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,arr[i].id,"remaining_atoms",0,&mrem)){free(arr);return -1;}if(trem<=0)break;if(mrem<=0)continue;int crosses=mvcc_ieq(side,"BUY")?(arr[i].price<=taker_price):(arr[i].price>=taker_price);if(!crosses)break;long long qty=trem<mrem?trem:mrem;if(mvcc_settle_match(db,snap,overlay,overlay_count,ws,market,arr[i].id,taker_id,qty,arr[i].price,height)){free(arr);return -1;}}
    free(arr);char pk[1024];snprintf(pk,sizeof(pk),"velocity:match_pending:%s",taker_id);return ws_put(ws,pk,"0");
}

static int mvcc_prepare_native_dynamic(QrxDB *db,const QrxDBReadTxn *snap,const QrxVelocityMvccKV *overlay,size_t overlay_count,const char *tx,const char *txid,size_t plan_index,uint32_t wave,long long height,QrxVelocityMvccWriteSet *ws){
    char type[64],agent[512],owner[512],payload[16384],body_hash[160];int rc=prepare_common_nontransfer(db,snap,overlay,overlay_count,tx,txid,plan_index,wave,height,ws,type,agent,owner,payload,body_hash);if(rc)return rc;ws->dynamic=1;
    if(strcmp(type,"ORDER_CREATE")&&strcmp(type,"ORDER_CANCEL")&&strcmp(type,"ORDER_REPLACE")){ws->status=QRX_MVCC_UNSUPPORTED;return QRX_MVCC_UNSUPPORTED;}
    if(!strcmp(type,"ORDER_CANCEL")){
        char target[160];if(payload_field_mvcc(payload,"order_id",target,sizeof(target)))goto bad;char kind[64],status[64],old_agent[512],old_owner[512],market[512],usage_key[1024];int fk=0,fs=0,fa=0,fo=0,fm=0;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"kind",kind,sizeof(kind),&fk)||!fk){ws->status=QRX_MVCC_BARRIER;return QRX_MVCC_BARRIER;}if(strcmp(kind,"native")){ws->status=QRX_MVCC_BARRIER;return QRX_MVCC_BARRIER;}if(mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"status",status,sizeof(status),&fs)||mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"agent",old_agent,sizeof(old_agent),&fa)||mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"owner",old_owner,sizeof(old_owner),&fo)||mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"market",market,sizeof(market),&fm)||!fs||!fa||!fo||!fm||strcmp(old_agent,agent)||strcmp(old_owner,owner)||!( !strcmp(status,"open")||!strcmp(status,"partially_filled") ))goto bad;snprintf(ws->dynamic_scope,sizeof(ws->dynamic_scope),"%s",market);int auth=mvcc_authorize_native_agent(db,snap,overlay,overlay_count,ws,agent,owner,market,0,height,0,usage_key);if(auth==1){ws->status=QRX_MVCC_BARRIER;return QRX_MVCC_BARRIER;}if(auth)goto bad;if(mvcc_release_locked(db,snap,overlay,overlay_count,ws,target)||mvcc_order_put(ws,target,"status","canceled")||mvcc_order_put_ll(ws,target,"updated_height",height)||mvcc_order_put(ws,target,"last_tx",body_hash))goto bad;ws->status=QRX_MVCC_OK;return QRX_MVCC_OK;
    }
    char market[512],side[32],otype[32],qtys[64],prices[64],exps[64],usage_key[1024];long long qty=0,price=0,exp=0;if(payload_field_mvcc(payload,"market",market,sizeof(market))||payload_field_mvcc(payload,"side",side,sizeof(side))||payload_field_mvcc(payload,"order_type",otype,sizeof(otype))||payload_field_mvcc(payload,"quantity_atoms",qtys,sizeof(qtys))||payload_field_mvcc(payload,"limit_price_atoms",prices,sizeof(prices))||payload_field_mvcc(payload,"order_expires_height",exps,sizeof(exps))||parse_ll(qtys,&qty,1)||parse_ll(prices,&price,1)||parse_ll(exps,&exp,1)||exp<=height||(!mvcc_ieq(side,"BUY")&&!mvcc_ieq(side,"SELL")))goto bad;char base[32],quote[32];if(mvcc_parse_market(market,base,quote))goto bad;snprintf(ws->dynamic_scope,sizeof(ws->dynamic_scope),"%s",market);
    int auth=mvcc_authorize_native_agent(db,snap,overlay,overlay_count,ws,agent,owner,market,qty,height,1,usage_key);if(auth==1){ws->status=QRX_MVCC_BARRIER;return QRX_MVCC_BARRIER;}if(auth)goto bad;
    if(!strcmp(type,"ORDER_REPLACE")){
        char target[160],kind[64],status[64],old_agent[512],old_owner[512],old_asset[64]="";int fk=0,fs=0,fa=0,fo=0,fasset=0;long long old_atoms=0;if(payload_field_mvcc(payload,"order_id",target,sizeof(target)))goto bad;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"kind",kind,sizeof(kind),&fk)||mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"status",status,sizeof(status),&fs)||mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"agent",old_agent,sizeof(old_agent),&fa)||mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"owner",old_owner,sizeof(old_owner),&fo)||!fk||!fs||!fa||!fo||strcmp(kind,"native")||strcmp(old_agent,agent)||strcmp(old_owner,owner)||!( !strcmp(status,"open")||!strcmp(status,"partially_filled") ))goto bad;if(mvcc_order_get(db,snap,overlay,overlay_count,ws,target,"locked_asset",old_asset,sizeof(old_asset),&fasset)||mvcc_order_get_ll(db,snap,overlay,overlay_count,ws,target,"locked_atoms",0,&old_atoms))goto bad;
        char new_asset[32];long long new_atoms=0;if(mvcc_ieq(side,"SELL")){snprintf(new_asset,sizeof(new_asset),"%s",base);new_atoms=qty;}else{snprintf(new_asset,sizeof(new_asset),"%s",quote);if(mvcc_quote_for_quantity(qty,price,&new_atoms))goto bad;}
        if(fasset&&mvcc_ieq(old_asset,new_asset)){long long cur=0,avail=0;if(mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,new_asset,owner,&cur)||add_ll(cur,old_atoms,&avail)||avail<new_atoms||mvcc_asset_put_ll(ws,new_asset,owner,avail-new_atoms))goto bad;}else{if(fasset&&old_atoms>0&&mvcc_asset_adjust(db,snap,overlay,overlay_count,ws,old_asset,owner,old_atoms))goto bad;long long cur=0;if(mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,new_asset,owner,&cur)||cur<new_atoms||mvcc_asset_put_ll(ws,new_asset,owner,cur-new_atoms))goto bad;}
        if(mvcc_order_put(ws,target,"status","replaced")||mvcc_order_put_ll(ws,target,"updated_height",height)||mvcc_order_put_ll(ws,target,"locked_atoms",0)||mvcc_order_put(ws,target,"replacement_order_id",body_hash)||mvcc_order_put(ws,target,"last_tx",body_hash)||mvcc_stage_order_payload(ws,body_hash,agent,owner,payload,body_hash,target,height)||mvcc_order_put(ws,body_hash,"locked_asset",new_asset)||mvcc_order_put_ll(ws,body_hash,"locked_atoms",new_atoms)||mvcc_order_put(ws,body_hash,"settlement_version","1")||mvcc_match_taker(db,snap,overlay,overlay_count,ws,body_hash,height))goto bad;ws->status=QRX_MVCC_OK;return QRX_MVCC_OK;
    }
    /* ORDER_CREATE */
    {char k[1024],tmp[32];int found=0;mvcc_order_key(k,sizeof(k),body_hash,"owner");if(mvcc_local_get(db,snap,overlay,overlay_count,ws,k,tmp,sizeof(tmp),&found)||found)goto bad;char asset[32];long long lock=0;if(mvcc_ieq(side,"SELL")){snprintf(asset,sizeof(asset),"%s",base);lock=qty;}else{snprintf(asset,sizeof(asset),"%s",quote);if(mvcc_quote_for_quantity(qty,price,&lock))goto bad;}long long cur=0;if(mvcc_asset_get_ll(db,snap,overlay,overlay_count,ws,asset,owner,&cur)||cur<lock||mvcc_asset_put_ll(ws,asset,owner,cur-lock)||mvcc_stage_order_payload(ws,body_hash,agent,owner,payload,body_hash,NULL,height)||mvcc_order_put(ws,body_hash,"locked_asset",asset)||mvcc_order_put_ll(ws,body_hash,"locked_atoms",lock)||mvcc_order_put(ws,body_hash,"settlement_version","1")||mvcc_match_taker(db,snap,overlay,overlay_count,ws,body_hash,height))goto bad;}
    ws->status=QRX_MVCC_OK;return QRX_MVCC_OK;
bad:ws->status=QRX_MVCC_ERROR;return QRX_MVCC_ERROR;
}
