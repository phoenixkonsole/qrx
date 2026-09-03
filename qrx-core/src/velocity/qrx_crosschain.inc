/* QRX Core 0.0.7 VELOCITY Phase 3D
 * Deterministic BTC/QUB cross-chain trading settlement.
 *
 * Security model:
 * - BTC remains on Bitcoin. No qBTC, bridge or custodian is introduced.
 * - QRX consensus locks only the QUB leg.
 * - The Bitcoin leg is a P2WSH HTLC template using the SAME SHA-256 hashlock.
 * - The BTC buyer reveals the preimage only when redeeming the BTC HTLC.
 * - The BTC seller then uses that public preimage to redeem the QUB leg.
 * - If the preimage is never revealed, the QUB buyer can refund after qrx_refund_height.
 *
 * Phase 3D.1 adds Bitcoin SPV verification committed through QRX consensus.
 * Funding proofs must be validated against the on-chain best-work header state before QUB redemption.
 */

#define QRX_CROSSCHAIN_MARKET "BTC/QUB"
#define QRX_CROSSCHAIN_SETTLEMENT_VERSION "2"
#define QRX_CROSSCHAIN_BTC_BLOCK_SECONDS_POLICY 600LL
#define QRX_CROSSCHAIN_SAFETY_SECONDS 3600LL
#define QRX_CROSSCHAIN_MAX_CSV_BLOCKS 65535LL

static int crosschain_hex_exact(const char *s,size_t min_len,size_t max_len){
    if(!s) return 0; size_t n=strlen(s); if(n<min_len||n>max_len) return 0;
    for(size_t i=0;i<n;i++) if(!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static int crosschain_compressed_pubkey_valid(const char *hex){
    if(!hex || strlen(hex)!=66 || (strncmp(hex,"02",2) && strncmp(hex,"03",2)) || !crosschain_hex_exact(hex,66,66)) return 0;
    unsigned char raw[33]; size_t n=0; if(hex_to_bytes(hex,raw,sizeof(raw),&n)!=0 || n!=33) return 0;
    EC_GROUP *group=EC_GROUP_new_by_curve_name(NID_secp256k1); if(!group) return 0;
    EC_POINT *point=EC_POINT_new(group); if(!point){EC_GROUP_free(group);return 0;}
    int ok=EC_POINT_oct2point(group,point,raw,n,NULL)==1 && EC_POINT_is_on_curve(group,point,NULL)==1 && !EC_POINT_is_at_infinity(group,point);
    EC_POINT_free(point);EC_GROUP_free(group);return ok;
}

static int crosschain_hashlock_valid(const char *hex){ return hex && strlen(hex)==64 && crosschain_hex_exact(hex,64,64); }
static int crosschain_secret_hex_valid(const char *hex){ size_t n=hex?strlen(hex):0; return n>=2 && n<=128 && !(n&1) && crosschain_hex_exact(hex,n,n); }

static int crosschain_secret_hash_hex(const char *secret_hex,char out[65]){
    unsigned char raw[64]; size_t n=0;
    if(!crosschain_secret_hex_valid(secret_hex) || hex_to_bytes(secret_hex,raw,sizeof(raw),&n)!=0) return -1;
    sha256_hex(raw,n,out); OPENSSL_cleanse(raw,sizeof(raw)); return 0;
}

/* Minimal Script number encoding for positive CSV values. */
static int crosschain_scriptnum(long long v,unsigned char out[8],size_t *out_len){
    if(v<=0 || v>QRX_CROSSCHAIN_MAX_CSV_BLOCKS || !out_len) return -1;
    size_t n=0; unsigned long long x=(unsigned long long)v;
    while(x){ out[n++]=(unsigned char)(x&0xffU); x>>=8; }
    if(out[n-1]&0x80U) out[n++]=0;
    *out_len=n; return 0;
}

/* P2WSH witness script:
 * OP_IF OP_SHA256 <32-byte hash> OP_EQUALVERIFY <buyer BTC pubkey> OP_CHECKSIG
 * OP_ELSE <CSV> OP_CHECKSEQUENCEVERIFY OP_DROP <seller BTC pubkey> OP_CHECKSIG OP_ENDIF
 */
static int crosschain_btc_htlc_script(const char *hashlock,const char *buyer_pub,const char *seller_pub,long long csv,
    unsigned char *script,size_t script_cap,size_t *script_len,char script_hex[513],char script_hash_hex[65],char scriptpubkey_hex[69]){
    unsigned char h[32],bp[33],sp[33],sn[8]; size_t hn=0,bpn=0,spn=0,snn=0,off=0;
    if(!crosschain_hashlock_valid(hashlock)||!crosschain_compressed_pubkey_valid(buyer_pub)||!crosschain_compressed_pubkey_valid(seller_pub)) return -1;
    if(hex_to_bytes(hashlock,h,sizeof(h),&hn)||hn!=32||hex_to_bytes(buyer_pub,bp,sizeof(bp),&bpn)||bpn!=33||hex_to_bytes(seller_pub,sp,sizeof(sp),&spn)||spn!=33||crosschain_scriptnum(csv,sn,&snn)) return -1;
#define APPEND_BYTE(b) do{ if(off+1>script_cap)return -1; script[off++]=(unsigned char)(b); }while(0)
#define APPEND_BUF(p,n) do{ if(off+(n)>script_cap)return -1; memcpy(script+off,(p),(n)); off+=(n); }while(0)
    APPEND_BYTE(0x63);                 /* OP_IF */
    APPEND_BYTE(0xa8);                 /* OP_SHA256 */
    APPEND_BYTE(0x20); APPEND_BUF(h,32);
    APPEND_BYTE(0x88);                 /* OP_EQUALVERIFY */
    APPEND_BYTE(0x21); APPEND_BUF(bp,33);
    APPEND_BYTE(0xac);                 /* OP_CHECKSIG */
    APPEND_BYTE(0x67);                 /* OP_ELSE */
    if(csv>=1 && csv<=16) APPEND_BYTE((unsigned char)(0x50+csv)); /* minimal OP_1..OP_16 */
    else { APPEND_BYTE((unsigned char)snn); APPEND_BUF(sn,snn); }
    APPEND_BYTE(0xb2);                 /* OP_CHECKSEQUENCEVERIFY */
    APPEND_BYTE(0x75);                 /* OP_DROP */
    APPEND_BYTE(0x21); APPEND_BUF(sp,33);
    APPEND_BYTE(0xac);                 /* OP_CHECKSIG */
    APPEND_BYTE(0x68);                 /* OP_ENDIF */
#undef APPEND_BYTE
#undef APPEND_BUF
    if(script_len)*script_len=off;
    for(size_t i=0;i<off;i++) sprintf(script_hex+i*2,"%02x",script[i]); script_hex[off*2]=0;
    unsigned char sh[32]; SHA256(script,off,sh); for(int i=0;i<32;i++)sprintf(script_hash_hex+i*2,"%02x",sh[i]);script_hash_hex[64]=0;
    snprintf(scriptpubkey_hex,69,"0020%s",script_hash_hex);
    return 0;
}

/* BIP173 Bech32 for witness v0 P2WSH addresses. */
static uint32_t crosschain_bech32_polymod(const unsigned char *v,size_t n){
    uint32_t c=1; static const uint32_t g[5]={0x3b6a57b2U,0x26508e6dU,0x1ea119faU,0x3d4233ddU,0x2a1462b3U};
    for(size_t i=0;i<n;i++){uint32_t top=c>>25;c=(c&0x1ffffffU)<<5^v[i];for(int j=0;j<5;j++)if((top>>j)&1U)c^=g[j];}return c;
}
static int crosschain_convertbits(unsigned char *out,size_t *outlen,int outbits,const unsigned char *in,size_t inlen,int inbits,int pad){
    uint32_t acc=0;int bits=0;size_t n=0;uint32_t maxv=((uint32_t)1<<outbits)-1,maxacc=((uint32_t)1<<(inbits+outbits-1))-1;
    for(size_t i=0;i<inlen;i++){if((in[i]>>inbits)!=0)return -1;acc=((acc<<inbits)|in[i])&maxacc;bits+=inbits;while(bits>=outbits){bits-=outbits;out[n++]=(unsigned char)((acc>>bits)&maxv);}}
    if(pad){if(bits)out[n++]=(unsigned char)((acc<<(outbits-bits))&maxv);}else if(bits>=inbits||((acc<<(outbits-bits))&maxv))return -1;*outlen=n;return 0;
}
static int crosschain_p2wsh_address(const char *network,const unsigned char program[32],char *out,size_t out_sz){
    const char *hrp=(!strcasecmp(network,"mainnet")||!strcasecmp(network,"bitcoin"))?"bc":(!strcasecmp(network,"regtest")?"bcrt":"tb");
    unsigned char data[80],vals[160];size_t dlen=0,vn=0;data[dlen++]=0;size_t conv=0;if(crosschain_convertbits(data+dlen,&conv,5,program,32,8,1))return -1;dlen+=conv;
    for(const char *p=hrp;*p;p++) vals[vn++]=(unsigned char)(*p>>5); vals[vn++]=0; for(const char *p=hrp;*p;p++) vals[vn++]=(unsigned char)(*p&31); for(size_t i=0;i<dlen;i++) vals[vn++]=data[i]; for(int i=0;i<6;i++)vals[vn++]=0;
    uint32_t pm=crosschain_bech32_polymod(vals,vn)^1U;static const char *cs="qpzry9x8gf2tvdw0s3jn54khce6mua7l";size_t need=strlen(hrp)+1+dlen+6+1;if(need>out_sz)return -1;size_t o=0;for(const char*p=hrp;*p;p++)out[o++]=*p;out[o++]='1';for(size_t i=0;i<dlen;i++)out[o++]=cs[data[i]];for(int i=0;i<6;i++)out[o++]=cs[(pm>>(5*(5-i)))&31U];out[o]=0;return 0;
}

static void crosschain_key(char *out,size_t out_sz,const char *sid,const char *field){snprintf(out,out_sz,"velocity:crosschain:%s:%s",sid,field);}
static char *crosschain_get_field(const char *chain_dir,const char *sid,const char *field){char k[1024];crosschain_key(k,sizeof(k),sid,field);return velocity_qrxdb_get_alloc(chain_dir,k);}
static long long crosschain_get_ll(const char *chain_dir,const char *sid,const char *field,long long fallback){char *v=crosschain_get_field(chain_dir,sid,field);if(!v||!*v){free(v);return fallback;}char*e=NULL;errno=0;long long n=strtoll(v,&e,10);int ok=!errno&&e&&!*e;free(v);return ok?n:fallback;}
static int crosschain_batch_put(QrxDBBatch *b,const char *sid,const char *field,const char *v){char k[1024];crosschain_key(k,sizeof(k),sid,field);return qrxdb_batch_put(b,k,v?v:"");}
static int crosschain_batch_put_ll(QrxDBBatch *b,const char *sid,const char *field,long long v){char k[1024];crosschain_key(k,sizeof(k),sid,field);return velocity_batch_put_ll(b,k,v);}

static int crosschain_order_live(const char *s){return s && !strcmp(s,"open");}
static int crosschain_market_valid(const char *m){return m && !strcasecmp(m,QRX_CROSSCHAIN_MARKET);}

static long long crosschain_required_qrx_window_blocks(const char *chain_dir,long long btc_csv){
    long long h=current_height_from_chain(chain_dir); long long bt=qrx_chain_get_ll_at_height_or_default(chain_dir,h,"block_time_seconds",10LL);if(bt<=0)bt=10;
    long long seconds=btc_csv*QRX_CROSSCHAIN_BTC_BLOCK_SECONDS_POLICY+QRX_CROSSCHAIN_SAFETY_SECONDS;return (seconds+bt-1)/bt;
}

static void validate_crosschain_order_fields(const char *chain_dir,const char *agent,const char *owner,const char *payload,const char *tx_expiry,const char *ed,const char *ml){
    validate_payload_clean(payload,"cross-chain trading payload");char *market=payload_get_field(payload,"market"),*side=payload_get_field(payload,"side"),*otype=payload_get_field(payload,"order_type"),*qs=payload_get_field(payload,"quantity_atoms"),*ps=payload_get_field(payload,"limit_price_atoms"),*oes=payload_get_field(payload,"order_expires_height"),*hash=payload_get_field(payload,"hashlock_hex"),*redeem=payload_get_field(payload,"btc_redeem_pubkey_hex"),*refund=payload_get_field(payload,"btc_refund_pubkey_hex"),*csvs=payload_get_field(payload,"btc_refund_csv_blocks"),*qrhs=payload_get_field(payload,"qrx_refund_height");
    if(!market||!side||!otype||!qs||!ps||!oes||!hash||!redeem||!refund||!csvs||!qrhs)die("cross-chain payload missing fields");
    if(!crosschain_market_valid(market))die("Phase 3D supports canonical BTC/QUB cross-chain market only");if(strcasecmp(otype,"LIMIT"))die("cross-chain Phase 3D supports LIMIT orders only");if(strcasecmp(side,"BUY")&&strcasecmp(side,"SELL"))die("cross-chain side must be BUY or SELL");
    long long qty=parse_positive_ll_strict(qs,"quantity_atoms"),price=parse_positive_ll_strict(ps,"limit_price_atoms"),oe=parse_positive_ll_strict(oes,"order_expires_height"),te=parse_positive_ll_strict(tx_expiry,"expiry_height"),h=current_height_from_chain(chain_dir);(void)price;
    if(oe<=h||oe>te)die("invalid cross-chain order expiry");agent_assert_trade_authorized(chain_dir,agent,owner,QRX_CROSSCHAIN_MARKET,"TRADE_CROSSCHAIN",qty,1,ed,ml);
    if(!strcasecmp(side,"BUY")){
        if(!crosschain_hashlock_valid(hash))die("BTC/QUB BUY requires a 32-byte SHA-256 hashlock");if(!crosschain_compressed_pubkey_valid(redeem))die("BTC/QUB BUY requires compressed btc_redeem_pubkey_hex");if(strcmp(refund,"-")||strcmp(csvs,"0"))die("BUY must use btc_refund_pubkey_hex=- and btc_refund_csv_blocks=0");long long qrh=parse_positive_ll_strict(qrhs,"qrx_refund_height");if(qrh<=oe)die("qrx_refund_height must be later than order expiry");long long lock=quote_for_quantity(qty,price);if(qrx_balance_get_authoritative(chain_dir,owner)<lock)die("insufficient owner QUB for cross-chain reserve");
    }else{
        if(strcmp(hash,"-")||strcmp(redeem,"-")||strcmp(qrhs,"0"))die("SELL must use hashlock=- btc_redeem_pubkey_hex=- qrx_refund_height=0");if(!crosschain_compressed_pubkey_valid(refund))die("BTC/QUB SELL requires compressed btc_refund_pubkey_hex");long long csv=parse_positive_ll_strict(csvs,"btc_refund_csv_blocks");if(csv>QRX_CROSSCHAIN_MAX_CSV_BLOCKS)die("btc_refund_csv_blocks too large");
    }
    free(market);free(side);free(otype);free(qs);free(ps);free(oes);free(hash);free(redeem);free(refund);free(csvs);free(qrhs);
}

static void validate_crosschain_action(const char *chain_dir,const char *from,const char *tx_type,const char *payload){
    validate_payload_clean(payload,"cross-chain action payload");char *sid=payload_get_field(payload,"session_id");if(!sid||!*sid)die("cross-chain action missing session_id");char *status=crosschain_get_field(chain_dir,sid,"status"),*buyer=crosschain_get_field(chain_dir,sid,"qrx_buyer"),*seller=crosschain_get_field(chain_dir,sid,"qrx_seller");long long rh=crosschain_get_ll(chain_dir,sid,"qrx_refund_height",0),h=current_height_from_chain(chain_dir);if(!status||!buyer||!seller)die("cross-chain session not found");
    if(!strcmp(tx_type,"CROSSCHAIN_REDEEM")){char *secret=payload_get_field(payload,"secret_hex"),*hash=crosschain_get_field(chain_dir,sid,"hashlock_hex");if(strcmp(status,"awaiting_btc_funding")&&strcmp(status,"btc_confirming")&&strcmp(status,"btc_funded"))die("cross-chain session is not redeemable");if(strcmp(from,seller))die("only QUB recipient can redeem cross-chain QUB leg");if(h>=rh)die("cross-chain QUB leg expired; refund path only");uint64_t btc_conf=0;int btc_active=0,btc_safe=0;if(btc_spv_funding_security_current(chain_dir,sid,&btc_conf,&btc_active,&btc_safe)!=0||!btc_safe)die("Bitcoin SPV funding is not currently safe/confirmed on active best-work chain");char calc[65];if(!secret||crosschain_secret_hash_hex(secret,calc)||!hash||strcasecmp(calc,hash))die("cross-chain secret does not match hashlock");free(secret);free(hash);
    }else if(!strcmp(tx_type,"CROSSCHAIN_REFUND")){if(strcmp(status,"awaiting_btc_funding")&&strcmp(status,"btc_confirming")&&strcmp(status,"btc_funded"))die("cross-chain session is not refundable");if(strcmp(from,buyer))die("only QUB buyer can refund cross-chain QUB leg");if(h<rh)die("qrx_refund_height not reached");}
    else die("unsupported cross-chain action");free(status);free(buyer);free(seller);free(sid);
}

static int crosschain_stage_order(QrxDBBatch *b,const char *chain_dir,const char *agent,const char *owner,const char *payload,const char *body_hash,long long h){
    if(atomic_stage_order_payload(b,body_hash,agent,owner,"crosschain","open",payload,body_hash,NULL,h))return -1;char *qs=payload_get_field(payload,"quantity_atoms"),*side=payload_get_field(payload,"side"),*ps=payload_get_field(payload,"limit_price_atoms");long long qty=parse_positive_ll_strict(qs,"quantity_atoms"),price=parse_positive_ll_strict(ps,"limit_price_atoms");int rc=atomic_stage_agent_usage(b,chain_dir,agent,qty);rc|=velocity_batch_put_order(b,body_hash,"settlement_version",QRX_CROSSCHAIN_SETTLEMENT_VERSION);
    if(!strcasecmp(side,"BUY")){long long lock=quote_for_quantity(qty,price),cur=qrx_balance_get_authoritative(chain_dir,owner);if(cur<lock)rc=-1;else{rc|=atomic_stage_asset_value(b,"QUB",owner,cur-lock);rc|=velocity_batch_put_order(b,body_hash,"locked_asset","QUB");rc|=velocity_batch_put_order_ll(b,body_hash,"locked_atoms",lock);}}
    else{rc|=velocity_batch_put_order(b,body_hash,"locked_asset","");rc|=velocity_batch_put_order_ll(b,body_hash,"locked_atoms",0);}
    char pk[768];snprintf(pk,sizeof(pk),"velocity:xmatch_pending:%s",body_hash);rc|=qrxdb_batch_put(b,pk,"1");free(qs);free(side);free(ps);return rc?-1:0;
}

static int crosschain_stage_action(QrxDBBatch *b,const char *chain_dir,const char *from,const char *tx_type,const char *payload,const char *body_hash,long long h){
    (void)from; char *sid=payload_get_field(payload,"session_id");if(!sid)return -1;long long locked=crosschain_get_ll(chain_dir,sid,"qrx_locked_atoms",0);if(locked<=0){free(sid);return -1;}int rc=0;
    if(!strcmp(tx_type,"CROSSCHAIN_REDEEM")){char *secret=payload_get_field(payload,"secret_hex");char sh[65];if(!secret||crosschain_secret_hash_hex(secret,sh)){free(secret);free(sid);return -1;}rc|=crosschain_batch_put(b,sid,"status","redeemed");rc|=crosschain_batch_put(b,sid,"secret_hex",secret);rc|=crosschain_batch_put(b,sid,"secret_hash",sh);rc|=crosschain_batch_put_ll(b,sid,"redeemed_height",h);free(secret);}else if(!strcmp(tx_type,"CROSSCHAIN_REFUND")){rc|=crosschain_batch_put(b,sid,"status","refunded");rc|=crosschain_batch_put_ll(b,sid,"refunded_height",h);}else rc=-1;
    rc|=crosschain_batch_put_ll(b,sid,"qrx_locked_atoms",0);rc|=crosschain_batch_put(b,sid,"last_tx",body_hash);free(sid);return rc?-1:0;
}

static int crosschain_make_session_id(const char *buy,const char *sell,const char *hash,char out[129]){char buf[1024];snprintf(buf,sizeof(buf),"QRX-CROSSCHAIN-BTC-QUB-V1|%s|%s|%s",buy,sell,hash);hash_primary_hex((unsigned char*)buf,strlen(buf),out);return 0;}

typedef struct {char id[160];long long price,qty,created;char side[8];} QrxCrossCandidate;
static int crosschain_candidate_better(const QrxCrossCandidate*a,const QrxCrossCandidate*b,int want_sell){if(a->price!=b->price)return want_sell?a->price<b->price:a->price>b->price;if(a->created!=b->created)return a->created<b->created;return strcmp(a->id,b->id)<0;}

static int crosschain_timelock_compatible(const char *chain_dir,const char *buy_id,const char *sell_id){long long qrh=order_db_get_ll(chain_dir,buy_id,"qrx_refund_height",0),csv=order_db_get_ll(chain_dir,sell_id,"btc_refund_csv_blocks",0),h=current_height_from_chain(chain_dir);if(qrh<=h||csv<=0)return 0;long long need=crosschain_required_qrx_window_blocks(chain_dir,csv);return (qrh-h)>=need;}

static int crosschain_settle_match(const char *chain_dir,const char *maker_id,const char *taker_id,long long price){
    char *ms=order_db_get_field(chain_dir,maker_id,"side"),*ts=order_db_get_field(chain_dir,taker_id,"side");if(!ms||!ts||!strcasecmp(ms,ts)){free(ms);free(ts);return -1;}const char *buy=!strcasecmp(ms,"BUY")?maker_id:taker_id,*sell=!strcasecmp(ms,"SELL")?maker_id:taker_id;long long bqty=order_db_get_ll(chain_dir,buy,"remaining_atoms",0),sqty=order_db_get_ll(chain_dir,sell,"remaining_atoms",0);if(bqty<=0||sqty<=0||bqty!=sqty){free(ms);free(ts);return -1;}if(!crosschain_timelock_compatible(chain_dir,buy,sell)){free(ms);free(ts);return 1;}
    char *hash=order_db_get_field(chain_dir,buy,"hashlock_hex"),*buyer_pub=order_db_get_field(chain_dir,buy,"btc_redeem_pubkey_hex"),*seller_pub=order_db_get_field(chain_dir,sell,"btc_refund_pubkey_hex"),*buyer_owner=order_db_get_field(chain_dir,buy,"owner"),*seller_owner=order_db_get_field(chain_dir,sell,"owner");long long csv=order_db_get_ll(chain_dir,sell,"btc_refund_csv_blocks",0),qrh=order_db_get_ll(chain_dir,buy,"qrx_refund_height",0),locked=order_db_get_ll(chain_dir,buy,"locked_atoms",0),quote=quote_for_quantity(bqty,price);if(!hash||!buyer_pub||!seller_pub||!buyer_owner||!seller_owner||locked<quote){free(hash);free(buyer_pub);free(seller_pub);free(buyer_owner);free(seller_owner);free(ms);free(ts);return -1;}
    unsigned char script[256],shraw[32];size_t slen=0,shn=0;char shex[513],shash[65],spk[69];if(crosschain_btc_htlc_script(hash,buyer_pub,seller_pub,csv,script,sizeof(script),&slen,shex,shash,spk)){free(hash);free(buyer_pub);free(seller_pub);free(buyer_owner);free(seller_owner);free(ms);free(ts);return -1;}hex_to_bytes(shash,shraw,sizeof(shraw),&shn);char bcaddr[128],tbaddr[128],bcrtaddr[128];crosschain_p2wsh_address("mainnet",shraw,bcaddr,sizeof(bcaddr));crosschain_p2wsh_address("testnet",shraw,tbaddr,sizeof(tbaddr));crosschain_p2wsh_address("regtest",shraw,bcrtaddr,sizeof(bcrtaddr));char sid[129];crosschain_make_session_id(buy,sell,hash,sid);long long h=current_height_from_chain(chain_dir),change=locked-quote,buyerbal=qrx_balance_get_authoritative(chain_dir,buyer_owner),newbal=0;checked_add_ll(buyerbal,change,"cross-chain price improvement",&newbal);
    QrxDB db;QrxDBBatch b;if(qrxdb_init(&db,chain_dir)||qrxdb_batch_begin(&db,&b)){free(hash);free(buyer_pub);free(seller_pub);free(buyer_owner);free(seller_owner);free(ms);free(ts);return -1;}int rc=0;rc|=atomic_batch_put_balance(&b,buyer_owner,newbal);
#define XPUT(f,v) do{rc|=crosschain_batch_put(&b,sid,(f),(v));}while(0)
#define XPUTLL(f,v) do{rc|=crosschain_batch_put_ll(&b,sid,(f),(v));}while(0)
    XPUT("market",QRX_CROSSCHAIN_MARKET);XPUT("status","awaiting_btc_funding");XPUT("buy_order_id",buy);XPUT("sell_order_id",sell);XPUT("maker_order_id",maker_id);XPUT("taker_order_id",taker_id);XPUT("qrx_buyer",buyer_owner);XPUT("qrx_seller",seller_owner);XPUTLL("quantity_sats",bqty);XPUTLL("price_atoms",price);XPUTLL("qub_atoms",quote);XPUTLL("qrx_locked_atoms",quote);XPUT("hashlock_hex",hash);XPUTLL("qrx_refund_height",qrh);XPUTLL("btc_refund_csv_blocks",csv);XPUT("btc_redeem_pubkey_hex",buyer_pub);XPUT("btc_refund_pubkey_hex",seller_pub);XPUT("btc_witness_script_hex",shex);XPUT("btc_script_sha256",shash);XPUT("btc_scriptpubkey_hex",spk);XPUT("btc_p2wsh_mainnet",bcaddr);XPUT("btc_p2wsh_testnet",tbaddr);XPUT("btc_p2wsh_regtest",bcrtaddr);XPUTLL("created_height",h);XPUT("bitcoin_spv_verified","false");XPUT("btc_funding_status","waiting");XPUT("safe_to_reveal_secret","false");XPUTLL("btc_required_confirmations",6);XPUT("settlement_model","HTLC_SHA256_P2WSH_CSV_SPV");
#undef XPUT
#undef XPUTLL
    rc|=velocity_batch_put_order(&b,buy,"status","matched");rc|=velocity_batch_put_order_ll(&b,buy,"filled_atoms",bqty);rc|=velocity_batch_put_order_ll(&b,buy,"remaining_atoms",0);rc|=velocity_batch_put_order_ll(&b,buy,"locked_atoms",0);rc|=velocity_batch_put_order(&b,buy,"crosschain_session_id",sid);rc|=velocity_batch_put_order_ll(&b,buy,"updated_height",h);
    rc|=velocity_batch_put_order(&b,sell,"status","matched");rc|=velocity_batch_put_order_ll(&b,sell,"filled_atoms",sqty);rc|=velocity_batch_put_order_ll(&b,sell,"remaining_atoms",0);rc|=velocity_batch_put_order(&b,sell,"crosschain_session_id",sid);rc|=velocity_batch_put_order_ll(&b,sell,"updated_height",h);
    char pk[768];snprintf(pk,sizeof(pk),"velocity:xmatch_pending:%s",buy);rc|=qrxdb_batch_put(&b,pk,"0");snprintf(pk,sizeof(pk),"velocity:xmatch_pending:%s",sell);rc|=qrxdb_batch_put(&b,pk,"0");if(rc||qrxdb_batch_commit(&b)){qrxdb_batch_abort(&b);qrxdb_close(&db);free(hash);free(buyer_pub);free(seller_pub);free(buyer_owner);free(seller_owner);free(ms);free(ts);return -1;}char root[129];qrxdb_merkle_root_hex(&db,root);qrxdb_close(&db);mirror_asset_balance_only(chain_dir,"QUB",buyer_owner,newbal);mirror_order_from_authoritative(chain_dir,buy);mirror_order_from_authoritative(chain_dir,sell);journal_append(chain_dir,"velocity_crosschain_match session=%s buy=%s sell=%s sats=%lld qub=%lld price=%lld state_root=%s",sid,buy,sell,bqty,quote,price,root);free(hash);free(buyer_pub);free(seller_pub);free(buyer_owner);free(seller_owner);free(ms);free(ts);return 0;
}

static int match_crosschain_order(const char *chain_dir,const char *taker_id){
    char *taker_side=order_db_get_field(chain_dir,taker_id,"side"),*towner=order_db_get_field(chain_dir,taker_id,"owner");if(!taker_side||!towner){free(taker_side);free(towner);return -1;}long long tprice=order_db_get_ll(chain_dir,taker_id,"limit_price_atoms",0),tqty=order_db_get_ll(chain_dir,taker_id,"remaining_atoms",0),h=current_height_from_chain(chain_dir);QrxCrossCandidate *a=NULL;size_t n=0;char path[1024];order_registry_path(chain_dir,path,sizeof(path));char *txt=read_file(path,NULL);if(txt){const char*cur=txt;const char suffix[]=".owner=";while(cur&&*cur){const char*e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);const char*suf=NULL;if(len>6&&!strncmp(cur,"order.",6)){for(size_t i=6;i+strlen(suffix)<len;i++)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}}if(suf){size_t il=(size_t)(suf-(cur+6));if(il>0&&il<160){char oid[160];memcpy(oid,cur+6,il);oid[il]=0;if(strcmp(oid,taker_id)){char*kind=order_db_get_field(chain_dir,oid,"kind"),*status=order_db_get_field(chain_dir,oid,"status"),*market=order_db_get_field(chain_dir,oid,"market"),*side=order_db_get_field(chain_dir,oid,"side"),*sv=order_db_get_field(chain_dir,oid,"settlement_version"),*owner=order_db_get_field(chain_dir,oid,"owner");long long exp=order_db_get_ll(chain_dir,oid,"order_expires_height",0),qty=order_db_get_ll(chain_dir,oid,"remaining_atoms",0);if(kind&&!strcmp(kind,"crosschain")&&status&&crosschain_order_live(status)&&market&&crosschain_market_valid(market)&&side&&strcasecmp(side,taker_side)&&sv&&!strcmp(sv,QRX_CROSSCHAIN_SETTLEMENT_VERSION)&&owner&&strcmp(owner,towner)&&exp>h&&qty==tqty){QrxCrossCandidate*nn=realloc(a,(n+1)*sizeof(*a));if(!nn)die("oom");a=nn;memset(&a[n],0,sizeof(a[n]));snprintf(a[n].id,sizeof(a[n].id),"%s",oid);snprintf(a[n].side,sizeof(a[n].side),"%s",side);a[n].price=order_db_get_ll(chain_dir,oid,"limit_price_atoms",0);a[n].qty=qty;a[n].created=order_db_get_ll(chain_dir,oid,"created_height",0);n++;}free(kind);free(status);free(market);free(side);free(sv);free(owner);}}}cur=e?e+1:NULL;}free(txt);}int want_sell=!strcasecmp(taker_side,"BUY");for(size_t i=1;i<n;i++){QrxCrossCandidate k=a[i];size_t j=i;while(j>0&&crosschain_candidate_better(&k,&a[j-1],want_sell)){a[j]=a[j-1];j--;}a[j]=k;}for(size_t i=0;i<n;i++){int crosses=!strcasecmp(taker_side,"BUY")?(a[i].price<=tprice):(a[i].price>=tprice);if(!crosses)break;int rc=crosschain_settle_match(chain_dir,a[i].id,taker_id,a[i].price);if(rc==0){free(a);free(taker_side);free(towner);return 0;}if(rc<0){free(a);free(taker_side);free(towner);return -1;}}free(a);free(taker_side);free(towner);return 0;
}

typedef struct{char**ids;size_t n,c;} CrossPending;
static int cross_pending_cb(const char*k,const char*v,uint32_t vl,void*ctx){(void)vl;CrossPending*p=ctx;const char*pfx="velocity:xmatch_pending:";if(!v||strcmp(v,"1")||strncmp(k,pfx,strlen(pfx)))return 0;if(p->n==p->c){size_t nc=p->c?p->c*2:8;char**nn=realloc(p->ids,nc*sizeof(*nn));if(!nn)return -1;p->ids=nn;p->c=nc;}p->ids[p->n++]=strdup(k+strlen(pfx));return p->ids[p->n-1]?0:-1;}
static void velocity_process_pending_crosschain_matches(const char *chain_dir){QrxDB db;CrossPending p={0};if(qrxdb_init(&db,chain_dir))return;qrxdb_scan_prefix(&db,"velocity:xmatch_pending:",cross_pending_cb,&p);qrxdb_close(&db);for(size_t i=0;i<p.n;i++){mirror_order_from_authoritative(chain_dir,p.ids[i]);match_crosschain_order(chain_dir,p.ids[i]);free(p.ids[i]);}free(p.ids);}

static int crosschain_status_cmd(const char *chain_dir,const char *sid){const char*fields[]={"market","status","buy_order_id","sell_order_id","maker_order_id","taker_order_id","qrx_buyer","qrx_seller","quantity_sats","price_atoms","qub_atoms","qrx_locked_atoms","hashlock_hex","qrx_refund_height","btc_refund_csv_blocks","btc_redeem_pubkey_hex","btc_refund_pubkey_hex","btc_witness_script_hex","btc_script_sha256","btc_scriptpubkey_hex","btc_p2wsh_mainnet","btc_p2wsh_testnet","btc_p2wsh_regtest","bitcoin_spv_verified","btc_funding_status","btc_funding_txid","btc_funding_vout","btc_funding_sats","btc_funding_block_hash","btc_funding_block_height","btc_proof_confirmations_at_submit","btc_required_confirmations","safe_to_reveal_secret","btc_proof_qrx_height","btc_proof_last_tx","settlement_model","created_height","redeemed_height","refunded_height","secret_hash","last_tx",NULL};int found=0;printf("session_id=%s\n",sid);for(int i=0;fields[i];i++){char*v=crosschain_get_field(chain_dir,sid,fields[i]);if(v){printf("%s=%s\n",fields[i],v);free(v);found=1;}}if(!found)die("cross-chain session not found");return 0;}
typedef struct{const char*sf;} CrossListCtx;
static int crosschain_list_cb(const char*k,const char*v,uint32_t vl,void*vp){(void)vl;CrossListCtx*cc=(CrossListCtx*)vp;const char*pfx="velocity:crosschain:";const char*suf=":status";size_t kl=strlen(k),pl=strlen(pfx),sl=strlen(suf);if(kl<=pl+sl||strncmp(k,pfx,pl)||strcmp(k+kl-sl,suf))return 0;if(cc->sf&&*cc->sf&&strcasecmp(cc->sf,v))return 0;char sid[160];size_t n=kl-pl-sl;if(n>=sizeof(sid))return 0;memcpy(sid,k+pl,n);sid[n]=0;printf("session_id=%s status=%s\n",sid,v);return 0;}
static int list_crosschain_cmd(const char *chain_dir,const char *status_filter){QrxDB db;if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");CrossListCtx c={status_filter};qrxdb_scan_prefix(&db,"velocity:crosschain:",crosschain_list_cb,&c);qrxdb_close(&db);return 0;}

static int crosschain_orderbook_cmd(const char *chain_dir,int depth){if(depth<=0)depth=20;if(depth>200)depth=200;char path[1024];order_registry_path(chain_dir,path,sizeof(path));char*txt=read_file(path,NULL);QrxCrossCandidate*b=NULL,*s=NULL;size_t nb=0,ns=0;if(txt){const char*cur=txt;const char suffix[]=".owner=";while(cur&&*cur){const char*e=strchr(cur,'\n');size_t len=e?(size_t)(e-cur):strlen(cur);const char*suf=NULL;if(len>6&&!strncmp(cur,"order.",6)){for(size_t i=6;i+strlen(suffix)<len;i++)if(!strncmp(cur+i,suffix,strlen(suffix))){suf=cur+i;break;}}if(suf){size_t il=(size_t)(suf-(cur+6));if(il>0&&il<160){char oid[160];memcpy(oid,cur+6,il);oid[il]=0;char*k=order_db_get_field(chain_dir,oid,"kind"),*st=order_db_get_field(chain_dir,oid,"status"),*m=order_db_get_field(chain_dir,oid,"market"),*side=order_db_get_field(chain_dir,oid,"side");if(k&&!strcmp(k,"crosschain")&&st&&crosschain_order_live(st)&&m&&crosschain_market_valid(m)&&side){QrxCrossCandidate**arr=!strcasecmp(side,"BUY")?&b:&s;size_t*n=!strcasecmp(side,"BUY")?&nb:&ns;QrxCrossCandidate*nn=realloc(*arr,(*n+1)*sizeof(**arr));if(!nn)die("oom");*arr=nn;memset(&nn[*n],0,sizeof(nn[*n]));snprintf(nn[*n].id,sizeof(nn[*n].id),"%s",oid);snprintf(nn[*n].side,sizeof(nn[*n].side),"%s",side);nn[*n].price=order_db_get_ll(chain_dir,oid,"limit_price_atoms",0);nn[*n].qty=order_db_get_ll(chain_dir,oid,"remaining_atoms",0);nn[*n].created=order_db_get_ll(chain_dir,oid,"created_height",0);(*n)++;}free(k);free(st);free(m);free(side);}}cur=e?e+1:NULL;}free(txt);}for(size_t i=1;i<nb;i++){QrxCrossCandidate k=b[i];size_t j=i;while(j&&crosschain_candidate_better(&k,&b[j-1],0)){b[j]=b[j-1];j--;}b[j]=k;}for(size_t i=1;i<ns;i++){QrxCrossCandidate k=s[i];size_t j=i;while(j&&crosschain_candidate_better(&k,&s[j-1],1)){s[j]=s[j-1];j--;}s[j]=k;}printf("market=%s base_unit=satoshi quote_unit=QUB-atom price_scale=%lld exact_fill_only=true\n",QRX_CROSSCHAIN_MARKET,(long long)QRX_TRADE_PRICE_SCALE);for(size_t i=0;i<nb&&(int)i<depth;i++)printf("side=BUY price_atoms=%lld quantity_sats=%lld order_id=%s\n",b[i].price,b[i].qty,b[i].id);for(size_t i=0;i<ns&&(int)i<depth;i++)printf("side=SELL price_atoms=%lld quantity_sats=%lld order_id=%s\n",s[i].price,s[i].qty,s[i].id);free(b);free(s);return 0;}

static int btc_htlc_template_cmd(const char *hash,const char *buyer_pub,const char *seller_pub,long long csv,const char *network){unsigned char script[256],sh[32];size_t sl=0,shn=0;char shex[513],hhex[65],spk[69],addr[128];if(crosschain_btc_htlc_script(hash,buyer_pub,seller_pub,csv,script,sizeof(script),&sl,shex,hhex,spk))die("invalid Bitcoin HTLC parameters");hex_to_bytes(hhex,sh,sizeof(sh),&shn);if(crosschain_p2wsh_address(network?network:"mainnet",sh,addr,sizeof(addr)))die("bech32 address generation failed");printf("witness_script_hex=%s\nscript_sha256=%s\nscript_pubkey_hex=%s\np2wsh_address=%s\nbtc_refund_csv_blocks=%lld\n",shex,hhex,spk,addr,csv);return 0;}

static int create_crosschain_buy_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *sats,const char *price,const char *order_exp,const char *hash,const char *btc_pub,const char *qrx_refund,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char p[4096];snprintf(p,sizeof(p),"market=%s;side=BUY;order_type=LIMIT;quantity_atoms=%s;limit_price_atoms=%s;order_expires_height=%s;hashlock_hex=%s;btc_redeem_pubkey_hex=%s;btc_refund_pubkey_hex=-;btc_refund_csv_blocks=0;qrx_refund_height=%s",QRX_CROSSCHAIN_MARKET,sats,price,order_exp,hash,btc_pub,qrx_refund);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"CROSSCHAIN_ORDER",lane,tx_exp,p,fee,nonce);}
static int create_crosschain_sell_raw_tx_cmd(const char *chain_dir,const char *agent,const char *owner,const char *sats,const char *price,const char *order_exp,const char *btc_refund_pub,const char *csv,const char *agent_ed,const char *agent_ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char p[4096];snprintf(p,sizeof(p),"market=%s;side=SELL;order_type=LIMIT;quantity_atoms=%s;limit_price_atoms=%s;order_expires_height=%s;hashlock_hex=-;btc_redeem_pubkey_hex=-;btc_refund_pubkey_hex=%s;btc_refund_csv_blocks=%s;qrx_refund_height=0",QRX_CROSSCHAIN_MARKET,sats,price,order_exp,btc_refund_pub,csv);return create_velocity_raw_tx_cmd(chain_dir,agent,owner,"0",agent_ed,agent_ml,"CROSSCHAIN_ORDER",lane,tx_exp,p,fee,nonce);}
static int create_crosschain_redeem_raw_tx_cmd(const char *chain_dir,const char *seller,const char *sid,const char *secret,const char *ed,const char *ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char p[1024];snprintf(p,sizeof(p),"session_id=%s;secret_hex=%s",sid,secret);return create_velocity_raw_tx_cmd(chain_dir,seller,seller,"0",ed,ml,"CROSSCHAIN_REDEEM",lane,tx_exp,p,fee,nonce);}
static int create_crosschain_refund_raw_tx_cmd(const char *chain_dir,const char *buyer,const char *sid,const char *ed,const char *ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char p[512];snprintf(p,sizeof(p),"session_id=%s",sid);return create_velocity_raw_tx_cmd(chain_dir,buyer,buyer,"0",ed,ml,"CROSSCHAIN_REFUND",lane,tx_exp,p,fee,nonce);}

static int crosschain_info_cmd(const char *chain_dir){(void)chain_dir;printf("phase=3D\nmarket=BTC/QUB\nbitcoin_asset_native=false\nqbtc_used=false\nbridge_required=false\nsettlement=HTLC_SHA256_P2WSH_CSV\nqrx_leg=QRXDB_WAL_ATOMIC\nbitcoin_leg=P2WSH_HTLC\nbitcoin_spv_consensus=true\nbitcoin_spv_phase=3D.1\nbitcoin_spv_header_state=QRXDB_WAL_CONSENSUS\nbitcoin_spv_merkle_proofs=true\nbitcoin_spv_reorg_tracking=true\nexact_fill_only=true\nsecret_encoding=hex_bytes\nmatching=price_then_created_height_then_order_id\nprice_execution=maker_limit_price\npermission=TRADE_CROSSCHAIN\nfunding_release_policy=SPV_ACTIVE_CHAIN_AND_CONFIRMATIONS\ndefault_btc_confirmations=6\n");return 0;}
