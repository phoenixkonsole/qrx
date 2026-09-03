/* QRX Core 0.0.7 VELOCITY Phase 3D.1
 * Bitcoin SPV verification committed through QRX consensus.
 *
 * Consensus rule: Bitcoin headers and cross-chain funding proofs that affect
 * settlement are not accepted as local mutable RPC state. They arrive inside
 * signed QRX VELOCITY transactions (BTC_SPV_HEADER / BTC_SPV_FUNDING_PROOF),
 * are deterministically verified by every QRX validator, and are committed in
 * the same QRXDB WAL transaction as fee/nonce/applied-tx state.
 */

#define QRX_BTC_SPV_DEFAULT_CONFIRMATIONS 6LL
#define QRX_BTC_SPV_MAX_CONFIRMATIONS_POLICY 144LL

static const char *btc_spv_network_for_chain(const char *chain_dir){
    if(chain_network_is(chain_dir,"mainnet")) return "mainnet";
    if(chain_network_is(chain_dir,"regtest")) return "regtest";
    return "testnet"; /* QRX alpha/testnet intentionally use Bitcoin testnet. */
}

static long long btc_spv_session_required_confirmations(const char *chain_dir,const char *sid){
    long long n=crosschain_get_ll(chain_dir,sid,"btc_required_confirmations",QRX_BTC_SPV_DEFAULT_CONFIRMATIONS);
    if(n<1)n=QRX_BTC_SPV_DEFAULT_CONFIRMATIONS;if(n>QRX_BTC_SPV_MAX_CONFIRMATIONS_POLICY)n=QRX_BTC_SPV_MAX_CONFIRMATIONS_POLICY;return n;
}

static int btc_spv_funding_security_current(const char *chain_dir,const char *sid,uint64_t *conf_out,int *active_out,int *safe_out){
    char *txid=crosschain_get_field(chain_dir,sid,"btc_funding_txid"),*bh=crosschain_get_field(chain_dir,sid,"btc_funding_block_hash");
    long long h=crosschain_get_ll(chain_dir,sid,"btc_funding_block_height",-1),req=btc_spv_session_required_confirmations(chain_dir,sid);
    if(conf_out)*conf_out=0;if(active_out)*active_out=0;if(safe_out)*safe_out=0;
    if(!txid||!*txid||!bh||!*bh||h<0){free(txid);free(bh);return 0;}
    QrxDB db;char err[256]={0};if(qrxdb_init(&db,chain_dir)){free(txid);free(bh);return -1;}uint64_t c=0;int active=0;int rc=qrx_btc_spv_confirmations(&db,btc_spv_network_for_chain(chain_dir),bh,(uint64_t)h,&c,&active,err,sizeof(err));qrxdb_close(&db);free(txid);free(bh);if(rc)return -1;if(conf_out)*conf_out=c;if(active_out)*active_out=active;if(safe_out)*safe_out=active&&c>=(uint64_t)req;return 0;
}

static void validate_btc_spv_header_tx(const char *chain_dir,const char *from,const char *to,const char *payload){
    (void)from;if(!to||!*to)die("BTC_SPV_HEADER missing to address");validate_payload_clean(payload,"Bitcoin SPV header payload");char *hex=payload_get_field(payload,"header_hex");if(!hex||strlen(hex)!=160)die("BTC_SPV_HEADER requires header_hex=160 hex chars");
    QrxDB db;QrxDBBatch b;QrxBtcSpvHeaderInfo hi;int best=0;char err[512]={0};if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");if(qrxdb_batch_begin(&db,&b)){qrxdb_close(&db);die("SPV validation batch failed");}int rc=qrx_btc_spv_stage_header(&db,&b,btc_spv_network_for_chain(chain_dir),hex,&hi,&best,err,sizeof(err));qrxdb_batch_abort(&b);qrxdb_close(&db);free(hex);if(rc)die("Bitcoin SPV header rejected: %s",err[0]?err:"validation failed");
}

static int atomic_stage_btc_spv_header(QrxDB *db,QrxDBBatch *b,const char *chain_dir,const char *payload){
    char *hex=payload_get_field(payload,"header_hex");if(!hex)return -1;QrxBtcSpvHeaderInfo hi;int best=0;char err[512]={0};int rc=qrx_btc_spv_stage_header(db,b,btc_spv_network_for_chain(chain_dir),hex,&hi,&best,err,sizeof(err));free(hex);return rc;
}

static int btc_spv_verify_crosschain_payload(const char *chain_dir,const char *from,const char *payload,QrxBtcSpvProofResult *proof,QrxBtcTxOutputMatch *match,char *sid_out,size_t sid_sz,char *err,size_t err_sz){
    validate_payload_clean(payload,"Bitcoin SPV funding proof payload");char *sid=payload_get_field(payload,"session_id"),*raw=payload_get_field(payload,"rawtx_hex"),*bh=payload_get_field(payload,"block_hash"),*idxs=payload_get_field(payload,"tx_index"),*branch=payload_get_field(payload,"merkle_branch");
    if(!sid||!*sid||!raw||!*raw||!bh||strlen(bh)!=64||!idxs||!*idxs||!branch){snprintf(err,err_sz,"missing funding proof field");goto fail;}
    char *buyer=crosschain_get_field(chain_dir,sid,"qrx_buyer"),*seller=crosschain_get_field(chain_dir,sid,"qrx_seller"),*spk=crosschain_get_field(chain_dir,sid,"btc_scriptpubkey_hex");long long sats=crosschain_get_ll(chain_dir,sid,"quantity_sats",-1);
    if(!buyer||!seller||!spk||sats<=0){snprintf(err,err_sz,"cross-chain session not found/incomplete");free(buyer);free(seller);free(spk);goto fail;}
    if(strcmp(from,buyer)&&strcmp(from,seller)){snprintf(err,err_sz,"only cross-chain participants may submit Bitcoin funding proof");free(buyer);free(seller);free(spk);goto fail;}
    char *e=NULL;errno=0;unsigned long long idx=strtoull(idxs,&e,10);if(errno||!e||*e){snprintf(err,err_sz,"invalid tx_index");free(buyer);free(seller);free(spk);goto fail;}
    if(qrx_btc_tx_find_output(raw,sats,spk,match,err,err_sz)){free(buyer);free(seller);free(spk);goto fail;}
    QrxDB db;if(qrxdb_init(&db,chain_dir)){snprintf(err,err_sz,"QRXDB init failed");free(buyer);free(seller);free(spk);goto fail;}int rc=qrx_btc_spv_verify_merkle(&db,btc_spv_network_for_chain(chain_dir),match->txid,bh,(uint64_t)idx,branch,proof,err,err_sz);qrxdb_close(&db);free(buyer);free(seller);free(spk);if(rc)goto fail;if(sid_out&&sid_sz)snprintf(sid_out,sid_sz,"%s",sid);free(sid);free(raw);free(bh);free(idxs);free(branch);return 0;
fail:free(sid);free(raw);free(bh);free(idxs);free(branch);return -1;
}

static void validate_btc_spv_funding_proof_tx(const char *chain_dir,const char *from,const char *to,const char *payload){
    (void)to;QrxBtcSpvProofResult p;QrxBtcTxOutputMatch m;char sid[160],err[512]={0};if(btc_spv_verify_crosschain_payload(chain_dir,from,payload,&p,&m,sid,sizeof(sid),err,sizeof(err)))die("Bitcoin SPV funding proof rejected: %s",err[0]?err:"validation failed");
}

static int atomic_stage_btc_spv_funding_proof(QrxDBBatch *b,const char *chain_dir,const char *from,const char *payload,const char *body_hash,long long qrx_height){
    QrxBtcSpvProofResult p;QrxBtcTxOutputMatch m;char sid[160],err[512]={0};if(btc_spv_verify_crosschain_payload(chain_dir,from,payload,&p,&m,sid,sizeof(sid),err,sizeof(err)))return -1;char *spk=crosschain_get_field(chain_dir,sid,"btc_scriptpubkey_hex");if(!spk)return -1;int rc=qrx_btc_spv_stage_proof(b,btc_spv_network_for_chain(chain_dir),&p,m.vout,m.sats,spk,err,sizeof(err));free(spk);long long req=btc_spv_session_required_confirmations(chain_dir,sid);int safe=p.active_chain&&p.confirmations>=(uint64_t)req;
    rc|=crosschain_batch_put(b,sid,"bitcoin_spv_verified","true");rc|=crosschain_batch_put(b,sid,"btc_funding_txid",p.txid);rc|=crosschain_batch_put_ll(b,sid,"btc_funding_vout",m.vout);rc|=crosschain_batch_put_ll(b,sid,"btc_funding_sats",m.sats);rc|=crosschain_batch_put(b,sid,"btc_funding_block_hash",p.block_hash);rc|=crosschain_batch_put_ll(b,sid,"btc_funding_block_height",(long long)p.block_height);rc|=crosschain_batch_put_ll(b,sid,"btc_proof_confirmations_at_submit",(long long)p.confirmations);rc|=crosschain_batch_put_ll(b,sid,"btc_required_confirmations",req);rc|=crosschain_batch_put(b,sid,"btc_funding_status",safe?"confirmed":"confirming");rc|=crosschain_batch_put(b,sid,"safe_to_reveal_secret",safe?"true":"false");rc|=crosschain_batch_put(b,sid,"status",safe?"btc_funded":"btc_confirming");rc|=crosschain_batch_put_ll(b,sid,"btc_proof_qrx_height",qrx_height);rc|=crosschain_batch_put(b,sid,"btc_proof_last_tx",body_hash);return rc?-1:0;
}

static int btc_spv_info_cmd(const char *chain_dir){
    const char*n=btc_spv_network_for_chain(chain_dir);QrxDB db;if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");QrxBtcSpvHeaderInfo h;char err[256]={0};int ok=qrx_btc_spv_get_best(&db,n,&h,err,sizeof(err))==0;printf("phase=3D.1\nnetwork=%s\nconsensus_committed=true\nheader_pow_validation=true\ndifficulty_validation=true\nmedian_time_past_validation=true\nchain_selection=highest_chainwork\nmerkle_validation=true\nfunding_output_validation=true\nreorg_tracking=true\ntransport=QRX_SPV_HEADER_TRANSACTIONS\ninitialized=%s\n",n,ok?"true":"false");if(ok)printf("best_height=%llu\nbest_hash=%s\nbest_chainwork=%s\nbest_time=%u\n",(unsigned long long)h.height,h.hash,h.chainwork_hex,h.timestamp);else{const char*g=qrx_btc_spv_genesis_header_hex(n);unsigned char raw[80],d[32];size_t rn=0;char gh[65]="";if(g&&!hex_to_bytes(g,raw,sizeof(raw),&rn)&&rn==80){unsigned char t[32];SHA256(raw,80,t);SHA256(t,32,d);unsigned char r[32];for(int i=0;i<32;i++)r[i]=d[31-i];for(int i=0;i<32;i++)sprintf(gh+i*2,"%02x",r[i]);}printf("expected_genesis_hash=%s\n",gh);}qrxdb_close(&db);return 0;
}

static int btc_spv_best_header_cmd(const char *chain_dir){QrxDB db;QrxBtcSpvHeaderInfo h;char err[256]={0};if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");if(qrx_btc_spv_get_best(&db,btc_spv_network_for_chain(chain_dir),&h,err,sizeof(err))){qrxdb_close(&db);die("%s",err);}qrxdb_close(&db);printf("hash=%s\nheight=%llu\nprev_hash=%s\nmerkle_root=%s\ntime=%u\nbits=%08x\nnonce=%u\nchainwork=%s\nactive=true\nheader_hex=%s\n",h.hash,(unsigned long long)h.height,h.prev_hash,h.merkle_root,h.timestamp,h.bits,h.nonce,h.chainwork_hex,h.header_hex);return 0;}
static int btc_spv_header_cmd(const char *chain_dir,const char *id){QrxDB db;QrxBtcSpvHeaderInfo h;char err[256]={0};if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");if(qrx_btc_spv_get_header(&db,btc_spv_network_for_chain(chain_dir),id,&h,err,sizeof(err))){qrxdb_close(&db);die("%s",err);}qrxdb_close(&db);printf("hash=%s\nheight=%llu\nprev_hash=%s\nmerkle_root=%s\ntime=%u\nbits=%08x\nnonce=%u\nchainwork=%s\nactive=%s\nheader_hex=%s\n",h.hash,(unsigned long long)h.height,h.prev_hash,h.merkle_root,h.timestamp,h.bits,h.nonce,h.chainwork_hex,h.active?"true":"false",h.header_hex);return 0;}

static int btc_spv_verify_proof_cmd(const char *chain_dir,const char *txid,const char *block_hash,const char *idx,const char *branch){char*e=NULL;errno=0;unsigned long long i=strtoull(idx,&e,10);if(errno||!e||*e)die("invalid tx index");QrxDB db;QrxBtcSpvProofResult p;char err[512]={0};if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");if(qrx_btc_spv_verify_merkle(&db,btc_spv_network_for_chain(chain_dir),txid,block_hash,(uint64_t)i,branch,&p,err,sizeof(err))){qrxdb_close(&db);die("%s",err);}qrxdb_close(&db);printf("txid=%s\nblock_hash=%s\nblock_height=%llu\nmerkle_index=%llu\nmerkle_valid=true\nactive_chain=true\nconfirmations=%llu\n",p.txid,p.block_hash,(unsigned long long)p.block_height,(unsigned long long)p.merkle_index,(unsigned long long)p.confirmations);return 0;}

static int crosschain_verify_funding_cmd(const char *chain_dir,const char *sid,const char *raw,const char *bh,const char *idx,const char *branch){
    char *buyer=crosschain_get_field(chain_dir,sid,"qrx_buyer");if(!buyer)die("cross-chain session not found");char payload[MAX_TX];snprintf(payload,sizeof(payload),"session_id=%s;rawtx_hex=%s;block_hash=%s;tx_index=%s;merkle_branch=%s",sid,raw,bh,idx,branch);QrxBtcSpvProofResult p;QrxBtcTxOutputMatch m;char xsid[160],err[512]={0};if(btc_spv_verify_crosschain_payload(chain_dir,buyer,payload,&p,&m,xsid,sizeof(xsid),err,sizeof(err))){free(buyer);die("%s",err);}free(buyer);long long req=btc_spv_session_required_confirmations(chain_dir,sid);printf("session_id=%s\nbtc_txid=%s\nbtc_vout=%d\nexpected_sats=%lld\nactual_sats=%lld\nblock_hash=%s\nblock_height=%llu\nmerkle_proof_valid=true\nheader_pow_valid=true\nactive_chain=true\nconfirmations=%llu\nrequired_confirmations=%lld\nsafe_to_reveal_secret=%s\nstate_mutated=false\nnext=createbtcspvfundingprooftransaction\n",sid,m.txid,m.vout,(long long)m.sats,(long long)m.sats,p.block_hash,(unsigned long long)p.block_height,(unsigned long long)p.confirmations,req,p.confirmations>=(uint64_t)req?"true":"false");return 0;
}

static int crosschain_funding_cmd(const char *chain_dir,const char *sid){
    char *txid=crosschain_get_field(chain_dir,sid,"btc_funding_txid"),*bh=crosschain_get_field(chain_dir,sid,"btc_funding_block_hash"),*verified=crosschain_get_field(chain_dir,sid,"bitcoin_spv_verified");if(!txid||!*txid){free(txid);free(bh);free(verified);printf("session_id=%s\nproof_submitted=false\nsafe_to_reveal_secret=false\n",sid);return 0;}uint64_t c=0;int active=0,safe=0;if(btc_spv_funding_security_current(chain_dir,sid,&c,&active,&safe)){free(txid);free(bh);free(verified);die("SPV state unavailable");}long long req=btc_spv_session_required_confirmations(chain_dir,sid),h=crosschain_get_ll(chain_dir,sid,"btc_funding_block_height",-1),vout=crosschain_get_ll(chain_dir,sid,"btc_funding_vout",-1),sats=crosschain_get_ll(chain_dir,sid,"btc_funding_sats",-1);printf("session_id=%s\nproof_submitted=true\nbitcoin_spv_verified=%s\nbtc_txid=%s\nbtc_vout=%lld\nbtc_sats=%lld\nblock_hash=%s\nblock_height=%lld\nactive_chain=%s\nconfirmations=%llu\nrequired_confirmations=%lld\nreorg_detected=%s\nsafe_to_reveal_secret=%s\n",sid,verified?verified:"false",txid,vout,sats,bh?bh:"",h,active?"true":"false",(unsigned long long)c,req,active?"false":"true",safe?"true":"false");free(txid);free(bh);free(verified);return 0;
}

static int crosschain_security_cmd(const char *chain_dir,const char *sid){uint64_t c=0;int active=0,safe=0;if(btc_spv_funding_security_current(chain_dir,sid,&c,&active,&safe))die("SPV state unavailable");long long req=btc_spv_session_required_confirmations(chain_dir,sid);char*verified=crosschain_get_field(chain_dir,sid,"bitcoin_spv_verified");printf("session_id=%s\nproof_cryptographically_verified=%s\nactive_best_work_chain=%s\nconfirmations=%llu\nrequired_confirmations=%lld\nqrx_consensus_committed_spv=true\nqbtc=false\nbridge=false\nsafe_to_reveal_secret=%s\n",sid,verified?verified:"false",active?"true":"false",(unsigned long long)c,req,safe?"true":"false");free(verified);return 0;}

static int btc_spv_confirmations_cmd(const char *chain_dir,const char *txid){QrxDB db;QrxBtcSpvProofResult p;int vout=0;int64_t sats=0;char spk[256],err[256]={0};if(qrxdb_init(&db,chain_dir))die("QRXDB init failed");if(qrx_btc_spv_get_stored_proof(&db,btc_spv_network_for_chain(chain_dir),txid,&p,&vout,&sats,spk,sizeof(spk),err,sizeof(err))){qrxdb_close(&db);die("%s",err);}qrxdb_close(&db);printf("txid=%s\nblock_hash=%s\nblock_height=%llu\nvout=%d\nsats=%lld\nactive_chain=%s\nconfirmations=%llu\n",p.txid,p.block_hash,(unsigned long long)p.block_height,vout,(long long)sats,p.active_chain?"true":"false",(unsigned long long)p.confirmations);return 0;}

static int create_btc_spv_header_raw_tx_cmd(const char *chain_dir,const char *address,const char *header,const char *ed,const char *ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){char p[512];snprintf(p,sizeof(p),"header_hex=%s",header);return create_velocity_raw_tx_cmd(chain_dir,address,address,"0",ed,ml,"BTC_SPV_HEADER",lane,tx_exp,p,fee,nonce);}
static int create_btc_spv_funding_proof_raw_tx_cmd(const char *chain_dir,const char *address,const char *sid,const char *raw,const char *bh,const char *idx,const char *branch,const char *ed,const char *ml,const char *lane,const char *tx_exp,const char *fee,const char *nonce){size_t cap=strlen(raw)+strlen(branch)+strlen(sid)+strlen(bh)+512;char*p=malloc(cap);if(!p)die("oom");snprintf(p,cap,"session_id=%s;rawtx_hex=%s;block_hash=%s;tx_index=%s;merkle_branch=%s",sid,raw,bh,idx,branch);int rc=create_velocity_raw_tx_cmd(chain_dir,address,address,"0",ed,ml,"BTC_SPV_FUNDING_PROOF",lane,tx_exp,p,fee,nonce);free(p);return rc;}
