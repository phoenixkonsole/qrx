#define _CRT_SECURE_NO_WARNINGS
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "qrxdb.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir_local(p) _mkdir(p)
#define SEP "\\"
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#define mkdir_local(p) mkdir(p,0700)
#define SEP "/"
#endif

#define QRXDB_MAX_KEY_SIZE   (1024u * 1024u)
#define QRXDB_MAX_VALUE_SIZE (512u * 1024u * 1024u)
#define QRXDB_WAL_BEGIN  1u
#define QRXDB_WAL_PUT    2u
#define QRXDB_WAL_COMMIT 3u

typedef struct {
    uint32_t magic;
    uint32_t type;
    uint64_t generation;
    uint64_t offset;
    uint32_t key_len;
    uint32_t value_len;
    uint32_t crc32;
} QrxDBWalHeader;

typedef struct {
    char *key;
    char *value;
    uint32_t key_len;
    uint32_t value_len;
    uint64_t offset;
    uint64_t generation;
} QrxDBKV;

typedef struct {
    char *key;
    char *value;
    uint32_t key_len;
    uint32_t value_len;
    uint64_t generation;
    int has_put;
    int committed;
} QrxDBWalTxn;

static void build_path(char *out, size_t out_sz, const char *a, const char *b){ snprintf(out,out_sz,"%s%s%s",a,SEP,b); }
static uint64_t align8(uint64_t x){ return (x + 7ULL) & ~7ULL; }

uint32_t qrxdb_crc32(const void *data, size_t len){
    const unsigned char *p = (const unsigned char*)data;
    uint32_t crc = 0xFFFFFFFFu;
    for(size_t i=0;i<len;i++){
        crc ^= p[i];
        for(int j=0;j<8;j++) crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int)(crc & 1u));
    }
    return ~crc;
}

static uint32_t record_crc(const char *key, uint32_t klen, const char *val, uint32_t vlen){
    uint32_t c = qrxdb_crc32(key, klen);
    c ^= qrxdb_crc32(val, vlen) + 0x9e3779b9u + (c << 6) + (c >> 2);
    return c;
}

static void qrxdb_zero_root(uint8_t root[QRXDB_MERKLE_HASH_SIZE]){ memset(root,0,QRXDB_MERKLE_HASH_SIZE); }

static void qrxdb_sha3_512_leaf(uint8_t out[QRXDB_MERKLE_HASH_SIZE], const char *key, uint32_t klen, const char *val, uint32_t vlen){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outlen = 0;
    static const char tag[] = "QRXDB_LEAF_SHA3_512_V1";
    if(!ctx) { memset(out,0,QRXDB_MERKLE_HASH_SIZE); return; }
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, tag, sizeof(tag)-1);
    EVP_DigestUpdate(ctx, &klen, sizeof(klen));
    EVP_DigestUpdate(ctx, key, klen);
    EVP_DigestUpdate(ctx, &vlen, sizeof(vlen));
    EVP_DigestUpdate(ctx, val, vlen);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

static void qrxdb_sha3_512_node(uint8_t out[QRXDB_MERKLE_HASH_SIZE], const uint8_t a[QRXDB_MERKLE_HASH_SIZE], const uint8_t b[QRXDB_MERKLE_HASH_SIZE]){
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outlen = 0;
    static const char tag[] = "QRXDB_NODE_SHA3_512_V1";
    if(!ctx) { memset(out,0,QRXDB_MERKLE_HASH_SIZE); return; }
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(ctx, tag, sizeof(tag)-1);
    EVP_DigestUpdate(ctx, a, QRXDB_MERKLE_HASH_SIZE);
    EVP_DigestUpdate(ctx, b, QRXDB_MERKLE_HASH_SIZE);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}


static int qrxdb_sha3_512_buf(const unsigned char *buf, size_t len, uint8_t out[QRXDB_MERKLE_HASH_SIZE]){
    unsigned int outlen=0; EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL)==1 && EVP_DigestUpdate(ctx, buf, len)==1 && EVP_DigestFinal_ex(ctx, out, &outlen)==1 && outlen==QRXDB_MERKLE_HASH_SIZE;
    EVP_MD_CTX_free(ctx); return ok?0:-1;
}

static void qrxdb_hex64(const uint8_t in[QRXDB_MERKLE_HASH_SIZE], char out[129]){
    static const char h[]="0123456789abcdef"; for(int i=0;i<64;i++){ out[i*2]=h[in[i]>>4]; out[i*2+1]=h[in[i]&15]; } out[128]=0;
}

static int qrxdb_sha3_512_file(const char *path, uint8_t out[QRXDB_MERKLE_HASH_SIZE]){
    FILE *f=fopen(path,"rb"); if(!f) return -1;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx){ fclose(f); return -1; }
    unsigned char buf[65536]; unsigned int outlen=0; int ok= EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL)==1;
    while(ok){ size_t n=fread(buf,1,sizeof(buf),f); if(n) ok = EVP_DigestUpdate(ctx,buf,n)==1; if(n<sizeof(buf)){ if(ferror(f)) ok=0; break; } }
    if(ok) ok = EVP_DigestFinal_ex(ctx,out,&outlen)==1 && outlen==QRXDB_MERKLE_HASH_SIZE;
    EVP_MD_CTX_free(ctx); fclose(f); return ok?0:-1;
}

static char *qrxdb_read_all(const char *path, size_t *out_len){
    FILE *f=fopen(path,"rb"); if(!f) return NULL; if(fseek(f,0,SEEK_END)!=0){ fclose(f); return NULL; } long n=ftell(f); if(n<0){ fclose(f); return NULL; } rewind(f);
    char *buf=(char*)malloc((size_t)n+1); if(!buf){ fclose(f); return NULL; } size_t r=fread(buf,1,(size_t)n,f); fclose(f); if(r!=(size_t)n){ free(buf); return NULL; } buf[r]=0; if(out_len)*out_len=r; return buf;
}

static int qrxdb_write_all(const char *path, const char *buf, size_t len){ FILE *f=fopen(path,"wb"); if(!f) return -1; int ok=fwrite(buf,1,len,f)==len; fflush(f); fclose(f); return ok?0:-1; }

static char *qrxdb_cfg_get(const char *text, const char *key){
    size_t klen=strlen(key); const char *p=text; while(p && *p){ const char *e=strchr(p,'\n'); size_t len=e?(size_t)(e-p):strlen(p); if(len>klen+1 && !strncmp(p,key,klen) && p[klen]=='='){ char *out=(char*)malloc(len-klen); if(!out)return NULL; memcpy(out,p+klen+1,len-klen-1); out[len-klen-1]=0; return out; } p=e?e+1:NULL; } return NULL;
}

static char *qrxdb_base64_encode(const unsigned char *buf, size_t len){
    BIO *b64=BIO_new(BIO_f_base64()), *mem=BIO_new(BIO_s_mem()); if(!b64||!mem){ if(b64)BIO_free(b64); if(mem)BIO_free(mem); return NULL; }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); BIO_push(b64, mem); if(BIO_write(b64, buf, (int)len)!=(int)len){ BIO_free_all(b64); return NULL; } BIO_flush(b64); BUF_MEM *b; BIO_get_mem_ptr(mem,&b); char *s=(char*)malloc(b->length+1); if(!s){ BIO_free_all(b64); return NULL; } memcpy(s,b->data,b->length); s[b->length]=0; BIO_free_all(b64); return s;
}

static unsigned char *qrxdb_base64_decode(const char *s, size_t *outlen){
    size_t len=strlen(s); unsigned char *out=(unsigned char*)malloc(len+1); if(!out) return NULL; BIO *b64=BIO_new(BIO_f_base64()), *mem=BIO_new_mem_buf(s,(int)len); if(!b64||!mem){ free(out); if(b64)BIO_free(b64); if(mem)BIO_free(mem); return NULL; } BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); mem=BIO_push(b64,mem); int n=BIO_read(mem,out,(int)len); BIO_free_all(mem); if(n<0){ free(out); return NULL; } if(outlen)*outlen=(size_t)n; return out;
}

static char *qrxdb_pubkey_pem_b64(EVP_PKEY *pkey){
    BIO *mem=BIO_new(BIO_s_mem()); if(!mem) return NULL; if(!PEM_write_bio_PUBKEY(mem,pkey)){ BIO_free(mem); return NULL; } BUF_MEM *b; BIO_get_mem_ptr(mem,&b); char *enc=qrxdb_base64_encode((unsigned char*)b->data,b->length); BIO_free(mem); return enc;
}

static EVP_PKEY *qrxdb_load_priv(const char *path, const char *pass){ FILE *f=fopen(path,"rb"); if(!f) return NULL; EVP_PKEY *p=PEM_read_PrivateKey(f,NULL,NULL,(void*)pass); fclose(f); return p; }
static EVP_PKEY *qrxdb_pub_from_pem_b64(const char *b64){ size_t n=0; unsigned char *pem=qrxdb_base64_decode(b64,&n); if(!pem) return NULL; BIO *mem=BIO_new_mem_buf(pem,(int)n); EVP_PKEY *p=mem?PEM_read_bio_PUBKEY(mem,NULL,NULL,NULL):NULL; if(mem)BIO_free(mem); free(pem); return p; }

static int qrxdb_sign_oneshot(EVP_PKEY *priv, const unsigned char *msg, size_t msglen, unsigned char **sig, size_t *siglen){
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx) return -1; if(EVP_DigestSignInit(ctx,NULL,NULL,NULL,priv)!=1){ EVP_MD_CTX_free(ctx); return -1; } if(EVP_DigestSign(ctx,NULL,siglen,msg,msglen)!=1){ EVP_MD_CTX_free(ctx); return -1; } *sig=(unsigned char*)malloc(*siglen); if(!*sig){ EVP_MD_CTX_free(ctx); return -1; } if(EVP_DigestSign(ctx,*sig,siglen,msg,msglen)!=1){ free(*sig); *sig=NULL; EVP_MD_CTX_free(ctx); return -1; } EVP_MD_CTX_free(ctx); return 0;
}

static int qrxdb_verify_oneshot(EVP_PKEY *pub, const unsigned char *msg, size_t msglen, const unsigned char *sig, size_t siglen){
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx) return -1; if(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,pub)!=1){ EVP_MD_CTX_free(ctx); return -1; } int ok=EVP_DigestVerify(ctx,sig,siglen,msg,msglen); EVP_MD_CTX_free(ctx); return ok==1?0:-1;
}

static int ensure_dir(const char *p){ if(mkdir_local(p) != 0 && errno != EEXIST) return -1; return 0; }

static int qrxdb_write_header(QrxDB *db){
    if(!db || !db->map) return -1;
    QrxDBFileHeader hdr; memset(&hdr,0,sizeof(hdr));
    hdr.magic = QRXDB_DATA_MAGIC;
    hdr.schema_version = QRXDB_SCHEMA_VERSION;
    hdr.header_size = align8(sizeof(QrxDBFileHeader));
    hdr.map_size = db->map_size;
    hdr.write_offset = db->write_offset;
    hdr.generation = db->generation;
    memcpy(hdr.merkle_root, db->merkle_root, QRXDB_MERKLE_HASH_SIZE);
    hdr.crc32 = qrxdb_crc32(&hdr, offsetof(QrxDBFileHeader, crc32));
    memcpy(db->map, &hdr, sizeof(hdr));
    return 0;
}

static int qrxdb_read_header(QrxDB *db){
    QrxDBFileHeader hdr;
    if(!db || !db->map || db->map_size < sizeof(hdr)) return -1;
    memcpy(&hdr, db->map, sizeof(hdr));
    if(hdr.magic != QRXDB_DATA_MAGIC || hdr.schema_version > QRXDB_SCHEMA_VERSION) return -1;
    uint32_t old = hdr.crc32; hdr.crc32 = 0;
    if(old != qrxdb_crc32(&hdr, offsetof(QrxDBFileHeader, crc32))) return -1;
    if(hdr.write_offset < align8(sizeof(QrxDBFileHeader)) || hdr.write_offset > db->map_size) return -1;
    db->write_offset = hdr.write_offset;
    db->generation = hdr.generation;
    memcpy(db->merkle_root, hdr.merkle_root, QRXDB_MERKLE_HASH_SIZE);
    return 0;
}

static int qrxdb_map_open(QrxDB *db, uint64_t initial_size){
#ifdef _WIN32
    HANDLE fh = CreateFileA(db->data_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(fh == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER cur;
    if(!GetFileSizeEx(fh, &cur)){ CloseHandle(fh); return -1; }
    if((uint64_t)cur.QuadPart < initial_size){ LARGE_INTEGER sz; sz.QuadPart = (LONGLONG)initial_size; SetFilePointerEx(fh, sz, NULL, FILE_BEGIN); SetEndOfFile(fh); cur = sz; }
    HANDLE mh = CreateFileMappingA(fh, NULL, PAGE_READWRITE, (DWORD)((uint64_t)cur.QuadPart >> 32), (DWORD)((uint64_t)cur.QuadPart & 0xffffffffu), NULL);
    if(!mh){ CloseHandle(fh); return -1; }
    db->map = MapViewOfFile(mh, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if(!db->map){ CloseHandle(mh); CloseHandle(fh); return -1; }
    db->file_handle = fh; db->mapping_handle = mh; db->map_size = (uint64_t)cur.QuadPart;
#else
    db->fd = open(db->data_path, O_RDWR | O_CREAT, 0600);
    if(db->fd < 0) return -1;
    off_t cur = lseek(db->fd, 0, SEEK_END);
    if(cur < 0) return -1;
    if((uint64_t)cur < initial_size){ if(ftruncate(db->fd, (off_t)initial_size) != 0) return -1; cur = (off_t)initial_size; }
    db->map = mmap(NULL, (size_t)cur, PROT_READ|PROT_WRITE, MAP_SHARED, db->fd, 0);
    if(db->map == MAP_FAILED){ db->map = NULL; return -1; }
    db->map_size = (uint64_t)cur;
#endif
    return 0;
}

int qrxdb_sync(QrxDB *db){
    if(!db || !db->map) return -1;
    qrxdb_write_header(db);
#ifdef _WIN32
    if(!FlushViewOfFile(db->map, 0)) return -1;
    return FlushFileBuffers((HANDLE)db->file_handle) ? 0 : -1;
#else
    if(msync(db->map, (size_t)db->map_size, MS_SYNC) != 0) return -1;
    return fsync(db->fd);
#endif
}

static int qrxdb_remap(QrxDB *db, uint64_t new_size){
    if(new_size <= db->map_size) return 0;
    qrxdb_write_header(db); qrxdb_sync(db);
#ifdef _WIN32
    if(db->map) UnmapViewOfFile(db->map);
    if(db->mapping_handle) CloseHandle((HANDLE)db->mapping_handle);
    LARGE_INTEGER sz; sz.QuadPart = (LONGLONG)new_size;
    SetFilePointerEx((HANDLE)db->file_handle, sz, NULL, FILE_BEGIN); SetEndOfFile((HANDLE)db->file_handle);
    HANDLE mh = CreateFileMappingA((HANDLE)db->file_handle, NULL, PAGE_READWRITE, (DWORD)(new_size >> 32), (DWORD)(new_size & 0xffffffffu), NULL);
    if(!mh) return -1;
    db->map = MapViewOfFile(mh, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if(!db->map){ CloseHandle(mh); return -1; }
    db->mapping_handle = mh; db->map_size = new_size;
#else
    if(db->map) munmap(db->map, (size_t)db->map_size);
    if(ftruncate(db->fd, (off_t)new_size) != 0) return -1;
    db->map = mmap(NULL, (size_t)new_size, PROT_READ|PROT_WRITE, MAP_SHARED, db->fd, 0);
    if(db->map == MAP_FAILED){ db->map = NULL; return -1; }
    db->map_size = new_size;
#endif
    return qrxdb_write_header(db);
}

static int qrxdb_ensure_space(QrxDB *db, uint64_t need){
    uint64_t end = db->write_offset + need;
    if(end <= db->map_size) return 0;
    uint64_t ns = db->map_size ? db->map_size : QRXDB_DEFAULT_MAP_SIZE;
    while(ns < end) ns *= 2ULL;
    return qrxdb_remap(db, ns);
}

static void wal_segment_path(QrxDB *db, uint64_t id, char *out, size_t out_sz){ snprintf(out,out_sz,"%s%sstate-%06llu.qwal",db->wal_dir,SEP,(unsigned long long)id); }
static int wal_open_current(QrxDB *db){
    if(db->wal_segment_id == 0) db->wal_segment_id = 1;
    wal_segment_path(db, db->wal_segment_id, db->wal_path, sizeof(db->wal_path));
    FILE *f = fopen(db->wal_path, "ab+"); if(!f) return -1;
    fseek(f,0,SEEK_END); db->wal_segment_offset = (uint64_t)ftell(f); fclose(f); return 0;
}
static int wal_rotate_if_needed(QrxDB *db, uint64_t add){ if(db->wal_segment_offset + add <= QRXDB_WAL_SEGMENT_SIZE) return 0; db->wal_segment_id++; db->wal_segment_offset = 0; return wal_open_current(db); }

static int wal_write_record(QrxDB *db, uint32_t type, uint64_t gen, uint64_t off, const char *key, uint32_t klen, const char *val, uint32_t vlen){
    uint64_t sz = sizeof(QrxDBWalHeader) + klen + vlen;
    if(wal_rotate_if_needed(db, sz) != 0) return -1;
    FILE *f = fopen(db->wal_path, "ab"); if(!f) return -1;
    QrxDBWalHeader wh; memset(&wh,0,sizeof(wh));
    wh.magic = QRXDB_WAL_MAGIC; wh.type = type; wh.generation = gen; wh.offset = off; wh.key_len = klen; wh.value_len = vlen;
    wh.crc32 = record_crc(key ? key : "", klen, val ? val : "", vlen) ^ qrxdb_crc32(&wh, offsetof(QrxDBWalHeader, crc32));
    int ok = fwrite(&wh,sizeof(wh),1,f)==1;
    if(ok && klen) ok = fwrite(key,1,klen,f)==klen;
    if(ok && vlen) ok = fwrite(val,1,vlen,f)==vlen;
    fflush(f);
#ifndef _WIN32
    fsync(fileno(f));
#endif
    fclose(f);
    if(!ok) return -1;
    db->wal_segment_offset += sz;
    return 0;
}

static int qrxdb_index_upsert(QrxDB *db, const char *key, uint32_t klen, uint64_t offset, uint64_t gen){
    for(size_t i=0;i<db->index_count;i++) if(db->index[i].key_len==klen && memcmp(db->index[i].key,key,klen)==0){ db->index[i].offset=offset; db->index[i].generation=gen; return 0; }
    if(db->index_count == db->index_cap){ size_t nc = db->index_cap ? db->index_cap*2 : 128; QrxDBIndexEntry *ne = (QrxDBIndexEntry*)realloc(db->index, nc*sizeof(QrxDBIndexEntry)); if(!ne) return -1; db->index=ne; db->index_cap=nc; }
    char *nk=(char*)malloc(klen+1); if(!nk) return -1; memcpy(nk,key,klen); nk[klen]=0;
    db->index[db->index_count].key=nk; db->index[db->index_count].key_len=klen; db->index[db->index_count].offset=offset; db->index[db->index_count].generation=gen; db->index_count++;
    return 0;
}

static void qrxdb_index_clear(QrxDB *db){ if(!db) return; for(size_t i=0;i<db->index_count;i++) free(db->index[i].key); free(db->index); db->index=NULL; db->index_count=0; db->index_cap=0; }
static int qrxdb_index_find(QrxDB *db, const char *key, uint32_t klen, uint64_t *off){ for(size_t i=0;i<db->index_count;i++) if(db->index[i].key_len==klen && memcmp(db->index[i].key,key,klen)==0){ if(off) *off=db->index[i].offset; return 0; } return -1; }

static int append_index_disk(QrxDB *db, const char *key, uint32_t klen, uint64_t offset, uint64_t generation){
    FILE *f = fopen(db->index_path,"ab"); if(!f) return -1;
    int ok = fwrite(&klen,sizeof(klen),1,f)==1 && fwrite(key,1,klen,f)==klen && fwrite(&offset,sizeof(offset),1,f)==1 && fwrite(&generation,sizeof(generation),1,f)==1;
    fflush(f);
#ifndef _WIN32
    fsync(fileno(f));
#endif
    fclose(f); return ok ? 0 : -1;
}

static int write_data_record(QrxDB *db, const char *key, uint32_t klen, const char *val, uint32_t vlen, uint64_t gen, uint64_t *out_offset){
    if(klen > QRXDB_MAX_KEY_SIZE || vlen > QRXDB_MAX_VALUE_SIZE) return -1;
    QrxDBRecordHeader hdr; memset(&hdr,0,sizeof(hdr));
    hdr.magic = QRXDB_MAGIC; hdr.schema_version = QRXDB_SCHEMA_VERSION; hdr.timestamp = gen; hdr.key_len = klen; hdr.value_len = vlen; hdr.crc32 = record_crc(key,klen,val,vlen);
    uint64_t recsz = align8(sizeof(hdr) + (uint64_t)klen + (uint64_t)vlen);
    if(qrxdb_ensure_space(db, recsz) != 0) return -1;
    uint64_t off = db->write_offset;
    unsigned char *ptr = (unsigned char*)db->map + off;
    memcpy(ptr,&hdr,sizeof(hdr)); ptr += sizeof(hdr);
    memcpy(ptr,key,klen); ptr += klen;
    memcpy(ptr,val,vlen);
    if(recsz > sizeof(hdr)+klen+vlen) memset((unsigned char*)db->map + off + sizeof(hdr)+klen+vlen,0,(size_t)(recsz-(sizeof(hdr)+klen+vlen)));
    db->write_offset += recsz; db->generation = gen;
    if(qrxdb_index_upsert(db,key,klen,off,gen)!=0) return -1;
    append_index_disk(db,key,klen,off,gen);
    if(out_offset) *out_offset = off;
    return 0;
}

static int read_record_at(QrxDB *db, uint64_t off, QrxDBRecordHeader *hdr, const char **k, const char **v, uint64_t limit){
    if(!db || !db->map || off + sizeof(QrxDBRecordHeader) > limit) return -1;
    memcpy(hdr, (unsigned char*)db->map + off, sizeof(*hdr));
    if(hdr->magic != QRXDB_MAGIC || hdr->schema_version > QRXDB_SCHEMA_VERSION || hdr->key_len > QRXDB_MAX_KEY_SIZE || hdr->value_len > QRXDB_MAX_VALUE_SIZE) return -1;
    uint64_t end = off + sizeof(*hdr) + hdr->key_len + hdr->value_len;
    if(end > limit) return -1;
    *k = (const char*)db->map + off + sizeof(*hdr); *v = *k + hdr->key_len;
    if(hdr->crc32 != record_crc(*k,hdr->key_len,*v,hdr->value_len)) return -1;
    return 0;
}

static int scan_valid_tail(QrxDB *db, uint64_t limit, uint64_t *last_good, uint64_t *last_gen){
    uint64_t off = align8(sizeof(QrxDBFileHeader)), gen = 0;
    while(off + sizeof(QrxDBRecordHeader) <= limit){
        QrxDBRecordHeader hdr; const char *k=NULL,*v=NULL;
        if(read_record_at(db,off,&hdr,&k,&v,limit)!=0) break;
        off = align8(off + sizeof(hdr) + hdr.key_len + hdr.value_len); gen = hdr.timestamp;
    }
    if(last_good) *last_good = off; if(last_gen) *last_gen = gen; return 0;
}

static int kv_upsert(QrxDBKV **arr, size_t *count, size_t *cap, const char *k, uint32_t kl, const char *v, uint32_t vl, uint64_t off, uint64_t gen){
    for(size_t i=0;i<*count;i++) if((*arr)[i].key_len==kl && memcmp((*arr)[i].key,k,kl)==0){ char *nv=(char*)malloc(vl+1); if(!nv) return -1; memcpy(nv,v,vl); nv[vl]=0; free((*arr)[i].value); (*arr)[i].value=nv; (*arr)[i].value_len=vl; (*arr)[i].offset=off; (*arr)[i].generation=gen; return 0; }
    if(*count==*cap){ size_t nc=*cap?*cap*2:64; QrxDBKV *na=(QrxDBKV*)realloc(*arr,nc*sizeof(QrxDBKV)); if(!na) return -1; *arr=na; *cap=nc; }
    (*arr)[*count].key=(char*)malloc(kl+1); (*arr)[*count].value=(char*)malloc(vl+1); if(!(*arr)[*count].key || !(*arr)[*count].value) return -1;
    memcpy((*arr)[*count].key,k,kl); (*arr)[*count].key[kl]=0; memcpy((*arr)[*count].value,v,vl); (*arr)[*count].value[vl]=0; (*arr)[*count].key_len=kl; (*arr)[*count].value_len=vl; (*arr)[*count].offset=off; (*arr)[*count].generation=gen; (*count)++; return 0;
}

static int cmp_kv_key(const void *a, const void *b){ const QrxDBKV *ka=(const QrxDBKV*)a, *kb=(const QrxDBKV*)b; uint32_t m=ka->key_len<kb->key_len?ka->key_len:kb->key_len; int r=memcmp(ka->key,kb->key,m); if(r) return r; return (ka->key_len>kb->key_len)-(ka->key_len<kb->key_len); }
static void kv_free(QrxDBKV *items, size_t count){ for(size_t i=0;i<count;i++){ free(items[i].key); free(items[i].value); } free(items); }

static int qrxdb_collect_live(QrxDB *db, uint64_t limit, uint64_t maxgen, QrxDBKV **out, size_t *out_count){
    QrxDBKV *items=NULL; size_t count=0, cap=0; uint64_t off=align8(sizeof(QrxDBFileHeader));
    while(off + sizeof(QrxDBRecordHeader) <= limit){
        QrxDBRecordHeader hdr; const char *k=NULL,*v=NULL;
        if(read_record_at(db,off,&hdr,&k,&v,limit)!=0) break;
        if(hdr.timestamp <= maxgen) if(kv_upsert(&items,&count,&cap,k,hdr.key_len,v,hdr.value_len,off,hdr.timestamp)!=0){ kv_free(items,count); return -1; }
        off = align8(off + sizeof(hdr) + hdr.key_len + hdr.value_len);
    }
    *out=items; *out_count=count; return 0;
}

static int qrxdb_recompute_merkle(QrxDB *db){
    QrxDBKV *items=NULL; size_t count=0; if(qrxdb_collect_live(db, db->write_offset, UINT64_MAX, &items, &count)!=0) return -1;
    if(count==0){ qrxdb_zero_root(db->merkle_root); return 0; }
    qsort(items,count,sizeof(QrxDBKV),cmp_kv_key);
    uint8_t *level=(uint8_t*)malloc(count*QRXDB_MERKLE_HASH_SIZE); if(!level){ kv_free(items,count); return -1; }
    for(size_t i=0;i<count;i++) qrxdb_sha3_512_leaf(level+i*QRXDB_MERKLE_HASH_SIZE, items[i].key, items[i].key_len, items[i].value, items[i].value_len);
    size_t n=count;
    while(n>1){ size_t outn=0; for(size_t i=0;i<n;i+=2){ uint8_t *a=level+i*QRXDB_MERKLE_HASH_SIZE; uint8_t *b=(i+1<n)?level+(i+1)*QRXDB_MERKLE_HASH_SIZE:a; qrxdb_sha3_512_node(level+outn*QRXDB_MERKLE_HASH_SIZE,a,b); outn++; } n=outn; }
    memcpy(db->merkle_root,level,QRXDB_MERKLE_HASH_SIZE); free(level); kv_free(items,count); return 0;
}

int qrxdb_rebuild_index(QrxDB *db){
    if(!db || !db->map) return -1;
    qrxdb_index_clear(db);
    FILE *idx=fopen(db->index_path,"wb"); if(idx) fclose(idx);
    uint64_t off=align8(sizeof(QrxDBFileHeader));
    while(off + sizeof(QrxDBRecordHeader) <= db->write_offset){
        QrxDBRecordHeader hdr; const char *k=NULL,*v=NULL;
        if(read_record_at(db,off,&hdr,&k,&v,db->write_offset)!=0) break;
        if(qrxdb_index_upsert(db,k,hdr.key_len,off,hdr.timestamp)!=0) return -1;
        append_index_disk(db,k,hdr.key_len,off,hdr.timestamp);
        off = align8(off + sizeof(hdr) + hdr.key_len + hdr.value_len);
    }
    return qrxdb_recompute_merkle(db);
}

static int wal_apply_txn_if_needed(QrxDB *db, QrxDBWalTxn *tx){
    if(!tx || !tx->committed || !tx->has_put || tx->generation <= db->generation) return 0;
    uint64_t off=0; if(write_data_record(db, tx->key, tx->key_len, tx->value, tx->value_len, tx->generation, &off)!=0) return -1;
    db->recovered_transactions++;
    return 0;
}

static void wal_txn_free(QrxDBWalTxn *tx){ if(tx){ free(tx->key); free(tx->value); memset(tx,0,sizeof(*tx)); } }

static int wal_replay_file(QrxDB *db, const char *path){
    FILE *f=fopen(path,"rb"); if(!f) return -1;
    QrxDBWalTxn tx; memset(&tx,0,sizeof(tx));
    for(;;){
        QrxDBWalHeader wh; size_t n=fread(&wh,1,sizeof(wh),f); if(n==0) break; if(n!=sizeof(wh)) break;
        if(wh.magic!=QRXDB_WAL_MAGIC || wh.key_len>QRXDB_MAX_KEY_SIZE || wh.value_len>QRXDB_MAX_VALUE_SIZE) break;
        char *k=NULL,*v=NULL;
        if(wh.key_len){ k=(char*)malloc(wh.key_len); if(!k) break; if(fread(k,1,wh.key_len,f)!=wh.key_len){ free(k); break; } }
        if(wh.value_len){ v=(char*)malloc(wh.value_len); if(!v){ free(k); break; } if(fread(v,1,wh.value_len,f)!=wh.value_len){ free(k); free(v); break; } }
        uint32_t got=wh.crc32; wh.crc32=0;
        uint32_t want = record_crc(k?k:"", wh.key_len, v?v:"", wh.value_len) ^ qrxdb_crc32(&wh, offsetof(QrxDBWalHeader, crc32));
        if(got!=want){ free(k); free(v); break; }
        if(wh.type==QRXDB_WAL_BEGIN){ wal_txn_free(&tx); tx.generation=wh.generation; }
        else if(wh.type==QRXDB_WAL_PUT && tx.generation==wh.generation){ free(tx.key); free(tx.value); tx.key=k; tx.value=v; tx.key_len=wh.key_len; tx.value_len=wh.value_len; tx.has_put=1; k=NULL; v=NULL; }
        else if(wh.type==QRXDB_WAL_COMMIT && tx.generation==wh.generation){ tx.committed=1; if(wal_apply_txn_if_needed(db,&tx)!=0){ free(k); free(v); wal_txn_free(&tx); fclose(f); return -1; } wal_txn_free(&tx); }
        free(k); free(v);
    }
    wal_txn_free(&tx); fclose(f); return 0;
}

static int wal_replay_all(QrxDB *db){
#ifndef _WIN32
    DIR *d=opendir(db->wal_dir); if(!d) return 0;
    uint64_t *ids=NULL; size_t count=0,cap=0; struct dirent *e;
    while((e=readdir(d))!=NULL){ unsigned long long id=0; if(sscanf(e->d_name,"state-%llu.qwal",&id)==1){ if(count==cap){ size_t nc=cap?cap*2:16; uint64_t *ni=(uint64_t*)realloc(ids,nc*sizeof(uint64_t)); if(!ni){ closedir(d); free(ids); return -1;} ids=ni; cap=nc;} ids[count++]=(uint64_t)id; if((uint64_t)id>db->wal_segment_id) db->wal_segment_id=(uint64_t)id; } }
    closedir(d);
    for(size_t i=0;i<count;i++) for(size_t j=i+1;j<count;j++) if(ids[j]<ids[i]){ uint64_t t=ids[i]; ids[i]=ids[j]; ids[j]=t; }
    for(size_t i=0;i<count;i++){ char p[1024]; wal_segment_path(db,ids[i],p,sizeof(p)); if(wal_replay_file(db,p)!=0){ free(ids); return -1; } }
    free(ids);
#else
    char p[1024]; for(uint64_t id=1; id<=db->wal_segment_id+128; id++){ wal_segment_path(db,id,p,sizeof(p)); FILE *f=fopen(p,"rb"); if(!f) continue; fclose(f); if(wal_replay_file(db,p)!=0) return -1; }
#endif
    return 0;
}

int qrxdb_recover(QrxDB *db){
    if(!db || !db->map) return -1;
    uint64_t good=align8(sizeof(QrxDBFileHeader)), gen=0;
    scan_valid_tail(db, db->map_size, &good, &gen);
    db->write_offset=good; db->generation=gen;
    if(qrxdb_rebuild_index(db)!=0) return -1;
    if(wal_replay_all(db)!=0) return -1;
    if(qrxdb_rebuild_index(db)!=0) return -1;
    return qrxdb_sync(db);
}

int qrxdb_init(QrxDB *db, const char *chain_dir){
    if(!db || !chain_dir) return -1;
    memset(db,0,sizeof(*db)); ensure_dir(chain_dir);
#ifndef _WIN32
    db->fd=-1;
#endif
    char qrxdb[1024]; build_path(qrxdb,sizeof(qrxdb),chain_dir,"qrxdb");
    snprintf(db->base_path,sizeof(db->base_path),"%s",qrxdb);
    build_path(db->data_path,sizeof(db->data_path),qrxdb,"state.qdb");
    build_path(db->wal_dir,sizeof(db->wal_dir),qrxdb,"wal");
    build_path(db->index_path,sizeof(db->index_path),qrxdb,"index" SEP "state.qix");
    build_path(db->snapshot_path,sizeof(db->snapshot_path),qrxdb,"snapshots");
    if(ensure_dir(qrxdb)!=0) return -1;
    { char p[1024]; build_path(p,sizeof(p),qrxdb,"wal"); if(ensure_dir(p)!=0) return -1; build_path(p,sizeof(p),qrxdb,"index"); if(ensure_dir(p)!=0) return -1; build_path(p,sizeof(p),qrxdb,"snapshots"); if(ensure_dir(p)!=0) return -1; }
    if(qrxdb_map_open(db, QRXDB_DEFAULT_MAP_SIZE)!=0) return -1;
    db->wal_segment_id=1;
#ifndef _WIN32
    DIR *d=opendir(db->wal_dir); if(d){ struct dirent *e; while((e=readdir(d))!=NULL){ unsigned long long id=0; if(sscanf(e->d_name,"state-%llu.qwal",&id)==1 && id>db->wal_segment_id) db->wal_segment_id=(uint64_t)id; } closedir(d); }
#endif
    if(qrxdb_read_header(db)!=0){ db->write_offset=align8(sizeof(QrxDBFileHeader)); db->generation=0; qrxdb_zero_root(db->merkle_root); qrxdb_write_header(db); qrxdb_sync(db); }
    qrxdb_recover(db);
    if(wal_open_current(db)!=0) return -1;
    db->initialized=1; return 0;
}

int qrxdb_put(QrxDB *db, const char *key, const char *value){
    if(!db || !db->initialized || !key || !value) return -1;
    uint32_t klen=(uint32_t)strlen(key), vlen=(uint32_t)strlen(value);
    if(klen==0 || klen>QRXDB_MAX_KEY_SIZE || vlen>QRXDB_MAX_VALUE_SIZE) return -1;
    uint64_t gen=db->generation+1;
    if(wal_write_record(db,QRXDB_WAL_BEGIN,gen,0,NULL,0,NULL,0)!=0) return -1;
    if(wal_write_record(db,QRXDB_WAL_PUT,gen,db->write_offset,key,klen,value,vlen)!=0) return -1;
    if(wal_write_record(db,QRXDB_WAL_COMMIT,gen,0,NULL,0,NULL,0)!=0) return -1;
    uint64_t off=0; if(write_data_record(db,key,klen,value,vlen,gen,&off)!=0) return -1;
    if(qrxdb_recompute_merkle(db)!=0) return -1;
    return qrxdb_sync(db);
}

int qrxdb_get_view_at(QrxDB *db, const QrxDBReadTxn *txn, const char *key, QrxDBView *view){
    if(!db || !db->map || !key || !view) return -1; memset(view,0,sizeof(*view)); uint32_t target=(uint32_t)strlen(key);
    if(!txn){ uint64_t off=0; if(qrxdb_index_find(db,key,target,&off)==0){ QrxDBRecordHeader hdr; const char *k=NULL,*v=NULL; if(read_record_at(db,off,&hdr,&k,&v,db->write_offset)==0){ view->key=k; view->value=v; view->key_len=hdr.key_len; view->value_len=hdr.value_len; view->generation=hdr.timestamp; view->offset=off; return 0; } } }
    uint64_t limit=txn?txn->write_offset:db->write_offset; uint64_t maxgen=txn?txn->generation:UINT64_MAX; uint64_t off=align8(sizeof(QrxDBFileHeader)); int found=0;
    while(off + sizeof(QrxDBRecordHeader) <= limit){ QrxDBRecordHeader hdr; const char *k=NULL,*v=NULL; if(read_record_at(db,off,&hdr,&k,&v,limit)!=0) break; if(hdr.timestamp<=maxgen && hdr.key_len==target && memcmp(k,key,target)==0){ view->key=k; view->value=v; view->key_len=hdr.key_len; view->value_len=hdr.value_len; view->generation=hdr.timestamp; view->offset=off; found=1; } off=align8(off+sizeof(hdr)+hdr.key_len+hdr.value_len); }
    return found?0:-1;
}
int qrxdb_get_view(QrxDB *db, const char *key, QrxDBView *view){ return qrxdb_get_view_at(db,NULL,key,view); }
int qrxdb_get(QrxDB *db, const char *key, char *out, size_t out_sz){ if(!out||out_sz==0) return -1; QrxDBView v; if(qrxdb_get_view(db,key,&v)!=0) return -1; size_t n=v.value_len<out_sz-1?v.value_len:out_sz-1; memcpy(out,v.value,n); out[n]=0; return 0; }
int qrxdb_read_txn_begin(QrxDB *db, QrxDBReadTxn *txn){ if(!db||!txn) return -1; txn->generation=db->generation; txn->write_offset=db->write_offset; memcpy(txn->merkle_root,db->merkle_root,QRXDB_MERKLE_HASH_SIZE); return 0; }
int qrxdb_parallel_validation_prepare(QrxDB *db, QrxDBReadTxn *snapshot){ return qrxdb_read_txn_begin(db,snapshot); }
const uint8_t *qrxdb_merkle_root(QrxDB *db){ return db?db->merkle_root:NULL; }
uint64_t qrxdb_generation(QrxDB *db){ return db?db->generation:0; }
uint64_t qrxdb_write_offset(QrxDB *db){ return db?db->write_offset:0; }

int qrxdb_verify(QrxDB *db){
    if(!db || !db->map) return -1;
    uint64_t good=0,gen=0; scan_valid_tail(db,db->write_offset,&good,&gen); if(good!=db->write_offset || gen!=db->generation) return -1;
    uint8_t old[QRXDB_MERKLE_HASH_SIZE]; memcpy(old,db->merkle_root,QRXDB_MERKLE_HASH_SIZE); if(qrxdb_recompute_merkle(db)!=0) return -1; int ok=memcmp(old,db->merkle_root,QRXDB_MERKLE_HASH_SIZE)==0; memcpy(db->merkle_root,old,QRXDB_MERKLE_HASH_SIZE); return ok?0:-1;
}

int qrxdb_snapshot(QrxDB *db, const char *snapshot_name){
    if(!db || !snapshot_name) return -1; if(qrxdb_sync(db)!=0) return -1;
    char dstf[1024], metaf[1024]; snprintf(dstf,sizeof(dstf),"%s%s%s.qsnap",db->snapshot_path,SEP,snapshot_name); snprintf(metaf,sizeof(metaf),"%s%s%s.meta",db->snapshot_path,SEP,snapshot_name);
    FILE *src=fopen(db->data_path,"rb"); if(!src) return -1; FILE *dst=fopen(dstf,"wb"); if(!dst){ fclose(src); return -1; }
    char buf[65536]; uint64_t left=db->write_offset; int ok=1; while(left){ size_t want=left<sizeof(buf)?(size_t)left:sizeof(buf); size_t n=fread(buf,1,want,src); if(n!=want){ ok=0; break; } if(fwrite(buf,1,n,dst)!=n){ ok=0; break; } left-=n; }
    fflush(dst);
#ifndef _WIN32
    fsync(fileno(dst));
#endif
    fclose(src); fclose(dst); if(!ok) return -1;
    uint8_t snap_hash[QRXDB_MERKLE_HASH_SIZE], payload_hash[QRXDB_MERKLE_HASH_SIZE];
    char snap_hash_hex[129], payload_hash_hex[129], root_hex[129];
    if(qrxdb_sha3_512_file(dstf, snap_hash)!=0) return -1;
    qrxdb_hex64(snap_hash, snap_hash_hex); qrxdb_hex64(db->merkle_root, root_hex);
    char meta[2048]; int n=snprintf(meta,sizeof(meta),
        "format=qrxdb-snapshot-v2\n"
        "signature_scheme=optional-ed25519+mldsa65\n"
        "hash_algo=sha3-512\n"
        "snapshot_name=%s\n"
        "generation=%llu\n"
        "write_offset=%llu\n"
        "merkle_root=%s\n"
        "snapshot_sha3_512=%s\n",
        snapshot_name,(unsigned long long)db->generation,(unsigned long long)db->write_offset,root_hex,snap_hash_hex);
    if(n<0 || (size_t)n>=sizeof(meta)) return -1;
    if(qrxdb_sha3_512_buf((unsigned char*)meta,(size_t)n,payload_hash)!=0) return -1;
    qrxdb_hex64(payload_hash,payload_hash_hex);
    FILE *mf=fopen(metaf,"wb"); if(!mf) return -1;
    fwrite(meta,1,(size_t)n,mf);
    fprintf(mf,"signed_payload_sha3_512=%s\n",payload_hash_hex);
    fclose(mf);
    return 0;
}

int qrxdb_snapshot_signed(QrxDB *db, const char *snapshot_name, const char *wallet_dir, const char *passphrase){
    if(!db || !snapshot_name || !wallet_dir) return -1;
    if(qrxdb_snapshot(db, snapshot_name)!=0) return -1;
    char metaf[1024], sigf[1024], edp[1024], mlp[1024];
    snprintf(metaf,sizeof(metaf),"%s%s%s.meta",db->snapshot_path,SEP,snapshot_name);
    snprintf(sigf,sizeof(sigf),"%s%s%s.sig",db->snapshot_path,SEP,snapshot_name);
    snprintf(edp,sizeof(edp),"%s%sed25519_priv.pem",wallet_dir,SEP);
    snprintf(mlp,sizeof(mlp),"%s%smldsa65_priv.pem",wallet_dir,SEP);
    size_t metalen=0; char *meta=qrxdb_read_all(metaf,&metalen); if(!meta) return -1;
    char *payload_hash=qrxdb_cfg_get(meta,"signed_payload_sha3_512"); if(!payload_hash){ free(meta); return -1; }
    const char *pass = passphrase ? passphrase : "";
    EVP_PKEY *ed=qrxdb_load_priv(edp,pass), *ml=qrxdb_load_priv(mlp,pass);
    if(!ed || !ml){ if(ed)EVP_PKEY_free(ed); if(ml)EVP_PKEY_free(ml); free(meta); free(payload_hash); return -1; }
    unsigned char *sig_ed=NULL,*sig_ml=NULL; size_t sig_ed_len=0,sig_ml_len=0;
    if(qrxdb_sign_oneshot(ed,(unsigned char*)meta,metalen,&sig_ed,&sig_ed_len)!=0 || qrxdb_sign_oneshot(ml,(unsigned char*)meta,metalen,&sig_ml,&sig_ml_len)!=0){ EVP_PKEY_free(ed); EVP_PKEY_free(ml); free(meta); free(payload_hash); free(sig_ed); free(sig_ml); return -1; }
    char *ed_pub_b64=qrxdb_pubkey_pem_b64(ed), *ml_pub_b64=qrxdb_pubkey_pem_b64(ml), *sig_ed_b64=qrxdb_base64_encode(sig_ed,sig_ed_len), *sig_ml_b64=qrxdb_base64_encode(sig_ml,sig_ml_len);
    if(!ed_pub_b64||!ml_pub_b64||!sig_ed_b64||!sig_ml_b64){ EVP_PKEY_free(ed); EVP_PKEY_free(ml); free(meta); free(payload_hash); free(sig_ed); free(sig_ml); free(ed_pub_b64); free(ml_pub_b64); free(sig_ed_b64); free(sig_ml_b64); return -1; }
    size_t outcap=strlen(ed_pub_b64)+strlen(ml_pub_b64)+strlen(sig_ed_b64)+strlen(sig_ml_b64)+strlen(payload_hash)+1024;
    char *out=(char*)malloc(outcap); if(!out){ return -1; }
    int n=snprintf(out,outcap,
        "format=qrxdb-snapshot-signature-v1\n"
        "scheme=ed25519+mldsa65\n"
        "hash_algo=sha3-512\n"
        "signed_file=%s.meta\n"
        "signed_payload_sha3_512=%s\n"
        "ed25519_pub_pem_b64=%s\n"
        "mldsa65_pub_pem_b64=%s\n"
        "sig_ed25519_b64=%s\n"
        "sig_mldsa65_b64=%s\n", snapshot_name, payload_hash, ed_pub_b64, ml_pub_b64, sig_ed_b64, sig_ml_b64);
    int rc=(n>0 && (size_t)n<outcap)?qrxdb_write_all(sigf,out,(size_t)n):-1;
    EVP_PKEY_free(ed); EVP_PKEY_free(ml); free(meta); free(payload_hash); free(sig_ed); free(sig_ml); free(ed_pub_b64); free(ml_pub_b64); free(sig_ed_b64); free(sig_ml_b64); free(out); return rc;
}

int qrxdb_snapshot_verify_signature(QrxDB *db, const char *snapshot_name){
    if(!db || !snapshot_name) return -1;
    char metaf[1024], sigf[1024], snapf[1024];
    snprintf(metaf,sizeof(metaf),"%s%s%s.meta",db->snapshot_path,SEP,snapshot_name);
    snprintf(sigf,sizeof(sigf),"%s%s%s.sig",db->snapshot_path,SEP,snapshot_name);
    snprintf(snapf,sizeof(snapf),"%s%s%s.qsnap",db->snapshot_path,SEP,snapshot_name);
    size_t metalen=0; char *meta=qrxdb_read_all(metaf,&metalen); char *sig=qrxdb_read_all(sigf,NULL); if(!meta||!sig){ free(meta); free(sig); return -1; }
    char *snapshot_hash_meta=qrxdb_cfg_get(meta,"snapshot_sha3_512"); char *payload_hash_meta=qrxdb_cfg_get(meta,"signed_payload_sha3_512"); char *payload_hash_sig=qrxdb_cfg_get(sig,"signed_payload_sha3_512");
    char *edpub=qrxdb_cfg_get(sig,"ed25519_pub_pem_b64"), *mlpub=qrxdb_cfg_get(sig,"mldsa65_pub_pem_b64"), *edsig=qrxdb_cfg_get(sig,"sig_ed25519_b64"), *mlsig=qrxdb_cfg_get(sig,"sig_mldsa65_b64");
    int rc=-1; uint8_t snap_hash[64]; char snap_hash_hex[129];
    if(!snapshot_hash_meta||!payload_hash_meta||!payload_hash_sig||!edpub||!mlpub||!edsig||!mlsig) goto done;
    if(strcmp(payload_hash_meta,payload_hash_sig)!=0) goto done;
    if(qrxdb_sha3_512_file(snapf,snap_hash)!=0) goto done; qrxdb_hex64(snap_hash,snap_hash_hex); if(strcmp(snap_hash_hex,snapshot_hash_meta)!=0) goto done;
    EVP_PKEY *ed=qrxdb_pub_from_pem_b64(edpub), *ml=qrxdb_pub_from_pem_b64(mlpub); size_t edsiglen=0, mlsiglen=0; unsigned char *edsigb=qrxdb_base64_decode(edsig,&edsiglen), *mlsigb=qrxdb_base64_decode(mlsig,&mlsiglen);
    if(ed && ml && edsigb && mlsigb && qrxdb_verify_oneshot(ed,(unsigned char*)meta,metalen,edsigb,edsiglen)==0 && qrxdb_verify_oneshot(ml,(unsigned char*)meta,metalen,mlsigb,mlsiglen)==0) rc=0;
    if(ed)EVP_PKEY_free(ed); if(ml)EVP_PKEY_free(ml); free(edsigb); free(mlsigb);
done:
    free(meta); free(sig); free(snapshot_hash_meta); free(payload_hash_meta); free(payload_hash_sig); free(edpub); free(mlpub); free(edsig); free(mlsig); return rc;
}

int qrxdb_compact(QrxDB *db){
    if(!db || !db->initialized) return -1;
    QrxDBReadTxn snap; if(qrxdb_read_txn_begin(db,&snap)!=0) return -1;
    QrxDBKV *items=NULL; size_t count=0; if(qrxdb_collect_live(db,snap.write_offset,snap.generation,&items,&count)!=0) return -1;
    qsort(items,count,sizeof(QrxDBKV),cmp_kv_key);
    char tmp[1024]; snprintf(tmp,sizeof(tmp),"%s.tmp",db->data_path);
    QrxDB ndb; memset(&ndb,0,sizeof(ndb)); snprintf(ndb.data_path,sizeof(ndb.data_path),"%s",tmp); qrxdb_zero_root(ndb.merkle_root); ndb.write_offset=align8(sizeof(QrxDBFileHeader)); ndb.generation=0;
#ifndef _WIN32
    ndb.fd=-1;
#endif
    if(qrxdb_map_open(&ndb, QRXDB_DEFAULT_MAP_SIZE)!=0) goto fail;
    qrxdb_write_header(&ndb);
    for(size_t i=0;i<count;i++){ uint64_t roff; if(write_data_record(&ndb,items[i].key,items[i].key_len,items[i].value,items[i].value_len,++ndb.generation,&roff)!=0) goto fail; }
    ndb.generation=snap.generation; if(qrxdb_recompute_merkle(&ndb)!=0) goto fail; qrxdb_sync(&ndb); qrxdb_close(&ndb);
    qrxdb_close(db);
#ifdef _WIN32
    remove(db->data_path);
#endif
    if(rename(tmp, db->data_path)!=0){ kv_free(items,count); return -1; }
    if(qrxdb_map_open(db, QRXDB_DEFAULT_MAP_SIZE)!=0){ kv_free(items,count); return -1; }
    qrxdb_read_header(db); qrxdb_rebuild_index(db); db->compacted_until_generation=snap.generation; db->initialized=1; wal_open_current(db); kv_free(items,count); return qrxdb_sync(db);
fail:
    kv_free(items,count); qrxdb_close(&ndb); remove(tmp); return -1;
}


int qrxdb_salvage(QrxDB *db){
    if(!db || !db->map) return -1;
    uint64_t good = 0, gen = 0;
    /* First prefer the header write offset; then scan the whole mapped file for a valid tail. */
    if(scan_valid_tail(db, db->write_offset, &good, &gen) != 0 || good < align8(sizeof(QrxDBFileHeader))){
        good = 0; gen = 0;
        if(scan_valid_tail(db, db->map_size, &good, &gen) != 0) return -1;
    }
    if(good < align8(sizeof(QrxDBFileHeader))) return -1;
    db->write_offset = good;
    db->generation = gen;
    if(qrxdb_rebuild_index(db) != 0) return -1;
    if(qrxdb_recompute_merkle(db) != 0) return -1;
    if(qrxdb_write_header(db) != 0) return -1;
    return qrxdb_sync(db);
}

int qrxdb_close(QrxDB *db){
    if(!db) return -1;
    if(db->map) qrxdb_write_header(db);
#ifdef _WIN32
    if(db->map){ FlushViewOfFile(db->map,0); UnmapViewOfFile(db->map); }
    if(db->mapping_handle) CloseHandle((HANDLE)db->mapping_handle);
    if(db->file_handle) CloseHandle((HANDLE)db->file_handle);
#else
    if(db->map){ msync(db->map,(size_t)db->map_size,MS_SYNC); munmap(db->map,(size_t)db->map_size); }
    if(db->fd >= 0) close(db->fd);
#endif
    qrxdb_index_clear(db); db->map=NULL; db->initialized=0; return 0;
}

static int qrxdb_put_fmt(QrxDB *db, const char *key, const char *fmt, ...){
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if(n < 0) return -1;
    if((size_t)n < sizeof(buf)) return qrxdb_put(db, key, buf);
    char *dyn = (char*)malloc((size_t)n + 1);
    if(!dyn) return -1;
    va_start(ap, fmt); vsnprintf(dyn, (size_t)n + 1, fmt, ap); va_end(ap);
    int rc = qrxdb_put(db, key, dyn);
    free(dyn);
    return rc;
}

int qrxdb_chain_put_block(QrxDB *db, uint64_t height, const char *block_hash, const char *block_text){
    if(!db || !block_hash || !block_text) return -1;
    char k_block[256], k_height[96], k_meta[256];
    snprintf(k_block, sizeof(k_block), "block:hash:%s", block_hash);
    snprintf(k_height, sizeof(k_height), "block:height:%020llu", (unsigned long long)height);
    snprintf(k_meta, sizeof(k_meta), "block:meta:%s", block_hash);
    if(qrxdb_put(db, k_block, block_text) != 0) return -1;
    if(qrxdb_put(db, k_height, block_hash) != 0) return -1;
    return qrxdb_put_fmt(db, k_meta, "height=%llu\nhash=%s\n", (unsigned long long)height, block_hash);
}

int qrxdb_chain_index_tx(QrxDB *db, const char *tx_hash, const char *block_hash, uint64_t height, uint32_t tx_index, const char *tx_text){
    if(!db || !tx_hash || !block_hash) return -1;
    char k_loc[256], k_payload[256];
    snprintf(k_loc, sizeof(k_loc), "tx:loc:%s", tx_hash);
    if(qrxdb_put_fmt(db, k_loc, "tx_hash=%s\nblock_hash=%s\nheight=%llu\nindex=%u\n", tx_hash, block_hash, (unsigned long long)height, tx_index) != 0) return -1;
    if(tx_text && *tx_text){
        snprintf(k_payload, sizeof(k_payload), "tx:payload:%s", tx_hash);
        if(qrxdb_put(db, k_payload, tx_text) != 0) return -1;
    }
    return 0;
}

int qrxdb_chain_get_block_by_hash(QrxDB *db, const char *block_hash, QrxDBView *view){
    if(!db || !block_hash || !view) return -1;
    char key[256]; snprintf(key, sizeof(key), "block:hash:%s", block_hash);
    return qrxdb_get_view(db, key, view);
}

int qrxdb_chain_get_block_hash_by_height(QrxDB *db, uint64_t height, char *out_hash, size_t out_sz){
    if(!db || !out_hash || out_sz == 0) return -1;
    char key[96]; snprintf(key, sizeof(key), "block:height:%020llu", (unsigned long long)height);
    return qrxdb_get(db, key, out_hash, out_sz);
}

int qrxdb_chain_get_tx_location(QrxDB *db, const char *tx_hash, char *out, size_t out_sz){
    if(!db || !tx_hash || !out || out_sz == 0) return -1;
    char key[256]; snprintf(key, sizeof(key), "tx:loc:%s", tx_hash);
    return qrxdb_get(db, key, out, out_sz);
}

static int qrxdb_chain_set_ll(QrxDB *db, const char *prefix, const char *name, long long value){
    if(!db || !prefix || !name) return -1;
    char key[512], val[64]; snprintf(key, sizeof(key), "%s:%s", prefix, name); snprintf(val, sizeof(val), "%lld", value);
    return qrxdb_put(db, key, val);
}
static int qrxdb_chain_get_ll(QrxDB *db, const char *prefix, const char *name, long long *out_value){
    if(!db || !prefix || !name || !out_value) return -1;
    char key[512], val[128]; snprintf(key, sizeof(key), "%s:%s", prefix, name);
    if(qrxdb_get(db, key, val, sizeof(val)) != 0) return -1;
    *out_value = atoll(val); return 0;
}
int qrxdb_chain_set_balance(QrxDB *db, const char *address, long long value){ return qrxdb_chain_set_ll(db, "acct:balance", address, value); }
int qrxdb_chain_get_balance(QrxDB *db, const char *address, long long *out_value){ return qrxdb_chain_get_ll(db, "acct:balance", address, out_value); }
int qrxdb_chain_set_nonce(QrxDB *db, const char *address, long long value){ return qrxdb_chain_set_ll(db, "acct:nonce", address, value); }
int qrxdb_chain_get_nonce(QrxDB *db, const char *address, long long *out_value){ return qrxdb_chain_get_ll(db, "acct:nonce", address, out_value); }

int qrxdb_chain_mark_applied(QrxDB *db, const char *tx_hash, uint64_t height){
    if(!db || !tx_hash) return -1;
    char key[256]; snprintf(key, sizeof(key), "tx:applied:%s", tx_hash);
    return qrxdb_put_fmt(db, key, "height=%llu\napplied=1\n", (unsigned long long)height);
}
int qrxdb_chain_is_applied(QrxDB *db, const char *tx_hash){
    if(!db || !tx_hash) return 0;
    char key[256]; QrxDBView v; snprintf(key, sizeof(key), "tx:applied:%s", tx_hash);
    return qrxdb_get_view(db, key, &v) == 0 ? 1 : 0;
}

int qrxdb_chain_put_utxo(QrxDB *db, const char *tx_hash, uint32_t vout, const char *owner, long long amount, uint64_t height){
    if(!db || !tx_hash || !owner) return -1;
    char key[300]; snprintf(key, sizeof(key), "utxo:%s:%u", tx_hash, vout);
    return qrxdb_put_fmt(db, key, "tx_hash=%s\nvout=%u\nowner=%s\namount=%lld\nheight=%llu\nspent=0\n", tx_hash, vout, owner, amount, (unsigned long long)height);
}
int qrxdb_chain_spend_utxo(QrxDB *db, const char *tx_hash, uint32_t vout, const char *spend_tx_hash, uint64_t height){
    if(!db || !tx_hash || !spend_tx_hash) return -1;
    char key[300]; snprintf(key, sizeof(key), "utxo:%s:%u", tx_hash, vout);
    return qrxdb_put_fmt(db, key, "tx_hash=%s\nvout=%u\nspent=1\nspent_by=%s\nspent_height=%llu\n", tx_hash, vout, spend_tx_hash, (unsigned long long)height);
}
int qrxdb_chain_get_utxo(QrxDB *db, const char *tx_hash, uint32_t vout, char *out, size_t out_sz){
    if(!db || !tx_hash || !out || out_sz == 0) return -1;
    char key[300]; snprintf(key, sizeof(key), "utxo:%s:%u", tx_hash, vout);
    return qrxdb_get(db, key, out, out_sz);
}
