#include "qrxdb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

static void fail(const char *m){ fprintf(stderr,"FAIL: %s\n",m); exit(1); }
static void expect_value(QrxDB *db,const char *k,const char *want){ char b[256]; if(qrxdb_get(db,k,b,sizeof(b))!=0) fail("missing key after recovery"); if(strcmp(b,want)!=0) fail("value mismatch after recovery"); }

int main(int argc,char **argv){
    if(argc!=2){ fprintf(stderr,"usage: %s CHAIN_DIR\n",argv[0]); return 2; }
    QrxDB db; if(qrxdb_init(&db,argv[1])!=0) fail("qrxdb_init baseline");
    if(qrxdb_put(&db,"baseline","ok")!=0) fail("baseline put");

    QrxDBBatch b; if(qrxdb_batch_begin(&db,&b)!=0) fail("batch begin");
    if(qrxdb_batch_put(&b,"atomic:a","alpha")!=0 || qrxdb_batch_put(&b,"atomic:b","bravo")!=0 || qrxdb_batch_put(&b,"atomic:c","charlie")!=0) fail("batch put");
    if(b.count!=3) fail("unexpected batch count");
    uint64_t second_offset=b.entries[1].offset;
    uint64_t planned_end=b.planned_end_offset;
    char data_path[1024]; snprintf(data_path,sizeof(data_path),"%s",db.data_path);
    if(qrxdb_batch_commit(&b)!=0) fail("batch commit");
    char committed_root[129]; if(qrxdb_merkle_root_hex(&db,committed_root)!=0) fail("root after commit");
    expect_value(&db,"atomic:a","alpha"); expect_value(&db,"atomic:b","bravo"); expect_value(&db,"atomic:c","charlie");
    if(qrxdb_verify(&db)!=0) fail("verify after commit");
    if(qrxdb_close(&db)!=0) fail("close after commit");

    /* Simulate a power loss after WAL COMMIT but while data records are only
       partly materialized: retain the first record, destroy records 2..N.
       The durable WAL must make the entire generation reappear on reopen. */
    FILE *f=fopen(data_path,"r+b"); if(!f) fail("open data for crash simulation");
    if(fseek(f,(long)second_offset,SEEK_SET)!=0) fail("seek crash offset");
    uint64_t remaining=planned_end-second_offset; unsigned char zero[4096]; memset(zero,0,sizeof(zero));
    while(remaining){ size_t n=remaining>sizeof(zero)?sizeof(zero):(size_t)remaining; if(fwrite(zero,1,n,f)!=n) fail("crash simulation write"); remaining-=n; }
    fflush(f);
#ifdef _WIN32
    _commit(_fileno(f));
#else
    fsync(fileno(f));
#endif
    fclose(f);

    QrxDB recovered; if(qrxdb_init(&recovered,argv[1])!=0) fail("qrxdb_init recovery");
    expect_value(&recovered,"baseline","ok"); expect_value(&recovered,"atomic:a","alpha"); expect_value(&recovered,"atomic:b","bravo"); expect_value(&recovered,"atomic:c","charlie");
    char recovered_root[129]; if(qrxdb_merkle_root_hex(&recovered,recovered_root)!=0) fail("root after recovery");
    if(strcmp(committed_root,recovered_root)!=0){ fprintf(stderr,"committed_root=%s\nrecovered_root=%s\n",committed_root,recovered_root); fail("state root changed after WAL recovery"); }
    if(recovered.recovered_transactions==0) fail("WAL recovery did not report recovered transaction");
    if(qrxdb_verify(&recovered)!=0) fail("verify after WAL recovery");
    printf("PASS: multi-key WAL batch recovered atomically\nstate_root=%s\nrecovered_transactions=%llu\n",recovered_root,(unsigned long long)recovered.recovered_transactions);
    qrxdb_close(&recovered);
    return 0;
}
