#include <stdio.h>
#include <string.h>
#include "qrxdb.h"

int main(int argc, char **argv){
    if(argc != 2){ fprintf(stderr,"usage: qrxdb_compact <chain-dir>\n"); return 2; }
    QrxDB db; memset(&db,0,sizeof(db));
    if(qrxdb_init(&db, argv[1]) != 0){ fprintf(stderr,"qrxdb_compact: open failed\n"); return 1; }
    if(qrxdb_verify(&db) != 0){ fprintf(stderr,"qrxdb_compact: verify failed before compaction; run qrxdb_salvage first\n"); qrxdb_close(&db); return 1; }
    if(qrxdb_compact(&db) != 0){ fprintf(stderr,"qrxdb_compact: compaction failed\n"); qrxdb_close(&db); return 1; }
    int rc = qrxdb_verify(&db);
    printf(rc == 0 ? "OK compacted generation=%llu write_offset=%llu\n" : "FAIL compacted DB did not verify\n", (unsigned long long)qrxdb_generation(&db), (unsigned long long)qrxdb_write_offset(&db));
    qrxdb_close(&db);
    return rc == 0 ? 0 : 1;
}
