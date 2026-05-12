#include <stdio.h>
#include <string.h>
#include "qrxdb.h"

int main(int argc, char **argv){
    if(argc != 2){ fprintf(stderr,"usage: qrxdb_salvage <chain-dir>\n"); return 2; }
    QrxDB db; memset(&db,0,sizeof(db));
    if(qrxdb_init(&db, argv[1]) != 0){ fprintf(stderr,"qrxdb_salvage: open failed\n"); return 1; }
    int rc = qrxdb_salvage(&db);
    if(rc == 0) rc = qrxdb_verify(&db);
    printf(rc == 0 ? "OK salvaged generation=%llu write_offset=%llu\n" : "FAIL salvage/verify failed\n", (unsigned long long)qrxdb_generation(&db), (unsigned long long)qrxdb_write_offset(&db));
    qrxdb_close(&db);
    return rc == 0 ? 0 : 1;
}
