#include <stdio.h>
#include <string.h>
#include "qrxdb.h"

static void print_root(const unsigned char *r){ for(int i=0;i<QRXDB_MERKLE_HASH_SIZE;i++) printf("%02x", r[i]); }

int main(int argc, char **argv){
    if(argc != 2 && argc != 4){ fprintf(stderr,"usage: qrxdb_verify <chain-dir> [--snapshot-signature <label>]\n"); return 2; }
    QrxDB db; memset(&db,0,sizeof(db));
    if(qrxdb_init(&db, argv[1]) != 0){ fprintf(stderr,"qrxdb_verify: open failed\n"); return 1; }
    int rc = qrxdb_verify(&db);
    if(rc == 0){
        printf("OK generation=%llu write_offset=%llu merkle_sha3_512=", (unsigned long long)qrxdb_generation(&db), (unsigned long long)qrxdb_write_offset(&db));
        print_root(qrxdb_merkle_root(&db));
        printf("\n");
    } else {
        printf("FAIL generation=%llu write_offset=%llu\n", (unsigned long long)qrxdb_generation(&db), (unsigned long long)qrxdb_write_offset(&db));
        qrxdb_close(&db); return 1;
    }
    if(argc == 4){
        if(strcmp(argv[2],"--snapshot-signature") != 0){ fprintf(stderr,"unknown option: %s\n", argv[2]); qrxdb_close(&db); return 2; }
        if(qrxdb_snapshot_verify_signature(&db, argv[3]) == 0) printf("OK snapshot_signature=%s scheme=ed25519+mldsa65\n", argv[3]);
        else { printf("FAIL snapshot_signature=%s\n", argv[3]); qrxdb_close(&db); return 1; }
    }
    qrxdb_close(&db);
    return 0;
}
