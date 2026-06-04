#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "qrxdb.h"

static void default_label(char *out, size_t out_sz){
    time_t now=time(NULL); struct tm *tmv=localtime(&now);
    if(tmv) strftime(out,out_sz,"snapshot-%Y%m%d-%H%M%S",tmv); else snprintf(out,out_sz,"snapshot-%llu",(unsigned long long)now);
}

int main(int argc, char **argv){
    if(argc < 2 || argc > 4){ fprintf(stderr,"usage: qrxdb_snapshot <chain-dir> [label] [signing-wallet-dir]\n       set QRX_PASSPHRASE for encrypted wallet keys\n"); return 2; }
    char label[128]; if(argc>=3) snprintf(label,sizeof(label),"%s",argv[2]); else default_label(label,sizeof(label));
    const char *wallet_dir = argc==4 ? argv[3] : NULL;
    const char *pass = getenv("QRX_PASSPHRASE");
    QrxDB db; memset(&db,0,sizeof(db));
    if(qrxdb_init(&db, argv[1]) != 0){ fprintf(stderr,"qrxdb_snapshot: open failed\n"); return 1; }
    if(qrxdb_verify(&db) != 0){ fprintf(stderr,"qrxdb_snapshot: verify failed; refusing snapshot\n"); qrxdb_close(&db); return 1; }
    int rc = wallet_dir ? qrxdb_snapshot_signed(&db,label,wallet_dir,pass) : qrxdb_snapshot(&db,label);
    if(rc != 0){ fprintf(stderr,"qrxdb_snapshot: snapshot%s failed\n", wallet_dir ? " signing" : ""); qrxdb_close(&db); return 1; }
    printf("OK snapshot=%s generation=%llu write_offset=%llu%s\n", label, (unsigned long long)qrxdb_generation(&db), (unsigned long long)qrxdb_write_offset(&db), wallet_dir ? " signed=ed25519+mldsa65" : " signed=no");
    qrxdb_close(&db); return 0;
}
