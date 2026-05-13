#include "qrxdb_shutdown.h"

int qrxdb_graceful_shutdown(qrxdb_t *db) {
    if(!db) return -1;

    qrxdb_stop_compaction(db);

    if(qrxdb_flush_wal(db) != 0)
        return -1;

    if(qrxdb_mmap_sync(db) != 0)
        return -1;

    if(qrxdb_commit_generation(db) != 0)
        return -1;

    return qrxdb_close(db);
}
