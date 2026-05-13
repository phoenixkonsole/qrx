#pragma once

typedef struct qrxdb qrxdb_t;

int qrxdb_flush_wal(qrxdb_t *db);
int qrxdb_mmap_sync(qrxdb_t *db);
int qrxdb_commit_generation(qrxdb_t *db);
int qrxdb_stop_compaction(qrxdb_t *db);
int qrxdb_close(qrxdb_t *db);

int qrxdb_graceful_shutdown(qrxdb_t *db);
