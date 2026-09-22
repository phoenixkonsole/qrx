#ifndef QRX_THREADS_H
#define QRX_THREADS_H

/* The storage workers need only joinable threads, non-recursive mutexes and
 * absolute UTC condition waits. Keep POSIX on Unix and use native Windows
 * primitives rather than requiring an unbundled pthread DLL. */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <process.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

typedef SRWLOCK qrx_mutex_t;
typedef CONDITION_VARIABLE qrx_cond_t;
typedef struct qrx_thread_state {
    HANDLE handle;
    void *(*function)(void *);
    void *argument;
    void *result;
} *qrx_thread_t;

static unsigned __stdcall qrx_thread_entry(void *argument) {
    qrx_thread_t thread = (qrx_thread_t)argument;
    thread->result = thread->function(thread->argument);
    return 0;
}
static int qrx_thread_create(qrx_thread_t *out, const void *attributes,
                             void *(*function)(void *), void *argument) {
    if (!out || !function || attributes) return EINVAL;
    qrx_thread_t thread = (qrx_thread_t)calloc(1, sizeof(*thread));
    if (!thread) return ENOMEM;
    thread->function = function;
    thread->argument = argument;
    thread->handle = (HANDLE)_beginthreadex(NULL, 0, qrx_thread_entry, thread, 0, NULL);
    if (!thread->handle) { free(thread); return EAGAIN; }
    *out = thread;
    return 0;
}
static int qrx_thread_join(qrx_thread_t thread, void **result) {
    if (!thread || WaitForSingleObject(thread->handle, INFINITE) != WAIT_OBJECT_0) return EINVAL;
    if (result) *result = thread->result;
    CloseHandle(thread->handle);
    free(thread);
    return 0;
}
static int qrx_mutex_init(qrx_mutex_t *mutex, const void *attributes) {
    if (attributes) return EINVAL;
    InitializeSRWLock(mutex);
    return 0;
}
static int qrx_mutex_lock(qrx_mutex_t *mutex) { AcquireSRWLockExclusive(mutex); return 0; }
static int qrx_mutex_unlock(qrx_mutex_t *mutex) { ReleaseSRWLockExclusive(mutex); return 0; }
static int qrx_mutex_destroy(qrx_mutex_t *mutex) { (void)mutex; return 0; }
static int qrx_cond_init(qrx_cond_t *condition, const void *attributes) {
    if (attributes) return EINVAL;
    InitializeConditionVariable(condition);
    return 0;
}
static int qrx_cond_broadcast(qrx_cond_t *condition) { WakeAllConditionVariable(condition); return 0; }
static int qrx_cond_destroy(qrx_cond_t *condition) { (void)condition; return 0; }
static int qrx_cond_timedwait(qrx_cond_t *condition, qrx_mutex_t *mutex,
                            const struct timespec *deadline) {
    struct timespec now;
    if (!deadline || deadline->tv_nsec < 0 || deadline->tv_nsec >= 1000000000L ||
        timespec_get(&now, TIME_UTC) != TIME_UTC) return EINVAL;
    long long seconds = (long long)deadline->tv_sec - (long long)now.tv_sec;
    DWORD timeout;
    if (seconds < 0) timeout = 0;
    else if (seconds >= (long long)(INFINITE - 1) / 1000) timeout = INFINITE - 1;
    else {
        long long ns = seconds * 1000000000LL + deadline->tv_nsec - now.tv_nsec;
        timeout = ns <= 0 ? 0 : (DWORD)((ns + 999999LL) / 1000000LL);
    }
    if (SleepConditionVariableSRW(condition, mutex, timeout, 0)) return 0;
    return GetLastError() == ERROR_TIMEOUT ? ETIMEDOUT : EINVAL;
}
#else
#include <pthread.h>
typedef pthread_t qrx_thread_t;
typedef pthread_mutex_t qrx_mutex_t;
typedef pthread_cond_t qrx_cond_t;
#define qrx_thread_create pthread_create
#define qrx_thread_join pthread_join
#define qrx_mutex_init pthread_mutex_init
#define qrx_mutex_lock pthread_mutex_lock
#define qrx_mutex_unlock pthread_mutex_unlock
#define qrx_mutex_destroy pthread_mutex_destroy
#define qrx_cond_init pthread_cond_init
#define qrx_cond_broadcast pthread_cond_broadcast
#define qrx_cond_destroy pthread_cond_destroy
#define qrx_cond_timedwait pthread_cond_timedwait
#endif
#endif
