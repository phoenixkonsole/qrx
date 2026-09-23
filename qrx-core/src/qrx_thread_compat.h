#ifndef QRX_THREAD_COMPAT_H
#define QRX_THREAD_COMPAT_H

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

typedef HANDLE pthread_t;
typedef CRITICAL_SECTION pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;

typedef struct {
    void *(*fn)(void *);
    void *arg;
} qrx_win_thread_start;

static unsigned __stdcall qrx_win_thread_entry(void *opaque) {
    qrx_win_thread_start *start=(qrx_win_thread_start*)opaque;
    void *(*fn)(void*)=start->fn;
    void *arg=start->arg;
    free(start);
    fn(arg);
    return 0;
}

static int pthread_create(pthread_t *thread,const void *attr,void *(*fn)(void*),void *arg) {
    (void)attr;
    qrx_win_thread_start *start=(qrx_win_thread_start*)malloc(sizeof(*start));
    if(!start)return -1;
    start->fn=fn;start->arg=arg;
    uintptr_t h=_beginthreadex(NULL,0,qrx_win_thread_entry,start,0,NULL);
    if(!h){free(start);return -1;}
    *thread=(HANDLE)h;
    return 0;
}
static int pthread_join(pthread_t thread,void **result) {
    if(result)*result=NULL;
    if(WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)return -1;
    return CloseHandle(thread)?0:-1;
}
static int pthread_mutex_init(pthread_mutex_t *mutex,const void *attr) {(void)attr;InitializeCriticalSection(mutex);return 0;}
static int pthread_mutex_destroy(pthread_mutex_t *mutex) {DeleteCriticalSection(mutex);return 0;}
static int pthread_mutex_lock(pthread_mutex_t *mutex) {EnterCriticalSection(mutex);return 0;}
static int pthread_mutex_unlock(pthread_mutex_t *mutex) {LeaveCriticalSection(mutex);return 0;}
static int pthread_cond_init(pthread_cond_t *cond,const void *attr) {(void)attr;InitializeConditionVariable(cond);return 0;}
static int pthread_cond_destroy(pthread_cond_t *cond) {(void)cond;return 0;}
static int pthread_cond_broadcast(pthread_cond_t *cond) {WakeAllConditionVariable(cond);return 0;}
static int pthread_cond_timedwait(pthread_cond_t *cond,pthread_mutex_t *mutex,const struct timespec *deadline) {
    struct timespec now;
    timespec_get(&now,TIME_UTC);
    int64_t ms=(int64_t)(deadline->tv_sec-now.tv_sec)*1000+(deadline->tv_nsec-now.tv_nsec)/1000000;
    if(ms<0)ms=0;if(ms>0xffffffffLL)ms=0xffffffffLL;
    return SleepConditionVariableCS(cond,mutex,(DWORD)ms)?0:(GetLastError()==ERROR_TIMEOUT?1:-1);
}
#else
#include <pthread.h>
#endif

#endif
