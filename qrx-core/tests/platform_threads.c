#include "platform/qrx_threads.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
enum { WORKERS = 8, ITERATIONS = 10000 };
static qrx_mutex_t mutex;
static qrx_cond_t condition;
static int ready, start, counter;
static struct timespec deadline(void) {
    struct timespec value;
    CHECK(timespec_get(&value, TIME_UTC) == TIME_UTC);
    value.tv_sec += 15;
    return value;
}
static void *worker(void *argument) {
    struct timespec until = deadline();
    CHECK(qrx_mutex_lock(&mutex) == 0);
    ++ready;
    CHECK(qrx_cond_broadcast(&condition) == 0);
    while (!start) CHECK(qrx_cond_timedwait(&condition, &mutex, &until) == 0);
    CHECK(qrx_mutex_unlock(&mutex) == 0);
    for (int i = 0; i < ITERATIONS; ++i) {
        CHECK(qrx_mutex_lock(&mutex) == 0);
        ++counter;
        CHECK(qrx_mutex_unlock(&mutex) == 0);
    }
    return argument;
}
int main(void) {
    qrx_thread_t threads[WORKERS];
    int identities[WORKERS];
    CHECK(qrx_mutex_init(&mutex, NULL) == 0);
    CHECK(qrx_cond_init(&condition, NULL) == 0);
    for (int i = 0; i < WORKERS; ++i) {
        identities[i] = i;
        CHECK(qrx_thread_create(&threads[i], NULL, worker, &identities[i]) == 0);
    }
    CHECK(qrx_mutex_lock(&mutex) == 0);
    struct timespec until = deadline();
    while (ready != WORKERS) CHECK(qrx_cond_timedwait(&condition, &mutex, &until) == 0);
    start = 1;
    CHECK(qrx_cond_broadcast(&condition) == 0);
    CHECK(qrx_mutex_unlock(&mutex) == 0);
    for (int i = 0; i < WORKERS; ++i) {
        void *result = NULL;
        CHECK(qrx_thread_join(threads[i], &result) == 0);
        CHECK(result == &identities[i]);
    }
    CHECK(counter == WORKERS * ITERATIONS);
    CHECK(qrx_mutex_lock(&mutex) == 0);
    CHECK(timespec_get(&until, TIME_UTC) == TIME_UTC);
    --until.tv_sec;
    CHECK(qrx_cond_timedwait(&condition, &mutex, &until) == ETIMEDOUT);
    CHECK(qrx_mutex_unlock(&mutex) == 0);
    CHECK(qrx_cond_destroy(&condition) == 0);
    CHECK(qrx_mutex_destroy(&mutex) == 0);
    puts("PASS: thread joins/results, mutex contention, broadcast wakeups and expired condition deadline");
    return 0;
}
