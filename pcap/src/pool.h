#pragma once

#include <stddef.h>

typedef void (*tp_fn) (void *arg);

typedef struct threadpool threadpool_t;

threadpool_t *threadpool_create (size_t nthreads);
int threadpool_submit (threadpool_t *tp, tp_fn fn, void *arg);
void threadpool_wait (threadpool_t *tp);
void threadpool_destroy (threadpool_t *tp);
