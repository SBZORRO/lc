#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include "pool.h"

typedef struct tp_job
{
  tp_fn fn;
  void *arg;
  struct tp_job *next;
} tp_job_t;

typedef struct threadpool
{
  pthread_t *threads;
  size_t nthreads; // #worker threads successfully created

  tp_job_t *head;
  tp_job_t *tail;

  pthread_mutex_t mu;
  pthread_cond_t cv_job;  // new job or shutdown
  pthread_cond_t cv_idle; // became idle (queue empty + no active jobs)

  size_t active; // #workers currently running a job
  int stop;      // 0 running, 1 stopping
} threadpool_t;

static void
tp_free_jobs (threadpool_t *tp)
{
  tp_job_t *job = tp->head;
  while (job)
    {
      tp_job_t *next = job->next;
      free (job);
      job = next;
    }
  tp->head = NULL;
  tp->tail = NULL;
}

static void
tp_stop_workers (threadpool_t *tp)
{
  pthread_mutex_lock (&tp->mu);
  tp->stop = 1;
  pthread_cond_broadcast (&tp->cv_job);
  pthread_mutex_unlock (&tp->mu);

  for (size_t i = 0; i < tp->nthreads; i++)
    {
      pthread_join (tp->threads[i], NULL);
    }
  tp->nthreads = 0;
}

static void *
tp_worker (void *p)
{
  threadpool_t *tp = (threadpool_t *) p;

  for (;;)
    {
      pthread_mutex_lock (&tp->mu);

      // Wait until there's work OR we're stopping.
      while (!tp->stop && tp->head == NULL)
        {
          pthread_cond_wait (&tp->cv_job, &tp->mu);
        }

      // If stopping and no pending work, exit.
      if (tp->stop && tp->head == NULL)
        {
          pthread_mutex_unlock (&tp->mu);
          break;
        }

      // Pop one job.
      tp_job_t *job = tp->head;
      tp->head = job->next;
      if (tp->head == NULL)
        tp->tail = NULL;

      tp->active++;
      pthread_mutex_unlock (&tp->mu);

      // Run job outside lock.
      job->fn (job->arg);
      free (job);

      pthread_mutex_lock (&tp->mu);
      tp->active--;

      // If now totally idle, signal waiters.
      if (tp->head == NULL && tp->active == 0)
        {
          pthread_cond_broadcast (&tp->cv_idle);
        }
      pthread_mutex_unlock (&tp->mu);
    }
  return NULL;
}

static int
tp_init (threadpool_t *tp, size_t nthreads)
{
  int rc;
  int mu_initialized = 0;
  int cv_job_initialized = 0;
  int cv_idle_initialized = 0;

  tp->threads = calloc (nthreads, sizeof (*tp->threads));
  if (!tp->threads)
    return ENOMEM;

  tp->nthreads = 0;
  tp->head = tp->tail = NULL;
  tp->active = 0;
  tp->stop = 0;

  if ((rc = pthread_mutex_init (&tp->mu, NULL)) != 0)
    goto fail;
  mu_initialized = 1;

  if ((rc = pthread_cond_init (&tp->cv_job, NULL)) != 0)
    goto fail;
  cv_job_initialized = 1;

  if ((rc = pthread_cond_init (&tp->cv_idle, NULL)) != 0)
    goto fail;
  cv_idle_initialized = 1;

  for (size_t i = 0; i < nthreads; i++)
    {
      rc = pthread_create (&tp->threads[i], NULL, tp_worker, tp);
      if (rc != 0)
        goto fail;
      tp->nthreads++;
    }
  return 0;

fail:
  if (tp->nthreads > 0)
    tp_stop_workers (tp);

  if (cv_idle_initialized)
    pthread_cond_destroy (&tp->cv_idle);
  if (cv_job_initialized)
    pthread_cond_destroy (&tp->cv_job);
  if (mu_initialized)
    pthread_mutex_destroy (&tp->mu);

  free (tp->threads);
  tp->threads = NULL;
  return rc;
}

threadpool_t *
threadpool_create (size_t nthreads)
{
  if (nthreads == 0)
    {
      errno = EINVAL;
      return NULL;
    }

  threadpool_t *tp = calloc (1, sizeof (*tp));
  if (!tp)
    return NULL;

  int rc = tp_init (tp, nthreads);
  if (rc != 0)
    {
      errno = rc;
      free (tp);
      return NULL;
    }
  return tp;
}

// Submit a job. Returns 0 on success, errno-style code on failure.
int
threadpool_submit (threadpool_t *tp, tp_fn fn, void *arg)
{
  if (!tp || !fn)
    return EINVAL;

  tp_job_t *job = malloc (sizeof (*job));
  if (!job)
    return ENOMEM;
  job->fn = fn;
  job->arg = arg;
  job->next = NULL;

  pthread_mutex_lock (&tp->mu);
  if (tp->stop)
    {
      pthread_mutex_unlock (&tp->mu);
      free (job);
      return EINVAL;
    }

  if (tp->tail)
    tp->tail->next = job;
  else
    tp->head = job;
  tp->tail = job;

  pthread_cond_signal (&tp->cv_job);
  pthread_mutex_unlock (&tp->mu);
  return 0;
}

// Wait until the queue is empty and all workers are idle.
void
threadpool_wait (threadpool_t *tp)
{
  if (!tp)
    return;
  pthread_mutex_lock (&tp->mu);
  while (tp->head != NULL || tp->active != 0)
    {
      pthread_cond_wait (&tp->cv_idle, &tp->mu);
    }
  pthread_mutex_unlock (&tp->mu);
}

// Destroy: finish pending jobs (drain queue) then stop workers.
void
threadpool_destroy (threadpool_t *tp)
{
  if (!tp)
    return;

  // Wait for existing jobs to finish (optional behavior; common default).
  threadpool_wait (tp);

  tp_stop_workers (tp);

  // Free any remaining queued jobs (should be none if we waited).
  tp_free_jobs (tp);

  pthread_cond_destroy (&tp->cv_idle);
  pthread_cond_destroy (&tp->cv_job);
  pthread_mutex_destroy (&tp->mu);
  free (tp->threads);
  free (tp);
}
