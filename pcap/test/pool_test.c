#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "../src/pool.h"

static void
count_job (void *arg)
{
  atomic_int *count = (atomic_int *) arg;
  atomic_fetch_add (count, 1);
}

int
main (void)
{
  enum
  {
    job_count = 64
  };

  atomic_int count = 0;
  threadpool_t *tp = threadpool_create (4);
  if (!tp)
    {
      perror ("threadpool_create");
      return 1;
    }

  for (int i = 0; i < job_count; i++)
    {
      int rc = threadpool_submit (tp, count_job, &count);
      if (rc != 0)
        {
          fprintf (stderr, "threadpool_submit failed: %d\n", rc);
          threadpool_destroy (tp);
          return 1;
        }
    }

  threadpool_wait (tp);
  threadpool_destroy (tp);

  if (atomic_load (&count) != job_count)
    {
      fprintf (stderr, "expected %d jobs, ran %d\n", job_count, atomic_load (&count));
      return 1;
    }
  return 0;
}
