#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_THREADS 5

void *
PrintHello (void *threadid)
{
  long tid;
  tid = (long) threadid;
  printf ("It's me, thread #%ld!\n", tid);
  pthread_exit (NULL);
}

void *
pcreate ()
{
  pthread_t threads[NUM_THREADS];
  int rc;
  long t;
  for (t = 0; t < NUM_THREADS; t++)
    {
      printf ("In main: creating thread %ld\n", t);
      rc = pthread_create (&threads[t], NULL, PrintHello, (void *) t);
      if (rc)
        {
          printf ("ERROR; return code from pthread_create() is %d\n", rc);
          exit (-1);
        }
    }
  pthread_exit (NULL);
}

int
main ()
{
  long t;
  pthread_t pt;
  pthread_create (&pt, NULL, pcreate, (void *) t);
  //  pthread_exit(NULL);
}
