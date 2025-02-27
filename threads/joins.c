#include <pthread.h>
#include <stdio.h>

#define NTHREADS 10
void *thread_function (void *);
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
int counter = 0;

int
main ()
{
  pthread_t thread_id[NTHREADS];
  int i, j;

  for (i = 0; i < NTHREADS; i++)
    {
      pthread_create (&thread_id[i], NULL, thread_function, NULL);
    }
  for (j = 0; j < NTHREADS; j++)
    {
      pthread_join (thread_id[j], NULL);
    }
  printf ("FINAL COUNTER VALUE: %d\n", counter);
}

void *
thread_function (void *dummyPtr)
{
  printf ("THREAD NUMBER %ld\n", pthread_self ());
  pthread_mutex_lock (&mutex1);
  counter++;
  pthread_mutex_unlock (&mutex1);
}
