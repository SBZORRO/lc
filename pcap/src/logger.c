#include <pthread.h>
#include <stdio.h>
#include "log.c/log.h"

void
init_logger (FILE *fp)
{
  log_set_level (LOG_DEBUG);
  log_set_quiet (0);

  log_add_fp (fp, LOG_DEBUG);
}

pthread_mutex_t MUTEX_LOG;
void log_lock (bool lock, void *udata);

int
init_logger_lock ()
{
  pthread_mutex_init (&MUTEX_LOG, NULL);
  log_set_lock (log_lock, &MUTEX_LOG);

  /* Insert threaded application code here... */

  /* pthread_mutex_destroy (&MUTEX_LOG); */

  return 0;
}

void
log_lock (bool lock, void *udata)
{
  pthread_mutex_t *LOCK = (pthread_mutex_t *) (udata);
  if (lock)
    pthread_mutex_lock (LOCK);
  else
    pthread_mutex_unlock (LOCK);
}
