#include <pthread.h>
#include <stdio.h>
#include "flow.h"
#include "log.c/log.h"

pthread_mutex_t MUTEX_LOG;
void logger_lock (bool lock, void *udata);

int
logger_init (FILE *fp, int lvl)
{
  log_set_level (lvl);
  log_set_quiet (0);

  logger_lock_init ();

  return log_add_fp (fp, lvl);
}

int
logger_lock_init ()
{
  pthread_mutex_init (&MUTEX_LOG, NULL);
  log_set_lock (logger_lock, &MUTEX_LOG);

  /* Insert threaded application code here... */

  /* pthread_mutex_destroy (&MUTEX_LOG); */

  return 0;
}

void
logger_lock (bool lock, void *udata)
{
  pthread_mutex_t *LOCK = (pthread_mutex_t *) (udata);
  if (lock)
    pthread_mutex_lock (LOCK);
  else
    pthread_mutex_unlock (LOCK);
}

void
logger_destory ()
{
  pthread_mutex_destroy (&MUTEX_LOG);
}
