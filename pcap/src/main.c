#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "flow.h"
#include "log.c/log.h"
#include "packet.h"
#include "spsc_queue.h"

extern flow_arr_t *fa; // flow array
extern spsc_queue *pkt_que;
extern pthread_mutex_t air_mutex; // flow add/init/reset mutex

/* 10.160.16.157 */
/* 4001-4008 */
/* dst host 10.160.16.157 and tcp dst portrange 4001-4008 */
char *filter_exp = "tcp"; /* The filter expression */

// handler -> ring -> th_dispatch_flow -> flow -> th_send_flow
int
main (int argc, char *argv[])
{
  /* init logger */
  FILE *fp;
  fp = fopen ("./log.txt", "ab");
  if (fp == NULL)
    {
      return -1;
    }
  init_logger (fp, LOG_DEBUG);
  log_info ("Hello World!");

  pkt_que = spsc_init (PKT_QUE_CAP);
  log_info ("pkt_que: %p", pkt_que);

  fa = flow_arr_init (FLOW_ARR_CAP);
  log_info ("flow_ptr: %p", fa);

  // reentrant lock
  pthread_mutexattr_t attr;
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&air_mutex, &attr);
  pthread_mutexattr_destroy (&attr);

  pthread_t tht_dispatch_flow;
  pthread_create (&tht_dispatch_flow, NULL, th_dispatch_flow, (void *) pkt_que);
  log_info ("tht_dispatch_flow: %u", tht_dispatch_flow);

  // block
  filter_exp = argv[1] == NULL ? filter_exp : argv[1];
  log_info ("filter_exp: %s", filter_exp);
  loop (filter_exp);

  pthread_exit (NULL);

  pthread_mutex_destroy (&air_mutex);

  fclose (fp);
}
