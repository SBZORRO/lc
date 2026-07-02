#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
char *log_dir = ".";
int log_level = LOG_INFO;

static const char *
parse_arg_value (const char *arg, const char *prefix)
{
  size_t prefix_len = strlen (prefix);

  if (strncmp (arg, prefix, prefix_len) != 0)
    return NULL;

  return arg + prefix_len;
}

static int
parse_arg_log_level (const char *value, int fallback)
{
  int lvl = value[0] - '0';
  if (lvl < LOG_TRACE || lvl > LOG_FATAL)
    return fallback;
  return lvl;
}

// handler -> ring -> th_dispatch_flow -> flow -> th_send_flow
int
main (int argc, char *argv[])
{
  /* parse args */
  for (int i = 1; i < argc; i++)
    {
      const char *arg_filter = parse_arg_value (argv[i], "--pcapFilter=");
      const char *arg_log_dir = parse_arg_value (argv[i], "--logDir=");
      const char *arg_log_lvl = parse_arg_value (argv[i], "--logLevel=");

      if (arg_log_lvl != NULL)
        {
          log_level = parse_arg_log_level (arg_log_lvl, log_level);
          continue;
        }
      if (arg_filter != NULL)
        {
          filter_exp = (char *) arg_filter;
          continue;
        }
      if (arg_log_dir != NULL)
        {
          log_dir = (char *) arg_log_dir;
          continue;
        }
    }

  char log_path[4096];
  snprintf (log_path, sizeof log_path, "%s/%s", log_dir, "log.txt");
  FILE *fp = fopen (log_path, "ab");
  if (fp == NULL)
    {
      fprintf (stderr, "failed to open log file: %s\n", log_path);
      return -1;
    }
  if (flow_net_init () != 0)
    {
      fclose (fp);
      return -1;
    }

  logger_init (fp, log_level);
  log_info ("Hello World!");
  log_info ("log_level: %s", log_level_string (log_level));
  log_info ("log_path: %s", log_path);

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

  log_info ("filter_exp: %s", filter_exp);
  loop (filter_exp);

  pthread_exit (NULL);

  pthread_mutex_destroy (&air_mutex);

  flow_net_cleanup ();
  fclose (fp);
}
