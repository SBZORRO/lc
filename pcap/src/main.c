#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "captotcp.h"

/* char filter_exp[] = "dst port 9998"; /\* The filter expression *\/ */
extern char *filter_exp;
extern flow_t *flow_ptr;
extern int flow_len;

int
main (int argc, char *argv[])
{
  filter_exp = argv[1];
  printf ("filter_exp%s\n", filter_exp);

  init_flow (&flow_ptr, (argc - 2) / 2);
  for (int i = 2; i < argc; i = i + 2)
    {
      flow_t *flow = add_flow (&flow_ptr[flow_len], argv[i], argv[i + 1]);
      flow_len++;
      /* do_connect (flow->ip_dst.s_addr, flow->dport); */
    }
  // print_flow (flow_ptr, flow_len);
  // loop ();

  /* pthread_t pid = 1; */
  /* pthread_create (&pid, NULL, NULL, NULL); */

  /* pthread_mutex_t pmt; */
  /* pthread_mutex_lock (&pmt); */
}
