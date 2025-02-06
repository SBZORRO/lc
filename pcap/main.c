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
  /* 1: pcap-filter */
  filter_exp = argv[1];

  /* 2: dst addr */
  char *addr = argv[2];
  char *dst_ip = strtok (addr, ":");
  char *dst_port = strtok (NULL, "\0");
  u_short d_port = htons (atoi (dst_port));
  u_int d_ip = inet_addr (dst_ip);

  do_connect (d_ip, d_port);

  /* 3-...: src addr */
  flow_len = argc - 3;
  init_flow (&flow_ptr, flow_len, argv + 3);
  /* flow_ptr = MALLOC (flow_t, argc - 3); */
  /* flow_len = argc - 3; */
  /* for (int i = 3, j = 0; i < argc; i++, j++) */
  /*   { */
  /*     char *addr = argv[i]; */
  /*     char *ip = strtok (addr, ":"); */
  /*     char *port = strtok (NULL, "\0"); */
  /*     /\* inet_aton (ip, &flow_ptr[j].ip_src); *\/ */
  /*     flow_ptr[j].ip_src.s_addr = inet_addr (dst_ip); */
  /*     flow_ptr[j].sport = htons (atoi (port)); */
  /*     flow_ptr[j].next = NULL; */
  /*     flow_ptr[j].nxt = 0; */
  /*     flow_ptr[j].isn = 0; */
  /*   } */

  loop ();

  /* pthread_t pid = 1; */
  /* pthread_create (&pid, NULL, NULL, NULL); */

  /* pthread_mutex_t pmt; */
  /* pthread_mutex_lock (&pmt); */
}
