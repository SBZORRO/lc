#include <arpa/inet.h>
#include <bits/time.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "flow.h"
#include "spsc_queue.h"

/* 10.160.16.157 */
/* 4001-4008 */
/* dst host 10.160.16.157 and tcp dst portrange 4001-4008 */
/* char filter_exp[] = "dst port 9998"; /\* The filter expression *\/ */
extern char *filter_exp; // pcap filter exp
extern flow_t *flow_ptr; // flow array
extern int flow_len;     // flow array length
extern int flow_cap;     // flow array cap

spsc_queue *pkt_que;
#define PKT_QUE_CAP 1024

/* servos */
/* servou */
char *server[] = { NULL, "127.0.0.1:9998", "127.0.0.1:9999", NULL };

/* RETSIGTYPE terminate(int sig) */
/* { */
/*   DEBUG(1) ("terminating"); */
/*   exit(0); /\* libpcap uses onexit to clean up *\/ */
/* } */

// handler -> ring -> th_dispatch_flow -> flow -> th_patrol_flow -> th_send_flow

void *
th_send_flow (void *f)
{
  int rst = 0;
  flow_t *flow = (flow_t *) f;
  while (1)
    {
      flow_state_t *state = flow->next;
      if (state == NULL && flow->nxt != state->seq)
        {
          rst++;
          sleep (1);
          continue;
        }
      rst = 0;
      if (flow->sock == 0)
        {
          int res = detect (flow);
          if (res == 0)
            {
              continue;
            }
          SET_IP (flow, tar, server[res]);
          while ((flow->sock = do_connect (flow->ip_tar, flow->port_tar)) == 0)
            {
              sleep (1);
            }
        }

      state = detach_flow_state (flow, state);
      do_sent (flow, (char *) state->payload, (size_t) state->len);
      free_flow_state (state);
    }
  pthread_exit (NULL);
}

// singleton
void *
th_patrol_flow (void *f)
{
  while (1)
    {
      for (int i = 0; i < flow_len; i++)
        {
          flow_t *flow = flow_ptr + i;
          flow_state_t *state = flow->next;
          if (flow->sock == 0 && state != NULL)
            {
              int res = detect (flow);
              if (res == 0)
                {
                  continue;
                }
              SET_IP (flow, tar, server[res]);
              // set_dst (flow, server_servos);
              pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow);
            }
        }
    }
  pthread_exit (NULL);
}

void *
th_dispatch_flow (void *arg)
{
  spsc_queue *q = (spsc_queue *) arg;

  while (1)
    {
      u_char *p = NULL;

      if (!spsc_dequeue (q, (void **) &p))
        {
          // 队空，稍微睡一下
          struct timespec ts = { 0, 1000000 };
          nanosleep (&ts, NULL);
          continue;
        }

      // 在这里使用 pkt（里面是完整的包数据）
      // parse_packet(pkt, ...);

      const struct sniff_ethernet *ethernet; /* The ethernet header */
      const struct sniff_ip *ip;             /* The IP header */
      const struct sniff_tcp *tcp;           /* The TCP header */
      const u_char *payload;                 /* Packet payload */

      u_int size_ip;
      u_int size_tcp;
      u_int size_payload;

      ethernet = (struct sniff_ethernet *) (p);
      ip = (struct sniff_ip *) (p + SIZE_ETHERNET);
      size_ip = IP_HL (ip) * 4;
      if (size_ip < 20)
        {
          printf ("   * Invalid IP header length: %u bytes\n", size_ip);
          return NULL;
        }

      tcp = (struct sniff_tcp *) (p + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF (tcp) * 4;
      if (size_tcp < 20)
        {
          printf ("   * Invalid TCP header length: %u bytes\n", size_tcp);
          return NULL;
        }

      flow_t *flow = find_flow (flow_ptr, flow_len, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
      flow->flags = flow->flags | tcp->th_flags;

      if (flow->state == 0)
        {
          pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow);
        }
      /* if ((tcp->th_flags & TH_FIN) || (tcp->th_flags & TH_RST)) // disconnect */
      /*   { */
      /*     reset_flow (flow); */
      /*     return NULL; */
      /*   } */
      /* if (tcp->th_flags & TH_SYN) // connect */
      /*   { */
      /*     reset_flow (flow); */
      /*     flow->flags = 1; */
      /*   } */

      size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
      if (size_payload == 0)
        {
          free (p);
          return NULL;
        }
      payload = (u_char *) (p + SIZE_ETHERNET + size_ip + size_tcp);

      u_int seq = ntohl (tcp->th_seq);
      u_int ack = ntohl (tcp->th_ack);

      if (flow->isn == 0 && flow->nxt == 0)
        {
          flow->isn = seq;
          flow->nxt = seq;
        }
      /* create_flow_state (&flow, seq, size_payload, payload); */
      flow_state_t *state = create_flow_state (flow, seq, size_payload, payload);
      attach_flow_state (flow, state);
      free (p);
    }
  pthread_exit (NULL);
}

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
  init_logger (fp);

  size_t bytes = sizeof (spsc_queue) + PKT_QUE_CAP * sizeof (void *);
  pkt_que = (spsc_queue *) check_malloc (bytes);
  spsc_init (pkt_que, PKT_QUE_CAP);

  init_flow_ptr (&flow_ptr, flow_cap);
  /* args */
  /* filter_exp = argv[1]; */
  /* log_info ("filter_exp%s\n", filter_exp); */
  /* int num = (argc - 2) / 2; */
  /* pthread_t threads[num]; */
  /* init_flow (&flow_ptr, num); */
  /* for (int i = 2; i < argc; i = i + 2) */
  /*   { */
  /*     // cache */
  /*     flow_t *flow = add_flow (&flow_ptr[flow_len], NULL, argv[i + 1]); */
  /*     flow_len++; */
  /*     // thread per flow */
  /*     pthread_create (&threads[i], NULL, send_flow, (void *) flow); */
  /*   } */

  loop ();

  pthread_t tht_dispatch_flow;
  pthread_create (&tht_dispatch_flow, NULL, th_dispatch_flow, (void *) pkt_que);

  pthread_exit (NULL);

  /* portable_signal(SIGTERM, terminate); */
  /* portable_signal(SIGINT, terminate); */
  /* portable_signal(SIGHUP, terminate); */

  fclose (fp);
}
