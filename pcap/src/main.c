#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "flow.h"
#include "spsc_queue.h"
#include "src/log.c/log.h"
#include "src/packet.h"

/* 10.160.16.157 */
/* 4001-4008 */
/* dst host 10.160.16.157 and tcp dst portrange 4001-4008 */
/* char filter_exp[] = "dst port 9998"; /\* The filter expression *\/ */
extern char *filter_exp; // pcap filter exp

flow_arr_t *flow_ptr; // flow array
#define FLOW_PTR_CAP 10

char *filter_exp = "dst port 9998"; /* The filter expression */

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

// handler -> ring -> th_dispatch_flow -> flow -> th_send_flow

void *
th_send_flow (void *f)
{
  flow_t *flow = (flow_t *) f;
  int rst = 0;
  while (1)
    {
      flow_state_t *state = flow->next;
      if (state == NULL && flow->seg_nxt != state->seq)
        {
          if (rst++ > 60)
            {
              flow_reset (flow);
              break;
            }
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

      state = flow_state_pop (flow, state);
      log_debug ("sending: \n%s", state->pkt);
      do_sent (flow, (char *) state->pkt + state->offset_payload, (size_t) state->len);
      flow_state_free (state);
    }
  pthread_exit (NULL);
}

// singleton
/* void * */
/* th_patrol_flow (void *f) */
/* { */
/*   while (1) */
/*     { */
/*       for (int i = 0; i < flow_len; i++) */
/*         { */
/*           flow_t *flow = flow_ptr + i; */
/*           flow_state_t *state = flow->next; */
/*           if (flow->sock == 0 && state != NULL) */
/*             { */
/*               int res = detect (flow); */
/*               if (res == 0) */
/*                 { */
/*                   continue; */
/*                 } */
/*               SET_IP (flow, tar, server[res]); */
/*               // set_dst (flow, server_servos); */
/*               pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow); */
/*             } */
/*         } */
/*     } */
/*   pthread_exit (NULL); */
/* } */

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
      u_char *payload;                       /* Packet payload */

      u_int size_ip;
      u_int size_tcp;
      u_int size_payload;
      u_int offset_payload;

      ethernet = (struct sniff_ethernet *) (p);
      /* Process IP */
      ip = (struct sniff_ip *) (p + SIZE_ETHERNET);
      size_ip = IP_HL (ip) * 4;
      if (size_ip < 20)
        {
          log_error ("   * Invalid IP header length: %u bytes\n", size_ip);
          free (p);
          continue;
        }
      /* Process TCP */
      tcp = (struct sniff_tcp *) (p + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF (tcp) * 4;
      if (size_tcp < 20)
        {
          log_error ("   * Invalid TCP header length: %u bytes\n", size_tcp);
          free (p);
          continue;
        }
      /* Process Payload */
      u_int seq = ntohl (tcp->th_seq);
      u_int ack = ntohl (tcp->th_ack);
      size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
      offset_payload = SIZE_ETHERNET + size_ip + size_tcp;
      payload = (u_char *) (p + offset_payload);

      /* Reassemble TCP */
      flow_t *flow = flow_find (flow_ptr, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
      if (flow == NULL)
        {
          flow_ptr = flow_arr_add (flow_ptr);
          flow = flow_ptr->flow + flow_ptr->flow_len;
          flow_init (flow, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
        }

      switch (tcp->th_flags)
        {
        case TH_RST:
          flow_reset (flow);
          flow->flags = TH_RST;
          free (p);
          continue;
          break;
        case TH_SYN:
          flow->flags = TH_SYN;
        default:
          // rst, discard following untill syn
          if (flow->flags & TH_RST)
            {
              free (p);
              continue;
            }
          flow->flags = flow->flags | tcp->th_flags;
          flow->seg_nxt = seq;
          break;
        }

      log_debug ("dequeued: \n%.*s", size_payload, payload);

      uint32_t e = seq + size_payload; // [s, e)
      // outside of window
      if (SEQ_LT (e, flow->seg_nxt))
        {
          log_debug ("DISCARD");
          free (p);
          continue;
        }
      else if (SEQ_LT (seq, flow->seg_nxt) && SEQ_GT (e, flow->seg_nxt)) // overlap
        {
          // s < r < e
          // 左半段是重复数据，右半段是新数据
          // 需要把 [s, r) 裁掉，只保留 [r, e)
          size_payload = e - flow->seg_nxt;
          offset_payload = e - size_payload;
          // 调整指针和长度：payload += (r - s); len = new_len;
        }

      flow_state_t *state = flow_state_create (flow, seq, ack, tcp->th_flags, size_payload, offset_payload, payload);
      flow_state_attach (flow, state);

      if (!(flow->flags & SENDING))
        {
          pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow);
          flow->flags = flow->flags | SENDING;
        }
    }
  pthread_exit (NULL);
}

/* 10.160.16.157 */
/* 4001-4008 */
/* dst host 10.160.16.157 and tcp dst portrange 4001-4008 */
/* char filter_exp[] = "dst port 9998"; /\* The filter expression *\/ */
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
  log_debug ("Hello World!");

  size_t bytes = sizeof (spsc_queue) + PKT_QUE_CAP * sizeof (void *);
  pkt_que = (spsc_queue *) check_malloc (bytes);
  spsc_init (pkt_que, PKT_QUE_CAP);
  log_debug ("pkt_que: %p", pkt_que);

  flow_ptr = flow_arr_init (FLOW_PTR_CAP);
  log_debug ("flow_ptr: %p", flow_ptr);

  pthread_t tht_dispatch_flow;
  pthread_create (&tht_dispatch_flow, NULL, th_dispatch_flow, (void *) pkt_que);
  log_debug ("tht_dispatch_flow: %u", tht_dispatch_flow);

  // block
  filter_exp = argv[1];
  loop (filter_exp);

  pthread_exit (NULL);

  /* portable_signal(SIGTERM, terminate); */
  /* portable_signal(SIGINT, terminate); */
  /* portable_signal(SIGHUP, terminate); */

  fclose (fp);
}
