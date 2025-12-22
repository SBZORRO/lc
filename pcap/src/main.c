#define _GNU_SOURCE
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
#include "log.c/log.h"
#include "packet.h"
#include "spsc_queue.h"

/* 10.160.16.157 */
/* 4001-4008 */
/* dst host 10.160.16.157 and tcp dst portrange 4001-4008 */
/* char filter_exp[] = "dst port 9998"; /\* The filter expression *\/ */
extern char *filter_exp; // pcap filter exp

flow_arr_t *flow_ptr; // flow array
#define FLOW_PTR_CAP 255

char *filter_exp = "dst port 9998"; /* The filter expression */

spsc_queue *pkt_que;
// 2^n
#define PKT_QUE_CAP 65536

/* servos */
/* servou */
char *server[] = { NULL, "127.0.0.1:9998", "127.0.0.1:9999", NULL };

// handler -> ring -> th_dispatch_flow -> flow -> th_send_flow

void *
th_send_flow (void *f)
{
  flow_t *flow = (flow_t *) f;
  int rc = pthread_setname_np (pthread_self (), "send_flow");
  if (rc != 0)
    log_debug ("sendflow_setname: %s\n", strerror (rc));
  int rst = 0;
  while (1)
    {
      pthread_mutex_lock (&flow->mutex);
      flow_state_t *state = flow_state_fix_and_pop (flow);
      pthread_mutex_unlock (&flow->mutex);

      if (state == NULL)
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

      /* if (flow->sock == 0) */
      /*   { */
      /*     int res = detect (flow); */
      /*     if (res == 0) */
      /*       { */
      /*         continue; */
      /*       } */
      /*     SET_IP (flow, tar, server[res]); */
      /*     while ((flow->sock = do_connect (flow->ip_tar, flow->port_tar)) == 0) */
      /*       { */
      /*         sleep (1); */
      /*       } */
      /*   } */

      log_debug ("sending: %p", state);
      // do_sent (flow, (char *) state->pkt + state->offset_payload, (size_t) state->len);

      /* write the data into the file */
      if (fwrite ((char *) state->pkt + state->offset_payload, (size_t) state->size_payload, 1, flow->fp) != 1)
        {
          // DEBUG (1) ("write to %s failed: ", flow_filename (state->flow));
          perror ("");
        }
      fflush (flow->fp);

      flow_state_free (state);
    }

  pthread_exit (NULL);
}

void *
th_dispatch_flow (void *arg)
{
  //  prctl (PR_SET_NAME, "main-thread", 0, 0, 0);
  int rc = pthread_setname_np (pthread_self (), "dispatch_flow");
  if (rc != 0)
    log_debug ("dispatch_setname: %s\n", strerror (rc));

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

      const struct sniff_ethernet *ethernet; /* The ethernet header */
      const struct sniff_ip *ip;             /* The IP header */
      const struct sniff_tcp *tcp;           /* The TCP header */
      uint8_t *payload;                      /* Packet payload */

      uint32_t size_ip;
      uint32_t size_tcp;
      uint32_t size_payload;
      uint32_t offset_payload;

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
      uint32_t seq = ntohl (tcp->th_seq);
      uint32_t ack = ntohl (tcp->th_ack);
      uint32_t flags = tcp->th_flags;
      size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
      offset_payload = SIZE_ETHERNET + size_ip + size_tcp;
      payload = (u_char *) (p + offset_payload);

      /* Reassemble TCP */
      flow_t *flow = flow_find (flow_ptr, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
      // add new flow
      if (flow == NULL)
        {
          flow_ptr = flow_arr_add (flow_ptr);
          flow = flow_ptr->flow + flow_ptr->flow_len - 1;
          flow_init (flow, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
        }

      // handle RST/SYN flags
      int res = flow_flags (flow, flags);
      if (res == 0)
        {
          free (p);
          continue;
        }
      else if (res == 1)
        {
          flow->seg_nxt = seq + 1; // SYN consumes one
        }
      else if (flow->seg_nxt == 0)
        {
          flow->seg_nxt = seq;
        }

      if (size_payload == 0)
        {
          free (p);
          continue;
        }

      uint32_t e = seq + size_payload; // [s, e)
      // outside of window
      if (SEQ_LEQ (e, flow->seg_nxt))
        {
          log_debug ("DISCARD");
          free (p);
          continue;
        }

      log_debug ("dequeued: \n%.*s", size_payload, payload);

      flow_state_t *state = flow_state_create (flow, seq, ack, flags, size_payload, offset_payload, p);
      flow_state_attach (flow, state);

      if (!(flow->flags & SENDING))
        {
          char *name = flow_filename (flow);
          if (flow->fp == NULL)
            {
              flow->fp = fopen (name, "ab");
            }
          flow->flags = flow->flags | SENDING;
          pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow);
          // int rc = pthread_setname_np (pthread_self (), name);
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
  log_debug ("filter_exp: %s", filter_exp);
  loop (filter_exp);

  pthread_exit (NULL);

  fclose (fp);
}
