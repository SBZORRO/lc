#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "flow.h"
#include "log.c/log.h"
#include "packet.h"
#include "spsc_queue.h"

/* 10.160.16.157 */
/* 4001-4008 */
/* dst host 10.160.16.157 and tcp dst portrange 4001-4008 */
char *filter_exp = "tcp"; /* The filter expression */

flow_arr_t *fa; // flow array

spsc_queue *pkt_que;

/* servos */
/* servou */
/* drager */
char *server[] = { NULL, "127.0.0.1:9999", "127.0.0.1:9998", "127.0.0.1:9997", NULL };

pthread_mutex_t air_mutex; // flow add/init/reset mutex

// handler -> ring -> th_dispatch_flow -> flow -> th_send_flow

void *
th_send_flow (void *f)
{
  flow_t *flow = (flow_t *) f;
  int rc = pthread_setname_np (pthread_self (), "send_flow");
  if (rc != 0)
    log_debug ("th_sendflow_setname: %s\n", strerror (rc));
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
              pthread_mutex_lock (&air_mutex);

              pthread_mutex_lock (&flow->mutex);
              state = flow_state_fix_and_pop (flow);
              pthread_mutex_unlock (&flow->mutex);
              if (state == NULL && rst++ > 60)
                {
                  flow_reset (flow);
                }
              pthread_mutex_unlock (&air_mutex);
              break;
            }
          sleep (1);
          continue;
        }
      rst = 0;

      /* write the data into the file */
      log_debug (" writing: [%p][%p][%u]", flow, state, state->seq);
      if (fwrite ((char *) state->pkt + state->offset_payload, (size_t) state->size_payload, 1, flow->fp) != 1)
        {
          log_error ("FAILED_WRITING: [%p][%p][%u]", flow, state, state->seq);
          // DEBUG (1) ("write to %s failed: ", flow_filename (state->flow));
          perror ("FAILED_WRITING");
        }
      fflush (flow->fp);

      if (flow->sock <= 0)
        {
          int res = detect (state);
          log_debug ("detected: [%p][%p][%u][%d]", flow, state, state->seq, res);
          if (res == 0)
            {
              continue;
            }
          SET_IP (flow, tar, server[res]);
          while ((flow->sock = do_connect (flow->ip_tar, flow->port_tar)) <= 0)
            {
              log_error ("FAILED_CONNECTING: [%p][%d]", flow, flow->sock);
              break;
              // sleep (1);
            }
        }
      log_debug (" sending: [%p][%p][%u]", flow, state, state->seq);
      do_sent (flow, (char *) state->pkt + state->offset_payload, (size_t) state->size_payload);

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
    log_debug ("th_dispatch_setname: %s\n", strerror (rc));

  spsc_queue *q = (spsc_queue *) arg;

  while (1)
    {
      uint8_t *p = NULL;

      if (!spsc_dequeue (q, (void **) &p))
        {
          log_trace ("QUEUE_SIZE_0");
          // 队空，稍微睡一下
          struct timespec ts = { 0, 1000000 };
          nanosleep (&ts, NULL);
          continue;
        }

      /* const struct sniff_ethernet *ethernet; /\* The ethernet header *\/ */
      const struct sniff_ip *ip;   /* The IP header */
      const struct sniff_tcp *tcp; /* The TCP header */
      uint8_t *payload;            /* Packet payload */

      uint32_t size_ip;
      uint32_t size_tcp;
      uint32_t size_payload;
      uint32_t offset_payload;

      /* ethernet = (struct sniff_ethernet *) (p); */
      /* Process IP */
      ip = (struct sniff_ip *) (p + SIZE_ETHERNET);
      size_ip = IP_HL (ip) * 4;
      if (size_ip < 20)
        {
          log_error ("Invalid_IP_header_length: %u\n", size_ip);
          free (p);
          continue;
        }
      /* Process TCP */
      tcp = (struct sniff_tcp *) (p + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF (tcp) * 4;
      if (size_tcp < 20)
        {
          log_error ("Invalid_TCP_ header_length: %u\n", size_tcp);
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

      log_info ("DEQUEUED: "
                "[%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d]"
                "[%u][%u][%u][%u][%u]",
                filename (ip->ip_src, tcp->th_sport, ip->ip_dst, tcp->th_dport),
                seq, ack, flags, offset_payload, size_payload);
      log_hex ("HPAYLOAD: %s", payload, size_payload);
      log_debug ("APAYLOAD: %.*s", size_payload, payload);

      /*
       * lock
       */
      pthread_mutex_lock (&air_mutex);
      /* Reassemble TCP */
      flow_t *flow = flow_find (fa, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
      // add new flow
      if (flow == NULL)
        {
          flow = flow_add (fa);
          if (flow == NULL)
            {
              log_error ("TOO_MUCH_FLOW!");
              pthread_mutex_unlock (&air_mutex);
              continue;
            }
          flow_init (flow, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
          log_debug (
            "NEW_FLOW: [%p][%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d]",
            flow,
            filename (flow->ip_src, flow->port_src, flow->ip_dst, flow->port_dst));
        }

      // handle RST/SYN flags
      if (flow_handshake (flow, flags, seq, size_payload) == 0)
        {
          free (p);
          pthread_mutex_unlock (&air_mutex);
          continue;
        }

      flow_state_t *state = flow_state_create (flow, seq, ack, flags, size_payload, offset_payload, p);
      log_debug ("NEW_STAT: [%p][%p][%u]", flow, state, seq);
      pthread_mutex_lock (&flow->mutex);
      flow_state_attach (flow, state);
      pthread_mutex_unlock (&flow->mutex);

      if (!(flow->flags & SENDING))
        {
          char *name = flow_filename (flow);
          if (flow->fp == NULL)
            {
              flow->fp = fopen (name, "ab");
            }
          flow->flags = flow->flags | SENDING;
          log_debug (
            "NEW_THRD: [%p][%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d]",
            flow,
            filename (flow->ip_src, flow->port_src, flow->ip_dst, flow->port_dst));
          pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow);
          // int rc = pthread_setname_np (pthread_self (), name);
        }
      pthread_mutex_unlock (&air_mutex);
      /*
       * unlock
       */
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

  pkt_que = spsc_init (PKT_QUE_CAP);
  log_debug ("pkt_que: %p", pkt_que);

  fa = flow_arr_init (FLOW_ARR_CAP);
  log_debug ("flow_ptr: %p", fa);

  // reentrant lock
  pthread_mutexattr_t attr;
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&air_mutex, &attr);
  pthread_mutexattr_destroy (&attr);

  pthread_t tht_dispatch_flow;
  pthread_create (&tht_dispatch_flow, NULL, th_dispatch_flow, (void *) pkt_que);
  log_debug ("tht_dispatch_flow: %u", tht_dispatch_flow);

  // block
  filter_exp = argv[1] == NULL ? filter_exp : argv[1];
  log_debug ("filter_exp: %s", filter_exp);
  loop (filter_exp);

  pthread_exit (NULL);

  pthread_mutex_destroy (&air_mutex);

  fclose (fp);
}
