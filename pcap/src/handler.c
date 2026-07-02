#include <pcap/pcap.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "flow.h"
#include "log.c/log.h"
#include "packet.h"
#include "spsc_queue.h"

flow_arr_t *fa;            // flow array
pthread_mutex_t air_mutex; // flow add/init/reset mutex

/* servos */
/* servou */
/* drager */
char *server[] = { NULL, "127.0.0.1:9999", "127.0.0.1:9998", "127.0.0.1:9997", NULL };

void *
th_send_flow (void *f)
{
  flow_t *flow = (flow_t *) f;
  int retry = 0;
  while (1)
    {
      pthread_mutex_lock (&flow->mutex);
      flow_state_t *state = flow_state_fix_and_pop (flow);
      pthread_mutex_unlock (&flow->mutex);

      if (state == NULL)
        {
          if (++retry <= 60)
            {
              sleep (1);
              continue;
            }
          pthread_mutex_lock (&air_mutex);
          pthread_mutex_lock (&flow->mutex);
          state = flow_state_fix_and_pop (flow);
          pthread_mutex_unlock (&flow->mutex);
          if (state == NULL)
            {
              flow_reset (flow);
              log_info ("RST_FLOW: [%p]", flow);
              pthread_mutex_unlock (&air_mutex);
              break;
            }
          pthread_mutex_unlock (&air_mutex);
        }
      retry = 0;
      log_debug ("POP_STAT: [%p][%p]", flow, state);

      /* write the data into the file */
      flow->fp = fopen (flow->filename, "ab");
      size_t sw = fwrite ((char *) state->pkt + state->offset_payload, 1, (size_t) state->size_payload, flow->fp);
      if (sw != state->size_payload)
        {
          perror ("fwrite");
          log_error ("FAILED_WRITING: [%p][%p][%u][%u]", flow, state, state->seq, sw);
          // DEBUG (1) ("write to %s failed: ", flow_filename (state->flow));
        }
      fflush (flow->fp);
      fclose (flow->fp);
      flow->fp = NULL;
      log_trace ("   wrote: [%p][%p][%u][%u]", flow, state, state->seq, sw);

      flow_detect_t res = detect (flow, state);
      log_debug ("  detect: [%u][%u][%u][%u]", res.dir, res.type, res.target, res.protocol);
      if (res.target == 0)
        {
          flow_state_free (state);
          continue;
        }
      log_info ("DETECTED: [%p][%p][%u][%u][%u][%u]", flow, state, state->seq, res.dir, res.protocol, res.type);

      if (flow->sock == FLOW_INVALID_SOCKET)
        {
          SET_IP (flow, tar, server[res.target]);
          while ((flow->sock = do_connect (flow->ip_tar, flow->port_tar)) == FLOW_INVALID_SOCKET)
            {
              log_warn ("FAILED_CONNECTING: [%p][%llu]", flow, (unsigned long long) flow->sock);
              break;
              // sleep (1);
            }
          log_info ("CONECTED: [%p][%p][%u][%llu]", flow, state, state->seq, (unsigned long long) flow->sock);
          if (flow->sock == FLOW_INVALID_SOCKET)
            {
              flow_state_free (state);
              continue;
            }
        }
      log_trace (" sending: [%p][%p][%u]", flow, state, state->seq);
      do_sent (flow, (char *) state->pkt + state->offset_payload, (size_t) state->size_payload);

      flow_state_free (state);
    }

  pthread_exit (NULL);
  return NULL;
}

void *
th_dispatch_flow (void *arg)
{
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
          log_warn ("Invalid_IP_header_length: %u\n", size_ip);
          free (p);
          continue;
        }
      /* Process TCP */
      tcp = (struct sniff_tcp *) (p + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF (tcp) * 4;
      if (size_tcp < 20)
        {
          log_warn ("Invalid_TCP_ header_length: %u\n", size_tcp);
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

      log_trace ("DEQUEUED: [%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d][%u][%u][%u][%u][%u]", filename (ip->ip_src, tcp->th_sport, ip->ip_dst, tcp->th_dport), seq, ack, flags, offset_payload, size_payload);
      log_hex (LOG_TRACE, "HPAYLOAD: %s", payload, size_payload);
      log_trace ("APAYLOAD: %.*s", size_payload, payload);

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
              free (p);
              pthread_mutex_unlock (&air_mutex);
              continue;
            }
          flow_init (flow, ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport);
          flow_link_peer (flow, flow_find_peer (fa, flow));
          log_info ("NEW_FLOW: [%p][%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d]", flow, filename (flow->ip_src, flow->port_src, flow->ip_dst, flow->port_dst));
        }

      // handle RST/SYN flags
      pthread_mutex_lock (&flow->mutex);
      uint32_t flow_flags = flow_handshake (flow, flags, seq, size_payload);
      pthread_mutex_unlock (&flow->mutex);
      if (flow_flags == 0)
        {
          free (p);
          pthread_mutex_unlock (&air_mutex);
          continue;
        }

      flow_state_t *state = flow_state_create (flow, seq, ack, flags, size_payload, offset_payload, p);
      pthread_mutex_lock (&flow->mutex);
      flow_state_attach (flow, state);
      pthread_mutex_unlock (&flow->mutex);
      log_debug ("NEW_STAT: [%p][%p][%u]", flow, state, seq);

      if (!(flow->flags & SENDING))
        {
          /* char *name = flow_filename (flow); */
          /* if (flow->fp == NULL) */
          /*   { */
          /*     flow->fp = fopen (name, "ab"); */
          /*   } */
          flow->flags = flow->flags | SENDING;
          log_info ("NEW_THRD: [%p][%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d]", flow, filename (flow->ip_src, flow->port_src, flow->ip_dst, flow->port_dst));
          pthread_create (&flow->thread, NULL, th_send_flow, (void *) flow);
          // int rc = pthread_setname_np (pthread_self (), name);
        }
      pthread_mutex_unlock (&air_mutex);
      /*
       * unlock
       */
    }
  pthread_exit (NULL);
  return NULL;
}

spsc_queue *pkt_que;

void
dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  /* spsc_queue *q = (spsc_queue *) user; */

  uint8_t *pkt = MALLOC (uint8_t, h->caplen);
  memcpy (pkt, p, h->caplen);

  log_trace ("  pkthdr: [%ld.%06ld][%u][%u]",
             (long) h->ts.tv_sec, (long) h->ts.tv_usec, h->caplen, h->len);
  log_hex (LOG_TRACE, "  pktbdy: %s", pkt, h->caplen);

  if (!spsc_enqueue (pkt_que, pkt))
    {
      log_warn ("spsc_discard: [%u][%u][%u]",
                pkt_que->head, pkt_que->tail, pkt_que->capacity);
      free (pkt);
    }
}
