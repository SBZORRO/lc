#include "flow.h"
#include <arpa/inet.h>
#include <bits/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "src/log.c/log.h"
#include "src/packet.h"

flow_arr_t *
flow_arr_init (uint32_t size)
{
  flow_arr_t *p = check_malloc (sizeof (flow_arr_t) + sizeof (flow_t) * size);
  p->flow_cap = size;
  p->flow_len = 0;
  return p;
}

flow_arr_t *
flow_arr_add (flow_arr_t *flow)
{
  if (flow->flow_len == flow->flow_cap)
    {
      /* TODO rework */
      /* flow_arr_t *new_flow = check_realloc (flow, sizeof (flow_arr_t) + sizeof (flow_t) * flow->flow_cap * 2); */
      /* new_flow->flow_cap = flow->flow_cap * 2; */
      /* new_flow->flow_len = flow->flow_len + 1; */
      /* return new_flow; */
      log_error ("OVERFLOW!");
      return NULL;
    }
  flow->flow_len = flow->flow_len + 1;
  return flow;
}

flow_t *
flow_find (flow_arr_t *fa,
           const struct in_addr src, const struct in_addr dst,
           const u_short sport, const u_short dport)
{
  for (int i = 0; i < fa->flow_len; i++)
    {
      if (fa->flow[i].ip_src.s_addr == src.s_addr
          && fa->flow[i].port_src == sport
          && fa->flow[i].ip_dst.s_addr == dst.s_addr
          && fa->flow[i].port_dst == dport)
        {
          return fa->flow + i;
        }
    }
  return NULL;
}

flow_t *
flow_init (flow_t *flow,
           const struct in_addr src, const struct in_addr dst,
           const u_short sport, const u_short dport)
{
  flow->ip_src = src;
  flow->port_src = sport;
  flow->ip_dst = dst;
  flow->port_dst = dport;
  flow->ip_tar.s_addr = 0;
  flow->port_tar = 0;

  flow->next = NULL;
  struct timespec ts = { 0 };
  flow->flags = 0;
  flow->sock = 0;
  FILE *fp = NULL;
  flow->size = 0;
  flow->seg_nxt = 0;

  // reentrant lock
  pthread_mutexattr_t attr;
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&flow->mutex, &attr);
  pthread_mutexattr_destroy (&attr);

  return flow;
}

void
flow_reset (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  flow->next = NULL; // detach first
  while (ptr)
    {
      flow_state_t *next = ptr->next;
      flow_state_free (ptr);
      ptr = next;
    }

  flow->ip_src.s_addr = 0;
  flow->port_src = 0;
  flow->ip_dst.s_addr = 0;
  flow->port_dst = 0;
  flow->ip_tar.s_addr = 0;
  flow->port_tar = 0;

  flow->next = NULL;
  struct timespec ts = { 0 };
  flow->flags = 0;
  flow->sock = 0;
  FILE *fp = NULL;
  flow->size = 0;
  flow->seg_nxt = 0;

  /* // reentrant lock */
  /* pthread_mutexattr_t attr; */
  /* pthread_mutexattr_init (&attr); */
  /* pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE); */
  /* pthread_mutex_init (&flow->mutex, &attr); */
  /* pthread_mutexattr_destroy (&attr); */
}

flow_t *
flow_set_dst (flow_t *flow, char *dst_addr)
{
  if (dst_addr != NULL)
    {
      char *dst = strdup (dst_addr);
      char *dst_ip = strsep (&dst, ":");
      char *dst_port = strsep (&dst, ":");
      /* flow->ip_dst.s_addr = inet_addr (dst_ip); */
      inet_aton (dst_ip, &flow->ip_dst);
      flow->port_dst = htons (atoi (dst_port));
      free (dst);
    }
  return flow;
}

flow_t *
flow_set_src (flow_t *flow, char *src_addr)
{
  if (src_addr != NULL)
    {
      char *src = strdup (src_addr);
      char *src_ip = strsep (&src, ":");
      char *src_port = strsep (&src, ":");
      /* flow->ip_dst.s_addr = inet_addr (dst_ip); */
      inet_aton (src_ip, &flow->ip_src);
      flow->port_src = htons (atoi (src_port));
      free (src);
    }
  return flow;
}

void
flow_state_detach_before (flow_t *flow, flow_state_t *cur)
{
  flow_state_t *ptr = flow->next;
  while (ptr != cur)
    {
      flow_state_pop (flow);
      ptr = ptr->next;
    }
}

flow_state_t *
flow_state_pop (flow_t *flow)
{
  pthread_mutex_lock (&flow->mutex);

  flow_state_t *state = flow->next;
  if (flow->seg_nxt >= state->seq)
    {
      flow->seg_nxt += state->size_payload;
    }
  flow->next = state->next;
  flow->size--;

  pthread_mutex_unlock (&flow->mutex);
  return flow->next;
}

flow_state_t *
flow_state_detach (flow_t *flow, flow_state_t *state)
{
  pthread_mutex_lock (&flow->mutex);

  if (state == NULL || flow->next == NULL)
    {
      return NULL;
    }

  flow_state_t *ptr = flow->next;
  if (ptr == state)
    {
      return flow_state_pop (flow);
    }

  while (ptr->next != state)
    {
      if (ptr->next == NULL)
        {
          return NULL;
        }
      ptr = ptr->next;
    }

  ptr->next = state->next;
  flow->size--;

  pthread_mutex_unlock (&flow->mutex);
  return ptr->next;
}

flow_state_t *
flow_state_attach (flow_t *flow, flow_state_t *state)
{
  pthread_mutex_lock (&flow->mutex);

  u_int seq = state->seq;
  clock_gettime (CLOCK_REALTIME, &flow->ts);
  if (flow->next == NULL)
    {
      flow->next = state;
      flow->size++;
      pthread_mutex_unlock (&flow->mutex);
      return state;
    }
  else
    {
      flow_state_t *ptr = flow->next;
      /* dup packet use new */
      if (seq == ptr->seq)
        {
          flow->next = state;
          pthread_mutex_unlock (&flow->mutex);
          return state;
        }
      /* retrans packet */
      if (SEQ_LT (seq, ptr->seq))
        {
          state->next = flow->next;
          flow->next = state;
          flow->size++;
          pthread_mutex_unlock (&flow->mutex);
          return state;
        }

      flow_state_t *prev = flow->next;
      ptr = prev->next;
      while (ptr != NULL)
        {
          /* dup packet use new */
          if (seq == ptr->seq)
            {
              state->next = ptr->next;
              prev->next = state;
              pthread_mutex_unlock (&flow->mutex);
              return state;
            }
          /* retrans packet */
          if (SEQ_LT (seq, ptr->seq))
            {
              state->next = ptr;
              prev->next = state;
              flow->size++;
              pthread_mutex_unlock (&flow->mutex);
              return state;
            }
          prev = ptr;
          ptr = ptr->next;
        }
      prev->next = state;
      flow->size++;
      pthread_mutex_unlock (&flow->mutex);
      return state;
    }
}

flow_state_t *
flow_state_create (flow_t *flow, u_int seq, u_int ack, u_int flags, u_int size_payload, u_int offset_payload, u_char *pkt)
{
  flow_state_t *new_flow_state = MALLOC (flow_state_t, 1);
  new_flow_state->next = NULL;
  new_flow_state->flow = flow;
  new_flow_state->seq = seq;
  new_flow_state->ack = ack;
  new_flow_state->size_payload = size_payload;
  new_flow_state->offset_payload = offset_payload;
  new_flow_state->flags = flags;
  new_flow_state->pkt = pkt;

  return new_flow_state;
}

void
flow_print (flow_t *flow, u_int len)
{
  for (int i = 0; i < len; i++)
    {
      flow_t *f = &flow[i];
      printf ("FLOW: %u\n", i);
      printf ("  From: %s:%u\n", inet_ntoa (f->ip_src), ntohs (f->port_src));
      printf ("    To: %s:%u\n", inet_ntoa (f->ip_dst), ntohs (f->port_dst));
      printf ("  next: %p\n", f->next);
      printf ("   nxt: %u\n", f->seg_nxt);
    }
}

void
flow_state_print (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      for (int i = 0; i < ptr->size_payload; ++i)
        {
          printf ("%c", ptr->pkt[i]);
        }
      // printf ("%u\n", ptr->len);
      ptr = ptr->next;
    }
  printf ("\n");
}

void
flow_state_assemble (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      for (int i = 0; i < ptr->size_payload; ++i)
        {
          printf ("%c", ptr->pkt[i]);
        }
      ptr = ptr->next;
    }
  printf ("\n");
}

void
flow_state_free (flow_state_t *fs)
{
  if (fs == NULL)
    return;
  fs->next = NULL;
  fs->flow = NULL;
  if (fs->pkt != NULL)
    {
      free (fs->pkt); // only if pkt is truly heap-owned by this node
    }
  fs->pkt = NULL;
  free (fs);
}

const char *servos_requ[] = { "\x1b", "HO", "RCTY1C", "RSEN0A", "SDADS", "SDADE", "SDADC", "SDADB", "RSTI1C", "SSMP0202F", "RADC14", NULL };
const char *servos_resp[] = { "900PCI", "Servo-s0", "Servo-i0", "Servo-s1", "Servo-i1", NULL };

const char *servou_resp[] = { "BER2057", "ER2015", "Servo-u0", "Servo-u1", "Servo-n0", "Servo-n1", "Servo-air0", "Servo-air1", NULL };

const char *default_resp = "*2A";

const char *EOT = "\x04";
const char *ESC = "\x1b";

const char *curve_phase_i = "\x81\x10\x80";
const char *curve_phase_p = "\x81\x20\x80";
const char *curve_phase_e = "\x81\x30\x80";

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

int
contain (u_char *str, u_int len, const char **targets)
{
  if (len == 0)
    {
      return 0;
    }
  // prefix
  for (int i = 0; targets[i] != NULL; i++)
    {
      int tarlen = strlen (targets[i]);
      int res = memcmp (str, targets[i], MIN (len, tarlen));
      if (res == 0)
        {
          return 1;
        }
    }

  // contain
  for (int i = 0; targets[i] != NULL; i++)
    {
      void *res = memmem (str, len, targets[i], strlen (targets[i]));
      if (res != NULL)
        {
          return 1;
        }
    }
  return 0;
}

int
detect (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      if (contain (ptr->pkt, ptr->size_payload, servos_resp))
        {
          return 1;
        }
      if (contain (ptr->pkt, ptr->size_payload, servou_resp))
        {
          return 2;
        }
      // contain (ptr->payload, ptr->len, servos_requ);

      ptr = ptr->next;
    }
  return 0;
}
