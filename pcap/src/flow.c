#include "flow.h"
#include <arpa/inet.h>
#include <bits/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

flow_state_t *flow_hash[0];

flow_t *flow_ptr;
int flow_len = 0;
int flow_cap = 10;

flow_t **
flow_ptr_init (flow_t **flow, int size)
{
  *flow = MALLOC (flow_t, size);
  return flow;
}

void
flow_reset (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      flow_state_free (ptr);
      ptr = ptr->next;
    }
  flow->next = NULL;
  flow->flags = 0;
  flow->isn = 0;
  flow->nxt = 0;
  flow->ts = (struct timespec) { 0 };
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

  flow->next = NULL;
  flow->nxt = 0;
  flow->isn = 0;

  // reentrant lock
  pthread_mutexattr_t attr;
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&flow->mutex, &attr);
  pthread_mutexattr_destroy (&attr);

  /* SET_IP (flow, src, src_addr); */
  /* SET_IP (flow, src, dst_addr); */
  /* if (src_addr != NULL) */
  /*   { */
  /*     char *src = strdup (src_addr); */
  /*     char *src_ip = strsep (&src, ":"); */
  /*     char *src_port = strsep (&src, ":"); */
  /*     /\* flow->ip_src.s_addr = inet_addr (ip); *\/ */
  /*     inet_aton (src_ip, &flow->ip_src); */
  /*     flow->port_src = htons (atoi (src_port)); */
  /*     free (src); */
  /*   } */
  /* if (dst_addr != NULL) */
  /*   { */
  /*     char *dst = strdup (dst_addr); */
  /*     char *dst_ip = strsep (&dst, ":"); */
  /*     char *dst_port = strsep (&dst, ":"); */
  /*     /\* flow->ip_dst.s_addr = inet_addr (dst_ip); *\/ */
  /*     inet_aton (dst_ip, &flow->ip_dst); */
  /*     flow->port_dst = htons (atoi (dst_port)); */
  /*     free (dst); */
  /*   } */

  return flow;
}

flow_t *
flow_find (flow_t *flow, int len,
           const struct in_addr src, const struct in_addr dst,
           const u_short sport, const u_short dport)
{
  for (int i = 0; i < len; i++)
    {
      if (flow[i].ip_src.s_addr == src.s_addr && flow[i].port_src == sport
          && flow[i].ip_dst.s_addr == dst.s_addr && flow[i].port_dst == dport)
        {
          return flow + i;
        }
    }
  flow_t *f = NULL;
  if (flow_len < flow_cap)
    {
      f = flow + len;
    }
  else
    {
      f = flow_grow ();
    }
  flow_init (f, src, dst, sport, dport);
  flow_len++;
  return f;
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

void *
check_malloc (size_t size)
{
  void *ptr;

  if ((ptr = malloc (size)) == NULL)
    {
      /* DEBUG(0) ("Malloc failed - out of memory?"); */
      exit (1);
    }
  return ptr;
}

void *
check_realloc (void *ptr, size_t size)
{
  void *newp = realloc (ptr, size);
  if (newp == NULL && size != 0)
    {
      perror ("realloc");
      // ptr 仍然安全，但你应该处理错误
    }
  return newp;
}

flow_t *
flow_grow ()
{
  if (flow_len == flow_cap)
    {
      size_t new_flow_cap = flow_cap * 2;
      flow_t *tmp = REALLOC (flow_ptr, flow_t, new_flow_cap);
      if (!tmp)
        {
          perror ("realloc");
          free (flow_ptr);
          exit (1);
        }
      flow_ptr = tmp;
      flow_cap = new_flow_cap;
    }
  return flow_ptr + flow_len;
}

void
flow_state_detach_before (flow_t *flow, flow_state_t *cur)
{
  flow_state_t *ptr = flow->next;
  while (ptr != cur)
    {
      flow_state_pop (flow, ptr);
      ptr = ptr->next;
    }
}

flow_state_t *
flow_state_pop (flow_t *flow, flow_state_t *state)
{
  pthread_mutex_lock (&flow->mutex);
  if (flow->nxt == state->seq)
    {
      flow->nxt += state->len;
    }
  flow->next = state->next;
  flow->size--;
  pthread_mutex_unlock (&flow->mutex);
  return state;
}

flow_state_t *
flow_state_detach (flow_t *flow, flow_state_t *state)
{
  pthread_mutex_lock (&flow->mutex);

  flow_state_t *ptr = flow->next;
  if (ptr == state)
    {
      return flow_state_pop (flow, state);
    }

  while (ptr->next != state)
    {
      ptr = ptr->next;
    }
  ptr->next = state->next;
  flow->size--;

  pthread_mutex_unlock (&flow->mutex);
  return state;
}

flow_state_t *
flow_state_attach (flow_t *flow, flow_state_t *state)
{
  pthread_mutex_lock (&flow->mutex);

  state->flow = flow;
  u_int seq = state->seq;
  flow_state_t **ptr = &(flow->next);
  while (*ptr != NULL)
    {
      /* dup packet use new */
      if (seq == (*ptr)->seq)
        {
          state->next = (*ptr)->next;
          *ptr = &(*state);
          pthread_mutex_unlock (&flow->mutex);
          return state;
        }
      /* retrans packet */
      if (seq < (*ptr)->seq)
        {
          state->next = *ptr;
          *ptr = &(*state);
          pthread_mutex_unlock (&flow->mutex);
          return state;
        }
      ptr = &((*ptr)->next);
    }

  *ptr = &(*state);

  flow->size++;
  clock_gettime (CLOCK_REALTIME, &flow->ts);

  pthread_mutex_unlock (&flow->mutex);
  return state;
}

flow_state_t *
flow_state_create (flow_t *flow, u_int seq, u_int size_payload, const u_char *payload)
{
  size_t bytes = sizeof (flow_state_t) + size_payload * sizeof (u_char);
  flow_state_t *new_flow_state = check_malloc (bytes);
  /* flow_state_t *new_flow_state = MALLOC (flow_state_t, 1); */
  new_flow_state->next = NULL;
  new_flow_state->flow = NULL;
  /* new_flow_state->flow = flow; */
  new_flow_state->seq = seq;
  new_flow_state->len = size_payload;
  /* new_flow_state->payload = MALLOC (u_char, size_payload); */
  memcpy (new_flow_state->payload, payload, size_payload);

  /* flow_state_t **ptr = &(flow->next); */
  /* while (*ptr != NULL) */
  /*   { */
  /*     /\* dup packet use new *\/ */
  /*     if (seq == (*ptr)->seq) */
  /*       { */
  /*         new_flow_state->next = (*ptr)->next; */
  /*         *ptr = &(*new_flow_state); */
  /*         return new_flow_state; */
  /*       } */
  /*     /\* retrans packet *\/ */
  /*     if (seq < (*ptr)->seq) */
  /*       { */
  /*         new_flow_state->next = *ptr; */
  /*         *ptr = &(*new_flow_state); */
  /*         return new_flow_state; */
  /*       } */
  /*     ptr = &((*ptr)->next); */
  /*   } */

  /* *ptr = &(*new_flow_state); */
  return new_flow_state;
}

void
flow_print (flow_t *flow, int len)
{
  for (int i = 0; i < len; i++)
    {
      flow_t *f = &flow[i];
      printf ("FLOW: %u\n", i);
      printf ("  From: %s:%u\n", inet_ntoa (f->ip_src), ntohs (f->port_src));
      printf ("    To: %s:%u\n", inet_ntoa (f->ip_dst), ntohs (f->port_dst));
      printf ("  next: %p\n", f->next);
      printf ("   nxt: %u\n", f->nxt);
      printf ("   isn: %u\n", f->isn);
    }
}

void
flow_state_print (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      for (int i = 0; i < ptr->len; ++i)
        {
          printf ("%c", ptr->payload[i]);
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
      for (int i = 0; i < ptr->len; ++i)
        {
          printf ("%c", ptr->payload[i]);
        }
      ptr = ptr->next;
    }
  printf ("\n");
}

void
flow_state_free (flow_state_t *fs)
{
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
contain (u_char *str, int len, const char **targets)
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
      if (contain (ptr->payload, ptr->len, servos_resp))
        {
          return 1;
        }
      if (contain (ptr->payload, ptr->len, servou_resp))
        {
          return 2;
        }
      // contain (ptr->payload, ptr->len, servos_requ);

      ptr = ptr->next;
    }
  return 0;
}
