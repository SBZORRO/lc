#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "captotcp.h"

flow_state_t *flow_hash[0];

flow_t *flow_ptr;
int flow_len = 0;

void
reset_flow (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      free_flow_state (ptr);
      ptr = ptr->next;
    }
  flow->next = NULL;
}

flow_t **
init_flow (flow_t **flow, int size)
{
  *flow = MALLOC (flow_t, size);
  return flow;
}

flow_t *
add_flow (flow_t *flow, char *src, char *dst)
{
  char *dst_ip = strtok (dst, ":");
  char *dst_port = strtok (NULL, "\0");

  char *ip = strtok (src, ":");
  char *port = strtok (NULL, "\0");

  /* inet_aton (ip, &flow_ptr[j].ip_src); */
  flow->ip_src.s_addr = inet_addr (ip);
  flow->sport = htons (atoi (port));
  flow->ip_dst.s_addr = inet_addr (dst_ip);
  flow->dport = htons (atoi (dst_port));
  flow->next = NULL;
  flow->nxt = 0;
  flow->isn = 0;
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

flow_state_t *
detach_flow_state (flow_t *flow, flow_state_t *state)
{
  /* while (state != NULL && flow->nxt == state->seq) */
  /*   { */
  /* do_sent ((char *) state->payload, (size_t) state->len); */
  flow->nxt += state->len;
  flow_state_t *tbf = state;
  state = state->next;
  /* free_flow_state (tbf); */
  /* } */
  flow->next = state;
  return tbf;
}

flow_state_t *
attach_flow_state (flow_t *flow, flow_state_t *new_flow_state)
{
  new_flow_state->flow = flow;
  u_int seq = new_flow_state->seq;
  flow_state_t **ptr = &(flow->next);
  while (*ptr != NULL)
    {
      /* dup packet use new */
      if (seq == (*ptr)->seq)
        {
          new_flow_state->next = (*ptr)->next;
          *ptr = &(*new_flow_state);
          return new_flow_state;
        }
      /* retrans packet */
      if (seq < (*ptr)->seq)
        {
          new_flow_state->next = *ptr;
          *ptr = &(*new_flow_state);
          return new_flow_state;
        }
      ptr = &((*ptr)->next);
    }

  *ptr = &(*new_flow_state);
  return new_flow_state;
}

flow_state_t *
create_flow_state (flow_t *flow, u_int seq, u_int size_payload, const u_char *payload)
{
  flow_state_t *new_flow_state = MALLOC (flow_state_t, 1);
  new_flow_state->next = NULL;
  new_flow_state->flow = NULL;
  /* new_flow_state->flow = flow; */
  new_flow_state->seq = seq;
  new_flow_state->len = size_payload;
  new_flow_state->payload = MALLOC (u_char, size_payload);
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
print_flow (flow_t *flow, int len)
{
  for (int i = 0; i < len; i++)
    {
      flow_t *f = &flow[i];
      printf ("FLOW: %u\n", i);
      printf ("  From: %s:%u\n", inet_ntoa (f->ip_src), ntohs (f->sport));
      printf ("    To: %s:%u\n", inet_ntoa (f->ip_dst), ntohs (f->dport));
      printf ("  next: %p\n", f->next);
      printf ("   nxt: %u\n", f->nxt);
      printf ("   isn: %u\n", f->isn);
    }
}

void
print_flow_state (flow_t *flow)
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
free_flow_state (flow_state_t *fs)
{
  free (fs->payload);
  free (fs);
}

flow_t *
find_flow (flow_t *flow, int len, const struct in_addr addr, const u_short port)
{
  for (int i = 0; i < len; i++)
    {
      if (flow[i].ip_src.s_addr == addr.s_addr && flow[i].sport == port)
        {
          return flow + i;
        }
    }
  return flow;
}
