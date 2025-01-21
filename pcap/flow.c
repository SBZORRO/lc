#include <stdlib.h>
#include <string.h>
#include "captotcp.h"

flow_state_t *flow_hash[0];

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
create_flow_state (flow_t *flow, tcp_seq seq, u_int size_payload,
                   const u_char *payload)
{
  flow_state_t *new_flow_state = MALLOC (flow_state_t, 1);
  new_flow_state->next = NULL;
  new_flow_state->flow = flow;
  new_flow_state->seq = seq;
  new_flow_state->len = size_payload;
  new_flow_state->payload = MALLOC (u_char, size_payload);
  memcpy (new_flow_state->payload, payload, size_payload);

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

void
print_flow_state (flow_t *flow)
{
  /* print source and destination IP addresses */
  printf ("       From: %s\n", inet_ntoa (flow->ip_src));
  printf ("         To: %s\n", inet_ntoa (flow->ip_dst));

  printf ("   Src port: %u\n", ntohs (flow->sport));
  printf ("   Dst port: %u\n", ntohs (flow->dport));

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

flow_t
find_flow (flow_t *flow, int len, const struct sniff_ip *ip,
           const struct sniff_tcp *tcp)
{
  for (int i = 0; i < len; i++)
    {
      if (flow[i].ip_src.s_addr == ip->ip_src.s_addr
          && flow[i].sport == tcp->th_sport)
        {
          return flow[i];
        }
    }
  return flow[0];
}
