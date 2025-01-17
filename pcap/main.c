#include <endian.h>
#include <pcap/pcap.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "client.h"
#include "packet.h"

void print_flow_state (flow_t *flow);

int loop ();
char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

char filter_exp[] = "dst port 9998"; /* The filter expression */

flow_t flow;
flow_state_t *flow_hash[0];

int
main (int argc, char *argv[])
{
  flow.next = NULL;
  flow.nxt = 0;
  flow.isn = 0;
  /* flow.src; */
  /* flow.dst; */
  /* flow.sport; */
  /* flow.dport; */
  do_connect ();
  loop ();
}

int
loop ()
{
  struct bpf_program fp; /* The compiled filter expression */
  bpf_u_int32 mask;      /* The netmask of our sniffing device */
  bpf_u_int32 net;       /* The IP of our sniffing device */

  pcap_handler handler = dl_ethernet;

  pcap_t *pt;
  char errbuf[PCAP_ERRBUF_SIZE];

  pt = pcap_open_live (get_if (), BUFSIZ, 1, 1000, errbuf);
  if (pt == NULL)
    {
      fprintf (stderr, "Could't open D %s: \n", errbuf);
    }

  if (pcap_compile (pt, &fp, filter_exp, 0, net) == -1)
    {
      fprintf (stderr, "Couldn't parse filter %s: %s\n", filter_exp,
               pcap_geterr (pt));
      return (2);
    }
  if (pcap_setfilter (pt, &fp) == -1)
    {
      fprintf (stderr, "Couldn't install filter %s: %s\n", filter_exp,
               pcap_geterr (pt));
      return (2);
    }

  pcap_loop (pt, -1, handler, NULL);
  return 0;
}

int
loop_handler (pcap_handler handler)
{
  struct bpf_program fp; /* The compiled filter expression */
  bpf_u_int32 mask;      /* The netmask of our sniffing device */
  bpf_u_int32 net;       /* The IP of our sniffing device */

  pcap_t *pt;
  char errbuf[PCAP_ERRBUF_SIZE];

  pt = pcap_open_live (get_if (), BUFSIZ, 1, 1000, errbuf);
  if (pt == NULL)
    {
      fprintf (stderr, "Could't open D %s: \n", errbuf);
    }

  if (pcap_compile (pt, &fp, filter_exp, 0, net) == -1)
    {
      fprintf (stderr, "Couldn't parse filter %s: %s\n", filter_exp,
               pcap_geterr (pt));
      return (2);
    }
  if (pcap_setfilter (pt, &fp) == -1)
    {
      fprintf (stderr, "Couldn't install filter %s: %s\n", filter_exp,
               pcap_geterr (pt));
      return (2);
    }

  printf ("loop!!!\n");
  pcap_loop (pt, -1, handler, NULL);
  return 0;
}

char *
get_if ()
{
  char buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *pit[1];
  int res = pcap_findalldevs (pit, buf);
  printf ("pit: %s\n", (pit[0])->name);
  return (pit[0])->name;
}

#define MALLOC(type, num) (type *) check_malloc ((num) * sizeof (type))

/* Simple wrapper around the malloc() function */
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

/* Create a new flow state structure, initialize its contents, and add
 * it to its hash bucket.  It is prepended to the hash bucket because
 * 1) doing so is fast (requiring constant time regardless of bucket
 * size; and 2) it'll tend to make lookups faster for more recently
 * added state, which will probably be more often used state.
 *
 * Returns a pointer to the new state. */
flow_state_t *
create_flow_state (flow_t *flow, tcp_seq seq, u_int size_payload,
                   const u_char *payload)
{
  flow_state_t *new_flow_state = MALLOC (flow_state_t, 1);
  new_flow_state->next = NULL;
  new_flow_state->flow = *flow;
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
dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
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
      return;
    }

  /* print source and destination IP addresses */
  printf ("       From: %s\n", inet_ntoa (ip->ip_src));
  printf ("         To: %s\n", inet_ntoa (ip->ip_dst));

  tcp = (struct sniff_tcp *) (p + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF (tcp) * 4;
  if (size_tcp < 20)
    {
      printf ("   * Invalid TCP header length: %u bytes\n", size_tcp);
      return;
    }
  printf ("   Src port: %d\n", ntohs (tcp->th_sport));
  printf ("   Dst port: %d\n", ntohs (tcp->th_dport));

  size_payload = ntohs (ip->ip_len) - (size_ip + size_tcp);
  payload = (u_char *) (p + SIZE_ETHERNET + size_ip + size_tcp);

  u_int seq = ntohl (tcp->th_seq);
  u_int ack = ntohl (tcp->th_ack);

  if (flow.isn == 0 && flow.nxt == 0)
    {
      flow.isn = seq;
      flow.nxt = seq;
    }
  /* create_flow_state (&flow, seq, size_payload, payload); */
  if (flow.nxt == seq)
    {
      do_sent ((char *) payload, (size_t) size_payload);
      flow.nxt += size_payload;
      flow_state_t *state = flow.next;
      while (state != NULL && flow.nxt == state->seq)
        {
          do_sent ((char *) state->payload, (size_t) state->len);
          flow.nxt += state->len;
          state = state->next;
        }
      flow.next = state;
    }
  else
    {
      create_flow_state (&flow, seq, size_payload, payload);
    }

  printf ("%u--%u--%u\n", flow.nxt, seq, ack);
  for (int i = 0; i < size_payload; ++i)
    {
      printf ("%c", payload[i]);
    }
  printf ("\n");

  print_flow_state (&flow);
  /* do_sent ((char *) payload, (size_t) size_payload); */
}

void
print_flow_state (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  printf ("---------------------------------------------------\n");
  while (ptr != NULL)
    {
      printf ("%u\n", ptr->seq);
      for (int i = 0; i < ptr->len; ++i)
        {
          printf ("%c", ptr->payload[i]);
        }
      printf ("\n");
      printf ("---------------------------------------------------\n");
      ptr = ptr->next;
    }
}
