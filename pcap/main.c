#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "captotcp.h"

int loop ();
char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
unsigned int bufsize = 1024 * 1024 * 1024;

char *dst_ip;
char *dst_port;
u_short d_port;
u_int d_ip;

/* char filter_exp[] = "dst port 9998"; /\* The filter expression *\/ */
char *filter_exp = "dst port 9998"; /* The filter expression */

flow_t *flow_ptr;
int flow_len;

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

int
loop ()
{
  struct bpf_program fp; /* The compiled filter expression */
  bpf_u_int32 mask;      /* The netmask of our sniffing device */
  bpf_u_int32 net;       /* The IP of our sniffing device */

  pcap_handler handler = dl_ethernet;

  pcap_t *pt;
  char errbuf[PCAP_ERRBUF_SIZE];

  pt = pcap_open_live (get_if (), bufsize, 1, 1000, errbuf);
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

char *
get_if ()
{
  char buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *pit[1];
  int res = pcap_findalldevs (pit, buf);
  printf ("pit: %s\n", (pit[0])->name);
  return (pit[0])->name;
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

  tcp = (struct sniff_tcp *) (p + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF (tcp) * 4;
  if (size_tcp < 20)
    {
      printf ("   * Invalid TCP header length: %u bytes\n", size_tcp);
      return;
    }

  flow_t flow = find_flow (flow_ptr, flow_len, ip, tcp);
  if ((tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN)
      || (tcp->th_flags & TH_RST))
    {
      reset_flow (&flow);
    }

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
          flow_state_t *tbf = state;
          state = state->next;
          free_flow_state (tbf);
        }
      flow.next = state;
    }
  else
    {
5      create_flow_state (&flow, seq, size_payload, payload);
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
init_flow (int argc, char *argv[])
{
  flow_ptr = MALLOC (flow_t, argc - 3);
  flow_len = argc - 3;
  for (int i = 3, j = 0; i < argc; i++, j++)
    {
      char *addr = argv[i];
      char *ip = strtok (addr, ":");
      char *port = strtok (NULL, "\0");
      /* inet_aton (ip, &flow_ptr[j].ip_src); */
      flow_ptr[j].ip_src.s_addr = inet_addr (dst_ip);
      flow_ptr[j].sport = htons (atoi (port));
      flow_ptr[j].next = NULL;
      flow_ptr[j].nxt = 0;
      flow_ptr[j].isn = 0;
    }
}

void
init_dst_addr (char *argv[])
{
  char *addr = argv[2];
  dst_ip = strtok (addr, ":");
  dst_port = strtok (NULL, "\0");
  d_port = htons (atoi (dst_port));
  d_ip = inet_addr (dst_ip);
}

int
main (int argc, char *argv[])
{
  /* 1: pcap-filter */
  filter_exp = argv[1];

  /* 2: dst addr */
  init_dst_addr (argv);
  /* char *addr = argv[2]; */
  /* dst_ip = strtok (addr, ":"); */
  /* dst_port = strtok (NULL, "\0"); */
  /* d_port = htons (atoi (dst_port)); */
  /* d_ip = inet_addr (dst_ip); */

  do_connect (d_ip, d_port);

  /* 3-...: src addr */
  init_flow (argc, argv);
  /* flow_ptr = MALLOC (flow_t, argc - 3); */
  /* flow_len = argc - 3; */
  /* for (int i = 3, j = 0; i < argc; i++, j++) */
  /*   { */
  /*     char *addr = argv[i]; */
  /*     char *ip = strtok (addr, ":"); */
  /*     char *port = strtok (NULL, "\0"); */
  /*     /\* inet_aton (ip, &flow_ptr[j].ip_src); *\/ */
  /*     flow_ptr[j].ip_src.s_addr = inet_addr (dst_ip); */
  /*     flow_ptr[j].sport = htons (atoi (port)); */
  /*     flow_ptr[j].next = NULL; */
  /*     flow_ptr[j].nxt = 0; */
  /*     flow_ptr[j].isn = 0; */
  /*   } */

  loop ();

  pthread_t pid = 1;
  pthread_create (&pid, NULL, NULL, NULL);

  pthread_mutex_t pmt;
  pthread_mutex_lock (&pmt);
}
