#include <endian.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "packet.h"

int loop ();
char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

char filter_exp[] = "dst port 9998"; /* The filter expression */

int
main (int argc, char *argv[])
{
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

void
dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  static int count = 1; /* packet counter */

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

  printf ("%u--%u", htobe32 (tcp->th_seq), htobe32 (tcp->th_ack));
  for (int i = 0; i < size_payload; ++i)
    {
      printf ("%c", payload[i]);
    }
  printf ("\n");
}
