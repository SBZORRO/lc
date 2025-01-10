#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>

char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h,
		  const u_char *p);
int
main (int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp; /* The compiled filter expression */
  char filter_exp[] = "port 9998"; /* The filter expression */
  bpf_u_int32 mask; /* The netmask of our sniffing device */
  bpf_u_int32 net;  /* The IP of our sniffing device */
  pcap_t *pt;
  struct pcap_pkthdr header; /* The header that pcap gives us */
  const u_char *packet;	     /* The actual packet */

  pcap_handler handler = dl_ethernet;

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
  /* packet = pcap_next (pt, &header); */
  /* printf ("packet: %s\n", packet); */

  pcap_loop (pt, -1, handler, NULL);
  return (0);
}

char *
get_if ()
{
  char buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *pit[100];
  int res = pcap_findalldevs (pit, buf);
  printf ("pit: %s\n", (pit[0])->name);
  return (pit[0])->name;
}

void
dl_ethernet (u_char *user, const struct pcap_pkthdr *h,
	     const u_char *p)
{
  for (int i = 0; i < h->len; ++i)
    {
      printf ("packet%d: %d\n", i, p[i]);
    }
    /* u_int caplen = h->caplen; */
    /* u_int length = h->len; */
    /* struct ether_header *eth_header = (struct ether_header *) p; */

    /* if (length != caplen) { */
    /* } */

    /* if (caplen < sizeof(struct ether_header)) { */
    /*   return; */
    /* } */

    /* /\* we're only expecting IP datagrams, nothing else *\/ */
    /* if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) { */
    /*   ntohs(eth_header->ether_type)); */
    /*   return; */
    /* } */

    /* process_ip(p + sizeof(struct ether_header), */
    /*      caplen - sizeof(struct ether_header)) */;
}
