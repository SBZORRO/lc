#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include "flow.h"
#include "log.c/log.h"

int
loop (char *filter_exp)
{
  pcap_handler handler = dl_ethernet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp; /* The compiled filter expression */
  bpf_u_int32 mask;      /* The netmask of our sniffing device */
  bpf_u_int32 net;       /* The IP of our sniffing device */
  pcap_t *pt;
  pcap_if_t *pit[1];
  char *dev;

  if (pcap_findalldevs (pit, errbuf) == -1)
    {
      fprintf (stderr, "Couldn't find default device: %s\n", errbuf);
      return (2);
    }
  dev = (pit[0])->name;
  if (pcap_lookupnet (dev, &net, &mask, errbuf) == -1)
    {
      fprintf (stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
      net = 0;
      mask = 0;
    }

  /* rpcap */
  /* struct pcap_rmtauth auth; */
  /* memset (&auth, 0, sizeof (auth)); */
  /* auth.type = RPCAP_RMTAUTH_NULL; */
  /* auth.username = ""; */
  /* auth.password = ""; */
  /* pcap_if_t *alldevs = NULL; */
  /* pcap_findalldevs_ex ("rpcap://127.0.0.1:2002/", &auth, &alldevs, errbuf); */

  pt = pcap_open_live (dev, CPTR_BUF_SIZE, 1, 1000, errbuf);
  // pt = pcap_open_live ("lo", CPTR_BUF_SIZE, 1, 1000, errbuf);
  // pt = pcap_open_live ("rpcap://127.0.0.1:2002/", CPTR_BUF_SIZE, 1, 1000, errbuf);
  // pt = pcap_open_offline ("../test/si.pcapng", errbuf);
  if (pt == NULL)
    {
      fprintf (stderr, "Could't open D %s: \n", errbuf);
    }

  if (pcap_compile (pt, &fp, filter_exp, 0, net) == -1)
    {
      fprintf (stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr (pt));
      return (2);
    }
  if (pcap_setfilter (pt, &fp) == -1)
    {
      fprintf (stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr (pt));
      return (2);
    }

  log_debug ("LOOPPING");
  pcap_loop (pt, -1, handler, NULL);
  return 0;
}
