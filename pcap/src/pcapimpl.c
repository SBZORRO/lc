#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "flow.h"
#include "src/log.c/log.h"
#include "src/spsc_queue.h"

unsigned int bufsize = 1024 * 1024 * 1024;

extern spsc_queue *pkt_que;

int
loop (char *filter_exp)
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

  log_debug ("LOOPPING");
  pcap_loop (pt, -1, handler, NULL);
  return 0;
}

char *
get_if ()
{
  char buf[PCAP_ERRBUF_SIZE];
  pcap_if_t *pit[1];
  int res = pcap_findalldevs (pit, buf);
  log_debug ("pit: %s\n", (pit[0])->name);
  return (pit[0])->name;
}

void
dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
  /* spsc_queue *q = (spsc_queue *) user; */

  u_char *pkt = check_malloc (h->caplen);
  memcpy (pkt, p, h->caplen);

  log_debug ("pcap_pkthdr: [%ld.%06ld][%u][%u]",
             (long) h->ts.tv_sec, (long) h->ts.tv_usec, h->caplen, h->len);

  if (!spsc_enqueue (pkt_que, pkt))
    {
      log_warn ("spsc_discard: [%u][%u][%u]",
                pkt_que->head, pkt_que->tail, pkt_que->capacity);
      free (pkt);
    }
}
