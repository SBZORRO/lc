#include <inttypes.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/flow.h"

static void
hex_dump (const uint8_t *p, int len, int max_bytes)
{
  int n = len < max_bytes ? len : max_bytes;
  for (int i = 0; i < n; i++)
    {
      printf ("%02x%s", p[i], (i + 1) % 16 == 0 ? "\n" : " ");
    }
  if (n % 16 != 0)
    printf ("\n");
  if (len > max_bytes)
    printf ("... (%d bytes total)\n", len);
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    {
      fprintf (stderr, "usage: %s <file.pcap|file.pcapng>\n", argv[0]);
      return 2;
    }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pt = pcap_open_offline (argv[1], errbuf);
  if (!pt)
    {
      fprintf (stderr, "pcap_open_offline failed: %s\n", errbuf);
      return 1;
    }

  struct bpf_program fp; /* The compiled filter expression */
  const char *filter_exp = "";
  if (pcap_compile (pt, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
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

  pcap_handler handler = dl_ethernet;
  pcap_loop (pt, -1, handler, NULL);

  return 0;

  /* int dlt = pcap_datalink (pt); */
  /* printf ("DLT=%d (%s)\n", dlt, pcap_datalink_val_to_name (dlt)); */

  /* struct pcap_pkthdr *hdr; */
  /* const uint8_t *data; */
  /* int rc; */
  /* uint64_t idx = 0; */

  /* while ((rc = pcap_next_ex (pt, &hdr, &data)) >= 0) */
  /*   { */
  /*     if (rc == 0) */
  /*       continue; // unlikely for offline, but safe */

  /*     idx++; */
  /*     // hdr->ts.tv_sec / hdr->ts.tv_usec (或 tv_nsec 取决于精度设置) */
  /*     printf ("#%" PRIu64 " ts=%ld.%06ld caplen=%u len=%u\n", */
  /*             idx, */
  /*             (long) hdr->ts.tv_sec, (long) hdr->ts.tv_usec, */
  /*             hdr->caplen, hdr->len); */

  /*     hex_dump (data, (int) hdr->caplen, 64); */
  /*   } */

  /* if (rc == -1) */
  /*   { */
  /*     fprintf (stderr, "pcap_next_ex error: %s\n", pcap_geterr (pt)); */
  /*   } */

  /* pcap_close (pt); */
  /* return (rc == -1) ? 1 : 0; */
}
