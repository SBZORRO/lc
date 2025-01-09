#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
  char dev[100];
  pcap_if_t* ift[100];
  
  pcap_findalldevs(ift, dev);
  if (dev == NULL) {
    fprintf(stderr, "C%s\n", dev);
    return(2);
  }
  printf("D:%s\n", ift[1]->name);
  return 0;
}
