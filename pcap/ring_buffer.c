#include <pcap.h>
#include <string.h>

int cur;
int nxt;
int isn;
int size_win;

u_char payload_buffer[1000000];

void
store_packet (flow_t flow, const u_char *data, u_int32_t length, u_int32_t seq)
{
  u_int offset = seq - state->isn;

  memcpy(payload_buffer, data, length);
}
