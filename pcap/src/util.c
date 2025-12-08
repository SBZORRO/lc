#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "flow.h"

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

void *
check_realloc (void *ptr, size_t size)
{
  void *newp = realloc (ptr, size);
  if (newp == NULL && size != 0)
    {
      perror ("realloc");
      exit (1);
      // ptr 仍然安全，但你应该处理错误
    }
  return newp;
}

#define RING_SIZE 6

char *
flow_filename (flow_t *flow)
{
  static char ring_buffer[RING_SIZE][48];
  static int ring_pos = 0;

  ring_pos = (ring_pos + 1) % RING_SIZE;

  sprintf (ring_buffer[ring_pos],
           "%03d.%03d.%03d.%03d.%05d-%03d.%03d.%03d.%03d.%05d",
           (uint8_t) ((flow->ip_src.s_addr & 0xff000000) >> 24),
           (uint8_t) ((flow->ip_src.s_addr & 0x00ff0000) >> 16),
           (uint8_t) ((flow->ip_src.s_addr & 0x0000ff00) >> 8),
           (uint8_t) (flow->ip_src.s_addr & 0x000000ff),
           flow->port_src,
           (uint8_t) ((flow->ip_dst.s_addr & 0xff000000) >> 24),
           (uint8_t) ((flow->ip_dst.s_addr & 0x00ff0000) >> 16),
           (uint8_t) ((flow->ip_dst.s_addr & 0x0000ff00) >> 8),
           (uint8_t) (flow->ip_dst.s_addr & 0x000000ff),
           flow->port_dst);

  return ring_buffer[ring_pos];
}

void
print_hex (const u_char *buf, size_t len)
{
  for (size_t i = 0; i < len; i++)
    printf ("%02x ", buf[i]);
  putchar ('\n');
}
