#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "flow.h"
#include "src/packet.h"

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

static char *debug_prefix = NULL;
#define DEBUG(message_level)        \
  if (debug_level >= message_level) \
  debug_real

/*
 * Remember our program name and process ID so we can use them later
 * for printing debug messages
 */
void
init_debug (char *argv[])
{
  debug_prefix = MALLOC (char, strlen (argv[0]) + 16);
  sprintf (debug_prefix, "%s[%d]", argv[0], (int) getpid ());
}

/*
 * Print a debugging message, given a va_list
 */
void
print_debug_message (char *fmt, va_list ap)
{
  /* print debug prefix */
  fprintf (stderr, "%s: ", debug_prefix);

  /* print the var-arg buffer passed to us */
  vfprintf (stderr, fmt, ap);

  /* add newline */
  fprintf (stderr, "\n");
  (void) fflush (stderr);
}

/* Print a debugging or informational message */
void
debug_real (char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  print_debug_message (fmt, ap);
  va_end (ap);
}

/* Print a debugging or informatioal message, then exit  */
void
die (char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  print_debug_message (fmt, ap);
  exit (1);
}
