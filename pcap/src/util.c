#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "flow.h"
#include "src/log.c/log.h"
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
           filename (flow->ip_src, flow->port_src, flow->ip_dst, flow->port_dst));

  return ring_buffer[ring_pos];
}

void
print_hex (const u_char *buf, size_t len)
{
  for (size_t i = 0; i < len; i++)
    printf ("%02x ", buf[i]);
  putchar ('\n');
}

const char hex[] = "0123456789ABCDEF";

void
log_hex (const char *fmt, const uint8_t *buf, size_t len)
{
  char *o = (char *) MALLOC (uint8_t, len * 2 + 1);
  for (size_t i = 0, j = 0; j < len; i = i + 2, j++)
    {
      o[i] = hex[(buf[j] >> 4) & 0x0F];
      o[i + 1] = hex[buf[j] & 0x0F];
    }
  o[len * 2] = 0;
  log_debug (fmt, o);
  free (o);
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

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line (const u_char *payload, int len, int offset)
{
  int i;
  int gap;
  const u_char *ch;

  /* offset */
  printf ("%05d   ", offset);

  /* hex */
  ch = payload;
  for (i = 0; i < len; i++)
    {
      printf ("%02x ", *ch);
      ch++;
      /* print extra space after 8th byte for visual aid */
      if (i == 7)
        printf (" ");
    }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    printf (" ");

  /* fill hex gap with spaces if not full line */
  if (len < 16)
    {
      gap = 16 - len;
      for (i = 0; i < gap; i++)
        {
          printf ("   ");
        }
    }
  printf ("   ");

  /* ascii (if printable) */
  ch = payload;
  for (i = 0; i < len; i++)
    {
      if (isprint (*ch))
        printf ("%c", *ch);
      else
        printf (".");
      ch++;
    }

  printf ("\n");

  return;
}
