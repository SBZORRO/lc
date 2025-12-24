#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <pcap/pcap.h>
#include "packet.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define make_filter(ip, p) (src host ip and src port p)

#define SET_IP(f, h, a)                          \
  do                                             \
    {                                            \
      if (a != NULL)                             \
        {                                        \
          char *h = strdup (a);                  \
          char *h##_ip = strsep (&h, ":");       \
          char *h##_port = strsep (&h, ":");     \
          inet_aton (h##_ip, &f->ip_##h);        \
          f->port_##h = htons (atoi (h##_port)); \
          free (h);                              \
        }                                        \
    }                                            \
  while (0)

/* client.c */
void do_sent (flow_t *flow, char *msg, size_t len);
int do_connect (struct in_addr sin_addr, u_short sin_port);

/* cptr.c */
int loop (char *filter_exp);
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

/* flow.c */
flow_state_t *flow_state_create (flow_t *flow, u_int seq, u_int ack, u_int flags, u_int size_payload, u_int offset_payload, u_char *pkt);
flow_state_t *flow_state_attach (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *flow_state_detach (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *flow_state_fix_and_pop (flow_t *flow);

uint32_t flow_state_assemble (flow_t *flow, uint8_t *buffer);
void flow_state_print (flow_t *flow);
void flow_state_free (flow_state_t *fs);

void flow_print (flow_t *flow, u_int len);
flow_t *flow_set_dst (flow_t *flow, char *dst_addr);
flow_t *flow_set_src (flow_t *flow, char *src_addr);
void flow_reset (flow_t *flow);
flow_t *flow_init (flow_t *flow, const struct in_addr src, const struct in_addr dst, const u_short sport, const u_short dport);
flow_t *flow_find (flow_arr_t *fa, struct in_addr src, struct in_addr dst, u_short sport, u_short dport);
uint32_t flow_handshake (flow_t *flow, uint32_t th_flags, uint32_t seq, uint32_t sp);
flow_t *flow_add (flow_arr_t *fa);

flow_arr_t *flow_arr_init (uint32_t size);
flow_arr_t *flow_arr_add (flow_arr_t *flow);

int contain (uint8_t *str, uint32_t len, const char **targets);
int detect (flow_t *flow);

/* logger.c */
void init_logger (FILE *fp);
int init_logger_lock ();
void log_lock (bool lock, void *udata);
void logger_destory ();

/* util.c */
#define MALLOC(type, num) (type *) check_malloc ((num) * sizeof (type))
#define REALLOC(ptr, type, num) (type *) check_realloc (ptr, (num) * sizeof (type))
void *check_malloc (size_t size);
void *check_realloc (void *ptr, size_t size);

#define filename(src, sp, dst, dp)               \
  (uint8_t) ((src.s_addr & 0xff000000) >> 24),   \
    (uint8_t) ((src.s_addr & 0x00ff0000) >> 16), \
    (uint8_t) ((src.s_addr & 0x0000ff00) >> 8),  \
    (uint8_t) (src.s_addr & 0x000000ff),         \
    htons (sp),                                  \
    (uint8_t) ((dst.s_addr & 0xff000000) >> 24), \
    (uint8_t) ((dst.s_addr & 0x00ff0000) >> 16), \
    (uint8_t) ((dst.s_addr & 0x0000ff00) >> 8),  \
    (uint8_t) (dst.s_addr & 0x000000ff),         \
    htons (dp)

#define RING_SIZE 1024
char *flow_filename (flow_t *flow);
void log_hex (const char *fmt, const u_char *buf, size_t len);
void print_hex (const u_char *buf, size_t len);

void init_debug (char *argv[]);
#define DEBUG(message_level)        \
  if (debug_level >= message_level) \
  debug_real
void debug_real (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void die (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
