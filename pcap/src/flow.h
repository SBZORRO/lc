#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <pcap/pcap.h>
#include "packet.h"

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
void do_sent (flow_t *flow, char *msg, int len);
int do_connect (struct in_addr sin_addr, u_short sin_port);

/* pcapimpl.c */
int loop (char *filter_exp);
char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

/* flow.c */
flow_state_t *flow_state_create (flow_t *flow, u_int seq, u_int ack, u_int flags, u_int size_payload, u_int offset_payload, u_char *pkt);
flow_state_t *flow_state_attach (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *flow_state_detach (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *flow_state_pop (flow_t *flow);

void flow_state_assemble (flow_t *flow);
void flow_state_print (flow_t *flow);
void flow_state_free (flow_state_t *fs);

void flow_print (flow_t *flow, u_int len);
flow_t *flow_set_dst (flow_t *flow, char *dst_addr);
flow_t *flow_set_src (flow_t *flow, char *src_addr);
void flow_reset (flow_t *flow);
flow_t *flow_init (flow_t *flow, const struct in_addr src, const struct in_addr dst, const u_short sport, const u_short dport);
flow_t *flow_find (flow_arr_t *fa, struct in_addr src, struct in_addr dst, u_short sport, u_short dport);

flow_arr_t *flow_arr_init (uint32_t size);
flow_arr_t *flow_arr_add (flow_arr_t *flow);

int contain (u_char *str, u_int len, const char **targets);
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

#define RING_SIZE 1024
char *flow_filename (flow_t *flow);
void print_hex (const u_char *buf, size_t len);

void init_debug (char *argv[]);
#define DEBUG(message_level)        \
  if (debug_level >= message_level) \
  debug_real
void debug_real (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void die (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
