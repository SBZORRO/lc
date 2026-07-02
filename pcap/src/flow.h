#pragma once
#include <pcap/pcap.h>
#ifndef _WIN32
# include <string.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "packet.h"

#define FLOW_ARR_CAP 1024
// 2^n
#define PKT_QUE_CAP 256 * 1024 * 1024

#define CPTR_BUF_SIZE 256 * 1024 * 1024

#define FLOW_DIR_UNKNOWN 0
#define FLOW_DIR_REQUEST 1
#define FLOW_DIR_RESPONSE 2

#define FLOW_REQ_UNKNOWN 0
#define FLOW_REQ_SERVOS_BASE 1000
#define FLOW_REQ_DRAGER_BASE 3000

#define FLOW_PROTO_SERVOS 1
#define FLOW_PROTO_SERVOU 2
#define FLOW_PROTO_DRAGER 3

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define HASH_SIZE 0
#define HASH_FLOW(flow)                                      \
  (((flow.sport & 0xff) | ((flow.dport & 0xff) << 8)         \
    | ((flow.src & 0xff) << 16) | ((flow.dst & 0xff) << 24)) \
   % HASH_SIZE)

#define SEQ_LT(a, b) ((int32_t) ((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((int32_t) ((a) - (b)) <= 0)
#define SEQ_GT(a, b) ((int32_t) ((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t) ((a) - (b)) >= 0)

#define make_filter(ip, p) (src host ip and src port p)

#define SET_IP(f, h, a)                                     \
  do                                                        \
    {                                                       \
      if (a != NULL)                                        \
        {                                                   \
          char *h = strdup (a);                             \
          char *hh = h;                                     \
          char *h##_ip = strtok (h, ":");                   \
          char *h##_port = strtok (NULL, ":");              \
          inet_pton (AF_INET, h##_ip, &f->ip_##h);          \
          f->port_##h = htons ((uint16_t) atoi (h##_port)); \
          free (hh);                                        \
        }                                                   \
    }                                                       \
  while (0)

/* client.c */
int flow_net_init (void);
void flow_net_cleanup (void);
void flow_close_socket (flow_t *flow);
void do_sent (flow_t *flow, char *msg, size_t len);
flow_socket_t do_connect (struct in_addr sin_addr, uint16_t sin_port);

/* cptr.c */
int loop (char *filter_exp);
void dl_ethernet (uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *p);

/* flow.c */
flow_state_t *flow_state_create (flow_t *flow, uint32_t seq, uint32_t ack, uint32_t flags, uint32_t size_payload, uint32_t offset_payload, uint8_t *pkt);
flow_state_t *flow_state_attach (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *flow_state_detach (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *flow_state_fix_and_pop (flow_t *flow);

uint32_t flow_state_assemble (flow_t *flow, uint8_t *buffer);
void flow_state_print (flow_t *flow);
void flow_state_print_hex (flow_t *flow);
void flow_state_free (flow_state_t *fs);

void flow_print (flow_t *flow);
flow_t *flow_set_dst (flow_t *flow, char *dst_addr);
flow_t *flow_set_src (flow_t *flow, char *src_addr);
void flow_reset (flow_t *flow);
flow_t *flow_init (flow_t *flow, const struct in_addr src, const struct in_addr dst, const uint16_t sport, const uint16_t dport);
flow_t *flow_find (flow_arr_t *fa, struct in_addr src, struct in_addr dst, uint16_t sport, uint16_t dport);
flow_t *flow_find_peer (flow_arr_t *fa, flow_t *flow);
void flow_link_peer (flow_t *flow, flow_t *peer);
uint32_t flow_handshake (flow_t *flow, uint32_t th_flags, uint32_t seq, uint32_t sp);
flow_t *flow_add (flow_arr_t *fa);

flow_arr_t *flow_arr_init (uint32_t size);
flow_arr_t *flow_arr_add (flow_arr_t *flow);

uint32_t contain (uint8_t *str, uint32_t len, const char **targets);
flow_detect_t detect (flow_t *flow, flow_state_t *state);
bool flow_should_forward_response (flow_t *flow, flow_detect_t response);

/* logger.c */
int logger_init (FILE *fp, int lvl);
int logger_lock_init ();
void logger_lock (bool lock, void *udata);
void logger_destory ();

/* util.c */
#define MALLOC(type, num) (type *) check_malloc ((num) * sizeof (type))
#define REALLOC(ptr, type, num) (type *) check_realloc (ptr, (num) * sizeof (type))
void *check_malloc (size_t size);
void *check_realloc (void *ptr, size_t size);

/* handler.c */
void *th_send_flow (void *f);
void *th_dispatch_flow (void *arg);
void dl_ethernet (uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *p);

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
void log_hex (int lvl, const char *fmt, const uint8_t *buf, size_t len);
void print_hex (const uint8_t *buf, size_t len);

void init_debug (char *argv[]);
#define DEBUG(message_level)        \
  if (debug_level >= message_level) \
  debug_real
void debug_real (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));
void die (char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

static void *
portable_memmem (const void *haystack, size_t haystacklen,
                 const void *needle, size_t needlelen)
{
  if (!haystack || !needle)
    return NULL;

  const unsigned char *h = (const unsigned char *) haystack;
  const unsigned char *n = (const unsigned char *) needle;

  if (needlelen == 0)
    return (void *) h;
  if (needlelen > haystacklen)
    return NULL;

  for (size_t i = 0; i + needlelen <= haystacklen; i++)
    {
      if (h[i] == n[0] && memcmp (h + i, n, needlelen) == 0)
        return (void *) (h + i);
    }
  return NULL;
}

#ifdef _WIN32
# define memmem portable_memmem
#endif
