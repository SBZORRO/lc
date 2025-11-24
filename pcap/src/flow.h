#include <stdbool.h>
#include <stdio.h>
#define make_filter(ip, p) (src host ip and src port p)

/* client */
#include <netinet/in.h>

/* flow */
#include <pcap/pcap.h>
#include <stddef.h>
#include <sys/types.h>
#include "packet.h"

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

void do_sent (flow_t *flow, char *msg, int len);
int do_connect (struct in_addr sin_addr, u_short sin_port);

#define MALLOC(type, num) (type *) check_malloc ((num) * sizeof (type))
#define REALLOC(ptr, type, num) (type *) check_realloc (ptr, (num) * sizeof (type))
void *check_malloc (size_t size);
void *check_realloc (void *ptr, size_t size);
int loop ();
char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

flow_state_t *create_flow_state (flow_t *flow, u_int seq, u_int size_payload,
                                 const u_char *payload);
flow_state_t *attach_flow_state (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *detach_flow_state (flow_t *flow, flow_state_t *new_flow_state);

void assemble_flow_state (flow_t *flow);
void print_flow_state (flow_t *flow);
void free_flow_state (flow_state_t *fs);

void print_flow (flow_t *flow, int len);
flow_t *find_flow (flow_t *flow, int len, struct in_addr src, struct in_addr dst, u_short sport, u_short dport);
flow_t *init_flow (flow_t *flow, const struct in_addr src, const struct in_addr dst, const u_short sport, const u_short dport);
flow_t **init_flow_ptr (flow_t **, int size);
void reset_flow (flow_t *flow);
flow_t *grow_flow ();

flow_t *set_dst (flow_t *flow, char *dst_addr);
flow_t *set_src (flow_t *flow, char *src_addr);

int contain (u_char *str, int len, const char **targets);
int detect (flow_t *flow);

void init_logger (FILE *fp);
void log_lock (bool lock, void *udata);
int init_logger_lock ();
void log_lock (bool lock, void *udata);
