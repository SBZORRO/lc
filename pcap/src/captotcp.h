#define make_filter(ip, p) (src host ip and src port p)
/* client */
#include <netinet/in.h>
void do_sent (char *msg, int len);
int do_connect (u_int sin_addr, u_short sin_port);

/* flow */
#include <pcap/pcap.h>
#include <stddef.h>
#include <sys/types.h>
#include "packet.h"
#define MALLOC(type, num) (type *) check_malloc ((num) * sizeof (type))
void *check_malloc (size_t size);
int loop ();
char *get_if ();
void dl_ethernet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);

flow_state_t *create_flow_state (flow_t *flow, u_int seq, u_int size_payload,
                                 const u_char *payload);
flow_state_t *attach_flow_state (flow_t *flow, flow_state_t *new_flow_state);
flow_state_t *detach_flow_state (flow_t *flow, flow_state_t *new_flow_state);

void print_flow_state (flow_t *flow);
void free_flow_state (flow_state_t *fs);

void print_flow (flow_t *flow, int len);
flow_t *find_flow (flow_t *flow, int len, struct in_addr addr, u_short port);
flow_t *add_flow (flow_t *, char *src_addr, char *dst_addr);
flow_t **init_flow (flow_t **, int size);
void reset_flow (flow_t *flow);
