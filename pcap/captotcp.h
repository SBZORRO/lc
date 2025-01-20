/* client */
void do_sent (char *msg, int len);

int do_connect ();

/* flow */
#include "packet.h"

#define MALLOC(type, num) (type *) check_malloc ((num) * sizeof (type))

void *check_malloc (size_t size);

flow_state_t *create_flow_state (flow_t *flow, tcp_seq seq, u_int size_payload,
                                 const u_char *payload);
void print_flow_state (flow_t *flow);
void free_flow_state (flow_state_t *fs);
flow_t find_flow (flow_t* flow);

