#include <pcap.h>

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
/* typedef union */
/* { */
/*   u_int seq; */
/*   u_char bytes[4]; */
/* } tcp_seq; */

struct sniff_tcp
{
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};

typedef struct flow_state_struct flow_state_t;
typedef struct flow_struct flow_t;

struct flow_struct
{
  flow_state_t *next; /* Link to next one */
  u_int nxt;
  u_int isn;
  struct in_addr ip_src, ip_dst; /* source and dest address */
  /* u_int32_t src;   /\* Source IP address *\/ */
  /* u_int32_t dst;   /\* Destination IP address *\/ */
  u_int16_t sport; /* Source port number */
  u_int16_t dport; /* Destination port number */
};

struct flow_state_struct
{
  flow_state_t *next; /* Link to next one */
  flow_t *flow;       /* Description of this flow */
  // tcp_seq isn;                    /* Initial sequence number we've seen */
  u_int seq;
  u_int len;
  u_char *payload;
  //  FILE *fp;			/* Pointer to file storing this flow's data */
  //  long pos; /* Current write position in fp */
  //  int flags;			/* Don't save any more data from this
  //  flow */ int last_access;		/* "Time" of last access */
};

#define HASH_SIZE 0
#define HASH_FLOW(flow)                                      \
  (((flow.sport & 0xff) | ((flow.dport & 0xff) << 8)         \
    | ((flow.src & 0xff) << 16) | ((flow.dst & 0xff) << 24)) \
   % HASH_SIZE)
