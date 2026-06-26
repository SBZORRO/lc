#pragma once
#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <winsock2.h>
# include <windows.h>
# include <ws2tcpip.h>
#else
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif
#include <pcap/pcap.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
typedef SOCKET flow_socket_t;
# define FLOW_INVALID_SOCKET INVALID_SOCKET
#else
typedef int flow_socket_t;
# define FLOW_INVALID_SOCKET (-1)
#endif

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
/* typedef u_int tcp_seq; */
/* typedef union */
/* { */
/*   u_int seq; */
/*   u_char bytes[4]; */
/* } tcp_seq; */

struct sniff_tcp
{
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  u_int th_seq;     /* sequence number */
  u_int th_ack;     /* acknowledgement number */
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

typedef struct flow_struct flow_t;
typedef struct flow_state_struct flow_state_t;
typedef struct flow_detect_struct flow_detect_t;
typedef struct flow_array_struct flow_arr_t;

struct flow_detect_struct
{
  uint8_t dir;       // FLOW_DIR_REQUEST / FLOW_DIR_RESPONSE / UNKNOWN
  uint32_t protocol; // 1 servos, 2 servou, 3 drager
  uint32_t type;     // matched target index
  uint32_t target;   // server[] index if forwardable, else 0
};

struct flow_state_struct
{
  flow_state_t *next; /* Link to next one */
  flow_t *flow;       /* Description of this flow */
  uint8_t *pkt;       /* pcap capture */
  uint32_t seq;
  uint32_t ack;
  uint32_t flags;
  uint32_t size_payload;
  uint32_t offset_payload;
};

struct flow_struct
{
  flow_state_t *next;    /* Link to next one */
  flow_t *peer;          // the other direction
  flow_detect_t detect;  // detect msg type
  struct timespec ts;    // last segment ts
  pthread_t thread;      // thread to process flow
  pthread_mutex_t mutex; // attach/detach mutex
  uint32_t flags;        // tcp flags/thread state
#define SENDING 0x8000
  flow_socket_t sock; // fd/socket to send
  FILE *fp;           // Pointer to file storing this flow's data
  uint32_t size;      // total flow_state
  uint32_t seg_nxt;   // expect byt
  struct in_addr
    ip_src,
    ip_dst,
    ip_tar;          // pcap src and dst, server to send
  uint16_t port_src; /* Source port number */
  uint16_t port_dst; /* Destination port number */
  uint16_t port_tar; /* target server port number */
  char filename[44];
};

struct flow_array_struct
{
  uint32_t flow_len;
  uint32_t flow_cap;
  flow_t flow[];
};
