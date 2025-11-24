#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "flow.h"

void
do_sent (flow_t *flow, char *msg, int len)
{
  while (send (flow->sock, msg, len, MSG_NOSIGNAL) < 0)
    {
      perror ("Send Fail");
      if (errno == EPIPE || errno == ECONNRESET)
        {
          while ((flow->sock = do_connect (flow->ip_dst, flow->port_dst)) == 0)
            {
              sleep (1);
            }
        }
    }
}

int
do_connect (struct in_addr ip, u_short port)
{
  struct sockaddr_in serv_addr;
  int sock = 0;
  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("Socket creation failed");
      return (EXIT_FAILURE);
    }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = port;
  serv_addr.sin_addr = ip;

  // Convert address to binary form
  /* if (inet_pton (AF_INET, IP, &serv_addr.sin_addr) <= 0) */
  /*   { */
  /*     perror ("Invalid address"); */
  /*     return (EXIT_FAILURE); */
  /*   } */

  if (connect (sock, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      perror ("Connection failed");
      return (EXIT_FAILURE);
    }

  printf ("Connection Start\n");

  /* send (sock, "Hello from client", strlen ("Hello from client"), 0); */
  /* int valread = read (sock, buffer, BUFFER_SIZE); */
  /* printf ("Received: %s\n", buffer); */

  /* close (sock); */

  return sock;
}

/* Set the specified socket in non-blocking mode, with no delay flag. */
int
socketSetNonBlockNoDelay (int fd)
{
  int flags, yes = 1;

  /* Set the socket nonblocking.
   * Note that fcntl(2) for F_GETFL and F_SETFL can't be
   * interrupted by a signal. */
  if ((flags = fcntl (fd, F_GETFL)) == -1)
    return -1;
  if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) == -1)
    return -1;

  /* This is best-effort. No need to check for errors. */
  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof (yes));
  return 0;
}
