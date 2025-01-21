#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "captotcp.h"

int sock = 0;
struct sockaddr_in serv_addr;

void
do_sent (char *msg, int len)
{
  while (send (sock, msg, len, MSG_NOSIGNAL) < 0)
    {
      perror ("Send Fail");
      if (errno == EPIPE || errno == ECONNRESET)
        {
          while (do_connect (serv_addr.sin_addr, serv_addr.sin_port))
            {
              sleep (1);
            }
        }
    }
}

int
do_connect (struct in_addr ip, in_port_t port)
{
  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("Socket creation failed");
      return (EXIT_FAILURE);
    }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons (port);
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

  return 0;
}
