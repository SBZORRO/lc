#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define IP "192.168.5.17"
#define PORT 9999
#define BUFFER_SIZE 1024

int sock = 0;

void
do_sent (char *msg, int len)
{
  send (sock, msg, len, 0);
}

int
do_connect ()
{
  struct sockaddr_in serv_addr;
  char buffer[BUFFER_SIZE] = { 0 };

  // 1. Create socket
  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      perror ("Socket creation failed");
      exit (EXIT_FAILURE);
    }

  // 2. Setup server address
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons (PORT);

  // Convert address to binary form
  if (inet_pton (AF_INET, IP, &serv_addr.sin_addr) <= 0)
    {
      perror ("Invalid address");
      exit (EXIT_FAILURE);
    }

  // 3. Connect to server
  if (connect (sock, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      perror ("Connection failed");
      exit (EXIT_FAILURE);
    }

  printf ("Connection Start\n");

  // 4. Communicate
  /* send (sock, "Hello from client", strlen ("Hello from client"), 0); */
  /* int valread = read (sock, buffer, BUFFER_SIZE); */
  /* printf ("Received: %s\n", buffer); */

  // 5. Close socket
  /* close (sock); */

  return 0;
}
