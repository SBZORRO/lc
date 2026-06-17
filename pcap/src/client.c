#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
# include <unistd.h>
#endif
#include "flow.h"
#include "log.c/log.h"
#include "packet.h"

#ifdef _WIN32
static int winsock_initialized = 0;

int
flow_net_init (void)
{
  if (winsock_initialized)
    return 0;

  WSADATA wsa_data;
  int rc = WSAStartup (MAKEWORD (2, 2), &wsa_data);
  if (rc != 0)
    {
      errno = rc;
      return -1;
    }

  winsock_initialized = 1;
  atexit (flow_net_cleanup);
  return 0;
}

void
flow_net_cleanup (void)
{
  if (winsock_initialized)
    {
      WSACleanup ();
      winsock_initialized = 0;
    }
}

static int
flow_socket_errno (void)
{
  return WSAGetLastError ();
}

static int
flow_socket_close (flow_socket_t sock)
{
  return closesocket (sock);
}

static int
flow_should_reconnect (int err)
{
  return err == WSAECONNRESET || err == WSAENOTCONN || err == WSAESHUTDOWN;
}
#else
int
flow_net_init (void)
{
  return 0;
}

void
flow_net_cleanup (void)
{
}

static int
flow_socket_errno (void)
{
  return errno;
}

static int
flow_socket_close (flow_socket_t sock)
{
  return close (sock);
}

static int
flow_should_reconnect (int err)
{
  return err == EPIPE || err == ECONNRESET || err == ENOTCONN;
}
#endif

void
flow_close_socket (flow_t *flow)
{
  if (flow->sock == FLOW_INVALID_SOCKET)
    return;

  if (flow_socket_close (flow->sock) < 0)
    {
      perror ("Close sock failed");
    }
  flow->sock = FLOW_INVALID_SOCKET;
}

void
do_sent (flow_t *flow, char *msg, size_t len)
{
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
  /* TODO half send */
  while (send (flow->sock, msg, len, MSG_NOSIGNAL) < 0)
    {
      perror ("Send Fail");
      int err = flow_socket_errno ();
      errno = err;
      log_error ("SEND_ERR: [%p][%d]", flow, err);
      if (flow_should_reconnect (err))
        {
          flow_close_socket (flow);
          while ((flow->sock = do_connect (flow->ip_tar, flow->port_tar)) == FLOW_INVALID_SOCKET)
            {
              log_warn ("FAILED_RECONNECTING: [%p][%llu]", flow,
                        (unsigned long long) flow->sock);
              break;
              // sleep (1);
            }
        }
      break;
    }
}

flow_socket_t
do_connect (struct in_addr ip, u_short port)
{
  struct sockaddr_in serv_addr;
  flow_socket_t sock = FLOW_INVALID_SOCKET;

  if (flow_net_init () != 0)
    {
      perror ("Winsock initialization failed");
      return FLOW_INVALID_SOCKET;
    }

  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) == FLOW_INVALID_SOCKET)
    {
      perror ("Socket creation failed");
      return sock;
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
      if (flow_socket_close (sock) < 0)
        {
          perror ("Close sock failed");
        }
      sock = FLOW_INVALID_SOCKET; // 防止后续误用/重复 close
      perror ("Connection failed");
      return sock;
    }

  /* send (sock, "Hello from client", strlen ("Hello from client"), 0); */
  /* int valread = read (sock, buffer, BUFFER_SIZE); */
  /* printf ("Received: %s\n", buffer); */

  /* close (sock); */

  return sock;
}

/* Set the specified socket in non-blocking mode, with no delay flag. */
/* int */
/* socketSetNonBlockNoDelay (int fd) */
/* { */
/*   int flags, yes = 1; */

/*   /\* Set the socket nonblocking. */
/*    * Note that fcntl(2) for F_GETFL and F_SETFL can't be */
/*    * interrupted by a signal. *\/ */
/*   if ((flags = fcntl (fd, F_GETFL)) == -1) */
/*     return -1; */
/*   if (fcntl (fd, F_SETFL, flags | O_NONBLOCK) == -1) */
/*     return -1; */

/*   /\* This is best-effort. No need to check for errors. *\/ */
/*   setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof (yes)); */
/*   return 0; */
/* } */
