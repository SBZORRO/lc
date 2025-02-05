#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "captotcp.h"

static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define EXPECT_EQ_BASE(equality, expect, actual, format)                     \
  do                                                                         \
    {                                                                        \
      test_count++;                                                          \
      if (equality)                                                          \
        test_pass++;                                                         \
      else                                                                   \
        {                                                                    \
          fprintf (stderr, "%s:%d: expect: " format " actual: " format "\n", \
                   __FILE__, __LINE__, expect, actual);                      \
          main_ret = 1;                                                      \
        }                                                                    \
    }                                                                        \
  while (0)

#define EXPECT_EQ_INT(expect, actual) \
  EXPECT_EQ_BASE ((expect) == (actual), expect, actual, "%d")

void *
check_malloc (size_t size)
{
  void *ptr;

  if ((ptr = malloc (size)) == NULL)
    {
      /* DEBUG(0) ("Malloc failed - out of memory?"); */
      exit (1);
    }
  return ptr;
}

void
test_create_flow ()
{
  char *argv[] = { "./hello",
                   "'(src host 172.17.80.1 and src port 9997) or (dst host "
                   "172.17.81.3 and dst port 9999)'",
                   "192.168.5.17:9999", "172.17.81.3:9998" };
  int argc = 4;

  char *addr = argv[3];
  printf ("%s", addr);
  char *split = strstr (addr, ":");
  char *port = split + 1;
  printf ("indi>%s<", ++split);
  printf ("\ngap: %d", (int) (addr - split));
  char ip[split - addr - 1];
  memcpy (ip, addr, split - addr - 1);
  printf ("\nip:: %s", ip);
  printf ("\nport:: %d", (int) strlen(port));

  /* char* ip = strncpy() */
  /* char *port = strtok (NULL, "\0"); */

  /* EXPECT_EQ_INT (1, len); */
}

int
main (int argc, char *argv[])
{

  test_create_flow ();
  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count,
          test_pass * 100.0 / test_count);
  return main_ret;
}
