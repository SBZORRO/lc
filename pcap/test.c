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
#define EXPECT_EQ_STRING(expect, actual, alength)             \
  EXPECT_EQ_BASE (sizeof (expect) - 1 == alength              \
                    && memcmp (expect, actual, alength) == 0, \
                  expect, actual, "%s")
#define EXPECT_EQ_STR(expect, actual, alength)                \
  EXPECT_EQ_BASE (strlen (expect) == alength                  \
                    && memcmp (expect, actual, alength) == 0, \
                  expect, actual, "%s")
#define EXPECT_EQ_PTR(expect, actual) \
  EXPECT_EQ_BASE ((expect) == (actual), expect, actual, "%p")

void
test_create_flow (int argc, char *argv[])
{
  flow_t *ptr;
  int len = argc - 1;

  argv++;

  char *act[len];
  for (int i = 0; i < len; ++i)
    {
      act[i] = malloc (strlen (argv[i]));
      memcpy (act[i], argv[i], (strlen (argv[i])));
    }
  init_flow (&ptr, len, argv);
  for (int i = 0; i < len; ++i)
    {
      char addr[22];
      char port[5];
      sprintf (port, "%d", ntohs (ptr[i].sport));
      strcpy (addr, inet_ntoa (ptr[i].ip_src));
      strcat (addr, ":");
      strcat (addr, port);

      EXPECT_EQ_STR (act[i], addr, strlen (addr));
      EXPECT_EQ_PTR (NULL, ptr[i].next);
      EXPECT_EQ_INT (0, ptr[i].nxt);
      EXPECT_EQ_INT (0, ptr[i].isn);
    }
}

void
test_create_flow_state ()
{
}

void
test_flow_state_count ()
{
}

void
test_flow_state ()
{
}

int
main (int argc, char *argv[])
{
  printf ("argc: %d\n", argc);
  for (int i = 1; i < argc; ++i)
    {
      printf ("argv: %s\n", argv[i]);
    }
  test_create_flow (argc, argv);
  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count,
          test_pass * 100.0 / test_count);
  return main_ret;
}
