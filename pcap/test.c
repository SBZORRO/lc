#include <stdio.h>
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

char *argv[] = { "./hello",
                 "'(src host 172.17.80.1 and src port 9997) or (dst host "
                 "172.17.81.3 and dst port 9999)'",
                 "192.168.5.17:9999", "172.17.81.3:9998" };
int argc = 4;

void
test_create_flow ()
{
  printf ("print 1");

  flow_t *ptr;
  int len = 0;

  init_flow (ptr, len, argc, argv);

  EXPECT_EQ_INT (1, len);
}

void
test_flow_count ()
{
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
  printf ("print 1");

  test_create_flow ();
  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count,
          test_pass * 100.0 / test_count);
  return main_ret;
}
