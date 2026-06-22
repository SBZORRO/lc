#include <stdio.h>
#include <stdlib.h>
#include "../src/spsc_queue.h"

static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define EXPECT_TRUE(expr)                                                   \
  do                                                                        \
    {                                                                       \
      test_count++;                                                         \
      if (expr)                                                             \
        test_pass++;                                                        \
      else                                                                  \
        {                                                                   \
          fprintf (stderr, "%s:%d: expected true: %s\n", __FILE__, __LINE__, \
                   #expr);                                                  \
          main_ret = 1;                                                     \
        }                                                                   \
    }                                                                       \
  while (0)

#define EXPECT_PTR(expect, actual)                                           \
  do                                                                         \
    {                                                                        \
      void *expect_ = (void *) (expect);                                      \
      void *actual_ = (void *) (actual);                                      \
      test_count++;                                                          \
      if (expect_ == actual_)                                                \
        test_pass++;                                                         \
      else                                                                   \
        {                                                                    \
          fprintf (stderr, "%s:%d: expect: %p actual: %p\n", __FILE__,        \
                   __LINE__, expect_, actual_);                              \
          main_ret = 1;                                                      \
        }                                                                    \
    }                                                                        \
  while (0)

static void
test_spsc_empty_full_order_and_wrap (void)
{
  printf ("test_spsc_empty_full_order_and_wrap\n");

  spsc_queue *q = spsc_init (4);
  int values[] = { 1, 2, 3, 4, 5 };
  void *out = NULL;

  EXPECT_TRUE (!spsc_dequeue (q, &out));

  EXPECT_TRUE (spsc_enqueue (q, &values[0]));
  EXPECT_TRUE (spsc_enqueue (q, &values[1]));
  EXPECT_TRUE (spsc_enqueue (q, &values[2]));
  EXPECT_TRUE (!spsc_enqueue (q, &values[3]));

  EXPECT_TRUE (spsc_dequeue (q, &out));
  EXPECT_PTR (&values[0], out);
  EXPECT_TRUE (spsc_dequeue (q, &out));
  EXPECT_PTR (&values[1], out);

  EXPECT_TRUE (spsc_enqueue (q, &values[3]));
  EXPECT_TRUE (spsc_enqueue (q, &values[4]));
  EXPECT_TRUE (!spsc_enqueue (q, &values[0]));

  EXPECT_TRUE (spsc_dequeue (q, &out));
  EXPECT_PTR (&values[2], out);
  EXPECT_TRUE (spsc_dequeue (q, &out));
  EXPECT_PTR (&values[3], out);
  EXPECT_TRUE (spsc_dequeue (q, &out));
  EXPECT_PTR (&values[4], out);
  EXPECT_TRUE (!spsc_dequeue (q, &out));

  free (q);
}

int
main (void)
{
  test_spsc_empty_full_order_and_wrap ();

  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count,
          test_pass * 100.0 / test_count);
  return main_ret;
}
