#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "../src/flow.h"
#include "/home/sbzorro/git-repo/lc/pcap/src/packet.h"

char filter[] = "((src host 10.160.231.153 and src port 9997) or (dst host 10.160.231.152 and dst port 9998))";
char *addrs[]
  = { "10.160.231.152:9999",
      "10.160.231.153:9997",
      "222.222.222.222:222",
      "22.22.22.22:22",
      "111.111.111.111:111",
      "11.11.11.11:11" };

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

#define ADD_FLOW(flow_ptr, flow_len)                       \
  do                                                       \
    {                                                      \
      flow_len = sizeof (addrs) / sizeof (addrs[0]);       \
      init_flow (&flow_ptr, flow_len);                     \
      for (int i = 0; i < flow_len; i = i + 2)             \
        {                                                  \
          add_flow (&flow_ptr[i], addrs[i], addrs[i + 1]); \
        }                                                  \
    }                                                      \
  while (0)

void
test_init_flow ()
{
  printf ("test_init_flow\n");
  flow_t *flow = NULL;
  EXPECT_EQ_PTR (flow, NULL);
  flow_ptr_init (&flow, 2);
  EXPECT_EQ_BASE (&flow != NULL, "NOT NULL", &flow, "%p");

  free (flow);
  flow = NULL;
}

void
test_grow_flow ()
{
  printf ("test_create_flow\n");
  flow_t *ptr = NULL;
  int len = 0;

      flow_len = sizeof (addrs) / sizeof (addrs[0]);       
      init_flow (&flow_ptr, flow_len);                     
      for (int i = 0; i < flow_len; i = i + 2)             
        {                                                  
          add_flow (&flow_ptr[i], addrs[i], addrs[i + 1]);
        }
  
  
  ADD_FLOW (ptr, len);
  for (int i = 0; i < len; i = i + 2)
    {
      char src_addr[22];
      char src_port[5];
      sprintf (src_port, "%d", ntohs (ptr[i].port_src));
      strcpy (src_addr, inet_ntoa (ptr[i].ip_src));
      strcat (src_addr, ":");
      strcat (src_addr, src_port);
      EXPECT_EQ_STR (addrs[i], src_addr, strlen (src_addr));
      char dst_addr[22];
      char dst_port[5];
      sprintf (dst_port, "%d", ntohs (ptr[i].port_dst));
      strcpy (dst_addr, inet_ntoa (ptr[i].ip_dst));
      strcat (dst_addr, ":");
      strcat (dst_addr, dst_port);
      EXPECT_EQ_STR (addrs[i + 1], dst_addr, strlen (dst_addr));
      EXPECT_EQ_PTR (NULL, ptr[i].next);
      EXPECT_EQ_INT (0, ptr[i].nxt);
      EXPECT_EQ_INT (0, ptr[i].isn);
    }

  free (ptr);
  ptr = NULL;
}

#define TEST_CREATE_FLOW_STATE(s, size_payload, pl)                        \
  do                                                                       \
    {                                                                      \
      flow_state_t *state = create_flow_state (NULL, s, size_payload, pl); \
      EXPECT_EQ_PTR (NULL, state->next);                                   \
      EXPECT_EQ_PTR (NULL, state->flow);                                   \
      EXPECT_EQ_INT (s, state->seq);                                       \
      EXPECT_EQ_INT (size_payload, state->len);                            \
      EXPECT_EQ_STRING (pl, state->payload, size_payload);                 \
      free (state->payload);                                               \
      free (state);                                                        \
      state = NULL;                                                        \
    }                                                                      \
  while (0)

void
test_create_flow_state ()
{
  printf ("test_create_flow_state\n");
  TEST_CREATE_FLOW_STATE (123, 3, "123");
  TEST_CREATE_FLOW_STATE (921034, 7, "1234567");
  TEST_CREATE_FLOW_STATE (154, 1, " ");
  TEST_CREATE_FLOW_STATE (321, 9, "abger0[g]");
  TEST_CREATE_FLOW_STATE (983, 3, "123");
  TEST_CREATE_FLOW_STATE (298346, 7, "       ");
}

#define ATTACH_FLOW_STATE(ptr, sq, sp, pl)                           \
  do                                                                 \
    {                                                                \
      attach_flow_state (ptr, create_flow_state (NULL, sq, sp, pl)); \
    }                                                                \
  while (0)

#define TEST_ATTACH_FLOW_STATE(flow, str)                       \
  do                                                            \
    {                                                           \
      flow_state_t *fs_ptr = flow->next;                        \
      int i = 0;                                                \
      while (fs_ptr != NULL)                                    \
        {                                                       \
          EXPECT_EQ_STR (str[i], fs_ptr->payload, fs_ptr->len); \
          fs_ptr = fs_ptr->next;                                \
          i++;                                                  \
        }                                                       \
    }                                                           \
  while (0)

// C99+
#define STR_ARR(...) ((const char *[]) { __VA_ARGS__ })
#define STR_ARR_LEN(...) (sizeof ((const char *[]) { __VA_ARGS__ }) / sizeof (const char *))

// C99+
#define MAKE_STR_ARRAY(name, ...)       \
  const char *name[] = { __VA_ARGS__ }; \
  const size_t name##_len = sizeof (name) / sizeof (name[0]);

// Example
// MAKE_STR_ARRAY (cols, "id", "name", "email");
// -> const char *cols[] = {"id","name","email"};
// -> const size_t cols_len = 3;

#define TEST_DETACH_FLOW_STATE(ptr, sq, sp, pl)  \
  do                                             \
    {                                            \
      flow_state_t *state = ptr->next;           \
      state = detach_flow_state (ptr, state);    \
      EXPECT_EQ_PTR (ptr, state->flow);          \
      EXPECT_EQ_INT (sq, state->seq);            \
      EXPECT_EQ_INT (sp, state->len);            \
      EXPECT_EQ_STRING (pl, state->payload, sp); \
      free (state->payload);                     \
      free (state);                              \
      state = NULL;                              \
    }                                            \
  while (0)

void
test_attach_flow_state ()
{
  printf ("test_attach_flow_state\n");
  flow_t *ptr = NULL;
  int len = 0;
  ADD_FLOW (ptr, len);

  ATTACH_FLOW_STATE (ptr, 123, 3, "123");
  ATTACH_FLOW_STATE (ptr, 921034, 7, "1234567");
  ATTACH_FLOW_STATE (ptr, 154, 1, " ");
  ATTACH_FLOW_STATE (ptr, 321, 9, "abger0[g]");
  ATTACH_FLOW_STATE (ptr, 983, 3, "123");
  ATTACH_FLOW_STATE (ptr, 298346, 7, "       ");

  MAKE_STR_ARRAY (str, "123", " ", "abger0[g]", "123", "       ", "1234567");

  TEST_ATTACH_FLOW_STATE (ptr, str);
  EXPECT_EQ_INT (0, ptr->isn);
  EXPECT_EQ_INT (0, ptr->nxt);

  printf ("payload: ");
  print_flow_state (ptr);

  TEST_DETACH_FLOW_STATE (ptr, 123, 3, "123");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, " ");
  TEST_DETACH_FLOW_STATE (ptr, 321, 9, "abger0[g]");
  TEST_DETACH_FLOW_STATE (ptr, 983, 3, "123");
  TEST_DETACH_FLOW_STATE (ptr, 298346, 7, "       ");
  TEST_DETACH_FLOW_STATE (ptr, 921034, 7, "1234567");
  printf ("payload: ");
  print_flow_state (ptr);
  EXPECT_EQ_BASE (ptr->next == NULL, NULL, ptr->next, "%p");
}

const char *test[] = { "test1", "Hello", "WORLD!", "\x1b", "*2A", NULL };

void
test_contain ()
{
  EXPECT_EQ_INT (contain ("test", 4, test), 1);
  EXPECT_EQ_INT (contain ("test1", 5, test), 1);
  EXPECT_EQ_INT (contain ("\x1b", 1, test), 1);
  EXPECT_EQ_INT (contain (NULL, 0, test), 0);
  EXPECT_EQ_INT (contain ("W", 1, test), 1);
  EXPECT_EQ_INT (contain ("Hello World!", 12, test), 1);
  EXPECT_EQ_INT (contain ("asdf\x04lasWORLD!adfasd\x04", 21, test), 1);
  EXPECT_EQ_INT (contain ("*2A\x04", 4, test), 1);
}

void
test_detect ()
{
  printf ("test_attach_flow_state\n");
  flow_t *ptr = NULL;
  int len = 0;
  ADD_FLOW (ptr, len);

  ATTACH_FLOW_STATE (ptr, 34, 5, "test1");
  ATTACH_FLOW_STATE (ptr, 5, 5, "Hello");
  ATTACH_FLOW_STATE (ptr, 77, 1, "\x1b");
  ATTACH_FLOW_STATE (ptr, 9487, 3, "*2A");
  ATTACH_FLOW_STATE (ptr, 372, 21, "asdf\x04lasWORLD!adfasd\x04");
  EXPECT_EQ_INT (detect (ptr), 0);

  ATTACH_FLOW_STATE (ptr + 1, 77, 8, "BER2057\x04");
  EXPECT_EQ_INT (detect (ptr + 1), 2);

  ATTACH_FLOW_STATE (ptr + 2, 7981, 4, "*2A\x04");
  EXPECT_EQ_INT (detect (ptr + 2), 0);

  ATTACH_FLOW_STATE (ptr + 3, 327, 9, "Servo-u0\x04");
  EXPECT_EQ_INT (detect (ptr + 3), 2);
}

int
main (int argc, char *argv[])
{
  test_init_flow ();
  test_create_flow ();
  test_create_flow_state ();
  test_attach_flow_state ();
  test_contain ();
  test_detect ();
  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);
  return main_ret;
}
