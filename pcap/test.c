#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
  int len = argc;
  char *act[len];
  for (int i = 0; i < len; ++i)
    {
      act[i] = malloc (strlen (argv[i]));
      memcpy (act[i], argv[i], (strlen (argv[i])));
    }
  init_flow (&ptr, len, act);
  for (int i = 0; i < len; ++i)
    {
      char addr[22];
      char port[5];
      sprintf (port, "%d", ntohs (ptr[i].sport));
      strcpy (addr, inet_ntoa (ptr[i].ip_src));
      strcat (addr, ":");
      strcat (addr, port);

      EXPECT_EQ_STR (argv[i], addr, strlen (addr));
      EXPECT_EQ_PTR (NULL, ptr[i].next);
      EXPECT_EQ_INT (0, ptr[i].nxt);
      EXPECT_EQ_INT (0, ptr[i].isn);
    }
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
    }                                                                      \
  while (0)

void
test_create_flow_state ()
{
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

#define TEST_DETACH_FLOW_STATE(ptr, sq, sp, pl)  \
  do                                             \
    {                                            \
      flow_state_t *state = ptr->next;           \
      state = detach_flow_state (ptr, state);    \
      EXPECT_EQ_PTR (ptr, state->flow);          \
      EXPECT_EQ_INT (sq, state->seq);            \
      EXPECT_EQ_INT (sp, state->len);            \
      EXPECT_EQ_STRING (pl, state->payload, sp); \
    }                                            \
  while (0)

void
test_attach_flow_state (int argc, char *argv[])
{
  flow_t *ptr;
  int len = argc;
  char *act[len];
  for (int i = 0; i < len; ++i)
    {
      act[i] = malloc (strlen (argv[i]));
      memcpy (act[i], argv[i], (strlen (argv[i])));
    }
  init_flow (&ptr, len, act);

  ATTACH_FLOW_STATE (ptr, 123, 3, "123");
  ATTACH_FLOW_STATE (ptr, 921034, 7, "1234567");
  ATTACH_FLOW_STATE (ptr, 154, 1, " ");
  ATTACH_FLOW_STATE (ptr, 321, 9, "abger0[g]");
  ATTACH_FLOW_STATE (ptr, 983, 3, "123");
  ATTACH_FLOW_STATE (ptr, 298346, 7, "       ");

  EXPECT_EQ_INT (0, ptr->isn);
  EXPECT_EQ_INT (0, ptr->nxt);

  print_flow_state (ptr);

  TEST_DETACH_FLOW_STATE (ptr, 123, 3, "123");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, " ");
  TEST_DETACH_FLOW_STATE (ptr, 321, 9, "abger0[g]");
  TEST_DETACH_FLOW_STATE (ptr, 983, 3, "123");
  TEST_DETACH_FLOW_STATE (ptr, 298346, 7, "       ");
  TEST_DETACH_FLOW_STATE (ptr, 921034, 7, "1234567");
  print_flow_state (ptr);
}

int
main (int argc, char *argv[])
{
  argv++;
  argc--;
  printf ("argc: %d\n", argc);
  for (int i = 0; i < argc; ++i)
    {
      printf ("argv: %s\n", argv[i]);
    }
  test_create_flow (argc, argv);
  test_create_flow_state ();
  test_attach_flow_state (argc, argv);
  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count,
          test_pass * 100.0 / test_count);
  return main_ret;
}
