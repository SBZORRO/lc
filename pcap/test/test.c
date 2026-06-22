#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include "../src/flow.h"
#include "../src/packet.h"
#include "../src/spsc_queue.h"

extern spsc_queue *pkt_que;

char filter[] = "((src host 10.160.231.153 and src port 9997) or (dst host 10.160.231.152 and dst port 9998))";
char *addrs[]
  = { "10.160.231.152:9999",
      "11.11.11.11:11" };

static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define U8(s) ((uint8_t *) (s))

// C99+
#define STR_ARR(...) ((const char *[]) { __VA_ARGS__ })
#define STR_ARR_LEN(...) (sizeof ((const char *[]) { __VA_ARGS__ }) / sizeof (const char *))

// C99+
#define MAKE_STR_ARRAY(name, ...)       \
  const char *name[] = { __VA_ARGS__ }; \
  const size_t name##_len = sizeof (name) / sizeof (name[0]);

#define MAKE_INT_ARRAY(name, ...)        \
  const size_t name[] = { __VA_ARGS__ }; \
  const size_t name##_len = sizeof (name) / sizeof (name[0]);

// Example
// MAKE_STR_ARRAY (cols, "id", "name", "email");
// -> const char *cols[] = {"id","name","email"};
// -> const size_t cols_len = 3;

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

#define TEST_FLOW_STATE_PKT_SLICE(ptr, sn, sp, op, p, len, tar)              \
  do                                                                         \
    {                                                                        \
      flow_state_t *state = flow_state_create (ptr, sn, 0, 0, sp, op, U8 (p)); \
      state->pkt = malloc (len);                                             \
      memcpy (state->pkt, p, len);                                           \
      EXPECT_EQ_INT (sn, state->seq);                                        \
      EXPECT_EQ_INT (sp, state->size_payload);                               \
      EXPECT_EQ_INT (op, state->offset_payload);                             \
      EXPECT_EQ_BASE (sp + op <= len, "<=", ">", "%s");                      \
      EXPECT_EQ_STRING (p, state->pkt, len);                                 \
      char *dst = malloc (state->size_payload);                              \
      memcpy (dst, state->pkt + state->offset_payload, state->size_payload); \
      int r = memcmp (tar, dst, state->size_payload);                        \
      EXPECT_EQ_INT (0, r);                                                  \
      free (dst);                                                            \
      if (ptr == NULL)                                                       \
        {                                                                    \
          flow_state_free (state);                                           \
        }                                                                    \
      else                                                                   \
        {                                                                    \
          flow_state_attach (ptr, state);                                    \
        }                                                                    \
    }                                                                        \
  while (0)

void
test_flow_state_pkt_slice ()
{
  printf ("test_flow_state_pkt_slice\n");
  // clang-format off
  TEST_FLOW_STATE_PKT_SLICE (NULL, 123, 3, 0, "123", 3, "123");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 8239, 4, 4, "1234567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 823, 4, 4, "\x0" "\x0" "34567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 8323, 4, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0" "34");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 8293, 3, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0" "3");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 8023, 2, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 8823, 1, 0, "\x0" "\x0" "34567890", 10, "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 83, 0, 0, "\x0" "\x0" "34567890", 10, "");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 82, 4, 4, "1" "\x0" "\x0" "4567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 23, 4, 4, "12" "\x0" "\x0" "567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 821239, 4, 4, "123" "\x0" "\x0" "67890", 10, "\x0" "678");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 823739, 4, 4, "1234" "\x0" "\x0" "7890", 10, "\x0" "\x0" "78");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 82399, 4, 4, "12345" "\x0" "\x0" "890", 10, "5" "\x0" "\x0" "8");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 98239, 4, 4, "123456" "\x0" "\x0" "90", 10, "56" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 18239, 4, 4, "1234567" "\x0" "\x0" "0", 10, "567" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 28239, 4, 4, "12345678" "\x0" "\x0", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 38239, 4, 6, "12345678" "\x0" "\x0", 10, "78" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 48239, 3, 7, "12345678" "\x0" "\x0", 10, "8" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 58239, 2, 8, "12345678" "\x0" "\x0", 10, "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 68239, 1, 9, "12345678" "\x0" "\x0", 10, "\x0");
  TEST_FLOW_STATE_PKT_SLICE (NULL, 78239, 1, 9, "12345678" "\x0" "\x0", 10, "");
  // clang-format on
}

#define CREATE_AND_ATTACH_PARTIALLY(ptr, sn, sp, op, p, len, tar)      \
  do                                                                   \
    {                                                                  \
      flow_state_t *st = flow_state_create (ptr, sn, 0, 0, sp, op, U8 (p)); \
      st->pkt = malloc (len);                                          \
      memcpy (st->pkt, p, len);                                        \
      flow_state_attach (ptr, st);                                     \
    }                                                                  \
  while (0)

void
test_flow_state_attach_partially ()
{
  printf ("test_flow_state_attach_partially\n");
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);
  // clang-format off
  TEST_FLOW_STATE_PKT_SLICE (ptr, 10, 3, 0, "123", 3, "123");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 20, 4, 4, "1234567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 30, 4, 4, "\x0" "\x0" "34567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 40, 4, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0" "34");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 50, 3, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0" "3");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 60, 2, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 70, 1, 0, "\x0" "\x0" "34567890", 10, "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 80, 0, 0, "\x0" "\x0" "34567890", 10, "");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 90, 4, 4, "1" "\x0" "\x0" "4567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 100, 4, 4, "12" "\x0" "\x0" "567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 110, 4, 4, "123" "\x0" "\x0" "67890", 10, "\x0" "678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 120, 4, 4, "1234" "\x0" "\x0" "7890", 10, "\x0" "\x0" "78");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 130, 4, 4, "12345" "\x0" "\x0" "890", 10, "5" "\x0" "\x0" "8");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 140, 4, 4, "123456" "\x0" "\x0" "90", 10, "56" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 150, 4, 4, "1234567" "\x0" "\x0" "0", 10, "567" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 160, 4, 4, "12345678" "\x0" "\x0", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 170, 4, 6, "12345678" "\x0" "\x0", 10, "78" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 180, 3, 7, "12345678" "\x0" "\x0", 10, "8" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 190, 2, 8, "12345678" "\x0" "\x0", 10, "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 200, 1, 9, "12345678" "\x0" "\x0", 10, "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 210, 1, 9, "12345678" "\x0" "\x0", 10, "");
  // clang-format on
  uint8_t buffer[1000000]; // 1M
  uint32_t i = flow_state_assemble (ptr, buffer);
  // clang-format off
  int r = memcmp (buffer, "123""5678""5678""\x0" "\x0" "34""\x0" "\x0" "3""\x0" "\x0""\x0""""5678""5678""\x0" "678""\x0" "\x0" "78""5" "\x0" "\x0" "8""56" "\x0" "\x0""567" "\x0""5678""78" "\x0" "\x0""8" "\x0" "\x0""\x0" "\x0""\x0""", i);
  // clang-format on
  EXPECT_EQ_INT (0, r);
  printf ("PAYLOAD: ");
  print_hex (buffer, i);
  printf ("PAYLOAD: ");
  // clang-format off
  print_hex ((const uint8_t *) "123""5678""5678""\x0" "\x0" "34""\x0" "\x0" "3""\x0" "\x0""\x0""""5678""5678""\x0" "678""\x0" "\x0" "78""5" "\x0" "\x0" "8""56" "\x0" "\x0""567" "\x0""5678""78" "\x0" "\x0""8" "\x0" "\x0""\x0" "\x0""\x0""", i);
  // clang-format on
  flow_reset (ptr);
}

void
test_flow_state_attach_retrans ()
{
  printf ("test_flow_state_attach_retrans\n");
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);
  // clang-format off
  TEST_FLOW_STATE_PKT_SLICE (ptr, 110, 4, 4, "123" "\x0" "\x0" "67890", 10, "\x0" "678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 100, 4, 4, "12" "\x0" "\x0" "567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 120, 4, 4, "1234" "\x0" "\x0" "7890", 10, "\x0" "\x0" "78");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 90, 4, 4, "1" "\x0" "\x0" "4567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 130, 4, 4, "12345" "\x0" "\x0" "890", 10, "5" "\x0" "\x0" "8");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 80, 0, 0, "\x0" "\x0" "34567890", 10, "");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 140, 4, 4, "123456" "\x0" "\x0" "90", 10, "56" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 70, 1, 0, "\x0" "\x0" "34567890", 10, "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 150, 4, 4, "1234567" "\x0" "\x0" "0", 10, "567" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 10, 3, 0, "123", 3, "123");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 20, 4, 4, "1234567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 30, 4, 4, "\x0" "\x0" "34567890", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 40, 4, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0" "34");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 50, 3, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0" "3");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 60, 2, 0, "\x0" "\x0" "34567890", 10, "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 160, 4, 4, "12345678" "\x0" "\x0", 10, "5678");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 170, 4, 6, "12345678" "\x0" "\x0", 10, "78" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 180, 3, 7, "12345678" "\x0" "\x0", 10, "8" "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 190, 2, 8, "12345678" "\x0" "\x0", 10, "\x0" "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 200, 1, 9, "12345678" "\x0" "\x0", 10, "\x0");
  TEST_FLOW_STATE_PKT_SLICE (ptr, 210, 1, 9, "12345678" "\x0" "\x0", 10, "");
  // clang-format on
  uint8_t buffer[1000000]; // 1M
  uint32_t i = flow_state_assemble (ptr, buffer);
  // clang-format off
  int r = memcmp (buffer, "123""5678""5678""\x0" "\x0" "34""\x0" "\x0" "3""\x0" "\x0""\x0""""5678""5678""\x0" "678""\x0" "\x0" "78""5" "\x0" "\x0" "8""56" "\x0" "\x0""567" "\x0""5678""78" "\x0" "\x0""8" "\x0" "\x0""\x0" "\x0""\x0""", i);
  // clang-format on
  EXPECT_EQ_INT (0, r);
  printf ("PAYLOAD: ");
  print_hex (buffer, i);
  printf ("PAYLOAD: ");
  // clang-format off
  print_hex ((const uint8_t *) "123""5678""5678""\x0" "\x0" "34""\x0" "\x0" "3""\x0" "\x0""\x0""""5678""5678""\x0" "678""\x0" "\x0" "78""5" "\x0" "\x0" "8""56" "\x0" "\x0""567" "\x0""5678""78" "\x0" "\x0""8" "\x0" "\x0""\x0" "\x0""\x0""", i);
  // clang-format on
  flow_reset (ptr);
}

#define CREATE_AND_ATTACH(ptr, seq, len, p)                             \
  do                                                                    \
    {                                                                   \
      flow_state_t *st = flow_state_create (ptr, seq, 0, 0, len, 0, U8 (p)); \
      st->pkt = malloc (len);                                           \
      memcpy (st->pkt, p, len);                                         \
      flow_state_attach (ptr, st);                                      \
    }                                                                   \
  while (0)

#define TEST_DETACH_FLOW_STATE(ptr, sq, sp, pl)          \
  do                                                     \
    {                                                    \
      flow_state_t *detached_state = ptr->next;          \
      flow_state_t *st = flow_state_detach (ptr, detached_state); \
      EXPECT_EQ_PTR (ptr, detached_state->flow);         \
      EXPECT_EQ_INT (sq, detached_state->seq);           \
      EXPECT_EQ_INT (sp, detached_state->size_payload);  \
      if (st != NULL)                                    \
        {                                                \
          EXPECT_EQ_STRING (pl, detached_state->pkt, sp); \
          flow_state_free (detached_state);              \
        }                                                \
      detached_state = NULL;                             \
    }                                                    \
  while (0)

void
test_flow_state_attach ()
{
  printf ("test_flow_state_attach\n");
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);

  MAKE_STR_ARRAY (str, "123", " ", "abger0[g]", "123", "       ", "1234567");
  MAKE_INT_ARRAY (len, sizeof ("123"), sizeof (" "), sizeof ("abger0[g]"), sizeof ("123"), sizeof ("       "), sizeof ("1234567"));
  (void) len_len;

  CREATE_AND_ATTACH (ptr, 123, 3, "123");
  CREATE_AND_ATTACH (ptr, 921034, 7, "1234567");
  CREATE_AND_ATTACH (ptr, 154, 1, " ");
  CREATE_AND_ATTACH (ptr, 321, 9, "abger0[g]");
  CREATE_AND_ATTACH (ptr, 983, 3, "123");
  CREATE_AND_ATTACH (ptr, 298346, 7, "       ");
  EXPECT_EQ_INT ((uint32_t) str_len, ptr->size);

  flow_state_t *state = ptr->next;
  for (size_t i = 0; i < str_len; i++)
    {
      int r = memcmp (str[i], state->pkt, len[i] - 1);
      EXPECT_EQ_INT (0, r);
      state = state->next;
    }

  // printf ("  payload: ");
  // flow_state_print (&flow);

  printf ("test_flow_state_pop\n");
  ptr->seg_nxt = 123;
  TEST_DETACH_FLOW_STATE (ptr, 123, 3, "123");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, " ");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, "abger0[g]");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, "123");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, "       ");
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, "1234567");
  EXPECT_EQ_INT (ptr->seg_nxt, 123 + 3);
  EXPECT_EQ_INT ((uint32_t) (str_len - 1), ptr->size);

  // printf ("  payload: ");
  // flow_state_print (ptr);
  ptr->seg_nxt = 154;
  TEST_DETACH_FLOW_STATE (ptr, 154, 1, " ");
  ptr->seg_nxt = 321;
  TEST_DETACH_FLOW_STATE (ptr, 321, 9, "abger0[g]");
  ptr->seg_nxt = 983;
  TEST_DETACH_FLOW_STATE (ptr, 983, 3, "123");
  ptr->seg_nxt = 298346;
  TEST_DETACH_FLOW_STATE (ptr, 298346, 7, "       ");
  ptr->seg_nxt = 921034;
  TEST_DETACH_FLOW_STATE (ptr, 921034, 7, "1234567");
  EXPECT_EQ_INT (0, ptr->size);
  EXPECT_EQ_BASE (ptr->next == NULL, NULL, ptr->next, "%p");
}

void
test_flow_state_attach2 ()
{
  printf ("test_flow_state_attach2\n");
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);

  MAKE_STR_ARRAY (str, "123", "456", "7", "89", "0", "11");
  MAKE_INT_ARRAY (len, sizeof ("123"), sizeof ("456"), sizeof ("7"), sizeof ("89"), sizeof ("0"), sizeof ("11"));
  (void) len_len;

  CREATE_AND_ATTACH (ptr, 3, 1, "7");
  CREATE_AND_ATTACH (ptr, 0, 3, "456");
  CREATE_AND_ATTACH (ptr, 4, 2, "89");
  CREATE_AND_ATTACH (ptr, 6, 1, "0");
  CREATE_AND_ATTACH (ptr, 0xfffffffd, 3, "123");
  CREATE_AND_ATTACH (ptr, 7, 2, "11");
  EXPECT_EQ_INT ((uint32_t) str_len, ptr->size);

  flow_state_t *state = ptr->next;
  for (size_t i = 0; i < str_len; i++)
    {
      int r = memcmp (str[i], state->pkt, len[i] - 1);
      EXPECT_EQ_INT (0, r);
      state = state->next;
    }

  /* printf ("  payload: "); */
  /* flow_state_print (&flow); */

  printf ("test_flow_state_pop2\n");
  ptr->seg_nxt = 0xfffffffd;
  TEST_DETACH_FLOW_STATE (ptr, 0xfffffffd, 3, "123");
  TEST_DETACH_FLOW_STATE (ptr, 0, 3, "456");
  TEST_DETACH_FLOW_STATE (ptr, 3, 1, "7");
  TEST_DETACH_FLOW_STATE (ptr, 4, 2, "89");
  TEST_DETACH_FLOW_STATE (ptr, 6, 1, "0");
  TEST_DETACH_FLOW_STATE (ptr, 7, 2, "11");
  EXPECT_EQ_INT (ptr->seg_nxt, 9);
  EXPECT_EQ_INT (0, ptr->size);

  // printf ("  payload: ");
  // flow_state_print (ptr);
  EXPECT_EQ_BASE (ptr->next == NULL, NULL, ptr->next, "%p");
}

void
test_flow_state_attach3 ()
{
  printf ("test_flow_state_attach3\n");
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);

  CREATE_AND_ATTACH (ptr, 123, 3, "123");
  CREATE_AND_ATTACH (ptr, 123, 2, "12");
  CREATE_AND_ATTACH (ptr, 921034, 7, "1234567");
  CREATE_AND_ATTACH (ptr, 154, 1, " ");
  CREATE_AND_ATTACH (ptr, 154, 3, "123");
  CREATE_AND_ATTACH (ptr, 321, 9, "abger0[g]");
  CREATE_AND_ATTACH (ptr, 983, 3, "123");
  CREATE_AND_ATTACH (ptr, 298346, 7, "       ");
  CREATE_AND_ATTACH (ptr, 123, 6, "456789");
  CREATE_AND_ATTACH (ptr, 983, 4, "abcd");

  flow_state_print(ptr);
  EXPECT_EQ_INT (6, ptr->size);
}

const char *test[] = { "test1", "Hello", "WORLD!", "\x1b", "*2A", NULL };

void
test_contain ()
{
  printf ("test_contain\n");
  EXPECT_EQ_INT (contain (U8 ("test"), 4, test), 1);
  EXPECT_EQ_INT (contain (U8 ("test1"), 5, test), 1);
  EXPECT_EQ_INT (contain (U8 ("\x1b"), 1, test), 1);
  EXPECT_EQ_INT (contain (NULL, 0, test), 0);
  EXPECT_EQ_INT (contain (U8 ("W"), 1, test), 1);
  EXPECT_EQ_INT (contain (U8 ("Hello World!"), 12, test), 1);
  EXPECT_EQ_INT (contain (U8 ("asdf\x04lasWORLD!adfasd\x04"), 21, test), 1);
  EXPECT_EQ_INT (contain (U8 ("*2A\x04"), 4, test), 1);
}

void
test_detect ()
{
  printf ("test_detect\n");

  flow_t flow;
  flow_t *fp = &flow;
  flow_init (fp, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);

  CREATE_AND_ATTACH (fp, 34, 2, "\x01T");
  CREATE_AND_ATTACH (fp, 5, 5, "Hello");
  CREATE_AND_ATTACH (fp, 77, 1, "\x1b");
  CREATE_AND_ATTACH (fp, 9487, 3, "*2A");
  CREATE_AND_ATTACH (fp, 6666, 8, "Servo-u0");
  CREATE_AND_ATTACH (fp, 3333, 3, "Servo-u0");
  CREATE_AND_ATTACH (fp, 372, 21, "asdf\x04lasWORLD!900PCI\x04");
  EXPECT_EQ_INT (detect (fp->next), 0);
  EXPECT_EQ_INT (detect (fp->next->next), 3);
  EXPECT_EQ_INT (detect (fp->next->next->next), 3);
  EXPECT_EQ_INT (detect (fp->next->next->next->next), 1);
  EXPECT_EQ_INT (detect (fp->next->next->next->next->next), 1);
  EXPECT_EQ_INT (detect (fp->next->next->next->next->next->next), 2);
  EXPECT_EQ_INT (detect (fp->next->next->next->next->next->next->next), 0);

  /* CREATE_AND_ATTACH (ptr + 1, 77, 8, "BER2057\x04"); */
  /* EXPECT_EQ_INT (detect (ptr + 1), 2); */

  /* CREATE_AND_ATTACH (ptr + 2, 7981, 4, "*2A\x04"); */
  /* EXPECT_EQ_INT (detect (ptr + 2), 0); */

  /* CREATE_AND_ATTACH (ptr + 3, 327, 9, "Servo-u0\x04"); */
  /* EXPECT_EQ_INT (detect (ptr + 3), 2); */

  flow_reset (fp);
}

#define TEST_CAL(sn, seq, sp_act, op_act, exp, sp_exp, op_exp) \
  do                                                           \
    {                                                          \
      uint32_t e = seq + sp_act;                               \
      if (SEQ_LEQ (e, sn))                                     \
        {                                                      \
          EXPECT_EQ_INT (exp, 1);                              \
        }                                                      \
      else if (SEQ_LT (seq, sn) && SEQ_GT (e, sn))             \
        {                                                      \
          EXPECT_EQ_INT (exp, 2);                              \
          EXPECT_EQ_INT (sp_exp, e - sn);                      \
          EXPECT_EQ_INT (op_exp, op_act + sn - seq);           \
        }                                                      \
      else                                                     \
        {                                                      \
          EXPECT_EQ_INT (exp, 0);                              \
        }                                                      \
    }                                                          \
  while (0)

void
test_cal ()
{
  printf ("test_cal\n");
  TEST_CAL (1, 1, 1600, 1600, 0, 123, 123);
  TEST_CAL (1, 2, 1600, 1600, 0, 123, 123);

  TEST_CAL (1000, 100, 600, 100, 1, 1500, 1700);
  TEST_CAL (1000, 100, 600, 200, 1, 1500, 1700);
  TEST_CAL (1000, 100, 600, 300, 1, 1500, 1700);
  TEST_CAL (1000, 100, 600, 400, 1, 1500, 1700);
  TEST_CAL (1000, 100, 600, 500, 1, 1500, 1700);
  TEST_CAL (1000, 100, 600, 600, 1, 1500, 1700);
  TEST_CAL (1000, 100, 600, 700, 1, 1500, 1700);

  TEST_CAL (1000, 100, 600, 500, 1, 1500, 1700);
  TEST_CAL (1000, 100, 700, 500, 1, 1500, 1700);
  TEST_CAL (1000, 100, 800, 500, 1, 1500, 1700);
  TEST_CAL (1000, 100, 900, 500, 1, 1, 500);
  TEST_CAL (1000, 100, 1000, 500, 2, 100, 1400);
  TEST_CAL (1000, 100, 1100, 500, 2, 200, 1400);
  TEST_CAL (1000, 100, 1200, 500, 2, 300, 1400);

  TEST_CAL (700, 900, 1600, 1600, 0, 1500, 1700);
  TEST_CAL (800, 900, 1600, 1600, 0, 1500, 1700);
  TEST_CAL (900, 900, 1600, 1600, 0, 1500, 1700);
  TEST_CAL (1000, 900, 1600, 1600, 2, 1500, 1700);
  TEST_CAL (1100, 900, 1600, 1600, 2, 1400, 1800);
  TEST_CAL (1200, 900, 1600, 1600, 2, 1300, 1900);

  TEST_CAL (0xffffffff, 1, 3, 100, 0, 1500, 1700);
  TEST_CAL (0xffffffff, 0, 3, 100, 0, 1500, 1700);
  TEST_CAL (0xffffffff, 0xffffffff, 3, 100, 0, 1500, 1700);
  TEST_CAL (0xffffffff, 0xfffffffe, 3, 100, 2, 2, 101);
  TEST_CAL (0xffffffff, 0xfffffffd, 3, 100, 2, 1, 102);
  TEST_CAL (0xffffffff, 0xfffffffc, 3, 100, 1, 1500, 1700);

  TEST_CAL (3, 0, 3, 100, 1, 1, 102);
  TEST_CAL (2, 0, 3, 100, 2, 1, 102);
  TEST_CAL (1, 0, 3, 100, 2, 2, 101);
  TEST_CAL (0, 0, 3, 100, 0, 1500, 1700);
  TEST_CAL (0xffffffff, 0, 3, 100, 0, 1500, 1700);

  TEST_CAL (2, 0xffffffff, 3, 100, 1, 1, 102);
  TEST_CAL (1, 0xffffffff, 3, 100, 2, 1, 102);
  TEST_CAL (0, 0xffffffff, 3, 100, 2, 2, 101);
  TEST_CAL (0xffffffff, 0xffffffff, 3, 100, 0, 1500, 1700);
  TEST_CAL (0xfffffffe, 0xffffffff, 3, 100, 0, 1500, 1700);
  TEST_CAL (0xfffffffd, 0xffffffff, 3, 100, 0, 1500, 1700);
}

void
test_flow_handshake ()
{
  printf ("test_detect\n");

  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0);

  ptr->flags |= TH_PUSH;
  EXPECT_EQ_INT (TH_PUSH | TH_ACK, flow_handshake (ptr, TH_ACK, 1, 1));
  EXPECT_EQ_INT (TH_PUSH | TH_ACK | TH_CWR, flow_handshake (ptr, TH_CWR, 1, 1));
  EXPECT_EQ_INT (TH_PUSH | TH_ACK | TH_CWR, flow_handshake (ptr, TH_ACK, 1, 1));

  EXPECT_EQ_INT (0, flow_handshake (ptr, TH_RST, 1, 1));
  EXPECT_EQ_INT (0, flow_handshake (ptr, TH_ACK, 1, 1));
  EXPECT_EQ_INT (0, flow_handshake (ptr, TH_CWR, 1, 1));
  EXPECT_EQ_INT (0, flow_handshake (ptr, TH_ACK, 1, 1));

  EXPECT_EQ_INT (0, flow_handshake (ptr, TH_SYN, 0, 0));
  EXPECT_EQ_INT (TH_SYN, flow_handshake (ptr, TH_SYN, 0, 1));
  EXPECT_EQ_INT (TH_SYN, flow_handshake (ptr, TH_SYN, 0, 2));
  EXPECT_EQ_INT (TH_SYN | TH_ACK, flow_handshake (ptr, TH_ACK, 1, 1));
  EXPECT_EQ_INT (TH_SYN | TH_ACK | TH_CWR, flow_handshake (ptr, TH_CWR, 1, 1));
  EXPECT_EQ_INT (TH_SYN | TH_ACK | TH_CWR | TH_URG, flow_handshake (ptr, TH_ACK | TH_URG, 1, 1));
}

void
test_flow_syn_resets_existing_tuple ()
{
  printf ("test_flow_syn_resets_existing_tuple\n");

  struct in_addr src = { .s_addr = 0x01020304 };
  struct in_addr dst = { .s_addr = 0x05060708 };
  uint16_t sport = htons (1234);
  uint16_t dport = htons (5678);
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, src, dst, sport, dport);

  ptr->flags = SENDING | TH_ACK;
  ptr->seg_nxt = 9000;
  SET_IP (ptr, tar, "127.0.0.1:9999");
  CREATE_AND_ATTACH (ptr, 9000, 3, "abc");

  EXPECT_EQ_INT (SENDING | TH_SYN, flow_handshake (ptr, TH_SYN, 100, 1));
  EXPECT_EQ_INT (src.s_addr, ptr->ip_src.s_addr);
  EXPECT_EQ_INT (dst.s_addr, ptr->ip_dst.s_addr);
  EXPECT_EQ_INT (sport, ptr->port_src);
  EXPECT_EQ_INT (dport, ptr->port_dst);
  EXPECT_EQ_INT (0, ptr->ip_tar.s_addr);
  EXPECT_EQ_INT (0, ptr->port_tar);
  EXPECT_EQ_PTR (NULL, ptr->next);
  EXPECT_EQ_INT (0, ptr->size);
  EXPECT_EQ_INT (101, ptr->seg_nxt);

  flow_reset (ptr);
}

void
test_flow_rst_keeps_mutex_usable ()
{
  printf ("test_flow_rst_keeps_mutex_usable\n");

  struct in_addr src = { .s_addr = 0x01020304 };
  struct in_addr dst = { .s_addr = 0x05060708 };
  uint16_t sport = htons (1234);
  uint16_t dport = htons (5678);
  flow_t flow;
  flow_t *ptr = &flow;
  flow_init (ptr, src, dst, sport, dport);

  ptr->seg_nxt = 100;
  CREATE_AND_ATTACH (ptr, 100, 3, "abc");

  EXPECT_EQ_INT (0, flow_handshake (ptr, TH_RST, 103, 1));
  EXPECT_EQ_INT (src.s_addr, ptr->ip_src.s_addr);
  EXPECT_EQ_INT (dst.s_addr, ptr->ip_dst.s_addr);
  EXPECT_EQ_INT (sport, ptr->port_src);
  EXPECT_EQ_INT (dport, ptr->port_dst);
  EXPECT_EQ_PTR (NULL, ptr->next);
  EXPECT_EQ_INT (0, ptr->size);
  EXPECT_EQ_INT (TH_RST, ptr->flags);

  EXPECT_EQ_INT (0, pthread_mutex_lock (&ptr->mutex));
  EXPECT_EQ_INT (0, pthread_mutex_unlock (&ptr->mutex));
  EXPECT_EQ_INT (TH_SYN, flow_handshake (ptr, TH_SYN, 200, 1));

  flow_reset (ptr);
}

#define TEST_SET_IP(t, host, ei, ep)                                         \
  do                                                                         \
    {                                                                        \
      flow_t flow;                                                           \
      flow_t *ptr = &flow;                                                   \
      flow_init (ptr, (struct in_addr) { 0 }, (struct in_addr) { 0 }, 0, 0); \
      SET_IP (ptr, t, host);                                                 \
      EXPECT_EQ_INT (ep, ntohs (ptr->port_##t));                             \
      EXPECT_EQ_BASE ((uint32_t) (ei) == ptr->ip_##t.s_addr,                 \
                      (uint32_t) (ei), ptr->ip_##t.s_addr, "%u");            \
      flow_reset (ptr);                                                      \
    }                                                                        \
  while (0)

void
test_set_ip ()
{
  TEST_SET_IP (tar, "127.0.0.1:1234", UINT32_C (1) << 24 | 127, 1234);
  TEST_SET_IP (tar, "192.168.0.1:9999", UINT32_C (1) << 24 | UINT32_C (168) << 8 | 192, 9999);
  TEST_SET_IP (tar, "1.1.1.1:1", UINT32_C (1) << 24 | UINT32_C (1) << 16 | UINT32_C (1) << 8 | 1, 1);
  TEST_SET_IP (tar, "255.255.255.255:255", UINT32_C (255) << 24 | UINT32_C (255) << 16 | UINT32_C (255) << 8 | 255, 255);
  TEST_SET_IP (src, "10.10.10.10:10", UINT32_C (10) << 24 | UINT32_C (10) << 16 | UINT32_C (10) << 8 | 10, 10);
  TEST_SET_IP (src, "0.0.0.0:0", 0, 0);
  TEST_SET_IP (dst, "127.0.1.1:65535", UINT32_C (1) << 24 | UINT32_C (1) << 16 | 127, 65535);
  TEST_SET_IP (dst, "0.127.127.1:123", UINT32_C (1) << 24 | UINT32_C (127) << 16 | UINT32_C (127) << 8, 123);
}

int
main (void)
{
  test_flow_state_attach ();
  test_flow_state_attach2 ();
  test_flow_state_attach3 ();
  test_flow_state_pkt_slice ();
  test_flow_state_attach_partially ();
  test_flow_state_attach_retrans ();
  test_contain ();
  test_detect ();
  test_cal ();
  test_flow_handshake ();
  test_flow_syn_resets_existing_tuple ();
  test_flow_rst_keeps_mutex_usable ();
  test_set_ip ();

  printf ("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);
  return main_ret;
}

// gdb-sudo  :program "./pcap/build/hello" :args  "\"dst host 192.168.101.182 or dst host 172.20.10.2\""
