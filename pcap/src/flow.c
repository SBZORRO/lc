#include "flow.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "log.c/log.h"
#include "packet.h"

flow_arr_t *
flow_arr_init (uint32_t size)
{
  flow_arr_t *p = check_malloc (sizeof (flow_arr_t) + sizeof (flow_t) * size);
  p->flow_cap = size;
  p->flow_len = 0;
  return p;
}

flow_arr_t *
flow_arr_add (flow_arr_t *fa)
{
  if (fa->flow_len == fa->flow_cap)
    {
      /* TODO rework */
      /* flow_arr_t *new_flow = check_realloc (flow, sizeof (flow_arr_t) + sizeof (flow_t) * flow->flow_cap * 2); */
      /* new_flow->flow_cap = flow->flow_cap * 2; */
      /* new_flow->flow_len = flow->flow_len + 1; */
      /* return new_flow; */
      log_error ("TOO_MUCH_FLOW: %u", fa->flow_len);
      return NULL;
    }
  fa->flow_len = fa->flow_len + 1;
  log_trace ("flow_arr_add: %u", fa->flow_len);
  return fa;
}

flow_t *
flow_add (flow_arr_t *fa)
{
  if (fa->flow_len == fa->flow_cap)
    {
      for (uint32_t i = 0; i < fa->flow_len; i++)
        {
          flow_t f = fa->flow[i];
          if (f.ip_src.s_addr == 0)
            {
              log_trace ("fa_reuse: %u", i);
              return &fa->flow[i];
            }
        }
      return NULL;
    }
  fa->flow_len = fa->flow_len + 1;
  log_trace ("  fa_add: %u", fa->flow_len);
  return fa->flow + fa->flow_len - 1;
}

flow_t *
flow_find (flow_arr_t *fa,
           const struct in_addr src, const struct in_addr dst,
           const u_short sport, const u_short dport)
{
  for (uint32_t i = 0; i < fa->flow_len; i++)
    {
      if (fa->flow[i].ip_src.s_addr == src.s_addr
          && fa->flow[i].port_src == sport
          && fa->flow[i].ip_dst.s_addr == dst.s_addr
          && fa->flow[i].port_dst == dport)
        {
          return fa->flow + i;
        }
    }
  return NULL;
}

flow_t *
flow_init (flow_t *flow,
           const struct in_addr src, const struct in_addr dst,
           const u_short sport, const u_short dport)
{
  flow->ip_src = src;
  flow->port_src = sport;
  flow->ip_dst = dst;
  flow->port_dst = dport;
  flow->ip_tar.s_addr = 0;
  flow->port_tar = 0;
  flow_filename (flow);

  flow->next = NULL;
  flow->ts = (struct timespec) { 0 };
  flow->flags = 0;
  flow->sock = FLOW_INVALID_SOCKET;
  flow->fp = NULL;
  flow->size = 0;
  flow->seg_nxt = 0;

  // reentrant lock
  pthread_mutexattr_t attr;
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&flow->mutex, &attr);
  pthread_mutexattr_destroy (&attr);

  return flow;
}

static void
flow_reset_state (flow_t *flow, bool clear_tuple)
{
  flow_state_t *ptr = flow->next;
  flow->next = NULL; // detach first
  while (ptr)
    {
      flow_state_t *next = ptr->next;
      flow_state_free (ptr);
      ptr = next;
    }

  if (clear_tuple)
    {
      flow->ip_src.s_addr = 0;
      flow->port_src = 0;
      flow->ip_dst.s_addr = 0;
      flow->port_dst = 0;
      flow->filename[0] = '\0'; // make it an empty string
    }
  else
    {
      flow_filename (flow);
    }
  flow->ip_tar.s_addr = 0;
  flow->port_tar = 0;

  flow->next = NULL;
  flow->ts = (struct timespec) { 0 };
  flow->flags = clear_tuple ? 0 : (flow->flags & SENDING);
  flow_close_socket (flow);
  if (flow->fp)
    {
      fclose (flow->fp);
      flow->fp = NULL;
    }
  flow->size = 0;
  flow->seg_nxt = 0;
}

void
flow_reset (flow_t *flow)
{
  flow_reset_state (flow, true);
  pthread_mutex_destroy (&flow->mutex);
}

uint32_t
flow_handshake (flow_t *flow, uint32_t th_flags, uint32_t seq, uint32_t sp)
{
  // 保留线程状态位
  const u_int THREAD_MASK = SENDING;
  const u_int TCP_MASK = 0xFF; // TH_* 都在低 8 位

  u_int thread_bits = flow->flags & THREAD_MASK;
  u_int tcp_bits = flow->flags & TCP_MASK;

  // receieve SYN
  if (th_flags & TH_SYN)
    {
      if (flow->next != NULL || flow->seg_nxt != 0 || flow->sock != FLOW_INVALID_SOCKET)
        {
          flow_reset_state (flow, false);
          thread_bits = flow->flags & THREAD_MASK;
          tcp_bits = 0;
        }
      tcp_bits &= ~TH_RST; // unset rst flag
      tcp_bits |= th_flags;
      flow->flags = thread_bits | tcp_bits;
      flow->seg_nxt = seq + 1;
      seq++; // SEQ_LEQ
      log_trace ("SYN");
      // return 1; // init seg_nxt seq
    }
  else if (th_flags & TH_RST) // receive RST
    {
      flow_reset_state (flow, false);
      tcp_bits = TH_RST; // reset tcp bits
      flow->flags = thread_bits | tcp_bits;
      log_trace ("RST");
      return 0;
    }
  else if (tcp_bits & TH_RST) // 丢包直到 SYN
    {
      flow->flags = thread_bits | tcp_bits;
      log_trace ("DISCARD_RST");
      return 0;
    }
  else if (flow->seg_nxt == 0)
    {
      flow->seg_nxt = seq;
      log_trace ("SEG_NXT");
    }

  if (sp == 0)
    {
      log_trace ("DISCARD_SIZE_0");
      return 0;
    }

  uint32_t e = seq + sp; // [s, e)
  // outside of window
  if (SEQ_LEQ (e, flow->seg_nxt))
    {
      log_trace ("DISCARD_OUT_OF_WINDOW");
      return 0;
    }

  tcp_bits |= th_flags;
  flow->flags = thread_bits | tcp_bits;

  return flow->flags;
}

flow_state_t *
flow_state_fix_and_pop (flow_t *flow)
{
  flow_state_t *state = flow->next;
  if (state == NULL || SEQ_LT (flow->seg_nxt, state->seq))
    {
      log_trace (" NOT_YET: [%p][%p]", flow, state);
      return NULL;
    }
  uint32_t e = state->seq + state->size_payload;
  // outside of window
  if (SEQ_LEQ (e, flow->seg_nxt))
    {
      log_trace (" DISCARD: [%p][%p]", flow, state);
      flow->next = state->next;
      flow->size--;
      flow_state_free (state);
      return NULL;
    }
  if (SEQ_LT (state->seq, flow->seg_nxt) && SEQ_GT (e, flow->seg_nxt)) // overlap
    {
      log_trace ("  SLICED: [%p][%p]", flow, state);
      state->size_payload = e - flow->seg_nxt;
      state->offset_payload = state->offset_payload + flow->seg_nxt - state->seq;
    }
  flow->seg_nxt += state->size_payload;
  flow->next = state->next;
  flow->size--;
  return state;
}

flow_state_t *
flow_state_detach (flow_t *flow, flow_state_t *state)
{
  if (state == NULL || flow->next == NULL)
    {
      return NULL;
    }

  flow_state_t *ptr = flow->next;
  if (ptr == state)
    {
      return flow_state_fix_and_pop (flow);
    }

  while (ptr->next != state)
    {
      if (ptr->next == NULL)
        {
          return NULL;
        }
      ptr = ptr->next;
    }

  ptr->next = state->next;
  flow->size--;

  return ptr->next;
}

flow_state_t *
flow_state_attach (flow_t *flow, flow_state_t *state)
{
  uint32_t seq = state->seq;
  clock_gettime (CLOCK_REALTIME, &flow->ts);
  if (flow->next == NULL)
    {
      flow->next = state;
      flow->size++;
      return state;
    }
  else
    {
      flow_state_t *ptr = flow->next;
      /* dup packet use long */
      if (seq == ptr->seq)
        {
          if (state->size_payload > ptr->size_payload)
            {
              state->next = ptr->next;
              flow->next = state;
              flow_state_free (ptr);
            }
          return state;
        }
      /* retrans packet */
      if (SEQ_LT (seq, ptr->seq))
        {
          state->next = flow->next;
          flow->next = state;
          flow->size++;
          return state;
        }

      flow_state_t *prev = flow->next;
      ptr = prev->next;
      while (ptr != NULL)
        {
          /* dup packet use long */
          if (seq == ptr->seq)
            {
              if (state->size_payload > ptr->size_payload)
                {
                  state->next = ptr->next;
                  prev->next = state;
                  flow_state_free (ptr);
                }
              return state;
            }

          /* retrans packet */
          if (SEQ_LT (seq, ptr->seq))
            {
              state->next = ptr;
              prev->next = state;
              flow->size++;
              return state;
            }
          prev = ptr;
          ptr = ptr->next;
        }
      prev->next = state;
      flow->size++;
      return state;
    }
}

flow_state_t *
flow_state_create (flow_t *flow, uint32_t seq, uint32_t ack, uint32_t flags, uint32_t size_payload, uint32_t offset_payload, uint8_t *pkt)
{
  flow_state_t *new_flow_state = MALLOC (flow_state_t, 1);
  new_flow_state->next = NULL;
  new_flow_state->flow = flow;
  new_flow_state->seq = seq;
  new_flow_state->ack = ack;
  new_flow_state->size_payload = size_payload;
  new_flow_state->offset_payload = offset_payload;
  new_flow_state->flags = flags;
  new_flow_state->pkt = pkt;

  return new_flow_state;
}

void
flow_print (flow_t *f)
{
  printf ("FLOW: \n");
  printf ("  From: %s:%u\n", inet_ntoa (f->ip_src), ntohs (f->port_src));
  printf ("    To: %s:%u\n", inet_ntoa (f->ip_dst), ntohs (f->port_dst));
  printf ("  next: %p\n", f->next);
  printf ("   nxt: %u\n", f->seg_nxt);
  printf ("  size: %u\n", f->size);
  printf ("  flag: %u\n", f->flags);
  printf ("  name: %s\n", f->filename);
  printf ("  time: %lu\n", f->ts.tv_nsec);
  printf ("  thrd: %lu\n", f->thread);
  printf ("  sock: %llu\n", (unsigned long long) f->sock);
  printf ("  file: %p\n", f->fp);
}

void
flow_state_print (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      for (size_t i = ptr->offset_payload; i < ptr->offset_payload + ptr->size_payload; i++)
        {
          printf ("%c", ptr->pkt[i]);
        }
      ptr = ptr->next;
    }
  printf ("\n");
}

void
flow_state_print_hex (flow_t *flow)
{
  flow_state_t *ptr = flow->next;
  while (ptr != NULL)
    {
      for (size_t i = ptr->offset_payload; i < ptr->offset_payload + ptr->size_payload; i++)
        {
          printf ("%02x ", ptr->pkt[i]);
        }
      ptr = ptr->next;
    }
  printf ("\n");
}

void
flow_state_log (flow_state_t *state)
{
  log_debug ("   STATE: [%p][%p][%p][%u][%u][%u][%u][%u]",
             state->next, state->flow, state->pkt,
             state->flags, state->seq, state->ack, state->offset_payload, state->size_payload);
}

uint32_t
flow_state_assemble (flow_t *flow, uint8_t *buffer)
{
  flow_state_t *state = flow->next;
  uint32_t i = 0;
  while (state != NULL)
    {
      memcpy (buffer + i, state->pkt + state->offset_payload, state->size_payload);
      i = i + state->size_payload;
      state = state->next;
    }
  return i;
}

void
flow_state_free (flow_state_t *fs)
{
  log_trace ("    free: [%p][%p]", fs->flow, fs);
  if (fs == NULL)
    return;
  fs->next = NULL;
  fs->flow = NULL;
  if (fs->pkt != NULL)
    {
      free (fs->pkt); // only if pkt is truly heap-owned by this node
    }
  fs->pkt = NULL;
  free (fs);
}

/* protocol section */
const char *servos_requ[] = { "\x1b", "HO", "RCTY1C", "RSEN0A", "SDADS", "SDADE", "SDADC", "SDADB", "RSTI1C", "SSMP0202F", "RADC14", NULL };
const char *servos_resp[] = { "900PCI", "Servo-s0", "Servo-i0", "Servo-s1", "Servo-i1", NULL };

const char *servou_resp[] = { "BER2057", "ER2015", "Servo-u0", "Servo-u1", "Servo-n0", "Servo-n1", "Servo-air0", "Servo-air1", NULL };

const char *default_resp = "*2A";

const char *EOT = "\x04";
const char *ESC = "\x1b";

const char *curve_phase_i = "\x81\x10\x80";
const char *curve_phase_p = "\x81\x20\x80";
const char *curve_phase_e = "\x81\x30\x80";

/* * 发送 */
/*   请求ICC:          1b5136430d */
/*   请求设备ID:       1b5236440d */
/*   请求测量数据CP1:  1b2433460d */
/*   请求测量数据CP2:  1b2b34360d */
/*   请求设备设置:     1b2934340d */
/*   请求文本消息:     1b2a34350d */
/*   请求停止通讯:     1b5537300d */
/*   发送NOP命令:      1b3034420d */
/*   请求实时数据配置: 1b5336450d */
/*   发送实时数据配置: 1b5430303031303130313033303142360d */
/*   启动数据流:       d0c1cfc0c0 */
/*   关闭数据流:       d0c1c0c0c0 */
/*   发送设备ID:       01523031363127536d6f44726167657256656e742730312e30333a30362e303041410d */
/*     0161'SmoDragerVent'01.03:06.00 */

// clang-format off
const char *drager_resp[] = { "\x1BQ", "\x01Q", "\x1BR", "\x01R", "\x01S", "\x01T", "\x01BV", "\x01$", "\x01+", "\x01)", "\x01*", "\x01""0", "\x1B""0", "\x01\x15", "\x01\x01", NULL };
// clang-format on
const char *drager_cmd[] = {
  /* "\x1b5136430d", */
  /* "\x1b5236440d", */
  /* "\x1b2433460d", */
  /* "\x1b2b34360d", */
  /* "\x1b2934340d", */
  /* "\x1b2a34350d", */
  /* "\x1b5537300d", */
  /* "\x1b3034420d", */
  /* "\x1b5336450d", */
  /* "\x1b5430303031303130313033303142360d", */
  /* "\xd0c1cfc0c0", */
  /* "\xd0c1c0c0c0", */
  /* "\x01523031363127536d6f44726167657256656e742730312e30333a30362e303041410d" */
};

int
contain (uint8_t *str, uint32_t len, const char **targets)
{
  if (len == 0)
    {
      return 0;
    }
  // prefix
  for (int i = 0; targets[i] != NULL; i++)
    {
      size_t tarlen = strlen (targets[i]);
      int res = memcmp (str, targets[i], MIN (len, tarlen));
      if (res == 0)
        {
          return 1;
        }
    }

  // contain
  for (int i = 0; targets[i] != NULL; i++)
    {
      void *res = memmem (str, len, targets[i], strlen (targets[i]));
      if (res != NULL)
        {
          return 1;
        }
    }
  return 0;
}

int
detect (flow_state_t *ptr)
{
  if (ptr != NULL)
    {
      if (contain (ptr->pkt + ptr->offset_payload, ptr->size_payload, servos_resp))
        {
          return 1;
        }
      if (contain (ptr->pkt + ptr->offset_payload, ptr->size_payload, servou_resp))
        {
          return 2;
        }
      if (contain (ptr->pkt + ptr->offset_payload, ptr->size_payload, drager_resp))
        {
          return 3;
        }
      // contain (ptr->payload, ptr->len, servos_requ);
    }
  return 0;
}
