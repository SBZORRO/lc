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
flow_find_peer (flow_arr_t *fa, flow_t *flow)
{
  if (fa == NULL || flow == NULL)
    {
      return NULL;
    }
  return flow_find (fa, flow->ip_dst, flow->ip_src, flow->port_dst, flow->port_src);
}

void
flow_link_peer (flow_t *flow, flow_t *peer)
{
  if (flow == NULL || peer == NULL || flow == peer)
    {
      return;
    }
  flow->peer = peer;
  peer->peer = flow;
  if (flow->detect.dir == FLOW_DIR_REQUEST)
    {
      peer->detect.dir = FLOW_DIR_RESPONSE;
    }
  else if (flow->detect.dir == FLOW_DIR_RESPONSE)
    {
      peer->detect.dir = FLOW_DIR_REQUEST;
    }
  else if (peer->detect.dir == FLOW_DIR_REQUEST)
    {
      flow->detect.dir = FLOW_DIR_RESPONSE;
    }
  else if (peer->detect.dir == FLOW_DIR_RESPONSE)
    {
      flow->detect.dir = FLOW_DIR_REQUEST;
    }
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
  flow->peer = NULL;
  flow->detect = (flow_detect_t){ 0 };
  flow->ip_tar.s_addr = 0;
  flow->port_tar = 0;
  flow_filename (flow);

  flow->next = NULL;
  flow->ts = (struct timespec){ 0 };
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
flow_clear (flow_t *flow, bool clear_tuple)
{
  if (clear_tuple && flow->peer != NULL)
    {
      flow->peer->peer = NULL;
      flow->peer->detect = (flow_detect_t){ 0 };
      flow->peer = NULL;
    }

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
  flow->ip_tar.s_addr = 0;
  flow->port_tar = 0;

  flow->next = NULL;
  flow->detect = (flow_detect_t){ 0 };
  flow->ts = (struct timespec){ 0 };
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
  flow_clear (flow, true);
  pthread_mutex_destroy (&flow->mutex);
}

uint32_t
flow_handshake (flow_t *flow, uint32_t th_flags, uint32_t seq, uint32_t sp)
{
  // 保留线程状态位
  const uint32_t THREAD_MASK = SENDING;
  const uint32_t TCP_MASK = 0xFF; // TH_* 都在低 8 位

  uint32_t thread_bits = flow->flags & THREAD_MASK;
  uint32_t tcp_bits = flow->flags & TCP_MASK;

  // receieve SYN
  if (th_flags & TH_SYN)
    {
      if (flow->next != NULL || flow->seg_nxt != 0 || flow->sock != FLOW_INVALID_SOCKET)
        {
          flow_clear (flow, false);
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
      flow_clear (flow, false);
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
