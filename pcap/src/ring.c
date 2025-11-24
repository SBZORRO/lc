/* #include <stdatomic.h> */
/* #include <stdint.h> */
/* #include <string.h> */
/* #include <sys/types.h> */

/* struct ring */
/* { */
/*   u_char *data; */
/*   uint32_t capacity; */
/*   _Atomic uint32_t head; */
/*   _Atomic uint32_t tail; */
/* }; */

/* int */
/* ring_push (struct ring *r, const uint8_t *buf, uint32_t len) */
/* { */
/*   uint32_t head = atomic_load_explicit (&r->head, memory_order_relaxed); */
/*   uint32_t tail = atomic_load_explicit (&r->tail, memory_order_acquire); */

/*   uint32_t next = (head + len) % r->capacity; */

/*   if (next == tail) */
/*     return -1; // full */

/*   // 写数据（可能wrap） */
/*   if (head + len <= r->capacity) */
/*     memcpy (r->data + head, buf, len); */
/*   else */
/*     { */
/*       uint32_t first = r->capacity - head; */
/*       memcpy (r->data + head, buf, first); */
/*       memcpy (r->data, buf + first, len - first); */
/*     } */

/*   atomic_store_explicit (&r->head, next, memory_order_release); */
/*   return 0; */
/* } */

/* int */
/* ring_pop (struct ring *r, uint8_t *out, uint32_t len) */
/* { */
/*   uint32_t tail = atomic_load_explicit (&r->tail, memory_order_relaxed); */
/*   uint32_t head = atomic_load_explicit (&r->head, memory_order_acquire); */

/*   if (tail == head) */
/*     return -1; // empty */

/*   uint32_t next = (tail + len) % r->capacity; */

/*   if (tail + len <= r->capacity) */
/*     memcpy (out, r->data + tail, len); */
/*   else */
/*     { */
/*       uint32_t first = r->capacity - tail; */
/*       memcpy (out, r->data + tail, first); */
/*       memcpy (out + first, r->data, len - first); */
/*     } */

/*   atomic_store_explicit (&r->tail, next, memory_order_release); */
/*   return 0; */
/* } */
