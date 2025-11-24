#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef CACHELINE
# define CACHELINE 64
#endif

// 要求 capacity 是 2 的幂
typedef struct spsc_queue
{
  size_t capacity;
  size_t mask;

  // head 只由消费者写，生产者读
  _Alignas (CACHELINE) _Atomic size_t head;
  // tail 只由生产者写，消费者读
  _Alignas (CACHELINE) _Atomic size_t tail;

  // 避免 head / tail false sharing
  char _pad1[CACHELINE - sizeof (_Atomic size_t)];

  void *buffer[];
} spsc_queue;

// 创建时要自己分配足够空间：sizeof(spsc_queue) + capacity * sizeof(void*)

// 初始化
static inline void
spsc_init (spsc_queue *q, size_t capacity)
{
  // capacity 必须是 2 的幂
  q->capacity = capacity;
  q->mask = capacity - 1;
  atomic_store_explicit (&q->head, 0, memory_order_relaxed);
  atomic_store_explicit (&q->tail, 0, memory_order_relaxed);
}

// 入队：生产者线程调用
static inline bool
spsc_enqueue (spsc_queue *q, void *val)
{
  size_t head = atomic_load_explicit (&q->head, memory_order_acquire);
  size_t tail = atomic_load_explicit (&q->tail, memory_order_relaxed);

  size_t next_tail = (tail + 1) & q->mask;

  // 队满：next_tail == head
  if (next_tail == head)
    {
      return false;
    }

  // 写数据
  q->buffer[tail] = val;

  // 发布：保证 buffer[tail] 对消费者可见
  atomic_store_explicit (&q->tail, next_tail, memory_order_release);
  return true;
}

// 出队：消费者线程调用
static inline bool
spsc_dequeue (spsc_queue *q, void **out)
{
  size_t tail = atomic_load_explicit (&q->tail, memory_order_acquire);
  size_t head = atomic_load_explicit (&q->head, memory_order_relaxed);

  // 队空
  if (head == tail)
    {
      return false;
    }

  void *val = q->buffer[head];

  size_t next_head = (head + 1) & q->mask;
  // 通知生产者可以复用该槽位
  atomic_store_explicit (&q->head, next_head, memory_order_release);

  *out = val;
  return true;
}
