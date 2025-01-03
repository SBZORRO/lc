#define offset(TYPE, MEMBER) ((size_t)&((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member)                                        \
  ((type *)(((char *)((type *)ptr)) - offsetof(type, member)))
