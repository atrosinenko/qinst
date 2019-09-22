#ifndef COMMON_BASE_H
#define COMMON_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t guest_base;

static inline void *g2h(uint64_t ptr)
{
  return (void *)((uintptr_t)ptr + guest_base);
}

static inline void *h2g(uint64_t ptr)
{
  return (void *)((uintptr_t)ptr - guest_base);
}

#ifdef __cplusplus
}
#endif

#endif // COMMON_BASE_H
