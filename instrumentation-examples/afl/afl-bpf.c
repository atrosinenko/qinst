#include <stdint.h>

extern uint8_t *__afl_area_ptr;
static uint64_t prev;

static __attribute__((always_inline)) void br(uint64_t x, uint64_t y)
{
  uint64_t tag = pc();
  __afl_area_ptr[((prev >> 1) ^ tag) & 0xFFFF] += 1;
  prev = tag;
}

void __attribute__((noinline)) inst_qemu_brcond_i64(uint64_t x, uint64_t y)
{
  br(x, y);
}

void __attribute__((noinline)) inst_qemu_brcond_i32(uint64_t x, uint64_t y)
{
  br(x, y);
}
