#include <stdint.h>

extern uint8_t *__afl_area_ptr;
extern uint64_t prev;

void inst_qemu_brcond_i64(uint64_t tag, uint64_t x, uint64_t y, uint64_t z, uint64_t u)
{
    __afl_area_ptr[((prev >> 1) ^ tag) & 0xFFFF] += 1;
	prev = tag;
}

void inst_qemu_brcond_i32(uint64_t tag, uint64_t x, uint64_t y, uint64_t z, uint64_t u)
{
    __afl_area_ptr[((prev >> 1) ^ tag) & 0xFFFF] += 1;
	prev = tag;
}
