QInst is a dynamic instrumentation tool based on [QEMU](https://www.qemu.org/) and supposed to perform trivial instrumentation with trivial code. It inserts snippets of code before the specified ops of QEMU internal representation. To achieve this, it takes arbitrary `plugin.so` with native code of the instrumenter run-time as well as little `plugin-bpf.a` with specially named functions that are hooked to QEMU internal ops. This allows to very easily hook into deep internals of QEMU between the disasm/codegen and dead code elimination/optimization logic.

This software is at the very early development stage, still it is already able to run instrumentation of [AFL](http://lcamtuf.coredump.cx/afl/).

The AFL instrumentation looks like the following (this is the actual working example):
```cpp
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
```

The nice fact about this tool is that its instrumentations are not tied to QEMU. Sure, they use QEMU opcode names and signatures but it should be probably easy to make the instrumentation cross-tool if other implementation will become available (such as LLVM or DynamoRIO).

Possibilities from slowest to fastest:
```
(a) Dynamic instrumentation: QEMU, DynamoRIO (you are here)
(b) Static instrumentation: LLVM
--
(c) Hardware-assisted generic instrumentation
(d) Hardware-assisted instrumentation baked into instantiated softprocessor
```

* (a) is already implemented as an early draft
* (b) is not very hard to implement
* (d) is probably achievable with something like RocketChip under present-and-near-future assumptions for QInst (no branches / only forward branches)
* (c) would be the most flexible (if possible at all) but requires some configurable FPGA-like additions to CPU :)

## Examples

Examples are in the `instrumentation-examples` directory. Compile the eBPF part with `compile-bpf.sh`, then compile native part and run
```
NATIVE_INST=./path/to/native.so BPF_INST=./path/to/bpf.o ./x86_64-linux-user/qemu-x86_64 -- /bin/gzip -d
```

**For now, Pull Requests are not accepted.** I hope to upstream it someday, but QEMU has a non-trivial policy on pushing the changes (Signed-Off's, etc.).
