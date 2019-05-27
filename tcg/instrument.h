/*
 * eBPF-based instrumenter for QEMU TCG
 *
 * Copyright (c) 2019 Anatoly Trosinenko
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef INSTRUMENT_H
#define INSTRUMENT_H

#include "qemu-common.h"
#include <stdint.h>
#include <elf.h>

#define MAX_OPS_PER_BPF_FUNCTION 1024

#define CHECK_THAT(expr) if (!(expr)) { fprintf(stderr, "Check [" stringify(expr) "] failed.\n"); exit(1); }

typedef struct {
  uint8_t opcode;
  uint8_t dst:4;
  uint8_t src:4;
  uint16_t offset;
  uint32_t imm;
} ebpf_op;

struct BpfInstrumentation;
typedef struct BpfInstrumentation {
  struct BpfInstrumentation *next;
  void *native_handle; /* Handle of the native part of instrumentation */

  // internal state
  Elf64_Ehdr *header;
  uint8_t *symtab;
  size_t symtab_count;
  size_t symtab_entsize;
  const char *strtab;
  uint8_t **sections;

  // loaded instrumenters
  ebpf_op *bpf_prog_by_op[256];
  size_t bpf_prog_len[256];
  void (*event_qemu_tb)(uint64_t pc, uint64_t cs_base, uint32_t flags);
  void (*event_cpu_exec)(uint32_t is_entry);
  void (*event_before_syscall)(int num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8);
  void (*event_after_syscall)(int num, uint64_t ret, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8);
} BpfInstrumentation;

BpfInstrumentation *instrumentation_load(void);

#endif /* INSTRUMENT_H */
