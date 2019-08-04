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

struct InstrumentationContext;
typedef struct {
  const char *name;
  void *user_data;
  void (*gen_function)(struct InstrumentationContext *c, void *user_data);
} CallbackDef;

extern CallbackDef callback_defs[];

typedef struct {
  uint8_t opcode;
  uint8_t dst:4;
  uint8_t src:4;
  uint16_t offset;
  uint32_t imm;
} ebpf_op;

typedef struct {
  ebpf_op *data;
  size_t len;
  bool requires_localization;
} bpf_prog;

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
  bpf_prog tracing_progs[256];
  bpf_prog tagging_progs[256];
  //  loaded event handlers
  void (*event_dispatch_slow_call)(void *env);
  void (*event_qemu_tb)(uint64_t pc, uint64_t cs_base, uint32_t flags);
  void (*event_qemu_link_tbs)(uint64_t from_pc, uint32_t tb_exit, uint64_t pc, uint64_t cs_base, uint32_t flags, uint32_t cf_mask);
  void (*event_cpu_exec)(uint32_t is_entry);
  uint64_t (*event_before_syscall)(uint32_t num, uint32_t *drop_syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8);
  void (*event_after_syscall)(int num, uint64_t ret, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8);
} BpfInstrumentation;

BpfInstrumentation *instrumentation_load(void);

#endif /* INSTRUMENT_H */
