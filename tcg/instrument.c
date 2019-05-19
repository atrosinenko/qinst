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

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "tcg-op.h"
#include "instrument.h"

static BpfInstrumentation *inst;

void instrumentation_init(void)
{
  inst = instrumentation_load();
}

typedef struct alu_op_mapping {
  TCGOpcode opc32;
  TCGOpcode opc64;
  uint8_t arg_cnt;
  uint8_t first_arg_src;
} alu_op_mapping;

#define MAX_REGS 16

#define ALU_UNARY(name, from_src) { .opc32 = INDEX_op_##name##_i32, .opc64 = INDEX_op_##name##_i64, .arg_cnt = 1, .first_arg_src = from_src }
#define ALU_BINARY(name) { .opc32 = INDEX_op_##name##_i32, .opc64 = INDEX_op_##name##_i64, .arg_cnt = 2, .first_arg_src = 0 }

static inline TCGArg reg_by_num(TCGContext *s, TCGOp *op, TCGOp *next_op, int reg_num, uint64_t *allocated_regs, TCGv_i64 *regs, target_ulong tag)
{
  const TCGOpDef * const def = &tcg_op_defs[op->opc];
  CHECK_THAT(reg_num < MAX_REGS);
  if ((*allocated_regs & (1 << reg_num)) == 0) {
    regs[reg_num] = tcg_temp_local_new_i64();
    *allocated_regs |= 1 << reg_num;

    if (1 == reg_num) {
      TCGOp *movi_op = tcg_op_insert_before(s, next_op, INDEX_op_movi_i64);
      movi_op->args[0] = tcgv_i64_arg(regs[reg_num]);
      movi_op->args[1] = tag;
    }
    if (2 <= reg_num && reg_num <= def->nb_iargs + 1) {
      TCGOp *mov_op = tcg_op_insert_before(s, next_op, INDEX_op_mov_i64);
      mov_op->args[0] = tcgv_i64_arg(regs[reg_num]);
      mov_op->args[1] = op->args[def->nb_oargs + reg_num - 2];
    }
  }
  return tcgv_i64_arg(regs[reg_num]);
}

static inline TCGArg reg_imm(TCGContext *s, TCGOp *next_op, uint64_t imm)
{
  TCGOp *movi_op = tcg_op_insert_before(s, next_op, INDEX_op_movi_i64);
  movi_op->args[0] = tcgv_i64_arg(tcg_temp_new_i64());
  movi_op->args[1] = imm;
  return movi_op->args[0];
}

static inline void insert_unary_before(TCGContext *s, TCGOp *next_op, TCGOpcode opc, TCGArg arg0, TCGArg arg1)
{
  TCGOp *new_op = tcg_op_insert_before(s, next_op, opc);
  new_op->args[0] = arg0;
  new_op->args[1] = arg1;
}

static inline void insert_binary_before(TCGContext *s, TCGOp *next_op, TCGOpcode opc, TCGArg arg0, TCGArg arg1, TCGArg arg2)
{
  TCGOp *new_op = tcg_op_insert_before(s, next_op, opc);
  new_op->args[0] = arg0;
  new_op->args[1] = arg1;
  new_op->args[2] = arg2;
}

static struct alu_op_mapping alu_opcodes[13] = {
    ALU_BINARY(add),
    ALU_BINARY(sub),
    ALU_BINARY(mul),
    ALU_BINARY(div),
    ALU_BINARY(or),
    ALU_BINARY(and),
    ALU_BINARY(shl),
    ALU_BINARY(shr),
    ALU_UNARY(neg, 0),
    ALU_BINARY(rem), /* TODO */
    ALU_BINARY(xor),
    ALU_UNARY(mov, 1),
    ALU_BINARY(sar),
};

static inline uint instrument_gen_alu(TCGContext *s, TCGOp *op, TCGOp *next_op, ebpf_op inst_op, int64_t imm64, uint64_t *allocated_regs, TCGv_i64 *regs, target_ulong tag)
{
  bool is_64bit = !!(inst_op.opcode & 0x04);
  bool is_imm = !(inst_op.opcode & 0x08);
  uint op_ind = (inst_op.opcode & 0xF0u) >> 4;

  assert(is_64bit);
  assert(op_ind < ARRAY_SIZE(alu_opcodes));

  alu_op_mapping mapping = alu_opcodes[op_ind];
  TCGArg arg0 = reg_by_num(s, op, next_op, inst_op.dst, allocated_regs, regs, tag);
  TCGArg arg1 = 0;
  TCGArg arg2 = 0;
  if (op_ind == 0x0b && is_imm)
    arg1 = reg_imm(s, next_op, inst_op.imm);
  else
    arg1 = reg_by_num(s, op, next_op, mapping.first_arg_src ? inst_op.src : inst_op.dst, allocated_regs, regs, tag);
  if (mapping.arg_cnt > 1) {
    if (is_imm) {
      arg2 = reg_imm(s, next_op, inst_op.imm);
    } else {
      arg2 = reg_by_num(s, op, next_op, inst_op.src, allocated_regs, regs, tag);
    }
  }
  insert_binary_before(s, next_op, is_64bit ? mapping.opc64 : mapping.opc32, arg0, arg1, arg2);
  return 1;
}

static inline uint instrument_gen_mem(TCGContext *s, TCGOp *op, TCGOp *next_op, ebpf_op inst_op, int64_t imm64, uint64_t *allocated_regs, TCGv_i64 *regs, target_ulong tag)
{
#define LD(opcode, width) \
  case opcode: \
  insert_binary_before(s, next_op, INDEX_op_ld##width##_i64, \
                       reg_by_num(s, op, next_op, inst_op.dst, allocated_regs, regs, tag), \
                       reg_by_num(s, op, next_op, inst_op.src, allocated_regs, regs, tag), \
                       inst_op.offset); \
    return 1;
#define ST_IMM(opcode, width, ret, val) \
  case opcode: \
    insert_binary_before(s, next_op, INDEX_op_st##width##_i64, \
                         val, \
                         reg_by_num(s, op, next_op, inst_op.dst, allocated_regs, regs, tag), \
                         inst_op.offset); \
    return ret;
#define ST_REG(opcode, width) \
  case opcode: \
    insert_binary_before(s, next_op, INDEX_op_st##width##_i64, \
                         reg_by_num(s, op, next_op, inst_op.src, allocated_regs, regs, tag), \
                         reg_by_num(s, op, next_op, inst_op.dst, allocated_regs, regs, tag), \
                         inst_op.offset); \
    return 1;

  switch (inst_op.opcode) {
  case 0x18:
    insert_unary_before(s, next_op, INDEX_op_movi_i64, reg_by_num(s, op, next_op, inst_op.dst, allocated_regs, regs, tag), imm64);
    return 2;
  LD(0x61, 32u)
  LD(0x69, 16u)
  LD(0x71, 8u)
  LD(0x79, )

  ST_IMM(0x62, 32, 1, reg_imm(s, next_op, inst_op.imm))
  ST_IMM(0x6A, 16, 1, reg_imm(s, next_op, inst_op.imm & 0xFFFF))
  ST_IMM(0x72, 8,  1, reg_imm(s, next_op, inst_op.imm & 0xFF))
  ST_IMM(0x7A, , 2, reg_imm(s, next_op, imm64))

  ST_REG(0x63, 32)
  ST_REG(0x6B, 16)
  ST_REG(0x73, 8)
  ST_REG(0x7B, )
  }
  tcg_abort();

#undef ST_REG
#undef ST_IMM
#undef LD
}

static inline void instrument_one_insn(TCGContext *s, TCGOp *op, ebpf_op *inst_ops, size_t inst_ops_count, target_ulong tag)
{
  static __thread TCGv_i64 regs[MAX_REGS];
  uint64_t allocated_regs = 0;
  size_t skip_insn = 0;

  for (size_t i = 0; i < inst_ops_count - 1 /* exit */; i += skip_insn) {
    ebpf_op cur_op = inst_ops[i];
    int64_t imm64 = cur_op.imm | (((uint64_t)inst_ops[i + 1].imm) << 32);
    switch (cur_op.opcode & 0x07) {
    case 0x07: // 64-bit ALU
    case 0x04: // 32-bit ALU
      skip_insn = instrument_gen_alu(s, op, op, cur_op, imm64, &allocated_regs, regs, tag);
      break;
    case 0x00: // memory, "see kernel documentation"
    case 0x01: // memory
    case 0x03:
      skip_insn = instrument_gen_mem(s, op, op, cur_op, imm64, &allocated_regs, regs, tag);
      break;
    case 0x05: // branch
    default:
      tcg_abort();
    }
  }
  for (int i = 0; i < MAX_REGS; ++i) {
    if (allocated_regs & (1 << i)) {
      tcg_temp_free_i64(regs[i]);
    }
  }
}

void tcg_instrument(TCGContext *s, target_ulong pc)
{
  TCGOp *op, *op_next;
  uint ctr = 0;

  if (!inst)
    return;

  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    TCGOpcode opc = op->opc;
    if (inst->bpf_prog_by_op[opc]) {
      instrument_one_insn(s, op, inst->bpf_prog_by_op[opc], inst->bpf_prog_len[opc], pc + (ctr++));
    }
  }
}
