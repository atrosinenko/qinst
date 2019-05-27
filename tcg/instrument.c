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

#define MAX_REGS 16

typedef struct {
  // thread-statically globals
  TCGv_i64 regs[MAX_REGS];
  TCGLabel *labels[MAX_OPS_PER_BPF_FUNCTION];
  uint64_t allocated_regs;

  // assigned in tcg_optimize
  TCGContext *s;

  // assigned in tcg_optimize inside a loop
  TCGOp *qemu_op;
  uint64_t tag;
  int inst_op_count;

  // assigned in instrument_one_insn
  ebpf_op inst_op;
} InstrumentationContext;

typedef struct alu_op_mapping {
  TCGOpcode opc32;
  TCGOpcode opc64;
  uint8_t arg_cnt;
  uint8_t first_arg_src;
} alu_op_mapping;


#define ALU_UNARY(name, from_src) { .opc32 = INDEX_op_##name##_i32, .opc64 = INDEX_op_##name##_i64, .arg_cnt = 1, .first_arg_src = from_src }
#define ALU_BINARY(name) { .opc32 = INDEX_op_##name##_i32, .opc64 = INDEX_op_##name##_i64, .arg_cnt = 2, .first_arg_src = 0 }

static inline void insert_unary_before(InstrumentationContext *c, TCGOpcode opc, TCGArg arg0, TCGArg arg1)
{
  TCGOp *new_op = tcg_op_insert_before(c->s, c->qemu_op, opc);
  new_op->args[0] = arg0;
  new_op->args[1] = arg1;
}

static inline void insert_binary_before(InstrumentationContext *c, TCGOpcode opc, TCGArg arg0, TCGArg arg1, TCGArg arg2)
{
  TCGOp *new_op = tcg_op_insert_before(c->s, c->qemu_op, opc);
  new_op->args[0] = arg0;
  new_op->args[1] = arg1;
  new_op->args[2] = arg2;
}

static inline TCGArg reg_by_num(InstrumentationContext *c, int reg_num)
{
  const TCGOpDef * const def = &tcg_op_defs[c->qemu_op->opc];
  CHECK_THAT(reg_num < MAX_REGS);
  if ((c->allocated_regs & (1 << reg_num)) == 0) {
    c->regs[reg_num] = tcg_temp_local_new_i64();
    c->allocated_regs |= 1 << reg_num;

    if (1 == reg_num) {
      insert_unary_before(c, INDEX_op_movi_i64, tcgv_i64_arg(c->regs[reg_num]), c->tag);
    }
    if (2 <= reg_num && reg_num <= def->nb_iargs + 1) {
      insert_unary_before(c, INDEX_op_mov_i64, tcgv_i64_arg(c->regs[reg_num]), c->qemu_op->args[def->nb_oargs + reg_num - 2]);
    }
  }
  return tcgv_i64_arg(c->regs[reg_num]);
}

static inline TCGArg reg_imm(InstrumentationContext *c, uint64_t imm)
{
  TCGOp *movi_op = tcg_op_insert_before(c->s, c->qemu_op, INDEX_op_movi_i64);
  movi_op->args[0] = tcgv_i64_arg(tcg_temp_new_i64());
  movi_op->args[1] = imm;
  return movi_op->args[0];
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

static inline uint instrument_gen_alu(InstrumentationContext *c)
{
  bool is_64bit = !!(c->inst_op.opcode & 0x04);
  bool is_imm = !(c->inst_op.opcode & 0x08);
  uint op_ind = (c->inst_op.opcode & 0xF0u) >> 4;

  assert(is_64bit);
  assert(op_ind < ARRAY_SIZE(alu_opcodes));

  alu_op_mapping mapping = alu_opcodes[op_ind];
  TCGArg arg0 = reg_by_num(c, c->inst_op.dst);
  TCGArg arg1 = 0;
  TCGArg arg2 = 0;
  if (op_ind == 0x0b && is_imm)
    arg1 = reg_imm(c, c->inst_op.imm);
  else
    arg1 = reg_by_num(c, mapping.first_arg_src ? c->inst_op.src : c->inst_op.dst);
  if (mapping.arg_cnt > 1) {
    if (is_imm) {
      arg2 = reg_imm(c, c->inst_op.imm);
    } else {
      arg2 = reg_by_num(c, c->inst_op.src);
    }
  }
  insert_binary_before(c, is_64bit ? mapping.opc64 : mapping.opc32, arg0, arg1, arg2);
  return 1;
}

static inline uint instrument_gen_mem(InstrumentationContext *c, int64_t imm64)
{
#define LD(opcode, width) \
  case opcode: \
  insert_binary_before(c, INDEX_op_ld##width##_i64, \
                       reg_by_num(c, c->inst_op.dst), \
                       reg_by_num(c, c->inst_op.src), \
                       c->inst_op.offset); \
    return 1;
#define ST_IMM(opcode, width, ret, val) \
  case opcode: \
    insert_binary_before(c, INDEX_op_st##width##_i64, \
                         val, \
                         reg_by_num(c, c->inst_op.dst), \
                         c->inst_op.offset); \
    return ret;
#define ST_REG(opcode, width) \
  case opcode: \
    insert_binary_before(c, INDEX_op_st##width##_i64, \
                         reg_by_num(c, c->inst_op.src), \
                         reg_by_num(c, c->inst_op.dst), \
                         c->inst_op.offset); \
    return 1;

  switch (c->inst_op.opcode) {
  case 0x18:
    insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, c->inst_op.dst), imm64);
    return 2;
  LD(0x61, 32u)
  LD(0x69, 16u)
  LD(0x71, 8u)
  LD(0x79, )

  ST_IMM(0x62, 32, 1, reg_imm(c, c->inst_op.imm))
  ST_IMM(0x6A, 16, 1, reg_imm(c, c->inst_op.imm & 0xFFFF))
  ST_IMM(0x72, 8,  1, reg_imm(c, c->inst_op.imm & 0xFF))
  ST_IMM(0x7A, , 2, reg_imm(c, imm64))

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

TCGCond branch_mapping[] = {
  TCG_COND_ALWAYS,
  TCG_COND_EQ,
  TCG_COND_GTU,
  TCG_COND_GEU,
  TCG_COND_LTU,
  TCG_COND_LEU,
  -1,
  TCG_COND_NE,
  TCG_COND_GT,
  TCG_COND_GE,
  TCG_COND_LT,
  TCG_COND_LE,
};

static TCGLabel *ref_label_for_ind(InstrumentationContext *c, int index)
{
  CHECK_THAT(index >= 0);
  CHECK_THAT(index <= c->inst_op_count);
  if (!c->labels[index])
    c->labels[index] = gen_new_label();
  return c->labels[index];
}

static void insert_brcond_before(InstrumentationContext *c, TCGCond cond, TCGArg arg1, TCGArg arg2, TCGLabel *label)
{
  if (cond == TCG_COND_ALWAYS) {
    TCGOp *new_op = tcg_op_insert_before(c->s, c->qemu_op, INDEX_op_br);
    label->refs++;
    new_op->args[0] = label_arg(label);
  } else if (cond != TCG_COND_NEVER) {
    TCGOp *new_op = tcg_op_insert_before(c->s, c->qemu_op, INDEX_op_brcond_i64);
    label->refs++;
    new_op->args[0] = arg1;
    new_op->args[1] = arg2;
    new_op->args[2] = cond;
    new_op->args[3] = label_arg(label);
  }
}

static inline uint instrument_gen_branch(InstrumentationContext *c, int cur_ind)
{
  bool is_imm = !(c->inst_op.opcode & 0x08);
  int op_ind = c->inst_op.opcode >> 4;
  if (op_ind == 9) {
    // exit
    TCGLabel *label = ref_label_for_ind(c, c->inst_op_count);
    insert_brcond_before(c, TCG_COND_ALWAYS, 0, 0, label);
    return 1;
  }
  CHECK_THAT(op_ind < ARRAY_SIZE(branch_mapping) && branch_mapping[op_ind] != -1);
  CHECK_THAT(c->inst_op.offset);
  TCGArg arg1 = reg_by_num(c, c->inst_op.dst);
  TCGArg arg2 = is_imm ? reg_imm(c, c->inst_op.imm) : reg_by_num(c, c->inst_op.src);
  insert_brcond_before(c, branch_mapping[op_ind], arg1, arg2, ref_label_for_ind(c, cur_ind + 1 + c->inst_op.offset));
  return 1;
}

static inline bool instrument_one_insn(InstrumentationContext *c, ebpf_op *inst_ops)
{
  size_t skip_insn = 0;

  bool has_branch = false;

  for (size_t i = 0; i < c->inst_op_count; i += skip_insn) {
    if (c->labels[i]) {
      c->labels[i]->present = 1;
      insert_unary_before(c, INDEX_op_set_label, label_arg(c->labels[i]), 0);
    }
    c->inst_op = inst_ops[i];
    int64_t imm64 = c->inst_op.imm | (((uint64_t)inst_ops[i + 1].imm) << 32);
    switch (c->inst_op.opcode & 0x07) {
    case 0x07: // 64-bit ALU
    case 0x04: // 32-bit ALU
      skip_insn = instrument_gen_alu(c);
      break;
    case 0x00: // memory, "see kernel documentation"
    case 0x01: // memory
    case 0x03:
      skip_insn = instrument_gen_mem(c, imm64);
      break;
    case 0x05: // branch
      skip_insn = instrument_gen_branch(c, i);
      has_branch = true;
      break;
    default:
      tcg_abort();
    }
  }
  if (c->labels[c->inst_op_count]) {
    c->labels[c->inst_op_count]->present = 1;
    insert_unary_before(c, INDEX_op_set_label, label_arg(c->labels[c->inst_op_count]), 0);
  }
  for (int i = 0; i < MAX_REGS; ++i) {
    if (c->allocated_regs & (1 << i)) {
      tcg_temp_free_i64(c->regs[i]);
    }
  }
  c->allocated_regs = 0;
  memset(c->labels, 0, (sizeof c->labels[0]) * (c->inst_op_count + 1));

  return has_branch;
}

static void localize_insn(TCGOp *op)
{
  const TCGOpDef * const def = &tcg_op_defs[op->opc];
  for (int i = 0; i < def->nb_oargs + def->nb_iargs; ++i) {
    TCGTemp *temp = arg_temp(op->args[i]);
    temp->temp_local = 1;
  }
}

void tcg_instrument(TCGContext *s, target_ulong pc, target_ulong cs_base, uint64_t flags)
{
  static __thread InstrumentationContext ctx;
  TCGOp *op, *op_next;
  uint ctr = 0;
  bool need_localization = false;

  if (!inst)
    return;

  ctx.s = s;

  if (inst->event_qemu_tb)
    inst->event_qemu_tb(pc, cs_base, flags);

  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    TCGOpcode opc = op->opc;
    ctr++;
    if (inst->bpf_prog_by_op[opc]) {
      ctx.qemu_op = op;
      ctx.tag = pc + ctr;
      ctx.inst_op_count = inst->bpf_prog_len[opc];
      need_localization |= instrument_one_insn(&ctx, inst->bpf_prog_by_op[opc]);
    }
  }

  if (need_localization) {
    QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
      localize_insn(op);
    }
  }
}

void instrument_event_cpu_exec(bool is_entry)
{
  if (inst->event_cpu_exec)
    inst->event_cpu_exec(is_entry);
}

void instrumentation_event_before_syscall(int num, target_long arg1, target_long arg2, target_long arg3, target_long arg4, target_long arg5, target_long arg6, target_long arg7, target_long arg8)
{
  if (inst->event_before_syscall)
    inst->event_before_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}
void instrumentation_event_after_syscall(int num, target_long ret, target_long arg1, target_long arg2, target_long arg3, target_long arg4, target_long arg5, target_long arg6, target_long arg7, target_long arg8)
{
  if (inst->event_after_syscall)
    inst->event_after_syscall(num, ret, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}
