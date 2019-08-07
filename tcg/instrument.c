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

// r0 - r9
#define MAX_REGS 10
// for static references via r10
#define MAX_STACK_WORDS 32

typedef struct InstrumentationContext {
  // thread-statically globals
  uint64_t allocated_regs;
  TCGv_i64 regs[MAX_REGS];
  uint64_t allocated_words;
  TCGv_i64 stack_words[MAX_STACK_WORDS];
  TCGLabel *labels[MAX_OPS_PER_BPF_FUNCTION];

  // assigned in tcg_instrument
  TCGContext *s;
  bool is_tagging;

  // assigned in tcg_instrument inside a loop
  TCGOp *qemu_op;
  uint64_t pc;
  bpf_prog *prog;

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

static inline void nb_oiargs(TCGOp *op, int *oargs, int *iargs)
{
  if (op->opc == INDEX_op_insn_start) {
    *oargs = 0;
    *iargs = 0;
  } else if (op->opc == INDEX_op_call) {
    *oargs = TCGOP_CALLO(op);
    *iargs = TCGOP_CALLI(op);
  } else {
    const TCGOpDef * const def = &tcg_op_defs[op->opc];
    *oargs = def->nb_oargs;
    *iargs = def->nb_iargs;
  }
}

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

static TCGv_i64 temp_new_i64(void)
{
  TCGTemp *temp = tcgv_i64_temp(tcg_temp_new_i64());
  temp->state = 0;
  temp->state_ptr = NULL;
  return temp_tcgv_i64(temp);
}

static inline TCGArg reg_by_num(InstrumentationContext *c, int reg_num)
{
  int nb_oargs, nb_iargs;
  nb_oiargs(c->qemu_op, &nb_oargs, &nb_iargs);
  CHECK_THAT(reg_num < MAX_REGS);
  if ((c->allocated_regs & (1 << reg_num)) == 0) {
    c->regs[reg_num] = temp_new_i64();
    c->allocated_regs |= 1 << reg_num;

    if (1 <= reg_num && reg_num <= nb_iargs) {
      insert_unary_before(c, INDEX_op_mov_i64, tcgv_i64_arg(c->regs[reg_num]), c->qemu_op->args[nb_oargs + reg_num - 1]);
    }
  }
  return tcgv_i64_arg(c->regs[reg_num]);
}

static inline TCGArg stack_word_by_num(InstrumentationContext *c, int word_num)
{
  word_num = -(int16_t)word_num;
  CHECK_THAT(word_num >= 0);
  CHECK_THAT((word_num & 0x7) == 0);
  word_num /= 8;
  CHECK_THAT(word_num < MAX_STACK_WORDS);
  if ((c->allocated_words & (1ll << word_num)) == 0) {
    c->stack_words[word_num] = temp_new_i64();
    c->allocated_words |= 1ll << word_num;
  }
  return tcgv_i64_arg(c->stack_words[word_num]);
}

static inline TCGArg reg_imm(InstrumentationContext *c, uint64_t imm)
{
  TCGOp *movi_op = tcg_op_insert_before(c->s, c->qemu_op, INDEX_op_movi_i64);
  movi_op->args[0] = tcgv_i64_arg(temp_new_i64());
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
  TCGOpcode new_opc = is_64bit ? mapping.opc64 : mapping.opc32;
  TCGArg arg0 = reg_by_num(c, c->inst_op.dst);
  TCGArg arg1 = 0;
  TCGArg arg2 = 0;
  if (op_ind == 0x0b && is_imm) {
    new_opc = INDEX_op_movi_i64;
    arg1 = c->inst_op.imm;
  } else {
    arg1 = reg_by_num(c, mapping.first_arg_src ? c->inst_op.src : c->inst_op.dst);
  }
  if (mapping.arg_cnt > 1) {
    if (is_imm) {
      arg2 = reg_imm(c, c->inst_op.imm);
    } else {
      arg2 = reg_by_num(c, c->inst_op.src);
    }
  }
  insert_binary_before(c, new_opc, arg0, arg1, arg2);
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

  if (c->inst_op.dst == 10) { // stores to "stack" via r10
    switch (c->inst_op.opcode) {
    case 0x7b: // store i64
      insert_unary_before(c, INDEX_op_mov_i64, stack_word_by_num(c, c->inst_op.offset), reg_by_num(c, c->inst_op.src));
      return 1;
    case 0x7a: // store i64 imm
      insert_unary_before(c, INDEX_op_movi_i64, stack_word_by_num(c, c->inst_op.offset), imm64);
      return 2;
    default:
      abort();
    }
  }
  if (c->inst_op.src == 10) { // loads from "stack" via r10
    switch (c->inst_op.opcode) {
    case 0x79: // load i64
      insert_unary_before(c, INDEX_op_mov_i64, reg_by_num(c, c->inst_op.dst), stack_word_by_num(c, c->inst_op.offset));
      return 1;
    default:
      abort();
    }
  }
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
  TCG_COND_ALWAYS, // 05
  TCG_COND_EQ,     // 15 / 1d
  TCG_COND_GTU,    // 25 / 2d
  TCG_COND_GEU,    // 35 / 3d
  -1,              // 45 / 4d
  TCG_COND_NE,     // 55 / 5d
  TCG_COND_GT,     // 65 / 6d
  TCG_COND_GE,     // 75 / 7d
  -1,              // 8...
  -1,              // 9...
  TCG_COND_LTU,    // a5 / ad
  TCG_COND_LEU,    // b5 / bd
  TCG_COND_LT,     // c5 / cd
  TCG_COND_LE,     // d5 / dd
};

static TCGLabel *ref_label_for_ind(InstrumentationContext *c, int index)
{
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

void HELPER(inst_slow_call)(CPUArchState *env)
{
  inst->event_dispatch_slow_call(env);
}

static void instrument_gen_call(struct InstrumentationContext *c, void *user_data)
{
  TCGOp *op = tcg_op_insert_before(c->s, c->qemu_op, INDEX_op_call);
  op->args[0] = tcgv_ptr_arg(cpu_env);
  op->args[1] = (uintptr_t)helper_inst_slow_call;
  op->args[2] = 0;
  TCGOP_CALLO(op) = 0;
  TCGOP_CALLI(op) = 1;
}

static void instrument_gen_pc(struct InstrumentationContext *c, void *user_data)
{
  insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, 0), c->pc);
}

static void instrument_gen_tag_for(struct InstrumentationContext *c, void *user_data)
{
  uintptr_t tag_ind = (uintptr_t)user_data;
  int nb_oargs, nb_iargs;
  nb_oiargs(c->qemu_op, &nb_oargs, &nb_iargs);
  CHECK_THAT(tag_ind < nb_iargs);
  TCGTemp *val = arg_temp(c->qemu_op->args[nb_oargs + tag_ind]);
  if (val->tag) {
    insert_unary_before(c, INDEX_op_mov_i64, reg_by_num(c, 0), temp_arg(val->tag));
  } else {
    insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, 0), 0);
  }
}

static void instrument_gen_const_for(struct InstrumentationContext *c, void *user_data)
{
  uintptr_t const_ind = (uintptr_t)user_data;
  int nb_cargs = tcg_op_defs[c->qemu_op->opc].nb_cargs;
  int nb_oargs, nb_iargs;
  nb_oiargs(c->qemu_op, &nb_oargs, &nb_iargs);
  CHECK_THAT(const_ind < nb_cargs);
  insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, 0), c->qemu_op->args[nb_oargs + nb_iargs + const_ind]);
}

CallbackDef callback_defs[] = {
  {"slow_call", NULL,      instrument_gen_call},
  {"pc",        NULL,      instrument_gen_pc},
  {"tag1",      (void *)0, instrument_gen_tag_for},
  {"tag2",      (void *)1, instrument_gen_tag_for},
  {"tag3",      (void *)2, instrument_gen_tag_for},
  {"const1",    (void *)0, instrument_gen_const_for},
  {"const2",    (void *)1, instrument_gen_const_for},
  {"const3",    (void *)2, instrument_gen_const_for},
  {NULL,        NULL,      NULL}
};

static inline uint instrument_gen_branch(InstrumentationContext *c, int cur_ind)
{
  bool is_imm = !(c->inst_op.opcode & 0x08);
  int op_ind = c->inst_op.opcode >> 4;
  if (op_ind == 8) {
    // call
    CHECK_THAT(c->inst_op.imm < ARRAY_SIZE(callback_defs));
    CallbackDef *def = callback_defs + c->inst_op.imm;
    def->gen_function(c, def->user_data);
    return 1;
  }
  if (op_ind == 9) {
    // exit
    TCGLabel *label = ref_label_for_ind(c, c->prog->len);
    insert_brcond_before(c, TCG_COND_ALWAYS, 0, 0, label);
    return 1;
  }
  CHECK_THAT(op_ind < ARRAY_SIZE(branch_mapping) && branch_mapping[op_ind] != -1);
  TCGArg arg1 = reg_by_num(c, c->inst_op.dst);
  TCGArg arg2 = is_imm ? reg_imm(c, c->inst_op.imm) : reg_by_num(c, c->inst_op.src);
  insert_brcond_before(c, branch_mapping[op_ind], arg1, arg2, ref_label_for_ind(c, cur_ind + 1 + c->inst_op.offset));
  return 1;
}

static inline void instrument_one_insn(InstrumentationContext *c)
{
  size_t skip_insn = 0;
  int nb_oargs, nb_iargs;
  nb_oiargs(c->qemu_op, &nb_oargs, &nb_iargs);

  for (size_t i = 0; i < c->prog->len; i += skip_insn) {
    if (c->labels[i]) {
      c->labels[i]->present = 1;
      insert_unary_before(c, INDEX_op_set_label, label_arg(c->labels[i]), 0);
    }
    c->inst_op = c->prog->data[i];
    int64_t imm64 = c->inst_op.imm | (((uint64_t)c->prog->data[i + 1].imm) << 32);
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
      break;
    default:
      tcg_abort();
    }
  }
  if (c->labels[c->prog->len]) {
    c->labels[c->prog->len]->present = 1;
    insert_unary_before(c, INDEX_op_set_label, label_arg(c->labels[c->prog->len]), 0);
  }
  if (nb_oargs > 0 && (c->allocated_regs & 1) != 0) {
    TCGTemp *temp = arg_temp(c->qemu_op->args[0]);
    TCGv_i64 tag = tcg_temp_local_new_i64();
    temp->tag = tcgv_i64_temp(tag);
    insert_unary_before(c, INDEX_op_mov_i64, tcgv_i64_arg(tag), tcgv_i64_arg(c->regs[0]));
  }

  c->allocated_regs = 0;
  c->allocated_words = 0;
  memset(c->labels, 0, (sizeof c->labels[0]) * (c->prog->len + 1));
}

static void clear_state(TCGOp *op)
{
  int nb_oargs, nb_iargs;
  nb_oiargs(op, &nb_oargs, &nb_iargs);
  for (int i = 0; i < nb_oargs + nb_iargs; ++i) {
    TCGTemp *temp = arg_temp(op->args[i]);
    temp->state = 0;
    temp->state_ptr = NULL;
  }
}

static void localize_insn1(TCGOp *op, uint *counter)
{
  TCGOpcode opc = op->opc;
  int nb_oargs, nb_iargs;
  nb_oiargs(op, &nb_oargs, &nb_iargs);

  // this instruction starts the BB
  if (opc == INDEX_op_set_label)
    *counter += 1;

  // process inputs first because they can be overwritten by this instruction
  for (int i = nb_oargs; i < nb_oargs + nb_iargs; ++i) {
    TCGTemp *temp = arg_temp(op->args[i]);

    if (!temp->temp_local && !temp->fixed_reg && !temp->temp_global) {
      if (temp->state == 0) {
        // first occurrence of this temp
        temp->state = 1 + *counter;
      } else if (temp->state != 1 + *counter && temp->state_ptr == NULL) {
        assert(TCG_TARGET_REG_BITS == 64);
        // create pending local temp
        TCGTemp *local_temp = tcg_temp_new_internal(temp->base_type, true);
        local_temp->tag = temp->tag;
        local_temp->state = 0;
        local_temp->state_ptr = NULL;
        temp->state_ptr = local_temp;
      }
    }
  }

  // then process outputs
  for (int i = 0; i < nb_oargs; ++i) {
    TCGTemp *temp = arg_temp(op->args[i]);
    temp->state = 1 + *counter;
  }

  // these instructions end the BB
  if (opc == INDEX_op_brcond_i32 || opc == INDEX_op_brcond_i64 || opc == INDEX_op_br ||
      opc == INDEX_op_goto_tb || opc == INDEX_op_exit_tb)
    *counter += 1;
}

static void localize_insn2(TCGOp *op)
{
  int nb_oargs, nb_iargs;
  nb_oiargs(op, &nb_oargs, &nb_iargs);
  for (int i = 0; i < nb_oargs + nb_iargs; ++i) {
    TCGTemp *temp = arg_temp(op->args[i]);
    if (temp->state_ptr) {
      op->args[i] = temp_arg((TCGTemp *)temp->state_ptr);
    }
  }
}

static void localize_insn_range(TCGOp *begin, TCGOp *end, uint *counter)
{
  for (TCGOp *cur = begin; cur != end; cur = cur->link.tqe_next) {
    localize_insn1(cur, counter);
  }
}

void tcg_instrument(TCGContext *s, target_ulong pc, target_ulong cs_base, uint64_t flags)
{
  static __thread InstrumentationContext ctx;
  TCGOp *op, *op_next;
  TCGOp *last_insn_start = NULL;
  bool need_localize_insn = false;

  if (!inst)
    return;

  ctx.s = s;

  if (inst->event_qemu_tb)
    inst->event_qemu_tb(pc, cs_base, flags);

  ctx.pc = 0;

  // TODO I don't know why this is required... :(
  // But otherwise it crashes somewhere in the
  // generated code
  temp_new_i64();
  uint counter = 0;

  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    clear_state(op);
  }

  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    TCGOpcode opc = op->opc;

    if (opc == INDEX_op_insn_start) {
      if (need_localize_insn && last_insn_start) {
        localize_insn_range(last_insn_start, op, &counter);
      }

      need_localize_insn = false;
      ctx.pc = op->args[0];
      last_insn_start = op;
    }

    if (ctx.pc) {
      ctx.qemu_op = op;
      if (inst->tracing_progs[opc].data) {
        ctx.is_tagging = false;
        ctx.prog = inst->tracing_progs + opc;
        instrument_one_insn(&ctx);
        need_localize_insn |= inst->tracing_progs[opc].requires_localization;
      }
      if (inst->tagging_progs[opc].data) {
        ctx.is_tagging = true;
        ctx.prog = inst->tagging_progs + opc;
        instrument_one_insn(&ctx);
        need_localize_insn |= inst->tagging_progs[opc].requires_localization;
      }
    }
  }
  if (need_localize_insn && last_insn_start) {
    localize_insn_range(last_insn_start, NULL, &counter);
  }
  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    localize_insn2(op);
  }
  for (int i = 0; i < s->nb_globals; ++i) {
    s->temps[i].tag = NULL;
  }
}

void instrument_event_link_tbs(target_ulong from_pc, int tb_exit, target_ulong pc, target_ulong cs_base, uint32_t flags, uint32_t cf_mask)
{
  if (inst->event_qemu_link_tbs)
    inst->event_qemu_link_tbs(from_pc, tb_exit, pc, cs_base, flags, cf_mask);
}

void instrument_event_cpu_exec(bool is_entry)
{
  if (inst->event_cpu_exec)
    inst->event_cpu_exec(is_entry);
}

target_long instrumentation_event_before_syscall(int num, uint32_t *drop_syscall, target_long arg1, target_long arg2, target_long arg3, target_long arg4, target_long arg5, target_long arg6, target_long arg7, target_long arg8)
{
  if (inst->event_before_syscall)
    return inst->event_before_syscall(num, drop_syscall, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
  else
    return 0;
}
void instrumentation_event_after_syscall(int num, target_long ret, target_long arg1, target_long arg2, target_long arg3, target_long arg4, target_long arg5, target_long arg6, target_long arg7, target_long arg8)
{
  if (inst->event_after_syscall)
    inst->event_after_syscall(num, ret, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}
