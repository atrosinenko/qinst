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

static int inst_verbose;

static void __attribute__((constructor)) constr(void)
{
  inst_verbose = getenv("INST_VERBOSE") != NULL;
}

int instrumentation_verbose(void)
{
  return inst_verbose;
}

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
  int cur_oargs, cur_iargs, cur_cargs;
  TCGArg *cur_outputs, *cur_inputs, *cur_consts;
  TCGOp *insertion_point;
  uint64_t pc;
  bpf_prog *prog;

  // assigned in instrument_one_insn
  ebpf_op inst_op;
} InstrumentationContext;

static int fill_opc(InstrumentationContext *c, TCGOpcode opc)
{
  TCGOpDef *def = tcg_op_defs + opc;
  c->cur_oargs = def->nb_oargs;
  c->cur_iargs = def->nb_iargs;
  c->cur_cargs = def->nb_cargs;
  return def->nb_oargs;
}

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
  TCGOp *new_op = tcg_op_insert_before(c->s, c->insertion_point, opc);
  new_op->args[0] = arg0;
  new_op->args[1] = arg1;
}

static inline void insert_binary_before(InstrumentationContext *c, TCGOpcode opc, TCGArg arg0, TCGArg arg1, TCGArg arg2)
{
  TCGOp *new_op = tcg_op_insert_before(c->s, c->insertion_point, opc);
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
  CHECK_THAT(reg_num < MAX_REGS);
  if ((c->allocated_regs & (1 << reg_num)) == 0) {
    c->regs[reg_num] = temp_new_i64();
    c->allocated_regs |= 1 << reg_num;

    if (1 <= reg_num && reg_num <= c->cur_iargs) {
      insert_unary_before(c, INDEX_op_mov_i64, tcgv_i64_arg(c->regs[reg_num]), c->cur_inputs[reg_num - 1]);
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
  TCGOp *movi_op = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_movi_i64);
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

  if (c->inst_op.opcode == 0xdc) { // to big-endian
    switch(c->inst_op.imm) {
    case 16:
      insert_unary_before(c, INDEX_op_bswap16_i64, reg_by_num(c, c->inst_op.dst), reg_by_num(c, c->inst_op.dst));
      break;
    case 32:
      insert_unary_before(c, INDEX_op_bswap32_i64, reg_by_num(c, c->inst_op.dst), reg_by_num(c, c->inst_op.dst));
      break;
    case 64:
      insert_unary_before(c, INDEX_op_bswap64_i64, reg_by_num(c, c->inst_op.dst), reg_by_num(c, c->inst_op.dst));
      break;
    default:
      abort();
    }
    return 1;
  }

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
    TCGOp *new_op = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_br);
    label->refs++;
    new_op->args[0] = label_arg(label);
  } else if (cond != TCG_COND_NEVER) {
    TCGOp *new_op = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_brcond_i64);
    label->refs++;
    new_op->args[0] = arg1;
    new_op->args[1] = arg2;
    new_op->args[2] = cond;
    new_op->args[3] = label_arg(label);
  }
}

void HELPER(inst_slow_call)(uint64_t arg)
{
  inst->event_dispatch_slow_call(arg);
}

void HELPER(inst_drop_tag)(uint64_t tag, uint32_t opc)
{
  inst->event_drop_tag(tag, opc);
}

static void instrument_gen_drop_tag(struct InstrumentationContext *c, TCGTemp *tag)
{
  TCGLabel *label = gen_new_label();
  insert_brcond_before(c, TCG_COND_EQ, temp_arg(tag), reg_imm(c, 0), label);
  TCGArg opc = reg_imm(c, c->insertion_point->opc);
  TCGOp *op = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_call);
  op->args[0] = temp_arg(tag);
  op->args[1] = opc;
  op->args[2] = (uintptr_t)helper_inst_drop_tag;
  op->args[3] = 0;
  TCGOP_CALLO(op) = 0;
  TCGOP_CALLI(op) = 2;
  TCGOp *op_label = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_set_label);
  op_label->args[0] = label_arg(label);
}

static uint64_t instrument_gen_call(struct InstrumentationContext *c, void *user_data)
{
  TCGArg arg;
  if (user_data)
    arg = reg_imm(c, *(uint64_t *)user_data);
  else
    arg = reg_by_num(c, 1);
  TCGOp *op = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_call);
  op->args[0] = arg;
  op->args[1] = (uintptr_t)helper_inst_slow_call;
  op->args[2] = 0;
  TCGOP_CALLO(op) = 0;
  TCGOP_CALLI(op) = 1;
  return 0;
}

static uint64_t instrument_gen_pc(struct InstrumentationContext *c, void *user_data)
{
  insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, 0), c->pc);
  return 0;
}

static uint64_t instrument_gen_tag_for(struct InstrumentationContext *c, void *user_data)
{
  uintptr_t tag_ind = (uintptr_t)user_data;
  CHECK_THAT(tag_ind < c->cur_iargs);
  TCGTemp *val = arg_temp(c->cur_inputs[tag_ind]);
  if (val->tag) {
    insert_unary_before(c, INDEX_op_mov_i64, reg_by_num(c, 0), temp_arg(val->tag));
  } else {
    insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, 0), 0);
  }
  return 0;
}

static uint64_t instrument_gen_const_for(struct InstrumentationContext *c, void *user_data)
{
  uintptr_t const_ind = (uintptr_t)user_data;
  CHECK_THAT(const_ind < c->cur_cargs);
  insert_unary_before(c, INDEX_op_movi_i64, reg_by_num(c, 0), c->cur_consts[const_ind]);
  return 0;
}

static uint64_t instrument_gen_stop_if_no_tags(struct InstrumentationContext *c, void *user_data)
{
  for (int i = 0; i < c->cur_iargs; ++i) {
    if (arg_temp(c->cur_inputs[i])->tag)
      return 0;
  }
  return ABORT_CURRENT_INSTRUMENTER;
}

static uint64_t instrument_gen_getcondres(struct InstrumentationContext *c, void *user_data)
{
  // (original-condition) ? (arg1) : (arg2)

  TCGOpcode opc = c->insertion_point->opc;
  CHECK_THAT(opc == INDEX_op_brcond_i32 || opc == INDEX_op_brcond_i64 ||
             opc == INDEX_op_setcond_i32 || opc == INDEX_op_setcond_i64 ||
             opc == INDEX_op_movcond_i32 || opc == INDEX_op_movcond_i64);

  TCGOp *op = tcg_op_insert_before(c->s, c->insertion_point, INDEX_op_setcond_i64);
  op->args[0] = reg_by_num(c, 0);
  op->args[1] = c->cur_inputs[0];
  op->args[2] = c->cur_inputs[1];
  op->args[3] = c->cur_consts[0];
  return 0;
}

CallbackDef callback_defs[] = {
  {"slow_call", NULL,      instrument_gen_call, 0},
  {"pc",        NULL,      instrument_gen_pc, 0},
  {"tag1",      (void *)0, instrument_gen_tag_for, 0},
  {"tag2",      (void *)1, instrument_gen_tag_for, 0},
  {"tag3",      (void *)2, instrument_gen_tag_for, 0},
  {"tag4",      (void *)3, instrument_gen_tag_for, 0},
  {"const1",    (void *)0, instrument_gen_const_for, 0},
  {"const2",    (void *)1, instrument_gen_const_for, 0},
  {"const3",    (void *)2, instrument_gen_const_for, 0},
  {"getcondres",(void *)0, instrument_gen_getcondres, 0},
  {"stop_if_no_tags", (void *)0, instrument_gen_stop_if_no_tags, 0},
  {NULL,        NULL,      NULL, 0}
};

static inline uint instrument_gen_branch(InstrumentationContext *c, int cur_ind)
{
  bool is_imm = !(c->inst_op.opcode & 0x08);
  int op_ind = c->inst_op.opcode >> 4;
  if (op_ind == 8) {
    // call
    CHECK_THAT((uint32_t)c->inst_op.imm < ARRAY_SIZE(callback_defs));
    CallbackDef *def = callback_defs + c->inst_op.imm;
    if (def->gen_function(c, def->user_data) & ABORT_CURRENT_INSTRUMENTER)
      return -1;
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
  int skip_insn = 0;

  for (size_t i = 0; i < c->prog->len; i += skip_insn) {
    if (c->labels[i]) {
      c->labels[i]->present = 1;
      insert_unary_before(c, INDEX_op_set_label, label_arg(c->labels[i]), 0);
    }
    c->inst_op = c->prog->data[i];
    int64_t imm64 = (uint32_t)c->inst_op.imm | (((uint64_t)c->prog->data[i + 1].imm) << 32);
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
    if (skip_insn < 0)
      break;
  }
  if (c->labels[c->prog->len]) {
    c->labels[c->prog->len]->present = 1;
    insert_unary_before(c, INDEX_op_set_label, label_arg(c->labels[c->prog->len]), 0);
  }
  if (c->cur_oargs && c->is_tagging) {
    TCGTemp *temp = arg_temp(c->cur_outputs[0]);
    if ((c->allocated_regs & 1) != 0) {
      if (!temp->tag) {
        TCGv_i64 tag = tcg_temp_local_new_i64();
        temp->tag = tcgv_i64_temp(tag);
        temp->tag->state = 0;
        temp->tag->state_ptr = NULL;
      }
      insert_unary_before(c, INDEX_op_mov_i64, temp_arg(temp->tag), tcgv_i64_arg(c->regs[0]));
    } else {
      temp->tag = NULL;
    }
  }

  c->allocated_regs = 0;
  c->allocated_words = 0;
  memset(c->labels, 0, (sizeof c->labels[0]) * (c->prog->len + 1));
}

static void preload_tag(InstrumentationContext *c, TCGTemp *temp)
{
  c->is_tagging = true;
  c->prog = inst->tagging_progs + INDEX_op_ld_i64;
  if (c->prog) {
    TCGArg addr_arg = temp_arg(temp->mem_base);
    TCGArg res_arg = temp_arg(temp);
    TCGArg off_arg = temp->mem_offset;
    fill_opc(c, INDEX_op_ld_i64);
    c->cur_outputs = &res_arg;
    c->cur_inputs = &addr_arg;
    c->cur_consts = &off_arg;
    instrument_one_insn(c);
  }
}

static void save_tag(InstrumentationContext *c, TCGTemp *temp)
{
  c->is_tagging = true;
  c->prog = inst->tagging_progs + INDEX_op_st_i64;
  if (c->prog) {
    TCGArg inputs[2] = {temp_arg(temp), temp_arg(temp->mem_base)};
    TCGArg off_arg = temp->mem_offset;
    fill_opc(c, INDEX_op_st_i64);
    c->cur_outputs = NULL;
    c->cur_inputs = inputs;
    c->cur_consts = &off_arg;
    instrument_one_insn(c);
  }
}

static void find_used_globals(InstrumentationContext *c)
{
  TCGOp *op, *op_next;
  int nb_oargs, nb_iargs;
  for (int i = 0; i < c->s->nb_globals; ++i)
    c->s->temps[i].state = 0;
  QTAILQ_FOREACH_SAFE(op, &c->s->ops, link, op_next) {
    nb_oiargs(op, &nb_oargs, &nb_iargs);
    for (int i = nb_oargs; i < nb_oargs + nb_iargs; ++i) {
      if (op->args[i] == TCG_CALL_DUMMY_ARG)
        continue;
      TCGTemp *temp = arg_temp(op->args[i]);
      if (temp->temp_global && !temp->state && !temp->fixed_reg && temp->mem_base && !temp->tag) {
        preload_tag(c, temp);
      }
    }
    if (nb_oargs != 0 && op->args[0] != TCG_CALL_DUMMY_ARG) {
      TCGTemp *temp = arg_temp(op->args[0]);
      temp->state = 1;
    }
  }
}

static void clear_state(TCGOp *op)
{
  int nb_oargs, nb_iargs;
  nb_oiargs(op, &nb_oargs, &nb_iargs);
  for (int i = 0; i < nb_oargs + nb_iargs; ++i) {
    if (op->args[i] == TCG_CALL_DUMMY_ARG)
      continue;
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
    if (op->args[i] == TCG_CALL_DUMMY_ARG)
      continue;
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
    if (op->args[i] == TCG_CALL_DUMMY_ARG)
      continue;
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
    if (op->args[i] == TCG_CALL_DUMMY_ARG)
      continue;
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

  ctx.insertion_point = s->ops.tqh_first;
  find_used_globals(&ctx); // before clearing

  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    clear_state(op);
  }

  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    TCGOpcode opc = op->opc;
    ctx.insertion_point = op;

    if (opc == INDEX_op_insn_start) {
      if (need_localize_insn && last_insn_start) 
        localize_insn_range(last_insn_start, op, &counter);
      if (inst->event_qemu_pc) {
        uint64_t res = inst->event_qemu_pc(op->args[0]);
        if (res)
          instrument_gen_call(&ctx, &res);
      }

      need_localize_insn = false;
      ctx.pc = op->args[0];
      last_insn_start = op;
    }

    if (opc == INDEX_op_goto_tb || opc == INDEX_op_goto_ptr || opc == INDEX_op_exit_tb) {
      ctx.insertion_point = op;
      for (int i = 0; i < s->nb_globals; ++i) {
        if (s->temps[i].tag)
          save_tag(&ctx, s->temps + i);
      }

      break;
    }

    if (ctx.pc) {
      fill_opc(&ctx, op->opc);
      ctx.cur_outputs = op->args;
      ctx.cur_inputs = op->args + ctx.cur_oargs;
      ctx.cur_consts = op->args + ctx.cur_oargs + ctx.cur_iargs;
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
      } else {
        for (int i = 0; i < ctx.cur_iargs; ++i) {
          if (inst->event_drop_tag && arg_temp(ctx.cur_inputs[i])->tag)
            instrument_gen_drop_tag(&ctx, arg_temp(ctx.cur_inputs[i])->tag);
        }
        for (int i = 0; i < ctx.cur_oargs; ++i) {
          if (ctx.cur_outputs[i] != TCG_CALL_DUMMY_ARG) {
            arg_temp(ctx.cur_outputs[i])->tag = NULL;
          }
        }
      }
    }
  }

  for (int i = 0; i < s->nb_globals; ++i) {
    s->temps[i].tag = NULL;
  }

  if (need_localize_insn && last_insn_start) {
    localize_insn_range(last_insn_start, NULL, &counter);
  }
  QTAILQ_FOREACH_SAFE(op, &s->ops, link, op_next) {
    localize_insn2(op);
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

const char *qemu_opcode_name(uint32_t opc)
{
  return tcg_op_defs[opc].name;
}
