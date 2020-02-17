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
#include "tcg/tcg.h"

#include "instrument.h"

#include <dlfcn.h>

static BpfInstrumentation *last_instrumentation;

void instrumentation_shutdown(void)
{
  while (last_instrumentation) {
    BpfInstrumentation *this_inst = last_instrumentation;
    last_instrumentation = last_instrumentation->next;

    if (this_inst->native_handle) {
      void (*finalize)(void) = (void (*)(void))dlsym(this_inst->native_handle, "finalize");
      if (finalize)
        finalize();
      dlclose(this_inst->native_handle);
    }
    if (this_inst->sections) {
      free(this_inst->sections);
    }
    free(this_inst);
  }
}

static void load_native_func(void **func, void *handle, const char *name)
{
  *func = dlsym(handle, name);
  if (*func) {
    INST_TRACE("Found native handler: %s\n", name);
  }
}

static void native_load(BpfInstrumentation *inst, const char *file_name)
{
  if (file_name) {
    inst->native_handle = dlopen(file_name, RTLD_NOW | RTLD_LOCAL);
    if (!inst->native_handle) {
      fprintf(stderr, "Error: %s\n", dlerror());
    }
    CHECK_THAT(inst->native_handle != NULL);

#define str(x) #x
#define LOAD(name) load_native_func((void **)&(inst->name), inst->native_handle, str(name));
    LOAD(event_dispatch_slow_call);
    LOAD(event_drop_tag);
    LOAD(event_qemu_pc);
    LOAD(event_qemu_tb);
    LOAD(event_qemu_link_tbs);
    LOAD(event_before_syscall);
    LOAD(event_after_syscall);
    LOAD(event_cpu_exec);
#undef str
#undef LOAD
  }
}

static uint8_t *bpf_map_data(const char *file_name)
{
  int bpf_fd = open(file_name, O_RDONLY);
  CHECK_THAT(bpf_fd >= 0);
  long bpf_data_size = lseek(bpf_fd, 0, SEEK_END);
  CHECK_THAT(bpf_data_size > 0);
  uint8_t *bpf_data = mmap(NULL, (size_t)bpf_data_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, bpf_fd, 0);
  CHECK_THAT(bpf_data != MAP_FAILED);
  close(bpf_fd);
  return bpf_data;
}

static Elf64_Ehdr *check_header(uint8_t *data)
{
  Elf64_Ehdr *header = (Elf64_Ehdr *)data;

  // Checking e_ident

  CHECK_THAT(header->e_ident[EI_MAG0] == 0x7F);
  CHECK_THAT(header->e_ident[EI_MAG1] == 'E');
  CHECK_THAT(header->e_ident[EI_MAG2] == 'L');
  CHECK_THAT(header->e_ident[EI_MAG3] == 'F');

  CHECK_THAT(header->e_ident[EI_CLASS] == ELFCLASS64);
#if defined(HOST_WORDS_BIGENDIAN)
  CHECK_THAT(header->e_ident[EI_DATA] == ELFDATA2MSB);
#else
  CHECK_THAT(header->e_ident[EI_DATA] == ELFDATA2LSB);
#endif

  // Checking other fields

  CHECK_THAT(header->e_type == ET_REL);
  CHECK_THAT(header->e_machine == EM_BPF);
  CHECK_THAT(header->e_version == EV_CURRENT);
  CHECK_THAT(header->e_shoff != 0);

  return header;
}

static void create_sections(BpfInstrumentation *inst, uint8_t *data)
{
  inst->sections        = calloc(inst->header->e_shnum, sizeof(uint8_t *));
  inst->section_headers = calloc(inst->header->e_shnum, sizeof(Elf64_Shdr *));
  CHECK_THAT(inst->sections != NULL);
  inst->symtab_entsize = sizeof(Elf64_Sym);

  for (int i = 0; i < inst->header->e_shnum; ++i) {
    Elf64_Shdr *section_header = (Elf64_Shdr *)(data + inst->header->e_shoff + inst->header->e_shentsize * i);
    inst->section_headers[i] = section_header;

    // Not respecting READ / WRITE permissions for now -- always rw-
    if (section_header->sh_type == SHT_NOBITS)
      inst->sections[i] = mmap(NULL, section_header->sh_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    else if (section_header->sh_type == SHT_NULL)
      inst->sections[i] = NULL;
    else
      inst->sections[i] = data + section_header->sh_offset;

    if (section_header->sh_type == SHT_SYMTAB) {
      CHECK_THAT(inst->symtab == NULL); // can we have multiple ones?
      inst->symtab = inst->sections[i];
      CHECK_THAT(section_header->sh_entsize == 0 || section_header->sh_entsize == sizeof(Elf64_Sym)); // is it correct?
      inst->symtab_count = section_header->sh_size / inst->symtab_entsize;
    }
    if (section_header->sh_type == SHT_STRTAB) {
      CHECK_THAT(inst->strtab == NULL); // can we have multiple ones?
      inst->strtab = (const char *)inst->sections[i];
    }
  }
}

static uint64_t find_symbol(BpfInstrumentation *inst, Elf64_Sym *sym)
{
  CHECK_THAT(sym->st_shndx != SHN_COMMON);
  if (sym->st_shndx == SHN_ABS) {
    return sym->st_value;
  } else if (sym->st_shndx == SHN_UNDEF) {
    const char *sym_name = inst->strtab + sym->st_name;
    for (int i = 0; callback_defs[i].name; ++i) {
      if (strcmp(sym_name, callback_defs[i].name) == 0) {
        INST_TRACE("Bound to callback: %s\n", callback_defs[i].name);
        return i;
      }
    }
    void *sym_val = dlsym(inst->native_handle, sym_name);
    INST_TRACE("Binding to native symbol %s := %p\n", sym_name, sym_val);
    CHECK_THAT(sym_val != 0);
    return (uint64_t)sym_val;
  } else {
    return (uint64_t)(inst->sections[sym->st_shndx] + sym->st_value);
  }
}

static void perform_relocation(BpfInstrumentation *inst, uint8_t *data)
{
  for (int i = 0; i < inst->header->e_shnum; ++i) {
    Elf64_Shdr *section_header = (Elf64_Shdr *)(data + inst->header->e_shoff + inst->header->e_shentsize * i);
    if (section_header->sh_type == SHT_REL) {
      for (size_t j = 0; j < section_header->sh_size / sizeof(Elf64_Rel); ++j) {
        Elf64_Rel *rel = ((Elf64_Rel *)inst->sections[i]) + j;
        uint sym_ind = ELF64_R_SYM(rel->r_info);
        Elf64_Sym sym = ((Elf64_Sym *)inst->sections[section_header->sh_link])[sym_ind];
        uint64_t symbol = find_symbol(inst, &sym);

        uint32_t *low = (uint32_t *)(inst->sections[section_header->sh_info] + rel->r_offset + 4);
        uint32_t *high = low + 2;

        if ((inst->section_headers[section_header->sh_info]->sh_flags & SHF_EXECINSTR) == 0) {
          continue;
        }

        if (ELF64_R_TYPE(rel->r_info) == R_BPF_64_64) {
          // TODO What with big endian?
          *low = (uint32_t)symbol;
          *high = (uint32_t)(symbol >> 32);
        } else {
          CHECK_THAT(ELF64_R_TYPE(rel->r_info) == R_BPF_64_32);
          CHECK_THAT((uint32_t)symbol == symbol);
          *low = (uint32_t)symbol;
        }
      }
    }
    if (section_header->sh_type == SHT_RELA) {
      CHECK_THAT(0 /* SHT_RELA not supported */);
    }
  }
}

struct instrumenter_for_qop {
  const char *name;
};

static struct instrumenter_for_qop instrumenter_for_qop_index[PROG_ARRAY_SIZE];

static void __attribute__((constructor)) constr(void)
{
#define DEF_REGULAR_32_64(qop_name, obj_name) \
  instrumenter_for_qop_index[INDEX_op_##qop_name##_i32] = (struct instrumenter_for_qop) {"inst_" stringify(obj_name)}; \
  instrumenter_for_qop_index[INDEX_op_##qop_name##_i64] = (struct instrumenter_for_qop) {"inst_" stringify(obj_name)};

  DEF_REGULAR_32_64(add, add)
  DEF_REGULAR_32_64(sub, sub)
  DEF_REGULAR_32_64(neg, neg)
  DEF_REGULAR_32_64(mul, mul)
  DEF_REGULAR_32_64(div, sdiv)
  DEF_REGULAR_32_64(divu, udiv)
  DEF_REGULAR_32_64(remu, urem)
  DEF_REGULAR_32_64(rem, srem_nonneg) // TODO select proper version
  DEF_REGULAR_32_64(and, and)
  DEF_REGULAR_32_64(or, or)
  DEF_REGULAR_32_64(xor, xor)
  DEF_REGULAR_32_64(nand, nand)
  DEF_REGULAR_32_64(nor, nor)
  DEF_REGULAR_32_64(eqv, eqv)
  DEF_REGULAR_32_64(not, not)
  DEF_REGULAR_32_64(clz, clz)
  DEF_REGULAR_32_64(ctz, ctz)
  DEF_REGULAR_32_64(shl, shl)
  DEF_REGULAR_32_64(shl, lshr)
  DEF_REGULAR_32_64(sar, ashr)
  DEF_REGULAR_32_64(setcond, cmp)

#undef DEF_REGULAR_32_64
}

static void try_load_instrumenter(bpf_prog *progs, BpfInstrumentation *inst, Elf64_Sym *sym)
{
  const char *sym_name = inst->strtab + sym->st_name;
  for (int target_opcode = 0; target_opcode < ARRAY_SIZE(instrumenter_for_qop_index); ++target_opcode) {
    const char *instrumenter_name = instrumenter_for_qop_index[target_opcode].name;
    if (instrumenter_name && strcmp(sym_name, instrumenter_name) == 0) {
      bpf_prog *prog = progs + target_opcode;

      prog->data = (ebpf_op *)(inst->sections[sym->st_shndx] + sym->st_value);
      prog->len = sym->st_size / 8;
      ebpf_op *last_op = prog->data + prog->len - 1;
      if (last_op->opcode == 0x95) // exit as the last insn
        prog->len--;
    }
  }
}

static void populate_instrumentation(BpfInstrumentation *inst)
{
  for (uint i = 0; i < inst->symtab_count; ++i) {
    Elf64_Sym *sym = (Elf64_Sym *)(inst->symtab + inst->symtab_entsize * i);
    if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;
    try_load_instrumenter(inst->progs, inst, sym);
  }
}

static void analyze_progs(BpfInstrumentation *inst)
{
  instrumenter_features_t total_features = 0;
  for (int qopc = 0; qopc < PROG_ARRAY_SIZE; ++qopc) {
    bpf_prog *prog = inst->progs + qopc;
    instrumenter_features_t features = 0;

    if (!prog->data) {
      continue;
    }

    for (int ind = 0; ind < prog->len; ++ind) {
      ebpf_op *inst_insn = prog->data + ind;
      if (inst_insn->opcode == 0x85) { // call
        features |= callback_defs[inst_insn->imm].required_features;
      } else if (inst_insn->opcode == 0x95) { // exit
        // do nothing
      } else if ((inst_insn->opcode & 0x07) == 0x05) { // generic branch
        features |= REQUIRES_LOCALIZATION;
        CHECK_THAT(inst_insn->offset >= 0);
        CHECK_THAT(ind + 1 + inst_insn->offset <= prog->len);
      }
    }
    prog->required_features = features;
    total_features |= features;

    INST_TRACE("Found instrumenter for %s, %ld insns%s%s\n",
            tcg_op_defs[qopc].name, prog->len,
            (features & REQUIRES_LOCALIZATION) ? ", requires localization" : "",
            (features & CAN_SET_TAG) ? ", can set tags" : "");
    CHECK_THAT(prog->len < MAX_OPS_PER_BPF_FUNCTION);
    if ((features & CAN_SET_TAG) && tcg_op_defs[qopc].nb_oargs == 0) {
      fprintf(stderr, "Error: instrumenter for void %s requests setting tags.\n", tcg_op_defs[qopc].name);
      exit(1);
    }
  }
  inst->needs_tags = !!(total_features & CAN_SET_TAG);
  if (!inst->needs_tags) {
    INST_TRACE("%s\n", "Tags are not used, disabling.");
  }
}

static void bpf_load(BpfInstrumentation *inst, const char *bpf_inst)
{
  uint8_t *bpf_data = bpf_map_data(bpf_inst);
  inst->header = check_header(bpf_data);
  create_sections(inst, bpf_data);
  perform_relocation(inst, bpf_data);
  populate_instrumentation(inst);
  analyze_progs(inst);
}

BpfInstrumentation *instrumentation_load(void)
{
  const char *native_inst = getenv("NATIVE_INST");
  const char *bpf_inst = getenv("BPF_INST");

  if (!native_inst && !bpf_inst)
    return NULL;

  atexit(instrumentation_shutdown);

  BpfInstrumentation *inst = (BpfInstrumentation *)calloc(sizeof(BpfInstrumentation), 1);
  if (native_inst) {
    native_load(inst, native_inst);
  }
  if (bpf_inst) {
    bpf_load(inst, bpf_inst);
  }
  void (*initialize)(void) = dlsym(inst->native_handle, "initialize");
  if (initialize)
    initialize();

  inst->next = last_instrumentation;
  last_instrumentation = inst;

  return inst;
}
