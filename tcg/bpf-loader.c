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

static void native_load(BpfInstrumentation *inst, const char *file_name)
{
  if (file_name) {
    inst->native_handle = dlopen(file_name, RTLD_NOW | RTLD_LOCAL);
    CHECK_THAT(inst->native_handle != NULL);
    inst->event_qemu_tb = dlsym(inst->native_handle, "event_qemu_tb");
    inst->event_before_syscall = dlsym(inst->native_handle, "event_before_syscall");
    inst->event_after_syscall = dlsym(inst->native_handle, "event_after_syscall");
    inst->event_cpu_exec = dlsym(inst->native_handle, "event_cpu_exec");
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
  inst->sections = calloc(inst->header->e_shnum, sizeof(uint8_t *));
  CHECK_THAT(inst->sections != NULL);
  inst->symtab_entsize = sizeof(Elf64_Sym);

  for (int i = 0; i < inst->header->e_shnum; ++i) {
    Elf64_Shdr *section_header = (Elf64_Shdr *)(data + inst->header->e_shoff + inst->header->e_shentsize * i);

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
    void *sym_val = dlsym(inst->native_handle, sym_name);
    fprintf(stderr, "Binding to native symbol %s := %p\n", sym_name, sym_val);
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
        CHECK_THAT(ELF64_R_TYPE(rel->r_info) == R_BPF_64_64);
        uint sym_ind = ELF64_R_SYM(rel->r_info);
        Elf64_Sym sym = ((Elf64_Sym *)inst->sections[section_header->sh_link])[sym_ind];
        uint64_t symbol = find_symbol(inst, &sym);

        // TODO What with big endian?
        uint32_t *low = (uint32_t *)(inst->sections[section_header->sh_info] + rel->r_offset + 4);
        uint32_t *high = low + 2;
        uint64_t val = symbol + ((((uint64_t)*high) << 32) | *low);
        *low = (uint32_t)val;
        *high = (uint32_t)(val >> 32);
      }
    }
    if (section_header->sh_type == SHT_RELA) {
      CHECK_THAT(0 /* SHT_RELA not supported */);
    }
  }
}

static const char *inst_function_names[] = {
#define DEF(name, a, b, c, d) stringify(inst_qemu_##name),
#include "tcg-opc.h"
#undef DEF
  NULL
};

static int opcode_for_name(const char **name_table, const char *name)
{
  for (int i = 0; name_table[i]; ++i) {
    if (strcmp(name, name_table[i]) == 0)
      return i;
  }
  return -1;
}

static void try_load_instrumenter(
    const char *title, bpf_prog *progs, const char **name_table,
    BpfInstrumentation *inst, Elf64_Sym *sym)
{
  const char *sym_name = inst->strtab + sym->st_name;
  int target_opcode = opcode_for_name(name_table, sym_name);
  if (target_opcode != -1) {
    bpf_prog *prog = progs + target_opcode;
    TCGOpDef *def = tcg_op_defs + target_opcode;

    prog->data = (ebpf_op *)(inst->sections[sym->st_shndx] + sym->st_value);
    prog->len = sym->st_size / 8;
    ebpf_op *last_op = prog->data + prog->len - 1;
    if (last_op->opcode == 0x95) // exit as the last insn
      prog->len--;
    fprintf(stderr, "[%s] Found instrumenter \"%s\", %ld insns [oargs = %d iargs = %d cargs = %d]\n",
            title, sym_name, prog->len,
            def->nb_oargs, def->nb_iargs, def->nb_cargs);
    CHECK_THAT(prog->len < MAX_OPS_PER_BPF_FUNCTION);
  }
}

static void populate_instrumentation(BpfInstrumentation *inst)
{
  for (uint i = 0; i < inst->symtab_count; ++i) {
    Elf64_Sym *sym = (Elf64_Sym *)(inst->symtab + inst->symtab_entsize * i);
    if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;
    try_load_instrumenter("tracing", inst->tracing_progs, inst_function_names, inst, sym);
  }
}

static void bpf_load(BpfInstrumentation *inst, const char *bpf_inst)
{
  uint8_t *bpf_data = bpf_map_data(bpf_inst);
  inst->header = check_header(bpf_data);
  create_sections(inst, bpf_data);
  perform_relocation(inst, bpf_data);
  populate_instrumentation(inst);
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
