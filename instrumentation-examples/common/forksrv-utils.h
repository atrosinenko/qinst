#ifndef FORKSRV_UTILS_H
#define FORKSRV_UTILS_H

#include "base.h"

// Based on the official QEMU patch from AFL (Apache 2.0 license) and some unoficial ones

#define TSL_FD              197

static unsigned char afl_fork_child_pid;

#define CPUState void
#define target_ulong uint64_t

static void afl_wait_tsl(int);
static void afl_request_tsl(target_ulong, uint32_t, target_ulong, target_ulong, uint32_t, uint32_t);

void *get_current_cpu(void);
void prelink_blocks(CPUState *cpu, uint64_t from_pc, uint32_t tb_exit, uint64_t pc, uint64_t cs_base, uint32_t flags, uint32_t cf_mask);
void pretranslate_block(CPUState *cpu, uint64_t pc, uint64_t cs_base, uint32_t flags);

__thread CPUState *current_cpu;
void ensure_current_cpu_initialized(void) {
  if (__builtin_expect(!current_cpu, 0))
    current_cpu = get_current_cpu();
}

#define MAX_EXTRA_EXEC 2048
static uint64_t extra_exec_start[MAX_EXTRA_EXEC];
static uint64_t extra_exec_end[MAX_EXTRA_EXEC];
static int extra_exec_count;

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong from_pc;
  uint32_t tb_exit;
  target_ulong pc;
  target_ulong cs_base;
  uint32_t flags;
  uint32_t cf_mask;
};


static void afl_request_tsl(target_ulong from_pc, uint32_t tb_exit, target_ulong pc, target_ulong cb, uint32_t flags, uint32_t cf_mask) {

  struct afl_tsl t;
  memset(&t, 0, sizeof(t));

  if (!afl_fork_child_pid) return;
  if (extra_exec_count >= MAX_EXTRA_EXEC) return;
  for (int i = 0; i < extra_exec_count; ++i) {
    if (extra_exec_start[i] <= pc && pc < extra_exec_end[i])
      return;
  }

  t.from_pc = from_pc;
  t.tb_exit = tb_exit;
  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;
  t.cf_mask = cf_mask;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

static void afl_wait_tsl(int fd) {
  struct afl_tsl t;

  while (1) {
    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;
    ensure_current_cpu_initialized();
    void *cpu = current_cpu;
    if (t.from_pc)
      prelink_blocks(cpu, t.from_pc, t.tb_exit, t.pc, t.cs_base, t.flags, t.cf_mask);
    else
      pretranslate_block(cpu, t.pc, t.cs_base, t.flags);
  }
  close(fd);

}

static void handle_mmap(uint64_t addr, uint64_t size, int prot)
{
  if (afl_fork_child_pid && (prot & PROT_EXEC) && extra_exec_count < MAX_EXTRA_EXEC) {
    extra_exec_start[extra_exec_count] = addr;
    extra_exec_end[extra_exec_count] = addr + size;
    fprintf(stderr, "Blacklisting %lx - %lx\n", extra_exec_start[extra_exec_count], extra_exec_end[extra_exec_count]);
    extra_exec_count += 1;
  }
}

/* Establish a channel with child to grab translation commands. We'll
   read from t_fd[0], child will write to TSL_FD. */
#define CREATE_PER_FORK_TSL_CHANNEL \
    int t_fd[2]; \
    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3); \
    close(t_fd[1]);

#define CHILD_HANDLE_TSL \
    afl_fork_child_pid = getpid(); \
    close(t_fd[0]);

/* Collect translation requests until child dies and closes the pipe. */
#define PARENT_PROCESS_TSL \
    close(TSL_FD); \
    afl_wait_tsl(t_fd[0]);

#define DEFAULT_TRANSLATION_HOOK \
    void event_qemu_tb(uint64_t pc, uint64_t cs_base, uint32_t flags) \
    { \
      afl_request_tsl(0, 0, pc, cs_base, flags, 0); \
    } \
    void event_qemu_link_tbs(uint64_t from_pc, uint32_t tb_exit, uint64_t pc, uint64_t cs_base, uint32_t flags, uint32_t cf_mask) \
    { \
      afl_request_tsl(from_pc, tb_exit, pc, cs_base, flags, cf_mask); \
    } \
    void event_after_syscall(int num, uint64_t ret, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8) \
    { \
      if (num == SYS_mmap) handle_mmap(ret, arg2, (int)arg3); \
    }

#endif
