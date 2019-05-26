/* Most of this file is copied from the AFL's qemu_mode sources covered by Apache 2.0 license */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syscall.h>
#include <string.h>


#define MAP_SIZE 65536
uint8_t start_buf[MAP_SIZE];
uint8_t *__afl_area_ptr = start_buf;
uint64_t prev;

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD          198
#define TSL_FD              197
static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;


#define CPUState void
#define target_ulong uint64_t
#define TranslationBlock void

static void afl_wait_tsl(int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

void *get_current_cpu(void);
void rcu_disable_atfork(void);
void pretranslate_block(CPUState *cpu, uint64_t pc, uint64_t cs_base, uint32_t flags);

void __attribute__((constructor)) constr(void)
{
  rcu_disable_atfork();
}


__thread CPUState *current_cpu;
void ensure_current_cpu_initialized(void) {
  if (__builtin_expect(!current_cpu, 0))
    current_cpu = get_current_cpu();
}

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint32_t flags;
};

static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  int shm_id;

  rcu_disable_atfork();

  if (id_str) {

    shm_id = atoi(id_str);
    __afl_area_ptr = shmat(shm_id, NULL, 0);

    if (__afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    /*if (inst_r)*/ __afl_area_ptr[0] = 1;


  }

}

/* Fork server logic, invoked once we hit _start. */

void afl_forkserver() {

  static unsigned char tmp[4];


  if (!__afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

     if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
     close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }
    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

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
    pretranslate_block(cpu, t.pc, t.cs_base, t.flags);
  }
  close(fd);

}

void init_once(void)
{
  if (afl_fork_child) return;

  afl_setup();
  afl_forkserver();
}

void event_qemu_tb(uint64_t pc, uint64_t cs_base, uint32_t flags)
{
  afl_request_tsl(pc, cs_base, flags);
}

void event_cpu_exec(uint32_t is_entry)
{
  if (is_entry)
    init_once();
}
