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
#include <errno.h>


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
static void afl_request_tsl(target_ulong, uint32_t, target_ulong, target_ulong, uint32_t, uint32_t);

void *get_current_cpu(void);
void rcu_disable_atfork(void);
void prelink_blocks(CPUState *cpu, uint64_t from_pc, uint32_t tb_exit, uint64_t pc, uint64_t cs_base, uint32_t flags, uint32_t cf_mask);
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
  target_ulong from_pc;
  uint32_t tb_exit;
  target_ulong pc;
  target_ulong cs_base;
  uint32_t flags;
  uint32_t cf_mask;
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

    if (read(FORKSRV_FD, tmp, 4) <= 0) exit(2);

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

static void afl_request_tsl(target_ulong from_pc, uint32_t tb_exit, target_ulong pc, target_ulong cb, uint32_t flags, uint32_t cf_mask) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

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

void init_once(void)
{
  if (afl_fork_child) return;
  fprintf(stderr, "==> AFL: INIT <==\n");

  afl_setup();
  afl_forkserver();
}

uint64_t event_before_syscall(uint32_t num, uint32_t *drop_syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8)
{
  // Init forkserver when reading from stdin
  if ((num == SYS_read && arg1 == 0)) {
    init_once();
  }
  // ... or trying to interact with it
  if (num == SYS_openat && strcmp((const char *)arg2, "/dev/stdin") == 0) {
    init_once();
  }
  if (num == SYS_stat   && strcmp((const char *)arg1, "/dev/stdin") == 0) {
    init_once();
  }

  // Do not crash parent due to dynamically loading iconv plugins in the child
  if (num == SYS_openat && strstr((const char *)arg2, "linux-gnu/gconv/gconv-modules")) {
    *drop_syscall = 1;
    return ENOENT;
  }

  // Forcefully trigger crash when trying to write to the filesystem.
  // This most probably signifies some security issue.
  //
  // When it can be disabled via some setting, this most probably
  // should be disabled, otherwise it can clutter the entire system
  // like with the command 'w' in sed.
  if ((num == SYS_openat && (arg3 & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT)) != 0))
  {
    abort();
  }

  // Forcefully trigger crash in **parent** when invoking execve.
  // This is probably invoked from the forkserver's grand-child
  // after fork in a child process when spawning some process.
  // Disable this for the same reasons as the above.
  if (num == SYS_execve) {
    kill(getppid(), SIGABRT);
  }
  return 0;
}

void event_qemu_tb(uint64_t pc, uint64_t cs_base, uint32_t flags)
{
  afl_request_tsl(0, 0, pc, cs_base, flags, 0);
}

void event_qemu_link_tbs(uint64_t from_pc, uint32_t tb_exit, uint64_t pc, uint64_t cs_base, uint32_t flags, uint32_t cf_mask)
{
  afl_request_tsl(from_pc, tb_exit, pc, cs_base, flags, cf_mask);
}

void event_cpu_exec(uint32_t is_entry)
{
}
