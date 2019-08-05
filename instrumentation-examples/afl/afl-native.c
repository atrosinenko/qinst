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

#include "../common/forksrv-utils.h"
#include "../common/fuzzer-utils.h"

// Based on the official QEMU patch from AFL (Apache 2.0 license)

#define MAP_SIZE 65536
uint8_t start_buf[MAP_SIZE];
uint8_t *__afl_area_ptr = start_buf;

#define SHM_ENV_VAR "__AFL_SHM_ID"
#define FORKSRV_FD          198
unsigned int afl_forksrv_pid;


static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  int shm_id;

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
    int status;

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) <= 0) exit(2);

    CREATE_PER_FORK_TSL_CHANNEL

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      CHILD_HANDLE_TSL

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      return;

    }
    /* Parent. */


    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    PARENT_PROCESS_TSL

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);
  }

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

  return handle_before_syscall(num, drop_syscall, arg1, arg2, arg3);
}

DEFAULT_TRANSLATION_HOOK
