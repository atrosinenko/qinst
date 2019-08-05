#ifndef FUZZER_UTILS_H
#define FUZZER_UTILS_H

#include <syscall.h>
#include <string.h>

static uint64_t handle_before_syscall(uint32_t num, uint32_t *drop_syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
  // Do not crash parent due to dynamically loading iconv plugins in the child
  if (num == SYS_openat && strstr((const char *)arg2, "linux-gnu/gconv/gconv-modules")) {
    *drop_syscall = 1;
    return ENOENT;
  }

  // Extended variant of watching for "dangerous" syscalls suggested on the AFL's mail list...

  // Forcefully trigger crash when trying to write to the filesystem.
  // This most probably signifies some security issue.
  //
  // When it can be disabled via some setting, this most probably
  // should be disabled, otherwise it can clutter the entire system
  // like with the command 'w' in sed.
  if (num == SYS_openat && (arg3 & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT)) != 0) {
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

#endif // FUZZERUTILS_H
