/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl service run-time.
 */

#include "native_client/src/include/portability.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "native_client/src/include/nacl_compiler_annotations.h"
#include "native_client/src/shared/platform/nacl_exit.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
#include "native_client/src/trusted/service_runtime/nacl_copy.h"
#include "native_client/src/trusted/service_runtime/nacl_switch_to_app.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_handlers.h"
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/sel_rt.h"

#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_stack_safety.h"



/*
 * HandleStackContext() fetches some of the inputs to the NaCl syscall
 * from the untrusted stack.  It updates NaClThreadContext so that the
 * saved state will be complete in case this state is read via the
 * thread suspension API.
 *
 * This is called while natp->suspend_state is set to
 * NACL_APP_THREAD_UNTRUSTED, which has two consequences:
 *
 *  1) We may read untrusted address space without calling
 *     NaClCopyTakeLock() first, because this function's execution
 *     will be suspended while any mmap hole is opened up on Windows.
 *
 *  2) We may not claim any locks.  This means we may not call
 *     NaClLog().  (An exception is that LOG_FATAL calls to NaClLog()
 *     should be okay for internal errors.)
 */
static void HandleStackContext(struct NaClAppThread *natp,
                               uint32_t             *tramp_ret_out,
                               uintptr_t            *sp_user_out) {
  struct NaClApp *nap = natp->nap;
  uintptr_t      sp_user;
  uintptr_t      sp_sys;
  uint32_t       tramp_ret;
  nacl_reg_t     user_ret;

  /*
   * sp_sys points to the top of the user stack where return addresses
   * and syscall arguments are stored.
   *
   * Note that on x86-64, NaClUserToSysStackAddr() and
   * NaClSysToUserStackAddr() do no range check.  sp_user must be okay
   * for control to have reached here, because nacl_syscall*.S writes
   * to the stack.
   */
  sp_user = NaClGetThreadCtxSp(&natp->user);
  sp_sys = NaClUserToSysStackAddr(nap, sp_user);
  /*
   * Get the trampoline return address.  This just tells us which
   * trampoline was called (and hence the syscall number); we never
   * return to the trampoline.
   */
  tramp_ret = *(volatile uint32_t *) (sp_sys + NACL_TRAMPRET_FIX);
  /*
   * Get the user return address (where we return to after the system
   * call).  We must ensure the address is properly sandboxed before
   * switching back to untrusted code.
   */
  user_ret = *(volatile uintptr_t *) (sp_sys + NACL_USERRET_FIX);
  user_ret = (nacl_reg_t) NaClSandboxCodeAddr(nap, (uintptr_t) user_ret);
  natp->user.new_prog_ctr = user_ret;

  *tramp_ret_out = tramp_ret;
  *sp_user_out = sp_user;
}

#define MAX_ARGS 6
typedef enum {
    ARG_NOARG,
    ARG_INT,
    ARG_CHAR_P,
    // Add other types as needed
} ArgType;

typedef struct {
    bool isValid;
    int nArgs;
    ArgType types[MAX_ARGS];
} SyscallArgTypesEntry;

NORETURN void NaClSyscallCSegHook(struct NaClThreadContext *ntcp) {
  struct NaClAppThread      *natp = NaClAppThreadFromThreadContext(ntcp);
  struct NaClApp            *nap;
  uint32_t                  tramp_ret;
  size_t                    sysnum;
  uintptr_t                 sp_user;
  uint32_t                  sysret;

  /*
   * Mark the thread as running on a trusted stack as soon as possible
   * so that we can report any crashes that occur after this point.
   */
  NaClStackSafetyNowOnTrustedStack();

  HandleStackContext(natp, &tramp_ret, &sp_user);

  /*
   * Before this call, the thread could be suspended, so we should not
   * lock any mutexes before this, otherwise it could cause a
   * deadlock.
   */
  NaClAppThreadSetSuspendState(natp, NACL_APP_THREAD_UNTRUSTED,
                               NACL_APP_THREAD_TRUSTED);

  nap = natp->nap;

  /*
   * held until syscall args are copied, which occurs in the generated
   * code.
   */

  sysnum = (tramp_ret - NACL_SYSCALL_START_ADDR) >> NACL_SYSCALL_BLOCK_SHIFT;

  NaClLog(4, "Entering syscall %"NACL_PRIuS
          ": return address 0x%08"NACL_PRIxNACL_REG"\n",
          sysnum, natp->user.new_prog_ctr);

//#ifdef TRACE
const char *syscall_names[] = {
    [1] = "null",
    [2] = "nameservice",
    [4] = "unlink",
    [5] = "link",
    [6] = "rename",
    [8] = "dup",
    [9] = "dup2",
    [10] = "dup3",
    [11] = "open",
    [12] = "close",
    [13] = "read",
    [14] = "write",
    [15] = "lseek",
    [16] = "ioctl",
    [17] = "stat",
    [18] = "fstat",
    [19] = "chmod",
    [20] = "brk",
    [21] = "mmap",
    [22] = "munmap",
    [23] = "getdents",
    [24] = "mprotect",
    [25] = "list_mappings",
    [26] = "truncate",
    [27] = "ftruncate",
    [30] = "exit",
    [31] = "getpid",
    [32] = "sched_yield",
    [33] = "sysconf",
    [34] = "send",
    [35] = "sendto",
    [36] = "recv",
    [37] = "recvfrom",
    [40] = "gettimeofday",
    [41] = "clock",
    [42] = "nanosleep",
    [43] = "clock_getres",
    [44] = "clock_gettime",
    [45] = "shutdown",
    [46] = "select",
    [47] = "getcwd",
    [48] = "poll",
    [49] = "socketpair",
    [50] = "getuid",
    [51] = "geteuid",
    [52] = "getgid",
    [53] = "getegid",
    [54] = "flock",
    [56] = "shmget",
    [57] = "shmat",
    [58] = "shmdt",
    [59] = "shmctl",
    [60] = "imc_makeboundsock",
    [61] = "imc_accept",
    [62] = "imc_connect",
    [63] = "imc_sendmsg",
    [64] = "imc_recvmsg",
    [65] = "imc_mem_obj_create",
    [66] = "imc_socketpair",
    [69] = "mutex_destroy",
    [70] = "mutex_create",
    [71] = "mutex_lock",
    [72] = "mutex_trylock",
    [73] = "mutex_unlock",
    [74] = "cond_create",
    [75] = "cond_wait",
    [76] = "cond_signal",
    [77] = "cond_broadcast",
    [78] = "cond_destroy",
    [79] = "cond_timed_wait_abs",
    [80] = "thread_create",
    [81] = "thread_exit",
    [82] = "tls_init",
    [83] = "thread_nice",
    [84] = "tls_get",
    [85] = "second_tls_set",
    [86] = "second_tls_get",
    [87] = "exception_handler",
    [88] = "exception_stack",
    [89] = "exception_clear_flag",
    [100] = "sem_create",
    [101] = "sem_wait",
    [102] = "sem_post",
    [103] = "sem_get_value",
    [104] = "dyncode_create",
    [105] = "dyncode_modify",
    [106] = "dyncode_delete",
    [109] = "test_infoleak",
    [110] = "test_crash",
    [111] = "test_syscall_1",
    [112] = "test_syscall_2",
    [114] = "pipe",
    [115] = "pipe2",
    [116] = "fork",
    [117] = "execv",
    [118] = "execve",
    [119] = "getppid",
    [120] = "waitpid",
    [121] = "wait",
    [122] = "wait4",
    [123] = "sigprocmask",
    [124] = "lstat",
    [125] = "gethostname",
    [126] = "pread",
    [127] = "pwrite",
    [128] = "fcntl_get",
    [129] = "fcntl_set",
    [130] = "chdir",
    [131] = "mkdir",
    [132] = "rmdir",
    [133] = "statfs",
    [134] = "fstatfs",
    [135] = "fchmod",
    [136] = "socket",
    [137] = "getsockopt",
    [138] = "setsockopt",
    [139] = "access",
    [140] = "accept",
    [141] = "connect",
    [142] = "bind",
    [143] = "listen",
    [144] = "getsockname",
    [145] = "getpeername",
    [146] = "getifaddrs",
    [157] = "epoll_create",
    [158] = "epoll_ctl",
    [159] = "epoll_wait",
    [161] = "fchdir",
};

//#endif
//#ifdef TRACE
  // the first condition below is checking that the given sysnum is within the number of elements inside syscall_names array
  char* syscall_name = NULL;
  if (sysnum < sizeof(syscall_names)/sizeof(syscall_names[0]) && syscall_names[sysnum] != NULL) {
    syscall_name = syscall_names[sysnum];
  } else {
    printf("Fatal: Calling an sysnum that doesn't exist: %zu\n", sysnum);
    exit(-1);
  }
//#endif

  /*
   * usr_syscall_args is used by Decoder functions in
   * nacl_syscall_handlers.c which is automatically generated file and
   * placed in the
   * scons-out/.../gen/native_client/src/trusted/service_runtime/
   * directory.  usr_syscall_args must point to the first argument of
   * a system call. System call arguments are placed on the untrusted
   * user stack.
   *
   * We save the user address for user syscall arguments fetching and
   * for VM range locking.
   */
  natp->usr_syscall_args = NaClRawUserStackAddrNormalize(sp_user +
                                                         NACL_SYSARGS_FIX);

  
  // parse and output the arguments
  const SyscallArgTypesEntry syscallArgTypes[] = {
    [NACL_sys_open] = {.isValid = true, .nArgs = 2, .types = {ARG_CHAR_P, ARG_INT, ARG_NOARG, ARG_NOARG, ARG_NOARG, ARG_NOARG}},
  };
  
  uintptr_t nextArgPtr = natp->usr_syscall_args;
  if (sysnum < sizeof(syscallArgTypes)/sizeof(syscallArgTypes[0]) && syscallArgTypes[sysnum].isValid) {
    for(int i = 0; i < MAX_ARGS; i++) {
      switch (syscallArgTypes[sysnum].types[i]) {
        case ARG_INT:
          printf("%d, ", *(int*)nextArgPtr);
          nextArgPtr += sizeof(int);
          break;
        case ARG_CHAR_P:
          printf("%s, ", *(char**)nextArgPtr);
          nextArgPtr += sizeof(char*);
          break;
        case ARG_NOARG:
          break;
      }
    }
    printf("\n");
  }

  if (NACL_UNLIKELY(sysnum >= NACL_MAX_SYSCALLS)) {
    NaClLog(2, "INVALID system call %"NACL_PRIdS"\n", sysnum);
    sysret = -NACL_ABI_EINVAL;
  } else {
    sysret = (*(nap->syscall_table[sysnum].handler))(natp);
    /* Implicitly drops lock */
  }
  NaClLog(4,
          ("Returning from syscall %"NACL_PRIdS": return value %"NACL_PRId32
           " (0x%"NACL_PRIx32")\n"),
          sysnum, sysret, sysret);
  natp->user.sysret = sysret;

  /*
   * After this NaClAppThreadSetSuspendState() call, we should not
   * claim any mutexes, otherwise we risk deadlock.  Note that if
   * NACLVERBOSITY is set high enough to enable the NaClLog() calls in
   * NaClSwitchToApp(), these calls could deadlock.
   */
  
  NaClAppThreadSetSuspendState(natp, NACL_APP_THREAD_TRUSTED,
                               NACL_APP_THREAD_UNTRUSTED);
  NaClStackSafetyNowOnUntrustedStack();

  NaClSwitchToApp(natp);
  /* NOTREACHED */

  fprintf(stderr, "NORETURN NaClSwitchToApp returned!?!\n");
  NaClAbort();
}
