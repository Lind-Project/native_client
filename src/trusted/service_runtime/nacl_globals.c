/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Server Runtime global scoped objects for handling global resources.
 */
#include <stdbool.h>
#include <stdio.h>

#include "native_client/src/shared/platform/nacl_interruptible_mutex.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/shared/platform/nacl_sync.h"
#include "native_client/src/shared/platform/nacl_sync_checked.h"
#include "native_client/src/shared/platform/nacl_threads.h"
#include "native_client/src/trusted/service_runtime/arch/sel_ldr_arch.h"
#include "native_client/src/trusted/service_runtime/nacl_app.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"

struct NaClThreadContext    *nacl_user[NACL_THREAD_MAX] = {NULL};
#if NACL_WINDOWS
uint32_t                    nacl_thread_ids[NACL_THREAD_MAX] = {0};
#endif

/*
 * Hack for gdb.  This records xlate_base in a place where (1) gdb can find it,
 * and (2) gdb doesn't need debug info (it just needs symbol info).
 */
uintptr_t                   nacl_global_xlate_base;
bool use_lkm = true;

long lind_syscall_execution_time[NACL_MAX_SYSCALLS];
int lind_syscall_invoked_times[NACL_MAX_SYSCALLS];

void add_syscall_time(int sysnum, double call_time) {
  lind_syscall_execution_time[sysnum] += call_time;
  lind_syscall_invoked_times[sysnum]++;
}

void print_execution_times(int sysnum) {
    if (lind_syscall_invoked_times[sysnum] == 0) return;
    int average_time = lind_syscall_execution_time[sysnum]/lind_syscall_invoked_times[sysnum];
    fprintf(stderr, "call number: %d, calls: %d, nsecs/call: %d \n", sysnum, lind_syscall_invoked_times[sysnum], average_time);
}

long LindGetTime_ns(void) {
  struct timespec tp;

  if( clock_gettime(CLOCK_MONOTONIC, &tp) == -1 ) {
    perror( "clock gettime" );
    exit( EXIT_FAILURE );
  }

  return (tp.tv_sec * 1000000000) + tp.tv_nsec;
}

double LindGetTime(void) {
  return ((double) LindGetTime_ns())/1000000000.0;
}

void NaClGlobalModuleInit(void) {
  NaClInitGlobals();
}

void NaClGlobalModuleFini(void) { /* no-op */ }
