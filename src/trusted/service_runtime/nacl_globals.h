/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Server Runtime globals.
 */

// yiwen: enable system call timing with SYSCALL_TIMING
// #define SYSCALL_TIMING

// yiwen: enable printing out debug info inside functions in NaCl runtime
#ifdef _DEBUG
# define DEBUG_INFO_ENABLED
#endif

// yiwen: enable printing out system call tracing info for NaCl irt calls
// #define NACL_SYSCALL_TRACE_ENABLED


#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_NACL_GLOBALS_H__
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_NACL_GLOBALS_H__

#include "native_client/src/include/portability.h"
#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/trusted/service_runtime/arch/sel_ldr_arch.h"
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
#include "native_client/src/shared/platform/lind_platform.h"

/* jp */
EXTERN_C_BEGIN
/* snprintf length limit for each argv string */
#define ARG_LIMIT (1u << 12)
#define SHM_SIZE (1u << 13)
#define PROT_RW (NACL_ABI_PROT_READ|NACL_ABI_PROT_WRITE)
#define PROT_RX (NACL_ABI_PROT_READ|NACL_ABI_PROT_EXEC)
#define F_ANON_PRIV (NACL_ABI_MAP_PRIVATE|NACL_ABI_MAP_ANONYMOUS)
#ifndef SIZE_T_MAX
# define SIZE_T_MAX (~(size_t)0)
#endif
#define LD_FILE "/lib/glibc/runnable-ld.so"
#define UNTRUSTED_ADDR_MASK 0xffffffffu

/* extract uint64_t object representation */
#define OBJ_REP_64(X) (((uint64_t)(X)[0] << (0 * CHAR_BIT))	\
                     | ((uint64_t)(X)[1] << (1 * CHAR_BIT))	\
                     | ((uint64_t)(X)[2] << (2 * CHAR_BIT))	\
                     | ((uint64_t)(X)[3] << (3 * CHAR_BIT))	\
                     | ((uint64_t)(X)[4] << (4 * CHAR_BIT))	\
                     | ((uint64_t)(X)[5] << (5 * CHAR_BIT))	\
                     | ((uint64_t)(X)[6] << (6 * CHAR_BIT))	\
                     | ((uint64_t)(X)[7] << (7 * CHAR_BIT)))

enum {
        PIPE_NUM_MAX = 1u << 4,
        CACHED_LIB_NUM_MAX = 1u << 5,
        CAGING_LIB_PATH_MAX = 1u << 6,
        FILE_DESC_MAX = 1u << 8,
        CHILD_NUM_MAX = 1u << 8,
        CAGING_FD_NUM  = 1u << 8,
        PIPE_BUF_MAX = 1u << 16
};

// yiwen: define struct for storing the <file_path, mem_addr> relation
//        which is being used by our "shared libs caching" mechanism
struct CachedLibTable {
  char path[CAGING_LIB_PATH_MAX];
  void *mem_addr;
};

struct NaClThreadContext;
struct NaClAppThread;
struct NaClMutex;
struct NaClApp;

/*
 * always points at original program context
 */
extern struct NaClThreadContext *master_ctx;

extern int nacl_syscall_counter;
extern int nacl_syscall_invoked_times[NACL_MAX_SYSCALLS];
extern int nacl_syscall_trace_level_counter;
extern double nacl_syscall_execution_time[NACL_MAX_SYSCALLS];
extern int lind_syscall_counter;
extern int lind_syscall_invoked_times[LIND_MAX_SYSCALLS];
extern double lind_syscall_execution_time[LIND_MAX_SYSCALLS];

// yiwen
extern int cage;
extern double time_counter;
extern double time_start;
extern double time_end;

// yiwen: this is the lookup table used, when checking if a lib has already been loaded previously,
//        and will contain the shared memory address for the lib if it has been loaded before.
extern struct CachedLibTable cached_lib_table[CACHED_LIB_NUM_MAX];
extern int cached_lib_num;

// yiwen: global pipe buffer
extern char pipe_buffer[PIPE_NUM_MAX][PIPE_BUF_MAX];
extern int pipe_mutex[PIPE_NUM_MAX];
extern int pipe_transfer_over[PIPE_NUM_MAX];

#if NACL_WINDOWS
__declspec(dllexport)
/*
 * This array is exported so that it can be used by a debugger.  However, it is
 * not a stable interface and it may change or be removed in the future.  A
 * debugger using this interface could break.
 */
#endif
extern struct NaClThreadContext *nacl_user[NACL_THREAD_MAX];
#if NACL_WINDOWS
/*
 * NaCl Idx -> Thread ID mapping. Gdb scans this array to find NaCl index
 * by Thread ID.
 *
 * This is not a stable interface and it may change or be removed in
 * the future.  A debugger using this interface could break.
 */
__declspec(dllexport) extern uint32_t nacl_thread_ids[NACL_THREAD_MAX];
#endif
/*
 * nacl_user is accessed without holding any locks.  once a thread is
 * live, only that thread itself may read/write the register context
 * contents (based on its %gs), and this allows a thread to context
 * switch from the application to the runtime, since we must have a
 * secure stack before calling any code, including lock acquisition
 * code.
 */

void  NaClGlobalModuleInit(void);
void  NaClGlobalModuleFini(void);

/* this is defined in src/trusted/service_runtime/arch/<arch>/ sel_rt.h */
void NaClInitGlobals(void);

static INLINE void NaClPatchAddr(uintptr_t child_bits, uintptr_t parent_bits, uintptr_t *start, size_t cnt) {
  for (size_t i = 0; i < cnt; i++) {
    if ((parent_bits >> NACL_PAGESHIFT) != (start[i] >> NACL_PAGESHIFT))
      continue;
    NaClLog(1, "patching %p\n", (void *)start[i]);
    start[i] = child_bits | (start[i] & UNTRUSTED_ADDR_MASK);
    NaClLog(1, "new addr %p\n", (void *)start[i]);
  }
}

static INLINE struct NaClAppThread *NaClAppThreadGetFromIndex(uint32_t thread_index) {
  DCHECK(thread_index < NACL_THREAD_MAX);
  return NaClAppThreadFromThreadContext(nacl_user[thread_index]);
}

/* hack for gdb */
#if NACL_WINDOWS
__declspec(dllexport)
#endif
extern uintptr_t nacl_global_xlate_base;

EXTERN_C_END

#endif  /* NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_NACL_GLOBALS_H__ */
