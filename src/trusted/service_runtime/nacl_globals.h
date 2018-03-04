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
// #define DEBUG_INFO_ENABLED

// yiwen: enable printing out system call tracing info for NaCl irt calls
// #define NACL_SYSCALL_TRACE_ENABLED


#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_NACL_GLOBALS_H__
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_NACL_GLOBALS_H__

#include "native_client/src/include/portability.h"
#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/trusted/service_runtime/arch/sel_ldr_arch.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"

// yiwen
#define CAGING_LIB_PATH_MAX 50 
#define CACHED_LIB_NUM_MAX 20

// yiwen: define struct for storing the <file_path, mem_addr> relation 
//        which is being used by our "shared libs caching" mechanism 
struct CachedLibTable {
  char path[CAGING_LIB_PATH_MAX];
  void *mem_addr; 
}; 

EXTERN_C_BEGIN
struct NaClThreadContext;
struct NaClAppThread;
struct NaClMutex;
struct NaClApp;

// yiwen
extern int cage;
extern int fork_num;
extern int fd_cage_table[2000][2000];
extern struct NaClApp state_ready;
extern struct NaClApp *nap_ready;
extern struct NaClApp state_ready_2;
extern struct NaClApp *nap_ready_2;

extern struct NaClApp state0;
extern struct NaClApp *nap0;
extern struct NaClApp state0_2;
extern struct NaClApp *nap0_2;

extern double time_counter;
extern double time_start;
extern double time_end;

// yiwen: this is the lookup table used, when checking if a lib has already been loaded previously, 
//        and will contain the shared memory address for the lib if it has been loaded before. 
extern struct CachedLibTable cached_lib_table[CACHED_LIB_NUM_MAX];
extern int cached_lib_num;

// yiwen: global pipe buffer
extern char pipe_buffer[16*4096];
extern char* buffer_ptr;
extern int pipe_mutex;
extern int pipe_transfer_over;

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

static INLINE struct NaClAppThread *NaClAppThreadGetFromIndex(
    uint32_t thread_index) {
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
