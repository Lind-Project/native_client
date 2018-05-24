/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Server Runtime user thread state.
 */

#include <string.h>

#include "native_client/src/shared/platform/aligned_malloc.h"
#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_exit.h"
#include "native_client/src/shared/platform/nacl_sync_checked.h"

#include "native_client/src/trusted/service_runtime/arch/sel_ldr_arch.h"
#include "native_client/src/trusted/service_runtime/nacl_app.h"
#include "native_client/src/trusted/service_runtime/nacl_desc_effector_ldr.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_stack_safety.h"
#include "native_client/src/trusted/service_runtime/nacl_switch_to_app.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_common.h"
#include "native_client/src/trusted/service_runtime/nacl_tls.h"
#include "native_client/src/trusted/service_runtime/osx/mach_thread_map.h"

// yiwen
#include "native_client/src/include/win/mman.h"
#include "native_client/src/trusted/service_runtime/load_file.h"
#include "native_client/src/trusted/service_runtime/sel_memory.h"

/* jp */
#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/shared/platform/lind_platform.h"
#include "native_client/src/trusted/service_runtime/include/bits/mman.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"


/*
 * always points at original program context
 *
 * -jp
 */
struct NaClThreadContext *master_ctx;

struct NaClApp *NaClChildNapCtor(struct NaClAppThread *natp) {
  struct NaClApp *nap = natp->nap;
  struct NaClApp *nap_child = NaClAlignedMalloc(sizeof *nap_child, __alignof(struct NaClApp));
  NaClErrorCode *mod_status = NULL;
  int newfd = 0;

  CHECK(nap);
  CHECK(nap_child);

  DPRINTF("%s\n", "Entered NaClChildNapCtor()");
  memset(nap_child, 0, sizeof *nap_child);
  if (!NaClAppCtor(nap_child))
    NaClLog(LOG_FATAL, "Failed to initialize fork child nap\n");
  mod_status = &nap_child->module_load_status;
  nap_child->command_num = nap->command_num;
  nap_child->binary_path = nap->binary_path;
  nap_child->binary_command = nap->binary_command;
  nap_child->nacl_file = nap->nacl_file;
  nap_child->enable_exception_handling = nap->enable_exception_handling;
  nap_child->validator_stub_out_mode = nap->validator_stub_out_mode;
  nap_child->fork_num  = nap_child->cage_id = nap->cage_id + 1;
  nap_child->parent_id = nap->cage_id;
  nap_child->parent = nap;
  nap_child->is_fork_child = 1;
  nap_child->num_children = 0;
  nap_child->num_lib = 3;
  nap_child->fd = 3;
  if (!nap_child->nacl_file)
    nap_child->nacl_file = LD_FILE;
  NaClAppInitialDescriptorHookup(nap_child);

  NaClXMutexLock(&nap_child->mu);
  if ((*mod_status = NaClAppLoadFileFromFilename(nap_child, nap_child->nacl_file)) != LOAD_OK) {
    DPRINTF("Error while loading \"%s\": %s\n",
            nap_child->nacl_file,
            NaClErrorString(*mod_status));
    DPRINTF("%s\n%s\n",
            "Using the wrong type of nexe (nacl-x86-32 on an x86-64 or vice versa) ",
            "or a corrupt nexe file may be responsible for this error.");
    exit(EXIT_FAILURE);
  }
  NaClXCondVarBroadcast(&nap_child->cv);
  NaClXMutexUnlock(&nap_child->mu);

  if ((*mod_status = NaClAppPrepareToLaunch(nap_child)) != LOAD_OK)
    NaClLog(LOG_FATAL, "Failed to prepare child nap for launch\n");
  DPRINTF("Loading blob file %s\n", nap_child->nacl_file);
  if (!nap_child->validator->readonly_text_implemented)
    NaClLog(LOG_FATAL, "fixed_feature_cpu_mode is not supported\n");
  DPRINTF("%s\n", "Enabling Fixed-Feature CPU Mode");
  nap_child->fixed_feature_cpu_mode = 1;
  if (!nap_child->validator->FixCPUFeatures(nap_child->cpu_features))
    NaClLog(LOG_FATAL, "This CPU lacks features required by fixed-function CPU mode.\n");
  if (!NaClAppLaunchServiceThreads(nap_child))
    NaClLog(LOG_FATAL, "Launch service threads failed\n");

  for (int oldfd = 0; oldfd < CAGING_FD_NUM; oldfd++) {
    struct NaClDesc *old_nd;
    old_nd = NaClGetDesc(nap, oldfd);
    if (!old_nd) {
      DPRINTF("NaClGetDesc() finished copying parent fd [%d] to child fd [%d]\n", oldfd - 1, newfd);
      break;
    }
    newfd = NaClSetAvail(nap_child, old_nd);
    NaClSetDesc(nap_child, newfd, old_nd);
    fd_cage_table[nap->cage_id][newfd] = fd_cage_table[nap->cage_id][oldfd];
  }

  NaClXMutexLock(&nap->children_mu);
  if (!DynArraySet(&nap->children, nap->num_children, nap_child))
    NaClLog(LOG_FATAL, "Failed to add child at idx %u\n", nap->num_children);
  nap->num_children++;
  NaClXMutexUnlock(&nap->children_mu);

  return nap_child;
}

/* jp */
void WINAPI NaClAppForkThreadLauncher(void *state) {
  struct NaClAppThread *natp = (struct NaClAppThread *) state;
  struct NaClApp *nap = natp->nap;
  struct NaClThreadContext *context = &natp->user;
  uint32_t thread_idx;
  nacl_reg_t secure_stack_ptr;

  UNREFERENCED_PARAMETER(context);

  DPRINTF("%s\n", "NaClAppForkThreadLauncher: entered");

  NaClSignalStackRegister(natp->signal_stack);

  DPRINTF("     natp  = 0x%016"NACL_PRIxPTR"\n", (uintptr_t)natp);
  DPRINTF(" prog_ctr  = 0x%016"NACL_PRIxNACL_REG"\n", natp->user.prog_ctr);
  DPRINTF("stack_ptr  = 0x%016"NACL_PRIxPTR"\n", NaClGetThreadCtxSp(&natp->user));

  thread_idx = nap->fork_num;
  CHECK(0 < thread_idx);
  CHECK(thread_idx < NACL_THREAD_MAX);
  NaClTlsSetCurrentThread(natp);
#if NACL_WINDOWS
  nacl_thread_ids[thread_idx] = GetCurrentThreadId();
#elif NACL_OSX
  NaClSetCurrentMachThreadForThreadIndex(thread_idx);
#endif

  /*
   * We have to hold the threads_mu and children_mu locks until
   * after thread_num field in this thread has been initialized.
   * All other threads can only find and examine this natp through
   * the threads table, so the fact that natp is not consistent (no
   * thread_num) will not be visible.
   */
  NaClXMutexLock(&nap->threads_mu);
  NaClXMutexLock(&nap->children_mu);
  natp->thread_num = NaClAddThreadMu(nap, natp);
  NaClXMutexUnlock(&nap->threads_mu);
  NaClXMutexUnlock(&nap->children_mu);

  NaClVmHoleThreadStackIsSafe(natp->nap);

  NaClStackSafetyNowOnUntrustedStack();

  /*
   * Notify the debug stub, that a new thread is availible.
   */
  if (NULL != natp->nap->debug_stub_callbacks) {
    natp->nap->debug_stub_callbacks->thread_create_hook(natp);
  }

#if !NACL_WINDOWS
  /*
   * Ensure stack alignment.  Stack pointer must be -8 mod 16 when no
   * __m256 objects are passed (8 mod 32 if __m256), after the call.
   * Note the current doc (as of 2009-12-09) at
   *
   *   http://www.x86-64.org/documentation/abi.pdf
   *
   * is wrong since it claims (%rsp-8) should be 0 mod 16 or mod 32
   * after the call, and it should be (%rsp+8) == 0 mod 16 or 32.
   * Clearly it makes no difference since -8 and 8 are the same mod
   * 16, but there is a difference when mod 32.
   *
   * This is not suitable for Windows because we do not reserve 32
   * bytes for the shadow space.
   */
  secure_stack_ptr = NaClGetStackPtr();
  DPRINTF("NaClStartThreadInApp: secure stack:   0x%"NACL_PRIxNACL_REG"\n",
          secure_stack_ptr);
  secure_stack_ptr = secure_stack_ptr & ~0x1f;
  DPRINTF("NaClStartThreadInApp: adjusted stack: 0x%"NACL_PRIxNACL_REG"\n",
          secure_stack_ptr);
  natp->user.trusted_stack_ptr = secure_stack_ptr;
#endif

  DPRINTF("NaClStackThreadInApp: user stack: 0x%"NACL_PRIxPTR"\n",
          NaClGetThreadCtxSp(context));
  DPRINTF("%s\n", "NaClStartThreadInApp: switching to untrusted code");

  DPRINTF("[NaClAppThreadLauncher] Nap %d is ready to launch! child registers: \n", nap->cage_id);
  NaClLogThreadContext(natp);
  NaClAppThreadPrintInfo(natp);
  CHECK(thread_idx == nacl_user[thread_idx]->tls_idx);

  /*
   * After this NaClAppThreadSetSuspendState() call, we should not
   * claim any mutexes, otherwise we risk deadlock.
   */
  NaClAppThreadSetSuspendState(natp, NACL_APP_THREAD_TRUSTED, NACL_APP_THREAD_UNTRUSTED);

#if NACL_WINDOWS
  /* This sets up a stack containing a return address that has unwind info. */
  NaClSwitchSavingStackPtr(context, &context->trusted_stack_ptr, NaClSwitchToApp);
#else
  NaClSwitchToApp(natp);
#endif
}

void WINAPI NaClAppThreadLauncher(void *state) {
  struct NaClAppThread *natp = (struct NaClAppThread *) state;
  uint32_t thread_idx;
  NaClLog(4, "NaClAppThreadLauncher: entered\n");

  NaClSignalStackRegister(natp->signal_stack);

  DPRINTF("     natp  = 0x%016"NACL_PRIxPTR"\n", (uintptr_t)natp);
  DPRINTF(" prog_ctr  = 0x%016"NACL_PRIxNACL_REG"\n", natp->user.prog_ctr);
  DPRINTF("stack_ptr  = 0x%016"NACL_PRIxPTR"\n",
          NaClGetThreadCtxSp(&natp->user));

  thread_idx = NaClGetThreadIdx(natp);
  CHECK(0 < thread_idx);
  CHECK(thread_idx < NACL_THREAD_MAX);
  NaClTlsSetCurrentThread(natp);
  nacl_user[thread_idx] = &natp->user;
#if NACL_WINDOWS
  nacl_thread_ids[thread_idx] = GetCurrentThreadId();
#elif NACL_OSX
  NaClSetCurrentMachThreadForThreadIndex(thread_idx);
#endif

  /*
   * We have to hold the threads_mu lock until after thread_num field
   * in this thread has been initialized.  All other threads can only
   * find and examine this natp through the threads table, so the fact
   * that natp is not consistent (no thread_num) will not be visible.
   */
  NaClXMutexLock(&natp->nap->threads_mu);
  natp->thread_num = NaClAddThreadMu(natp->nap, natp);
  NaClXMutexUnlock(&natp->nap->threads_mu);

  NaClVmHoleThreadStackIsSafe(natp->nap);

  NaClStackSafetyNowOnUntrustedStack();

  /*
   * Notify the debug stub, that a new thread is availible.
   */
  if (NULL != natp->nap->debug_stub_callbacks) {
    natp->nap->debug_stub_callbacks->thread_create_hook(natp);
  }

  /*
   * After this NaClAppThreadSetSuspendState() call, we should not
   * claim any mutexes, otherwise we risk deadlock.
   */
  NaClAppThreadSetSuspendState(natp, NACL_APP_THREAD_TRUSTED,
                               NACL_APP_THREAD_UNTRUSTED);

  // yiwen:
  DPRINTF("%s\n", "[NaCl Main Loader] NaCl Loader: user program about to start running inside the cage!");
  /* NaClVmmapDebug(&natp->nap->mem_map, "parent vmmap:"); */
  NaClStartThreadInApp(natp, natp->user.prog_ctr);
}

/*
 * natp should be thread_self(), called while holding no locks.
 */
void NaClAppThreadTeardown(struct NaClAppThread *natp) {
  struct NaClApp  *nap = natp->nap;
  size_t          thread_idx;

  /*
   * mark this thread as dead; doesn't matter if some other thread is
   * asking us to commit suicide.
   */
  DPRINTF("[NaClAppThreadTeardown] cage id: %d\n", nap->cage_id);

  if (nap->parent) {
    DPRINTF("Signaling parent from cage id: %d\n", nap->cage_id);
    NaClXMutexLock(&nap->parent->mu);
    NaClXCondVarSignal(&nap->parent->cv);
    NaClXMutexUnlock(&nap->parent->mu);
    /*
     * remove self from parent's child_list
     */
    NaClXMutexLock(&nap->parent->children_mu);
    DPRINTF("Decrementing parent child count for cage id: %d\n", nap->parent->cage_id);
    DPRINTF("Parent new child count: %d\n", --nap->parent->num_children);
    nap->parent->children_ids[nap->parent->num_children] = 0;
    nap->parent->child_list[nap->cage_id] = NULL;
    NaClXMutexUnlock(&nap->parent->children_mu);
    goto out;
  }

  /*
   * cleanup list of children
   */
  DPRINTF("%s\n", "Thread has no parent");
  NaClXMutexLock(&nap->mu);
  DPRINTF("Thread children count: %d\n", nap->num_children);
  while (nap->num_children > 0)
    NaClXCondVarWait(&nap->cv, &nap->mu);
  free(nap->child_list);
  nap->child_list = NULL;
  NaClXMutexUnlock(&nap->mu);

out:
  if (nap->debug_stub_callbacks) {
    DPRINTF("%s\n", " notifying the debug stub of the thread exit");
    /*
     * This must happen before deallocating the ID natp->thread_num.
     * We have the invariant that debug stub lock should be acquired before
     * nap->threads_mu lock. Hence we must not hold threads_mu lock while
     * calling debug stub hooks.
     */
    nap->debug_stub_callbacks->thread_exit_hook(natp);
  }

  DPRINTF("%s\n", " getting thread table lock");
  NaClXMutexLock(&nap->threads_mu);
  DPRINTF("%s\n", " getting thread lock");
  NaClXMutexLock(&natp->mu);

  /*
   * Remove ourselves from the ldt-indexed global tables.  The ldt
   * entry is released as part of NaClAppThreadDelete(), and if
   * another thread is immediately created (from some other running
   * thread) we want to be sure that any ldt-based lookups will not
   * reach this dying thread's data.
   */
  thread_idx = NaClGetThreadIdx(natp);
  /*
   * On x86-64 and ARM, clearing nacl_user entry ensures that we will
   * fault if another syscall is made with this thread_idx.  In
   * particular, thread_idx 0 is never used.
   */
  nacl_user[thread_idx] = NULL;
#if NACL_WINDOWS
  nacl_thread_ids[thread_idx] = 0;
#elif NACL_OSX
  NaClClearMachThreadForThreadIndex(thread_idx);
#endif
  /*
   * Unset the TLS variable so that if a crash occurs during thread
   * teardown, the signal handler does not dereference a dangling
   * NaClAppThread pointer.
   */
  NaClTlsSetCurrentThread(NULL);

  DPRINTF("%s\n", " removing thread from thread table");
  /* Deallocate the ID natp->thread_num. */
  NaClRemoveThreadMu(nap, natp->thread_num);
  DPRINTF("%s\n", " unlocking thread");
  NaClXMutexUnlock(&natp->mu);
  DPRINTF("%s\n", " unlocking thread table");
  NaClXMutexUnlock(&nap->threads_mu);
  DPRINTF("%s\n", " unregistering signal stack");
  NaClSignalStackUnregister();
  DPRINTF("%s\n", " freeing thread object");
  NaClAppThreadDelete(natp);
  DPRINTF("%s\n", " NaClThreadExit");

  NaClThreadExit();
  NaClLog(LOG_FATAL, "NaClAppThreadTeardown: NaClThreadExit() should not return\n");
  /* NOTREACHED */
}

struct NaClAppThread *NaClAppThreadMake(struct NaClApp *nap,
                                        uintptr_t      usr_entry,
                                        uintptr_t      usr_stack_ptr,
                                        uint32_t       user_tls1,
                                        uint32_t       user_tls2) {
 struct NaClAppThread *natp;
 uint32_t tls_idx;

 natp = NaClAlignedMalloc(sizeof *natp, __alignof(struct NaClAppThread));
 if (natp == NULL) {
  return NULL;
 }

  DPRINTF("         natp = 0x%016"NACL_PRIxPTR"\n", (uintptr_t) natp);
  DPRINTF("          nap = 0x%016"NACL_PRIxPTR"\n", (uintptr_t) nap);
  DPRINTF("    usr_entry = 0x%016"NACL_PRIxPTR"\n", usr_entry);
  DPRINTF("usr_stack_ptr = 0x%016"NACL_PRIxPTR"\n", usr_stack_ptr);

  /*
   * Set these early, in case NaClTlsAllocate() wants to examine them.
   */
  natp->nap = nap;

  natp->thread_num = -1;  /* illegal index */
  natp->host_thread_is_defined = 0;
  memset(&natp->host_thread, 0, sizeof(natp->host_thread));

  /*
   * Even though we don't know what segment base/range should gs/r9/nacl_tls_idx
   * select, we still need one, since it identifies the thread when we context
   * switch back.  This use of a dummy tls is only needed for the main thread,
   * which is expected to invoke the tls_init syscall from its crt code (before
   * main or much of libc can run).  Other threads are spawned with the thread
   * pointer address as a parameter.
   */
  tls_idx = NaClTlsAllocate(natp);
  if (NACL_TLS_INDEX_INVALID == tls_idx) {
    NaClLog(LOG_ERROR, "No tls for thread, num_thread %d\n", nap->num_threads);
    goto cleanup_free;
  }


  NaClThreadContextCtor(&natp->user, nap, usr_entry, usr_stack_ptr, tls_idx);

  NaClTlsSetTlsValue1(natp, user_tls1);
  NaClTlsSetTlsValue2(natp, user_tls2);

  natp->signal_stack = NULL;
  natp->exception_stack = 0;
  natp->exception_flag = 0;

  if (!NaClMutexCtor(&natp->mu)) {
    goto cleanup_free;
  }

  if (!NaClSignalStackAllocate(&natp->signal_stack)) {
    goto cleanup_mu;
  }

  if (!NaClMutexCtor(&natp->suspend_mu)) {
    goto cleanup_mu;
  }
  natp->suspend_state = NACL_APP_THREAD_TRUSTED;
  natp->suspended_registers = NULL;
  natp->fault_signal = 0;

  natp->dynamic_delete_generation = 0;
  return natp;

 cleanup_mu:
  NaClMutexDtor(&natp->mu);
  if (NULL != natp->signal_stack) {
    NaClSignalStackFree(&natp->signal_stack);
    natp->signal_stack = NULL;
  }
 cleanup_free:
  NaClAlignedFree(natp);
  return NULL;
}

/* jp */
#define NaClLogSysMemoryContentType(TYPE, NDIG, ADDR)						\
 do {												\
  unsigned char *addr = (unsigned char *)(ADDR);						\
  UNREFERENCED_PARAMETER(addr);									\
  DPRINTF("[Memory] Memory addr:                   %p\n", (void *)addr);			\
  DPRINTF("[Memory] Memory content (byte-swapped): 0x%0" #NDIG "lx\n", OBJ_REP_64(addr));	\
  DPRINTF("[Memory] Memory content (raw):          0x%0" #NDIG "lx\n", *(TYPE *)addr);		\
 } while (0)

/* jp */
int NaClAppForkThreadSpawn(struct NaClApp           *nap_parent,
                           struct NaClAppThread     *natp_parent,
                           size_t                   stack_size,
                           struct NaClThreadContext *parent_ctx,
                           struct NaClApp           *nap_child,
                           uintptr_t                usr_entry,
                           uintptr_t                usr_stack_ptr,
                           uint32_t                 user_tls1,
                           uint32_t                 user_tls2) {
  static THREAD void *stack_ptr_parent;
  static THREAD void *stack_ptr_child;
  static THREAD size_t stack_total_size;
  static THREAD size_t stack_ptr_offset;
  static THREAD size_t base_ptr_offset;
  static THREAD struct NaClAppThread *natp_child;
  static THREAD struct NaClThreadContext ctx;

  UNREFERENCED_PARAMETER(stack_ptr_offset);
  UNREFERENCED_PARAMETER(base_ptr_offset);
  UNREFERENCED_PARAMETER(ctx);

  if (!nap_parent->running)
   return 0;

  NaClXMutexLock(&nap_parent->mu);
  NaClXMutexLock(&nap_child->mu);

  /*
   * make space to copy the parent stack
   */
  stack_total_size = nap_parent->stack_size;
  nap_child->stack_size = stack_total_size;
  /* align the child stack correctly */
  stack_size = (stack_total_size + NACL_STACK_ALIGN_MASK) & ~NACL_STACK_ALIGN_MASK;
  stack_ptr_parent = (void *)NaClUserToSysAddrRange(nap_parent,
                                                    NaClGetInitialStackTop(nap_parent) - stack_total_size,
                                                    stack_total_size);
  stack_ptr_child = (void *)NaClUserToSysAddrRange(nap_child,
                                                   NaClGetInitialStackTop(nap_child) - stack_size,
                                                   stack_size);
  stack_ptr_offset = parent_ctx->rsp - (uintptr_t)stack_ptr_parent;
  base_ptr_offset = parent_ctx->rbp - parent_ctx->rsp;
  usr_stack_ptr = NaClSysToUserStackAddr(nap_child, (uintptr_t)stack_ptr_child);
  natp_child = NaClAppThreadMake(nap_child, usr_entry, usr_stack_ptr, user_tls1, user_tls2);
  if (!natp_child)
    return 0;

  /* save child trampoline addresses and set cage_id */
  ctx = natp_child->user;
  DPRINTF("%s\n", "Thread context of child before copy");
  NaClLogThreadContext(natp_child);
  /* copy parent page tables and execution context */
  NaClCopyExecutionContext(nap_parent, nap_child);
  /* copy parent thread context */
  natp_child->user = *parent_ctx;
  DPRINTF("%s\n", "Thread context of child after copy");
  NaClLogThreadContext(natp_child);

  /*
   * set return value for fork().
   *
   * linux is a unix-like system. however, its kernel uses the
   * microsoft system-call convention of passing parameters in
   * registers. as with the unix convention, the function number
   * is placed in eax. the parameters, however, are not passed on
   * the stack but in %rbx, %rcx, %rdx, %rsi, %rdi, %rbp:
   *
   * ; SYS_open's syscall number is 5
   * open:
   *	mov	$5, %eax
   *	mov	$path, %ebx
   *	mov	$flags, %ecx
   *	mov	$mode, %edx
   *	int	$0x80
   *
   * n.b. fork() return value is stored in %rdx
   * instead of %rax like other syscalls, but
   * thankfully in NaCl we only need to set %sysret
   * in order to change the return value.
   *
   * -jp
   */
  natp_child->user.sysret = 0;

  /*
   * adjust trampolines and %rip
   */
  nap_child->mem_start = ctx.r15;
  /* nap_child->mem_start = parent_ctx->r15; */
  /* nap_child->mem_start = master_ctx->r15; */
  natp_child->user.r15 = nap_child->mem_start;
  natp_child->user.rsp = ctx.rsp + stack_ptr_offset;
  /* natp_child->user.rbp = ctx.rbp + base_ptr_offset; */
  /* natp_child->user.prog_ctr += -parent_ctx->r15 + ctx.r15; */
  /* natp_child->user.new_prog_ctr += -parent_ctx->r15 + ctx.r15; */

#define NUM_STACK_VALS 8
#define TYPE_TO_EXAMINE nacl_reg_t
  /*
   * patch stack addresses
   */
  NaClPatchAddr(ctx.r15, nap_parent->mem_start, (uintptr_t *)natp_child->user.rsp, NUM_STACK_VALS);
  NaClPatchAddr(ctx.r15, nap_parent->mem_start, (uintptr_t *)&natp_child->user.rbp, 1);
  for (size_t i = 0; i < NUM_STACK_VALS; i++) {
    uintptr_t child_addr = (uintptr_t)&((TYPE_TO_EXAMINE *)natp_child->user.rsp)[i];
    uintptr_t parent_addr = (uintptr_t)&((TYPE_TO_EXAMINE *)parent_ctx->rsp)[i];
    /*
     * DPRINTF("child_stack[%zu]:\n", i);
     * NaClLogSysMemoryContentType(TYPE_TO_EXAMINE, 16, &((TYPE_TO_EXAMINE *)stack_ptr_child)[i]);
     * DPRINTF("parent_stack[%zu]:\n", i);
     * NaClLogSysMemoryContentType(TYPE_TO_EXAMINE, 16, &((TYPE_TO_EXAMINE *)stack_ptr_parent)[i]);
     */
    DPRINTF("child_rsp[%zu]:\n", i);
    NaClLogSysMemoryContentType(TYPE_TO_EXAMINE, 16, child_addr);
    DPRINTF("parent_rsp[%zu]:\n", i);
    NaClLogSysMemoryContentType(TYPE_TO_EXAMINE, 16, parent_addr);
  }
#undef NUM_STACK_VALS
#undef TYPE_TO_EXAMINE

  /*
   * setup TLS slot in the global nacl_user array
   */
  natp_child->user.tls_idx = nap_child->fork_num;
  NaClTlsSetTlsValue1(natp_child, user_tls1);
  NaClTlsSetTlsValue2(natp_child, user_tls2);
  if (nacl_user[natp_child->user.tls_idx]) {
    NaClLog(LOG_FATAL, "nacl_user[%u] not NULL (%p)\n)",
            natp_child->user.tls_idx,
            (void *)nacl_user[natp_child->user.tls_idx]);
  }
  nacl_user[natp_child->user.tls_idx] = &natp_child->user;
  DPRINTF("usr_syscall_args address (child: %p) (parent: %p))\n",
          (void *)natp_child->usr_syscall_args,
          (void *)natp_parent->usr_syscall_args);
  DPRINTF("Registers after copy (%%rsp: %p) (%%rbp: %p) (%%r15: %p)\n",
          (void *)natp_child->user.rsp,
          (void *)natp_child->user.rbp,
          (void *)natp_child->user.r15);

  /*
   * We set host_thread_is_defined assuming, for now, that
   * NaClThreadCtor() will succeed.
   */
  natp_child->host_thread_is_defined = 1;

  NaClXCondVarSignal(&nap_parent->cv);
  NaClXMutexUnlock(&nap_parent->mu);
  NaClXMutexUnlock(&nap_child->mu);

  /*
  * No other thread saw the NaClAppThread, so it is OK that
  * host_thread was not initialized despite host_thread_is_defined
  * being set.
  */
  if (!NaClThreadCreateJoinable(&natp_child->host_thread,
                                NaClAppForkThreadLauncher,
                                natp_child,
                                NACL_KERN_STACK_SIZE)) {
    natp_child->host_thread_is_defined = 0;
    NaClAppThreadDelete(natp_child);
    return 0;
  }

  return 1;
}

int NaClAppThreadSpawn(struct NaClApp *nap,
                       uintptr_t      usr_entry,
                       uintptr_t      usr_stack_ptr,
                       uint32_t       user_tls1,
                       uint32_t       user_tls2) {
  struct NaClAppThread *natp = NaClAppThreadMake(nap, usr_entry, usr_stack_ptr,
                                                 user_tls1, user_tls2);
  if (!natp)
    return 0;
  nap->parent = NULL;
  nap->is_fork_child = 0;
  nap->fork_num = nap->cage_id;

  /*
   * save master thread context pointer
   */
  if (nap->cage_id == 1)
    master_ctx = &natp->user;

  /*
   * We set host_thread_is_defined assuming, for now, that
   * NaClThreadCtor() will succeed.
   */
  natp->host_thread_is_defined = 1;
  if (!NaClThreadCtor(&natp->host_thread, NaClAppThreadLauncher, (void *) natp,
                      NACL_KERN_STACK_SIZE)) {
    /*
     * No other thread saw the NaClAppThread, so it is OK that
     * host_thread was not initialized despite host_thread_is_defined
     * being set.
     */
    natp->host_thread_is_defined = 0;
    NaClAppThreadDelete(natp);
    return 0;
  }
  return 1;
}

/*
* n.b. the thread must not be still running, else this crashes the system
*/
void NaClAppThreadDelete(struct NaClAppThread *natp) {
  if (natp->host_thread_is_defined) {
    NaClThreadDtor(&natp->host_thread);
  }
  free(natp->suspended_registers);
  NaClMutexDtor(&natp->suspend_mu);
  NaClSignalStackFree(natp->signal_stack);
  natp->signal_stack = NULL;
  NaClTlsFree(natp);
  NaClMutexDtor(&natp->mu);
  NaClAlignedFree(natp);
}

/* jp */
void NaClAppThreadPrintInfo(struct NaClAppThread *natp) {
  DPRINTF("[NaClAppThreadPrintInfo] "
          "cage id = %d, prog_ctr = %#lx, new_prog_ctr = %#lx, sysret = %#lx\n",
          natp->nap->cage_id,
          (long unsigned)natp->user.prog_ctr,
          (long unsigned)natp->user.new_prog_ctr,
          (long unsigned)natp->user.sysret);
}
