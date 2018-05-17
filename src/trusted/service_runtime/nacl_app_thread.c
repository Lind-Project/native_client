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
#include "native_client/src/trusted/service_runtime/nacl_desc_effector_ldr.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_tls.h"
#include "native_client/src/trusted/service_runtime/nacl_switch_to_app.h"
#include "native_client/src/trusted/service_runtime/nacl_stack_safety.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_common.h"
#include "native_client/src/trusted/service_runtime/osx/mach_thread_map.h"

// yiwen
#include "native_client/src/include/win/mman.h"
#include "native_client/src/trusted/service_runtime/load_file.h"
#include "native_client/src/trusted/service_runtime/sel_memory.h"

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

  /* NaClAppThreadSetSuspendState(natp, NACL_APP_THREAD_TRUSTED, NACL_APP_THREAD_UNTRUSTED); */
  /* NaClSwitchFork(&natp->user); */
  /* NaClStartThreadInApp(natp, natp->user.new_prog_ctr); */

  /*
   * broken context switch methods
   * -jp
   *
   * NaClSwitchToApp(natp);
   * NaClStartThreadInApp(natp, natp->user.prog_ctr);
   */

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

  /*
   * don't change sysret and program count since we
   * are context switching straight into fork() point.
   *
   * -jp
   *
   * context->new_prog_ctr = new_prog_ctr;
   * context->sysret = 0;
   */

  DPRINTF("NaClStackThreadInApp: user stack: 0x%"NACL_PRIxPTR"\n",
          NaClGetThreadCtxSp(context));
  DPRINTF("%s\n", "NaClStartThreadInApp: switching to untrusted code");

  DPRINTF("[NaClAppThreadLauncher] Nap %d is ready to launch. \n", natp->nap->cage_id);
  NaClLogThreadContext(natp);
  NaClAppThreadPrintInfo(natp);

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
  NaClStartThreadInApp(natp, natp->user.prog_ctr);
}


/*
 * natp should be thread_self(), called while holding no locks.
 */
void NaClAppThreadTeardown(struct NaClAppThread *natp) {
  struct NaClApp  *nap;
  size_t          thread_idx;

  /*
   * mark this thread as dead; doesn't matter if some other thread is
   * asking us to commit suicide.
   */
  DPRINTF("NaClAppThreadTeardown(0x%08"NACL_PRIxPTR")\n", (uintptr_t)natp);
  nap = natp->nap;

  /* TODO: add mutex locks */
  if (natp->parent) {
    DPRINTF("Decrementing parent child count for cage id: %d\n", natp->parent->cage_id);
    DPRINTF("Parent new child count: %d\n", --natp->parent->num_children);
    /*
     * sleep(1);
     * NaClThreadYield();
     */
    goto out;
  }

  DPRINTF("%s\n", "Thread has no parent");

  /* busy wait for now */
  while (nap->num_children) {
    /*
     * while (nap->child_list[0]->num_children) {
     *   sleep(1);
     *   DPRINTF("Thread child children count: %d\n", nap->num_children);
     * }
     */
    sleep(1);
    DPRINTF("Thread children count: %d\n", nap->num_children);
  }

  /* cleanup list of children */
  free(nap->child_list);
  nap->child_list = NULL;

  if (NULL != nap->debug_stub_callbacks) {
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

out:
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
int NaClAppForkThreadSpawn(struct NaClApp           *nap_parent,
                           struct NaClAppThread     *natp_parent,
                           size_t                   stack_size,
                           struct NaClThreadContext *parent_ctx,
                           struct NaClApp           *nap_child,
                           uintptr_t                usr_entry,
                           uintptr_t                usr_stack_ptr,
                           uint32_t                 user_tls1,
                           uint32_t                 user_tls2) {
  void *sysaddr_parent;
  void *sysaddr_child;
  size_t size_of_dynamic_text;
  size_t stack_total_size;
  uintptr_t entry_point;
  uintptr_t stack_ptr_parent;
  uintptr_t stack_ptr_child;
  struct NaClAppThread *natp_child;
  struct NaClThreadContext ctx;

  if (!nap_parent->running)
   return 0;

  NaClXMutexLock(&nap_child->mu);
  NaClXMutexLock(&nap_parent->mu);

  UNREFERENCED_PARAMETER(ctx);
  UNREFERENCED_PARAMETER(usr_entry);

  stack_total_size = nap_parent->stack_size;
  if (stack_size < stack_total_size)
    nap_child->stack_size = stack_size = stack_total_size;
  stack_ptr_parent = NaClUserToSysAddrRange(nap_parent,
                                            NaClGetInitialStackTop(nap_parent) - stack_total_size,
                                            stack_total_size);
  stack_ptr_child = NaClUserToSysAddrRange(nap_child,
                                           NaClGetInitialStackTop(nap_child) - stack_total_size,
                                           stack_total_size);
  usr_stack_ptr = NaClSysToUserStackAddr(nap_child, stack_ptr_child);
  entry_point = usr_entry;
  natp_child = NaClAppThreadMake(nap_child, entry_point, usr_stack_ptr, user_tls1, user_tls2);
  /* natp_child = NaClAppThreadMake(nap_parent, entry_point, usr_stack_ptr, user_tls1, user_tls2); */
  if (!natp_child)
    return 0;
  natp_child->parent = nap_parent;
  natp_child->parent_id = nap_parent->cage_id;

  /*
   * save child trampoline addresses and set cage_id
   */
  ctx = natp_child->user;
  if (natp_child->nap != nap_child) {
    DPRINTF("%s\n", "natp_child->nap != nap_child");
    nap_child = natp_child->nap;
  }
  nap_child->cage_id = nap_parent->cage_id + 1;
  natp_child->is_fork_child = 1;

  /*
   * find the first unused slot in the nacl_user array
   */
  nap_child->fork_num = 1;
  while (nacl_user[++nap_child->fork_num]) /* no-op */;
  /* nap_child->fork_num = parent_ctx->tls_idx + 1; */
  natp_child->user.tls_idx = nap_child->fork_num;
  if (nacl_user[natp_child->user.tls_idx]) {
    NaClLog(LOG_FATAL, "nacl_user[%u] not NULL (%p)\n)",
            natp_child->user.tls_idx,
            (void *)nacl_user[natp_child->user.tls_idx]);
  }
  sysaddr_parent = (void *)NaClUserToSys(nap_parent, nap_parent->dynamic_text_start);
  sysaddr_child = (void *)NaClUserToSys(nap_child, nap_child->dynamic_text_start);
  size_of_dynamic_text = nap_parent->dynamic_text_end - nap_parent->dynamic_text_start;
  DPRINTF("parent: [%p] child: [%p]\n", sysaddr_parent, sysaddr_child);
  DPRINTF("nap_parent cage id: [%d]\n", nap_parent->cage_id);
  DPRINTF("nap_child fork_num: [%d]\n", natp_child->nap->fork_num);
  CHECK(nap_child->dynamic_text_end - nap_child->dynamic_text_start == size_of_dynamic_text);

  if (NaClMprotect(sysaddr_child, size_of_dynamic_text, PROT_READ|PROT_WRITE) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");
  if (NaClMprotect(sysaddr_parent, size_of_dynamic_text, PROT_READ|PROT_WRITE) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");
  if (NaClMprotect((void *)stack_ptr_child, stack_total_size, PROT_READ|PROT_WRITE) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");
  if (NaClMprotect((void *)stack_ptr_parent, stack_total_size, PROT_READ|PROT_WRITE) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");

  NaClPrintAddressSpaceLayout(nap_parent);
  DPRINTF("copying page table from %p to %p\n", (void *)nap_parent, (void *)nap_child);
  NaClVmCopyAddressSpace(nap_parent, nap_child);
  NaClPrintAddressSpaceLayout(nap_child);

  DPRINTF("Copying parent stack (%zu [%#lx] bytes) from %p to %p\n",
          (size_t)stack_total_size,
          (size_t)stack_total_size,
          (void *)stack_ptr_parent,
          (void *)stack_ptr_child);
  memcpy((void *)stack_ptr_child, (void *)stack_ptr_parent, stack_total_size);
  DPRINTF("copying dynamic text (%zu [%#lx] bytes) from %p to %p\n",
          size_of_dynamic_text,
          size_of_dynamic_text,
          sysaddr_parent,
          sysaddr_child);
  memcpy(sysaddr_child, sysaddr_parent, size_of_dynamic_text);

  /*
   * DPRINTF("Thread context of parent\n");
   * NaClLogThreadContext(natp_parent);
   */
  DPRINTF("%s\n", "Thread context of child before copy");
  NaClLogThreadContext(natp_child);
  /* restore child trampoline addresses and stack pointer */
  natp_child->user = *parent_ctx;
  DPRINTF("%s\n", "Thread context of child after copy");
  NaClLogThreadContext(natp_child);

  /*
   * use parent's memory mapping
   */
  natp_child->user.r15 = parent_ctx->r15;
  nap_child->mem_start = parent_ctx->r15;
  /* natp_child->user.r15 = ctx.r15; */
  /* nap_child->mem_start = ctx.r15; */
  nap_child->break_addr = nap_parent->break_addr;
  nap_child->nacl_syscall_addr = nap_parent->nacl_syscall_addr;
  nap_child->get_tls_fast_path1_addr = nap_parent->get_tls_fast_path1_addr;
  nap_child->get_tls_fast_path2_addr = nap_parent->get_tls_fast_path2_addr;
  natp_child->usr_syscall_args = natp_parent->usr_syscall_args;
  natp_child->user.trusted_stack_ptr = ctx.trusted_stack_ptr;

  /*
   * set return value for fork().
   *
   * linux is a unix-like system. however, its kernel uses the
   * microsoft system-call convention of passing parameters in
   * registers. as with the unix convention, the function number
   * is placed in eax. the parameters, however, are not passed on
   * the stack but in %rbx, %rcx, %rdx, %rsi, %rdi, %rbp:
   *
   * # SYS_open's syscall number is 5
   * open:
   *	mov	$5, %eax
   *	mov	$path, %ebx
   *	mov	$flags, %ecx
   *	mov	$mode, %edx
   *	int	$0x80
   *
   * n.b. fork() return value is stored in %rdx
   * instead of %rax like other syscalls.
   *
   * -jp
   */
  natp_child->user.sysret = 0;
  /* don't segfault on add %al, (%rax)` instructions (0x00) */
  /* natp_child->user.rax = ctx.rsp - 8; */
  /* natp_child->user.rax = 0; */
  /* natp_child->user.rbx = 0; */
  /* natp_child->user.rcx = 0; */
  natp_child->user.rdx = 0;
  /* natp_child->user.rsi = 0; */
  /* natp_child->user.rdi = 0; */

  /*
   * restore trampolines and adjust %rip
   */
  /* natp_child->user.rbp += -parent_ctx->r15 + ctx.r15; */
  /* natp_child->user.prog_ctr += -parent_ctx->r15 + ctx.r15; */
  /* natp_child->user.new_prog_ctr += -parent_ctx->r15 + ctx.r15; */
  /* natp_child->user.rsp = ctx.rsp; */
  /* natp_child->user.rsp -= 0x8; */

  /*
   * natp_child->nap->main_exe_prevalidated = 1;
   * natp_child->nap->enable_dyncode_syscalls = 1;
   * natp_child->nap->running = 1;
   * natp_child->nap->skip_validator = 1;
   * natp_child->nap->ignore_validator_result = 1;
   */

  DPRINTF("usr_syscall_args address child: %p parent: %p)\n",
          (void *)natp_child->usr_syscall_args,
          (void *)natp_parent->usr_syscall_args);
  DPRINTF("Registers after copy [%%rsp] %p [%%rbp] %p)\n",
          (void *)natp_child->user.rsp,
          (void *)natp_child->user.rbp);
  DPRINTF("Registers after copy [%%r15] %p [%%rdi] %p)\n",
          (void *)natp_child->user.r15,
          (void *)natp_child->user.rdi);

  if (NaClMprotect(sysaddr_child, size_of_dynamic_text, PROT_READ|PROT_EXEC) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");
  if (NaClMprotect(sysaddr_parent, size_of_dynamic_text, PROT_READ|PROT_EXEC) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");
  if (NaClMprotect((void *)stack_ptr_child, stack_total_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");
  if (NaClMprotect((void *)stack_ptr_parent, stack_total_size, PROT_READ|PROT_WRITE|PROT_EXEC) == -1)
    DPRINTF("%s\n", "parent NaClMprotect failed!");

  NaClXMutexUnlock(&nap_child->mu);
  NaClXMutexUnlock(&nap_parent->mu);

  /*
   * We set host_thread_is_defined assuming, for now, that
   * NaClThreadCtor() will succeed.
   */
  natp_child->host_thread_is_defined = 1;

  /*
  * No other thread saw the NaClAppThread, so it is OK that
  * host_thread was not initialized despite host_thread_is_defined
  * being set.
  */
  /*
   * if (!NaClThreadCreateJoinable(&natp_child->host_thread,
   *                               NaClSwitchFork,
   *                               &natp_child->user,
   *                               NACL_KERN_STACK_SIZE)) {
   */
  /* if (!NaClThreadCreate(&natp_child->host_thread, */
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
  if (natp == NULL)
    return 0;
  natp->parent = NULL;
  natp->is_fork_child = 0;
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
          "cage id = %d, prog_ctr = %p, new_prog_ctr = %p, sysret = %p\n",
          natp->nap->cage_id,
          (void*)natp->user.prog_ctr,
          (void*)natp->user.new_prog_ctr,
          (void*)natp->user.sysret);
}
