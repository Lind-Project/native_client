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
#include "native_client/src/trusted/service_runtime/dyn_array.h"
#include "native_client/src/trusted/service_runtime/nacl_app.h"
#include "native_client/src/trusted/service_runtime/nacl_desc_effector_ldr.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_stack_safety.h"
#include "native_client/src/trusted/service_runtime/nacl_switch_to_app.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_common.h"
#include "native_client/src/trusted/service_runtime/nacl_tls.h"
#include "native_client/src/trusted/service_runtime/osx/mach_thread_map.h"

#include "native_client/src/include/win/mman.h"
#include "native_client/src/trusted/service_runtime/load_file.h"
#include "native_client/src/trusted/service_runtime/sel_memory.h"

#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/shared/platform/lind_platform.h"
#include "native_client/src/trusted/service_runtime/include/bits/mman.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"


struct NaClMutex ccmut;
struct NaClCondVar cccv;
int cagecount;
extern bool use_lkm;

struct NaClThread reaper;

struct NaClMutex teardown_mutex;
bool in_teardown = false;
struct NaClAppThread *natp_to_teardown = NULL;
struct NaClMutex reapermut;
struct NaClCondVar reapercv;
bool reap = true;

/*
 * dynamically allocate and initilize a copy
 * of the parents NaClApp structure which is
 * used in NaClSysFork()
 */
struct NaClApp *NaClChildNapCtor(struct NaClApp *nap, int child_cage_id, enum NaClThreadLaunchType tl_type) {
  struct NaClApp *nap_child = NaClAlignedMalloc(sizeof(*nap_child), __alignof(struct NaClApp));
  struct NaClApp *nap_parent = nap;
  NaClErrorCode *mod_status = NULL;
  int envc = 0;
  char const **childe;

  CHECK(nap_parent);
  CHECK(nap_child);

  NaClLog(1, "%s\n", "Entered NaClChildNapCtor()");
  memset(nap_child, 0, sizeof(*nap_child));
  if (!NaClAppCtor(nap_child)) {
    NaClLog(LOG_FATAL, "%s\n", "Failed to initialize fork child nap");
  }

  mod_status = &nap_child->module_load_status;
  nap_child->tl_type = tl_type;     /* Set nap's thread launch type */
  nap_child->argc = nap_parent->argc;
  nap_child->argv = nap_parent->argv;
  nap_child->binary = nap_parent->binary;
  nap_child->nacl_file = nap_parent->nacl_file ? nap_parent->nacl_file : LD_FILE;
  nap_child->enable_exception_handling = nap_parent->enable_exception_handling;
  nap_child->validator_stub_out_mode = nap_parent->validator_stub_out_mode;
  nap_child->ignore_validator_result = nap_parent->ignore_validator_result;
  nap_child->skip_validator = nap_parent->skip_validator;
  nap_child->user_entry_pt = nap_parent->user_entry_pt;
  nap_child->parent_id = nap_parent->cage_id;
  nap_child->parent = nap_parent;
  nap_child->in_fork = 0;

  for(char const *const *ce = nap_parent->clean_environ; ce && *ce; ++ce) {
    envc++;
  }
  childe = malloc((envc + 1) * sizeof(char*));
  nap_child->clean_environ = (const char *const *)childe;
  for(char const *const *ce = nap_parent->clean_environ; ce && *ce; ++ce) {
     *childe++ = *ce;
  }
  *childe++ = NULL;

  NaClXMutexLock(&ccmut);
  cagecount++;
  NaClXMutexUnlock(&ccmut);

  NaClXMutexLock(&nap_parent->children_mu);
  /*
   * increment fork generation count and generate child (holding parent mutex)
   */
  InitializeCage(nap_child, child_cage_id);
  nap_parent->num_children++;

  if (nap_parent->num_children > CHILD_NUM_MAX) {
    NaClLog(LOG_FATAL, "[nap %u] child_idx > %d\n", nap_parent->cage_id, CHILD_NUM_MAX);
  }
  if (!DynArraySet(&nap_parent->children, nap_child->cage_id, nap_child)) {
    NaClLog(LOG_FATAL, "[nap %u] failed to add cage_id %d\n", nap_parent->cage_id, nap_child->cage_id);
  }
  NaClLog(1, "[nap %d] new child count: %d\n", nap_parent->cage_id, nap_parent->num_children);

  NaClXMutexUnlock(&nap_parent->children_mu);

  NaClLog(1, "fork_num = %d, cage_id = %d\n", fork_num, nap_child->cage_id);
  if(!use_lkm || tl_type != THREAD_LAUNCH_FORK) {
    //exec not prevalidated
    if ((*mod_status = NaClAppLoadFileFromFilename(nap_child, nap_child->nacl_file)) != LOAD_OK) {
      NaClLog(1, "Error while loading \"%s\": %s\n", nap_child->nacl_file, NaClErrorString(*mod_status));
      NaClLog(LOG_FATAL, "%s\n%s\n",
                         "Using the wrong type of nexe (nacl-x86-32 on an x86-64 or vice versa) ",
                         "or a corrupt nexe file may be responsible for this error.");
    }
  } else {
    //we already know the fork child has an ok nexe, and we don't even need to load it
    nap_child->stack_size = nap_parent->stack_size;
    nap_child->static_text_end = nap_parent->static_text_end;
    nap_child->rodata_start = nap_parent->rodata_start;
    nap_child->data_start = nap_parent->data_start;
    nap_child->break_addr = nap_parent->break_addr;
    nap_child->data_end = nap_parent->data_end;
    nap_child->bundle_size = NACL_INSTR_BLOCK_SIZE;
    nap_child->initial_entry_pt = nap_parent->initial_entry_pt;
    nap_child->dynamic_text_start = nap_parent->dynamic_text_start;
    nap_child->text_shm = nap_parent->text_shm;
    NaClAllocAddrSpaceAslr(nap_child, NACL_ENABLE_ASLR);
    NaClInitSwitchToApp(nap_child); 
    //NaClMemoryProtection(nap_child);
  }

  if ((*mod_status = NaClAppPrepareToLaunch(nap_child)) != LOAD_OK) {
    NaClLog(LOG_FATAL, "Failed to prepare child nap_parent for launch\n");
  }
  NaClLog(1, "Loading blob file %s\n", nap_child->nacl_file);
  if (!nap_child->validator->readonly_text_implemented) {
    NaClLog(LOG_FATAL, "fixed_feature_cpu_mode is not supported\n");
  }

  NaClLog(1, "%s\n", "Enabling Fixed-Feature CPU Mode");
  nap_child->fixed_feature_cpu_mode = 1;
  if (!nap_child->validator->FixCPUFeatures(nap_child->cpu_features)) {
    NaClLog(LOG_FATAL, "This CPU lacks features required by fixed-function CPU mode.\n");
  }
  if (!NaClAppLaunchServiceThreads(nap_child)) {
    NaClLog(LOG_FATAL, "Launch service threads failed\n");
  }

  
  /* duplicate file descriptor table starting at child_fd = 3 (0-2 setup previously)*/
  NaClXMutexLock(&nap_parent->mu);

  for (int fd = 0; fd <= FILE_DESC_MAX; fd++) {

    /* Retrive the host fd we had stored in the Cage Table for the parent */
    int parent_host_fd = fd_cage_table[nap_parent->cage_id][fd];
    if (parent_host_fd == NACL_BAD_FD) {
      fd_cage_table[nap_child->cage_id][fd] = NACL_BAD_FD;
      continue;
    }
    /* Retrieve Parent NaCl Descriptor based on current child fd in the parent */
    struct NaClDesc *parent_nd;
    parent_nd = NaClGetDesc(nap_parent, parent_host_fd);
    if (!parent_nd) {
      continue;
    }

    /* Translate from NaCl Desc to Host Desc */
    struct NaClDescIoDesc *self = (struct NaClDescIoDesc *) &parent_nd->base;
    struct NaClHostDesc *parent_hd = self->hd;

    /* If we're creating an exec cage and we have CLOEXEC set, dont pass these on */
    if ((tl_type == THREAD_LAUNCH_EXEC) && (parent_hd->flags & NACL_ABI_O_CLOEXEC)) {
      fd_cage_table[nap_child->cage_id][fd] = NACL_BAD_FD;
      continue;
    }

    /* Create and set vars for child hd */
    struct NaClHostDesc *child_hd;
    child_hd = malloc(sizeof(*child_hd));
    if (!child_hd) {
        NaClLog(LOG_FATAL, "NaClChildNapCtor: Error initializing child descriptor\n");
    }

    child_hd->d = parent_hd->d;
    child_hd->flags = parent_hd->flags;
    child_hd->cageid = nap_child->cage_id;
    child_hd->userfd = parent_hd->userfd;

    /* Create and set new NaClDesc from Child HD in Child nap */
    int child_host_fd = NaClSetAvail(nap_child, ((struct NaClDesc *) NaClDescIoDescMake(child_hd)));

    NaClDescUnref(parent_nd);

    /* Set childs cage table with the current fd to the old parent host fd */
    fd_cage_table[nap_child->cage_id][fd] = child_host_fd;


    NaClLog(1, "NaClGetDesc() copied parent fd [%d] to child fd [%d]\n", fd);
  }
  NaClXMutexUnlock(&nap_parent->mu);

  return nap_child;
}

void WINAPI NaClAppThreadLauncher(void *state) {
  struct NaClAppThread *natp = (struct NaClAppThread *) state;
  struct NaClApp *nap = natp->nap;
  struct NaClThreadContext *context = &natp->user;
  enum NaClThreadLaunchType tl_type = nap->tl_type;

  uint32_t thread_idx;
  nacl_reg_t secure_stack_ptr;

  NaClLog(1, "%s\n", "NaClAppForkThreadLauncher: entered");

  NaClSignalStackRegister(natp->signal_stack);

  NaClLog(1, "     natp  = 0x%016"NACL_PRIxPTR"\n", (uintptr_t)natp);
  NaClLog(1, " prog_ctr  = 0x%016"NACL_PRIxNACL_REG"\n", natp->user.prog_ctr);
  NaClLog(1, "stack_ptr  = 0x%016"NACL_PRIxPTR"\n", NaClGetThreadCtxSp(&natp->user));

  thread_idx = NaClGetThreadIdx(natp);
  CHECK(thread_idx > 0 && thread_idx < NACL_THREAD_MAX);
  NaClTlsSetCurrentThread(natp);
  #if NACL_WINDOWS
    nacl_thread_ids[thread_idx] = GetCurrentThreadId();
  #elif NACL_OSX
    NaClSetCurrentMachThreadForThreadIndex(thread_idx);
  #endif

  if (tl_type == THREAD_LAUNCH_FORK){
      /*
    * We have to hold the threads_mu and children_mu locks until
    * after thread_num field in this thread has been initialized.
    * All other threads can only find and examine this natp through
    * the threads table, so the fact that natp is not consistent (no
    * thread_num) will not be visible.
    */
    NaClXMutexLock(&nap->threads_mu);
    NaClXMutexLock(&nap->children_mu);
    nap->num_threads = thread_idx + 1;
    natp->thread_num = thread_idx + 1;
    if (!DynArraySet(&nap->threads, natp->thread_num, natp)) {
      NaClLog(LOG_FATAL, "NaClAddThreadMu: DynArraySet at position %d failed\n", natp->thread_num);
    }
    NaClXMutexUnlock(&nap->threads_mu);
    NaClXMutexUnlock(&nap->children_mu);

    NaClVmHoleThreadStackIsSafe(natp->nap);

    NaClStackSafetyNowOnUntrustedStack();
  }
  else {
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

  }
  /*
    * Notify the debug stub, that a new thread is availible.
    */
  if (natp->nap->debug_stub_callbacks) {
    natp->nap->debug_stub_callbacks->thread_create_hook(natp);
  }

  if (tl_type == THREAD_LAUNCH_FORK) {
    #if !NACL_WINDOWS
      /*
      * Ensure stack alignment.  Stack pointer must be -8 mod 16 when no
      * __m256 objects are passed (8 mod 32 if __m256), after the call.
      * Note the current doc (as of 2009-12-09) at
      *
      *   https://github.com/Lind-Project/native_client/raw/fork_implementation/documentation/x86-64_ABI.pdf
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
      NaClLog(1, "NaClStartThreadInApp: secure stack:   0x%"NACL_PRIxNACL_REG"\n",
              secure_stack_ptr);
      secure_stack_ptr = secure_stack_ptr & ~0x1f;
      NaClLog(1, "NaClStartThreadInApp: adjusted stack: 0x%"NACL_PRIxNACL_REG"\n",
              secure_stack_ptr);
      natp->user.trusted_stack_ptr = secure_stack_ptr;
    #endif

    NaClLog(1, "NaClStackThreadInApp: user stack: 0x%"NACL_PRIxPTR"\n",
            NaClGetThreadCtxSp(context));
    NaClLog(1, "%s\n", "NaClStartThreadInApp: switching to untrusted code");

    NaClLog(1, "[NaClAppThreadLauncher] Nap %d is ready to launch! child registers: \n", nap->cage_id);
    NaClLogThreadContext(natp);
    NaClAppThreadPrintInfo(natp);
    CHECK(thread_idx == nacl_user[thread_idx]->tls_idx);

  }

    /*
    * After this NaClAppThreadSetSuspendState() call, we should not
    * claim any mutexes, otherwise we risk deadlock.
    */
    NaClAppThreadSetSuspendState(natp, NACL_APP_THREAD_TRUSTED, NACL_APP_THREAD_UNTRUSTED);

  /* Not exactly sure what hole exec falls into */
  if (tl_type == THREAD_LAUNCH_FORK) {
    #if NACL_WINDOWS
      /* This sets up a stack containing a return address that has unwind info. */
      NaClSwitchSavingStackPtr(context, &context->trusted_stack_ptr, NaClSwitchToApp);
    #else
      NaClSwitchToApp(natp);
    #endif
  }
  else {
    NaClLog(1, "%s\n", "[NaCl Main Loader] User program about to start running inside the cage!");
    NaClStartThreadInApp(natp, natp->user.prog_ctr);
  }
}


void NaClAppThreadTeardownChildren(struct NaClAppThread *natp) {
  struct NaClApp  *nap = natp->nap;
  struct NaClApp  *nap_parent = nap->parent;
  size_t          thread_idx;

  /* remove self from parent's list of children */
  if (nap_parent) {
    NaClXMutexLock(&nap_parent->children_mu);
    nap_parent->num_children--;
    NaClLog(1, "[parent %d] new child count: %d\n", nap_parent->cage_id, nap_parent->num_children);
    if (!DynArraySet(&nap_parent->children, nap->cage_id, NULL)) {
      NaClLog(1, "[NaClAppThreadTeardown][parent %d] did not find cage to remove: cage_id = %d\n", nap_parent->cage_id, nap->cage_id);
    }
    else {
      NaClLog(1, "[NaClAppThreadTeardown][parent %d] removed cage: cage_id = %d\n", nap_parent->cage_id, nap->cage_id);
    }
    NaClXCondVarBroadcast(&nap_parent->children_cv);
    NaClXMutexUnlock(&nap_parent->children_mu);

    NaClXMutexLock(&ccmut);
    cagecount--;
    NaClXCondVarBroadcast(&cccv);
    NaClXMutexUnlock(&ccmut);
  }
}

/*
 * preconditions:
 * * natp must be thread_self(), called while holding no locks.
 */
void NaClAppThreadTeardownInner(struct NaClAppThread *natp, bool active_thread) {
  struct NaClApp  *nap = natp->nap;
  struct NaClApp  *nap_parent = nap->parent;
  size_t          thread_idx;


  /*
   * mark this thread as dead; doesn't matter if some other thread is
   * asking us to commit suicide.
   */
  NaClLog(1, "[NaClAppThreadTeardown] cage id: %d\n", nap->cage_id);

  if (nap->debug_stub_callbacks) {
    NaClLog(3, " notifying the debug stub of the thread exit\n");
    /*
     * This must happen before deallocating the ID natp->thread_num.
     * We have the invariant that debug stub lock should be acquired before
     * nap->threads_mu lock. Hence we must not hold threads_mu lock while
     * calling debug stub hooks.
     */
    nap->debug_stub_callbacks->thread_exit_hook(natp);
  }

  // if we're not active, we're getting cleaned up so we lock outside for efficiency
  if (active_thread) {
    NaClLog(3, " getting thread table lock\n");
    NaClXMutexLock(&nap->threads_mu);
  }

  NaClLog(3, " getting thread lock\n");
  NaClXMutexLock(&natp->mu);

  /*
   * Remove ourselves from the ldt-indexed global tables.  The ldt
   * entry is released as part of NaClAppThreadDelete(), and if
   * another thread is immediately created (from some other running
   * thread) we want to be sure that any ldt-based lookups will not
   * reach this dying thread's data.
   */
  thread_idx = NaClGetThreadIdx(natp);


  if (natp->is_cage_mainthread) {
    // handle children upon exit
    NaClAppThreadTeardownChildren(natp);

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
  }
  /*
   * Unset the TLS variable so that if a crash occurs during thread
   * teardown, the signal handler does not dereference a dangling
   * NaClAppThread pointer.
   */
  if (active_thread) NaClTlsSetCurrentThread(NULL);

  NaClLog(3, " removing thread from thread table\n");
  /* Deallocate the ID natp->thread_num. */
  NaClRemoveThreadMu(nap, natp->thread_num);
  NaClLog(3, " unlocking thread\n");
  NaClXMutexUnlock(&natp->mu);

  // again we trigger the lock outside for non-active threads, we also cant unregister the sig stack
  // here so lets destroy everything
  if (active_thread) {
    NaClLog(3, " unlocking thread table\n");
    NaClXMutexUnlock(&nap->threads_mu);
    NaClLog(3, " unregistering signal stack\n");
    NaClSignalStackUnregister();
  }


  if (natp->is_cage_mainthread) {
    if (nap->tl_type!=THREAD_LAUNCH_FORK) NaClXCondVarWait(&nap->exit_cv, &nap->exit_mu);
    NaClAppDtor(nap);
  }

  NaClLog(3, " freeing thread object\n");
  NaClAppThreadDelete(natp);
  
  // if were handling threads, we'll call pthread_cancel from outside, otherwise lets leave
  if (active_thread) {
    NaClLog(3, " NaClThreadExit\n");
    NaClThreadExit();
    NaClLog(LOG_FATAL, "NaClAppThreadTeardown: NaClThreadExit() should not return\n");
    /* NOTREACHED */
  }
}


void NaClAppThreadTeardown(struct NaClAppThread *natp) {
  NaClAppThreadTeardownInner(natp, true);
}


struct NaClAppThread *NaClAppThreadMake(struct NaClApp *nap,
                                        uintptr_t      usr_entry,
                                        uintptr_t      usr_stack_ptr,
                                        uint32_t       user_tls1,
                                        uint32_t       user_tls2) {
  struct NaClAppThread *natp;
  uint32_t tls_idx;

  natp = NaClAlignedMalloc(sizeof(*natp), __alignof(struct NaClAppThread));
  if (!natp) {
    return NULL;
  }

  NaClLog(4, "         natp = 0x%016"NACL_PRIxPTR"\n", (uintptr_t) natp);
  NaClLog(4, "          nap = 0x%016"NACL_PRIxPTR"\n", (uintptr_t) nap);
  NaClLog(4, "    usr_entry = 0x%016"NACL_PRIxPTR"\n", usr_entry);
  NaClLog(4, "usr_stack_ptr = 0x%016"NACL_PRIxPTR"\n", usr_stack_ptr);

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

void NaClForkThreadContextSetup(struct NaClAppThread     *natp_parent,
                              struct NaClAppThread     *natp_child,
                              void *stack_ptr_parent,
                              void *stack_ptr_child) {

    size_t stack_ptr_offset;
    size_t base_ptr_offset;
    struct NaClApp *nap_parent = natp_parent->nap;
    struct NaClApp *nap_child = natp_child->nap;
    /* make a copy of parent and child thread context */

    struct NaClThreadContext parent_ctx = natp_parent->user;  
    struct NaClThreadContext child_ctx = natp_child->user;

    stack_ptr_offset = parent_ctx.rsp - (uintptr_t)stack_ptr_parent;
    base_ptr_offset = parent_ctx.rbp - (uintptr_t)stack_ptr_parent;
    /* copy parent page tables and execution context */
    NaClCopyExecutionContext(nap_parent, nap_child, parent_ctx.rsp);
    NaClLog(1, "child cage_id: [%d], parent cage id: [%d]\n",
            nap_child->cage_id,
            nap_parent->cage_id);
    NaClLog(1, "%s\n", "Thread context of child before copy");
    NaClLogThreadContext(natp_child);
    natp_child->user = natp_parent->user;
    NaClLog(1, "%s\n", "Thread context of child after copy");
    NaClLogThreadContext(natp_child);

    /*
    * adjust trampolines and %rip
    */
    nap_child->mem_start = child_ctx.r15;
    natp_child->user.r15 = nap_child->mem_start;
    natp_child->user.rsp = (uintptr_t)stack_ptr_child + stack_ptr_offset;
    natp_child->user.rbp = (uintptr_t)stack_ptr_child + base_ptr_offset;
    natp_child->user.sysret = 0;

  /* examine arbitrary stack values */
  #if defined(_DEBUG)
  # define NUM_STACK_VALS 16
  # define OUTPUT_FMT "0x%016lx"
  # define TYPE_TO_EXAMINE uintptr_t
  # define EXAMINE_ADDR(TYPE, FMT, ADDR)                                                             \
          do {                                                                                       \
            unsigned char *addr = (unsigned char *)(ADDR);                                           \
            UNREFERENCED_PARAMETER(addr);                                                            \
            NaClLog(2, "[Memory] Memory addr:                   %p\n", (void *)addr);                \
            NaClLog(2, "[Memory] Memory content (byte-swapped): " FMT "\n", (TYPE)OBJ_REP_64(addr)); \
            NaClLog(2, "[Memory] Memory content (raw):          " FMT "\n", *(TYPE *)addr);          \
          } while (0)
    for (size_t i = 0; i < NUM_STACK_VALS; i++) {
      NaClLog(2, "child_stack[%zu]:\n", i);
      EXAMINE_ADDR(TYPE_TO_EXAMINE, OUTPUT_FMT, (TYPE_TO_EXAMINE *)stack_ptr_child + i);
      NaClLog(2, "parent_stack[%zu]:\n", i);
      EXAMINE_ADDR(TYPE_TO_EXAMINE, OUTPUT_FMT, (TYPE_TO_EXAMINE *)stack_ptr_parent + i);
    }
    for (size_t i = 0; i < NUM_STACK_VALS; i++) {
      uintptr_t child_addr = (uintptr_t)((TYPE_TO_EXAMINE *)natp_child->user.rsp + i);
      uintptr_t parent_addr = (uintptr_t)((TYPE_TO_EXAMINE *)parent_ctx.rsp + i);
      NaClLog(2, "child_rsp[%zu]:\n", i);
      EXAMINE_ADDR(TYPE_TO_EXAMINE, OUTPUT_FMT, child_addr);
      NaClLog(2, "parent_rsp[%zu]:\n", i);
      EXAMINE_ADDR(TYPE_TO_EXAMINE, OUTPUT_FMT, parent_addr);
    }
  # undef NUM_STACK_VALS
  # undef OUTPUT_FMT
  # undef TYPE_TO_EXAMINE
  # undef EXAMINE_ADDR
  #endif /* defined(_DEBUG) */
}

int NaClAppThreadSpawn(struct NaClAppThread     *natp_parent,
                       struct NaClApp           *nap_child,
                       uintptr_t                usr_entry,
                       uintptr_t                sys_stack_ptr,
                       uint32_t                 user_tls1,
                       uint32_t                 user_tls2,
                       bool                     cage_thread){


  void *stack_ptr_parent;
  void *stack_ptr_child;
  uintptr_t usr_stack_ptr;

  struct NaClAppThread *natp_child;
  struct NaClApp *nap_parent;
  static THREAD int ignored_ret;
  enum NaClThreadLaunchType tl_type = nap_child->tl_type;



  if (tl_type == THREAD_LAUNCH_FORK) {
    nap_parent = natp_parent->nap;
    if (!nap_parent->running) return 0;

    NaClXMutexLock(&nap_parent->mu);
    NaClXMutexLock(&nap_child->mu);

    /* guard against extra spawned instances */
    if (nap_child->in_fork) {
    goto already_running;
    }
    nap_child->in_fork = 1;
  

    nap_child->stack_size = nap_parent->stack_size;
    stack_ptr_parent = (void *)NaClUserToSysAddr(nap_parent, NaClGetInitialStackTop(nap_parent));
    stack_ptr_child = (void *)NaClUserToSysAddr(nap_child, NaClGetInitialStackTop(nap_child));
    
    usr_stack_ptr = NaClSysToUserStackAddr(nap_child, (uintptr_t)stack_ptr_child);
  }
  else usr_stack_ptr = NaClSysToUserStackAddr(nap_child, (uintptr_t)sys_stack_ptr);

  /* Make new/child thread natp */
  natp_child = NaClAppThreadMake(nap_child, usr_entry, usr_stack_ptr, user_tls1, user_tls2);

  if (!natp_child) return 0;

  if (cage_thread){
    nap_child->parent = NULL;
  }
  else if (tl_type == THREAD_LAUNCH_FORK) {
    NaClForkThreadContextSetup(natp_parent, natp_child, stack_ptr_parent, stack_ptr_child);
  }
 

  /*
   * setup TLS slot in the global nacl_user array for Fork/Exec
   */
  if ((tl_type == THREAD_LAUNCH_FORK) || (tl_type == THREAD_LAUNCH_EXEC)) {
    natp_child->user.tls_idx = nap_child->cage_id;
    if (nacl_user[natp_child->user.tls_idx]) {
      NaClLog(1, "nacl_user[%u] not NULL (%p)\n)",
              natp_child->user.tls_idx,
              (void *)nacl_user[natp_child->user.tls_idx]);
      goto already_running;
    }
    nacl_user[natp_child->user.tls_idx] = &natp_child->user;
    NaClTlsSetTlsValue1(natp_child, user_tls1);
    NaClTlsSetTlsValue2(natp_child, user_tls2);
  }


  if (tl_type != THREAD_LAUNCH_THREAD) {
    natp_child->is_cage_mainthread = true;
    natp_child->cage_mainthread = NULL;
    natp_child->tearing_down = false;
  } 
  else {
    natp_child->is_cage_mainthread = false;
    natp_child->cage_mainthread = natp_parent;
  }

  /*
   * We set host_thread_is_defined assuming, for now, that
   * NaClThreadCtor() will succeed.
   */
  natp_child->host_thread_is_defined = 1;

  if (tl_type == THREAD_LAUNCH_FORK){
    NaClXCondVarBroadcast(&nap_parent->cv);
    NaClXMutexUnlock(&nap_parent->mu);
    NaClXMutexUnlock(&nap_child->mu);

    /* TODO: figure out a better way to avoid extra instance spawns -jp */
    NaClThreadYield();
    NaClXMutexLock(&nap_child->mu);
    nap_child->in_fork = 0;
    NaClXMutexUnlock(&nap_child->mu);
  }



  if (!NaClThreadCtor(&natp_child->host_thread, NaClAppThreadLauncher, natp_child, NACL_KERN_STACK_SIZE)) {
    /*
    * No other thread saw the NaClAppThread, so it is OK that
    * host_thread was not initialized despite host_thread_is_defined
    * being set.
    */
    natp_child->host_thread_is_defined = 0;
    NaClAppThreadDelete(natp_child);
    return 0;
  }

  return 1;

already_running:
    NaClXCondVarBroadcast(&nap_parent->cv);
    NaClXMutexUnlock(&nap_parent->mu);
    NaClXMutexUnlock(&nap_child->mu);
    pthread_exit(&ignored_ret);
}

/*
 * preconditions:
 *  * natp must _not_ be running
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


/**
 * The following functions are used to reap any cages which have received a fatal signal.
 * On launch, sel_main creates the Reaper thread which calls the fault teardown functions when
 * a faulted thread is caught in the signal handler (nacl_signal.c)
 * 
 * The fault teardown function will cycle through all child threads in cage,
 * tear them down, and call pthread_cancle upon them
 * 
 * Finally it will exit the parent thread and signal that the cage has exited with SIGKILL
 * 
 * Note: We implement it this way because
 * 1. We can't fully teardown threads within the signal handler since
 *  a. We can't unregister/unmap the handler while within itself
 *  b. Most libc functions are invalid within the handler
 * 2. We need to not only teardown the faulting thread itself, but any other threads that have been
 *    launched wtihin that cage.
 */


void InitFatalThreadTeardown(void) {
  if (!NaClMutexCtor(&teardown_mutex)) {
    NaClLog(LOG_FATAL, "%s\n", "Failed to initialize handler cleanup mutex");
  }
    if (!NaClMutexCtor(&reapermut)) {
    NaClLog(LOG_FATAL, "%s\n", "Failed to initialize reaper mutex");
  }
    if (!NaClCondVarCtor(&reapercv)) {
    NaClLog(LOG_FATAL, "%s\n", "Failed to initialize reaper cv");
  }
}

void DestroyFatalThreadTeardown(void) {
  NaClMutexDtor(&teardown_mutex);
  NaClCondVarDtor(&reapercv);
  NaClMutexDtor(&reapermut);
}


void AddToFatalThreadTeardown(struct NaClAppThread *natp) {
    if (natp_to_teardown == natp) return;
    NaClXMutexLock(&teardown_mutex);
    natp_to_teardown = natp;
    natp->tearing_down = true;
    NaClXCondVarBroadcast(&reapercv);
    NaClXMutexUnlock(&teardown_mutex);
}

void FatalThreadTeardown(void) {
  struct NaClThread *thread;
  int status = 137; // Fatal error signal SIGKILL

  if ((natp_to_teardown != NULL) && !in_teardown) {
    NaClXMutexLock(&teardown_mutex);
    in_teardown = true;
    struct NaClApp *nap = natp_to_teardown->nap;

    NaClXMutexLock(&nap->threads_mu);
    int num_threads = NaClGetNumThreads(nap);

    for(int i = 0; i < num_threads; i++) {

      struct NaClAppThread *natp_child = NaClGetThreadMu(nap, i);
      if (natp_child && natp_child != natp_to_teardown) {
        struct NaClThread *child_thread;
        child_thread = &natp_child->host_thread;
        NaClAppThreadTeardownInner(natp_child, false);
        NaClThreadCancel(child_thread);
      }
    }
    
    lind_exit(status, nap->cage_id);
    (void) NaClReportExitStatus(nap, NACL_ABI_W_EXITCODE(status, 0));
    thread = &natp_to_teardown->host_thread;
    NaClXMutexUnlock(&nap->threads_mu);

    NaClAppThreadTeardownInner(natp_to_teardown, false);
    NaClThreadCancel(thread);
    natp_to_teardown = NULL;

    in_teardown = false;
    NaClXMutexUnlock(&teardown_mutex);
  }
}

void ThreadReaper(void* arg) {
  while (reap) {
    NaClXCondVarWait(&reapercv, &reapermut);
    FatalThreadTeardown();
  }
}

void LaunchThreadReaper(void) {
  InitFatalThreadTeardown();
  if (!NaClThreadCtor(&reaper, ThreadReaper, NULL, NACL_KERN_STACK_SIZE)) {
    NaClLog(LOG_FATAL, "%s\n", "Failed to initialize reaper");
  }
}

void DestroyReaper(void) {
  reap = false;
  NaClXCondVarBroadcast(&reapercv);
  DestroyFatalThreadTeardown();
  NaClThreadCancel(&reaper);
}


void NaClAppThreadPrintInfo(struct NaClAppThread *natp) {
  NaClLog(1, "[NaClAppThreadPrintInfo] "
          "cage id = %d, prog_ctr = %#lx, new_prog_ctr = %#lx, sysret = %#lx\n",
          natp->nap->cage_id,
          (unsigned long)natp->user.prog_ctr,
          (unsigned long)natp->user.new_prog_ctr,
          (unsigned long)natp->user.sysret);
}
