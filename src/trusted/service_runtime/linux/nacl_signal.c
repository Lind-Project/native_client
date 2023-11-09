/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>

#include "native_client/src/include/nacl_macros.h"
#include "native_client/src/include/portability_io.h"
#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_exit.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/trusted/service_runtime/arch/sel_ldr_arch.h"
#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
#include "native_client/src/trusted/service_runtime/nacl_exception.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_signal.h"
#include "native_client/src/trusted/service_runtime/nacl_tls.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/sel_rt.h"
#include "native_client/src/trusted/service_runtime/thread_suspension.h"
#include "native_client/src/trusted/service_runtime/nacl_stack_safety.h"
#include "native_client/src/trusted/service_runtime/nacl_switch_to_app.h"


/*
 * This module is based on the Posix signal model.  See:
 * http://www.opengroup.org/onlinepubs/009695399/functions/sigaction.html
 */

/*
 * ----------------------------------------------------------------------------------------------- *
 *                The overall architecture of the untrusted signal handling system:                *
 * ----------------------------------------------------------------------------------------------- *
 *
 * When a a caught signal is recieved, we want to allow untrusted signal
 * handlers to run. This involves a large number of considerations for different
 * cases and the general architecture of that whole system is laid out here.
 *
 *
 * Sigaction & SignalCatch
 * -----------------------
 * The signal handler SignalCatch is registered in the function NaClSignalHandlerInit
 * which sets a sigmask containing all NaCl handled signals on signal receipt.
 *
 * This SignalCatch function is used in various contexts, including plenty of cases
 * which are not supposed to be handled in untrusted, such as NaCl internal signals
 * and signals to threads which execute no untrusted code. It sets up the sig_ctx
 * field which contains the register state of the program when the signal was received
 * as well as the is_untrusted variable by checking whether the instruction pointer
 * when the signal was received was in trusted or untrusted code. Other than some
 * checks for a signal that is not user-generated, the next point of interest in the
 * execution of untrusted signal handlers is the function DispatchToUntrustedHandler.
 *
 *
 * 32 byte alignment & single stepping
 * -----------------------------------
 * Before we get too deep into that, it is worth making a point on NaCl's security model
 * which requires that all jump targets be 32 byte aligned. This serves the practial
 * purpose of preventing the user from jumping into the middle of an instruction. Because
 * we may, after running a signal handler, return to the point of last execution as specified
 * by a field on the stack, and because the user can modify this at will, it is important
 * for us security-wise to return to 32 byte aligned addresses. However, this may lead to
 * incorrect behavior when the signal is not received on an instruction that is 32 byte aligned.
 * Thus, we need to ensure that all handled signals are received only on 32 byte aligned
 * addresses, although there is no direct way to do this. We had to get creative with how to
 * accomplish this. We set the TRAP flag in x86 (0x100 in EFLAGS) when we recieve a signal at
 * an untrusted instruction of an offset not divisible by 32, thus causing every subsequent
 * instruction to raise a SIGTRAP signal, allowing us to essentially single-step the processor
 * until we reach a 32 byte aligned instruction address, at which point we unset the TRAP flag
 * and are able to run the untrusted signal handler as if the signal were recieved there.
 * No instructions or pseudo-instructions can be allowed to cross a 32 byte alignment boundary.
 * Also all jump targets are 32 byte aligned and this means that at any point in untrusted we must
 * be able to reach a 32 byte aligned address in normal execution very quickly--either the next
 * 32 byte aligned address from sequential execution or the next jump target must be 32 byte
 * aligned. We don't need to do this for signals caught in trusted code as we don't execute
 * the signal handler until we return from trusted, and the point in untrusted we wish to
 * return to from the signal handler is the point where trusted was going to return to anyway
 * which means that it must have been 32 byte aligned. It is possible that we catch a signal
 * first in untrusted and the next 32 byte aligned address is in trusted code, however that
 * situation poses no problem, and aside from the unsetting of the trap flag is handled
 * like a normal signal received in trusted code.
 * Because single stepping uses the trap flag it is incredibly difficult to pair well with
 * gdb and especially rr and so you should be aware that any programs which end up single
 * stepping may be a lot harder to debug, and weird behavior may happen within a debugger.
 *
 *
 * DispatchToUntrustedHandler: Initial
 * -----------------------------------
 * DispatchToUntrustedHandler performs the majority of setup work for the execution of
 * an untrusted handler, finding the register state that we want to set in order to execute
 * the untrusted handler and allow returning from it. The first thing we do is check if we
 * are still single stepping, if so we check if we've reached a 32 byte aligned address and
 * if so stop single stepping--unset the TRAP flag in untrusted and the bookkeeping in the natp.
 * Otherwise we return and indicate by return code to SignalCatch that we wish to return from it
 * immediately after copying out register state--this will cause the sigreturn syscall to be
 * executed which importantly restores the flags register from the copied out values including
 * the trap flag which remains there.
 *
 * If there is no untrusted handler in the signal received, return and indicate that SignalCatch
 * treat the signal as unhandled which for us means terminate. This should change in the future
 * when we actually handle signal disposition. This untrusted handler is stored as an address in
 * rust.
 * If we're in untrusted we need to check if we need to activate single stepping mode which is
 * handled by setting the SIGTRAP flag in the user space registers, and doing some natp bookkeeping.
 * Then we return as discussed in the 32 byte alignment & single stepping section
 *
 *
 * DispatchToUntrustedHandler: Trusted special cases
 * -------------------------------------------------
 * If the signal is received while executing trusted code however, we need to handle a wide number
 * of cases. This is because there are quite a large number of edge cases in trusted code. The first
 * is simply if we receive a signal in the first few instructions of a syscall, we can not rely on
 * the natp being properly populated. Second, if we receive a signal in the last few instructions
 * of a syscall, we may have already made some decisions on what to spit out to untrusted which may
 * have been made differently had the signal ocurred already so we need to rerun the system call
 * exit code.
 * The other two special cases involve the functions NaClGetTlsFastPath1 and 2. These funcitons
 * have a special pathway into trusted code from any other syscall, and thus must be handled
 * separately. Additionally, they modify the stack pointer halfway through so we must account
 * for that as well. All of these special cases are signified by the lack of the natp->signatpflag
 * which is a flag that is set whenever the natp in a normal syscall is prepared for a signal
 * receive and has not yet had any parts of it copied out. We determine which case is which of
 * the four aforemntioned special cases by statically checking the address of the instruction
 * pointer against the known bounds of these functions.
 * For all but the tls syscall cases we must set the natp->signalpending flag which signifies that
 * we must be aware that a signal handler is the next untrusted code to be executed on exit from
 * trusted code, and decisions are made based on it in NaClSwitchToApp.
 *
 *
 * DispatchToUntrustedHandler: Stack handling
 * ------------------------------------------
 * After we handle those special cases we must deposit the untrusted registers on the stack for
 * restoration upon return from the signal handler. However, we must respect the redzone of the
 * stack as well as allocate enough space to store these registers in the struct NaClExceptionFrame.
 * when the signal is caught in untrusted code the registers we want to restore are in the regs
 * variable copied out from the ucontext field. However, when the signal is caught in trusted code,
 * we only want to restore the callee save registers in the natp. We also may want to send the
 * return value of the syscall in rax back to untrusted upon signal handler return. After this,
 * practically all the relevant information is set up for signal handling, and we return to
 * SignalCatch.
 *
 *
 * SignalCatch: Restoration to previous point of execution
 * -------------------------------------------------------
 * SignalCatch, if the DispatchToUntrustedHandler returned at the end of all that successfully,
 * does different things for untrusted and trusted code. For the tls fast path function cases it
 * does something yet different and just puts the untrusted handler address into the register
 * whose value is the address returned to at the end of the tls fast path functions and restores
 * all relevant registers' values to what they are in the regs field and return execution to where
 * the signal was received by restoring the callee saved registers and rip. For untrusted code we
 * restore only the registers relevant to the handler--these being rip and rsp for obvious reasons
 * and rdi to store the first argument, the signal number. We don't support the extended signal
 * return arguments in lind yet so we don't need to handle a siginfo_t or anything. For trusted
 * code we restore every single register and then return execution to the point in trusted we
 * were stopped at.
 *
 * In trusted, when the syscall a signal was received in wishes to return, it calls NaClSwitchToApp
 * which in turn calls NaClmaskRestore which in case the pendingsignal flag is set unsets it and
 * modifies the rax value to be restored on signal handler return based on the syscall return value.
 *
 *
 * For what happens on return from an untrusted signal handler see the comment above the function
 * NaClTrampolineRegRestore in arch/x86_64/nacl_syscall_64.S
 *
 * - Jonathan Singer
 */

/*
 * The signals listed here should either be handled by NaCl (or otherwise
 * trusted) or have handlers that are expected to crash.
 * Signals for which handlers are expected to crash should be listed
 * in the NaClSignalHandleCustomCrashHandler function below.
 */
static int s_Signals[] = {
#if NACL_ARCH(NACL_BUILD_ARCH) != NACL_mips
  /* This signal does not exist on MIPS. */
  SIGSTKFLT,
#endif
  SIGSYS, /* Used to support a seccomp-bpf sandbox. */
  NACL_THREAD_SUSPEND_SIGNAL,
  SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV, SIGCHLD, SIGALRM, SIGPIPE,
  /* Handle SIGABRT in case someone sends it asynchronously using kill(). */
  SIGABRT, SIGUSR1, SIGUSR2
};

static struct sigaction s_OldActions[NACL_ARRAY_SIZE_UNSAFE(s_Signals)];

static NaClSignalHandler g_handler_func;
uint32_t lindgetsighandler(uint64_t cagenum, int signo);

extern char NaClSyscallCSegHook;
extern char NaClSyscallCSegHookInitialized; //These are not real function pointers but we just need the address
extern void NaClSyscallSeg(void);
extern char NaClSyscallSegEnd;
extern char NaClGetTlsFastPath1;
extern char NaClGetTlsFastPath1RspRestored;
extern char NaClGetTlsFastPath1End;
extern char NaClGetTlsFastPath2;
extern char NaClGetTlsFastPath2RspRestored;
extern char NaClGetTlsFastPath2End;

void NaClSignalHandlerSet(NaClSignalHandler func) {
  g_handler_func = func;
}

void PrintNaClSignalRegisters(const struct NaClSignalContext *ctx) {
    printf("rax: 0x%016llx\n", ctx->rax);
    printf("rbx: 0x%016llx\n", ctx->rbx);
    printf("rcx: 0x%016llx\n", ctx->rcx);
    printf("rdx: 0x%016llx\n", ctx->rdx);
    printf("rsi: 0x%016llx\n", ctx->rsi);
    printf("rdi: 0x%016llx\n", ctx->rdi);
    printf("rbp: 0x%016llx\n", ctx->rbp);
    printf("stack_ptr: 0x%016llx\n", ctx->stack_ptr);
    printf("r8: 0x%016llx\n", ctx->r8);
    printf("r9: 0x%016llx\n", ctx->r9);
    printf("r10: 0x%016llx\n", ctx->r10);
    printf("r11: 0x%016llx\n", ctx->r11);
    printf("r12: 0x%016llx\n", ctx->r12);
    printf("r13: 0x%016llx\n", ctx->r13);
    printf("r14: 0x%016llx\n", ctx->r14);
    printf("r15: 0x%016llx\n", ctx->r15);
    printf("prog_ctr: 0x%016llx\n", ctx->prog_ctr);
}

void PrintUserRegisters(const struct NaClAppThread *natp) {
    printf("rax: 0x%016llx\n", natp->user.rax);
    printf("rbx: 0x%016llx\n", natp->user.rbx);
    printf("rcx: 0x%016llx\n", natp->user.rcx);
    printf("rdx: 0x%016llx\n", natp->user.rdx);
    printf("rbp: 0x%016llx\n", natp->user.rbp);
    printf("rsi: 0x%016llx\n", natp->user.rsi);
    printf("rdi: 0x%016llx\n", natp->user.rdi);
    printf("rsp: 0x%016llx\n", natp->user.rsp);
    printf("r8: 0x%016llx\n", natp->user.r8);
    printf("r9: 0x%016llx\n", natp->user.r9);
    printf("r10: 0x%016llx\n", natp->user.r10);
    printf("r11: 0x%016llx\n", natp->user.r11);
    printf("r12: 0x%016llx\n", natp->user.r12);
    printf("r13: 0x%016llx\n", natp->user.r13);
    printf("r14: 0x%016llx\n", natp->user.r14);
    printf("r15: 0x%016llx\n", natp->user.r15);
    printf("prog_ctr: 0x%016llx\n", natp->user.prog_ctr);
    printf("new_prog_ctr: 0x%016llx\n", natp->user.new_prog_ctr);
}

// A large prime number for the hash modulo operation
#define HASH_PRIME 0xFFFFFFFFFFFFFFC5ull

uint64_t HashNaClSignalRegisters(const struct NaClSignalContext *ctx) {
    uint64_t sum = 0;
    sum += ctx->rax;
    sum += ctx->rbx;
    sum += ctx->rcx;
    sum += ctx->rdx;
    sum += ctx->rsi;
    sum += ctx->rdi;
    sum += ctx->rbp;
    sum += ctx->stack_ptr;
    sum += ctx->r8;
    sum += ctx->r9;
    sum += ctx->r10;
    sum += ctx->r11;
    sum += ctx->r12;
    sum += ctx->r13;
    sum += ctx->r14;
    sum += ctx->r15;
    sum += ctx->prog_ctr;
    // Apply a simple hash function by taking the sum modulo a large prime number
    return sum % HASH_PRIME;
}

uint64_t HashUserRegisters(const struct NaClAppThread *natp) {
    uint64_t sum = 0;
    sum += natp->user.rax;
    sum += natp->user.rbx;
    sum += natp->user.rcx;
    sum += natp->user.rdx;
    sum += natp->user.rbp;
    sum += natp->user.rsi;
    sum += natp->user.rdi;
    sum += natp->user.rsp;
    sum += natp->user.r8;
    sum += natp->user.r9;
    sum += natp->user.r10;
    sum += natp->user.r11;
    sum += natp->user.r12;
    sum += natp->user.r13;
    sum += natp->user.r14;
    sum += natp->user.r15;
    sum += natp->user.prog_ctr;
    sum += natp->user.new_prog_ctr;
    // Apply a simple hash function by taking the sum modulo a large prime number
    return sum % HASH_PRIME;
}





/*
 * Returns, via is_untrusted, whether the signal happened while
 * executing untrusted code.
 *
 * Returns, via result_thread, the NaClAppThread that untrusted code
 * was running in.
 *
 * Note that this should only be called from the thread in which the
 * signal occurred, because on x86-64 it reads a thread-local variable
 * (nacl_current_thread).
 */
static void GetCurrentThread(const struct NaClSignalContext *sig_ctx,
                             int *is_untrusted,
                             struct NaClAppThread **result_thread) {
#if NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86 && NACL_BUILD_SUBARCH == 32
  /*
   * For x86-32, if %cs does not match, it is untrusted code.
   *
   * Note that this check might not be valid on Mac OS X, because
   * thread_get_state() does not return the value of NaClGetGlobalCs()
   * for a thread suspended inside a syscall.  However, this code is
   * not used on Mac OS X.
   */
  *is_untrusted = (NaClGetGlobalCs() != sig_ctx->cs);
  *result_thread = NaClAppThreadGetFromIndex(sig_ctx->gs >> 3);
#elif (NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86 && NACL_BUILD_SUBARCH == 64) || \
      NACL_ARCH(NACL_BUILD_ARCH) == NACL_arm || \
      NACL_ARCH(NACL_BUILD_ARCH) == NACL_mips
  struct NaClAppThread *natp = NaClTlsGetCurrentThread();
  if (natp == NULL) {
    *is_untrusted = 0;
    *result_thread = NULL;
  } else {
    /*
     * Get the address of an arbitrary local, stack-allocated variable,
     * just for the purpose of doing a sanity check.
     */
    void *pointer_into_stack = &natp;
    /*
     * Sanity check: Make sure the stack we are running on is not
     * allocated in untrusted memory.  This checks that the alternate
     * signal stack is correctly set up, because otherwise, if it is
     * not set up, the test case would not detect that.
     *
     * There is little point in doing a CHECK instead of a DCHECK,
     * because if we are running off an untrusted stack, we have already
     * lost.
     */
    DCHECK(!NaClIsUserAddr(natp->nap, (uintptr_t) pointer_into_stack));
    *is_untrusted = NaClIsUserAddr(natp->nap, sig_ctx->prog_ctr);
    *result_thread = natp;
  }
#else
# error Unsupported architecture
#endif

  /*
   * Trusted code could accidentally jump into sandbox address space,
   * so don't rely on prog_ctr on its own for determining whether a
   * crash comes from untrusted code.  We don't want to restore
   * control to an untrusted exception handler if trusted code
   * crashes.
   */
  if (*is_untrusted &&
      ((*result_thread)->suspend_state & NACL_APP_THREAD_UNTRUSTED) == 0) {
    *is_untrusted = 0;
  }
}

/*
 * If |sig| had a handler that was expected to crash, exit.
 */
static void NaClSignalHandleCustomCrashHandler(int sig) {
  /* Only SIGSYS is expected to have a custom crash handler. */
  if (sig == SIGSYS) {
    char tmp[128];
    SNPRINTF(tmp, sizeof(tmp),
        "\n** Signal %d has a custom crash handler but did not crash.\n",
        sig);
    NaClSignalErrorMessage(tmp);
    NaClExit(-sig);
  }
}

static void FindAndRunHandler(int sig, siginfo_t *info, void *uc) {
  unsigned int a;

  /* If we need to keep searching, try the old signal handler. */
  for (a = 0; a < NACL_ARRAY_SIZE(s_Signals); a++) {
    /* If we handle this signal */
    if (s_Signals[a] == sig) {
      /* If this is a real sigaction pointer... */
      if ((s_OldActions[a].sa_flags & SA_SIGINFO) != 0) {
        /*
         * On Mac OS X, sigaction() can return a "struct sigaction"
         * with SA_SIGINFO set but with a NULL sa_sigaction if no
         * signal handler was previously registered.  This is allowed
         * by POSIX, which does not require a struct returned by
         * sigaction() to be intelligible.  We check for NULL here to
         * avoid a crash.
         */
        if (s_OldActions[a].sa_sigaction != NULL) {
          /* then call the old handler. */
          s_OldActions[a].sa_sigaction(sig, info, uc);
          NaClSignalHandleCustomCrashHandler(sig);
          break;
        }
      } else {
        /* otherwise check if it is a real signal pointer */
        if ((s_OldActions[a].sa_handler != SIG_DFL) &&
            (s_OldActions[a].sa_handler != SIG_IGN)) {
          /* and call the old signal. */
          s_OldActions[a].sa_handler(sig);
          NaClSignalHandleCustomCrashHandler(sig);
          break;
        }
      }
      /*
       * We matched the signal, but didn't handle it, so we emulate
       * the default behavior which is to exit the app with the signal
       * number as the error code.
       */
      NaClExit(-sig);
    }
  }
}

/*
 * This function checks whether we can dispatch the signal to an
 * untrusted exception handler.  If we can, it modifies the register
 * state to call the handler and writes a stack frame into into
 * untrusted address space, and returns true.  Otherwise, it returns
 * false. See the DispatchToUntrustedHandler sections in the explanatory
 * comment above.
 * 
 * Note: struct NaClSignalContext *regs is:
 * untrusted: the untrusted registers
 * trusted: the trusted registers (untrusted registers are stored in natp->user at this point)
 * trusted also has edges cases where this isn't true (see edge cases below)
 */
static int DispatchToUntrustedHandler(struct NaClAppThread *natp,
                                      int sig,
                                      struct NaClSignalContext *regs,
                                      int* is_untrusted) {
  struct NaClApp *nap = natp->nap;
  uintptr_t frame_addr;
  volatile struct NaClExceptionFrame *frame;
  uint32_t new_stack_ptr;
  uintptr_t context_user_addr;
  uint32_t lind_exception_handler;
  
  // Single stepping to 32-byte boundary if we have set SIGTRAP
  // if we reach boundary: unset SIGTRAP, otherwise return
  // This must be before the lindgetsighandler call
  // See the "32 byte alignment & single stepping" section in the explanatory comment at the top of this file
  if(sig == SIGTRAP && natp->single_stepping_signum) {
    if((regs->prog_ctr & 31) == 0) { //if our address is 32 bit aligned
      regs->flags &= ~0x100; //get rid of the trap flag
      sig = natp->single_stepping_signum; //overwrite SIGTRAP
      natp->single_stepping_signum = 0;
    } else {
      return -1;
    }
  }

  lind_exception_handler = lindgetsighandler(nap->cage_id, sig); // retrive handler address from RustPOSIX

  if (lind_exception_handler == 0) {
    return 0;
  }
  if (lind_exception_handler == 1) {
    return -1;
  }
  if (natp->exception_flag) {
    return 0; // I believe this prevents double faults
  }

  if (*is_untrusted) {
    // See the "32 byte alignment & single stepping" section in the explanatory comment at the top of this file
    if(regs->prog_ctr & 31 && sig != SIGSEGV && sig != SIGBUS &&  sig != SIGTRAP && sig != SIGILL && sig != SIGFPE) {
      if(!natp->single_stepping_signum)  {
        natp->single_stepping_signum = sig;
        regs->flags |= 0x100; //set the trap flag on return
      }
      return -1;
    }
  } else {
    natp->pendingsignal = true;
    if (!natp->signatpflag) {
      /* See the "DispatchToUntrustedHandler: Trusted special cases" section in the 
       * explanatory comment at the top of this file
       *
       * we need to handle the signal differently when the syscall is entering or exiting
       * if it's entering and the natp has not been initialized yet we need to manually
       * initialize the natp from values on the user stack. If it's exiting and has already
       * copied out some of the key values (i.e. the stack pointer) from the natp to user
       * registers then we need to re-copy everything back from the natp to user registers.
       * We can know whether it's in the relevant syscall entry code by statically checking
       * the rip address.
       * Additionally, because the return mechanism is different for the tls case we need
       * to essentially manually perform the operation and then return to user control by
       * manually setting registers and the program counter.
       */
      char *pc = (void*) regs->prog_ctr;

      if (pc >= &NaClGetTlsFastPath1 &&
          pc < &NaClGetTlsFastPath1End) {
        
        // Case 1: TLSFastPath1
        // we just emulate the tls_syscall function (assembly in nacl_syscall_64.S) here instead of interuppting it

        *is_untrusted = -1;
        natp->user.rax = (uintptr_t) natp->user.tls_value1; 
        if (regs->prog_ctr < (uintptr_t) &NaClGetTlsFastPath1RspRestored) {
          natp->user.rcx = *(uintptr_t*) regs->stack_ptr;
          regs->stack_ptr += 8;  /* Pop user return address */
        } else {
          if (regs->prog_ctr == (uintptr_t) &NaClGetTlsFastPath1RspRestored)
            natp->user.rcx = regs->rcx;
          else
            natp->user.rcx = regs->rcx - 31;
        }

      } else if (pc >= &NaClGetTlsFastPath2 &&
                 pc < &NaClGetTlsFastPath2End) {

        // Case 2: TLSFastPath2 (same logic as fastpath 1)

        *is_untrusted = -1;
        natp->user.rax = (uintptr_t) natp->user.tls_value2;
        if (regs->prog_ctr < (uintptr_t) &NaClGetTlsFastPath2RspRestored) {
          natp->user.rcx = *(uintptr_t*) regs->stack_ptr;
          regs->stack_ptr += 8;  /* Pop user return address */
        } else {
          if (regs->prog_ctr == (uintptr_t) &NaClGetTlsFastPath2RspRestored)
            natp->user.rcx = regs->rcx;
          else
            natp->user.rcx = regs->rcx - 31;
          natp->user.rcx = regs->rcx;
        }

      } else if(pc >= (char*) &NaClSyscallSeg && pc < &NaClSyscallSegEnd) {

        // Case 3: Syscall Entry

        //syscall start, manually populate natp for callee saved registers
        // we don't know where we've split the regs population but it doesnt hurt to set values twice, so we do that here
        natp->user.rbx = regs->rbx;
        natp->user.rbp = regs->rbp;
        if(NaClIsUserAddr(natp->nap, regs->stack_ptr))
          natp->user.rsp = regs->stack_ptr + 8; //to correspond to the lea in NaClSyscallSeg
        natp->user.r12 = regs->r12;
        natp->user.r13 = regs->r13;
      } else if (!(pc >= &NaClSyscallCSegHook && pc < &NaClSyscallCSegHookInitialized)) {

        // Case 4: Syscall Exit

        //syscall end, re-run register copy-out
        // we just need to set rip/rdi/rsp to make sure we run NaClSwitchToApp properly
        // NaClSwitch will handle the rest of the register switching
        regs->prog_ctr = (uintptr_t) &NaClSwitchToApp;
        regs->rdi = (uintptr_t) natp;
        regs->stack_ptr = natp->user.trusted_stack_ptr; //in case rsp is restored, making sure we stay on the trusted stack
      } //otherwise we are in syscall start but everything is already known to be ok

      if(*is_untrusted == -1) {
        // Complete TLSFastPath register switching
        natp->user.rbp = regs->rbp;
        natp->user.rbx = regs->rbx;
        natp->user.rsp = regs->stack_ptr;
        natp->user.r12 = regs->r12;
        natp->user.r13 = regs->r13;
        natp->pendingsignal = false;
      }
    }
  }

  natp->exception_flag = 1;

  // For the rest of the function see the "DispatchToUntrustedHandler: Stack handling" 
  // section of the explanatory comment at the top of this file
  if (natp->exception_stack == 0) {
    //account for redzone in untrusted
    if(*is_untrusted > 0)
	  new_stack_ptr = regs->stack_ptr - NACL_STACK_RED_ZONE - 8; //the -8 to standardize things between trusted and untrusted
    else if(*is_untrusted == -1)
	  new_stack_ptr = natp->user.rsp - NACL_STACK_RED_ZONE - 8; //the -8 to standardize things between trusted and untrusted
    else
	  new_stack_ptr = natp->user.rsp - NACL_STACK_RED_ZONE;
  } else {
    new_stack_ptr = natp->exception_stack;
  }

  /* Allocate space for the stack frame, and ensure its alignment. */
  new_stack_ptr -=
      sizeof(struct NaClExceptionFrame) - NACL_STACK_PAD_BELOW_ALIGN;
  new_stack_ptr = new_stack_ptr & ~NACL_STACK_ALIGN_MASK;
  new_stack_ptr -= NACL_STACK_ARGS_SIZE;
  new_stack_ptr -= NACL_STACK_PAD_BELOW_ALIGN;
  frame_addr = NaClUserToSysAddrRange(nap, new_stack_ptr,
                                      sizeof(struct NaClExceptionFrame));
  if (frame_addr == kNaClBadAddress) {
    /* We cannot write the stack frame. */
    return 0;
  }
  context_user_addr = new_stack_ptr + offsetof(struct NaClExceptionFrame,
                                               context);

  frame = (struct NaClExceptionFrame *) frame_addr;
  if (*is_untrusted > 0) {
    NaClSignalSetUpExceptionFrame(frame, regs, context_user_addr);
  } else {
    NaClSignalSetUpExceptionFrameTrusted(frame, natp, context_user_addr);
    if(*is_untrusted == -1) {
      frame->context.regs.rax = natp->user.rax;
      frame->context.regs.prog_ctr = NaClUserToSysAddr(natp->nap, natp->user.rcx & 0xffffffe0);
    }
  }
  frame->return_addr = nap->mem_start + NACL_SYSCALL_START_ADDR
                       + (NACL_SYSCALL_BLOCK_SIZE * NACL_sys_reg_restore);

#if NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86 && NACL_BUILD_SUBARCH == 32
  regs->prog_ctr = lind_exception_handler;
  regs->stack_ptr = new_stack_ptr;
#elif NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86 && NACL_BUILD_SUBARCH == 64
  natp->user.rdi = context_user_addr; /* Argument 1 */
  natp->user.new_prog_ctr = NaClUserToSys(nap, lind_exception_handler);
  //TODO: I don't think this is handled correctly for the exception stack case
  natp->user.rsp = NaClUserToSys(nap, new_stack_ptr);
#elif NACL_ARCH(NACL_BUILD_ARCH) == NACL_arm
  /*
   * Returning from the exception handler is not possible, so to avoid
   * any confusion that might arise from jumping to an uninitialised
   * address, we set the return address to zero.
   */
  regs->lr = 0;
  regs->r0 = context_user_addr;  /* Argument 1 */
  regs->prog_ctr = NaClUserToSys(nap, lind_exception_handler);
  regs->stack_ptr = NaClUserToSys(nap, new_stack_ptr);
#elif NACL_ARCH(NACL_BUILD_ARCH) == NACL_mips
  regs->return_addr = 0;
  regs->a0 = context_user_addr;
  regs->prog_ctr = NaClUserToSys(nap, lind_exception_handler);
  regs->stack_ptr = NaClUserToSys(nap, new_stack_ptr);
  /*
   * Per Linux/MIPS convention, PIC functions assume that t9 holds
   * the function's address on entry.
   */
  regs->t9 = regs->prog_ctr;
#else
# error Unsupported architecture
#endif

#if NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86
  regs->flags &= ~NACL_X86_DIRECTION_FLAG;
#endif

  return 1;
}

static void SignalCatch(int sig, siginfo_t *info, void *uc) {
  struct NaClSignalContext sig_ctx;
  int is_untrusted;
  struct NaClAppThread *natp;

#if NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86
  /*
   * Reset the x86 direction flag.  New versions of gcc and libc
   * assume that the direction flag is clear on entry to a function,
   * as the x86 ABI requires.  However, untrusted code can set this
   * flag, and versions of Linux before 2.6.25 do not clear the flag
   * before running the signal handler, so we clear it here for safety.
   * See http://code.google.com/p/nativeclient/issues/detail?id=1495
   */
  __asm__("cld");
#endif

  //See the "Sigaction & SignalCatch" of the explanatory comment at the top of this file for an explanation
  NaClSignalContextFromHandler(&sig_ctx, uc);
  GetCurrentThread(&sig_ctx, &is_untrusted, &natp);

  if (!is_untrusted) {
    PrintNaClSignalRegisters(&sig_ctx);

    uint64_t signal_hash = HashNaClSignalRegisters(&sig_ctx);
    printf("Hash of NaClSignalContext registers: 0x%016llx\n", signal_hash);
  }



#if NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86 && NACL_BUILD_SUBARCH == 32
  /*
   * On Linux, the kernel does not restore %gs when entering the
   * signal handler, so we must do that here.  We need to do this for
   * TLS to work and for glibc's syscall wrappers to work, because
   * some builds of glibc fetch a syscall function pointer from the
   * static TLS area.  There is the potential for vulnerabilities if
   * we call glibc without restoring %gs (such as
   * http://code.google.com/p/nativeclient/issues/detail?id=1607),
   * although the risk is reduced because the untrusted %gs segment
   * has an extent of only 4 bytes (see
   * http://code.google.com/p/nativeclient/issues/detail?id=2176).
   *
   * Note that, in comparison, Breakpad tries to avoid using libc
   * calls at all when a crash occurs.
   *
   * For comparison, on Mac OS X, the kernel *does* restore the
   * original %gs when entering the signal handler.  On Mac, our
   * assignment to %gs here wouldn't be necessary, but it wouldn't be
   * harmful either.  However, this code is not currently used on Mac
   * OS X.
   *
   * Both Linux and Mac OS X necessarily restore %cs, %ds, and %ss
   * otherwise we would have a hard time handling signals generated by
   * untrusted code at all.
   *
   * Note that we check natp (which is based on %gs) rather than
   * is_untrusted (which is based on %cs) because we need to handle
   * the case where %gs is set to the untrusted-code value but %cs is
   * not.
   *
   * GCC's stack protector (-fstack-protector) will make use of %gs even before
   * we have a chance to restore it. It is important that this function is not
   * compiled with -fstack-protector.
   */
  if (natp != NULL) {
    NaClSetGs(natp->user.trusted_gs);
  }
#endif


  // we've called thread suspend from the fatal handler, we can safely exit the thread here
  struct NaClThread *host_thread;
  if (natp != NULL) {
    host_thread = &natp->host_thread;
    if (sig == NACL_THREAD_SUSPEND_SIGNAL && natp->suspend_state == (NACL_APP_THREAD_UNTRUSTED | NACL_APP_THREAD_SUSPENDING) && lindcheckthread(natp->nap->cage_id, host_thread->tid)) {
      lindsetthreadkill(natp->nap->cage_id, host_thread->tid, false);
      NaClThreadExit();
    }
  }

  // Lind: we removed the NaClThreadSuspensionSignalHandler function here
  // since we don't need to deal with the VMhole issue on Linux, the only time we use
  // NACL_THREAD_SUSPEND_SIGNAL is for the reaper/untrusted teardown which is handled above

  if (natp != NULL) {
    //For an explanation of the below switch, see the  "SignalCatch: Restoration to previous point of execution:
    //section of the explanatory comment at the top of this file
    switch (DispatchToUntrustedHandler(natp, sig, &sig_ctx, &is_untrusted)) {
      case -1:
        NaClSignalContextToHandler(uc, &sig_ctx);
        return;
      case 0:
        break;
      default:
        /* Resume execution of code using the modified register state. */
        if (is_untrusted > 0) {
          NaClStackSafetyNowOnUntrustedStack();

          //clobber for restore
          sig_ctx.prog_ctr = natp->user.new_prog_ctr;
          sig_ctx.stack_ptr = natp->user.rsp;
          sig_ctx.rdi = sig;
          NaClSwitchFromSignal(&sig_ctx);
        } else if (is_untrusted == -1) {
          //Hijack and return to untrusted
          NaClSwitchFromSignalTls(sig, &natp->user);
        } else {

            if (!is_untrusted) {
              PrintNaClSignalRegisters(&sig_ctx);

              uint64_t signal_hash = HashNaClSignalRegisters(&sig_ctx);
              printf("Hash of NaClSignalContext registers: 0x%016llx\n", signal_hash);
            }
          NaClSwitchFromSignalTrusted(&sig_ctx);
        }

        NaClLog(LOG_FATAL, "Couldn't switch control after signal handling activated\n");
        break;
    }
  }
  
  if (sig == SIGCHLD) {
        NaClSignalContextToHandler(uc, &sig_ctx);
        return;
  }

  if (g_handler_func != NULL) {
    g_handler_func(sig, &sig_ctx, is_untrusted);
    return;
  }

  if (natp == NULL) {
      char tmp[128];
    SNPRINTF(tmp, sizeof(tmp),
        "\n** User exited program with signal %d.\n",
        sig);
    NaClSignalErrorMessage(tmp);
    NaClExit(-sig);
  }

  // Lind: If we segfault on a user address (presumably because it was unmapped between check and use), we can call that an untrusted fault
  if ((sig == SIGSEGV) && ((uintptr_t)info->si_addr & ~(natp->nap->addr_bits))) is_untrusted = true;

  // Lind: if we get SIGPIPE set to one of the cage threads its interal and we can shutdown gracefully
  if ((sig == SIGPIPE) && (natp != NULL)) is_untrusted = true;

  NaClSignalHandleUntrusted(natp, sig, &sig_ctx, is_untrusted);

  FindAndRunHandler(sig, info, uc);
}


/*
 * Check that the current process has no signal handlers registered
 * that we won't override with safe handlers.
 *
 * We want to discourage Chrome or libraries from registering signal
 * handlers themselves, because those signal handlers are often not
 * safe when triggered from untrusted code.  For background, see:
 * http://code.google.com/p/nativeclient/issues/detail?id=1607
 */
static void AssertNoOtherSignalHandlers(void) {
  unsigned int index;
  int signum;
  char handled_by_nacl[NSIG];

  /* 0 is not a valid signal number. */
  for (signum = 1; signum < NSIG; signum++) {
    handled_by_nacl[signum] = 0;
  }
  for (index = 0; index < NACL_ARRAY_SIZE(s_Signals); index++) {
    signum = s_Signals[index];
    CHECK(signum > 0);
    CHECK(signum < NSIG);
    handled_by_nacl[signum] = 1;
  }
  for (signum = 1; signum < NSIG; signum++) {
    struct sigaction sa;

    if (handled_by_nacl[signum])
      continue;

    if (sigaction(signum, NULL, &sa) != 0) {
      /*
       * Don't complain if the kernel does not consider signum to be a
       * valid signal number, which produces EINVAL.
       */
      if (errno != EINVAL) {
        NaClLog(LOG_FATAL, "AssertNoOtherSignalHandlers: "
                "sigaction() call failed for signal %d: errno=%d\n",
                signum, errno);
      }
    } else {
      if ((sa.sa_flags & SA_SIGINFO) == 0) {
        if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN)
          continue;
      } else {
        /*
         * It is not strictly legal for sa_sigaction to contain NULL
         * or SIG_IGN, but Valgrind reports SIG_IGN for signal 64, so
         * we allow it here.
         */
        if (sa.sa_sigaction == NULL ||
            sa.sa_sigaction == (void (*)(int, siginfo_t *, void *)) SIG_IGN)
          continue;
      }
      NaClLog(LOG_FATAL, "AssertNoOtherSignalHandlers: "
              "A signal handler is registered for signal %d\n", signum);
    }
  }
}

//See the "Sigaction & SignalCatch" of the explanatory comment at the top of this file for an explanation
void NaClSignalHandlerInit(void) {
  struct sigaction sa;
  unsigned int a;

  AssertNoOtherSignalHandlers();
  
  memset(&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = SignalCatch;
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO;

  /*
   * Mask all signals we catch to prevent re-entry.
   *
   * In particular, NACL_THREAD_SUSPEND_SIGNAL must be masked while we
   * are handling a fault from untrusted code, otherwise the
   * suspension signal will interrupt the trusted fault handler.  That
   * would cause NaClAppThreadGetSuspendedRegisters() to report
   * trusted-code register state rather than untrusted-code register
   * state from the point where the fault occurred.
   */
  for (a = 0; a < NACL_ARRAY_SIZE(s_Signals); a++) {
    sigaddset(&sa.sa_mask, s_Signals[a]);
  }

  /* Install all handlers */
  for (a = 0; a < NACL_ARRAY_SIZE(s_Signals); a++) {
    if (sigaction(s_Signals[a], &sa, &s_OldActions[a]) != 0) {
      NaClLog(LOG_FATAL, "Failed to install handler for %d.\n\tERR:%s\n",
                          s_Signals[a], strerror(errno));
    }
  }
}

void NaClSignalHandlerFini(void) {
  unsigned int a;

  /* Remove all handlers */
  for (a = 0; a < NACL_ARRAY_SIZE(s_Signals); a++) {
    if (sigaction(s_Signals[a], &s_OldActions[a], NULL) != 0) {
      NaClLog(LOG_FATAL, "Failed to unregister handler for %d.\n\tERR:%s\n",
                          s_Signals[a], strerror(errno));
    }
  }
}
