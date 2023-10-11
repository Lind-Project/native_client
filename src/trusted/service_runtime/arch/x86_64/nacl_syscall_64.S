/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * The MacOS assembler has a macro facility that is pretty close
 * to GNU as macros, but not quite the same.
 */
#if NACL_OSX || defined(__clang__)
# define MACRO(name)    .macro name
# define ENDMACRO       .endmacro
# define MACROARG1      $0
# define MACROARG2      $1
# define MACROARG3      $2
# define MACROARG4      $3
#else
# define MACRO(name)    .macro name arg1=0, arg2=0, arg3=0, arg4=0
# define ENDMACRO       .endm
# define MACROARG1      \arg1
# define MACROARG2      \arg2
# define MACROARG3      \arg3
# define MACROARG4      \arg4
#endif
/*
 * We must write x86 assembly immediates as "$ 0" rather than "$0" to
 * avoid this being treated as a macro argument by the Mac/Clang
 * assemblers.  We use DOLLAR below to make this more explicit.
 */
#define DOLLAR $

/*
 * This code gets executed when switching from a 64-bit nacl module to
 * the 64-bit service. NaClSyscallSeg is the lcall target from the
 * syscall trampoline code, and this code is responsible for figuring
 * out the identity of the thread, saving the user registers, finish
 * restoring the segment registers (and getting out of the sandbox),
 * and actually invoking the C system call handler code.
 */

#include "native_client/src/trusted/service_runtime/arch/x86_64/sel_rt_64.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"

/*
 * This macro gets the NaClThreadContext from the nacl_current_thread
 * TLS variable in Windows or Linux, or the corresponding
 * pthread_getspecific(...) TSD data in OSX and puts it in %rdx.
 *
 * May clobber two registers, %rax and %rcx.
 *
 * If %rdx contains 0, then this is an invalid thread.
 */
MACRO(get_tls)
        /*
         * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
         *
         * Open coded TLS (or TSD) access, for all of our target host
         * OS/toolchains.  If the compiler / runtime conventions for
         * how to access TLS or TSD changes, this code will break
         * mysteriously.
         *
         * Any changes/fixes for this must be mirrored in nacl_test_capture.S
         *
         * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
         */
#if NACL_LINUX
        /*
         * Linux uses TLS.
         * We use "@GOTTPOFF" rather than "@TPOFF" in order to be PIC-friendly.
         */
        movq    nacl_current_thread@GOTTPOFF(%rip), %rax
        movq    %fs:(%rax), %rdx
#elif NACL_OSX
        /*
         * This assumes a particular implementation of OS X's
         * pthread_getspecific(), which we check for in NaClTlsInit().
         */
        movl    _nacl_current_thread_tls_offset(%rip), %eax
        movq    %gs:(%rax), %rdx
#elif NACL_WINDOWS
        /*
         * NOTE: This code should match the code in platform/win/test_tls.S!
         * If you change this code, please update that file as well.
         *
         * The following two lines generate this instruction:
         *   ba XX XX XX XX    movl $nacl_current_thread@SECREL, %edx
         *
         * SECREL is a relocation type which gives the offset of
         * nacl_current_thread within the TLS template section.  GNU
         * binutils' assembler does not have a syntax for generating
         * this relocation as part of an instruction.  It only has the
         * .secrel32 syntax for generating the relocated value as a
         * 32-bit literal.  We use this here for generating the
         * instruction by hand.
         *
         * For background, see:
         * http://code.google.com/p/nativeclient/issues/detail?id=2155
         *
         * because of the need to do .byte, we cannot simply name the
         * scratch registers via macro arguments.
         */
        .byte 0xba
        .secrel32 nacl_current_thread

        mov _tls_index(%rip), %ecx
        movq %gs:0x58, %rax
        /* Get the address of this module (executable/DLL)'s TLS area. */
        movq (%rax,%rcx,8), %rax
        /* Get the value of nacl_current_thread from the TLS area. */
        movq (%rdx,%rax), %rdx
#else
# error "What OS/compiler is the service runtime being compiled with?"
#endif
ENDMACRO

/*
 * On untrusted stack:
 *      return-addr-to-caller-of-trampoline
 *      return-addr-to-trampoline (essentially syscall number)
 *
 * This code must save the syscall arguments so that they can be
 * accessed in an uniformed way, regardless of whether the service
 * runtime was compiled using gcc (NACL_LINUX and NACL_OSX) or
 * using MS Studio (NACL_WINDOWS).
 */
        .text
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(NaClSyscallSeg):
        cld

        /* Save system call arguments on the untrusted stack. */
        movl %r9d, -0x0c(%rsp)
        movl %r8d, -0x10(%rsp)
        movl %ecx, -0x14(%rsp)
        movl %edx, -0x18(%rsp)
        movl %esi, -0x1c(%rsp)
        movl %edi, -0x20(%rsp)

        /* rax, rdi, rsi, rdx, rcx, r8, r9 are usable for scratch */

        get_tls
        /*
         * Code below will segfault if %rdx is the NULL pointer, since
         * the zero page is unmapped.
         */

        /* only save the callee saved registers */
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(NaClSyscallThreadCaptureFault):

        movq    %rbx, NACL_THREAD_CONTEXT_OFFSET_RBX(%rdx)
        movq    %rbp, NACL_THREAD_CONTEXT_OFFSET_RBP(%rdx)
        /*
         * Record the value of %rsp that we will restore when
         * returning to untrusted code from the syscall.
         * Because the signal handler can clobber RSP in the
         * thread context we must use that value if present
         */
        leaq    8(%rsp), %rcx
        xchgq   %rcx, NACL_THREAD_CONTEXT_OFFSET_RSP(%rdx) 
        cmpb    $0, NACL_THREAD_PENDING_SIGNAL_OFFSET(%rdx)
        je NaClSyscallSegSPSet
        cmpq    %rcx, NACL_THREAD_CONTEXT_OFFSET_RSP(%rdx)
        jbe NaClSyscallSegSPSet
        movq    %rcx, NACL_THREAD_CONTEXT_OFFSET_RSP(%rdx)
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(NaClSyscallSegSPSet):
        
        movq    %r12, NACL_THREAD_CONTEXT_OFFSET_R12(%rdx)
        movq    %r13, NACL_THREAD_CONTEXT_OFFSET_R13(%rdx)
        /* r15 need not be saved, since it is immutable from user code */
        /* r14 need not be saved, since it is not specified  in user code behavior */

        /*
         * Save the x87 FPU control word.  This is callee-saved,
         * while all other x87 state is caller-saved.  Then reload
         * the system default state to use while running trusted code.
         */
        fnstcw  NACL_THREAD_CONTEXT_OFFSET_FCW(%rdx)
        fldcw   NACL_THREAD_CONTEXT_OFFSET_SYS_FCW(%rdx)

        /*
         * Save the SSE control word.  Then reload the system default
         * state to use while running trusted code.
         */
        stmxcsr NACL_THREAD_CONTEXT_OFFSET_MXCSR(%rdx)
        ldmxcsr NACL_THREAD_CONTEXT_OFFSET_SYS_MXCSR(%rdx)
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(NaClSyscallSegRegsSaved):

        movq    NACL_THREAD_CONTEXT_OFFSET_TRUSTED_STACK_PTR(%rdx), %rsp
#if NACL_LINUX || NACL_OSX
        movq    %rdx, %rdi
#elif NACL_WINDOWS
        movq    %rdx, %rcx
#else
# error "What OS/compiler is the service runtime being compiled with?"
#endif
        /*
         * Although NaClSyscallCSegHook() never returns, we want to
         * make sure that the return address on the stack will be
         * handled properly by the host system's stack unwinder.
         *
         * For Linux, it is fine that the return address does not have
         * associated unwind info, because libgcc's stack unwinder
         * will stop unwinding when it reaches such an address.  Note
         * that pthread_exit() causes stack unwinding.
         *
         * We cannot do the same thing on Windows because its stack
         * unwinder does not have a similar safe default.  If it
         * encounters a return address without unwind info, it applies
         * the rule for leaf functions (even though this rule does not
         * make sense for return addresses in the Windows x86-64 ABI),
         * and it does so even for zero return addresses.  This can
         * cause it to read uninitialised memory.
         *
         * So, for Windows, the stack has already been set up by
         * NaClSwitchSavingStackPtr() with a return address with
         * associated unwind info.
         */
#if NACL_WINDOWS
        jmp     IDENTIFIER(NaClSyscallCSegHook)
#else
        call    IDENTIFIER(NaClSyscallCSegHook)
        hlt
        /* noret */
#endif
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(NaClSyscallSegEnd):

        /*
         * untrusted stack after call to NaClSyscallCSegHook:
         *
         * 0x20   0x8 return-addr-to-caller-of-trampoline
         * 0x18   0x0 return-addr-to-trampoline (essentially syscall number)
         * 0x14 -0x04 r9
         * 0x10 -0x08 r8
         * 0x0c -0x0c rcx
         * 0x08 -0x10 rdx
         * 0x04 -0x14 rsi
         * 0x00 -0x18 rdi
         */

MACRO(tls_syscall)
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(MACROARG1):  /* Entry */
        get_tls
        movl    MACROARG4(%rdx), %eax
        /* sandbox the return, straight off the untrusted stack */
        pop     %rcx
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(MACROARG2):  /* RspRestored */
        addl    DOLLAR 31, %ecx
        andl    DOLLAR 0xffffffe0, %ecx
        leaq    (%r15, %rcx), %r11
        /*
         * Set %rdx to zero so that we do not leak the address of the
         * NaClThreadContext struct.  This also resets flags.
         * Resetting flags to fixed values by doing this last
         * simplifies testing that we do not leak any information via
         * flags.
         */
        xorl    %edx, %edx
        jmp     *%r11
DEFINE_GLOBAL_HIDDEN_IDENTIFIER(MACROARG3):  /* End */
ENDMACRO

        /*
         * Note that long lines are required here because "\" does not
         * work in the Windows build.
         */
        tls_syscall NaClGetTlsFastPath1, NaClGetTlsFastPath1RspRestored, NaClGetTlsFastPath1End, NACL_THREAD_CONTEXT_OFFSET_TLS_VALUE1
        tls_syscall NaClGetTlsFastPath2, NaClGetTlsFastPath2RspRestored, NaClGetTlsFastPath2End, NACL_THREAD_CONTEXT_OFFSET_TLS_VALUE2


/*
 * --------------------------------------------------------------------------------------------------------------------------
 * Returning from an untrusted signal handler
 * --------------------------------------------------------------------------------------------------------------------------
 * 
 * This function's address is put onto the stack immediately under the signal handler's stack frame such that it is called
 * as soon as the untrusted signal handler returns. This function is loaded into the trampoline at NaClPatchRegTrampolineCall
 * called from sel_ldr.c, and lives in cage memory. First it calls into another trampoline entry for NaClSysSigmaskSigreturn
 * which resets the sigprocmask of the thread which was set by sigaction, and also unsets some natp bookkeeping.
 *
 * After that it restores all registers to the values they should be in untrusted. However this created an issue--
 * when we wanted to restore to the previous untrusted state we had to be at a point where every register contains
 * the correct value for the untrusted state except for the instruction pointer. The question then arises, where is
 * the instruction pointer to be restored from? The answer is either a static address, on the untrusted stack, a fixed
 * trusted address, or nowhere. It may be possible to store some sort of protected thread local stack data structure
 * for addreses of received signals but as the fixed trusted address can't handle multiple signals called on top of
 * each other and the untrusted address leaves us very vulnerable to TOCTTOUs, we decided that we had little choice
 * but to reserve the r14 register expressly for this purpose--any use of it within untrusted code is undefined.
 * The rip and rsp values are importantly masked to 32 byte aligned addresses, see the comment at the top of
 * linux/nacl_signal.c for more information, and the flags register is masked on the stack although this is pretty useless
 * We make sure to restore the flags as it's crucial that things like OF and SF are restored.
 *
 * - Jonathan Singer
 */

.globl NaClTrampolineRegRestore
.hidden NaClTrampolineRegRestore

.align 32
NaClTrampolineRegRestore:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore1
.hidden NaClTrampolineRegRestore1

.align 32
NaClTrampolineRegRestore1:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 2
.globl NaClTrampolineRegRestore2
.hidden NaClTrampolineRegRestore2

.align 32
NaClTrampolineRegRestore2:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 3
.globl NaClTrampolineRegRestore3
.hidden NaClTrampolineRegRestore3

.align 32
NaClTrampolineRegRestore3:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore4
.hidden NaClTrampolineRegRestore4

.align 32
NaClTrampolineRegRestore4:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore5
.hidden NaClTrampolineRegRestore5

.align 32
NaClTrampolineRegRestore5:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore6
.hidden NaClTrampolineRegRestore6

.align 32
NaClTrampolineRegRestore6:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore7
.hidden NaClTrampolineRegRestore7

.align 32
NaClTrampolineRegRestore7:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore8
.hidden NaClTrampolineRegRestore8

.align 32
NaClTrampolineRegRestore8:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore9
.hidden NaClTrampolineRegRestore9

.align 32
NaClTrampolineRegRestore9:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore10
.hidden NaClTrampolineRegRestore10

.align 32
NaClTrampolineRegRestore10:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore11
.hidden NaClTrampolineRegRestore11

.align 32
NaClTrampolineRegRestore11:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore12
.hidden NaClTrampolineRegRestore12

.align 32
NaClTrampolineRegRestore12:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore13
.hidden NaClTrampolineRegRestore13

.align 32
NaClTrampolineRegRestore13:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore14
.hidden NaClTrampolineRegRestore14

.align 32
NaClTrampolineRegRestore14:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14

// offset 1
.globl NaClTrampolineRegRestore15
.hidden NaClTrampolineRegRestore15

.align 32
NaClTrampolineRegRestore15:
# restore sigprocmask using custom syscall
# we must return to a 32 byte address,so pad with nops
.nops 23
    lea 130(%rip), %rax
    call *%rax # 128 + 2 where instruction is 2 bytes for this indirect call, this points to the address of the NaClSysSigmaskSigreturn trampoline entry
# we do this as an indirect call so that the call being at the end of a 32 byte section is easier
.align 32
    addl $64, %esp /* skip unused fields */
    addq %r15, %rsp
    popq %rax
    popq %rcx
    popq %rdx
    popq %rbx
    popq %rsi #we avoid restoring rsp in this manner, so pop to a scratch register to be clobbered
    popq %rsi #use a scratch register for rbp too
    movl %esi, %ebp
    addq %r15, %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
.align 32
    addl $16, %esp # skip restoring r14, r15
    addq %r15, %rsp
    popq %r14
    addl $24, %esp #skip flags for now, other unused fields
    addq %r15, %rsp
.align 32
#    andl $0xffffffe0, %r14d
    movl %r14d, %r14d
    addq %r15, %r14
    andl $0x7ff, (%rsp) #this is cleared by the system anyway, but can't hurt
    popfq #now restore flags from the duplicate location
    leaq 136(%rsp), %rsp
    jmp *%r14