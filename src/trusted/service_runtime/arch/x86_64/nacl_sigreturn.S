/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "native_client/src/trusted/service_runtime/arch/x86_64/nacl_signal_64.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
.text


.globl NaClSwitchFromSignal
.hidden NaClSwitchFromSignal
.globl NaClSwitchFromSignalTrusted
.hidden NaClSwitchFromSignalTrusted

NaClSwitchFromSignal:
#if NACL_WINDOWS
        /* On Windows, 1st param is in %rcx. */
        mov     %rcx, %r11
#elif NACL_LINUX || NACL_OSX
        /* On Linux/OSX, 1st param is in %rdi. */
        mov     %rdi, %r11
#else
# error "What OS/compiler is the service runtime being compiled with?"
#endif

        movq NACL_SIGNAL_CONTEXT_R15_OFFSET(%r11), %r15
        xor %rax, %rax
        xor %rbx, %rbx
        xor %rcx, %rcx
        xor %rdx, %rdx
        xor %rsi, %rsi
        movq NACL_SIGNAL_CONTEXT_RDI_OFFSET(%r11), %rdi
        movq NACL_SIGNAL_CONTEXT_RBP_OFFSET(%r11), %rbp #rbp must not be allowed to be out of range, so we restore it even though it's unnecessary
        movq NACL_SIGNAL_CONTEXT_STACK_PTR_OFFSET(%r11), %rsp
        xor %r8, %r8
        xor %r9, %r9
        xor %r10, %r10
        xor %r12, %r12
        xor %r13, %r13
        xor %r14, %r14

        movq    NACL_SIGNAL_CONTEXT_PROG_CTR_OFFSET(%r11), %r11

        jmp *%r11

NaClSwitchFromSignalTrusted:
#if NACL_WINDOWS
        /* On Windows, 1st param is in %rcx. */
        mov     %rcx, %r11
#elif NACL_LINUX || NACL_OSX
        /* On Linux/OSX, 1st param is in %rdi. */
        mov     %rdi, %r11
#else
# error "What OS/compiler is the service runtime being compiled with?"
#endif

        movq NACL_SIGNAL_CONTEXT_R15_OFFSET(%r11), %r15
        movq NACL_SIGNAL_CONTEXT_R14_OFFSET(%r11), %r14
        movq NACL_SIGNAL_CONTEXT_R13_OFFSET(%r11), %r13
        movq NACL_SIGNAL_CONTEXT_R12_OFFSET(%r11), %r12
        movq NACL_SIGNAL_CONTEXT_R10_OFFSET(%r11), %r10
        movq NACL_SIGNAL_CONTEXT_R9_OFFSET(%r11), %r9
        movq NACL_SIGNAL_CONTEXT_R8_OFFSET(%r11), %r8
        movq NACL_SIGNAL_CONTEXT_RAX_OFFSET(%r11), %rax
        movq NACL_SIGNAL_CONTEXT_RBX_OFFSET(%r11), %rbx
        movq NACL_SIGNAL_CONTEXT_RCX_OFFSET(%r11), %rcx
        movq NACL_SIGNAL_CONTEXT_RDX_OFFSET(%r11), %rdx
        movq NACL_SIGNAL_CONTEXT_RDI_OFFSET(%r11), %rdi
        movq NACL_SIGNAL_CONTEXT_RSI_OFFSET(%r11), %rsi
        movq NACL_SIGNAL_CONTEXT_STACK_PTR_OFFSET(%r11), %rsp
        movq NACL_SIGNAL_CONTEXT_PROG_CTR_OFFSET(%r11), %rbp
        movq %rbp, -160(%rsp)
        movq NACL_SIGNAL_CONTEXT_RBP_OFFSET(%r11), %rbp
        subq $128, %rsp
        pushq NACL_SIGNAL_CONTEXT_FLAGS_OFFSET(%r11)
        pushq NACL_SIGNAL_CONTEXT_R11_OFFSET(%r11)
        popq %r11
        popfq
        leaq 128(%rsp), %rsp
        jmp *-160(%rsp)
