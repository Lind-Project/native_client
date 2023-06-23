/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Signal Context
 */

#ifndef __NATIVE_CLIENT_SERVICE_RUNTIME_ARCH_X86_64_NACL_SIGNAL_64_H__
#define __NATIVE_CLIENT_SERVICE_RUNTIME_ARCH_X86_64_NACL_SIGNAL_64_H__ 1

#if !defined(__ASSEMBLER__)
#include "native_client/src/include/portability.h"

/*
 * Architecture specific context object.  Register order matches that
 * found in src/trusted/debug_stub/abi.cc, which allows us to use an
 * abi context (GDB ordered context), and a signal context interchangably.
 * In addition, we use common names for the stack and program counter to
 * allow functions which use them to avoid conditional compilation.
 */
struct NaClSignalContext {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t rbp;
  uint64_t stack_ptr;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t prog_ctr;
  uint32_t flags;
  uint32_t cs;
  uint32_t ss;
  uint32_t ds;
  uint32_t es;
  uint32_t fs;
  uint32_t gs;
  uint32_t padding;  /* Pad to a multiple of 8 bytes */
};

NORETURN void NaClSwitchFromSignal(struct NaClSignalContext* ctx);
NORETURN void NaClSwitchFromSignalTrusted(struct NaClSignalContext* ctx);

#endif /* !defined(__ASSEMBLER__) */

#define NACL_SIGNAL_CONTEXT_RAX_OFFSET 0
#define NACL_SIGNAL_CONTEXT_RBX_OFFSET 8
#define NACL_SIGNAL_CONTEXT_RCX_OFFSET 16
#define NACL_SIGNAL_CONTEXT_RDX_OFFSET 24
#define NACL_SIGNAL_CONTEXT_RSI_OFFSET 32
#define NACL_SIGNAL_CONTEXT_RDI_OFFSET 40
#define NACL_SIGNAL_CONTEXT_RBP_OFFSET 48
#define NACL_SIGNAL_CONTEXT_STACK_PTR_OFFSET 56
#define NACL_SIGNAL_CONTEXT_R8_OFFSET 64
#define NACL_SIGNAL_CONTEXT_R9_OFFSET 72
#define NACL_SIGNAL_CONTEXT_R10_OFFSET 80
#define NACL_SIGNAL_CONTEXT_R11_OFFSET 88
#define NACL_SIGNAL_CONTEXT_R12_OFFSET 96
#define NACL_SIGNAL_CONTEXT_R13_OFFSET 104
#define NACL_SIGNAL_CONTEXT_R14_OFFSET 112
#define NACL_SIGNAL_CONTEXT_R15_OFFSET 120
#define NACL_SIGNAL_CONTEXT_PROG_CTR_OFFSET 128
#define NACL_SIGNAL_CONTEXT_FLAGS_OFFSET 136
#define NACL_SIGNAL_CONTEXT_CS_OFFSET 140
#define NACL_SIGNAL_CONTEXT_SS_OFFSET 144
#define NACL_SIGNAL_CONTEXT_DS_OFFSET 148
#define NACL_SIGNAL_CONTEXT_ES_OFFSET 152
#define NACL_SIGNAL_CONTEXT_FS_OFFSET 156
#define NACL_SIGNAL_CONTEXT_GS_OFFSET 160

#endif /* __NATIVE_CLIENT_SERVICE_RUNTIME_ARCH_X86_64_NACL_SIGNAL_64_H__ */
