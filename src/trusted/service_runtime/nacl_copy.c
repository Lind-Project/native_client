/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <string.h>

#include "native_client/src/trusted/service_runtime/nacl_copy.h"

#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_sync_checked.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/include/bits/mman.h"


int NaClCopyInFromUser(struct NaClApp *nap,
                       void           *dst_sys_ptr,
                       uintptr_t      src_usr_addr,
                       size_t         num_bytes) {
  uintptr_t src_sys_addr;

  src_sys_addr = NaClUserToSysAddrRangeProt(nap, src_usr_addr, num_bytes, NACL_ABI_PROT_READ);
  if (kNaClBadAddress == src_sys_addr) {
    return 0;
  }
  NaClCopyTakeLock(nap);
  memcpy((void *) dst_sys_ptr, (void *) src_sys_addr, num_bytes);
  NaClCopyDropLock(nap);

  return 1;
}

int NaClCopyInFromUserAndDropLock(struct NaClApp *nap,
                                  void           *dst_sys_ptr,
                                  uintptr_t      src_usr_addr,
                                  size_t         num_bytes) {
  uintptr_t src_sys_addr;

  src_sys_addr = NaClUserToSysAddrRangeProt(nap, src_usr_addr, num_bytes, NACL_ABI_PROT_READ);
  if (kNaClBadAddress == src_sys_addr) {
    return 0;
  }

  memcpy((void *) dst_sys_ptr, (void *) src_sys_addr, num_bytes);
  NaClCopyDropLock(nap);

  return 1;
}

int NaClCopyInFromUserZStr(struct NaClApp *nap,
                           char           *dst_buffer,
                           size_t         dst_buffer_bytes,
                           uintptr_t      src_usr_addr) {
  uintptr_t src_sys_addr;
  int copy_bytes;
  CHECK(dst_buffer_bytes > 0);
  src_sys_addr = NaClUserToSysAddrProt(nap, src_usr_addr, NACL_ABI_PROT_READ);
  if (kNaClBadAddress == src_sys_addr) {
    dst_buffer[0] = '\0';
    return 0;
  }

  // copy_bytes = strnlen(src_sys_addr, dst_buffer_bytes);
  // if (copy_bytes == dst_buffer_bytes) {
  //   dst_buffer[0] = '\0';
  //   return 0;
  // }

  NaClCopyTakeLock(nap);
  strncpy(dst_buffer, (char *) src_sys_addr, copy_bytes);
  NaClCopyDropLock(nap);

  /* POSIX strncpy pads with NUL characters */
  if (dst_buffer[dst_buffer_bytes - 1] != '\0') {
    dst_buffer[dst_buffer_bytes - 1] = '\0';
    return 0;
  }
  return 1;
}


int NaClCopyOutToUser(struct NaClApp  *nap,
                      uintptr_t       dst_usr_addr,
                      void            *src_sys_ptr,
                      size_t          num_bytes) {
  uintptr_t dst_sys_addr;

  dst_sys_addr = NaClUserToSysAddrRangeProt(nap, dst_usr_addr, num_bytes, NACL_ABI_PROT_WRITE);
  if (kNaClBadAddress == dst_sys_addr) {
    return 0;
  }
  NaClCopyTakeLock(nap);
  memcpy((void *) dst_sys_addr, src_sys_ptr, num_bytes);
  NaClCopyDropLock(nap);

  return 1;
}
