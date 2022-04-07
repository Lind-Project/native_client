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

  /* We don't need to check protections here
   * this is used by nacl_syscall_handlers, and we can check the actual args later
   */
  src_sys_addr = NaClUserToSysAddrRange(nap, src_usr_addr, num_bytes);
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
  CHECK(dst_buffer_bytes > 0);


  src_sys_addr = NaClUserToSysAddr(nap, src_usr_addr);
  if (kNaClBadAddress == src_sys_addr) {
    dst_buffer[0] = '\0';
    return 0;
  }

  uintptr_t check_addr = src_usr_addr;
  int bytes_copied = 0;

  /*
   * We need to handle NULL terminated strings that possibly could overlap VMMap entries,
   * are not actually NULL terminated, or are longer than the destination buffer.
   * To do this we check the mapping of the starting address, and copy what we can from that page.
   * If it overlaps we continue on to check the next page.
   * Exit conditions are: 1) page is non-valid, 2) we've found a NULL character, 3) we've copied up to the destination length
   */

  NaClCopyTakeLock(nap);
  while (1) {
    uintptr_t page_end = NaClVmmapCheckAddrMapping( &nap->mem_map, check_addr >> NACL_PAGESHIFT, 1, NACL_ABI_PROT_READ);
    if (!page_end) break;
    int page_room = (page_end << NACL_PAGESHIFT) - check_addr;
    int dst_bytes_remaining = dst_buffer_bytes - bytes_copied;
    int copy_bytes = page_room < dst_bytes_remaining ? page_room : dst_bytes_remaining;
    strncpy(dst_buffer + bytes_copied, (char *) src_sys_addr + bytes_copied, copy_bytes);
    bytes_copied = bytes_copied + copy_bytes;
    if (strnlen(dst_buffer, bytes_copied) < bytes_copied) break;
    if (bytes_copied == dst_buffer_bytes) break;
    check_addr = (page_end + 1) << NACL_PAGESHIFT;
  }
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
