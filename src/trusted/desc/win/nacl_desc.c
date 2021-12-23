/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Service Runtime.  I/O Descriptor / Handle abstraction.  Memory
 * mapping using descriptors.
 */

#include "native_client/src/include/portability.h"
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_host_desc.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/trusted/desc/nacl_desc_base.h"
#include "native_client/src/trusted/desc/nacl_desc_sync_socket.h"
#include "native_client/src/trusted/service_runtime/nacl_config.h"
#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/include/sys/stat.h"

void NaClDescUnmapUnsafe(struct NaClDesc *desc, void *addr, size_t length) {
  int rc = (*NACL_VTBL(NaClDesc, desc)->UnmapUnsafe)(desc, addr, length);
  if (rc != 0) {
    NaClLog(LOG_FATAL,
            "NaClDescUnmapUnsafe: UnmapUnsafe() failed, rc %d, error %d\n",
            rc, GetLastError());
  }
}



/* Read/write to a NaClHandle */
ssize_t NaClDescReadFromHandle(NaClHandle handle,
                               void       *buf,
                               size_t     length) {
  size_t count = 0;
  CHECK(length < kMaxSyncSocketMessageLength);

  while (count < length) {
    DWORD len;
    DWORD chunk = (DWORD) (
      ((length - count) <= UINT_MAX) ? (length - count) : UINT_MAX);
    if (ReadFile(handle, (char *) buf + count,
                 chunk, &len, NULL) == FALSE) {
      return (ssize_t) ((0 < count) ? count : -1);
    }
    count += len;
  }
  return (ssize_t) count;
}

ssize_t NaClDescWriteToHandle(NaClHandle handle,
                              void const *buf,
                              size_t     length) {
  size_t count = 0;
  CHECK(length < kMaxSyncSocketMessageLength);

  while (count < length) {
    DWORD len;
    DWORD chunk = (DWORD) (
      ((length - count) <= UINT_MAX) ? (length - count) : UINT_MAX);
    if (WriteFile(handle, (const char *) buf + count,
                  chunk, &len, NULL) == FALSE) {
      return (ssize_t) ((0 < count) ? count : -1);
    }
    count += len;
  }
  return (ssize_t) count;
}
