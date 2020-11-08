/*
 * Copyright (c) 2013 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "native_client/src/trusted/service_runtime/load_file.h"

#include "native_client/src/trusted/desc/nacl_desc_base.h"
#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"
#include "native_client/src/trusted/service_runtime/nacl_valgrind_hooks.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_helpers.h"



NaClErrorCode NaClAppLoadFileFromFilename(struct NaClApp *nap,
                                          const char *filename) {
  int fd  
  NaClErrorCode err;

  NaClFileNameForValgrind(filename);

  fd = NaClOpenHelper(filename, NACL_ABI_O_RDONLY,
                                              0666, nap->cage_id);
  if (fd < 0) {
    return LOAD_OPEN_ERROR;
  }

  err = NaClAppLoadFile(fd, nap);

  if (err != LOAD_OK) {
    return err;
  }

  return err;
}
