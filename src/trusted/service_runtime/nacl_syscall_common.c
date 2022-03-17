/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl service run-time, non-platform specific system call helper routines.
 */

#include <sys/stat.h>
#include <sys/types.h>

/* avoid errors caused by conflicts with feature_test_macros(7) */
#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE

#include <stdio.h>
#include <Python.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <netinet/in.h>


#include "native_client/src/trusted/service_runtime/nacl_syscall_common.h"

#include "native_client/src/include/nacl_assert.h"
#include "native_client/src/include/nacl_macros.h"
#include "native_client/src/include/nacl_platform.h"
#include "native_client/src/include/portability_process.h"
#include "native_client/src/include/portability_string.h"

#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_clock.h"
#include "native_client/src/shared/platform/nacl_exit.h"
#include "native_client/src/shared/platform/nacl_host_desc.h"
#include "native_client/src/shared/platform/nacl_host_dir.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/shared/platform/nacl_sync_checked.h"
#include "native_client/src/shared/platform/nacl_time.h"

#include "native_client/src/trusted/desc/nacl_desc_base.h"
#include "native_client/src/trusted/desc/nacl_desc_cond.h"
#include "native_client/src/trusted/desc/nacl_desc_dir.h"
#include "native_client/src/trusted/desc/nacl_desc_effector_trusted_mem.h"
#include "native_client/src/trusted/desc/nacl_desc_imc.h"
#include "native_client/src/trusted/desc/nacl_desc_imc_shm.h"
#include "native_client/src/trusted/desc/nacl_desc_invalid.h"
#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/trusted/desc/nacl_desc_mutex.h"
#include "native_client/src/trusted/desc/nacl_desc_semaphore.h"
#include "native_client/src/trusted/desc/nrd_xfer.h"

#include "native_client/src/trusted/fault_injection/fault_injection.h"

#include "native_client/src/trusted/service_runtime/include/bits/mman.h"
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"
#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"
#include "native_client/src/trusted/service_runtime/include/sys/stat.h"

#include "native_client/src/trusted/service_runtime/include/sys/nacl_test_crash.h"
#include "native_client/src/trusted/service_runtime/internal_errno.h"

#include "native_client/src/trusted/service_runtime/nacl_app_thread.h"
#include "native_client/src/trusted/service_runtime/nacl_copy.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_signal.h"
#include "native_client/src/trusted/service_runtime/nacl_switch_to_app.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_handlers.h"
#include "native_client/src/trusted/service_runtime/nacl_text.h"
#include "native_client/src/trusted/service_runtime/nacl_thread_nice.h"
#include "native_client/src/trusted/service_runtime/nacl_tls.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/sel_memory.h"
#include "native_client/src/trusted/service_runtime/thread_suspension.h"
#include "native_client/src/trusted/service_runtime/win/debug_exception_handler.h"

#if NACL_WINDOWS
#  include "native_client/src/trusted/service_runtime/win/debug_exception_handler.h"
#  include "native_client/src/shared/platform/win/xlate_system_error.h"
#endif

#include "native_client/src/trusted/validator/ncvalidate.h"
#include "native_client/src/trusted/validator/validation_metadata.h"
#include "native_client/src/trusted/service_runtime/env_cleanser.h"
#include "native_client/src/trusted/service_runtime/nacl_all_modules.h"
#include "native_client/src/trusted/service_runtime/nacl_app.h"
#include "native_client/src/trusted/service_runtime/load_file.h"

#define kKnownInvalidDescNumber (-1)
#define kdefault_io_buffer_bytes_to_log 64ull
#define kMaxUsableFileSize (SIZE_MAX >> 1)
#define MIN(a, b) ((size_t)((a < b) ? a : b))

struct NaClDescQuotaInterface;
struct NaClSyscallTableEntry nacl_syscall[NACL_MAX_SYSCALLS];

// Translate Host FD to NaclDesc
// if functions returns NULL, calling function should return -NACL_ABI_EBADF
struct NaClDesc *GetDescFromCagetable(struct NaClApp *nap, int fd) {

  if ((fd >= FILE_DESC_MAX) || (fd < 0)) {
    return NULL;
  }

  int naclfd = fd_cage_table[nap->cage_id][fd];
  if (naclfd < 0) {
    return NULL;
  }
  
  return NaClGetDesc(nap, naclfd);
}

// extract lindfd from NaClDesc
int NaClDesc2Lindfd(struct NaClDesc * ndp) {
  return ((struct NaClDescIoDesc *) ndp)->hd->d;
}

int32_t NaClSysNotImplementedDecoder(struct NaClAppThread *natp) {
  NaClCopyDropLock(natp->nap);
  return -NACL_ABI_ENOSYS;
}

void NaClAddSyscall(int num, int32_t (*fn)(struct NaClAppThread *)) {
  if (nacl_syscall[num].handler != &NaClSysNotImplementedDecoder) {
    NaClLog(LOG_FATAL, "Duplicate syscall number %d\n", num);
  }
  nacl_syscall[num].handler = fn;
}

int32_t NaClSysNull(struct NaClAppThread *natp) {
  UNREFERENCED_PARAMETER(natp);
  return 0;
}

int32_t NaClSysBrk(struct NaClAppThread *natp,
                   uintptr_t            new_break) {
  struct NaClApp        *nap = natp->nap;
  uintptr_t             break_addr;
  int32_t               rv = -NACL_ABI_EINVAL;
  struct NaClVmmapIter  iter;
  struct NaClVmmapEntry *ent;
  struct NaClVmmapEntry *next_ent;
  uintptr_t             sys_break;
  uintptr_t             sys_new_break;
  uintptr_t             usr_last_data_page;
  uintptr_t             usr_new_last_data_page;
  uintptr_t             last_internal_data_addr;
  uintptr_t             last_internal_page;
  uintptr_t             start_new_region;
  uintptr_t             region_size;

  break_addr = nap->break_addr;

  NaClLog(3, "Entered NaClSysBrk(new_break 0x%08"NACL_PRIxPTR")\n",
          new_break);

  sys_new_break = NaClUserToSysAddr(nap, new_break);
  NaClLog(3, "sys_new_break 0x%08"NACL_PRIxPTR"\n", sys_new_break);

  if (kNaClBadAddress == sys_new_break) {
    goto cleanup_no_lock;
  }
  if (NACL_SYNC_OK != NaClMutexLock(&nap->mu)) {
    NaClLog(LOG_ERROR, "Could not get app lock for 0x%08"NACL_PRIxPTR"\n",
            (uintptr_t) nap);
    goto cleanup_no_lock;
  }
  if (new_break < nap->data_end) {
    NaClLog(4, "new_break before data_end (0x%"NACL_PRIxPTR")\n",
            nap->data_end);
    goto cleanup;
  }
  if (new_break <= nap->break_addr) {
    /* freeing memory */
    NaClLog(4, "new_break before break (0x%"NACL_PRIxPTR"); freeing\n",
            nap->break_addr);
    nap->break_addr = new_break;
    break_addr = new_break;
  } else {
    /*
     * See if page containing new_break is in mem_map; if so, we are
     * essentially done -- just update break_addr.  Otherwise, we
     * extend the VM map entry from the page containing the current
     * break to the page containing new_break.
     */

    sys_break = NaClUserToSys(nap, nap->break_addr);

    usr_last_data_page = (nap->break_addr - 1) >> NACL_PAGESHIFT;

    usr_new_last_data_page = (new_break - 1) >> NACL_PAGESHIFT;

    last_internal_data_addr = NaClRoundAllocPage(new_break) - 1;
    last_internal_page = last_internal_data_addr >> NACL_PAGESHIFT;

    NaClLog(4, ("current break sys addr 0x%08"NACL_PRIxPTR", "
                "usr last data page 0x%"NACL_PRIxPTR"\n"),
            sys_break, usr_last_data_page);
    NaClLog(4, "new break usr last data page 0x%"NACL_PRIxPTR"\n",
            usr_new_last_data_page);
    NaClLog(4, "last internal data addr 0x%08"NACL_PRIxPTR"\n",
            last_internal_data_addr);

    if (!NaClVmmapFindPageIter(&nap->mem_map, usr_last_data_page, &iter)
        || NaClVmmapIterAtEnd(&iter)) {
      NaClLog(LOG_FATAL, ("current break (0x%08"NACL_PRIxPTR", "
                          "sys 0x%08"NACL_PRIxPTR") "
                          "not in address map\n"),
              nap->break_addr, sys_break);
    }
    ent = NaClVmmapIterStar(&iter);
    NaClLog(4, ("segment containing current break"
                ": page_num 0x%08"NACL_PRIxPTR", npages 0x%"NACL_PRIxS"\n"),
            ent->page_num, ent->npages);
    if (usr_new_last_data_page < ent->page_num + ent->npages) {
      NaClLog(4, "new break within break segment, just bumping addr\n");
      nap->break_addr = new_break;
      break_addr = new_break;
    } else {
      NaClVmmapIterIncr(&iter);
      if (!NaClVmmapIterAtEnd(&iter)
          && ((next_ent = NaClVmmapIterStar(&iter))->page_num
              <= last_internal_page)) {
        /* ran into next segment! */
        NaClLog(4,
                ("new break request of usr address "
                 "0x%08"NACL_PRIxPTR" / usr page 0x%"NACL_PRIxPTR
                 " runs into next region, page_num 0x%"NACL_PRIxPTR", "
                 "npages 0x%"NACL_PRIxS"\n"),
                new_break, usr_new_last_data_page,
                next_ent->page_num, next_ent->npages);
        goto cleanup;
      }
      NaClLog(4,
              "extending segment: page_num 0x%08"NACL_PRIxPTR", "
              "npages 0x%"NACL_PRIxS"\n",
              ent->page_num, ent->npages);
      /* go ahead and extend ent to cover, and make pages accessible */
      start_new_region = (ent->page_num + ent->npages) << NACL_PAGESHIFT;
      ent->npages = (last_internal_page - ent->page_num + 1);
      region_size = (((last_internal_page + 1) << NACL_PAGESHIFT)
                     - start_new_region);
      if (NaClMprotect((void *) NaClUserToSys(nap, start_new_region),
                            region_size,
                            PROT_READ | PROT_WRITE)) {
        NaClLog(LOG_FATAL,
                ("Could not mprotect(0x%08"NACL_PRIxPTR", "
                 "0x%08"NACL_PRIxPTR", "
                 "PROT_READ|PROT_WRITE)\n"),
                start_new_region,
                region_size);
      }
      NaClLog(4, "segment now: page_num 0x%08"NACL_PRIxPTR", "
              "npages 0x%"NACL_PRIxS"\n",
              ent->page_num, ent->npages);
      nap->break_addr = new_break;
      break_addr = new_break;
    }
    /*
     * Zero out memory between old break and new break.
     */
    ASSERT(sys_new_break > sys_break);
    memset((void *) sys_break, 0, sys_new_break - sys_break);
  }



cleanup:
  NaClXMutexUnlock(&nap->mu);
cleanup_no_lock:

  /*
   * This cast is safe because the incoming value (new_break) cannot
   * exceed the user address space--even though its type (uintptr_t)
   * theoretically allows larger values.
   */
  rv = (int32_t) break_addr;

  NaClLog(3, "NaClSysBrk: returning 0x%08"NACL_PRIx32"\n", rv);
  return rv;
}

int NaClAclBypassChecks = 0;

void NaClInsecurelyBypassAllAclChecks(void) {
  NaClLog(LOG_WARNING, "BYPASSING ALL ACL CHECKS\n");
  NaClAclBypassChecks = 1;
}

int NaClHighResolutionTimerEnabled(void) {
  return NaClAclBypassChecks;
}

/*
 * NaClOpenAclCheck: Is the NaCl app authorized to open this file?  The
 * return value is syscall return convention, so 0 is success and
 * small negative numbers are negated errno values.
 */
int32_t NaClOpenAclCheck(struct NaClApp *nap,
                         char const     *path,
                         int            flags,
                         int            mode) {
  /*
   * TODO(bsy): provide some minimal authorization check, based on
   * whether a debug flag is set; eventually provide a data-driven
   * authorization configuration mechanism, perhaps persisted via
   * gears.  need GUI for user configuration, as well as designing an
   * appropriate language (with sufficient expressiveness), however.
   */
  NaClLog(1, "NaClOpenAclCheck(0x%08"NACL_PRIxPTR", %s, 0%o, 0%o)\n",
          (uintptr_t) nap, path, flags, mode);
  NaClLog(4, "O_ACCMODE: 0%o\n", flags & NACL_ABI_O_ACCMODE);
  NaClLog(4, "O_RDONLY = %d\n", NACL_ABI_O_RDONLY);
  NaClLog(4, "O_WRONLY = %d\n", NACL_ABI_O_WRONLY);
  NaClLog(4, "O_RDWR   = %d\n", NACL_ABI_O_RDWR);
#define FLOG(VAR, BIT) NaClLog(1, "%s: %s\n", #BIT, ((VAR) & (BIT)) ? "yes" : "no")
    FLOG(flags, NACL_ABI_O_CREAT);
    FLOG(flags, NACL_ABI_O_TRUNC);
    FLOG(flags, NACL_ABI_O_APPEND);
#undef FLOG
  if (NaClAclBypassChecks) {
    return 0;
  }
  return -NACL_ABI_EACCES;
}

/*
 * NaClStatAclCheck: Is the NaCl app authorized to stat this pathname?  The
 * return value is syscall return convention, so 0 is success and
 * small negative numbers are negated errno values.
 *
 * This is primarily for debug use.  File access should be through
 * SRPC-based file servers.
 */
int32_t NaClStatAclCheck(struct NaClApp *nap,
                         char const     *path) {
  NaClLog(2,
          "NaClStatAclCheck(0x%08"NACL_PRIxPTR", %s)\n", (uintptr_t) nap, path);
  if (NaClAclBypassChecks) {
    return 0;
  }
  return -NACL_ABI_EACCES;
}

int32_t NaClIoctlAclCheck(struct NaClApp  *nap, //Unused for now
                          struct NaClDesc *ndp,
                          unsigned long   request,
                          void            *arg) {
  NaClLog(2,
          ("NaClIoctlAclCheck(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR","
           " %d, 0x%08"NACL_PRIxPTR"\n"),
          (uintptr_t) nap, (uintptr_t) ndp, request, (uintptr_t) arg);
  if (NaClAclBypassChecks) {
    return 0;
  }
  return -NACL_ABI_EINVAL;
}

int32_t NaClSysGetpid(struct NaClAppThread *natp) {
  int32_t pid;
  struct NaClApp *nap = natp->nap;

  pid = lind_getpid(nap->cage_id);
  NaClLog(1, "NaClSysGetpid: returning %d\n", pid);

  return pid;
}

int32_t NaClSysGetppid(struct NaClAppThread *natp) {
  int32_t ppid;
  struct NaClApp *nap = natp->nap;

  ppid = lind_getppid(nap->cage_id);
  NaClLog(1, "NaClSysGetpid: returning %d\n", ppid);

  return ppid;
}

int32_t NaClSysExit(struct NaClAppThread  *natp,
                    int                   status) {

  struct NaClApp *nap = natp->nap;
  lind_exit(status, nap->cage_id);
  NaClLog(1, "Exit syscall handler: %d\n", status);
  (void) NaClReportExitStatus(nap, NACL_ABI_W_EXITCODE(status, 0));
  NaClAppThreadTeardown(natp);
  free((void*) nap->clean_environ);
  /* NOTREACHED */
  return -NACL_ABI_EINVAL;

}

int32_t NaClSysThreadExit(struct NaClAppThread  *natp,
                          int32_t               *stack_flag) {
  uint32_t  zero = 0;

  NaClLog(4, "NaClSysThreadExit(0x%08"NACL_PRIxPTR", "
          "0x%08"NACL_PRIxPTR"\n",
          (uintptr_t) natp,
          (uintptr_t) stack_flag);
  /*
   * NB: NaClThreads are never joinable, but the abstraction for NaClApps
   * are.
   */

  if (stack_flag) {
    NaClLog(2, "aClSysThreadExit: stack_flag is %"NACL_PRIxPTR"\n", (uintptr_t)stack_flag);
    if (!NaClCopyOutToUser(natp->nap, (uintptr_t) stack_flag, &zero, sizeof(zero))) {
      NaClLog(2, "NaClSysThreadExit: ignoring invalid"
               " stack_flag 0x%"NACL_PRIxPTR"\n",
               (uintptr_t)stack_flag);
    }
  }

  NaClAppThreadTeardown(natp);
  /* NOTREACHED */
  return -NACL_ABI_EINVAL;
}

int32_t NaClSysNameService(struct NaClAppThread *natp,
                           int32_t              *desc_addr) {
  struct NaClApp *nap = natp->nap;
  int32_t   retval = -NACL_ABI_EINVAL;
  int32_t   desc;

  NaClLog(3,
          ("NaClSysNameService(0x%08"NACL_PRIxPTR","
           " 0x%08"NACL_PRIxPTR")\n"),
          (uintptr_t) natp,
          (uintptr_t) desc_addr);

  if (!NaClCopyInFromUser(nap, &desc, (uintptr_t) desc_addr, sizeof(desc))) {
    NaClLog(LOG_ERROR,
            "Invalid address argument to NaClSysNameService\n");
    retval = -NACL_ABI_EFAULT;
    goto done;
  }

  if (-1 == desc) {
    /* read */
    desc = NaClSetAvail(nap, NaClDescRef(nap->name_service_conn_cap));
    if (NaClCopyOutToUser(nap, (uintptr_t) desc_addr,
                          &desc, sizeof(desc))) {
      retval = 0;
    } else {
      retval = -NACL_ABI_EFAULT;
    }
  } else {
    struct NaClDesc *desc_obj_ptr = NaClGetDesc(nap, desc);

    if (!desc_obj_ptr) {
      retval = -NACL_ABI_EBADF;
      goto done;
    }
    if (NACL_DESC_CONN_CAP != NACL_VTBL(NaClDesc, desc_obj_ptr)->typeTag &&
        NACL_DESC_CONN_CAP_FD != NACL_VTBL(NaClDesc, desc_obj_ptr)->typeTag) {
      retval = -NACL_ABI_EINVAL;
      goto done;
    }
    /* write */
    NaClXMutexLock(&nap->mu);
    NaClDescUnref(nap->name_service_conn_cap);
    nap->name_service_conn_cap = desc_obj_ptr;
    NaClXMutexUnlock(&nap->mu);
    retval = 0;
  }

 done:
  return retval;
}

int32_t NaClSysDup(struct NaClAppThread *natp, int oldfd) {
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *old_nd;
  int old_hostfd;
  int new_desc;
  int ret;

  NaClLog(1, "NaClSysDup(0x%08"NACL_PRIxPTR", %d)\n", (uintptr_t)natp, oldfd);

  if ((oldfd >= FILE_DESC_MAX)  || (oldfd < 0)) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }

  old_hostfd = fd_cage_table[nap->cage_id][oldfd];

  if (old_hostfd < 0) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }

  if (!(old_nd = NaClGetDesc(nap, old_hostfd))) {
    ret= -NACL_ABI_EBADF;
    goto out;
  }

  /* Translate from NaCl Desc to Host Desc */
  struct NaClDescIoDesc *self = (struct NaClDescIoDesc *) &old_nd->base;
  struct NaClHostDesc *old_hd = self->hd;

  /* Create and set vars for child hd */
  struct NaClHostDesc *new_hd;
  new_hd = malloc(sizeof(*new_hd));
  if (!new_hd) {
      NaClLog(LOG_FATAL, "NaClSysDup: Error initializing new descriptor\n");
  }

  new_hd->d = lind_dup(old_hd->d, nap->cage_id);
  new_hd->flags = old_hd->flags  & ~NACL_ABI_O_CLOEXEC; // dup does not pass on CLOEXEC flag
  new_hd->cageid = nap->cage_id;

  /* Set new nacl desc as available */
  int new_hostfd = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(new_hd)));

  /* We've got to put that old NaClDescriptor back in there... */
  NaClSetDesc(nap, old_hostfd, old_nd);

  ret = NextFd(nap->cage_id);
  new_hd->userfd = ret;
  fd_cage_table[nap->cage_id][ret] = new_hostfd;


out:
  return ret;
}

int32_t NaClSysDup2(struct NaClAppThread  *natp,
                    int                   oldfd,
                    int                   newfd) {
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *old_nd;
  struct NaClDesc *new_nd;

  int old_hostfd;
  int new_hostfd;
  int ret;

  NaClLog(1, "%s\n", "[dup2] Entered dup2!");
  NaClLog(1, "[dup2] cage id = %d \n", nap->cage_id);
  NaClLog(1, "[dup2] oldfd = %d \n", oldfd);
  NaClLog(1, "[dup2] newfd = %d \n", newfd);

  if ((oldfd >= FILE_DESC_MAX)  || (oldfd < 0)) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }

  if ((newfd >= FILE_DESC_MAX)  || (newfd < 0)) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }

  if (newfd >= FILE_DESC_MAX) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }

  if (oldfd == newfd) {
    ret = oldfd;
    goto out;
  }

  /* Get old host fd from cage table, and use that to get nacl descriptor */
  old_hostfd = fd_cage_table[nap->cage_id][oldfd];

  if (old_hostfd < 0) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }
  
  if (!(old_nd = NaClGetDesc(nap, old_hostfd))) {
    ret = -NACL_ABI_EBADF;
    goto out;
  }

  /* Translate from NaCl Desc to Host Desc */
  struct NaClDescIoDesc *old_self = (struct NaClDescIoDesc *) &old_nd->base;
  struct NaClHostDesc *old_hd = old_self->hd;

  /* Check if newfd exists 

    Scenarios
    1. new_hostfd is < 0 - this implies that newfd has been a number specified by the user and we should create
    a new nacl desc and dup it via regular dup
    2. new_hostfd is >= 0 - we have this fd already, lets dup it

  
  */

  new_hostfd = fd_cage_table[nap->cage_id][newfd];


  if (new_hostfd < 0) {
    
    /* Scenario 1: Create and set vars for new hd */
    struct NaClHostDesc *new_hd;
    new_hd = malloc(sizeof(*new_hd));
    if (!new_hd) {
        NaClLog(LOG_FATAL, "NaClSysDup2: Error initializing new descriptor\n");
    }

    /* We have to use regular dup at this point because were creating a lind FD from scratch */

    new_hd->d = lind_dup(old_hd->d, nap->cage_id);
    new_hd->flags = old_hd->flags & ~NACL_ABI_O_CLOEXEC; // dup does not pass on CLOEXEC flag
    new_hd->cageid = nap->cage_id;
    new_hd->userfd = newfd;

    /* Set new nacl desc as available */
    int new_hostfd = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(new_hd)));
    /* and add the new hostfd to the cage table */
    fd_cage_table[nap->cage_id][newfd] = new_hostfd;



  }
  else {
    /* Scenario 2 */

    new_nd = NaClGetDesc(nap, new_hostfd);
    if (!new_nd) {
      ret = -NACL_ABI_EBADF;
      goto out;
    }

    /* Translate from NaCl Desc to Host Desc */
    struct NaClDescIoDesc *new_self = (struct NaClDescIoDesc *) &new_nd->base;
    struct NaClHostDesc *new_hd = new_self->hd;

    new_hd->d = lind_dup2(old_hd->d, new_hd->d, nap->cage_id);
    new_hd->flags = old_hd->flags  & ~NACL_ABI_O_CLOEXEC; // dup does not pass on CLOEXEC flag
    new_hd->cageid = nap->cage_id;

    /* Re-add the nacl desc to the nap */
    NaClSetDesc(nap, new_hostfd, new_nd);
  }
  
  /* We've got to put that old NaClDescriptor back in there... */
  NaClSetDesc(nap, old_hostfd, old_nd);
  
  ret = newfd;

out:
  return ret;
}

int32_t NaClSysDup3(struct NaClAppThread  *natp,
                    int                   oldfd,
                    int                   newfd,
                    int                   flags) {
  struct NaClApp *nap = natp->nap;
  int ret;

  NaClLog(1, "%s\n", "[dup3] Entered dup3!");
  NaClLog(1, "[dup3] cage id = %d \n", nap->cage_id);
  NaClLog(1, "[dup3] oldfd = %d \n", oldfd);
  NaClLog(1, "[dup3] newfd = %d \n", newfd);

  UNREFERENCED_PARAMETER(nap);
  UNREFERENCED_PARAMETER(ret);
  /*
   * TODO: implement dup3 flags -jp
   */
  UNREFERENCED_PARAMETER(flags);

  return NaClSysDup2(natp, oldfd, newfd);
}

static uint32_t CopyPathFromUser(struct NaClApp *nap,
                                 char           *dest,
                                 size_t         num_bytes,
                                 uintptr_t      src) {
  /*
   * NaClCopyInFromUserZStr may (try to) get bytes that is outside the
   * app's address space and generate a fault.
   */
  if (!NaClCopyInFromUserZStr(nap, dest, num_bytes, src)) {
    if (dest[0] == '\0') {
      NaClLog(LOG_ERROR, "NaClSys: invalid address for pathname\n");
      return -NACL_ABI_EFAULT;
    }

    NaClLog(LOG_ERROR, "NaClSys: pathname string too long\n");
    return -NACL_ABI_ENAMETOOLONG;
  }

  return 0;
}

int32_t NaClSysOpen(struct NaClAppThread  *natp,
                    char                  *pathname,
                    int                   flags,
                    int                   mode) {
  struct NaClApp       *nap = natp->nap;
  int                  retval = -NACL_ABI_EINVAL;
  char                 path[NACL_CONFIG_PATH_MAX];
  nacl_host_stat_t     stbuf;
  int                  allowed_flags;
  int                  fd_retval = -1;
  const char           *glibc_prefix = "/lib/glibc/";
  const char           *tls_prefix = "/lib/glibc/tls/";
  const size_t         tls_start_idx = strlen(glibc_prefix);
  const size_t         tls_end_idx = strlen(tls_prefix);

  /* this is the virtual fd returned to the cage */
  struct NaClHostDesc  *hd = NULL;


  NaClLog(2, "NaClSysOpen(0x%08"NACL_PRIxPTR", "
          "0x%08"NACL_PRIxPTR", 0x%x, 0x%x)\n",
          (uintptr_t)natp, (uintptr_t)pathname, flags, mode);

  retval = CopyPathFromUser(nap, path, sizeof(path), (uintptr_t)pathname);

  /*
   * TODO:
   * find a cleaner method to prevent the
   * runtime linker from searching for libc
   * in /lib/glibc/tls/ (this removes the
   * tls/ path component).
   *
   * -jp
   */
  if (!memcmp(path, tls_prefix, sizeof(tls_prefix) - 1)) {
    char *left_side = path + tls_start_idx;
    char *right_side = path + tls_end_idx;
    size_t len_of_rest = strlen(right_side) + 1;
    memmove(left_side, right_side, len_of_rest);
  }

  if (retval) {
    goto cleanup;
  }

  allowed_flags = (NACL_ABI_O_ACCMODE | NACL_ABI_O_CREAT
                   | NACL_ABI_O_TRUNC | NACL_ABI_O_APPEND | 
                   NACL_ABI_O_CLOEXEC);
  if (flags & ~allowed_flags) {
    NaClLog(1, "Invalid open flags 0%o, ignoring extraneous bits\n", flags);
    flags &= allowed_flags;
  }
  if (mode & ~0600) {
    NaClLog(1, "IGNORING Invalid access mode bits 0%o\n", mode);
    mode &= 0600;
  }

  retval = NaClOpenAclCheck(nap, path, flags, mode);
  if (retval) {
    NaClLog(2, "Open ACL check rejected \"%s\".\n", path);
    goto cleanup;
  }

  hd = malloc(sizeof(*hd));
  if (!hd) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup;
  }
  /* Assign CageID to Host Descriptor */
  hd->cageid = nap->cage_id;

  retval = NaClHostDescOpen(hd, path, flags, mode);
  NaClLog(1, "Cage %d NaClHostDescOpen(0x%08"NACL_PRIxPTR", %s, 0%o, 0%o) returned %d\n",
          nap->cage_id, (uintptr_t) hd, path, flags, mode, retval);
  
  if (retval < 0) {
    NaClLog(1, "Open returned error %d\n", retval);
    return -NACL_ABI_EPERM;
  }
  
  fd_retval = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd)));
  NaClLog(1, "Entered into open file table at %d\n", retval);


cleanup:
  /*
    Now translate the real fds to virtual fds and return them to the cage 
    Get next available, and set cagetable there to nacl retval
  */
  
  retval = NextFd(nap->cage_id);
  if(hd) {
    hd->userfd = retval;
  }
  fd_cage_table[nap->cage_id][retval] = fd_retval;
  NaClLog(1, "[NaClSysOpen] fd = %d, filepath = %s \n", retval, path);

  return retval;
}

int32_t NaClSysClose(struct NaClAppThread *natp, int d) {
  struct NaClApp  *nap = natp->nap;
  struct NaClDesc *ndp = NULL;
  int             ret = -NACL_ABI_EBADF;
  int             fd = 0;

  NaClLog(1, "Cage %d Entered NaClSysClose(0x%08"NACL_PRIxPTR", %d)\n",
          nap->cage_id, (uintptr_t) natp, d);

  if (d >= FILE_DESC_MAX) {
    return -NACL_ABI_EBADF;
  }

  /* there is no standard input to close, but return success anyway */
  if (!d) {
    return 0;
  }

  NaClFastMutexLock(&nap->desc_mu);

  /* Let's find the fd from the cagetable, and then get the NaCl descriptor based on that fd */
  fd = fd_cage_table[nap->cage_id][d];
  ndp = NaClGetDescMu(nap, fd);

  /* If we have an fd and nacl descriptor, lets close it */
  if (fd >= 0 && ndp){
    NaClLog(1, "Invoking Close virtual function of object 0x%08"NACL_PRIxPTR"\n", (uintptr_t) ndp);
    NaClSetDescMu(nap, fd, NULL);
    NaClDescUnref(ndp);
    ret = 0;
  }

  /* mark file descriptor d as invalid (stdin is not a valid file descriptor) */
  fd_cage_table[nap->cage_id][d] = NACL_BAD_FD;

  NaClFastMutexUnlock(&nap->desc_mu);
  return ret;
}

int32_t NaClSysGetdents(struct NaClAppThread *natp,
                        int                  d,
                        void                 *dirp,
                        size_t               count) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  ssize_t         getdents_ret;
  uintptr_t       sysaddr;
  struct NaClDesc *ndp;

  int fd;

  NaClLog(1, "Entered NaClSysGetdents(0x%08"NACL_PRIxPTR","
          " %d, 0x%08"NACL_PRIxPTR","
          " %"NACL_PRIdS"[0x%"NACL_PRIxS"])\n",
          (uintptr_t) natp, d, (uintptr_t) dirp, count, count);

  ndp = GetDescFromCagetable(nap, d);
  if (!ndp) {
    return - NACL_ABI_EBADF;
  }
  int lind_fd = NaClDesc2Lindfd(ndp);

  /*
   * Generic NaClCopyOutToUser is not sufficient, since buffer size
   * |count| is arbitrary and we wouldn't want to have to allocate
   * memory in trusted address space to match.
   */
  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) dirp, count);
  if (kNaClBadAddress == sysaddr) {
    NaClLog(4, " illegal address for directory data\n");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  /*
   * Clamp count to INT32_MAX to avoid the possibility of Getdents returning
   * a value that is outside the range of an int32.
   */
  if (count > INT32_MAX) {
    count = INT32_MAX;
  }

  /*
   * Grab addr space lock; getdents should not normally block, though
   * if the directory is on a networked filesystem this could, and
   * cause mmap to be slower on Windows.
   */
  NaClXMutexLock(&nap->mu);

  getdents_ret = lind_getdents(lind_fd,
                              (void *) sysaddr,
                              count,
                              nap->cage_id);
  NaClXMutexUnlock(&nap->mu);
  /* drop addr space lock */
  if ((getdents_ret < INT32_MIN && !NaClSSizeIsNegErrno(&getdents_ret))
      || INT32_MAX < getdents_ret) {
    /* This should never happen, because we already clamped the input count */
    NaClLog(LOG_FATAL, "Overflow in Getdents: return value is %"NACL_PRIxS,
            getdents_ret);
  } else {
    retval = (int32_t) getdents_ret;
  }
  if (retval > 0) {
    NaClLog(4, "getdents returned %d bytes\n", retval);
    NaClLog(8, "getdents result: %.*s\n", retval, (char *) sysaddr);
  } else {
    NaClLog(4, "getdents returned %d\n", retval);
  }

cleanup:
  NaClDescUnref(ndp);
  return retval;
}

int32_t NaClSysRead(struct NaClAppThread  *natp,
                    int                   d,
                    void                  *buf,
                    size_t                count) {
  struct NaClApp  *nap = natp->nap;
  int             fd = fd_cage_table[nap->cage_id][d];
  int32_t         retval = -NACL_ABI_EINVAL;
  ssize_t         read_result = -NACL_ABI_EINVAL;
  uintptr_t       sysaddr;
  struct NaClDesc *ndp;
  size_t          log_bytes;
  char const      *ellipsis = "";

  NaClLog(2, "Cage %d Entered NaClSysRead(0x%08"NACL_PRIxPTR", "
           "%d, 0x%08"NACL_PRIxPTR", "
           "%"NACL_PRIdS"[0x%"NACL_PRIxS"])\n",
          nap->cage_id, (uintptr_t) natp, d, (uintptr_t) buf, count, count);

  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  /* check for closed fds */
  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  NaClFastMutexLock(&nap->desc_mu);
  /* It's fine to not do a ref here because the mutex will assure that a close() can't be called in between */
  ndp = NaClGetDescMuNoRef(nap, fd);

  NaClLog(2, " ndp = %"NACL_PRIxPTR"\n", (uintptr_t) ndp);
  if (!ndp) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) buf, count);
  if (kNaClBadAddress == sysaddr) {
    retval = -NACL_ABI_EFAULT;
    goto out;
  }

  /*
   * The maximum length for read and write is INT32_MAX--anything larger and
   * the return value would overflow. Passing larger values isn't an error--
   * we'll just clamp the request size if it's too large.
   */
  if (count > INT32_MAX) {
    count = INT32_MAX;
  }


  /* Lind - we removed the VMIOWillStart and End functions here, which is fine for Linux
   * See note in sel_ldr.h
   */
  read_result = ((struct NaClDescVtbl const *)ndp->base.vtbl)->Read(ndp, (void *)sysaddr, count);

  if (read_result > 0) {
    NaClLog(4, "read returned %"NACL_PRIdS" bytes\n", read_result);
    log_bytes = (size_t) read_result;
    if (log_bytes > INT32_MAX) {
      log_bytes = INT32_MAX;
      ellipsis = "...";
    }
    if (log_bytes > kdefault_io_buffer_bytes_to_log) {
      log_bytes = kdefault_io_buffer_bytes_to_log;
      ellipsis = "...";
    }
    NaClLog(8, "read result: %.*s%s\n",
            (int) log_bytes, (char *) sysaddr, ellipsis);
  } else {
    NaClLog(4, "read returned %"NACL_PRIdS"\n", read_result);
  }

  /* This cast is safe because we clamped count above.*/
  retval = (int32_t) read_result;
out:
  NaClFastMutexUnlock(&nap->desc_mu);
  return retval;
}

int32_t NaClSysPread(struct NaClAppThread  *natp, //will make NaCl logs like read
                     int                   d,
                     void                  *buf,
                     size_t                count,
                     off_t                 offset) { 
  struct NaClApp  *nap = natp->nap;
  int             fd = fd_cage_table[nap->cage_id][d];
  int32_t         retval = -NACL_ABI_EINVAL;
  ssize_t         read_result = -NACL_ABI_EINVAL;
  uintptr_t       sysaddr;
  struct NaClDesc *ndp;
  size_t          log_bytes;
  char const      *ellipsis = "";

  NaClLog(2, "Cage %d Entered NaClSysPRead(0x%08"NACL_PRIxPTR", "
           "%d, 0x%08"NACL_PRIxPTR", "
           "%"NACL_PRIdS"[0x%"NACL_PRIxS"])\n",
          nap->cage_id, (uintptr_t) natp, d, (uintptr_t) buf, count, count);

  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  /* check for closed fds */
  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  ndp = NaClGetDesc(nap, fd);
  NaClLog(2, " ndp = %"NACL_PRIxPTR"\n", (uintptr_t) ndp);
  if (!ndp) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) buf, count);
  if (kNaClBadAddress == sysaddr) {
    NaClDescUnref(ndp);
    retval = -NACL_ABI_EFAULT;
    goto out;
  }

  /*
   * The maximum length for read and write is INT32_MAX--anything larger and
   * the return value would overflow. Passing larger values isn't an error--
   * we'll just clamp the request size if it's too large.
   */
  if (count > INT32_MAX) {
    count = INT32_MAX;
  }

  NaClVmIoWillStart(nap,
                    (uint32_t) (uintptr_t) buf,
                    (uint32_t) (((uintptr_t) buf) + count - 1));
  read_result = ((struct NaClDescVtbl const *)ndp->base.vtbl)->PRead(ndp, (void *)sysaddr, count, (nacl_off64_t) offset);

  NaClVmIoHasEnded(nap,
                    (uint32_t) (uintptr_t) buf,
                    (uint32_t) (((uintptr_t) buf) + count - 1));
  if (read_result > 0) {
    NaClLog(4, "pread returned %"NACL_PRIdS" bytes\n", read_result);
    log_bytes = (size_t) read_result;
    if (log_bytes > INT32_MAX) {
      log_bytes = INT32_MAX;
      ellipsis = "...";
    }
    if (log_bytes > kdefault_io_buffer_bytes_to_log) {
      log_bytes = kdefault_io_buffer_bytes_to_log;
      ellipsis = "...";
    }
    NaClLog(8, "pread result: %.*s%s\n",
            (int) log_bytes, (char *) sysaddr, ellipsis);
  } else {
    NaClLog(4, "pread returned %"NACL_PRIdS"\n", read_result);
  }
  NaClDescUnref(ndp);

  /* This cast is safe because we clamped count above.*/
  retval = (int32_t) read_result;
out:
  return retval;
}

int32_t NaClSysWrite(struct NaClAppThread *natp,
                     int                  d,
                     void                 *buf,
                     size_t               count) {
  struct NaClApp  *nap = natp->nap;
  int             fd = fd_cage_table[nap->cage_id][d];
  int32_t         retval = -NACL_ABI_EINVAL;
  ssize_t         write_result = -NACL_ABI_EINVAL;
  uintptr_t       sysaddr;
  char const      *ellipsis = "";
  struct NaClDesc *ndp;
  size_t          log_bytes;

  NaClLog(2, "Cage %d Entered NaClSysWrite(0x%08"NACL_PRIxPTR", "
          "%d, 0x%08"NACL_PRIxPTR", "
          "%"NACL_PRIdS"[0x%"NACL_PRIxS"])\n",
          nap->cage_id, (uintptr_t) natp, d, (uintptr_t) buf, count, count);


  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  NaClFastMutexLock(&nap->desc_mu);
  /* It's fine to not do a ref here because the mutex will assure that a close() can't be called in between */
  ndp = NaClGetDescMuNoRef(nap, fd);


  NaClLog(2, " ndp = %"NACL_PRIxPTR"\n", (uintptr_t) ndp);
  if (!ndp) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) buf, count);
  if (kNaClBadAddress == sysaddr) {
    retval = -NACL_ABI_EFAULT;
    goto out;
  }

  /*
   * The maximum length for read and write is INT32_MAX--anything larger and
   * the return value would overflow. Passing larger values isn't an error--
   * we'll just clamp the request size if it's too large.
   */
  count = count > INT32_MAX ? INT32_MAX : count;
  log_bytes = count;
  if (log_bytes == INT32_MAX) {
    ellipsis = "...";
  }
  UNREFERENCED_PARAMETER(ellipsis);
  if (log_bytes > kdefault_io_buffer_bytes_to_log) {
     log_bytes = kdefault_io_buffer_bytes_to_log;
     ellipsis = "...";
  }
  UNREFERENCED_PARAMETER(log_bytes);
  UNREFERENCED_PARAMETER(ellipsis);
  NaClLog(2, "In NaClSysWrite(%d, %.*s%s, %"NACL_PRIdS")\n",
          d, (int)log_bytes, (char *)sysaddr, ellipsis, count);

  /* Lind - we removed the VMIOWillStart and End functions here, which is fine for Linux
   * See note in sel_ldr.h
   */
  write_result = ((struct NaClDescVtbl const *)ndp->base.vtbl)->Write(ndp, (void *)sysaddr, count);

  /* This cast is safe because we clamped count above.*/
  retval = (int32_t)write_result;

out:
  NaClFastMutexUnlock(&nap->desc_mu);
  return retval;
}

int32_t NaClSysPwrite(struct NaClAppThread *natp,
                      int                   d,
                      const void            *buf,
                      size_t                count,
                      off_t                 offset) {
  struct NaClApp  *nap = natp->nap;
  int             fd = fd_cage_table[nap->cage_id][d];
  int32_t         retval = -NACL_ABI_EINVAL;
  ssize_t         write_result = -NACL_ABI_EINVAL;
  uintptr_t       sysaddr;
  char const      *ellipsis = "";
  struct NaClDesc *ndp;
  size_t          log_bytes;

  NaClLog(2, "Cage %d Entered NaClSysPWrite(0x%08"NACL_PRIxPTR", "
          "%d, 0x%08"NACL_PRIxPTR", "
          "%"NACL_PRIdS"[0x%"NACL_PRIxS"])\n",
          nap->cage_id, (uintptr_t) natp, d, (uintptr_t) buf, count, count);


  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  ndp = NaClGetDesc(nap, fd);
  NaClLog(2, " ndp = %"NACL_PRIxPTR"\n", (uintptr_t) ndp);
  if (!ndp) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) buf, count);
  if (kNaClBadAddress == sysaddr) {
    NaClDescUnref(ndp);
    retval = -NACL_ABI_EFAULT;
    goto out;
  }

  /*
   * The maximum length for read and write is INT32_MAX--anything larger and
   * the return value would overflow. Passing larger values isn't an error--
   * we'll just clamp the request size if it's too large.
   */
  count = count > INT32_MAX ? INT32_MAX : count;
  log_bytes = count;
  if (log_bytes == INT32_MAX) {
    ellipsis = "...";
  }
  UNREFERENCED_PARAMETER(ellipsis);
  if (log_bytes > kdefault_io_buffer_bytes_to_log) {
     log_bytes = kdefault_io_buffer_bytes_to_log;
     ellipsis = "...";
  }
  UNREFERENCED_PARAMETER(log_bytes);
  UNREFERENCED_PARAMETER(ellipsis);
  NaClLog(2, "In NaClSysPWrite(%d, %.*s%s, %"NACL_PRIdS")\n",
          d, (int)log_bytes, (char *)sysaddr, ellipsis, count);

  NaClVmIoWillStart(nap,
                    (uint32_t)(uintptr_t)buf,
                    (uint32_t)(((uintptr_t)buf) + count - 1));
  write_result = ((struct NaClDescVtbl const *)ndp->base.vtbl)->PWrite(ndp, (void *)sysaddr, count, (nacl_off64_t) offset);

  NaClVmIoHasEnded(nap,
                   (uint32_t)(uintptr_t)buf,
                   (uint32_t)(((uintptr_t)buf) + count - 1));

  NaClDescUnref(ndp);

  /* This cast is safe because we clamped count above.*/
  retval = (int32_t)write_result;

out:
  return retval;
}

/*
 * This implements 64-bit offsets, so we use |offp| as an in/out
 * address so we can have a 64 bit return value.
 */
int32_t NaClSysLseek(struct NaClAppThread *natp,
                     int                  d,
                     nacl_abi_off_t       *offp,
                     int                  whence) {
  struct NaClApp  *nap = natp->nap;
  nacl_abi_off_t  offset;
  nacl_off64_t    retval64;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *ndp;
  int             fd;

  NaClLog(2, "Entered NaClSysLseek(0x%08"NACL_PRIxPTR", %d,"
           " 0x%08"NACL_PRIxPTR", %d)\n",
          (uintptr_t) natp, d, (uintptr_t) offp, whence);

  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  fd = fd_cage_table[nap->cage_id][d];

  /* check for closed fds */
  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  ndp = NaClGetDesc(nap, fd);
  if (!ndp) {
    retval = -NACL_ABI_EBADF;
    goto out;
  }

  if (!NaClCopyInFromUser(nap, &offset, (uintptr_t) offp, sizeof(offset))) {
    retval = -NACL_ABI_EFAULT;
    goto out_unref;
  }
  NaClLog(4, "offset 0x%08"NACL_PRIxNACL_OFF"\n", offset);

  retval64 = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
              Seek)(ndp, (nacl_off64_t) offset, whence);
  if (NaClOff64IsNegErrno(&retval64)) {
    retval = (int32_t) retval64;
  } else {
    if (NaClCopyOutToUser(nap, (uintptr_t) offp, &retval64, sizeof(retval64))) {
      retval = 0;
    } else {
      NaClLog(LOG_FATAL,
              "NaClSysLseek: in/out ptr became invalid at copyout?\n");
    }
  }
out_unref:
  NaClDescUnref(ndp);
out:
  return retval;
}

int32_t NaClSysIoctl(struct NaClAppThread *natp,
                     int                  d,
                     unsigned long        request,
                     void                 *arg_ptr) {
  struct NaClApp  *nap = natp->nap;
  int             retval = -NACL_ABI_EINVAL;
  uintptr_t       sysaddr;
  int             fd;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysIoctl(0x%08"NACL_PRIxPTR
           ", %d, %d, 0x%08"NACL_PRIxPTR")\n",
           nap->cage_id, (uintptr_t)natp, d, request,
           (uintptr_t)arg_ptr);

  sysaddr = NaClUserToSysAddr(nap, (uintptr_t) arg_ptr);
  if (kNaClBadAddress == sysaddr) {
    NaClLog(2, "NaClSysIoctl could not translate buffer address, returning%d\n", -NACL_ABI_EFAULT);
    retval = -NACL_ABI_EFAULT;
    return retval;
  }

  ndp = GetDescFromCagetable(nap,fd);
  if (!ndp) {
    NaClLog(2, "NaClSysIoctl was passed an unrecognized file descriptor, returning %d\n", -NACL_ABI_EBADF);
    return -NACL_ABI_EBADF;
  }
  fd = NaClDesc2Lindfd(ndp);

  // Further checks might be necessary for ioctl calls with structs or arrays
  // Those calls are not implemented for now
  
  retval = lind_ioctl(fd ,request, sysaddr, nap->cage_id);

cleanup:
  NaClLog(2, "NaClSysIoctl: returning %d\n", retval);
  NaClDescUnref(ndp);
  return retval;
}


int32_t NaClSysFstat(struct NaClAppThread *natp,
                     int                  d,
                     struct nacl_abi_stat *nasp) {
  struct NaClApp        *nap = natp->nap;
  int32_t               retval = -NACL_ABI_EINVAL;
  struct NaClDesc       *ndp;
  struct nacl_abi_stat  result;
  int                   fd;

  NaClLog(2, "Entered NaClSysFstat(0x%08"NACL_PRIxPTR
           ", %d, 0x%08"NACL_PRIxPTR")\n",
           (uintptr_t)natp,
           d, (uintptr_t)nasp);

  NaClLog(2, "sizeof(struct nacl_abi_stat) = %"NACL_PRIdS" (0x%"NACL_PRIxS")\n",
          sizeof(*nasp), sizeof(*nasp));

  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  fd = fd_cage_table[nap->cage_id][d];

  /* check for closed fds */
  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  ndp = NaClGetDesc(nap, fd);
  if (!ndp) {
    NaClLog(2, "%s\n", "bad desc");
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
            Fstat)(ndp, &result);
  if (!retval) {
    if (!NaClCopyOutToUser(nap, (uintptr_t) nasp,
                           &result, sizeof(result))) {
      retval = -NACL_ABI_EFAULT;
    }
  }

  NaClDescUnref(ndp);
cleanup:
  return retval;
}

int32_t NaClSysStat(struct NaClAppThread  *natp,
                    const char            *pathname,
                    struct nacl_abi_stat  *buf) {
  struct NaClApp      *nap = natp->nap;
  int32_t             retval = -NACL_ABI_EINVAL;
  char                path[NACL_CONFIG_PATH_MAX];
  nacl_host_stat_t    stbuf;

  NaClLog(2, "Entered NaClSysStat(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR","
           " 0x%08"NACL_PRIxPTR")\n",
          (uintptr_t)natp,(uintptr_t)pathname, (uintptr_t)buf);

  retval = CopyPathFromUser(nap, path, sizeof(path), (uintptr_t) pathname);
  if (retval) {
    goto cleanup;
  }

  retval = NaClStatAclCheck(nap, path);
  if (retval) {
    goto cleanup;
  }

  /*
   * Perform a host stat.
   */
  retval = NaClHostDescStat(path, &stbuf, nap->cage_id);
  if (!retval) {
    struct nacl_abi_stat abi_stbuf;

    retval = NaClAbiStatHostDescStatXlateCtor(&abi_stbuf,
                                              &stbuf);
    if (!NaClCopyOutToUser(nap, (uintptr_t) buf,
                           &abi_stbuf, sizeof(abi_stbuf))) {
      retval = -NACL_ABI_EFAULT;
    }
  }
cleanup:
  return retval;
}

int32_t NaClSysLStat(struct NaClAppThread  *natp,
                    const char            *pathname,
                    struct nacl_abi_stat  *buf) {
  struct NaClApp      *nap = natp->nap;
  int32_t             retval = -NACL_ABI_EINVAL;
  char                path[NACL_CONFIG_PATH_MAX];
  nacl_host_stat_t    stbuf;

  NaClLog(2, "Entered NaClSysLStat(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR","
           " 0x%08"NACL_PRIxPTR")\n",
          (uintptr_t)natp,(uintptr_t)pathname, (uintptr_t)buf);

  retval = CopyPathFromUser(nap, path, sizeof(path), (uintptr_t) pathname);
  if (retval) {
    goto cleanup;
  }

  retval = NaClStatAclCheck(nap, path);
  if (retval) {
    goto cleanup;
  }

  /*
   * Perform a host stat.
   */
  retval = NaClHostDescStat(path, &stbuf, nap->cage_id);
  if (!retval) {
    struct nacl_abi_stat abi_stbuf;

    retval = NaClAbiStatHostDescStatXlateCtor(&abi_stbuf,
                                              &stbuf);
    if (!NaClCopyOutToUser(nap, (uintptr_t) buf,
                           &abi_stbuf, sizeof(abi_stbuf))) {
      retval = -NACL_ABI_EFAULT;
    }
  }
cleanup:
  return retval;
}

int32_t NaClSysMkdir(struct NaClAppThread *natp,
                     uint32_t             pathname,
                     int                  mode) {
  struct NaClApp *nap = natp->nap;
  char           path[NACL_CONFIG_PATH_MAX];
  int32_t        retval = -NACL_ABI_EINVAL;

  NaClLog(2, "Cage %d Entered NaClSysMkdir(0x%08"NACL_PRIxPTR", "
          "%d, %d)\n", nap->cage_id, (uintptr_t) natp, pathname, mode);

  if (!NaClAclBypassChecks) {
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  retval = CopyPathFromUser(nap, path, sizeof(path), pathname);
  if (retval) {
    goto cleanup;
  }

  retval = lind_mkdir(path, mode, natp->nap->cage_id);
cleanup:
  NaClLog(2, "NaClSysMkdir: returning %d\n", retval);
  return retval;
}

int32_t NaClSysRmdir(struct NaClAppThread *natp,
                     uint32_t             pathname) {
  struct NaClApp *nap = natp->nap;
  char           path[NACL_CONFIG_PATH_MAX];
  int32_t        retval = -NACL_ABI_EINVAL;

  NaClLog(2, "Cage %d Entered NaClSysRmdir(0x%08"NACL_PRIxPTR", "
          "%d)\n", nap->cage_id, (uintptr_t) natp, pathname);

  if (!NaClAclBypassChecks) {
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  retval = CopyPathFromUser(nap, path, sizeof(path), pathname);
  if (retval) {
    goto cleanup;
  }

  retval = lind_rmdir(path, natp->nap->cage_id);
cleanup:
  NaClLog(2, "NaClSysRmdir: returning %d\n", retval);
  return retval;
}

int32_t NaClSysChdir(struct NaClAppThread *natp,
                     uint32_t             pathname) {
  struct NaClApp *nap = natp->nap;
  char           path[NACL_CONFIG_PATH_MAX];
  int32_t        retval = -NACL_ABI_EINVAL;

  NaClLog(2, "Cage %d Entered NaClSysChdir(0x%08"NACL_PRIxPTR", "
          "%d)\n", nap->cage_id, (uintptr_t) natp, pathname);

  if (!NaClAclBypassChecks) {
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  retval = CopyPathFromUser(nap, path, sizeof(path), pathname);
  if (retval) {
    goto cleanup;
  }

  retval = lind_chdir(path, natp->nap->cage_id);
cleanup:
  NaClLog(2, "NaClSysChdir: returning %d\n", retval);
  return retval;
}

int32_t NaClSysGetcwd(struct NaClAppThread *natp,
                      char                 *buf,
                      size_t               size) {
  struct NaClApp *nap = natp->nap;
  uintptr_t      sysaddr;
  int32_t        retval = -NACL_ABI_EINVAL;

  NaClLog(2, "Cage %d Entered NaClSysGetcwd(0x%08"NACL_PRIxPTR", "
          "0x%08"NACL_PRIxPTR", "
          "%d)\n",
          nap->cage_id, (uintptr_t) natp, (uintptr_t) buf, size);

  if (!NaClAclBypassChecks) {
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  if (size >= NACL_CONFIG_PATH_MAX) {
    size = NACL_CONFIG_PATH_MAX - 1;
  }

  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) buf, size);
  if (kNaClBadAddress == sysaddr) {
    NaClLog(2, "NaClSysGetcwd could not translate buffer address, returning%d\n", -NACL_ABI_EFAULT);
    retval = -NACL_ABI_EFAULT;
    return retval;
  }

  retval = lind_getcwd(sysaddr, size, natp->nap->cage_id);

cleanup:
  NaClLog(2, "NaClSysGetcwd: returning %d\n", retval);
  return retval;
}

int32_t NaClSysLink(struct NaClAppThread *natp, char* from, char* to) {
  struct NaClApp *nap = natp->nap;
  char           srcpath[NACL_CONFIG_PATH_MAX];
  char           dstpath[NACL_CONFIG_PATH_MAX];
  int32_t        retval;

  if ((retval = CopyPathFromUser(nap, srcpath, sizeof(srcpath), (uintptr_t) from))) {
    return retval;
  }
  if ((retval = CopyPathFromUser(nap, dstpath, sizeof(dstpath), (uintptr_t) to))) {
    return retval;
  }

  return lind_link(srcpath, dstpath, nap->cage_id);
}
int32_t NaClSysUnlink(struct NaClAppThread *natp, char* pathname) {
  struct NaClApp *nap = natp->nap;
  char           path[NACL_CONFIG_PATH_MAX];
  int32_t        retval;

  if ((retval = CopyPathFromUser(nap, path, sizeof(path), (uintptr_t) pathname))) {
    return retval;
  }

  return lind_unlink(path, nap->cage_id);
}

int NaClSysCommonAddrRangeContainsExecutablePages(struct NaClApp *nap,
                                                  uintptr_t usraddr,
                                                  size_t length) {
  /*
   * NOTE: currently only trampoline and text region are executable,
   * and they are at the beginning of the address space, so this code
   * is fine.  We will probably never allow users to mark other pages
   * as executable; but if so, we will have to revisit how this check
   * is implemented.
   *
   * nap->static_text_end is a multiple of 4K, the memory protection
   * granularity.  Since this routine is used for checking whether
   * memory map adjustments / allocations -- which has 64K granularity
   * -- is okay, usraddr must be an allocation granularity value.  Our
   * callers (as of this writing) does this, but we truncate it down
   * to an allocation boundary to be sure.
   */
  UNREFERENCED_PARAMETER(length);
  usraddr = NaClTruncAllocPage(usraddr);
  return usraddr < nap->dynamic_text_end;
}

int NaClSysCommonAddrRangeInAllowedDynamicCodeSpace(struct NaClApp *nap,
                                                    uintptr_t usraddr,
                                                    size_t length) {
  uintptr_t usr_region_end = usraddr + length;

  if (usr_region_end < usraddr) {
    /* Check for unsigned addition overflow */
    return 0;
  }
  usr_region_end = NaClRoundAllocPage(usr_region_end);
  if (usr_region_end < usraddr) {
    /* 32-bit systems only, rounding caused uint32_t overflow */
    return 0;
  }
  return (nap->dynamic_text_start <= usraddr &&
          usr_region_end <= nap->dynamic_text_end);
}

static int32_t MunmapInternal(struct NaClApp *nap, uintptr_t sysaddr, size_t length) {
#if NACL_WINDOWS
  uintptr_t addr;
  uintptr_t endaddr = sysaddr + length;
  uintptr_t usraddr;
  for (addr = sysaddr; addr < endaddr; addr += NACL_MAP_PAGESIZE) {
    struct NaClVmmapEntry const *entry;
    uintptr_t                   page_num;
    uintptr_t                   offset;

    usraddr = NaClSysToUser(nap, addr);

    entry = NaClVmmapFindPage(&nap->mem_map, usraddr >> NACL_PAGESHIFT);
    if (!entry) {
      continue;
    }
    NaClLog(2, "NaClSysMunmap: addr 0x%08lx, desc 0x%08"NACL_PRIxPTR"\n",
            addr, (uintptr_t)entry->desc);

    page_num = usraddr - (entry->page_num << NACL_PAGESHIFT);
    offset = (uintptr_t) entry->offset + page_num;

    if (entry->desc &&
        offset < (uintptr_t) entry->file_size) {
      if (!UnmapViewOfFile((void *) addr)) {
        NaClLog(1, "MunmapInternal: UnmapViewOfFile failed to at addr"
                " 0x%08"NACL_PRIxPTR", error %d\n",
                addr, GetLastError());
      }
      /*
      * Fill the address space hole that we opened
      * with UnmapViewOfFile().
      */
      if (!VirtualAlloc((void *) addr, NACL_MAP_PAGESIZE, MEM_RESERVE,
                        PAGE_READWRITE)) {
        NaClLog(LOG_FATAL, "MunmapInternal: "
                "failed to fill hole with VirtualAlloc(), error %d\n",
                GetLastError());
      }
    } else {
      /*
       * Anonymous memory; we just decommit it and thus
       * make it inaccessible.
       */
      if (!VirtualFree((void *) addr,
                       NACL_MAP_PAGESIZE,
                       MEM_DECOMMIT)) {
        int error = GetLastError();
        NaClLog(LOG_FATAL,
                ("MunmapInternal: Could not VirtualFree MEM_DECOMMIT"
                 " addr 0x%08x, error %d (0x%x)\n"),
                addr, error, error);
      }
    }
    NaClVmmapRemove(&nap->mem_map,
                    usraddr >> NACL_PAGESHIFT,
                    NACL_PAGES_PER_MAP);
  }
#else /* NACL_WINDOWS */
  UNREFERENCED_PARAMETER(nap);
  NaClLog(3, "MunmapInternal(0x%08"NACL_PRIxPTR", 0x%"NACL_PRIxS")\n", sysaddr, length);
  /*
   * Overwrite current mapping with inaccessible, anonymous
   * zero-filled pages, which should be copy-on-write and thus
   * relatively cheap.  Do not open up an address space hole.
   */
  if (MAP_FAILED == lind_mmap((void *) sysaddr,
                              length,  
                              PROT_NONE,  
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 
                              -1, 
                              (off_t) 0,
                              nap->cage_id)) {
    NaClLog(2, "mmap to put in anonymous memory failed, errno = %d\n", errno);
    return -NaClXlateErrno(errno);
  }
  NaClVmmapRemove(&nap->mem_map,
                  NaClSysToUser(nap, sysaddr) >> NACL_PAGESHIFT,
                  length >> NACL_PAGESHIFT);
#endif /* NACL_WINDOWS */
  return 0;
}

/* Warning: sizeof(nacl_abi_off_t) != sizeof(off_t) on OSX */
int32_t NaClSysMmapIntern(struct NaClApp        *nap,
                          void                  *start,
                          size_t                length,
                          int                   prot,
                          int                   flags,
                          int                   d,
                          nacl_abi_off_t        offset) {
  int                         allowed_flags;
  struct NaClDesc             *ndp;
  uintptr_t                   usraddr;
  uintptr_t                   usrpage;
  uintptr_t                   sysaddr;
  uintptr_t                   endaddr;
  int                         mapping_code;
  uintptr_t                   map_result;
  int                         holding_app_lock;
  struct nacl_abi_stat        stbuf;
  size_t                      alloc_rounded_length;
  nacl_off64_t                host_rounded_file_bytes;
  size_t                      alloc_rounded_file_bytes;
  int fd;

  holding_app_lock = 0;
  ndp = NULL;

  allowed_flags = (NACL_ABI_MAP_FIXED | NACL_ABI_MAP_SHARED
                   | NACL_ABI_MAP_PRIVATE | NACL_ABI_MAP_ANONYMOUS);

  usraddr = (uintptr_t) start;

  if ((flags & ~allowed_flags)) {
    NaClLog(2, "invalid mmap flags 0%o, ignoring extraneous bits\n", flags);
    flags &= allowed_flags;
  }

  if ((flags & NACL_ABI_MAP_ANONYMOUS)) {
    /*
     * anonymous mmap, so backing store is just swap: no descriptor is
     * involved, and no memory object will be created to represent the
     * descriptor.
     */
    ndp = NULL;
  } else {
    if ((d >= FILE_DESC_MAX)  || (d < 0)) {
      map_result = -NACL_ABI_EBADF;
      goto cleanup;
    }
    fd = fd_cage_table[nap->cage_id][d];
    if (fd < 0) {
      map_result = -NACL_ABI_EBADF;
      goto cleanup;
    }
    ndp = NaClGetDesc(nap, fd);
    if (!ndp) {
      map_result = -NACL_ABI_EBADF;
      goto cleanup;
    }
  }

  mapping_code = 0;
  /*
   * Check if application is trying to do dynamic code loading by
   * mmaping a file.
   */
  if ((NACL_ABI_PROT_EXEC & prot) &&
      (NACL_ABI_MAP_FIXED & flags) &&
      ndp &&
      NaClSysCommonAddrRangeInAllowedDynamicCodeSpace(nap, usraddr, length)) {
    if (!nap->enable_dyncode_syscalls) {
#ifdef  _DEBUG
      NaClLog(1, "%s\n",
              "NaClSysMmap: PROT_EXEC when dyncode syscalls are disabled.");
#endif
      map_result = -NACL_ABI_EINVAL;
      goto cleanup;
    }
    if ((NACL_ABI_PROT_WRITE & prot)) {
      NaClLog(2, "%s\n", "NaClSysMmap: asked for writable and executable code pages?!?");
      map_result = -NACL_ABI_EINVAL;
      goto cleanup;
    }
    mapping_code = 1;
  } else if ((prot & NACL_ABI_PROT_EXEC)) {
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  /*
   * Starting address must be aligned to worst-case allocation
   * granularity.  (Windows.)
   */
  if (!NaClIsAllocPageMultiple(usraddr)) {
    NaClLog(2, "NaClSysMmap: address not allocation granularity aligned\n");
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  /*
   * Offset should be non-negative (nacl_abi_off_t is signed).  This
   * condition is caught when the file is stat'd and checked, and
   * offset is ignored for anonymous mappings.
   */
  if (offset < 0) {
    NaClLog(1,  /* application bug */
            "NaClSysMmap: negative file offset: %"NACL_PRIdNACL_OFF"\n",
            offset);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  /*
   * And offset must be a multiple of the allocation unit.
   */
  if (!NaClIsAllocPageMultiple((uintptr_t) offset)) {
    NaClLog(1, "NaClSysMmap: file offset 0x%08"NACL_PRIxPTR" not multiple"
            " of allocation size\n",
            (uintptr_t)offset);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  if (!length) {
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  alloc_rounded_length = NaClRoundAllocPage(length);
  if (alloc_rounded_length != length) {
    if (mapping_code) {
      NaClLog(2, "%s\n", "NaClSysMmap: length not a multiple of allocation size");
      map_result = -NACL_ABI_EINVAL;
      goto cleanup;
    }
    NaClLog(1, "NaClSysMmap: rounded length to 0x%"NACL_PRIxS"\n",
            alloc_rounded_length);
  }

 
  length = alloc_rounded_length;

  /*
   * Lock the addr space.
   */
  NaClXMutexLock(&nap->mu);

  NaClVmHoleOpeningMu(nap);

  holding_app_lock = 1;

  if (0 == (flags & NACL_ABI_MAP_FIXED)) {
    /*
     * The user wants us to pick an address range.
     */
    if (!usraddr) {
      /*
       * Pick a hole in addr space of appropriate size, anywhere.
       * We pick one that's best for the system.
       */
      usrpage = NaClVmmapFindMapSpace(&nap->mem_map,
                                      alloc_rounded_length >> NACL_PAGESHIFT);
      NaClLog(2, "NaClSysMmap: FindMapSpace: page 0x%05"NACL_PRIxPTR"\n",
              usrpage);
      if (!usrpage) {
        map_result = -NACL_ABI_ENOMEM;
        goto cleanup;
      }
      usraddr = usrpage << NACL_PAGESHIFT;
      NaClLog(2, "NaClSysMmap: new starting addr: 0x%08"NACL_PRIxPTR
              "\n", usraddr);
    } else {
      /*
       * user supplied an addr, but it's to be treated as a hint; we
       * find a hole of the right size in the app's address space,
       * according to the usual mmap semantics.
       */
      usrpage = NaClVmmapFindMapSpaceAboveHint(&nap->mem_map,
                                               usraddr,
                                               (alloc_rounded_length
                                                >> NACL_PAGESHIFT));
      NaClLog(2, "NaClSysMmap: FindSpaceAboveHint: page 0x%05"NACL_PRIxPTR"\n",
              usrpage);
      if (!usrpage) {
        NaClLog(2, "%s\n", "NaClSysMmap: hint failed, doing generic allocation");
        usrpage = NaClVmmapFindMapSpace(&nap->mem_map,
                                        alloc_rounded_length >> NACL_PAGESHIFT);
      }
      if (!usrpage) {
        map_result = -NACL_ABI_ENOMEM;
        goto cleanup;
      }
      usraddr = usrpage << NACL_PAGESHIFT;
      NaClLog(2, "NaClSysMmap: new starting addr: 0x%08"NACL_PRIxPTR"\n",
              usraddr);
    }
  }

  /*
   * Validate [usraddr, endaddr) is okay.
   */
  if (usraddr >= ((uintptr_t) 1 << nap->addr_bits)) {
    NaClLog(2,
            ("NaClSysMmap: start address (0x%08"NACL_PRIxPTR") outside address"
             " space\n"),
            usraddr);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  endaddr = usraddr + alloc_rounded_length;
  if (endaddr < usraddr) {
    NaClLog(0,
            ("NaClSysMmap: integer overflow -- "
             "NaClSysMmap(0x%08"NACL_PRIxPTR",0x%"NACL_PRIxS",0x%x,0x%x,%d,"
             "0x%08"NACL_PRIxPTR"\n"),
            usraddr, length, prot, flags, d, (uintptr_t) offset);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  /*
   * NB: we use > instead of >= here.
   *
   * endaddr is the address of the first byte beyond the target region
   * and it can equal the address space limit.  (of course, normally
   * the main thread's stack is there.)
   */
  if (endaddr > ((uintptr_t) 1 << nap->addr_bits)) {
    NaClLog(2,
            ("NaClSysMmap: end address (0x%08"NACL_PRIxPTR") is beyond"
             " the end of the address space\n"),
            endaddr);
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  if (mapping_code) {
    NaClLog(4,
            "NaClSysMmap: PROT_EXEC requested, usraddr 0x%08"NACL_PRIxPTR
            ", length %"NACL_PRIxS"\n",
            usraddr, length);
    if (!NACL_FI("MMAP_BYPASS_DESCRIPTOR_SAFETY_CHECK",
                 NaClDescIsSafeForMmap(ndp),
                 1)) {
      NaClLog(4, "NaClSysMmap: descriptor not blessed\n");
      map_result = -NACL_ABI_EINVAL;
      goto cleanup;
    }
    NaClLog(4, "NaClSysMmap: allowed\n");
  } else if (NaClSysCommonAddrRangeContainsExecutablePages(nap,
                                                           usraddr,
                                                           length)) {
    NaClLog(2, "NaClSysMmap: region contains executable pages\n");
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  NaClVmIoPendingCheck_mu(nap,
                          (uint32_t) usraddr,
                          (uint32_t) (usraddr + length - 1));

  /*
   * Force NACL_ABI_MAP_FIXED, since we are specifying address in NaCl
   * app address space.
   */
  flags |= NACL_ABI_MAP_FIXED;

  /*
   * Turn off PROT_EXEC -- normal user mmapped pages should not be
   * executable.  This is primarily for the service runtime's own
   * bookkeeping -- prot is used in NaClVmmapAddWithOverwrite and will
   * be needed for remapping data pages on Windows if page protection
   * is set to PROT_NONE and back.
   *
   * NB: we've captured the notion of mapping executable memory for
   * dynamic library loading etc in mapping_code, so when we do map
   * text we will explicitly OR in NACL_ABI_PROT_EXEC as needed.
   */
  prot &= ~NACL_ABI_PROT_EXEC;

  /*
   * Exactly one of NACL_ABI_MAP_SHARED and NACL_ABI_MAP_PRIVATE is set.
   */
  if ((0 == (flags & NACL_ABI_MAP_SHARED)) ==
      (0 == (flags & NACL_ABI_MAP_PRIVATE))) {
    map_result = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  sysaddr = NaClUserToSys(nap, usraddr);

  /* [0, length) */
  if (length > 0) {
    if (!ndp) {
      NaClLog(2, "NaClSysMmap: NaClDescIoDescMap(,,0x%08"NACL_PRIxPTR","
               "0x%08"NACL_PRIxS",0x%x,0x%x,0x%08"NACL_PRIxPTR")\n",
               sysaddr, length, prot, flags, (uintptr_t)offset);
      map_result = NaClDescIoDescMapAnon(nap->effp,
                                         (void *) sysaddr,
                                         length,
                                         prot,
                                         flags,
                                         (off_t) offset);
    } else if (mapping_code) {
      /*
       * Map a read-only view in trusted memory, ask validator if
       * valid without patching; if okay, then map in untrusted
       * executable memory.  Fallback to using the dyncode_create
       * interface otherwise.
       *
       * On Windows, threads are already stopped by the
       * NaClVmHoleOpeningMu invocation above.
       *
       * For mmap, stopping threads on Windows is needed to ensure
       * that nothing gets allocated into the temporary address space
       * hole.  This would otherwise have been particularly dangerous,
       * since the hole is in an executable region.  We must abort the
       * program if some other trusted thread (or injected thread)
       * allocates into this space.  We also need interprocessor
       * interrupts to flush the icaches associated other cores, since
       * they may contain stale data.  NB: mmap with PROT_EXEC should
       * do this for us, since otherwise loading shared libraries in a
       * multithreaded environment cannot work in a portable fashion.
       * (Mutex locks only ensure dcache coherency.)
       *
       * For eventual munmap, stopping threads also involve looking at
       * their registers to make sure their %rip/%eip/%ip are not
       * inside the region being modified (impossible for initial
       * insertion).  This is needed because mmap->munmap->mmap could
       * cause problems due to scheduler races.
       *
       * Use NaClDynamicRegionCreate to mark region as allocated.
       *
       * See NaClElfFileMapSegment in elf_util.c for corresponding
       * mmap-based main executable loading.
       */
      uintptr_t image_sys_addr;
      NaClValidationStatus validator_status = NaClValidationFailed;
      struct NaClValidationMetadata metadata;
      int sys_ret;  /* syscall return convention */
      int ret;

      NaClLog(4, "NaClSysMmap: checking descriptor type\n");
      if (NACL_VTBL(NaClDesc, ndp)->typeTag != NACL_DESC_HOST_IO) {
        NaClLog(4, "NaClSysMmap: not supported type, got %d\n",
                NACL_VTBL(NaClDesc, ndp)->typeTag);
        map_result = -NACL_ABI_EINVAL;
        goto cleanup;
      }

      /*
       * First, try to mmap.  Check if target address range is
       * available.  It must be neither in use by NaClText interface,
       * nor used by previous mmap'd code.  We record mmap'd code
       * regions in the NaClText's data structures to avoid having to
       * deal with looking in two data structures.
       *
       * This mapping is PROT_READ | PROT_WRITE, MAP_PRIVATE so that
       * if validation fails in read-only mode, we can re-run the
       * validator to patch in place.
       */

      image_sys_addr = NACL_VTBL(NaClDesc, ndp)->Map(ndp,
                                                     NaClDescEffectorTrustedMem(),
                                                     NULL,
                                                     length,
                                                     NACL_ABI_PROT_READ | NACL_ABI_PROT_WRITE,
                                                     NACL_ABI_MAP_PRIVATE,
                                                     offset);
      if (NaClPtrIsNegErrno(&image_sys_addr)) {
        map_result = image_sys_addr;
        goto cleanup;
      }

      /* Ask validator / validation cache */
      NaClMetadataFromNaClDescCtor(&metadata, ndp);
      validator_status = NACL_FI("MMAP_FORCE_MMAP_VALIDATION_FAIL",
                                 (*nap->validator->
                                  Validate)(usraddr,
                                            (uint8_t *) image_sys_addr,
                                            length,
                                            0,  /* stubout_mode: no */
                                            1,  /* readonly_text: yes */
                                            nap->cpu_features,
                                            &metadata,
                                            nap->validation_cache),
                                 NaClValidationFailed);
      NaClLog(3, "NaClSysMmap: prot_exec, validator_status %d\n",
              validator_status);
      NaClMetadataDtor(&metadata);

      if (NaClValidationSucceeded == validator_status) {
        /*
         * Check if target address range is actually available.  It
         * must be neither in use by NaClText interface, nor used by
         * previous mmap'd code.  We record mmap'd code regions in the
         * NaClText's data structures to avoid lo both having to deal
         * with looking in two data structures.  We could do this
         * first since this is a cheaper check, but it shouldn't
         * matter since application errors ought to be rare and we
         * shouldn't optimize for error handling, and this makes the
         * code simpler (releasing a created region is more code).
         */
        NaClXMutexLock(&nap->dynamic_load_mutex);
        ret = NaClDynamicRegionCreate(nap, NaClUserToSys(nap, usraddr), length,
                                      1);
        NaClXMutexUnlock(&nap->dynamic_load_mutex);
        if (!ret) {
          NaClLog(3, "NaClSysMmap: PROT_EXEC region"
                  " overlaps other dynamic code\n");
          map_result = -NACL_ABI_EINVAL;
          goto cleanup;
        }
        /*
         * Remove scratch mapping.
         */
        NaClDescUnmapUnsafe(ndp, (void *) image_sys_addr, length);
        /*
         * We must succeed in mapping into the untrusted executable
         * space, since otherwise it would mean that the temporary
         * hole (for Windows) was filled by some other thread, and
         * that's unrecoverable.  For Linux and OSX, this should never
         * happen, since it's an atomic overmap.
         */
        NaClLog(3, "NaClSysMmap: mapping into executable memory\n");
        image_sys_addr = (*NACL_VTBL(NaClDesc, ndp)->
                          Map)(ndp,
                               nap->effp,
                               (void *) sysaddr,
                               length,
                               NACL_ABI_PROT_READ | NACL_ABI_PROT_EXEC,
                               NACL_ABI_MAP_PRIVATE | NACL_ABI_MAP_FIXED,
                               offset);
        if (image_sys_addr != sysaddr) {
          NaClLog(LOG_FATAL,
                  "NaClSysMmap: map into executable memory failed:"
                  " got 0x%"NACL_PRIxPTR"\n", image_sys_addr);
        }
        map_result = (int32_t) usraddr;
        goto cleanup;
      }

      NaClLog(3,
              "NaClSysMmap: did not validate in readonly_text mode;"
              " attempting to use dyncode interface.\n");

      if (holding_app_lock) {
        NaClVmHoleClosingMu(nap);
        NaClXMutexUnlock(&nap->mu);
      }

      if (NACL_FI("MMAP_STUBOUT_EMULATION", 0, 1)) {
        NaClLog(3, "NaClSysMmap: emulating stubout mode by touching memory\n");
        *(volatile uint8_t *) image_sys_addr =
            *(volatile uint8_t *) image_sys_addr;
      }

      /*
       * Fallback implementation.  Use the mapped memory as source for
       * the dynamic code insertion interface.
       */
      sys_ret = NaClTextDyncodeCreate(nap,
                                      (uint32_t) usraddr,
                                      (uint8_t *) image_sys_addr,
                                      (uint32_t) length,
                                      NULL);
      if (sys_ret < 0) {
        map_result = sys_ret;
      } else {
        map_result = (int32_t) usraddr;
      }

#if NACL_WINDOWS
      sys_ret = (*NACL_VTBL(NaClDesc, ndp)->
                 UnmapUnsafe)(ndp, (void *) image_sys_addr, length);
#else
      sys_ret = munmap((void *) image_sys_addr, length);
#endif
      if (sys_ret) {
        NaClLog(1, "aClSysMmap: could not unmap text at 0x%"NACL_PRIxPTR","
                " length 0x%"NACL_PRIxS", NaCl errno %d\n",
                image_sys_addr, length, -sys_ret);
      }
      goto cleanup_no_locks;
    } else {


      NaClLog(4,
              ("NaClSysMmap: (*ndp->Map)(,,0x%08"NACL_PRIxPTR","
               "0x%08"NACL_PRIxS",0x%x,0x%x,0x%08"NACL_PRIxPTR")\n"),
              sysaddr, length, prot, flags, (uintptr_t) offset);

      map_result = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                    Map)(ndp,
                         nap->effp,
                         (void *) sysaddr,
                         length,
                         prot,
                         flags,
                         (off_t) offset);
    }
    /*
     * "Small" negative integers are errno values.  Larger ones are
     * virtual addresses.
     */
    if (NaClPtrIsNegErrno(&map_result)) {
      if ((uintptr_t) -NACL_ABI_E_MOVE_ADDRESS_SPACE == map_result) {
        NaClLog(LOG_FATAL,
                ("NaClSysMmap: Map failed, but we"
                 " cannot handle address space move, error %"NACL_PRIuS"\n"),
                (size_t) map_result);
      }
      /*
       * Propagate all other errors to user code.
       */
      goto cleanup;
    }
    if (map_result != sysaddr) {
      NaClLog(LOG_FATAL, "system mmap did not honor NACL_ABI_MAP_FIXED\n");
    }
  }
  /*
   * If we are mapping beyond the end of the file, we fill this space
   * with PROT_NONE pages.
   *
   * Windows forces us to expose a mixture of 64k and 4k pages, and we
   * expose the same mappings on other platforms.  For example,
   * suppose untrusted code requests to map 0x40000 bytes from a file
   * of extent 0x100.  We will create the following regions:
   *
   *       0-  0x100  A: Bytes from the file
   *   0x100- 0x1000  B: The rest of the 4k page is accessible but undefined
   *  0x1000-0x10000  C: The rest of the 64k page is inaccessible (PROT_NONE)
   * 0x10000-0x40000  D: Further 64k pages are also inaccessible (PROT_NONE)
   *
   * On Windows, a single MapViewOfFileEx() call creates A, B and C.
   * This call will not accept a size greater than 0x100, so we have
   * to create D separately.  The hardware requires B to be accessible
   * (whenever A is accessible), but Windows does not allow C to be
   * mapped as accessible.  This is unfortunate because it interferes
   * with how ELF dynamic linkers usually like to set up an ELF
   * object's BSS.
   */
  /* inaccessible: [length, alloc_rounded_length) */
  if (length < alloc_rounded_length) {
    /*
     * On Unix, this maps regions C and D as inaccessible.  On
     * Windows, it just maps region D; region C has already been made
     * inaccessible.
     */
    size_t map_len = alloc_rounded_length - length;
    map_result = MunmapInternal(nap, sysaddr + length, map_len);
    if (map_result != 0) {
      goto cleanup;
    }
  }

  if (alloc_rounded_length > 0) {
    NaClVmmapAddWithOverwrite(&nap->mem_map,
                              NaClSysToUser(nap, sysaddr) >> NACL_PAGESHIFT,
                              alloc_rounded_length >> NACL_PAGESHIFT,
                              prot,
                              flags,
                              ndp,
                              offset,
                              length);
  }

  map_result = usraddr;

 cleanup:
  if (holding_app_lock) {
    NaClVmHoleClosingMu(nap);
    NaClXMutexUnlock(&nap->mu);
  }
 cleanup_no_locks:
  if (ndp) {
    NaClDescUnref(ndp);
  }

  /*
   * Check to ensure that map_result will fit into a 32-bit value. This is
   * a bit tricky because there are two valid ranges: one is the range from
   * 0 to (almost) 2^32, the other is from -1 to -4096 (our error range).
   * For a 32-bit value these ranges would overlap, but if the value is 64-bit
   * they will be disjoint.
   */
  if (map_result > UINT32_MAX
      && !NaClPtrIsNegErrno(&map_result)) {
    NaClLog(LOG_FATAL, "Overflow in NaClSysMmap: return address is "
                       "0x%"NACL_PRIxPTR"\n", map_result);
  }
  NaClLog(3, "NaClSysMmap: returning 0x%08"NACL_PRIxPTR"\n", map_result);

  return (int32_t) map_result;
}

int32_t NaClSysMmap(struct NaClAppThread  *natp,
                    void                  *start,
                    size_t                length,
                    int                   prot,
                    int                   flags,
                    int                   d,
                    nacl_abi_off_t        *offp) {
  struct NaClApp     *nap = natp->nap;
  int32_t            retval;
  volatile uintptr_t sysaddr;
  nacl_abi_off_t     offset;

  NaClLog(2, "Entered NaClSysMmap(0x%08"NACL_PRIxPTR",0x%"NACL_PRIxS","
          "0x%x,0x%x,%d,0x%08"NACL_PRIxPTR")\n",
          (uintptr_t) start, length, prot, flags, d, (uintptr_t)offp);

  if (!offp) {
    /*
     * This warning is really targetted towards trusted code,
     * especially tests that didn't notice the argument type change.
     * Unfortunatey, zero is a common and legitimate offset value, and
     * the compiler will not complain since an automatic type
     * conversion works.
     */
#ifdef  _DEBUG
    NaClLog(1, "aClSysMmap: NULL pointer used"
            " for offset in/out argument\n");
#endif
    return -NACL_ABI_EINVAL;
  }

  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t)offp, sizeof(offset));
  if (kNaClBadAddress == sysaddr) {
    NaClLog(2, "%s\n", "NaClSysMmap: offset in a bad untrusted memory location");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }
  offset = *(nacl_abi_off_t *)sysaddr;
  NaClLog(2, " offset = 0x%08"NACL_PRIxNACL_OFF"\n", offset);
  retval = NaClSysMmapIntern(nap, start, length, prot, flags, d, offset);

cleanup:
  return retval;
}

int32_t NaClSysMunmap(struct NaClAppThread  *natp,
                      void                  *start,
                      size_t                length) {
  struct NaClApp *nap = natp->nap;
  int32_t   retval = -NACL_ABI_EINVAL;
  uintptr_t sysaddr;
  int       holding_app_lock = 0;
  size_t    alloc_rounded_length;

  NaClLog(2, "Entered NaClSysMunmap(0x%08"NACL_PRIxPTR", "
          "0x%08"NACL_PRIxPTR", 0x%"NACL_PRIxS")\n",
          (uintptr_t) natp, (uintptr_t) start, length);

  if (!NaClIsAllocPageMultiple((uintptr_t) start)) {
    NaClLog(2, "%s\n", "start addr not allocation multiple");
    retval = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  if (!length) {
    /*
     * Without this check we would get the following inconsistent
     * behaviour:
     *  * On Linux, an mmap() of zero length yields a failure.
     *  * On Mac OS X, an mmap() of zero length returns no error,
     *    which would lead to a NaClVmmapUpdate() of zero pages, which
     *    should not occur.
     *  * On Windows we would iterate through the 64k pages and do
     *    nothing, which would not yield a failure.
     */
    retval = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  alloc_rounded_length = NaClRoundAllocPage(length);
  if (alloc_rounded_length != length) {
    length = alloc_rounded_length;
    NaClLog(2, "munmap: rounded length to 0x%"NACL_PRIxS"\n", length);
  }
  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) start, length);
  if (kNaClBadAddress == sysaddr) {
    NaClLog(4, "munmap: region not user addresses\n");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  NaClXMutexLock(&nap->mu);

  NaClVmHoleOpeningMu(nap);

  holding_app_lock = 1;

  /*
   * User should be unable to unmap any executable pages.  We check here.
   */
  if (NaClSysCommonAddrRangeContainsExecutablePages(nap,
                                                    (uintptr_t) start,
                                                    length)) {
    NaClLog(2, "NaClSysMunmap: region contains executable pages\n");
    retval = -NACL_ABI_EINVAL;
    goto cleanup;
  }

  NaClVmIoPendingCheck_mu(nap,
                          (uint32_t) (uintptr_t) start,
                          (uint32_t) ((uintptr_t) start + length - 1));

  retval = MunmapInternal(nap, sysaddr, length);
cleanup:
  if (holding_app_lock) {
    NaClVmHoleClosingMu(nap);
    NaClXMutexUnlock(&nap->mu);
  }
  return retval;
}

#if NACL_WINDOWS
static int32_t MprotectInternal(struct NaClApp *nap,
                                uintptr_t sysaddr, size_t length, int prot) {
  uintptr_t addr;
  uintptr_t endaddr = sysaddr + length;
  uintptr_t usraddr;
  DWORD     flProtect;
  DWORD     flOldProtect;

  /*
   * VirtualProtect region cannot span allocations, all addresses must be
   * in one region of memory returned from VirtualAlloc or VirtualAllocEx.
   */
  for (addr = sysaddr; addr < endaddr; addr += NACL_MAP_PAGESIZE) {
    struct NaClVmmapEntry const *entry;
    uintptr_t                   page_num;
    uintptr_t                   offset;

    usraddr = NaClSysToUser(nap, addr);

    entry = NaClVmmapFindPage(&nap->mem_map, usraddr >> NACL_PAGESHIFT);
    if (!entry) {
      continue;
    }
    NaClLog(2, "MprotectInternal: addr 0x%08x, desc 0x%08"NACL_PRIxPTR"\n",
            addr, (uintptr_t) entry->desc);

    page_num = usraddr - (entry->page_num << NACL_PAGESHIFT);
    offset = (uintptr_t) entry->offset + page_num;

    if (!entry->desc) {
      flProtect = NaClflProtectMap(prot);

      /* Change the page protection */
      if (!VirtualProtect((void *) addr,
                          NACL_MAP_PAGESIZE,
                          flProtect,
                          &flOldProtect)) {
        int error = GetLastError();
        NaClLog(LOG_FATAL, "MprotectInternal: "
                "failed to change the memory protection with VirtualProtect,"
                " addr 0x%08x, error %d (0x%x)\n",
                addr, error, error);
        return -NaClXlateSystemError(error);
      }
    } else if (offset < (uintptr_t) entry->file_size) {
      nacl_off64_t  file_bytes;
      size_t        chunk_size;
      size_t        rounded_chunk_size;
      int           desc_flags;
      char const    *err_msg;

      desc_flags = (*NACL_VTBL(NaClDesc, entry->desc)->GetFlags)(entry->desc);
      NaClflProtectAndDesiredAccessMap(prot,
                                       (entry->flags
                                        & NACL_ABI_MAP_PRIVATE) != 0,
                                       (desc_flags & NACL_ABI_O_ACCMODE),
                                       /* flMaximumProtect= */ NULL,
                                       &flProtect,
                                       /* dwDesiredAccess= */ NULL,
                                       &err_msg);
      if (!flProtect) {
        /*
         * This shouldn't really happen since we already checked the address
         * space using NaClVmmapCheckExistingMapping, but better be safe.
         */
        NaClLog(1, "MprotectInternal: %s\n", err_msg);
      }

      file_bytes = entry->file_size - offset;
      chunk_size = MIN((size_t) file_bytes, NACL_MAP_PAGESIZE);
      rounded_chunk_size = NaClRoundPage(chunk_size);

      NaClLog(2, "VirtualProtect(0x%08x, 0x%"NACL_PRIxS", %x)\n",
              addr, rounded_chunk_size, flProtect);

      /* Change the page protection */
      if (!VirtualProtect((void *) addr,
                          rounded_chunk_size,
                          flProtect,
                          &flOldProtect)) {
        int error = GetLastError();
        NaClLog(LOG_FATAL, "MprotectInternal: "
                "failed to change the memory protection with VirtualProtect()"
                " addr 0x%08x, error %d (0x%x)\n",
                addr, error, error);
        return -NaClXlateSystemError(error);
      }
    }
  }

  return 0;
}
#else
static int32_t MprotectInternal(struct NaClApp *nap,
                                uintptr_t sysaddr, size_t length, int prot) {
  uintptr_t               addr;
  uintptr_t               usraddr;
  uintptr_t               last_page_num;
  int                     host_prot;
  struct NaClVmmapIter    iter;
  struct NaClVmmapEntry   *entry;

  host_prot = NaClProtMap(prot);

  usraddr = NaClSysToUser(nap, sysaddr);
  last_page_num = (usraddr + length) >> NACL_PAGESHIFT;

  for (NaClVmmapFindPageIter(&nap->mem_map,
                             usraddr >> NACL_PAGESHIFT,
                             &iter);
       !NaClVmmapIterAtEnd(&iter) &&
         (entry = NaClVmmapIterStar(&iter))->page_num < last_page_num;
       NaClVmmapIterIncr(&iter)) {
    size_t entry_len = entry->npages << NACL_PAGESHIFT;

    usraddr = entry->page_num << NACL_PAGESHIFT;
    addr = NaClUserToSys(nap, usraddr);

    NaClLog(2, "MprotectInternal: "
            "addr 0x%08"NACL_PRIxPTR", desc 0x%08"NACL_PRIxPTR"\n",
            addr, (uintptr_t) entry->desc);

    if (!entry->desc) {
      if (mprotect((void *) addr, entry_len, host_prot)) {
        NaClLog(1, "MprotectInternal: "
                "mprotect on anonymous memory failed, errno = %d\n", errno);
        return -NaClXlateErrno(errno);
      }
    } else if (entry->offset < entry->file_size) {
      nacl_abi_off64_t  file_bytes;
      size_t            rounded_file_bytes;
      size_t            prot_len;

      file_bytes = entry->file_size - entry->offset;
      rounded_file_bytes = NaClRoundPage((size_t) file_bytes);
      prot_len = MIN(rounded_file_bytes, entry_len);

      if (mprotect((void *) addr, prot_len, host_prot)) {
        NaClLog(1, "MprotectInternal: "
                "mprotect on file-backed memory failed, errno = %d\n", errno);
        return -NaClXlateErrno(errno);
      }
    }
  }

  return 0;
}
#endif

int32_t NaClSysMprotectInternal(struct NaClApp  *nap,
                                uint32_t        start,
                                size_t          length,
                                int             prot) {
  int32_t     retval = -NACL_ABI_EINVAL;
  uintptr_t   sysaddr;
  int         holding_app_lock = 0;

  if (!NaClIsAllocPageMultiple((uintptr_t) start)) {
    NaClLog(2, "%s\n", "mprotect: start addr not allocation multiple");
    retval = -NACL_ABI_EINVAL;
    goto cleanup;
  }
  length = NaClRoundAllocPage(length);
  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) start, length);
  if (kNaClBadAddress == sysaddr) {
    NaClLog(2, "%s\n", "mprotect: region not user addresses");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }
  if ((~(NACL_ABI_PROT_READ | NACL_ABI_PROT_WRITE) & prot)) {
    NaClLog(2, "%s\n", "mprotect: prot has other bits than PROT_{READ|WRITE}");
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  NaClXMutexLock(&nap->mu);

  holding_app_lock = 1;

  if (!NaClVmmapCheckExistingMapping(
           &nap->mem_map, NaClSysToUser(nap, sysaddr) >> NACL_PAGESHIFT,
           length >> NACL_PAGESHIFT, prot)) {
    NaClLog(4, "mprotect: no such region\n");
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  /*
   * User should be unable to change protection of any executable pages.
   */
  if (NaClSysCommonAddrRangeContainsExecutablePages(nap,
                                                    (uintptr_t) start,
                                                    length)) {
    NaClLog(2, "NaClSysMprotect: region contains executable pages\n");
    retval = -NACL_ABI_EACCES;
    goto cleanup;
  }

  NaClVmIoPendingCheck_mu(nap,
                          (uint32_t) (uintptr_t) start,
                          (uint32_t) ((uintptr_t) start + length - 1));

  retval = MprotectInternal(nap, sysaddr, length, prot);
  if (!retval &&
      !NaClVmmapChangeProt(&nap->mem_map,
                           NaClSysToUser(nap, sysaddr) >> NACL_PAGESHIFT,
                           length >> NACL_PAGESHIFT,
                           prot)) {
    retval = -NACL_ABI_EACCES;
  }
cleanup:
  if (holding_app_lock) {
    NaClXMutexUnlock(&nap->mu);
  }
  return retval;
}

int32_t NaClSysMprotect(struct NaClAppThread  *natp,
                        uint32_t              start,
                        size_t                length,
                        int                   prot) {
  struct NaClApp  *nap = natp->nap;

  NaClLog(3, "Entered NaClSysMprotect(0x%08"NACL_PRIxPTR", "
          "0x%08"NACL_PRIxPTR", 0x%"NACL_PRIxS", 0x%x)\n",
          (uintptr_t) natp, (uintptr_t) start, length, prot);

  if (!NaClAclBypassChecks) {
    return -NACL_ABI_EACCES;
  }

  return NaClSysMprotectInternal(nap, start, length, prot);
}

int32_t NaClSysImcMakeBoundSock(struct NaClAppThread *natp,
                                int32_t              *sap) {
  /*
   * Create a bound socket descriptor and a socket address descriptor.
   */
  struct NaClApp              *nap = natp->nap;
  int32_t                     retval = -NACL_ABI_EINVAL;
  struct NaClDesc             *pair[2];
  int32_t                     usr_pair[2];

  NaClLog(2, "Entered NaClSysImcMakeBoundSock(0x%08"NACL_PRIxPTR","
           " 0x%08"NACL_PRIxPTR")\n",
           (uintptr_t)natp, (uintptr_t)sap);

  retval = NaClCommonDescMakeBoundSock(pair);
  if (retval) {
    goto cleanup;
  }

  usr_pair[0] = NaClSetAvail(nap, pair[0]);
  usr_pair[1] = NaClSetAvail(nap, pair[1]);
  if (!NaClCopyOutToUser(nap, (uintptr_t) sap,
                         usr_pair, sizeof(usr_pair))) {
    /*
     * NB: The descriptors were briefly observable to untrusted code
     * in this window, even though the syscall had not returned yet,
     * and another thread which guesses their numbers could actually
     * use them, so the NaClDescSafeUnref inside NaClSetDesc below
     * might not actually deallocate right away.  To avoid this, we
     * could grab the descriptor lock and hold it until after the
     * copyout is done, but that imposes an ordering between the
     * descriptor lock and the VM lock which can cause problems
     * elsewhere.
     */
    NaClSetDesc(nap, usr_pair[0], NULL);
    NaClSetDesc(nap, usr_pair[1], NULL);
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  retval = 0;

cleanup:
  return retval;
}

/*
 * This function converts addresses from user addresses to system
 * addresses, copying into kernel space as needed to avoid TOCvTOU
 * races, then invokes the descriptor's SendMsg() method.
 */
int32_t NaClSysImcSendmsg(struct NaClAppThread         *natp,
                          int                          d,
                          struct NaClAbiNaClImcMsgHdr *nanimhp,
                          int                          flags) {
  struct NaClApp                *nap = natp->nap;
  int32_t                       retval;
  ssize_t                       ssize_retval;
  uintptr_t                     sysaddr;
  /* copy of user-space data for validation */
  struct NaClAbiNaClImcMsgHdr   kern_nanimh;
  struct NaClAbiNaClImcMsgIoVec kern_naiov[NACL_ABI_IMC_IOVEC_MAX];
  struct NaClImcMsgIoVec        kern_iov[NACL_ABI_IMC_IOVEC_MAX];
  int32_t                       usr_desc[NACL_ABI_IMC_USER_DESC_MAX];
  /* kernel-side representatin of descriptors */
  struct NaClDesc               *kern_desc[NACL_ABI_IMC_USER_DESC_MAX];
  struct NaClImcTypedMsgHdr     kern_msg_hdr;
  struct NaClDesc               *ndp;
  size_t                        i;
  int                           fd;

  NaClLog(2, "Entered NaClSysImcSendmsg(0x%08"NACL_PRIxPTR", %d,"
           " 0x%08"NACL_PRIxPTR", 0x%x)\n",
           (uintptr_t)natp, d, (uintptr_t)nanimhp, flags);

  if (!NaClCopyInFromUser(nap, &kern_nanimh, (uintptr_t) nanimhp,
                          sizeof(kern_nanimh))) {
    NaClLog(2, "%s\n", "NaClImcMsgHdr not in user address space");
    retval = -NACL_ABI_EFAULT;
    goto cleanup_leave;
  }
  /* copy before validating contents */

  /*
   * Some of these checks duplicate checks that will be done in the
   * nrd xfer library, but it is better to check before doing the
   * address translation of memory/descriptor vectors if those vectors
   * might be too long.  Plus, we need to copy and validate vectors
   * for TOCvTOU race protection, and we must prevent overflows.  The
   * nrd xfer library's checks should never fire when called from the
   * service runtime, but the nrd xfer library might be called from
   * other code.
   */
  if (kern_nanimh.iov_length > NACL_ABI_IMC_IOVEC_MAX) {
    NaClLog(2, "%s\n", "gather/scatter array too large");
    retval = -NACL_ABI_EINVAL;
    goto cleanup_leave;
  }
  if (kern_nanimh.desc_length > NACL_ABI_IMC_USER_DESC_MAX) {
    NaClLog(2, "%s\n", "handle vector too long");
    retval = -NACL_ABI_EINVAL;
    goto cleanup_leave;
  }

  if (kern_nanimh.iov_length > 0) {
    if (!NaClCopyInFromUser(nap, kern_naiov, (uintptr_t)kern_nanimh.iov,
                            (kern_nanimh.iov_length * sizeof(kern_naiov[0])))) {
      NaClLog(2, "%s\n", "gather/scatter array not in user address space");
      retval = -NACL_ABI_EFAULT;
      goto cleanup_leave;
    }

    for (i = 0; i < kern_nanimh.iov_length; ++i) {
      sysaddr = NaClUserToSysAddrRange(nap,
                                       (uintptr_t)kern_naiov[i].base,
                                       kern_naiov[i].length);
      if (kNaClBadAddress == sysaddr) {
        retval = -NACL_ABI_EFAULT;
        goto cleanup_leave;
      }
      kern_iov[i].base = (void *)sysaddr;
      kern_iov[i].length = kern_naiov[i].length;
    }
  }

  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto cleanup_leave;
  }

  fd = fd_cage_table[nap->cage_id][d];
  if (fd < 0) {
    retval = -NACL_ABI_EBADF;
    goto cleanup_leave;
  }
  ndp = NaClGetDesc(nap, fd);
  if (!ndp) {
    retval = -NACL_ABI_EBADF;
    goto cleanup_leave;
  }

  /*
   * make things easier for cleaup exit processing
   */
  memset(kern_desc, 0, sizeof(kern_desc));

  kern_msg_hdr.iov = kern_iov;
  kern_msg_hdr.iov_length = kern_nanimh.iov_length;

  if (!kern_nanimh.desc_length) {
    kern_msg_hdr.ndescv = 0;
    kern_msg_hdr.ndesc_length = 0;
  } else {
    if (!NaClCopyInFromUser(nap, usr_desc, kern_nanimh.descv,
                            kern_nanimh.desc_length * sizeof(usr_desc[0]))) {
      retval = -NACL_ABI_EFAULT;
      goto cleanup;
    }

    for (i = 0; i < kern_nanimh.desc_length; ++i) {
      if (kKnownInvalidDescNumber == usr_desc[i]) {
        kern_desc[i] = (struct NaClDesc *) NaClDescInvalidMake();
      } else {
        /* NaCl modules are ILP32, so this works on ILP32 and LP64 systems */
        kern_desc[i] = NaClGetDesc(nap, usr_desc[i]);
      }
      if (!kern_desc[i]) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
      }
    }
    kern_msg_hdr.ndescv = kern_desc;
    kern_msg_hdr.ndesc_length = kern_nanimh.desc_length;
  }
  kern_msg_hdr.flags = kern_nanimh.flags;

  /* lock user memory ranges in kern_naiov */
  for (i = 0; i < kern_nanimh.iov_length; ++i) {
    NaClVmIoWillStart(nap,
                      kern_naiov[i].base,
                      kern_naiov[i].base + kern_naiov[i].length - 1);
  }
  ssize_retval = NACL_VTBL(NaClDesc, ndp)->SendMsg(ndp, &kern_msg_hdr, flags);
  /* unlock user memory ranges in kern_naiov */
  for (i = 0; i < kern_nanimh.iov_length; ++i) {
    NaClVmIoHasEnded(nap,
                     kern_naiov[i].base,
                     kern_naiov[i].base + kern_naiov[i].length - 1);
  }

  if (NaClSSizeIsNegErrno(&ssize_retval)) {
    /*
     * NaClWouldBlock uses TSD (for both the errno-based and
     * GetLastError()-based implementations), so this is threadsafe.
     */
    if ((flags & NACL_DONT_WAIT) && NaClWouldBlock()) {
      retval = -NACL_ABI_EAGAIN;
    } else if (-NACL_ABI_EMSGSIZE == ssize_retval) {
      /*
       * Allow the caller to handle the case when imc_sendmsg fails because
       * the message is too large for the system to send in one piece.
       */
      retval = -NACL_ABI_EMSGSIZE;
    } else {
      /*
       * TODO(bsy): the else case is some mysterious internal error.
       * Should we destroy the ndp or otherwise mark it as bad?  Was
       * the failure atomic?  Did it send some partial data?  Linux
       * implementation appears okay.
       */
      retval = -NACL_ABI_EIO;
    }
  } else if (ssize_retval > INT32_MAX || ssize_retval < INT32_MIN) {
    retval = -NACL_ABI_EOVERFLOW;
  } else {
    /* cast is safe due to range checks above */
    retval = (int32_t)ssize_retval;
  }

cleanup:
  for (i = 0; i < kern_nanimh.desc_length; ++i) {
    if (kern_desc[i]) {
      NaClDescUnref(kern_desc[i]);
      kern_desc[i] = NULL;
    }
  }
  NaClDescUnref(ndp);
cleanup_leave:
  NaClLog(2, "NaClSysImcSendmsg: returning %d\n", retval);
  return retval;
}

int32_t NaClSysImcRecvmsg(struct NaClAppThread         *natp,
                          int                          d,
                          struct NaClAbiNaClImcMsgHdr  *nanimhp,
                          int                          flags) {
  struct NaClApp                        *nap = natp->nap;
  int32_t                               retval = -NACL_ABI_EINVAL;
  ssize_t                               ssize_retval;
  uintptr_t                             sysaddr;
  size_t                                i;
  struct NaClDesc                       *ndp;
  struct NaClAbiNaClImcMsgHdr           kern_nanimh;
  struct NaClAbiNaClImcMsgIoVec         kern_naiov[NACL_ABI_IMC_IOVEC_MAX];
  struct NaClImcMsgIoVec                kern_iov[NACL_ABI_IMC_IOVEC_MAX];
  int32_t                               usr_desc[NACL_ABI_IMC_USER_DESC_MAX];
  struct NaClImcTypedMsgHdr             recv_hdr;
  struct NaClDesc                       *new_desc[NACL_ABI_IMC_DESC_MAX];
  nacl_abi_size_t                       num_user_desc;
  struct NaClDesc                       *invalid_desc = NULL;
  int                                   fd;

  NaClLog(2, "Entered NaClSysImcRecvMsg(0x%08"NACL_PRIxPTR", %d,"
           " 0x%08"NACL_PRIxPTR")\n",
           (uintptr_t)natp, d, (uintptr_t)nanimhp);

  /*
   * First, we validate user-supplied message headers before
   * allocating a receive buffer.
   */
  if (!NaClCopyInFromUser(nap, &kern_nanimh, (uintptr_t) nanimhp,
                          sizeof(kern_nanimh))) {
    NaClLog(4, "NaClImcMsgHdr not in user address space\n");
    retval = -NACL_ABI_EFAULT;
    goto cleanup_leave;
  }
  /* copy before validating */

  if (kern_nanimh.iov_length > NACL_ABI_IMC_IOVEC_MAX) {
    NaClLog(4, "gather/scatter array too large: %"NACL_PRIdNACL_SIZE"\n",
            kern_nanimh.iov_length);
    retval = -NACL_ABI_EINVAL;
    goto cleanup_leave;
  }
  if (kern_nanimh.desc_length > NACL_ABI_IMC_USER_DESC_MAX) {
    NaClLog(4, "handle vector too long: %"NACL_PRIdNACL_SIZE"\n",
            kern_nanimh.desc_length);
    retval = -NACL_ABI_EINVAL;
    goto cleanup_leave;
  }

  if (kern_nanimh.iov_length > 0) {
    /*
     * Copy IOV array into kernel space.  Validate this snapshot and do
     * user->kernel address conversions on this snapshot.
     */
    if (!NaClCopyInFromUser(nap, kern_naiov, (uintptr_t) kern_nanimh.iov,
                            (kern_nanimh.iov_length * sizeof(kern_naiov[0])))) {
      NaClLog(4, "gather/scatter array not in user address space\n");
      retval = -NACL_ABI_EFAULT;
      goto cleanup_leave;
    }
    /*
     * Convert every IOV base from user to system address, validate
     * range of bytes are really in user address space.
     */

    for (i = 0; i < kern_nanimh.iov_length; ++i) {
      sysaddr = NaClUserToSysAddrRange(nap,
                                       (uintptr_t) kern_naiov[i].base,
                                       kern_naiov[i].length);
      if (kNaClBadAddress == sysaddr) {
        NaClLog(4, "iov number %"NACL_PRIdS" not entirely in user space\n", i);
        retval = -NACL_ABI_EFAULT;
        goto cleanup_leave;
      }
      kern_iov[i].base = (void *) sysaddr;
      kern_iov[i].length = kern_naiov[i].length;
    }
  }

  if (kern_nanimh.desc_length > 0) {
    sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t)kern_nanimh.descv,
                                     kern_nanimh.desc_length * sizeof(int32_t));
    if (kNaClBadAddress == sysaddr) {
      retval = -NACL_ABI_EFAULT;
      goto cleanup_leave;
    }
  }

  if ((d >= FILE_DESC_MAX)  || (d < 0)) {
    retval = -NACL_ABI_EBADF;
    goto cleanup_leave;
  }

  fd = fd_cage_table[nap->cage_id][d];
  if (fd < 0) {
    NaClLog(1, "%s\n", "receiving descriptor invalid");
    retval = -NACL_ABI_EBADF;
    goto cleanup_leave;
  }
  ndp = NaClGetDesc(nap, fd);
  if (!ndp) {
    NaClLog(1, "%s\n", "receiving descriptor invalid");
    retval = -NACL_ABI_EBADF;
    goto cleanup_leave;
  }

  recv_hdr.iov = kern_iov;
  recv_hdr.iov_length = kern_nanimh.iov_length;

  recv_hdr.ndescv = new_desc;
  recv_hdr.ndesc_length = sizeof(new_desc);
  memset(new_desc, 0, sizeof(new_desc));

  recv_hdr.flags = 0;  /* just to make it obvious; IMC will clear it for us */

  /* lock user memory ranges in kern_naiov */
  for (i = 0; i < kern_nanimh.iov_length; ++i) {
    NaClVmIoWillStart(nap,
                      kern_naiov[i].base,
                      kern_naiov[i].base + kern_naiov[i].length - 1);
  }
  ssize_retval = NACL_VTBL(NaClDesc, ndp)->RecvMsg(ndp, &recv_hdr, flags,
      (struct NaClDescQuotaInterface *) nap->reverse_quota_interface);
  /* unlock user memory ranges in kern_naiov */
  for (i = 0; i < kern_nanimh.iov_length; ++i) {
    NaClVmIoHasEnded(nap,
                     kern_naiov[i].base,
                     kern_naiov[i].base + kern_naiov[i].length - 1);
  }
  /*
   * retval is number of user payload bytes received and excludes the
   * header bytes.
   */
  NaClLog(3, "NaClSysImcRecvMsg: RecvMsg() returned %"NACL_PRIdS"\n",
          ssize_retval);
  if (NaClSSizeIsNegErrno(&ssize_retval)) {
    /* negative error numbers all have valid 32-bit representations,
     * so this cast is safe. */
    retval = (int32_t) ssize_retval;
    goto cleanup;
  } else if (ssize_retval > INT32_MAX || ssize_retval < INT32_MIN) {
    retval = -NACL_ABI_EOVERFLOW;
    goto cleanup;
  } else {
    /* cast is safe due to range check above */
    retval = (int32_t) ssize_retval;
  }

  /*
   * NB: recv_hdr.flags may contain NACL_ABI_MESSAGE_TRUNCATED and/or
   * NACL_ABI_HANDLES_TRUNCATED.
   */

  kern_nanimh.flags = recv_hdr.flags;

  /*
   * Now internalize the NaClHandles as NaClDesc objects.
   */
  num_user_desc = recv_hdr.ndesc_length;

  if (kern_nanimh.desc_length < num_user_desc) {
    kern_nanimh.flags |= NACL_ABI_RECVMSG_DESC_TRUNCATED;
    for (i = kern_nanimh.desc_length; i < num_user_desc; ++i) {
      NaClDescUnref(new_desc[i]);
      new_desc[i] = NULL;
    }
    num_user_desc = kern_nanimh.desc_length;
  }

  invalid_desc = (struct NaClDesc *) NaClDescInvalidMake();
  /* prepare to write out to user space the descriptor numbers */
  for (i = 0; i < num_user_desc; ++i) {
    if (invalid_desc == new_desc[i]) {
      usr_desc[i] = kKnownInvalidDescNumber;
      NaClDescUnref(new_desc[i]);
    } else {
      usr_desc[i] = NaClSetAvail(nap, new_desc[i]);
    }
    new_desc[i] = NULL;
  }
  if (num_user_desc &&
      !NaClCopyOutToUser(nap, (uintptr_t)kern_nanimh.descv, usr_desc,
                         num_user_desc * sizeof(usr_desc[0]))) {
    NaClLog(1, "NaClSysImcRecvMsg: in/out ptr (descv %"NACL_PRIxPTR
            ") became invalid at copyout?\n",
            (uintptr_t) kern_nanimh.descv);
  }

  kern_nanimh.desc_length = num_user_desc;
  if (!NaClCopyOutToUser(nap, (uintptr_t)nanimhp, &kern_nanimh,
                         sizeof(kern_nanimh))) {
    NaClLog(1, "%s\n",
            "NaClSysImcRecvMsg: in/out ptr (iov) became"
            " invalid at copyout?");
  }

cleanup:
  /* copy out updated desc count, flags */
  if (retval < 0) {
    for (i = 0; i < sizeof(new_desc) / sizeof(*new_desc); ++i) {
      if (new_desc[i]) {
        NaClDescUnref(new_desc[i]);
        new_desc[i] = NULL;
      }
    }
  }
  NaClDescUnref(ndp);
  NaClDescSafeUnref(invalid_desc);
  NaClLog(3, "NaClSysImcRecvMsg: returning %d\n", retval);
cleanup_leave:
  return retval;
}

int32_t NaClSysImcMemObjCreate(struct NaClAppThread  *natp,
                               size_t                size) {
  struct NaClApp        *nap = natp->nap;
  int32_t               retval = -NACL_ABI_EINVAL;
  struct NaClDescImcShm *shmp;
  off_t                 size_as_off;

  NaClLog(2, "Entered NaClSysImcMemObjCreate(0x%08"NACL_PRIxPTR
           " 0x%08"NACL_PRIxS")\n",
           (uintptr_t)natp, size);

  if (size & (NACL_MAP_PAGESIZE - 1)) {
    return -NACL_ABI_EINVAL;
  }
  /*
   * TODO(bsy): policy about maximum shm object size should be
   * enforced here.
   */
  size_as_off = (off_t)size;
  if (size_as_off < 0) {
    return -NACL_ABI_EINVAL;
  }

  shmp = malloc(sizeof(*shmp));
  if (!shmp) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup;
  }

  if (!NaClDescImcShmAllocCtor(shmp, size_as_off, /* executable= */0)) {
    /* is this reasonable? */
    retval = -NACL_ABI_ENOMEM;
    goto cleanup;
  }

  retval = NaClSetAvail(nap, (struct NaClDesc *)shmp);
  shmp = NULL;

cleanup:
  free(shmp);

  return retval;
}

int32_t NaClSysImcSocketPair(struct NaClAppThread *natp,
                             uint32_t             descs_out) {
  struct NaClApp          *nap = natp->nap;
  int32_t                 usr_pair[2];
  struct NaClDesc         *pair[2];
  int32_t                 retval;

  NaClLog(2, "Entered NaClSysImcSocketPair(0x%08"NACL_PRIxPTR
           " 0x%08"NACL_PRIx32")\n",
           (uintptr_t)natp, descs_out);

  retval = NaClCommonDescSocketPair(pair);
  if (retval) {
    goto cleanup;
  }

  usr_pair[0] = NaClSetAvail(nap, pair[0]);
  usr_pair[1] = NaClSetAvail(nap, pair[1]);

  if (!NaClCopyOutToUser(nap, (uintptr_t) descs_out, usr_pair,
                         sizeof(usr_pair))) {
    NaClSetDesc(nap, usr_pair[0], NULL);
    NaClSetDesc(nap, usr_pair[1], NULL);
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }
  retval = 0;

cleanup:
  return retval;
}

int32_t NaClSysSocketPair(struct NaClAppThread *natp,
                          int                  domain,
                          int                  type,
                          int                  protocol,
                          int                  *fds) {

  struct NaClApp          *nap = natp->nap;
  void                    *hd_struct = NULL;
  struct NaClHostDesc     *hd;
  int                     lind_fds[2];
  int                     nacl_fd;
  int                     user_fds[2];
  int32_t                 retval;

  NaClLog(2, "Cage %d Entered NaClSysSocketPair(0x%08"NACL_PRIxPTR", "
           "%d, %d, %d, %lx)\n",
           nap->cage_id, (uintptr_t)natp, domain, type, protocol, (uintptr_t)fds);

  hd_struct = malloc(sizeof(struct NaClHostDesc)*2);
  if (!hd_struct) {
    retval = -NACL_ABI_ENOMEM;
    return retval;
  }

  retval = lind_socketpair (domain, type, protocol, lind_fds, nap->cage_id);

  if (retval < 0) {
    free(hd_struct);
    return retval;
  }

  for(int i=0; i<2; ++i) {
    hd = &((struct NaClHostDesc*)hd_struct)[i];

    //NaClHostDescCtor(hd, lind_fd, NACL_ABI_O_RDWR):
    hd->d = lind_fds[i];
    hd->flags = NACL_ABI_O_RDWR;

    hd->cageid = nap->cage_id;
    nacl_fd = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd)));
    user_fds[i] = NextFd(nap->cage_id);
    fd_cage_table[nap->cage_id][user_fds[i]] = nacl_fd;
  }

    /* copy out NaCl fds */
  if (!NaClCopyOutToUser(nap, (uintptr_t)fds, user_fds, sizeof(user_fds))) {
      lind_close(lind_fds[0], nap->cage_id);
      lind_close(lind_fds[1], nap->cage_id);
      retval = -NACL_ABI_EFAULT;
  }


  NaClLog(2, "NaClSysSocketPair: returning %d\n", retval);

  return retval;
}

int32_t NaClSysTlsInit(struct NaClAppThread  *natp,
                       uint32_t              thread_ptr) {
  int32_t   retval = -NACL_ABI_EINVAL;
  uintptr_t sys_tls;

  NaClLog(3,
          ("Entered NaClSysTlsInit(0x%08"NACL_PRIxPTR
           ", 0x%08"NACL_PRIxPTR")\n"),
          (uintptr_t) natp, (uintptr_t) thread_ptr);

  /* Verify that the address in the app's range and translated from
   * nacl module address to service runtime address - a nop on ARM
   */
  sys_tls = NaClUserToSysAddrRange(natp->nap, thread_ptr, 4);
  NaClLog(4,
          "NaClSysTlsInit: thread_ptr 0x%"NACL_PRIx32
          ", sys_tls 0x%"NACL_PRIxPTR"\n",
          thread_ptr, sys_tls);
  if (kNaClBadAddress == sys_tls) {
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  NaClTlsSetTlsValue1(natp, thread_ptr);
  retval = 0;
cleanup:
  return retval;
}

int32_t NaClSysThreadCreate(struct NaClAppThread *natp,
                            void                 *prog_ctr,
                            uint32_t             stack_ptr,
                            uint32_t             thread_ptr,
                            uint32_t             second_thread_ptr) {
  struct NaClApp *nap = natp->nap;
  int32_t     retval = -NACL_ABI_EINVAL;
  uintptr_t   sys_tls;
  uintptr_t   sys_stack;

  NaClLog(3,
          ("Entered NaClSysThreadCreate(0x%08"NACL_PRIxPTR
           " pc=0x%08"NACL_PRIxPTR", sp=0x%08"NACL_PRIx32", thread_ptr=0x%08"
           NACL_PRIx32")\n"),
          (uintptr_t) natp, (uintptr_t) prog_ctr, stack_ptr, thread_ptr);

  if (!NaClIsValidJumpTarget(nap, (uintptr_t) prog_ctr)) {
    NaClLog(LOG_ERROR, "NaClSysThreadCreate: Bad function pointer\n");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  /* Align the stack pointer. */
  stack_ptr = ((stack_ptr + NACL_STACK_PAD_BELOW_ALIGN)
               & ~NACL_STACK_ALIGN_MASK) - NACL_STACK_PAD_BELOW_ALIGN
              - NACL_STACK_ARGS_SIZE;

  sys_stack = NaClUserToSysAddr(nap, stack_ptr);
  if (kNaClBadAddress == sys_stack) {
    NaClLog(LOG_ERROR, "bad stack\n");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }
  sys_tls = NaClUserToSysAddrRange(nap, thread_ptr, 4);
  if (kNaClBadAddress == sys_tls) {
    NaClLog(LOG_ERROR, "bad TLS pointer\n");
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  NaClVmHoleWaitToStartThread(nap);

  retval = NaClCreateAdditionalThread(nap,
                                      (uintptr_t) prog_ctr,
                                      sys_stack,
                                      thread_ptr,
                                      second_thread_ptr);

cleanup:
  return retval;
}

/*
 * This is not used on x86-64 and its functionality is replaced by
 * NaClGetTlsFastPath1 (see nacl_syscall_64.S).
 */
int32_t NaClSysTlsGet(struct NaClAppThread *natp) {
  return NaClTlsGetTlsValue1(natp);
}

int32_t NaClSysSecondTlsSet(struct NaClAppThread *natp,
                            uint32_t             new_value) {
  NaClTlsSetTlsValue2(natp, new_value);
  return 0;
}

/*
 * This is not used on x86-64 and its functionality is replaced by
 * NaClGetTlsFastPath2 (see nacl_syscall_64.S).
 */
int32_t NaClSysSecondTlsGet(struct NaClAppThread *natp) {
  return NaClTlsGetTlsValue2(natp);
}

int NaClSysThreadNice(struct NaClAppThread *natp,
                      int                  nice) {
  /* Note: implementation of nacl_thread_nice is OS dependent. */
  UNREFERENCED_PARAMETER(natp);
  return nacl_thread_nice(nice);
}

int32_t NaClSysMutexCreate(struct NaClAppThread *natp) {
  struct NaClApp       *nap = natp->nap;
  int32_t              retval = -NACL_ABI_EINVAL;
  struct NaClDescMutex *desc;

  NaClLog(3,
          ("Entered NaClSysMutexCreate(0x%08"NACL_PRIxPTR")\n"),
          (uintptr_t) natp);

  desc = malloc(sizeof(*desc));

  if (!desc || !NaClDescMutexCtor(desc)) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup;
  }

  retval = NaClSetAvail(nap, (struct NaClDesc *) desc);
  desc = NULL;
cleanup:
  free(desc);
  NaClLog(3,
          ("NaClSysMutexCreate(0x%08"NACL_PRIxPTR") = %d\n"),
          (uintptr_t) natp, retval);
  return retval;
}

int32_t NaClSysMutexLock(struct NaClAppThread  *natp,
                         int32_t               mutex_handle) {
  struct NaClApp        *nap = natp->nap;
  int32_t               retval = -NACL_ABI_EINVAL;
  struct NaClDesc       *desc;

  NaClLog(2, "Entered NaClSysMutexLock(0x%08"NACL_PRIxPTR", %d)\n",
          (uintptr_t)natp, mutex_handle);

  desc = NaClGetDesc(nap, mutex_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->Lock)(desc);
  NaClDescUnref(desc);

cleanup:
  return retval;
}

int32_t NaClSysMutexUnlock(struct NaClAppThread  *natp,
                           int32_t               mutex_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *desc;

  NaClLog(2, "Entered NaClSysMutexUnlock(0x%08"NACL_PRIxPTR", %d)\")",
          (uintptr_t)natp, mutex_handle);

  desc = NaClGetDesc(nap, mutex_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->Unlock)(desc);
  NaClDescUnref(desc);

cleanup:
  return retval;
}

int32_t NaClSysMutexTrylock(struct NaClAppThread   *natp,
                            int32_t                 mutex_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *desc;

  NaClLog(2, "Entered NaClSysMutexTrylock(0x%08"NACL_PRIxPTR", %d)\n",
          (uintptr_t)natp, mutex_handle);

  desc = NaClGetDesc(nap, mutex_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->TryLock)(desc);
  NaClDescUnref(desc);

cleanup:
  return retval;
}

int32_t NaClSysCondCreate(struct NaClAppThread *natp) {
  struct NaClApp         *nap = natp->nap;
  int32_t                retval = -NACL_ABI_EINVAL;
  struct NaClDescCondVar *desc;

  NaClLog(3,
          ("Entered NaClSysCondCreate(0x%08"NACL_PRIxPTR")\n"),
          (uintptr_t) natp);

  desc = malloc(sizeof(*desc));

  if (!desc || !NaClDescCondVarCtor(desc)) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup;
  }

  retval = NaClSetAvail(nap, (struct NaClDesc *)desc);
  desc = NULL;
cleanup:
  free(desc);
  NaClLog(2, "NaClSysCondCreate(0x%08"NACL_PRIxPTR") = %d\n",
           (uintptr_t)natp, retval);
  return retval;
}

int32_t NaClSysCondWait(struct NaClAppThread *natp,
                        int32_t              cond_handle,
                        int32_t              mutex_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *cv_desc;
  struct NaClDesc *mutex_desc;

  NaClLog(2, "Entered NaClSysCondWait(0x%08"NACL_PRIxPTR", %d, %d)\n",
           (uintptr_t)natp, cond_handle, mutex_handle);

  cv_desc = NaClGetDesc(nap, cond_handle);

  if (!cv_desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  mutex_desc = NaClGetDesc(nap, mutex_handle);
  if (!mutex_desc) {
    NaClDescUnref(cv_desc);
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) cv_desc->base.vtbl)->
            Wait)(cv_desc, mutex_desc);
  NaClDescUnref(cv_desc);
  NaClDescUnref(mutex_desc);

cleanup:
  return retval;
}

int32_t NaClSysCondSignal(struct NaClAppThread *natp,
                          int32_t              cond_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *desc;

  NaClLog(2, "Entered NaClSysCondSignal(0x%08"NACL_PRIxPTR", %d)\n",
           (uintptr_t)natp, cond_handle);

  desc = NaClGetDesc(nap, cond_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->Signal)(desc);
  NaClDescUnref(desc);
cleanup:
  return retval;
}

int32_t NaClSysCondBroadcast(struct NaClAppThread  *natp,
                             int32_t               cond_handle) {
  struct NaClApp  *nap = natp->nap;
  struct NaClDesc *desc;
  int32_t         retval = -NACL_ABI_EINVAL;

  NaClLog(2, "Entered NaClSysCondBroadcast(0x%08"NACL_PRIxPTR", %d)\n",
          (uintptr_t)natp, cond_handle);

  desc = NaClGetDesc(nap, cond_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->Broadcast)(desc);
  NaClDescUnref(desc);

cleanup:
  return retval;
}

int32_t NaClSysCondTimedWaitAbs(struct NaClAppThread     *natp,
                                int32_t                  cond_handle,
                                int32_t                  mutex_handle,
                                struct nacl_abi_timespec *ts) {
  struct NaClApp           *nap = natp->nap;
  int32_t                  retval = -NACL_ABI_EINVAL;
  struct NaClDesc          *cv_desc;
  struct NaClDesc          *mutex_desc;
  struct nacl_abi_timespec trusted_ts;

  NaClLog(2, "Entered NaClSysCondTimedWaitAbs(0x%08"NACL_PRIxPTR
           ", %d, %d, 0x%08"NACL_PRIxPTR")\n",
           (uintptr_t)natp, cond_handle, mutex_handle, (uintptr_t)ts);

  if (!NaClCopyInFromUser(nap, &trusted_ts,
                          (uintptr_t) ts, sizeof(trusted_ts))) {
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  /* TODO(gregoryd): validate ts - do we have a limit for time to wait? */

  cv_desc = NaClGetDesc(nap, cond_handle);
  if (!cv_desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  mutex_desc = NaClGetDesc(nap, mutex_handle);
  if (!mutex_desc) {
    NaClDescUnref(cv_desc);
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = ((struct NaClDescVtbl const *)cv_desc->base.vtbl)->TimedWaitAbs(cv_desc, mutex_desc, &trusted_ts);
  NaClDescUnref(cv_desc);
  NaClDescUnref(mutex_desc);
cleanup:
  return retval;
}

int32_t NaClSysSemCreate(struct NaClAppThread *natp,
                         int32_t              init_value) {
  struct NaClApp           *nap = natp->nap;
  int32_t                  retval = -NACL_ABI_EINVAL;
  struct NaClDescSemaphore *desc;

  NaClLog(3,
          ("Entered NaClSysSemCreate(0x%08"NACL_PRIxPTR
           ", %d)\n"),
          (uintptr_t) natp, init_value);

  desc = malloc(sizeof(*desc));

  if (!desc || !NaClDescSemaphoreCtor(desc, init_value)) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup;
  }

  retval = NaClSetAvail(nap, (struct NaClDesc *) desc);
  desc = NULL;
cleanup:
  free(desc);
  return retval;
}


int32_t NaClSysSemWait(struct NaClAppThread *natp,
                       int32_t              sem_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *desc;

  NaClLog(2, "Entered NaClSysSemWait(0x%08"NACL_PRIxPTR
           ", %d)\n",
          (uintptr_t)natp, sem_handle);

  desc = NaClGetDesc(nap, sem_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  /*
   * TODO(gregoryd): we have to decide on the syscall API: do we
   * switch to read/write/ioctl API or do we stay with the more
   * detailed API. Anyway, using a single syscall for waiting on all
   * synchronization objects makes sense.
   */
  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->SemWait)(desc);
  NaClDescUnref(desc);
cleanup:
  return retval;
}

int32_t NaClSysSemPost(struct NaClAppThread *natp,
                       int32_t              sem_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *desc;

  NaClLog(2, "Entered NaClSysSemPost(0x%08"NACL_PRIxPTR
           ", %d)\n",
           (uintptr_t)natp, sem_handle);

  desc = NaClGetDesc(nap, sem_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = ((struct NaClDescVtbl const *) desc->base.vtbl)->Post(desc);
  NaClDescUnref(desc);
cleanup:
  return retval;
}

int32_t NaClSysSemGetValue(struct NaClAppThread *natp,
                           int32_t              sem_handle) {
  struct NaClApp  *nap = natp->nap;
  int32_t         retval = -NACL_ABI_EINVAL;
  struct NaClDesc *desc;

  NaClLog(2, "Entered NaClSysSemGetValue(0x%08"NACL_PRIxPTR
           ", %d)\n",
           (uintptr_t)natp, sem_handle);

  desc = NaClGetDesc(nap, sem_handle);

  if (!desc) {
    retval = -NACL_ABI_EBADF;
    goto cleanup;
  }

  retval = (*((struct NaClDescVtbl const *) desc->base.vtbl)->GetValue)(desc);
  NaClDescUnref(desc);
cleanup:
  return retval;
}

int32_t NaClSysNanosleep(struct NaClAppThread     *natp,
                         struct nacl_abi_timespec *req,
                         struct nacl_abi_timespec *rem) {
  struct NaClApp            *nap = natp->nap;
  struct nacl_abi_timespec  t_sleep;
  struct nacl_abi_timespec  t_rem;
  struct nacl_abi_timespec  *remptr;
  int                       retval = -NACL_ABI_EINVAL;

  NaClLog(2, "Entered NaClSysNanosleep(0x%08"NACL_PRIxPTR
           ", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR"x)\n",
           (uintptr_t)natp, (uintptr_t)req, (uintptr_t)rem);

  /* do the check before we sleep */
  if (rem && kNaClBadAddress ==
      NaClUserToSysAddrRange(nap, (uintptr_t) rem, sizeof(*rem))) {
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  if (!NaClCopyInFromUser(nap, &t_sleep,
                          (uintptr_t) req, sizeof(t_sleep))) {
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  remptr = !rem ? NULL : &t_rem;

  /*
   * We assume that we do not need to normalize the time request values.
   *
   * If bogus values can cause the underlying OS to get into trouble,
   * then we need more checking here.
   */
  NaClLog(2, "NaClSysNanosleep(time = %"NACL_PRId64".%09"NACL_PRId64" S)\n",
          (int64_t) t_sleep.tv_sec, (int64_t) t_sleep.tv_nsec);
  retval = NaClNanosleep(&t_sleep, remptr);
  NaClLog(2, "NaClNanosleep returned %d\n", retval);

  if (-NACL_ABI_EINTR == retval && rem && !NaClCopyOutToUser(nap, (uintptr_t)rem, remptr, sizeof(*remptr))) {
    NaClLog(1, "%s\n", "NaClSysNanosleep: check rem failed at copyout\n");
  }

cleanup:
  NaClLog(2, "%s\n", "nanosleep done.");
  return retval;
}

int32_t NaClSysSchedYield(struct NaClAppThread *natp) {
  UNREFERENCED_PARAMETER(natp);
  NaClThreadYield();
  return 0;
}

int32_t NaClSysExceptionHandler(struct NaClAppThread *natp,
                                uint32_t             handler_addr,
                                uint32_t             old_handler) {
  struct NaClApp *nap = natp->nap;
  int32_t rv = -NACL_ABI_EINVAL;

  if (!nap->enable_exception_handling) {
    rv = -NACL_ABI_ENOSYS;
    goto no_lock_exit;
  }
  if (!NaClIsValidJumpTarget(nap, handler_addr)) {
    rv = -NACL_ABI_EFAULT;
    goto no_lock_exit;
  }
  NaClXMutexLock(&nap->exception_mu);

  /*
   * This needs to be done while holding the lock so that we don't
   * start two Windows debug exception handlers.
   */
  if (handler_addr != 0) {
    if (!NaClDebugExceptionHandlerEnsureAttached(nap)) {
      rv = -NACL_ABI_ENOSYS;
      goto unlock_exit;
    }
  }

  if (old_handler &&
      !NaClCopyOutToUser(nap, (uintptr_t) old_handler,
                         &nap->exception_handler,
                         sizeof(nap->exception_handler))) {
    rv = -NACL_ABI_EFAULT;
    goto unlock_exit;
  }
  nap->exception_handler = handler_addr;
  rv = 0;
 unlock_exit:
  NaClXMutexUnlock(&nap->exception_mu);
 no_lock_exit:
  return rv;
}

int32_t NaClSysExceptionStack(struct NaClAppThread *natp,
                              uint32_t             stack_addr,
                              uint32_t             stack_size) {
  if (!natp->nap->enable_exception_handling) {
    return -NACL_ABI_ENOSYS;
  }
  if (kNaClBadAddress == NaClUserToSysAddrNullOkay(natp->nap,
                                                   stack_addr + stack_size)) {
    return -NACL_ABI_EINVAL;
  }
  natp->exception_stack = stack_addr + stack_size;
  return 0;
}

int32_t NaClSysExceptionClearFlag(struct NaClAppThread *natp) {
  if (!natp->nap->enable_exception_handling) {
    return -NACL_ABI_ENOSYS;
  }
  natp->exception_flag = 0;
  return 0;
}


int32_t NaClSysTestInfoLeak(struct NaClAppThread *natp) {
#if NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86
  /*
   * Put some interesting bits into the x87 and SSE registers.
   */
  union fxsave {
    char buf[512];
    struct {
      uint16_t fcw;
      uint16_t fsw;
      uint16_t ftw;
      uint16_t fop;
      union {
        struct {
          uint64_t rip;
          uint64_t rdp;
        } x64;
        struct {
          uint32_t fpu_ip;
          uint32_t cs;
          uint32_t fpu_dp;
          uint32_t ds;
        } ia32;
      } bitness;
      uint32_t mxcsr;
      uint32_t mxcsr_mask;
      struct {
        uint8_t st[10];
        uint8_t reserved[6];
      } st_space[8];
      uint32_t xmm_space[64];
    } fxsave;
  };

  static const char tenbytes[10] = "SecretBits";
  static const char manybytes[256] =
      "Highly sensitive information must not be leaked to untrusted code!\n"
      "xyzzy\nplugh\nYou are likely to be eaten by a grue.\n"
      "When in the Course of human events it becomes necessary for one people"
      " to dissolve the political bands which have connected them with ...\n";

# ifdef __GNUC__
  union fxsave u __attribute__((aligned(16)));
# elif NACL_WINDOWS
  __declspec(align(16)) union fxsave u;
# else
#  error Unsupported platform
# endif

  int i;

# ifdef __GNUC__
  __asm__("fxsave %0" : "=m" (u));
# elif NACL_WINDOWS
#  if NACL_BUILD_SUBARCH == 64
  NaClDoFxsave(&u);
#  else
  __asm {
    fxsave u
  };
#  endif
# else
# error Unsupported platform
# endif

  for (i = 0; i < 8; ++i)
    memcpy(&u.fxsave.st_space[i], tenbytes, sizeof(tenbytes));

  memcpy(u.fxsave.xmm_space, manybytes, sizeof(u.fxsave.xmm_space));

  /*
   * Set the MXCSR to an unlikely (but valid) value: all valid bits set.
   * The mask is provided by the hardware to say which bits can be set
   * (all others are reserved).  The untrusted test code (in
   * tests/infoleak/test_infoleak.c) sets MXCSR to zero before
   * making this system call so this value ensures that the test
   * actually verifies the behavior of the syscall return path.
   */
  u.fxsave.mxcsr = u.fxsave.mxcsr_mask;

# ifdef __GNUC__
  __asm__ volatile("fxrstor %0" :: "m" (u));
# elif NACL_WINDOWS
#  if NACL_BUILD_SUBARCH == 64
  NaClDoFxrstor(&u);
#  else
  __asm {
    fxrstor u
  };
#  endif
# else
# error Unsupported platform
# endif

#elif NACL_ARCH(NACL_BUILD_ARCH) == NACL_arm
  /*
   * Put some interesting bits into the VFP registers.
   */

  static const char manybytes[64] =
      "Sensitive information must not be leaked to untrusted code!!!!\n";

  __asm__ volatile("vldm %0, {d0-d7}" :: "r" (manybytes) :
                   "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7");
  __asm__ volatile("fmxr fpscr, %0" :: "r" (0xdeadbeef) : "vfpcc");

#endif

  UNREFERENCED_PARAMETER(natp);

  return -NACL_ABI_ENOSYS;
}

/*
 * This syscall is intended for testing NaCl's support for Breakpad
 * crash reporting inside Chromium.  When
 * http://code.google.com/p/nativeclient/issues/detail?id=579 is
 * addressed, we might put this syscall behind a flag.  Until then,
 * untrusted code can trigger Breakpad-reported crashes inside
 * syscalls, so there is no benefit to restricting this syscall.
 */
int32_t NaClSysTestCrash(struct NaClAppThread *natp, int crash_type) {
  /*
   * Despite being volatile, the Apple system compiler, llvm-gcc, still
   * optimizes the null pointer dereference into an illegal instruction when
   * written as a one-liner. That interferes with tests that expect precisely
   * a SIGSEGV, because they'll see a SIGILL instead.
   */
  volatile int *volatile p = 0;
  UNREFERENCED_PARAMETER(natp);

  switch (crash_type) {
    case NACL_TEST_CRASH_MEMORY:
      *p = 0;
      break;
    case NACL_TEST_CRASH_LOG_FATAL:
      NaClLog(LOG_FATAL, "NaClSysTestCrash: This is a test error\n");
      break;
    case NACL_TEST_CRASH_CHECK_FAILURE:
      CHECK(0);
      break;
  }
  return -NACL_ABI_EINVAL;
}

int32_t NaClSysGetTimeOfDay(struct NaClAppThread      *natp,
                            struct nacl_abi_timeval   *tv,
                            struct nacl_abi_timezone  *tz) {
  int                     retval;
  struct nacl_abi_timeval now;

  UNREFERENCED_PARAMETER(tz);

  NaClLog(3,
          ("Entered NaClSysGetTimeOfDay(%08"NACL_PRIxPTR
           ", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n"),
          (uintptr_t) natp, (uintptr_t) tv, (uintptr_t) tz);

  /*
   * tz is not supported in linux, nor is it supported by glibc, since
   * tzset(3) and the zoneinfo file should be used instead.
   *
   * TODO(bsy) Do we make the zoneinfo directory available to
   * applications?
   */

  retval = NaClGetTimeOfDay(&now);
  if (retval) {
    return retval;
  }
#if !NACL_WINDOWS
  /*
   * Coarsen the time to the same level we get on Windows -
   * 10 microseconds.
   */
  if (!NaClHighResolutionTimerEnabled()) {
    now.nacl_abi_tv_usec = (now.nacl_abi_tv_usec / 10) * 10;
  }
#endif
  CHECK(now.nacl_abi_tv_usec >= 0);
  CHECK(now.nacl_abi_tv_usec < NACL_MICROS_PER_UNIT);
  if (!NaClCopyOutToUser(natp->nap, (uintptr_t)tv, &now, sizeof(now))) {
    return -NACL_ABI_EFAULT;
  }
  return 0;
}

/* convenience typedef */
typedef int clock_func(nacl_clockid_t, struct nacl_abi_timespec *);

static int NaClIsValidClockId(int clk_id) {
  int ret = 0;
  switch (clk_id) {
  case NACL_ABI_CLOCK_REALTIME:
  case NACL_ABI_CLOCK_MONOTONIC:
  case NACL_ABI_CLOCK_PROCESS_CPUTIME_ID:
  case NACL_ABI_CLOCK_THREAD_CPUTIME_ID:
    ret = 1;
  }
  return ret;
}

int32_t NaClSysClockGetCommon(struct NaClAppThread  *natp,
                              int                   clk_id,
                              uint32_t              ts_addr,
                              clock_func            *time_func) {
  struct NaClApp            *nap = natp->nap;
  int                       retval = -NACL_ABI_EINVAL;
  struct nacl_abi_timespec  out_buf;

  if (!NaClIsValidClockId(clk_id)) {
    goto done;
  }
  retval = time_func((nacl_clockid_t) clk_id, &out_buf);
  if (!retval && !NaClCopyOutToUser(nap, (uintptr_t)ts_addr, &out_buf, sizeof(out_buf))) {
    retval = -NACL_ABI_EFAULT;
  }

 done:
  return retval;
}

int32_t NaClSysClockGetRes(struct NaClAppThread *natp,
                           int                  clk_id,
                           uint32_t             tsp) {
  return NaClSysClockGetCommon(natp, clk_id, (uintptr_t) tsp, NaClClockGetRes);
}

int32_t NaClSysClockGetTime(struct NaClAppThread  *natp,
                            int                   clk_id,
                            uint32_t              tsp) {
  return NaClSysClockGetCommon(natp, clk_id, (uintptr_t) tsp, NaClClockGetTime);
}

int32_t NaClSysPipe2(struct NaClAppThread  *natp, uint32_t *pipedes, int flags) {
  struct NaClApp *nap = natp->nap;
  int32_t ret = 0;
  int actualflags = flags & NACL_ABI_O_CLOEXEC;
  int lind_fds[2];
  int nacl_fds[2];
  int accflags;

  /* Attempt lind pipe RPC. Return lind pipe fds, if not return NaCl Error */
  
  ret = lind_pipe2(lind_fds, actualflags, nap->cage_id);
  if (-1 == ret) {
    NaClLog(2, "NaClSysPipe: pipe returned -1, errno %d\n", errno);
    return -NaClXlateErrno(errno);
  }

   /* Sync NaCl fds with Lind ufds*/
  for (int i = 0; i < 2; i++) {
    
    /* set flags for the read and write ends of the pipe */
    switch (i) {
    case 0:
      accflags = NACL_ABI_O_RDONLY;
      break;
    case 1:
      accflags = NACL_ABI_O_WRONLY|NACL_ABI_O_APPEND;
      break;
    default:
      /* something went terribly wrong */
      ret = -NACL_ABI_EFAULT;
      goto out;
    }

    /* Attempt to make NaCl fds */
    struct NaClHostDesc  *hd;

    hd = malloc(sizeof(*hd));
    if (!hd) {
      ret = -NACL_ABI_ENOMEM;
      goto out;
    }
    hd->cageid = nap->cage_id;

    /* Set up Host Descriptor via Pipe wrapper */

    int retval = NaClHostDescPipe(hd, lind_fds[i], accflags | actualflags);
    NaClLog(1, "NaClSysPipeCtor(0x%08"NACL_PRIxPTR", 0%o) returned %d\n",
            (uintptr_t) hd, accflags | actualflags, retval);
    /* Then let's make a NaCl descriptor and insert it into NaCls descriptor system */
    if (!retval) {
      retval = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd)));
      NaClLog(1, "Entered into open file descriptor table at %d\n", retval);
    }
    

    /* Update cage table with our lind fds */
    int pipe_fd = NextFd(nap->cage_id);
    if (pipe_fd < 0) {
      ret = -NACL_ABI_EBADF;
      goto out;
    }
    hd->userfd = pipe_fd;
    hd->flags = accflags | actualflags;
    fd_cage_table[nap->cage_id][pipe_fd] = retval;
    nacl_fds[i] = pipe_fd;

  }

  /* copy out NaCl fds */
  if (!NaClCopyOutToUser(nap, (uintptr_t)pipedes, nacl_fds, sizeof(nacl_fds))) {
      lind_close(lind_fds[0], nap->cage_id);
      lind_close(lind_fds[1], nap->cage_id);
      ret = -NACL_ABI_EFAULT;
  }

out:
  return ret;
}

int32_t NaClSysPipe(struct NaClAppThread *natp, uint32_t *pipedes) {
  return NaClSysPipe2(natp, pipedes, 0);
}

int32_t NaClSysFork(struct NaClAppThread *natp) {
  struct NaClApp *nap = natp->nap;
  struct NaClApp *nap_child = 0;
  char **child_argv = 0;
  int child_argc = 0;
  int ret = -NACL_ABI_ENOMEM;

  NaClLog(1, "%s\n", "[NaClSysFork] NaCl fork starts!");

  /* set up new "child" NaClApp */
  NaClLogThreadContext(natp);

  /* get new id and setup new cage in safeposix */
  NaClXMutexLock(&nap->mu); 
  int child_cage_id = INIT_PROCESS_NUM + ++fork_num;
  lind_fork(child_cage_id, nap->cage_id); 
  NaClXMutexUnlock(&nap->mu);

  nap_child = NaClChildNapCtor(natp->nap, child_cage_id, THREAD_LAUNCH_FORK);
  child_argc = nap_child->argc;
  child_argv = nap_child->argv;
  nap_child->running = 0;
  ret = child_cage_id;

  /* start fork thread */
  if (!NaClCreateThread(natp, nap_child, child_argc, child_argv, nap_child->clean_environ)) {
    NaClLog(1, "%s\n", "[NaClSysFork] forking program failed!");
    ret = -NACL_ABI_ENOMEM;

    /* exit failed process in safeposix */
    lind_exit(EXIT_FAILURE, child_cage_id);
    goto fail;
  }

  /* success */
  
  NaClLog(1, "[fork_num = %u, child = %u, parent = %u]\n", fork_num, nap_child->cage_id, nap->cage_id);

fail:

  return ret;
}

int32_t NaClSysExecve(struct NaClAppThread *natp, char const *path, char *const *argv, char *const *envp) {
  struct NaClApp *nap = natp->nap;
  struct NaClEnvCleanser env_cleanser = {0};
  uint32_t *sys_envp_ptr = { NULL };
  char **new_envp = 0;
  int new_envc = 0;
  int ret = -NACL_ABI_ENOMEM;

  /* Make sys_envp_ptr a NULL array if we were passed NULL by EXECV */
  if (envp) sys_envp_ptr = (uint32_t*)NaClUserToSysAddr(nap, (uintptr_t)envp);

  NaClLog(1, "%s\n", "[NaClSysExecve] NaCl execve() starts!");

  /* set up environment, only do this if we initially were passed an environment*/
  NaClEnvCleanserCtor(&env_cleanser, 0);
  if (envp) {
    /* Count amount of env from acquired NaCl pointer */
    uint32_t *envcountptr = sys_envp_ptr;
    while (envcountptr[new_envc] != NULL) {
      new_envc++;
    }
    new_envp = calloc(new_envc + 1, sizeof(*new_envp));
    if (!new_envp) {
      NaClLog(LOG_ERROR, "%s\n", "Failed to allocate new_envv");
      NaClEnvCleanserDtor(&env_cleanser);
      goto fail;
    }
    for (int i = 0; i < new_envc; i++) {
      char *env = (void *)NaClUserToSysAddr(nap, (uintptr_t)sys_envp_ptr[i]);
      env = (uintptr_t)env == kNaClBadAddress ? 0 : env;
      if (!env) {
        new_envp[i] = NULL;
        break;
      }
      else {
        int envsize = NACL_ENV_PREFIX_LENGTH + strlen(env) + 1;
        new_envp[i] = calloc(envsize, sizeof(char));
        snprintf(new_envp[i], envsize, "%s%s", NACL_ENV_PREFIX, env);
      } 
    }
  }
  new_envp[new_envc] = NULL;

  /* We've already cleaned the native environment, so just supply extra args from this syscall */
  if (!NaClEnvCleanserInit(&env_cleanser, (char const *const *)new_envp, 0)) {
    NaClLog(LOG_ERROR, "%s\n", "Failed to initialize environment cleanser");
    NaClEnvCleanserDtor(&env_cleanser);
    goto fail;
  }

  nap->clean_environ = NaClEnvCleanserEnvironment(&env_cleanser);
  ret = NaClSysExecv(natp, path, argv);

fail:
  for (char **pp = new_envp; pp && *pp; pp++) {
    free(*pp);
  }
  free(new_envp);

  return ret; 
}

int32_t NaClSysExecv(struct NaClAppThread *natp, char const *path, char *const *argv) {
  struct NaClApp *nap = natp->nap;
  struct NaClApp *nap_child = 0;
  char *sys_pathname;
  uint32_t *sys_argv_ptr;
  char *binary; 
  char **child_argv = 0;
  char **new_argv = 0;
  int child_argc = 0;
  int new_argc = 0;
  int ret = -NACL_ABI_ENOMEM;
  void *dyncode_child;
  size_t dyncode_size;
  size_t dyncode_npages;
  size_t tramp_size;
  size_t tramp_npages;
  uintptr_t dyncode_pnum_child;
  uintptr_t parent_start_addr;
  uintptr_t child_start_addr;
  uintptr_t tramp_pnum;

  /* Convert pathname from user path, set binary */
  sys_pathname = NaClUserToSysAddr(nap, path);
  binary = sys_pathname ? strdup(sys_pathname) : NULL;

  /* 
    Convert to a Sys Pointer for argv** 
    We need to turn these to uint32_t pointers for now because these are still NaCl pointers
    We'll convert to a char** later.
  */
  sys_argv_ptr = (uint32_t*)NaClUserToSysAddr(nap, (uintptr_t)argv);

  /* set up argv and argc */
  if (!sys_argv_ptr) {
    NaClLog(LOG_ERROR, "%s\n", "Passed a NULL pointer in argp");
    goto fail;
  }
  
  /* Count amount of args from acquired NaCl pointer */
  uint32_t *argcountptr = sys_argv_ptr;
  while (argcountptr[new_argc] != NULL) {
    new_argc++;
  }

  new_argv = calloc(new_argc + 1, sizeof(*new_argv));
  if (!new_argv) {
    NaClLog(LOG_ERROR, "%s\n", "Failed to allocate new_argv");
    goto fail;
  }
  for (int i = 0; i < new_argc; i++) {
    char *arg = (void *)NaClUserToSysAddr(nap, (uintptr_t)sys_argv_ptr[i]);
    arg = (uintptr_t)arg == kNaClBadAddress ? 0 : arg;
    new_argv[i] = arg ? strdup(arg) : 0;
    if (!arg) {
      break;
    }
  }
  new_argv[new_argc] = 0;

  /* set up new "child" NaClApp */
  child_argc = new_argc + 3;
  child_argv = calloc(child_argc + 1, sizeof(*child_argv));
  if (!child_argv) {
    NaClLog(LOG_ERROR, "%s\n", "Failed to allocate child_argv");
    goto fail;
  }
  child_argv[0] = "NaClMain";
  child_argv[1] = "--library-path";
  child_argv[2] = "/lib/glibc";
  for (int i = 0; i < new_argc; i++) {
    child_argv[i + 3] = new_argv[i] ? strdup(new_argv[i]) : NULL;
  }
  child_argv[child_argc] = NULL;
  nap->argc = child_argc;
  nap->argv = child_argv;
  if (binary) {
    free(nap->argv[3]);
    nap->argv[3] = strdup(binary);
  }
  nap->binary = child_argv[3];

  /* initialize child from parent state */
  NaClLogThreadContext(natp);
  int child_cage_id = INIT_PROCESS_NUM + ++fork_num;

  /* Copy fd table in SafePOSIX */
  NaClXMutexLock(&nap->mu); 
  NaClLog(2, "Copying fd table in SafePOSIX\n");
  lind_exec(child_cage_id, nap->cage_id);
  NaClXMutexUnlock(&nap->mu);

  nap_child = NaClChildNapCtor(nap, child_cage_id, THREAD_LAUNCH_EXEC);
  nap_child->running = 0;
  nap_child->in_fork = 0;

  /* TODO: fix dynamic text validation -jp */
  nap_child->skip_validator = 1;
  nap_child->main_exe_prevalidated = 1;
  
  /* calculate page addresses and sizes */
  dyncode_child = (void *)NaClUserToSys(nap_child, nap_child->dynamic_text_start);
  dyncode_size = NaClRoundPage(nap_child->dynamic_text_end - nap->dynamic_text_start);
  dyncode_npages = dyncode_size >> NACL_PAGESHIFT;
  tramp_size = NaClRoundPage(nap->static_text_end - NACL_SYSCALL_START_ADDR);
  tramp_npages = tramp_size >> NACL_PAGESHIFT;
  dyncode_pnum_child = NaClSysToUser(nap_child, (uintptr_t)dyncode_child) >> NACL_PAGESHIFT;
  parent_start_addr = nap->mem_start + NACL_SYSCALL_START_ADDR;
  child_start_addr = nap_child->mem_start + NACL_SYSCALL_START_ADDR;
  tramp_pnum = NaClSysToUser(nap, parent_start_addr) >> NACL_PAGESHIFT;

  /* map dynamic text into child */
  if (NaClMakeDynamicTextShared(nap_child) != LOAD_OK) {
    NaClLog(LOG_FATAL, "[cage id %d] failed to map dynamic text in NaClSysExecve()\n", nap_child->cage_id);
  }
  NaClVmmapAddWithOverwrite(&nap_child->mem_map,
                            dyncode_pnum_child,
                            dyncode_npages,
                            PROT_RX,
                            NACL_ABI_MAP_PRIVATE,
                            nap_child->text_shm,
                            0,
                            dyncode_size);

  /* add guard page mapping */
  NaClVmmapAdd(&nap_child->mem_map,
               0,
               NACL_SYSCALL_START_ADDR >> NACL_PAGESHIFT,
               NACL_ABI_PROT_NONE,
               NACL_ABI_MAP_PRIVATE,
               NULL,
               0,
               0);

  /*
   * The next pages up to NACL_TRAMPOLINE_END are the trampolines.
   * Immediately following that is the loaded text section.
   * These are collectively marked as PROT_READ | PROT_EXEC.
   */
  NaClLog(3,
          ("Trampoline/text region start 0x%08"NACL_PRIxPTR","
           " size 0x%08"NACL_PRIxS", end 0x%08"NACL_PRIxPTR"\n"),
          child_start_addr,
          tramp_size,
          child_start_addr + tramp_size);
  if (NaClMprotect((void *)child_start_addr, tramp_size, PROT_RW)) {
    NaClLog(LOG_FATAL, "NaClMemoryProtection: "
            "NaClMprotect(0x%08"NACL_PRIxPTR", "
            "0x%08"NACL_PRIxS", 0x%x) failed\n",
            child_start_addr,
            tramp_size,
            PROT_RW);
  }
  /* allocate and map child trampoline pages */
  NaClVmmapAddWithOverwrite(&nap_child->mem_map,
                            tramp_pnum,
                            tramp_npages,
                            PROT_RW,
                            MAP_ANON_PRIV,
                            NULL,
                            0,
                            0);
  if (!NaClPageAllocFlags((void **)&child_start_addr, tramp_size, NACL_ABI_MAP_ANON)) {
    NaClLog(LOG_FATAL, "%s\n", "child vmmap NaClPageAllocAtAddr failed!");
  }

  /* temporarily set RW page permissions for copy */
  NaClVmmapChangeProt(&nap_child->mem_map, tramp_pnum, tramp_npages, PROT_RW);
  NaClVmmapChangeProt(&nap->mem_map, tramp_pnum, tramp_npages, PROT_RW);
  if (NaClMprotect((void *)child_start_addr, tramp_size, PROT_RW) == -1) {
    NaClLog(LOG_FATAL, "%s\n", "child vmmap page NaClMprotect failed!");
  }
  if (NaClMprotect((void *)parent_start_addr, tramp_size, PROT_RW) == -1) {
    NaClLog(LOG_FATAL, "%s\n", "parent vmmap page NaClMprotect failed!");
  }

  /* setup trampolines */
  nap_child->nacl_syscall_addr = 0;
  NaClLog(2, "Initializing arch switcher\n");
  NaClInitSwitchToApp(nap_child);
  NaClLog(2, "Installing trampoline\n");
  NaClLoadTrampoline(nap_child);
  NaClLog(2, "Installing springboard\n");
  NaClLoadSpringboard(nap_child);
  /* copy the trampolines from parent */
  memmove((void *)child_start_addr, (void *)parent_start_addr, tramp_size);

  /*
   * NaClMemoryProtection also initializes the mem_map w/ information
   * about the memory pages and their current protection value.
   *
   * The contents of the dynamic text region will get remapped as
   * non-writable.
   */
  NaClLog(2, "Applying memory protection\n");
  if (NaClMemoryProtection(nap_child) != LOAD_OK) {
    NaClLog(LOG_FATAL, "%s\n", "child NaClMemoryProtection failed!");
  }

  /* reset permissions to executable */
  NaClLog(2, "Setting child permissions to executable\n");
  NaClVmmapChangeProt(&nap_child->mem_map, tramp_pnum, tramp_npages, PROT_RX);
  NaClLog(2, "Setting parent permissions to executable\n");
  NaClVmmapChangeProt(&nap->mem_map, tramp_pnum, tramp_npages, PROT_RX);

  NaClLog(2, "Child mprotect\n");
  if (NaClMprotect((void *)child_start_addr, tramp_size, PROT_RX) == -1) {
    NaClLog(LOG_FATAL, "%s\n", "child vmmap page NaClMprotect failed!");
  }
  NaClLog(2, "Parent mprotect\n");

  if (NaClMprotect((void *)parent_start_addr, tramp_size, PROT_RX) == -1) {
    NaClLog(LOG_FATAL, "%s\n", "parent vmmap page NaClMprotect failed!");
  }

  /* execute new binary, we pass NULL as parent natp since we're not basing the new thread off of this one. */
  ret = -NACL_ABI_ENOEXEC;
  NaClLog(1, "binary = %s\n", nap->binary);
  if (!NaClCreateThread(NULL, nap_child, child_argc, child_argv, nap_child->clean_environ)) {
    NaClLog(LOG_ERROR, "%s\n", "NaClCreateThread() failed");
    /* remove child cage */
    lind_exit(EXIT_FAILURE, child_cage_id);

    goto fail;
  }
    
  /* wait for child to finish before cleaning up */
  NaClWaitForMainThreadToExit(nap_child);
  NaClReportExitStatus(nap, nap_child->exit_status);
  NaClAppThreadTeardown(natp);

  /* success */
  ret = 0;

fail:
  /*  Env Cleanser */
  free((void *) nap->clean_environ);
  nap->clean_environ = NULL;

  for (char **pp = new_argv; pp && *pp; pp++) {
    free(*pp);
  }
  free(new_argv);
  free(binary);
  return ret;
}

#define WAIT_ANY (-1)
#define WAIT_ANY_PG 0

int32_t NaClSysWaitpid(struct NaClAppThread *natp,
                       int pid,
                       uint32_t *stat_loc,
                       int options) {

  /* seconds between thread switching */
  NACL_TIMESPEC_T const timeout = {1, 0};
  struct NaClApp *nap = natp->nap;
  struct NaClApp *nap_child = 0;
  uintptr_t sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t)stat_loc, 4);
  int *stat_loc_ptr = sysaddr == kNaClBadAddress ? NULL : (int *)sysaddr;
  int pid_max = fork_num;
  int ret = 0;

  NaClLog(1, "%s\n", "[NaClSysWaitpid] entered waitpid!");

  CHECK(nap->num_children < NACL_THREAD_MAX);
  if (stat_loc_ptr) {
    *stat_loc_ptr = 0;
  }

  if (!nap->num_children || pid > pid_max) {
    ret = -NACL_ABI_ECHILD;
    goto out;
  }

  /*
   * WAITPID: explicit child pid given
   */
  if (pid > 0 && pid <= pid_max) {
    int cage_id = pid;
    /* make sure children exists */
    NaClXMutexLock(&nap->children_mu);
    nap_child = DynArrayGet(&nap->children, cage_id);
    if (!nap_child) {
      ret = -NACL_ABI_ECHILD;
      NaClXCondVarBroadcast(&nap->children_cv);
      NaClXMutexUnlock(&nap->children_mu);
      goto out;
    }
    NaClLog(1, "Thread children count: %d\n", nap->num_children);
    /* wait for child to finish */
    while (DynArrayGet(&nap->children, cage_id)) {
      NaClXCondVarTimedWaitRelative(&nap->children_cv, &nap->children_mu, &timeout);
    }
    NaClXCondVarBroadcast(&nap->children_cv);
    NaClXMutexUnlock(&nap->children_mu);
    ret = pid;
    goto out;
  }

  /*
   * WAIT or WAITPID(-1)
   * TODO: implement pid == WAIT_ANY_PG (0), we currently don't deal with process groups
   */
  if (pid <= 0) {
    while(1){

      /* Cycle through possible cages up to the fork number (max amount of created cages) */
      for (int cage_id = 0; cage_id < fork_num; cage_id++) {

        NaClXMutexLock(&nap->children_mu);

        /* make sure children exist, if not send ABI_ECHILD */
        if (!nap->num_children) {
          ret = -NACL_ABI_ECHILD;
          NaClXCondVarBroadcast(&nap->children_cv);
          NaClXMutexUnlock(&nap->children_mu);
          goto out;
        }
        /* wait for next child to exit */
        nap_child = DynArrayGet(&nap->children, cage_id);
        if (nap_child) {
          NaClLog(1, "Thread children count: %d\n", nap->num_children);
          NaClXCondVarTimedWaitRelative(&nap->children_cv, &nap->children_mu, &timeout);
          /* exit if selected child has finished */
          if (!(nap_child = DynArrayGet(&nap->children, cage_id)) || !nap_child->running) {
            ret = cage_id;
            NaClXCondVarBroadcast(&nap->children_cv);
            NaClXMutexUnlock(&nap->children_mu);
            goto out;
          }
        }
    
        NaClXCondVarBroadcast(&nap->children_cv);

        NaClXMutexUnlock(&nap->children_mu);
      }
      
    }
    
  }

out:
  if (nap_child && stat_loc_ptr) {
    *stat_loc_ptr = nap_child->exit_status;
  }
  NaClLog(1, "[NaClSysWaitpid] pid = %d \n", pid);
  NaClLog(1, "[NaClSysWaitpid] status = %d \n", stat_loc_ptr ? *stat_loc_ptr : 0);
  NaClLog(1, "[NaClSysWaitpid] options = %d \n", options);
  NaClLog(1, "[NaClSysWaitpid] ret = %d \n", ret);

  return ret;
}

int32_t NaClSysWait(struct NaClAppThread *natp, uint32_t *stat_loc) {
  struct NaClApp *nap = natp->nap;
  int ret;

  NaClLog(1, "%s\n", "[NaClSysWait] entered wait! \n");

  if (!nap->num_children) {
    ret = -NACL_ABI_ECHILD;
    goto out;
  }
  ret = NaClSysWaitpid(natp, WAIT_ANY, stat_loc, 0);

out:
  NaClLog(1, "[NaClSysWait] ret = %d \n", ret);
  return ret;
}

int32_t NaClSysWait4(struct NaClAppThread *natp, int pid, uint32_t *stat_loc, int options, void *rusage) {
  UNREFERENCED_PARAMETER(rusage);
  return NaClSysWaitpid(natp, pid, stat_loc, options);
}

int32_t NaClSysSigProcMask(struct NaClAppThread *natp, int how, const void *set, void *oldset) {
  UNREFERENCED_PARAMETER(natp);
  UNREFERENCED_PARAMETER(how);
  UNREFERENCED_PARAMETER(set);
  UNREFERENCED_PARAMETER(oldset);
  return 0;
}

int32_t NaClSysGethostname(struct NaClAppThread *natp, char *name, size_t len) {
  int32_t ret;
  uintptr_t sysaddr;
  struct NaClApp *nap = natp->nap;
  
  NaClLog(2, "Cage %d Entered NaClSysGethostname(0x%08"NACL_PRIxPTR", "
          "0x%08"NACL_PRIxPTR", "
          "%d)\n",
          nap->cage_id, (uintptr_t) natp, (uintptr_t) name, len);
  
  sysaddr = NaClUserToSysAddrRange(nap, (uintptr_t) name, len);
  if (kNaClBadAddress == sysaddr) {
    NaClLog(2, "NaClSysGethostname could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    ret = -NACL_ABI_EFAULT;
    return ret;
  }
  
  ret = lind_gethostname (sysaddr, len, nap->cage_id);
  
  NaClLog(2, "NaClSysGethostname: returning %d\n", ret);
  
  return ret;
}

int32_t NaClSysSocket(struct NaClAppThread *natp, int domain, int type, int protocol) {
  int32_t ret;

  struct NaClApp *nap = natp->nap;
  struct NaClHostDesc *hd;
  int naclfd;
  int userfd;

  NaClLog(2, "Cage %d Entered NaClSysSocket(0x%08"NACL_PRIxPTR", "
          "%d, %d, %d)\n",
          nap->cage_id, (uintptr_t) natp, domain, type, protocol);
   
  hd = malloc(sizeof(struct NaClHostDesc));
  if (!hd) {
    ret = -NACL_ABI_ENOMEM;
    return ret;
  }
  
  ret = lind_socket (domain, type, protocol, nap->cage_id);
  
  if (ret < 0) {
    free(hd);
    return ret;
  }

  hd->d = ret; //old NaClHostDescCtor 
  hd->flags = NACL_ABI_O_RDWR; //old NaClHostDescCtor 
  
  hd->cageid = nap->cage_id;
  naclfd = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd)));
  userfd = NextFd(nap->cage_id);
  fd_cage_table[nap->cage_id][userfd] = naclfd;
  
  NaClLog(2, "NaClSysSocket: returning %d\n", userfd);
  
  return userfd;
}

int32_t NaClSysSend(struct NaClAppThread *natp, int sockfd, size_t len, int flags, const void *buf) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  
  const void *sysbufaddr = (const void*) NaClUserToSysAddrRange(nap, (uintptr_t) buf, len);
  NaClLog(2, "Cage %d Entered NaClSysSend(0x%08"NACL_PRIxPTR", "
          "%d, %ld, %d, 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, sockfd, len, flags, (uintptr_t) buf);

  if ((void*) kNaClBadAddress == sysbufaddr) {
    NaClLog(2, "NaClSysSend could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysSend was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);

  ret = lind_send(sockfd, sysbufaddr, len, flags, nap->cage_id);
  NaClLog(2, "NaClSysSend: returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysSendto(struct NaClAppThread *natp, int sockfd, const void *buf, size_t len,
                         int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;

  const void *sysbufaddr = (const void*) NaClUserToSysAddrRange(nap, (uintptr_t) buf, len);
  const void *syssockaddraddr = dest_addr == NULL ? NULL : (const void*) NaClUserToSysAddrRange(nap, (uintptr_t) dest_addr, addrlen);
  NaClLog(2, "Cage %d Entered NaClSysSendto(0x%08"NACL_PRIxPTR", "
          "%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d)\n",
          nap->cage_id, (uintptr_t) natp, sockfd, (uintptr_t) buf, len, flags, (uintptr_t) dest_addr, addrlen);

  if ((void*) kNaClBadAddress == sysbufaddr) {
    NaClLog(2, "NaClSysSendto could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }
  if ((void*) kNaClBadAddress == syssockaddraddr) {
    NaClLog(2, "NaClSysSendto could not translate sockaddr address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

 ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysSendto was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);

  ret = lind_sendto(sockfd, sysbufaddr, len, flags, syssockaddraddr, addrlen, nap->cage_id);
  NaClLog(2, "NaClSysSendto: returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysRecv(struct NaClAppThread *natp, int sockfd, size_t len, int flags, void *buf) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;

  void *sysbufaddr = (void*) NaClUserToSysAddrRange(nap, (uintptr_t) buf, len);
  NaClLog(2, "Cage %d Entered NaClSysRecv(0x%08"NACL_PRIxPTR", "
          "%d, %ld, %d, 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, sockfd, len, flags, (uintptr_t) buf);

  if ((void*) kNaClBadAddress == sysbufaddr) {
    NaClLog(2, "NaClSysRecv could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

 ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysRecv was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);

  ret = lind_recv(sockfd, sysbufaddr, len, flags, nap->cage_id);
  NaClLog(2, "NaClSysRecv: returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysRecvfrom(struct NaClAppThread *natp, int sockfd, void *buf, size_t len, int flags,
                           struct sockaddr *src_addr, socklen_t *addrlen) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;

  void *sysbufaddr = (void*) NaClUserToSysAddrRange(nap, (uintptr_t) buf, len);
  socklen_t *sysaddrlenaddr = addrlen == NULL ? NULL : (void*) NaClUserToSysAddrRange(nap, (uintptr_t) addrlen, sizeof(socklen_t));
  struct sockaddr *sysaddraddr;
  NaClLog(2, "Cage %d Entered NaClSysRecvfrom(0x%08"NACL_PRIxPTR", "
          "%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, sockfd, buf, len, flags, (uintptr_t)src_addr, (uintptr_t)addrlen);

  if ((void*) kNaClBadAddress == sysbufaddr) {
    NaClLog(2, "NaClSysRecvfrom could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }
  if ((void*) kNaClBadAddress == sysaddrlenaddr) {
    NaClLog(2, "NaClSysRecvfrom could not translate address length pointer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  if(sysaddrlenaddr != NULL) {
    sysaddraddr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) src_addr, sizeof(struct sockaddr_in6));//we use sockaddr_in6 to be conservative
 
    if ((void*) kNaClBadAddress == sysaddraddr) {
      NaClLog(2, "NaClSysRecvfrom could not translate socket address address, returning %d\n", -NACL_ABI_EFAULT);
      return -NACL_ABI_EFAULT;
    }
  } else {
    if(src_addr != NULL) {
      NaClLog(2, "NaClSysRecvfrom had a 0 length specified but the address was not NULL, returning %d\n", -NACL_ABI_EINVAL);
      return -NACL_ABI_EINVAL;
    } else {
      sysaddraddr = NULL;
    }
  }

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysRecvfrom was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }

  sockfd = NaClDesc2Lindfd(ndp);

  ret = lind_recvfrom(sockfd, sysbufaddr, len, flags, sysaddraddr, sysaddrlenaddr, nap->cage_id);
  NaClLog(2, "NaClSysRecvfrom: returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysShutdown(struct NaClAppThread *natp, int sockfd, int how)
{
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysShutdown(0x%08"NACL_PRIxPTR", %d, %d)\n",
          nap->cage_id, (uintptr_t) natp, sockfd, how);

ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysShutdown was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  
  ret = lind_shutdown(sockfd, how, nap->cage_id);
  NaClLog(2, "NaClSysShutdown returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysGetuid(struct NaClAppThread *natp)
{
  struct NaClApp *nap = natp->nap;
  int ret = lind_getuid(nap->cage_id);
  NaClLog(2, "NaClSysGetuid returning %d\n", ret);
  return ret;
}

int32_t NaClSysGeteuid(struct NaClAppThread *natp)
{
  struct NaClApp *nap = natp->nap;
  int ret = lind_geteuid(nap->cage_id);
  NaClLog(2, "NaClSysGeteuid returning %d\n", ret);
  return ret;
}

int32_t NaClSysGetgid(struct NaClAppThread *natp)
{
  struct NaClApp *nap = natp->nap;
  int ret = lind_getgid(nap->cage_id);
  NaClLog(2, "NaClSysGetgid returning %d\n", ret);
  return ret;
}

int32_t NaClSysGetegid(struct NaClAppThread *natp)
{
  struct NaClApp *nap = natp->nap;
  int ret = lind_getegid(nap->cage_id);
  NaClLog(2, "NaClSysGetegid returning %d\n", ret);
  return ret;
}

int32_t NaClSysFlock(struct NaClAppThread *natp, int fd, int operation)
{
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysFlock(0x%08"NACL_PRIxPTR", %d, %d)\n",
          nap->cage_id, (uintptr_t) natp, fd, operation);
  
 ndp = GetDescFromCagetable(nap, fd);
  if (!ndp) {
    NaClLog(2, "NaClSysFlock was passed an unrecognized file descriptor, returning %d\n", fd);
    return -NACL_ABI_EBADF;
  }
  
  fd = NaClDesc2Lindfd(ndp);

  ret = lind_flock(fd, operation, nap->cage_id);
  NaClLog(2, "NaClSysFlock returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysGetsockopt(struct NaClAppThread *natp, int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  unsigned int *syslenaddr = (unsigned int*) NaClUserToSysAddr(nap, (uintptr_t) optlen);
  void *sysvaladdr;
  struct NaClDesc *ndp;

  if ((void*) kNaClBadAddress == syslenaddr) {
    NaClLog(2, "NaClSysGetsockopt could not translate optlen address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  sysvaladdr = (void*) NaClUserToSysAddrRange(nap, (uintptr_t) optval, *syslenaddr);
  NaClLog(2, "Cage %d Entered NaClSysGetsockopt(0x%08"NACL_PRIxPTR", %d, %d, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, sockfd, level, optname, (uintptr_t) optval, (uintptr_t) optlen);
  NaClLog(2, "NaClSysgetSockopt %d %p %p\n", *syslenaddr, syslenaddr, optlen);

  if ((void*) kNaClBadAddress == sysvaladdr) {
    NaClLog(2, "NaClSysGetsockopt could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

 ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
     NaClLog(2, "NaClSysGetsockopt was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  
  ret = lind_getsockopt(sockfd, level, optname, sysvaladdr, syslenaddr, nap->cage_id);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysSetsockopt(struct NaClAppThread *natp, int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  
  const void *sysvaladdr = (const void*) NaClUserToSysAddrRange(nap, (uintptr_t) optval, optlen);
  NaClLog(2, "Cage %d Entered NaClSysSetsockopt(0x%08"NACL_PRIxPTR", %d, %d, %d, 0x%08"NACL_PRIxPTR", %u)\n",
          nap->cage_id, (uintptr_t) natp, sockfd, level, optname, (uintptr_t) optval, optlen);

  if ((void*) kNaClBadAddress == sysvaladdr) {
    NaClLog(2, "NaClSysSetsockopt could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysSetsockopt was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  
  ret = lind_setsockopt(sockfd, level, optname, sysvaladdr, optlen, nap->cage_id);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysFstatfs(struct NaClAppThread *natp,
                       int                  d,
                       struct lind_statfs   *buf) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  struct lind_statfs *sysbufaddr = (struct lind_statfs*) NaClUserToSysAddrRange(nap, (uintptr_t) buf, sizeof(struct lind_statfs));
  NaClLog(2, "Cage %d Entered NaClSysFstatfs(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, d, (uintptr_t) buf);

  if ((void*) kNaClBadAddress == sysbufaddr) {
    NaClLog(2, "NaClSysFstatfs could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  ndp = GetDescFromCagetable(nap, d);
  if (!ndp) {
    NaClLog(2, "NaClSysFstatfs was passed an unrecognized file descriptor, returning %d\n", d);
    return -NACL_ABI_EBADF;
  }

  d = NaClDesc2Lindfd(ndp);
  ret = lind_fstatfs(d, sysbufaddr, nap->cage_id);

  if(ret > 0) ret = 0;
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysStatfs(struct NaClAppThread *natp,
                      const char           *pathname,
                      struct lind_statfs   *buf) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct lind_statfs *sysbufaddr = (struct lind_statfs*) NaClUserToSysAddrRange(nap, (uintptr_t) buf, sizeof(struct lind_statfs));
  char           path[NACL_CONFIG_PATH_MAX];

  ret = CopyPathFromUser(nap, path, sizeof(path), (uintptr_t) pathname);

  NaClLog(2, "Cage %d Entered NaClSysStatfs(0x%08"NACL_PRIxPTR", %s, 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, path, (uintptr_t) buf);

  if (ret) {
    NaClLog(2, "NaClSysStatfs could not translate path address, returning %d\n", ret);
    return ret;
  }

  if ((void*) kNaClBadAddress == sysbufaddr) {
    NaClLog(2, "NaClSysStatfs could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }


  ret = lind_statfs(path, sysbufaddr, nap->cage_id);

  if(ret > 0) ret = 0;

  return ret;
}

int32_t NaClSysGetsockname(struct NaClAppThread *natp, 
                        int sockfd, 
                        struct sockaddr * addr,
                        socklen_t * addrlen) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  struct sockaddr * sysaddr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) addr, sizeof(struct sockaddr));
  socklen_t * sysaddrlen = (socklen_t*) NaClUserToSysAddrRange(nap, (uintptr_t) addrlen, sizeof(socklen_t));

  if ((void*) kNaClBadAddress == sysaddr) {
    NaClLog(2, "NaClSysGetpeername could not translate socket address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  if ((void*) kNaClBadAddress == sysaddrlen) {
    NaClLog(2, "NaClSysGetpeername could not translate addrlen address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  NaClLog(2, "Cage %d Entered NaClSysGetsockname(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n", 
          nap->cage_id, (uintptr_t) natp, sockfd, (uintptr_t) addr, (uintptr_t) addrlen);

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysGetsockname was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  
  ret = lind_getsockname(sockfd, sysaddr, sysaddrlen, nap->cage_id);
  NaClLog(2, "NaClSysGetsockname returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret; 
}

int32_t NaClSysGetpeername(struct NaClAppThread *natp, 
                        int sockfd, 
                        struct sockaddr * addr,
                        socklen_t * addrlen) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  struct sockaddr * sysaddr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) addr, sizeof(struct sockaddr));
  socklen_t * sysaddrlen = (socklen_t*) NaClUserToSysAddrRange(nap, (uintptr_t) addrlen, sizeof(socklen_t));

  if ((void*) kNaClBadAddress == sysaddr) {
    NaClLog(2, "NaClSysGetpeername could not translate socket address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  if ((void*) kNaClBadAddress == sysaddrlen) {
    NaClLog(2, "NaClSysGetpeername could not translate addrlen address, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  NaClLog(2, "Cage %d Entered NaClSysGetpeername(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n", 
          nap->cage_id, (uintptr_t) natp, sockfd, (uintptr_t) addr, (uintptr_t) addrlen);

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysGetpeername was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  
  ret = lind_getpeername(sockfd, sysaddr, sysaddrlen, nap->cage_id);
  NaClLog(2, "NaClSysGetpeername returning %d\n", ret);
  NaClDescUnref(ndp);
  return ret; 
}

int32_t NaClSysAccess(struct NaClAppThread *natp,
                      const char *file, int mode) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  char path[NACL_CONFIG_PATH_MAX];

  ret = CopyPathFromUser(nap, path, sizeof(path), (uintptr_t) file);

  NaClLog(2, "Cage %d Entered NaClSysAccess(0x%08"NACL_PRIxPTR", %s, %d)\n",
          nap->cage_id, (uintptr_t) natp, path, mode);

  if (ret) {
    NaClLog(2, "NaClSysStatfs could not translate path address, returning %d\n", ret);
    return ret;
  }

  ret = lind_access(path, mode, nap->cage_id);

  return ret;
}

int32_t NaClSysConnect(struct NaClAppThread *natp,
                       int sockfd,
                       const struct sockaddr *addr, 
                       socklen_t addrlen) {
  struct NaClApp *nap = natp->nap;
  const struct sockaddr* sysvaladdr;
  int32_t ret;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysConnect(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR", %d)\n",
          nap->cage_id, (uintptr_t) natp, sockfd, (uintptr_t) addr, addrlen);

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysConnect was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  
  sysvaladdr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) addr, addrlen);

  if ((void*) kNaClBadAddress == sysvaladdr) {
    NaClLog(2, "NaClSysConnect could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    ret = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  ret = lind_connect(sockfd, sysvaladdr, addrlen, nap->cage_id);
cleanup:
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysAccept(struct NaClAppThread *natp,
                      int sockfd, 
                      struct sockaddr *addr, 
                      socklen_t *addrlen) {
  struct NaClApp *nap = natp->nap;
  struct sockaddr* sysvaladdr;
  const socklen_t* syslenaddr;
  int32_t ret;
  int userfd;
  struct NaClHostDesc* nd;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysAccept(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, sockfd, (uintptr_t) addr, (uintptr_t) addrlen);

  nd = malloc(sizeof(struct NaClHostDesc));
  if (!nd) {
    NaClLog(2, "NaClSysAccept could not allocate room for returning NaCl desc\n");
    return -NACL_ABI_ENOMEM;
  }

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysAccept was passed an unrecognized file descriptor, returning %d\n", sockfd);
    free(nd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);
  syslenaddr = addrlen == NULL ? NULL : (socklen_t*) NaClUserToSysAddrRange(nap, (uintptr_t) addrlen, sizeof(socklen_t));
 
  if ((void*) kNaClBadAddress == syslenaddr) {
    NaClLog(2, "NaClSysAccept could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    free(nd);
    userfd = -NACL_ABI_EFAULT; // As we return userfd instead of a retvalue, changed ret with userfd.
    goto cleanup;
  }

  if(syslenaddr != NULL) {
    sysvaladdr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) addr, sizeof(struct sockaddr_in6));
 
    if ((void*) kNaClBadAddress == sysvaladdr) {
      NaClLog(2, "NaClSysAccept could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
      free(nd);
      userfd = -NACL_ABI_EFAULT; // As we return userfd instead of a retvalue, changed ret with userfd.
      goto cleanup;
    }
  } else {
    if(addr != NULL) {
      NaClLog(2, "NaClSysAccept had a 0 length specified but the address was not NULL, returning %d\n", -NACL_ABI_EINVAL);
      free(nd);
      userfd = -NACL_ABI_EINVAL;
      goto cleanup;
    } else {
      sysvaladdr = NULL;
    }
  }

  ret = lind_accept(sockfd, sysvaladdr, syslenaddr, nap->cage_id);

  nd->d = ret;
  nd->flags = NACL_ABI_O_RDWR;
  nd->cageid = nap->cage_id;

  ret = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(nd)));
  userfd = NextFd(nap->cage_id);
  fd_cage_table[nap->cage_id][userfd] = ret;

cleanup:
  NaClDescUnref(ndp);
  return userfd;
}

int32_t NaClSysBind(struct NaClAppThread *natp,
                       int sockfd, 
                       const struct sockaddr *addr,
                       socklen_t addrlen) { 
  
  struct NaClApp *nap = natp->nap;
  const struct sockaddr* sysvaladdr;
  int32_t ret;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysBind(0x%08"NACL_PRIxPTR", %d, %d, 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, sockfd, (uintptr_t) addr, addrlen);

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysBind was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp);

  sysvaladdr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) addr, addrlen);

  if ((void*) kNaClBadAddress == sysvaladdr) {
    NaClLog(2, "NaClSysBind could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    ret = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  ret = lind_bind(sockfd, sysvaladdr, addrlen, nap->cage_id);
  NaClLog(2, "NaClSysBind returning %d\n", ret);

cleanup:
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysListen(struct NaClAppThread *natp,
                       int sockfd, 
                       int backlog) {
  
  struct NaClApp *nap = natp->nap;
  int32_t ret;
  struct NaClDesc *ndp;

  NaClLog(2, "Cage %d Entered NaClSysListen(0x%08"NACL_PRIxPTR", %d, %d)\n",
          nap->cage_id, (uintptr_t) natp, sockfd, backlog);

  ndp = GetDescFromCagetable(nap, sockfd);
  if (!ndp) {
    NaClLog(2, "NaClSysListen was passed an unrecognized file descriptor, returning %d\n", sockfd);
    return -NACL_ABI_EBADF;
  }
  
  sockfd = NaClDesc2Lindfd(ndp); 
  
  ret = lind_listen(sockfd, backlog, nap->cage_id);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysFcntlGet (struct NaClAppThread *natp,
                         int fd, int cmd) {
  int32_t ret;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  NaClLog(2, "Cage %d Entered NaClSysFcntlGet(0x%08"NACL_PRIxPTR", %d, %d)\n",
          nap->cage_id, (uintptr_t) natp, fd, cmd);

  ndp = GetDescFromCagetable(nap, fd);
  if (!ndp) {
    NaClLog(2, "NaClSysFcntlGet was passed an unrecognized file descriptor, returning %d\n", fd);
    return -NACL_ABI_EBADF;
  }
  
  fd = NaClDesc2Lindfd(ndp);
  
  ret = lind_fcntl_get(fd, cmd, nap->cage_id);
  NaClDescUnref(ndp);
  return ret;
}

int32_t NaClSysFcntlSet (struct NaClAppThread *natp,
                         int fd, int cmd, long set_op) {
  int32_t ret;
  int fdtrans;
  struct NaClApp *nap = natp->nap;
  struct NaClDesc *ndp;
  NaClLog(2, "Cage %d Entered NaClSysFcntlSet(0x%08"NACL_PRIxPTR", %d, %d, %ld)\n",
          nap->cage_id, (uintptr_t) natp, fd, cmd, set_op);

  int naclfd = fd_cage_table[nap->cage_id][fd];
  if (naclfd < 0 || !(ndp = NaClGetDesc(nap, naclfd))) {
    NaClLog(2, "NaClSysFcntlSet was passed an unrecognized file descriptor, returning %d\n", -NACL_ABI_EBADF);
    return -NACL_ABI_EBADF;
  }
  fdtrans = ((struct NaClDescIoDesc *) ndp)->hd->d;

  if(cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
    struct NaClHostDesc *nhd = malloc(sizeof(struct NaClHostDesc));
    int new_hostfd;
    int newuser;
    int old_hostfd;
    struct NaClDesc *old_nd;
    struct NaClDescIoDesc *old_self;
    struct NaClHostDesc *old_hd;

    if(nhd == NULL) {
      ret = -NACL_ABI_ENOMEM;
      goto cleanup;
    }

    old_hostfd = fd_cage_table[nap->cage_id][fd];

    if (!(old_nd = NaClGetDesc(nap, old_hostfd))) {
      ret = -NACL_ABI_EBADF;
      goto cleanup;
    }

    old_self = (struct NaClDescIoDesc *) &old_nd->base;
    old_hd = old_self->hd;

    ret = lind_fcntl_set(fdtrans, cmd, set_op, nap->cage_id);
    if(ret < 0) {
        goto cleanup;
    }

    newuser = NextFdBounded(nap->cage_id, set_op);
    nhd->d = ret;
    nhd->flags = old_hd->flags;
    nhd->cageid = nap->cage_id;
    nhd->userfd = newuser;

    /* Set new nacl desc as available */
    new_hostfd = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(nhd)));
    /* and add the new hostfd to the cage table */
    fd_cage_table[nap->cage_id][newuser] = new_hostfd;
  
    /* We've got to put that old NaClDescriptor back in there... */
    NaClSetDesc(nap, old_hostfd, old_nd);
  
    ret = newuser;
  } else {
    if(cmd == F_SETFD) {
      struct NaClDescIoDesc *iodesc;
      struct NaClHostDesc *hostdesc;
      iodesc = (struct NaClDescIoDesc *) &ndp->base;
      hostdesc = iodesc->hd;
      if(set_op & NACL_ABI_O_CLOEXEC) {
        hostdesc->flags |= NACL_ABI_O_CLOEXEC;
      } else {
        hostdesc->flags &= ~NACL_ABI_O_CLOEXEC;
      }
    }

    ret = lind_fcntl_set(fdtrans, cmd, set_op, nap->cage_id);
  }
  
cleanup:
  NaClDescUnref(ndp);
  NaClLog(2, "Exiting NaClSysFcntlSet\n");
  return ret;
}

int32_t NaClSysPoll(struct NaClAppThread *natp, struct pollfd *fds, nfds_t nfds, int timeout) {
  struct NaClApp *nap = natp->nap;

  int retval = 0;
  struct pollfd *lind_fds, *fds_sysaddr;
  struct NaClDesc **ndps;

  fds_sysaddr = (struct sockaddr*) NaClUserToSysAddrRange(nap, (uintptr_t) fds, nfds * sizeof(struct pollfd));

  if ((void*) kNaClBadAddress == fds_sysaddr) {
    NaClLog(2, "NaClSysPoll could not translate fds array, returning %d\n", -NACL_ABI_EFAULT);
    return -NACL_ABI_EFAULT;
  }

  lind_fds = malloc(sizeof(struct pollfd) * nfds);
  ndps = malloc(sizeof(struct NaClDesc) * nfds);

  if (!lind_fds) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup; // ? what if it goes into cleanup before we fill ndps?
  }

  if (!ndps) {
    retval = -NACL_ABI_ENOMEM;
    goto cleanup; // ? what if it goes into cleanup before we fill ndps?
  }

  
  NaClFastMutexLock(&nap->desc_mu);
  for(unsigned int i = 0; i < nfds; ++i) {
      
    ndps[i] = GetDescFromCagetable(nap, fds_sysaddr[i].fd);
    if (!ndps) {
      NaClLog(2, "NaClSysPoll was passed an unrecognized file descriptor, returning %d\n", fds_sysaddr[i].fd);
      retval = -NACL_ABI_EBADF;
      goto cleanup;
    }
    int fd = NaClDesc2Lindfd(ndps[i]);
    lind_fds[i].fd = fd;

    lind_fds[i].events = fds_sysaddr[i].events;
    lind_fds[i].revents = lind_fds[i].revents;
  }
  NaClFastMutexUnlock(&nap->desc_mu);

  retval = lind_poll(lind_fds, nfds, timeout, nap->cage_id);

  for(unsigned int i = 0; i < nfds; ++i) {
    fds_sysaddr[i].revents = lind_fds[i].revents;
  }
    
cleanup:
  NaClLog(2, "Exiting NaClSysPoll\n");
  free(lind_fds);

  for (int i = 0; i < nfds; i++) //for all ndps
  {
    NaClDescUnref(ndps[i]);
  }
  free(ndps);
  return retval;
}

int32_t NaClSysEpollCreate(struct NaClAppThread  *natp, int size) {

  struct NaClApp *nap = natp->nap;
  struct NaClHostDesc  *hd;
  int userfd;
  int code = 0; //usage must be checked
  int32_t ret;

  
  NaClLog(2, "Cage %d Entered NaClSysEpollCreate(0x%08"NACL_PRIxPTR", ""%d)\n",
          nap->cage_id, (uintptr_t) natp, size);
   
  hd = malloc(sizeof(struct NaClHostDesc));
  if (!hd) {
    ret = -NACL_ABI_ENOMEM;
    return ret;
  }
  
  ret = lind_epoll_create(size, nap->cage_id);

  if (ret < 0) {
    free(hd);
    return ret;
  }
      
  hd->d = ret; //old NaClHostDescCtor 
  hd->flags = NACL_ABI_O_RDWR; //old NaClHostDescCtor 
  
  hd->cageid = nap->cage_id;
  code = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd)));
  userfd = NextFd(nap->cage_id);
  fd_cage_table[nap->cage_id][userfd] = code;
  code = userfd;
  
  NaClLog(2, "NaClSysEpollCreate: returning %d\n", userfd);
  
  return userfd;
}

int32_t NaClSysEpollCtl(struct NaClAppThread  *natp, int epfd, int op, int fd, struct epoll_event *event) {

  struct NaClApp *nap = natp->nap;
  struct epoll_event *eventsysaddr;
  int32_t ret;
  struct NaClDesc *ndp, *ndpe;

  NaClLog(2, "Cage %d Entered NaClSysEpollCtl(0x%08"NACL_PRIxPTR", %d, %d, %d, 0x%08"NACL_PRIxPTR", %d)\n",
          nap->cage_id, (uintptr_t) natp, epfd, op, fd, (uintptr_t) event);

  ndpe = GetDescFromCagetable(nap, epfd);
  if (!ndpe) {
    NaClLog(2, "NaClSysEpollCtl was passed an unrecognized file descriptor, returning %d\n", epfd);
    return -NACL_ABI_EBADF;
  }
  epfd = NaClDesc2Lindfd(ndpe);

  ndp = GetDescFromCagetable(nap, fd);
  if (!ndp) {
    NaClLog(2, "NaClSysEpollCtl was passed an unrecognized file descriptor, returning %d\n", fd);
    return -NACL_ABI_EBADF;
  }
  fd = NaClDesc2Lindfd(ndp);

  eventsysaddr = (struct epoll_event*) NaClUserToSysAddrRange(nap, (uintptr_t) event, sizeof(eventsysaddr));

  if ((void*) kNaClBadAddress == eventsysaddr) {
    NaClLog(2, "NaClSysEpollCtl could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    ret = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  ret = lind_epoll_ctl(epfd, op, fd, eventsysaddr, nap->cage_id);
cleanup:
  NaClDescUnref(ndpe);
  NaClDescUnref(ndp);
  return ret;
}


int32_t NaClSysEpollWait(struct NaClAppThread  *natp, int epfd, struct epoll_event *events, int maxevents, int timeout) {

  struct NaClApp *nap = natp->nap;
  struct epoll_event *eventsysaddr;
  int retval = 0;
  int nfds;
  int hfd;
  struct epoll_event *pfds;
  struct NaClDesc * ndp;

  NaClLog(2, "Cage %d Entered NaClSysEpollWait(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR", %d, %d,)\n",
          nap->cage_id, (uintptr_t) natp, epfd, (uintptr_t) events, maxevents, timeout);

  ndp = GetDescFromCagetable(nap, epfd);
  if (!ndp) {
    NaClLog(2, "NaClSysEpollWait was passed an unrecognized file descriptor, returning %d\n", epfd);
    return -NACL_ABI_EBADF;
  }

  epfd = NaClDesc2Lindfd(ndp);

  pfds = (struct epoll_event*) NaClUserToSysAddrRange(nap, (uintptr_t) events, sizeof(eventsysaddr));

  if ((void*) kNaClBadAddress == pfds) {
    NaClLog(2, "NaClSysEpollCtl could not translate buffer address, returning %d\n", -NACL_ABI_EFAULT);
    retval = -NACL_ABI_EFAULT;
    goto cleanup;
  }

  nfds = lind_epoll_wait(epfd, pfds, maxevents, timeout, nap->cage_id);
          
  NaClFastMutexLock(&nap->desc_mu);

  for(int i = 0; i < nfds; ++i) {
      for(int j = 0; j < 1024; ++j) {
          ndp = NaClGetDescMu(nap, j);
          if(!ndp) {
              NaClDescSafeUnref(ndp);
              continue;
          }
          hfd = ((struct NaClDescIoDesc *)ndp)->hd->d;
          if(pfds[i].data.fd == hfd) {
              pfds[i].data.fd = j;
          }
          NaClDescUnref(ndp);
      }
  }
  
  NaClFastMutexUnlock(&nap->desc_mu);

cleanup:
  NaClDescUnref(ndp);
  return retval;
}

char *fd_set_fd_translator_tolind(struct NaClApp* nap, fd_set *fdset, int maxfd, int *nfd) {
  //before this we must translate the ptr
  int fds[FD_SETSIZE];
  int fdsindex = 0;
  int ourmax = 0;
  struct NaClDesc *ndp;

  for(int i = 0; i < maxfd; i++) {
    if(FD_ISSET(i, fdset)) {  
      ndp = GetDescFromCagetable(nap, i);
      int tempfd = NaClDesc2Lindfd(ndp);
      int translated_fd = fds[fdsindex++] = tempfd;
      if(translated_fd < 0) {
        return (char*) -NACL_ABI_EBADF;
      }
      if(translated_fd >= ourmax)
        ourmax = translated_fd + 1;
    }
  }

  char *newset = malloc((ourmax + 7) / 8); //bitfield which can contain our fds now
  if(!newset)
    return (char*) -NACL_ABI_ENOMEM;
  for(int i = 0; i < fdsindex; i++) {
    int bitposition = fds[i];
    newset[bitposition / 8] |= 1 << (bitposition & 7); //sets the bit in the bitfield
  }

  if(ourmax > *nfd) {
    *nfd = ourmax;
  }

  return newset;
}

void fd_set_fd_translator_fromlind(struct NaClApp* nap, fd_set *fdset, char* otherbitfield, int maxfd) {
  int fds[FD_SETSIZE];
  int fdsindex = 0;
  struct NaClDesc *ndp;

  for(int i = 0; i < maxfd; i++) {
    if(FD_ISSET(i, fdset)) {
      ndp = GetDescFromCagetable(nap, i);
      int tempfd = NaClDesc2Lindfd(ndp);
      int translated_fd = fds[fdsindex++] = tempfd;
      NaClDescUnref(ndp);

      if(translated_fd == -1) {
        NaClLog(LOG_FATAL, "User fd %d which was valid on entering select call invalid upon exit\n", i);
      }
      if(!(otherbitfield[translated_fd / 8] & 1 << (translated_fd & 7))) {
        FD_CLR(i, fdset);
      }
    }
  }
}

int32_t NaClSysSelect (struct NaClAppThread *natp, int nfds, fd_set * readfds, 
                       fd_set * writefds, fd_set * exceptfds, struct timeval *timeout) {
  struct NaClApp *nap = natp->nap;
  int retval;
  int max_fd = 0;
  fd_set *naclwritefds, *naclreadfds, *naclexceptfds;
  struct timeval* nacltimeout = NULL;
  char *safeposixreadfds, *safeposixwritefds, *safeposixexceptfds;
  char *safeposixreadfds2 = NULL, *safeposixwritefds2 = NULL, *safeposixexceptfds2 = NULL;
  NaClLog(2, "Cage %d Entered NaClSysSelect(0x%08"NACL_PRIxPTR", %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR")\n",
          nap->cage_id, (uintptr_t) natp, nfds, (uintptr_t) readfds, (uintptr_t) writefds, (uintptr_t) exceptfds, (uintptr_t) timeout);

  if(readfds) {
    naclreadfds = (fd_set*) NaClUserToSysAddrRange(nap, (uintptr_t) readfds, sizeof(fd_set));

    if ((void*) kNaClBadAddress == naclreadfds) {
      NaClLog(2, "NaClSysSelect could not translate read fds address, returning %d\n", -NACL_ABI_EFAULT);
      return -NACL_ABI_EFAULT;
    }
    safeposixreadfds = fd_set_fd_translator_tolind(nap, naclreadfds, nfds, &max_fd);

    if ((long) safeposixreadfds < 0) {
      NaClLog(2, "NaClSysSelect could not translate fds in readfds %d\n", -NACL_ABI_EFAULT);
      return (long) safeposixreadfds;
    }
  }
  
  if(writefds) {
    naclwritefds = (fd_set*) NaClUserToSysAddrRange(nap, (uintptr_t) writefds, sizeof(fd_set));

    if ((void*) kNaClBadAddress == naclwritefds) {
      NaClLog(2, "NaClSysSelect could not translate write fds address, returning %d\n", -NACL_ABI_EFAULT);
      goto earlycleanup_write;
    }

    safeposixwritefds = fd_set_fd_translator_tolind(nap, naclwritefds, nfds, &max_fd);

    if ((long) safeposixwritefds < 0) {
      NaClLog(2, "NaClSysSelect could not translate fds in writefds %d\n", -NACL_ABI_EFAULT);
      retval = (long) safeposixwritefds;
      goto earlycleanup_write;
    }
  }

  if(exceptfds) {
    naclexceptfds = (fd_set*) NaClUserToSysAddrRange(nap, (uintptr_t) exceptfds, sizeof(fd_set));

    if ((void*) kNaClBadAddress == naclexceptfds) {
      NaClLog(2, "NaClSysSelect could not translate except fds address, returning %d\n", -NACL_ABI_EFAULT);
      goto earlycleanup_except;
    }

    safeposixexceptfds = fd_set_fd_translator_tolind(nap, naclexceptfds, nfds, &max_fd);

    if ((long) safeposixexceptfds < 0) {
      NaClLog(2, "NaClSysSelect could not translate fds in exceptfds %d\n", -NACL_ABI_EFAULT);
      retval = (long) safeposixexceptfds;
      goto earlycleanup_except;
    }
  }

  if(timeout) {
    nacltimeout = (struct timeval*) NaClUserToSysAddrRange(nap, (uintptr_t) timeout, sizeof(struct timeval));

    if ((void*) kNaClBadAddress == nacltimeout) {
      NaClLog(2, "NaClSysSelect could not translate timeout address, returning %d\n", -NACL_ABI_EFAULT);
      goto earlycleanup_timeout;
    }
  }

  if(readfds && safeposixreadfds) {
    if(!(safeposixreadfds2 = realloc(safeposixreadfds, (max_fd + 7)/8))) {
      retval = -NACL_ABI_ENOMEM;
      goto cleanup;
    }
  }

  if(writefds && safeposixwritefds) {
    if(!(safeposixwritefds2 = realloc(safeposixwritefds, (max_fd + 7)/8))) {
      retval = -NACL_ABI_ENOMEM;
      goto cleanup;
    }
  }

  if(exceptfds && safeposixexceptfds) {
    if(!(safeposixexceptfds2 = realloc(safeposixexceptfds, (max_fd + 7)/8))) {
      retval = -NACL_ABI_ENOMEM;
      goto cleanup;
    }
  }

  retval = lind_select(max_fd, safeposixreadfds2, safeposixwritefds2, safeposixexceptfds2, nacltimeout, nap->cage_id);
  
  if(safeposixreadfds2)
    fd_set_fd_translator_fromlind(nap, naclreadfds, safeposixreadfds2, nfds);
  if(safeposixwritefds2)
    fd_set_fd_translator_fromlind(nap, naclwritefds, safeposixwritefds2, nfds);
  if(safeposixexceptfds2)
    fd_set_fd_translator_fromlind(nap, naclexceptfds, safeposixexceptfds2, nfds);

cleanup:
  if(safeposixreadfds2) 
    free(safeposixreadfds);
  if(safeposixwritefds2) 
    free(safeposixwritefds);
  if(safeposixexceptfds2)
    free(safeposixexceptfds);

  return retval;
earlycleanup_timeout:
  if(exceptfds)
    free(safeposixexceptfds);
earlycleanup_except:
  if(writefds)
    free(safeposixwritefds);
earlycleanup_write:
  if(readfds) 
    free(safeposixreadfds);
  return -NACL_ABI_EFAULT;
}
