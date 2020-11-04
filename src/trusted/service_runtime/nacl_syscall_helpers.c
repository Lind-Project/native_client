/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Service Runtime.  I/O Descriptor / Handle abstraction.  Memory
 * mapping using descriptors.
 *
 * Note that we avoid using the thread-specific data / thread local
 * storage access to the "errno" variable, and instead use the raw
 * system call return interface of small negative numbers as errors.
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include "native_client/src/include/nacl_platform.h"
#include "native_client/src/include/portability.h"

#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/shared/platform/lind_platform.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_helpers.h"

#include "native_client/src/trusted/service_runtime/include/sys/errno.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"
#include "native_client/src/trusted/service_runtime/include/bits/mman.h"
#include "native_client/src/trusted/service_runtime/include/sys/stat.h"

#if NACL_LINUX
# define PREAD pread64
# define PWRITE pwrite64
#elif NACL_OSX
# define PREAD pread
# define PWRITE pwrite
#else
# error "Which POSIX OS?"
#endif

/*
 * Map our ABI to the host OS's ABI.  On linux, this should be a big no-op.
 */
static INLINE int NaClMapOpenFlags(int nacl_flags) {
  int host_os_flags;

  nacl_flags &= (NACL_ABI_O_ACCMODE | NACL_ABI_O_CREAT
                 | NACL_ABI_O_TRUNC | NACL_ABI_O_APPEND);

  host_os_flags = 0;
#define C(H) case NACL_ABI_ ## H: \
  host_os_flags |= H;             \
  break;
  switch (nacl_flags & NACL_ABI_O_ACCMODE) {
    C(O_RDONLY);
    C(O_WRONLY);
    C(O_RDWR);
  }
#undef C
#define M(H) do { \
    if (0 != (nacl_flags & NACL_ABI_ ## H)) {   \
      host_os_flags |= H;                       \
    }                                           \
  } while (0)
  M(O_CREAT);
  M(O_TRUNC);
  M(O_APPEND);
#undef M
  return host_os_flags;
}

static INLINE int NaClMapOpenPerm(int nacl_perm) {
  int host_os_perm;

  host_os_perm = 0;
#define M(H) do { \
    if (0 != (nacl_perm & NACL_ABI_ ## H)) { \
      host_os_perm |= H; \
    } \
  } while (0)
  M(S_IRUSR);
  M(S_IWUSR);
#undef M
  return host_os_perm;
}

static INLINE int NaClMapFlagMap(int nacl_map_flags) {
  int host_os_flags;

  host_os_flags = 0;
#define M(H) do { \
    if (0 != (nacl_map_flags & NACL_ABI_ ## H)) { \
      host_os_flags |= H; \
    } \
  } while (0)
  M(MAP_SHARED);
  M(MAP_PRIVATE);
  M(MAP_FIXED);
  M(MAP_ANONYMOUS);
#undef M

  return host_os_flags;
}

/*
 * TODO(bsy): handle the !NACL_ABI_MAP_FIXED case.
 */
uintptr_t NaClMapHelper(int                 fd,
                        int                 cageid,
                        void                *start_addr,
                        size_t              len,
                        int                 prot,
                        int                 flags,
                        nacl_off64_t        offset) {
  int   desc;
  void  *map_addr;
  int   host_prot;
  int   tmp_prot;
  int   host_flags;
  int   need_exec;
  int   whichcage;
  unsigned long topbits;
  unsigned int mapbottom;

  NaClLog(4,
          ("NaClMapHelper(%d, "
           "0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxS", "
           "0x%x, 0x%x, 0x%08"NACL_PRIx64")\n"),
          fd,
          (uintptr_t) start_addr,
          len,
          prot,
          flags,
          (int64_t) offset);
  if (fd < 0 && 0 == (flags & NACL_ABI_MAP_ANONYMOUS)) {
    NaClLog(LOG_FATAL, "NaClMapHelper: 'there is no fd and not anon map\n");
  }

  if ((0 == (flags & NACL_ABI_MAP_SHARED)) ==
      (0 == (flags & NACL_ABI_MAP_PRIVATE))) {
    NaClLog(LOG_FATAL,
            "NaClMapHelper: exactly one of NACL_ABI_MAP_SHARED"
            " and NACL_ABI_MAP_PRIVATE must be set.\n");
  }

  prot &= NACL_ABI_PROT_MASK;


  /*
   * Translate prot, flags to host_prot, host_flags.
   */
  host_prot = NaClProtMap(prot);
  host_flags = NaClMapFlagMap(flags);

  NaClLog(4, "NaClMapHelper: host_prot 0x%x, host_flags 0x%x\n",
          host_prot, host_flags);

  /*
   * In chromium-os, the /dev/shm and the user partition (where
   * installed apps live) are mounted no-exec, and a special
   * modification was made to the chromium-os version of the Linux
   * kernel to allow mmap to use files as backing store with
   * PROT_EXEC. The standard mmap code path will fail mmap requests
   * that ask for PROT_EXEC, but mprotect will allow chaning the
   * permissions later. This retains most of the defense-in-depth
   * property of disallowing PROT_EXEC in mmap, but enables the use
   * case of getting executable code from a file without copying.
   *
   * See https://code.google.com/p/chromium/issues/detail?id=202321
   * for details of the chromium-os change.
   */
  tmp_prot = host_prot & ~PROT_EXEC;
  need_exec = (0 != (PROT_EXEC & host_prot));
  //By this point in execution, the mmap call is MAP_FIXED,
  //so start_addr should and cannot be null, but we sanity check
  if(!start_addr){
    NaClLog(LOG_FATAL,
            "NaClMapHelper: start_addr cannot be NULL.\n");
  }
  //if no hostDesc is specified, let the cageid to be 0, the init cage
  
  topbits = (long) start_addr & 0xffffffff00000000L;
  /* The RPC interface can only return ints, not longs. This means  
   * we can't get the top 32 bits of the address. Thankfully, the 
   * top 32 bits of the address, a cage invariant, are already
   * specified because MAP_FIXED is set, so we bitmask them from the 
   * start address.
   */
  mapbottom = lind_mmap(start_addr, len, tmp_prot, host_flags, desc, offset, cageid);
  /* MAP_FAILED is -1, so if we get that as our bottom 32 bits, we 
   * return a long -1 as our return value. Otherwise, combine the 
   * top bits and bottom bits into our full return value.
   */
  map_addr = (void*) (mapbottom == (unsigned int) -1 ? (unsigned long) -1L : topbits | (unsigned long) mapbottom);
  if (need_exec && MAP_FAILED != map_addr) {
    if (0 != mprotect(map_addr, len, host_prot)) {
      /*
       * Not being able to turn on PROT_EXEC is fatal: we have already
       * replaced the original mapping -- restoring them would be too
       * painful.  Without scanning /proc (disallowed by outer
       * sandbox) or Mach's vm_region call, there is no way
       * simple/direct to figure out what was there before.  On Linux
       * we could have mremap'd the old memory elsewhere, but still
       * would require probing to find the contiguous memory segments
       * within the original address range.  And restoring dirtied
       * pages on OSX the mappings for which had disappeared may well
       * be impossible (getting clean copies of the pages is feasible,
       * but insufficient).
       */
      NaClLog(LOG_FATAL,
              "NaClMapHelper: mprotect to turn on PROT_EXEC failed,"
              " errno %d\n", errno);
    }
  }

  NaClLog(4, "NaClMapHelper: mmap returned %"NACL_PRIxPTR"\n",
          (uintptr_t) map_addr);

  if (MAP_FAILED == map_addr) {
    NaClLog(LOG_INFO,
            ("NaClMapHelper: "
             "mmap(0x%08"NACL_PRIxPTR", 0x%"NACL_PRIxS", "
             "0x%x, 0x%x, %d, 0x%"NACL_PRIx64")"
             " failed, errno %d.\n"),
            (uintptr_t) start_addr, len, host_prot, host_flags, fd,
            (int64_t) offset,
            errno);
    return -NaClXlateErrno(errno);
  }
  if (0 != (flags & NACL_ABI_MAP_FIXED) && map_addr != start_addr) {
    NaClLog(LOG_FATAL,
            ("NaClMapHelper: mmap with MAP_FIXED not fixed:"
             " returned 0x%08"NACL_PRIxPTR" instead of 0x%08"NACL_PRIxPTR"\n"),
            (uintptr_t) map_addr,
            (uintptr_t) start_addr);
  }
  NaClLog(4, "NaClMapHelper: returning 0x%08"NACL_PRIxPTR"\n",
          (uintptr_t) map_addr);

  return (uintptr_t) map_addr;
}

int NaClUnmapUnsafeHelper(void *start_addr, size_t len) {
  return (0 == munmap(start_addr, len)) ? 0 : -errno;
}


int NaClOpenHelper( int                   cageid,
                    char const           *path,
                    int                  flags,
                    int                  mode) {
  nacl_host_stat_t stbuf;
  int posix_flags;
  int fd;

  NaClLog(3, "NaClOpenHelper(%s, 0x%x, 0x%x)\n",
          path, flags, mode);

  /*
   * Sanitize access flags.
   */
  if (0 != (flags & ~NACL_ALLOWED_OPEN_FLAGS)) {
    return -NACL_ABI_EINVAL;
  }

  switch (flags & NACL_ABI_O_ACCMODE) {
    case NACL_ABI_O_RDONLY:
    case NACL_ABI_O_WRONLY:
    case NACL_ABI_O_RDWR:
      break;
    default:
      NaClLog(LOG_ERROR,
              "NaClOpenHelper: bad access flags 0x%x.\n",
              flags);
      return -NACL_ABI_EINVAL;
  }

  posix_flags = NaClMapOpenFlags(flags);
#if NACL_LINUX
  posix_flags |= O_LARGEFILE;
#endif
  mode = NaClMapOpenPerm(mode);

  NaClLog(3, "NaClOpenHelper: invoking POSIX open(%s,0x%x,0%o)\n",
          path, posix_flags, mode);
  fd = lind_open(posix_flags, mode, path, cageid);
  NaClLog(3, "NaClOpenHelper: got descriptor %d\n", fd);
  if (-1 == fd) {
    NaClLog(2, "NaClOpenHelper: open returned -1, errno %d\n", errno);
    return -NaClXlateErrno(errno);
  }

  return fd;
}


ssize_t NaClReadHelper(int                    fd,
                         int                  cageid,
                         void                 *buf,
                         size_t               len) {
  ssize_t retval;

  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClReadHelper: invalid fd\n");
  } 
  return ((-1 == (retval = lind_read(fd, len, buf, cageid)))
          ? -NaClXlateErrno(errno) : retval);
}

ssize_t NaClWriteHelper(int                  fd,
                        int                  cageid,
                        void const          *buf,
                        size_t              len) {
  ssize_t retval;

  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClWriteHelper: invalid fd\n");
  } 
  return ((-1 == (retval = lind_write(fd, len, buf, cageid)))
          ? -NaClXlateErrno(errno) : retval);
}

nacl_off64_t NaClSeekHelper(int                  fd,
                            int                  cageid,
                            nacl_off64_t         offset,
                            int                  whence) {
  nacl_off64_t retval;

  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClSeekHelper: invalid fd\n");
  } 
  
  return ((-1 == (retval = lind_lseek(offset, fd, whence, cageid)))
          ? -NaClXlateErrno(errno) : retval);

}

ssize_t NaClHostDescPRead(int                  fd,
                          int                  cageid,
                          void                *buf,
                          size_t               len,
                          nacl_off64_t         offset) {
  ssize_t retval;

  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClSeekHelper: invalid fd\n");
  } 
  return ((-1 == (retval = lind_pread(fd, buf, len, offset, cageid)))
          ? -NaClXlateErrno(errno) : retval);
}

ssize_t NaClPWriteHelper(int                  fd,
                        int                   cageid,
                        void const            *buf,
                        size_t                len,
                        nacl_off64_t          offset) {
  ssize_t retval;
  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClPWriteHelper: invalid fd\n");
  } 

  return ((-1 == (retval = lind_pwrite(fd, buf, len, offset, cageid)))
          ? -NaClXlateErrno(errno) : retval);
}


/*
 * See NaClHostDescStat below.
 */
int NaClFstatHelper(int                  fd,
                    int                  cageid,
                    nacl_host_stat_t     *nhsp) {
  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClFstatHelper: invalid fd\n");
  } 

  if (lind_fxstat(fd, 1, nhsp, cageid) == -1) {
    return -errno;
  }


  return 0;
}

int NaClCloseHelper(int                  fd,
                      int                  cageid) {
  int retval;

  if (fd < 0) {
    NaClLog(LOG_FATAL, "NaClCloseHelper: invalid fd\n");
  }   retval = lind_close(fd, cageid);

  return (-1 == retval) ? -NaClXlateErrno(errno) : retval;
}

/*
 * This is not a host descriptor function, but is closely related to
 * fstat and should behave similarly.
 */
int NaClStatHelper(char const       *host_os_pathname,
                    nacl_host_stat_t *nhsp,
		                int cageid) {

  if (lind_xstat(1, host_os_pathname, nhsp, cageid) == -1) {
    return -errno;
  }

  return 0;
}
