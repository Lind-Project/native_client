/*
 * Tracing functionalities will be enabled when OS environment TRACING_ENABLED = 1 
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/poll.h>
#include "native_client/src/trusted/service_runtime/nacl_syscall_strace.h"

FILE *tracingOutputFile = NULL;

void NaClStraceSetOutputFile(char *path) {
    if (path == NULL || strlen(path) == 0) {
        // if the path is NULL, always revert to stderr
        tracingOutputFile = stderr;
        return;
    }

    FILE *newFile = fopen(path, "w");
    if (newFile == NULL) {
        perror("Error opening the tracing output file. Now output to stderr");
        tracingOutputFile = stderr;
    } else {
        if (tracingOutputFile != stderr && tracingOutputFile != NULL) {
            fclose(tracingOutputFile);
        }
        tracingOutputFile = newFile;
        // setbuf(tracingOutputFile, NULL);
    }
}

void NaClStraceCloseFile() {
    if (tracingOutputFile != NULL && tracingOutputFile != stderr) {
        if (fclose(tracingOutputFile) != 0) perror("Error closing file");
    }
}

void NaClStraceGetpid(int cageid, int pid) {
    fprintf(tracingOutputFile, "%d getpid() = %d\n", cageid, pid);
}

void NaClStraceGetppid(int cageid, int pid) {
    fprintf(tracingOutputFile, "%d getppid() = %d\n", cageid, pid);
}

void NaClStraceOpen(int cageid, char* path, int flags, int mode, int fd) {
    fprintf(tracingOutputFile, "%d open(%s, %d, %d) = %d\n", cageid, path, flags, mode, fd);
}

void NaClStraceClose(int cageid, int d, int ret) {
    fprintf(tracingOutputFile, "%d close(%d) = %d\n", cageid, d, ret);
}

void NaClStraceRead(int cageid, int d, void *buf, size_t count, int ret) {
    fprintf(tracingOutputFile, "%d read(%d, %p, %zu) = %d\n", cageid, d, buf, count, ret);
}
void NaClStraceExit(int cageid, int status){
    fprintf(tracingOutputFile, "%d exit() = %d\n", cageid, status);

}
void NaClStraceThreadExit(int cageid, int32_t *stack_flag, uint32_t zero){
    fprintf(tracingOutputFile, "%d thread_exit(%d, %u) = void\n", cageid, stack_flag ? *stack_flag : 0, zero);
}

void NaClStraceDup(int cageid, int oldfd,int ret){
    fprintf(tracingOutputFile, "%d dup(%d) = %d\n", cageid, oldfd, ret);

}
void NaClStraceDup2(int cageid, int oldfd,int newfd,int ret){
    fprintf(tracingOutputFile, "%d dup2(%d, %d) = %d\n", cageid, oldfd, newfd, ret);

}
void NaClStraceDup3(int cageid, int oldfd,int newfd,int flags,int ret){
    fprintf(tracingOutputFile, "%d dup3(%d, %d, %d) = %d\n", cageid, oldfd, newfd, flags, ret);

}
void NaClStraceGetdents(int cageid, int d, void *dirp, size_t count, size_t retval, ssize_t getdents_ret, uintptr_t sysaddr) {
    fprintf(tracingOutputFile, "%d getdents(%d, %p, %zu, %zu, %zd, %zu) = void\n", 
            cageid, d, dirp, count, retval, getdents_ret, sysaddr);
}


void NaClStracePread(int cageid, int d, void *buf, size_t count, off_t offset, int32_t retval) {
    fprintf(tracingOutputFile, "%d pread(%d, %p, %zu, %lld) = %d\n", cageid, d, buf, count, (long long)offset, retval);
}


void NaClStraceWrite(int cageid, int d, void *buf, size_t count, int32_t ret) {
    fprintf(tracingOutputFile, "%d write(%d, %p, %zu) = %d\n", cageid, d, buf, count, ret);
}

void NaClStracePWrite(int cageid, int d, const void *buf, size_t count, off_t offset, int32_t retval) {
    fprintf(tracingOutputFile, "%d pwrite(%d, %p, %zu, %lld) = %d\n", cageid, d, buf, count, (long long)offset, retval);
}


void NaClStraceLseek(int cageid, int d, int whence, uintptr_t offset, int32_t ret) {
    fprintf(tracingOutputFile, "%d lseek(%d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, d, whence, offset, ret);
}

void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret) {
    fprintf(tracingOutputFile, "%d ioctl(%d, %lu, %p) = %d\n", cageid, d, request, arg_ptr, ret);

}

void NaClStraceFstat(int cageid, int d, uintptr_t result, int retval) {
    fprintf(tracingOutputFile, "%d fstat(%d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, d, result, retval);
}

void NaClStraceStat(int cageid, char* path, uintptr_t result, int32_t retval) {
    fprintf(tracingOutputFile, "%d stat(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, result, retval);
}


void NaClStraceLStat(int cageid, char* path, uintptr_t result, int32_t retval) {
    fprintf(tracingOutputFile, "%d lstat(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, result, retval);
}

void NaClStraceMkdir(int cageid, char* path, int mode, int32_t retval) {
    fprintf(tracingOutputFile, "%d mkdir(%s, %d) = %d\n", cageid, path, mode, retval);
}


void NaClStraceRmdir(int cageid, uint32_t pathname, const char* path, int32_t retval) {
    fprintf(tracingOutputFile, "%d rmdir(%u, %s) = %d\n", cageid, pathname, path, retval);
}
void NaClStraceChdir(int cageid, uint32_t pathname, const char* path, int32_t retval) {
    fprintf(tracingOutputFile, "%d chdir(%u, %s) = %d\n", cageid, pathname, path, retval);
}


void NaClStraceChmod(int cageid, const char *path, int mode, int32_t retval) {
    fprintf(tracingOutputFile, "%d chmod(%s, %d) = %d\n", cageid, path, mode, retval);
}

void NaClStraceFchmod(int cageid, int fd,int mode,int retval) {
    fprintf(tracingOutputFile, "%d fchmod(%d, %d) = %d\n", cageid, fd, mode, retval);

}

void NaClStraceFchdir(int cageid, int fd, int retval) {
    fprintf(tracingOutputFile, "%d fchdir(%d) = %d\n", cageid, fd, retval);
}

void NaClStraceFsync(int cageid, int fd, int ret) {
    fprintf(tracingOutputFile, "%d fsync(%d) = %d\n", cageid, fd, ret);
}

void NaClStraceFdatasync(int cageid, int fd, int ret) {
    fprintf(tracingOutputFile, "%d fdatasync(%d) = %d\n", cageid, fd, ret);
}
void NaClStraceGetcwd(int cageid, char* buf, size_t size, uintptr_t sysaddr, int32_t retval) {
    fprintf(tracingOutputFile, "%d getcwd(%p, %zu, 0x%08"NACL_PRIxPTR") = %d\n",cageid, buf, size, sysaddr, retval);
}


void NaClStraceLink(int cageid, char* from,char* to) {
    fprintf(tracingOutputFile, "%d link(%s, %s) = void\n", cageid, from, to);

}
void NaClStraceUnlink(int cageid, char* pathname,int32_t retval){
    fprintf(tracingOutputFile, "%d unlink(%s) = %d\n", cageid, pathname, retval);

}

void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int32_t retval) {
    fprintf(tracingOutputFile, "%d rename(oldpath: \"%s\", newpath: \"%s\") = %d\n", cageid, oldpath, newpath, retval);
}
void NaClStraceMmap(int cageid, void *start,size_t length,int prot,int flags,int d, uintptr_t offset, int32_t retval) {
    fprintf(tracingOutputFile, "%d mmap(%p, %zu, %d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, start, length, prot, flags, d, offset, retval);

}
// void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length,int32_t retval) {
//    fprintf(tracingOutputFile, "%d munmap(0x%08"NACL_PRIxPTR", %zu) = %d\n", cageid, sysaddr, length, retval);

// }

void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval) {
    fprintf(tracingOutputFile, "%d shmat(%d, %p, %d) = %d\n", cageid, shmid, shmaddr, shmflg, retval);
}
void NaClStraceShmget(int cageid, int key, size_t size, int shmflg, int retval) {
    fprintf(tracingOutputFile, "%d shmget(%d, %zu, %d) = %d\n", cageid, key, size, shmflg, retval);
}
void NaClStraceShmdt(int cageid, void *shmaddr, int retval) {
    fprintf(tracingOutputFile, "%d shmdt(%p) = %d\n", cageid, shmaddr, retval);
}

void NaClStraceShmctl(int cageid, int shmid, int cmd, int32_t retval) {
    fprintf(tracingOutputFile, "%d shmctl(%d, %d) = %d\n", cageid, shmid, cmd, retval);

}
void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *fds, int *lindfds, int32_t retval) {
    fprintf(tracingOutputFile, "%d SocketPair(%d, %d, %d, %p, %p) = %d\n", cageid, domain, type, protocol, (void *)fds, (void *)lindfds, retval);
}

void NaClStraceTlsInit(int cageid, uint32_t thread_ptr,int32_t retval,uintptr_t sys_tls){
    fprintf(tracingOutputFile, "%d tls_init(%u, %lu) = %d\n", cageid, thread_ptr, sys_tls, retval);
}

void NaClStraceSecondTlsSet(int cageid, uint32_t new_value) {
    fprintf(tracingOutputFile, "%d SecondTlsSet(new_value=%u)\n", cageid, new_value);
}
void NaClStraceMutexCreate(int cageid, int32_t retval){
    fprintf(tracingOutputFile, "%d mutex_create() = %d\n", cageid, retval);

}
void NaClStraceMutexLock(int cageid, int32_t mutex_handle, int32_t retval) {
    fprintf(tracingOutputFile, "%d mutex_lock(%d) = %d\n", cageid, mutex_handle, retval);

}
void NaClStraceMutexUnLock(int cageid, int32_t mutex_handle, int32_t retval) {
    fprintf(tracingOutputFile, "%d mutex_unlock(%d) = %d\n", cageid, mutex_handle, retval);
}
void NaClStraceMutexTrylock(int cageid, int32_t mutex_handle, int32_t retval){
    fprintf(tracingOutputFile, "%d mutex_trylock(%d) = %d\n", cageid, mutex_handle, retval);
}
void NaClStraceMutexDestroy(int cageid, int32_t mutex_handle,int32_t retval){
    fprintf(tracingOutputFile, "%d mutex_destroy(%d) = %d\n", cageid, mutex_handle, retval);
}
void NaClStraceCondCreate(int cageid, int32_t retval){
    fprintf(tracingOutputFile, "%d cond_create() = %d\n", cageid, retval);
}
void NaClStraceCondWait(int cageid, int32_t cond_handle,int32_t mutex_handle,int32_t retval){
    fprintf(tracingOutputFile, "%d cond_wait(%d, %d) = %d\n", cageid, cond_handle, mutex_handle, retval);
}
void NaClStraceCondSignal(int cageid, int32_t cond_handle,int32_t retval){
    fprintf(tracingOutputFile, "%d cond_signal(%d) = %d\n", cageid, cond_handle, retval);
}
void NaClStraceCondBroadcast(int cageid, int32_t cond_handle, int32_t retval) {
    fprintf(tracingOutputFile, "%d CondBroadcast(cond_handle=%d, retval=%d)\n", cageid, cond_handle, retval);
}
void NaClStraceCondDestroy(int cageid, int32_t cond_handle,int32_t retval){
    fprintf(tracingOutputFile, "%d cond_destroy(%d) = %d\n", cageid, cond_handle, retval);
}
void NaClStraceCondTimedWaitAbs(int cageid, int32_t cond_handle,int32_t mutex_handle, uintptr_t trusted_ts, int32_t retval){
    fprintf(tracingOutputFile, "%d cond_timedwaitabs(%d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, cond_handle, mutex_handle, trusted_ts, retval);
}   
void NaClStraceSemCreate(int cageid, int32_t init_value, int32_t retval) {
    fprintf(tracingOutputFile, "%d sem_create(%d) = %d\n", cageid, init_value, retval);

}

void NaClStraceSecondTlsGet(int cageid, uintptr_t natp) {
    // this is not used in x86 anyway
    fprintf(tracingOutputFile, "%d SecondTlsGet(some natp)\n", cageid);
}

void NaClStraceSemWait(int cageid, int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "%d semwait(%d) = %d\n", cageid, sem_handle, ret);
}

void NaClStraceSemTryWait(int cageid, int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "%d semwait(%d) = %d\n", cageid, sem_handle, ret);
}

void NaClStraceSemInit(int cageid, int32_t sem, int32_t pshared, int32_t value, int ret) {
    fprintf(tracingOutputFile, "%d seminit(%d, %d, %d) = %d\n", cageid, sem, pshared, value, ret);
}

void NaClStraceSemDestroy(int cageid, int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "%d semdestroy(%d) = %d\n", cageid, sem_handle, ret);
}

void NaClStraceSemTimedWait(int cageid, uint32_t sem, uintptr_t trusted_abs, int ret) {
    fprintf(tracingOutputFile, "%d semTimedWait(%d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, sem, trusted_abs, ret);    
}

void NaClStraceSemPost(int cageid, int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "%d sempost(%d) = %d\n", cageid, sem_handle, ret);
}

void NaClStraceSemGetValue(int cageid, int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "%d semgetvalue(%d) = %d\n", cageid, sem_handle, ret);
}

void NaClStraceNanosleep(int cageid, uintptr_t req, uintptr_t rem, int ret) {
    fprintf(tracingOutputFile, "%d nanosleep(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", cageid, req, rem, ret);
}

void NaClStraceSchedYield(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d schedyield() = %d\n", cageid, ret);
}

void NaClStraceExceptionHandler(int cageid, uint32_t             handler_addr,
                                uint32_t             old_handler, int ret) {
                                    fprintf(tracingOutputFile, "%d exceptionhandler(%u, %u) = %d\n", cageid, handler_addr, old_handler, ret);
                                }

void NaClStraceExceptionStack(int cageid, uint32_t stack_addr, uint32_t stack_size, int ret) {
    fprintf(tracingOutputFile, "%d exceptionstack(%u, %u) = %d\n", cageid, stack_addr, stack_size, ret);
}

void NaClStraceExceptionClearFlag(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d exceptionclearflag() = %d\n", cageid, ret);
}

void NaClStraceTestInfoLeak(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d testinfoleak() = %d\n", cageid, ret);
}

void NaClStraceTestCrash(int cageid, int crash_type, int ret) {
    fprintf(tracingOutputFile, "%d testcrash(%d) = %d\n", cageid, crash_type, ret);
}

void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret) {
    fprintf(tracingOutputFile, "%d gettimeofday(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, tv, tz, ret);
}

void NaClStraceClockGetCommon(int cageid, int                   clk_id,
                              uint32_t              ts_addr,
                              uintptr_t            *time_func, 
                              int ret) {
                                fprintf(tracingOutputFile, "%d clockgetcommon(%d, %u, 0x%08"NACL_PRIxPTR") = %d\n",
                                 cageid, clk_id, ts_addr, time_func, ret
                                );
                              }

void NaClStracePipe2(int cageid, uint32_t *pipedes, int flags, int ret) {
    fprintf(tracingOutputFile, "%d pipe2(0x%08"NACL_PRIxPTR", %d) = %d\n",
     cageid, (uintptr_t) pipedes, flags, ret
    );
}

void NaClStraceFork(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d fork() = %d\n",
     cageid, ret
    );
}

void NaClStraceExecve(int cageid, char const *path, char *const *argv, char *const *envp, int ret) {
    fprintf(tracingOutputFile, "%d execve(%s, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n",
     cageid, path, (uintptr_t)argv, (uintptr_t)envp, ret
    );
}

void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret) {
    fprintf(tracingOutputFile, "%d execv(%s, 0x%08"NACL_PRIxPTR") = %d\n",
     cageid, path, (uintptr_t) argv, ret
    );
}

void NaClStraceWaitpid(int cageid, int pid, uint32_t *stat_loc, int options, int ret) {
    fprintf(tracingOutputFile, "%d waitpid(%d, %d, %d) = %d\n",
     cageid, pid, *stat_loc, options, ret
    );
}

void NaClStraceGethostname(int cageid, char *name, size_t len, int ret) {
    fprintf(tracingOutputFile, "%d gethostname(%s, %lu) = %d\n",
     cageid, name, len, ret
    );
}

void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret) {
    fprintf(tracingOutputFile, "%d getifaddrs(%s, %lu) = %d\n",
     cageid, buf, len, ret
    );
}

void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret) {
    fprintf(tracingOutputFile, "%d socket(%d, %d, %d) = %d\n",
     cageid, domain, type, protocol, ret
    );
}

void NaClStraceSend(int cageid, int sockfd, size_t len, int flags, const void *buf, int ret) {
    fprintf(tracingOutputFile, "%d send(%d, %ld, %d, 0x%08"NACL_PRIxPTR") = %d\n",
     cageid, sockfd, len, flags, (uintptr_t) buf, ret
    );
}

void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len,
    int flags, uintptr_t dest_addr, socklen_t addrlen, int ret) {
        fprintf(tracingOutputFile, "%d sendto(%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d) = %d\n",
         cageid, sockfd, (uintptr_t) buf, len, flags, dest_addr, addrlen, ret
        );
    }

void NaClStraceRecv(int cageid, int sockfd, size_t len, int flags, void *buf, int ret) {
    fprintf(tracingOutputFile, "%d recv(%d, %ld, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, len, flags, (uintptr_t)buf, ret);
}

void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags,
    uintptr_t src_addr, socklen_t *addrlen, int ret) {
        fprintf(tracingOutputFile, "%d recvfrom(%d, %p"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, buf, len, flags, src_addr,
            (uintptr_t)addrlen, ret);
    }

void NaClStraceShutdown(int cageid, int sockfd, int how, int ret) {
    fprintf(tracingOutputFile, "%d shutdown(%d, %d) = %d\n", cageid, sockfd, how, ret);
}

void NaClStraceGetuid(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d getuid() = %d\n", cageid, ret);
}

void NaClStraceGeteuid(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d geteuid() = %d\n", cageid, ret);
}

void NaClStraceGetgid(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d getgid() = %d\n", cageid, ret);
}

void NaClStraceGetegid(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d getegid() = %d\n", cageid, ret);
}

void NaClStraceFlock(int cageid, int fd, int operation, int ret) {
    fprintf(tracingOutputFile, "%d flock(%d, %d) = %d\n", cageid, fd, operation, ret);
}

void NaClStraceGetsockopt(int cageid, int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret) {
    fprintf(tracingOutputFile, "%d getsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, level, optname, (uintptr_t)optval, (uintptr_t)optlen, ret);
}

void NaClStraceSetsockopt(int cageid, int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret) {
    fprintf(tracingOutputFile, "%d setsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", %u) = %d\n", cageid, sockfd, level, optname, (uintptr_t)optval, optlen, ret);
}

void NaClStraceFstatfs(int cageid, int d, uintptr_t buf, int ret) {
    fprintf(tracingOutputFile, "%d fstatfs(%d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, d, buf, ret);
}

void NaClStraceStatfs(int cageid, const char *pathname, uintptr_t buf, int ret) {
    fprintf(tracingOutputFile, "%d statfs(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, pathname, buf, ret);
}

void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    fprintf(tracingOutputFile, "%d getsockname(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    fprintf(tracingOutputFile, "%d getpeername(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceAccess(int cageid, char *path, int mode, int ret) {
    fprintf(tracingOutputFile, "%d access(%s, %d) = %d\n", cageid, path, mode, ret);
}

void NaClStraceTruncate(int cageid, uint32_t path, int length, int ret) {
    fprintf(tracingOutputFile, "%d truncate(%u, %d) = %d\n", cageid, path, length, ret);
}

void NaClStraceFtruncate(int cageid, int fd, int length, int ret) {
    fprintf(tracingOutputFile, "%d ftruncate(%d, %d) = %d\n", cageid, fd, length, ret);
}

void NaClStraceConnect(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    fprintf(tracingOutputFile, "%d connect(%d, 0x%08"NACL_PRIxPTR", %u) = %d\n", cageid, sockfd, addr, addrlen, ret);
}

void NaClStraceAccept(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret) {
    fprintf(tracingOutputFile, "%d accept(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceBind(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    fprintf(tracingOutputFile, "%d bind(%d, 0x%08"NACL_PRIxPTR", %u) = %d\n", cageid, sockfd, addr, addrlen, ret);
}

void NaClStraceListen(int cageid, int sockfd, int backlog, int ret) {
    fprintf(tracingOutputFile, "%d listen(%d, %d) = %d\n", cageid, sockfd, backlog, ret);
}

void NaClStraceFcntlGet(int cageid, int fd, int cmd, int ret) {
    fprintf(tracingOutputFile, "%d fcntlget(%d, %d) = %d\n", cageid, fd, cmd, ret);
}

void NaClStraceFcntlSet(int cageid, int fd, int cmd, long set_op, int ret) {
    fprintf(tracingOutputFile, "%d fcntlset(%d, %d, %ld) = %d\n", cageid, fd, cmd, set_op, ret);
}

void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int ret) {
    fprintf(tracingOutputFile, "%d poll(0x%08"NACL_PRIxPTR", %d, %d) = %d\n", cageid, fds, nfds, timeout, ret);
}

void NaClStraceEpollCreate(int cageid, int size, int ret) {
    fprintf(tracingOutputFile, "%d epollcreate(%d) = %d\n", cageid, size, ret);
}

void NaClStraceEpollCtl(int cageid, int epfd, int op, int fd, uintptr_t event, int ret) {
    fprintf(tracingOutputFile, "%d epollctl(%d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, epfd, op, fd, event, ret);
}

void NaClStraceEpollWait(int cageid, int epfd, uintptr_t events,int maxevents, int timeout, int ret) {
    fprintf(tracingOutputFile, "%d epollwait(%d, 0x%08"NACL_PRIxPTR", %d, %d) = %d\n", cageid, epfd, events, maxevents, timeout, ret);
}

void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, 
                                uintptr_t exceptfds, uintptr_t timeout, int ret) {
    fprintf(tracingOutputFile, "%d select(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, nfds, readfds, writefds, exceptfds, timeout, ret);
                       }
void NaClStraceThreadCreate(int cageid, void *prog_ctr, uint32_t stack_ptr, uint32_t thread_ptr, uint32_t second_thread_ptr, int32_t retval) {
    fprintf(tracingOutputFile, "%d ThreadCreate(pc=0x%08"NACL_PRIxPTR", sp=0x%08"NACL_PRIx32", thread_ptr=0x%08"NACL_PRIx32", second_thread_ptr=0x%08"NACL_PRIx32") = %d\n", 
            cageid, (uintptr_t)prog_ctr, stack_ptr, thread_ptr, second_thread_ptr, retval);
}
void NaClStraceThreadNice(int cageid, int nice, int retval) {
    fprintf(tracingOutputFile, "%d ThreadNice(nice=%d) = %d\n", cageid, nice, retval);
}

void NaClStraceNameService(int cageid, int32_t *desc_addr, int32_t retval) {
    fprintf(tracingOutputFile, "%d NameService(desc_addr=%p) = %d\n", 
            cageid, desc_addr, retval);
}
void NaClStraceCommonAddrRangeContainsExecutablePages(int cageid, uintptr_t usraddr, size_t length) {
    fprintf(tracingOutputFile, "%d CommonAddrRangeContainsExecutablePages(usraddr=0x%08"NACL_PRIxPTR", length=%zu)\n", cageid, usraddr, length);
}
void NaClStraceCommonAddrRangeInAllowedDynamicCodeSpace(int cageid, uintptr_t usraddr, size_t length) {
    fprintf(tracingOutputFile, "%d CommonAddrRangeInAllowedDynamicCodeSpace(usraddr=0x%08"NACL_PRIxPTR", length=%zu)\n", cageid, usraddr, length);
}
void NaClStraceMmapIntern(int cageid, void *start, size_t length, int prot, int flags, int d, nacl_abi_off_t offset, int32_t retval) {
    fprintf(tracingOutputFile, "%d MmapIntern(start=%p, length=%zu, prot=%d, flags=%d, d=%d, offset=%lld) = %d\n", 
            cageid, start, length, prot, flags, d, (long long)offset, retval);
}
