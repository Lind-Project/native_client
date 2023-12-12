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
void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, size_t ret, ssize_t getdents_ret, uintptr_t sysaddr) {
    fprintf(tracingOutputFile, "%d getdents(%d, %p, %zu) = %zu, Getdents Ret: %zd, Sysaddr: %p\n", cageid, d, drip, count, ret, getdents_ret, (void *)sysaddr);
}

void NaClStracePread(int cageid, int d, void *buf, int count,  size_t log_bytes){
    fprintf(tracingOutputFile, "%d pread(%d, %p, %d, %zu)\n", cageid, d, buf, count, log_bytes);
}


void NaClStraceWrite(int cageid, int d, void *buf, int count) {
    fprintf(tracingOutputFile, "%d write(%d, %p, %d)\n", cageid, d, buf, count);
}

void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset) {
    fprintf(tracingOutputFile, "%d pwrite(%d, %p, %d, %jd)\n", cageid, d, buf, count, (intmax_t)offset);
}

void NaClStraceLseek(int cageid, int d, int whence, uintptr_t offset, size_t ret) {
    fprintf(tracingOutputFile, "%d lseek(%d, %d, 0x%08"NACL_PRIxPTR") = %zu\n", cageid, d, whence, offset, ret);

}
void NaClStraceIoctl(int cageid, int d, unsigned long request, size_t ret){
    fprintf(tracingOutputFile, "%d ioctl(%d, %lu) = %zu\n", cageid, d, request, ret);

}
void NaClStraceFstat(int cageid, int d, size_t retval){
    fprintf(tracingOutputFile, "%d fstat(%d) = %zu\n", cageid, d, retval);
}
void NaClStraceStat(int cageid, char* path, size_t retval){
    fprintf(tracingOutputFile, "%d stat(%s) = %zu\n", cageid, path, retval);

}
void NaClStraceMkdir(int cageid, char* path, int mode,size_t retval){
    fprintf(tracingOutputFile, "%d mkdir(%s, %d) = %zu\n", cageid, path, mode, retval);

}
void NaClStraceRmdir(int cageid, const char *path, int32_t retval) {
    fprintf(tracingOutputFile, "%d rmdir(%s) = %d\n", cageid, path, retval);
}
void NaClStraceChdir(int cageid, const char *path, int32_t retval) {
    fprintf(tracingOutputFile, "%d chdir(%s) = %d\n", cageid, path, retval);
}
void NaClStraceChmod(int cageid, const char *path, int mode, int32_t retval) {
    fprintf(tracingOutputFile, "%d chmod(%s, %d) = %d\n", cageid, path, mode, retval);
}
void NaClStraceFchmod(int cageid, int fd,int mode,int retval){
    fprintf(tracingOutputFile, "%d fchmod(%d, %d) = %d\n", cageid, fd, mode, retval);

}
void NaClStraceFchdir(int cageid, int fd){
    fprintf(tracingOutputFile, "%d fchdir(%d) =\n", cageid, fd);
}
void NaClStraceGetcwd(int cageid, char *buf, size_t size, uintptr_t sysaddr, int32_t retval) {
    fprintf(tracingOutputFile, "%d getcwd(%p, %zu) = %d, Sysaddr: %p\n", cageid, (void *)buf, size, retval, (void *)sysaddr);
}


void NaClStraceLink(int cageid, char* from,char* to){
    fprintf(tracingOutputFile, "%d link(%s, %s) = void\n", cageid, from, to);

}
void NaClStraceUnlink(int cageid, char* pathname,int32_t retval){
    fprintf(tracingOutputFile, "%d unlink(%s) = %d\n", cageid, pathname, retval);

}

void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int32_t retval) {
    fprintf(tracingOutputFile, "%d rename(oldpath: \"%s\", newpath: \"%s\") = %d\n", cageid, oldpath, newpath, retval);
}
void NaClStraceMmap(int cageid, void *start,size_t length,int prot,int flags,int d,int32_t retval){
    fprintf(tracingOutputFile, "%d mmap(%p, %zu, %d, %d, %d) = %d\n", cageid, start, length, prot, flags, d, retval);

}
void NaClStraceMunmap(int cageid, void *start, size_t length, int32_t retval, uintptr_t sysaddr, size_t alloc_rounded_length){
   fprintf(tracingOutputFile, "%d munmap(%p, %zu) = %d, Sysaddr: %p, alloc_rounded_ength: %zu\n", cageid, start, length, retval, (void*)sysaddr, alloc_rounded_length);

}
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
    fprintf(tracingOutputFile, "%d SocketPair(domain=%d, type=%d, protocol=%d, fds=%p, lindfds=%p, retval=%d)\n", cageid, domain, type, protocol, (void *)fds, (void *)lindfds, retval);
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
void NaClStraceCondTimedWaitAbs(int cageid, int32_t cond_handle,int32_t mutex_handle,int32_t retval){
    fprintf(tracingOutputFile, "%d cond_timedwaitabs(%d, %d) = %d\n", cageid, cond_handle, mutex_handle, retval);
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
