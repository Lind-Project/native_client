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
    }
}

void NaClStraceGetpid(int pid) {
    fprintf(tracingOutputFile, "getpid() = %d\n", pid);
}

void NaClStraceOpen(char* path, int flags, int mode, int fd) {
    fprintf(tracingOutputFile, "open(%s, %d, %d) = %d\n", path, flags, mode, fd);
}

void NaClStraceClose(int d, int ret) {
    fprintf(tracingOutputFile, "close(%d) = %d\n", d, ret);
}

void NaClStraceRead(int d, void *buf, size_t count, int ret) {
    fprintf(tracingOutputFile, "read(%d, %p, %zu) = %d\n", d, buf, count, ret);
}
void NaClStraceExit(int status){
    fprintf(tracingOutputFile, "exit() = %d\n", status);

}
void NaClStraceThreadExit(int32_t *stack_flag, uint32_t zero){
    fprintf(tracingOutputFile, "thread_exit(%d, %u) = void\n", stack_flag ? *stack_flag : 0, zero);
}

void NaClStraceDup(int oldfd,int ret){
    fprintf(tracingOutputFile, "dup(%d) = %d\n", oldfd, ret);

}
void NaClStraceDup2(int oldfd,int newfd,int ret){
    fprintf(tracingOutputFile, "dup2(%d, %d) = %d\n", oldfd, newfd, ret);

}
void NaClStraceDup3(int oldfd,int newfd,int flags,int ret){
    fprintf(tracingOutputFile, "dup3(%d, %d, %d) = %d\n", oldfd, newfd, flags, ret);

}
void NaClStraceGetdents(int d, void *drip, size_t count, size_t ret, ssize_t getdents_ret, uintptr_t sysaddr) {
    fprintf(tracingOutputFile, "getdents(%d, %p, %zu) = %zu, Getdents Ret: %zd, Sysaddr: %p\n", d, drip, count, ret, getdents_ret, (void *)sysaddr);
}

void NaClStracePread(int d, void *buf, int count,  size_t log_bytes){
    fprintf(tracingOutputFile, "pread(%d, %p, %d, %zu)\n", d, buf, count, log_bytes);
}


void NaClStraceWrite(int d, void *buf, int count) {
    fprintf(tracingOutputFile, "write(%d, %p, %d)\n", d, buf, count);
}

void NaClStracePWrite(int d, const void *buf, int count, off_t offset) {
    fprintf(tracingOutputFile, "pwrite(%d, %p, %d, %jd)\n", d, buf, count, (intmax_t)offset);
}

void NaClStraceIoctl(int d, unsigned long request, size_t ret){
    fprintf(tracingOutputFile, "ioctl(%d, %lu) = %zu\n", d, request, ret);

}
void NaClStraceFstat(int d, size_t retval){
    fprintf(tracingOutputFile, "fstat(%d) = %zu\n", d, retval);
}
void NaClStraceStat(char* path, size_t retval){
    fprintf(tracingOutputFile, "stat(%s) = %zu\n", path, retval);

}
void NaClStraceMkdir(char* path, int mode,size_t retval){
    fprintf(tracingOutputFile, "mkdir(%s, %d) = %zu\n", path, mode, retval);

}
void NaClStraceRmdir(const char *path, int32_t retval) {
    fprintf(tracingOutputFile, "rmdir(%s) = %d\n", path, retval);
}
void NaClStraceChdir(const char *path, int32_t retval) {
    fprintf(tracingOutputFile, "chdir(%s) = %d\n", path, retval);
}
void NaClStraceChmod(const char *path, int mode, int32_t retval) {
    fprintf(tracingOutputFile, "chmod(%s, %d) = %d\n", path, mode, retval);
}
void NaClStraceFchmod(int fd,int mode,int retval){
    fprintf(tracingOutputFile, "fchmod(%d, %d) = %d\n", fd, mode, retval);

}
void NaClStraceFchdir(int fd){
    fprintf(tracingOutputFile, "fchdir(%d) =\n", fd);
}
void NaClStraceGetcwd(char *buf, size_t size, uintptr_t sysaddr, int32_t retval) {
    fprintf(tracingOutputFile, "getcwd(%p, %zu) = %d, Sysaddr: %p\n", (void *)buf, size, retval, (void *)sysaddr);
}


void NaClStraceLink(char* from,char* to){
    fprintf(tracingOutputFile, "link(%s, %s) = void\n", from, to);

}
void NaClStraceUnlink(char* pathname,int32_t retval){
    fprintf(tracingOutputFile, "unlink(%s) = %d\n", pathname, retval);

}

void NaClStraceRename(const char *oldpath, const char *newpath, int32_t retval) {
    fprintf(tracingOutputFile, "rename(oldpath: \"%s\", newpath: \"%s\") = %d\n", oldpath, newpath, retval);
}
void NaClStraceMmap(void *start,size_t length,int prot,int flags,int d,int32_t retval){
    fprintf(tracingOutputFile, "mmap(%p, %zu, %d, %d, %d) = %d\n", start, length, prot, flags, d, retval);

}
void NaClStraceMunmap(void *start, size_t length, int32_t retval, uintptr_t sysaddr, size_t alloc_rounded_length){
   fprintf(tracingOutputFile, "munmap(%p, %zu) = %d, Sysaddr: %p, alloc_rounded_ength: %zu\n", start, length, retval, (void*)sysaddr, alloc_rounded_length);

}
void NaClStraceShmat(int shmid, void *shmaddr, int shmflg) {
    fprintf(tracingOutputFile, "shmat(%d, %p, %d) \n", shmid, shmaddr, shmflg);
}

void NaClSysBrkTrace(uintptr_t new_break, int32_t retval) {
    fprintf(tracingOutputFile, "brktrace: NaClSysBrk(new_break: %p, retval: %d)\n", (void*)new_break, retval);
}

void NaClStraceShmget(int key, size_t size, int shmflg, int retval) {
    fprintf(tracingOutputFile, "shmget(%d, %zu, %d) = %d\n", key, size, shmflg, retval);
}
void NaClStraceShmdt(void *shmaddr, int retval) {
    fprintf(tracingOutputFile, "shmdt(%p) = %d\n", shmaddr, retval);
}

void NaClStraceShmctl(int shmid, int cmd, int32_t retval) {
    fprintf(tracingOutputFile, "shmctl(%d, %d) = %d\n", shmid, cmd, retval);

}
void NaClStraceSocketPair(int domain, int type, int protocol, int *fds, int *lindfds, int32_t retval) {
    fprintf(tracingOutputFile, "SocketPair(domain=%d, type=%d, protocol=%d, fds=%p, lindfds=%p, retval=%d)\n", domain, type, protocol, (void *)fds, (void *)lindfds, retval);
}

void NaClStraceTlsInit(uint32_t thread_ptr,int32_t retval,uintptr_t sys_tls){
    fprintf(tracingOutputFile, "tls_init(%u, %lu) = %d\n", thread_ptr, sys_tls, retval);
}

void NaClStraceSecondTlsSet(uint32_t new_value) {
    fprintf(tracingOutputFile, "SecondTlsSet(new_value=%u)\n", new_value);
}
void NaClStraceMutexCreate(int32_t retval){
    fprintf(tracingOutputFile, "mutex_create() = %d\n", retval);

}
void NaClStraceMutexLock(int32_t mutex_handle, int32_t retval) {
    fprintf(tracingOutputFile, "mutex_lock(%d) = %d\n", mutex_handle, retval);

}
void NaClStraceMutexUnLock(int32_t mutex_handle, int32_t retval) {
    fprintf(tracingOutputFile, "mutex_unlock(%d) = %d\n", mutex_handle, retval);
}
void NaClStraceMutexTrylock(int32_t mutex_handle, int32_t retval){
    fprintf(tracingOutputFile, "mutex_trylock(%d) = %d\n", mutex_handle, retval);
}
void NaClStraceMutexDestroy(int32_t mutex_handle,int32_t retval){
    fprintf(tracingOutputFile, "mutex_destroy(%d) = %d\n", mutex_handle, retval);
}
void NaClStraceCondCreate(int32_t retval){
    fprintf(tracingOutputFile, "cond_create() = %d\n", retval);
}
void NaClStraceCondWait(int32_t cond_handle,int32_t mutex_handle,int32_t retval){
    fprintf(tracingOutputFile, "cond_wait(%d, %d) = %d\n", cond_handle, mutex_handle, retval);
}
void NaClStraceCondSignal(int32_t cond_handle,int32_t retval){
    fprintf(tracingOutputFile, "cond_signal(%d) = %d\n", cond_handle, retval);
}
void NaClStraceCondBroadcast(int32_t cond_handle, int32_t retval) {
    fprintf(tracingOutputFile, "CondBroadcast(cond_handle=%d, retval=%d)\n", cond_handle, retval);
}
void NaClStraceCondDestroy(int32_t cond_handle,int32_t retval){
    fprintf(tracingOutputFile, "cond_destroy(%d) = %d\n", cond_handle, retval);
}
void NaClStraceCondTimedWaitAbs(int32_t cond_handle,int32_t mutex_handle,int32_t retval){
    fprintf(tracingOutputFile, "cond_timedwaitabs(%d, %d) = %d\n", cond_handle, mutex_handle, retval);
}   
void NaClStraceSemCreate(int32_t init_value, int32_t retval) {
    fprintf(tracingOutputFile, "sem_create(%d) = %d\n", init_value, retval);

}
void NaClStraceLStat(char* path, size_t retval){
    fprintf(tracingOutputFile, "stat(%s) = %zu\n", path, retval);

}

void NaClStraceLseek(int d, int whence) {
    fprintf(tracingOutputFile, "lseek(descriptor: %d, whence: %d)\n", d, whence);
}
void NaClStraceCommon(uintptr_t usraddr, size_t length) {
    fprintf(tracingOutputFile, "StraceCommon(usraddr: %p, length: %zu)\n", (void*)usraddr, length);
}
void NaClStraceCommonAddrRangeInAllowedDynamicCodeSpace(uintptr_t usraddr, size_t length) {
    fprintf(tracingOutputFile, "NaClStraceCommonAddrRangeInAllowedDynamicCodeSpace(usraddr: %p, length: %zu)\n", (void*)usraddr, length);
}
void NaClStraceTlsGet(int32_t retval) {
    printf("TlsGet(retval: %d)\n", retval);
}
void NaClStraceNameService(int32_t *desc_addr, int32_t retval) {
    printf("NameService(desc_addr: 0x%08"NACL_PRIxPTR", retval: %d)\n", 
           (uintptr_t)desc_addr, retval);
}
void NaClStraceNull(int32_t retval) {
    printf("TlsGet(retval: %d)\n", retval);
}
void NaClStraceNotImplementedDecoder(int32_t retval) {
    printf("TlsGet(retval: %d)\n", retval);
}

void NaClStraceSecondTlsGet(int32_t retval) {
    printf("SecondTlsGet(retval: %d)\n", retval);
}

void NaClStraceSemWait(int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "semwait(%d) = %d\n", sem_handle, ret);
}

void NaClStraceSemInit(int32_t sem, int32_t pshared, int32_t value, int ret) {
    fprintf(tracingOutputFile, "seminit(%d, %d, %d) = %d", sem, pshared, value, ret);
}

void NaClStraceSemDestroy(int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "semdestroy(%d) = %d\n", sem_handle, ret);
}

void NaClStraceSemPost(int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "sempost(%d) = %d\n",sem_handle, ret);
}

void NaClStraceSemGetValue(int32_t sem_handle, int ret) {
    fprintf(tracingOutputFile, "semgetvalue(%d) = %d\n", sem_handle, ret);
}

void NaClStraceNanosleep(uintptr_t req, uintptr_t rem, int ret) {
    fprintf(tracingOutputFile, "nanosleep(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d",req, rem, ret);
}

void NaClStraceSchedYield(int ret) {
    fprintf(tracingOutputFile, "schedyield() = %d\n", ret);
}

void NaClStraceExceptionHandler(uint32_t             handler_addr,
                                uint32_t             old_handler, int ret) {
                                    fprintf(tracingOutputFile, "exceptionhandler(%u, %u) = %d\n", handler_addr, old_handler, ret);
                                }

void NaClStraceExceptionStack(uint32_t stack_addr, uint32_t stack_size, int ret) {
    fprintf(tracingOutputFile, "exceptionstack(%u, %u) = %d\n", stack_addr, stack_size, ret);
}

void NaClStraceExceptionClearFlag(int ret) {
    fprintf(tracingOutputFile, "exceptionclearflag() = %d\n", ret);
}

void NaClStraceTestInfoLeak(int ret) {
    fprintf(tracingOutputFile, "testinfoleak() = %d\n",ret);
}

void NaClStraceTestCrash(int crash_type, int ret) {
    fprintf(tracingOutputFile, "testcrash(%d) = %d\n", crash_type, ret);
}

void NaClStraceGetTimeOfDay(uintptr_t tv, uintptr_t tz, int ret) {
    fprintf(tracingOutputFile, "gettimeofday(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", tv, tz, ret);
}

void NaClStraceClockGetCommon(int                   clk_id,
                              uint32_t              ts_addr,
                              uintptr_t            *time_func, 
                              int ret) {
                                fprintf(tracingOutputFile, "clockgetcommon(%d, %u, 0x%08"NACL_PRIxPTR") = %d\n",
                                clk_id, ts_addr, time_func, ret
                                );
                              }

void NaClStracePipe2(uint32_t *pipedes, int flags, int ret) {
    fprintf(tracingOutputFile, "pipe2(0x%08"NACL_PRIxPTR", %d) = %d\n",
    (uintptr_t) pipedes, flags, ret
    );
}

void NaClStraceFork(int ret) {
    fprintf(tracingOutputFile, "fork() = %d\n",
    ret
    );
}

void NaClStraceExecve(char const *path, char *const *argv, char *const *envp, int ret) {
    fprintf(tracingOutputFile, "execve(%s, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n",
    path, (uintptr_t)argv, (uintptr_t)envp, ret
    );
}

void NaClStraceExecv(char const *path, char *const *argv, int ret) {
    fprintf(tracingOutputFile, "execv(%s, 0x%08"NACL_PRIxPTR") = %d\n",
    path, (uintptr_t) argv, ret
    );
}

void NaClStraceWaitpid(int pid, uint32_t *stat_loc, int options, int ret) {
    fprintf(tracingOutputFile, "waitpid(%d, %d, %d) = %d\n",
    pid, *stat_loc, options, ret
    );
}

void NaClStraceGethostname(char *name, size_t len, int ret) {
    fprintf(tracingOutputFile, "gethostname(%s, %lu) = %d\n",
    name, len, ret
    );
}

void NaClStraceGetifaddrs(char *buf, size_t len, int ret) {
    fprintf(tracingOutputFile, "getifaddrs(%s, %lu) = %d\n",
    buf, len, ret
    );
}

void NaClStraceSocket(int domain, int type, int protocol, int ret) {
    fprintf(tracingOutputFile, "socket(%d, %d, %d) = %d\n",
    domain, type, protocol, ret
    );
}

void NaClStraceSend(int sockfd, size_t len, int flags, const void *buf, int ret) {
    fprintf(tracingOutputFile, "send(%d, %ld, %d, 0x%08"NACL_PRIxPTR") = %d\n",
    sockfd, len, flags, (uintptr_t) buf, ret
    );
}

void NaClStraceSendto(int sockfd, const void *buf, size_t len,
    int flags, uintptr_t dest_addr, socklen_t addrlen, int ret) {
        fprintf(tracingOutputFile, "sendto(%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d) = %d\n",
        sockfd, (uintptr_t) buf, len, flags, dest_addr, addrlen, ret
        );
    }

void NaClStraceRecv(int sockfd, size_t len, int flags, void *buf, int ret) {
    fprintf(tracingOutputFile, "recv(%d, %ld, %d, 0x%08"NACL_PRIxPTR") = %d\n", sockfd, len, flags, (uintptr_t)buf, ret);
}

void NaClStraceRecvfrom(int sockfd, void *buf, size_t len, int flags,
    uintptr_t src_addr, socklen_t *addrlen, int ret) {
        fprintf(tracingOutputFile, "recvfrom(%d, %p"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", sockfd, buf, len, flags, src_addr,
            (uintptr_t)addrlen, ret);
    }

void NaClStraceShutdown(int sockfd, int how, int ret) {
    fprintf(tracingOutputFile, "shutdown(%d, %d) = %d\n", sockfd, how, ret);
}

void NaClStraceGetuid(int ret) {
    fprintf(tracingOutputFile, "getuid() = %d\n", ret);
}

void NaClStraceGeteuid(int ret) {
    fprintf(tracingOutputFile, "geteuid() = %d\n", ret);
}

void NaClStraceGetgid(int ret) {
    fprintf(tracingOutputFile, "getgid() = %d\n", ret);
}

void NaClStraceGetegid(int ret) {
    fprintf(tracingOutputFile, "getegid() = %d\n", ret);
}

void NaClStraceFlock(int fd, int operation, int ret) {
    fprintf(tracingOutputFile, "flock(%d, %d) = %d\n", fd, operation, ret);
}

void NaClStraceGetsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret) {
    fprintf(tracingOutputFile, "getsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", sockfd, level, optname, (uintptr_t)optval, (uintptr_t)optlen, ret);
}

void NaClStraceSetsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret) {
    fprintf(tracingOutputFile, "setsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", %u) = %d\n", sockfd, level, optname, (uintptr_t)optval, optlen, ret);
}

void NaClStraceFstatfs(int d, uintptr_t buf, int ret) {
    fprintf(tracingOutputFile, "fstatfs(%d, 0x%08"NACL_PRIxPTR") = %d\n", d, buf, ret);
}

void NaClStraceStatfs(const char *pathname, uintptr_t buf, int ret) {
    fprintf(tracingOutputFile, "statfs(%s, 0x%08"NACL_PRIxPTR") = %d\n", pathname, buf, ret);
}

void NaClStraceGetsockname(int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    fprintf(tracingOutputFile, "getsockname(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceGetpeername(int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    fprintf(tracingOutputFile, "getpeername(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceAccess(char *path, int mode, int ret) {
    fprintf(tracingOutputFile, "access(%s, %d) = %d\n", path, mode, ret);
}

void NaClStraceTruncate(uint32_t path, int length, int ret) {
    fprintf(tracingOutputFile, "truncate(%u, %d) = %d\n", path, length, ret);
}

void NaClStraceFtruncate(int fd, int length, int ret) {
    fprintf(tracingOutputFile, "ftruncate(%d, %d) = %d\n", fd, length, ret);
}

void NaClStraceConnect(int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    fprintf(tracingOutputFile, "connect(%d, 0x%08"NACL_PRIxPTR", %u) = %d\n", sockfd, addr, addrlen, ret);
}

void NaClStraceAccept(int sockfd, uintptr_t addr, socklen_t *addrlen, int ret) {
    fprintf(tracingOutputFile, "accept(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceBind(int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    fprintf(tracingOutputFile, "bind(%d, 0x%08" NACL_PRIxPTR ", %u) = %d\n", sockfd, addr, addrlen, ret);
}
void NaClStraceListen(int sockfd, int backlog, int ret) {
    fprintf(tracingOutputFile, "listen(%d, %d) = %d\n", sockfd, backlog, ret);
}

void NaClStraceFcntlGet(int fd, int cmd, int ret) {
    fprintf(tracingOutputFile, "fcntlget(%d, %d) = %d\n", fd, cmd, ret);
}

void NaClStraceFcntlSet(int fd, int cmd, long set_op, int ret) {
    fprintf(tracingOutputFile, "fcntlset(%d, %d, %ld) = %d\n", fd, cmd, set_op, ret);
}

void NaClStracePoll(uintptr_t fds, nfds_t nfds, int timeout, int ret) {
    fprintf(tracingOutputFile, "poll(0x%08" NACL_PRIxPTR ", %d, %d) = %d\n", fds, nfds, timeout, ret);
}

void NaClStraceEpollCreate(int size, int ret) {
    fprintf(tracingOutputFile, "epollcreate(%d) = %d\n", size, ret);
}

void NaClStraceEpollCtl(int epfd, int op, int fd, uintptr_t event, int ret) {
    fprintf(tracingOutputFile, "epollctl(%d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", epfd, op, fd, event, ret);
}

void NaClStraceEpollWait(int epfd, uintptr_t events,int maxevents, int timeout, int ret) {
    fprintf(tracingOutputFile, "epollwait(%d, 0x%08"NACL_PRIxPTR", %d, %d) = %d\n", epfd, events, maxevents, timeout, ret);
}

void NaClStraceSelect(int nfds, fd_set * readfds, fd_set * writefds, 
                                fd_set * exceptfds, uintptr_t timeout, int ret) {
    fprintf(tracingOutputFile, "select(%d, %d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", nfds, readfds, writefds, exceptfds, timeout);
                       }
