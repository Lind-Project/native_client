/*
 * Tracing functionalities will be enabled when OS environment TRACING_ENABLED = 1 
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/poll.h>
#include "native_client/src/trusted/service_runtime/nacl_syscall_strace.h"

void NaClStraceGetpid(int pid) {
    printf("getpid() = %d\n", pid);
}

void NaClStraceOpen(char* path, int flags, int mode, int fd) {
    printf("open(%s, %d, %d) = %d\n", path, flags, mode, fd);
}

void NaClStraceClose(int d, int ret) {
    printf("close(%d) = %d\n", d, ret);
}

void NaClStraceRead(int d, void *buf, size_t count, int ret) {
    printf("read(%d, %p, %zu) = %d", d, buf, count, ret);
}

void NaClStraceSemWait(int32_t sem_handle, int ret) {
    printf("semwait(%d) = %d", sem_handle, ret);
}

void NaClStraceSemPost(int32_t sem_handle, int ret) {
    printf("sempost(%d) = %d",sem_handle, ret);
}

void NaClStraceSemGetValue(int32_t sem_handle, int ret) {
    printf("semgetvalue(%d) = %d", sem_handle, ret);
}

void NaClStraceNanosleep(uintptr_t req, uintptr_t rem, int ret) {
    printf("nanosleep(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d",req, rem, ret);
}

void NaClStraceSchedYield(int ret) {
    printf("schedyield() = %d", ret);
}

void NaClStraceExceptionHandler(uint32_t             handler_addr,
                                uint32_t             old_handler, int ret) {
                                    printf("exceptionhandler(%u, %u) = %d", handler_addr, old_handler, ret);
                                }

void NaClStraceExceptionStack(uint32_t stack_addr, uint32_t stack_size, int ret) {
    printf("exceptionstack(%u, %u) = %d", stack_addr, stack_size, ret);
}

void NaClStraceExceptionClearFlag(int ret) {
    printf("exceptionclearflag() = %d", ret);
}

void NaClStraceTestInfoLeak(int ret) {
    printf("testinfoleak() = %d",ret);
}

void NaClStraceTestCrash(int crash_type, int ret) {
    printf("testcrash(%d) = %d", crash_type, ret);
}

void NaClStraceGetTimeOfDay(uintptr_t tv, uintptr_t tz, int ret) {
    printf("gettimeofday(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", tv, tz, ret);
}

void NaClStraceClockGetCommon(int                   clk_id,
                              uint32_t              ts_addr,
                              uintptr_t            *time_func, 
                              int ret) {
                                printf("clockgetcommon(%d, %u, 0x%08"NACL_PRIxPTR") = %d",
                                clk_id, ts_addr, time_func, ret
                                );
                              }

void NaClStracePipe2(uint32_t *pipedes, int flags, int ret) {
    printf("pipe2(0x%08"NACL_PRIxPTR", %d) = %d",
    (uintptr_t) pipedes, flags, ret
    );
}

void NaClStraceFork(int ret) {
    printf("fork() = %d",
    ret
    );
}

void NaClStraceExecve(char const *path, char *const *argv, char *const *envp, int ret) {
    printf("execve(%s, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d",
    path, (uintptr_t)argv, (uintptr_t)envp, ret
    );
}

void NaClStraceExecv(char const *path, char *const *argv, int ret) {
    printf("execv(%s, 0x%08"NACL_PRIxPTR") = %d",
    path, (uintptr_t) argv, ret
    );
}

void NaClStraceWaitpid(int pid, uint32_t *stat_loc, int options, int ret) {
    printf("waitpid(%d, %d, %d) = %d",
    pid, *stat_loc, options, ret
    );
}

void NaClStraceGethostname(char *name, size_t len, int ret) {
    printf("gethostname(%s, %lu) = %d",
    name, len, ret
    );
}

void NaClStraceGetifaddrs(char *buf, size_t len, int ret) {
    printf("getifaddrs(%s, %lu) = %d",
    buf, len, ret
    );
}

void NaClStraceSocket(int domain, int type, int protocol, int ret) {
    printf("socket(%d, %d, %d) = %d",
    domain, type, protocol, ret
    );
}

void NaClStraceSend(int sockfd, size_t len, int flags, const void *buf, int ret) {
    printf("send(%d, %ld, %d, 0x%08"NACL_PRIxPTR") = %d",
    sockfd, len, flags, (uintptr_t) buf, ret
    );
}

void NaClStraceSendto(int sockfd, const void *buf, size_t len,
    int flags, uintptr_t dest_addr, socklen_t addrlen, int ret) {
        printf("sendto(%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d) = %d",
        sockfd, (uintptr_t) buf, len, flags, dest_addr, addrlen, ret
        );
    }

void NaClStraceRecv(int sockfd, size_t len, int flags, void *buf, int ret) {
    printf("recv(%d, %ld, %d, 0x%08"NACL_PRIxPTR") = %d", sockfd, len, flags, (uintptr_t)buf, ret);
}

void NaClStraceRecvfrom(int sockfd, void *buf, size_t len, int flags,
    uintptr_t src_addr, socklen_t *addrlen, int ret) {
        printf("recvfrom(%d, %p"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", sockfd, buf, len, flags, src_addr,
            (uintptr_t)addrlen, ret);
    }

void NaClStraceShutdown(int sockfd, int how, int ret) {
    printf("shutdown(%d, %d) = %d", sockfd, how, ret);
}

void NaClStraceGetuid(int ret) {
    printf("getuid() = %d", ret);
}

void NaClStraceGeteuid(int ret) {
    printf("geteuid() = %d", ret);
}

void NaClStraceGetgid(int ret) {
    printf("getgid() = %d", ret);
}

void NaClStraceGetegid(int ret) {
    printf("getegid() = %d", ret);
}

void NaClStraceFlock(int fd, int operation, int ret) {
    printf("flock(%d, %d) = %d", fd, operation, ret);
}

void NaClStraceGetsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret) {
    printf("getsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", sockfd, level, optname, (uintptr_t)optval, (uintptr_t)optlen, ret);
}

void NaClStraceSetsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret) {
    printf("setsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", %u) = %d", sockfd, level, optname, (uintptr_t)optval, optlen, ret);
}

void NaClStraceFstatfs(int d, uintptr_t buf, int ret) {
    printf("fstatfs(%d, 0x%08"NACL_PRIxPTR") = %d", d, buf, ret);
}

void NaClStraceStatfs(const char *pathname, uintptr_t buf, int ret) {
    printf("statfs(%s, 0x%08"NACL_PRIxPTR") = %d", pathname, buf, ret);
}

void NaClStraceGetsockname(int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    printf("getsockname(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceGetpeername(int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    printf("getpeername(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceAccess(const char *file, int mode, int ret) {
    printf("access(%s, %d) = %d");
}

void NaClStraceTruncate(uint32_t file, int length, int ret) {
    printf("truncate(%u, %d) = %d", file, length, ret);
}

void NaClStraceFtruncate(int fd, int length, int ret) {
    printf("ftruncate(%d, %d) = %d", fd, length, ret);
}

void NaClStraceConnect(int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    printf("connect(%d, 0x%08"NACL_PRIxPTR", %u) = %d", sockfd, addr, addrlen, ret);
}

void NaClStraceAccept(int sockfd, uintptr_t addr, socklen_t *addrlen, int ret) {
    printf("accept(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d", sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceBind(int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    printf("bind(%d, 0x%08"NACL_PRIxPTR", %u) = %d");
}

void NaClStraceListen(int sockfd, int backlog, int ret) {
    printf("listen(%d, %d) = %d", sockfd, backlog, ret);
}

void NaClStraceFcntlGet(int fd, int cmd, int ret) {
    printf("fcntlget(%d, %d) = %d", fd, cmd, ret);
}

void NaClStraceFcntlSet(int fd, int cmd, long set_op, int ret) {
    printf("fcntlset(%d, %d, %ld) = %d", fd, cmd, set_op, ret);
}

void NaClStracePoll(uintptr_t fds, nfds_t nfds, int timeout, int ret) {
    printf("poll(0x%08"NACL_PRIxPTR", %d, %d) = %d");
}

void NaClStraceEpollCreate(int size, int ret) {
    printf("epollcreate(%d) = %d", size, ret);
}

void NaClStraceEpollCtl(int epfd, int op, int fd, uintptr_t event, int ret) {
    printf("epollctl(%d, %d, %d, 0x%08"NACL_PRIxPTR") = %d", epfd, op, fd, event, ret);
}

void NaClStraceEpollWait(int epfd, uintptr_t events,int maxevents, int timeout, int ret) {
    printf("epollwait(%d, 0x%08"NACL_PRIxPTR", %d, %d) = %d", epfd, events, maxevents, timeout, ret);
}

void NaClStraceSelect(int nfds, fd_set * readfds, fd_set * writefds, 
                                fd_set * exceptfds, uintptr_t timeout, int ret) {
    printf("select(%d, %d, %d, %d, 0x%08"NACL_PRIxPTR") = %d", nfds, readfds, writefds, exceptfds, timeout);
                       }