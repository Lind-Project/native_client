#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "native_client/src/include/portability.h" 


void NaClStraceGetpid(int pid);
void NaClStraceOpen(char* path, int flags, int mode, int fd);
void NaClStraceClose(int d, int ret);
void NaClStraceRead(int d, void *buf, size_t count, int ret);
void NaClStraceSemWait(int32_t sem_handle, int ret);
void NaClStraceSemPost(int32_t sem_handle, int ret);
void NaClStraceSemGetValue(int32_t sem_handle, int ret);
void NaClStraceNanosleep(uintptr_t req, uintptr_t rem, int ret);
void NaClStraceSchedYield(int ret);
void NaClStraceExceptionHandler(uint32_t             handler_addr,
                                uint32_t             old_handler, int ret);
void NaClStraceExceptionStack(uint32_t stack_addr, uint32_t stack_size, int ret);
void NaClStraceExceptionClearFlag(int ret);
void NaClStraceTestInfoLeak(int ret);
void NaClStraceTestCrash(int crash_type, int ret);
void NaClStraceGetTimeOfDay(uintptr_t tv, uintptr_t tz, int ret);
void NaClStraceClockGetCommon(int                   clk_id,
                              uint32_t              ts_addr,
                              uintptr_t            *time_func, 
                              int ret);
void NaClStracePipe2(uint32_t *pipedes, int flags, int ret);
void NaClStraceFork(int ret);
void NaClStraceExecve(char const *path, char *const *argv, char *const *envp, int ret);
void NaClStraceExecv(char const *path, char *const *argv, int ret);
void NaClStraceWaitpid(int pid, uint32_t *stat_loc, int options, int ret);
void NaClStraceGethostname(char *name, size_t len, int ret);
void NaClStraceGetifaddrs(char *buf, size_t len, int ret);
void NaClStraceSocket(int domain, int type, int protocol, int ret);
void NaClStraceSend(int sockfd, size_t len, int flags, const void *buf, int ret);
void NaClStraceSendto(int sockfd, const void *buf, size_t len,
    int flags, uintptr_t dest_addr, socklen_t addrlen, int ret);
void NaClStraceRecv(int sockfd, size_t len, int flags, void *buf, int ret);
void NaClStraceRecvfrom(int sockfd, void *buf, size_t len, int flags,
    uintptr_t src_addr, socklen_t *addrlen, int ret);
void NaClStraceShutdown(int sockfd, int how, int ret);
void NaClStraceGetuid(int ret);
void NaClStraceGeteuid(int ret);
void NaClStraceGetgid(int ret);
void NaClStraceGetegid(int ret);
void NaClStraceFlock(int fd, int operation, int ret);
void NaClStraceGetsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret);
void NaClStraceSetsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret);
void NaClStraceFstatfs(int d, uintptr_t buf, int ret);
void NaClStraceStatfs(const char *pathname, uintptr_t buf, int ret);
void NaClStraceGetsockname(int sockfd, uintptr_t addr, socklen_t * addrlen, int ret);
void NaClStraceGetpeername(int sockfd, uintptr_t addr, socklen_t * addrlen, int ret);
void NaClStraceAccess(const char *file, int mode, int ret);
void NaClStraceTruncate(uint32_t file, int length, int ret);
void NaClStraceFtruncate(int fd, int length, int ret);
void NaClStraceConnect(int sockfd, uintptr_t addr, socklen_t addrlen, int ret);
void NaClStraceAccept(int sockfd, uintptr_t addr, socklen_t *addrlen, int ret);
void NaClStraceBind(int sockfd, uintptr_t addr, socklen_t addrlen, int ret);
void NaClStraceListen(int sockfd, int backlog, int ret);
void NaClStraceFcntlGet(int fd, int cmd, int ret);
void NaClStraceFcntlSet(int fd, int cmd, long set_op, int ret);
void NaClStracePoll(uintptr_t fds, nfds_t nfds, int timeout, int ret);
void NaClStraceEpollCreate(int size, int ret);
void NaClStraceEpollCtl(int epfd, int op, int fd, uintptr_t event, int ret);
void NaClStraceEpollWait(int epfd, uintptr_t events, int maxevents, int timeout, int ret);
void NaClStraceSelect(int nfds, fd_set * readfds, 
                       fd_set * writefds, fd_set * exceptfds, uintptr_t timeout, int ret);