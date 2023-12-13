#include <string.h>
#include <stdio.h>
#include "sys/types.h"
#include <stdint.h>
#include "native_client/src/include/portability.h" 

void NaClStraceSetOutputFile(char *path);
void NaClStraceGetpid(int pid);
void NaClStraceGetppid(int pid);
void NaClStraceOpen(char* path, int flags, int mode, int fd);
void NaClStraceClose(int d, int ret);
void NaClStraceRead(int d, void *buf, size_t count, int ret);
void NaClStraceExit(int status);
void NaClStraceThreadExit(int32_t *stack_flag, uint32_t zero);
void NaClStraceDup(int oldfd,int ret);
void NaClStraceDup2(int oldfd,int newfd,int ret);
void NaClStraceDup3(int oldfd,int newfd,int flags,int ret);
void NaClStraceGetdents(int d, void *drip, size_t count, size_t ret, ssize_t getdents_ret, uintptr_t sysaddr);
void NaClStracePread(int d, void *buf, int count,  size_t log_bytes);
void NaClStraceWrite(int d, void *buf, int count);
void NaClStracePWrite(int d, const void *buf, int count, off_t offset);
void NaClStraceIoctl(int d, unsigned long request, size_t ret);
void NaClStraceFstat(int d, size_t retval);
void NaClStraceStat(char* path, size_t retval);
void NaClStraceMkdir(char* path, int mode,size_t retval);
void NaClStraceRmdir(const char *path, int32_t retval);
void NaClStraceChdir(const char *path, int32_t retval);
void NaClStraceChmod(const char *path, int mode, int32_t retval);
void NaClStraceFchmod(int fd,int mode,int retval);
void NaClStraceFchdir(int fd);
void NaClStraceGetcwd(char *buf, size_t size, uintptr_t sysaddr, int32_t retval);
void NaClStraceLink(char* from,char* to);
void NaClStraceUnlink(char* pathname,int32_t retval);
void NaClStraceRename(const char *oldpath, const char *newpath, int32_t retval);
void NaClStraceCommon(uintptr_t usraddr, size_t length);
void NaClStraceSecondTlsSet(uint32_t new_value);
void NaClStraceMmap(void *start,size_t length,int prot,int flags,int d,int32_t retval);
void NaClStraceMunmap(void *start,size_t length,int32_t retval,uintptr_t sysaddr,size_t alloc_rounded_length);
void NaClStraceMprotectInternal(uint32_t start,size_t length,int prot,uintptr_t sysaddr,int32_t retval,int holding_app_lock);
void NaClStraceMprotect(uint32_t start,size_t length,int prot);
void NaClStraceShmat(int shmid, void *shmaddr, int shmflg);
void NaClStraceShmget(int key, size_t size, int shmflg, int retval);
void NaClStraceShmdt(void *shmaddr, int retval);
void NaClStraceShmctl(int shmid, int cmd, int32_t retval);
void NaClStraceSocketPair(int domain, int type, int protocol, int *fds, int *lindfds, int32_t retval);
void NaClStraceMutexCreate(int32_t retval);
void NaClStraceMutexLock(int32_t mutex_handle, int32_t retval);
void NaClStraceMutexUnLock(int32_t mutex_handle, int32_t retval);
void NaClStraceMutexTrylock(int32_t mutex_handle, int32_t retval);
void NaClStraceMutexDestroy(int32_t mutex_handle,int32_t retval);
void NaClStraceCondCreate(int32_t retval);
void NaClStraceCondWait(int32_t cond_handle,int32_t mutex_handle,int32_t retval);
void NaClStraceCondSignal(int32_t cond_handle,int32_t retval);
void NaClStraceCondBroadcast(int32_t cond_handle, int32_t retval);
void NaClStraceCondDestroy(int32_t cond_handle,int32_t retval);
void NaClStraceCondTimedWaitAbs(int32_t cond_handle,int32_t mutex_handle,int32_t retval);
void NaClStraceSemCreate(int32_t init_value, int32_t retval);
void NaClStraceSecondTlsGet(int32_t retval);
void NaClStraceSemInit(int32_t sem, int32_t pshared, int32_t value, int retval);
void NaClStraceSemWait(int32_t sem_handle, int ret);
void NaClStraceSemPost(int32_t sem_handle, int ret);
void NaClStraceSemDestroy(int32_t sem_handle, int ret);
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
void NaClStraceAccess(char *file, int mode, int ret);
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
void NaClStraceLseek(int d, int whence);
void NaClStraceLStat(char* path, size_t retval);
void NaClStraceTlsGet(int32_t retval);
void NaClStraceNameService(int32_t *desc_addr, int32_t retval);
void NaClStraceNull(int32_t retval);
void NaClStraceNotImplementedDecoder(int32_t retval);
void NaClStraceTlsInit(uint32_t thread_ptr,int32_t retval,uintptr_t sys_tls);
void NaClStraceCommonAddrRangeInAllowedDynamicCodeSpace(uintptr_t usraddr, size_t length);
void NaClSysBrkTrace(uintptr_t new_break, int32_t retval);