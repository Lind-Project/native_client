#include <string.h>
#include <stdio.h>
#include "sys/types.h"
#include <stdint.h>
#include "native_client/src/include/portability.h" 

void NaClStraceSetOutputFile(char *path);
void NaClStraceCloseFile();
void NaClStraceGetpid(int cageid, int pid);
void NaClStraceGetppid(int cageid, int pid);
void NaClStraceOpen(int cageid, char* path, int flags, int mode, int userfd);
void NaClStraceClose(int cageid, int d, int ret);
void NaClStraceRead(int cageid, int d, void *buf, int count, int ret);
void NaClStraceExit(int cageid, int status);
void NaClStraceThreadExit(int cageid, int *stack_flag, uint32_t zero);
void NaClStraceDup(int NaClStraceExitcageid, int oldfd,int ret);
void NaClStraceDup2(int cageid, int oldfd,int newfd,int ret);
void NaClStraceDup3(int cageid, int oldfd,int newfd,int flags,int ret);
void NaClStraceGetdents(int cageid, int d, void *dirp, int count, int retval, int getdents_ret, uintptr_t sysaddr);
void NaClStracePread(int cageid, int d, void *buf, int count,  off_t offset, int ret);
void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret);
void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval);
void NaClStraceLseek(int cageid, int d, int whence, uintptr_t offset, int ret);
void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret);
// void NaClStraceFstat(int cageid, int d, uintptr_t result, int retval);
void NaClStraceFstat(int cageid, int d, int retval);
void NaClStraceStat(int cageid, char* path, uintptr_t result, int retval);
void NaClStraceLStat(int cageid, char* path, uintptr_t result, int retval);
void NaClStraceMkdir(int cageid, char* path, int mode,int retval);
void NaClStraceRmdir(int cageid, uint32_t pathname, const char* path, int retval);
void NaClStraceChdir(int cageid, uint32_t pathname, const char* path, int retval);
void NaClStraceChmod(int cageid, const char *path, int mode, int retval);
void NaClStraceFchmod(int cageid, int fd,int mode,int retval);
void NaClStraceFchdir(int cageid, int fd, int retval);
void NaClStraceFsync(int cageid, int fd, int ret);
void NaClStraceFdatasync(int cageid, int fd, int ret);
void NaClStraceGetcwd(int cageid, char* buf, int size, uintptr_t sysaddr, int retval);
void NaClStraceLink(int cageid, char* from,char* to);
void NaClStraceUnlink(int cageid, char* pathname,int retval);
void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval);
void NaClStraceCommon(int cageid, uintptr_t usraddr, int length);
void NaClStraceSecondTlsSet(int cageid, uint32_t new_value);
void NaClStraceMmap(int cageid, void *start,int length,int prot,int flags,int d, uintptr_t offset, int retval);
void NaClStraceMprotectInternal(int cageid, uint32_t start,int length,int prot,uintptr_t sysaddr,int retval,int holding_app_lock);
void NaClStraceMprotect(int cageid, uint32_t start,int length,int prot);
void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval);
void NaClStraceShmget(int cageid, int key, int size, int shmflg, int retval);
void NaClStraceShmdt(int cageid, void *shmaddr, int retval);
void NaClStraceShmctl(int cageid, int shmid, int cmd, int retval);
void fSocketPair(int cageid, int domain, int type, int protocol, int *fds, int *lindfds, int retval);
void NaClStraceMutexCreate(int cageid, int retval);
void NaClStraceMutexLock(int cageid, int mutex_handle, int retval);
void NaClStraceMutexUnLock(int cageid, int mutex_handle, int retval);
void NaClStraceMutexTrylock(int cageid, int mutex_handle, int retval);
void NaClStraceMutexDestroy(int cageid, int mutex_handle,int retval);
void NaClStraceCondCreate(int cageid, int retval);
void NaClStraceCondWait(int cageid, int cond_handle,int mutex_handle,int retval);
void NaClStraceCondSignal(int cageid, int cond_handle,int retval);
void NaClStraceCondBroadcast(int cageid, int cond_handle, int retval);
void NaClStraceCondDestroy(int cageid, int cond_handle,int retval);
void NaClStraceCondTimedWaitAbs(int cageid, int cond_handle, int mutex_handle, uintptr_t trusted_ts, int retval);
void NaClStraceSemCreate(int cageid, int init_value, int retval);
void NaClStraceSecondTlsGet(int cageid, int retval);
void NaClStraceSemInit(int cageid, int sem, int pshared, int value, int retval);
void NaClStraceSemWait(int cageid, int sem_handle, int ret);
void NaClStraceSemTryWait(int cageid, int sem_handle, int ret);
void NaClStraceSemTimedWait(int cageid, uint32_t sem, uintptr_t trusted_abs, int ret);
void NaClStraceSemPost(int cageid, int sem_handle, int ret);
void NaClStraceSemDestroy(int cageid, int sem_handle, int ret);
void NaClStraceSemGetValue(int cageid, int sem_handle, int ret);
void NaClStraceNanosleep(int cageid, uintptr_t req, uintptr_t rem, int ret);
void NaClStraceSchedYield(int cageid, int ret);
void NaClStraceExceptionHandler(int cageid, uint32_t             handler_addr,
                                uint32_t             old_handler, int ret);
void NaClStraceExceptionStack(int cageid, uint32_t stack_addr, uint32_t stack_size, int ret);
void NaClStraceExceptionClearFlag(int cageid, int ret);
void NaClStraceTestInfoLeak(int cageid, int ret);
void NaClStraceTestCrash(int cageid, int crash_type, int ret);
void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret);
void NaClStraceClockGetCommon(int cageid, int                   clk_id,
                              uint32_t              ts_addr,
                              uintptr_t            *time_func, 
                              int ret);
void NaClStracePipe2(int cageid, uint32_t *pipedes, int flags, int ret);
void NaClStraceFork(int cageid, int ret);
void NaClStraceExecve(int cageid, char const *path, char *const *argv, char *const *envp, int ret);
void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret);
void NaClStraceWaitpid(int cageid, int pid, uint32_t *stat_loc, int options, int ret);
void NaClStraceGethostname(int cageid, uintptr_t sysaddr, int len, int ret);
void NaClStraceGetifaddrs(int cageid, char *buf, int len, int ret);
void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret);
void NaClStraceSend(int cageid, int sockfd, int len, int flags, const void *buf, int ret);
void NaClStraceSendto(int cageid, int sockfd, const void *buf, int len,
    int flags, uintptr_t dest_addr, socklen_t addrlen, int ret);
void NaClStraceRecv(int cageid, int sockfd, int len, int flags, void *buf, int ret);
void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, int len, int flags,
    uintptr_t src_addr, socklen_t *addrlen, int ret);
void NaClStraceShutdown(int cageid, int sockfd, int how, int ret);
void NaClStraceGetuid(int cageid, int ret);
void NaClStraceGeteuid(int cageid, int ret);
void NaClStraceGetgid(int cageid, int ret);
void NaClStraceGetegid(int cageid, int ret);
void NaClStraceFlock(int cageid, int fd, int operation, int ret);
void NaClStraceGetsockopt(int cageid, int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret);
void NaClStraceSetsockopt(int cageid, int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret);
void NaClStraceFstatfs(int cageid, int d, uintptr_t buf, int ret);
void NaClStraceStatfs(int cageid, const char *pathname, uintptr_t buf, int ret);
void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret);
void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret);
void NaClStraceAccess(int cageid, char *file, int mode, int ret);
void NaClStraceTruncate(int cageid, uint32_t file, int length, int ret);
void NaClStraceFtruncate(int cageid, int fd, int length, int ret);
void NaClStraceConnect(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret);
void NaClStraceAccept(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret);
void NaClStraceBind(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret);
void NaClStraceListen(int cageid, int sockfd, int backlog, int ret);
void NaClStraceFcntlGet(int cageid, int fd, int cmd, int ret);
void NaClStraceFcntlSet(int cageid, int fd, int cmd, long set_op, int ret);
void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int ret);
void NaClStraceEpollCreate(int cageid, int size, int ret);
void NaClStraceEpollCtl(int cageid, int epfd, int op, int fd, uintptr_t event, int ret);
void NaClStraceEpollWait(int cageid, int epfd, uintptr_t events, int maxevents, int timeout, int ret);
void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, 
                       uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret);
void NaClStraceThreadCreate(int cageid, void *prog_ctr, uint32_t stack_ptr, uint32_t thread_ptr, uint32_t second_thread_ptr, int retval);
void NaClStraceThreadNice(int cageid, int nice, int retval);
void NaClStraceNameService(int cageid, int *desc_addr, int retval);
void NaClStraceCommonAddrRangeContainsExecutablePages(int cageid, uintptr_t usraddr, int length);
void NaClStraceCommonAddrRangeInAllowedDynamicCodeSpace(int cageid, uintptr_t usraddr, int length);
void NaClStraceMmapIntern(int cageid, void *start, int length, int prot, int flags, int d, nacl_abi_off_t offset, int retval);
void NaClStraceTlsInit(int cageid, uint32_t thread_ptr, int retval);
void NaClStraceThreadCreate(int cageid, void *prog_ctr, uint32_t stack_ptr, uint32_t thread_ptr, uint32_t second_thread_ptr, int retval);
void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *fds, int *lindfds, int retval);