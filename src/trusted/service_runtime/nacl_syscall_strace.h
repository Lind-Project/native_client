#include <string.h>
#include <stdio.h>
#include "sys/types.h"
#include <stdint.h>
#include "native_client/src/include/portability.h" 

void NaClStraceSetOutputFile(char *path);
void NaClStraceCloseFile();
void NaClStraceGetpid(int cageid, int pid);
void NaClStraceGetppid(int cageid, int pid);
void NaClStraceOpen(int cageid, char* path, int flags, int mode, int fd);
void NaClStraceClose(int cageid, int d, int ret);
void NaClStraceRead(int cageid, int d, void *buf, size_t count, int ret);
void NaClStraceExit(int cageid, int status);
void NaClStraceThreadExit(int cageid, pthread_t tid);
void NaClStraceDup(int cageid, int oldfd, int ret);
void NaClStraceDup2(int cageid, int oldfd, int newfd, int ret);
void NaClStraceDup3(int cageid, int oldfd, int newfd, int flags, int ret);
void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, int ret);
void NaClStracePread(int cageid, int d, void *buf, int count,  off_t offset, int ret);
void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret);
void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval);
void NaClStraceLseek(int cageid, int d, uintptr_t offset, int whence, int ret);
void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret);
void NaClStraceFstat(int cageid, int d, uintptr_t result, int retval);
void NaClStraceStat(int cageid, char* path, uintptr_t result, int retval);
void NaClStraceLStat(int cageid, char* path, uintptr_t result, int retval);
void NaClStraceMkdir(int cageid, char* path, int mode, int retval);
void NaClStraceRmdir(int cageid, const char *path, int retval);
void NaClStraceChdir(int cageid, const char *path, int retval);
void NaClStraceChmod(int cageid, const char *path, int mode, int retval);
void NaClStraceFchmod(int cageid, int fd, int mode, int retval);
void NaClStraceFchdir(int cageid, int fd, int retval);
void NaClStraceFsync(int cageid, int fd, int ret);
void NaClStraceFdatasync(int cageid, int fd, int ret);
void NaClStraceSyncFileRange(int cageid, int fd, off_t offset, off_t nbytes, uint32_t flags, int retval);
void NaClStraceGetcwd(int cageid, char *buf, size_t size, int retval);
void NaClStraceLink(int cageid, char* from, char* to, int retval);
void NaClStraceUnlink(int cageid, char* pathname, int retval);
void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval);
void NaClStraceCommon(int cageid, uintptr_t usraddr, size_t length);
void NaClStraceMmap(int cageid, void *start, size_t length, int prot, int flags, int d, uintptr_t offset, int retval);
void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length, int retval);
void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval);
void NaClStraceShmget(int cageid, int key, size_t size, int shmflg, int retval);
void NaClStraceShmdt(int cageid, void *shmaddr, int retval);
void NaClStraceShmctl(int cageid, int shmid, int cmd, uintptr_t bufsysaddr, int retval);
void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval);
void NaClStraceMutexCreate(int cageid, int retval);
void NaClStraceMutexLock(int cageid, int32_t mutex_handle, int retval);
void NaClStraceMutexUnLock(int cageid, int32_t mutex_handle, int retval);
void NaClStraceMutexTrylock(int cageid, int32_t mutex_handle, int retval);
void NaClStraceMutexDestroy(int cageid, int32_t mutex_handle, int retval);
void NaClStraceCondCreate(int cageid, int retval);
void NaClStraceCondWait(int cageid, int32_t cond_handle, int32_t mutex_handle, int retval);
void NaClStraceCondSignal(int cageid, int32_t cond_handle, int retval);
void NaClStraceCondBroadcast(int cageid, int32_t cond_handle, int retval);
void NaClStraceCondDestroy(int cageid, int32_t cond_handle, int retval);
void NaClStraceCondTimedWaitAbs(int cageid, int32_t cond_handle, int32_t mutex_handle, uintptr_t trusted_ts, int retval);
void NaClStraceSemInit(int cageid, int32_t sem, int32_t pshared, int32_t value, int retval);
void NaClStraceSemWait(int cageid, int32_t sem_handle, int ret);
void NaClStraceSemTryWait(int cageid, int32_t sem_handle, int ret);
void NaClStraceSemTimedWait(int cageid, uint32_t sem, uintptr_t trusted_abs, int ret);
void NaClStraceSemPost(int cageid, int32_t sem_handle, int ret);
void NaClStraceSemDestroy(int cageid, int32_t sem_handle, int ret);
void NaClStraceSemGetValue(int cageid, int32_t sem_handle, int ret);
void NaClStraceNanosleep(int cageid, uintptr_t req, uintptr_t rem, int ret);
void NaClStraceSchedYield(int cageid, int ret);
void NaClStraceExceptionHandler(int cageid, uint32_t handler_addr, uint32_t old_handler, int ret);
void NaClStraceExceptionStack(int cageid, uint32_t stack_addr, uint32_t stack_size, int ret);
void NaClStraceExceptionClearFlag(int cageid, int ret);
void NaClStraceTestInfoLeak(int cageid, int ret);
void NaClStraceTestCrash(int cageid, int crash_type, int ret);
void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret);
void NaClStraceClockGetCommon(int cageid, int clk_id, uint32_t ts_addr, uintptr_t *time_func, int ret) ;
void NaClStracePipe2(int cageid, uint32_t *pipedes, int flags, int ret);
void NaClStraceFork(int cageid, int ret);
void NaClStraceExecve(int cageid, char const *path, char *const *argv, int ret);
void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret);
void NaClStraceWaitpid(int cageid, int pid, uintptr_t sysaddr, int options, int ret);
void NaClStraceGethostname(int cageid, char *name, size_t len, int ret);
void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret);
void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret);
void NaClStraceSend(int cageid, int sockfd, const void *buf, size_t len, int flags, int ret);
void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len, int flags, uintptr_t dest_addr, socklen_t addrlen, int ret);
void NaClStraceRecv(int cageid, int sockfd, void *buf, size_t len, int flags, int ret);
void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags, uintptr_t src_addr, socklen_t *addrlen, int ret);
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
void NaClStraceTruncate(int cageid, char *path, int length, int ret);
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
void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret);
void NaClStraceTlsInit(int cageid, uint32_t thread_ptr, int32_t retval);
void NaClStraceThreadCreate(int cageid,
                            uintptr_t prog_ctr,
                            uint32_t stack_ptr,
                            uint32_t thread_ptr,
                            uint32_t second_thread_ptr,
                            int32_t retval);
void NaClStraceTlsGet(int cageid, int32_t retval);
void NaClStraceSecondTlsSet(int cageid, uint32_t new_value, int32_t retval);
void NaClStraceSecondTlsGet(int cageid, int32_t retval);
void NaClStraceMprotectInternal(int cageid, uint32_t start, size_t length, int prot, int32_t retval);
void NaClStraceMprotect(int cageid, uint32_t start, size_t length, int prot, int32_t retval);
void NaClStraceNameService(int cageid, uintptr_t desc_addr, int32_t retval);
void NaClStraceBrk(int cageid, uintptr_t new_break, uintptr_t result);
void NaClStraceNull(int cageid, int ret);
void NaClStraceMmapIntern(int cageid, uintptr_t start, size_t length, int prot, int flags, int d, nacl_abi_off_t offset, int32_t retval);