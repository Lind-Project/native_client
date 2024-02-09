#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include "sys/types.h"
#include <stdint.h>
#include "native_client/src/include/portability.h"
void NaClStraceSetOutputFile(char *path);
void NaClStraceCloseFile();
void NaClStraceEnableDashc();
void NaClStraceGetpid(int cageid, int pid, long long elapsedTime);
void NaClStraceGetppid(int cageid, int pid, long long elapsedTime) ;
void NaClStraceOpen(int cageid, char* path, int flags, int mode, int fd, long long elapsedTime) ;
void NaClStraceClose(int cageid, int d, int ret, long long elapsedTime) ;
void NaClStraceRead(int cageid, int d, void *buf, size_t count, int ret, long long time) ;
void NaClStraceExit(int cageid, int status, long long elapsedTime) ;
void NaClStraceDup(int cageid, int oldfd, int ret, long long elapsedTime) ;
void NaClStraceDup2(int cageid, int oldfd, int newfd, int ret, long long elapsedTime) ;
void NaClStraceDup3(int cageid, int oldfd, int newfd, int flags, int ret, long long elapsedTime) ;
void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, int ret, long long elapsedTime) ;
void NaClStracePread(int cageid, int d, void *buf, int count, off_t offset, int ret, long long elapsedTime) ;
void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret, long long elapsedTime) ;
void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval, long long elapsedTime) ;
void NaClStraceLseek(int cageid, int d, uintptr_t offset, int whence, int ret, long long time) ;
void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret, long long elapsedTime) ;
void NaClStraceFstat(int cageid, int d, uintptr_t result, int32_t retval, long long time) ;
void NaClStraceStat(int cageid, char* path, uintptr_t result, int32_t retval, long long elapsedTime) ;
void NaClStraceLStat(int cageid, const char* path, uintptr_t result, int32_t retval, long long time) ;
void NaClStraceMkdir(int cageid, const char *path, int mode, int retval, long long totaltime)  ;
void NaClStraceRmdir(int cageid, const char *path, int retval, long long elapsedTime) ;
void NaClStraceChdir(int cageid, const char *path, int retval, long long elapsedTime) ;
void NaClStraceChmod(int cageid, const char *path, int mode, int retval, long long elapsedTime) ;
void NaClStraceFchmod(int cageid, int fd, int mode, int retval, long long elapsedTime) ;
void NaClStraceFchdir(int cageid, int fd, int retval, long long elapsedTime) ;
void NaClStraceFsync(int cageid, int fd, int ret, long long elapsedTime) ;
void NaClStraceFdatasync(int cageid, int fd, int ret, long long elapsedTime) ;
void NaClStraceSyncFileRange(int cageid, int fd, off_t offset, off_t nbytes, uint32_t flags, int retval, long long elapsedTime) ;
void NaClStraceGetcwd(int cageid, char *buf, size_t size, int retval, long long elapsedTime) ;
void NaClStraceLink(int cageid, char* from, char* to, int retval, long long elapsedTime) ;
void NaClStraceUnlink(int cageid, char* pathname, int retval, long long elapsedTime) ;
void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval, long long elapsedTime) ;
void NaClStraceMmap(int cageid, void *start, size_t length, int prot, int flags, int d, uintptr_t offset, int retval, long long time) ;
void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length, int retval, long long elapsedTime) ;
void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval, long long elapsedTime) ;
void NaClStraceShmget(int cageid, int key, size_t size, int shmflg, int retval, long long elapsedTime) ;
void NaClStraceShmdt(int cageid, void *shmaddr, int retval, long long elapsedTime) ;
void NaClStraceShmctl(int cageid, int shmid, int cmd, uintptr_t bufsysaddr, int retval, long long elapsedTime) ;
void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval, long long elapsedTime) ;
// void NaClStraceNanosleep(int cageid, uintptr_t req, uintptr_t rem, int ret, long long elapsedTime) ;
//void NaClStraceSchedYield(int cageid, int ret, long long elapsedTime) ;
void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret, long long elapsedTime) ;
void NaClStraceClockGetCommon(int cageid, int clk_id, uint32_t ts_addr, uintptr_t *time_func, int ret, long long elapsedTime) ;
void NaClStraceFork(int cageid, int ret, long long elapsedTime) ;
void NaClStraceExecve(int cageid, char const *path, char *const *argv, int ret, long long elapsedTime) ;
void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret, long long elapsedTime) ;
void NaClStraceWaitpid(int cageid, int pid, uintptr_t sysaddr, int options, int ret, long long elapsedTime) ;
void NaClStraceGethostname(int cageid, char *name, size_t len, int ret, long long elapsedTime) ;
void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret, long long elapsedTime) ;
void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret, long long elapsedTime) ;
void NaClStraceSend(int cageid, int sockfd, const void *buf, size_t len, int flags, int ret, long long elapsedTime) ;
void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len, int flags, uintptr_t dest_addr, socklen_t addrlen, int ret, long long elapsedTime) ;
void NaClStraceRecv(int cageid, int sockfd, void *buf, size_t len, int flags, int ret, long long elapsedTime) ;
void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags, uintptr_t src_addr, socklen_t *addrlen, int ret, long long elapsedTime) ;
void NaClStraceShutdown(int cageid, int sockfd, int how, int ret, long long elapsedTime) ;
void NaClStraceGetuid(int cageid, int ret, long long time) ;
void NaClStraceGeteuid(int cageid, int ret, long long time) ;
void NaClStraceGetgid(int cageid, int ret, long long elapsedTime) ;
void NaClStraceGetegid(int cageid, int ret, long long elapsedTime) ;
void NaClStraceFlock(int cageid, int fd, int operation, int ret, long long elapsedTime) ;
void NaClStraceGetsockopt(int cageid, int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret, long long elapsedTime) ;
void NaClStraceSetsockopt(int cageid, int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret, long long elapsedTime) ;
void NaClStraceFstatfs(int cageid, int d, uintptr_t buf, int ret, long long elapsedTime) ;
void NaClStraceStatfs(int cageid, const char *pathname, uintptr_t buf, int ret, long long elapsedTime) ;
void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long elapsedTime) ;
void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long elapsedTime) ;
void NaClStraceAccess(int cageid, char *path, int mode, int ret, long long elapsedTime) ;
void NaClStraceTruncate(int cageid, uint32_t path, int length, int ret, long long elapsedTime) ;
void NaClStraceFtruncate(int cageid, int fd, int length, int ret, long long elapsedTime) ;
void NaClStraceConnect(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret, long long elapsedTime) ;
void NaClStraceAccept(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long elapsedTime) ;
void NaClStraceBind(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret, long long elapsedTime) ;
void NaClStraceListen(int cageid, int sockfd, int backlog, int ret, long long elapsedTime) ;
void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int retval, long long elapsedTime) ;
void NaClStraceFcntlGet(int cageid, int fd, int cmd, int ret, long long elapsedTime) ;
void NaClStraceFcntlSet(int cageid, int fd, int cmd, long set_op, int ret, long long elapsedTime) ;
void NaClStraceEpollCreate(int cageid, int size, int ret, long long elapsedTime) ;
void NaClStraceEpollCtl(int cageid, int epfd, int op, int fd, uintptr_t event, int ret, long long elapsedTime) ;
void NaClStraceEpollWait(int cageid, int epfd, uintptr_t events, int maxevents, int timeout, int ret, long long elapsedTime) ;
void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret, long long elapsedTime) ;
void printFinalSyscallStats();
const char* getSyscallName(int syscallIndex);
