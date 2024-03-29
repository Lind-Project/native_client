#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include "sys/types.h"
#include <stdint.h>
#include "native_client/src/include/portability.h"
void NaClStraceSetOutputFile(char *path);
void NaClStraceCloseFile();
void NaClStraceEnableDashc();
void NaClStraceGetpid(int cageid, int pid, long long totaltime);
void NaClStraceGetppid(int cageid, int pid, long long totaltime) ;
void NaClStraceOpen(int cageid, char* path, int flags, int mode, int fd, long long totaltime) ;
void NaClStraceClose(int cageid, int d, int ret, long long totaltime) ;
void NaClStraceRead(int cageid, int d, void *buf, size_t count, int ret, long long totaltime) ;
void NaClStraceExit(int cageid, int status, long long totaltime) ;
void NaClStraceDup(int cageid, int oldfd, int ret, long long totaltime) ;
void NaClStraceDup2(int cageid, int oldfd, int newfd, int ret, long long totaltime) ;
void NaClStraceDup3(int cageid, int oldfd, int newfd, int flags, int ret, long long totaltime) ;
void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, int ret, long long totaltime) ;
void NaClStracePread(int cageid, int d, void *buf, int count, off_t offset, int ret, long long totaltime) ;
void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret, long long totaltime) ;
void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval, long long totaltime) ;
void NaClStraceLseek(int cageid, int d, uintptr_t offset, int whence, int ret, long long totaltime) ;
void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret, long long totaltime) ;
void NaClStraceFstat(int cageid, int d, uintptr_t result, int32_t retval, long long totaltime) ;
void NaClStraceStat(int cageid, char* path, uintptr_t result, int32_t retval, long long totaltime) ;
void NaClStraceLStat(int cageid, const char* path, uintptr_t result, int32_t retval, long long totaltime) ;
void NaClStraceMkdir(int cageid, const char *path, int mode, int retval, long long totaltime)  ;
void NaClStraceRmdir(int cageid, const char *path, int retval, long long totaltime) ;
void NaClStraceChdir(int cageid, const char *path, int retval, long long totaltime) ;
void NaClStraceChmod(int cageid, const char *path, int mode, int retval, long long totaltime) ;
void NaClStraceFchmod(int cageid, int fd, int mode, int retval, long long totaltime) ;
void NaClStraceFchdir(int cageid, int fd, int retval, long long totaltime) ;
void NaClStraceFsync(int cageid, int fd, int ret, long long totaltime) ;
void NaClStraceFdatasync(int cageid, int fd, int ret, long long totaltime) ;
void NaClStraceSyncFileRange(int cageid, int fd, off_t offset, off_t nbytes, uint32_t flags, int retval, long long totaltime) ;
void NaClStraceGetcwd(int cageid, char *buf, size_t size, int retval, long long totaltime) ;
void NaClStraceLink(int cageid, char* from, char* to, int retval, long long totaltime) ;
void NaClStraceUnlink(int cageid, char* pathname, int retval, long long totaltime) ;
void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval, long long totaltime) ;
void NaClStraceMmap(int cageid, void *start, size_t length, int prot, int flags, int d, uintptr_t offset, int retval, long long totaltime) ;
void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length, int retval, long long totaltime) ;
void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval, long long totaltime) ;
void NaClStraceShmget(int cageid, int key, size_t size, int shmflg, int retval, long long totaltime) ;
void NaClStraceShmdt(int cageid, void *shmaddr, int retval, long long totaltime) ;
void NaClStraceShmctl(int cageid, int shmid, int cmd, uintptr_t bufsysaddr, int retval, long long totaltime) ;
void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval, long long totaltime) ;
void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret, long long totaltime) ;
void NaClStraceClockGetCommon(int cageid, int clk_id, uint32_t ts_addr, uintptr_t *time_func, int ret, long long totaltime) ;
void NaClStraceFork(int cageid, int ret, long long totaltime) ;
void NaClStraceExecve(int cageid, char const *path, char *const *argv, int ret, long long totaltime) ;
void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret, long long totaltime) ;
void NaClStraceWaitpid(int cageid, int pid, uintptr_t sysaddr, int options, int ret, long long totaltime) ;
void NaClStraceGethostname(int cageid, char *name, size_t len, int ret, long long totaltime) ;
void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret, long long totaltime) ;
void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret, long long totaltime) ;
void NaClStraceSend(int cageid, int sockfd, const void *buf, size_t len, int flags, int ret, long long totaltime) ;
void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len, int flags, uintptr_t dest_addr, socklen_t addrlen, int ret, long long totaltime) ;
void NaClStraceRecv(int cageid, int sockfd, void *buf, size_t len, int flags, int ret, long long totaltime) ;
void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags, uintptr_t src_addr, socklen_t *addrlen, int ret, long long totaltime) ;
void NaClStraceShutdown(int cageid, int sockfd, int how, int ret, long long totaltime) ;
void NaClStraceGetuid(int cageid, int ret, long long time) ;
void NaClStraceGeteuid(int cageid, int ret, long long time) ;
void NaClStraceGetgid(int cageid, int ret, long long totaltime) ;
void NaClStraceGetegid(int cageid, int ret, long long totaltime) ;
void NaClStraceFlock(int cageid, int fd, int operation, int ret, long long totaltime) ;
void NaClStraceGetsockopt(int cageid, int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret, long long totaltime) ;
void NaClStraceSetsockopt(int cageid, int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret, long long totaltime) ;
void NaClStraceFstatfs(int cageid, int d, uintptr_t buf, int ret, long long totaltime) ;
void NaClStraceStatfs(int cageid, const char *pathname, uintptr_t buf, int ret, long long totaltime) ;
void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long totaltime) ;
void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long totaltime) ;
void NaClStraceAccess(int cageid, char *path, int mode, int ret, long long totaltime) ;
void NaClStraceTruncate(int cageid, uint32_t path, int length, int ret, long long totaltime) ;
void NaClStraceFtruncate(int cageid, int fd, int length, int ret, long long totaltime) ;
void NaClStraceConnect(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret, long long totaltime) ;
void NaClStraceAccept(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long totaltime) ;
void NaClStraceBind(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret, long long totaltime) ;
void NaClStraceListen(int cageid, int sockfd, int backlog, int ret, long long totaltime) ;
void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int retval, long long totaltime) ;
void NaClStraceFcntlGet(int cageid, int fd, int cmd, int ret, long long totaltime) ;
void NaClStraceFcntlSet(int cageid, int fd, int cmd, long set_op, int ret, long long totaltime) ;
void NaClStraceEpollCreate(int cageid, int size, int ret, long long totaltime) ;
void NaClStraceEpollCtl(int cageid, int epfd, int op, int fd, uintptr_t event, int ret, long long totaltime) ;
void NaClStraceEpollWait(int cageid, int epfd, uintptr_t events, int maxevents, int timeout, int ret, long long totaltime) ;
void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret, long long totaltime) ;
void printFinalSyscallStats();
const char* getSyscallName(int syscallIndex);

