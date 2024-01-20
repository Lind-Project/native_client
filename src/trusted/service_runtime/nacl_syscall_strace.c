/*
 * Tracing functionalities will be enabled when OS environment TRACING_ENABLED = 1 
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/poll.h>
#include "native_client/src/trusted/service_runtime/nacl_syscall_strace.h"

FILE *tracingOutputFile = NULL;

// this defines the number of characters we display for printing a string buf
#define STR_PRINT_LEN 30

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

void NaClStraceCloseFile() {
    if (tracingOutputFile != NULL && tracingOutputFile != stderr) {
        if (fclose(tracingOutputFile) != 0) perror("Error closing file");
    }
}

// replace all the line breaks in the string by "\\n" to make outputs tidy
char* formatStringArgument(const char *input) {
    if (input == NULL) {
        return NULL;
    }

    char *output = calloc(STR_PRINT_LEN + 1, sizeof(char)); // 1 for '\0'
    if (output == NULL) {
        return NULL; // Allocation failed
    }

    char *srcPtr = input;
    char *dstPtr = output;
    int dstLen = 0;

    while (*srcPtr && *srcPtr != '\0' && dstLen < STR_PRINT_LEN - 1) { 
        if (*srcPtr == '\n' && dstLen < STR_PRINT_LEN - 2) {
            *dstPtr++ = '\\';
            *dstPtr++ = 'n';
            dstLen += 2;
        } else if (*srcPtr == '\n') {
            break;
        } else {
            *dstPtr++ = *srcPtr;
            dstLen++;
        }
        srcPtr++;
    }

    return output;
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

void NaClStraceExit(int cageid, int status) {
    fprintf(tracingOutputFile, "%d exit() = %d\n", cageid, status);
}

void NaClStraceThreadExit(int cageid, pthread_t tid) {
    fprintf(tracingOutputFile, "%d thread_exit(%lu) = void\n", cageid, (unsigned long)tid);
}

void NaClStraceDup(int cageid, int oldfd, int ret){
    fprintf(tracingOutputFile, "%d dup(%d) = %d\n", cageid, oldfd, ret);
}

void NaClStraceDup2(int cageid, int oldfd, int newfd, int ret){
    fprintf(tracingOutputFile, "%d dup2(%d, %d) = %d\n", cageid, oldfd, newfd, ret);
}

void NaClStraceDup3(int cageid, int oldfd, int newfd, int flags, int ret){
    fprintf(tracingOutputFile, "%d dup3(%d, %d, %d) = %d\n", cageid, oldfd, newfd, flags, ret);
}

void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, int ret) {
    fprintf(tracingOutputFile, "%d getdents(%d, %p, %zu) = %d\n", cageid, d, drip, count, ret);
}

void NaClStracePread(int cageid, int d, void *buf, int count, off_t offset, int ret) {
    fprintf(tracingOutputFile, "%d pread(%d, %p, %d, %ld) = %d\n", cageid, d, buf, count, offset, ret);
}

void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret) {
    char *strBuf = formatStringArgument((char *)buf);
    fprintf(tracingOutputFile, "%d write(%d, \"%s\", %d) = %d\n", cageid, d, strBuf ? strBuf : "NULL", count, ret);
    free(strBuf);
}

void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval) {
    char *strBuf = formatStringArgument((char *)buf);
    fprintf(tracingOutputFile, "%d pwrite(%d, \"%s\", %d, %jd) = %d\n", cageid, d, strBuf ? strBuf : "NULL", count, (intmax_t)offset, retval);
    free(strBuf);
}

void NaClStraceLseek(int cageid, int d, uintptr_t offset, int whence, int ret) {
    fprintf(tracingOutputFile, "%d lseek(%d, 0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, d, offset, whence, ret);
}

void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret) {
    fprintf(tracingOutputFile, "%d ioctl(%d, %lu, %p) = %d\n", cageid, d, request, arg_ptr, ret);
}

void NaClStraceFstat(int cageid, int d, uintptr_t result, int retval) {
    fprintf(tracingOutputFile, "%d fstat(%d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, d, result, retval);
}
// int fstat(int fildes, struct stat *buf);
void NaClStraceStat(int cageid, char* path, uintptr_t result, int retval) {
    fprintf(tracingOutputFile, "%d stat(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, result, retval);
}

void NaClStraceLStat(int cageid, char* path, uintptr_t result, int retval) {
    fprintf(tracingOutputFile, "%d lstat(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, result, retval);
}

void NaClStraceMkdir(int cageid, char* path, int mode, int retval) {
    fprintf(tracingOutputFile, "%d mkdir(%s, %d) = %d\n", cageid, path, mode, retval);
}

void NaClStraceRmdir(int cageid, const char *path, int retval) {
    fprintf(tracingOutputFile, "%d rmdir(%s) = %d\n", cageid, path, retval);
}

void NaClStraceChdir(int cageid, const char *path, int retval) {
    fprintf(tracingOutputFile, "%d chdir(%s) = %d\n", cageid, path, retval);
}

void NaClStraceChmod(int cageid, const char *path, int mode, int retval) {
    fprintf(tracingOutputFile, "%d chmod(%s, %d) = %d\n", cageid, path, mode, retval);
}

void NaClStraceFchmod(int cageid, int fd,int mode, int retval) {
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

void NaClStraceSyncFileRange(int cageid, int fd, off_t offset, off_t nbytes, uint32_t flags, int retval) {
    fprintf(tracingOutputFile, "%d syncfilerange(%d, %ld, %ld, %u) = %d\n", cageid, fd, offset, nbytes, flags, retval);
}

void NaClStraceGetcwd(int cageid, char *buf, size_t size, int retval) {
    char *strBuf = formatStringArgument(buf);
    fprintf(tracingOutputFile, "%d getcwd(%s, %zu) = %d\n", cageid, strBuf ? strBuf : "NULL", size, retval);
    free(strBuf);
}

void NaClStraceLink(int cageid, char* from, char* to, int retval) {
    char *strBuf1 = formatStringArgument(from);
    char *strBuf2 = formatStringArgument(to);
    fprintf(tracingOutputFile, "%d link(%s, %s) = %d\n", cageid, strBuf1 ? strBuf1 : "NULL", strBuf2 ? strBuf2 : "NULL", retval);
    free(strBuf1);
    free(strBuf2);
}

void NaClStraceUnlink(int cageid, char* pathname, int retval){
    char *strBuf = formatStringArgument(pathname);
    fprintf(tracingOutputFile, "%d unlink(\"%s\") = %d\n", cageid, strBuf ? strBuf : "NULL", retval);
    free(strBuf);
}

// TODO: double check this
void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval) {
    char *strBuf1 = formatStringArgument(oldpath);
    char *strBuf2 = formatStringArgument(newpath);
    fprintf(tracingOutputFile, "%d rename(\"%s\", \"%s\") = %d\n", cageid, strBuf1 ? strBuf1 : "NULL", strBuf2 ? strBuf2 : "NULL", retval);
    free(strBuf1);
    free(strBuf2);
}

void NaClStraceMmap(int cageid, void *start, size_t length, int prot, int flags, int d, uintptr_t offset, int retval) {
    fprintf(tracingOutputFile, "%d mmap(%p, %zu, %d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, start, length, prot, flags, d, offset, retval);
}

void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length, int retval) {
   fprintf(tracingOutputFile, "%d munmap(0x%08"NACL_PRIxPTR", %zu) = %d\n", cageid, sysaddr, length, retval);
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

void NaClStraceShmctl(int cageid, int shmid, int cmd, uintptr_t bufsysaddr, int retval) {
    fprintf(tracingOutputFile, "%d shmctl(%d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, shmid, cmd, bufsysaddr, retval);
}

// void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval) {
//     fprintf(tracingOutputFile, "%d SocketPair(%d, %d, %d, %p, %p) = %d\n", cageid, domain, type, protocol, (void *)lindfds, retval);
// }
void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval) {
    fprintf(tracingOutputFile, "%d SocketPair(%d, %d, %d, [%d, %d]) = %d\n", 
            cageid, domain, type, protocol, lindfds[0], lindfds[1], retval);
}


void NaClStraceMutexCreate(int cageid, int retval) {
    fprintf(tracingOutputFile, "%d mutex_create() = %d\n", cageid, retval);
}

void NaClStraceMutexLock(int cageid, int32_t mutex_handle, int retval) {
    fprintf(tracingOutputFile, "%d mutex_lock(%d) = %d\n", cageid, mutex_handle, retval);
}

void NaClStraceMutexUnLock(int cageid, int32_t mutex_handle, int retval) {
    fprintf(tracingOutputFile, "%d mutex_unlock(%d) = %d\n", cageid, mutex_handle, retval);
}

void NaClStraceMutexTrylock(int cageid, int32_t mutex_handle, int retval) {
    fprintf(tracingOutputFile, "%d mutex_trylock(%d) = %d\n", cageid, mutex_handle, retval);
}

void NaClStraceMutexDestroy(int cageid, int32_t mutex_handle,int retval) {
    fprintf(tracingOutputFile, "%d mutex_destroy(%d) = %d\n", cageid, mutex_handle, retval);
}

void NaClStraceCondCreate(int cageid, int retval) {
    fprintf(tracingOutputFile, "%d cond_create() = %d\n", cageid, retval);
}

void NaClStraceCondWait(int cageid, int32_t cond_handle,int32_t mutex_handle,int retval) {
    fprintf(tracingOutputFile, "%d cond_wait(%d, %d) = %d\n", cageid, cond_handle, mutex_handle, retval);
}

void NaClStraceCondSignal(int cageid, int32_t cond_handle,int retval) {
    fprintf(tracingOutputFile, "%d cond_signal(%d) = %d\n", cageid, cond_handle, retval);
}

void NaClStraceCondBroadcast(int cageid, int32_t cond_handle, int retval) {
    fprintf(tracingOutputFile, "%d CondBroadcast(cond_handle=%d, retval=%d)\n", cageid, cond_handle, retval);
}

void NaClStraceCondDestroy(int cageid, int32_t cond_handle, int retval) {
    fprintf(tracingOutputFile, "%d cond_destroy(%d) = %d\n", cageid, cond_handle, retval);
}

void NaClStraceCondTimedWaitAbs(int cageid, int32_t cond_handle,int32_t mutex_handle, uintptr_t trusted_ts, int retval) {
    fprintf(tracingOutputFile, "%d cond_timedwaitabs(%d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, cond_handle, mutex_handle, trusted_ts, retval);
}  

void NaClStraceSemCreate(int cageid, int32_t init_value, int retval) {
    fprintf(tracingOutputFile, "%d sem_create(%d) = %d\n", cageid, init_value, retval);
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

void NaClStraceClockGetCommon(int cageid, int clk_id, uint32_t ts_addr, uintptr_t *time_func, int ret) {
    fprintf(tracingOutputFile, "%d clockgetcommon(%d, %u, 0x%08"NACL_PRIxPTR") = %d\n",
    cageid, clk_id, ts_addr, time_func, ret
    );
}

void NaClStracePipe2(int cageid, uint32_t *pipedes, int flags, int ret) {
    fprintf(tracingOutputFile, "%d pipe2(0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, (uintptr_t) pipedes, flags, ret);
}

void NaClStraceFork(int cageid, int ret) {
    fprintf(tracingOutputFile, "%d fork() = %d\n", cageid, ret);
}

void NaClStraceExecve(int cageid, char const *path, char *const *argv, int ret) {
    fprintf(tracingOutputFile, "%d execve(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, (uintptr_t)argv, ret);
}

void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret) {
    fprintf(tracingOutputFile, "%d execv(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, (uintptr_t) argv, ret);
}

void NaClStraceWaitpid(int cageid, int pid, uintptr_t sysaddr, int options, int ret) {
    fprintf(tracingOutputFile, "%d waitpid(%d, 0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, pid, sysaddr, options, ret);
}
// void NaClStraceWaitpid(int cageid, int pid, int *stat_loc, int options, int32_t retval) {
//     fprintf(tracingOutputFile, "%d waitpid(%d, %p, %d) = %d\n",
//             cageid, pid, (void *)stat_loc, options, retval);
// }
void NaClStraceGethostname(int cageid, char *name, size_t len, int ret) {
    char *strBuf = formatStringArgument(name);
    fprintf(tracingOutputFile, "%d gethostname(%s, %lu) = %d\n", cageid, strBuf ? strBuf : "NULL", len, ret);
    free(strBuf);
}

void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret) {
    char *strBuf = formatStringArgument(buf);
    fprintf(tracingOutputFile, "%d getifaddrs(%s, %lu) = %d\n", cageid, strBuf ? strBuf : "NULL", len, ret);
    free(strBuf);
}

void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret) {
    fprintf(tracingOutputFile, "%d socket(%d, %d, %d) = %d\n", cageid, domain, type, protocol, ret);
}

void NaClStraceSend(int cageid, int sockfd, const void *buf, size_t len, int flags, int ret) {
    fprintf(tracingOutputFile, "%d send(%d, 0x%08"NACL_PRIxPTR", %ld, %d) = %d\n", cageid, sockfd, (uintptr_t)buf, len, flags, ret);
}

void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len, int flags, uintptr_t dest_addr, socklen_t addrlen, int ret) {
    fprintf(tracingOutputFile, "%d sendto(%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, sockfd, (uintptr_t) buf, len, flags, dest_addr, addrlen, ret);
}

void NaClStraceRecv(int cageid, int sockfd, void *buf, size_t len, int flags, int ret) {
    fprintf(tracingOutputFile, "%d recv(%d, 0x%08"NACL_PRIxPTR", %ld, %d) = %d\n", cageid, sockfd, (uintptr_t)buf, len, flags, ret);
}

void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags, uintptr_t src_addr, socklen_t *addrlen, int ret) {
    fprintf(tracingOutputFile, "%d recvfrom(%d, %p"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, buf, len, flags, src_addr, (uintptr_t)addrlen, ret);
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
    fprintf(tracingOutputFile, "%d statfs(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, formatStringArgument(pathname), buf, ret);
}

void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    fprintf(tracingOutputFile, "%d getsockname(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    fprintf(tracingOutputFile, "%d getpeername(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
}

void NaClStraceAccess(int cageid, char *path, int mode, int ret) {
    char *strBuf = formatStringArgument(path);
    fprintf(tracingOutputFile, "%d access(%s, %d) = %d\n", cageid, strBuf ? strBuf : "NULL", mode, ret);
    free(strBuf);
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

void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int retval) {
    fprintf(tracingOutputFile, "%d poll(0x%08"NACL_PRIxPTR", %lu, %d) = %d\n", cageid, fds, nfds, timeout, retval);
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

void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret) {
    fprintf(tracingOutputFile, "%d select(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, nfds, readfds, writefds, exceptfds, timeout, ret);
}
