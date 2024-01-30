/*
 * Tracing functionalities will be enabled when OS environment TRACING_ENABLED = 1 
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/poll.h>
#include "native_client/src/trusted/service_runtime/nacl_syscall_strace.h"
#include <time.h>
#include <stdbool.h>
#define NUM_SYSCALLS 100 
#define SYS_MKDIR 1 
#define SYS_MMAP 2 
#define SYS_GETEUID 3
#define SYS_GETUID 4
#define SYS_READ 5
#define SYS_LSEEK 6
#define SYS_FSTAT 7
#define SYS_CLOSE 8
#define SYS_GETCWD 9
#define SYS_MUNMAP 10
#define SYS_ACCESS 11
#define SYS_OPEN 12
#define SYS_GETGID 13
#define SYS_GETEGID 14
#define SYS_SELECT 15
#define SYS_FCNTL 16
#define SYS_EPOLL_CREATE 17
#define SYS_EPOLL_CTL 18
#define SYS_EPOLL_WAIT 19
#define SYS_BIND 20
#define SYS_LISTEN 21
#define SYS_POLL 22
#define SYS_FCNTL_GET 23
#define SYS_TRUNCATE 24
#define SYS_FTRUNCATE 25
#define SYS_CONNECT 26
#define SYS_ACCEPT 27
#define SYS_FLOCK 28
#define SYS_GETSOCKOPT 29
#define SYS_SETSOCKOPT 30
#define SYS_FSTATFS 31
#define SYS_STATFS 32
#define SYS_GETSOCKNAME 33
#define SYS_GETPEERNAME 34
#define SYS_SOCKET 35
#define SYS_SEND 36
#define SYS_SENDTO 37
#define SYS_RECV 38
#define SYS_RECVFROM 39
#define SYS_SHUTDOWN 40
#define SYS_FORK 41
#define SYS_EXECVE 42
#define SYS_EXECV 43
#define SYS_WAITPID 44
#define SYS_GETHOSTNAME 45
#define SYS_GETIFADDRS 46
#define SYS_SHMAT 47
#define SYS_SHMGET 48
#define SYS_SHMDT 49
#define SYS_SHMCTL 50
#define SYS_SOCKETPAIR 51
#define SYS_NANOSLEEP 52
#define SYS_SCHEDYIELD 53
#define SYS_GETTIMEOFDAY 54
#define SYS_CLOCKGETCOMMON 55
#define SYS_LINK 56
#define SYS_UNLINK 57
#define SYS_RENAME 58
#define SYS_RMDIR 59
#define SYS_CHDIR 60
#define SYS_CHMOD 61
#define SYS_FCHMOD 62
#define SYS_FCHDIR 63
#define SYS_FSYNC 64
#define SYS_FDATASYNC 65
#define SYS_SYNC_FILE_RANGE 66
#define SYS_EXIT 67
#define SYS_DUP 68
#define SYS_DUP2 69
#define SYS_DUP3 70
#define SYS_GETDENTS 71
#define SYS_PREAD 72
#define SYS_WRITE 73
#define SYS_PWRITE 74
#define SYS_IOCTL 75
#define SYS_LSTAT 76
#define SYS_STAT 77
#define SYS_GETPID 78
#define SYS_GETPPID 79

long long gettimens() {
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (long long)tp.tv_sec * 1000000000LL + tp.tv_nsec;
}
FILE *tracingOutputFile = NULL;
long long totalSyscallsTime = 0; // Total time for all syscalls

typedef struct {
    long long count;      // Number of times the syscall was called
    long long totalTime;  // Total time spent in the syscall (in nanoseconds)
    long long errorCount; // Number of errors encountered in the syscall
} SyscallStats;
long long totalSyscallsMicroseconds = 0; // Total time for all syscalls (in microseconds)
int totalSyscallsCount = 0;

SyscallStats syscallStats[NUM_SYSCALLS];
 

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
    //ifdef dashC, do the format prints
    if (tracingOutputFile != NULL && tracingOutputFile != stderr) {
        #ifdef TRACING_DASHC
        printFinalSyscallStats(); // Print the final statistics
        #endif
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
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETPID].count++;
    syscallStats[SYS_GETPID].totalTime += (endTime - startTime);
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getpid() = %d\n", cageid, pid);
    #endif
}

void NaClStraceGetppid(int cageid, int pid) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETPPID].count++;
    syscallStats[SYS_GETPPID].totalTime += (endTime - startTime);
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getppid() = %d\n", cageid, pid);
    #endif
}


void NaClStraceOpen(int cageid, char* path, int flags, int mode, int fd) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_OPEN].count++;
    syscallStats[SYS_OPEN].totalTime += endTime - startTime;
    if (fd < 0) {
        syscallStats[SYS_OPEN].errorCount++;
    }
    #endif
    #ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d open(%s, %d, %d) = %d\n", cageid, path, flags, mode, fd);
    #endif

}

void NaClStraceClose(int cageid, int d, int ret) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_CLOSE].count++;
    syscallStats[SYS_CLOSE].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_CLOSE].errorCount++;
    }
    
#endif
#ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d close(%d) = %d\n", cageid, d, ret);
#endif
}

void NaClStraceRead(int cageid, int d, void *buf, size_t count, int ret) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_READ].count++;
    syscallStats[SYS_READ].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_READ].errorCount++;
    }
#endif
#ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d read(%d, %p, %zu) = %d\n", cageid, d, buf, count, ret);
#endif
}


void NaClStraceExit(int cageid, int status) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_EXIT].count++;
    syscallStats[SYS_EXIT].totalTime += (endTime - startTime);
    if (status != 0) {
        syscallStats[SYS_EXIT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d exit() = %d\n", cageid, status);
    #endif
}

void NaClStraceDup(int cageid, int oldfd, int ret){
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_DUP].count++;
    syscallStats[SYS_DUP].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_DUP].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d dup(%d) = %d\n", cageid, oldfd, ret);
    #endif
}

void NaClStraceDup2(int cageid, int oldfd, int newfd, int ret){
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_DUP2].count++;
    syscallStats[SYS_DUP2].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_DUP2].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d dup2(%d, %d) = %d\n", cageid, oldfd, newfd, ret);
    #endif
}

void NaClStraceDup3(int cageid, int oldfd, int newfd, int flags, int ret){
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_DUP3].count++;
    syscallStats[SYS_DUP3].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_DUP3].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d dup3(%d, %d, %d) = %d\n", cageid, oldfd, newfd, flags, ret);
    #endif
}

void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETDENTS].count++;
    syscallStats[SYS_GETDENTS].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETDENTS].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getdents(%d, %p, %zu) = %d\n", cageid, d, drip, count, ret);
    #endif
}

void NaClStracePread(int cageid, int d, void *buf, int count, off_t offset, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_PREAD].count++;
    syscallStats[SYS_PREAD].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_PREAD].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d pread(%d, %p, %d, %ld) = %d\n", cageid, d, buf, count, offset, ret);
    #endif
}

void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_WRITE].count++;
    syscallStats[SYS_WRITE].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_WRITE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf = formatStringArgument((char *)buf);
    fprintf(tracingOutputFile, "%d write(%d, \"%s\", %d) = %d\n", cageid, d, strBuf ? strBuf : "NULL", count, ret);
    free(strBuf);
    #endif
}

void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_PWRITE].count++;
    syscallStats[SYS_PWRITE].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_PWRITE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf = formatStringArgument((char *)buf);
    fprintf(tracingOutputFile, "%d pwrite(%d, \"%s\", %d, %lld) = %d\n", cageid, d, strBuf ? strBuf : "NULL", count, (intmax_t)offset, retval);
    free(strBuf);
    #endif
}

void NaClStraceLseek(int cageid, int d, uintptr_t offset, int whence, int ret) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_LSEEK].count++;
    syscallStats[SYS_LSEEK].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_LSEEK].errorCount++;
    }
#endif
#ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d lseek(%d, 0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, d, offset, whence, ret);
#endif
}

void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_IOCTL].count++;
    syscallStats[SYS_IOCTL].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_IOCTL].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d ioctl(%d, %lu, %p) = %d\n", cageid, d, request, arg_ptr, ret);
    #endif
}

void NaClStraceFstat(int cageid, int d, uintptr_t result, int32_t retval) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_FSTAT].count++;
    syscallStats[SYS_FSTAT].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_FSTAT].errorCount++;
    }
#endif
#ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d fstat(%d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, d, result, retval);
#endif
}

void NaClStraceStat(int cageid, char* path, uintptr_t result, int32_t retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_STAT].count++;
    syscallStats[SYS_STAT].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_STAT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d stat(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, result, retval);
    #endif
}

void NaClStraceLStat(int cageid, char* path, uintptr_t result, int32_t retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_LSTAT].count++;
    syscallStats[SYS_LSTAT].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_LSTAT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d lstat(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, result, retval);
    #endif
}

//test totaltime
void NaClStraceMkdir(int cageid, const char *path, int mode, int retval, long long totaltime) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    long long elapsedTime = endTime - startTime;  // Time for this call in nanoseconds
    syscallStats[SYS_MKDIR].count++;
    syscallStats[SYS_MKDIR].totalTime += elapsedTime;
    totalSyscallsTime += elapsedTime; // Update total time for all syscalls
    if (retval < 0) {
        syscallStats[SYS_MKDIR].errorCount++;
    }
    totalSyscallsCount++;
    totalSyscallsMicroseconds += elapsedTime / 1000; // Convert nanoseconds to microseconds


    // Calculate and print individual syscall stats for mkdir
    double totalTimeInSeconds = (double)syscallStats[SYS_MKDIR].totalTime / 1000000000.0;
    double avgTimePerCallInMicroseconds = syscallStats[SYS_MKDIR].count > 0 
                                         ? (double)syscallStats[SYS_MKDIR].totalTime / syscallStats[SYS_MKDIR].count / 1000.0
                                         : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / (totalSyscallsTime / 1000000000.0);
    
    long long totalCalls = 0, totalErrors = 0;
    double totalSeconds = 0.0;
    long long totalMicroseconds = 0; // To store the total microseconds for all syscalls

    for (int i = 0; i < NUM_SYSCALLS; i++) {
        totalCalls += syscallStats[i].count;
        totalErrors += syscallStats[i].errorCount;
        totalSeconds += syscallStats[i].totalTime / 1000000000.0;
    
        // Add the total time (in microseconds) for each syscall
        totalMicroseconds += syscallStats[i].totalTime / 1000;
    }

    long long avgMicrosecondsPerCall = totalCalls > 0 ? totalMicroseconds / totalCalls : 0;
    


    #endif


    fprintf("%d total time",totaltime);
    fprintf(tracingOutputFile, "%d mkdir(%s, %d) = %d\n", cageid, path, mode, retval);


}


void printFinalSyscallStats() {
    #ifdef TRACING_DASHC
    fprintf(tracingOutputFile, "%% time     seconds  usecs/call     calls    errors syscall\n");
    fprintf(tracingOutputFile, "------ ----------- ----------- --------- --------- ----------------\n");

    long long totalCalls = 0, totalErrors = 0;
    double totalSeconds = 0.0;

    for (int i = 0; i < NUM_SYSCALLS; i++) {
        if (syscallStats[i].count > 0) {
            double totalTimeInSeconds = (double)syscallStats[i].totalTime / 1000000000.0;
            long long avgTimePerCallInMicroseconds = syscallStats[i].count > 0 
                                                     ? syscallStats[i].totalTime / syscallStats[i].count / 1000 
                                                     : 0;
            fprintf(tracingOutputFile, "100.00    %.9f   %lld        %lld       %lld       %s\n", 
                    totalTimeInSeconds, avgTimePerCallInMicroseconds, syscallStats[i].count, syscallStats[i].errorCount, getSyscallName(i));
            totalCalls += syscallStats[i].count;
            totalErrors += syscallStats[i].errorCount;
            totalSeconds += totalTimeInSeconds;
        }
    }

    // Print the total summary line
    fprintf(tracingOutputFile, "------ ----------- ----------- --------- --------- ----------------\n");
    fprintf(tracingOutputFile, "100.00    %.9f      0       %lld       %lld            total\n", 
            totalSeconds, totalCalls, totalErrors);
    #endif
}

// Helper function to get syscall name from its index
const char* getSyscallName(int syscallIndex) {
    switch (syscallIndex) {
        case SYS_MKDIR:
            return "mkdir";
        case SYS_MMAP:
            return "mmap";
        case SYS_GETEUID:
            return "geteuid";
        case SYS_GETUID:
            return "getuid";
        case SYS_READ:
            return "read";
        case SYS_LSEEK:
            return "lseek";
        case SYS_FSTAT:
            return "fstat";
        case SYS_CLOSE:
            return "close";
        case SYS_GETCWD:
            return "getcwd";
        case SYS_MUNMAP:
            return "munmap";
        case SYS_ACCESS:
            return "access";
        case SYS_OPEN:
            return "open";    
        case SYS_GETGID:
            return "getgid";
        case SYS_GETEGID:
            return "getegid";
        case SYS_SELECT:
            return "select";
        case SYS_EPOLL_CREATE:
            return "epoll_create";
        case SYS_EPOLL_CTL:
            return "epoll_ctl";
        case SYS_EPOLL_WAIT:
            return "epoll_wait";
        case SYS_BIND:
            return "bind";
        case SYS_LISTEN:
            return "listen";
        case SYS_POLL:
            return "poll";
        case SYS_FCNTL_GET:
            return "fcntl_get";
        case SYS_TRUNCATE:
            return "truncate";
        case SYS_FTRUNCATE:
            return "ftruncate";
        case SYS_CONNECT:
            return "connect";
        case SYS_ACCEPT:
            return "accept";
        case SYS_FLOCK:
            return "flock";
        case SYS_GETSOCKOPT:
            return "getsockopt";
        case SYS_SETSOCKOPT:
            return "setsockopt";
        case SYS_FSTATFS:
            return "fstatfs";
        case SYS_STATFS:
            return "statfs";
        case SYS_GETSOCKNAME:
            return "getsockname";
        case SYS_GETPEERNAME:
            return "getpeername";
        case SYS_SOCKET:
            return "socket";
        case SYS_SEND:
            return "send";
        case SYS_SENDTO:
            return "sendto";
        case SYS_RECV:
            return "recv";
        case SYS_RECVFROM:
            return "recvfrom";
        case SYS_SHMAT:
            return "shmat";
        case SYS_SHMGET:
            return "shmget";
        case SYS_SHMDT:
            return "shmdt";
        case SYS_SHMCTL:
            return "shmctl";
        case SYS_SOCKETPAIR:
            return "socketpair";
        case SYS_NANOSLEEP:
            return "nanosleep";
        case SYS_GETTIMEOFDAY:
            return "gettimeofday";
        case SYS_LINK:
            return "link";
        case SYS_UNLINK:
            return "unlink";
        case SYS_RENAME:
            return "rename";
        case SYS_RMDIR:
            return "rmdir";
        case SYS_CHDIR:
            return "chdir";
        case SYS_CHMOD:
            return "chmod";
        case SYS_FCHMOD:
            return "fchmod";
        case SYS_FCHDIR:
            return "fchdir";
        case SYS_FSYNC:
            return "fsync";
        case SYS_FDATASYNC:
            return "fdatasync";
        case SYS_SYNC_FILE_RANGE:
            return "syncfilerange";
        case SYS_EXIT:
            return "exit";
        case SYS_DUP:
            return "dup";
        case SYS_DUP2:
            return "dup2";
        case SYS_DUP3:
            return "dup3";
        case SYS_GETDENTS:
            return "getdents";
        case SYS_PREAD:
            return "pread";
        case SYS_WRITE:
            return "write";
        case SYS_PWRITE:
            return "pwrite";
        case SYS_IOCTL:
            return "ioctl";
        case SYS_LSTAT:
            return "lstat";
        case SYS_STAT:
            return "stat";
        case SYS_GETPID:
            return "getpid";
        case SYS_GETPPID:
            return "getppid";
        default:
            return "unknown";
    }
}



void NaClStraceRmdir(int cageid, const char *path, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_RMDIR].count++;
    syscallStats[SYS_RMDIR].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_RMDIR].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d rmdir(%s) = %d\n", cageid, path, retval);
    #endif
}

void NaClStraceChdir(int cageid, const char *path, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_CHDIR].count++;
    syscallStats[SYS_CHDIR].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_CHDIR].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d chdir(%s) = %d\n", cageid, path, retval);
    #endif
}

void NaClStraceChmod(int cageid, const char *path, int mode, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_CHMOD].count++;
    syscallStats[SYS_CHMOD].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_CHMOD].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d chmod(%s, %d) = %d\n", cageid, path, mode, retval);
    #endif
}

void NaClStraceFchmod(int cageid, int fd, int mode, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FCHMOD].count++;
    syscallStats[SYS_FCHMOD].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_FCHMOD].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fchmod(%d, %d) = %d\n", cageid, fd, mode, retval);
    #endif
}

void NaClStraceFchdir(int cageid, int fd, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    
    long long endTime = gettimens();
    syscallStats[SYS_FCHDIR].count++;
    syscallStats[SYS_FCHDIR].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_FCHDIR].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fchdir(%d) = %d\n", cageid, fd, retval);
    #endif
}

void NaClStraceFsync(int cageid, int fd, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FSYNC].count++;
    syscallStats[SYS_FSYNC].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FSYNC].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fsync(%d) = %d\n", cageid, fd, ret);
    #endif
}

void NaClStraceFdatasync(int cageid, int fd, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FDATASYNC].count++;
    syscallStats[SYS_FDATASYNC].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FDATASYNC].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fdatasync(%d) = %d\n", cageid, fd, ret);
    #endif
}

void NaClStraceSyncFileRange(int cageid, int fd, off_t offset, off_t nbytes, uint32_t flags, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SYNC_FILE_RANGE].count++;
    syscallStats[SYS_SYNC_FILE_RANGE].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_SYNC_FILE_RANGE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d syncfilerange(%d, %ld, %ld, %u) = %d\n", cageid, fd, offset, nbytes, flags, retval);
    #endif
}

void NaClStraceGetcwd(int cageid, char *buf, size_t size, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETCWD].count++;
    syscallStats[SYS_GETCWD].totalTime += endTime - startTime;
    if (retval < 0) {
        syscallStats[SYS_GETCWD].errorCount++;
    }
    #endif
#ifdef TRACING_INDIVIDUAL_CALLS

    char *strBuf = formatStringArgument(buf);
    fprintf(tracingOutputFile, "%d getcwd(%s, %zu) = %d\n", cageid, strBuf ? strBuf : "NULL", size, retval);
    free(strBuf);
#endif

}
void NaClStraceLink(int cageid, char* from, char* to, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    
    long long endTime = gettimens();
    syscallStats[SYS_LINK].count++;
    syscallStats[SYS_LINK].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_LINK].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf1 = formatStringArgument(from);
    char *strBuf2 = formatStringArgument(to);
    fprintf(tracingOutputFile, "%d link(%s, %s) = %d\n", cageid, strBuf1 ? strBuf1 : "NULL", strBuf2 ? strBuf2 : "NULL", retval);
    free(strBuf1);
    free(strBuf2);
    #endif
}

void NaClStraceUnlink(int cageid, char* pathname, int retval){
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_UNLINK].count++;
    syscallStats[SYS_UNLINK].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_UNLINK].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf = formatStringArgument(pathname);
    fprintf(tracingOutputFile, "%d unlink(\"%s\") = %d\n", cageid, strBuf ? strBuf : "NULL", retval);
    free(strBuf);
    #endif
}

void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_RENAME].count++;
    syscallStats[SYS_RENAME].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_RENAME].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf1 = formatStringArgument(oldpath);
    char *strBuf2 = formatStringArgument(newpath);
    fprintf(tracingOutputFile, "%d rename(\"%s\", \"%s\") = %d\n", cageid, strBuf1 ? strBuf1 : "NULL", strBuf2 ? strBuf2 : "NULL", retval);
    free(strBuf1);
    free(strBuf2);
    #endif
}


void NaClStraceMmap(int cageid, void *start, size_t length, int prot, int flags, int d, uintptr_t offset, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    long long elapsedTime = endTime - startTime;
    syscallStats[SYS_MMAP].count++;
    syscallStats[SYS_MMAP].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[SYS_MMAP].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[SYS_MMAP].totalTime / 1000000000.0;
    long long avgTimePerCallInMicroseconds = syscallStats[SYS_MMAP].count > 0 
                                         ? syscallStats[SYS_MMAP].totalTime / syscallStats[SYS_MMAP].count / 1000
                                         : 0;
    double percentTime = 100.0 * totalTimeInSeconds / (totalSyscallsTime / 1000000000.0);

    
    #endif
#ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d mmap(%p, %zu, %d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, start, length, prot, flags, d, offset, retval);
#endif

}


void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_MUNMAP].count++;
    syscallStats[SYS_MUNMAP].totalTime += endTime - startTime;
    if (retval < 0) {
        syscallStats[SYS_MUNMAP].errorCount++;
    }
    #endif
#ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d munmap(0x%08"NACL_PRIxPTR", %zu) = %d\n", cageid, sysaddr, length, retval);
#endif    
}
void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SHMAT].count++;
    syscallStats[SYS_SHMAT].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_SHMAT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d shmat(%d, %p, %d) = %d\n", cageid, shmid, shmaddr, shmflg, retval);
    #endif
}

void NaClStraceShmget(int cageid, int key, size_t size, int shmflg, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SHMGET].count++;
    syscallStats[SYS_SHMGET].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_SHMGET].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d shmget(%d, %zu, %d) = %d\n", cageid, key, size, shmflg, retval);
    #endif
}

void NaClStraceShmdt(int cageid, void *shmaddr, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SHMDT].count++;
    syscallStats[SYS_SHMDT].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_SHMDT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d shmdt(%p) = %d\n", cageid, shmaddr, retval);
    #endif
}

void NaClStraceShmctl(int cageid, int shmid, int cmd, uintptr_t bufsysaddr, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SHMCTL].count++;
    syscallStats[SYS_SHMCTL].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_SHMCTL].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d shmctl(%d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, shmid, cmd, bufsysaddr, retval);
    #endif
}

void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SOCKETPAIR].count++;
    syscallStats[SYS_SOCKETPAIR].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_SOCKETPAIR].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d socketpair(%d, %d, %d, %p, %p) = %d\n", cageid, domain, type, protocol, (void *)lindfds, retval);
    #endif
}

void NaClStraceNanosleep(int cageid, uintptr_t req, uintptr_t rem, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    
    // ... original nanosleep functionality ...

    long long endTime = gettimens();
    syscallStats[SYS_NANOSLEEP].count++;
    syscallStats[SYS_NANOSLEEP].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_NANOSLEEP].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d nanosleep(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, req, rem, ret);
    #endif
}

void NaClStraceSchedYield(int cageid, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SCHEDYIELD].count++;
    syscallStats[SYS_SCHEDYIELD].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SCHEDYIELD].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d schedyield() = %d\n", cageid, ret);
    #endif
}

void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETTIMEOFDAY].count++;
    syscallStats[SYS_GETTIMEOFDAY].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETTIMEOFDAY].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d gettimeofday(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, tv, tz, ret);
    #endif
}

void NaClStraceClockGetCommon(int cageid, int clk_id, uint32_t ts_addr, uintptr_t *time_func, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_CLOCKGETCOMMON].count++;
    syscallStats[SYS_CLOCKGETCOMMON].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_CLOCKGETCOMMON].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d clockgetcommon(%d, %u, 0x%08"NACL_PRIxPTR") = %d\n", cageid, clk_id, ts_addr, time_func, ret);
    #endif
}

void NaClStraceFork(int cageid, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FORK].count++;
    syscallStats[SYS_FORK].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FORK].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fork() = %d\n", cageid, ret);
    #endif
}

void NaClStraceExecve(int cageid, char const *path, char *const *argv, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_EXECVE].count++;
    syscallStats[SYS_EXECVE].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_EXECVE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d execve(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, (uintptr_t)argv, ret);
    #endif
}

void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_EXECV].count++;
    syscallStats[SYS_EXECV].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_EXECV].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d execv(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, path, (uintptr_t) argv, ret);
    #endif
}

void NaClStraceWaitpid(int cageid, int pid, uintptr_t sysaddr, int options, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_WAITPID].count++;
    syscallStats[SYS_WAITPID].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_WAITPID].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d waitpid(%d, 0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, pid, sysaddr, options, ret);
    #endif
}

void NaClStraceGethostname(int cageid, char *name, size_t len, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETHOSTNAME].count++;
    syscallStats[SYS_GETHOSTNAME].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETHOSTNAME].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf = formatStringArgument(name);
    fprintf(tracingOutputFile, "%d gethostname(%s, %lu) = %d\n", cageid, strBuf ? strBuf : "NULL", len, ret);
    free(strBuf);
    #endif
}

void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETIFADDRS].count++;
    syscallStats[SYS_GETIFADDRS].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETIFADDRS].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    char *strBuf = formatStringArgument(buf);
    fprintf(tracingOutputFile, "%d getifaddrs(%s, %lu) = %d\n", cageid, strBuf ? strBuf : "NULL", len, ret);
    free(strBuf);
    #endif
}

void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SOCKET].count++;
    syscallStats[SYS_SOCKET].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SOCKET].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d socket(%d, %d, %d) = %d\n", cageid, domain, type, protocol, ret);
    #endif
}

void NaClStraceSend(int cageid, int sockfd, const void *buf, size_t len, int flags, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SEND].count++;
    syscallStats[SYS_SEND].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SEND].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d send(%d, 0x%08"NACL_PRIxPTR", %ld, %d) = %d\n", cageid, sockfd, (uintptr_t)buf, len, flags, ret);
    #endif
}

void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len, int flags, uintptr_t dest_addr, socklen_t addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SENDTO].count++;
    syscallStats[SYS_SENDTO].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SENDTO].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d sendto(%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d) = %d\n", cageid, sockfd, (uintptr_t) buf, len, flags, dest_addr, addrlen, ret);
    #endif
}

void NaClStraceRecv(int cageid, int sockfd, void *buf, size_t len, int flags, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_RECV].count++;
    syscallStats[SYS_RECV].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_RECV].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d recv(%d, 0x%08"NACL_PRIxPTR", %ld, %d) = %d\n", cageid, sockfd, (uintptr_t)buf, len, flags, ret);
    #endif
}

void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags, uintptr_t src_addr, socklen_t *addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_RECVFROM].count++;
    syscallStats[SYS_RECVFROM].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_RECVFROM].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d recvfrom(%d, %p"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, buf, len, flags, src_addr, (uintptr_t)addrlen, ret);
    #endif
}

void NaClStraceShutdown(int cageid, int sockfd, int how, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SHUTDOWN].count++;
    syscallStats[SYS_SHUTDOWN].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SHUTDOWN].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d shutdown(%d, %d) = %d\n", cageid, sockfd, how, ret);
    #endif
}


void NaClStraceGetuid(int cageid, int ret) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    long long elapsedTime = endTime - startTime;
    syscallStats[SYS_GETUID].count++;
    syscallStats[SYS_GETUID].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[SYS_GETUID].errorCount++;
    }
#endif
#ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d getuid() = %d\n", cageid, ret);
#endif
}


void NaClStraceGeteuid(int cageid, int ret) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    long long elapsedTime = endTime - startTime;
    syscallStats[SYS_GETEUID].count++;
    syscallStats[SYS_GETEUID].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[SYS_GETEUID].errorCount++;
    }
#endif
#ifdef TRACING_INDIVIDUAL_CALLS

    // Print the syscall information
    fprintf(tracingOutputFile, "%d geteuid() = %d\n", cageid, ret);
#endif
}


void NaClStraceGetgid(int cageid, int ret) {
#ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_GETGID].count++;
    syscallStats[SYS_GETGID].totalTime += endTime - startTime;
    if (ret < 0) {
        syscallStats[SYS_GETGID].errorCount++;
    }
#endif
#ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getgid() = %d\n", cageid, ret);
#endif
}


void NaClStraceGetegid(int cageid, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();


    long long endTime = gettimens();
    syscallStats[SYS_GETEGID].count++;
    syscallStats[SYS_GETEGID].totalTime += endTime - startTime;
    if (ret < 0) {
        syscallStats[SYS_GETEGID].errorCount++;
    }
    #endif
    #ifdef TRACING_INDIVIDUAL_CALLS

    fprintf(tracingOutputFile, "%d getegid() = %d\n", cageid, ret);
    #endif

}

void NaClStraceFlock(int cageid, int fd, int operation, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FLOCK].count++;
    syscallStats[SYS_FLOCK].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FLOCK].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d flock(%d, %d) = %d\n", cageid, fd, operation, ret);
    #endif
}

void NaClStraceGetsockopt(int cageid, int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETSOCKOPT].count++;
    syscallStats[SYS_GETSOCKOPT].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETSOCKOPT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, level, optname, (uintptr_t)optval, (uintptr_t)optlen, ret);
    #endif
}

void NaClStraceSetsockopt(int cageid, int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SETSOCKOPT].count++;
    syscallStats[SYS_SETSOCKOPT].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SETSOCKOPT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d setsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", %u) = %d\n", cageid, sockfd, level, optname, (uintptr_t)optval, optlen, ret);
    #endif
}

void NaClStraceFstatfs(int cageid, int d, uintptr_t buf, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FSTATFS].count++;
    syscallStats[SYS_FSTATFS].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FSTATFS].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fstatfs(%d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, d, buf, ret);
    #endif
}

void NaClStraceStatfs(int cageid, const char *pathname, uintptr_t buf, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_STATFS].count++;
    syscallStats[SYS_STATFS].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_STATFS].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d statfs(%s, 0x%08"NACL_PRIxPTR") = %d\n", cageid, formatStringArgument(pathname), buf, ret);
    #endif
}

void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETSOCKNAME].count++;
    syscallStats[SYS_GETSOCKNAME].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETSOCKNAME].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getsockname(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
    #endif
}

void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t * addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_GETPEERNAME].count++;
    syscallStats[SYS_GETPEERNAME].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_GETPEERNAME].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d getpeername(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
    #endif
}

void NaClStraceAccess(int cageid, char *path, int mode, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();

    // ... original access functionality ...

    long long endTime = gettimens();
    syscallStats[SYS_ACCESS].count++;
    syscallStats[SYS_ACCESS].totalTime += endTime - startTime;
    if (ret < 0) {
        syscallStats[SYS_ACCESS].errorCount++;
    }
    #endif
#ifdef TRACING_INDIVIDUAL_CALLS

    char *strBuf = formatStringArgument(path);
    fprintf(tracingOutputFile, "%d access(%s, %d) = %d\n", cageid, strBuf ? strBuf : "NULL", mode, ret);
    free(strBuf);
#endif

}
void NaClStraceTruncate(int cageid, uint32_t path, int length, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_TRUNCATE].count++;
    syscallStats[SYS_TRUNCATE].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_TRUNCATE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d truncate(%u, %d) = %d\n", cageid, path, length, ret);
    #endif
}

void NaClStraceFtruncate(int cageid, int fd, int length, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FTRUNCATE].count++;
    syscallStats[SYS_FTRUNCATE].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FTRUNCATE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d ftruncate(%d, %d) = %d\n", cageid, fd, length, ret);
    #endif
}

void NaClStraceConnect(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_CONNECT].count++;
    syscallStats[SYS_CONNECT].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_CONNECT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d connect(%d, 0x%08"NACL_PRIxPTR", %u) = %d\n", cageid, sockfd, addr, addrlen, ret);
    #endif
}

void NaClStraceAccept(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_ACCEPT].count++;
    syscallStats[SYS_ACCEPT].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_ACCEPT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d accept(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret);
    #endif
}

void NaClStraceBind(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_BIND].count++;
    syscallStats[SYS_BIND].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_BIND].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d bind(%d, 0x%08"NACL_PRIxPTR", %u) = %d\n", cageid, sockfd, addr, addrlen, ret);
    #endif
}

void NaClStraceListen(int cageid, int sockfd, int backlog, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_LISTEN].count++;
    syscallStats[SYS_LISTEN].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_LISTEN].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d listen(%d, %d) = %d\n", cageid, sockfd, backlog, ret);
    #endif
}

void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int retval) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_POLL].count++;
    syscallStats[SYS_POLL].totalTime += (endTime - startTime);
    if (retval < 0) {
        syscallStats[SYS_POLL].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d poll(0x%08"NACL_PRIxPTR", %lu, %d) = %d\n", cageid, fds, nfds, timeout, retval);
    #endif
}

void NaClStraceFcntlGet(int cageid, int fd, int cmd, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_FCNTL_GET].count++;
    syscallStats[SYS_FCNTL_GET].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FCNTL_GET].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fcntlget(%d, %d) = %d\n", cageid, fd, cmd, ret);
    #endif
}

void NaClStraceFcntlSet(int cageid, int fd, int cmd, long set_op, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    
    long long endTime = gettimens();
    syscallStats[SYS_FCNTL].count++;
    syscallStats[SYS_FCNTL].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_FCNTL].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d fcntlset(%d, %d, %ld) = %d\n", cageid, fd, cmd, set_op, ret);
    #endif
}

void NaClStraceEpollCreate(int cageid, int size, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_EPOLL_CREATE].count++;
    syscallStats[SYS_EPOLL_CREATE].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_EPOLL_CREATE].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d epollcreate(%d) = %d\n", cageid, size, ret);
    #endif
}

void NaClStraceEpollCtl(int cageid, int epfd, int op, int fd, uintptr_t event, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_EPOLL_CTL].count++;
    syscallStats[SYS_EPOLL_CTL].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_EPOLL_CTL].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d epollctl(%d, %d, %d, 0x%08"NACL_PRIxPTR") = %d\n", cageid, epfd, op, fd, event, ret);
    #endif
}

void NaClStraceEpollWait(int cageid, int epfd, uintptr_t events, int maxevents, int timeout, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_EPOLL_WAIT].count++;
    syscallStats[SYS_EPOLL_WAIT].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_EPOLL_WAIT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d epollwait(%d, 0x%08"NACL_PRIxPTR", %d, %d) = %d\n", cageid, epfd, events, maxevents, timeout, ret);
    #endif
}

void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret) {
    #ifdef TRACING_DASHC
    long long startTime = gettimens();
    

    long long endTime = gettimens();
    syscallStats[SYS_SELECT].count++;
    syscallStats[SYS_SELECT].totalTime += (endTime - startTime);
    if (ret < 0) {
        syscallStats[SYS_SELECT].errorCount++;
    }
    #endif
    
    #ifdef TRACING_INDIVIDUAL_CALLS
    fprintf(tracingOutputFile, "%d select(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d\n", cageid, nfds, readfds, writefds, exceptfds, timeout, ret);
    #endif
}
