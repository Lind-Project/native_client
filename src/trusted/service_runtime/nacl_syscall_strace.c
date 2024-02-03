/*
 * Tracing functionalities will be enabled when OS environment TRACING_ENABLED = 1 
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/poll.h>
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_strace.h"
#include <time.h>
#include <stdbool.h>
#define NUM_SYSCALLS 200 


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
int strace_c = 0;

static long long totalMkdirTime = 0;
static long long totalLstatTime = 0;
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

void NaClStraceGetpid(int cageid, int pid, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getpid].count++;
    syscallStats[NACL_sys_getpid].totalTime += elapsedTime;

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getpid].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getpid].count > 0 
                                     ? (double)syscallStats[NACL_sys_getpid].totalTime / syscallStats[NACL_sys_getpid].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d getpid() = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, pid, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceGetppid(int cageid, int pid, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getppid].count++;
    syscallStats[NACL_sys_getppid].totalTime += elapsedTime;

    // Calculate and print individual syscall stats for getppid
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getppid].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getppid].count > 0 
                                     ? (double)syscallStats[NACL_sys_getppid].totalTime / syscallStats[NACL_sys_getppid].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_getppid() = %d (Total time: %.9f seconds)\n", cageid, pid, (double)elapsedTime / 1000000000.0);
    }
}



void NaClStraceOpen(int cageid, char* path, int flags, int mode, int fd, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_open].count++;
    syscallStats[NACL_sys_open].totalTime += elapsedTime;
    if (fd < 0) {
        syscallStats[NACL_sys_open].errorCount++;
    }

    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for open
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_open].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_open].count > 0 
                                     ? (double)syscallStats[NACL_sys_open].totalTime / syscallStats[NACL_sys_open].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    
    char *strBuf = formatStringArgument(path);
    if (strace_c) {
        // Print detailed information for each syscall when strace_c is enabled
        fprintf(tracingOutputFile, "%d NACL_sys_open(%s, %d, %d) = %d (Total time: %.9f seconds)\n", cageid, strBuf ? strBuf : "NULL", flags, mode, fd, (double)elapsedTime / 1000000000.0);
    }
    free(strBuf);
   
}


void NaClStraceClose(int cageid, int d, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_close].count++;
    syscallStats[NACL_sys_close].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_close].errorCount++;
    }

    // Calculate and print individual syscall stats for close
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_close].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_close].count > 0 
                                     ? (double)syscallStats[NACL_sys_close].totalTime / syscallStats[NACL_sys_close].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_close(%d) = %d (Total time: %.9f seconds)\n", cageid, d, ret, (double)elapsedTime / 1000000000.0);
    }
}


void NaClStraceRead(int cageid, int d, void *buf, size_t count, int ret, long long time) {
#ifdef TRACING_DASHC
    syscallStats[NACL_sys_read].count++;
    syscallStats[NACL_sys_read].totalTime += time;
    if (ret < 0) {
        syscallStats[NACL_sys_read].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)time / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for read
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_read].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_read].count > 0 
                                     ? (double)syscallStats[NACL_sys_read].totalTime / syscallStats[NACL_sys_read].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
#endif
    
if (strace_c) {
    fprintf(tracingOutputFile, "%d read(%d, %p, %zu) = %d (Total time: %.9f seconds)\n", cageid, d, buf, count, ret, (double)time / 1000000000.0);
}
}


void NaClStraceExit(int cageid, int status, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_exit].count++;
    syscallStats[NACL_sys_exit].totalTime += elapsedTime;
    if (status != 0) {
        syscallStats[NACL_sys_exit].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for exit
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_exit].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_exit].count > 0 
                                     ? (double)syscallStats[NACL_sys_exit].totalTime / syscallStats[NACL_sys_exit].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {    fprintf(tracingOutputFile, "%d NACL_sys_exit() = %d (Total time: %.9f seconds)\n", cageid, status, (double)elapsedTime / 1000000000.0);
}}


void NaClStraceDup(int cageid, int oldfd, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_dup].count++;
    syscallStats[NACL_sys_dup].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_dup].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for dup
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_dup].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_dup].count > 0 
                                     ? (double)syscallStats[NACL_sys_dup].totalTime / syscallStats[NACL_sys_dup].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_dup(%d) = %d (Total time: %.9f seconds)\n", cageid, oldfd, ret, (double)elapsedTime / 1000000000.0);
    }
}

void NaClStraceDup2(int cageid, int oldfd, int newfd, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_dup2].count++;
    syscallStats[NACL_sys_dup2].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_dup2].errorCount++;
    }

    // Calculate and print individual syscall stats for dup2
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_dup2].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_dup2].count > 0 
                                     ? (double)syscallStats[NACL_sys_dup2].totalTime / syscallStats[NACL_sys_dup2].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_dup2(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, oldfd, newfd, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceDup3(int cageid, int oldfd, int newfd, int flags, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_dup3].count++;
    syscallStats[NACL_sys_dup3].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_dup3].errorCount++;
    }

    // Calculate and print individual syscall stats for dup3
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_dup3].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_dup3].count > 0 
                                     ? (double)syscallStats[NACL_sys_dup3].totalTime / syscallStats[NACL_sys_dup3].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_dup3(%d, %d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, oldfd, newfd, flags, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceGetdents(int cageid, int d, void *drip, size_t count, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getdents].count++;
    syscallStats[NACL_sys_getdents].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getdents].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getdents].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getdents].count > 0 
                                     ? (double)syscallStats[NACL_sys_getdents].totalTime / syscallStats[NACL_sys_getdents].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_getdents(%d, %p, %zu) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, d, drip, count, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStracePread(int cageid, int d, void *buf, int count, off_t offset, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_pread].count++;
    syscallStats[NACL_sys_pread].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_pread].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_pread].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_pread].count > 0 
                                     ? (double)syscallStats[NACL_sys_pread].totalTime / syscallStats[NACL_sys_pread].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_pread(%d, %p, %d, %ld) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, d, buf, count, offset, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceWrite(int cageid, int d, void *buf, int count, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_write].count++;
    syscallStats[NACL_sys_write].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_write].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_write].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_write].count > 0 
                                     ? (double)syscallStats[NACL_sys_write].totalTime / syscallStats[NACL_sys_write].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    char *strBuf = formatStringArgument((char *)buf);
    fprintf(tracingOutputFile, "%d NACL_sys_write(%d, \"%s\", %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, d, strBuf ? strBuf : "NULL", count, ret, (double)elapsedTime / 1000000000.0, percentTime);
    free(strBuf);
    }
}


void NaClStracePWrite(int cageid, int d, const void *buf, int count, off_t offset, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_pwrite].count++;
    syscallStats[NACL_sys_pwrite].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_pwrite].errorCount++;
    }

    // Calculate and print individual syscall stats for pwrite
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_pwrite].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_pwrite].count > 0 
                                     ? (double)syscallStats[NACL_sys_pwrite].totalTime / syscallStats[NACL_sys_pwrite].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    char *strBuf = formatStringArgument((char *)buf);
    fprintf(tracingOutputFile, "%d NACL_sys_pwrite(%d, \"%s\", %d, %lld) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, d, strBuf ? strBuf : "NULL", count, (intmax_t)offset, retval, (double)elapsedTime / 1000000000.0, percentTime);
    free(strBuf);
    }
}


void NaClStraceLseek(int cageid, int d, uintptr_t offset, int whence, int ret, long long time) {
#ifdef TRACING_DASHC
    syscallStats[NACL_sys_lseek].count++;
    syscallStats[NACL_sys_lseek].totalTime += time;
    if (ret < 0) {
        syscallStats[NACL_sys_lseek].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)time / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for lseek
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_lseek].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_lseek].count > 0 
                                     ? (double)syscallStats[NACL_sys_lseek].totalTime / syscallStats[NACL_sys_lseek].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
#endif
    
if (strace_c) {
    fprintf(tracingOutputFile, "%d lseek(%d, 0x%08"NACL_PRIxPTR", %d) = %d (Total time: %.9f seconds)\n", cageid, d, offset, whence, ret, (double)time / 1000000000.0);
}
}


void NaClStraceIoctl(int cageid, int d, unsigned long request, void *arg_ptr, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_ioctl].count++;
    syscallStats[NACL_sys_ioctl].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_ioctl].errorCount++;
    }

    // Calculate and print individual syscall stats for ioctl
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_ioctl].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_ioctl].count > 0 
                                     ? (double)syscallStats[NACL_sys_ioctl].totalTime / syscallStats[NACL_sys_ioctl].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_ioctl(%d, %lu, %p) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, d, request, arg_ptr, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFstat(int cageid, int d, uintptr_t result, int32_t retval, long long time) {
#ifdef TRACING_DASHC
    syscallStats[NACL_sys_fstat].count++;
    syscallStats[NACL_sys_fstat].totalTime += time;
    if (retval < 0) {
        syscallStats[NACL_sys_fstat].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)time / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for fstat
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fstat].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fstat].count > 0 
                                     ? (double)syscallStats[NACL_sys_fstat].totalTime / syscallStats[NACL_sys_fstat].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
#endif
    
if (strace_c) {
    fprintf(tracingOutputFile, "%d fstat(%d, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds)\n", cageid, d, result, retval, (double)time / 1000000000.0);
}
}

void NaClStraceStat(int cageid, char* path, uintptr_t result, int32_t retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_stat].count++;
    syscallStats[NACL_sys_stat].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_stat].errorCount++;
    }

    // Calculate and print individual syscall stats for stat
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_stat].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_stat].count > 0 
                                     ? (double)syscallStats[NACL_sys_stat].totalTime / syscallStats[NACL_sys_stat].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_stat(%s, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds)\n", cageid, path, result, retval, (double)elapsedTime / 1000000000.0);
    }
}



void NaClStraceLStat(int cageid, const char* path, uintptr_t result, int32_t retval, long long time) {
    #ifdef TRACING_DASHC

    syscallStats[NACL_sys_lstat].count++;
    syscallStats[NACL_sys_lstat].totalTime += time;
    totalLstatTime += time; // Add total time for lstat

    if (retval < 0) {
        syscallStats[NACL_sys_lstat].errorCount++;
    }
    
    totalSyscallsCount++;
    totalSyscallsMicroseconds += time / 1000; // Convert nanoseconds to microseconds

    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d lstat(%s, 0x%08"NACL_PRIxPTR") = %d (Total time: %lld ns)\n", cageid, path, result, retval, time);
    }
}




void NaClStraceMkdir(int cageid, const char *path, int mode, int retval, long long totaltime)  {
    #ifdef TRACING_DASHC
    // Time for this call in nanoseconds
    syscallStats[NACL_sys_mkdir].count++;
    syscallStats[NACL_sys_mkdir].totalTime += totaltime;
    totalSyscallsTime += totaltime; // Update total time for all syscalls
    if (retval < 0) {
        syscallStats[NACL_sys_mkdir].errorCount++;
    }
    totalSyscallsCount++;
    totalSyscallsMicroseconds += totaltime / 1000; // Convert nanoseconds to microseconds


    // Calculate and print individual syscall stats for mkdir
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_mkdir].totalTime / 1000000000.0;
    double avgTimePerCallInMicroseconds = syscallStats[NACL_sys_mkdir].count > 0 
                                         ? (double)syscallStats[NACL_sys_mkdir].totalTime / syscallStats[NACL_sys_mkdir].count / 1000.0
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
    
    totalMkdirTime += totaltime;
    
    #endif
    if (strace_c) {

    fprintf(tracingOutputFile, "%d mkdir(%s, %o) = %d (%lld ns)\n", cageid, path, mode, retval, totaltime);
    }

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
        case NACL_sys_mkdir:
            return "mkdir";
        case NACL_sys_mmap:
            return "mmap";
        case NACL_sys_geteuid:
            return "geteuid";
        case NACL_sys_getuid:
            return "getuid";
        case NACL_sys_read:
            return "read";
        case NACL_sys_lseek:
            return "lseek";
        case NACL_sys_fstat:
            return "fstat";
        case NACL_sys_close:
            return "close";
        case NACL_sys_getcwd:
            return "getcwd";
        case NACL_sys_munmap:
            return "munmap";
        case NACL_sys_access:
            return "access";
        case NACL_sys_open:
            return "open";
        case NACL_sys_getgid:
            return "getgid";
        case NACL_sys_getegid:
            return "getegid";
        case NACL_sys_select:
            return "select";
        case NACL_sys_epoll_create:
            return "epoll_create";
        case NACL_sys_epoll_ctl:
            return "epoll_ctl";
        case NACL_sys_epoll_wait:
            return "epoll_wait";
        case NACL_sys_bind:
            return "bind";
        case NACL_sys_listen:
            return "listen";
        case NACL_sys_poll:
            return "poll";
        case NACL_sys_fcntl_get:
            return "fcntl_get";
        case NACL_sys_truncate:
            return "truncate";
        case NACL_sys_ftruncate:
            return "ftruncate";
        case NACL_sys_connect:
            return "connect";
        case NACL_sys_accept:
            return "accept";
        case NACL_sys_flock:
            return "flock";
        case NACL_sys_getsockopt:
            return "getsockopt";
        case NACL_sys_setsockopt:
            return "setsockopt";
        case NACL_sys_fstatfs:
            return "fstatfs";
        case NACL_sys_statfs:
            return "statfs";
        case NACL_sys_getsockname:
            return "getsockname";
        case NACL_sys_getpeername:
            return "getpeername";
        case NACL_sys_socket:
            return "socket";
        case NACL_sys_send:
            return "send";
        case NACL_sys_sendto:
            return "sendto";
        case NACL_sys_recv:
            return "recv";
        case NACL_sys_recvfrom:
            return "recvfrom";
        case NACL_sys_shmat:
            return "shmat";
        case NACL_sys_shmget:
            return "shmget";
        case NACL_sys_shmdt:
            return "shmdt";
        case NACL_sys_shmctl:
            return "shmctl";
        case NACL_sys_socketpair:
            return "socketpair";
        case NACL_sys_nanosleep:
            return "nanosleep";
        case NACL_sys_gettimeofday:
            return "gettimeofday";
        case NACL_sys_link:
            return "link";
        case NACL_sys_unlink:
            return "unlink";
        case NACL_sys_rename:
            return "rename";
        case NACL_sys_rmdir:
            return "rmdir";
        case NACL_sys_chdir:
            return "chdir";
        case NACL_sys_chmod:
            return "chmod";
        case NACL_sys_fchmod:
            return "fchmod";
        case NACL_sys_fchdir:
            return "fchdir";
        case NACL_sys_fsync:
            return "fsync";
        case NACL_sys_fdatasync:
            return "fdatasync";
        case NACL_sys_sync_file_range:
            return "sync_file_range";
        case NACL_sys_exit:
            return "exit";
        case NACL_sys_dup:
            return "dup";
        case NACL_sys_dup2:
            return "dup2";
        case NACL_sys_dup3:
            return "dup3";
        case NACL_sys_getdents:
            return "getdents";
        case NACL_sys_pread:
            return "pread";
        case NACL_sys_write:
            return "write";
        case NACL_sys_pwrite:
            return "pwrite";
        case NACL_sys_ioctl:
            return "ioctl";
        case NACL_sys_lstat:
            return "lstat";
        case NACL_sys_stat:
            return "stat";
        case NACL_sys_getpid:
            return "getpid";
        case NACL_sys_getppid:
            return "getppid";
        default:
            return "unknown";
    }
}




void NaClStraceRmdir(int cageid, const char *path, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_rmdir].count++;
    syscallStats[NACL_sys_rmdir].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_rmdir].errorCount++;
    }

    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for rmdir
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_rmdir].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_rmdir].count > 0 
                                     ? (double)syscallStats[NACL_sys_rmdir].totalTime / syscallStats[NACL_sys_rmdir].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_rmdir(%s) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, path, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceChdir(int cageid, const char *path, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_chdir].count++;
    syscallStats[NACL_sys_chdir].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_chdir].errorCount++;
    }

// Calculate and print individual syscall stats for chdir
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_chdir].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_chdir].count > 0 
                                 ? (double)syscallStats[NACL_sys_chdir].totalTime / syscallStats[NACL_sys_chdir].count / 1000000000.0
                                 : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif


    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_chdir(%s) = %d (Total time: %.9f seconds)\n", cageid, path, retval, (double)elapsedTime / 1000000000.0);
    }
}


void NaClStraceChmod(int cageid, const char *path, int mode, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_chmod].count++;
    syscallStats[NACL_sys_chmod].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_chmod].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_chmod].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_chmod].count > 0 
                                     ? (double)syscallStats[NACL_sys_chmod].totalTime / syscallStats[NACL_sys_chmod].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_chmod(%s, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, path, mode, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceFchmod(int cageid, int fd, int mode, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fchmod].count++;
    syscallStats[NACL_sys_fchmod].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_fchmod].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fchmod].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fchmod].count > 0 
                                     ? (double)syscallStats[NACL_sys_fchmod].totalTime / syscallStats[NACL_sys_fchmod].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_fchmod(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, mode, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceFchdir(int cageid, int fd, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fchdir].count++;
    syscallStats[NACL_sys_fchdir].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_fchdir].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fchdir].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fchdir].count > 0 
                                     ? (double)syscallStats[NACL_sys_fchdir].totalTime / syscallStats[NACL_sys_fchdir].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_fchdir(%d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFsync(int cageid, int fd, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fsync].count++;
    syscallStats[NACL_sys_fsync].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_fsync].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fsync].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fsync].count > 0 
                                     ? (double)syscallStats[NACL_sys_fsync].totalTime / syscallStats[NACL_sys_fsync].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_fsync(%d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, ret, (double)elapsedTime / 1000000000.0, percentTime);
   }
}


void NaClStraceFdatasync(int cageid, int fd, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fdatasync].count++;
    syscallStats[NACL_sys_fdatasync].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_fdatasync].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fdatasync].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fdatasync].count > 0 
                                     ? (double)syscallStats[NACL_sys_fdatasync].totalTime / syscallStats[NACL_sys_fdatasync].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_fdatasync(%d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceSyncFileRange(int cageid, int fd, off_t offset, off_t nbytes, uint32_t flags, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_sync_file_range].count++;
    syscallStats[NACL_sys_sync_file_range].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_sync_file_range].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_sync_file_range].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_sync_file_range].count > 0 
                                     ? (double)syscallStats[NACL_sys_sync_file_range].totalTime / syscallStats[NACL_sys_sync_file_range].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_sync_file_range(%d, %ld, %ld, %u) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, offset, nbytes, flags, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceGetcwd(int cageid, char *buf, size_t size, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getcwd].count++;
    syscallStats[NACL_sys_getcwd].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_getcwd].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for getcwd
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getcwd].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getcwd].count > 0 
                                     ? (double)syscallStats[NACL_sys_getcwd].totalTime / syscallStats[NACL_sys_getcwd].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    char *strBuf = formatStringArgument(buf);
    fprintf(tracingOutputFile, "%d NACL_sys_getcwd(%s, %zu) = %d (Total time: %.9f seconds)\n", cageid, strBuf ? strBuf : "NULL", size, retval, (double)elapsedTime / 1000000000.0);
    free(strBuf);
    }
}

void NaClStraceLink(int cageid, char* from, char* to, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_link].count++;
    syscallStats[NACL_sys_link].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_link].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_link].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_link].count > 0 
                                     ? (double)syscallStats[NACL_sys_link].totalTime / syscallStats[NACL_sys_link].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_link(\"%s\", \"%s\") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, from, to, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceUnlink(int cageid, char* pathname, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_unlink].count++;
    syscallStats[NACL_sys_unlink].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_unlink].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_unlink].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_unlink].count > 0 
                                     ? (double)syscallStats[NACL_sys_unlink].totalTime / syscallStats[NACL_sys_unlink].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_unlink(\"%s\") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, pathname, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceRename(int cageid, const char *oldpath, const char *newpath, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_rename].count++;
    syscallStats[NACL_sys_rename].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_rename].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_rename].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_rename].count > 0 
                                     ? (double)syscallStats[NACL_sys_rename].totalTime / syscallStats[NACL_sys_rename].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_rename(\"%s\", \"%s\") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, oldpath, newpath, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceMmap(int cageid, void *start, size_t length, int prot, int flags, int d, uintptr_t offset, int retval, long long time) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_mmap].count++;
    syscallStats[NACL_sys_mmap].totalTime += time;
    if (retval < 0) {
        syscallStats[NACL_sys_mmap].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)time / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for mmap
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_mmap].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_mmap].count > 0 
                                     ? (double)syscallStats[NACL_sys_mmap].totalTime / syscallStats[NACL_sys_mmap].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d mmap(0x%08"NACL_PRIxPTR", %zu, %d, %d, %d, %"NACL_PRId32") = %d (Total time: %.9f seconds)\n", cageid, (uintptr_t)start, length, prot, flags, d, offset, retval, (double)time / 1000000000.0);
    }
}





void NaClStraceMunmap(int cageid, uintptr_t sysaddr, size_t length, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_munmap].count++;
    syscallStats[NACL_sys_munmap].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_munmap].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for munmap
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_munmap].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_munmap].count > 0 
                                     ? (double)syscallStats[NACL_sys_munmap].totalTime / syscallStats[NACL_sys_munmap].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_munmap(0x%08"NACL_PRIxPTR", %zu) = %d (Total time: %.9f seconds)\n", cageid, sysaddr, length, retval, (double)elapsedTime / 1000000000.0);
    }
}
void NaClStraceShmat(int cageid, int shmid, void *shmaddr, int shmflg, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_shmat].count++;
    syscallStats[NACL_sys_shmat].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_shmat].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_shmat].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_shmat].count > 0 
                                     ? (double)syscallStats[NACL_sys_shmat].totalTime / syscallStats[NACL_sys_shmat].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_shmat(%d, %p, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, shmid, shmaddr, shmflg, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceShmget(int cageid, int key, size_t size, int shmflg, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_shmget].count++;
    syscallStats[NACL_sys_shmget].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_shmget].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_shmget].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_shmget].count > 0 
                                     ? (double)syscallStats[NACL_sys_shmget].totalTime / syscallStats[NACL_sys_shmget].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_shmget(%d, %zu, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, key, size, shmflg, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceShmdt(int cageid, void *shmaddr, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_shmdt].count++;
    syscallStats[NACL_sys_shmdt].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_shmdt].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_shmdt].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_shmdt].count > 0 
                                     ? (double)syscallStats[NACL_sys_shmdt].totalTime / syscallStats[NACL_sys_shmdt].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_shmdt(%p) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, shmaddr, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }

}

void NaClStraceShmctl(int cageid, int shmid, int cmd, uintptr_t bufsysaddr, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_shmctl].count++;
    syscallStats[NACL_sys_shmctl].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_shmctl].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_shmctl].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_shmctl].count > 0 
                                     ? (double)syscallStats[NACL_sys_shmctl].totalTime / syscallStats[NACL_sys_shmctl].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_shmctl(%d, %d, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, shmid, cmd, bufsysaddr, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}



void NaClStraceSocketPair(int cageid, int domain, int type, int protocol, int *lindfds, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_socketpair].count++;
    syscallStats[NACL_sys_socketpair].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_socketpair].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_socketpair].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_socketpair].count > 0 
                                     ? (double)syscallStats[NACL_sys_socketpair].totalTime / syscallStats[NACL_sys_socketpair].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_socketpair(%d, %d, %d, %p, %p) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, domain, type, protocol, (void *)lindfds, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


// void NaClStraceNanosleep(int cageid, uintptr_t req, uintptr_t rem, int ret, long long elapsedTime) {
//     #ifdef TRACING_DASHC
//     syscallStats[NACL_sys_nanosleep].count++;
//     syscallStats[NACL_sys_nanosleep].totalTime += elapsedTime;
//     if (ret < 0) {
//         syscallStats[NACL_sys_nanosleep].errorCount++;
//     }

//     double totalTimeInSeconds = (double)syscallStats[NACL_sys_nanosleep].totalTime / 1000000000.0;
//     double avgTimePerCallInSeconds = syscallStats[NACL_sys_nanosleep].count > 0 
//                                      ? (double)syscallStats[NACL_sys_nanosleep].totalTime / syscallStats[NACL_sys_nanosleep].count / 1000000000.0
//                                      : 0.0;
//     double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
//     #endif
    
//     if (strace_c) {
//     fprintf(tracingOutputFile, "%d NACL_sys_nanosleep(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, req, rem, ret, (double)elapsedTime / 1000000000.0, percentTime);
//     }
// }


// void NaClStraceSchedYield(int cageid, int ret, long long elapsedTime) {
//     #ifdef TRACING_DASHC
//     syscallStats[NACL_sys_sched_yield].count++;
//     syscallStats[NACL_sys_sched_yield].totalTime += elapsedTime;
//     if (ret < 0) {
//         syscallStats[NACL_sys_sched_yield].errorCount++;
//     }

//     double totalTimeInSeconds = (double)syscallStats[NACL_sys_sched_yield].totalTime / 1000000000.0;
//     double avgTimePerCallInSeconds = syscallStats[NACL_sys_sched_yield].count > 0 
//                                      ? (double)syscallStats[NACL_sys_sched_yield].totalTime / syscallStats[NACL_sys_sched_yield].count / 1000000000.0
//                                      : 0.0;
//     double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
//     #endif
    
//     if (strace_c) {
//     fprintf(tracingOutputFile, "%d NACL_sys_sched_yield() = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, ret, (double)elapsedTime / 1000000000.0, percentTime);
//     }
// }


void NaClStraceGetTimeOfDay(int cageid, uintptr_t tv, uintptr_t tz, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_gettimeofday].count++;
    syscallStats[NACL_sys_gettimeofday].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_gettimeofday].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_gettimeofday].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_gettimeofday].count > 0 
                                     ? (double)syscallStats[NACL_sys_gettimeofday].totalTime / syscallStats[NACL_sys_gettimeofday].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_gettimeofday(0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, tv, tz, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

//check this again the NACL_sys_clock
void NaClStraceClockGetCommon(int cageid, int clk_id, uint32_t ts_addr, uintptr_t *time_func, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_clock].count++;
    syscallStats[NACL_sys_clock].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_clock].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_clock].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_clock].count > 0 
                                     ? (double)syscallStats[NACL_sys_clock].totalTime / syscallStats[NACL_sys_clock].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_clockgetcommon(%d, %u, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, clk_id, ts_addr, time_func, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFork(int cageid, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fork].count++;
    syscallStats[NACL_sys_fork].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_fork].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fork].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fork].count > 0 
                                     ? (double)syscallStats[NACL_sys_fork].totalTime / syscallStats[NACL_sys_fork].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_fork() = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceExecve(int cageid, char const *path, char *const *argv, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_execve].count++;
    syscallStats[NACL_sys_execve].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_execve].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_execve].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_execve].count > 0 
                                     ? (double)syscallStats[NACL_sys_execve].totalTime / syscallStats[NACL_sys_execve].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_execve(%s, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, path, (uintptr_t)argv, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceExecv(int cageid, char const *path, char *const *argv, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_execv].count++;
    syscallStats[NACL_sys_execv].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_execv].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_execv].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_execv].count > 0 
                                     ? (double)syscallStats[NACL_sys_execv].totalTime / syscallStats[NACL_sys_execv].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_execv(%s, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, path, (uintptr_t)argv, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceWaitpid(int cageid, int pid, uintptr_t sysaddr, int options, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_waitpid].count++;
    syscallStats[NACL_sys_waitpid].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_waitpid].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_waitpid].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_waitpid].count > 0 
                                     ? (double)syscallStats[NACL_sys_waitpid].totalTime / syscallStats[NACL_sys_waitpid].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_waitpid(%d, 0x%08"NACL_PRIxPTR", %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, pid, sysaddr, options, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceGethostname(int cageid, char *name, size_t len, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_gethostname].count++;
    syscallStats[NACL_sys_gethostname].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_gethostname].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_gethostname].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_gethostname].count > 0 
                                     ? (double)syscallStats[NACL_sys_gethostname].totalTime / syscallStats[NACL_sys_gethostname].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    char *strBuf = formatStringArgument(name);
    fprintf(tracingOutputFile, "%d gethostname(%s, %lu) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, strBuf ? strBuf : "NULL", len, ret, (double)elapsedTime / 1000000000.0, percentTime);
    free(strBuf);
    }
}


void NaClStraceGetifaddrs(int cageid, char *buf, size_t len, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getifaddrs].count++;
    syscallStats[NACL_sys_getifaddrs].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getifaddrs].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getifaddrs].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getifaddrs].count > 0 
                                     ? (double)syscallStats[NACL_sys_getifaddrs].totalTime / syscallStats[NACL_sys_getifaddrs].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    char *strBuf = formatStringArgument(buf);
    fprintf(tracingOutputFile, "%d getifaddrs(%s, %lu) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, strBuf ? strBuf : "NULL", len, ret, (double)elapsedTime / 1000000000.0, percentTime);
    free(strBuf);
    }
}


void NaClStraceSocket(int cageid, int domain, int type, int protocol, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_socket].count++;
    syscallStats[NACL_sys_socket].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_socket].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_socket].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_socket].count > 0 
                                     ? (double)syscallStats[NACL_sys_socket].totalTime / syscallStats[NACL_sys_socket].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d socket(%d, %d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, domain, type, protocol, ret, (double)elapsedTime / 1000000000.0, percentTime);
}
}


void NaClStraceSend(int cageid, int sockfd, const void *buf, size_t len, int flags, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_send].count++;
    syscallStats[NACL_sys_send].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_send].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_send].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_send].count > 0 
                                     ? (double)syscallStats[NACL_sys_send].totalTime / syscallStats[NACL_sys_send].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d send(%d, 0x%08"NACL_PRIxPTR", %ld, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, (uintptr_t)buf, len, flags, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceSendto(int cageid, int sockfd, const void *buf, size_t len, int flags, uintptr_t dest_addr, socklen_t addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_sendto].count++;
    syscallStats[NACL_sys_sendto].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_sendto].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_sendto].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_sendto].count > 0 
                                     ? (double)syscallStats[NACL_sys_sendto].totalTime / syscallStats[NACL_sys_sendto].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d sendto(%d, 0x%08"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, (uintptr_t) buf, len, flags, dest_addr, addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    #endif
}


void NaClStraceRecv(int cageid, int sockfd, void *buf, size_t len, int flags, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_recv].count++;
    syscallStats[NACL_sys_recv].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_recv].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_recv].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_recv].count > 0 
                                     ? (double)syscallStats[NACL_sys_recv].totalTime / syscallStats[NACL_sys_recv].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d recv(%d, 0x%08"NACL_PRIxPTR", %ld, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, (uintptr_t)buf, len, flags, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceRecvfrom(int cageid, int sockfd, void *buf, size_t len, int flags, uintptr_t src_addr, socklen_t *addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_recvfrom].count++;
    syscallStats[NACL_sys_recvfrom].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_recvfrom].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_recvfrom].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_recvfrom].count > 0 
                                     ? (double)syscallStats[NACL_sys_recvfrom].totalTime / syscallStats[NACL_sys_recvfrom].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d recvfrom(%d, %p"NACL_PRIxPTR", %ld, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, buf, len, flags, src_addr, (uintptr_t)addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}

void NaClStraceShutdown(int cageid, int sockfd, int how, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_shutdown].count++;
    syscallStats[NACL_sys_shutdown].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_shutdown].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_shutdown].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_shutdown].count > 0 
                                     ? (double)syscallStats[NACL_sys_shutdown].totalTime / syscallStats[NACL_sys_shutdown].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d shutdown(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, how, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}



void NaClStraceGetuid(int cageid, int ret, long long time) {
#ifdef TRACING_DASHC
    syscallStats[NACL_sys_getuid].count++;
    syscallStats[NACL_sys_getuid].totalTime += time;
    if (ret < 0) {
        syscallStats[NACL_sys_getuid].errorCount++;
    }
    
    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)time / 1000000000.0; // Convert from nanoseconds to seconds
    
    // Calculate and print individual syscall stats for getuid
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getuid].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getuid].count > 0 
                                     ? (double)syscallStats[NACL_sys_getuid].totalTime / syscallStats[NACL_sys_getuid].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
#endif
    
if (strace_c) {
    fprintf(tracingOutputFile, "%d getuid() = %d (Total time: %.9f seconds)\n", cageid, ret, (double)time / 1000000000.0);
}
}



void NaClStraceGeteuid(int cageid, int ret, long long time) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_geteuid].count++;
    syscallStats[NACL_sys_geteuid].totalTime += time;
    if (ret < 0) {
        syscallStats[NACL_sys_geteuid].errorCount++;
    }
    
    // Update total time for all syscalls
    totalSyscallsTime += time;
    
    // Calculate and print individual syscall stats for geteuid
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_geteuid].totalTime / 1000000000.0;
    long long avgTimePerCallInMicroseconds = syscallStats[NACL_sys_geteuid].count > 0 
                                             ? syscallStats[NACL_sys_geteuid].totalTime / syscallStats[NACL_sys_geteuid].count / 1000
                                             : 0;
    double percentTime = 100.0 * totalTimeInSeconds / (totalSyscallsTime / 1000000000.0);
    #endif
    
    if (strace_c) {
    // Print the syscall information
    fprintf(tracingOutputFile, "%d geteuid() = %d (Total time: %lld ns)\n", cageid, ret, time);
    }
}



void NaClStraceGetgid(int cageid, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getgid].count++;
    syscallStats[NACL_sys_getgid].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getgid].errorCount++;
    }

    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for getgid
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getgid].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getgid].count > 0 
                                     ? (double)syscallStats[NACL_sys_getgid].totalTime / syscallStats[NACL_sys_getgid].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_getgid() = %d (Total time: %.9f seconds)\n", cageid, ret, (double)elapsedTime / 1000000000.0);
   }
}



void NaClStraceGetegid(int cageid, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getegid].count++;
    syscallStats[NACL_sys_getegid].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getegid].errorCount++;
    }

    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for getegid
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getegid].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getegid].count > 0 
                                     ? (double)syscallStats[NACL_sys_getegid].totalTime / syscallStats[NACL_sys_getegid].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    fprintf(tracingOutputFile, "%d NACL_sys_getegid() = %d (Total time: %.9f seconds)\n", cageid, ret, (double)elapsedTime / 1000000000.0);
}
}


void NaClStraceFlock(int cageid, int fd, int operation, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_flock].count++;
    syscallStats[NACL_sys_flock].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_flock].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_flock].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_flock].count > 0 
                                     ? (double)syscallStats[NACL_sys_flock].totalTime / syscallStats[NACL_sys_flock].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d flock(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, operation, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceGetsockopt(int cageid, int sockfd, int level, int optname, void *optval, socklen_t *optlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getsockopt].count++;
    syscallStats[NACL_sys_getsockopt].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getsockopt].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getsockopt].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getsockopt].count > 0 
                                     ? (double)syscallStats[NACL_sys_getsockopt].totalTime / syscallStats[NACL_sys_getsockopt].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d getsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, level, optname, (uintptr_t)optval, (uintptr_t)optlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceSetsockopt(int cageid, int sockfd, int level, int optname, const void *optval, socklen_t optlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_setsockopt].count++;
    syscallStats[NACL_sys_setsockopt].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_setsockopt].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_setsockopt].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_setsockopt].count > 0 
                                     ? (double)syscallStats[NACL_sys_setsockopt].totalTime / syscallStats[NACL_sys_setsockopt].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d setsockopt(%d, %d, %d, 0x%08"NACL_PRIxPTR", %u) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, level, optname, (uintptr_t)optval, optlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFstatfs(int cageid, int d, uintptr_t buf, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fstatfs].count++;
    syscallStats[NACL_sys_fstatfs].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_fstatfs].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fstatfs].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fstatfs].count > 0 
                                     ? (double)syscallStats[NACL_sys_fstatfs].totalTime / syscallStats[NACL_sys_fstatfs].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d fstatfs(%d, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, d, buf, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceStatfs(int cageid, const char *pathname, uintptr_t buf, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_statfs].count++;
    syscallStats[NACL_sys_statfs].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_statfs].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_statfs].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_statfs].count > 0 
                                     ? (double)syscallStats[NACL_sys_statfs].totalTime / syscallStats[NACL_sys_statfs].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d statfs(%s, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, formatStringArgument(pathname), buf, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceGetsockname(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getsockname].count++;
    syscallStats[NACL_sys_getsockname].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getsockname].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getsockname].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getsockname].count > 0 
                                     ? (double)syscallStats[NACL_sys_getsockname].totalTime / syscallStats[NACL_sys_getsockname].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d getsockname(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceGetpeername(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_getpeername].count++;
    syscallStats[NACL_sys_getpeername].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_getpeername].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_getpeername].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_getpeername].count > 0 
                                     ? (double)syscallStats[NACL_sys_getpeername].totalTime / syscallStats[NACL_sys_getpeername].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d getpeername(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceAccess(int cageid, char *path, int mode, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_access].count++;
    syscallStats[NACL_sys_access].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_access].errorCount++;
    }

    // Update total time for all syscalls (in seconds)
    totalSyscallsTime += (double)elapsedTime / 1000000000.0; // Convert from nanoseconds to seconds

    // Calculate and print individual syscall stats for access
    double totalTimeInSeconds = (double)syscallStats[NACL_sys_access].totalTime / 1000000000.0; // Convert to seconds
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_access].count > 0 
                                     ? (double)syscallStats[NACL_sys_access].totalTime / syscallStats[NACL_sys_access].count / 1000000000.0 // Convert to seconds
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif

    if (strace_c) {
    char *strBuf = formatStringArgument(path);
    fprintf(tracingOutputFile, "%d NACL_sys_access(%s, %d) = %d (Total time: %.9f seconds)\n", cageid, strBuf ? strBuf : "NULL", mode, ret, (double)elapsedTime / 1000000000.0);
    free(strBuf);
    }
}

void NaClStraceTruncate(int cageid, uint32_t path, int length, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_truncate].count++;
    syscallStats[NACL_sys_truncate].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_truncate].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_truncate].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_truncate].count > 0 
                                     ? (double)syscallStats[NACL_sys_truncate].totalTime / syscallStats[NACL_sys_truncate].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d truncate(%u, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, path, length, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFtruncate(int cageid, int fd, int length, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_ftruncate].count++;
    syscallStats[NACL_sys_ftruncate].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_ftruncate].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_ftruncate].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_ftruncate].count > 0 
                                     ? (double)syscallStats[NACL_sys_ftruncate].totalTime / syscallStats[NACL_sys_ftruncate].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d ftruncate(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, length, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceConnect(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_connect].count++;
    syscallStats[NACL_sys_connect].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_connect].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_connect].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_connect].count > 0 
                                     ? (double)syscallStats[NACL_sys_connect].totalTime / syscallStats[NACL_sys_connect].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d connect(%d, 0x%08"NACL_PRIxPTR", %u) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, addr, addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceAccept(int cageid, int sockfd, uintptr_t addr, socklen_t *addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_accept].count++;
    syscallStats[NACL_sys_accept].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_accept].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_accept].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_accept].count > 0 
                                     ? (double)syscallStats[NACL_sys_accept].totalTime / syscallStats[NACL_sys_accept].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d accept(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, addr, (uintptr_t)addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceBind(int cageid, int sockfd, uintptr_t addr, socklen_t addrlen, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_bind].count++;
    syscallStats[NACL_sys_bind].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_bind].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_bind].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_bind].count > 0 
                                     ? (double)syscallStats[NACL_sys_bind].totalTime / syscallStats[NACL_sys_bind].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d bind(%d, 0x%08"NACL_PRIxPTR", %u) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, addr, addrlen, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceListen(int cageid, int sockfd, int backlog, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_listen].count++;
    syscallStats[NACL_sys_listen].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_listen].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_listen].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_listen].count > 0 
                                     ? (double)syscallStats[NACL_sys_listen].totalTime / syscallStats[NACL_sys_listen].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d listen(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, sockfd, backlog, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStracePoll(int cageid, uintptr_t fds, nfds_t nfds, int timeout, int retval, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_poll].count++;
    syscallStats[NACL_sys_poll].totalTime += elapsedTime;
    if (retval < 0) {
        syscallStats[NACL_sys_poll].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_poll].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_poll].count > 0 
                                     ? (double)syscallStats[NACL_sys_poll].totalTime / syscallStats[NACL_sys_poll].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d poll(0x%08"NACL_PRIxPTR", %lu, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fds, nfds, timeout, retval, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFcntlGet(int cageid, int fd, int cmd, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fcntl_get].count++;
    syscallStats[NACL_sys_fcntl_get].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_fcntl_get].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fcntl_get].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fcntl_get].count > 0 
                                     ? (double)syscallStats[NACL_sys_fcntl_get].totalTime / syscallStats[NACL_sys_fcntl_get].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d fcntlget(%d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, cmd, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceFcntlSet(int cageid, int fd, int cmd, long set_op, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_fcntl_set].count++;
    syscallStats[NACL_sys_fcntl_set].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_fcntl_set].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_fcntl_set].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_fcntl_set].count > 0 
                                     ? (double)syscallStats[NACL_sys_fcntl_set].totalTime / syscallStats[NACL_sys_fcntl_set].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d fcntlset(%d, %d, %ld) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, fd, cmd, set_op, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceEpollCreate(int cageid, int size, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_epoll_create].count++;
    syscallStats[NACL_sys_epoll_create].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_epoll_create].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_epoll_create].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_epoll_create].count > 0 
                                     ? (double)syscallStats[NACL_sys_epoll_create].totalTime / syscallStats[NACL_sys_epoll_create].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d epollcreate(%d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, size, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceEpollCtl(int cageid, int epfd, int op, int fd, uintptr_t event, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_epoll_ctl].count++;
    syscallStats[NACL_sys_epoll_ctl].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_epoll_ctl].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_epoll_ctl].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_epoll_ctl].count > 0 
                                     ? (double)syscallStats[NACL_sys_epoll_ctl].totalTime / syscallStats[NACL_sys_epoll_ctl].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d epollctl(%d, %d, %d, 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, epfd, op, fd, event, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceEpollWait(int cageid, int epfd, uintptr_t events, int maxevents, int timeout, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_epoll_wait].count++;
    syscallStats[NACL_sys_epoll_wait].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_epoll_wait].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_epoll_wait].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_epoll_wait].count > 0 
                                     ? (double)syscallStats[NACL_sys_epoll_wait].totalTime / syscallStats[NACL_sys_epoll_wait].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d epollwait(%d, 0x%08"NACL_PRIxPTR", %d, %d) = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, epfd, events, maxevents, timeout, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}


void NaClStraceSelect(int cageid, int nfds, uintptr_t readfds, uintptr_t writefds, uintptr_t exceptfds, uintptr_t timeout, int ret, long long elapsedTime) {
    #ifdef TRACING_DASHC
    syscallStats[NACL_sys_select].count++;
    syscallStats[NACL_sys_select].totalTime += elapsedTime;
    if (ret < 0) {
        syscallStats[NACL_sys_select].errorCount++;
    }

    double totalTimeInSeconds = (double)syscallStats[NACL_sys_select].totalTime / 1000000000.0;
    double avgTimePerCallInSeconds = syscallStats[NACL_sys_select].count > 0 
                                     ? (double)syscallStats[NACL_sys_select].totalTime / syscallStats[NACL_sys_select].count / 1000000000.0
                                     : 0.0;
    double percentTime = 100.0 * totalTimeInSeconds / totalSyscallsTime;
    #endif
    
    if (strace_c) {
    fprintf(tracingOutputFile, "%d select(%d, 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR", 0x%08"NACL_PRIxPTR") = %d (Total time: %.9f seconds, Percent of total time: %.2f%%)\n", cageid, nfds, readfds, writefds, exceptfds, timeout, ret, (double)elapsedTime / 1000000000.0, percentTime);
    }
}
