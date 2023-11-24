/*
 * Tracing functionalities will be enabled when OS environment TRACING_ENABLED = 1 
 */

#include <string.h>
#include <stdio.h>
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
void NaClStraceExit(int status){
    printf("exit() = %d\n", status);

}