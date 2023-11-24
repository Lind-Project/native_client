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
void NaClStraceThreadExit(int stack_flag,uint32_t  zero){
    printf("thread_exit(%d, %u) = void\n", stack_flag, zero);

}
void NaClStraceDup(int oldfd,int ret){
    printf("dup(%d) = %d\n", oldfd, ret);

}
void NaClStraceDup2(int oldfd,int newfd,int ret){
    printf("dup2(%d, %d) = %d\n", oldfd, newfd, ret);

}
void NaClStraceDup3(int oldfd,int newfd,int flags,int ret){
    printf("dup3(%d, %d, %d) = %d\n", oldfd, newfd, flags, ret);

}
void NaClStraceGetdents(int d,void *drip,int  count,size_t ret,ssize_t getdents_ret,uintptr_t sysaddr){
    printf("getdents(%d, %p, %d) = %zu, Getdents Ret: %zd, Sysaddr: %p\n", d, drip, count, ret, getdents_ret, (void*)sysaddr);


}
void NaClStracePread(int d, void *buf, int count,  size_t log_bytes,int32_t ret){
    printf("pread(%d, %p, %d, %zu) = %d\n", d, buf, count, log_bytes, ret);
}


void NaClStraceWrite(int d, void *buf, int count, size_t ret){
    printf("write(%d, %p, %d) = %zu\n", d, buf, count, ret);

}
