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
void NaClStracePWrite(int d, void *buf, int count,off_t offset, size_t ret){
    printf("pwrite(%d, %p, %d, %jd) = %zu\n", d, buf, count, (intmax_t)offset, ret);

}
// void NaClStraceLseek(int d, nacl_abi_off_t offp, int whence,size_t ret){
//     printf("lseek(%d, %lld, %d) = %zu\n", d, (long long)offp, whence, ret);

// }
void NaClStraceIoctl(int d, unsigned long request, size_t ret){
    printf("ioctl(%d, %lu) = %zu\n", d, request, ret);

}
void NaClStraceFstat(int d, size_t retval){
    printf("fstat(%d) = %zu\n", d, retval);
}
void NaClStraceStat(char* path, size_t retval){
    printf("stat(%s) = %zu\n", path, retval);

}
void NaClStraceMkdir(char* path, int mode,size_t retval){
    printf("mkdir(%s, %d) = %zu\n", path, mode, retval);

}
void NaClStraceRmdir(uint32_t path, int32_t retval){
    printf("rmdir(%u) = %d\n", path, retval);
}
void NaClStraceChdir(uint32_t path, int32_t retval){
    printf("chdir(%u) = %d\n", path, retval);

}
void NaClStraceChmod(uint32_t path,int mode,int32_t retval){
    printf("chmod(%u, %d) = %d\n", path, mode, retval);

}
void NaClStraceFchmod(int fd,int mode,int retval){
    printf("fchmod(%d, %d) = %d\n", fd, mode, retval);

}
void NaClStraceFchdir(int fd,int32_t retval){
    printf("fchdir(%d) = %d\n", fd, retval);
}