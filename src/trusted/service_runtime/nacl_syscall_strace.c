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
void NaClStraceThreadExit(int32_t *stack_flag, uint32_t zero){
    printf("thread_exit(%d, %u) = void\n", stack_flag ? *stack_flag : 0, zero);
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
void NaClStraceGetdents(int d, void *drip, size_t count, size_t ret, ssize_t getdents_ret, uintptr_t sysaddr) {
    printf("getdents(%d, %p, %zu) = %zu, Getdents Ret: %zd, Sysaddr: %p\n", d, drip, count, ret, getdents_ret, (void *)sysaddr);
}

void NaClStracePread(int d, void *buf, int count,  size_t log_bytes){
    printf("pread(%d, %p, %d, %zu) = %d\n", d, buf, count, log_bytes);
}


void NaClStraceWrite(int d, void *buf, int count) {
    printf("write(%d, %p, %d)\n", d, buf, count);
}

void NaClStracePWrite(int d, const void *buf, int count, off_t offset) {
    printf("pwrite(%d, %p, %d, %jd)\n", d, buf, count, (intmax_t)offset);
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
void NaClStraceRmdir(const char *path, int32_t retval) {
    printf("rmdir(%s) = %d\n", path, retval);
}
void NaClStraceChdir(const char *path, int32_t retval) {
    printf("chdir(%s) = %d\n", path, retval);
}
void NaClStraceChmod(const char *path, int mode, int32_t retval) {
    printf("chmod(%s, %d) = %d\n", path, mode, retval);
}
void NaClStraceFchmod(int fd,int mode,int retval){
    printf("fchmod(%d, %d) = %d\n", fd, mode, retval);

}
void NaClStraceFchdir(int fd){
    printf("fchdir(%d) =\n", fd);
}
void NaClStraceGetcwd(char *buf, size_t size, uintptr_t sysaddr, int32_t retval) {
    printf("getcwd(%p, %zu) = %d, Sysaddr: %p\n", (void *)buf, size, retval, (void *)sysaddr);
}


void NaClStraceLink(char* from,char* to){
    printf("link(%s, %s) = void\n", from, to);

}
void NaClStraceUnlink(char* pathname,int32_t retval){
    printf("unlink(%s) = %d\n", pathname, retval);

}
void NaClStraceCommon(uintptr_t usraddr, size_t length) {
    printf("User Address: %p, Length: %zu\n", (void*)usraddr, length);
}

void NaClStraceRename(const char *oldpath, const char *newpath, int32_t retval) {
    printf("rename(oldpath: \"%s\", newpath: \"%s\") = %d\n", oldpath, newpath, retval);
}
void NaClStraceMmap(void *start,size_t length,int prot,int flags,int d,int32_t retval){
    printf("mmap(%p, %zu, %d, %d, %d) = %d\n", start, length, prot, flags, d, retval);

}
void NaClStraceMunmap(void *start,size_t length,int32_t retval,uintptr_t sysaddr,size_t alloc_rounded_length){
   printf("munmap(%p, %zu) = %d, Sysaddr: %p, Alloc Rounded Length: %zu\n", start, length, retval, (void*)sysaddr, alloc_rounded_length);

}
void NaClStraceMprotectInternal(uint32_t start,size_t length,int prot,uintptr_t sysaddr,int32_t retval,int holding_app_lock){
    printf("mprotect_internal(%u, %zu, %d, %p) = %d, Holding App Lock: %d\n", start, length, prot, (void*)sysaddr, retval, holding_app_lock);
    
}
void NaClStraceMprotect(uint32_t start,size_t length,int prot){
    printf("mprotect(%u, %zu, %d) = void\n", start, length, prot);

}
void NaClStraceShmat(int key,size_t size,int shmflg,int32_t retval,size_t alloc_rounded_size){
    printf("Key: %d, Size: %zu, Shmflg: %d, Return Value: %d, Alloc Rounded Size: %zu\n",key, size, shmflg, retval, alloc_rounded_size);
}
void NaClStraceShmget(int key,size_t size,int shmflg,int32_t retval,size_t alloc_rounded_size){
    printf("Key: %d, Size: %zu, Shmflg: %d, Return Value: %d, Alloc Rounded Size: %zu\n",key, size, shmflg, retval, alloc_rounded_size);
}
void NaClStraceShmdt(int shmid, void *shmaddr, int shmflg) {
    printf("shmdt(%d, %p, %d) = void\n", shmid, shmaddr, shmflg);
}

// void NaClStraceSyst(void *shmaddr,int shmid,uintptr_t sysaddr,int length){
//     printf("syst(%p, %d, %lu, %d) = void\n", shmaddr, shmid, sysaddr, length);
//}


void NaClStraceShmctl(int shmid,int cmd, int32_t retval){
    printf("shmctl(%d, %d) = %d\n", shmid, cmd, retval);

}
void NaClStraceSocketPair(int domain, int type, int protocol, int *fds, int *lindfds, int32_t retval) {
    printf("SocketPair(domain=%d, type=%d, protocol=%d, fds=%p, lindfds=%p, retval=%d)\n", domain, type, protocol, (void *)fds, (void *)lindfds, retval);
}

void NaClStraceTlsInit(uint32_t thread_ptr,int32_t retval,uintptr_t sys_tls){
    printf("tls_init(%u, %lu) = %d\n", thread_ptr, sys_tls, retval);
}
void NaClStraceThreadCreate(void *prog_ctr, uint32_t stack_ptr, uint32_t thread_ptr, uint32_t second_thread_ptr, int32_t retval, uintptr_t sys_tls, uintptr_t sys_stack) {
    printf("thread_create(%p, %u, %u, %u, %lu, %lu) = %d\n", *(void **)prog_ctr, stack_ptr, thread_ptr, second_thread_ptr, sys_tls, sys_stack, retval);
}

// void NaClStraceTlsGet(struct NaClAppThread *natp) {
//     printf("TlsGet(natp=%p)\n", natp);
// }

void NaClStraceSecondTlsSet(uint32_t new_value) {
    printf("SecondTlsSet(new_value=%u)\n", new_value);
}
void NaClStraceMutexCreate(int32_t retval){
    printf("mutex_create() = %d\n", retval);

}
void NaClStraceMutexLock(int32_t mutex_handle, int32_t retval) {
    printf("mutex_lock(%d) = %d\n", mutex_handle, retval);

}
void NaClStraceMutexUnLock(int32_t mutex_handle, int32_t retval) {
    printf("mutex_unlock(%d) = %d\n", mutex_handle, retval);
}
void NaClStraceMutexTrylock(int32_t mutex_handle, int32_t retval){
    printf("mutex_trylock(%d) = %d\n", mutex_handle, retval);
}
void NaClStraceMutexDestroy(int32_t mutex_handle,int32_t retval){
    printf("mutex_destroy(%d) = %d\n", mutex_handle, retval);
}
void NaClStraceCondCreate(int32_t retval){
    printf("cond_create() = %d\n", retval);
}
void NaClStraceCondWait(int32_t cond_handle,int32_t mutex_handle,int32_t retval){
    printf("cond_wait(%d, %d) = %d\n", cond_handle, mutex_handle, retval);
}
void NaClStraceCondSignal(int32_t cond_handle,int32_t retval){
    printf("cond_signal(%d) = %d\n", cond_handle, retval);
}
void NaClStraceCondBroadcast(int32_t cond_handle, int32_t retval) {
    printf("CondBroadcast(cond_handle=%d, retval=%d)\n", cond_handle, retval);
}
void NaClStraceCondDestroy(int32_t cond_handle,int32_t retval){
    printf("cond_destroy(%d) = %d\n", cond_handle, retval);
}
void NaClStraceCondTimedWaitAbs(int32_t cond_handle,int32_t mutex_handle,int32_t retval){
    printf("cond_timedwaitabs(%d, %d) = %d\n", cond_handle, mutex_handle, retval);
}   
void NaClStraceSemCreate(int32_t init_value, int32_t retval) {
    printf("sem_create(%d) = %d\n", init_value, retval);

}