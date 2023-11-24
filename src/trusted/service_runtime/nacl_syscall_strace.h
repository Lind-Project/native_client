#include <string.h>
#include <stdio.h>
#include "sys/types.h"
#include <stdint.h>

void NaClStraceGetpid(int pid);
void NaClStraceOpen(char* path, int flags, int mode, int fd);
void NaClStraceClose(int d, int ret);
void NaClStraceRead(int d, void *buf, size_t count, int ret);
void NaClStraceExit(int status);
void NaClStraceThreadExit(int stack_flag,uint32_t  zero);
void NaClStraceDup(int oldfd,int ret);
void NaClStraceDup2(int oldfd,int newfd,int ret);
void NaClStraceDup3(int oldfd,int newfd,int flags,int ret);
void NaClStraceGetdents(int d,void *drip,int  count,size_t ret,ssize_t getdents_ret,uintptr_t sysaddr);
void NaClStracePread(int d, void *buf, int count,  size_t log_bytes,int32_t ret);
void NaClStraceWrite(int d, void *buf, int count, size_t ret);
void NaClStracePWrite(int d, void *buf, int count,off_t offset, size_t ret);
void NaClStraceIoctl(int d, unsigned long request, size_t ret);
void NaClStraceFstat(int d, size_t retval);
void NaClStraceStat(char* path, size_t retval);
void NaClStraceMkdir(char* path, int mode,size_t retval);
void NaClStraceRmdir(uint32_t path, int32_t retval);
void NaClStraceChdir(uint32_t path, int32_t retval);
void NaClStraceChmod(uint32_t path,int mode, int32_t retval);
void NaClStraceFchmod(int fd,int mode,int retval);
void NaClStraceFchdir(int fd,int32_t retval);
void NaClStraceGetcwd(char buf, size_t size, uintptr_t sysaddr, int32_t retval);
void NaClStraceLink(char* from,char* to);
void NaClStraceUnlink(char* pathname,int32_t retval);
void NaClStraceRename(const char *oldpath, const char *newpath, int32_t retval);
void NaClStraceCommon(uintptr_t usraddr, size_t length);
void NaClStraceMmap(void *start,size_t length,int prot,int flags,int d,int32_t retval);
void NaClStraceMunmap(void *start,size_t length,int32_t retval,uintptr_t sysaddr,size_t alloc_rounded_length);
void NaClStraceMprotectInternal(uint32_t start,size_t length,int prot,uintptr_t sysaddr,int32_t retval,int holding_app_lock);
void NaClStraceMprotect(uint32_t start,size_t length,int prot);
void NaClStraceShmat(int key,size_t size,int shmflg,int32_t retval,size_t alloc_rounded_size);
void NaClStraceShmget(int key,size_t size,int shmflg,int32_t retval,size_t alloc_rounded_size);
void NaClStraceShmdt(int shmid,void *shmaddr,int shmflg);
void NaClStraceShmctl(int shmid,int cmd, int32_t retval);