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
void NaClStraceIoctl(int d, unsigned long request, size_t ret);
void NaClStraceFstat(int d, size_t retval);
void NaClStraceStat(char* path, size_t retval);
void NaClStraceMkdir(char* path, int mode,size_t retval);
void NaClStraceRmdir(uint32_t path, int32_t retval);
void NaClStraceChdir(uint32_t path, int32_t retval);
void NaClStraceChmod(uint32_t path,int mode, int32_t retval);
void NaClStraceFchmod(int fd,int mode,int retval);
void NaClStraceFchdir(int fd,int32_t retval);
void NaClStraceLink(char* from,char* to);
void NaClStraceUnlink(char* pathname,int32_t retval);
void NaClStraceRename(uintptr_t usraddr, size_t length);
void NaClStraeCommon(uintptr_t usraddr, size_t length);