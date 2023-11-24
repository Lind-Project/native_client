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