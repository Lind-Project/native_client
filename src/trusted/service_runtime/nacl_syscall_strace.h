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
