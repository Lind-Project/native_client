#include <string.h>
#include <stdio.h>

#include <sys/shm.h>
EXTERN_C_BEGIN
void NaClStraceGetpid(int pid);
void NaClStraceOpen(char* path, int flags, int mode, int fd);
void NaClStraceClose(int d, int ret);
EXTERN_C_END