#include <string.h>
#include <stdio.h>


void NaClStraceGetpid(int pid);
void NaClStraceOpen(char* path, int flags, int mode, int fd);
void NaClStraceClose(int d, int ret);
void NaClStraceRead(int d, void *buf, size_t count, int ret);
void NaClStraceExit(int status);