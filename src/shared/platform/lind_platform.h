/*
 * lind_platform.h
 *
 *  Created on: Jul 23, 2013
 *      Author: sji
 */

#ifndef LIND_PLATFORM_H_
#define LIND_PLATFORM_H_

#include <sys/types.h>
#if NACL_LINUX
# include <sys/statfs.h>
#endif
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>

/* avoid errors caused by conflicts with feature_test_macros(7) */
#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE

#include <unistd.h>
#include <stdint.h>
#include <Python.h>

#include "native_client/src/shared/platform/lind_stat.h"

#if NACL_OSX
# define __SOCKADDR_ARG struct sockaddr
#endif

#define LIND_debug_noop                 1
#define LIND_safe_fs_access             2
#define LIND_debug_trace                3
#define LIND_safe_fs_unlink             4
#define LIND_safe_fs_link               5
#define LIND_safe_fs_xstat              9
#define LIND_safe_fs_open               10
#define LIND_safe_fs_close              11
#define LIND_safe_fs_read               12
#define LIND_safe_fs_write              13
#define LIND_safe_fs_lseek              14
#define LIND_fs_ioctl                   15
#define LIND_safe_fs_fxstat             17
#define LIND_safe_fs_fstatfs            19
#define LIND_safe_fs_mmap               21
#define LIND_safe_fs_munmap             22
#define LIND_safe_fs_getdents           23
#define LIND_safe_fs_dup                24
#define LIND_safe_fs_dup2               25
#define LIND_safe_fs_statfs             26
#define LIND_safe_fs_fcntl              28

#define LIND_safe_sys_getppid           29
#define LIND_safe_sys_exit              30
#define LIND_safe_sys_getpid            31

#define LIND_safe_net_bind              33
#define LIND_safe_net_send              34
#define LIND_safe_net_sendto            35
#define LIND_safe_net_recv              36
#define LIND_safe_net_recvfrom          37
#define LIND_safe_net_connect           38
#define LIND_safe_net_listen            39
#define LIND_safe_net_accept            40
#define LIND_safe_net_getpeername       41
#define LIND_safe_net_getsockname       42
#define LIND_safe_net_getsockopt        43
#define LIND_safe_net_setsockopt        44
#define LIND_safe_net_shutdown          45
#define LIND_safe_net_select            46
#define LIND_safe_net_getifaddrs        47
#define LIND_safe_net_poll              48
#define LIND_safe_net_socketpair        49
#define LIND_safe_sys_getuid            50
#define LIND_safe_sys_geteuid           51
#define LIND_safe_sys_getgid            52
#define LIND_safe_sys_getegid           53
#define LIND_safe_fs_flock              54
#define LIND_safe_fs_rename             55

#define LIND_safe_fs_pipe               66
#define LIND_safe_fs_pipe2              67
#define LIND_safe_fs_fork               68
#define LIND_safe_fs_exec               69

#define LIND_safe_net_gethostname       125

#define LIND_safe_net_socket            136

#define LIND_safe_fs_pread              126
#define LIND_safe_fs_pwrite             127
#define LIND_safe_fs_chdir              130
#define LIND_safe_fs_mkdir              131
#define LIND_safe_fs_rmdir              132



struct select_results {
    struct timeval used_t;
    fd_set r;
    fd_set w;
    fd_set e;
};

int LindPythonInit(void);
int LindPythonFinalize(void);

PyObject* CallPythonFunc(PyObject* context, const char* func, PyObject* args);
int ParseResponse(PyObject* response, int* isError, int* code, char** dataOrMessage, int* len);

int lind_pread(int fd, void* buf, size_t count, off_t offset, int cageid);
int lind_pwrite(int fd, const void *buf, size_t count, off_t offset, int cageid);
int lind_access (const char *file, int mode, int cageid);
int lind_unlink (const char *name, int cageid);
int lind_link (const char *from, const char *to, int cageid);
int lind_chdir (const char *name, int cageid);
int lind_mkdir (const char *path, int mode, int cageid);
int lind_rmdir (const char *path, int cageid);
int lind_xstat (const char *path, struct lind_stat *buf, int cageid);
int lind_open (const char *path, int flags, int mode, int cageid);
int lind_close (int fd, int cageid);
int lind_read (int fd, void *buf, int size, int cageid);
int lind_write (int fd, const void *buf, size_t count, int cageid);
int lind_lseek (int fd, off_t offset, int whence, int cageid);
int lind_fxstat (int fd, struct lind_stat *buf, int cageid);
int lind_fstatfs (int fd, struct lind_statfs *buf, int cageid);
int lind_statfs (const char *path, struct lind_statfs *buf, int cageid);
int lind_noop (int cageid);
int lind_dup (int oldfd, int cageid);
int lind_dup2 (int oldfd, int newfd, int cageid);
int lind_getdents (int fd, char *buf, size_t nbytes, int cageid);
int lind_fcntl_get (int fd, int cmd, int cageid);
int lind_fcntl_set (int fd, int cmd, long set_op, int cageid);

int lind_bind (int sockfd, const struct sockaddr *addr, socklen_t addrlen, int cageid);
int lind_send (int sockfd, const void *buf, size_t len, int flags, int cageid);
int lind_recv (int sockfd, void *buf, size_t len, int flags, int cageid);
int lind_connect (int sockfd, const struct sockaddr *src_addr, socklen_t addrlen, int cageid);
int lind_listen (int sockfd, int backlog, int cageid);
int lind_sendto (int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, int cageid);
int lind_accept (int sockfd, struct sockaddr *addr, socklen_t *addrlen, int cageid);
int lind_getpeername (int sockfd, socklen_t addrlen_in, __SOCKADDR_ARG addr, socklen_t * addrlen_out);
int lind_setsockopt (int sockfd, int level, int optname, const void *optval, socklen_t optlen, int cageid);
int lind_getsockopt (int sockfd, int level, int optname, void *optval, socklen_t *optlen, int cageid);
int lind_shutdown (int sockfd, int how, int cageid);
int lind_select (int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval *timeout, struct select_results *result);
int lind_getifaddrs (int ifaddrs_buf_siz, void *ifaddrs);
int lind_recvfrom (int sockfd, size_t len, int flags, socklen_t addrlen, socklen_t * addrlen_out, void *buf, struct sockaddr *src_addr, int cageid);
int lind_poll (int nfds, int timeout, struct pollfd *fds_in, struct pollfd *fds_out);
int lind_socketpair (int domain, int type, int protocol, int *fds);
int lind_getuid (int cageid);
int lind_geteuid (int cageid);
int lind_getgid (int cageid);
int lind_getegid (int cageid);
int lind_flock (int fd, int operation, int cageid);
int lind_pipe(int* pipefds, int cageid);
int lind_pipe2(int* pipefds, int flags, int cageid);  /* unimplemented */
int lind_fork(int newcageid, int cageid);
int lind_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset, int cageid);
int lind_munmap(void *addr, size_t length, int cageid);
int lind_getpid(int cageid);
int lind_getppid(int cageid);
int lind_exec(int newcageid, int cageid);
void lind_exit(int status, int cageid);

int lind_gethostname (char *name, size_t len, int cageid);

int lind_socket (int domain, int type, int protocol, int cageid);

#endif /* LIND_PLATFORM_H_ */
