/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl kernel / service run-time system call numbers
 */

#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_BITS_NACL_SYSCALLS_H_
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_BITS_NACL_SYSCALLS_H_

/* intentionally not using zero */

/*
 * TODO(bsy,sehr): these identifiers should be NACL_ABI_SYS_<name>.
 */

#define NACL_sys_null                    1
#define NACL_sys_nameservice             2
#define NACL_sys_unlink                  4
#define NACL_sys_link                    5
#define NACL_sys_rename                  6

#define NACL_sys_dup                     8
#define NACL_sys_dup2                    9
#define NACL_sys_dup3                   10
#define NACL_sys_open                   11
#define NACL_sys_close                  12
#define NACL_sys_read                   13
#define NACL_sys_write                  14
#define NACL_sys_lseek                  15
#define NACL_sys_ioctl                  16
#define NACL_sys_stat                   17
#define NACL_sys_fstat                  18
#define NACL_sys_chmod                  19

#define NACL_sys_brk                    20
#define NACL_sys_mmap                   21
#define NACL_sys_munmap                 22

#define NACL_sys_getdents               23

#define NACL_sys_mprotect               24

#define NACL_sys_list_mappings          25

#define NACL_sys_exit                   30
#define NACL_sys_getpid                 31
#define NACL_sys_sched_yield            32
#define NACL_sys_sysconf                33
#define NACL_sys_send                   34
#define NACL_sys_sendto                 35
#define NACL_sys_recv                   36
#define NACL_sys_recvfrom               37

#define NACL_sys_gettimeofday           40
#define NACL_sys_clock                  41
#define NACL_sys_nanosleep              42
#define NACL_sys_clock_getres           43
#define NACL_sys_clock_gettime          44
#define NACL_sys_shutdown               45

#define NACL_sys_select                 46
#define NACL_sys_getcwd                 47
#define NACL_sys_poll                   48
#define NACL_sys_socketpair             49
#define NACL_sys_getuid                 50
#define NACL_sys_geteuid                51
#define NACL_sys_getgid                 52
#define NACL_sys_getegid                53
#define NACL_sys_flock                  54

#define NACL_sys_shmget                 56
#define NACL_sys_shmat                  57
#define NACL_sys_shmdt                  58
#define NACL_sys_shmctl                 59

#define NACL_sys_imc_makeboundsock      60
#define NACL_sys_imc_accept             61
#define NACL_sys_imc_connect            62
#define NACL_sys_imc_sendmsg            63
#define NACL_sys_imc_recvmsg            64
#define NACL_sys_imc_mem_obj_create     65
#define NACL_sys_imc_socketpair         66

#define NACL_sys_mutex_create           70
#define NACL_sys_mutex_lock             71
#define NACL_sys_mutex_trylock          72
#define NACL_sys_mutex_unlock           73
#define NACL_sys_cond_create            74
#define NACL_sys_cond_wait              75
#define NACL_sys_cond_signal            76
#define NACL_sys_cond_broadcast         77
#define NACL_sys_cond_timed_wait_abs    79

#define NACL_sys_thread_create          80
#define NACL_sys_thread_exit            81
#define NACL_sys_tls_init               82
#define NACL_sys_thread_nice            83
#define NACL_sys_tls_get                84
#define NACL_sys_second_tls_set         85
#define NACL_sys_second_tls_get         86
#define NACL_sys_exception_handler      87
#define NACL_sys_exception_stack        88
#define NACL_sys_exception_clear_flag   89

#define NACL_sys_sem_create             100
#define NACL_sys_sem_wait               101
#define NACL_sys_sem_post               102
#define NACL_sys_sem_get_value          103

#define NACL_sys_dyncode_create         104
#define NACL_sys_dyncode_modify         105
#define NACL_sys_dyncode_delete         106

#define NACL_sys_test_infoleak          109
#define NACL_sys_test_crash             110

/*
 * These syscall numbers are set aside for use in tests that add
 * syscalls that must coexist with the normal syscalls.
 */
#define NACL_sys_test_syscall_1         111
#define NACL_sys_test_syscall_2         112

#define NACL_sys_pipe                   114
#define NACL_sys_pipe2                  115
#define NACL_sys_fork                   116
#define NACL_sys_execv                  117
#define NACL_sys_execve                 118
#define NACL_sys_getppid                119
#define NACL_sys_waitpid                120
#define NACL_sys_wait                   121
#define NACL_sys_wait4                  122
#define NACL_sys_sigprocmask            123
#define NACL_sys_lstat                  124

#define NACL_sys_gethostname            125

#define NACL_sys_pread                  126
#define NACL_sys_pwrite                 127

#define NACL_sys_fcntl_get              128
#define NACL_sys_fcntl_set              129

#define NACL_sys_chdir                  130
#define NACL_sys_mkdir                  131
#define NACL_sys_rmdir                  132
#define NACL_sys_statfs                 133
#define NACL_sys_fstatfs                134
#define NACL_sys_fchmod                 135
#define NACL_sys_socket                 136
#define NACL_sys_getsockopt             137
#define NACL_sys_setsockopt             138


#define NACL_sys_access                 139
#define NACL_sys_accept                 140
#define NACL_sys_connect                141
#define NACL_sys_bind                   142
#define NACL_sys_listen                 143
#define NACL_sys_getsockname            144
#define NACL_sys_getpeername            145
#define NACL_sys_getifaddrs             146

#define NACL_sys_epoll_create           157
#define NACL_sys_epoll_ctl              158
#define NACL_sys_epoll_wait             159

#define NACL_MAX_SYSCALLS               256

#endif
