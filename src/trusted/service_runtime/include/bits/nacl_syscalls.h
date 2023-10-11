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

#define NACL_sys_truncate               26
#define NACL_sys_ftruncate              27

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

#define NACL_sys_mutex_destroy          69
#define NACL_sys_mutex_create           70
#define NACL_sys_mutex_lock             71
#define NACL_sys_mutex_trylock          72
#define NACL_sys_mutex_unlock           73
#define NACL_sys_cond_create            74
#define NACL_sys_cond_wait              75
#define NACL_sys_cond_signal            76
#define NACL_sys_cond_broadcast         77
#define NACL_sys_cond_destroy           78
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

#define NACL_sys_sem_init               91
#define NACL_sys_sem_wait               92
#define NACL_sys_sem_trywait            93
#define NACL_sys_sem_timedwait          94
#define NACL_sys_sem_post               95
#define NACL_sys_sem_destroy            96
#define NACL_sys_sem_getvalue           97

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

#define NACL_sys_sigaction		        147
#define NACL_sys_kill			        148
#define NACL_sys_sigprocmask            149
#define NACL_sys_lindsetitimer		    150

#define NACL_sys_epoll_create           157
#define NACL_sys_epoll_ctl              158
#define NACL_sys_epoll_wait             159
#define NACL_sys_fchdir                 161

#define NACL_sys_reg_restore            190
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore_reserved_slot2    191
#define __reg_restore_reserved_slot3    192
#define __reg_restore_reserved_slot4    193

#define NACL_sys_reg_restore1            194
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore1_reserved_slot2    195
#define __reg_restore1_reserved_slot3    196
#define __reg_restore1_reserved_slot4    197

#define NACL_sys_reg_restore2            198
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore2_reserved_slot2    199
#define __reg_restore2_reserved_slot3    200
#define __reg_restore2_reserved_slot4    201

#define NACL_sys_reg_restore3            202
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore3_reserved_slot2    203
#define __reg_restore3_reserved_slot3    204
#define __reg_restore3_reserved_slot4    205

#define NACL_sys_reg_restore4            206
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore4_reserved_slot2    207
#define __reg_restore4_reserved_slot3    208
#define __reg_restore4_reserved_slot4    209

#define NACL_sys_reg_restore5            210
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore5_reserved_slot2    211
#define __reg_restore5_reserved_slot3    212
#define __reg_restore5_reserved_slot4    213

#define NACL_sys_reg6_restore6           214
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore6_reserved_slot2    215
#define __reg_restore6_reserved_slot3    216
#define __reg_restore6_reserved_slot4    217

#define NACL_sys_reg_restore7            218
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore7_reserved_slot2    219
#define __reg_restore7_reserved_slot3    220
#define __reg_restore7_reserved_slot4    221

#define NACL_sys_reg_restore8            222
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore8_reserved_slot2    223
#define __reg_restore8_reserved_slot3    224
#define __reg_restore8_reserved_slot4    225

#define NACL_sys_reg_restore9            226
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore9_reserved_slot2    227
#define __reg_restore9_reserved_slot3    228
#define __reg_restore9_reserved_slot4    229

#define NACL_sys_reg_restore10            230
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore10_reserved_slot2    231
#define __reg_restore10_reserved_slot3    232
#define __reg_restore10_reserved_slot4    233

#define NACL_sys_reg_restore11            234
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore11_reserved_slot2    235
#define __reg_restore11_reserved_slot3    236
#define __reg_restore11_reserved_slot4    237

#define NACL_sys_reg_restore12            238
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore12_reserved_slot2    239
#define __reg_restore12_reserved_slot3    240
#define __reg_restore12_reserved_slot4    241

#define NACL_sys_reg_restore13            242
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore13_reserved_slot2    243
#define __reg_restore13_reserved_slot3    244
#define __reg_restore13_reserved_slot4    245

#define NACL_sys_reg_restore14            246
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore14_reserved_slot2    247
#define __reg_restore14_reserved_slot3    248
#define __reg_restore14_reserved_slot4    249

#define NACL_sys_reg_restore15            250
//We need to reserve more slots as the reg restoration takes more than 32 bytes
#define __reg_restore15_reserved_slot2    251
#define __reg_restore15_reserved_slot3    252
#define __reg_restore15_reserved_slot4    253

#define NACL_sys_sigmask_sigreturn      255

#define NACL_MAX_SYSCALLS               256

#endif
