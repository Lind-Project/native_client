#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_SIGACTION_H_
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_SIGACTION_H_

#include <signal.h>
#include <stdint.h>

struct nacl_sigset {
	unsigned long int val[16];
};

struct nacl_abi_sigaction {
	__sighandler_t __sa_handler;
	struct nacl_sigset sa_mask;
	int sa_flags;
};

#endif
