#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_SIGACTION_H_
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_SIGACTION_H_

#include <signal.h>
#include <stdint.h>

struct nacl_abi_sigaction {
	uint32_t __sa_handler;
	uint64_t sa_mask;
	int sa_flags;
};

#endif
