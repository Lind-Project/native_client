#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_SIGACTION_H_
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_SIGACTION_H_

#include <stdint.h>

struct nacl_abi_iovec {
	uintptr_t iov_base;
	uint32_t iov_len;
};

#endif
