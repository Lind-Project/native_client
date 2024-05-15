#ifndef NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_UIO_H_
#define NATIVE_CLIENT_SRC_TRUSTED_SERVICE_RUNTIME_INCLUDE_SYS_UIO_H_

#include <stdint.h>

struct nacl_abi_iovec {
	uint32_t *iov_base;
	unsigned int iov_len;
};

#endif
