#pragma once

// TODO revise constant values
typedef enum {
    ECALL_FILLDIR       = 0x02,
    ECALL_CREATE        = 0x03,
    ECALL_LOOKUP        = 0x04,
    ECALL_STAT          = 0x05,
    ECALL_REMOVE        = 0x06,

    ECALL_HARDLINK      = 0x07,
    ECALL_SYMLINK       = 0x08,
    ECALL_READLINK      = 0x09,
    ECALL_RENAME        = 0x10,

    ECALL_ENCRYPT       = 0x12,
    ECALL_DECRYPT       = 0x13
} ecall_op;

typedef enum {
    IOBUF_ALLOC         = 0x101,
    IOBUF_GET           = 0x102,
    IOBUF_PUT           = 0x103,
    IOBUF_FLUSH         = 0x104,
    IOBUF_NEW           = 0x106,
    IOBUF_DEL           = 0x107,
    IOBUF_HARDLINK      = 0x108,
    IOBUF_RENAME        = 0x109,
    IOBUF_STAT          = 0x110,

    IOBUF_LOCK          = 0x111,
    IOBUF_UNLOCK        = 0x112,
} ocall_op;



#ifdef DTRACE_ENABLED

#include "backend_sgx.probes.h"

#else

#define BACKEND_SGX_ECALL_START(...)     (void)0
#define BACKEND_SGX_ECALL_FINISH(...)    (void)0

#define BACKEND_SGX_IOBUF_START(...)     (void)0
#define BACKEND_SGX_IOBUF_FINISH(...)    (void)0

#endif
