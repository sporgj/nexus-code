#pragma once

typedef enum {
    ECALL_FILLDIR       = 2,
    ECALL_CREATE        = 3,
    ECALL_LOOKUP        = 4,
    ECALL_REMOVE        = 5,
    ECALL_HARDLINK      = 6,
    ECALL_SYMLINK       = 7,
    ECALL_RENAME        = 8,

    ECALL_STOREACL      = 9,

    ECALL_ENCRYPT       = 10,
    ECALL_DECRYPT       = 11
} ecall_op;

typedef enum {
    IOBUF_ALLOC         = 0x101,
    IOBUF_GET           = 0x102,
    IOBUF_PUT           = 0x103,
    IOBUF_FLUSH         = 0x104,
    IOBUF_LOCK          = 0x105,
    IOBUF_NEW           = 0x106,
    IOBUF_DEL           = 0x107,
    IOBUF_HARDLINK      = 0x108,
    IOBUF_RENAME        = 0x109,
    IOBUF_STAT          = 0x110
} ocall_op;



#ifndef TRACE
#define DECALL_PROBE 0
#endif

#include "backend_sgx.probes.h"
