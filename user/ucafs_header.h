#pragma once
#ifdef __KERNEL__
#else
#include <stdint.h>
#endif

#include "ucafs_env.h"

#if defined(UCPRIV_ENCLAVE) || defined(KERNEL)
typedef struct {
    uint8_t bin[16];
} uuid_t;
#else
#include <uuid/uuid.h>
#endif

#define UCAFS_PATH_MAX 4096
#define UCAFS_FNAME_MAX 256

#ifdef UCAFS_DEV
#define UCAFS_PATH_KERN "/xyz.vm/user/djoko"
#define UCAFS_PATH "/afs" UCAFS_PATH_KERN
#else
#define UCAFS_PATH_KERN "/maatta.sgx/user/bruyne"
#define UCAFS_PATH "/afs" UCAFS_PATH_KERN
#endif

#define UC_AFS_WATCH "sgx"

typedef enum {
    UC_STATUS_NOOP,
    UC_STATUS_ERROR
} uc_err_t;

typedef enum {
    UC_FILE = 0x00000001,
    UC_DIR = 0x00000002,
    UC_LINK = 0x00000004,
    UC_ANY = UC_FILE | UC_DIR | UC_LINK,
} ucafs_entry_type;

/* prefixes for the different file types */
#define UC_METADATA_PREFIX "md"
#define UC_FILEDATA_PREFIX "fd"
#define UC_PREFIX_LEN(x) sizeof(x) - 1

#define UC_ENCRYPT 0x00000001
#define UC_DECRYPT 0x00000002
#define UC_VERIFY 0x00000004
typedef uint32_t uc_crypto_op_t;

typedef enum {
    UCAFS_STORE = UC_ENCRYPT,
    UCAFS_FETCH = UC_DECRYPT
} uc_xfer_op_t;

#define UCAFS_CHUNK_LOG 20
#define UCAFS_CHUNK_SIZE (1 << UCAFS_CHUNK_LOG)

typedef struct {
    uc_xfer_op_t op;
    uint16_t xfer_size;
    uint32_t offset;
    uint32_t file_size;
    int xfer_id;
} __attribute__((packed)) uc_fetchstore_t;

static inline int
UCAFS_CHUNK_BASE(int offset)
{
    return ((offset < UCAFS_CHUNK_SIZE)
                ? 0
                : (((offset - UCAFS_CHUNK_SIZE) & ~(UCAFS_CHUNK_SIZE - 1))
                   + UCAFS_CHUNK_SIZE));
}

static inline int
UCAFS_CHUNK_NUM(int offset)
{
    return ((offset < UCAFS_CHUNK_SIZE)
                ? 0
                : 1 + ((offset - UCAFS_CHUNK_SIZE) >> UCAFS_CHUNK_LOG));
}

static inline int
UCAFS_CHUNK_COUNT(int file_size)
{
    return UCAFS_CHUNK_NUM(file_size) + 1;
}

static inline size_t
CHUNK_RATIO(int numerator_log, int denomintor_log)
{
    int ratio = numerator_log - denomintor_log;
    return ratio <= 0 ? 2 : (1 << ratio) + 1;
}

/* module-userspace data structures */
typedef uint16_t mid_t;

typedef enum {
    UCAFS_MSG_PING,
    UCAFS_MSG_FILLDIR,
    UCAFS_MSG_CREATE,
    UCAFS_MSG_LOOKUP,
    UCAFS_MSG_REMOVE,
    UCAFS_MSG_HARDLINK,
    UCAFS_MSG_SYMLINK,
    UCAFS_MSG_RENAME,
    UCAFS_MSG_STORE,
    UCAFS_MSG_FETCH
} uc_msg_type_t;

typedef enum {
    UCAFS_SUBMSG_NONE,
    UCAFS_SUBMSG_BEGIN,
    UCAFS_SUBMSG_PROCESS,
    UCAFS_SUBMSG_FINISH
} uc_msg_subtype_t;

typedef struct {
    uc_msg_type_t type;
    uc_msg_subtype_t sub_type;
    uint16_t msg_id; /* the ID of the message */
    uint16_t ack_id; /* the message it responds to */
    uint32_t len; /* the length of the payload */
    int32_t status; /* status from the call, set by return */
    char payload[0];
} ucrpc_msg_t;

extern mid_t msg_counter;
#define MSG_SIZE(msg) sizeof(ucrpc_msg_t) + (((ucrpc_msg_t *)msg)->len)

#undef TYPE_TO_STR
#define TYPE_TO_STR(t)                                                         \
    (t == UC_FILE ? "F" : (t == UC_DIR ? "D" : (t == UC_LINK ? "L" : "U")))
