#pragma once
#ifdef __KERNEL__
#else
#include <stdint.h>
#endif

#if defined(UCPRIV_ENCLAVE) || defined(KERNEL)
#if defined(KERNEL)
#include <linux/types.h>
#endif

typedef struct {
    uint8_t bin[16];
} uuid_t;
#else
#include <uuid/uuid.h>
#include <stdlib.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#endif

#ifndef UCPRIV_ENCLAVE
#include <linux/ioctl.h>

#define NEXUS_IOC_MAGIC 'W'

#define IOCTL_ADD_PATH _IOW(NEXUS_IOC_MAGIC, 1, char *)
#define IOCTL_MMAP_SIZE _IOR(NEXUS_IOC_MAGIC, 2, int *)

#define NEXUS_IOC_MAXNR 2

typedef struct {
    int len;
    char path[0];
} watchlist_path_t;
#endif

#define NEXUS_DATA_BUFPAGES 1
#define NEXUS_DATA_BUFLEN (PAGE_SIZE << NEXUS_DATA_BUFPAGES)

#define NEXUS_PATH_MAX 4096
#define NEXUS_FNAME_MAX 256

#define NEXUS_SUPER_FNAME "nexus"
#define NEXUS_REPO_DIR ".afsx"
#define NEXUS_WATCH_DIR "sgx"
#define NEXUS_METADATA_DIR NEXUS_REPO_DIR
#define NEXUS_ROOT_DIRNODE  "root_dnode"

#define CONFIG_PUBKEY   "profile/public_key"
#define CONFIG_PRIVKEY  "profile/private_key"
#define CONFIG_ENCLAVE_PUBKEY   "profile/enclave_pubkey"

#define CONFIG_GCM_KEYBITS 128
#define CONFIG_CRYPTO_BUFLEN   256

typedef enum {
    UC_STATUS_GOOD = 0,
    UC_STATUS_NOOP,
    UC_STATUS_ERROR
} uc_err_t;

typedef enum {
    UC_ANY = 0x0,
    UC_FILE = 0x1,
    UC_DIR = 0x2,
    UC_LINK = 0x3
} __attribute__((packed)) nexus_entry_type;

typedef enum {
    ACL_READ = 0x1,
    ACL_WRITE = 0x2,
    ACL_INSERT = 0x4,
    ACL_LOOKUP = 0x8,
    ACL_DELETE = 0x10,
    ACL_LOCK = 0x20,
    ACL_ADMINISTER = 0x40
} acl_type_t;

/* prefixes for the different file types */
#define UC_METADATA_PREFIX "m"
#define UC_METADIR_PREFIX "_"
#define UC_FILEDATA_PREFIX "f"
#define UC_PREFIX_LEN(x) sizeof(x) - 1

#define UC_ENCRYPT 0x00000001
#define UC_DECRYPT 0x00000002
#define UC_VERIFY 0x00000004
typedef uint32_t uc_crypto_op_t;

typedef enum {
    NEXUS_STORE = UC_ENCRYPT,
    NEXUS_FETCH = UC_DECRYPT
} uc_xfer_op_t;

#define NEXUS_CHUNK_LOG 20
#define NEXUS_CHUNK_SIZE (1 << NEXUS_CHUNK_LOG)

typedef struct {
    uc_xfer_op_t op;
    uint32_t xfer_size;
    uint32_t offset;
    uint32_t file_size;
} __attribute__((packed)) xfer_req_t;

typedef struct {
    int xfer_id;
} __attribute__((packed)) xfer_rsp_t;

static inline size_t
NEXUS_CHUNK_BASE(size_t offset)
{
    return ((offset < NEXUS_CHUNK_SIZE)
                ? 0
                : (((offset - NEXUS_CHUNK_SIZE) & ~(NEXUS_CHUNK_SIZE - 1))
                   + NEXUS_CHUNK_SIZE));
}

static inline size_t
NEXUS_CHUNK_NUM(size_t offset)
{
    return ((offset < NEXUS_CHUNK_SIZE)
                ? 0
                : 1 + ((offset - (size_t)NEXUS_CHUNK_SIZE) >> NEXUS_CHUNK_LOG));
}

static inline size_t
NEXUS_CHUNK_COUNT(size_t file_size)
{
    return NEXUS_CHUNK_NUM(file_size) + 1;
}

/* module-userspace data structures */
typedef uint16_t mid_t;

typedef enum {
    NEXUS_MSG_PING = 1,
    NEXUS_MSG_FILLDIR,
    NEXUS_MSG_CREATE,
    NEXUS_MSG_LOOKUP,
    NEXUS_MSG_REMOVE,
    NEXUS_MSG_HARDLINK,
    NEXUS_MSG_SYMLINK,
    NEXUS_MSG_RENAME,
    NEXUS_MSG_STOREACL,
    NEXUS_MSG_CHECKACL,
    NEXUS_MSG_XFER_INIT,
    NEXUS_MSG_XFER_RUN,
    NEXUS_MSG_XFER_EXIT,
} uc_msg_type_t;

typedef struct {
    uc_msg_type_t type;
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
