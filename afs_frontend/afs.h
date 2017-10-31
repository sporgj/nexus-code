#pragma once
#ifndef MODULE
#include <stdint.h>
#include <stdlib.h>

#include <linux/ioctl.h>

#include <uuid/uuid.h>
#endif

#include <nexus.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE (4096)
#endif

#define NEXUS_IOC_MAGIC 'W'
#define IOCTL_ADD_PATH  _IOW(NEXUS_IOC_MAGIC, 1, char *)
#define IOCTL_MMAP_SIZE _IOR(NEXUS_IOC_MAGIC, 2, int *)
#define NEXUS_IOC_MAXNR 2

#define NEXUS_MOD_NAME      "nx_mod"
#define NEXUS_PROC_NAME     "nx_proc"

struct nexus_watched_path {
    size_t len;
    char   path[0];
};

typedef enum {
    ACL_READ       = 0x1,
    ACL_WRITE      = 0x2,
    ACL_INSERT     = 0x4,
    ACL_LOOKUP     = 0x8,
    ACL_DELETE     = 0x10,
    ACL_LOCK       = 0x20,
    ACL_ADMINISTER = 0x40
} acl_type_t;


typedef struct {
    uint32_t      op;
    uint32_t      xfer_size;
    uint64_t      offset;
    uint64_t      file_size;
} __attribute__((packed)) xfer_req_t;

typedef struct {
    int xfer_id;
} __attribute__((packed)) xfer_rsp_t;

/* the shim layer messages between kernel and userspace */
typedef enum {
    AFS_OP_INVALID       = 0,
    AFS_OP_PING          = 1,
    AFS_OP_FILLDIR       = 2,
    AFS_OP_CREATE        = 3,
    AFS_OP_LOOKUP        = 4,
    AFS_OP_REMOVE        = 5,
    AFS_OP_HARDLINK      = 6,
    AFS_OP_SYMLINK       = 7,
    AFS_OP_RENAME        = 8,

    AFS_OP_STOREACL      = 9,  /* Do we need this */

    AFS_OP_ENCRYPT_START = 14,
    AFS_OP_ENCRYPT_READY = 15,
    AFS_OP_ENCRYPT_STOP  = 16,

    AFS_OP_DECRYPT_START = 17,
    AFS_OP_DECRYPT_READY = 18,
    AFS_OP_DECRYPT_STOP  = 19
} afs_op_type_t;

struct afs_op_msg {
    afs_op_type_t type;
    uint16_t      msg_id; /* the ID of the message */
    uint16_t      ack_id; /* the message it responds to */
    uint32_t      len;    /* the length of the payload */
    int32_t       status; /* status from the call, set by return */
    char          payload[0];
};

#define AFS_OP_MSG_SIZE(m)\
    sizeof(struct afs_op_msg) + (((struct afs_op_msg *)m)->len)

/* counter for request and response messages */
typedef uint16_t mid_t;
