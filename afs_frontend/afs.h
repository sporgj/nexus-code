#pragma once
#include <stdint.h>
#include <stdlib.h>

#include <linux/ioctl.h>

#include <uuid/uuid.h>


#define PAGE_SIZE (4096)


#define UCAFS_IOC_MAGIC 'W'

#define IOCTL_ADD_PATH  _IOW(UCAFS_IOC_MAGIC, 1, char *)
#define IOCTL_MMAP_SIZE _IOR(UCAFS_IOC_MAGIC, 2, int *)

#define UCAFS_IOC_MAXNR 2

typedef struct {
    int  len;
    char path[0];
} watchlist_path_t;

#define UCAFS_DATA_BUFPAGES (1)
#define UCAFS_DATA_BUFLEN (PAGE_SIZE << UCAFS_DATA_BUFPAGES)

#define UCAFS_PATH_MAX  (4096)
#define UCAFS_FNAME_MAX (256)



typedef enum {
    UC_STATUS_GOOD = 0,
    UC_STATUS_NOOP,
    UC_STATUS_ERROR
} uc_err_t;

typedef enum {
    UC_ANY  = 0x0,
    UC_FILE = 0x1,
    UC_DIR  = 0x2,
    UC_LINK = 0x3
} __attribute__((packed)) nexus_entry_type;

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
    AFS_OP_CHECKACL      = 10, /* We almost certainly don't need this */
    
    AFS_OP_XFER_INIT     = 11, /* These are crap and need to go */
    AFS_OP_XFER_RUN      = 12,
    AFS_OP_XFER_EXIT     = 13,

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
