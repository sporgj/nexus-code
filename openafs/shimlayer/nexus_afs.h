#pragma once


#define NEXUS_IOC_MAGIC 'W'
#define IOCTL_ADD_PATH  _IOW(NEXUS_IOC_MAGIC, 1, char *)
#define IOCTL_MMAP_SIZE _IOR(NEXUS_IOC_MAGIC, 2, int *)
#define NEXUS_IOC_MAXNR 2

/* for the transfer buffers */
#define NEXUS_DATABUF_ORDER (9)
#define NEXUS_DATABUF_PAGES (1 << NEXUS_DATABUF_ORDER)
#define NEXUS_DATABUF_SIZE  (NEXUS_DATABUF_PAGES << PAGE_SHIFT)

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

    AFS_OP_ENCRYPT       = 10,
    AFS_OP_DECRYPT       = 11
} afs_op_type_t;
