#pragma once
#include <stdint.h>
#include <stdlib.h>

#include <linux/ioctl.h>

#include <nexus.h>
#include <nexus_util.h>


#define NEXUS_IOC_MAGIC            'W'
#define NEXUS_IOCTL_CREATE_VOLUME  _IOW(NEXUS_IOC_MAGIC, 1, char *)
#define IOCTL_MMAP_SIZE            _IOR(NEXUS_IOC_MAGIC, 2, int *)
#define NEXUS_IOC_MAXNR             2


#define NEXUS_DEVICE "/dev/nexus"


#define NEXUS_DATABUF_SIZE (4096 * 32)



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

    AFS_OP_ENCRYPT_START = 14,
    AFS_OP_ENCRYPT_READY = 15,
    AFS_OP_ENCRYPT_STOP  = 16,

    AFS_OP_DECRYPT_START = 17,
    AFS_OP_DECRYPT_READY = 18,
    AFS_OP_DECRYPT_STOP  = 19
} afs_op_type_t;



