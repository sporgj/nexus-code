#pragma once

#include <nexus_uuid.h>
#include <nexus_ringbuf.h>


struct metadata_buf;

typedef enum fs_op_type {
    FS_OP_FILLDIR       = 2,
    FS_OP_CREATE        = 3,
    FS_OP_LOOKUP        = 4,
    FS_OP_REMOVE        = 5,
    FS_OP_HARDLINK      = 6,
    FS_OP_SYMLINK       = 7,
    FS_OP_RENAME        = 8,

    FS_OP_STOREACL      = 9,

    FS_OP_ENCRYPT       = 10,
    FS_OP_DECRYPT       = 11
} fs_op_type_t;


struct fs_metadata {
    struct nexus_uuid             uuid;

    uint8_t                     * data_ptr;

    struct metadata_buf         * buf;
};


struct fs_dentry {
    struct fs_metadata          * metadata;

    struct nexus_uuid             uuid;

    struct nexus_dentry         * parent;

    struct list_head              children;
    struct list_head              siblings;
};


struct fs_manager {
    size_t                        fs_ops_counter;
    size_t                        fs_ops_len;
    struct list_head              fs_ops_list;
};


extern struct nexus_ringbuf * updated_dirents;


// namei.c

/**
 * Updates a dentry's timestamp returns the affected object
 * @param parent the dentry to start from
 * @param name
 * @param uuid
 */
struct fs_dentry *
__namei_touch_dentry(struct fs_dentry * parent, char * name, struct nexus_uuid * uuid);


namei_touch_dentry

/**
 * Tries to find the dentry pointing at that path
 * @param root
 * @param fullpath
 * @return NULL if nothing found
 */
struct fs_dentry *
namei_get_dentry(struct fs_dentry * root, char * fullpath);



// fs.c

struct nexus_fsop_req *
fs_create_op(struct fs_manager * fs_manager, fs_op_type type);


int
fs_process_op(struct fs_manager * fs_manager, struct nexus_fsop_req * req);
