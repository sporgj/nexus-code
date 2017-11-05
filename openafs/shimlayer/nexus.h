#pragma once


/* maximum path length */
#define NEXUS_PATH_MAX  (4096)

/* the maximum file name */
#define NEXUS_FNAME_MAX (256)




/* filesystem object types */
/* JRL: What is an ANY object? */


typedef enum {
    NEXUS_STORE = 1,
    NEXUS_FETCH = 2
} nexus_xfer_op_t;

/* JRL: What do these even mean in the context of Nexus???? */
struct nexus_fs_acl {
    uint64_t    read   : 1;
    uint64_t    write  : 1;
    uint64_t    insert : 1;
    uint64_t    lookup : 1;
    uint64_t    delete : 1;
    uint64_t    lock   : 1;
    uint64_t    admin  : 1;
};


