#pragma once

#include <sgx_spinlock.h>

#include <nexus_uuid.h>


struct nexus_metadata;


typedef enum {
    DENTRY_PARENT_CHANGED  = 0x0001,
    DENTRY_DELETED         = 0x0002
} dcache_flags_t;

struct nexus_dentry {
    nexus_dirent_type_t         dirent_type;

    dcache_flags_t              flags;

    size_t                      d_count;

    char                        name[NEXUS_NAME_MAX];
    size_t                      name_len;

    struct nexus_uuid           link_uuid;

    struct nexus_dentry       * parent;
    struct nexus_metadata     * metadata;

    struct list_head            children;

    struct list_head            siblings;

    struct list_head            aliases; // other hardlinks
};



extern struct nexus_dentry      * root_dentry;


typedef enum {
    PATH_WALK_NORMAL        = 1,
    PATH_WALK_PARENT        = 2    // stop at the parent and return that dentry
} path_walk_type_t;


// structure populated during lookups
struct path_walker {
    struct nexus_dentry * parent_dentry;

    char                * remaining_path; // the path left to be looked up

    path_walk_type_t      type;
};

// initializes the root dentry
void
dcache_init_root();


struct nexus_dentry *
dentry_get(struct nexus_dentry * dentry);

void
dentry_put(struct nexus_dentry * dentry);


int
dentry_revalidate(struct nexus_dentry * dentry, nexus_io_flags_t flags);

/**
 * Performs a dentry lookups
 * @param root_dentry
 * @param path
 */
struct nexus_dentry *
dentry_lookup(struct path_walker * walker);

void
dentry_delete(struct nexus_dentry * dentry);

/**
 * @param parent_dentry
 * @param child
 */
void
dentry_delete_child(struct nexus_dentry * parent_dentry, const char * child);



