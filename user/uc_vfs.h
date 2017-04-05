#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdatomic.h>

#include <uv.h>

#include "uc_dirnode.h"
#include "uc_filebox.h"

#include "third/hashmap.h"
#include "third/queue.h"

#define MAP_INIT_SIZE 2 << 12

typedef atomic_int ref_t;

typedef enum {
    DIROPS_CREATE = 0x01,
    DIROPS_LOOKUP = 0x02,
    DIROPS_CHECKACL = 0x04,
    DIROPS_SETACL = 0x08,
    DIROPS_HARDLINK = 0x10,
    DIROPS_SYMLINK = 0x20,
    DIROPS_MOVE = 0x40,
    DIROPS_FILEOP = 0x80
} lookup_flags_t;

struct dentry_tree;
struct metadata_entry;

struct path_element {
    shadow_t * shdw;
    TAILQ_ENTRY(path_element) next_entry;
};

typedef TAILQ_HEAD(path_builder, path_element) path_builder_t;

typedef struct dentry_list_entry {
    struct uc_dentry * dentry;
    TAILQ_ENTRY(dentry_list_entry) next_entry;
} dentry_list_entry_t;

typedef TAILQ_HEAD(dentry_head, dentry_list_entry) dentry_list_head_t;

typedef struct metadata_entry {
    uc_dirnode_t * dn;
    time_t epoch;
    shadow_t shdw_name;
    uv_mutex_t lock; /* locking the whole structure */
    dentry_list_head_t aliases;
} metadata_entry_t, metadata_t;

typedef struct {
    const struct uc_dentry * parent;
    int * p_hashval;
    sds name;
} dcache_key_t;

typedef struct dentry_item {
    struct uc_dentry * dentry;
    TAILQ_ENTRY(dentry_item) next_entry;
} dentry_item_t;

typedef struct uc_dentry {
    bool valid, negative, is_root; /* if the entry is valid */
    ref_t count; /* number of references to the dentry */
    shadow_t shdw_name; /* the dirnode file name */
    dcache_key_t key;
    struct dentry_tree * tree;
    metadata_t * metadata;

    TAILQ_HEAD(dentry_list, dentry_item) subdirs;
} dentry_t;

struct dentry_tree {
    shadow_t root_shadow;
    struct uc_dentry * root_dentry;
    sds root_path, afsx_path, watch_path;
};

/* dentry stuff */
dentry_t *
d_instantiate(dentry_t * dentry, metadata_t * mcache);

void
d_get(dentry_t * dentry);

void
d_put(dentry_t * dentry);

void
d_remove(dentry_t * dentry, const char * name);

dentry_t *
dentry_lookup(const char * path, lookup_flags_t flags);

uc_filebox_t *
dcache_filebox(const char * path, size_t size_hint);

static inline uc_dirnode_t *
d_dirnode(dentry_t * dentry)
{
    return dentry->metadata ? dentry->metadata->dn : NULL;
}

/* vfs */
sds
vfs_metadata_path(const char * path, const shadow_t * shdw_name);

sds
vfs_metadata_fpath(const uc_dirnode_t * dirnode, const shadow_t * shdw);

void
metadata_rm_dirnode(const shadow_t * shdw);

sds
vfs_relpath(const char * path, bool dirpath);

sds
vfs_root_path(const char * path);

const shadow_t * vfs_root_dirnode(const char * path);

sds
vfs_root_dirnode_path(const char * path);

struct dentry_tree *
vfs_tree(const char * path);

int
vfs_mount(const char * path);

sds
vfs_afsx_path(const char * path, const shadow_t * shdw);

/**
 * Returns the dirnode from the metadata
 * @param is shadow name
 */
uc_dirnode_t *
metadata_get_dirnode(const path_builder_t *, struct uc_dentry *);

uc_filebox_t *
metadata_get_filebox(struct uc_dentry * parent_dentry,
                     uc_dirnode_t * dirnode,
                     const path_builder_t * path_build,
                     const shadow_t * shdw,
                     size_t size_hint,
                     int jrnl);

sds
metadata_afsx_path(const uc_dirnode_t * parent_dirnode,
                   const shadow_t * shdw,
                   sds * dpath);

void
metadata_update_entry(struct metadata_entry * entry);

void
metadata_prune(metadata_t * entry);

#ifdef __cplusplus
};
#endif
