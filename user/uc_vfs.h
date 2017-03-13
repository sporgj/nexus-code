#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdatomic.h>

#include "uc_dirnode.h"
#include "uc_filebox.h"

#include "third/hashmap.h"
#include "third/queue.h"

#define MAP_INIT_SIZE 2 << 12

typedef atomic_int ref_t;

struct dentry_tree;
struct metadata_entry;

typedef struct dentry_list_entry {
    struct uc_dentry * dentry;
    SLIST_ENTRY(dentry_list_entry) next_item;
} dentry_list_entry_t;

typedef SLIST_HEAD(dentry_head, dentry_list_entry) dentry_list_head_t;

typedef struct metadata_entry {
    uc_dirnode_t * dn;
    time_t epoch;
    shadow_t shdw_name;
    uv_mutex_t lock; /* locking the whole structure */
    dentry_list_head_t d_entries;
} metadata_entry_t;

typedef struct {
    const struct uc_dentry * parent;
    int * p_hashval;
    sds name;
} dcache_key_t;

typedef struct dcache_item {
    struct uc_dentry * dentry;
    SLIST_ENTRY(dcache_item) next_dptr;
} dcache_item_t;

struct uc_dentry {
    bool valid; /* if the entry is valid */
    ref_t count; /* number of references to the dentry */
    shadow_t shdw_name; /* the dirnode file name */
    dcache_key_t key;
    SLIST_HEAD(dcache_list_t, dcache_item) children;
    struct dentry_tree * dentry_tree;
    struct metadata_entry * metadata;

    uv_mutex_t v_lock; /* required to change valid */
    uv_mutex_t c_lock; /* to change the children */
};

struct dentry_tree {
    Hashmap * hashmap;
    struct uc_dentry * root_dentry;
    uv_mutex_t dcache_lock;
    sds root_path;
};

uc_dirnode_t *
dcache_lookup(struct dentry_tree * tree, const char * path, bool dirpath);

void
dcache_put(uc_dirnode_t * dn);

void
dcache_rm(uc_dirnode_t * dn, const char * entry);

uc_filebox_t *
dcache_get_filebox(struct dentry_tree * tree, const char * path, size_t hint);

struct dentry_tree *
dcache_new_root(shadow_t * root_shdw, const char * root_path);

/* vfs */
sds
vfs_metadata_path(const char * path, const shadow_t * shdw_name);

sds
vfs_relpath(const char * path, bool dirpath);

sds
vfs_root_path(const char * path);

const shadow_t * vfs_root_dirnode(const char * path);

sds
vfs_root_dirnode_path(const char * path);

sds
vfs_append(sds root_path, const shadow_t * shdw_name);

int
vfs_mount(const char * path);

uc_filebox_t *
vfs_get_filebox(const char * path, size_t hint);

uc_dirnode_t *
vfs_lookup(const char * path, bool dirpath);

sds
vfs_dirnode_path(const char * path, const shadow_t * shdw);

sds
vfs_filebox_path(const char * path, const shadow_t * shdw);

/**
 * Returns the dirnode from the metadata
 * @param is shadow name
 */
uc_dirnode_t *
metadata_get_dirnode(const char * path, struct uc_dentry *);

void
metadata_update_entry(struct metadata_entry * entry);

#ifdef __cplusplus
};
#endif
