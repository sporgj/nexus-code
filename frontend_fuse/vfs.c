#include "nexus_fuse.h"

#include <stdint.h>

#include <assert.h>

#include <nexus_hashtable.h>


static struct nexus_hashtable * inode_cache      = NULL;

static struct my_dentry       * root_dentry      = NULL;


static struct my_inode *
__icache_alloc(fuse_ino_t ino, struct nexus_uuid * uuid);


static uint32_t
hash_from_key_fn(uintptr_t k)
{
    return (uint32_t) k; // our keys are fuse_ino_t (which are uint64_t)
}

static int
keys_equal_fn(uintptr_t key1, uintptr_t key2)
{
    return ((fuse_ino_t)key1) == ((fuse_ino_t)key2);
}

int
vfs_init()
{
    inode_cache = nexus_create_htable(256, hash_from_key_fn, keys_equal_fn);

    if (inode_cache == NULL) {
        log_error("nexus_create_hashtable FAILED\n");
        return -1;
    }

    root_dentry = dentry_create(NULL, "", NEXUS_DIR);
    root_dentry->inode = __icache_alloc(FUSE_ROOT_ID, NULL);

    dentry_instantiate(root_dentry, root_dentry->inode);

    return 0;
}

void
vfs_deinit()
{
    // TODO iterate through all the inodes and dentries
    nexus_free_htable(inode_cache, 1, 0);
}

static struct my_inode *
__icache_alloc(fuse_ino_t ino, struct nexus_uuid * uuid)
{
    struct my_inode * inode = nexus_malloc(sizeof(struct my_inode));

    inode->ino = ino;

    if (uuid) {
        nexus_uuid_copy(uuid, &inode->uuid);
    }

    assert(nexus_htable_insert(inode_cache, (uintptr_t)inode->ino, (uintptr_t)inode)
           != (uintptr_t)NULL);

    return inode;
}


static inline struct my_inode *
icache_find(fuse_ino_t ino)
{
    return nexus_htable_search(inode_cache, (uintptr_t)ino);
}

static inline void
icache_del(fuse_ino_t ino)
{
    struct my_inode * inode = NULL;

    inode = (struct my_inode *) nexus_htable_remove(inode_cache, (uintptr_t)ino, 0);

    if (inode) {
        nexus_free(inode);
    }
}

struct my_inode *
vfs_get_inode(fuse_ino_t ino)
{
    return icache_find(ino);
}

struct my_dentry *
vfs_get_dentry(fuse_ino_t ino)
{
    struct my_inode * inode = icache_find(ino);

    return inode ? inode->dentry : NULL;
}

struct my_dentry *
_vfs_cache_dentry(struct my_dentry * parent, char * name, struct nexus_fs_lookup * lookup_info)
{
    fuse_ino_t  ino = nexus_uuid_hash(&lookup_info->uuid);

    struct my_inode  * inode  = icache_find(ino);
    struct my_dentry * dentry = dentry_lookup(parent, name);


    if (inode == NULL) {
        inode = __icache_alloc(ino, &lookup_info->uuid);
    }

    if (dentry == NULL) {
        dentry = dentry_create(parent, name, lookup_info->type);
    }

    memcpy(&dentry->lookup_info, lookup_info, sizeof(struct nexus_fs_lookup));
    dentry_instantiate(dentry, inode);

    return dentry;
}

struct my_dentry *
vfs_cache_dentry(struct my_dentry  * parent,
                 char              * name,
                 struct nexus_uuid * uuid,
                 nexus_dirent_type_t type)
{
    struct nexus_fs_lookup lookup_info = { .type = type };

    nexus_uuid_copy(uuid, &lookup_info.uuid);

    return _vfs_cache_dentry(parent, name, &lookup_info);
}

void
vfs_forget_dentry(struct my_dentry * dentry)
{
    // TODO
}

void
vfs_remove_inode(struct my_inode * inode)
{
    if (inode == NULL || inode->lookup_count) {
        return;
    }

    dentry_put(inode->dentry);

    icache_del(inode->ino);
}



// TODO add file to list of open files
struct my_file *
vfs_file_alloc(struct my_dentry * dentry)
{
    struct my_file * file_ptr = nexus_malloc(sizeof(struct my_file));

    file_ptr->dentry   = dentry_get(dentry);
    file_ptr->filepath = dentry_get_fullpath(dentry);

    return file_ptr;
}

void
vfs_file_free(struct my_file * file_ptr)
{
    dentry_put(file_ptr->dentry);
    nexus_free(file_ptr->filepath);
    nexus_free(file_ptr);
}


// TODO add directory to open directories
struct my_dir *
vfs_dir_alloc(struct my_dentry * dentry)
{
    struct my_dir * dir_ptr = nexus_malloc(sizeof(struct my_dir));

    dir_ptr->dentry  = dentry_get(dentry);
    dir_ptr->dirpath = dentry_get_fullpath(dentry);

    return dir_ptr;
}

void
vfs_dir_free(struct my_dir * dir_ptr)
{
    dentry_put(dir_ptr->dentry);
    nexus_free(dir_ptr->dirpath);
    nexus_free(dir_ptr);
}




void
inode_incr_lookup(struct my_inode * inode, uint64_t count)
{
    inode->lookup_count += count;
}

void
inode_decr_lookup(struct my_inode * inode, uint64_t count)
{
    assert(inode->lookup_count >= count);

    inode->lookup_count -= count;

    if (inode->lookup_count == 0) {
        vfs_remove_inode(inode);
    }
}
