#include "nexus_fuse.h"

#include <stdint.h>

#include <assert.h>

#include <nexus_hashtable.h>


static struct nexus_hashtable * icache_table     = NULL;

static pthread_mutex_t          icache_mutex;


static struct my_dentry       * root_dentry      = NULL;

static struct my_inode        * root_inode       = NULL;


static int file_counter = 0;


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
    icache_table = nexus_create_htable(256, hash_from_key_fn, keys_equal_fn);

    if (icache_table == NULL) {
        log_error("nexus_create_hashtable FAILED\n");
        return -1;
    }

    pthread_mutex_init(&icache_mutex, NULL);

    root_dentry = dentry_create(NULL, "", NEXUS_DIR);
    root_inode  = __icache_alloc(FUSE_ROOT_ID, NULL);

    root_inode->lookup_count = 1;

    dentry_instantiate(root_dentry, root_inode);

    return 0;
}

void
vfs_deinit()
{
    // TODO iterate through all the inodes and dentries
    if (icache_table) {
        nexus_free_htable(icache_table, 1, 0);
        pthread_mutex_destroy(&icache_mutex);
    }
}

static struct my_inode *
__icache_alloc(fuse_ino_t ino, struct nexus_uuid * uuid)
{
    struct my_inode * inode = nexus_malloc(sizeof(struct my_inode));

    inode->ino = ino;

    INIT_LIST_HEAD(&inode->dentry_list);

    if (uuid) {
        nexus_uuid_copy(uuid, &inode->uuid);
    }

    pthread_mutex_init(&inode->lock, NULL);
    pthread_mutex_init(&inode->dentry_lock, NULL);

    pthread_mutex_lock(&icache_mutex);
    assert(nexus_htable_insert(icache_table, (uintptr_t)inode->ino, (uintptr_t)inode)
           != (uintptr_t)NULL);
    pthread_mutex_unlock(&icache_mutex);

    return inode;
}


static inline struct my_inode *
__icache_find(fuse_ino_t ino)
{
    struct my_inode * inode = NULL;

    pthread_mutex_lock(&icache_mutex);
    inode = nexus_htable_search(icache_table, (uintptr_t)ino);
    pthread_mutex_unlock(&icache_mutex);

    return inode;
}

static inline void
__icache_del(fuse_ino_t ino)
{
    struct my_inode * inode = NULL;

    pthread_mutex_lock(&icache_mutex);
    inode = (struct my_inode *) nexus_htable_remove(icache_table, (uintptr_t)ino, 0);
    pthread_mutex_unlock(&icache_mutex);

    if (inode) {
        nexus_free(inode);
    }
}

struct my_inode *
vfs_get_inode(fuse_ino_t ino)
{
    struct my_inode * inode = __icache_find(ino);

    if (inode) {
        return inode_get(inode);
    }

    return NULL;
}

struct my_dentry *
vfs_get_dentry(fuse_ino_t ino, struct my_inode ** inode_ptr)
{
    struct my_inode * inode = __icache_find(ino);

    if (inode && inode->dentry_count) {
        *inode_ptr = inode_get(inode);
        return list_first_entry(&inode->dentry_list, struct my_dentry, aliases);
    }

    return NULL;
}

struct my_dentry *
_vfs_cache_dentry(struct my_dentry * parent, char * name, struct nexus_fs_lookup * lookup_info)
{
    fuse_ino_t  ino = nexus_uuid_hash(&lookup_info->uuid);

    struct my_inode  * inode  = __icache_find(ino);
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
vfs_forget_dentry(struct my_dentry * parent_dentry, char * name)
{
    struct my_dentry * child = dentry_lookup(parent_dentry, name);

    if (child) {
        dentry_invalidate(child);
    }
}

void
vfs_remove_inode(struct my_inode * inode)
{
    struct list_head * curr = NULL;

    if (inode == NULL || inode->lookup_count) {
        return;
    }

    list_for_each(curr, &inode->dentry_list) {
        struct my_dentry * dentry = list_entry(curr, struct my_dentry, aliases);

        dentry_invalidate(dentry);
    }

    __icache_del(inode->ino);
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
inode_lock(struct my_inode * inode)
{
    pthread_mutex_lock(&inode->lock);
}

void
inode_unlock(struct my_inode * inode)
{
    pthread_mutex_unlock(&inode->lock);
}

struct my_inode *
inode_get(struct my_inode * inode)
{
    if (inode) {
        pthread_mutex_lock(&inode->lock);
        inode->refcount += 1;
        pthread_mutex_unlock(&inode->lock);
        return inode;
    }

    return NULL;
}

void
inode_put(struct my_inode * inode)
{
    if (inode) {
        pthread_mutex_lock(&inode->lock);
        inode->refcount -= 1;
        pthread_mutex_unlock(&inode->lock);
    }
}

void
inode_incr_lookup(struct my_inode * inode, uint64_t count)
{
    pthread_mutex_lock(&inode->lock);
    inode->lookup_count += count;
    pthread_mutex_unlock(&inode->lock);
}

void
inode_decr_lookup(struct my_inode * inode, uint64_t count)
{
    pthread_mutex_lock(&inode->lock);
    assert(inode->lookup_count >= count);

    inode->lookup_count -= count;

    if (inode->lookup_count == 0) {
        vfs_remove_inode(inode);
    }
    pthread_mutex_unlock(&inode->lock);
}

bool
inode_is_file(struct my_inode * inode)
{
    return inode->attrs.stat_info.type == NEXUS_REG;
}

bool
inode_is_dir(struct my_inode * inode)
{
    return inode->attrs.stat_info.type == NEXUS_DIR;
}

void
file_set_clean(struct my_file * file_ptr)
{
    file_ptr->is_dirty = false;
}

void
file_set_dirty(struct my_file * file_ptr)
{
    file_ptr->is_dirty = true;
}


// TODO add file to list of open files
struct my_file *
vfs_file_alloc(struct my_dentry * dentry)
{
    return file_open(dentry, ++file_counter);
}

void
vfs_file_free(struct my_file * file_ptr)
{
    file_close(file_ptr);
}
