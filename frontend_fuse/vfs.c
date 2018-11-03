#include "nexus_fuse.h"

#include <stdint.h>

#include <nexus_hashtable.h>


static struct nexus_hashtable * inode_hashtable = NULL;

static struct my_dentry       * root_dentry      = NULL;


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
    inode_hashtable = nexus_create_htable(256, hash_from_key_fn, keys_equal_fn);

    if (inode_hashtable == NULL) {
        log_error("nexus_create_hashtable FAILED\n");
        return -1;
    }


    root_dentry = dentry_create(NULL, "", NULL, NEXUS_DIR);
    root_dentry->ino = FUSE_ROOT_ID;

    if (!nexus_htable_insert(inode_hashtable, (uintptr_t)root_dentry->ino, (uintptr_t)root_dentry)) {
        nexus_free(root_dentry);
        nexus_free_htable(inode_hashtable, 0, 0);
        log_error("could not insert root dentry into hashtable\n");

        return -1;
    }

    return 0;
}

void
vfs_deinit()
{
    nexus_free_htable(inode_hashtable, 1, 0);
}


struct my_dentry *
vfs_get_dentry(fuse_ino_t ino)
{
    struct my_dentry * result = nexus_htable_search(inode_hashtable, (uintptr_t)ino);

    if (result) {
        result->lookup_count += 1;
    }

    return result;
}


struct my_dentry *
vfs_add_dentry(struct my_dentry * parent, char * name, struct nexus_uuid * uuid, nexus_dirent_type_t type)
{
    struct my_dentry * result = dentry_lookup(parent, name);

    if (result) {
        result->lookup_count += 1;
        return result;
    }

    result = dentry_create(parent, name, uuid, type);

    if (!nexus_htable_insert(inode_hashtable, (uintptr_t)result->ino, (uintptr_t)result)) {
        dentry_delete_and_free(result);
        log_error("could not insert root dentry into hashtable\n");

        return NULL;
    }

    result->lookup_count = 1;

    return result;
}


void
vfs_remove_inode(fuse_ino_t ino)
{
    struct my_dentry * dentry = nexus_htable_search(inode_hashtable, (uintptr_t)ino);

    if (dentry == NULL) {
        return;
    }


    dentry->lookup_count -= 1;

    if (dentry) {
        return;
    }


    if (dentry->lookup_count == 0) {
        nexus_htable_remove(inode_hashtable, (uintptr_t)ino, 0);
    }


    dentry_delete_and_free(dentry);
}



// TODO add file to list of open files
struct my_file *
vfs_create_file(struct my_dentry * dentry)
{
    struct my_file * file_ptr = nexus_malloc(sizeof(struct my_file));

    file_ptr->dentry = dentry;


    if (dentry) {
        dentry->openers += 1;
    }

    return file_ptr;
}

void
vfs_delete_file(struct my_file * file_ptr)
{
    if (file_ptr->dentry) {
        file_ptr->dentry->openers -= 1;
    }

    nexus_free(file_ptr);
}


// TODO add directory to open directories
struct my_dir *
vfs_create_dir(struct my_dentry * dentry)
{
    struct my_dir * dir_ptr = nexus_malloc(sizeof(struct my_dir));

    dir_ptr->dentry = dentry;


    if (dentry) {
        dentry->openers += 1;
    }

    return dir_ptr;
}

void
vfs_delete_dir(struct my_dir * dir_ptr)
{
    if (dir_ptr->dentry) {
        dir_ptr->dentry->openers -= 1;
    }

    nexus_free(dir_ptr);
}
