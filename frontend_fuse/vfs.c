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


    root_dentry = dentry_create(NULL, "/", FUSE_ROOT_ID);

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
    return nexus_htable_search(inode_hashtable, (uintptr_t)ino);
}


struct my_dentry *
vfs_add_dentry(struct my_dentry * parent, char * name, fuse_ino_t ino)
{
    struct my_dentry * result = dentry_lookup(parent, name);

    if (result) {
        return result;
    }

    result = dentry_create(parent, name, ino);

    if (!nexus_htable_insert(inode_hashtable, (uintptr_t)result->ino, (uintptr_t)result)) {
        dentry_delete_and_free(result);
        log_error("could not insert root dentry into hashtable\n");

        return NULL;
    }

    return result;
}
