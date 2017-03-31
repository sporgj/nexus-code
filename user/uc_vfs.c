#include "uc_encode.h"
#include "uc_supernode.h"
#include "uc_types.h"
#include "uc_uspace.h"
#include "uc_vfs.h"

#include "third/log.h"
#include "third/queue.h"
#include "third/sds.h"

struct supernode_entry {
    SLIST_ENTRY(supernode_entry) next_entry;
    supernode_t * super;
    struct dentry_tree * dentry_tree;
    sds path;
};

typedef struct supernode_entry supernode_entry_t;

static SLIST_HEAD(_list, supernode_entry) _s = SLIST_HEAD_INITIALIZER(NULL),
                                          *snode_list = &_s;

static inline sds
_append_root_dirnode_path(sds root_path, const char * metadata_fname);

uc_filebox_t *
vfs_get_filebox(const char * path, size_t hint)
{
    supernode_entry_t * curr;
    SLIST_FOREACH(curr, snode_list, next_entry)
    {
        if (strstr(path, curr->path)) {
            return dcache_get_filebox(curr->dentry_tree, path, hint);
        }
    }

    return NULL;
}

uc_dirnode_t *
vfs_lookup(const char * path, bool dirpath)
{
    supernode_entry_t * curr;
    SLIST_FOREACH(curr, snode_list, next_entry)
    {
        if (strstr(path, curr->path)) {
            return dcache_lookup(curr->dentry_tree, path, dirpath);
        }
    }

    return NULL;
}

static inline sds
_append_root_dirnode_path(sds root_path, const char * metadata_fname)
{
    root_path = sdscat(root_path, "/");
    root_path = sdscat(root_path, UCAFS_REPO_DIR);
    root_path = sdscat(root_path, "/");
    root_path = sdscat(root_path, metadata_fname);
    return root_path;
}

static inline sds
vfs_append(sds root_path, const shadow_t * shdw_name)
{
    char * metaname = metaname_bin2str(shdw_name);
    root_path = _append_root_dirnode_path(root_path, metaname);
    free(metaname);

    return root_path;
}

/**
 * Adds the path to the list of all supernodes
 * @param path
 * @return false if the path could node be loaded
 */
int
vfs_mount(const char * path)
{
    int ret = -1;
    supernode_entry_t * snode_entry;
    struct uc_dentry * root_dentry;
    sds snode_path = ucafs_supernode_path(path), root_dnode_path = NULL;

    /* open the supernode object */
    supernode_t * super = supernode_from_file(snode_path);
    if (super == NULL) {
        sdsfree(snode_path);
        return -1;
    }

    if (supernode_mount(super)) {
        log_error("mounting supernode failed: %s", snode_path);
        goto out;
    }

    snode_entry = (supernode_entry_t *)malloc(sizeof(supernode_entry_t));
    if (snode_entry == NULL) {
        log_fatal("allocation failed :(");
        goto out;
    }

    snode_entry->super = super;
    snode_entry->path = sdsnew(path);

    SLIST_INSERT_HEAD(snode_list, snode_entry, next_entry);

    // initialize the root dentry
    root_dnode_path = vfs_append(sdsnew(path), &super->root_dnode);
    snode_entry->dentry_tree = dcache_new_root(&super->root_dnode, path);

    ret = 0;
out:
    if (ret) {
        sdsfree(snode_path);

        supernode_free(super);
    }

    if (root_dnode_path) {
        sdsfree(root_dnode_path);
    }

    return ret;
}

static sds
_vfs_get_root_path(const char * path, const shadow_t ** root_shdw)
{
    supernode_entry_t * curr;
    SLIST_FOREACH(curr, snode_list, next_entry)
    {
        if (strstr(path, curr->path)) {
            if (root_shdw) {
                *root_shdw = &curr->super->root_dnode;
            }

            return sdsdup(curr->path);
        }
    }

    return NULL;
}

sds
vfs_get_root_path(const char * path)
{
    return _vfs_get_root_path(path, NULL);
}

const shadow_t * vfs_root_dirnode(const char * path)
{
    sds root_path;
    supernode_entry_t * curr;
    SLIST_FOREACH(curr, snode_list, next_entry)
    {
        if (strstr(path, curr->path)) {
            return &curr->super->root_dnode;
        }
    }

    return NULL;
}

sds
vfs_root_dirnode_path(const char * path)
{
    char * metaname;
    sds root_path;
    supernode_entry_t * curr;
    SLIST_FOREACH(curr, snode_list, next_entry)
    {
        if (strstr(path, curr->path)) {
            root_path = sdsdup(curr->path);

            /* to return the root, return the path and root */
            metaname = metaname_bin2str(&curr->super->root_dnode);
            root_path = _append_root_dirnode_path(root_path, metaname);
            free(metaname);

            return root_path;
        }
    }

    return NULL;
}

sds
vfs_afsx_path(const char * path, const shadow_t * shdw)
{
    return vfs_append(sdsnew(path), shdw);
}

sds
vfs_relpath(const char * path, bool dirpath)
{
    const char *ptr1 = path, *ptr2;
    int len1, len2, nchar;

    /* 1 - Find the root directory */
    sds root_path = vfs_get_root_path(path);
    if (root_path == NULL) {
        return NULL;
    }

    /* if we are here, we have already shown that root_path is a substring
     * of path */
    len1 = strlen(root_path), len2 = strlen(path);
    sdsfree(root_path);

    /* now lets find the relative component */
    ptr1 = path + len1;
    if (*ptr1 == '/') {
        ptr1++;
    }

    /* check if the sgx */
    if (memcmp(UCAFS_WATCH_DIR, ptr1, sizeof(UCAFS_WATCH_DIR) - 1)) {
        return NULL;
    }

    ptr1 += sizeof(UCAFS_WATCH_DIR) - 1;
    if (*ptr1 == '/') {
        ptr1++;
    }

    ptr2 = path + len2;
    if (!dirpath) {
        while (*ptr2 != '/' && ptr2 != ptr1) {
            ptr2--;
        }
    }

    nchar = ptr2 - ptr1;
    return nchar > 0 ? sdsnewlen(ptr1, nchar) : sdsnew("");
}

int
ucafs_init_vfs()
{
    return 0;
}

int
ucafs_exit_vfs()
{
    return 0;
}
