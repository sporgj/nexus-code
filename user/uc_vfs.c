#include "uc_vfs.h"
#include "uc_types.h"
#include "uc_uspace.h"
#include "uc_encode.h"
#include "uc_supernode.h"

#include "third/log.h"
#include "third/sds.h"
#include "third/queue.h"

struct supernode_entry {
    SLIST_ENTRY(supernode_entry) next_entry;
    supernode_t * super;
    sds path;
};

typedef struct supernode_entry supernode_entry_t;

static SLIST_HEAD(_list, supernode_entry) _s = SLIST_HEAD_INITIALIZER(NULL),
                                          *snode_list = &_s;

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
    sds snode_path = ucafs_supernode_path(path);

    /* open the supernode object */
    supernode_t * super = supernode_from_file(path);
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

    ret = 0;
out:
    if (ret) {
        sdsfree(snode_path);

        supernode_free(super);
    }

    return ret;
}

sds
vfs_get_root_path(const char * path)
{
    supernode_entry_t * curr;
    SLIST_FOREACH(curr, snode_list, next_entry)
    {
        if (strstr(path, curr->path)) {
            return sdsdup(curr->path);
        }
    }

    return NULL;
}

sds
vfs_metedata_path(const char * path, shadow_t * shdw_name)
{
    char * metaname;
    sds root_path = vfs_get_root_path(path);
    if (root_path == NULL) {
        return NULL;
    }

    metaname = metaname_bin2str(shdw_name);
    root_path = sdscat(root_path, "/");
    root_path = sdscat(root_path, UCAFS_REPO_DIR);
    root_path = sdscat(root_path, metaname);

    free(metaname);
    return root_path;
}

sds
vfs_relpath(const char * path, bool dirpath)
{
    const char * ptr1 = path, * ptr2;
    int len1, len2, nchar;

    /* 1 - Find the root directory */
    sds root_path = vfs_get_root_path(path);
    if (root_path == NULL) {
        return NULL;
    }

    /* if we are here, we have already shown that root_path is a substring
     * of path */
    len1 = strlen(root_path), len2 = strlen(path);

    ptr2 = path + len1;
    if (*ptr2 == '/') {
        ptr2++;
    }

    sdsfree(root_path);

    /* check if the sgx */
    if (memcmp(UCAFS_WATCH_DIR, ptr2, sizeof(UCAFS_WATCH_DIR) - 1)) {
        return NULL;
    }

    ptr2 += sizeof(UCAFS_WATCH_DIR);
    if (*ptr2 == '/') {
        ptr2++;
    }

    if ((ptr2 - path) > len2) {
        return NULL;
    }
    
    return sdsnew(ptr2);
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
