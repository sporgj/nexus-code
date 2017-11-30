#include "nexus_internal.h"

static struct nx_dentry *
d_alloc(struct nx_dentry * parent, struct uuid * uuid, const char * name)
{
    struct nx_dentry * dentry
        = (struct nx_dentry *)calloc(1, sizeof(struct nx_dentry));

    dentry->parent   = parent;
    dentry->volume   = parent->volume;
    dentry->name_len = strnlen(name, PATH_MAX);
    dentry->name     = strndup(name, PATH_MAX);

    memcpy(&dentry->uuid, uuid, sizeof(struct uuid));
    TAILQ_INIT(&dentry->children);

    TAILQ_INSERT_TAIL(&parent->children, dentry, next_item);

    return dentry;
}

static struct nx_dentry *
d_lookup(struct nx_dentry * parent, const char * name)
{
    size_t             len    = strlen(name);
    struct nx_dentry * dentry = NULL;

    TAILQ_FOREACH(dentry, &parent->children, next_item)
    {
        if (len == dentry->name_len && (memcmp(name, dentry->name, len) == 0)) {
            return dentry;
        }
    }

    return NULL;
}

static struct nx_dentry *
walk_path(struct nx_dentry *    root_dentry,
          struct path_builder * builder,
          char *                relpath)
{
    int                 ret     = -1;
    nexus_fs_obj_type_t atype   = NEXUS_ANY;
    char *              nch     = NULL;
    char *              pch     = NULL;
    struct dirnode *    dirnode = NULL;
    struct nx_dentry *  parent  = NULL;
    struct nx_dentry *  dentry  = NULL;
    struct nx_inode *   inode   = NULL;
    struct uuid         uuid;

    nch = strtok_r(relpath, "/", &pch);

    parent = root_dentry;

    while (nch != NULL) {
        // check for . and ..
        if (nch[0] == '.') {
            if (nch[1] == '\0') {
                // skip this term
                goto skip;
            } else if (nch[1] == '.') {
                // move back to the parent
                parent = parent->parent;
                if (parent == NULL) {
                    log_error("error with path");
                    return NULL;
                }

                path_pop(builder);
            }
        }

        // check the dentry cache if it entry exists
        dentry = d_lookup(parent, nch);
        if (dentry != NULL) {
            // if found, check that the underlying nx_inode is fresh
            vfs_refresh_inode(dentry->inode);

	    // XXX: if the inode is fresh, then we have to invalidate
	    // all the dentry's children...
	    
            goto next;
        }

        // otherwise, we load dirnode from disk
        inode = vfs_read_inode(parent, builder);
        if (inode == NULL) {
            log_error("metadata_load_inode() FAILED");
            return NULL;
        }

        dirnode = inode->dirnode;

        ret = backend_dirnode_find_by_name(dirnode, nch, &uuid, &atype);
        if (ret != 0) {
            log_error("backend_dirnode_find_by_name() FAILED");
            return NULL;
        }

	// if the entry is not found, let's leave
	if (ret || atype != NEXUS_DIR) {
            log_error("path entry (%s) is not a directory/symlink", nch);
            return NULL;
        }

	// allocate and add the dentry to the tree
	dentry = d_alloc(parent, &uuid, nch);

    next:
	path_push(builder, &dentry->uuid);
	parent = dentry;
    skip:
        nch = strtok_r(relpath, "/", &pch);
    }

    return dentry;
}

struct nx_dentry *
nexus_dentry_lookup(struct nx_dentry * root_dentry, char * relpath)
{
    struct nx_dentry * dentry = NULL;
    struct path_builder * builder = path_alloc();

    if (relpath[0] == '\0') {
        dentry = root_dentry;
    } else {
        dentry = walk_path(root_dentry, builder, relpath);
    }

    // resolve the dentry and return
    if (vfs_read_inode(dentry, builder) == NULL) {
        path_free(builder);
        log_error("vfs_read_inode() FAILED");
        return NULL;
    }

    path_free(builder);
    return dentry;
}
