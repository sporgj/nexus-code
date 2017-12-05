#include "nexus_mstore_internal.h"

static struct nexus_dentry *
d_alloc(struct nexus_dentry * parent,
        struct uuid *         uuid,
        const char *          name,
        nexus_fs_obj_type_t   type)
{
    struct nexus_dentry * dentry
        = (struct nexus_dentry *)calloc(1, sizeof(struct nexus_dentry));

    dentry->type     = type;
    dentry->parent   = parent;
    dentry->volume   = parent->volume;
    dentry->name_len = strnlen(name, PATH_MAX);
    dentry->name     = strndup(name, PATH_MAX);

    memcpy(&dentry->uuid, uuid, sizeof(struct uuid));
    TAILQ_INIT(&dentry->children);

    TAILQ_INSERT_TAIL(&parent->children, dentry, next_item);

    return dentry;
}

static struct nexus_dentry *
d_lookup(struct nexus_dentry * parent, const char * name)
{
    struct nexus_dentry * dentry = NULL;

    size_t len = strlen(name);

    TAILQ_FOREACH(dentry, &parent->children, next_item)
    {
        if (len == dentry->name_len && (memcmp(name, dentry->name, len) == 0)) {
            return dentry;
        }
    }

    return NULL;
}

static struct nexus_dentry *
walk_path(struct nexus_dentry * root_dentry,
          struct path_builder * builder,
          char *                relpath)
{
    nexus_fs_obj_type_t atype = NEXUS_ANY;

    char * nch = NULL;
    char * pch = NULL;

    struct nexus_dentry * parent = root_dentry;
    struct nexus_dentry * dentry = NULL;

    struct nexus_metadata * metadata = NULL;

    struct uuid uuid;

    int ret = -1;

    nch = strtok_r(relpath, "/", &pch);
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
            // if found, check that the underlying nexus_metadata is fresh
            vfs_revalidate(dentry);

            goto next;
        }

        // otherwise, we load dirnode from disk
        metadata = vfs_read_metadata(parent, builder);
        if (metadata == NULL) {
            log_error("metadata_load_metadata() FAILED");
            return NULL;
        }

        ret = nexus_dirnode_lookup(metadata->dirnode, nch, &uuid, &atype);
        if (ret != 0) {
            log_error("nexus_dirnode_lookup() FAILED");
            return NULL;
        }

        // if the entry is not found, let's leave
        if (ret || atype != NEXUS_DIR) {
            log_error("path entry (%s) is not a directory/symlink", nch);
            return NULL;
        }

        // allocate and add the dentry to the tree
        dentry = d_alloc(parent, &uuid, nch, atype);

    next:
        path_push(builder, &dentry->uuid);
        parent = dentry;
    skip:
        nch = strtok_r(NULL, "/", &pch);
    }

    return dentry;
}

struct nexus_dentry *
nexus_dentry_lookup(struct nexus_dentry * root_dentry, char * relpath)
{
    struct nexus_dentry * dentry  = NULL;
    struct path_builder * builder = path_alloc();

    if (relpath[0] == '\0') {
        dentry = root_dentry;
    } else {
        dentry = walk_path(root_dentry, builder, relpath);
    }

    // resolve the dentry and return
    if (dentry && vfs_read_metadata(dentry, builder) == NULL) {
        path_free(builder);
        log_error("vfs_read_metadata() FAILED");
        return NULL;
    }

    path_free(builder);
    return dentry;
}
