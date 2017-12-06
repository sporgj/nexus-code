#include "nexus_mstore_internal.h"

static struct nexus_dentry *
create_dentry(struct nexus_dentry * parent,
	      struct uuid         * uuid,
	      const char          * name,
	      nexus_fs_obj_type_t   type)
{
    struct nexus_dentry * dentry = NULL;

    dentry = (struct nexus_dentry *)calloc(1, sizeof(struct nexus_dentry));

    if (dentry == NULL) {
	log_error("Could not allocate dentry\n");
	return NULL;
    }

    TAILQ_INIT(&dentry->children);
    
    dentry->type     = type;
    dentry->parent   = parent;
    dentry->volume   = parent->volume;
    dentry->name_len = strnlen(name, PATH_MAX);
    dentry->name     = strndup(name, PATH_MAX);
    
    memcpy(&dentry->uuid, uuid, sizeof(struct uuid));
    
    
    /* Add dentry as a child to the parent */
    TAILQ_INSERT_TAIL(&parent->children, dentry, next_item);

    return dentry;
}

static struct nexus_dentry *
d_lookup(struct nexus_dentry * parent,
	 const char          * name)
{
    struct nexus_dentry * dentry = NULL;

    size_t len = strlen(name);

    TAILQ_FOREACH(dentry, &parent->children, next_item)
    {
        if ( (dentry->name_len                 == len) &&
	     (strncmp(name, dentry->name, len) == 0) ) {
            return dentry;
        }
    }

    return NULL;
}

static struct nexus_dentry *
walk_path(struct nexus_dentry * root_dentry,
          char                * relpath)
{
    nexus_fs_obj_type_t atype = NEXUS_ANY;

    char * token = NULL;
    char * saveptr = NULL;

    struct nexus_dentry * parent = root_dentry;
    struct nexus_dentry * dentry = NULL;

    struct nexus_metadata * metadata = NULL;

    struct uuid uuid;

    int ret = -1;

    token = strtok_r(relpath, "/", &saveptr);
    while (token != NULL) {
        // check for . and ..
        if (token[0] == '.') {
            if (token[1] == '\0') {
                // skip this term
                goto skip;
            } else if (token[1] == '.') {
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
        dentry = d_lookup(parent, token);

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

        ret = nexus_dirnode_lookup(metadata->dirnode, token, &uuid, &atype);
        if (ret != 0) {
            log_error("nexus_dirnode_lookup() FAILED");
            return NULL;
        }

        // if the entry is not found, let's leave
        if (atype != NEXUS_DIR) {
            log_error("path entry (%s) is not a directory/symlink", token);
            return NULL;
        }

        // allocate and add the dentry to the tree
        dentry = create_dentry(parent, &uuid, token, atype);

    next:
        parent = dentry;
    skip:
        token = strtok_r(NULL, "/", &saveptr);
    }

    return dentry;
}

struct nexus_dentry *
nexus_dentry_lookup(struct nexus_dentry * root_dentry,
		    char                * relpath)
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
