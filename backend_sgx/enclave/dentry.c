#include "enclave_internal.h"

#include "path_builder.c"


static struct nexus_dentry *
create_dentry(struct nexus_dentry * parent,
              struct nexus_uuid   * uuid,
              const char          * name,
              nexus_dirent_type_t   type)
{
    struct nexus_dentry * dentry = NULL;

    dentry = nexus_malloc(sizeof(struct nexus_dentry));

    if (dentry == NULL) {
        log_error("Could not allocate dentry\n");
        return NULL;
    }

    INIT_LIST_HEAD(&dentry->children);

    dentry->metadata_type = (type == NEXUS_DIR ? NEXUS_DIRNODE : NEXUS_FILENODE);
    dentry->parent        = parent;
    dentry->name_len      = strnlen(name, NEXUS_NAME_MAX);
    dentry->name          = strndup(name, NEXUS_NAME_MAX);

    nexus_uuid_copy(uuid, &dentry->uuid);

    /* Add dentry as a child to the parent */
    list_add_tail(&dentry->siblings, &parent->children);

    return dentry;
}

static struct nexus_dentry *
d_lookup(struct nexus_dentry * parent, const char * name)
{
    struct list_head * curr = NULL;

    size_t len = strlen(name);

    list_for_each(curr, &parent->children)
    {
        struct nexus_dentry * dentry = NULL;

        dentry = list_entry(curr, struct nexus_dentry, siblings);

        if ((dentry->name_len == len) && (memcmp(name, dentry->name, len) == 0)) {
            return dentry;
        }
    }

    return NULL;
}

static int
revalidate_dentry(struct nexus_dentry * dentry, struct path_builder * builder)
{
    int ret = -1;


    if (dentry->metadata) {
        ret = nexus_vfs_revalidate(dentry->metadata);

        if (ret != 0) {
            log_error("could not revalidate dentry\n");
            return -1;
        }
    }

    // dentry->metadata = NULL
    dentry->metadata = nexus_vfs_load(&dentry->uuid, dentry->metadata_type);

    if (dentry->metadata == NULL) {
        log_error("could not load metadata\n");
        return -1;
    }

    // otherwise, add dirnode to metadata list
    dentry->metadata->dentry = dentry;

    return 0;
}

static struct nexus_dentry *
walk_path(struct nexus_dentry * root_dentry, char * relpath, struct path_builder * builder)
{
    nexus_dirent_type_t atype;

    char * name       = NULL;
    char * next_token = NULL;

    struct nexus_dentry * curr_dentry = root_dentry;
    struct nexus_dentry * next_dentry = NULL;

    struct nexus_uuid uuid;

    int ret = -1;

    name = strtok_r(relpath, "/", &next_token);
    while (name != NULL) {
        // check for . and ..
        if (name[0] == '.') {
            if (name[1] == '\0') {
                // skip this term
                goto skip;
            } else if (name[1] == '.') {
                // move back to the parent
                curr_dentry = curr_dentry->parent;
                if (curr_dentry == NULL) {
                    log_error("error with path");
                    return NULL;
                }

                path_builder_pop(builder);
            }
        }

        if (curr_dentry->metadata_type != NEXUS_DIRNODE) {
            log_error("path traversal encountered an incorrect dentry type\n");
            return NULL;
        }

        ret = revalidate_dentry(curr_dentry, builder);
        if (ret != 0) {
            log_error("dentry revalidation FAILED\n");
            return NULL;
        }

        // check the dentry cache if it entry exists
        next_dentry = d_lookup(curr_dentry, name);
        if (next_dentry != NULL) {
            goto next;
        }

        // if the entry is not found, let's leave
        ret = dirnode_find_by_name(curr_dentry->metadata->dirnode, name, &atype, &uuid);
        if (ret != 0) {
            log_error("nexus_dirnode_lookup() FAILED");
            return NULL;
        }


        // allocate and add the dentry to the tree
        next_dentry = create_dentry(curr_dentry, &uuid, name, atype);

    next:
        path_builder_push(builder, &curr_dentry->uuid);
        curr_dentry = next_dentry;
    skip:
        name = strtok_r(NULL, "/", &next_token);
    }

    return curr_dentry;
}

struct nexus_dentry *
dentry_lookup(struct nexus_dentry * root_dentry, char * path)
{
    struct nexus_dentry * dentry  = NULL;

    struct path_builder builder;


    path_builder_init(&builder);

    if (path == NULL) {
        log_error("path cannot be null\n");
        return NULL;
    }

    if (path[0] == '\0') {
        dentry = root_dentry;
    } else {
        dentry = walk_path(root_dentry, path, &builder);
    }

    // resolve the dentry and return
    if (dentry && revalidate_dentry(dentry, &builder) == -1) {
        path_builder_free(&builder);
        log_error("revalidating dentry FAILED");
        return NULL;
    }

    path_builder_free(&builder);

    return dentry;
}

struct nexus_uuid_path *
dentry_uuid_path(struct nexus_dentry * dentry)
{
#if 0
    struct nexus_uuid_path * uuid_path = NULL;

    struct path_builder builder;


    path_builder_init(&builder);

    while (dentry != NULL) {
        path_builder_prepend(&builder, dentry);
        dentry = dentry->parent;
    }

    uuid_path = path_builder_get_path(&builder);

    path_builder_free(&builder);

    return uuid_path;
#endif

    return NULL;
}
