#include "enclave_internal.h"

static struct nexus_dentry *
walk_path(struct path_walker * walker);

static struct nexus_dentry *
d_alloc(struct nexus_dentry * parent,
        struct nexus_uuid   * uuid,
        const char          * name,
        nexus_dirent_type_t   type)
{
    struct nexus_dentry * dentry = nexus_malloc(sizeof(struct nexus_dentry));

    INIT_LIST_HEAD(&dentry->children);

    dentry->dirent_type   = type;
    dentry->parent        = parent;
    dentry->name_len      = strnlen(name, NEXUS_NAME_MAX);
    dentry->name          = strndup(name, NEXUS_NAME_MAX);

    nexus_uuid_copy(uuid, &dentry->link_uuid);

    return dentry;
}

static void
d_free(struct nexus_dentry * dentry)
{
    if (dentry->symlink_target) {
        nexus_free(dentry->symlink_target);
    }

    nexus_free(dentry->name);
    nexus_free(dentry);
}

static struct nexus_dentry *
create_dentry(struct nexus_dentry * parent,
              struct nexus_uuid   * uuid,
              const char          * name,
              nexus_dirent_type_t   type)
{
    struct nexus_dentry * dentry = d_alloc(parent, uuid, name, type);

    list_add_tail(&dentry->siblings, &parent->children);

    return dentry;
}

static void
d_prune(struct nexus_dentry * dentry)
{
    while (!list_empty(&dentry->children)) {
        struct nexus_dentry * first_child = NULL;

        first_child = list_first_entry(&dentry->children, struct nexus_dentry, siblings);

        list_del(&first_child->siblings);

        d_prune(first_child);

        d_free(first_child);
    }

    if (dentry->metadata) {
        // TODO refactor into VFS call
        dentry->metadata->dentry = NULL;
    }
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

void
dentry_delete(struct nexus_dentry * dentry)
{
    list_del(&dentry->siblings);
    d_prune(dentry);
    d_free(dentry);
}

void
dentry_delete_child(struct nexus_dentry * parent_dentry, const char * child_filename)
{
    struct nexus_dentry * dentry = NULL;

    dentry = d_lookup(parent_dentry, child_filename);

    if (dentry != NULL) {
        dentry_delete(dentry);
    }
}

static int
__revalidate_inode(struct nexus_dentry * dentry, nexus_io_flags_t flags)
{
    nexus_metadata_type_t metadata_type;

    if (dentry->metadata) {
        if (nexus_vfs_revalidate(dentry->metadata, flags)) {
            log_error("could not revalidate dentry\n");
            return -1;
        }

        return 0; //
    }


    if (dentry->dirent_type == NEXUS_DIR) {
        metadata_type = NEXUS_DIRNODE;
    } else if (dentry->dirent_type == NEXUS_REG) {
        metadata_type = NEXUS_FILENODE;
    }

    // dentry->metadata = NULL
    dentry->metadata = nexus_vfs_load(&dentry->link_uuid, metadata_type, flags);

    if (dentry->metadata == NULL) {
        log_error("could not load metadata\n");
        return -1;
    }

    // otherwise, add dirnode to metadata list
    dentry->metadata->dentry = dentry;

    return 0;
}

int
revalidate_dentry(struct nexus_dentry * dentry, nexus_io_flags_t flags)
{
    if (dentry->dirent_type == NEXUS_LNK) {
        // TODO not implemented
        log_error("could not revalidate symlink\n");
        return -1;
    }

    if (__revalidate_inode(dentry, flags)) {
        return -1;
    }

    if (dentry->parent == NULL) {   // revalidate top dentry
        struct nexus_dirnode * root_dirnode = (struct nexus_dirnode *)dentry->metadata->object;

        return nexus_uuid_compare(&global_supernode->root_uuid, &root_dirnode->my_uuid);
    }

    return nexus_metadata_verify_uuids(dentry);
}

static struct nexus_dentry *
dentry_follow_link(struct nexus_dentry * dentry, char * symlink_target)
{
    struct path_walker walker
        = { .parent_dentry = dentry, .remaining_path = symlink_target, .type = PATH_WALK_NORMAL };

    // TODO handle absolute paths in symlink targets

    return walk_path(&dentry);
}

static struct nexus_dentry *
walk_path(struct path_walker * walker)
{
    nexus_dirent_type_t atype;

    char * name       = NULL;
    char * next_token = NULL;

    struct nexus_dirnode * dirnode    = NULL;

    struct nexus_dentry * curr_dentry = walker->parent_dentry;
    struct nexus_dentry * next_dentry = NULL;

    struct nexus_uuid link_uuid;

    name = strtok_r(NULL, "/", &walker->remaining_path);

    while (name != NULL) {
        // check for . and ..
        if (name[0] == '.') {
            if (name[1] == '\0') {
                goto skip;
            } else if (name[1] == '.') {
                curr_dentry = curr_dentry->parent;

                if (curr_dentry == NULL) {
                    log_error("error with path");
                    return NULL;
                }

                goto skip;
            }
        }

        if (curr_dentry->dirent_type != NEXUS_DIR) {
            log_error("path traversal encountered an incorrect dentry type\n");
            return NULL;
        }

        if (walker->type == PATH_WALK_PARENT && walker->remaining_path == NULL) {
            walker->remaining_path = name;
            return curr_dentry;
        }


        if (revalidate_dentry(curr_dentry, NEXUS_FREAD)) {
            log_error("dentry revalidation FAILED\n");
            return NULL;
        }


        // check the dentry cache if it exists
        next_dentry = d_lookup(curr_dentry, name);

        if (next_dentry != NULL) {
            goto next;
        }


        // otherwise, let's look inside the dirnode
        dirnode = curr_dentry->metadata->dirnode;

        if (dirnode_find_by_name(dirnode, name, &atype, &link_uuid)) {
            log_error("could not find('%s') metadata\n", name);
            return NULL;
        }


        if (atype == NEXUS_LNK) {
            char * target = dirnode_get_link(dirnode, &next_dentry->link_uuid);

            next_dentry = dentry_follow_link(curr_dentry, target);

            nexus_free(target);
        } else {
            // allocate and add the dentry to the tree
            next_dentry = create_dentry(curr_dentry, &link_uuid, name, atype);
        }


        if (next_dentry == NULL) {
            log_error("could not find dentry\n");
            return NULL;
        }

    next:
        walker->parent_dentry = curr_dentry = next_dentry;

    skip:
        name = strtok_r(NULL, "/", &walker->remaining_path);
    }

    return curr_dentry;
}

struct nexus_dentry *
dentry_lookup(struct path_walker * walker)
{
    if (walker->remaining_path == NULL) {
        return walker->parent_dentry;
    }

    return walk_path(walker);
}
