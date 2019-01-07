#include "enclave_internal.h"


struct nexus_dentry * global_root_dentry = NULL;


struct list_head      dcache_pruned_dentries;


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
    INIT_LIST_HEAD(&dentry->aliases);
    INIT_LIST_HEAD(&dentry->siblings);

    dentry->dirent_type   = type;
    dentry->name_len      = strnlen(name, NEXUS_NAME_MAX);

    strncpy(dentry->name, name, NEXUS_NAME_MAX);

    dentry->d_count       = 1;

    if (parent) {
        dentry->parent    = dentry_get(parent);

        list_add_tail(&dentry->siblings, &parent->children);
    }

    nexus_uuid_copy(uuid, &dentry->link_uuid);

    return dentry;
}

static void
d_free(struct nexus_dentry * dentry)
{
    nexus_free(dentry);
}

void
dcache_init_root()
{
    if (global_root_dentry) {
        nexus_free(global_root_dentry);
    }

    global_root_dentry = d_alloc(NULL, &global_supernode->root_uuid, "/", NEXUS_DIR);
}

static void
d_iput(struct nexus_dentry * dentry)
{
    if (dentry && dentry->metadata) {
        list_del(&dentry->aliases);
        dentry->metadata->dentry_count -= 1;
        dentry->metadata = NULL;
    }
}

static void
__dcache_prune(struct nexus_dentry * dentry)
{
    struct list_head * curr_child = NULL;
    struct list_head * next_pos = NULL;

    // try deleting its children
    list_for_each_safe(curr_child, next_pos, &dentry->children) {
        struct nexus_dentry * child_dentry = NULL;

        child_dentry = list_entry(curr_child, struct nexus_dentry, siblings);

        __dcache_prune(child_dentry);
    }

    // if there're no other links, remove it from parents
    if (dentry->d_count <= 1) {
        d_iput(dentry);

        if (dentry->parent) {
            dentry_put(dentry->parent);
            list_del(&dentry->siblings);
        }

        d_free(dentry);
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


struct nexus_dentry *
dentry_get(struct nexus_dentry * dentry)
{
    if (dentry == NULL) {
        return NULL;
    }

    dentry->d_count += 1;
    return dentry;
}

void
dentry_put(struct nexus_dentry * dentry)
{
    if (dentry == NULL) {
        return;
    }

    dentry->d_count -= 1;

    if (dentry->d_count == 0) {
        dentry_delete(dentry);
    }
}


void
dentry_instantiate(struct nexus_dentry * dentry, struct nexus_metadata * metadata)
{
    if (dentry->metadata) {
        abort();
    }

    dentry->metadata = metadata;

    dentry->flags |= DENTRY_INITIALIZED;

    if (metadata) {
        list_add(&dentry->aliases, &metadata->dentry_list);
        metadata->dentry_count += 1;
    }
}

void
dentry_invalidate(struct nexus_dentry * dentry)
{
    d_iput(dentry);

    dentry->flags &= (~DENTRY_INITIALIZED);
}

void
dentry_delete(struct nexus_dentry * dentry)
{
    if (dentry->parent) {
        dentry_put(dentry->parent);
        list_del(&dentry->siblings);
        dentry->parent = NULL;
    }

    // mark it as deleted and add it to the list of dropped dentries
    dentry->flags = DENTRY_DELETED;

    d_iput(dentry);

    // we don't touch the root dentry
    if (dentry == global_root_dentry) {
        return;
    }

    // if it's only one reference (files and empty directories), remove it
    if (dentry->d_count <= 1) {
        __dcache_prune(dentry);
        return;
    }

    // move it to the pruned list, will be collected later
    list_add(&dentry->siblings, &dcache_pruned_dentries);
}

void
dentry_delete_child(struct nexus_dentry * parent_dentry, const char * child_filename)
{
    struct nexus_dentry * dentry = d_lookup(parent_dentry, child_filename);

    if (dentry) {
        dentry_delete(dentry);
    }
}

static int
__dentry_revalidate(struct nexus_dentry * dentry, nexus_io_flags_t flags)
{
    nexus_metadata_type_t metadata_type;

    if (dentry->metadata) {
        bool has_reloaded = false;

        if (nexus_vfs_revalidate(dentry->metadata, flags, &has_reloaded)) {
            log_error("could not revalidate dentry\n");
            return -1;
        }

        // update all the child dentries
        if (has_reloaded) {
            struct list_head * curr = NULL;

            list_for_each(curr, &dentry->children) {
                struct nexus_dentry * child_dentry = NULL;

                child_dentry = list_entry(curr, struct nexus_dentry, siblings);

                child_dentry->flags |= DENTRY_PARENT_CHANGED;
            }
        }

        return 0; //
    }


    if (dentry->dirent_type == NEXUS_DIR) {
        metadata_type = NEXUS_DIRNODE;
    } else if (dentry->dirent_type == NEXUS_REG) {
        metadata_type = NEXUS_FILENODE;
    }

    // instantiate the dentry
    {
        struct nexus_metadata * metadata = NULL;

        metadata = nexus_vfs_load(&dentry->link_uuid, metadata_type, flags);

        if (metadata == NULL) {
            log_error("could not load metadata\n");
            return -1;
        }

        dentry_instantiate(dentry, metadata);
    }

    return 0;
}

int
dentry_revalidate(struct nexus_dentry * dentry, nexus_io_flags_t flags)
{
    if (dentry->dirent_type == NEXUS_LNK) {
        // TODO not implemented
        log_error("could not revalidate symlink\n");
        return -1;
    }

    if (__dentry_revalidate(dentry, flags)) {
        return -1;
    }

    if (dentry == global_root_dentry) {
        struct nexus_dirnode * root_dirnode = (struct nexus_dirnode *)dentry->metadata->object;

        return nexus_uuid_compare(&global_supernode->root_uuid, &root_dirnode->my_uuid);
    }

    return nexus_metadata_verify_uuids(dentry);
}

static struct nexus_dentry *
dentry_follow_link(struct nexus_dentry * dentry, char * symlink_target, struct path_walker * prev_walker)
{
    struct path_walker walker = {
        .parent_dentry        = dentry,
        .remaining_path       = symlink_target,
        .type                 = PATH_WALK_NORMAL,
        .io_flags             = prev_walker->io_flags
    };

    // TODO handle absolute paths in symlink targets

    return walk_path(&walker);
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
                    log_error("error with path\n");
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


        if (dentry_revalidate(curr_dentry, walker->io_flags)) {
            log_error("dentry revalidation FAILED\n");
            return NULL;
        }


        // check the dentry cache if it exists
        next_dentry = d_lookup(curr_dentry, name);

        if (next_dentry) {
            if (next_dentry->flags & DENTRY_PARENT_CHANGED) {
                goto lookup_dirnode;
            }

            goto next;
        }


lookup_dirnode:
        // otherwise, let's look inside the dirnode
        dirnode = curr_dentry->metadata->dirnode;

        if (dirnode_find_by_name(dirnode, name, &atype, &link_uuid)) {
            log_error("could not find('%s') metadata\n", name);
            return NULL;
        }


        if (atype == NEXUS_LNK) {
            char * target = dirnode_get_link(dirnode, &link_uuid);

            next_dentry = dentry_follow_link(curr_dentry, target, walker);

            nexus_free(target);
        } else {
            if (next_dentry == NULL) {
                next_dentry = d_alloc(curr_dentry, &link_uuid, name, atype);
            } else {
                // if it's the same, uuid, we can just change the flag
                if (nexus_uuid_compare(&link_uuid, &next_dentry->link_uuid) == 0) {
                    next_dentry->flags &= ~DENTRY_PARENT_CHANGED;
                } else {
                    // we have to delete this dentry
                    dentry_delete(next_dentry);
                    next_dentry = d_alloc(curr_dentry, &link_uuid, name, atype);
                }
            }
        }


        if (next_dentry == NULL) {
            log_error("could not find dentry\n");
            return NULL;
        }

    next:
        walker->parent_dentry = curr_dentry = next_dentry;
        next_dentry = NULL;

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
