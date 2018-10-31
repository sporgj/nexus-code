#include "nexus_fuse.h"


struct my_dentry *
dentry_alloc()
{
    struct my_dentry * dentry = nexus_malloc(sizeof(struct my_dentry));

    INIT_LIST_HEAD(&dentry->children);
    INIT_LIST_HEAD(&dentry->siblings);

    return dentry;
}

static void
d_free(struct my_dentry * dentry)
{
    nexus_free(dentry);
}

static void
d_prune(struct my_dentry * dentry)
{
    while (!list_empty(&dentry->children)) {
        struct my_dentry * first_child = NULL;

        first_child = list_first_entry(&dentry->children, struct my_dentry, siblings);

        list_del(&first_child->siblings);

        d_prune(first_child);

        d_free(first_child);
    }
}

struct my_dentry *
dentry_lookup(struct my_dentry * parent, const char * name)
{
    struct list_head * curr = NULL;

    size_t len = strlen(name);

    list_for_each(curr, &parent->children)
    {
        struct my_dentry * dentry = NULL;

        dentry = list_entry(curr, struct my_dentry, siblings);

        if ((dentry->name_len == len) && (memcmp(name, dentry->name, len) == 0)) {
            return dentry;
        }
    }

    return NULL;
}

void
dentry_delete_and_free(struct my_dentry * dentry)
{
    list_del(&dentry->siblings);
    d_prune(dentry);
    d_free(dentry);
}

struct my_dentry *
dentry_create(struct my_dentry * parent, char * name, struct nexus_uuid * uuid, nexus_dirent_type_t type)
{
    struct my_dentry * dentry = dentry_alloc();

    strncpy(dentry->name, name, NEXUS_NAME_MAX);
    dentry->name_len = strnlen(dentry->name, NEXUS_NAME_MAX);

    dentry->type = type;

    if (uuid) {
        nexus_uuid_copy(uuid, &dentry->uuid);
        dentry->ino = nexus_uuid_hash(uuid);
    }

    dentry->parent = parent;

    if (parent) {
        list_add(&dentry->siblings, &parent->children);
    }

    return dentry;
}

char *
dentry_get_fullpath(struct my_dentry * dentry)
{
    char * result = NULL;
    char * end    = NULL;

    struct my_dentry * current = NULL;

    size_t total_len = 0;


    if (dentry->parent == NULL) {
        return strndup("/", NEXUS_NAME_MAX);
    }

    current = dentry;

    while (current != NULL) {
        total_len += (current->name_len + 1);

        current = current->parent;
    }

    // allocate and start writing the dentry names from the end
    result = nexus_malloc(total_len + 1);
    end    = result + total_len;

    current = dentry;

    while (current->parent) {
        char * ptr = end - (current->name_len + 1);

        *ptr = '/';
        memcpy(ptr + 1, current->name, current->name_len);
        end = ptr;

        current = current->parent;
    }

    return result;
}

char *
dentry_get_parent_fullpath(struct my_dentry * dentry)
{
    if (dentry->parent == NULL) {
        return strndup("/", NEXUS_NAME_MAX);
    }

    return dentry_get_fullpath(dentry->parent);
}
