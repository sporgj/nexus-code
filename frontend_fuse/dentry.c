#include "nexus_fuse.h"

#include <assert.h>


struct my_dentry *
dentry_alloc()
{
    struct my_dentry * dentry = nexus_malloc(sizeof(struct my_dentry));

    INIT_LIST_HEAD(&dentry->children);
    INIT_LIST_HEAD(&dentry->siblings);

    return dentry;
}

static void
dentry_free(struct my_dentry * dentry)
{
    nexus_free(dentry);
}

struct my_dentry *
dentry_get(struct my_dentry * dentry)
{
    dentry->refcount += 1;

    return dentry;
}

void
dentry_put(struct my_dentry * dentry)
{
    assert(dentry->refcount > 0);
    dentry->refcount -= 1;

    if (dentry->refcount == 0) {
        dentry_invalidate(dentry);
    }
}


// TODO redo function to skip dentry's with >1 refcount
static void
dentry_prune(struct my_dentry * dentry)
{
    while (!list_empty(&dentry->children)) {
        struct my_dentry * first_child = NULL;

        first_child = list_first_entry(&dentry->children, struct my_dentry, siblings);

        list_del(&first_child->siblings);

        dentry_prune(first_child);

        dentry_free(first_child);
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
    dentry_prune(dentry);
    dentry_free(dentry);
}

struct my_dentry *
dentry_create(struct my_dentry * parent, char * name, nexus_dirent_type_t type)
{
    struct my_dentry * dentry = dentry_alloc();

    strncpy(dentry->name, name, NEXUS_NAME_MAX);

    dentry->name_len = strnlen(dentry->name, NEXUS_NAME_MAX);

    dentry->type = type;

    if (parent) {
        dentry->parent = dentry_get(parent);
        list_add(&dentry->siblings, &parent->children);
    }

    return dentry;
}

void
dentry_set_name(struct my_dentry * dentry, const char * name)
{
    size_t len = strlen(name);

    assert(len < NEXUS_NAME_MAX);

    strncpy(dentry->name, name, NEXUS_NAME_MAX);

    dentry->name_len = len;
}

void
dentry_invalidate(struct my_dentry * dentry)
{
    struct my_inode * inode = dentry->inode;

    if (inode) {
        pthread_mutex_lock(&inode->dentry_lock);
        dentry->inode->dentry_count -= 1;
        list_del(&dentry->aliases);
        dentry->inode = NULL;
        pthread_mutex_unlock(&inode->dentry_lock);

        // TODO add to invalid list
    }

    if (dentry->parent) {
        dentry_put(dentry->parent);
        list_del(&dentry->siblings);
    }
}

void
dentry_instantiate(struct my_dentry * dentry, struct my_inode * inode)
{
    dentry->inode = inode;

    pthread_mutex_lock(&inode->dentry_lock);
    list_add_tail(&dentry->aliases, &inode->dentry_list);
    inode->dentry_count += 1;
    pthread_mutex_unlock(&inode->dentry_lock);

    dentry_get(dentry);
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

    while (current->parent) {
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

void
dentry_export_attrs(struct my_dentry * dentry, struct stat * st_dest)
{
    st_dest->st_mode = nexus_fs_sys_mode_from_type(dentry->type);

    st_dest->st_ino = nexus_uuid_hash(&dentry->lookup_info.uuid);

    switch(dentry->type) {
    case NEXUS_DIR:
        st_dest->st_nlink = 2;
        break;
    case NEXUS_REG:
        // TODO add handling for hardlinks
    default:
        st_dest->st_nlink = 1;
        break;
    }
}
