#include "nexus_trusted.h"

static struct dirnode *
dirnode_copy_whole(struct dirnode * dirnode)
{
    size_t           tsize = dirnode->header.total_size;
    struct dirnode * copy  = (struct dirnode *)calloc(1, tsize);
    if (copy == NULL) {
        ocall_debug("allocation error");
        return NULL;
    }

    memcpy(copy, dirnode, tsize);

    return copy;
}

// TODO
static void
dirnode_wrapper_free(struct dirnode_wrapper * wrapper)
{
    // iterate the dirnode from the back
    dirnode_free(wrapper->dirnode);
}

static struct dirnode_wrapper *
dirnode_find_wrapper(struct dirnode * sealed_dirnode)
{
    struct uuid *            uuid            = &sealed_dirnode->header.uuid;
    struct dirnode_wrapper * dirnode_wrapper = NULL;
    struct dirnode_header *  header          = NULL;

    // iterate the dirnode cache and find a wrapper with a matching uuid
    TAILQ_FOREACH(dirnode_wrapper, dirnode_cache, next_item)
    {
        header = &dirnode_wrapper->dirnode->header;
        if (memcmp(&header->uuid, uuid, sizeof(struct uuid)) == 0) {
            // JBD; the sealed_dirnode is not checked for integrity
            // before comparing for versions. It doesn't really change much
            // because it will be checked for unsealing.

            if (header->version < sealed_dirnode->header.version) {
                dirnode_wrapper_free(dirnode_wrapper);
                return NULL;
            }

            return dirnode_wrapper;
        }
    }

    return NULL;
}

static int
dirnode_wrapper_initialize(struct dirnode_wrapper * wrapper)
{
    struct dirnode *               dirnode    = wrapper->dirnode;
    struct dirnode_direntry_list * head       = &wrapper->direntry_head;
    struct dirnode_direntry_item * entryitem  = NULL;
    struct dirnode_direntry_item * item0      = NULL;
    struct dirnode_direntry *      direntry   = NULL;

    int count      = 0;
    int bytes_left = 0;
    int size       = 0;

    int ret = -1;

    // let's allocate the list in advance
    count = dirnode->header.dir_count;
    size  = count * sizeof(struct dirnode_direntry_item);

    item0 = (struct dirnode_direntry_item *)calloc(1, size);
    if (item0 == NULL) {
        ocall_debug("allocation error for entryitems");
        return -1;
    }

    entryitem = item0;

    TAILQ_INIT(head);

    direntry   = dirnode->entries;
    bytes_left = dirnode->header.dir_size;
    while (bytes_left > 0) {
        size = direntry->entry_len;

        // set the entryitem to point to the direntry
        entryitem->freeable = false;
        entryitem->direntry = direntry;
        TAILQ_INSERT_TAIL(head, entryitem, next_item);

        bytes_left -= size;
        entryitem++;
    }

    // the first element is freeable
    item0->freeable = true;

    ret = 0;
out:
    return ret;
}

/**
 * Gets a wrapper from a dirnode
 *
 * @param sealed_dirnode
 * @return NULL on error
 */
struct dirnode_wrapper *
dirnode_get_wrapper(struct dirnode * sealed_dirnode)
{
    struct dirnode_wrapper * wrapper   = NULL;
    struct dirnode *         dirnode   = NULL;
    struct volumekey *       volumekey = NULL;

    int ret = -1;

    // let's first find it in our cache
    wrapper = dirnode_find_wrapper(sealed_dirnode);
    if (wrapper) {
        return wrapper;
    }

    volumekey = volumekey_from_rootuuid(&sealed_dirnode->header.root_uuid);
    if (volumekey == NULL) {
        ocall_debug("could not find dirnode volumekey");
        return NULL;
    }

    ret = dirnode_decryption(sealed_dirnode, volumekey, &dirnode);
    if (ret != 0) {
        ocall_debug("dirnode_decryption() FAILED");
        return NULL;
    }

    wrapper
        = (struct dirnode_wrapper *)calloc(1, sizeof(struct dirnode_wrapper));

    if (wrapper == NULL) {
        ocall_debug("allocation error");
        return NULL;
    }

    // initialize the wrapper and return it all
    wrapper->volumekey = volumekey;
    wrapper->dirnode   = dirnode;

    ret = dirnode_wrapper_initialize(wrapper);

    // add it to the dirnode cache
    TAILQ_INSERT_TAIL(dirnode_cache, wrapper, next_item);

    ret = 0;
out:
    if (ret) {
        my_free(dirnode);
    }

    return wrapper;
}

struct dirnode_wrapper *
dirnode_get_wrapper_from_ext(struct dirnode * sealed_dirnode_ext)
{
    struct dirnode_wrapper * dirnode_wrapper = NULL;

    struct dirnode * sealed_dirnode = dirnode_copy_whole(sealed_dirnode_ext);
    if (sealed_dirnode == NULL) {
        ocall_debug("could not copy dirnode");
        return NULL;
    }

    dirnode_wrapper = dirnode_get_wrapper(sealed_dirnode);
    my_free(sealed_dirnode);

    return dirnode_wrapper;
}

/**
 * Drops reference on a dirnode_wrapper
 * @param dirnode_wrapper
 */
// TODO
void
dirnode_put_wrapper(struct dirnode_wrapper * dirnode_wrapper)
{
    // my_free(dirnode_wrapper->dirnode);
    // my_free(dirnode_wrapper);
}

struct dirnode *
dirnode_new(struct uuid * uuid, struct uuid * root_uuid)
{
    // 1 - allocate a new dirnode
    struct dirnode * dirnode = NULL;

    dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    if (dirnode == NULL) {
        ocall_debug("allocation error");
        return NULL;
    }

    // 2 - copy the uuid & root uuid into the dirnode
    memcpy(&dirnode->header.uuid, uuid, sizeof(struct uuid));
    memcpy(&dirnode->header.root_uuid, root_uuid, sizeof(struct uuid));
    dirnode->header.total_size = sizeof(struct dirnode);

    return dirnode;
}

void
dirnode_free(struct dirnode * dirnode)
{
    free(dirnode);
}

static int
dirnode_add(struct dirnode_wrapper * dirnode_wrapper,
            struct uuid *            entry_uuid,
            const char *             fname_str,
            nexus_fs_obj_type_t      type)
{
    struct dirnode * dirnode = dirnode_wrapper->dirnode;

    struct dirnode_direntry_list * head      = &dirnode_wrapper->direntry_head;
    struct dirnode_direntry_item * entryitem = NULL;
    struct dirnode_direntry *      direntry  = NULL;

    const char * curr_fname = NULL;

    size_t size      = 0;
    size_t fname_len = 0;
    int    ret       = -1;

    // 1 - checks if the entry is in the dirnode
    // XXX: this might be an overkill as the "lookup" is always called before
    // creating a file/directory. If it exists, the create call will not be
    // issued
    TAILQ_FOREACH(entryitem, head, next_item)
    {
        direntry = entryitem->direntry;

        ret = strncmp(direntry->name, fname_str, direntry->name_len);
        if (ret == 0) {
            ocall_debug("directory entry already exists");
            return -1;
        }

        ret = memcmp(&direntry->uuid, entry_uuid, sizeof(struct uuid));
        if (ret == 0) {
            ocall_debug("directory entry already exists");
            return -1;
        }
    }

    // 2 - allocate space for the new dirnode entry
    {
        entryitem = NULL;
        direntry  = NULL;

        fname_len = strnlen(fname_str, NEXUS_MAX_FILENAME_LEN);
        size      = sizeof(struct dirnode_direntry) + fname_len + 1;

        direntry  = (struct dirnode_direntry *)calloc(1, size);
        entryitem = (struct dirnode_direntry_item *)calloc(
            1, sizeof(struct dirnode_direntry_item));

        if (direntry == NULL || entryitem == NULL) {
            ocall_debug("allocation error");
            goto out;
        }
    }

    // 3 - initialize the contents and add it to the list
    {
        direntry->type      = type;
        direntry->entry_len = size;
        direntry->name_len  = fname_len;

        memcpy(&direntry->uuid, entry_uuid, sizeof(struct uuid));
        memcpy(&direntry->name, fname_str, fname_len);

        entryitem->freeable = true;
        entryitem->direntry = direntry;
        TAILQ_INSERT_TAIL(head, entryitem, next_item);

        dirnode->header.total_size += size;
        dirnode->header.dir_size += size;
        dirnode->header.dir_count += 1;
    }

    dirnode_wrapper->modified = true;

    ret = 0;
out:
    if (ret) {
        my_free(direntry);
        my_free(entryitem);
    }

    return ret;
}

static struct dirnode_direntry_item *
_dirnode_find_or_remove(struct dirnode_wrapper * dirnode_wrapper,
                        const char *             fname_str,
                        nexus_fs_obj_type_t *    p_type,
                        struct uuid *            uuid)
{
    struct dirnode_direntry_list * head      = &dirnode_wrapper->direntry_head;
    struct dirnode_direntry_item * entryitem = NULL;
    struct dirnode_direntry *      direntry  = NULL;

    // iterate the dirnode entries until we find a matching filename
    TAILQ_FOREACH(entryitem, head, next_item)
    {
        direntry = entryitem->direntry;

        if (strncmp(direntry->name, fname_str, direntry->name_len) == 0) {
            *p_type = direntry->type;
            memcpy(uuid, &direntry->uuid, sizeof(struct uuid));

            return entryitem;
        }
    }

    return NULL;
}

/**
 * Finds dirnode entry by name
 * @param dirnode_wrapper
 * @param fname_str
 * @param fname_len
 * @param p_type the resulting entry file object type
 * @param p_uuid destination pointer for the uuid
 * @return 0 on success
 */
static int
dirnode_find_by_name(struct dirnode_wrapper * dirnode_wrapper,
                     const char *             fname_str,
                     nexus_fs_obj_type_t *    p_type,
                     struct uuid *            uuid)
{
    // NULL means it failed, so we return 1
    struct dirnode_direntry_item * direntry_item
        = _dirnode_find_or_remove(dirnode_wrapper, fname_str, p_type, uuid);

    return (direntry_item == NULL) ? -1 : 0;
}

static int
dirnode_remove(struct dirnode_wrapper * dirnode_wrapper,
               const char *             fname_str,
               nexus_fs_obj_type_t *    p_type,
               struct uuid *            uuid)
{
    struct dirnode_direntry_item * direntry_item
        = _dirnode_find_or_remove(dirnode_wrapper, fname_str, p_type, uuid);

    // adjust the size of the dirnode
    if (direntry_item) {
        struct dirnode * dirnode = dirnode_wrapper->dirnode;

        size_t size = direntry_item->direntry->entry_len;
        dirnode->header.total_size -= size;
        dirnode->header.dir_size -= size;
        dirnode->header.dir_count -= 1;

        TAILQ_REMOVE(&dirnode_wrapper->direntry_head, direntry_item, next_item);
        if (direntry_item->freeable) {
            free(direntry_item->direntry);
            free(direntry_item);
        }

        return 0;
    }

    return -1;
}

static int
dirnode_find_by_uuid(struct dirnode_wrapper * dirnode_wrapper,
                     struct uuid *            uuid,
                     nexus_fs_obj_type_t *    p_type,
                     const char **            p_fname,
                     size_t *                 p_fname_len)
{
    struct dirnode_direntry_list * head      = &dirnode_wrapper->direntry_head;
    struct dirnode_direntry_item * entryitem = NULL;
    struct dirnode_direntry *      direntry  = NULL;

    // iterate the dirnode entries until we find a matching uuid
    TAILQ_FOREACH(entryitem, head, next_item)
    {
        direntry = entryitem->direntry;

        if (memcmp(&direntry->uuid, uuid, sizeof(struct uuid)) == 0) {
            // set p_type & p_fname
            *p_type      = direntry->type;
            *p_fname     = direntry->name;
            *p_fname_len = direntry->name_len;

            return 0;
        }
    }

    return -1;
}

int
ecall_dirnode_new(struct uuid *    uuid_ext,
                  struct uuid *    root_uuid_ext,
                  struct dirnode * dirnode_out_ext)
{
    struct uuid        uuid;
    struct uuid        root_uuid;

    struct dirnode *   dirnode        = NULL;
    struct dirnode *   sealed_dirnode = NULL;
    struct volumekey * volumekey      = NULL;

    int ret = -1;

    memcpy(&uuid, uuid_ext, sizeof(struct uuid));
    memcpy(&root_uuid, root_uuid_ext, sizeof(struct uuid));

    volumekey = volumekey_from_rootuuid(&root_uuid);
    if (volumekey == NULL) {
        ocall_debug("could not find dirnode volumekey");
        return -1;
    }

    // create the new dirnode and send to the exterior
    dirnode = dirnode_new(&uuid, &root_uuid);
    if (dirnode == NULL) {
        return -1;
    }

    ret = dirnode_encryption1(NULL, dirnode, volumekey, &sealed_dirnode);
    if (ret != 0) {
        ocall_debug("dirnode_encryption1() FAILED");
        goto out;
    }

    memcpy(dirnode_out_ext, sealed_dirnode, dirnode->header.total_size);

    ret = 0;
out:
    my_free(dirnode);
    my_free(sealed_dirnode);

    return ret;
}

int
ecall_dirnode_add(struct dirnode *    sealed_dirnode_ext,
                  struct uuid *       entry_uuid,
                  const char *        fname_str_in,
                  nexus_fs_obj_type_t type)
{
    struct dirnode_wrapper * dirnode_wrapper = NULL;

    struct uuid uuid = { 0 };

    int ret = -1;

    dirnode_wrapper = dirnode_get_wrapper_from_ext(sealed_dirnode_ext);
    if (dirnode_wrapper == NULL) {
        ocall_debug("dirnode_get_wrapper_from_ext() FAILED");
        return -1;
    }

    memcpy(&uuid, entry_uuid, sizeof(struct uuid));

    // add it and return the status
    ret = dirnode_add(dirnode_wrapper, &uuid, fname_str_in, type);

    dirnode_put_wrapper(dirnode_wrapper);

    return ret;
}

int
ecall_dirnode_find_by_uuid(struct dirnode *      sealed_dirnode_ext,
                           struct uuid *         uuid_ext,
                           char **               fname_str_out_ext,
                           nexus_fs_obj_type_t * type_out_ext)
{
    struct dirnode_wrapper * dirnode_wrapper = NULL;

    struct uuid uuid = { 0 };

    nexus_fs_obj_type_t type = NEXUS_ANY;

    const char * fname           = NULL;
    char *       fname_alloc_ext = NULL;

    size_t fname_len = 0;
    int    ret       = -1;

    dirnode_wrapper = dirnode_get_wrapper_from_ext(sealed_dirnode_ext);
    if (dirnode_wrapper == NULL) {
        ocall_debug("dirnode_get_wrapper_from_ext() FAILED");
        return -1;
    }

    // copy in the uuid and call dirnode_find_by_uuid()
    memcpy(&uuid, uuid_ext, sizeof(struct uuid));

    ret = dirnode_find_by_uuid(
        dirnode_wrapper, &uuid, &type, &fname, &fname_len);

    if (ret != 0) {
        goto out;
    }

    ret = ocall_calloc((void **)&fname_alloc_ext, fname_len);
    if (ret != 0 || fname_alloc_ext == NULL) {
        ocall_debug("ocall_calloc() FAILED");
        goto out;
    }

    memcpy(fname_alloc_ext, fname, fname_len);
    *fname_str_out_ext = fname_alloc_ext;
    *type_out_ext      = type;

    ret = 0;
out:
    dirnode_put_wrapper(dirnode_wrapper);

    return ret;
}

int
ecall_dirnode_find_or_remove(struct dirnode *      sealed_dirnode_ext,
                             char *                fname_str_in,
                             struct uuid *         uuid_out_ext,
                             nexus_fs_obj_type_t * type_out_ext,
                             bool                  remove)
{
    struct dirnode_wrapper * dirnode_wrapper = NULL;

    nexus_fs_obj_type_t type = NEXUS_ANY;

    struct uuid uuid;

    int ret = -1;

    dirnode_wrapper = dirnode_get_wrapper_from_ext(sealed_dirnode_ext);
    if (dirnode_wrapper == NULL) {
        ocall_debug("dirnode_get_wrapper_from_ext() FAILED");
        return -1;
    }

    if (remove) {
        ret = dirnode_remove(dirnode_wrapper, fname_str_in, &type, &uuid);
    } else {
        ret = dirnode_find_by_name(dirnode_wrapper, fname_str_in, &type, &uuid);
    }

    if (ret != 0) {
        ocall_debug("could not find the name entry");
        goto out;
    }

    // write out the data
    memcpy(uuid_out_ext, &uuid, sizeof(struct uuid));
    *type_out_ext = type;

    ret = 0;
out:
    dirnode_put_wrapper(dirnode_wrapper);

    return ret;
}

int
ecall_dirnode_find_by_name(struct dirnode *      sealed_dirnode_ext,
                           char *                fname_str_in,
                           struct uuid *         uuid_out_ext,
                           nexus_fs_obj_type_t * type_out_ext)
{
    return ecall_dirnode_find_or_remove(
        sealed_dirnode_ext, fname_str_in, uuid_out_ext, type_out_ext, false);
}

int
ecall_dirnode_remove(struct dirnode *      sealed_dirnode_ext,
                     char *                fname_str_in,
                     struct uuid *         uuid_out_ext,
                     nexus_fs_obj_type_t * type_out_ext)
{
    return ecall_dirnode_find_or_remove(
        sealed_dirnode_ext, fname_str_in, uuid_out_ext, type_out_ext, true);
}

int
ecall_dirnode_serialize(struct dirnode *  dirnode,
                        struct dirnode ** p_sealed_dirnode_out_ext)
{
    struct dirnode_wrapper * dirnode_wrapper = NULL;

    struct dirnode * sealed_dirnode     = NULL;
    struct dirnode * sealed_dirnode_ext = NULL;

    size_t size = 0;
    int    ret  = -1;

    // get the wrapper and encrypt the dirnode
    dirnode_wrapper = dirnode_get_wrapper(dirnode);
    if (dirnode_wrapper == NULL) {
        ocall_debug("dirnode_get_wrapper FAILED");
        return -1;
    }

    ret = dirnode_encryption(dirnode_wrapper, &sealed_dirnode);
    if (ret != 0) {
        ocall_debug("dirnode_encryption FAILED");
        goto out;
    }

    // allocate an external buffer and copy out the sealed dirnode
    size = sealed_dirnode->header.total_size;
    ret  = ocall_calloc((void **)&sealed_dirnode_ext, size);
    if (ret != 0) {
        ocall_debug("ocall_calloc for sealed_dirnode FAILED");
        goto out;
    }

    memcpy(sealed_dirnode_ext, sealed_dirnode, size);
    *p_sealed_dirnode_out_ext = sealed_dirnode_ext;

    ret = 0;
out:
    if (sealed_dirnode) {
        my_free(sealed_dirnode);
    }

    dirnode_put_wrapper(dirnode_wrapper);

    return ret;
}
