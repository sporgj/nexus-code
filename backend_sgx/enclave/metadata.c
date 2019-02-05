#include "enclave_internal.h"


void
__metadata_set_clean(struct nexus_metadata * metadata)
{
    metadata->is_dirty = false;
}


void
__metadata_set_dirty(struct nexus_metadata * metadata)
{
    metadata->is_dirty = true;
}

static inline void
__set_metadata_object(struct nexus_metadata * metadata, void * object)
{
    struct nexus_supernode * supernode = NULL;
    struct nexus_dirnode   * dirnode   = NULL;
    struct nexus_filenode  * filenode  = NULL;

    switch (metadata->type) {
    case NEXUS_SUPERNODE:
        if (metadata->supernode) {
            supernode_free(metadata->supernode);
        }

        supernode = object;
        supernode->metadata = metadata;
        break;
    case NEXUS_DIRNODE:
        if (metadata->dirnode) {
            dirnode_free(metadata->dirnode);
        }

        dirnode = object;
        dirnode->metadata = metadata;
        break;
    case NEXUS_FILENODE:
        if (metadata->filenode) {
            filenode_free(metadata->filenode);
        }

        filenode = object;
        filenode->metadata = metadata;
        break;
    }

    metadata->object = object;
}

struct nexus_dentry *
metadata_get_dentry(struct nexus_metadata * metadata)
{
    if (metadata->dentry_count == 0) {
        return NULL;
    }

    return list_first_entry(&metadata->dentry_list, struct nexus_dentry, aliases);
}

struct nexus_metadata *
nexus_metadata_from_object(struct nexus_uuid     * uuid,
                           void                  * obj,
                           nexus_metadata_type_t   type,
                           nexus_io_flags_t        flags,
                           uint32_t                version)
{
    struct nexus_metadata * metadata = nexus_malloc(sizeof(struct nexus_metadata));

    metadata->type    = type;
    metadata->flags   = flags;
    metadata->version = version;

    metadata->dentry_lock = SGX_SPINLOCK_INITIALIZER;

    nexus_uuid_copy(uuid, &metadata->uuid);

    __set_metadata_object(metadata, obj);

    INIT_LIST_HEAD(&metadata->dentry_list);

    if (flags & (NEXUS_FWRITE | NEXUS_FCREATE)) {
        metadata->is_locked = true;
    }

    return metadata;
}

struct nexus_metadata *
nexus_metadata_create(struct nexus_uuid * uuid, nexus_dirent_type_t dirent_type)
{
    void * object = NULL;

    nexus_metadata_type_t metadata_type;


    /* we will first lock the file in the buffer layer */
    if (buffer_layer_lock(uuid, NEXUS_FCREATE)) {
        log_error("could not lock metadata file\n");
        return NULL;
    }


    metadata_type = (dirent_type == NEXUS_DIR) ? NEXUS_DIRNODE : NEXUS_FILENODE;

    switch (metadata_type) {
    case NEXUS_DIRNODE:
        object = dirnode_create(&global_supernode->root_uuid, uuid);
        break;
    case NEXUS_FILENODE:
        object = filenode_create(&global_supernode->root_uuid, uuid);
        break;
    case NEXUS_SUPERNODE:
        log_error("cannot create supernode from nexus_metadata_create()\n");
        return NULL;
    }

    return nexus_metadata_from_object(uuid, object, metadata_type, NEXUS_FCREATE, 0);
}

void
nexus_metadata_free(struct nexus_metadata * metadata)
{
    switch (metadata->type) {
    case NEXUS_SUPERNODE:
        supernode_free(metadata->supernode);
        break;
    case NEXUS_DIRNODE:
        dirnode_free(metadata->dirnode);
        break;
    case NEXUS_FILENODE:
        filenode_free(metadata->filenode);
        break;
    }

    if (metadata->dentry_count) {
        struct list_head * curr = NULL;
        struct list_head * pos = NULL;

        list_for_each_safe(curr, pos, &metadata->dentry_list) {
            struct nexus_dentry * dentry = NULL;

            dentry = list_entry(curr, struct nexus_dentry, aliases);

            dentry_invalidate(dentry);
        }

        metadata->dentry_count = 0;
    }

    memset(metadata, 0, sizeof(struct nexus_metadata));

    nexus_free(metadata);
}

static void *
__read_object(struct nexus_uuid     * uuid,
              nexus_metadata_type_t   type,
              nexus_io_flags_t        flags,
              uint32_t              * version)
{
    void                    * object     = NULL;

    struct nexus_crypto_buf * crypto_buf = NULL;


    if (type == NEXUS_FILENODE) {
        flags |= NEXUS_IO_FNODE;
    }

    crypto_buf = nexus_crypto_buf_create(uuid, flags);

    if (crypto_buf == NULL) {
        log_error("could not read crypto_buf\n");
        return NULL;
    }

    *version = nexus_crypto_buf_version(crypto_buf);

    if (*version == 0) {
        switch (type) {
        case NEXUS_DIRNODE:
            object = dirnode_create(&global_supernode->root_uuid, uuid);
            break;
        case NEXUS_FILENODE:
            object = filenode_create(&global_supernode->root_uuid, uuid);
            break;
        case NEXUS_SUPERNODE:
            log_error("supernode cannot be version 0\n");
            break;
        }
    } else {
        switch (type) {
        case NEXUS_DIRNODE:
            object = dirnode_from_crypto_buf(crypto_buf, flags);
            break;
        case NEXUS_FILENODE:
            object = filenode_from_crypto_buf(crypto_buf, flags);
            break;
        case NEXUS_SUPERNODE:
            object = supernode_from_crypto_buf(crypto_buf, flags);
            break;
        }
    }

    nexus_crypto_buf_free(crypto_buf);

    return object;
}

int
nexus_metadata_reload(struct nexus_metadata * metadata, nexus_io_flags_t flags)
{
    void    * object = NULL;

    uint32_t version = 0;


    object = __read_object(&metadata->uuid, metadata->type, flags, &version);

    if (object == NULL) {
        log_error("could not reload metadata object\n");
        return -1;
    }

    metadata->flags = flags;
    __set_metadata_object(metadata, object);

    if (flags & NEXUS_FWRITE) {
        metadata->is_locked = true;
    }

    metadata->is_invalid = false;

    metadata->is_dirty = false;

    return 0;
}

struct nexus_metadata *
nexus_metadata_load(struct nexus_uuid * uuid, nexus_metadata_type_t type, nexus_io_flags_t flags)
{
    void    * object = NULL;

    uint32_t version = 0;


    object = __read_object(uuid, type, flags, &version);

    if (object == NULL) {
        log_error("reading metadata object FAILED\n");
        return NULL;
    }

    return nexus_metadata_from_object(uuid, object, type, flags, version);
}

int
nexus_metadata_store(struct nexus_metadata * metadata)
{
    int ret = -1;

    if (!metadata->is_dirty && !(metadata->flags & NEXUS_FCREATE)) {
        return 0;
    }


    switch (metadata->type) {
    case NEXUS_SUPERNODE:
        ret = supernode_store(metadata->supernode, metadata->version, NULL);
        break;
    case NEXUS_DIRNODE:
        ret = dirnode_store(&metadata->uuid, metadata->dirnode, metadata->version, NULL);
        break;
    case NEXUS_FILENODE:
        ret = filenode_store(&metadata->uuid, metadata->filenode, metadata->version, NULL);
        break;
    }

    if (ret == 0) {
        __metadata_set_clean(metadata);
        metadata->version += 1;
        metadata->is_locked = false;
    } else {
        metadata->is_invalid = true;
    }

    return ret;
}

struct nexus_metadata *
nexus_metadata_get(struct nexus_metadata * metadata)
{
    if (metadata) {
        metadata->ref_count += 1;
    }

    return metadata;
}

/**
 * Decrements the ref count of the metadata object
 * @param metadata
 */
void
nexus_metadata_put(struct nexus_metadata * metadata)
{
    metadata->ref_count -= 1;
}


int
nexus_metadata_lock(struct nexus_metadata * metadata, nexus_io_flags_t flags)
{
    if (metadata->is_locked) {
        return 0;
    }

    if (metadata->type == NEXUS_FILENODE) {
        flags |= NEXUS_IO_FNODE;
    }

    if (buffer_layer_lock(&metadata->uuid, flags)) {
        log_error("buffer_layer_lock() FAILED\n");
        return -1;
    }

    metadata->is_locked = true;

    return 0;
}

void
nexus_metadata_unlock(struct nexus_metadata * metadata)
{
    if (metadata->is_locked) {
        buffer_layer_unlock(&metadata->uuid);
        metadata->is_locked = false;
    }
}

int
nexus_metadata_verify_uuids(struct nexus_dentry * dentry)
{
    // make sure the dentry's real uuid matches the metadata's uuid
    if (nexus_uuid_compare(&dentry->metadata->uuid, &dentry->link_uuid)) {
        return -1;
    }

    return 0;
}

void
nexus_metadata_set_parent_uuid(struct nexus_metadata * metadata, struct nexus_uuid * parent_uuid)
{
    struct nexus_dirnode   * dirnode   = NULL;
    struct nexus_filenode  * filenode  = NULL;

    if (metadata->type == NEXUS_DIRNODE) {
        dirnode = (struct nexus_dirnode *)metadata->object;

        dirnode_set_parent(dirnode, parent_uuid);
    } else if (metadata->type == NEXUS_FILENODE) {
        filenode = (struct nexus_dirnode *)metadata->object;

        filenode_set_parent(filenode, parent_uuid);
    }
}
