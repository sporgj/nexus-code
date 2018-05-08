#include "enclave_internal.h"

static inline void
__set_metadata_object(struct nexus_metadata * metadata, void * object)
{
    struct nexus_supernode * supernode = NULL;
    struct nexus_dirnode   * dirnode   = NULL;
    struct nexus_filenode  * filenode  = NULL;

    metadata->object = object;

    switch (metadata->type) {
    case NEXUS_SUPERNODE:
        supernode = object;
        supernode->metadata = metadata;
        break;
    case NEXUS_DIRNODE:
        dirnode = object;
        dirnode->metadata = metadata;
        break;
    case NEXUS_FILENODE:
        filenode = object;
        filenode->metadata = metadata;
        break;
    }
}

struct nexus_metadata *
nexus_metadata_new(struct nexus_uuid     * uuid,
                   void                  * obj,
                   nexus_metadata_type_t   type,
                   nexus_io_flags_t        flags,
                   uint32_t                version)
{
    struct nexus_metadata * metadata = nexus_malloc(sizeof(struct nexus_metadata));

    metadata->type    = type;
    metadata->flags   = flags;
    metadata->version = version;

    nexus_uuid_copy(uuid, &metadata->uuid);

    __set_metadata_object(metadata, obj);

    return metadata;
}

void
nexus_metadata_free(struct nexus_metadata * metadata)
{
    switch (metadata->type) {
    case NEXUS_SUPERNODE:
        supernode_free(metadata->supernode);
    case NEXUS_DIRNODE:
        dirnode_free(metadata->dirnode);
        break;
    case NEXUS_FILENODE:
        filenode_free(metadata->filenode);
        break;
    }

    if (metadata->dentry) {
        metadata->dentry->metadata = NULL;
    }

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


    crypto_buf = nexus_crypto_buf_create(uuid, flags);

    if (crypto_buf == NULL) {
        log_error("could not read crypto_buf\n");
        return NULL;
    }

    *version = nexus_crypto_buf_version(crypto_buf);

    if (*version == 0) {
        switch (type) {
        case NEXUS_SUPERNODE:
            log_error("supernode cannot be version 0\n");
            break;
        case NEXUS_DIRNODE:
            object = dirnode_create(&global_supernode->root_uuid, uuid);
            break;
        case NEXUS_FILENODE:
            object = filenode_create(&global_supernode->root_uuid, uuid);
            break;
        }
    } else {
        switch (type) {
        case NEXUS_SUPERNODE:
            object = supernode_from_crypto_buf(crypto_buf, flags);
            break;
        case NEXUS_DIRNODE:
            object = dirnode_from_crypto_buf(crypto_buf, flags);
            break;
        case NEXUS_FILENODE:
            object = filenode_from_crypto_buf(crypto_buf, flags);
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

    // throw the old object and set the new
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

    metadata->flags = flags;
    __set_metadata_object(metadata, object);

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

    return nexus_metadata_new(uuid, object, type, flags, version);
}

// FIXME: this is temporary until a more stable solution to hardlinks/rename
// is found.
static int
__metadata_store_supernode(struct nexus_metadata * metadata)
{
    struct nexus_supernode * supernode = metadata->supernode;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    buffer = buffer_layer_get(&supernode->my_uuid, NEXUS_FWRITE, &buflen);

    if (buffer == NULL) {
        log_error("buffer_layer_get FAILED\n");
        return -1;
    }

    return supernode_store(metadata->supernode, metadata->version, NULL);
}

int
nexus_metadata_store(struct nexus_metadata * metadata)
{
    int ret = -1;

    if (!metadata->is_dirty) {
        return 0;
    }

    switch (metadata->type) {
    case NEXUS_SUPERNODE:
        ret = __metadata_store_supernode(metadata);
        break;
    case NEXUS_DIRNODE:
        ret = dirnode_store(&metadata->uuid, metadata->dirnode, metadata->version, NULL);
        break;
    case NEXUS_FILENODE:
        ret = filenode_store(&metadata->uuid, metadata->filenode, metadata->version, NULL);
        break;
    }

    if (ret == 0) {
        metadata->is_dirty = false;
        metadata->version += 1;
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
