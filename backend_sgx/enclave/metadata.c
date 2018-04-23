#include "enclave_internal.h"

struct nexus_metadata *
nexus_metadata_new(struct nexus_uuid     * uuid,
                   void                  * obj,
                   nexus_metadata_type_t   type,
                   nexus_io_flags_t        flags,
                   uint32_t                version)
{
    struct nexus_metadata * metadata = nexus_malloc(sizeof(struct nexus_metadata));

    nexus_uuid_copy(uuid, &metadata->uuid);

    metadata->type    = type;
    metadata->version = version;

    if (type == NEXUS_DIRNODE) {
        metadata->dirnode = (struct nexus_dirnode *) obj;
    } else if (type == NEXUS_FILENODE) {
        metadata->filenode = (struct nexus_filenode *)obj;
    }

    metadata->mode = flags;

    return metadata;
}

void
nexus_metadata_free(struct nexus_metadata * metadata)
{
    switch (metadata->type) {
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
        case NEXUS_DIRNODE:
            object = dirnode_create(&global_supernode->root_uuid, uuid);
            break;
        case NEXUS_FILENODE:
            object = filenode_create(&global_supernode->root_uuid, uuid);
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
    }

    // throw the old object and set the new
    switch (metadata->type) {
    case NEXUS_DIRNODE:
        dirnode_free(metadata->dirnode);
        break;
    case NEXUS_FILENODE:
        filenode_free(metadata->filenode);
        break;
    }

    metadata->object = object;

    return 0;
}

struct nexus_metadata *
nexus_metadata_load(struct nexus_uuid * uuid, nexus_metadata_type_t type, nexus_io_flags_t mode)
{
    void    * object = NULL;

    uint32_t version = 0;


    object = __read_object(uuid, type, mode, &version);

    if (object == NULL) {
        log_error("reading metadata object FAILED\n");
        return NULL;
    }

    return nexus_metadata_new(uuid, object, type, mode, version);
}

int
nexus_metadata_store(struct nexus_metadata * metadata)
{
    int ret = -1;

    switch (metadata->type) {
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
