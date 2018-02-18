#include "enclave_internal.h"

struct nexus_supernode  * global_supernode = NULL;

static struct nexus_list  metadata_objects_list;
static size_t             metadata_objects_count;

static struct nexus_dentry root_dentry;

int
nexus_vfs_init()
{
    global_supernode = NULL;

    nexus_list_init(&metadata_objects_list);

    metadata_objects_count = 0;

    return 0;
}

void
nexus_vfs_deinit()
{
    nexus_list_destroy(&metadata_objects_list);
    metadata_objects_count = 0;

    if (global_supernode) {
        supernode_free(global_supernode);

        global_supernode = NULL;
    }
}

int
nexus_vfs_mount(struct nexus_crypto_buf * supernode_crypto_buf)
{
    // if we are doing a remount
    if (global_supernode) {
        supernode_free(global_supernode);
    }

    global_supernode = supernode_from_crypto_buffer(supernode_crypto_buf);

    if (global_supernode == NULL) {
        log_error("supernode_from_buffer FAILED\n");
        return -1;
    }

    // initialize the root nexus dentry
    memset(&root_dentry, 0, sizeof(struct nexus_dentry));
    INIT_LIST_HEAD(&root_dentry.children);
    nexus_uuid_copy(&global_supernode->root_uuid, &root_dentry.uuid);

    root_dentry.metadata_type = NEXUS_DIRNODE;

    return 0;
}

int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash)
{
    struct nexus_user * user = NULL;

    user = nexus_usertable_find_pubkey(global_supernode->usertable, user_pubkey_hash);

    if (user == NULL) {
        return -1;
    }

    return 0;
}

struct nexus_metadata *
nexus_vfs_get(char * filepath, nexus_metadata_type_t type)
{
    struct nexus_dentry * dentry = NULL;


    dentry = dentry_lookup(&root_dentry, filepath);

    if (dentry == NULL) {
        log_error("dentry_lookup FAILED\n");
        return NULL;
    }

    return dentry->metadata;
}

static void
free_metadata(struct nexus_metadata * metadata)
{
    switch (metadata->type) {
    case NEXUS_DIRNODE:
        dirnode_free(metadata->dirnode);
        break;
    case NEXUS_FILENODE:
        filenode_free(metadata->filenode);
        break;
    }

    if (metadata->uuid_path) {
        nexus_free(metadata->uuid_path);
    }

    // update the dentry that the metadata doesn't exist
    metadata->dentry->metadata = NULL;

    nexus_free(metadata);
}

void
nexus_vfs_put(struct nexus_metadata * metadata)
{
    // we have no caching for now, just delete
    free_metadata(metadata);
}

int
nexus_vfs_flush(struct nexus_metadata * metadata)
{
    switch (metadata->type) {
    case NEXUS_DIRNODE:
        return dirnode_store(metadata->dirnode, metadata->uuid_path, NULL);
    case NEXUS_FILENODE:
        return filenode_store(metadata->filenode, metadata->uuid_path, NULL);
    default:
        log_error("Flush operation for metadata not implemented\n");
        return -1;
    }

    return -1;
}

int
nexus_vfs_revalidate(struct nexus_metadata * metadata)
{
    // TODO
    return -1;
}

static struct nexus_metadata *
create_metadata(struct nexus_uuid      * metadata_uuid,
                struct nexus_uuid_path * uuid_path,
                void                   * metadata_obj,
                nexus_metadata_type_t    metadata_type)
{
    struct nexus_metadata * metadata = NULL;

    metadata = nexus_malloc(sizeof(struct nexus_metadata));

    metadata->type      = metadata_type;
    metadata->uuid_path = uuid_path;

    nexus_uuid_copy(metadata_uuid, &metadata->uuid);

    if (metadata_type == NEXUS_DIRNODE) {
        metadata->dirnode = (struct nexus_dirnode *) metadata_obj;
    } else if (metadata_type == NEXUS_FILENODE) {
        metadata->filenode = (struct nexus_filenode *) metadata_obj;
    }

    return metadata;
}

struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid      * metadata_uuid,
               struct nexus_uuid_path * uuid_path,
               nexus_metadata_type_t    metadata_type)
{
    struct nexus_dirnode  * dirnode  = NULL;
    struct nexus_filenode * filenode = NULL;

    switch (metadata_type) {
    case NEXUS_DIRNODE:
        dirnode = dirnode_load(metadata_uuid, uuid_path);

        if (dirnode == NULL) {
            log_error("loading dirnode in VFS failed\n");
            return NULL;
        }

        return create_metadata(metadata_uuid, uuid_path, dirnode, NEXUS_DIRNODE);

    case NEXUS_FILENODE:
        filenode = filenode_load(metadata_uuid, uuid_path);

        if (filenode == NULL) {
            log_error("loading filenode in VFS failed\n");
            return NULL;
        }

        return create_metadata(metadata_uuid, uuid_path, filenode, NEXUS_FILENODE);
    }

    log_error("incorrect metadata type (%d)\n", metadata_type);
    return NULL;
}
