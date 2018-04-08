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

struct nexus_metadata *
nexus_vfs_create(struct nexus_dentry * parent_dentry, nexus_metadata_type_t type)
{
    struct nexus_metadata * metadata = NULL;


    // XXX: the parent dentry could be used to inform the metadata store about the
    // path to this new metadata object;
    (void)parent_dentry;

    metadata = nexus_malloc(sizeof(struct nexus_metadata));

    metadata->type = type;

    nexus_uuid_gen(&metadata->uuid);

    if (type == NEXUS_DIRNODE) {
        metadata->dirnode = dirnode_create(&global_supernode->my_uuid, &metadata->uuid);

        if (metadata->dirnode == NULL) {
            log_error("creating dirnode FAILED\n");
        }
    } else {
        metadata->filenode = filenode_create(&global_supernode->my_uuid, &metadata->uuid);

        if (metadata->filenode == NULL) {
            log_error("creating filenode FAILED\n");
        }
    }

    return metadata;
}

struct nexus_metadata *
nexus_vfs_get(char * filepath, nexus_metadata_type_t type, struct nexus_dentry ** path_dentry)
{
    struct nexus_dentry * dentry = dentry_lookup(&root_dentry, filepath);

    if (dentry == NULL) {
        log_error("dentry_lookup FAILED\n");
        return NULL;
    }

    *path_dentry = dentry;

    return dentry->metadata;
}


int
nexus_vfs_put(struct nexus_metadata * metadata)
{
    int ret = -1;

    if (metadata->is_dirty) {
        ret = nexus_metadata_store(metadata);
    }

    // we have no caching for now, just delete
    nexus_metadata_free(metadata);

    return ret;
}

void
nexus_vfs_drop(struct nexus_metadata * metadata)
{
    // TODO
    nexus_metadata_free(metadata);
}

int
nexus_vfs_revalidate(struct nexus_metadata * metadata)
{
    // TODO stat the metadata store and check if the metadata is old
    return 0;
}

struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid * uuid, nexus_metadata_type_t type)
{
    // search cache for contents
    return nexus_metadata_load(uuid, type);
}

void
nexus_vfs_delete(struct nexus_uuid * uuid)
{
    // TODO

    buffer_layer_delete(uuid);
}
