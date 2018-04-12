#include "enclave_internal.h"

#define LRU_CAPACITY    (256)


struct nexus_supernode      * global_supernode         = NULL;

static struct nexus_lru     * metadata_objects_list    = NULL;
static size_t                 metadata_objects_count   = 0;

static struct nexus_dentry    root_dentry;


uint32_t
__hasher(uintptr_t key)
{
    return nexus_uuid_hash((struct nexus_uuid *)key);
}

int __equals(uintptr_t key1, uintptr_t key2)
{
    return (nexus_uuid_compare((struct nexus_uuid *)key1, (struct nexus_uuid *)key2) == 0);
}

void
__freer(uintptr_t element, uintptr_t key)
{
    struct nexus_metadata * metadata = (struct nexus_metadata *) element;

    nexus_metadata_free(metadata);
}



int
nexus_vfs_init()
{
    global_supernode = NULL;

    metadata_objects_list = nexus_lru_create(LRU_CAPACITY, __hasher, __equals, __freer);

    metadata_objects_count = 0;

    return 0;
}

void
nexus_vfs_deinit()
{
    nexus_lru_destroy(metadata_objects_list);

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
    struct nexus_metadata * metadata = NULL;

    struct nexus_dentry   * dentry   = dentry_lookup(&root_dentry, filepath);

    if (dentry == NULL) {
        log_error("dentry_lookup FAILED\n");
        return NULL;
    }

    *path_dentry = dentry;

    metadata = dentry->metadata;

    // TODO increase usage count

    return metadata;
}


void
nexus_vfs_put(struct nexus_metadata * metadata)
{
    // TODO
}

void
nexus_vfs_drop(struct nexus_metadata * metadata)
{
    // this eventually calls nexus_metadata_free
    nexus_lru_del(metadata_objects_list, &metadata->uuid);
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
    struct nexus_metadata * metadata = nexus_metadata_load(uuid, type);

    if (metadata == NULL) {
        log_error("loading data into VFS failed\n");
        return NULL;
    }

    nexus_lru_put(metadata_objects_list, uuid, metadata);

    return metadata;
}

void
nexus_vfs_delete(struct nexus_uuid * uuid)
{
    nexus_lru_del(metadata_objects_list, uuid);

    buffer_layer_delete(uuid);
}
