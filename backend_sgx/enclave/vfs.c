#include "enclave_internal.h"

#define LRU_CAPACITY    (256)


struct nexus_supernode      * global_supernode                = NULL;

struct nexus_metadata       * global_supernode_metadata       = NULL;

static struct nexus_lru     * metadata_objects_list           = NULL;

static struct nexus_dentry    root_dentry;

void
__lru_shrinker(uintptr_t element, uintptr_t key)
{
    struct nexus_metadata * metadata = (struct nexus_metadata *) element;

    buffer_layer_evict(&metadata->uuid);

    nexus_metadata_free(metadata);
}



int
nexus_vfs_init()
{
    global_supernode = NULL;

    metadata_objects_list = nexus_lru_create(LRU_CAPACITY,
                                             __uuid_hasher,
                                             __uuid_equals,
                                             __lru_shrinker);

    return 0;
}

void
nexus_vfs_deinit()
{
    nexus_lru_destroy(metadata_objects_list);

    if (global_supernode) {
        supernode_free(global_supernode);

        global_supernode = NULL;
    }
}

int
nexus_vfs_mount(struct nexus_crypto_buf * supernode_crypto_buf)
{
    // if we are doing a remount
    if (global_supernode_metadata) {
        nexus_metadata_free(global_supernode_metadata);
    }

    global_supernode = supernode_from_crypto_buf(supernode_crypto_buf, NEXUS_FREAD);

    if (global_supernode == NULL) {
        log_error("supernode_from_buffer FAILED\n");
        return -1;
    }


    global_supernode_metadata = nexus_metadata_new(&global_supernode->my_uuid,
                                                   global_supernode,
                                                   NEXUS_SUPERNODE,
                                                   NEXUS_FREAD,
                                                   nexus_crypto_buf_version(supernode_crypto_buf));

    if (global_supernode_metadata == NULL) {
        log_error("could not create metadata\n");
        goto out_err;
    }

    // initialize the root nexus dentry
    // TODO add code to cleanup root dentry
    memset(&root_dentry, 0, sizeof(struct nexus_dentry));
    INIT_LIST_HEAD(&root_dentry.children);
    nexus_uuid_copy(&global_supernode->root_uuid, &root_dentry.uuid);

    root_dentry.metadata_type = NEXUS_DIRNODE;

    return 0;

out_err:
    supernode_free(global_supernode);
    global_supernode = NULL;
    return -1;
}

struct nexus_dentry *
nexus_vfs_lookup(char * filepath)
{
    return dentry_lookup(&root_dentry, filepath);
}

struct nexus_metadata *
nexus_vfs_get(char * filepath, nexus_io_flags_t flags)
{
    struct nexus_dentry * dentry = dentry_lookup(&root_dentry, filepath);

    if (dentry == NULL) {
        log_error("dentry_lookup FAILED\n");
        return NULL;
    }

    return dentry_get_metadata(dentry, flags, true);
}


void
nexus_vfs_put(struct nexus_metadata * metadata)
{
    nexus_metadata_put(metadata);

    if (metadata->is_locked) {
        nexus_metadata_unlock(metadata);
    }
}

void
nexus_vfs_drop(struct nexus_metadata * metadata)
{
    // this eventually calls nexus_metadata_free
    nexus_lru_del(metadata_objects_list, &metadata->uuid);
}

int
nexus_vfs_revalidate(struct nexus_metadata * metadata, nexus_io_flags_t flags)
{
    bool should_reload = true;

    if (metadata->is_invalid) {
        return nexus_metadata_reload(metadata, flags);
    }

    buffer_layer_revalidate(&metadata->uuid, &should_reload);

    if (should_reload) {
        return nexus_metadata_reload(metadata, flags);
    }

    if (flags & NEXUS_FWRITE) {
        return buffer_layer_lock(&metadata->uuid);
    }

    return 0;
}

struct nexus_supernode *
nexus_vfs_acquire_supernode(nexus_io_flags_t flags)
{
    if (nexus_vfs_revalidate(global_supernode_metadata, flags)) {
        log_error("could not revalidate supernode\n");
        return NULL;
    }

    return (struct nexus_supernode *)global_supernode_metadata->object;
}


void
nexus_vfs_release_supernode()
{
    if (global_supernode_metadata->is_locked) {
        nexus_metadata_unlock(global_supernode_metadata);
    }
}


struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid * uuid, nexus_metadata_type_t type, nexus_io_flags_t flags)
{
    struct nexus_metadata * metadata  = NULL;

    struct nexus_uuid     * real_uuid = uuid;

    // check if we are loading a hardlink
    if (type == NEXUS_FILENODE) {
        struct nexus_uuid * tmp_uuid = supernode_get_reallink(global_supernode, uuid);

        if (tmp_uuid != NULL) {
            real_uuid = tmp_uuid;
        }
    }

    // try loading from cache
    metadata = nexus_lru_get(metadata_objects_list, real_uuid);

    if (metadata) {
        if (nexus_vfs_revalidate(metadata, flags) == 0) {
            return metadata;
        }

        // XXX: should we return -1 on FAILED revalidation ?
    }

    // otherwise, load from disk
    metadata = nexus_metadata_load(real_uuid, type, flags);

    if (metadata == NULL) {
        log_error("loading data into VFS failed\n");
        return NULL;
    }

    nexus_lru_put(metadata_objects_list, real_uuid, metadata);

    return metadata;
}

void
nexus_vfs_delete(struct nexus_uuid * uuid)
{
    nexus_lru_del(metadata_objects_list, uuid);

    buffer_layer_delete(uuid);
}
