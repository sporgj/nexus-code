#include "enclave_internal.h"

#define LRU_CAPACITY    (256)


struct nexus_supernode      * global_supernode           = NULL;

struct nexus_metadata       * global_supernode_metadata  = NULL;

static struct nexus_lru     * metadata_cache             = NULL;

static sgx_spinlock_t         mcache_lock                = SGX_SPINLOCK_INITIALIZER;

static sgx_spinlock_t         traversal_lock             = SGX_SPINLOCK_INITIALIZER;


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

    metadata_cache = nexus_lru_create(LRU_CAPACITY, __uuid_hasher, __uuid_equals, __lru_shrinker);

    return 0;
}

void
nexus_vfs_deinit()
{
    nexus_lru_destroy(metadata_cache);

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

    global_supernode_metadata
        = nexus_metadata_from_object(&global_supernode->my_uuid,
                                     global_supernode,
                                     NEXUS_SUPERNODE,
                                     NEXUS_FREAD,
                                     nexus_crypto_buf_version(supernode_crypto_buf));

    if (global_supernode_metadata == NULL) {
        log_error("could not create metadata\n");
        goto out_err;
    }

    dcache_init_root();

    return 0;

out_err:
    supernode_free(global_supernode);
    global_supernode = NULL;
    return -1;
}

struct nexus_metadata *
dentry_get_metadata(struct nexus_dentry * dentry, nexus_io_flags_t flags, bool revalidate)
{
    if (revalidate && dentry_revalidate(dentry, flags)) {
        log_error("could revalidate dentry\n");
        return NULL;
    }

    return nexus_metadata_get(dentry->metadata);
}

struct nexus_dentry *
nexus_vfs_lookup(char * filepath)
{
    struct nexus_dentry * dentry = NULL;

    struct path_walker walker = {
        .remaining_path       = filepath,
        .type                 = PATH_WALK_NORMAL,
        .parent_dentry        = global_root_dentry
    };

    sgx_spin_lock(&traversal_lock);
    dentry = dentry_lookup(&walker);
    sgx_spin_unlock(&traversal_lock);

    return dentry;
}

struct nexus_dentry *
nexus_vfs_lookup_parent(char * filepath, struct path_walker * walker)
{
    walker->remaining_path = filepath;
    walker->parent_dentry  = global_root_dentry;
    walker->type           = PATH_WALK_PARENT;

    sgx_spin_lock(&traversal_lock);
    struct nexus_dentry * dentry = dentry_lookup(walker);
    sgx_spin_unlock(&traversal_lock);

    if (dentry == NULL) {
        return NULL;
    }

    if (dentry_revalidate(dentry, NEXUS_FREAD)) {
        return NULL;
    }

    return dentry;
}

struct nexus_metadata *
nexus_vfs_complete_lookup(struct path_walker * walker, nexus_io_flags_t flags)
{
    walker->type = PATH_WALK_NORMAL;

    struct nexus_dentry * start_dentry = walker->parent_dentry;

    struct nexus_dentry * dentry = dentry_lookup(walker);

    if (dentry == NULL) {
        log_error("dentry_lookup FAILED\n");
        return NULL;
    }

    if (dentry == start_dentry) {
        return nexus_metadata_get(dentry->metadata);
    }

    return dentry_get_metadata(dentry, flags, true);
}

struct nexus_metadata *
nexus_vfs_get(char * filepath, nexus_io_flags_t flags)
{
    struct nexus_dentry * dentry = nexus_vfs_lookup(filepath);

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

int
__vfs_revalidate(struct nexus_metadata * metadata, nexus_io_flags_t flags, bool * has_changed)
{
    if (metadata->is_invalid) {
        return nexus_metadata_reload(metadata, flags);
    }

    buffer_layer_revalidate(&metadata->uuid, has_changed);

    if (*has_changed) {
        return nexus_metadata_reload(metadata, flags);
    }

    if (flags & NEXUS_FWRITE) {
        metadata->is_locked = true;
        return buffer_layer_lock(&metadata->uuid, flags);
    }

    return 0;
}

int
nexus_vfs_revalidate(struct nexus_metadata * metadata, nexus_io_flags_t flags, bool * has_changed)
{
    int ret = __vfs_revalidate(metadata, flags, has_changed);

    if (ret == 0) {
        // TODO make this into a function
        metadata->flags = flags;
    }

    return ret;
}

struct nexus_supernode *
nexus_vfs_acquire_supernode(nexus_io_flags_t flags)
{
    bool has_changed = false;

    if (nexus_vfs_revalidate(global_supernode_metadata, flags, &has_changed)) {
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
nexus_vfs_load(struct nexus_uuid * real_uuid, nexus_metadata_type_t type, nexus_io_flags_t flags)
{
    struct nexus_metadata * metadata  = NULL;

    // try loading from cache
    metadata = nexus_lru_get(metadata_cache, real_uuid);

    if (metadata) {
        bool has_changed = false;

        if (nexus_vfs_revalidate(metadata, flags, &has_changed) == 0) {
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

    sgx_spin_lock(&mcache_lock);
    nexus_lru_put(metadata_cache, &metadata->uuid, metadata);
    sgx_spin_unlock(&mcache_lock);

    return metadata;
}

void
nexus_vfs_delete(struct nexus_uuid * uuid)
{
    sgx_spin_lock(&mcache_lock);
    nexus_lru_del(metadata_cache, uuid);
    sgx_spin_unlock(&mcache_lock);

    buffer_layer_delete(uuid);
}
