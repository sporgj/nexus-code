#include "enclave_internal.h"

struct nexus_supernode  * global_supernode = NULL;

static struct nexus_list  metadata_objects_list;
static size_t             metadata_objects_count;

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
    // TODO
    return NULL;
}

void
nexus_vfs_put(struct nexus_metadata * metadata)
{
    //TODO
}

int
nexus_vfs_flush(struct nexus_metadata * metadata)
{
    // TODO
    return -1;
}

struct nexus_metadata *
nexus_vfs_load(struct nexus_uuid * metadata_uuid, struct nexus_uuid_path * uuid_path)
{
    // TODO
    return NULL;
}
