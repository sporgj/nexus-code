#include "enclave_internal.h"

struct supernode         * global_supernode      = NULL;

static struct nexus_list * vfs_dirnode_list      = NULL;
static size_t              vfs_dirnode_list_size = 0;

int
nexus_vfs_init()
{
    global_supernode = NULL;

    vfs_dirnode_list = nexus_malloc(sizeof(struct nexus_list));

    nexus_list_init(vfs_dirnode_list);

    vfs_dirnode_list_size = 0;

    return 0;
}

void
nexus_vfs_deinit()
{
    nexus_list_destroy(vfs_dirnode_list);
    nexus_free(vfs_dirnode_list);

    if (global_supernode) {
        supernode_free(global_supernode);

        global_supernode = NULL;
    }
}

int
nexus_vfs_mount(struct nexus_crypto_buf * supernode_crypto_buf)
{
    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    buffer = nexus_crypto_buf_get(supernode_crypto_buf, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return -1;
    }

    // if we are doing a remount
    if (global_supernode) {
        supernode_free(global_supernode);
    }

    global_supernode = supernode_from_buffer(buffer, buflen);

    if (global_supernode == NULL) {
        log_error("supernode_from_buffer FAILED\n");
        return -1;
    }

    return 0;
}

int
nexus_vfs_verfiy_pubkey(struct nexus_hash * user_pubkey_hash)
{
    // XXX here will be code that goes through the user_table list
    return nexus_hash_compare(&global_supernode->owner_pubkey_hash, user_pubkey_hash);
}

// for now, this is just a wrapper for dirnode_from_buffer
struct nexus_dirnode *
nexus_vfs_get_dirnode(struct nexus_crypto_buf * dirnode_crypto_buf)
{
    struct nexus_dirnode * dirnode = NULL;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;


    buffer = nexus_crypto_buf_get(dirnode_crypto_buf, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }

    dirnode = dirnode_from_buffer(buffer, buflen);

    if (dirnode == NULL) {
        log_error("dirnode_from_buffer FAILED\n");
        return NULL;
    }

    // TODO dirnode_list management here

    return dirnode;
}

void
nexus_vfs_put_dirnode(struct nexus_dirnode * dirnode)
{
    // TODO dirnode_list management here
    dirnode_free(dirnode);
}

// TODO for now, this just loads the root dirnode
struct nexus_dirnode *
nexus_vfs_find_dirnode(char * dirpath)
{
    struct nexus_dirnode * dirnode = NULL;

    struct nexus_crypto_buf * crypto_buf = NULL;


    crypto_buf = metadata_read(&global_supernode->root_uuid, NULL);
    if (crypto_buf == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    dirnode = nexus_vfs_get_dirnode(crypto_buf);

    nexus_crypto_buf_free(crypto_buf);

    return dirnode;
}
