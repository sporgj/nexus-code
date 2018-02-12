#include "enclave_internal.h"

struct __supernode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    struct nexus_uuid usertable_uuid;
    struct nexus_mac  usertable_mac;
} __attribute__((packed));


int
__parse_supernode(struct supernode * supernode, uint8_t * buffer, size_t buflen)
{
    struct __supernode_hdr * header = (struct __supernode_hdr *)buffer;

    if (buflen < sizeof(struct __supernode_hdr)) {
        log_error("buflen is too small for supernode\n");
        return -1;
    }

    nexus_uuid_copy(&header->my_uuid, &supernode->my_uuid);
    nexus_uuid_copy(&header->root_uuid, &supernode->root_uuid);

    nexus_uuid_copy(&header->usertable_uuid, &supernode->usertable_uuid);
    nexus_mac_copy(&header->usertable_mac, &supernode->usertable_mac);

    return 0;
}

int
__serialize_supernode(struct supernode * supernode, uint8_t * buffer)
{
    struct __supernode_hdr * header = (struct __supernode_hdr *)buffer;

    nexus_uuid_copy(&supernode->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&supernode->root_uuid, &header->root_uuid);

    nexus_uuid_copy(&supernode->usertable_uuid, &header->usertable_uuid);
    nexus_mac_copy(&supernode->usertable_mac, &header->usertable_mac);

    return 0;
}

static size_t
__supernode_buflen(struct supernode * supernode)
{
    return sizeof(struct __supernode_hdr);
}

struct supernode *
supernode_from_crypto_buffer(struct nexus_crypto_buf * crypto_buffer)
{
    struct supernode * supernode = NULL;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    int ret = -1;


    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }


    supernode = nexus_malloc(sizeof(supernode));

    ret = __parse_supernode(supernode, buffer, buflen);

    if (ret != 0) {
        nexus_free(supernode);

        log_error("__parse_supernode FAILED\n");
        return NULL;
    }

    return supernode;
}

struct supernode *
supernode_load(struct nexus_uuid * uuid)
{
    struct supernode * supernode = NULL;

    struct nexus_crypto_buf * crypto_buffer = NULL;


    crypto_buffer = metadata_read(uuid, NULL);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    supernode = supernode_from_crypto_buffer(crypto_buffer);

    nexus_crypto_buf_free(crypto_buffer);

    return supernode;
}

static struct supernode *
supernode_new(char * user_pubkey)
{
    struct supernode * supernode = NULL;

    supernode = nexus_malloc(sizeof(struct supernode));

    nexus_uuid_gen(&supernode->my_uuid);
    nexus_uuid_gen(&supernode->root_uuid);

    supernode->usertable = nexus_usertable_create(user_pubkey);
    if (supernode->usertable == NULL) {
        nexus_free(supernode);

        log_error("loading usertable failed\n");
        return NULL;
    }

    return supernode;
}

struct supernode *
supernode_create(char * user_pubkey)
{
    struct supernode * supernode = NULL;

    int ret = -1;


    supernode = supernode_new(user_pubkey);
    if (supernode == NULL) {
        return NULL;
    }

    // user table
#if 0
    {
        struct volume_usertable * usertable = NULL;

        usertable = volume_usertable_create(&supernode->user_list_uuid);
        if (usertable == NULL) {
            goto out;
        }

        ret = volume_usertable_store(usertable, &supernode->user_list_mac);

        volume_usertable_free(usertable);

        if (ret != 0) {
            ocall_debug("volume_usertable_store FAILED");
            goto out;
        }
    }
#endif

    // dirnode
    {
        struct nexus_dirnode * root_dirnode = dirnode_create(&supernode->root_uuid);
        if (root_dirnode == NULL) {
            ret = -1;
            goto out;
        }

        nexus_uuid_copy(&root_dirnode->root_uuid, &root_dirnode->my_uuid);

        ret = dirnode_store(root_dirnode, NULL, NULL);

        dirnode_free(root_dirnode);

        if (ret != 0) {
            log_error("dirnode_store FAILED\n");
            goto out;
        }
    }

    ret = 0;
out:
    if (ret) {
        supernode_free(supernode);
        return NULL;
    }

    return supernode;
}

int
supernode_store(struct supernode       * supernode,
                struct nexus_uuid_path * uuid_path,
                struct nexus_mac       * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t * serialized_buffer = NULL;
    size_t    serialized_buflen = 0;

    int ret = -1;


    serialized_buflen = __supernode_buflen(supernode);

    // allocates the crypto buffer
    crypto_buffer = nexus_crypto_buf_new(serialized_buflen);
    if (!crypto_buffer) {
        goto out;
    }

    // write to the buffer
    {
        uint8_t * output_buffer = NULL;

        size_t    buffer_size   = 0;


        output_buffer = nexus_crypto_buf_get(crypto_buffer, &buffer_size, NULL);

        if (output_buffer == NULL) {
            log_error("could not get the crypto_bufffer buffer\n");
            goto out;
        }

        memcpy(output_buffer, serialized_buffer, serialized_buflen);

        ret = nexus_crypto_buf_put(crypto_buffer, mac);

        if (ret) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
    }

    // flush the buffer to the backend
    ret = metadata_write(&supernode->my_uuid, uuid_path, crypto_buffer);
    if (ret) {
        log_error("metadata_write FAILED\n");
        goto out;
    }


    ret = 0;
out:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return ret;
}

void
supernode_free(struct supernode * supernode)
{
    nexus_free(supernode);
}
