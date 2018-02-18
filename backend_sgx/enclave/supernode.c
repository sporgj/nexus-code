#include "enclave_internal.h"

struct __supernode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    struct nexus_uuid usertable_uuid;
    struct nexus_mac  usertable_mac;
} __attribute__((packed));


int
__parse_supernode(struct nexus_supernode * supernode, uint8_t * buffer, size_t buflen)
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
__serialize_supernode(struct nexus_supernode * supernode, uint8_t * buffer)
{
    struct __supernode_hdr * header = (struct __supernode_hdr *)buffer;

    nexus_uuid_copy(&supernode->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&supernode->root_uuid, &header->root_uuid);

    nexus_uuid_copy(&supernode->usertable_uuid, &header->usertable_uuid);
    nexus_mac_copy(&supernode->usertable_mac, &header->usertable_mac);

    return 0;
}

static size_t
__supernode_buflen(struct nexus_supernode * supernode)
{
    return sizeof(struct __supernode_hdr);
}

struct nexus_supernode *
supernode_from_crypto_buffer(struct nexus_crypto_buf * crypto_buffer)
{
    struct nexus_supernode * supernode = NULL;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    int ret = -1;


    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }


    supernode = nexus_malloc(sizeof(struct nexus_supernode));

    ret = __parse_supernode(supernode, buffer, buflen);

    if (ret != 0) {
        nexus_free(supernode);

        log_error("__parse_supernode FAILED\n");
        return NULL;
    }

    // get the usertable
    {
        struct nexus_mac usertable_mac;

        supernode->usertable = nexus_usertable_load(&supernode->usertable_uuid, &usertable_mac);

        if (supernode->usertable == NULL) {
            log_error("could not load usertable\n");
            goto err;
        }

        if (nexus_mac_compare(&usertable_mac, &supernode->usertable_mac)) {
            log_error("the version of the usertable does not match\n");
            goto err;
        }
    }

    return supernode;
err:
    if (supernode) {
        supernode_free(supernode);
    }

    return NULL;
}

struct nexus_supernode *
supernode_load(struct nexus_uuid * uuid)
{
    struct nexus_supernode * supernode = NULL;

    struct nexus_crypto_buf * crypto_buffer = NULL;


    crypto_buffer = buffer_layer_read_datastore(uuid, NULL);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    supernode = supernode_from_crypto_buffer(crypto_buffer);

    nexus_crypto_buf_free(crypto_buffer);

    if (supernode == NULL) {
        log_error("parsing the supernode failed\n");
        return NULL;
    }

    return supernode;
}

struct nexus_supernode *
supernode_create(char * user_pubkey)
{
    struct nexus_supernode * supernode = NULL;

    supernode = nexus_malloc(sizeof(struct nexus_supernode));

    nexus_uuid_gen(&supernode->my_uuid);
    nexus_uuid_gen(&supernode->root_uuid);

    supernode->usertable = nexus_usertable_create(user_pubkey);
    if (supernode->usertable == NULL) {
        nexus_free(supernode);

        log_error("loading usertable failed\n");
        return NULL;
    }

    nexus_usertable_copy_uuid(supernode->usertable, &supernode->usertable_uuid);

    return supernode;
}

int
supernode_store(struct nexus_supernode * supernode, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t    serialized_buflen = 0;

    int ret = -1;


    // first write out the usertable
    ret = nexus_usertable_store(supernode->usertable, &supernode->usertable_mac);

    if (ret != 0) {
        log_error("writing usertable FAILED\n");
        return -1;
    }

    serialized_buflen = __supernode_buflen(supernode);

    // allocates the crypto buffer
    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, &supernode->my_uuid);
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

        ret = __serialize_supernode(supernode, output_buffer);
        if (ret != 0) {
            log_error("serializing supernode FAILED\n");
            goto out;
        }

        ret = nexus_crypto_buf_put(crypto_buffer, mac);
        if (ret != 0) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
    }

    // flush the buffer to the backend
    ret = nexus_crypto_buf_flush(crypto_buffer, NULL);
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
supernode_free(struct nexus_supernode * supernode)
{
    nexus_usertable_free(supernode->usertable);
    nexus_free(supernode);
}
