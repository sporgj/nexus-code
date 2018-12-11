#include "enclave_internal.h"

struct __supernode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    struct nexus_uuid usertable_uuid;
    struct nexus_mac  usertable_mac;
} __attribute__((packed));



void
__supernode_set_clean(struct nexus_supernode * supernode)
{
    if (supernode->metadata) {
        __metadata_set_clean(supernode->metadata);
    }
}

void
__supernode_set_dirty(struct nexus_supernode * supernode)
{
    if (supernode->metadata) {
        __metadata_set_dirty(supernode->metadata);
    }
}

uint8_t *
__parse_supernode_header(struct nexus_supernode * supernode, uint8_t * buffer, size_t buflen)
{
    struct __supernode_hdr * header = (struct __supernode_hdr *)buffer;

    if (buflen < sizeof(struct __supernode_hdr)) {
        log_error("buflen is too small for supernode\n");
        return NULL;
    }

    nexus_uuid_copy(&header->my_uuid, &supernode->my_uuid);
    nexus_uuid_copy(&header->root_uuid, &supernode->root_uuid);

    nexus_uuid_copy(&header->usertable_uuid, &supernode->usertable_uuid);
    nexus_mac_copy(&header->usertable_mac, &supernode->usertable_mac);

    return buffer + sizeof(struct __supernode_hdr);
}

static size_t
__supernode_buflen(struct nexus_supernode * supernode)
{
    return sizeof(struct __supernode_hdr);
}

static void
supernode_init(struct nexus_supernode * supernode)
{
    return;
}

struct nexus_supernode *
supernode_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer, nexus_io_flags_t mode)
{
    struct nexus_supernode * supernode = nexus_malloc(sizeof(struct nexus_supernode));

    uint8_t * buffer = NULL;
    size_t    buflen = 0;


    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, &supernode->mac);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        goto err;
    }


    supernode_init(supernode);

    buffer = __parse_supernode_header(supernode, buffer, buflen);

    if (buffer == NULL) {
        log_error("__parse_supernode FAILED\n");
        goto err;
    }


    // get the usertable
    {
        struct nexus_mac usertable_mac;

        supernode->usertable = nexus_usertable_load(&supernode->usertable_uuid,
                                                    NEXUS_FREAD,
                                                    &usertable_mac);

        if (supernode->usertable == NULL) {
            log_error("could not load usertable\n");
            goto err;
        }

        if (nexus_mac_compare(&usertable_mac, &supernode->usertable_mac)) {
            log_error("the version of the usertable does not match\n");
            goto err;
        }

        __usertable_set_supernode(supernode->usertable, supernode);
    }

    return supernode;
err:
    supernode_free(supernode);

    return NULL;
}

struct nexus_supernode *
supernode_load(struct nexus_uuid * uuid, nexus_io_flags_t mode)
{
    struct nexus_supernode * supernode = NULL;

    struct nexus_crypto_buf * crypto_buffer = NULL;


    crypto_buffer = nexus_crypto_buf_create(uuid, mode);

    if (crypto_buffer == NULL) {
        log_error("metadata_read FAILED\n");
        return NULL;
    }

    supernode = supernode_from_crypto_buf(crypto_buffer, mode);

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

    __usertable_set_supernode(supernode->usertable, supernode);

    supernode_init(supernode);

    return supernode;
}

uint8_t *
__serialize_supernode_header(struct nexus_supernode * supernode, uint8_t * buffer)
{
    struct __supernode_hdr * header = (struct __supernode_hdr *)buffer;

    nexus_uuid_copy(&supernode->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&supernode->root_uuid, &header->root_uuid);

    nexus_uuid_copy(&supernode->usertable_uuid, &header->usertable_uuid);
    nexus_mac_copy(&supernode->usertable_mac, &header->usertable_mac);

    return (buffer + sizeof(struct __supernode_hdr));
}

int
supernode_store(struct nexus_supernode * supernode, int version, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t serialized_buflen                = 0;

    int ret = -1;


    // first write out the usertable
    ret = nexus_usertable_store(supernode->usertable, &supernode->usertable_mac);

    if (ret != 0) {
        log_error("writing usertable FAILED\n");
        return -1;
    }

    serialized_buflen = __supernode_buflen(supernode);

    // allocates the crypto buffer
    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, version, &supernode->my_uuid);
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

        output_buffer = __serialize_supernode_header(supernode, output_buffer);

        if (output_buffer == NULL) {
            log_error("serializing supernode FAILED\n");
            goto out;
        }

        ret = nexus_crypto_buf_put(crypto_buffer, &supernode->mac);
        if (ret != 0) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
    }


    if (mac) {
        nexus_mac_copy(&supernode->mac, mac);
    }

    __supernode_set_clean(supernode);

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
