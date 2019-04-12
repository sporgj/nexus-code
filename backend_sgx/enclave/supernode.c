#include "enclave_internal.h"

struct __supernode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    struct nexus_uuid usertable_uuid;

    struct nexus_uuid hardlink_table_uuid;

    struct abac_superinfo abac_superinfo;
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

    nexus_uuid_copy(&header->hardlink_table_uuid, &supernode->hardlink_table_uuid);

    memcpy(&supernode->abac_superinfo, &header->abac_superinfo, sizeof(struct abac_superinfo));

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


    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        goto err;
    }


    supernode_init(supernode);

    buffer = __parse_supernode_header(supernode, buffer, buflen);

    if (buffer == NULL) {
        log_error("__parse_supernode_header FAILED\n");
        goto err;
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
        log_error("nexus_crypto_buf_create FAILED\n");
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
    struct nexus_supernode * supernode = nexus_malloc(sizeof(struct nexus_supernode));

    nexus_uuid_gen(&supernode->my_uuid);
    nexus_uuid_gen(&supernode->root_uuid);
    nexus_uuid_gen(&supernode->hardlink_table_uuid);
    nexus_uuid_gen(&supernode->usertable_uuid);

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

    nexus_uuid_copy(&supernode->hardlink_table_uuid, &header->hardlink_table_uuid);

    memcpy(&header->abac_superinfo, &supernode->abac_superinfo, sizeof(struct abac_superinfo));

    return (buffer + sizeof(struct __supernode_hdr));
}

int
supernode_store(struct nexus_supernode * supernode, int version, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t serialized_buflen                = 0;

    int ret = -1;


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

        ret = nexus_crypto_buf_put(crypto_buffer, mac);
        if (ret != 0) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
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
    nexus_free(supernode);
}
