#include "enclave_internal.h"

struct __supernode_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    struct nexus_uuid usertable_uuid;
    struct nexus_mac  usertable_mac;

    uint32_t          hardlink_count;
} __attribute__((packed));


struct __hardlink_pair {
    struct nexus_uuid link_uuid;    // the hardlink uuid
    struct nexus_uuid real_uuid;    // the name of the file stored on disk
} __attribute__((packed));



static void
__free_hardlink_pair(void * element)
{
    struct __hardlink_pair * pair = (struct __hardlink_pair *)element;

    nexus_free(pair);
}

void
__supernode_set_clean(struct nexus_supernode * supernode)
{
    if (supernode->metadata) {
        supernode->metadata->is_dirty = false;
    }
}

void
__supernode_set_dirty(struct nexus_supernode * supernode)
{
    if (supernode->metadata) {
        supernode->metadata->is_dirty = true;
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

    supernode->hardlink_count = header->hardlink_count;

    return buffer + sizeof(struct __supernode_hdr);
}

int
__parse_hardlink_table(struct nexus_supernode * supernode, uint8_t * buffer)
{
    struct __hardlink_pair * src_pair = (struct __hardlink_pair *)buffer;

    for (size_t i = 0; i < supernode->hardlink_count; i++) {
        struct __hardlink_pair * pair = nexus_malloc(sizeof(struct __hardlink_pair));

        memcpy(pair, src_pair, sizeof(struct __hardlink_pair));

        nexus_list_append(&supernode->hardlink_table, pair);
    }

    return 0;
}

static size_t
__supernode_buflen(struct nexus_supernode * supernode)
{
    return sizeof(struct __supernode_hdr) +
           (sizeof(struct __hardlink_pair) * supernode->hardlink_count);
}

static void
supernode_init(struct nexus_supernode * supernode)
{
    nexus_list_init(&supernode->hardlink_table);
    nexus_list_set_deallocator(&supernode->hardlink_table, __free_hardlink_pair);
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
        log_error("__parse_supernode FAILED\n");
        goto err;
    }


    if (__parse_hardlink_table(supernode, buffer)) {
        log_error("__parse_linktable FAILED\n");
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

    header->hardlink_count = supernode->hardlink_count;

    return (buffer + sizeof(struct __supernode_hdr));
}

int
__serialize_hardlinks(struct nexus_supernode * supernode, uint8_t * buffer)
{
    struct nexus_list_iterator * iter     = list_iterator_new(&supernode->hardlink_table);

    struct __hardlink_pair     * dst_pair = (struct __hardlink_pair *)buffer;

    while (list_iterator_is_valid(iter)) {
        struct __hardlink_pair * pair = list_iterator_get(iter);

        memcpy(dst_pair, pair, sizeof(struct __hardlink_pair));

        dst_pair += 1;

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return 0;
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

        if (__serialize_hardlinks(supernode, output_buffer)) {
            log_error("could not serialize hardlinks\n");
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
    nexus_list_destroy(&supernode->hardlink_table);
    nexus_usertable_free(supernode->usertable);
    nexus_free(supernode);
}

struct nexus_list_iterator *
__get_hardlink_pair_iterator(struct nexus_supernode * supernode, struct nexus_uuid * link_uuid)
{
    struct nexus_list_iterator * iter = list_iterator_new(&supernode->hardlink_table);

    while (list_iterator_is_valid(iter)) {
        struct __hardlink_pair * pair = list_iterator_get(iter);

        if (nexus_uuid_compare(&pair->link_uuid, link_uuid) == 0) {
            return iter;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return NULL;
}

size_t
__get_link_count(struct nexus_supernode * supernode, struct nexus_uuid * uuid)
{
    size_t link_count = 0;

    struct nexus_list_iterator * iter = list_iterator_new(&supernode->hardlink_table);

    while (list_iterator_is_valid(iter)) {
        struct __hardlink_pair * pair = list_iterator_get(iter);

        if (nexus_uuid_compare(&pair->real_uuid, uuid) == 0) {
            link_count += 1;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return link_count;
}

int
__add_hardlink(struct nexus_supernode * supernode,
               struct nexus_uuid      * src_uuid,
               struct nexus_uuid      * real_uuid)
{
    struct __hardlink_pair * pair = nexus_malloc(sizeof(struct __hardlink_pair));

    nexus_uuid_copy(src_uuid, &pair->link_uuid);
    nexus_uuid_copy(real_uuid, &pair->real_uuid);

    nexus_list_append(&supernode->hardlink_table, pair);
    supernode->hardlink_count += 1;

    __supernode_set_dirty(supernode);

    return 0;
}

struct nexus_uuid *
supernode_get_reallink(struct nexus_supernode * supernode, struct nexus_uuid * link_uuid)
{
    struct nexus_list_iterator * iter = __get_hardlink_pair_iterator(supernode, link_uuid);

    if (iter) {
        struct __hardlink_pair * pair        = list_iterator_get(iter);

        struct nexus_uuid      * result_uuid = &pair->real_uuid;

        list_iterator_free(iter);

        return result_uuid;
    }

    return NULL;
}

int
supernode_add_hardlink(struct nexus_supernode * supernode,
                       struct nexus_uuid      * src_uuid,
                       struct nexus_uuid      * dst_uuid)
{
    struct nexus_uuid * real_uuid = NULL;

    if (supernode_get_reallink(supernode, src_uuid)) {
        log_error("file is already linked\n");
        return -1;
    }

    // accounts for hardlinking on a hardlink
    real_uuid = supernode_get_reallink(supernode, dst_uuid);

    if (real_uuid == NULL) {
        // then we are hardlinking on a normal file
        real_uuid = dst_uuid;
        // add a spare hardlink (count = 2, for metadata)
        __add_hardlink(supernode, real_uuid, real_uuid);
    }

    return __add_hardlink(supernode, src_uuid, real_uuid);
}

bool
supernode_del_hardlink(struct nexus_supernode  * supernode,
                       struct nexus_uuid       * link_uuid,
                       struct nexus_uuid      ** real_uuid)
{
    struct __hardlink_pair     * hardlink_pair = NULL;

    struct nexus_list_iterator * iter          = NULL;

    iter = __get_hardlink_pair_iterator(supernode, link_uuid);

    if (iter == NULL) {
        return false;
    }

    hardlink_pair = list_iterator_get(iter);

    // if it's the last "real link"
    if (__get_link_count(supernode, &hardlink_pair->real_uuid) == 1) {
        *real_uuid = nexus_uuid_clone(&hardlink_pair->real_uuid);
    }

    // delete the entry
    list_iterator_del(iter);
    list_iterator_free(iter);

    supernode->hardlink_count -= 1;

    __supernode_set_dirty(supernode);

    return true;
}

bool
supernode_rename_link(struct nexus_supernode * supernode,
                      struct nexus_uuid      * old_uuid,
                      struct nexus_uuid      * new_uuid,
                      bool                   * is_real_file)
{
    struct nexus_list_iterator * iter = list_iterator_new(&supernode->hardlink_table);

    bool linkuuid_renamed = false;
    bool realuuid_renamed = false; // if we actually change a UUID which has a file on disk

    while (list_iterator_is_valid(iter)) {
        struct __hardlink_pair * pair = list_iterator_get(iter);

        if (nexus_uuid_compare(&pair->link_uuid, old_uuid) == 0) {
            nexus_uuid_copy(new_uuid, &pair->link_uuid);
            __supernode_set_dirty(supernode);

            if (realuuid_renamed == false) {
                *is_real_file = false;
            }

            linkuuid_renamed = true;
        }

        if (nexus_uuid_compare(&pair->real_uuid, old_uuid) == 0) {
            nexus_uuid_copy(new_uuid, &pair->real_uuid);
            __supernode_set_dirty(supernode);

            realuuid_renamed = true;
            *is_real_file  = true;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return (linkuuid_renamed | realuuid_renamed);
}
