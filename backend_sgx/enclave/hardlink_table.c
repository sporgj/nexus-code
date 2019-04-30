#include "enclave_internal.h"

#include "./libnexus_trusted/nexus_hashtable.h"


struct __hardlink_table_hdr {
    struct  nexus_uuid      uuid;
    struct  nexus_uuid      root_uuid;
    uint32_t                count;
} __attribute__((packed));


struct __hardlink_table_entry {
    uint32_t                link_count;

    struct nexus_uuid       link_uuid;
} __attribute__((packed));



void
hardlink_table_set_metadata(struct hardlink_table * hardlink_table,
                            struct nexus_metadata * metadata)
{
    hardlink_table->metadata = metadata;
}

struct __hardlink_table_entry *
__get_entry(struct hardlink_table * table, struct nexus_uuid * uuid)
{
    struct __hardlink_table_entry * entry = NULL;

    entry = (struct __hardlink_table_entry *) nexus_htable_search(table->hashtable, (uintptr_t)uuid);

    return entry;
}

struct __hardlink_table_entry *
__put_entry(struct hardlink_table * table, struct nexus_uuid * uuid, size_t count)
{
    struct __hardlink_table_entry * entry = nexus_malloc(sizeof(struct __hardlink_table_entry));

    nexus_uuid_copy(uuid, &entry->link_uuid);

    entry->link_count = count;

    nexus_htable_insert(table->hashtable, (uintptr_t)&entry->link_uuid, (uintptr_t)entry);

    table->count += 1;

    return entry;
}

static void
__del_entry(struct hardlink_table * table, struct nexus_uuid * uuid)
{
    struct __hardlink_table_entry * entry = NULL;

    entry = (struct __hardlink_table_entry *)nexus_htable_remove(table->hashtable, (uintptr_t)uuid, 0);

    if (entry) {
        table->count -= 1;
    }

    nexus_free(entry);
}

static void
__hardlink_table_set_dirty(struct hardlink_table * hardlink_table)
{
    if (hardlink_table->metadata) {
        __metadata_set_dirty(hardlink_table->metadata);
    }
}

static void
__hardlink_table_set_clean(struct hardlink_table * hardlink_table)
{
    if (hardlink_table->metadata) {
        __metadata_set_clean(hardlink_table->metadata);
    }
}

static void
hardlink_table_init(struct hardlink_table * hardlink_table,
                    struct nexus_uuid     * root_uuid,
                    struct nexus_uuid     * uuid)
{

    hardlink_table->hashtable = nexus_create_htable(32, __uuid_hasher, __uuid_equals);

    nexus_uuid_copy(uuid, &hardlink_table->my_uuid);

    if (root_uuid) {
        nexus_uuid_copy(root_uuid, &hardlink_table->root_uuid);
    }
}

void
hardlink_set_metadata(struct hardlink_table * hardlink_table, struct nexus_metadata * metadata)
{
    hardlink_table->metadata = metadata;
}

struct hardlink_table *
hardlink_table_create( struct nexus_uuid * root_uuid, struct nexus_uuid * table_uuid)
{
    struct hardlink_table * hardlink_table = nexus_malloc(sizeof(struct hardlink_table));

    hardlink_table_init(hardlink_table, root_uuid, table_uuid);

    return hardlink_table;
}


void
hardlink_table_free(struct hardlink_table * hardlink_table)
{
    nexus_free_htable(hardlink_table->hashtable, 1, 0);
    nexus_free(hardlink_table);
}


int
__parse_hardlink_table(struct hardlink_table * hardlink_table, uint8_t * buffer, size_t buflen)
{
    struct __hardlink_table_hdr   * header = (struct __hardlink_table_hdr *)buffer;

    struct __hardlink_table_entry * entry  = NULL;


    hardlink_table_init(hardlink_table, &header->root_uuid, &header->uuid);

    entry = (struct __hardlink_table_entry *)(buffer + sizeof(struct __hardlink_table_hdr));

    for (size_t i = 0; i < header->count; i++) {
        // will increment the table size by 1
        __put_entry(hardlink_table, &entry->link_uuid, entry->link_count);

        entry += 1;
    }

    return 0;
}

static size_t
__hardlink_total_size(struct hardlink_table * hardlink_table)
{
    return (hardlink_table->count * sizeof(struct __hardlink_table_entry))
              + sizeof(struct __hardlink_table_hdr);
}

static int
__serialize_hardlink_table(struct hardlink_table * hardlink_table, uint8_t * buffer)
{
    struct nexus_hashtable_iter   * iter  = NULL;

    struct __hardlink_table_entry * src_entry = NULL;
    struct __hardlink_table_entry * dst_entry = NULL;


    // write the header
    {
        struct __hardlink_table_hdr * hdr = (struct __hardlink_table_hdr *)buffer;

        nexus_uuid_copy(&hardlink_table->root_uuid, &hdr->root_uuid);
        nexus_uuid_copy(&hardlink_table->my_uuid, &hdr->uuid);

        hdr->count = hardlink_table->count;
    }

    dst_entry = (struct __hardlink_table_entry *)(buffer + sizeof(struct __hardlink_table_hdr));

    iter = nexus_htable_create_iter(hardlink_table->hashtable);

    do {
        if (iter->entry == NULL) {
            break;
        }

        src_entry = (struct __hardlink_table_entry *)nexus_htable_get_iter_value(iter);

        if (src_entry == NULL) {
            break;
        }

        memcpy(dst_entry, src_entry, sizeof(struct __hardlink_table_entry));

        dst_entry += 1;
    } while(nexus_htable_iter_advance(iter));

    nexus_htable_free_iter(iter);

    return 0;
}

int
hardlink_table_store(struct hardlink_table * hardlink_table, size_t version, struct nexus_mac * mac)
{
    uint8_t * output_buffer = NULL;
    size_t    output_buflen = 0;

    size_t    total_buflen  = __hardlink_total_size(hardlink_table);

    struct nexus_crypto_buf * crypto_buffer = NULL;


    crypto_buffer = nexus_crypto_buf_new(total_buflen, version, &hardlink_table->my_uuid);
    if (crypto_buffer == NULL) {
        goto out_err;
    }

    output_buffer = nexus_crypto_buf_get(crypto_buffer, &output_buflen, NULL);

    if (output_buffer == NULL) {
        log_error("could not get the crypto_buffer buffer\n");
        goto out_err;
    }

    if (__serialize_hardlink_table(hardlink_table, output_buffer)) {
        log_error("__serialize_hardlink_table() FAILED\n");
        goto out_err;
    }

    if (nexus_crypto_buf_put(crypto_buffer, &hardlink_table->mac)) {
        log_error("nexus_crypto_buf_put FAILED\n");
        goto out_err;
    }

    nexus_crypto_buf_free(crypto_buffer);

    if (mac) {
        nexus_mac_copy(&hardlink_table->mac, mac);
    }

    __hardlink_table_set_clean(hardlink_table);

    return 0;
out_err:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return -1;
}

struct hardlink_table *
hardlink_table_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer, nexus_io_flags_t flags)
{
    struct hardlink_table * hardlink_table = nexus_malloc(sizeof(struct hardlink_table));

    uint8_t * buffer = NULL;
    size_t    buflen = 0;


    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, &hardlink_table->mac);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        goto out_err;
    }

    if (__parse_hardlink_table(hardlink_table, buffer, buflen)) {
        log_error("__parse_hardlink_table() FAILED\n");
        goto out_err;
    }

    return hardlink_table;

out_err:
    if (hardlink_table) {
        hardlink_table_free(hardlink_table);
    }

    return NULL;
}

int
hardlink_table_incr_uuid(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid)
{
    struct __hardlink_table_entry * entry = __get_entry(hardlink_table, uuid);

    if (entry == NULL) {
        entry = __put_entry(hardlink_table, uuid, 1);
    }

    __hardlink_table_set_dirty(hardlink_table);

    entry->link_count += 1;

    return 0;
}

int
hardlink_table_decr_uuid(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid)
{
    struct __hardlink_table_entry * entry = __get_entry(hardlink_table, uuid);

    int link_count = 0;

    if (entry == NULL) {
        return -1;
    }

    entry->link_count -= 1;

    link_count = entry->link_count;

    __hardlink_table_set_dirty(hardlink_table);

    if (link_count < 2) {
        __del_entry(hardlink_table, uuid);
    }

    return link_count;
}

bool
hardlink_table_contains_uuid(struct hardlink_table * hardlink_table, struct nexus_uuid * uuid)
{
    struct __hardlink_table_entry * entry = __get_entry(hardlink_table, uuid);

    if (entry == NULL) {
        return false;
    }

    return true;
}

int
hardlink_table_get_uuid(struct hardlink_table * hardlink_table,
                        struct nexus_uuid     * uuid,
                        size_t                * link_count)
{
    struct __hardlink_table_entry * entry = __get_entry(hardlink_table, uuid);

    if (entry == NULL) {
        return -1;
    }

    *link_count = entry->link_count;

    return 0;
}
