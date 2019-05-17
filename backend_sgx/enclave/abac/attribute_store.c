#include <ctype.h>

#include "attribute_store.h"

struct __attr_store_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint32_t count;
} __attribute__((packed));

struct __attr_store_entry {
    attribute_type_t  type;
    char              name[ATTRIBUTE_NAME_MAX];
    struct nexus_uuid uuid;
} __attribute__((packed));



static inline size_t
__get_attribute_store_size(struct attribute_store * attribute_store)
{
    return sizeof(struct __attr_store_hdr)
           + (attribute_store->count * sizeof(struct __attr_store_entry));
}

static inline struct attribute_schema *
__attribute_schema_from_list_entry(struct list_head * entry)
{
    return (struct attribute_schema *) container_of(entry, struct attribute_schema, list_entry);
}

static struct attribute_schema *
__find_attribute_schema_by_name(struct attribute_store * attribute_store, char * name)
{
    struct list_head * curr = NULL;

    size_t len = strnlen(name, ATTRIBUTE_NAME_MAX);

    list_for_each(curr, &attribute_store->list_attribute_schemas)
    {
        struct attribute_schema * schema = __attribute_schema_from_list_entry(curr);

        if ((len == strnlen(schema->name, ATTRIBUTE_NAME_MAX))
            && (memcmp(name, schema->name, len) == 0)) {
            return schema;
        }
    }

    return NULL;
}

static struct attribute_schema *
__find_attribute_schema_by_uuid(struct attribute_store * attribute_store, struct nexus_uuid * uuid)
{
    struct list_head * curr = NULL;

    list_for_each(curr, &attribute_store->list_attribute_schemas)
    {
        struct attribute_schema * schema = __attribute_schema_from_list_entry(curr);

        if (nexus_uuid_compare(&schema->uuid, uuid) == 0) {
            return schema;
        }
    }

    return NULL;
}

static struct attribute_schema *
__put_attribute(struct attribute_store * attribute_store,
                char *                   name,
                struct nexus_uuid *      uuid,
                attribute_type_t         type)
{
    struct attribute_schema * schema = nexus_malloc(sizeof(struct attribute_schema));

    nexus_uuid_copy(uuid, &schema->uuid);
    strncpy(schema->name, name, ATTRIBUTE_NAME_MAX);
    schema->type = type;

    list_add_tail(&schema->list_entry, &attribute_store->list_attribute_schemas);
    attribute_store->count += 1;

    return schema;
}

static void
__del_attribute(struct attribute_store * attribute_store, struct attribute_schema * schema)
{
    list_del(&schema->list_entry);
    attribute_store->count -= 1;

    nexus_free(schema);
}


// -- creating/destroying

struct attribute_store *
attribute_store_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid)
{
    struct attribute_store * attribute_store = nexus_malloc(sizeof(struct attribute_store));

    nexus_uuid_copy(uuid, &attribute_store->my_uuid);
    nexus_uuid_copy(root_uuid, &attribute_store->root_uuid);

    INIT_LIST_HEAD(&attribute_store->list_attribute_schemas);

    return attribute_store;
}

void
attribute_store_free(struct attribute_store * attr_store)
{
    struct list_head * curr = NULL;
    struct list_head * next = NULL;

    list_for_each_safe(curr, next, &attr_store->list_attribute_schemas)
    {
        struct attribute_schema * schema = __attribute_schema_from_list_entry(curr);

        list_del(&schema->list_entry);
        nexus_free(schema);
    }

    nexus_free(attr_store);
}


// -- store/load

static struct attribute_store *
attribute_store_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct __attr_store_hdr * header = (struct __attr_store_hdr *)buffer;

    struct __attr_store_entry * in_entry = NULL;

    struct attribute_store * attribute_store = NULL;

    if (buflen < sizeof(struct __attr_store_hdr)) {
        log_error("buffer is too small\n");
    }

    attribute_store = attribute_store_create(&header->root_uuid, &header->my_uuid);

    // now parse the entries
    in_entry = (struct __attr_store_entry *)(buffer + sizeof(struct __attr_store_hdr));

    for (size_t i = 0; i < header->count; i++) {
        __put_attribute(attribute_store, in_entry->name, &in_entry->uuid, in_entry->type);
        in_entry += 1;
    }

    return attribute_store;
}

struct attribute_store *
attribute_store_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    struct attribute_store * attribute_store = NULL;
    struct nexus_mac mac;

    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, &mac);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }

    attribute_store = attribute_store_from_buffer(buffer, buflen);

    if (attribute_store == NULL) {
        log_error("attribute_store_from_buffer FAILED\n");
        return NULL;
    }

    nexus_mac_copy(&mac, &attribute_store->mac);

    return attribute_store;
}

static int
attribute_store_serialize(struct attribute_store * attribute_store, uint8_t * buffer)
{
    struct __attr_store_hdr * header = (struct __attr_store_hdr *)buffer;

    struct list_head * curr = NULL;

    struct __attr_store_entry * out_entry = NULL;


    // serialize the header
    nexus_uuid_copy(&attribute_store->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&attribute_store->root_uuid, &header->root_uuid);
    header->count = attribute_store->count;

    // now serialize the entries
    out_entry = (struct __attr_store_entry *)(buffer + sizeof(struct __attr_store_hdr));

    list_for_each(curr, &attribute_store->list_attribute_schemas)
    {
        struct attribute_schema * schema = __attribute_schema_from_list_entry(curr);

        nexus_uuid_copy(&schema->uuid, &out_entry->uuid);
        out_entry->type = schema->type;
        memcpy(out_entry->name, schema->name, ATTRIBUTE_NAME_MAX);

        out_entry += 1;
    }

    return 0;
}

int
attribute_store_store(struct attribute_store * attribute_store,
                      size_t                   version,
                      struct nexus_mac       * mac)
{
    size_t serialized_buflen = __get_attribute_store_size(attribute_store);

    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t    buflen = 0;
    uint8_t * buffer = NULL;


    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, version, &attribute_store->my_uuid);
    if (crypto_buffer == NULL) {
        log_error("nexus_crypto_buf_new() FAILED\n");
        return -1;
    }

    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);
    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        goto out_err;
    }

    if (attribute_store_serialize(attribute_store, buffer)) {
        log_error("attribute_store_serialize() FAILED\n");
        goto out_err;
    }

    if (nexus_crypto_buf_put(crypto_buffer, &attribute_store->mac)) {
        log_error("nexus_crypto_buf_put() FAILED\n");
        goto out_err;
    }

    nexus_crypto_buf_free(crypto_buffer);

    return 0;
out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}


// -- add/del from attribute_store

static void
__attribute_store_set_dirty(struct attribute_store * attribute_store)
{
    if (attribute_store->metadata) {
        __metadata_set_dirty(attribute_store->metadata);
    }
}

int
attribute_store_add(struct attribute_store * attr_store, char * name, attribute_type_t type)
{
    struct attribute_schema * schema = __find_attribute_schema_by_name(attr_store, name);

    struct nexus_uuid uuid;

    if (schema != NULL) {
        return -1;
    }

    if (!isalpha(name[0])) {
        log_error("attribute name `%s` is invalid\n", name);
        return -1;
    }

    // make sure it's not a permission types
    if (perm_type_from_string(name) != PERM_UNK) {
        log_error("illegal attribute name specified (%s)\n", name);
        return -1;
    }

    nexus_uuid_gen(&uuid);

    __put_attribute(attr_store, name, &uuid, type);

    __attribute_store_set_dirty(attr_store);

    return 0;
}

int
attribute_store_del(struct attribute_store * attr_store, char * name)
{
    struct attribute_schema * schema = __find_attribute_schema_by_name(attr_store, name);

    if (schema == NULL) {
        return -1;
    }

    __del_attribute(attr_store, schema);

    __attribute_store_set_dirty(attr_store);

    return 0;
}

const struct attribute_schema *
attribute_store_find_uuid(struct attribute_store * attr_store, struct nexus_uuid * uuid)
{
    return __find_attribute_schema_by_uuid(attr_store, uuid);
}

const struct attribute_schema *
attribute_store_find_name(struct attribute_store * attr_store, char * name)
{
    return __find_attribute_schema_by_name(attr_store, name);
}

void
attribute_store_export_macversion(struct attribute_store * attr_store,
                                  struct mac_and_version * macversion)
{
    nexus_mac_copy(&attr_store->mac, &macversion->mac);
}

int
UNSAFE_attribute_store_export(struct attribute_store      * attr_store,
                              struct nxs_attribute_schema * attribute_schema_array_out,
                              size_t                        attribute_schema_array_capacity,
                              size_t                        offset,
                              size_t                      * total_count_out,
                              size_t                      * result_count_out)
{
    struct list_head * curr = NULL;

    struct nxs_attribute_schema * out_attribute_schema = attribute_schema_array_out;

    size_t copied = 0;


    list_for_each(curr, &attr_store->list_attribute_schemas)
    {
        if (offset) {
            offset -= 1;
            continue;
        }

        struct attribute_schema * schema = __attribute_schema_from_list_entry(curr);

        strncpy(out_attribute_schema->schema_str, schema->name, ATTRIBUTE_NAME_MAX);
        attribute_type_to_str(
            schema->type, out_attribute_schema->type_str, sizeof(out_attribute_schema->type_str));

        out_attribute_schema += 1;
        copied += 1;

        if (copied == attribute_schema_array_capacity) {
            break;
        }
    }

    *result_count_out = copied;
    *total_count_out = attr_store->count;

    return 0;
}
