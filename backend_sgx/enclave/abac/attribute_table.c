#include "attribute_table.h"

#include "../libnexus_trusted/hashmap.h"


struct __attr_table_hdr {
    size_t                  count;
} __attribute__((packed));


struct __attr_table_entry {
    struct nexus_uuid attr_uuid;
    size_t            attr_val_len;
    char              attr_val[ATTRIBUTE_VALUE_SIZE];
} __attribute__((packed));



// adding and removing entries from the attribute table's hashmap

static int
__put_attr_entry(struct attribute_table * attribute_table,
                 struct nexus_uuid *      uuid,
                 char *                   value,
                 size_t                   len)
{
    struct attribute_entry * new_entry = nexus_malloc(sizeof(struct attribute_entry));

    memcpy(new_entry->attr_val, value, len);
    new_entry->attr_val_len = len;

    hashmap_entry_init(&new_entry->hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    nexus_uuid_copy(uuid, &new_entry->attr_uuid);

    hashmap_add(&attribute_table->attribute_map, &new_entry->hash_entry);

    attribute_table->count += 1;

    return 0;
}

static int
__del_attr_entry(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    struct attribute_entry * rst_entry = NULL;
    struct attribute_entry   tmp_entry;

    hashmap_entry_init(&tmp_entry.hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    nexus_uuid_copy(uuid, &tmp_entry.attr_uuid);

    rst_entry = hashmap_remove(&attribute_table->attribute_map, &tmp_entry, NULL);
    if (rst_entry == NULL) {
        return -1;
    }

    nexus_free(rst_entry);

    attribute_table->count -= 1;

    return 0;
}

static struct attribute_entry *
__get_attr_entry(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    struct attribute_entry tmp_entry;

    hashmap_entry_init(&tmp_entry.hash_entry, memhash(uuid, sizeof(struct nexus_uuid)));
    nexus_uuid_copy(uuid, &tmp_entry.attr_uuid);

    return (struct attribute_entry *)hashmap_get(&attribute_table->attribute_map, &tmp_entry, NULL);
}

int
attribute_table_add(struct attribute_table * attribute_table, struct nexus_uuid * uuid, char * value)
{
    struct attribute_entry * entry = __get_attr_entry(attribute_table, uuid);

    size_t len = strnlen(value, ATTRIBUTE_VALUE_SIZE);

    if (entry == NULL) {
        entry = __put_attr_entry(attribute_table, uuid, value, len);

        return 0;
    }

    // update the entry
    entry->attr_val_len = len;
    memcpy(entry->attr_val, value, len);

    return 0;
}

int
attribute_table_del(struct attribute_table * attribute_table, struct nexus_uuid * uuid)
{
    return __del_attr_entry(attribute_table, uuid);
}


static int
__attribute_htable_cmp(const void *                   data,
                       const struct attribute_entry * entry1,
                       const struct attribute_entry * entry2,
                       const void *                   keydata)
{
    return nexus_uuid_compare(&entry1->attr_uuid, &entry2->attr_uuid);
}

static void
attribute_table_init(struct attribute_table * attribute_table)
{
    hashmap_init(&attribute_table->attribute_map, (hashmap_cmp_fn)__attribute_htable_cmp, NULL, 0);
}

struct attribute_table *
attribute_table_create()
{
    struct attribute_table * attribute_table = nexus_malloc(sizeof(struct attribute_table));

    attribute_table_init(attribute_table);

    return attribute_table;
}

void
attribute_table_free(struct attribute_table * attribute_table)
{
    hashmap_free(&attribute_table->attribute_map, true);
    nexus_free(attribute_table);
}


uint8_t *
__parse_attribute_table_hdr(struct attribute_table * attribute_table, uint8_t * buffer)
{
    struct __attr_table_hdr * header = (struct __attr_table_hdr *)buffer;

    attribute_table->count = header->count;

    return buffer + sizeof(struct __attr_table_hdr);
}

int
__parse_attribute_table_body(struct attribute_table * attribute_table, uint8_t * buffer)
{
    struct __attr_table_entry * input_entry = (struct __attr_table_entry *)buffer;

    size_t count = attribute_table->count;

    attribute_table->count = 0; // __put_attr_entry increments the count

    for (size_t i = 0; i < count; i++) {
        if (__put_attr_entry(attribute_table,
                             &input_entry->attr_uuid,
                             input_entry->attr_val,
                             input_entry->attr_val_len)) {
            log_error("__put_attr_entry FAILED\n");
            return -1;
        }

        input_entry += 1;
    }

    return 0;
}

struct attribute_table *
attribute_table_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct attribute_table * attribute_table = NULL;

    if (buflen < sizeof(struct __attr_table_hdr)) {
        log_error("attribute_table buffer is too small (len=%zu, min=%zu)\n",
                  buflen,
                  sizeof(struct __attr_table_hdr));

        return NULL;
    }

    attribute_table = nexus_malloc(sizeof(struct attribute_table));

    attribute_table_init(attribute_table);

    buffer = __parse_attribute_table_hdr(attribute_table, buffer);

    buffer += sizeof(struct __attr_table_hdr);

    if (__parse_attribute_table_body(attribute_table, buffer)) {
        log_error("__parse_attribute_table_body FAILED\n");
        goto err;
    }

    return attribute_table;
err:
    if (attribute_table) {
        nexus_free(attribute_table);
    }

    return NULL;
}

size_t
attribute_table_get_size(struct attribute_table * attribute_table)
{
    return sizeof(struct __attr_table_hdr)
           + (attribute_table->count * sizeof(struct __attr_table_entry));
}

uint8_t *
__serialize_attribute_header(struct attribute_table * attribute_table, uint8_t * buffer)
{
    struct __attr_table_hdr * dest_header = (struct __attr_table_hdr *)buffer;

    dest_header->count = attribute_table->count;

    return buffer + sizeof(struct __attr_table_hdr);
}

uint8_t *
__serialize_attribute_entry(struct attribute_entry * attribute_entry, uint8_t * buffer)
{
    struct __attr_table_entry * dest_entry = (struct __attr_table_entry *)buffer;

    nexus_uuid_copy(&attribute_entry->attr_uuid, &dest_entry->attr_uuid);
    dest_entry->attr_val_len = attribute_entry->attr_val_len;
    memcpy(dest_entry->attr_val, attribute_entry->attr_val, attribute_entry->attr_val_len);

    return (buffer + sizeof(struct __attr_table_entry));
}

int
attribute_table_store(struct attribute_table * attribute_table, uint8_t * buffer, size_t buflen)
{
    struct hashmap_iter iter;

    size_t total_len = attribute_table_get_size(attribute_table);

    if (buflen < total_len) {
        log_error("attribute_table buffer too small. (got=%zu, min=%zu)\n", buflen, total_len);
        return -1;
    }

    buffer = __serialize_attribute_header(attribute_table, buffer);

    hashmap_iter_init(&attribute_table->attribute_map, &iter);

    do {
        struct attribute_entry * attr_entry = hashmap_iter_next(&iter);

        if (attr_entry == NULL) {
            break;
        }

        buffer = __serialize_attribute_entry(attr_entry, buffer);
    } while (1);

    return 0;
}

